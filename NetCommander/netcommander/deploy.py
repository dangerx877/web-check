"""Staged deployments with an approval workflow.

Lifecycle::

    draft -> pending_approval -> approved -> running -> completed
                 |                  |           |-> halted (a stage failed; later stages skipped)
                 |-> rejected       |-> cancelled

Controls
* Separation of duties: the requester cannot approve their own plan (unless explicitly allowed).
* Approval is bound to a SHA-256 of the exact commands + stage layout; editing a plan voids approvals.
* ``required_approvals`` distinct approvers (default 1), each needing APPROVE_DEPLOY.
* Stages run in order (e.g. canary -> 25% -> rest); a failed stage halts the rollout.
* Every transition is audited; state is persisted atomically after each change and survives restarts.
  A plan found ``running`` after a restart is marked ``halted`` (interrupted) - never silently resumed.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, List

from .audit import AuditLog
from .filelock import FileLock
from .rbac import Permission, PermissionDenied, require
from .security import _write_private

STATUSES = ("draft", "pending_approval", "approved", "running", "completed", "halted", "rejected", "cancelled")

# push(device, commands) -> (ok, message)
PushFn = Callable[[str, list[str]], "tuple[bool, str]"]
EventFn = Callable[[str, dict], None]


class DeployError(RuntimeError):
    pass


def plan_digest(commands: Mapping[str, Sequence[str]], stages: Sequence[Sequence[str]],
                options: Mapping[str, Any] | None = None) -> str:
    body = {"commands": {k: list(v) for k, v in sorted(commands.items())}, "stages": [list(s) for s in stages],
            "options": dict(options or {})}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


def _options(p: Mapping[str, Any]) -> dict[str, Any]:
    """Execution options an approver must be shown and that approval is therefore bound to."""
    return {"save_after": p["save_after"], "auto_rollback": p["auto_rollback"], "checks": p["checks"],
            "halt_on_failure": p["halt_on_failure"]}


def make_stages(devices: Sequence[str], canary: int = 1, batch_size: int | None = None) -> list[list[str]]:
    """Canary stage first, then batches of ``batch_size`` (default: everything left in one stage)."""
    devs = list(dict.fromkeys(devices))
    if not devs:
        raise ValueError("No devices selected.")
    canary = max(0, min(canary, len(devs)))
    stages = [devs[:canary]] if canary else []
    rest = devs[canary:]
    if rest:
        size = batch_size if batch_size and batch_size > 0 else len(rest)
        stages += [rest[i:i + size] for i in range(0, len(rest), size)]
    return stages


class DeploymentStore:
    def __init__(
        self,
        path: Path,
        role_of: Callable[[str], str],
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.time,
        allow_self_approval: bool = False,
    ) -> None:
        self.path = Path(path)
        self._role_of, self._audit, self._clock = role_of, audit, clock
        self.allow_self_approval = allow_self_approval
        self._lock = threading.RLock()
        self._flock = FileLock(self.path)
        self._mtime = -1.0
        self._plans: dict[str, dict] = self._load()

    # ---- persistence ---------------------------------------------------
    def _read(self) -> dict[str, dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._mtime = self.path.stat().st_mtime_ns
        except (OSError, ValueError):
            return {}
        return {p["id"]: p for p in data.get("plans", []) if isinstance(p, dict) and "id" in p}

    def _refresh(self, force: bool = False) -> None:
        """Pick up changes made by another process (e.g. the CLI) since we last looked."""
        try:
            m = self.path.stat().st_mtime_ns
        except OSError:
            return
        if force or m != self._mtime:
            self._plans = self._read()

    def _load(self) -> dict[str, dict]:
        plans = self._read()
        for p in plans.values():
            if p.get("status") == "running":
                p["status"] = "halted"
                p.setdefault("log", []).append({"ts": self._clock(), "msg": "Interrupted by restart; not resumed."})
        return plans

    def _save(self, plans: dict[str, dict]) -> None:
        _write_private(self.path, json.dumps({"plans": list(plans.values())}, indent=2))
        try:
            self._mtime = self.path.stat().st_mtime_ns
        except OSError:
            self._mtime = -1.0

    def _mutate(self, plan_id: str, fn: Callable[[dict], None]) -> dict:
        """Apply ``fn`` to a copy; persist; publish only if the write succeeded."""
        with self._lock, self._flock:                      # cross-process read-modify-write
            self._refresh(force=True)
            cur = self._plans.get(plan_id)
            if cur is None:
                raise DeployError(f"No deployment {plan_id!r}.")
            work = json.loads(json.dumps(cur))
            fn(work)
            candidate = dict(self._plans)
            candidate[plan_id] = work
            self._save(candidate)
            self._plans = candidate
            return json.loads(json.dumps(work))

    def _log(self, actor: str, action: str, plan: Mapping[str, Any], outcome: str = "ok", detail: str = "") -> None:
        if self._audit:
            self._audit.record(actor, f"deploy.{action}", f"{plan.get('id')}: {plan.get('title')}", outcome, detail)

    def _need(self, actor: str, perm: Permission) -> None:
        try:
            require(self._role_of(actor), perm)
        except PermissionDenied:
            if self._audit:
                self._audit.record(actor, f"deny.{perm.value}", outcome="denied")
            raise

    # ---- queries -------------------------------------------------------
    def get(self, plan_id: str) -> dict:
        with self._lock:
            self._refresh()
            if plan_id not in self._plans:
                raise DeployError(f"No deployment {plan_id!r}.")
            return json.loads(json.dumps(self._plans[plan_id]))

    def list(self, status: str | None = None) -> List[dict]:
        with self._lock:
            self._refresh()
            plans = [json.loads(json.dumps(p)) for p in self._plans.values()]
        return sorted((p for p in plans if status in (None, p["status"])), key=lambda p: p["created_at"])

    # ---- workflow ------------------------------------------------------
    def create(
        self, actor: str, title: str, commands: Mapping[str, Sequence[str]], stages: Sequence[Sequence[str]],
        *, save_after: bool = True, halt_on_failure: bool = True, required_approvals: int = 1,
        auto_rollback: bool = False, checks: Sequence[Mapping[str, str]] = (),
    ) -> dict:
        self._need(actor, Permission.REQUEST_DEPLOY)
        if not title.strip():
            raise ValueError("A deployment needs a title.")
        staged = [d for s in stages for d in s]
        if not staged or len(set(staged)) != len(staged):
            raise ValueError("Each device must appear in exactly one stage.")
        missing = [d for d in staged if not list(commands.get(d, []))]
        if missing:
            raise ValueError(f"No commands for: {', '.join(missing)}")
        if required_approvals < 1:
            raise ValueError("At least one approval is required.")
        pid = f"D{int(self._clock())}-{secrets.token_hex(3)}"
        plan: dict[str, Any] = {
            "id": pid, "title": title.strip(), "created_by": actor, "created_at": self._clock(), "status": "draft",
            "commands": {d: list(commands[d]) for d in staged}, "stages": [list(s) for s in stages],
            "save_after": save_after, "halt_on_failure": halt_on_failure, "required_approvals": required_approvals,
            "auto_rollback": auto_rollback, "checks": [dict(c) for c in checks],
            "approvals": [], "results": {}, "log": [],
        }
        plan["digest"] = plan_digest(plan["commands"], plan["stages"], _options(plan))
        with self._lock, self._flock:
            self._refresh(force=True)
            candidate = dict(self._plans)
            candidate[pid] = plan
            self._save(candidate)
            self._plans = candidate
        self._log(actor, "create", plan, detail=f"{len(staged)} devices in {len(stages)} stage(s)")
        return json.loads(json.dumps(plan))

    def submit(self, actor: str, plan_id: str) -> dict:
        self._need(actor, Permission.REQUEST_DEPLOY)

        def fn(p: dict) -> None:
            if p["status"] != "draft":
                raise DeployError(f"Only drafts can be submitted (this one is {p['status']}).")
            if p["created_by"] != actor and self._role_of(actor) != "admin":
                raise DeployError("Only the requester or an admin can submit this plan.")
            p["status"] = "pending_approval"
        out = self._mutate(plan_id, fn)
        self._log(actor, "submit", out)
        return out

    def decide(self, actor: str, plan_id: str, approve: bool, note: str = "") -> dict:
        self._need(actor, Permission.APPROVE_DEPLOY)

        def fn(p: dict) -> None:
            if p["status"] != "pending_approval":
                raise DeployError(f"Not awaiting approval (status: {p['status']}).")
            if not self.allow_self_approval and actor == p["created_by"]:
                raise DeployError("Separation of duties: you cannot approve your own deployment.")
            if any(a["by"] == actor for a in p["approvals"]):
                raise DeployError("You have already reviewed this deployment.")
            if p["digest"] != plan_digest(p["commands"], p["stages"], _options(p)):
                raise DeployError("Plan contents changed after submission; re-create it.")
            p["approvals"].append({"by": actor, "ts": self._clock(), "approve": approve, "note": note,
                                   "digest": p["digest"]})
            if not approve:
                p["status"] = "rejected"
            elif sum(1 for a in p["approvals"] if a["approve"]) >= p["required_approvals"]:
                p["status"] = "approved"
        out = self._mutate(plan_id, fn)
        self._log(actor, "approve" if approve else "reject", out, detail=note)
        return out

    def cancel(self, actor: str, plan_id: str) -> dict:
        def fn(p: dict) -> None:
            if p["status"] in ("running", "completed", "halted", "rejected", "cancelled"):
                raise DeployError(f"Cannot cancel a {p['status']} deployment.")
            if p["created_by"] != actor:
                require(self._role_of(actor), Permission.APPROVE_DEPLOY)
            p["status"] = "cancelled"
        out = self._mutate(plan_id, fn)
        self._log(actor, "cancel", out)
        return out

    # ---- execution -----------------------------------------------------
    def execute(
        self, actor: str, plan_id: str, push: PushFn, *, workers: int = 4,
        on_event: EventFn | None = None, stage_gate: Callable[[int, List[str]], bool] | None = None,
    ) -> dict:
        """Run an approved plan. ``stage_gate(i, devices)`` may veto starting stage ``i`` (>0)."""
        self._need(actor, Permission.PUSH_CONFIG)
        emit = on_event or (lambda k, p: None)

        def start(p: dict[str, Any]) -> None:
            if p["status"] != "approved":
                raise DeployError(f"Only approved deployments can run (status: {p['status']}).")
            if p["digest"] != plan_digest(p["commands"], p["stages"], _options(p)) or not all(
                    a["digest"] == p["digest"] for a in p["approvals"] if a["approve"]):
                raise DeployError("Approved content does not match the plan; refusing to run.")
            p["status"], p["started_at"], p["results"] = "running", self._clock(), {}
        plan = self._mutate(plan_id, start)
        self._log(actor, "execute", plan)

        halted = False
        for i, stage in enumerate(plan["stages"]):
            if halted or (i > 0 and stage_gate is not None and not stage_gate(i, list(stage))):
                halted = True
                self._record(plan_id, {d: {"status": "skipped", "message": "earlier stage failed or was stopped"}
                                       for d in stage})
                continue
            emit("stage_start", {"plan": plan_id, "stage": i, "devices": list(stage)})

            def one(dev: str, p: dict = plan) -> tuple[str, dict]:
                try:
                    ok, msg = push(dev, list(p["commands"][dev]))
                except Exception as exc:                       # a crash on one device must not kill the stage
                    ok, msg = False, f"{type(exc).__name__}: {exc}"
                return dev, {"status": "ok" if ok else "failed", "message": msg, "ts": self._clock()}

            with ThreadPoolExecutor(max_workers=max(1, min(workers, len(stage)))) as pool:
                results = dict(pool.map(one, stage))
            self._record(plan_id, results)
            emit("stage_done", {"plan": plan_id, "stage": i, "results": results})
            if plan["halt_on_failure"] and any(r["status"] != "ok" for r in results.values()):
                halted = True

        def finish(p: dict) -> None:
            p["status"] = "halted" if halted or any(r["status"] != "ok" for r in p["results"].values()) else "completed"
            p["finished_at"] = self._clock()
        out = self._mutate(plan_id, finish)
        self._log(actor, "finish", out, outcome="ok" if out["status"] == "completed" else "failed",
                  detail=f"status={out['status']}")
        return out

    def _record(self, plan_id: str, results: dict[str, dict]) -> None:
        self._mutate(plan_id, lambda p: p["results"].update(results))
