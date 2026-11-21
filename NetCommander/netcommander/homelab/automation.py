"""Automation Center: scripts, workflows, approvals, execution history and policy-gated remediation.

Execution kinds
* ``python``      - runs **on the NetCommander host** in a separate interpreter (``python -I``), in a
  throw-away working directory, with a minimal environment (no credentials, no ``NETCOMMANDER_*``
  variables) and a timeout. Use it for reports and API glue, not as a sandbox for untrusted code.
* ``ssh``         - a shell command on Linux/Unix targets over SSH (host keys verified).
* ``powershell``  - a PowerShell script on Windows targets over WinRM.

Safety model
1. Every script declares a **risk**: ``read_only``, ``change`` or ``destructive``. A static scan
   (:func:`scan_risk`) refuses to accept a script whose body clearly does more than it declares
   (e.g. "read_only" containing ``rm -rf`` or ``Restart-Computer``). The scan is a guard-rail, not a
   proof - the approval step is the real control.
2. Running needs ``RUN_AUTOMATION``; authoring needs ``MANAGE_AUTOMATION``.
3. Risks listed in ``automation.require_approval_for`` (default: change, destructive) need **approval by
   a different person** holding ``APPROVE_AUTOMATION``. The approval is bound to the script's SHA-256:
   editing the script after approval invalidates it.
4. Parameters are substituted only after validation against the declared pattern (default
   ``^[A-Za-z0-9_.@:-]{1,64}$``) - no quoting games.
5. Automatic remediation happens **only** through an explicit :class:`RemediationPolicy` created by an
   admin, with an expiry, recorded in the audit log; destructive scripts additionally need
   ``allow_destructive`` on the policy.
6. Output is captured (size-capped), secrets are redacted, and every run is kept in the history.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from ..rbac import Permission, PermissionDenied, Role, can, require
from .core.db import Database
from .core.errors import NotFound, ValidationError
from .core.events import EventBus
from .core.runners import CommandResult, Runner
from .core.sanitize import redact_text
from .models import new_id

log = logging.getLogger(__name__)
SCRIPTS, RUNS, WORKFLOWS, POLICIES = "automation_scripts", "automation_runs", "automation_workflows", "automation_policies"
KINDS = ("python", "ssh", "powershell")
RISKS = ("read_only", "change", "destructive")
RISK_RANK = {r: i for i, r in enumerate(RISKS)}
DEFAULT_PARAM_PATTERN = r"^[A-Za-z0-9_.@:-]{1,64}$"
_PARAM_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_PLACEHOLDER = re.compile(r"\{\{\s*([a-z][a-z0-9_]{0,31})\s*\}\}")

_DESTRUCTIVE = [re.compile(p, re.I) for p in (
    r"\brm\s+-[a-z]*r[a-z]*f?\b", r"\bmkfs(\.\w+)?\b", r"\bdd\s+[^\n]*of=/dev/", r"\bwipefs\b", r"\bshred\b",
    r"\b(shutdown|poweroff|halt|reboot)\b", r"\bsystemctl\s+(poweroff|reboot|halt)\b", r"\bzpool\s+(destroy|labelclear)\b",
    r"\bzfs\s+destroy\b", r"\bdocker\s+(rm|rmi|system\s+prune|volume\s+rm)\b", r"\bqm\s+destroy\b", r"\bpct\s+destroy\b",
    r"\bvirsh\s+(undefine|destroy)\b", r"Remove-Item\b[^\n]*-Recurse", r"\bFormat-Volume\b", r"\bClear-Disk\b",
    r"\b(Stop|Restart)-Computer\b", r"\bRemove-VM\b", r"\bdrop\s+(table|database)\b", r"\bshutil\.rmtree\b",
    r"\bos\.(remove|unlink|rmdir)\b", r"\btruncate\s+-s\s*0\b", r">\s*/dev/sd[a-z]",
)]
_CHANGE = [re.compile(p, re.I) for p in (
    r"\bsystemctl\s+(restart|start|stop|enable|disable|reload)\b", r"\bservice\s+\S+\s+(restart|start|stop)\b",
    r"\b(apt|apt-get|dnf|yum|zypper|apk|pacman)\s+(install|remove|upgrade|-S|-R|update)\b", r"\bdocker\s+(restart|stop|start|pull|run|compose\s+up)\b",
    r"\b(Restart|Start|Stop|Set)-Service\b", r"\bSet-\w+\b", r"\bNew-\w+\b", r"\bchmod\b", r"\bchown\b", r"\bmv\s", r"\bcp\s",
    r"\bsed\s+-i\b", r"\btee\b", r"(^|[^2&])>{1,2}\s*[^&\s]", r"\bkill(all)?\b", r"\bopen\([^)]*['\"][wa]", r"\brequests\.(post|put|delete|patch)\b",
    r"\bcrontab\b", r"\buseradd\b|\busermod\b|\bpasswd\b", r"\bqm\s+(start|stop|shutdown|reboot)\b", r"\bpct\s+(start|stop)\b",
)]


def scan_risk(body: str) -> tuple[str, list[str]]:
    """Lowest risk level the body plausibly needs, and the reasons."""
    hits_d = [p.pattern for p in _DESTRUCTIVE if p.search(body)]
    if hits_d:
        return "destructive", hits_d
    hits_c = [p.pattern for p in _CHANGE if p.search(body)]
    if hits_c:
        return "change", hits_c
    return "read_only", []


@dataclass
class Script:
    name: str
    kind: str
    body: str
    risk: str
    description: str = ""
    params: list[dict[str, Any]] = field(default_factory=list)   # [{"name": "service", "pattern": "...", "default": ""}]
    timeout: int = 120
    id: str = field(default_factory=lambda: new_id("scr"))
    created_by: str = ""
    updated: float = field(default_factory=time.time)
    builtin: bool = False

    @property
    def sha256(self) -> str:
        return hashlib.sha256(f"{self.kind}\0{self.risk}\0{self.body}".encode()).hexdigest()

    def validate(self) -> Script:
        problems = []
        if not self.name.strip() or len(self.name) > 100:
            problems.append("name is required (max 100)")
        if self.kind not in KINDS:
            problems.append(f"kind must be one of {', '.join(KINDS)}")
        if self.risk not in RISKS:
            problems.append(f"risk must be one of {', '.join(RISKS)}")
        if not self.body.strip() or len(self.body) > 200_000:
            problems.append("body is required (max 200 kB)")
        if not 1 <= int(self.timeout) <= 86400:
            problems.append("timeout must be 1-86400 seconds")
        declared = {p.get("name") for p in self.params}
        for p in self.params:
            if not _PARAM_NAME.match(str(p.get("name", ""))):
                problems.append(f"invalid parameter name {p.get('name')!r}")
            try:
                re.compile(p.get("pattern") or DEFAULT_PARAM_PATTERN)
            except re.error:
                problems.append(f"parameter {p.get('name')}: invalid pattern")
        for used in set(_PLACEHOLDER.findall(self.body)) - declared:
            problems.append(f"placeholder {{{{{used}}}}} has no declared parameter")
        if self.risk in RISKS:
            needed, why = scan_risk(self.body)
            if RISK_RANK[needed] > RISK_RANK[self.risk]:
                problems.append(f"declared '{self.risk}' but the script looks '{needed}' (matched: {why[0]}); "
                                "declare the higher risk")
        if problems:
            raise ValidationError("Invalid script: " + "; ".join(problems), problems)
        return self

    def render(self, values: Mapping[str, str]) -> str:
        spec = {p["name"]: p for p in self.params}
        problems = []
        final: dict[str, str] = {}
        for name, p in spec.items():
            v = str(values.get(name, p.get("default", "")) or "")
            if not re.fullmatch(p.get("pattern") or DEFAULT_PARAM_PATTERN, v):
                problems.append(f"parameter {name}={v!r} does not match {p.get('pattern') or DEFAULT_PARAM_PATTERN}")
            final[name] = v
        extra = set(values) - set(spec)
        if extra:
            problems.append(f"unknown parameters: {', '.join(sorted(extra))}")
        if problems:
            raise ValidationError("; ".join(problems), problems)
        return _PLACEHOLDER.sub(lambda m: final[m.group(1)], self.body)


@dataclass
class RemediationPolicy:
    """Standing authorisation: when ``alert_metric`` alerts on a matching asset, run ``script_id``."""
    script_id: str
    alert_metric: str
    created_by: str
    expires: float
    scope_kind: str = ""
    scope_asset: str = ""
    min_severity: str = "critical"
    params: dict[str, str] = field(default_factory=dict)
    allow_destructive: bool = False
    enabled: bool = True
    cooldown_minutes: int = 60
    id: str = field(default_factory=lambda: new_id("pol"))
    last_fired: dict[str, float] = field(default_factory=dict)


BUILTIN_SCRIPTS: tuple[dict[str, Any], ...] = (
    {"id": "builtin-disk-report", "name": "Disk usage report", "kind": "ssh", "risk": "read_only",
     "body": "df -hP -x tmpfs -x devtmpfs", "description": "Filesystem usage on Linux hosts."},
    {"id": "builtin-failed-units", "name": "Failed systemd units", "kind": "ssh", "risk": "read_only",
     "body": "systemctl --failed --no-pager --no-legend", "description": "Services in failed state."},
    {"id": "builtin-updates", "name": "Pending package updates (apt)", "kind": "ssh", "risk": "read_only",
     "body": "apt list --upgradable 2>/dev/null | tail -n +2", "description": "Debian/Ubuntu/Proxmox pending updates."},
    {"id": "builtin-restart-service", "name": "Restart a systemd service", "kind": "ssh", "risk": "change",
     "body": "systemctl restart {{service}} && systemctl is-active {{service}}",
     "params": [{"name": "service", "pattern": r"^[A-Za-z0-9@._-]{1,64}$"}],
     "description": "Restart one service and report its state (needs approval by default)."},
    {"id": "builtin-win-services", "name": "Stopped automatic Windows services", "kind": "powershell", "risk": "read_only",
     "body": "Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | "
             "Select-Object Name,DisplayName,Status | Format-Table -AutoSize | Out-String -Width 200",
     "description": "Automatic services that are not running."},
    {"id": "builtin-restart-win-service", "name": "Restart a Windows service", "kind": "powershell", "risk": "change",
     "body": "Restart-Service -Name '{{service}}' -PassThru | Select-Object Name,Status | Out-String",
     "params": [{"name": "service", "pattern": r"^[A-Za-z0-9_.-]{1,64}$"}], "description": "Needs approval by default."},
    {"id": "builtin-zpool-status", "name": "ZFS pool status", "kind": "ssh", "risk": "read_only",
     "body": "zpool status -x", "description": "Only prints pools with problems."},
    {"id": "builtin-docker-ps", "name": "Docker containers", "kind": "ssh", "risk": "read_only",
     "body": "docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.Image}}'", "description": "Container states."},
)
RunnerFactory = Callable[[str, str], Runner]      # (asset_id, kind) -> Runner


def run_python(body: str, timeout: int, max_output: int) -> CommandResult:
    """Separate interpreter, isolated mode, scrubbed environment, temporary working directory."""
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "LANG", "TZ")}
    env["PYTHONIOENCODING"] = "utf-8"
    with tempfile.TemporaryDirectory(prefix="nc-auto-") as wd:
        path = os.path.join(wd, "script.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        try:
            p = subprocess.run([sys.executable, "-I", path], cwd=wd, env=env, capture_output=True, timeout=timeout,
                               check=False)
        except subprocess.TimeoutExpired as exc:
            return CommandResult("python", 124, (exc.stdout or b"")[:max_output].decode("utf-8", "replace"),
                                 f"timed out after {timeout}s")
    return CommandResult("python", p.returncode, p.stdout[:max_output].decode("utf-8", "replace"),
                         p.stderr[:max_output].decode("utf-8", "replace"))


class AutomationCenter:
    def __init__(self, db: Database, bus: EventBus, runner_factory: RunnerFactory,
                 audit: Callable[[str, str, str, str, str], Any], config: Mapping[str, Any],
                 clock: Callable[[], float] = time.time, python_exec: Callable[[str, int, int], CommandResult] = run_python) -> None:
        self.db, self.bus, self._runner_for, self._audit = db, bus, runner_factory, audit
        self.cfg = dict(config)
        self._clock, self._python = clock, python_exec
        self._lock = threading.RLock()
        for b in BUILTIN_SCRIPTS:
            if self.db.get(SCRIPTS, b["id"]) is None:
                self.db.put(SCRIPTS, b["id"], asdict(Script(**b, builtin=True, created_by="builtin")))

    # ---- scripts ---------------------------------------------------------
    def scripts(self) -> list[dict[str, Any]]:
        out = []
        for d in self.db.all(SCRIPTS):
            s = Script(**d)
            out.append({**d, "sha256": s.sha256, "needs_approval": self.needs_approval(s.risk)})
        return sorted(out, key=lambda s: s["name"].lower())

    def script(self, sid: str) -> Script:
        d = self.db.get(SCRIPTS, sid)
        if not d:
            raise NotFound(f"No script {sid!r}.")
        return Script(**d)

    def save_script(self, user: str, role: Role | str, data: Mapping[str, Any]) -> Script:
        require(role, Permission.MANAGE_AUTOMATION)
        allowed = {"id", "name", "kind", "body", "risk", "description", "params", "timeout"}
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"Unknown fields: {', '.join(sorted(unknown))}")
        if data.get("id") and str(data["id"]).startswith("builtin-"):
            raise ValidationError("Built-in scripts are read-only; save a copy under a new name.")
        s = Script(**{**data, "created_by": user, "updated": self._clock()}).validate()
        self.db.put(SCRIPTS, s.id, asdict(s))
        self._audit(user, "automation.script.save", s.id, "ok", f"{s.name} risk={s.risk} sha={s.sha256[:12]}")
        return s

    def delete_script(self, user: str, role: Role | str, sid: str) -> bool:
        require(role, Permission.MANAGE_AUTOMATION)
        if sid.startswith("builtin-"):
            raise ValidationError("Built-in scripts cannot be deleted.")
        ok = self.db.delete(SCRIPTS, sid)
        if ok:
            self._audit(user, "automation.script.delete", sid, "ok", "")
        return ok

    def needs_approval(self, risk: str) -> bool:
        return risk in self.cfg.get("require_approval_for", ["change", "destructive"])

    # ---- runs --------------------------------------------------------------
    def runs(self, limit: int = 100) -> list[dict[str, Any]]:
        return sorted(self.db.all(RUNS), key=lambda r: -r["created"])[:limit]

    def run_record(self, rid: str) -> dict[str, Any]:
        r = self.db.get(RUNS, rid)
        if not r:
            raise NotFound(f"No run {rid!r}.")
        return r

    def request(self, user: str, role: Role | str, script_id: str, targets: list[str],
                params: Mapping[str, str] | None = None, note: str = "", *, via_policy: str = "") -> dict[str, Any]:
        """Create a run. Runs that need no approval are returned with status ``approved`` (call :meth:`execute`)."""
        if not via_policy:
            require(role, Permission.RUN_AUTOMATION)
        s = self.script(script_id)
        rendered = s.render(params or {})                        # validates parameters now
        if s.kind in ("ssh", "powershell") and not targets:
            raise ValidationError("Choose at least one target for an SSH/PowerShell script.")
        if s.kind == "python" and targets:
            raise ValidationError("Python scripts run on the NetCommander host; do not pass targets.")
        need = self.needs_approval(s.risk) and not via_policy
        run = {"id": new_id("run"), "script_id": s.id, "script_name": s.name, "kind": s.kind, "risk": s.risk,
               "sha256": s.sha256, "params": dict(params or {}), "targets": list(targets), "requested_by": user,
               "note": note[:500], "created": self._clock(), "status": "pending_approval" if need else "approved",
               "approved_by": via_policy and f"policy:{via_policy}" or "", "decided": None, "started": None,
               "finished": None, "results": {}, "preview": redact_text(rendered)[:2000]}
        self.db.put(RUNS, run["id"], run)
        self._audit(user, "automation.request", run["id"], "ok",
                    f"{s.name} risk={s.risk} targets={','.join(targets)[:150]}{' policy=' + via_policy if via_policy else ''}")
        self.bus.emit("automation.requested", "automation", run["id"], f"{user} requested '{s.name}'",
                      severity="info", needs_approval=need)
        return run

    def decide(self, user: str, role: Role | str, run_id: str, approve: bool, comment: str = "",
               single_admin: bool = False) -> dict[str, Any]:
        try:
            require(role, Permission.APPROVE_AUTOMATION)
        except PermissionDenied:
            self._audit(user, "automation.decide", run_id, "denied", "needs approve_automation")
            raise
        with self._lock:
            run = self.run_record(run_id)
            if run["status"] != "pending_approval":
                raise ValidationError(f"Run is {run['status']}, not waiting for approval.")
            if run["requested_by"] == user and not (single_admin and self.cfg.get("allow_self_approval_when_single_admin")):
                self._audit(user, "automation.decide", run_id, "denied", "self-approval")
                raise PermissionDenied(Role.parse(role), Permission.APPROVE_AUTOMATION,
                                       "you cannot approve your own request (separation of duties)")
            run.update(status="approved" if approve else "rejected", approved_by=user if approve else "",
                       rejected_by="" if approve else user, decided=self._clock(), decision_comment=comment[:500])
            self.db.put(RUNS, run_id, run)
        self._audit(user, "automation.approve" if approve else "automation.reject", run_id, "ok", comment[:200])
        self.bus.emit("automation.decided", "automation", run_id, f"{user} {'approved' if approve else 'rejected'} "
                      f"'{run['script_name']}'")
        return run

    def cancel(self, user: str, run_id: str) -> dict[str, Any]:
        with self._lock:
            run = self.run_record(run_id)
            if run["status"] not in ("pending_approval", "approved"):
                raise ValidationError(f"Run is {run['status']}; it cannot be cancelled.")
            if run["requested_by"] != user:
                raise PermissionError("Only the requester can cancel a run.")
            run.update(status="cancelled", finished=self._clock())
            self.db.put(RUNS, run_id, run)
        self._audit(user, "automation.cancel", run_id, "ok", "")
        return run

    def execute(self, user: str, role: Role | str, run_id: str) -> dict[str, Any]:
        """Run an approved run (synchronously - call it from the task runner)."""
        with self._lock:
            run = self.run_record(run_id)
            if run["status"] != "approved":
                raise ValidationError(f"Run is {run['status']}; only approved runs can execute.")
            if not run["approved_by"].startswith("policy:") and run["requested_by"] != user and \
                    not can(role, Permission.APPROVE_AUTOMATION):
                raise PermissionError("Only the requester or an approver can start this run.")
            s = self.script(run["script_id"])
            if s.sha256 != run["sha256"]:
                run.update(status="failed", finished=self._clock(), error="script changed after approval - request again")
                self.db.put(RUNS, run_id, run)
                self._audit(user, "automation.execute", run_id, "denied", "script changed after approval")
                return run
            run.update(status="running", started=self._clock(), started_by=user)
            self.db.put(RUNS, run_id, run)
        body = s.render(run["params"])
        max_out = int(self.cfg.get("max_output_kb", 512)) * 1024
        results: dict[str, Any] = {}
        if s.kind == "python":
            r = self._python(body, s.timeout, max_out)
            results["local"] = self._result(r)
        else:
            for target in run["targets"]:
                try:
                    runner = self._runner_for(target, s.kind)
                    try:
                        r = runner.run(body, timeout=s.timeout)
                    finally:
                        close = getattr(runner, "close", None)
                        if close:
                            close()
                    results[target] = self._result(r)
                except Exception as exc:
                    results[target] = {"exit_code": 255, "stdout": "", "stderr": redact_text(str(exc))[:2000], "ok": False}
        ok = all(v["ok"] for v in results.values()) if results else False
        with self._lock:
            run = self.run_record(run_id)
            run.update(status="succeeded" if ok else "failed", finished=self._clock(), results=results)
            self.db.put(RUNS, run_id, run)
        self._audit(user, "automation.execute", run_id, "ok" if ok else "failed",
                    f"{s.name}: {sum(1 for v in results.values() if v['ok'])}/{len(results)} ok")
        self.bus.emit("automation.finished", "automation", run_id, f"'{s.name}' {run['status']}",
                      severity="info" if ok else "warning")
        return run

    @staticmethod
    def _result(r: CommandResult) -> dict[str, Any]:
        return {"exit_code": r.exit_code, "stdout": redact_text(r.stdout), "stderr": redact_text(r.stderr), "ok": r.ok}

    # ---- workflows ---------------------------------------------------------------
    def workflows(self) -> list[dict[str, Any]]:
        return self.db.all(WORKFLOWS)

    def save_workflow(self, user: str, role: Role | str, name: str, steps: list[dict[str, Any]],
                      wid: str = "") -> dict[str, Any]:
        require(role, Permission.MANAGE_AUTOMATION)
        if not name.strip() or not steps:
            raise ValidationError("A workflow needs a name and at least one step.")
        clean = []
        for st in steps:
            s = self.script(str(st.get("script_id")))
            s.render(st.get("params") or {})
            clean.append({"script_id": s.id, "targets": list(st.get("targets") or []), "params": dict(st.get("params") or {}),
                          "continue_on_error": bool(st.get("continue_on_error"))})
        risk = max((self.script(st["script_id"]).risk for st in clean), key=lambda r: RISK_RANK[r])
        wf = {"id": wid or new_id("wf"), "name": name.strip()[:100], "steps": clean, "risk": risk, "created_by": user}
        self.db.put(WORKFLOWS, wf["id"], wf)
        self._audit(user, "automation.workflow.save", wf["id"], "ok", f"{wf['name']} risk={risk}")
        return wf

    def run_workflow(self, user: str, role: Role | str, wid: str) -> list[dict[str, Any]]:
        """Request every step. Steps that need approval stay pending; the rest execute in order."""
        wf = self.db.get(WORKFLOWS, wid)
        if not wf:
            raise NotFound(f"No workflow {wid!r}.")
        out = []
        for st in wf["steps"]:
            run = self.request(user, role, st["script_id"], st["targets"], st["params"], note=f"workflow {wf['name']}")
            if run["status"] == "approved":
                run = self.execute(user, role, run["id"])
                if run["status"] != "succeeded" and not st["continue_on_error"]:
                    out.append(run)
                    break
            out.append(run)
            if run["status"] == "pending_approval":
                break                                         # later steps wait until this one is approved and run
        return out

    # ---- remediation policies -----------------------------------------------------
    def policies(self) -> list[dict[str, Any]]:
        return self.db.all(POLICIES)

    def add_policy(self, user: str, role: Role | str, data: Mapping[str, Any]) -> RemediationPolicy:
        require(role, Permission.MANAGE_AUTOMATION)
        require(role, Permission.APPROVE_AUTOMATION)
        days = float(data.get("valid_days", 30))
        if not 0 < days <= 365:
            raise ValidationError("A remediation policy must expire within 365 days.")
        s = self.script(str(data.get("script_id")))
        if s.risk == "destructive" and not data.get("allow_destructive"):
            raise ValidationError("This script is destructive: set allow_destructive explicitly to automate it.")
        s.render(data.get("params") or {})
        p = RemediationPolicy(script_id=s.id, alert_metric=str(data.get("alert_metric") or ""), created_by=user,
                              expires=self._clock() + days * 86400, scope_kind=str(data.get("scope_kind") or ""),
                              scope_asset=str(data.get("scope_asset") or ""),
                              min_severity=str(data.get("min_severity") or "critical"),
                              params=dict(data.get("params") or {}), allow_destructive=bool(data.get("allow_destructive")),
                              cooldown_minutes=int(data.get("cooldown_minutes", 60)))
        if not p.alert_metric:
            raise ValidationError("alert_metric is required.")
        self.db.put(POLICIES, p.id, asdict(p))
        self._audit(user, "automation.policy.add", p.id, "ok",
                    f"{s.name} on {p.alert_metric} until {time.strftime('%Y-%m-%d', time.localtime(p.expires))}")
        return p

    def remove_policy(self, user: str, role: Role | str, pid: str) -> bool:
        require(role, Permission.MANAGE_AUTOMATION)
        ok = self.db.delete(POLICIES, pid)
        if ok:
            self._audit(user, "automation.policy.remove", pid, "ok", "")
        return ok

    def on_alert(self, alert: Mapping[str, Any], asset_kind: str) -> list[dict[str, Any]]:
        """Called for each newly raised alert; runs matching, valid, non-expired policies."""
        fired = []
        now = self._clock()
        for d in self.policies():
            p = RemediationPolicy(**d)
            if not p.enabled or p.expires < now or p.alert_metric != alert.get("metric"):
                continue
            if p.min_severity == "critical" and alert.get("severity") != "critical":
                continue
            if p.scope_asset and p.scope_asset != alert.get("target") or p.scope_kind and p.scope_kind != asset_kind:
                continue
            last = p.last_fired.get(str(alert.get("target")))
            if last is not None and now - last < p.cooldown_minutes * 60:
                continue
            try:
                s = self.script(p.script_id)
            except NotFound:
                continue
            if s.risk == "destructive" and not p.allow_destructive:
                continue
            targets = [str(alert["target"])] if s.kind != "python" else []
            run = self.request(f"policy:{p.id}", Role.ADMIN, p.script_id, targets, p.params,
                               note=f"remediation for {alert.get('id')}", via_policy=p.id)
            p.last_fired[str(alert.get("target"))] = now
            self.db.put(POLICIES, p.id, asdict(p))
            fired.append(self.execute(f"policy:{p.id}", Role.ADMIN, run["id"]))
        return fired
