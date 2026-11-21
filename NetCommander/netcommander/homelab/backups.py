"""Backup & disaster-recovery center.

Uptime Funk does not replace your backup software; it **watches** it:

* **Backup inventory** - jobs you register (or that integrations report), each with an expected
  frequency (``max_age_hours``) and optional minimum size.
* **Status / verification** - evaluated from the platform that runs the backup:
  ``proxmox`` (vzdump task history), ``truenas`` (replication / cloud-sync state), ``file``
  (newest file in a local or SSH-reachable directory: age, size, size-drop detection, optional SHA-256
  for local files), ``netcommander`` (the built-in network config backups), ``manual`` (you record runs).
* **Recovery points** - successful runs with timestamps.
* **Exports** - full inventory (JSON/CSV) and a configuration bundle (settings, integrations, scripts,
  IPAM - never secrets) for rebuilding Uptime Funk itself.
* **Recovery documentation** - a Markdown runbook generated from the inventory, dependencies and backups.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .core.db import Database
from .core.errors import NotFound, ValidationError
from .core.runners import Runner
from .models import Asset, new_id

JOBS, RUNS = "backup_jobs", "backup_runs"
PLATFORMS = ("proxmox", "truenas", "file", "netcommander", "manual")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./@+-]{1,500}$")


@dataclass
class BackupJob:
    name: str
    platform: str
    max_age_hours: float = 26.0
    source_asset: str = ""             # what is protected
    integration: str = ""              # proxmox / truenas integration id
    match: str = ""                    # proxmox vmid, truenas task name, file directory, device name
    destination: str = ""
    min_size: int = 0
    runner_asset: str = ""             # for remote "file" jobs: asset whose SSH config reaches the directory
    checksum: bool = False
    notes: str = ""                    # restore procedure
    id: str = field(default_factory=lambda: new_id("bk"))

    def validate(self) -> BackupJob:
        problems = []
        if not self.name.strip():
            problems.append("name is required")
        if self.platform not in PLATFORMS:
            problems.append(f"platform must be one of {', '.join(PLATFORMS)}")
        if not 0.1 <= float(self.max_age_hours) <= 24 * 400:
            problems.append("max_age_hours must be between 0.1 and 9600")
        if self.platform in ("proxmox", "truenas") and not self.integration:
            problems.append("integration is required for proxmox/truenas jobs")
        if self.platform == "file":
            if not self.match or not _SAFE_PATH.match(self.match) or ".." in self.match:
                if not (self.match and os.name == "nt" and re.match(r"^[A-Za-z]:\\[^<>|\"*?]+$", self.match)):
                    problems.append("file jobs need an absolute directory path without spaces or shell characters")
        if problems:
            raise ValidationError("Invalid backup job: " + "; ".join(problems), problems)
        return self


@dataclass
class BackupStatus:
    job_id: str
    state: str                          # ok | stale | failed | unknown
    last_success: float | None = None
    last_attempt: float | None = None
    last_size: int | None = None
    age_hours: float | None = None
    message: str = ""
    recovery_points: list[dict[str, Any]] = field(default_factory=list)
    verified: dict[str, Any] = field(default_factory=dict)


def evaluate(job: BackupJob, points: list[dict[str, Any]], now: float, failures: list[dict[str, Any]] | None = None) -> BackupStatus:
    """Turn raw recovery points (``{"ts", "size"?, "ok"}``) into a status with verification results."""
    good = sorted((p for p in points if p.get("ok", True) and p.get("ts")), key=lambda p: p["ts"])
    bad = sorted(failures or [], key=lambda p: p.get("ts") or 0)
    st = BackupStatus(job.id, "unknown", recovery_points=good[-50:][::-1])
    st.last_attempt = max([p["ts"] for p in good] + [b.get("ts") or 0 for b in bad] or [0]) or None
    if not good:
        st.state = "failed" if bad else "unknown"
        st.message = (bad[-1].get("message") or "last run failed") if bad else "no successful backup found"
        return st
    last = good[-1]
    st.last_success, st.last_size = last["ts"], last.get("size")
    st.age_hours = round((now - last["ts"]) / 3600, 1)
    checks: dict[str, Any] = {"age_ok": st.age_hours <= job.max_age_hours}
    if job.min_size and last.get("size") is not None:
        checks["size_ok"] = last["size"] >= job.min_size
    if len(good) >= 2 and good[-2].get("size") and last.get("size") is not None:
        checks["no_size_drop"] = last["size"] >= 0.5 * good[-2]["size"]
    if "sha256" in last:
        checks["checksum"] = last["sha256"]
    st.verified = checks
    if bad and (bad[-1].get("ts") or 0) > last["ts"]:
        st.state, st.message = "failed", bad[-1].get("message") or "most recent run failed"
    elif not checks["age_ok"]:
        st.state, st.message = "stale", f"last good backup {st.age_hours:g} h ago (expected every {job.max_age_hours:g} h)"
    elif checks.get("size_ok") is False or checks.get("no_size_drop") is False:
        st.state, st.message = "failed", "backup is suspiciously small"
    else:
        st.state, st.message = "ok", f"last good backup {st.age_hours:g} h ago"
    return st


def file_points_local(directory: str, checksum: bool = False, limit: int = 30) -> list[dict[str, Any]]:
    out = []
    try:
        entries = [e for e in os.scandir(directory) if e.is_file()]
    except OSError as exc:
        raise ValidationError(f"Cannot read {directory}: {exc}") from None
    for e in sorted(entries, key=lambda e: e.stat().st_mtime, reverse=True)[:limit]:
        st = e.stat()
        p: dict[str, Any] = {"ts": st.st_mtime, "size": st.st_size, "ok": True, "name": e.name}
        out.append(p)
    if checksum and out:
        h = hashlib.sha256()
        with open(os.path.join(directory, out[0]["name"]), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        out[0]["sha256"] = h.hexdigest()
    return out


def parse_stat_lines(text: str) -> list[dict[str, Any]]:
    """Output of ``stat -c '%Y %s %n' DIR/*`` (GNU/BusyBox)."""
    out = []
    for line in text.splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            out.append({"ts": float(parts[0]), "size": int(parts[1]), "ok": True, "name": os.path.basename(parts[2])})
    return sorted(out, key=lambda p: -p["ts"])


def file_points_remote(runner: Runner, directory: str) -> list[dict[str, Any]]:
    if not _SAFE_PATH.match(directory) or ".." in directory:
        raise ValidationError("Unsafe directory path.")
    r = runner.run(f"stat -c '%Y %s %n' {directory.rstrip('/')}/*", timeout=30)
    if r.exit_code == 255:
        raise ValidationError(r.stderr or "remote host unreachable")
    return parse_stat_lines(r.stdout)[:30]


def proxmox_points(tasks: Iterable[Mapping[str, Any]], vmid: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    good: list[dict[str, Any]] = []
    bad: list[dict[str, Any]] = []
    for t in tasks:
        if vmid and str(t.get("vmid")) != str(vmid):
            continue
        if t.get("status") in (None, "", "running"):
            continue
        rec = {"ts": t.get("end") or t.get("start"), "ok": t.get("status") == "OK", "node": t.get("node"),
               "message": str(t.get("status"))}
        (good if rec["ok"] else bad).append(rec)
    return good, bad


def truenas_points(tasks: Iterable[Mapping[str, Any]], name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    good: list[dict[str, Any]] = []
    bad: list[dict[str, Any]] = []
    for t in tasks:
        if name and t.get("name") != name:
            continue
        ts = t.get("last")
        ts = ts / 1000.0 if isinstance(ts, (int, float)) and ts > 1e11 else ts
        state = str(t.get("state", "")).upper()
        if state in ("SUCCESS", "FINISHED"):
            good.append({"ts": ts, "ok": True})
        elif state in ("ERROR", "FAILED", "ABORTED"):
            bad.append({"ts": ts, "ok": False, "message": state})
    return good, bad


class BackupCenter:
    def __init__(self, db: Database, clock: Callable[[], float] = time.time) -> None:
        self.db, self._clock = db, clock

    def jobs(self) -> list[BackupJob]:
        return [BackupJob(**j) for j in self.db.all(JOBS)]

    def job(self, jid: str) -> BackupJob:
        d = self.db.get(JOBS, jid)
        if not d:
            raise NotFound(f"No backup job {jid!r}.")
        return BackupJob(**d)

    def save_job(self, data: Mapping[str, Any]) -> BackupJob:
        j = BackupJob(**{k: v for k, v in data.items() if k in BackupJob.__dataclass_fields__}).validate()
        self.db.put(JOBS, j.id, asdict(j))
        return j

    def delete_job(self, jid: str) -> bool:
        return self.db.delete(JOBS, jid)

    def record_manual(self, jid: str, ok: bool, size: int | None = None, message: str = "") -> dict[str, Any]:
        self.job(jid)
        rec: dict[str, Any] = {"id": new_id("br"), "job": jid, "ts": self._clock(), "ok": bool(ok), "size": size, "message": message[:300]}
        self.db.put(RUNS, rec["id"], rec)
        return rec

    def manual_points(self, jid: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        runs = [r for r in self.db.all(RUNS) if r["job"] == jid]
        return [r for r in runs if r["ok"]], [r for r in runs if not r["ok"]]

    def store_status(self, st: BackupStatus) -> None:
        self.db.put("backup_status", st.job_id, asdict(st))

    def statuses(self) -> list[dict[str, Any]]:
        out = []
        for j in self.jobs():
            st = self.db.get("backup_status", j.id) or asdict(BackupStatus(j.id, "unknown", message="not checked yet"))
            out.append({**asdict(j), "status": st})
        return out


# ---------------------------------------------------------------- recovery documentation
def recovery_runbook(assets: list[Asset], backups: list[dict[str, Any]], generated_by: str, now: float | None = None) -> str:
    now = time.time() if now is None else now
    by_id = {a.id: a for a in assets}
    lines = [
        "# Infrastructure recovery runbook", "",
        f"Generated by Uptime Funk on {time.strftime('%Y-%m-%d %H:%M', time.localtime(now))} by {generated_by}.",
        "Keep a printed or offline copy: you will need it when the systems below are down.", "",
        "## Recovery order", "",
        "Restore from the bottom of the dependency chain upwards: network -> storage -> hypervisors / Docker hosts -> "
        "servers -> virtual machines -> containers -> services.", "",
    ]
    order = ["router", "firewall", "switch", "access_point", "nas", "storage", "hypervisor", "docker_host", "server",
             "vm", "container", "service"]
    groups: dict[str, list[Asset]] = {}
    for a in assets:
        groups.setdefault(a.kind, []).append(a)
    for kind in order + sorted(set(groups) - set(order)):
        items = groups.get(kind)
        if not items:
            continue
        lines += [f"## {kind.replace('_', ' ').title()}s", ""]
        for a in sorted(items, key=lambda x: x.name.lower()):
            lines.append(f"### {a.name}")
            facts = [("IP", a.ip), ("Hostname", a.hostname), ("MAC", a.mac), ("OS", a.os),
                     ("Hardware", " ".join(x for x in (a.manufacturer, a.model) if x)), ("Location", a.location),
                     ("Runs on", by_id[a.parent].name if a.parent in by_id else "")]
            for label, val in facts:
                if val:
                    lines.append(f"- **{label}:** {val}")
            mgmt = ", ".join(f"{k} as {v.get('username', '?')}@{v.get('host', a.ip)}" for k, v in a.management.items()
                             if isinstance(v, dict))
            if mgmt:
                lines.append(f"- **Management:** {mgmt} (credentials are in the Uptime Funk vault)")
            deps = [f"{lk['type'].replace('_', ' ')} {by_id[lk['to']].name}" + (f" ({lk['port']})" if lk.get("port") else "")
                    for lk in a.links if lk.get("to") in by_id]
            if deps:
                lines.append(f"- **Depends on:** {'; '.join(deps)}")
            kids = [x.name for x in assets if x.parent == a.id]
            if kids:
                lines.append(f"- **Hosts:** {', '.join(sorted(kids))}")
            covering = [b for b in backups if b.get("source_asset") == a.id]
            if covering:
                for b in covering:
                    st = b.get("status") or {}
                    last = st.get("last_success")
                    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "never"
                    lines.append(f"- **Backup:** {b['name']} ({b['platform']}) -> {b.get('destination') or 'n/a'}; "
                                 f"last good: {when}; state: {st.get('state', 'unknown')}")
                    if b.get("notes"):
                        lines.append(f"  - Restore: {b['notes']}")
            elif kind not in ("container", "service"):
                lines.append("- **Backup:** none registered - consider adding one.")
            if a.notes:
                lines.append(f"- **Notes:** {a.notes}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def config_bundle(db: Database, settings: Mapping[str, Any], version: str) -> dict[str, Any]:
    """Everything needed to rebuild Uptime Funk's homelab configuration - but no secrets and no history."""
    from .core.sanitize import redact_mapping
    collections = ("integrations", "ipam_subnets", "ipam_vlans", "ipam_reservations", "monitor_checks",
                   "monitor_rules", "automation_scripts", "automation_workflows", "automation_policies", "backup_jobs",
                   "assets")
    return {"format": "netcommander-homelab-config", "version": version, "exported": time.time(),
            "settings": redact_mapping(dict(settings)),
            "collections": {c: redact_mapping(db.all(c)) for c in collections}}


def write_json(path: Path | str, data: Any) -> Path:
    from ..security import _write_private
    _write_private(Path(path), json.dumps(data, indent=2, sort_keys=True, default=str))
    return Path(path)
