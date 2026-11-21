"""HomelabPlatform: wires the homelab modules together behind one permission-checked, audited facade.

The GUI, the headless CLI and the HTTP API all call this class, so authorization, confirmation of
risky actions, auditing and event publication are implemented exactly once. Every public method takes
a :class:`Ctx` (who is asking, with which role); the platform itself owns the vault-backed secrets.

Long-running work (discovery sweeps, integration polls, monitoring) runs on the
:class:`~netcommander.homelab.core.tasks.TaskRunner`; callers get a task id back immediately.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .. import __version__
from ..audit import AuditLog, sinks_from_env
from ..config import Paths
from ..rbac import Permission, PermissionDenied, Role, can, require
from ..security import CredentialVault
from . import backups as bk
from . import monitoring as mon
from . import netmgmt, servers
from .adapters import builtin_registry
from .automation import AutomationCenter
from .containers import ACTION_RISK, container_observation
from .core import settings as cfgmod
from .core.authz import Action, ActionGuard
from .core.db import Database
from .core.errors import IntegrationError, NotFound, ValidationError
from .core.events import Event, EventBus
from .core.notify import FileChannel, LogChannel, Notifier, SmtpChannel, WebhookChannel
from .core.registry import build_adapter
from .core.runners import Runner, SshRunner, SshTarget, WinRmRunner, WinRmTarget
from .core.sanitize import redact_mapping
from .core.secrets import SecretStore
from .core.tasks import PeriodicScheduler, TaskInfo, TaskRunner
from .discovery import DiscoveryEngine, tcp_probe
from .inventory import AssetStore
from .models import Asset, new_id
from .storage.base import forecast, share_checks
from .virtualization.base import POWER_RISK

log = logging.getLogger(__name__)
INTEGRATIONS = "integrations"
HOST_KIND = {"hypervisor": "hypervisor", "docker": "docker_host", "storage": "nas"}


@dataclass(frozen=True)
class Ctx:
    user: str
    role: Role

    @classmethod
    def of(cls, user: str, role: Role | str) -> Ctx:
        return cls(user, Role.parse(role))


@dataclass(frozen=True)
class HomelabPaths:
    db: Path
    config: Path
    secrets: Path

    @classmethod
    def from_paths(cls, paths: Paths) -> HomelabPaths:
        return cls(paths.root / "homelab.db", paths.root / "homelab.json", paths.root / "homelab_secrets.json")


def load_network_devices(paths: Paths) -> dict[str, dict]:
    """The classic network inventory (topology.json), read-only."""
    if not paths.topology.exists():
        return {}
    from ..network import load_inventory_json
    try:
        return load_inventory_json(paths.topology)
    except (OSError, ValueError):
        return {}


class HomelabPlatform:
    def __init__(self, paths: Paths, vault: CredentialVault, *, device_source: Callable[[], Mapping[str, dict]] | None = None,
                 config: Mapping[str, Any] | None = None, clock: Callable[[], float] = time.time,
                 adapter_factory: Callable[[dict], Any] | None = None, probe: Callable[[str, int, float], str] = tcp_probe,
                 runner_factory: Callable[[Asset, str, bool], Runner] | None = None,
                 discovery_factory: Callable[[dict], DiscoveryEngine] | None = None, audit: AuditLog | None = None,
                 start_background: bool = False) -> None:
        self.paths = paths
        self.hpaths = HomelabPaths.from_paths(paths)
        self.cfg = cfgmod.validate(config) if config is not None else cfgmod.load(self.hpaths.config)
        self._clock = clock
        self.vault = vault
        self.db = Database(self.hpaths.db, clock=clock)
        self.bus = EventBus()
        self.audit_log = audit or AuditLog(paths.audit, sinks=sinks_from_env())
        self.secrets = SecretStore(self.hpaths.secrets, vault)
        self.registry = builtin_registry()
        if self.cfg["plugins"]["enabled"]:
            self.registry.load_entry_points(self.cfg["plugins"]["allow"])
        self.tasks = TaskRunner(max_workers=self.cfg["monitoring"]["workers"], on_change=self._task_changed)
        self.periodic = PeriodicScheduler(self.tasks)
        self.inventory = AssetStore(self.db, self.bus, network_source=device_source or (lambda: load_network_devices(paths)),
                                    clock=clock)
        self.guard = ActionGuard(self._audit, clock=clock)
        self.notifier = self._build_notifier()
        self._probe = probe
        self.monitor = mon.MonitoringEngine(self.db, self.bus, self.notifier, self._asset_or_none, clock=clock,
                                            workers=self.cfg["monitoring"]["workers"], probe=probe)
        self.automation = AutomationCenter(self.db, self.bus, self._automation_runner, self._audit, self.cfg["automation"],
                                           clock=clock)
        self.backups = bk.BackupCenter(self.db, clock=clock)
        self.ipam = netmgmt.Ipam(self.db)
        self.diag = netmgmt.Diagnostics(probe=probe)
        self._adapter_factory = adapter_factory
        self._runner_factory = runner_factory
        self._discovery_factory = discovery_factory
        self._adapters: dict[str, Any] = {}
        self._adapter_lock = threading.Lock()
        self.bus.subscribe("*", self._persist_event)
        self.bus.subscribe("alert.raised", self._on_alert)
        if start_background:
            self.start()

    # ================================================================ lifecycle
    def start(self) -> None:
        m = self.cfg["monitoring"]
        self.periodic.every("monitor", m["interval_seconds"], self.monitor_cycle)
        self.periodic.every("collect", m["collect_interval_seconds"], self.collect_cycle)
        self.periodic.every("backups", 900, self.backup_cycle)
        self.periodic.every("housekeeping", 3600, lambda: self.monitor.prune(m["retention_days"], m["event_retention_days"]))
        self.periodic.start()

    def stop(self) -> None:
        self.periodic.stop()
        self.tasks.shutdown(wait=False)
        self.db.close()

    def _build_notifier(self) -> Notifier:
        channels: list[Any] = [LogChannel()]
        for ch in self.cfg["notifications"]["channels"]:
            try:
                sev = ch.get("min_severity", "warning")
                if ch["type"] == "file":
                    channels.append(FileChannel(ch.get("path") or str(self.paths.root / "alerts.jsonl"), min_severity=sev))
                elif ch["type"] == "webhook":
                    tok = self.secrets.get(ch["token_ref"]) if ch.get("token_ref") else ""
                    channels.append(WebhookChannel(ch["url"], tok, min_severity=sev, allow_http=bool(ch.get("allow_http"))))
                elif ch["type"] == "email":
                    pw = self.secrets.get(ch["password_ref"]) if ch.get("password_ref") else ""
                    channels.append(SmtpChannel(ch["host"], ch["sender"], list(ch.get("recipients") or []),
                                                int(ch.get("port", 587)), ch.get("username", ""), pw,
                                                ch.get("security", "starttls"), min_severity=sev))
            except Exception as exc:                       # a bad channel must not stop the platform
                log.warning("notification channel %s disabled: %s", ch.get("type"), exc)
        return Notifier(channels, dedup_window=self.cfg["notifications"]["dedup_minutes"] * 60, clock=self._clock)

    # ================================================================ helpers
    def _audit(self, actor: str, action: str, target: str = "", outcome: str = "ok", detail: str = "") -> None:
        self.audit_log.record(actor, action, target, outcome, detail)

    def _need(self, ctx: Ctx, perm: Permission, action: str = "") -> None:
        try:
            require(ctx.role, perm)
        except PermissionDenied:
            self._audit(ctx.user, f"deny.{action or perm.value}", "", "denied", f"needs {perm.value}")
            raise

    def _task_changed(self, t: TaskInfo) -> None:
        self.bus.emit("task.changed", "tasks", t.id, t.status, severity="debug")

    def _persist_event(self, ev: Event) -> None:
        if ev.severity == "debug":
            return
        try:
            self.db.add_event(ev.severity, ev.source, ev.kind, ev.target, ev.message, redact_mapping(ev.data), ev.ts)
        except Exception:                                  # pragma: no cover - never break publishers
            log.exception("could not persist event")

    def _asset_or_none(self, aid: str) -> Asset | None:
        if aid.startswith("backup:"):
            try:
                job = self.backups.job(aid.split(":", 1)[1])
                return Asset(id=aid, name=f"backup {job.name}", kind="service")
            except NotFound:
                return None
        try:
            return self.inventory.get(aid)
        except NotFound:
            return None

    def _on_alert(self, ev: Event) -> None:
        alert = self.db.get(mon.ALERTS, ev.data.get("alert_id", ""))
        if not alert:
            return
        asset = self._asset_or_none(alert["target"])
        if self.automation.policies():
            self.tasks.submit("remediation", self.automation.on_alert, alert, asset.kind if asset else "", owner="policy")

    def submit(self, ctx: Ctx, name: str, fn: Callable[..., Any], *args: Any) -> TaskInfo:
        return self.tasks.submit(name, fn, *args, owner=ctx.user)

    # ================================================================ inventory
    def assets(self, ctx: Ctx, **filters: Any) -> list[dict[str, Any]]:
        self._need(ctx, Permission.VIEW)
        alerts = self.monitor.alerts()
        out = []
        for a in self.inventory.search(**filters):
            d = a.summary()
            d["health"] = mon.health_score(a, alerts)
            out.append(d)
        return out

    def asset(self, ctx: Ctx, aid: str) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        a = self.inventory.get(aid)
        alerts = [x for x in self.monitor.alerts() if x["target"] == aid]
        latest = {k: v[1] for k, v in self.db.latest_metrics(aid).items()}
        return {**a.summary(), "health": mon.health_score(a, alerts), "alerts": alerts, "metrics": latest,
                "children": [c.summary() for c in self.inventory.children(aid)],
                "events": self.db.events(limit=30, target=aid),
                "checks": [asdict(c) for c in self.monitor.checks() if c.target == aid]}

    def create_asset(self, ctx: Ctx, data: Mapping[str, Any]) -> dict[str, Any]:
        self._need(ctx, Permission.EDIT_INVENTORY, "asset.create")
        a = self.inventory.create(data, ctx.user)
        self._audit(ctx.user, "asset.create", a.id, "ok", a.name)
        return a.summary()

    def update_asset(self, ctx: Ctx, aid: str, changes: Mapping[str, Any]) -> dict[str, Any]:
        self._need(ctx, Permission.EDIT_INVENTORY, "asset.update")
        a = self.inventory.update(aid, changes, ctx.user)
        self._audit(ctx.user, "asset.update", aid, "ok", ",".join(sorted(changes)))
        return a.summary()

    def delete_asset(self, ctx: Ctx, aid: str, confirm: str = "") -> bool:
        self._need(ctx, Permission.EDIT_INVENTORY, "asset.delete")
        a = self.inventory.get(aid)
        self.guard.authorize(ctx.user, ctx.role, Action("asset.delete", Permission.EDIT_INVENTORY, "change", aid,
                                                        description=f"Remove {a.name} from the inventory"), confirm)
        ok = self.inventory.delete(aid, ctx.user)
        for c in self.monitor.checks():
            if c.target == aid:
                self.monitor.remove_check(c.id)
        self._audit(ctx.user, "asset.delete", aid, "ok", a.name)
        return ok

    def link_assets(self, ctx: Ctx, src: str, dst: str, link_type: str, port: str = "") -> dict[str, Any]:
        self._need(ctx, Permission.EDIT_INVENTORY, "asset.link")
        a = self.inventory.link(src, dst, link_type, port)
        self._audit(ctx.user, "asset.link", src, "ok", f"{link_type} {dst} {port}")
        return a.summary()

    def import_assets_csv(self, ctx: Ctx, text: str) -> dict[str, Any]:
        self._need(ctx, Permission.EDIT_INVENTORY, "asset.import")
        created, problems = self.inventory.import_csv(text, ctx.user)
        self._audit(ctx.user, "asset.import", "", "ok", f"{created} created, {len(problems)} problems")
        return {"created": created, "problems": problems}

    def export_inventory(self, ctx: Ctx, fmt: str = "json") -> str:
        self._need(ctx, Permission.VIEW)
        self._audit(ctx.user, "inventory.export", fmt)
        if fmt == "csv":
            return self.inventory.export_csv()
        return json.dumps({"format": "netcommander-inventory", "version": __version__, "exported": self._clock(),
                           "assets": redact_mapping(self.inventory.export_rows())}, indent=2, default=str)

    # ================================================================ discovery
    def discovery_engine(self) -> DiscoveryEngine:
        d = self.cfg["discovery"]
        if self._discovery_factory:
            return self._discovery_factory(d)
        return DiscoveryEngine(d["ports"], d["timeout"], d["workers"], d["max_hosts"], d["reverse_dns"])

    def run_discovery(self, ctx: Ctx, targets: list[str]) -> dict[str, Any]:
        """Synchronous sweep (use :meth:`start_discovery` from interactive callers)."""
        self._need(ctx, Permission.DISCOVER)
        eng = self.discovery_engine()
        self._audit(ctx.user, "discovery.start", ",".join(targets)[:200])
        self.bus.emit("discovery.started", "discovery", "", f"{ctx.user} started discovery of {', '.join(targets)[:100]}")
        def progress(done: int, total: int) -> None:
            self.bus.emit("discovery.progress", "discovery", "", f"{done}/{total}", severity="debug", done=done, total=total)
        found = eng.scan(targets, progress=progress)
        created = 0
        for h in found:
            _a, new = self.inventory.upsert_observed(h.observation(), source="discovery")
            created += int(new)
        summary: dict[str, Any] = {"scanned": targets, "alive": len(found), "new": created}
        self._audit(ctx.user, "discovery.finish", ",".join(targets)[:200], "ok", json.dumps(summary)[:200])
        self.bus.emit("discovery.finished", "discovery", "", f"discovery found {len(found)} hosts ({created} new)", **summary)
        return summary

    def start_discovery(self, ctx: Ctx, targets: list[str]) -> TaskInfo:
        self._need(ctx, Permission.DISCOVER)
        from .discovery import expand_targets
        expand_targets(targets, self.cfg["discovery"]["max_hosts"])          # validate before queuing
        return self.submit(ctx, "discovery", self.run_discovery, ctx, targets)

    # ================================================================ integrations
    def integrations(self, ctx: Ctx) -> list[dict[str, Any]]:
        self._need(ctx, Permission.VIEW)
        out = []
        for rec in self.db.all(INTEGRATIONS):
            spec = self.registry.get(rec["category"], rec["kind"])
            out.append({**rec, "title": spec.title, "maturity": spec.maturity, "capabilities": sorted(spec.capabilities)})
        return out

    def integration(self, iid: str) -> dict[str, Any]:
        rec = self.db.get(INTEGRATIONS, iid)
        if not rec:
            raise NotFound(f"No integration {iid!r}.")
        return rec

    def add_integration(self, ctx: Ctx, category: str, kind: str, name: str, config: Mapping[str, Any],
                        secrets: Mapping[str, str] | None = None, iid: str = "") -> dict[str, Any]:
        self._need(ctx, Permission.MANAGE_INTEGRATIONS, "integration.add")
        spec = self.registry.get(category, kind)
        if not name.strip():
            raise ValidationError("An integration needs a name.")
        iid = iid or new_id("int")
        cfg = dict(config)
        secret_fields = {f.name for f in spec.fields if f.secret}
        for field_name, value in (secrets or {}).items():
            if field_name not in secret_fields:
                raise ValidationError(f"{field_name} is not a secret field of {spec.title}.")
            if value:
                ref = f"int.{iid}.{field_name}"
                self.secrets.put(ref, value)
                cfg[f"{field_name}_ref"] = ref
        clean = self.registry.validate_config(category, kind, cfg)
        prev = self.db.get(INTEGRATIONS, iid)
        host_asset = prev.get("host_asset") if prev else ""
        rec = {"id": iid, "category": category, "kind": kind, "name": name.strip()[:64], "config": clean,
               "enabled": True, "host_asset": host_asset, "created_by": ctx.user, "last_poll": None,
               "last_error": "", "ok": None}
        self.db.put(INTEGRATIONS, iid, rec)
        with self._adapter_lock:
            self._adapters.pop(iid, None)
        self._audit(ctx.user, "integration.save", iid, "ok", f"{spec.title} {name} insecure_tls="
                    f"{clean.get('verify_tls') is False and not clean.get('pin_sha256')}")
        return rec

    def remove_integration(self, ctx: Ctx, iid: str, confirm: str = "") -> bool:
        self._need(ctx, Permission.MANAGE_INTEGRATIONS, "integration.remove")
        rec = self.integration(iid)
        self.guard.authorize(ctx.user, ctx.role, Action("integration.remove", Permission.MANAGE_INTEGRATIONS, "change", iid,
                                                        description=f"Remove integration {rec['name']}"), confirm)
        for k, v in rec["config"].items():
            if k.endswith("_ref") and str(v).startswith(f"int.{iid}."):
                self.secrets.delete(str(v))
        with self._adapter_lock:
            self._adapters.pop(iid, None)
        self._audit(ctx.user, "integration.remove", iid, "ok", rec["name"])
        return self.db.delete(INTEGRATIONS, iid)

    def adapter(self, iid: str) -> Any:
        with self._adapter_lock:
            if iid in self._adapters:
                return self._adapters[iid]
        rec = self.integration(iid)
        if self._adapter_factory:
            ad = self._adapter_factory(rec)
        else:
            ad = build_adapter(self.registry, rec["category"], rec["kind"], rec["config"], self.secrets.get)
        with self._adapter_lock:
            self._adapters[iid] = ad
        return ad

    @staticmethod
    def _config_ip(rec: dict[str, Any]) -> str:
        """The IP address in an integration's URL/host setting, if it is a literal address."""
        import urllib.parse

        from .models import normalize_ip
        for key in ("url", "host"):
            val = str(rec["config"].get(key, "") or "")
            if not val or val.startswith("unix:"):
                continue
            host = urllib.parse.urlsplit(val).hostname if "://" in val else val
            try:
                return normalize_ip(host or "")
            except ValidationError:
                continue
        return ""

    def _host_asset(self, rec: dict[str, Any], name: str, external: str, obs: dict[str, Any]) -> Asset:
        a, _ = self.inventory.upsert_observed({"name": name, "kind": HOST_KIND[rec["category"]], "integration": rec["id"],
                                               "external_id": external, "source": "integration", **obs},
                                              source="integration")
        return a

    def poll_integration(self, iid: str) -> dict[str, Any]:
        rec = self.integration(iid)
        started = self._clock()
        try:
            ad = self.adapter(iid)
            if rec["category"] == "hypervisor":
                summary = self._poll_hypervisor(rec, ad)
            elif rec["category"] == "docker":
                summary = self._poll_docker(rec, ad)
            elif rec["category"] == "storage":
                summary = self._poll_storage(rec, ad)
            else:
                raise ValidationError(f"Unsupported category {rec['category']}")
            rec.update(last_poll=started, last_error="", ok=True, summary=summary)
        except (IntegrationError, ValidationError, OSError) as exc:
            msg = str(exc)[:500]
            rec.update(last_poll=started, last_error=msg, ok=False)
            self.db.put(INTEGRATIONS, iid, rec)
            if rec.get("host_asset"):
                try:
                    self.inventory.observe(rec["host_asset"], {"status": "offline"})
                    self.monitor.ingest(rec["host_asset"], {"up": 0.0})
                except NotFound:
                    pass
            self.bus.emit("integration.error", "integrations", iid, f"{rec['name']}: {msg}", severity="warning")
            raise
        self.db.put(INTEGRATIONS, iid, rec)
        return summary

    def _poll_hypervisor(self, rec: dict[str, Any], ad: Any) -> dict[str, Any]:
        hosts, vms = ad.hosts(), ad.list_vms()
        host_ids: dict[str, str] = {}
        single_ip = self._config_ip(rec) if len(hosts) == 1 else ""
        for h in hosts:
            alloc = h.allocation(vms)
            a = self._host_asset(rec, h.name, f"host:{h.name}", {
                "ip": single_ip if single_ip and not self._ip_taken(single_ip, rec["id"]) else "",
                "status": h.status, "cpu_cores": h.cpus, "cpu_pct": h.cpu_pct, "mem_total": h.mem_total,
                "mem_used": h.mem_used, "uptime_s": h.uptime_s, "os": h.version or rec["kind"],
                "storage_total": sum(int(s.get("total") or 0) for s in h.storage),
                "storage_used": sum(int(s.get("used") or 0) for s in h.storage),
                "extra": {"platform": rec["kind"], "allocation": alloc, "datastores": h.storage}})
            host_ids[h.name] = a.id
            if not rec.get("host_asset"):
                rec["host_asset"] = a.id
            m = {"up": 1.0 if h.status == "online" else 0.0}
            if h.cpu_pct is not None:
                m["cpu_pct"] = h.cpu_pct
            if h.mem_total:
                m["mem_pct"] = round(100.0 * h.mem_used / h.mem_total, 1)
            total = sum(int(s.get("total") or 0) for s in h.storage)
            if total:
                m["disk_pct"] = round(100.0 * sum(int(s.get("used") or 0) for s in h.storage) / total, 1)
            self.monitor.ingest(a.id, m)
        seen = set()
        for v in vms:
            obs = v.observation(rec["id"], host_ids.get(v.host, rec.get("host_asset", "")))
            a, _ = self.inventory.upsert_observed(obs, source="integration")
            seen.add(v.id)
            if v.status == "running" and not v.template:
                m = {}
                if v.cpu_pct is not None:
                    m["cpu_pct"] = v.cpu_pct
                if v.mem_total:
                    m["mem_pct"] = round(100.0 * v.mem_used / v.mem_total, 1)
                if m:
                    self.monitor.ingest(a.id, m)
        self.inventory.mark_missing(rec["id"], seen | {f"host:{h.name}" for h in hosts})
        return {"hosts": len(hosts), "vms": len(vms), "running": sum(1 for v in vms if v.status == "running")}

    def _poll_docker(self, rec: dict[str, Any], ad: Any) -> dict[str, Any]:
        info = ad.info()
        cs = ad.containers()
        projects = ad.compose_projects(cs)
        host = self._host_asset(rec, info["name"] or rec["name"], "docker-host", {
            "status": "online", "cpu_cores": info.get("cpus", 0), "mem_total": int(info.get("mem_total") or 0),
            "os": info.get("os", ""), "extra": {"docker_version": info.get("version"), "compose_projects": projects,
                                                "images": info.get("images")}})
        rec["host_asset"] = host.id
        seen = {"docker-host"}
        unhealthy = 0
        for c in cs:
            stats = None
            if c["state"] == "running":
                try:
                    stats = ad.stats(c["id"])
                except IntegrationError:
                    stats = None
            a, _ = self.inventory.upsert_observed(container_observation(c, rec["id"], host.id, stats), source="integration")
            seen.add(c["full_id"] or c["id"])
            m: dict[str, float] = {"unhealthy": 1.0 if c["health"] == "unhealthy" else 0.0}
            unhealthy += int(c["health"] == "unhealthy")
            if stats:
                if stats.get("cpu_pct") is not None:
                    m["cpu_pct"] = stats["cpu_pct"]
                if stats.get("mem_pct") is not None:
                    m["mem_pct"] = stats["mem_pct"]
                m["net_rx_bytes"], m["net_tx_bytes"] = float(stats["net_rx"]), float(stats["net_tx"])
            if c["state"] == "running":
                self.monitor.ingest(a.id, m)
        self.monitor.ingest(host.id, {"up": 1.0, "containers_running": float(sum(1 for c in cs if c["state"] == "running")),
                                      "containers_unhealthy": float(unhealthy)})
        self.inventory.mark_missing(rec["id"], seen)
        return {"containers": len(cs), "running": sum(1 for c in cs if c["state"] == "running"), "unhealthy": unhealthy,
                "projects": len(projects)}

    def _poll_storage(self, rec: dict[str, Any], ad: Any) -> dict[str, Any]:
        report = ad.report()
        host_ip = self._config_ip(rec)
        obs = report.observation(rec["id"], "" if self._ip_taken(host_ip, rec["id"]) else host_ip)
        obs["external_id"] = "nas"
        a, _ = self.inventory.upsert_observed(obs, source="integration")
        rec["host_asset"] = a.id
        self.monitor.ingest(a.id, {"up": 1.0, **report.metrics()})
        return {"pools": len(report.pools), "disks": len(report.disks), "shares": len(report.shares), "health": report.health,
                "errors": report.errors[:5]}

    def _ip_taken(self, ip: str, integration: str) -> bool:
        """True if another integration's asset already owns this IP (never merge two integrations' hosts)."""
        if not ip:
            return False
        return any(a.ip == ip and a.integration and a.integration != integration for a in self.inventory.all(False))

    def test_integration(self, ctx: Ctx, iid: str) -> dict[str, Any]:
        self._need(ctx, Permission.DISCOVER)
        res = self.poll_integration(iid)
        self._audit(ctx.user, "integration.test", iid, "ok", json.dumps(res)[:200])
        return res

    # ================================================================ servers (SSH / WinRM collection)
    def _resolve(self, conf: Mapping[str, Any], name: str) -> str:
        ref = conf.get(f"{name}_ref")
        return self.secrets.get(str(ref)) if ref else ""

    def runner_for(self, asset: Asset, kind: str, read_only: bool = True) -> Runner:
        """kind: ssh | powershell. Read-only runners carry the collector allowlist."""
        if self._runner_factory:
            return self._runner_factory(asset, kind, read_only)
        if kind == "ssh":
            conf = asset.management.get("ssh")
            if not conf:
                raise ValidationError(f"{asset.name} has no SSH management settings.")
            return SshRunner(SshTarget(conf.get("host") or asset.ip or asset.hostname, int(conf.get("port", 22)),
                                       conf.get("username", "root"), self._resolve(conf, "password"), conf.get("key_file", "")),
                             servers.LINUX_POLICY if read_only else None)
        if kind == "powershell":
            conf = asset.management.get("winrm")
            if not conf:
                raise ValidationError(f"{asset.name} has no WinRM management settings.")
            return WinRmRunner(WinRmTarget(conf.get("host") or asset.ip or asset.hostname, conf.get("username", ""),
                                           self._resolve(conf, "password"), int(conf.get("port", 5986)),
                                           conf.get("transport", "ntlm"), bool(conf.get("https", True)), conf.get("ca_file", "")),
                               servers.WINDOWS_POLICY if read_only else None)
        raise ValidationError(f"Unknown runner kind {kind!r}.")

    def _automation_runner(self, target: str, kind: str) -> Runner:
        return self.runner_for(self.inventory.get(target), kind, read_only=False)

    def collect_server(self, aid: str) -> dict[str, Any]:
        a = self.inventory.get(aid)
        if "ssh" in a.management:
            runner = self.runner_for(a, "ssh")
            try:
                res = servers.collect_linux(runner)
            finally:
                getattr(runner, "close", lambda: None)()
        elif "winrm" in a.management:
            res = servers.collect_windows(self.runner_for(a, "powershell"))
        else:
            raise ValidationError(f"{a.name} has no SSH or WinRM management settings.")
        obs = dict(res.observation)
        self.inventory.observe(aid, {**obs, "extra": {**obs.get("extra", {}), "details": res.details,
                                                      "collect_errors": res.errors[:10], "collected": self._clock()}})
        self.monitor.ingest(aid, {"up": 1.0 if res.reachable else 0.0, **res.metrics})
        return {"reachable": res.reachable, "errors": res.errors, "metrics": res.metrics}

    def collect_now(self, ctx: Ctx, aid: str) -> TaskInfo:
        self._need(ctx, Permission.DISCOVER)
        self.inventory.get(aid)
        return self.submit(ctx, f"collect {aid}", self.collect_server, aid)

    def server_connectivity(self, ctx: Ctx, aid: str) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        a = self.inventory.get(aid)
        host = a.ip or a.hostname
        if not host:
            raise ValidationError(f"{a.name} has no IP address or host name.")
        return servers.connectivity(netmgmt.valid_target(host), self._probe)

    def server_details(self, ctx: Ctx, aid: str) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        a = self.inventory.get(aid)
        return {"asset": a.summary(), "details": a.extra.get("details", {}), "errors": a.extra.get("collect_errors", []),
                "collected": a.extra.get("collected")}

    # ================================================================ virtualization
    def vm_details(self, ctx: Ctx, iid: str, vm_id: str) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        ad = self.adapter(iid)
        out: dict[str, Any] = {"integration": iid, "vm_id": vm_id}
        for key, fn in (("config", ad.vm_config), ("snapshots", ad.snapshots)):
            try:
                val = fn(vm_id)
                out[key] = redact_mapping(val if isinstance(val, dict) else [asdict(s) for s in val])
            except (IntegrationError, ValidationError, NotImplementedError) as exc:
                out[key + "_error"] = str(exc)
        if hasattr(ad, "disks"):
            try:
                out["disks"] = [asdict(d) for d in ad.disks(vm_id)]
            except (IntegrationError, ValidationError, ValueError) as exc:
                out["disks_error"] = str(exc)
        return out

    def vm_power(self, ctx: Ctx, iid: str, vm_id: str, action: str, confirm: str = "") -> dict[str, Any]:
        rec = self.integration(iid)
        if rec["category"] != "hypervisor":
            raise ValidationError("Not a hypervisor integration.")
        if action not in POWER_RISK:
            raise ValidationError(f"Unknown power action {action!r}.")
        self.guard.authorize(ctx.user, ctx.role, Action(f"vm.{action}", Permission.CONTROL_WORKLOADS, POWER_RISK[action],
                                                        f"{iid}:{vm_id}", description=f"{action.title()} VM {vm_id}"), confirm)
        try:
            res = self.adapter(iid).power(vm_id, action)
        except Exception as exc:
            self._audit(ctx.user, f"vm.{action}", f"{iid}:{vm_id}", "failed", str(exc)[:200])
            raise
        self._audit(ctx.user, f"vm.{action}", f"{iid}:{vm_id}", "ok", str(res)[:200])
        self.bus.emit("vm.power", "virtualization", vm_id, f"{ctx.user}: {action} {vm_id}", user=ctx.user, action=action)
        return {"result": res}

    # ================================================================ containers
    def _docker(self, iid: str) -> Any:
        rec = self.integration(iid)
        if rec["category"] != "docker":
            raise ValidationError("Not a Docker integration.")
        return self.adapter(iid)

    def docker_overview(self, ctx: Ctx, iid: str) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        ad = self._docker(iid)
        cs = ad.containers()
        return {"info": ad.info(), "containers": cs, "projects": ad.compose_projects(cs), "images": ad.images(),
                "networks": ad.networks(), "volumes": ad.volumes()}

    def container_logs(self, ctx: Ctx, iid: str, cid: str, tail: int = 200) -> list[dict[str, str]]:
        self._need(ctx, Permission.RUN_SHOW, "container.logs")          # logs can contain sensitive data
        from .core.sanitize import redact_text
        self._audit(ctx.user, "container.logs", f"{iid}:{cid}")
        return [{**line, "line": redact_text(line["line"])} for line in self._docker(iid).logs(cid, tail)]

    def container_inspect(self, ctx: Ctx, iid: str, cid: str) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        ad = self._docker(iid)
        return {"inspect": redact_mapping(ad.inspect(cid)), "stats": ad.stats(cid)}

    def container_action(self, ctx: Ctx, iid: str, cid: str, action: str, confirm: str = "") -> dict[str, Any]:
        if action not in ACTION_RISK:
            raise ValidationError(f"Unknown container action {action!r}.")
        ad = self._docker(iid)
        self.guard.authorize(ctx.user, ctx.role, Action(f"container.{action}", Permission.CONTROL_WORKLOADS, ACTION_RISK[action],
                                                        f"{iid}:{cid}", description=f"{action.title()} container {cid}"), confirm)
        try:
            res = ad.action(cid, action)
        except Exception as exc:
            self._audit(ctx.user, f"container.{action}", f"{iid}:{cid}", "failed", str(exc)[:200])
            raise
        self._audit(ctx.user, f"container.{action}", f"{iid}:{cid}", "ok", res)
        self.bus.emit("container.action", "containers", cid, f"{ctx.user}: {action} {cid}", user=ctx.user)
        return {"result": res}

    # ================================================================ storage
    def storage_overview(self, ctx: Ctx) -> list[dict[str, Any]]:
        self._need(ctx, Permission.VIEW)
        out = []
        now = self._clock()
        for rec in self.db.all(INTEGRATIONS):
            if rec["category"] != "storage" or not rec.get("host_asset"):
                continue
            try:
                a = self.inventory.get(rec["host_asset"])
            except NotFound:
                continue
            st = a.extra.get("storage") or {}
            pools = []
            for p in st.get("pools", []):
                pts = self.db.series(a.id, f"pool.{p['name']}.used", now - 90 * 86400, now, max_points=2000)
                pools.append({**p, "forecast": forecast(pts, p.get("total") or 0, now)})
            out.append({"integration": rec["id"], "name": rec["name"], "kind": rec["kind"], "asset": a.id, "status": a.status,
                        "health": a.extra.get("storage_health", "unknown"), "system": st.get("system", {}),
                        "pools": pools, "disks": st.get("disks", []), "shares": st.get("shares", []),
                        "errors": st.get("errors", [])})
        return out

    def storage_connectivity(self, ctx: Ctx, aid: str, protocols: list[str]) -> list[dict[str, Any]]:
        self._need(ctx, Permission.DISCOVER)
        a = self.inventory.get(aid)
        host = netmgmt.valid_target(a.ip or a.hostname)
        bad = set(protocols) - {"smb", "nfs", "iscsi"}
        if bad:
            raise ValidationError(f"Unknown protocols: {', '.join(sorted(bad))}")
        return share_checks(host, protocols, self._probe)

    # ================================================================ monitoring
    def monitor_cycle(self) -> dict[str, Any]:
        if self.cfg["monitoring"]["auto_checks"]:
            self.ensure_reachability_checks()
        return {"checks": len(self.monitor.sweep())}

    def ensure_reachability_checks(self) -> int:
        have = {c.target for c in self.monitor.checks() if c.type == "reachability"}
        added = 0
        for a in self.inventory.all():
            if a.id in have or not (a.ip or (a.source == "network" and a.extra.get("mgmt_host"))):
                continue
            if a.kind == "container" or a.status in ("stopped", "paused"):
                continue
            host = a.ip or a.extra.get("mgmt_host", "")
            try:
                self.monitor.add_check({"target": a.id, "type": "reachability", "host": host,
                                        "timeout": self.cfg["monitoring"]["ping_timeout"], "name": "auto"})
                added += 1
            except ValidationError:
                continue
        return added

    def collect_cycle(self) -> dict[str, Any]:
        ok = failed = 0
        for rec in self.db.all(INTEGRATIONS):
            if not rec.get("enabled", True):
                continue
            try:
                self.poll_integration(rec["id"])
                ok += 1
            except Exception as exc:
                failed += 1
                log.info("poll of %s failed: %s", rec["id"], exc)
        for a in self.inventory.all(include_network=False):
            if ("ssh" in a.management or "winrm" in a.management) and a.management.get("collect", True) is not False:
                try:
                    self.collect_server(a.id)
                    ok += 1
                except Exception as exc:
                    failed += 1
                    self.monitor.ingest(a.id, {"up": 0.0})
                    log.info("collection from %s failed: %s", a.name, exc)
        return {"ok": ok, "failed": failed}

    def dashboard(self, ctx: Ctx) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        assets = self.inventory.all()
        alerts = self.monitor.alerts()
        by_kind: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for a in assets:
            by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
            by_status[a.status] = by_status.get(a.status, 0) + 1

        def group(kinds: tuple[str, ...]) -> dict[str, Any]:
            items = [a for a in assets if a.kind in kinds]
            scored = [mon.health_score(a, alerts) for a in items]
            return {"total": len(items), "online": sum(1 for a in items if a.status == "online"),
                    "offline": sum(1 for a in items if a.status == "offline"),
                    "degraded": sum(1 for a in items if a.status == "degraded"),
                    "health": round(sum(scored) / len(scored)) if scored else None}
        nas = [a for a in assets if a.kind in ("nas", "storage")]
        vms = [a for a in assets if a.kind == "vm" and not a.extra.get("template")]
        cts = [a for a in assets if a.kind == "container"]
        top = sorted((a for a in assets if a.cpu_pct is not None and a.status == "online"), key=lambda a: -(a.cpu_pct or 0))[:5]
        backups = self.backups.statuses()
        return {
            "generated": self._clock(), "version": __version__,
            "totals": {"devices": len(assets), "online": by_status.get("online", 0), "offline": by_status.get("offline", 0),
                       "degraded": by_status.get("degraded", 0), "by_kind": by_kind},
            "health": mon.infrastructure_score(assets, alerts),
            "servers": group(("server", "hypervisor", "docker_host", "desktop", "laptop")),
            "network": group(("router", "switch", "firewall", "access_point")),
            "storage_health": group(("nas", "storage")),
            "vms": {"total": len(vms), "running": sum(1 for v in vms if v.status == "online")},
            "containers": {"total": len(cts), "running": sum(1 for c in cts if c.status in ("online", "degraded")),
                           "unhealthy": sum(1 for c in cts if c.status == "degraded")},
            "storage": {"total": sum(a.storage_total for a in nas), "used": sum(a.storage_used for a in nas)},
            "alerts": {"critical": sum(1 for a in alerts if a["severity"] == "critical"),
                       "warning": sum(1 for a in alerts if a["severity"] == "warning"), "items": alerts[:10]},
            "backups": {"ok": sum(1 for b in backups if b["status"]["state"] == "ok"),
                        "problems": sum(1 for b in backups if b["status"]["state"] in ("stale", "failed")),
                        "total": len(backups)},
            "events": self.db.events(limit=15),
            "top_cpu": [{"id": a.id, "name": a.name, "cpu_pct": a.cpu_pct, "kind": a.kind} for a in top],
            "integrations": [{"id": r["id"], "name": r["name"], "kind": r["kind"], "ok": r.get("ok"),
                              "last_poll": r.get("last_poll"), "last_error": r.get("last_error", "")}
                             for r in self.db.all(INTEGRATIONS)],
        }

    def metrics(self, ctx: Ctx, target: str, metric: str, hours: float = 24) -> list[tuple[float, float]]:
        self._need(ctx, Permission.VIEW)
        now = self._clock()
        pts = self.db.series(target, metric, now - hours * 3600, now)
        if metric.endswith("_bytes"):
            return mon.counter_rate(pts)
        return pts

    def acknowledge_alert(self, ctx: Ctx, aid: str) -> dict[str, Any]:
        self._need(ctx, Permission.RUN_SHOW, "alert.ack")
        a = self.monitor.acknowledge(aid, ctx.user)
        self._audit(ctx.user, "alert.ack", aid)
        return a

    def set_rule(self, ctx: Ctx, data: Mapping[str, Any]) -> dict[str, Any]:
        self._need(ctx, Permission.CHANGE_SETTINGS, "monitor.rule")
        r = self.monitor.set_rule(data)
        self._audit(ctx.user, "monitor.rule.save", r.id, "ok", f"{r.metric} w={r.warning} c={r.critical}")
        return asdict(r)

    def add_check(self, ctx: Ctx, data: Mapping[str, Any]) -> dict[str, Any]:
        self._need(ctx, Permission.EDIT_INVENTORY, "monitor.check")
        self.inventory.get(str(data.get("target")))
        c = self.monitor.add_check(data)
        self._audit(ctx.user, "monitor.check.add", c.target, "ok", f"{c.type} {c.host or c.url}:{c.port or ''}")
        return asdict(c)

    def remove_check(self, ctx: Ctx, cid: str) -> bool:
        self._need(ctx, Permission.EDIT_INVENTORY, "monitor.check")
        self._audit(ctx.user, "monitor.check.remove", cid)
        return self.monitor.remove_check(cid)

    def report(self, ctx: Ctx, hours: int = 24) -> dict[str, Any]:
        self._need(ctx, Permission.VIEW)
        assets = self.inventory.all()
        return {"generated": self._clock(), "hours": hours, "rows": mon.utilization_report(self.db, assets, hours, self._clock()),
                "health": mon.infrastructure_score(assets, self.monitor.alerts())}

    # ================================================================ backups
    def backup_cycle(self) -> list[dict[str, Any]]:
        out = []
        now = self._clock()
        for job in self.backups.jobs():
            try:
                good, bad = self._backup_points(job)
                st = bk.evaluate(job, good, now, bad)
            except Exception as exc:
                st = bk.BackupStatus(job.id, "unknown", message=str(exc)[:300])
            self.backups.store_status(st)
            if st.age_hours is not None:
                self.monitor.ingest(f"backup:{job.id}", {"backup_age_hours": st.age_hours,
                                                         "backup_failed": 1.0 if st.state == "failed" else 0.0})
            elif st.state == "failed":
                self.monitor.ingest(f"backup:{job.id}", {"backup_age_hours": 1e6, "backup_failed": 1.0})
            out.append(asdict(st))
        return out

    def _backup_points(self, job: bk.BackupJob) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if job.platform == "proxmox":
            return bk.proxmox_points(self.adapter(job.integration).backup_tasks(), job.match)
        if job.platform == "truenas":
            return bk.truenas_points(self.adapter(job.integration).replication_tasks(), job.match)
        if job.platform == "file":
            if job.runner_asset:
                a = self.inventory.get(job.runner_asset)
                runner = self.runner_for(a, "ssh", read_only=False)
                try:
                    return bk.file_points_remote(runner, job.match), []
                finally:
                    getattr(runner, "close", lambda: None)()
            return bk.file_points_local(job.match, job.checksum), []
        if job.platform == "netcommander":
            from ..network import list_snapshots
            names = [job.match] if job.match else sorted(load_network_devices(self.paths))
            pts = []
            for n in names:
                for snap in list_snapshots(n, self.paths.backups):
                    pts.append({"ts": snap.stat().st_mtime, "size": snap.stat().st_size, "ok": True, "device": n})
            return pts, []
        return self.backups.manual_points(job.id)

    def save_backup_job(self, ctx: Ctx, data: Mapping[str, Any]) -> dict[str, Any]:
        self._need(ctx, Permission.MANAGE_SCHEDULES, "backup.job")
        j = self.backups.save_job(data)
        self._audit(ctx.user, "backup.job.save", j.id, "ok", f"{j.name} {j.platform}")
        return asdict(j)

    def delete_backup_job(self, ctx: Ctx, jid: str) -> bool:
        self._need(ctx, Permission.MANAGE_SCHEDULES, "backup.job")
        self._audit(ctx.user, "backup.job.delete", jid)
        return self.backups.delete_job(jid)

    def record_backup(self, ctx: Ctx, jid: str, ok: bool, size: int | None = None, message: str = "") -> dict[str, Any]:
        self._need(ctx, Permission.BACKUP, "backup.record")
        rec = self.backups.record_manual(jid, ok, size, message)
        self._audit(ctx.user, "backup.record", jid, "ok" if ok else "failed", message[:100])
        return rec

    def runbook(self, ctx: Ctx) -> str:
        self._need(ctx, Permission.VIEW)
        self._audit(ctx.user, "recovery.runbook")
        return bk.recovery_runbook(self.inventory.all(), self.backups.statuses(), ctx.user, self._clock())

    def config_bundle(self, ctx: Ctx) -> dict[str, Any]:
        self._need(ctx, Permission.CHANGE_SETTINGS, "config.export")
        self._audit(ctx.user, "config.export")
        return bk.config_bundle(self.db, self.cfg, __version__)

    # ================================================================ automation (thin RBAC wrappers)
    def run_script(self, ctx: Ctx, script_id: str, targets: list[str], params: Mapping[str, str] | None = None,
                   note: str = "") -> dict[str, Any]:
        run = self.automation.request(ctx.user, ctx.role, script_id, targets, params, note)
        if run["status"] == "approved":
            self.submit(ctx, f"automation {run['id']}", self.automation.execute, ctx.user, ctx.role, run["id"])
        return run

    def approve_run(self, ctx: Ctx, run_id: str, approve: bool, comment: str = "", execute: bool = True) -> dict[str, Any]:
        run = self.automation.decide(ctx.user, ctx.role, run_id, approve, comment, single_admin=self._single_admin())
        if approve and execute:
            self.submit(ctx, f"automation {run_id}", self.automation.execute, ctx.user, ctx.role, run_id)
        return run

    def _single_admin(self) -> bool:
        try:
            from ..security import AuthManager
            users = AuthManager(self.paths.auth).list_users()
            return sum(1 for _u, r in users if r == "admin") <= 1
        except Exception:
            return False

    # ================================================================ security view
    def trust_host(self, ctx: Ctx, host: str, port: int, fingerprint: str, confirm: str = "") -> dict[str, Any]:
        """Add an SSH host key to known_hosts after the user compared the fingerprint (TOFU, explicit)."""
        from ..network import fetch_host_key, trust_host_key
        host = netmgmt.valid_target(host)
        key = fetch_host_key(host, int(port))
        if key["fingerprint"] != fingerprint.strip():
            self._audit(ctx.user, "ssh.trust", f"{host}:{port}", "denied", "fingerprint mismatch")
            raise ValidationError(f"The host now presents {key['fingerprint']}, not the fingerprint you approved.")
        self.guard.authorize(ctx.user, ctx.role, Action("ssh.trust", Permission.CHANGE_SETTINGS, "change", f"{host}:{port}",
                                                        {"fp": fingerprint}, f"Trust SSH key {fingerprint}"), confirm)
        path = trust_host_key(host, int(port), key["type"], key["base64"])
        self._audit(ctx.user, "ssh.trust", f"{host}:{port}", "ok", key["fingerprint"])
        return {"host": host, "port": port, "fingerprint": key["fingerprint"], "known_hosts": str(path)}

    def host_key(self, ctx: Ctx, host: str, port: int = 22) -> dict[str, str]:
        self._need(ctx, Permission.VIEW)
        from ..network import fetch_host_key
        k = fetch_host_key(netmgmt.valid_target(host), int(port))
        return {"type": k["type"], "fingerprint": k["fingerprint"]}

    def audit_entries(self, ctx: Ctx, limit: int = 200) -> dict[str, Any]:
        self._need(ctx, Permission.READ_AUDIT)
        ok, msg = self.audit_log.verify()
        return {"verified": ok, "message": msg, "entries": self.audit_log.entries(limit)[::-1]}

    def set_secret(self, ctx: Ctx, ref: str, value: str) -> dict[str, Any]:
        self._need(ctx, Permission.MANAGE_INTEGRATIONS, "secret.set")
        self.secrets.put(ref, value)
        self._audit(ctx.user, "secret.set", ref)
        return {"ref": ref, "persistent": self.secrets.persistent}

    def can(self, ctx: Ctx, perm: Permission) -> bool:
        return can(ctx.role, perm)
