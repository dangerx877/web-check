"""Unified Monitoring Center.

* **Checks** (run concurrently on the task pool, never on the UI thread):
  ``reachability`` (TCP connect to management ports: latency, jitter, packet loss - no root/ICMP needed),
  ``tcp`` (a specific service port) and ``http`` (status code, optional keyword, latency, TLS
  certificate days-to-expiry). Resource metrics (CPU, memory, disk, throughput, container/VM/NAS health)
  arrive from the collectors and integrations and go through the same threshold engine.
* **Thresholds** - rules with warning/critical levels, direction and a "for N consecutive samples" delay;
  scoped to all assets, a kind, a tag or one asset.
* **Alerts** - one alert per (rule, target) with hysteresis (raise after N breaches, resolve after 2
  good samples), acknowledgement, event timeline entries and notifications.
* **Health scores** per asset and infrastructure-wide; utilisation reports from metric history.
"""
from __future__ import annotations

import logging
import socket
import ssl
import statistics
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any

from .core.db import Database
from .core.errors import NotFound, ValidationError
from .core.events import EventBus
from .core.notify import Notification, Notifier
from .discovery import tcp_probe
from .models import Asset, new_id

log = logging.getLogger(__name__)
CHECKS, RULES, ALERTS = "monitor_checks", "monitor_rules", "alerts"
CHECK_TYPES = ("reachability", "tcp", "http")
DEFAULT_RULES: tuple[dict[str, Any], ...] = (
    {"id": "r-up", "metric": "up", "direction": "below", "warning": None, "critical": 1, "for_count": 2, "name": "Device down"},
    {"id": "r-cpu", "metric": "cpu_pct", "direction": "above", "warning": 85, "critical": 95, "for_count": 3, "name": "High CPU"},
    {"id": "r-mem", "metric": "mem_pct", "direction": "above", "warning": 90, "critical": 97, "for_count": 3, "name": "High memory"},
    {"id": "r-disk", "metric": "disk_pct", "direction": "above", "warning": 85, "critical": 95, "for_count": 1, "name": "Storage filling up"},
    {"id": "r-lat", "metric": "latency_ms", "direction": "above", "warning": 100, "critical": 500, "for_count": 3, "name": "High latency"},
    {"id": "r-loss", "metric": "loss_pct", "direction": "above", "warning": 20, "critical": 60, "for_count": 2, "name": "Packet loss"},
    {"id": "r-temp", "metric": "disk_temp_max", "direction": "above", "warning": 55, "critical": 65, "for_count": 2, "name": "Disk temperature"},
    {"id": "r-svc", "metric": "failed_services", "direction": "above", "warning": 0.5, "critical": None, "for_count": 1, "name": "Failed services"},
    {"id": "r-smart", "metric": "disks_failing", "direction": "above", "warning": None, "critical": 0.5, "for_count": 1, "name": "Disk failing (SMART)"},
    {"id": "r-pool", "metric": "pools_unhealthy", "direction": "above", "warning": None, "critical": 0.5, "for_count": 1, "name": "Storage pool degraded"},
    {"id": "r-health", "metric": "unhealthy", "direction": "above", "warning": 0.5, "critical": None, "for_count": 2, "name": "Container unhealthy"},
    {"id": "r-cert", "metric": "cert_days", "direction": "below", "warning": 21, "critical": 7, "for_count": 1, "name": "TLS certificate expiring"},
    {"id": "r-backup", "metric": "backup_age_hours", "direction": "above", "warning": 26, "critical": 50, "for_count": 1, "name": "Backup overdue"},
)
SEV_RANK = {"ok": 0, "warning": 1, "critical": 2}


# ---------------------------------------------------------------- checks
@dataclass
class Check:
    target: str                          # asset id
    type: str = "reachability"
    host: str = ""
    port: int = 0
    ports: list[int] = field(default_factory=lambda: [22, 443, 80, 445, 3389, 8006])
    url: str = ""
    expect_status: int = 200
    keyword: str = ""
    verify_tls: bool = True
    attempts: int = 3
    timeout: float = 2.0
    enabled: bool = True
    id: str = field(default_factory=lambda: new_id("chk"))
    name: str = ""

    def validate(self) -> Check:
        problems = []
        if self.type not in CHECK_TYPES:
            problems.append(f"type must be one of {', '.join(CHECK_TYPES)}")
        if self.type in ("reachability", "tcp") and not self.host:
            problems.append("host is required")
        if self.type == "tcp" and not 1 <= int(self.port or 0) <= 65535:
            problems.append("port must be 1-65535")
        if self.type == "http":
            u = urllib.parse.urlsplit(self.url)
            if u.scheme not in ("http", "https") or not u.hostname:
                problems.append("url must be http(s)://host/...")
        if not 1 <= int(self.attempts) <= 10:
            problems.append("attempts must be 1-10")
        if not 0.1 <= float(self.timeout) <= 30:
            problems.append("timeout must be 0.1-30 seconds")
        if problems:
            raise ValidationError("Invalid check: " + "; ".join(problems), problems)
        if self.host:
            from .netmgmt import valid_target
            self.host = valid_target(self.host)
        return self


def run_reachability(host: str, ports: list[int], attempts: int, timeout: float,
                     probe: Callable[[str, int, float], str] = tcp_probe) -> dict[str, float]:
    """TCP-connect 'ping': find a port that answers, then measure ``attempts`` round trips."""
    port = None
    for p in ports:
        if probe(host, p, timeout) in ("open", "closed"):
            port = p
            break
    if port is None:
        return {"up": 0.0, "loss_pct": 100.0}
    rtts, lost = [], 0
    for _ in range(attempts):
        t0 = time.perf_counter()
        st = probe(host, port, timeout)
        if st in ("open", "closed"):
            rtts.append((time.perf_counter() - t0) * 1000)
        else:
            lost += 1
    out = {"up": 1.0 if rtts else 0.0, "loss_pct": round(100.0 * lost / attempts, 1)}
    if rtts:
        out["latency_ms"] = round(statistics.mean(rtts), 2)
        out["jitter_ms"] = round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0
    return out


def cert_days_left(host: str, port: int, timeout: float = 5.0, now: float | None = None) -> float | None:
    """Days until the server certificate expires (validated chain; None if TLS fails)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, \
                ctx.wrap_socket(raw, server_hostname=host) as s:
            cert = s.getpeercert()
    except (OSError, ssl.SSLError):
        return None
    exp = ssl.cert_time_to_seconds(str(cert["notAfter"])) if cert and cert.get("notAfter") else None
    return round((exp - (now or time.time())) / 86400, 1) if exp else None


def run_http(check: Check, opener: Callable[..., Any] | None = None) -> dict[str, float]:
    import urllib.error
    import urllib.request
    ctx = ssl.create_default_context() if check.verify_tls else ssl._create_unverified_context()
    req = urllib.request.Request(check.url, headers={"User-Agent": "NetCommander-Monitor"})
    t0 = time.perf_counter()
    status, body = 0, b""
    try:
        resp = (opener or urllib.request.urlopen)(req, timeout=check.timeout, context=ctx)
        with resp:
            status, body = resp.status, resp.read(256 * 1024)
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (OSError, ValueError):
        status = 0
    ms = round((time.perf_counter() - t0) * 1000, 2)
    ok = status == check.expect_status and (not check.keyword or check.keyword.encode() in body)
    out = {"up": 1.0 if ok else 0.0, "http_status": float(status)}
    if status:
        out["latency_ms"] = ms
    u = urllib.parse.urlsplit(check.url)
    if u.scheme == "https" and check.verify_tls and opener is None:
        days = cert_days_left(u.hostname or "", u.port or 443, check.timeout)
        if days is not None:
            out["cert_days"] = days
    return out


# ---------------------------------------------------------------- rules / alerts
@dataclass
class Rule:
    metric: str
    direction: str = "above"
    warning: float | None = None
    critical: float | None = None
    for_count: int = 1
    scope_kind: str = ""
    scope_tag: str = ""
    scope_asset: str = ""
    name: str = ""
    enabled: bool = True
    id: str = field(default_factory=lambda: new_id("r"))

    def validate(self) -> Rule:
        problems = []
        if not self.metric:
            problems.append("metric is required")
        if self.direction not in ("above", "below"):
            problems.append("direction must be above or below")
        if self.warning is None and self.critical is None:
            problems.append("set a warning and/or critical level")
        if self.warning is not None and self.critical is not None:
            if (self.direction == "above" and self.warning > self.critical) or \
                    (self.direction == "below" and self.warning < self.critical):
                problems.append("warning must be less severe than critical")
        if not 1 <= int(self.for_count) <= 100:
            problems.append("for_count must be 1-100")
        if problems:
            raise ValidationError("Invalid rule: " + "; ".join(problems), problems)
        return self

    def applies(self, asset: Asset | None, target: str) -> bool:
        if self.scope_asset and self.scope_asset != target:
            return False
        if asset is None:
            return not (self.scope_kind or self.scope_tag)
        if self.scope_kind and asset.kind != self.scope_kind:
            return False
        return not (self.scope_tag and self.scope_tag not in asset.tags)

    def level(self, value: float) -> str:
        def breach(limit: float | None) -> bool:
            if limit is None:
                return False
            return value >= limit if self.direction == "above" else value < limit
        if breach(self.critical):
            return "critical"
        if breach(self.warning):
            return "warning"
        return "ok"


class MonitoringEngine:
    def __init__(self, db: Database, bus: EventBus, notifier: Notifier, assets: Callable[[str], Asset | None],
                 clock: Callable[[], float] = time.time, workers: int = 16,
                 probe: Callable[[str, int, float], str] = tcp_probe,
                 http: Callable[[Check], dict[str, float]] = run_http) -> None:
        self.db, self.bus, self.notifier, self._asset = db, bus, notifier, assets
        self._clock, self._workers, self._probe, self._http = clock, workers, probe, http
        self._lock = threading.RLock()
        self._streak: dict[tuple[str, str], tuple[str, int]] = {}     # (rule, target) -> (level, count)
        self._ok_streak: dict[tuple[str, str], int] = {}
        if not self.db.ids(RULES):
            self.db.put_many(RULES, ((r["id"], {**asdict(Rule(**{k: v for k, v in r.items()}))}) for r in DEFAULT_RULES))

    # ---- configuration -----------------------------------------------------
    def checks(self) -> list[Check]:
        return [Check(**c) for c in self.db.all(CHECKS)]

    def add_check(self, data: Mapping[str, Any]) -> Check:
        c = Check(**{k: v for k, v in data.items() if k in Check.__dataclass_fields__}).validate()
        self.db.put(CHECKS, c.id, asdict(c))
        return c

    def remove_check(self, cid: str) -> bool:
        return self.db.delete(CHECKS, cid)

    def rules(self) -> list[Rule]:
        return [Rule(**r) for r in self.db.all(RULES)]

    def set_rule(self, data: Mapping[str, Any]) -> Rule:
        r = Rule(**{k: v for k, v in data.items() if k in Rule.__dataclass_fields__}).validate()
        self.db.put(RULES, r.id, asdict(r))
        return r

    def remove_rule(self, rid: str) -> bool:
        return self.db.delete(RULES, rid)

    # ---- running checks ------------------------------------------------------
    def run_check(self, c: Check) -> dict[str, float]:
        if c.type == "reachability":
            return run_reachability(c.host, c.ports, c.attempts, c.timeout, self._probe)
        if c.type == "tcp":
            t0 = time.perf_counter()
            st = self._probe(c.host, c.port, c.timeout)
            out = {"up": 1.0 if st == "open" else 0.0}
            if st == "open":
                out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            return out
        return self._http(c)

    def sweep(self) -> dict[str, dict[str, float]]:
        """Run every enabled check concurrently; record metrics and evaluate rules. Returns per-check results."""
        checks = [c for c in self.checks() if c.enabled]
        results: dict[str, dict[str, float]] = {}
        if not checks:
            return results
        with ThreadPoolExecutor(max_workers=min(self._workers, len(checks)), thread_name_prefix="nc-mon") as pool:
            futures = {pool.submit(self.run_check, c): c for c in checks}
            for fut, c in futures.items():
                try:
                    res = fut.result()
                except Exception as exc:                  # a broken check is a failed check, not a crash
                    log.warning("check %s failed: %s", c.id, exc)
                    res = {"up": 0.0}
                results[c.id] = res
        merged: dict[str, dict[str, float]] = {}
        for c in checks:
            res = results[c.id]
            bucket = merged.setdefault(c.target, {})
            if c.type == "reachability":
                bucket.update(res)
            else:
                prefix = f"{c.type}.{c.port or c.name or c.id}."
                bucket.update({prefix + k: v for k, v in res.items()})
                if res.get("up", 1.0) < 1:
                    bucket["services_down"] = bucket.get("services_down", 0) + 1
                if "cert_days" in res:
                    bucket["cert_days"] = min(res["cert_days"], bucket.get("cert_days", 1e9))
        for target, metrics in merged.items():
            metrics.setdefault("services_down", 0.0)
            self.ingest(target, metrics)
        return results

    # ---- metric ingestion + alerting --------------------------------------------
    def ingest(self, target: str, metrics: Mapping[str, float], ts: float | None = None) -> list[dict[str, Any]]:
        """Store metrics and evaluate every applicable rule. Returns alerts whose state changed."""
        ts = self._clock() if ts is None else ts
        self.db.add_metrics(target, dict(metrics), ts)
        asset = self._asset(target)
        changed = []
        for rule in self.rules():
            if not rule.enabled or rule.metric not in metrics or not rule.applies(asset, target):
                continue
            try:
                value = float(metrics[rule.metric])
            except (TypeError, ValueError):
                continue
            ch = self._evaluate(rule, target, asset, value, ts)
            if ch:
                changed.append(ch)
        return changed

    def _evaluate(self, rule: Rule, target: str, asset: Asset | None, value: float, ts: float) -> dict[str, Any] | None:
        key = (rule.id, target)
        level = rule.level(value)
        aid = f"{rule.id}:{target}"
        with self._lock:
            current = self.db.get(ALERTS, aid)
            active = current if current and current.get("state") != "resolved" else None
            if level == "ok":
                self._streak.pop(key, None)
                if not active:
                    return None
                n = self._ok_streak.get(key, 0) + 1
                self._ok_streak[key] = n
                if n < 2:
                    return None
                self._ok_streak.pop(key, None)
                active.update(state="resolved", resolved=ts, value=value)
                self.db.put(ALERTS, aid, active)
                self._announce(active, asset, resolved=True)
                return active
            self._ok_streak.pop(key, None)
            prev_level, count = self._streak.get(key, ("ok", 0))
            count = count + 1 if SEV_RANK[level] >= SEV_RANK[prev_level] and prev_level != "ok" else 1
            self._streak[key] = (level, count)
            if count < rule.for_count:
                return None
            if active and active["severity"] == level:
                active.update(value=value, last=ts)
                self.db.put(ALERTS, aid, active)
                return None
            name = asset.name if asset else target
            limit = rule.critical if level == "critical" else rule.warning
            alert = {"id": aid, "rule": rule.id, "rule_name": rule.name or rule.metric, "metric": rule.metric,
                     "target": target, "target_name": name, "severity": level, "state": "active", "value": value,
                     "threshold": limit, "since": (active or {}).get("since", ts), "last": ts, "acked_by": "",
                     "message": f"{rule.name or rule.metric} on {name}: {value:g} "
                                f"({'≥' if rule.direction == 'above' else '<'} {limit:g})"}
            self.db.put(ALERTS, aid, alert)
            self._announce(alert, asset)
            return alert

    def _announce(self, alert: dict[str, Any], asset: Asset | None, resolved: bool = False) -> None:
        sev = "info" if resolved else alert["severity"]
        msg = f"RESOLVED: {alert['message']}" if resolved else alert["message"]
        self.bus.emit("alert.resolved" if resolved else "alert.raised", "monitoring", alert["target"], msg, severity=sev,
                      alert_id=alert["id"], metric=alert["metric"])
        self.notifier.notify(Notification(title=alert["rule_name"], message=msg, severity=sev, target=alert["target_name"],
                                          dedup_key=f"{alert['id']}:{'r' if resolved else alert['severity']}"))

    # ---- alert queries ---------------------------------------------------------------
    def alerts(self, include_resolved: bool = False) -> list[dict[str, Any]]:
        items = [a for a in self.db.all(ALERTS) if include_resolved or a.get("state") != "resolved"]
        return sorted(items, key=lambda a: (-SEV_RANK.get(a["severity"], 0), -a.get("last", 0)))

    def acknowledge(self, aid: str, user: str) -> dict[str, Any]:
        a = self.db.get(ALERTS, aid)
        if not a:
            raise NotFound(f"No alert {aid!r}.")
        a.update(acked_by=user, acked_at=self._clock())
        self.db.put(ALERTS, aid, a)
        self.bus.emit("alert.acked", "monitoring", a["target"], f"{user} acknowledged {a['rule_name']}", user=user)
        return a

    def prune(self, retention_days: int, event_days: int) -> tuple[int, int]:
        now = self._clock()
        resolved_cut = now - event_days * 86400
        for a in self.db.all(ALERTS):
            if a.get("state") == "resolved" and a.get("resolved", now) < resolved_cut:
                self.db.delete(ALERTS, a["id"])
        return self.db.prune_metrics(now - retention_days * 86400), self.db.prune_events(resolved_cut)


# ---------------------------------------------------------------- scores and reports
def health_score(asset: Asset, alerts: Iterable[Mapping[str, Any]]) -> int:
    if asset.status == "offline":
        return 0
    score = 100
    if asset.status in ("degraded",):
        score -= 25
    for a in alerts:
        if a.get("target") == asset.id and a.get("state") != "resolved":
            score -= 40 if a.get("severity") == "critical" else 15
    return max(0, min(100, score))


IMPORTANT = {"router": 3, "firewall": 3, "switch": 3, "hypervisor": 3, "nas": 3, "storage": 3, "docker_host": 2,
             "server": 2, "vm": 1, "container": 1}


def infrastructure_score(assets: Iterable[Asset], alerts: Sequence[Mapping[str, Any]]) -> int | None:
    total = weight = 0
    for a in assets:
        # stopped/paused workloads are intentional; never-checked assets say nothing about health
        if a.status in ("stopped", "paused", "unknown") or (a.source == "discovery" and a.kind == "unknown"):
            continue
        w = IMPORTANT.get(a.kind, 1)
        total += health_score(a, alerts) * w
        weight += w
    return round(total / weight) if weight else None


def utilization_report(db: Database, assets: Iterable[Asset], hours: int = 24, now: float | None = None) -> list[dict[str, Any]]:
    now = time.time() if now is None else now
    since = now - hours * 3600
    rows = []
    for a in assets:
        row: dict[str, Any] = {"id": a.id, "name": a.name, "kind": a.kind, "status": a.status}
        any_data = False
        for metric in ("cpu_pct", "mem_pct", "disk_pct", "latency_ms", "loss_pct"):
            pts = db.series(a.id, metric, since, now, max_points=10_000)
            if pts:
                vals = [p[1] for p in pts]
                row[metric] = {"last": vals[-1], "avg": round(sum(vals) / len(vals), 1), "max": max(vals)}
                any_data = True
        if any_data:
            rows.append(row)
    return rows


def counter_rate(points: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Per-second rates from a monotonically increasing counter series (resets are skipped)."""
    out = []
    for (t0, v0), (t1, v1) in zip(points, points[1:]):
        if t1 > t0 and v1 >= v0:
            out.append((t1, (v1 - v0) / (t1 - t0)))
    return out
