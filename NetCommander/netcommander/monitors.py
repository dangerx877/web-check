"""Out-of-band monitoring: SNMPv3 and REST API pollers, rolling history and alerts.

* SNMPv3 only (authPriv/authNoPriv). v1/v2c community strings are deliberately unsupported:
  they are cleartext shared secrets. The wire work is delegated to ``pysnmp`` (optional extra,
  imported lazily) through one small seam - ``SnmpGet`` - so everything else is testable offline.
* REST pollers GET a JSON endpoint and pull numbers out by dotted path (``data.cpu.0.usage``).
  TLS verification is ON unless explicitly disabled per monitor.
* Secrets (SNMP keys, API tokens) are encrypted with the vault when persisted; a guest session
  (ephemeral vault) refuses to persist them.

Wire-level behaviour (pysnmp calls, real HTTP) has been verified only against fakes here;
see docs/MONITORING.md for the lab-test checklist.
"""
from __future__ import annotations

import base64
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .security import CredentialVault, _write_private

log = logging.getLogger(__name__)

AUTH_PROTOCOLS = ("SHA", "SHA224", "SHA256", "SHA384", "SHA512", "MD5")
PRIV_PROTOCOLS = ("AES", "AES192", "AES256", "DES")
MIN_KEY_LEN = 8                                        # RFC 3414 minimum for USM passphrases
STD_OIDS = {"uptime": "1.3.6.1.2.1.1.3.0", "sysname": "1.3.6.1.2.1.1.5.0"}


class MonitorError(ValueError):
    pass


# ---------------------------------------------------------------- history
@dataclass
class Sample:
    ts: float
    ok: bool
    metrics: dict[str, float] = field(default_factory=dict)
    error: str = ""


class History:
    """Thread-safe bounded per-target sample history."""

    def __init__(self, maxlen: int = 240) -> None:
        self._maxlen = maxlen
        self._data: dict[str, deque[Sample]] = {}
        self._lock = threading.RLock()

    def add(self, target: str, sample: Sample) -> None:
        with self._lock:
            self._data.setdefault(target, deque(maxlen=self._maxlen)).append(sample)

    def last(self, target: str) -> Sample | None:
        with self._lock:
            d = self._data.get(target)
            return d[-1] if d else None

    def series(self, target: str, metric: str) -> list[tuple[float, float]]:
        with self._lock:
            return [(s.ts, s.metrics[metric]) for s in self._data.get(target, ()) if s.ok and metric in s.metrics]

    def targets(self) -> list[str]:
        with self._lock:
            return sorted(self._data)

    def availability(self, target: str) -> float | None:
        with self._lock:
            d = self._data.get(target)
            return None if not d else 100.0 * sum(s.ok for s in d) / len(d)


def counter_rate(prev: tuple[float, float] | None, cur: tuple[float, float], bits: int = 64) -> float | None:
    """Per-second rate of a monotonic counter, wrap-aware. ``None`` when it cannot be computed."""
    if prev is None:
        return None
    dt = cur[0] - prev[0]
    if dt <= 0:
        return None
    delta = cur[1] - prev[1]
    if delta < 0:
        delta += 2 ** bits
        if delta > 2 ** bits * 0.9:               # looks like a counter reset, not a wrap
            return None
    return delta / dt


# ---------------------------------------------------------------- REST
def dig(data: Any, path: str) -> float:
    """``a.b.0.c`` → number. Raises MonitorError with the failing segment."""
    cur = data
    for part in path.split("."):
        try:
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        except (KeyError, IndexError, ValueError, TypeError):
            raise MonitorError(f"path '{path}' not found at '{part}'") from None
    if isinstance(cur, bool):
        return float(cur)
    try:
        return float(cur)
    except (TypeError, ValueError):
        raise MonitorError(f"path '{path}' is not numeric ({cur!r})") from None


@dataclass
class RestMonitor:
    name: str
    url: str
    metrics: dict[str, str]                               # metric name -> dotted path
    auth: str = "none"                                    # none | basic | bearer
    user: str = ""
    secret: str = ""                                      # password or token
    verify_tls: bool = True
    timeout: float = 8.0
    kind: str = "rest"

    def validate(self) -> None:
        if not self.url.lower().startswith(("http://", "https://")):
            raise MonitorError("URL must start with http:// or https://")
        if self.auth not in ("none", "basic", "bearer"):
            raise MonitorError("auth must be none, basic or bearer")
        if not self.metrics:
            raise MonitorError("Define at least one metric (name → JSON path).")
        if self.auth != "none" and not self.secret:
            raise MonitorError("A secret/token is required for this auth type.")

    def poll(self, opener: Callable[..., Any] = urllib.request.urlopen, clock: Callable[[], float] = time.time) -> Sample:
        self.validate()
        req = urllib.request.Request(self.url, headers={"Accept": "application/json", "User-Agent": "NetCommander"})
        if self.auth == "basic":
            tok = base64.b64encode(f"{self.user}:{self.secret}".encode()).decode("ascii")
            req.add_header("Authorization", f"Basic {tok}")
        elif self.auth == "bearer":
            req.add_header("Authorization", f"Bearer {self.secret}")
        ctx = None
        if self.url.lower().startswith("https://") and not self.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with opener(req, timeout=self.timeout, context=ctx) if ctx else opener(req, timeout=self.timeout) as resp:
                body = resp.read(2_000_000)
            data = json.loads(body.decode("utf-8"))
            vals = {m: dig(data, p) for m, p in self.metrics.items()}
        except MonitorError as exc:
            return Sample(clock(), False, error=str(exc))
        except urllib.error.HTTPError as exc:
            return Sample(clock(), False, error=f"HTTP {exc.code}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return Sample(clock(), False, error=f"{type(exc).__name__}: {exc}"[:200])
        return Sample(clock(), True, vals)


# ---------------------------------------------------------------- SNMPv3
SnmpGet = Callable[["SnmpV3Monitor", list[str]], "dict[str, Any]"]


@dataclass
class SnmpV3Monitor:
    name: str
    host: str
    user: str
    auth_proto: str = "SHA"
    auth_key: str = ""
    priv_proto: str = ""                                  # "" = authNoPriv
    priv_key: str = ""
    oids: dict[str, str] = field(default_factory=lambda: {"uptime": STD_OIDS["uptime"]})
    counters: tuple[str, ...] = ()                        # metrics that are counters → also exposed as "<m>_rate"
    port: int = 161
    timeout: float = 4.0
    retries: int = 1
    kind: str = "snmpv3"

    @property
    def level(self) -> str:
        return "authPriv" if self.priv_proto else "authNoPriv"

    def validate(self) -> None:
        if not self.user:
            raise MonitorError("SNMPv3 needs a security user name.")
        if self.auth_proto not in AUTH_PROTOCOLS:
            raise MonitorError(f"auth protocol must be one of {AUTH_PROTOCOLS}")
        if len(self.auth_key) < MIN_KEY_LEN:
            raise MonitorError(f"Authentication passphrase must be at least {MIN_KEY_LEN} characters.")
        if self.priv_proto:
            if self.priv_proto not in PRIV_PROTOCOLS:
                raise MonitorError(f"privacy protocol must be one of {PRIV_PROTOCOLS}")
            if len(self.priv_key) < MIN_KEY_LEN:
                raise MonitorError(f"Privacy passphrase must be at least {MIN_KEY_LEN} characters.")
        if self.auth_proto == "MD5" or self.priv_proto == "DES":
            log.warning("SNMPv3 monitor %s uses a weak protocol (MD5/DES); prefer SHA + AES", self.name)
        if not self.oids:
            raise MonitorError("Define at least one OID.")
        for m, oid in self.oids.items():
            if not all(p.isdigit() for p in oid.strip(".").split(".")):
                raise MonitorError(f"'{oid}' is not a numeric OID (metric {m})")


def pysnmp_get(mon: SnmpV3Monitor, oids: list[str]) -> dict[str, Any]:
    """Real SNMPv3 GET via pysnmp's synchronous high-level API. Returns ``{oid: value}``."""
    try:
        from pysnmp.hlapi import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            getCmd,
            usmAesCfb128Protocol,
            usmAesCfb192Protocol,
            usmAesCfb256Protocol,
            usmDESPrivProtocol,
            usmHMAC128SHA224AuthProtocol,
            usmHMAC192SHA256AuthProtocol,
            usmHMAC256SHA384AuthProtocol,
            usmHMAC384SHA512AuthProtocol,
            usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
        )
    except ImportError as exc:
        raise MonitorError("SNMP support needs the 'pysnmp' package (pip install 'netcommander[snmp]').") from exc
    auth = {"MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol, "SHA224": usmHMAC128SHA224AuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol, "SHA384": usmHMAC256SHA384AuthProtocol,
            "SHA512": usmHMAC384SHA512AuthProtocol}[mon.auth_proto]
    kwargs: dict[str, Any] = {"authKey": mon.auth_key, "authProtocol": auth}
    if mon.priv_proto:
        kwargs.update(privKey=mon.priv_key, privProtocol={
            "DES": usmDESPrivProtocol, "AES": usmAesCfb128Protocol,
            "AES192": usmAesCfb192Protocol, "AES256": usmAesCfb256Protocol}[mon.priv_proto])
    err_ind, err_stat, _, binds = next(getCmd(
        SnmpEngine(), UsmUserData(mon.user, **kwargs),
        UdpTransportTarget((mon.host, mon.port), timeout=mon.timeout, retries=mon.retries), ContextData(),
        *[ObjectType(ObjectIdentity(o)) for o in oids]))
    if err_ind:
        raise MonitorError(str(err_ind))
    if err_stat:
        raise MonitorError(err_stat.prettyPrint())
    return {str(name): value for name, value in binds}


class SnmpPoller:
    def __init__(self, get: SnmpGet = pysnmp_get, clock: Callable[[], float] = time.time) -> None:
        self._get, self._clock = get, clock
        self._prev: dict[tuple[str, str], tuple[float, float]] = {}
        self._lock = threading.Lock()

    def poll(self, mon: SnmpV3Monitor) -> Sample:
        now = self._clock()
        try:
            mon.validate()
            raw = self._get(mon, list(mon.oids.values()))
        except Exception as exc:
            return Sample(now, False, error=f"{type(exc).__name__}: {exc}"[:200])
        metrics: dict[str, float] = {}
        for metric, oid in mon.oids.items():
            val = raw.get(oid, raw.get("." + oid))
            if val is None:
                continue
            try:
                num = float(int(val)) if not isinstance(val, float) else val
            except (TypeError, ValueError):
                continue                                  # non-numeric (e.g. sysName) is skipped, not an error
            metrics[metric] = num
            if metric in mon.counters:
                key = (mon.name, metric)
                with self._lock:
                    rate = counter_rate(self._prev.get(key), (now, num))
                    self._prev[key] = (now, num)
                if rate is not None:
                    metrics[f"{metric}_rate"] = rate
        if not metrics:
            return Sample(now, False, error="no numeric values returned")
        return Sample(now, True, metrics)


# ---------------------------------------------------------------- alerts
def check_thresholds(metrics: Mapping[str, float], limits: Mapping[str, tuple[float | None, float | None]]) -> list[str]:
    """``limits[m] = (min, max)``; returns human-readable breaches."""
    out = []
    for m, (lo, hi) in limits.items():
        if m not in metrics:
            continue
        v = metrics[m]
        if hi is not None and v > hi:
            out.append(f"{m}={v:g} above {hi:g}")
        if lo is not None and v < lo:
            out.append(f"{m}={v:g} below {lo:g}")
    return out


# ---------------------------------------------------------------- persistence
class MonitorStore:
    """Monitor definitions on disk; secrets encrypted with the vault."""

    SECRET_FIELDS = {"rest": ("secret",), "snmpv3": ("auth_key", "priv_key")}

    def __init__(self, path: Path, vault: CredentialVault) -> None:
        self.path, self.vault = Path(path), vault
        self._lock = threading.RLock()

    def save(self, monitors: list[RestMonitor | SnmpV3Monitor]) -> None:
        if self.vault.ephemeral and any(self._secrets(m) for m in monitors):
            raise MonitorError("Guest mode does not persist monitoring secrets. Sign in to save monitors.")
        rows = []
        for m in monitors:
            d = asdict(m)
            for f in self.SECRET_FIELDS[m.kind]:
                d[f] = self.vault.encrypt_text(d[f]) if d.get(f) else ""
            rows.append(d)
        with self._lock:
            _write_private(self.path, json.dumps({"monitors": rows}, indent=2))

    @staticmethod
    def _secrets(m: RestMonitor | SnmpV3Monitor) -> bool:
        return bool(getattr(m, "secret", "") or getattr(m, "auth_key", "") or getattr(m, "priv_key", ""))

    def load(self) -> list[RestMonitor | SnmpV3Monitor]:
        with self._lock:
            try:
                rows = json.loads(self.path.read_text(encoding="utf-8")).get("monitors", [])
            except (OSError, ValueError):
                return []
        out: list[RestMonitor | SnmpV3Monitor] = []
        for d in rows:
            try:
                kind = d.pop("kind", "rest")
                for f in self.SECRET_FIELDS[kind]:
                    d[f] = self.vault.decrypt_text(d[f]) if d.get(f) else ""
                if kind == "snmpv3":
                    d["counters"] = tuple(d.get("counters", ()))
                    out.append(SnmpV3Monitor(**d))
                else:
                    out.append(RestMonitor(**d))
            except Exception as exc:
                log.warning("skipping unreadable monitor definition: %s", type(exc).__name__)
        return out


# ---------------------------------------------------------------- runner
class MonitorRunner:
    def __init__(
        self, monitors: list[RestMonitor | SnmpV3Monitor], history: History | None = None,
        limits: Mapping[str, tuple[float | None, float | None]] | None = None,
        on_alert: Callable[[str, list[str]], None] | None = None, snmp: SnmpPoller | None = None,
        rest_opener: Callable[..., Any] = urllib.request.urlopen, interval: float = 30.0, workers: int = 8,
        on_sweep: Callable[[], None] | None = None,
    ) -> None:
        self.on_sweep = on_sweep
        self.monitors, self.history = list(monitors), history or History()
        self.limits, self.on_alert = dict(limits or {}), on_alert
        self.snmp = snmp or SnmpPoller()
        self._opener, self.interval, self.workers = rest_opener, interval, workers
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def poll_one(self, m: RestMonitor | SnmpV3Monitor) -> Sample:
        s = self.snmp.poll(m) if isinstance(m, SnmpV3Monitor) else m.poll(opener=self._opener)
        self.history.add(m.name, s)
        if s.ok and self.on_alert:
            breaches = check_thresholds(s.metrics, self.limits)
            if breaches:
                self.on_alert(m.name, breaches)
        return s

    def set_monitors(self, monitors: list[RestMonitor | SnmpV3Monitor]) -> None:
        """Replace the monitored set (atomic list swap; a sweep in progress finishes on the old list)."""
        self.monitors = list(monitors)

    def poll_all(self) -> dict[str, Sample]:
        mons = list(self.monitors)
        if not mons:
            return {}
        with ThreadPoolExecutor(max_workers=max(1, min(self.workers, len(mons)))) as pool:
            out = {m.name: s for m, s in zip(mons, pool.map(self.poll_one, mons))}
        if self.on_sweep:
            try:
                self.on_sweep()
            except Exception:                              # pragma: no cover - UI callback must not kill polling
                log.exception("on_sweep callback failed")
        return out

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.poll_all()
                except Exception:                         # pragma: no cover - defensive
                    log.exception("monitor sweep failed")
                self._stop.wait(self.interval)
        self._thread = threading.Thread(target=loop, name="monitors", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(5)
