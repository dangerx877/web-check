"""Common storage model, connectivity checks and capacity forecasting."""
from __future__ import annotations

import os
import socket
import struct
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol


@dataclass
class Disk:
    name: str
    model: str = ""
    serial: str = ""
    size: int = 0
    type: str = ""                   # HDD | SSD | NVMe
    pool: str = ""
    temperature_c: float | None = None
    smart_ok: bool | None = None     # None = unknown / not supported
    power_on_hours: int | None = None
    reallocated: int | None = None
    pending: int | None = None
    status: str = ""

    @property
    def health(self) -> str:
        if self.smart_ok is False or (self.pending or 0) > 0 or (self.reallocated or 0) > 50:
            return "failing"
        if (self.reallocated or 0) > 0 or (self.temperature_c or 0) >= 60:
            return "warning"
        return "ok" if self.smart_ok else "unknown"


@dataclass
class Pool:
    name: str
    status: str = "unknown"          # ONLINE | DEGRADED | FAULTED | normal | ...
    healthy: bool | None = None
    layout: str = ""                 # RAIDZ2 | mirror | RAID5 | SHR ...
    total: int = 0
    used: int = 0
    disks: list[str] = field(default_factory=list)

    @property
    def pct(self) -> float | None:
        return round(100.0 * self.used / self.total, 1) if self.total else None


@dataclass
class Share:
    name: str
    protocol: str                    # smb | nfs | iscsi
    path: str = ""
    enabled: bool = True
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class StorageReport:
    system: dict[str, Any]
    pools: list[Pool] = field(default_factory=list)
    disks: list[Disk] = field(default_factory=list)
    shares: list[Share] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"system": self.system, "errors": self.errors,
                "pools": [{**asdict(p), "pct": p.pct} for p in self.pools],
                "disks": [{**asdict(d), "health": d.health} for d in self.disks],
                "shares": [asdict(s) for s in self.shares]}

    @property
    def health(self) -> str:
        if any(p.healthy is False for p in self.pools) or any(d.health == "failing" for d in self.disks):
            return "critical"
        if any(d.health == "warning" for d in self.disks) or any((p.pct or 0) >= 85 for p in self.pools):
            return "warning"
        return "ok"

    def metrics(self) -> dict[str, float]:
        m: dict[str, float] = {}
        for p in self.pools:
            m[f"pool.{p.name}.used"] = float(p.used)
            m[f"pool.{p.name}.total"] = float(p.total)
            if p.pct is not None:
                m[f"pool.{p.name}.pct"] = p.pct
        total, used = sum(p.total for p in self.pools), sum(p.used for p in self.pools)
        if total:
            m["disk_pct"] = round(100.0 * used / total, 1)
        temps = [d.temperature_c for d in self.disks if d.temperature_c is not None]
        if temps:
            m["disk_temp_max"] = float(max(temps))
        m["disks_failing"] = float(sum(1 for d in self.disks if d.health == "failing"))
        m["pools_unhealthy"] = float(sum(1 for p in self.pools if p.healthy is False))
        return m

    def observation(self, integration: str, ip: str = "") -> dict[str, Any]:
        s = self.system
        return {"name": s.get("hostname") or integration, "hostname": s.get("hostname", ""), "kind": "nas",
                "status": {"ok": "online", "warning": "degraded", "critical": "degraded"}[self.health],
                "integration": integration, "external_id": f"nas:{s.get('hostname') or integration}", "ip": ip,
                "os": s.get("version", ""), "manufacturer": s.get("vendor", ""), "model": s.get("model", ""),
                "mem_total": int(s.get("mem_total") or 0), "uptime_s": s.get("uptime_s"),
                "storage_total": sum(p.total for p in self.pools), "storage_used": sum(p.used for p in self.pools),
                "source": "integration", "extra": {"storage": self.to_dict(), "storage_health": self.health}}


class StorageAdapter(Protocol):
    platform: str

    def report(self) -> StorageReport: ...


# ---------------------------------------------------------------- connectivity checks
Probe = Callable[[str, int, float], str]


def smb2_negotiate_packet() -> bytes:
    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    header = (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"\x00" * 16)
    body = struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0) + os.urandom(16) + struct.pack("<Q", 0) + \
        b"".join(struct.pack("<H", d) for d in dialects)
    msg = header + body
    return b"\x00" + len(msg).to_bytes(3, "big") + msg


def parse_smb2_negotiate_response(data: bytes) -> str | None:
    """Return the negotiated dialect (``"3.0.2"``) or None when the reply is not SMB2."""
    if len(data) < 4 + 64 + 6 or data[4:8] != b"\xfeSMB":
        return None
    dialect = struct.unpack("<H", data[4 + 64 + 4:4 + 64 + 6])[0]
    return {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}.get(dialect, hex(dialect))


def smb_check(host: str, port: int = 445, timeout: float = 3.0) -> dict[str, Any]:
    """Unauthenticated SMB2 NEGOTIATE: proves an SMB server answers (no login, nothing written)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(smb2_negotiate_packet())
            data = s.recv(512)
    except OSError as exc:
        return {"protocol": "smb", "host": host, "port": port, "ok": False, "detail": str(exc) or type(exc).__name__}
    dialect = parse_smb2_negotiate_response(data)
    return {"protocol": "smb", "host": host, "port": port, "ok": dialect is not None,
            "detail": f"SMB {dialect}" if dialect else "port open but no SMB2 reply (SMB1-only or not SMB)"}


def tcp_service_check(protocol: str, host: str, port: int, probe: Probe, timeout: float = 3.0) -> dict[str, Any]:
    state = probe(host, port, timeout)
    return {"protocol": protocol, "host": host, "port": port, "ok": state == "open", "detail": f"tcp/{port} {state}"}


def share_checks(host: str, protocols: Sequence[str], probe: Probe,
                 smb: Callable[[str], dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    out = []
    for proto in protocols:
        if proto == "smb":
            out.append((smb or smb_check)(host))
        elif proto == "nfs":
            out.append(tcp_service_check("nfs", host, 2049, probe))
        elif proto == "iscsi":
            out.append(tcp_service_check("iscsi", host, 3260, probe))
    return out


# ---------------------------------------------------------------- forecasting
def linear_fit(points: Sequence[tuple[float, float]]) -> tuple[float, float] | None:
    """Least-squares ``value = a + b*t``; returns (a, b) or None with fewer than 2 distinct times."""
    n = len(points)
    if n < 2:
        return None
    mt = sum(p[0] for p in points) / n
    mv = sum(p[1] for p in points) / n
    var = sum((p[0] - mt) ** 2 for p in points)
    if var == 0:
        return None
    b = sum((p[0] - mt) * (p[1] - mv) for p in points) / var
    return mv - b * mt, b


def forecast(points: Sequence[tuple[float, float]], total: float, now: float,
             thresholds: Sequence[float] = (0.8, 0.9, 1.0)) -> dict[str, Any]:
    """Growth rate (bytes/day) and days until each fill threshold, from (timestamp, used_bytes) history."""
    fit = linear_fit(points)
    if fit is None or total <= 0:
        return {"growth_per_day": None, "days_until": {}, "samples": len(points)}
    a, b = fit
    per_day = b * 86400
    current = a + b * now
    days: dict[str, float | None] = {}
    for t in thresholds:
        target = total * t
        if current >= target:
            days[f"{int(t * 100)}%"] = 0.0
        elif b <= 0:
            days[f"{int(t * 100)}%"] = None                      # not growing: never
        else:
            days[f"{int(t * 100)}%"] = round((target - current) / b / 86400, 1)
    return {"growth_per_day": round(per_day), "days_until": days, "samples": len(points),
            "projected_used": round(current)}
