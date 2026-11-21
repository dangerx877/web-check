"""The unified asset model shared by every module.

An :class:`Asset` is anything the platform knows about: a physical server, a laptop, a switch, a NAS,
a VM, a container, or a network service. Assets are plain JSON-serialisable data; relationships are
explicit (``parent`` = the host a VM/container runs on, ``links`` = typed edges such as
``connected_to`` a switch port or ``stores_on`` a NAS).

Fields an administrator edits by hand are recorded in ``locked`` and are never overwritten by
discovery or integrations, so manual inventory and automatic inventory can coexist.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from .core.errors import ValidationError

KINDS = (
    "server", "desktop", "laptop", "router", "switch", "firewall", "access_point", "appliance", "nas",
    "storage", "hypervisor", "vm", "container", "docker_host", "service", "printer", "iot", "unknown",
)
STATUSES = ("online", "offline", "degraded", "unknown", "stopped", "paused")
SOURCES = ("manual", "discovery", "integration", "network", "import")
LINK_TYPES = ("connected_to", "runs_on", "stores_on", "depends_on", "backs_up_to", "member_of")
_MAC = re.compile(r"^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$", re.I)
_DOTTED_MAC = re.compile(r"^([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})$", re.I)
EDITABLE = ("name", "kind", "hostname", "ip", "mac", "os", "manufacturer", "model", "cpu_model", "cpu_cores",
            "mem_total", "storage_total", "location", "notes", "tags", "parent", "management", "status")


def normalize_mac(mac: str) -> str:
    mac = (mac or "").strip()
    if not mac:
        return ""
    m = _MAC.match(mac)
    if m:
        return ":".join(g.lower() for g in m.groups())
    d = _DOTTED_MAC.match(mac)
    if d:
        h = "".join(d.groups()).lower()
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    raise ValidationError(f"Invalid MAC address {mac!r}.")


def normalize_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if not ip:
        return ""
    try:
        return str(ipaddress.ip_address(ip.strip("[]")))
    except ValueError:
        raise ValidationError(f"Invalid IP address {ip!r}.") from None


def new_id(prefix: str = "a") -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


@dataclass
class Asset:
    name: str
    kind: str = "unknown"
    id: str = field(default_factory=new_id)
    status: str = "unknown"
    hostname: str = ""
    ip: str = ""
    mac: str = ""
    os: str = ""
    manufacturer: str = ""
    model: str = ""
    cpu_model: str = ""
    cpu_cores: int = 0
    cpu_pct: float | None = None
    mem_total: int = 0                   # bytes
    mem_used: int = 0
    storage_total: int = 0               # bytes
    storage_used: int = 0
    uptime_s: int | None = None
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    location: str = ""
    notes: str = ""
    parent: str = ""                     # asset id of the host (VM/container -> hypervisor/docker host)
    links: list[dict[str, Any]] = field(default_factory=list)
    source: str = "manual"
    integration: str = ""                # integration id that reports this asset
    external_id: str = ""                # id inside that integration (e.g. "pve1/qemu/101")
    management: dict[str, Any] = field(default_factory=dict)   # {"ssh": {...}, "winrm": {...}} - refs only
    locked: list[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    # ---- (de)serialisation ------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Asset:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def validate(self) -> Asset:
        problems: list[str] = []
        self.name = str(self.name or "").strip()
        if not self.name or len(self.name) > 128:
            problems.append("name is required (max 128 characters)")
        if self.kind not in KINDS:
            problems.append(f"kind must be one of: {', '.join(KINDS)}")
        if self.status not in STATUSES:
            problems.append(f"status must be one of: {', '.join(STATUSES)}")
        if self.source not in SOURCES:
            problems.append(f"source must be one of: {', '.join(SOURCES)}")
        for attr, fn in (("ip", normalize_ip), ("mac", normalize_mac)):
            try:
                setattr(self, attr, fn(getattr(self, attr)))
            except ValidationError as exc:
                problems.append(str(exc))
        for attr in ("cpu_cores", "mem_total", "mem_used", "storage_total", "storage_used"):
            try:
                v = int(getattr(self, attr) or 0)
                if v < 0:
                    raise ValueError
                setattr(self, attr, v)
            except (TypeError, ValueError):
                problems.append(f"{attr} must be a non-negative integer")
        if not isinstance(self.tags, list) or not all(isinstance(t, str) for t in self.tags):
            problems.append("tags must be a list of strings")
        for link in self.links:
            if not isinstance(link, dict) or link.get("type") not in LINK_TYPES or not link.get("to"):
                problems.append(f"links entries need 'to' and a type in {', '.join(LINK_TYPES)}")
                break
        if not isinstance(self.management, dict):
            problems.append("management must be an object")
        else:
            for proto, conf in self.management.items():
                if not isinstance(conf, dict):
                    problems.append(f"management.{proto} must be an object")
                    continue
                for k in conf:
                    if k in ("password", "secret", "token"):
                        problems.append(f"management.{proto}.{k}: store it in the secret store and use {k}_ref")
        if problems:
            raise ValidationError("Invalid asset: " + "; ".join(problems), problems)
        return self

    # ---- derived values ------------------------------------------------------
    @property
    def mem_pct(self) -> float | None:
        return round(100.0 * self.mem_used / self.mem_total, 1) if self.mem_total else None

    @property
    def storage_pct(self) -> float | None:
        return round(100.0 * self.storage_used / self.storage_total, 1) if self.storage_total else None

    def summary(self) -> dict[str, Any]:
        d = self.to_dict()
        d["mem_pct"], d["storage_pct"] = self.mem_pct, self.storage_pct
        return d


def merge_observation(current: Asset, observed: dict[str, Any], now: float | None = None) -> Asset:
    """Apply an observation from discovery/integrations without touching locked (hand-edited) fields.

    Empty observed values never erase known data (a probe that could not read the OS does not blank it).
    """
    data = current.to_dict()
    locked = set(current.locked)
    for key, val in observed.items():
        if key in ("id", "locked", "first_seen", "links", "notes", "tags", "location", "management"):
            continue
        if key in locked or key not in data:
            continue
        if val in (None, "", [], {}) and key not in ("cpu_pct",):
            continue
        if key == "extra" and isinstance(val, dict):
            data["extra"] = {**data.get("extra", {}), **val}
            continue
        data[key] = val
    data["last_seen"] = time.time() if now is None else now
    return Asset.from_dict(data)
