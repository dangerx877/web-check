"""Common virtualization model and adapter interface.

Every hypervisor adapter returns the same shapes (:class:`VirtualMachine`, :class:`HostInfo`,
:class:`Snapshot`) so the rest of the platform - inventory, monitoring, dashboard - is hypervisor-agnostic.
Power actions are part of the interface but are only ever called by the platform *after*
:class:`~netcommander.homelab.core.authz.ActionGuard` has authorised them.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from ..core.errors import ValidationError

POWER_ACTIONS = ("start", "shutdown", "stop", "reboot")
POWER_RISK = {"start": "change", "shutdown": "destructive", "stop": "destructive", "reboot": "destructive"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:+@/-]{1,128}$")


def safe_id(value: str, what: str = "id") -> str:
    """IDs are interpolated into API paths and commands: allow only a conservative character set."""
    if not isinstance(value, str) or not _SAFE_ID.match(value) or ".." in value:
        raise ValidationError(f"Invalid {what} {value!r}.")
    return value


@dataclass
class VirtualDisk:
    name: str
    size: int = 0                  # bytes
    used: int = 0
    storage: str = ""


@dataclass
class Snapshot:
    name: str
    created: float | None = None
    description: str = ""
    parent: str = ""


@dataclass
class VirtualMachine:
    id: str                        # adapter-specific, stable (e.g. "pve1/qemu/101")
    name: str
    host: str = ""
    type: str = "vm"               # vm | lxc | container
    status: str = "unknown"        # running | stopped | paused | unknown
    cpus: int = 0
    cpu_pct: float | None = None
    mem_total: int = 0
    mem_used: int = 0
    disk_total: int = 0
    disk_used: int = 0
    uptime_s: int | None = None
    os: str = ""
    template: bool = False
    disks: list[VirtualDisk] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def observation(self, integration: str, host_asset: str = "") -> dict[str, Any]:
        status = {"running": "online", "stopped": "stopped", "paused": "paused"}.get(self.status, "unknown")
        return {"name": self.name, "kind": "container" if self.type in ("lxc", "container") else "vm",
                "status": status, "integration": integration, "external_id": self.id, "parent": host_asset,
                "cpu_cores": self.cpus, "cpu_pct": self.cpu_pct, "mem_total": self.mem_total, "mem_used": self.mem_used,
                "storage_total": self.disk_total, "storage_used": self.disk_used, "uptime_s": self.uptime_s,
                "os": self.os, "source": "integration",
                "extra": {"hypervisor_host": self.host, "vm_type": self.type, "template": self.template,
                          "disks": [asdict(d) for d in self.disks], **self.extra}}


@dataclass
class HostInfo:
    name: str
    status: str = "unknown"        # online | offline
    cpus: int = 0
    cpu_pct: float | None = None
    mem_total: int = 0
    mem_used: int = 0
    storage: list[dict[str, Any]] = field(default_factory=list)   # [{"name","type","total","used"}]
    uptime_s: int | None = None
    version: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def allocation(self, vms: list[VirtualMachine]) -> dict[str, Any]:
        """How much of this host the VMs have been *given* (over-commit visibility)."""
        mine = [v for v in vms if v.host == self.name and not v.template]
        vcpus = sum(v.cpus for v in mine)
        vmem = sum(v.mem_total for v in mine)
        return {"vms": len(mine), "running": sum(1 for v in mine if v.status == "running"),
                "vcpus": vcpus, "vcpu_ratio": round(vcpus / self.cpus, 2) if self.cpus else None,
                "mem_assigned": vmem, "mem_ratio": round(vmem / self.mem_total, 2) if self.mem_total else None}


class HypervisorAdapter(Protocol):
    platform: str

    def hosts(self) -> list[HostInfo]: ...
    def list_vms(self) -> list[VirtualMachine]: ...
    def vm_config(self, vm_id: str) -> dict[str, Any]: ...
    def snapshots(self, vm_id: str) -> list[Snapshot]: ...
    def power(self, vm_id: str, action: str) -> str: ...


def check_action(action: str) -> str:
    if action not in POWER_ACTIONS:
        raise ValidationError(f"Unknown power action {action!r}; use one of {', '.join(POWER_ACTIONS)}.")
    return action
