"""KVM / QEMU via libvirt: the official ``virsh`` CLI, locally or over SSH.

``virsh domstats --raw`` returns state, vCPU, balloon memory and block statistics for every domain in
one call. Domains are addressed by UUID (validated) for actions and details.
"""
from __future__ import annotations

import re
from typing import Any

from ..core.errors import IntegrationError, ValidationError
from ..core.runners import Runner
from .base import HostInfo, Snapshot, VirtualDisk, VirtualMachine, check_action

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_URI = re.compile(r"^(qemu|qemu\+ssh|qemu\+tls|lxc|xen)(\+\w+)?://[\w@.:/-]*$")
STATES = {"1": "running", "2": "running", "3": "paused", "4": "stopped", "5": "stopped", "6": "stopped", "7": "paused"}


def parse_domstats(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    cur: dict[str, str] | None = None
    for line in text.splitlines():
        m = re.match(r"^Domain:\s*'(.*)'\s*$", line.strip())
        if m:
            cur = out.setdefault(m.group(1), {})
            continue
        if cur is not None and "=" in line:
            k, v = line.strip().split("=", 1)
            cur[k] = v
    return out


def parse_kv_colon(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


class LibvirtAdapter:
    platform = "libvirt"

    def __init__(self, runner: Runner, host_name: str = "localhost", uri: str = "qemu:///system") -> None:
        if not _URI.match(uri):
            raise ValidationError(f"Invalid libvirt URI {uri!r}.")
        self.runner, self.host_name, self.uri = runner, host_name, uri

    def _virsh(self, args: str, timeout: float = 30) -> str:
        r = self.runner.run(f"virsh -c {self.uri} {args}", timeout)
        if not r.ok:
            raise IntegrationError(f"virsh {args.split()[0]} failed: {r.stderr.strip()[:200]}")
        return r.stdout

    def hosts(self) -> list[HostInfo]:
        info = parse_kv_colon(self._virsh("nodeinfo"))
        mem = parse_kv_colon(self._virsh("nodememstats"))

        def kib(s: str) -> int:
            return int(re.sub(r"\D", "", s or "0") or 0) * 1024
        total = kib(info.get("Memory size", "0"))
        free = kib(mem.get("free", "0")) + kib(mem.get("buffers", "0")) + kib(mem.get("cached", "0"))
        return [HostInfo(name=self.host_name, status="online", cpus=int(info.get("CPU(s)", "0") or 0),
                         mem_total=total, mem_used=max(0, total - free) if mem else 0,
                         extra={"cpu_model": info.get("CPU model", "")})]

    def _uuids(self) -> dict[str, str]:
        out = {}
        for line in self._virsh("list --all --uuid --name").splitlines():
            parts = line.split()
            if len(parts) == 2 and _UUID.match(parts[0]):
                out[parts[1]] = parts[0]
        return out

    def list_vms(self) -> list[VirtualMachine]:
        stats = parse_domstats(self._virsh("domstats --raw"))
        try:
            uuids = self._uuids()
        except IntegrationError:
            uuids = {}
        out = []
        for name, s in stats.items():
            disks, total, used = [], 0, 0
            for i in range(int(s.get("block.count", "0") or 0)):
                cap, alloc = int(s.get(f"block.{i}.capacity", "0") or 0), int(s.get(f"block.{i}.allocation", "0") or 0)
                disks.append(VirtualDisk(name=s.get(f"block.{i}.name", f"disk{i}"), size=cap, used=alloc,
                                         storage=s.get(f"block.{i}.path", "")))
                total, used = total + cap, used + alloc
            bal_max = int(s.get("balloon.maximum", "0") or 0) * 1024
            bal_cur = int(s.get("balloon.current", "0") or 0) * 1024
            unused = int(s.get("balloon.unused", "0") or 0) * 1024
            out.append(VirtualMachine(
                id=uuids.get(name, name), name=name, host=self.host_name, status=STATES.get(s.get("state.state", ""), "unknown"),
                cpus=int(s.get("vcpu.current", "0") or 0), mem_total=bal_max or bal_cur,
                mem_used=max(0, bal_cur - unused) if unused else bal_cur, disk_total=total, disk_used=used, disks=disks,
                extra={"cpu_time_ns": int(s.get("cpu.time", "0") or 0)}))
        return out

    def _dom(self, vm_id: str) -> str:
        if not _UUID.match(vm_id or ""):
            raise ValidationError(f"libvirt domain ids are UUIDs; got {vm_id!r}.")
        return vm_id

    def vm_config(self, vm_id: str) -> dict[str, Any]:
        return parse_kv_colon(self._virsh(f"dominfo {self._dom(vm_id)}"))

    def snapshots(self, vm_id: str) -> list[Snapshot]:
        text = self._virsh(f"snapshot-list {self._dom(vm_id)} --parent")
        out = []
        for line in text.splitlines()[2:]:
            parts = line.split()
            if parts:
                out.append(Snapshot(parts[0], parent=parts[-1] if len(parts) > 1 and parts[-1] != "-" else ""))
        return out

    def power(self, vm_id: str, action: str) -> str:
        check_action(action)
        verb = {"start": "start", "shutdown": "shutdown", "stop": "destroy", "reboot": "reboot"}[action]
        self._virsh(f"{verb} {self._dom(vm_id)}", 120)
        return "ok"
