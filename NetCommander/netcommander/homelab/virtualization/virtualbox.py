"""Oracle VirtualBox adapter: ``VBoxManage`` (the official CLI) locally or over SSH.

VMs are addressed by UUID (validated). Works for desktop/lab hosts; there is no remote API to secure
beyond SSH itself.
"""
from __future__ import annotations

import re
from typing import Any

from ..core.errors import IntegrationError, ValidationError
from ..core.runners import Runner
from .base import HostInfo, Snapshot, VirtualMachine, check_action

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LIST = re.compile(r'^"(.*)"\s+\{([0-9a-fA-F-]{36})\}$')


def _uuid(v: str) -> str:
    if not _UUID.match(v or ""):
        raise ValidationError(f"VirtualBox VM ids are UUIDs; got {v!r}.")
    return v


def parse_list_vms(text: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in (_LIST.match(line.strip()) for line in text.splitlines()) if m]


def parse_machinereadable(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip().strip('"')] = v.strip().strip('"')
    return out


class VirtualBoxAdapter:
    platform = "virtualbox"

    def __init__(self, runner: Runner, host_name: str = "localhost", vboxmanage: str = "VBoxManage") -> None:
        if not re.match(r"^[A-Za-z0-9_./\\:-]+$", vboxmanage):
            raise ValidationError("Invalid VBoxManage path.")
        self.runner, self.host_name, self.bin = runner, host_name, vboxmanage

    def _run(self, args: str, timeout: float = 30) -> str:
        r = self.runner.run(f"{self.bin} {args}", timeout)
        if not r.ok:
            raise IntegrationError(f"VBoxManage {args.split()[0]} failed: {r.stderr.strip()[:200]}")
        return r.stdout

    def hosts(self) -> list[HostInfo]:
        info: dict[str, str] = {}
        text = self._run("list hostinfo")
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
        mem = int(re.sub(r"\D", "", info.get("Memory size", "0")) or 0) * 1024 * 1024
        avail = int(re.sub(r"\D", "", info.get("Memory available", "0")) or 0) * 1024 * 1024
        return [HostInfo(name=self.host_name, status="online", cpus=int(info.get("Processor count", "0") or 0),
                         mem_total=mem, mem_used=max(0, mem - avail),
                         version=f"{info.get('Operating system', '')} {info.get('Operating system version', '')}".strip())]

    def list_vms(self) -> list[VirtualMachine]:
        out = []
        for name, uid in parse_list_vms(self._run("list vms")):
            try:
                info = parse_machinereadable(self._run(f"showvminfo {uid} --machinereadable"))
            except IntegrationError:
                info = {}
            state = info.get("VMState", "")
            out.append(VirtualMachine(
                id=uid, name=name, host=self.host_name,
                status={"running": "running", "poweroff": "stopped", "aborted": "stopped", "saved": "stopped",
                        "paused": "paused"}.get(state, "unknown"),
                cpus=int(info.get("cpus", "0") or 0), mem_total=int(info.get("memory", "0") or 0) * 1024 * 1024,
                os=info.get("ostype", ""), extra={"state": state}))
        return out

    def vm_config(self, vm_id: str) -> dict[str, Any]:
        info = parse_machinereadable(self._run(f"showvminfo {_uuid(vm_id)} --machinereadable"))
        return {k: v for k, v in info.items() if not k.lower().startswith(("vrdeproperty", "guestproperty"))}

    def snapshots(self, vm_id: str) -> list[Snapshot]:
        r = self.runner.run(f"{self.bin} snapshot {_uuid(vm_id)} list --machinereadable", 30)
        if not r.ok:
            return []                              # "does not have any snapshots" exits non-zero
        info = parse_machinereadable(r.stdout)
        return [Snapshot(name=v, description=info.get(k.replace("SnapshotName", "SnapshotDescription"), ""))
                for k, v in info.items() if k.startswith("SnapshotName")]

    def power(self, vm_id: str, action: str) -> str:
        check_action(action)
        u = _uuid(vm_id)
        args = {"start": f"startvm {u} --type headless", "shutdown": f"controlvm {u} acpipowerbutton",
                "stop": f"controlvm {u} poweroff", "reboot": f"controlvm {u} reset"}[action]
        self._run(args, 120)
        return "ok"
