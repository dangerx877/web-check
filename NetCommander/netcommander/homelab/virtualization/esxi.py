"""VMware ESXi / vCenter adapter using VMware's official Python SDK, pyVmomi (optional extra).

``pip install 'netcommander[vmware]'``. TLS is verified by default; point ``ca_file`` at the host's CA
(or the exported self-signed certificate) for standalone ESXi. A read-only role is enough for
monitoring; power actions need *VirtualMachine.Interaction.PowerOn/PowerOff/Reset*.

Status: the object mapping is verified against fakes shaped like pyVmomi's managed objects; it has not
been exercised against every ESXi version (see docs/INTEGRATIONS.md for the lab checklist).
"""
from __future__ import annotations

import ssl
from collections.abc import Callable
from typing import Any

from ..core.errors import IntegrationError
from .base import HostInfo, Snapshot, VirtualDisk, VirtualMachine, check_action, safe_id

MB = 1024 * 1024


def _pyvmomi_connect(host: str, username: str, password: str, port: int, verify_tls: bool, ca_file: str) -> Any:
    try:
        from pyVim.connect import SmartConnect  # type: ignore[import-not-found]
    except ImportError as exc:
        raise IntegrationError("VMware support needs the optional 'pyvmomi' package: "
                               "pip install 'netcommander[vmware]'.") from exc
    ctx = ssl.create_default_context(cafile=ca_file or None) if verify_tls else ssl._create_unverified_context()
    try:
        return SmartConnect(host=host, user=username, pwd=password, port=port, sslContext=ctx)
    except Exception as exc:
        raise IntegrationError(f"Could not log in to {host}: {type(exc).__name__}") from None


def _vim_types() -> tuple[Any, Any]:
    from pyVmomi import vim  # type: ignore[import-not-found]
    return vim.VirtualMachine, vim.HostSystem


class EsxiAdapter:
    platform = "esxi"

    def __init__(self, host: str, username: str, password: str = "", port: int = 443, verify_tls: bool = True,
                 ca_file: str = "", connect: Callable[..., Any] | None = None,
                 types: Callable[[], tuple[Any, Any]] | None = None) -> None:
        self.host, self.username, self.password, self.port = host, username, password, port
        self.verify_tls, self.ca_file = verify_tls, ca_file
        self._connect = connect or _pyvmomi_connect
        self._types = types or _vim_types
        self._si: Any = None

    def _content(self) -> Any:
        if self._si is None:
            self._si = self._connect(self.host, self.username, self.password, self.port, self.verify_tls, self.ca_file)
        return self._si.RetrieveContent()

    def _objects(self, which: int) -> list[Any]:
        content = self._content()
        kind = self._types()[which]
        view = content.viewManager.CreateContainerView(content.rootFolder, [kind], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def hosts(self) -> list[HostInfo]:
        out = []
        for h in self._objects(1):
            s = h.summary
            hw, qs = s.hardware, s.quickStats
            total_mhz = (hw.cpuMhz or 0) * (hw.numCpuCores or 0)
            out.append(HostInfo(
                name=s.config.name, status="online" if str(s.runtime.connectionState) == "connected" else "offline",
                cpus=int(hw.numCpuThreads or hw.numCpuCores or 0),
                cpu_pct=round(100.0 * (qs.overallCpuUsage or 0) / total_mhz, 1) if total_mhz else None,
                mem_total=int(hw.memorySize or 0), mem_used=int(qs.overallMemoryUsage or 0) * MB,
                uptime_s=qs.uptime, version=getattr(s.config.product, "fullName", ""),
                storage=[{"name": d.summary.name, "type": d.summary.type, "total": int(d.summary.capacity or 0),
                          "used": int((d.summary.capacity or 0) - (d.summary.freeSpace or 0))}
                         for d in getattr(h, "datastore", [])]))
        return out

    def _vm_id(self, vm: Any) -> str:
        return str(getattr(vm, "_moId", "") or vm.summary.config.instanceUuid)

    def list_vms(self) -> list[VirtualMachine]:
        out = []
        for vm in self._objects(0):
            s = vm.summary
            c, r, q, st = s.config, s.runtime, s.quickStats, s.storage
            state = str(r.powerState)
            status = {"poweredOn": "running", "poweredOff": "stopped", "suspended": "paused"}.get(state, "unknown")
            host_name = getattr(getattr(r, "host", None), "name", "") or self.host
            max_mhz = getattr(r, "maxCpuUsage", 0) or 0
            out.append(VirtualMachine(
                id=self._vm_id(vm), name=c.name, host=host_name, status=status, cpus=int(c.numCpu or 0),
                cpu_pct=round(100.0 * (q.overallCpuUsage or 0) / max_mhz, 1) if max_mhz else None,
                mem_total=int(c.memorySizeMB or 0) * MB, mem_used=int(q.guestMemoryUsage or 0) * MB,
                disk_total=int((st.committed or 0) + (st.uncommitted or 0)), disk_used=int(st.committed or 0),
                uptime_s=q.uptimeSeconds, os=c.guestFullName or "", template=bool(c.template),
                extra={"uuid": c.instanceUuid, "tools": str(getattr(s.guest, "toolsStatus", "")),
                       "guest_ip": getattr(s.guest, "ipAddress", "")}))
        return out

    def _find(self, vm_id: str) -> Any:
        safe_id(vm_id, "VM id")
        for vm in self._objects(0):
            if self._vm_id(vm) == vm_id:
                return vm
        raise IntegrationError(f"VM {vm_id} not found on {self.host}.")

    def vm_config(self, vm_id: str) -> dict[str, Any]:
        vm = self._find(vm_id)
        c = vm.summary.config
        disks = [VirtualDisk(name=d.deviceInfo.label, size=int(getattr(d, "capacityInBytes", 0) or 0))
                 for d in getattr(vm.config.hardware, "device", []) if hasattr(d, "capacityInBytes")]
        return {"name": c.name, "cpus": c.numCpu, "memory_mb": c.memorySizeMB, "guest": c.guestFullName,
                "path": c.vmPathName, "disks": [d.__dict__ for d in disks]}

    def snapshots(self, vm_id: str) -> list[Snapshot]:
        vm = self._find(vm_id)
        out: list[Snapshot] = []

        def walk(nodes: Any, parent: str = "") -> None:
            for n in nodes or []:
                created = n.createTime.timestamp() if hasattr(n.createTime, "timestamp") else None
                out.append(Snapshot(n.name, created, n.description or "", parent))
                walk(n.childSnapshotList, n.name)
        snap = getattr(vm, "snapshot", None)
        walk(getattr(snap, "rootSnapshotList", None))
        return out

    def power(self, vm_id: str, action: str) -> str:
        check_action(action)
        vm = self._find(vm_id)
        method = {"start": "PowerOnVM_Task", "stop": "PowerOffVM_Task", "shutdown": "ShutdownGuest",
                  "reboot": "RebootGuest"}[action]
        res = getattr(vm, method)()
        return str(getattr(getattr(res, "info", None), "key", "") or "requested")
