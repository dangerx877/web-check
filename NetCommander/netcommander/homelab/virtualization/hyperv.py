"""Microsoft Hyper-V adapter: the Hyper-V PowerShell module over WinRM (PowerShell remoting).

VMs are always addressed by their GUID (validated), never by name, so a VM called ``x'; Remove-VM *``
cannot inject PowerShell. Read-only collection needs membership of *Hyper-V Administrators* on
the host (Hyper-V has no finer read-only role); power actions use the same rights.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..core.errors import IntegrationError, ValidationError
from ..core.runners import Runner
from .base import HostInfo, Snapshot, VirtualMachine, check_action

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
LIST_VMS = ("Get-VM | Select-Object Name,@{n='Id';e={$_.Id.ToString()}},@{n='State';e={$_.State.ToString()}},"
            "CPUUsage,ProcessorCount,MemoryAssigned,MemoryStartup,@{n='Uptime';e={[int64]$_.Uptime.TotalSeconds}},"
            "Generation,Version | ConvertTo-Json -Depth 3 -Compress")
HOST_INFO = ("$h = Get-VMHost; $os = Get-CimInstance Win32_OperatingSystem; "
             "$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; "
             "[pscustomobject]@{ name = $h.ComputerName; cpus = $h.LogicalProcessorCount; mem_total = $h.MemoryCapacity; "
             "mem_free = [int64]$os.FreePhysicalMemory * 1024; cpu_pct = $cpu; "
             "uptime = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds; version = $os.Caption } "
             "| ConvertTo-Json -Compress")


def _guid(vm_id: str) -> str:
    if not _GUID.match(vm_id or ""):
        raise ValidationError(f"Hyper-V VM ids are GUIDs; got {vm_id!r}.")
    return vm_id


def _json(text: str) -> Any:
    text = text.strip().lstrip("﻿")
    if not text:
        return []
    try:
        return json.loads(text)
    except ValueError:
        raise IntegrationError("Hyper-V returned output that is not JSON.") from None


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else ([v] if v else [])


class HyperVAdapter:
    platform = "hyperv"

    def __init__(self, runner: Runner, host_name: str = "") -> None:
        self.runner, self.host_name = runner, host_name

    def _ps(self, script: str) -> Any:
        r = self.runner.run(script, timeout=60)
        if not r.ok:
            raise IntegrationError(f"Hyper-V command failed: {r.stderr.strip()[:200] or r.exit_code}")
        return _json(r.stdout)

    def hosts(self) -> list[HostInfo]:
        h = self._ps(HOST_INFO)
        total = int(h.get("mem_total") or 0)
        return [HostInfo(name=h.get("name") or self.host_name, status="online", cpus=int(h.get("cpus") or 0),
                         cpu_pct=h.get("cpu_pct"), mem_total=total, mem_used=max(0, total - int(h.get("mem_free") or 0)),
                         uptime_s=h.get("uptime"), version=h.get("version", ""))]

    def list_vms(self) -> list[VirtualMachine]:
        out = []
        for v in _list(self._ps(LIST_VMS)):
            state = str(v.get("State", "")).lower()
            out.append(VirtualMachine(
                id=v.get("Id", ""), name=v.get("Name", ""), host=self.host_name,
                status={"running": "running", "off": "stopped", "paused": "paused", "saved": "stopped"}.get(state, "unknown"),
                cpus=int(v.get("ProcessorCount") or 0), cpu_pct=float(v.get("CPUUsage") or 0),
                mem_total=int(v.get("MemoryStartup") or 0), mem_used=int(v.get("MemoryAssigned") or 0),
                uptime_s=v.get("Uptime"), extra={"generation": v.get("Generation"), "version": v.get("Version"),
                                                 "state": state}))
        return out

    def vm_config(self, vm_id: str) -> dict[str, Any]:
        g = _guid(vm_id)
        data = self._ps(f"Get-VM -Id '{g}' | Select-Object Name,ProcessorCount,MemoryStartup,DynamicMemoryEnabled,"
                        "Generation,Path,@{n='Disks';e={@(Get-VMHardDiskDrive -VM $_ | Select-Object Path,ControllerType)}},"
                        "@{n='Nics';e={@(Get-VMNetworkAdapter -VM $_ | Select-Object SwitchName,MacAddress)}} "
                        "| ConvertTo-Json -Depth 4 -Compress")
        return data if isinstance(data, dict) else {}

    def snapshots(self, vm_id: str) -> list[Snapshot]:
        g = _guid(vm_id)
        rows = _list(self._ps(f"Get-VMSnapshot -VM (Get-VM -Id '{g}') | Select-Object Name,ParentSnapshotName,"
                              "@{n='Created';e={[int64](Get-Date $_.CreationTime -UFormat %s)}} | ConvertTo-Json -Compress"))
        return [Snapshot(r.get("Name", ""), float(r["Created"]) if r.get("Created") else None, "",
                         r.get("ParentSnapshotName") or "") for r in rows]

    def power(self, vm_id: str, action: str) -> str:
        check_action(action)
        g = _guid(vm_id)
        script = {"start": f"Start-VM -VM (Get-VM -Id '{g}')",
                  "shutdown": f"Stop-VM -VM (Get-VM -Id '{g}') -Force",
                  "stop": f"Stop-VM -VM (Get-VM -Id '{g}') -TurnOff -Force",
                  "reboot": f"Restart-VM -VM (Get-VM -Id '{g}') -Force"}[action]
        r = self.runner.run(script, timeout=120)
        if not r.ok:
            raise IntegrationError(f"Hyper-V {action} failed: {r.stderr.strip()[:200]}")
        return "ok"
