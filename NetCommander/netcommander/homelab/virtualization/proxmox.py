"""Proxmox VE adapter (official REST API, ``/api2/json``) using an API token.

Create a token in *Datacenter -> Permissions -> API Tokens*. For read-only monitoring give it the
``PVEAuditor`` role; add ``PVEVMUser`` (VM.PowerMgmt) only if you want power actions. The token is
sent as ``Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>``.
"""
from __future__ import annotations

from typing import Any

from ..core.httpclient import HttpClient
from .base import HostInfo, Snapshot, VirtualDisk, VirtualMachine, check_action, safe_id


class ProxmoxAdapter:
    platform = "proxmox"

    def __init__(self, url: str, token_id: str, token: str = "", verify_tls: bool = True, ca_file: str = "",
                 pin_sha256: str = "", timeout: float = 15.0, transport: Any = None) -> None:
        headers = {"Authorization": f"PVEAPIToken={token_id}={token}"} if token else {}
        self.http = HttpClient(url.rstrip("/") + "/api2/json", headers, verify_tls=verify_tls, ca_file=ca_file or None,
                               pin_sha256=pin_sha256 or None, timeout=timeout, transport=transport)

    def _data(self, path: str, **kw: Any) -> Any:
        res = self.http.get(path, **kw)
        return res.get("data") if isinstance(res, dict) else None

    def hosts(self) -> list[HostInfo]:
        out = []
        for n in self._data("/nodes") or []:
            node = safe_id(str(n.get("node", "")), "node")
            storage = []
            if n.get("status") == "online":
                for s in self._data(f"/nodes/{node}/storage") or []:
                    storage.append({"name": s.get("storage"), "type": s.get("type"), "total": int(s.get("total") or 0),
                                    "used": int(s.get("used") or 0), "active": bool(s.get("active", 1)),
                                    "content": s.get("content", "")})
            out.append(HostInfo(
                name=node, status="online" if n.get("status") == "online" else "offline",
                cpus=int(n.get("maxcpu") or 0), cpu_pct=round(float(n.get("cpu") or 0) * 100, 1),
                mem_total=int(n.get("maxmem") or 0), mem_used=int(n.get("mem") or 0), storage=storage,
                uptime_s=n.get("uptime"), extra={"level": n.get("level", "")}))
        return out

    def list_vms(self) -> list[VirtualMachine]:
        out = []
        for r in self._data("/cluster/resources", params={"type": "vm"}) or []:
            vtype = r.get("type", "qemu")
            vmid = str(r.get("vmid", ""))
            node = str(r.get("node", ""))
            status = str(r.get("status", "unknown"))
            out.append(VirtualMachine(
                id=f"{node}/{vtype}/{vmid}", name=r.get("name") or f"{vtype}-{vmid}", host=node,
                type="lxc" if vtype == "lxc" else "vm",
                status=status if status in ("running", "stopped", "paused") else "unknown",
                cpus=int(r.get("maxcpu") or 0), cpu_pct=round(float(r.get("cpu") or 0) * 100, 1),
                mem_total=int(r.get("maxmem") or 0), mem_used=int(r.get("mem") or 0),
                disk_total=int(r.get("maxdisk") or 0), disk_used=int(r.get("disk") or 0),
                uptime_s=r.get("uptime"), template=bool(r.get("template")),
                extra={"vmid": vmid, "pool": r.get("pool", ""), "tags": r.get("tags", ""),
                       "netin": r.get("netin"), "netout": r.get("netout")}))
        return out

    def _path(self, vm_id: str) -> str:
        node, vtype, vmid = safe_id(vm_id, "VM id").split("/")
        if vtype not in ("qemu", "lxc") or not vmid.isdigit():
            raise ValueError(f"Not a Proxmox VM id: {vm_id!r}")
        return f"/nodes/{node}/{vtype}/{vmid}"

    def vm_config(self, vm_id: str) -> dict[str, Any]:
        cfg = self._data(self._path(vm_id) + "/config") or {}
        return {k: v for k, v in cfg.items() if k not in ("cipassword",)}

    def disks(self, vm_id: str) -> list[VirtualDisk]:
        out = []
        for key, val in self.vm_config(vm_id).items():
            if any(key.startswith(p) for p in ("scsi", "virtio", "sata", "ide", "rootfs", "mp")) and isinstance(val, str) \
                    and ":" in val and "media=cdrom" not in val:
                storage = val.split(":", 1)[0]
                size = 0
                for part in val.split(","):
                    if part.startswith("size="):
                        size = _size_to_bytes(part[5:])
                out.append(VirtualDisk(name=key, size=size, storage=storage))
        return out

    def snapshots(self, vm_id: str) -> list[Snapshot]:
        return [Snapshot(name=s.get("name", ""), created=s.get("snaptime"), description=s.get("description", ""),
                         parent=s.get("parent", ""))
                for s in self._data(self._path(vm_id) + "/snapshot") or [] if s.get("name") != "current"]

    def power(self, vm_id: str, action: str) -> str:
        check_action(action)
        res = self.http.post(self._path(vm_id) + f"/status/{action}")
        return str(res.get("data") if isinstance(res, dict) else res)       # task UPID

    def backup_tasks(self, limit: int = 50) -> list[dict[str, Any]]:
        """Recent vzdump (backup) tasks across all online nodes - used by the Backup Center."""
        out = []
        for h in self.hosts():
            if h.status != "online":
                continue
            for t in self._data(f"/nodes/{h.name}/tasks", params={"typefilter": "vzdump", "limit": limit}) or []:
                out.append({"node": h.name, "vmid": t.get("id", ""), "start": t.get("starttime"),
                            "end": t.get("endtime"), "status": t.get("status", "running"), "upid": t.get("upid", "")})
        return out


def _size_to_bytes(text: str) -> int:
    units = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
    t = text.strip().upper()
    try:
        if t and t[-1] in units:
            return int(float(t[:-1]) * units[t[-1]])
        return int(t)
    except ValueError:
        return 0
