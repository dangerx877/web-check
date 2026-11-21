"""TrueNAS (SCALE / CORE) adapter - REST API v2.0 with an API key (``Authorization: Bearer``).

Create a key under *Credentials -> API Keys* (on 24.10+ it can be tied to a read-only user).
Note: iXsystems is moving to a JSON-RPC-over-WebSocket API and marks REST as deprecated from 25.04;
REST still works there. If a future release removes it, this adapter is the one file to replace.
"""
from __future__ import annotations

from typing import Any

from ..core.errors import IntegrationError
from ..core.httpclient import HttpClient
from .base import Disk, Pool, Share, StorageReport


def _vdev_layout(topology: dict[str, Any]) -> str:
    data = (topology or {}).get("data") or []
    kinds = sorted({str(v.get("type", "")).upper() for v in data if v.get("type")})
    return "+".join(kinds) if kinds else ""


def _vdev_disks(topology: dict[str, Any]) -> list[str]:
    out: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "DISK" and node.get("disk"):
                out.append(str(node["disk"]))
            for child in node.get("children") or []:
                walk(child)
        elif isinstance(node, list):
            for x in node:
                walk(x)
    for section in ("data", "cache", "log", "spare", "special", "dedup"):
        walk((topology or {}).get(section))
    return out


class TrueNasAdapter:
    platform = "truenas"

    def __init__(self, url: str, api_key: str = "", verify_tls: bool = True, ca_file: str = "", pin_sha256: str = "",
                 transport: Any = None) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.http = HttpClient(url.rstrip("/") + "/api/v2.0", headers, verify_tls=verify_tls, ca_file=ca_file or None,
                               pin_sha256=pin_sha256 or None, transport=transport)

    def _try(self, errors: list[str], fn: Any, *a: Any, **kw: Any) -> Any:
        try:
            return fn(*a, **kw)
        except IntegrationError as exc:
            errors.append(str(exc))
            return None

    def report(self) -> StorageReport:
        errors: list[str] = []
        info = self.http.get("/system/info") or {}          # fail hard if the API itself is unreachable
        system = {"hostname": info.get("hostname", ""), "version": info.get("version", ""), "vendor": "iXsystems",
                  "model": info.get("system_product") or info.get("model", ""), "mem_total": info.get("physmem", 0),
                  "uptime_s": int(info.get("uptime_seconds") or 0) or None, "platform": "truenas"}
        pools = []
        for p in self._try(errors, self.http.get, "/pool") or []:
            total = int(p.get("size") or 0)
            used = int(p.get("allocated") or 0)
            pools.append(Pool(name=p.get("name", ""), status=p.get("status", "unknown"), healthy=p.get("healthy"),
                              layout=_vdev_layout(p.get("topology") or {}), total=total, used=used,
                              disks=_vdev_disks(p.get("topology") or {})))
        disk_pool = {d: p.name for p in pools for d in p.disks}
        disks = []
        for d in self._try(errors, self.http.get, "/disk") or []:
            name = d.get("name", "")
            disks.append(Disk(name=name, model=d.get("model") or "", serial=d.get("serial") or "",
                              size=int(d.get("size") or 0), type=str(d.get("type") or ""),
                              pool=d.get("pool") or disk_pool.get(name, "")))
        if disks:
            temps = self._try(errors, self.http.post, "/disk/temperatures",
                              json_body={"names": [d.name for d in disks]}) or {}
            if isinstance(temps, dict):
                for d in disks:
                    t = temps.get(d.name)
                    d.temperature_c = float(t) if isinstance(t, (int, float)) else None
            results = self._try(errors, self.http.get, "/smart/test/results") or []
            last: dict[str, str] = {}
            for r in results:
                tests = r.get("tests") or []
                if tests:
                    last[r.get("disk", "")] = str(tests[0].get("status", ""))
            for d in disks:
                if d.name in last:
                    d.smart_ok = last[d.name].upper() in ("SUCCESS", "RUNNING")
                    d.status = f"last SMART test: {last[d.name]}"
        shares = [Share(s.get("name") or s.get("path", ""), "smb", s.get("path", ""), bool(s.get("enabled", True)))
                  for s in self._try(errors, self.http.get, "/sharing/smb") or []]
        for s in self._try(errors, self.http.get, "/sharing/nfs") or []:
            paths = s.get("paths") or ([s["path"]] if s.get("path") else [])
            shares.append(Share(", ".join(paths), "nfs", ", ".join(paths), bool(s.get("enabled", True)),
                                {"networks": s.get("networks", []), "hosts": s.get("hosts", [])}))
        base = ""
        gl = self._try(errors, self.http.get, "/iscsi/global") or {}
        if isinstance(gl, dict):
            base = gl.get("basename", "")
        for t in self._try(errors, self.http.get, "/iscsi/target") or []:
            shares.append(Share(f"{base}:{t.get('name')}" if base else str(t.get("name")), "iscsi", "",
                                True, {"alias": t.get("alias") or ""}))
        return StorageReport(system, pools, disks, shares, errors)

    def replication_tasks(self) -> list[dict[str, Any]]:
        """Replication + cloud-sync job states for the Backup Center."""
        out = []
        for r in self.http.get("/replication") or []:
            st = r.get("state") or {}
            out.append({"name": r.get("name"), "type": "replication", "enabled": r.get("enabled", True),
                        "state": st.get("state", "UNKNOWN"), "last": (st.get("datetime") or {}).get("$date")})
        for c in self.http.get("/cloudsync") or []:
            job = c.get("job") or {}
            out.append({"name": c.get("description"), "type": "cloudsync", "enabled": c.get("enabled", True),
                        "state": job.get("state", "UNKNOWN"), "last": (job.get("time_finished") or {}).get("$date")})
        return out
