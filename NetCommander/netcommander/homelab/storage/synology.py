"""Synology DSM adapter - the DSM Web API (``/webapi/entry.cgi``).

Login uses ``SYNO.API.Auth`` (POST, so the password never appears in a URL or proxy log) with a
dedicated, non-admin DSM account where possible; 2FA-protected accounts are not supported for
unattended polling. Storage data comes from ``SYNO.Storage.CGI.Storage`` (what Storage Manager uses)
and shares from ``SYNO.Core.Share``. Synology documents the Auth API publicly but not every storage
field, so this adapter is marked **beta**: unknown fields are skipped, never fatal.
"""
from __future__ import annotations

from typing import Any

from ..core.errors import IntegrationError
from ..core.httpclient import HttpClient
from .base import Disk, Pool, Share, StorageReport


class SynologyAdapter:
    platform = "synology"

    def __init__(self, url: str, username: str, password: str = "", verify_tls: bool = True, ca_file: str = "",
                 pin_sha256: str = "", transport: Any = None) -> None:
        self.http = HttpClient(url.rstrip("/") + "/webapi", verify_tls=verify_tls, ca_file=ca_file or None,
                               pin_sha256=pin_sha256 or None, transport=transport)
        self.username, self.password = username, password

    def _call(self, sid: str, api: str, method: str, version: int, **params: Any) -> Any:
        res = self.http.get("/entry.cgi", params={"api": api, "method": method, "version": version, "_sid": sid, **params})
        if not isinstance(res, dict) or not res.get("success"):
            code = (res or {}).get("error", {}).get("code") if isinstance(res, dict) else None
            raise IntegrationError(f"Synology {api}.{method} failed (error {code}).")
        return res.get("data") or {}

    def _login(self) -> str:
        res = self.http.post("/entry.cgi", form={"api": "SYNO.API.Auth", "method": "login", "version": 6,
                                                 "account": self.username, "passwd": self.password,
                                                 "session": "NetCommander", "format": "sid"})
        if not isinstance(res, dict) or not res.get("success"):
            code = (res or {}).get("error", {}).get("code") if isinstance(res, dict) else None
            hint = " (account uses 2FA?)" if code in (403, 404, 406) else ""
            raise IntegrationError(f"Synology login failed (error {code}){hint}.")
        return str(res["data"]["sid"])

    def _logout(self, sid: str) -> None:
        try:
            self.http.get("/entry.cgi", params={"api": "SYNO.API.Auth", "method": "logout", "version": 6,
                                                "session": "NetCommander", "_sid": sid})
        except IntegrationError:
            pass

    def report(self) -> StorageReport:
        sid = self._login()
        errors: list[str] = []
        try:
            system: dict[str, Any] = {"vendor": "Synology", "platform": "synology"}
            try:
                info = self._call(sid, "SYNO.DSM.Info", "getinfo", 2)
                system.update({"hostname": info.get("hostname", ""), "model": info.get("model", ""),
                               "version": info.get("version_string", ""), "mem_total": int(info.get("ram") or 0) * 1024 * 1024,
                               "uptime_s": info.get("uptime"), "temperature_c": info.get("temperature")})
            except IntegrationError as exc:
                errors.append(str(exc))
            st = self._call(sid, "SYNO.Storage.CGI.Storage", "load_info", 1)
            disks = []
            for d in st.get("disks") or []:
                smart = str(d.get("smart_status", "")).lower()
                disks.append(Disk(
                    name=d.get("name") or d.get("id", ""), model=str(d.get("model", "")).strip(),
                    serial=str(d.get("serial", "")), size=int(d.get("size_total") or 0),
                    type=str(d.get("diskType", "")), temperature_c=float(d["temp"]) if d.get("temp") not in (None, -1) else None,
                    smart_ok=None if not smart else smart in ("normal", "safe"), status=str(d.get("status", "")),
                    power_on_hours=d.get("power_on_hours") if isinstance(d.get("power_on_hours"), int) else None))
            id_to_name = {d.get("id"): (d.get("name") or d.get("id")) for d in st.get("disks") or []}
            pools = []
            for p in st.get("storagePools") or []:
                size = p.get("size") or {}
                status = str(p.get("status", ""))
                pools.append(Pool(name=p.get("id", ""), status=status, healthy=status.lower() == "normal",
                                  layout=str(p.get("device_type") or p.get("raidType", "")),
                                  total=int(size.get("total") or 0), used=int(size.get("used") or 0),
                                  disks=[str(id_to_name.get(x, x)) for x in p.get("disks") or []]))
            if not pools:                                   # older DSM: volumes only
                for v in st.get("volumes") or []:
                    size = v.get("size") or {}
                    status = str(v.get("status", ""))
                    pools.append(Pool(name=v.get("id", ""), status=status, healthy=status.lower() == "normal",
                                      layout=str(v.get("raid_type", "")), total=int(size.get("total") or 0),
                                      used=int(size.get("used") or 0)))
            for p in pools:
                for dn in p.disks:
                    for d in disks:
                        if d.name == dn:
                            d.pool = p.name
            shares = []
            try:
                for s in (self._call(sid, "SYNO.Core.Share", "list", 1).get("shares") or []):
                    shares.append(Share(s.get("name", ""), "smb", s.get("vol_path", "") + "/" + s.get("name", ""), True))
            except IntegrationError as exc:
                errors.append(str(exc))
            return StorageReport(system, pools, disks, shares, errors)
        finally:
            self._logout(sid)
