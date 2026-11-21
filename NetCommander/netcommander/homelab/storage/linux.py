"""Generic Linux storage server over SSH - also used for UGREEN (UGOS Pro) and QNAP (QTS/QuTS) NAS.

UGREEN and QNAP do not publish a stable management API for third parties, so NetCommander talks to them
the way an administrator would: SSH (enable it in the NAS control panel) and standard Linux tools.
Everything is read-only and allowlisted (:data:`STORAGE_POLICY`):

* ``lsblk -J`` (disks), ``df`` (capacity), ``/proc/mdstat`` (mdadm RAID), ``zpool list/status`` (ZFS),
  ``btrfs filesystem show`` is not needed - capacity comes from ``df``;
* ``smartctl -j`` for SMART health (requires root: set ``use_sudo`` and allow
  ``smartctl`` in sudoers with NOPASSWD for the monitoring account, or connect as root);
* ``/etc/exports`` (NFS), ``testparm -s`` (Samba shares), ``/sys/kernel/config/target/iscsi`` (LIO iSCSI).

Missing tools simply leave that part of the report empty.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..core.errors import IntegrationError
from ..core.runners import CommandPolicy, Runner, run_all
from ..servers import parse_df
from .base import Disk, Pool, Share, StorageReport

COMMANDS = {
    "hostname": "hostname",
    "os": "cat /etc/os-release",
    "lsblk": "lsblk -J -b -o NAME,SIZE,TYPE,MODEL,SERIAL,ROTA,TRAN,MOUNTPOINT,FSTYPE",
    "df": "df -P -k",
    "mdstat": "cat /proc/mdstat",
    "zpool": "zpool list -H -p -o name,size,alloc,health",
    "zstatus": "zpool status",
    "exports": "cat /etc/exports",
    "smb": "testparm -s --suppress-prompt",
    "iscsi": "ls /sys/kernel/config/target/iscsi",
    "meminfo": "cat /proc/meminfo",
    "uptime": "cat /proc/uptime",
}
SMART_PREFIXES = ("smartctl -j -H -A -i /dev/", "sudo -n smartctl -j -H -A -i /dev/")
STORAGE_POLICY = CommandPolicy(COMMANDS.values(), SMART_PREFIXES)
_DISK_NAME = re.compile(r"^(sd[a-z]{1,2}|nvme\d+n\d+|vd[a-z]{1,2}|hd[a-z]|xvd[a-z]{1,2})$")


def parse_lsblk(text: str) -> list[dict[str, Any]]:
    try:
        devs = json.loads(text).get("blockdevices") or []
    except (ValueError, AttributeError):
        return []
    return [d for d in devs if d.get("type") == "disk" and _DISK_NAME.match(str(d.get("name", "")))]


def parse_mdstat(text: str) -> list[Pool]:
    pools = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(md\d+)\s*:\s*(\w+)\s+(?:\(\w+\)\s+)?(raid\d+|linear)?\s*(.*)$", line)
        if not m:
            continue
        name, state, level, members = m.group(1), m.group(2), m.group(3) or "", m.group(4)
        disks = [re.sub(r"\d+$", "", x.split("[")[0]) if not x.startswith("nvme") else re.sub(r"p\d+$", "", x.split("[")[0])
                 for x in members.split()]
        failed = "(F)" in members
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        st = re.search(r"\[([U_]+)\]", nxt)
        degraded = failed or (st is not None and "_" in st.group(1))
        recovering = i + 2 < len(lines) and re.search(r"recovery|resync|reshape", lines[i + 2]) is not None
        pools.append(Pool(name=name, status=("degraded" if degraded else state) + (" (rebuilding)" if recovering else ""),
                          healthy=state == "active" and not degraded, layout=level.upper(),
                          disks=sorted(set(disks))))
    return pools


def parse_zpool_list(text: str) -> list[Pool]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) >= 4 and parts[1].isdigit():
            out.append(Pool(name=parts[0], status=parts[3], healthy=parts[3] == "ONLINE", total=int(parts[1]),
                            used=int(parts[2])))
    return out


def parse_zpool_status(text: str) -> dict[str, dict[str, Any]]:
    """Per pool: vdev layout and member disks."""
    out: dict[str, dict[str, Any]] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"^\s*pool:\s*(\S+)", line)
        if m:
            cur = out.setdefault(m.group(1), {"layout": set(), "disks": []})
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+(mirror|raidz[123]?|draid\S*)-\d+\s", line)
        if m:
            cur["layout"].add(m.group(1).upper())
            continue
        m = re.match(r"^\s+((?:sd[a-z]+|nvme\d+n\d+|vd[a-z]+|ata-\S+|wwn-\S+|scsi-\S+|nvme-\S+))\S*\s+(ONLINE|DEGRADED|FAULTED|UNAVAIL|OFFLINE|REMOVED)", line)
        if m:
            cur["disks"].append(m.group(1))
    return {k: {"layout": "+".join(sorted(v["layout"])) or "stripe", "disks": v["disks"]} for k, v in out.items()}


def parse_smartctl(text: str) -> dict[str, Any]:
    try:
        d = json.loads(text)
    except ValueError:
        return {}
    out: dict[str, Any] = {"model": d.get("model_name", ""), "serial": d.get("serial_number", ""),
                           "smart_ok": (d.get("smart_status") or {}).get("passed"),
                           "temperature_c": (d.get("temperature") or {}).get("current"),
                           "power_on_hours": (d.get("power_on_time") or {}).get("hours")}
    for attr in (d.get("ata_smart_attributes") or {}).get("table") or []:
        if attr.get("id") == 5:
            out["reallocated"] = (attr.get("raw") or {}).get("value")
        elif attr.get("id") == 197:
            out["pending"] = (attr.get("raw") or {}).get("value")
    nv = d.get("nvme_smart_health_information_log") or {}
    if nv:
        out["temperature_c"] = out["temperature_c"] or nv.get("temperature")
        out["power_on_hours"] = out["power_on_hours"] or nv.get("power_on_hours")
        if nv.get("media_errors"):
            out["pending"] = nv.get("media_errors")
    return out


def parse_exports(text: str) -> list[Share]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            path, *clients = line.split()
            out.append(Share(path, "nfs", path, True, {"clients": clients}))
    return out


def parse_testparm(text: str) -> list[Share]:
    out, cur, attrs = [], None, {}
    for line in text.splitlines() + ["[__end__]"]:
        m = re.match(r"^\s*\[(.+)\]\s*$", line)
        if m:
            if cur and cur.lower() not in ("global", "printers", "print$", "homes"):
                out.append(Share(cur, "smb", attrs.get("path", ""), attrs.get("available", "yes") != "no",
                                 {"read_only": attrs.get("read only", "yes"), "guest_ok": attrs.get("guest ok", "no")}))
            cur, attrs = m.group(1), {}
        elif "=" in line and cur:
            k, v = line.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
    return out


class LinuxStorageAdapter:
    platform = "linux"

    def __init__(self, runner: Runner, use_sudo: bool = False, vendor: str = "", smart: bool = True) -> None:
        self.runner, self.use_sudo, self.vendor, self.smart = runner, use_sudo, vendor, smart

    def report(self) -> StorageReport:
        res = run_all(self.runner, list(COMMANDS.values()), timeout=30)
        out = {k: (res[c].stdout if res[c].ok else "") for k, c in COMMANDS.items()}
        if all(r.exit_code == 255 for r in res.values()):
            raise IntegrationError(next(iter(res.values())).stderr or "storage host unreachable")
        os_name = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', out["os"], re.M)).get("PRETTY_NAME", "")
        mem = re.search(r"MemTotal:\s+(\d+)", out["meminfo"])
        system = {"hostname": out["hostname"].strip(), "version": os_name, "vendor": self.vendor or "Linux",
                  "platform": self.platform, "mem_total": int(mem.group(1)) * 1024 if mem else 0,
                  "uptime_s": int(float(out["uptime"].split()[0])) if out["uptime"].strip() else None}
        disks = []
        for d in parse_lsblk(out["lsblk"]):
            tran = str(d.get("tran") or "")
            disks.append(Disk(name=d["name"], model=str(d.get("model") or "").strip(), serial=str(d.get("serial") or ""),
                              size=int(d.get("size") or 0),
                              type="NVMe" if tran == "nvme" else ("HDD" if str(d.get("rota")) in ("1", "True", "true") else "SSD")))
        pools = parse_zpool_list(out["zpool"])
        zs = parse_zpool_status(out["zstatus"])
        for p in pools:
            info = zs.get(p.name, {})
            p.layout, p.disks = info.get("layout", ""), info.get("disks", [])
        md = parse_mdstat(out["mdstat"])
        mounts = parse_df(out["df"])
        for p in md:                                       # md capacity = filesystems mounted from it
            for m in mounts:
                if m["filesystem"] == f"/dev/{p.name}":
                    p.total, p.used = p.total + m["total"], p.used + m["used"]
            if not p.total:
                vols = [m for m in mounts if m["mount"].startswith(("/volume", "/share/CACHEDEV", "/mnt"))]
                if len(md) == 1 and vols:
                    p.total, p.used = sum(v["total"] for v in vols), sum(v["used"] for v in vols)
        pools += md
        if not pools:                                      # plain disks / LVM / btrfs: report data mounts
            for m in mounts:
                if m["mount"] == "/" or m["mount"].startswith(("/srv", "/data", "/mnt", "/volume", "/export", "/home")):
                    pools.append(Pool(name=m["mount"], status="mounted", healthy=None, total=m["total"], used=m["used"]))
        for p in pools:
            for dn in p.disks:
                for d in disks:
                    if dn == d.name or dn.endswith(d.serial or "\0"):
                        d.pool = p.name
        errors: list[str] = []
        if self.smart:
            prefix = SMART_PREFIXES[1] if self.use_sudo else SMART_PREFIXES[0]
            for d in disks:
                r = self.runner.run(prefix + d.name, 30)
                data = parse_smartctl(r.stdout)
                if not data:
                    errors.append(f"SMART unavailable for {d.name} (needs root / smartmontools)")
                    continue
                d.smart_ok = data.get("smart_ok")
                d.temperature_c = data.get("temperature_c")
                d.power_on_hours = data.get("power_on_hours")
                d.reallocated, d.pending = data.get("reallocated"), data.get("pending")
                d.model = d.model or data.get("model", "")
                d.serial = d.serial or data.get("serial", "")
        shares = parse_testparm(out["smb"]) + parse_exports(out["exports"])
        shares += [Share(t, "iscsi") for t in out["iscsi"].split() if t.startswith("iqn.")]
        return StorageReport(system, pools, disks, shares, errors)


class UgreenAdapter(LinuxStorageAdapter):
    platform = "ugreen"

    def __init__(self, runner: Runner, use_sudo: bool = True, smart: bool = True) -> None:
        super().__init__(runner, use_sudo, "UGREEN", smart)


class QnapAdapter(LinuxStorageAdapter):
    platform = "qnap"

    def __init__(self, runner: Runner, use_sudo: bool = False, smart: bool = True) -> None:
        super().__init__(runner, use_sudo, "QNAP", smart)
