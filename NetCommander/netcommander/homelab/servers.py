"""Server management: read-only resource collection from Linux (SSH) and Windows (PowerShell remoting).

Collectors run a **fixed, allowlisted** set of commands (:data:`LINUX_POLICY`, :data:`WINDOWS_SCRIPT`)
through a :class:`~netcommander.homelab.core.runners.Runner`, then parse the output with pure functions
that are unit-tested against captured samples. Missing tools (BusyBox, minimal containers) degrade
to partial data instead of failing the whole collection.

Remote *changes* (restarting a service, running scripts) are not done here: they go through the
Automation Center, which requires permissions, confirmation and (by policy) a second approver.
"""
from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .core.runners import CommandPolicy, CommandResult, Runner, run_all

# ---------------------------------------------------------------- Linux
LINUX_COMMANDS = {
    "hostname": "hostname",
    "os_release": "cat /etc/os-release",
    "uname": "uname -srm",
    "loadavg": "cat /proc/loadavg",
    "meminfo": "cat /proc/meminfo",
    "uptime": "cat /proc/uptime",
    "stat": "cat /proc/stat",
    "cpuinfo": "cat /proc/cpuinfo",
    "df": "df -P -k",
    "netdev": "cat /proc/net/dev",
    "ipaddr": "ip -j addr",
    "ps": "ps -eo pid,user,pcpu,pmem,rss,comm",
    "services": "systemctl list-units --type=service --all --no-pager --no-legend --plain",
    "vendor": "cat /sys/class/dmi/id/sys_vendor",
    "product": "cat /sys/class/dmi/id/product_name",
}
LINUX_POLICY = CommandPolicy(LINUX_COMMANDS.values())
_PSEUDO_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "devpts",
              "efivarfs", "ramfs", "udev", "none", "shm", "run", "nsfs", "tracefs", "fusectl"}


def parse_meminfo(text: str) -> dict[str, int]:
    vals: dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)\s*(kB)?", line)
        if m:
            vals[m.group(1)] = int(m.group(2)) * (1024 if m.group(3) else 1)
    total = vals.get("MemTotal", 0)
    avail = vals.get("MemAvailable", vals.get("MemFree", 0) + vals.get("Buffers", 0) + vals.get("Cached", 0))
    return {"mem_total": total, "mem_used": max(0, total - avail), "swap_total": vals.get("SwapTotal", 0),
            "swap_used": max(0, vals.get("SwapTotal", 0) - vals.get("SwapFree", 0))}


def parse_loadavg(text: str) -> dict[str, float]:
    parts = text.split()
    try:
        return {"load1": float(parts[0]), "load5": float(parts[1]), "load15": float(parts[2])}
    except (IndexError, ValueError):
        return {}


def parse_uptime(text: str) -> int | None:
    try:
        return int(float(text.split()[0]))
    except (IndexError, ValueError):
        return None


def parse_proc_stat_cpu(text: str) -> tuple[int, int] | None:
    """(busy, total) jiffies from the aggregate ``cpu`` line."""
    for line in text.splitlines():
        if line.startswith("cpu "):
            nums = [int(x) for x in line.split()[1:] if x.isdigit()]
            if len(nums) < 4:
                return None
            idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
            total = sum(nums[:8]) if len(nums) >= 8 else sum(nums)
            return total - idle, total
    return None


def cpu_percent(a: tuple[int, int] | None, b: tuple[int, int] | None) -> float | None:
    if not a or not b or b[1] <= a[1]:
        return None
    return round(100.0 * (b[0] - a[0]) / (b[1] - a[1]), 1)


def parse_cpuinfo(text: str) -> dict[str, Any]:
    model = ""
    cores = 0
    for line in text.splitlines():
        if line.lower().startswith(("model name", "hardware", "cpu model")) and not model:
            model = line.split(":", 1)[-1].strip()
        if line.startswith("processor"):
            cores += 1
    return {"cpu_model": model, "cpu_cores": cores}


def parse_df(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, size, used, avail, mount = parts[0], parts[1], parts[2], parts[3], " ".join(parts[5:])
        if not size.isdigit() or fs in _PSEUDO_FS or fs.startswith(("/dev/loop",)) or mount.startswith(
                ("/proc", "/sys", "/run", "/dev", "/snap")):
            continue
        total = int(size) * 1024
        out.append({"filesystem": fs, "mount": mount, "total": total, "used": int(used) * 1024,
                    "avail": int(avail) * 1024 if avail.isdigit() else 0,
                    "pct": round(100.0 * int(used) / int(size), 1) if int(size) else 0.0})
    return out


def parse_net_dev(text: str) -> dict[str, dict[str, int]]:
    out = {}
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        nums = data.split()
        if len(nums) >= 9 and name.strip() != "lo":
            out[name.strip()] = {"rx_bytes": int(nums[0]), "rx_errors": int(nums[2]), "rx_drop": int(nums[3]),
                                 "tx_bytes": int(nums[8]), "tx_errors": int(nums[10]) if len(nums) > 10 else 0}
    return out


def parse_ip_addr_json(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for itf in data if isinstance(data, list) else []:
        if itf.get("ifname") == "lo":
            continue
        out.append({"name": itf.get("ifname", ""), "mac": itf.get("address", ""),
                    "state": (itf.get("operstate") or "").lower(), "mtu": itf.get("mtu"),
                    "addresses": [f"{a.get('local')}/{a.get('prefixlen')}" for a in itf.get("addr_info", [])
                                  if a.get("local")]})
    return out


def parse_os_release(text: str) -> str:
    vals = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', text, re.M))
    return vals.get("PRETTY_NAME") or " ".join(x for x in (vals.get("NAME"), vals.get("VERSION_ID")) if x)


def parse_ps(text: str, top: int = 25) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split(None, 5)
        if len(parts) < 6 or not parts[0].isdigit():
            continue
        try:
            rows.append({"pid": int(parts[0]), "user": parts[1], "cpu_pct": float(parts[2]),
                         "mem_pct": float(parts[3]), "rss": int(parts[4]) * 1024, "command": parts[5][:120]})
        except ValueError:
            continue
    return sorted(rows, key=lambda r: (r["cpu_pct"], r["mem_pct"]), reverse=True)[:top]


def parse_systemctl(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            out.append({"name": parts[0][:-8], "load": parts[1], "active": parts[2], "sub": parts[3],
                        "description": parts[4] if len(parts) > 4 else ""})
    return out


@dataclass
class CollectResult:
    observation: dict[str, Any]
    metrics: dict[str, float] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    reachable: bool = True


def collect_linux(runner: Runner, sleep: Callable[[float], None] = time.sleep, cpu_sample: float = 1.0) -> CollectResult:
    res = run_all(runner, list(LINUX_COMMANDS.values()), timeout=20)
    if all(r.exit_code == 255 for r in res.values()):
        return CollectResult({"status": "offline"}, errors=[next(iter(res.values())).stderr], reachable=False)
    out: dict[str, str] = {k: (res[c].stdout if res[c].ok else "") for k, c in LINUX_COMMANDS.items()}
    errors = [f"{c}: {r.stderr.strip()[:120] or f'exit {r.exit_code}'}" for c, r in res.items()
              if not r.ok and c not in (LINUX_COMMANDS["vendor"], LINUX_COMMANDS["product"])]
    first = parse_proc_stat_cpu(out["stat"])
    cpu = None
    if first:
        sleep(cpu_sample)
        again = runner.run(LINUX_COMMANDS["stat"], 10)
        cpu = cpu_percent(first, parse_proc_stat_cpu(again.stdout if again.ok else ""))
    mem = parse_meminfo(out["meminfo"])
    disks = parse_df(out["df"])
    real = [d for d in disks if d["filesystem"].startswith(("/dev/", "zfs", "rpool", "tank")) or "/" in d["filesystem"]]
    real = real or disks
    root_disks = {d["filesystem"]: d for d in real}.values()          # same device mounted twice counts once
    nets = parse_net_dev(out["netdev"])
    info = parse_cpuinfo(out["cpuinfo"])
    load = parse_loadavg(out["loadavg"])
    interfaces = parse_ip_addr_json(out["ipaddr"]) or [{"name": n} for n in nets]
    for itf in interfaces:
        itf.update(nets.get(itf.get("name", ""), {}))
    obs: dict[str, Any] = {
        "status": "online", "hostname": out["hostname"].strip(), "os": parse_os_release(out["os_release"]) or
        out["uname"].strip(), "manufacturer": out["vendor"].strip(), "model": out["product"].strip(),
        "cpu_pct": cpu, "uptime_s": parse_uptime(out["uptime"]), "interfaces": interfaces,
        "mem_total": mem.get("mem_total", 0), "mem_used": mem.get("mem_used", 0),
        "storage_total": sum(d["total"] for d in root_disks), "storage_used": sum(d["used"] for d in root_disks),
        "services": [{"name": s["name"], "state": s["sub"], "active": s["active"]} for s in parse_systemctl(out["services"])
                     if s["active"] in ("active", "failed")],
        **{k: v for k, v in info.items() if v},
        "extra": {"kernel": out["uname"].strip(), "load": load},
    }
    metrics: dict[str, float] = {}
    if cpu is not None:
        metrics["cpu_pct"] = cpu
    if mem.get("mem_total"):
        metrics["mem_pct"] = round(100.0 * mem["mem_used"] / mem["mem_total"], 1)
    if obs["storage_total"]:
        metrics["disk_pct"] = round(100.0 * obs["storage_used"] / obs["storage_total"], 1)
    metrics.update({k: v for k, v in load.items()})
    metrics["net_rx_bytes"] = float(sum(n["rx_bytes"] for n in nets.values()))
    metrics["net_tx_bytes"] = float(sum(n["tx_bytes"] for n in nets.values()))
    failed = [s["name"] for s in parse_systemctl(out["services"]) if s["active"] == "failed"]
    metrics["failed_services"] = float(len(failed))
    details = {"disks": disks, "processes": parse_ps(out["ps"]), "failed_services": failed,
               "swap": {k: mem[k] for k in ("swap_total", "swap_used") if k in mem}}
    return CollectResult(obs, metrics, details, errors)


# ---------------------------------------------------------------- Windows
WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = @(Get-CimInstance Win32_Processor)
[pscustomobject]@{
  hostname = $env:COMPUTERNAME
  os = $os.Caption + ' ' + $os.Version
  manufacturer = $cs.Manufacturer
  model = $cs.Model
  cpu_model = $cpu[0].Name
  cpu_cores = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
  cpu_pct = ($cpu | Measure-Object -Property LoadPercentage -Average).Average
  mem_total = [int64]$os.TotalVisibleMemorySize * 1024
  mem_free = [int64]$os.FreePhysicalMemory * 1024
  uptime_s = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
  disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID, Size, FreeSpace, FileSystem)
  nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description, MACAddress, IPAddress)
  net = @(Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface | Select-Object Name, BytesReceivedPersec, BytesSentPersec)
  services = @(Get-Service | Select-Object Name, DisplayName, @{n='Status';e={$_.Status.ToString()}}, @{n='StartType';e={$_.StartType.ToString()}})
  processes = @(Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 Id, ProcessName, CPU, WorkingSet64)
} | ConvertTo-Json -Depth 4 -Compress
""".strip()
WINDOWS_POLICY = CommandPolicy([WINDOWS_SCRIPT])


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parse_windows(text: str) -> CollectResult:
    try:
        d = json.loads(text.strip().lstrip("﻿"))
    except ValueError:
        return CollectResult({"status": "degraded"}, errors=["could not parse PowerShell output"])
    total, free = int(d.get("mem_total") or 0), int(d.get("mem_free") or 0)
    disks = [{"filesystem": x.get("DeviceID"), "mount": x.get("DeviceID"), "fstype": x.get("FileSystem"),
              "total": int(x.get("Size") or 0), "used": int(x.get("Size") or 0) - int(x.get("FreeSpace") or 0)}
             for x in _as_list(d.get("disks"))]
    for x in disks:
        x["pct"] = round(100.0 * x["used"] / x["total"], 1) if x["total"] else 0.0
    nics = [{"name": n.get("Description", ""), "mac": n.get("MACAddress", ""),
             "addresses": _as_list(n.get("IPAddress"))} for n in _as_list(d.get("nics"))]
    services = [{"name": s.get("Name"), "description": s.get("DisplayName"), "state": str(s.get("Status", "")).lower(),
                 "start_type": s.get("StartType")} for s in _as_list(d.get("services"))]
    stopped_auto = [s["name"] for s in services if s["state"] == "stopped" and s.get("start_type") == "Automatic"]
    net = _as_list(d.get("net"))
    obs = {
        "status": "online", "hostname": d.get("hostname", ""), "os": (d.get("os") or "").strip(),
        "manufacturer": d.get("manufacturer", ""), "model": d.get("model", ""), "cpu_model": (d.get("cpu_model") or "").strip(),
        "cpu_cores": int(d.get("cpu_cores") or 0), "cpu_pct": d.get("cpu_pct"), "uptime_s": d.get("uptime_s"),
        "mem_total": total, "mem_used": max(0, total - free), "interfaces": nics,
        "storage_total": sum(x["total"] for x in disks), "storage_used": sum(x["used"] for x in disks),
        "services": [s for s in services if s["state"] == "running"],
    }
    metrics: dict[str, float] = {"failed_services": float(len(stopped_auto))}
    if d.get("cpu_pct") is not None:
        metrics["cpu_pct"] = float(d["cpu_pct"])
    if total:
        metrics["mem_pct"] = round(100.0 * obs["mem_used"] / total, 1)
    if obs["storage_total"]:
        metrics["disk_pct"] = round(100.0 * obs["storage_used"] / obs["storage_total"], 1)
    metrics["net_rx_bytes"] = float(sum(int(n.get("BytesReceivedPersec") or 0) for n in net))
    metrics["net_tx_bytes"] = float(sum(int(n.get("BytesSentPersec") or 0) for n in net))
    procs = [{"pid": p.get("Id"), "command": p.get("ProcessName"), "cpu_seconds": p.get("CPU"),
              "rss": p.get("WorkingSet64")} for p in _as_list(d.get("processes"))]
    return CollectResult(obs, metrics, {"disks": disks, "processes": procs, "failed_services": stopped_auto})


def collect_windows(runner: Runner) -> CollectResult:
    r: CommandResult = run_all(runner, [WINDOWS_SCRIPT], timeout=90)[WINDOWS_SCRIPT]
    if r.exit_code == 255:
        return CollectResult({"status": "offline"}, errors=[r.stderr], reachable=False)
    if not r.ok and not r.stdout.strip():
        return CollectResult({"status": "degraded"}, errors=[r.stderr.strip()[:300] or f"exit {r.exit_code}"])
    return parse_windows(r.stdout)


# ---------------------------------------------------------------- connectivity
MANAGEMENT_PORTS = {"ssh": 22, "winrm": 5985, "winrm-tls": 5986, "rdp": 3389, "https": 443}


def connectivity(host: str, probe: Callable[[str, int, float], str], ports: Mapping[str, int] | None = None,
                 timeout: float = 2.0) -> dict[str, Any]:
    """Which management endpoints answer, plus round-trip time of the first open one."""
    ports = dict(ports or MANAGEMENT_PORTS)
    out: dict[str, Any] = {"host": host, "ports": {}}
    for name, port in ports.items():
        t0 = time.perf_counter()
        state = probe(host, port, timeout)
        out["ports"][name] = state
        if state == "open" and "rtt_ms" not in out:
            out["rtt_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["reachable"] = any(s in ("open", "closed") for s in out["ports"].values())
    return out
