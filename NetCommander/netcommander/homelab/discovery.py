"""Agentless, read-only infrastructure discovery.

What it does (and does not do)
* **TCP connect probes** on a short list of well-known ports (configurable). A refused connection also
  proves the host is alive, so no raw sockets / root privileges / ICMP are needed.
* **Banners**: the SSH identification string, and the HTTP ``Server`` header from a single
  ``HEAD /`` request (no credentials are ever sent during discovery).
* **MAC addresses** from this machine's neighbour (ARP/NDP) table - only hosts on a directly attached
  segment have one - and a small built-in vendor (OUI) table for common homelab hardware.
* **Reverse DNS** names.
* A **classifier** turns ports + banners + vendor into a best-guess kind (server, NAS, hypervisor...)
  and service list. Guesses are labelled ``confidence`` and are easy to correct by hand (manual edits lock).

Safety: sweeps are capped (``discovery.max_hosts``, default 1024 addresses), run with bounded
concurrency and short timeouts, and need the ``DISCOVER`` permission. Only scan networks you own.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .core.errors import ValidationError
from .models import normalize_mac

log = logging.getLogger(__name__)

SERVICE_NAMES = {
    22: "ssh", 53: "dns", 80: "http", 443: "https", 445: "smb", 139: "netbios", 2049: "nfs", 111: "rpcbind",
    3260: "iscsi", 5000: "synology-dsm", 5001: "synology-dsm-tls", 5985: "winrm", 5986: "winrm-tls",
    8006: "proxmox", 8080: "http-alt", 8443: "https-alt", 9000: "portainer", 9443: "portainer-tls",
    2375: "docker", 2376: "docker-tls", 902: "vmware-auth", 161: "snmp", 3389: "rdp", 9100: "jetdirect",
    631: "ipp", 1883: "mqtt", 8123: "home-assistant", 8007: "proxmox-backup", 8086: "influxdb", 3000: "grafana",
    9090: "prometheus", 32400: "plex", 8096: "jellyfin", 6443: "kubernetes", 10250: "kubelet", 3306: "mysql",
    5432: "postgresql", 6379: "redis", 25: "smtp", 21: "ftp", 23: "telnet", 8291: "mikrotik-winbox",
}

# A deliberately small OUI table (first three octets) for vendors common in homelabs.
OUI_VENDORS = {
    "00:11:32": "Synology", "90:09:d0": "Synology", "00:08:9b": "QNAP", "24:5e:be": "QNAP",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi",
    "2c:cf:67": "Raspberry Pi", "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "52:54:00": "QEMU/KVM", "08:00:27": "VirtualBox", "00:15:5d": "Microsoft Hyper-V", "02:42:ac": "Docker",
    "bc:24:11": "Proxmox", "fc:ec:da": "Ubiquiti", "24:5a:4c": "Ubiquiti", "74:83:c2": "Ubiquiti",
    "78:8a:20": "Ubiquiti", "f0:9f:c2": "Ubiquiti", "4c:5e:0c": "MikroTik", "64:d1:54": "MikroTik",
    "cc:2d:e0": "MikroTik", "48:8f:5a": "MikroTik", "00:1b:21": "Intel", "3c:fd:fe": "Intel", "a0:36:9f": "Intel",
    "00:25:90": "Supermicro", "ac:1f:6b": "Supermicro", "f4:52:14": "Mellanox", "00:1c:73": "Arista",
    "18:66:da": "Dell", "f8:bc:12": "Dell", "b0:83:fe": "Dell", "3c:a8:2a": "HPE", "94:57:a5": "HPE",
    "00:17:a4": "HPE", "50:c7:bf": "TP-Link", "a4:2b:b0": "TP-Link", "e8:48:b8": "TP-Link", "a0:40:a0": "Netgear",
    "00:1e:58": "D-Link", "00:00:0c": "Cisco", "00:1b:0d": "Cisco", "58:97:1e": "Cisco", "f8:ff:c2": "Apple",
    "a4:83:e7": "Apple", "3c:22:fb": "Apple", "00:e0:4c": "Realtek", "04:d9:f5": "ASUS", "b4:2e:99": "Gigabyte",
    "00:d8:61": "Micro-Star", "9c:6b:00": "ASRock", "30:9c:23": "Micro-Star", "e0:63:da": "Ubiquiti",
}


def vendor_for_mac(mac: str) -> str:
    if not mac:
        return ""
    try:
        m = normalize_mac(mac)
    except ValidationError:
        return ""
    v = OUI_VENDORS.get(m[:8], "")
    if not v and int(m[:2], 16) & 0x02:
        return "(locally administered)"
    return v


# ---------------------------------------------------------------- targets
def expand_targets(specs: Iterable[str], max_hosts: int = 1024) -> list[str]:
    """``10.0.0.0/24``, ``10.0.0.5``, ``10.0.0.10-10.0.0.40`` or ``10.0.0.10-40``. Raises if over ``max_hosts``."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in specs:
        spec = raw.strip()
        if not spec:
            continue
        try:
            if "/" in spec:
                net = ipaddress.ip_network(spec, strict=False)
                if net.num_addresses > max_hosts + 2:
                    raise ValidationError(f"{spec} has {net.num_addresses} addresses; the limit is {max_hosts} "
                                          "(discovery.max_hosts).")
                hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
            elif "-" in spec:
                start_s, end_s = spec.split("-", 1)
                start = ipaddress.ip_address(start_s.strip())
                end_txt = end_s.strip()
                if "." not in end_txt and ":" not in end_txt:
                    end_txt = start_s.rsplit(".", 1)[0] + "." + end_txt
                end = ipaddress.ip_address(end_txt)
                if int(end) < int(start) or start.version != end.version:
                    raise ValidationError(f"Invalid range {spec!r}.")
                if int(end) - int(start) + 1 > max_hosts:
                    raise ValidationError(f"{spec} exceeds the {max_hosts}-address limit.")
                hosts = [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
            else:
                hosts = [str(ipaddress.ip_address(spec))]
        except ValueError:
            raise ValidationError(f"Not an IP address, range or CIDR: {spec!r}.") from None
        for h in hosts:
            if h not in seen:
                seen.add(h)
                out.append(h)
    if len(out) > max_hosts:
        raise ValidationError(f"{len(out)} addresses requested; the limit is {max_hosts}.")
    return out


# ---------------------------------------------------------------- probes
@dataclass
class PortResult:
    port: int
    state: str                      # open | closed | filtered
    banner: str = ""


def tcp_probe(host: str, port: int, timeout: float = 0.8) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"                                   # RST: the host is alive
    except (socket.timeout, TimeoutError):
        return "filtered"
    except OSError:
        return "filtered"


def grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """SSH identification line or HTTP ``Server`` header. Never sends credentials."""
    try:
        if port == 22:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                return s.recv(256).decode("utf-8", "replace").strip().splitlines()[0][:200]
        if port in (80, 8080, 5000, 8123, 3000, 9000, 443, 8443, 5001, 8006, 9443, 8007):
            tls = port in (443, 8443, 5001, 8006, 9443, 8007)
            raw = socket.create_connection((host, port), timeout=timeout)
            sock: Any = raw
            if tls:
                ctx = ssl._create_unverified_context()          # read-only banner; nothing secret is sent
                sock = ctx.wrap_socket(raw, server_hostname=host if not _is_ip(host) else None)
            with sock:
                sock.settimeout(timeout)
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NetCommander-Discovery\r\n\r\n".encode())
                head = sock.recv(2048).decode("latin-1", "replace")
            server = re.search(r"(?im)^server:\s*(.+)$", head)
            title = head.split("\r\n", 1)[0]
            return (server.group(1).strip() if server else title)[:200]
    except (OSError, ssl.SSLError, IndexError):
        return ""
    return ""


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


# ---------------------------------------------------------------- neighbour tables
def parse_proc_net_arp(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00" and parts[2] != "0x0":
            out[parts[0]] = parts[3].lower()
    return out


def parse_ip_neigh(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s.*lladdr\s+([0-9a-fA-F:]{17})\s+(\w+)", line.strip())
        if m and m.group(3).upper() not in ("FAILED", "INCOMPLETE"):
            out[m.group(1)] = m.group(2).lower()
    return out


def parse_arp_a(text: str) -> dict[str, str]:
    """``arp -a`` on Windows (``10.0.0.1  aa-bb-cc-dd-ee-ff  dynamic``) and macOS/BSD (``? (10.0.0.1) at aa:bb:...``)."""
    out = {}
    for line in text.splitlines():
        m = re.search(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b", line)
        if not m:
            continue
        octets = re.split(r"[:-]", m.group(2))
        mac = ":".join(o.zfill(2) for o in octets).lower()
        if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            out[m.group(1)] = mac
    return out


def local_neighbor_table() -> dict[str, str]:
    """IP -> MAC from this machine's ARP/NDP cache (best effort, no privileges needed)."""
    try:
        if sys.platform.startswith("linux"):
            try:
                with open("/proc/net/arp", encoding="utf-8") as fh:
                    table = parse_proc_net_arp(fh.read())
            except OSError:
                table = {}
            try:
                p = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5, check=False)
                table.update(parse_ip_neigh(p.stdout))
            except (OSError, subprocess.SubprocessError):
                pass
            return table
        p = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10, check=False)
        return parse_arp_a(p.stdout)
    except (OSError, subprocess.SubprocessError):
        return {}


# ---------------------------------------------------------------- classification
@dataclass
class Classification:
    kind: str
    platform: str = ""
    confidence: str = "low"           # low | medium | high
    os: str = ""
    services: list[dict[str, Any]] = field(default_factory=list)


def classify(open_ports: Sequence[int], banners: dict[int, str] | None = None, vendor: str = "",
             hostname: str = "") -> Classification:
    banners = banners or {}
    ports = set(open_ports)
    text = " ".join(banners.values()).lower()
    host = hostname.lower()
    services = [{"port": p, "proto": "tcp", "name": SERVICE_NAMES.get(p, f"tcp/{p}"), "banner": banners.get(p, "")}
                for p in sorted(ports)]
    os_guess = ""
    m = re.search(r"ssh-2\.0-\S+\s+(\w+)", banners.get(22, "").lower())
    if m:
        os_guess = {"debian": "Debian", "ubuntu": "Ubuntu", "raspbian": "Raspberry Pi OS",
                    "freebsd": "FreeBSD"}.get(m.group(1), m.group(1).title())
    if "openssh" in banners.get(22, "").lower() and "windows" in banners.get(22, "").lower():
        os_guess = "Windows"
    c = Classification("unknown", os=os_guess, services=services)

    def done(kind: str, platform: str = "", conf: str = "medium", os_: str = "") -> Classification:
        c.kind, c.platform, c.confidence = kind, platform, conf
        if os_:
            c.os = os_
        return c

    if 8006 in ports or "pve-api-daemon" in text or "proxmox" in text:
        return done("hypervisor", "proxmox", "high", c.os or "Proxmox VE")
    if 8007 in ports:
        return done("appliance", "proxmox-backup", "medium", "Proxmox Backup Server")
    if 902 in ports and (443 in ports or "vmware" in text):
        return done("hypervisor", "esxi", "high", "VMware ESXi")
    if vendor == "Synology" or {5000, 5001} & ports and ("synology" in text or "nginx" in text and vendor == "Synology"):
        return done("nas", "synology", "high" if vendor == "Synology" else "medium", "Synology DSM")
    if vendor == "QNAP" or "qnap" in text or "http server" in text and 8080 in ports and vendor == "QNAP":
        return done("nas", "qnap", "high", "QNAP QTS")
    if "truenas" in text or "freenas" in text or "truenas" in host:
        return done("nas", "truenas", "high", "TrueNAS")
    if "ugreen" in text or "ugos" in text or "ugreen" in host:
        return done("nas", "ugreen", "medium", "UGREEN UGOS")
    if {2375, 2376} & ports:
        return done("docker_host", "docker", "high")
    if {9000, 9443} & ports and "portainer" in text:
        return done("docker_host", "portainer", "medium")
    if vendor in ("Ubiquiti",) and not {22, 445} & ports:
        return done("access_point", "unifi", "low")
    if vendor in ("MikroTik",) or 8291 in ports:
        return done("router", "mikrotik", "medium", "RouterOS")
    if {9100, 631} & ports and not {22, 445} & ports:
        return done("printer", "", "medium")
    if 8123 in ports:
        return done("appliance", "home-assistant", "medium", c.os or "Home Assistant OS")
    if 1883 in ports and len(ports) <= 2:
        return done("iot", "mqtt", "low")
    if {445, 2049, 3260} & ports and len({445, 2049, 3260} & ports) >= 2:
        return done("nas", "generic", "low")
    if {3389, 5985, 5986} & ports and 22 not in ports:
        kind = "server" if {5985, 5986} & ports else "desktop"
        return done(kind, "windows", "medium", "Windows")
    if vendor in ("VMware", "QEMU/KVM", "VirtualBox", "Microsoft Hyper-V", "Proxmox"):
        return done("vm", vendor.lower(), "medium")
    if vendor in ("Apple",) and not {22, 445} & ports:
        return done("laptop", "apple", "low", "macOS")
    if vendor in ("Cisco", "Arista", "HPE", "Netgear", "TP-Link", "D-Link") and not {445, 2049} & ports \
            and ({161, 23} & ports or not ports - {22, 80, 443}):
        return done("switch", vendor.lower(), "low")
    if 53 in ports and len(ports) <= 3 and 22 not in ports:
        return done("router", "", "low")
    if 22 in ports:
        return done("server", "linux" if c.os != "Windows" else "windows", "low", c.os)
    return c


# ---------------------------------------------------------------- engine
Probe = Callable[[str, int, float], str]
BannerFn = Callable[[str, int, float], str]


@dataclass
class HostResult:
    ip: str
    alive: bool
    ports: list[PortResult]
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    classification: Classification | None = None

    def observation(self) -> dict[str, Any]:
        c = self.classification or Classification("unknown")
        return {
            "name": self.hostname.split(".")[0] if self.hostname else self.ip,
            "hostname": self.hostname, "ip": self.ip, "mac": self.mac, "manufacturer": self.vendor,
            "kind": c.kind, "os": c.os, "status": "online" if self.alive else "offline",
            "services": c.services,
            "extra": {"platform_guess": c.platform, "confidence": c.confidence,
                      "open_ports": [p.port for p in self.ports if p.state == "open"]},
        }


class DiscoveryEngine:
    def __init__(self, ports: Sequence[int], timeout: float = 0.8, workers: int = 64, max_hosts: int = 1024,
                 reverse_dns_enabled: bool = True, probe: Probe = tcp_probe, banner: BannerFn = grab_banner,
                 neighbors: Callable[[], dict[str, str]] = local_neighbor_table,
                 resolver: Callable[[str], str] = reverse_dns) -> None:
        self.ports = sorted({int(p) for p in ports})
        self.timeout, self.workers, self.max_hosts = timeout, max(1, workers), max_hosts
        self.rdns = reverse_dns_enabled
        self._probe, self._banner, self._neighbors, self._resolver = probe, banner, neighbors, resolver

    def scan_host(self, ip: str) -> HostResult:
        results = [PortResult(p, self._probe(ip, p, self.timeout)) for p in self.ports]
        alive = any(r.state in ("open", "closed") for r in results)
        for r in results:
            if r.state == "open":
                r.banner = self._banner(ip, r.port, max(self.timeout, 1.0)) or ""
        return HostResult(ip=ip, alive=alive, ports=results)

    def scan(self, specs: Iterable[str], progress: Callable[[int, int], None] | None = None) -> list[HostResult]:
        targets = expand_targets(specs, self.max_hosts)
        started = time.monotonic()
        done = 0
        found: list[HostResult] = []
        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(targets))),
                                thread_name_prefix="nc-discover") as pool:
            for res in pool.map(self.scan_host, targets):
                done += 1
                if progress and (done % 16 == 0 or done == len(targets)):
                    progress(done, len(targets))
                if res.alive:
                    found.append(res)
        neigh = self._neighbors() if found else {}
        for h in found:
            h.mac = neigh.get(h.ip, "")
            h.vendor = vendor_for_mac(h.mac)
            if self.rdns:
                h.hostname = self._resolver(h.ip)
            opened = [p.port for p in h.ports if p.state == "open"]
            h.classification = classify(opened, {p.port: p.banner for p in h.ports if p.banner}, h.vendor, h.hostname)
        log.info("discovery: %d/%d hosts alive in %.1fs", len(found), len(targets), time.monotonic() - started)
        return found
