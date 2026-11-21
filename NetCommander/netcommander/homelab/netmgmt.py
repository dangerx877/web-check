"""Network management for the homelab layer: IPAM, VLANs, diagnostics and the unified topology.

This *extends* the original Network Commander (SSH command runner, LLDP/CDP discovery, config backups,
health probes), which keeps working unchanged. Here:

* **IPAM** - subnets (overlap-checked), reservations, utilisation computed from the live inventory,
  duplicate-IP detection and next-free-address suggestions.
* **VLANs** - inventory of VLAN ids/names and the subnets carried on them.
* **Diagnostics** - ping, traceroute, DNS lookup and TCP port checks with strict target validation
  (no option injection, no shell).
* **Topology** - one graph across classic network devices (from ``topology.json``, LLDP/CDP links) and
  homelab assets (``connected_to`` switch ports, VMs ``runs_on`` hosts, ``stores_on`` NAS).
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from .core.db import Database
from .core.errors import NotFound, ValidationError
from .core.runners import LocalRunner
from .models import Asset, new_id

SUBNETS, VLANS, RESERVATIONS = "ipam_subnets", "ipam_vlans", "ipam_reservations"
_HOST = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def valid_target(host: str) -> str:
    """An IP address or DNS name - never something that could be read as a command-line option."""
    host = (host or "").strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOST.match(host):
        raise ValidationError(f"{host!r} is not a valid IP address or host name.")
    return host


class Ipam:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- subnets -----------------------------------------------------------
    def subnets(self) -> list[dict[str, Any]]:
        return sorted(self.db.all(SUBNETS), key=lambda s: ipaddress.ip_network(s["cidr"]))

    def add_subnet(self, cidr: str, name: str = "", vlan: int | None = None, gateway: str = "", dns: str = "",
                   description: str = "", site: str = "") -> dict[str, Any]:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            raise ValidationError(f"Invalid subnet {cidr!r}.") from None
        for s in self.subnets():
            other = ipaddress.ip_network(s["cidr"])
            if other.version == net.version and net.overlaps(other):
                raise ValidationError(f"{net} overlaps existing subnet {other} ({s.get('name') or s['id']}).")
        if gateway:
            gw = ipaddress.ip_address(gateway)
            if gw not in net:
                raise ValidationError(f"Gateway {gw} is not inside {net}.")
        if vlan is not None and not 1 <= int(vlan) <= 4094:
            raise ValidationError("VLAN id must be 1-4094.")
        rec = {"id": new_id("net"), "cidr": str(net), "name": name.strip()[:64], "vlan": int(vlan) if vlan else None,
               "gateway": gateway, "dns": dns, "description": description[:500], "site": site[:64]}
        self.db.put(SUBNETS, rec["id"], rec)
        return rec

    def delete_subnet(self, sid: str) -> bool:
        return self.db.delete(SUBNETS, sid)

    # ---- reservations ---------------------------------------------------------
    def reserve(self, ip: str, name: str, note: str = "", mac: str = "") -> dict[str, Any]:
        addr = str(ipaddress.ip_address(ip.strip()))
        if not self.subnet_for(addr):
            raise ValidationError(f"{addr} is not inside any managed subnet.")
        for r in self.db.all(RESERVATIONS):
            if r["ip"] == addr:
                raise ValidationError(f"{addr} is already reserved for {r['name']}.")
        rec = {"id": new_id("ip"), "ip": addr, "name": name[:64], "note": note[:200], "mac": mac}
        self.db.put(RESERVATIONS, rec["id"], rec)
        return rec

    def release(self, rid: str) -> bool:
        return self.db.delete(RESERVATIONS, rid)

    def subnet_for(self, ip: str) -> dict[str, Any] | None:
        addr = ipaddress.ip_address(ip)
        best = None
        for s in self.subnets():
            net = ipaddress.ip_network(s["cidr"])
            if addr in net and (best is None or net.prefixlen > ipaddress.ip_network(best["cidr"]).prefixlen):
                best = s
        return best

    # ---- utilisation -----------------------------------------------------------
    def usage(self, assets: Iterable[Asset]) -> list[dict[str, Any]]:
        by_ip: dict[str, list[Asset]] = defaultdict(list)
        for a in assets:
            if a.ip:
                by_ip[a.ip].append(a)
            for itf in a.interfaces:
                for cidr in itf.get("addresses", []) or []:
                    ip = str(cidr).split("/")[0]
                    if ip and ip != a.ip:
                        by_ip[ip].append(a)
        reservations = {r["ip"]: r for r in self.db.all(RESERVATIONS)}
        out = []
        for s in self.subnets():
            net = ipaddress.ip_network(s["cidr"])
            size = max(net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0), 1)
            used: dict[str, dict[str, Any]] = {}
            conflicts = []
            for ip, holders in by_ip.items():
                try:
                    if ipaddress.ip_address(ip) not in net:
                        continue
                except ValueError:
                    continue
                uniq = {h.id: h for h in holders}
                macs = {h.mac for h in uniq.values() if h.mac}
                used[ip] = {"ip": ip, "assets": [{"id": h.id, "name": h.name} for h in uniq.values()]}
                if len(uniq) > 1 and (len(macs) > 1 or not macs) and not any(h.kind in ("vm", "container") and h.parent
                                                                             for h in uniq.values()):
                    conflicts.append({"ip": ip, "assets": [h.name for h in uniq.values()]})
            res_in = {ip: r for ip, r in reservations.items() if ipaddress.ip_address(ip) in net}
            taken = set(used) | set(res_in) | ({s["gateway"]} if s.get("gateway") else set())
            out.append({**s, "size": size, "used": len(taken), "pct": round(100.0 * len(taken) / size, 1),
                        "addresses": sorted(used.values(), key=lambda x: ipaddress.ip_address(x["ip"])),
                        "reservations": sorted(res_in.values(), key=lambda r: ipaddress.ip_address(r["ip"])),
                        "conflicts": conflicts, "next_free": self._free(net, taken, 5)})
        return out

    @staticmethod
    def _free(net: ipaddress.IPv4Network | ipaddress.IPv6Network, taken: set[str], n: int) -> list[str]:
        out = []
        for i, host in enumerate(net.hosts()):
            if i > 70000:
                break
            if str(host) not in taken:
                out.append(str(host))
                if len(out) >= n:
                    break
        return out

    # ---- VLANs ---------------------------------------------------------------
    def vlans(self) -> list[dict[str, Any]]:
        subnets = self.subnets()
        out = []
        for v in sorted(self.db.all(VLANS), key=lambda v: v["vid"]):
            out.append({**v, "subnets": [s["cidr"] for s in subnets if s.get("vlan") == v["vid"]]})
        return out

    def set_vlan(self, vid: int, name: str, description: str = "") -> dict[str, Any]:
        vid = int(vid)
        if not 1 <= vid <= 4094:
            raise ValidationError("VLAN id must be 1-4094.")
        if not name.strip():
            raise ValidationError("A VLAN needs a name.")
        rec = {"id": f"vlan-{vid}", "vid": vid, "name": name.strip()[:64], "description": description[:200]}
        self.db.put(VLANS, rec["id"], rec)
        return rec

    def delete_vlan(self, vid: int) -> bool:
        return self.db.delete(VLANS, f"vlan-{int(vid)}")

    def get_subnet(self, sid: str) -> dict[str, Any]:
        s = self.db.get(SUBNETS, sid)
        if not s:
            raise NotFound(f"No subnet {sid!r}.")
        return s


# ---------------------------------------------------------------- diagnostics
def ping_command(host: str, count: int = 4) -> str:
    host = valid_target(host)
    count = max(1, min(int(count), 20))
    if sys.platform.startswith("win"):
        return f"ping -n {count} -w 2000 {host}"
    return f"ping -c {count} -W 2 {host}"


def parse_ping(text: str) -> dict[str, Any]:
    loss = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss", text)
    rtt = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", text)                       # Linux/macOS min/avg/max
    win = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", text)
    out: dict[str, Any] = {"loss_pct": float(loss.group(1)) if loss else None}
    if rtt:
        out.update(min_ms=float(rtt.group(1)), avg_ms=float(rtt.group(2)), max_ms=float(rtt.group(3)))
    elif win:
        out.update(min_ms=float(win.group(1)), avg_ms=float(win.group(3)), max_ms=float(win.group(2)))
    return out


class Diagnostics:
    def __init__(self, runner: LocalRunner | None = None, probe: Callable[[str, int, float], str] | None = None,
                 resolver: Callable[[str], list[str]] | None = None) -> None:
        from .discovery import tcp_probe
        self.runner = runner or LocalRunner()
        self.probe = probe or tcp_probe
        self.resolver = resolver or (lambda h: sorted({i[4][0] for i in socket.getaddrinfo(h, None)}))

    def ping(self, host: str, count: int = 4) -> dict[str, Any]:
        r = self.runner.run(ping_command(host, count), timeout=count * 3 + 5)
        return {"host": host, "ok": r.ok, **parse_ping(r.stdout), "output": r.stdout[-4000:] or r.stderr[-1000:]}

    def traceroute(self, host: str) -> dict[str, Any]:
        h = valid_target(host)
        cmd = f"tracert -d -h 20 {h}" if sys.platform.startswith("win") else f"traceroute -n -m 20 -w 2 {h}"
        r = self.runner.run(cmd, timeout=90)
        return {"host": h, "ok": r.ok, "output": (r.stdout or r.stderr)[-8000:]}

    def dns(self, name: str) -> dict[str, Any]:
        h = valid_target(name)
        t0 = time.perf_counter()
        try:
            addrs = self.resolver(h)
            ok = True
        except OSError as exc:
            addrs, ok = [str(exc)], False
        return {"name": h, "ok": ok, "addresses": addrs, "ms": round((time.perf_counter() - t0) * 1000, 1)}

    def tcp(self, host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
        h = valid_target(host)
        if not 1 <= int(port) <= 65535:
            raise ValidationError("Port must be 1-65535.")
        t0 = time.perf_counter()
        state = self.probe(h, int(port), timeout)
        return {"host": h, "port": int(port), "state": state, "ok": state == "open",
                "ms": round((time.perf_counter() - t0) * 1000, 1)}


# ---------------------------------------------------------------- topology
TIERS = {"router": 0, "firewall": 0, "switch": 1, "access_point": 2, "hypervisor": 2, "docker_host": 2, "server": 2,
         "nas": 2, "storage": 2, "appliance": 2, "desktop": 3, "laptop": 3, "printer": 3, "iot": 3, "vm": 4,
         "container": 5, "service": 5, "unknown": 3}


def topology(assets: Iterable[Asset]) -> dict[str, Any]:
    items = list(assets)
    ids = {a.id for a in items}
    nodes = [{"id": a.id, "name": a.name, "kind": a.kind, "status": a.status, "ip": a.ip, "tier": TIERS.get(a.kind, 3),
              "source": a.source} for a in items]
    edges, seen = [], set()
    for a in items:
        if a.parent and a.parent in ids:
            key = (a.id, a.parent, "runs_on")
            if key not in seen:
                seen.add(key)
                edges.append({"from": a.id, "to": a.parent, "type": "runs_on", "label": ""})
        for lk in a.links:
            if lk.get("to") not in ids:
                continue
            pair = tuple(sorted((a.id, lk["to"]))) + (lk["type"],)
            if pair in seen:
                continue
            seen.add(pair)
            edges.append({"from": a.id, "to": lk["to"], "type": lk["type"], "label": lk.get("port", "")})
    return {"nodes": nodes, "edges": edges}
