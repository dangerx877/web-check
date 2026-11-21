"""Docker / container management through the official Docker Engine API.

Connect with the local Unix socket (``unix:///var/run/docker.sock``), over SSH-forwarded sockets, or
``tcp://host:2376`` with **mutual TLS** (``ca_file`` + ``client_cert`` + ``client_key``, the same files
``docker --tlsverify`` uses). Unauthenticated ``tcp://host:2375`` is refused unless explicitly allowed:
it gives root on the host to anyone who can reach the port.

Read operations: containers, stats, logs, images, networks, volumes, health, Compose projects.
Write operations (start/stop/restart) exist on the adapter but the platform only calls them after an
authorised, confirmed action (``CONTROL_WORKLOADS``). Nothing here removes containers, images or volumes.
"""
from __future__ import annotations

import re
import struct
import urllib.parse
from collections import defaultdict
from typing import Any

from .core.errors import IntegrationError, ValidationError
from .core.httpclient import HttpClient

CONTAINER_ACTIONS = ("start", "stop", "restart")
ACTION_RISK = {"start": "change", "stop": "destructive", "restart": "destructive"}
_CID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def safe_container(cid: str) -> str:
    if not isinstance(cid, str) or not _CID.match(cid):
        raise ValidationError(f"Invalid container id or name {cid!r}.")
    return cid


def decode_log_stream(data: bytes, tty: bool = False) -> list[tuple[str, str]]:
    """Docker multiplexes stdout/stderr (8-byte frame headers) unless the container has a TTY."""
    if tty:
        return [("stdout", line) for line in data.decode("utf-8", "replace").splitlines()]
    out: list[tuple[str, str]] = []
    i = 0
    while i + 8 <= len(data):
        stream, size = data[i], struct.unpack(">I", data[i + 4:i + 8])[0]
        if stream not in (0, 1, 2) or data[i + 1:i + 4] != b"\x00\x00\x00" or i + 8 + size > len(data):
            break                                       # not a valid frame header
        chunk = data[i + 8:i + 8 + size]
        i += 8 + size
        name = {1: "stdout", 2: "stderr"}.get(stream, "stdout")
        out.extend((name, line) for line in chunk.decode("utf-8", "replace").splitlines())
    if i == 0 and data:                                 # not a multiplexed stream after all
        return [("stdout", line) for line in data.decode("utf-8", "replace").splitlines()]
    return out


def cpu_percent(stats: dict[str, Any]) -> float | None:
    cpu, pre = stats.get("cpu_stats") or {}, stats.get("precpu_stats") or {}
    try:
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu["system_cpu_usage"] - pre["system_cpu_usage"]
    except (KeyError, TypeError):
        return None
    ncpu = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or []) or 1
    if sys_delta <= 0 or cpu_delta < 0:
        return 0.0
    return round(cpu_delta / sys_delta * ncpu * 100.0, 2)


def memory_usage(stats: dict[str, Any]) -> tuple[int, int]:
    m = stats.get("memory_stats") or {}
    usage = int(m.get("usage") or 0)
    st = m.get("stats") or {}
    cache = int(st.get("inactive_file", st.get("total_inactive_file", st.get("cache", 0))) or 0)
    return max(0, usage - cache), int(m.get("limit") or 0)


def health_of(container: dict[str, Any]) -> str:
    """healthy | unhealthy | starting | none (no HEALTHCHECK) | stopped."""
    state = (container.get("State") or "").lower() if isinstance(container.get("State"), str) else \
        str((container.get("State") or {}).get("Status", "")).lower()
    if state != "running":
        return "stopped"
    if isinstance(container.get("State"), dict):
        h = (container["State"].get("Health") or {}).get("Status")
        if h:
            return str(h)
    status = str(container.get("Status", "")).lower()
    for h in ("unhealthy", "healthy", "health: starting"):
        if f"({h})" in status:
            return "starting" if "starting" in h else h
    return "none"


class DockerAdapter:
    platform = "docker"

    def __init__(self, url: str = "unix:///var/run/docker.sock", ca_file: str = "", client_cert: str = "",
                 client_key: str = "", allow_insecure_tcp: bool = False, timeout: float = 20.0,
                 transport: Any = None, host_name: str = "") -> None:
        u = urllib.parse.urlsplit(url)
        self.host_name = host_name or (u.hostname or "local")
        if u.scheme == "unix":
            self.http = HttpClient("http://localhost", unix_socket=u.path, timeout=timeout, transport=transport)
        elif u.scheme in ("tcp", "https"):
            port = u.port or 2376
            tls = bool(client_cert) or u.scheme == "https" or port == 2376
            if not tls and not allow_insecure_tcp:
                raise ValidationError("Docker over plain TCP (port 2375) is unauthenticated root access to the host. "
                                      "Use TLS (client certificates) or SSH, or explicitly allow insecure TCP.")
            base = f"{'https' if tls else 'http'}://{u.hostname}:{port}"
            self.http = HttpClient(base, ca_file=ca_file or None, client_cert=client_cert or None,
                                   client_key=client_key or None, allow_http=allow_insecure_tcp, timeout=timeout,
                                   transport=transport)
        else:
            raise ValidationError(f"Docker URL must be unix://, tcp:// or https://, got {url!r}.")

    # ---- reads ----------------------------------------------------------
    def info(self) -> dict[str, Any]:
        i = self.http.get("/info") or {}
        return {"name": i.get("Name", self.host_name), "version": i.get("ServerVersion", ""), "cpus": i.get("NCPU", 0),
                "mem_total": i.get("MemTotal", 0), "os": i.get("OperatingSystem", ""), "containers": i.get("Containers", 0),
                "running": i.get("ContainersRunning", 0), "stopped": i.get("ContainersStopped", 0),
                "images": i.get("Images", 0), "swarm": (i.get("Swarm") or {}).get("LocalNodeState", "inactive")}

    def containers(self, all_: bool = True) -> list[dict[str, Any]]:
        out = []
        for c in self.http.get("/containers/json", params={"all": 1 if all_ else 0}) or []:
            labels = c.get("Labels") or {}
            out.append({
                "id": c.get("Id", "")[:12], "full_id": c.get("Id", ""), "name": (c.get("Names") or ["/?"])[0].lstrip("/"),
                "image": c.get("Image", ""), "state": c.get("State", ""), "status": c.get("Status", ""),
                "health": health_of(c), "created": c.get("Created"),
                "ports": [f"{p.get('IP', '')}:{p.get('PublicPort')}->{p.get('PrivatePort')}/{p.get('Type')}"
                          if p.get("PublicPort") else f"{p.get('PrivatePort')}/{p.get('Type')}" for p in c.get("Ports") or []],
                "networks": sorted((c.get("NetworkSettings") or {}).get("Networks", {}) or {}),
                "mounts": [{"type": m.get("Type"), "source": m.get("Name") or m.get("Source"), "dest": m.get("Destination")}
                           for m in c.get("Mounts") or []],
                "compose_project": labels.get("com.docker.compose.project", ""),
                "compose_service": labels.get("com.docker.compose.service", ""),
            })
        return out

    def inspect(self, cid: str) -> dict[str, Any]:
        d = self.http.get(f"/containers/{safe_container(cid)}/json") or {}
        env = (d.get("Config") or {}).get("Env") or []
        if env:                                         # never expose environment variable values (secrets)
            d.setdefault("Config", {})["Env"] = [e.split("=", 1)[0] + "=********" for e in env]
        return d

    def stats(self, cid: str) -> dict[str, Any]:
        s = self.http.get(f"/containers/{safe_container(cid)}/stats", params={"stream": "false"}) or {}
        used, limit = memory_usage(s)
        nets = s.get("networks") or {}
        blk = (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
        return {"cpu_pct": cpu_percent(s), "mem_used": used, "mem_limit": limit,
                "mem_pct": round(100.0 * used / limit, 1) if limit else None,
                "net_rx": sum(int(n.get("rx_bytes", 0)) for n in nets.values()),
                "net_tx": sum(int(n.get("tx_bytes", 0)) for n in nets.values()),
                "blk_read": sum(int(b.get("value", 0)) for b in blk if str(b.get("op", "")).lower() == "read"),
                "blk_write": sum(int(b.get("value", 0)) for b in blk if str(b.get("op", "")).lower() == "write"),
                "pids": (s.get("pids_stats") or {}).get("current")}

    def logs(self, cid: str, tail: int = 200, since: int | None = None) -> list[dict[str, str]]:
        tail = max(1, min(int(tail), 5000))
        tty = bool(((self.inspect(cid).get("Config")) or {}).get("Tty"))
        _st, _h, data = self.http.request_raw("GET", f"/containers/{safe_container(cid)}/logs", params={
            "stdout": 1, "stderr": 1, "tail": tail, "timestamps": 1, "since": since})
        if _st >= 400:
            raise IntegrationError(f"logs for {cid}: HTTP {_st}", _st)
        return [{"stream": s, "line": line} for s, line in decode_log_stream(data, tty)]

    def images(self) -> list[dict[str, Any]]:
        return [{"id": i.get("Id", "").split(":")[-1][:12], "tags": i.get("RepoTags") or [], "size": i.get("Size", 0),
                 "created": i.get("Created"), "containers": i.get("Containers", -1)}
                for i in self.http.get("/images/json") or []]

    def networks(self) -> list[dict[str, Any]]:
        return [{"id": n.get("Id", "")[:12], "name": n.get("Name"), "driver": n.get("Driver"), "scope": n.get("Scope"),
                 "subnets": [c.get("Subnet") for c in ((n.get("IPAM") or {}).get("Config") or []) if c.get("Subnet")],
                 "internal": n.get("Internal", False)} for n in self.http.get("/networks") or []]

    def volumes(self) -> list[dict[str, Any]]:
        res = self.http.get("/volumes") or {}
        return [{"name": v.get("Name"), "driver": v.get("Driver"), "mountpoint": v.get("Mountpoint"),
                 "created": v.get("CreatedAt"), "labels": v.get("Labels") or {}} for v in res.get("Volumes") or []]

    def compose_projects(self, containers: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """Deployment status per Compose project (from the labels Compose puts on every container)."""
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for c in containers if containers is not None else self.containers():
            if c["compose_project"]:
                groups[c["compose_project"]].append(c)
        out = []
        for name, items in sorted(groups.items()):
            running = sum(1 for c in items if c["state"] == "running")
            unhealthy = sum(1 for c in items if c["health"] == "unhealthy")
            status = "healthy" if running == len(items) and not unhealthy else ("down" if running == 0 else "degraded")
            out.append({"project": name, "services": sorted({c["compose_service"] for c in items}),
                        "containers": len(items), "running": running, "unhealthy": unhealthy, "status": status})
        return out

    # ---- writes (called only after authorisation) -------------------------------
    def action(self, cid: str, action: str, timeout: int = 10) -> str:
        if action not in CONTAINER_ACTIONS:
            raise ValidationError(f"Unknown container action {action!r}.")
        params = {"t": int(timeout)} if action in ("stop", "restart") else None
        status, _h, data = self.http.request_raw("POST", f"/containers/{safe_container(cid)}/{action}", params=params)
        if status == 304:
            return "already in that state"
        if status >= 400:
            raise IntegrationError(f"{action} {cid}: HTTP {status} {data[:200].decode('utf-8', 'replace')}", status)
        return "ok"


def container_observation(c: dict[str, Any], integration: str, host_asset: str, stats: dict[str, Any] | None = None) -> dict[str, Any]:
    s = stats or {}
    status = "online" if c["state"] == "running" else ("paused" if c["state"] == "paused" else "stopped")
    if c["health"] == "unhealthy":
        status = "degraded"
    return {"name": c["name"], "kind": "container", "status": status, "integration": integration,
            "external_id": c["full_id"] or c["id"], "parent": host_asset, "cpu_pct": s.get("cpu_pct"),
            "mem_total": s.get("mem_limit") or 0, "mem_used": s.get("mem_used") or 0, "source": "integration",
            "services": [{"name": p, "proto": "tcp"} for p in c["ports"]],
            "extra": {"image": c["image"], "health": c["health"], "status_text": c["status"],
                      "compose_project": c["compose_project"], "compose_service": c["compose_service"],
                      "networks": c["networks"], "mounts": c["mounts"]}}
