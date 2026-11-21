"""Neighbor-discovery parsing: TextFSM normalization, raw vendor parsers, link resolution.

Everything here is pure (no network, no I/O) except :func:`_run_discovery_cmd`,
which only needs an object with a Netmiko-style ``send_command`` method.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Callable, Iterable, Mapping

__all__ = [
    "RAW_PARSERS", "apply_discovered_links", "normalize_hostname", "normalize_textfsm",
    "resolve_neighbor", "shorten_intf",
]

log = logging.getLogger(__name__)

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_MACISH = re.compile(r"^([0-9a-fA-F]{4}[.-]){2}[0-9a-fA-F]{4}$|^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")

_INTF_ABBR = (
    ("HundredGigE", "Hu"), ("FortyGigabitEthernet", "Fo"), ("TwentyFiveGigE", "Twe"),
    ("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"),
    ("Port-channel", "Po"), ("Ethernet", "Eth"), ("ae", "ae"),
)


def normalize_hostname(raw_name: str) -> str:
    """Upper-case short hostname (domain stripped); IPs and MAC-like IDs are kept whole."""
    raw = (raw_name or "").strip().strip('"')
    if not raw:
        return ""
    short = raw if (_IPV4.match(raw) or _MACISH.match(raw)) else raw.split(".")[0]
    return re.sub(r"\s+", "", short).upper()


def shorten_intf(name: str) -> str:
    for long, short in _INTF_ABBR:
        if name.startswith(long) and long != short:
            return short + name[len(long):]
    return name


# ======================================================================
# Record construction / TextFSM normalization
# ======================================================================
def _record(name: str, local: str, remote: str, mgmt_ip: str = "") -> dict | None:
    nbr = normalize_hostname(name)
    if not nbr:
        return None
    return {
        "neighbor": nbr,
        "local_intf": (local or "").strip(),
        "remote_intf": (remote or "").strip(),
        "mgmt_ip": (mgmt_ip or "").strip(),
    }


def _first(entry: Mapping[str, Any], keys: Iterable[str]) -> str:
    for k in keys:
        v = entry.get(k)
        if isinstance(v, list):
            v = v[0] if v else ""
        if v:
            return str(v).strip()
    return ""


def normalize_textfsm(rows: list[dict]) -> list[dict]:
    """Map the differing field names of ntc-templates onto one neighbor record shape."""
    out = []
    for e in rows:
        if not isinstance(e, Mapping):
            continue
        rec = _record(
            _first(e, ("neighbor", "neighbor_name", "system_name", "destination_host",
                       "chassis_name", "sysname", "device_id")),
            _first(e, ("local_interface", "local_port", "local_intf", "interface")),
            _first(e, ("neighbor_interface", "neighbor_port_id", "remote_port", "port_id",
                       "port_description", "neighbor_port")),
            _first(e, ("management_ip", "mgmt_ip", "mgmt_address", "management_address",
                       "mgmt_ip_address", "ip_address")),
        )
        if rec:
            out.append(rec)
    return out


# ======================================================================
# Raw vendor parsers (fallback when no TextFSM template exists)
# ======================================================================
def _pick_port(port_id: str, port_desc: str) -> str:
    port_id = (port_id or "").strip()
    port_desc = (port_desc or "").strip()
    if port_id and not _MACISH.match(port_id):
        return port_id
    if port_desc and "not advertised" not in port_desc.lower():
        return port_desc
    return port_id


def _search(pattern: str, text: str, flags: int = 0) -> str:
    m = re.search(pattern, text, flags)
    return m.group(1).strip().strip('"') if m else ""


def _parse_cisco_lldp(text: str) -> list[dict]:
    out = []
    for block in re.split(r"^-{10,}\s*$", text, flags=re.M):
        local = _search(r"Local Intf:\s*(\S+)", block)
        name = _search(r"System Name:\s*(.+)", block)
        if not (local and name):
            continue
        remote = _pick_port(
            _search(r"^Port id:\s*(.+)$", block, re.M | re.I),
            _search(r"^Port Description:\s*(.+)$", block, re.M | re.I),
        )
        ip = _search(r"Management Addresses:.*?IP:\s*(\d+\.\d+\.\d+\.\d+)", block, re.S)
        rec = _record(name, local, remote, ip)
        if rec:
            out.append(rec)
    return out


def _parse_cisco_cdp(text: str) -> list[dict]:
    out = []
    for block in re.split(r"^-{10,}\s*$", text, flags=re.M):
        dev = _search(r"Device ID:\s*(\S+)", block)
        m = re.search(r"Interface:\s*([^,\s]+),\s*Port ID \(outgoing port\):\s*(\S+)", block)
        if not (dev and m):
            continue
        ip = _search(r"IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)", block)
        rec = _record(dev, m.group(1), m.group(2), ip)
        if rec:
            out.append(rec)
    return out


def _parse_arista_lldp(text: str) -> list[dict]:
    out = []
    sections = re.split(r"^Interface (\S+) detected \d+ LLDP neighbors?:", text, flags=re.M)
    for i in range(1, len(sections) - 1, 2):
        local, body = sections[i], sections[i + 1]
        for nb in re.split(r"\n\s+Neighbor ", body)[1:]:
            port_id = _search(r'Port ID\s*:\s*"?([^"\n]+?)"?\s*$', nb, re.M)
            port_desc = _search(r'Port Description:\s*"?([^"\n]+?)"?\s*$', nb, re.M)
            name = _search(r'System Name:\s*"?([^"\n]+?)"?\s*$', nb, re.M)
            ip = _search(r"Management Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", nb)
            rec = _record(name, local, _pick_port(port_id, port_desc), ip)
            if rec:
                out.append(rec)
    return out


def _parse_junos_lldp(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 5 and not line.lower().startswith("local interface"):
            rec = _record(parts[4], parts[0], parts[3])
            if rec:
                out.append(rec)
    return out


def _parse_huawei_lldp(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[-1].isdigit() and re.match(r"^[A-Za-z\-]+\d", parts[0]):
            rec = _record(parts[1], parts[0], parts[2])
            if rec:
                out.append(rec)
    return out


def _parse_comware_lldp(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and re.match(r"^[A-Za-z\-]+\d", parts[0]):
            rec = _record(parts[3], parts[0], parts[2])
            if rec:
                out.append(rec)
    return out


def _slice_cols(header: str, names: list[str]) -> dict[str, tuple[int, int | None]]:
    """Column spans taken from a fixed-width header row (values may contain spaces)."""
    pos = [(n, header.find(n)) for n in names]
    if any(i < 0 for _, i in pos):
        return {}
    pos.sort(key=lambda t: t[1])
    return {n: (i, pos[k + 1][1] if k + 1 < len(pos) else None) for k, (n, i) in enumerate(pos)}


def _parse_procurve_lldp(text: str) -> list[dict]:
    """HPE/Aruba ProCurve ``show lldp info remote-device`` (fixed-width table)."""
    out: list[dict] = []
    cols: dict[str, tuple[int, int | None]] = {}
    for line in text.splitlines():
        if "LocalPort" in line and "SysName" in line:
            cols = _slice_cols(line, ["LocalPort", "PortId", "PortDescr", "SysName"])
            continue
        if not cols or "|" not in line or set(line.strip()) <= set("-+ |"):
            continue
        def cell(n: str, line: str = line, cols: dict[str, tuple[int, int | None]] = cols) -> str:
            a, b = cols[n]
            return line[a:b].strip()
        rec = _record(cell("SysName"), line.split("|", 1)[0].strip(), _pick_port(cell("PortId"), cell("PortDescr")))
        if rec:
            out.append(rec)
    return out


def _parse_os10_lldp(text: str) -> list[dict]:
    """Dell OS10 ``show lldp neighbors``: ``Loc PortID  Rem Host Name  Rem Port Id  Rem Chassis Id``."""
    out: list[dict] = []
    for line in text.splitlines():
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 3 and re.match(r"(?i)^(ethernet|mgmt|port-channel|vlan)", parts[0]):
            rec = _record(parts[1], parts[0], parts[2])
            if rec:
                out.append(rec)
    return out


def _parse_srl_lldp(text: str) -> list[dict]:
    """Nokia SR Linux box-drawing table; columns located by header name."""
    out: list[dict] = []
    idx: dict[str, int] = {}
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if "Neighbor System Name" in cells and "Neighbor Port" in cells:
            idx = {"local": 0, "name": cells.index("Neighbor System Name"), "port": cells.index("Neighbor Port")}
            continue
        if idx and len(cells) > max(idx.values()) and cells[idx["local"]]:
            rec = _record(cells[idx["name"]], cells[idx["local"]], cells[idx["port"]])
            if rec:
                out.append(rec)
    return out


def _parse_mikrotik_nbr(text: str) -> list[dict]:
    out = []
    for block in re.split(r"^\s*\d+\s", text, flags=re.M):
        kv = {k: v.strip('"') for k, v in re.findall(r'([\w-]+)=("[^"]*"|\S+)', block)}
        rec = _record(
            kv.get("identity", ""), kv.get("interface", ""),
            kv.get("interface-name", "") or kv.get("port-id", ""),
            kv.get("address", ""),
        )
        if rec:
            out.append(rec)
    return out


def _parse_linux_lldpctl(text: str) -> list[dict]:
    grouped: dict[str, dict] = {}
    for m in re.finditer(r"^lldp\.([^.=]+)\.(.+?)=(.*)$", text, flags=re.M):
        grouped.setdefault(m.group(1), {})[m.group(2)] = m.group(3).strip()
    out = []
    for intf, kv in grouped.items():
        remote = _pick_port(kv.get("port.ifname", "") or kv.get("port.id", ""),
                            kv.get("port.descr", ""))
        rec = _record(kv.get("chassis.name", ""), intf, remote, kv.get("chassis.mgmt-ip", ""))
        if rec:
            out.append(rec)
    return out


RAW_PARSERS: dict[str, Callable[[str], list[dict]]] = {
    "cisco_lldp": _parse_cisco_lldp,
    "cisco_cdp": _parse_cisco_cdp,
    "arista_lldp": _parse_arista_lldp,
    "junos_lldp": _parse_junos_lldp,
    "huawei_lldp": _parse_huawei_lldp,
    "comware_lldp": _parse_comware_lldp,
    "mikrotik_nbr": _parse_mikrotik_nbr,
    "linux_lldpctl": _parse_linux_lldpctl,
    "procurve_lldp": _parse_procurve_lldp,
    "os10_lldp": _parse_os10_lldp,
    "srl_lldp": _parse_srl_lldp,
}


def _run_discovery_cmd(conn: Any, cmd: str, parser_key: str | None) -> list[dict]:
    """Run one discovery command and return normalized neighbor records.

    * TextFSM output (a list of dicts) is normalized directly.
    * Raw text is handed to the parser registered under ``parser_key``.
    * Raw text with ``parser_key=None`` (profiles such as hp_procurve, dell_os10,
      extreme_exos, paloalto_panos have no raw parser) or an unknown key yields
      ``[]`` instead of raising ``KeyError``.
    """
    try:
        out = conn.send_command(cmd, use_textfsm=True, read_timeout=30)
    except Exception as exc:                      # template/parse problem: retry as raw text
        log.debug("textfsm failed for %r (%s); retrying raw", cmd, exc)
        out = conn.send_command(cmd, read_timeout=30)
    if isinstance(out, list):
        return normalize_textfsm(out)
    if isinstance(out, str):
        parser = RAW_PARSERS.get(parser_key) if parser_key else None
        if parser is None:
            if parser_key:
                log.warning("no raw parser registered for key %r", parser_key)
            return []
        return parser(out)
    return []


# ======================================================================
# Link resolution
# ======================================================================
def resolve_neighbor(devices: Mapping[str, dict], name: str, mgmt_ip: str = "") -> str | None:
    """Inventory name for a discovered neighbor: by hostname first, then by management IP."""
    if name in devices:
        return name
    if mgmt_ip:
        for dev_name, info in devices.items():
            if info["params"].get("host") == mgmt_ip:
                return dev_name
    return None


def apply_discovered_links(devices: dict, source_name: str, neighbors: list[dict]) -> list[str]:
    """Record discovered neighbors on both ends of each link; returns human-readable lines.

    NOT thread-safe on its own: call it through ``DeviceStore.apply_discovery``.
    """
    if source_name not in devices:
        return []

    src_dev = devices[source_name]
    src_peers = set(src_dev.get("peers", []))
    src_links = src_dev.setdefault("links", {})
    lines = []

    for item in neighbors:
        loc_if = item.get("local_intf") or "?"
        rem_if = item.get("remote_intf") or "?"
        proto = item.get("protocol") or "LLDP/CDP"
        target = resolve_neighbor(devices, item["neighbor"], item.get("mgmt_ip", ""))
        shown = target or item["neighbor"]
        tag = "" if target else "  [not in inventory]"
        lines.append(f"{source_name}[{loc_if}] <-> {shown}[{rem_if}] ({proto}){tag}")

        if target and target != source_name:
            src_peers.add(target)
            src_links[target] = {"local_intf": loc_if, "remote_intf": rem_if, "protocol": proto}

            nbr_dev = devices[target]
            nbr_peers = set(nbr_dev.get("peers", []))
            nbr_peers.add(source_name)
            nbr_dev["peers"] = sorted(nbr_peers)
            nbr_links = nbr_dev.setdefault("links", {})
            nbr_links.setdefault(
                source_name, {"local_intf": rem_if, "remote_intf": loc_if, "protocol": proto}
            )

    src_dev["peers"] = sorted(src_peers)
    return lines
