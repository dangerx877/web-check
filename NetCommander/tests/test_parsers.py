"""parsers.py: vendor neighbor parsers, TextFSM normalization, the parser_key=None guard, link resolution."""
from __future__ import annotations

import pytest
from conftest import FakeConn

from netcommander import network
from netcommander.config import VENDOR_PROFILES
from netcommander.parsers import (
    RAW_PARSERS,
    _parse_arista_lldp,
    _parse_cisco_cdp,
    _parse_cisco_lldp,
    _parse_comware_lldp,
    _parse_huawei_lldp,
    _parse_junos_lldp,
    _parse_linux_lldpctl,
    _parse_mikrotik_nbr,
    _pick_port,
    _run_discovery_cmd,
    apply_discovered_links,
    normalize_hostname,
    normalize_textfsm,
    resolve_neighbor,
    shorten_intf,
)
from netcommander.store import make_device

DASHES = "-" * 30


# ---------------------------------------------------------------- hostnames / interfaces
@pytest.mark.parametrize("raw,expected", [
    ("sw1.lab.local", "SW1"), ("  Core R1 ", "CORER1"), ('"edge2"', "EDGE2"), ("", ""), (None, ""),
    ("10.0.0.1", "10.0.0.1"), ("0011.2233.4455", "0011.2233.4455"), ("00:11:22:33:44:55", "00:11:22:33:44:55"),
])
def test_normalize_hostname(raw, expected):
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("GigabitEthernet0/1", "Gi0/1"), ("TenGigabitEthernet1/0/1", "Te1/0/1"), ("FastEthernet0/24", "Fa0/24"),
    ("Port-channel5", "Po5"), ("HundredGigE0/0/0/1", "Hu0/0/0/1"), ("Ethernet49", "Eth49"),
    ("ae0", "ae0"), ("ether1", "ether1"), ("Gi0/1", "Gi0/1"),
])
def test_shorten_intf(raw, expected):
    assert shorten_intf(raw) == expected


def test_pick_port_prefers_interface_name_over_mac_chassis_style_ids():
    assert _pick_port("Gi0/2", "desc") == "Gi0/2"
    assert _pick_port("0011.2233.4455", "uplink to core") == "uplink to core"
    assert _pick_port("0011.2233.4455", "not advertised") == "0011.2233.4455"
    assert _pick_port("", "") == ""


# ---------------------------------------------------------------- raw vendor parsers
class TestCisco:
    LLDP = (
        f"{DASHES}\nLocal Intf: Gi0/1\nChassis id: 0011.2233.4455\nPort id: Gi0/2\n"
        f"Port Description: to-core\nSystem Name: sw2.lab\n\nManagement Addresses:\n    IP: 10.0.0.2\n"
        f"{DASHES}\nLocal Intf: Gi0/3\nPort id: 0011.2233.4466\nPort Description: access uplink\n"
        f"System Name: sw3.lab\n{DASHES}\n"
    )
    CDP = (
        f"{DASHES}\nDevice ID: SW3.lab\nEntry address(es):\n  IP address: 10.0.0.3\n"
        f"Platform: cisco WS-C3850,  Capabilities: Switch IGMP\n"
        f"Interface: GigabitEthernet0/3,  Port ID (outgoing port): GigabitEthernet0/4\n"
        f"{DASHES}\nDevice ID: router9\nInterface: Gi0/9,  Port ID (outgoing port): Gi0/10\n"
    )

    def test_lldp(self):
        a, b = _parse_cisco_lldp(self.LLDP)
        assert (a["neighbor"], a["local_intf"], a["remote_intf"], a["mgmt_ip"]) == ("SW2", "Gi0/1", "Gi0/2", "10.0.0.2")
        assert (b["neighbor"], b["remote_intf"], b["mgmt_ip"]) == ("SW3", "access uplink", "")

    def test_cdp(self):
        a, b = _parse_cisco_cdp(self.CDP)
        assert (a["neighbor"], a["local_intf"], a["remote_intf"], a["mgmt_ip"]) == (
            "SW3", "GigabitEthernet0/3", "GigabitEthernet0/4", "10.0.0.3")
        assert (b["neighbor"], b["mgmt_ip"]) == ("ROUTER9", "")

    def test_blocks_without_required_fields_are_skipped(self):
        assert _parse_cisco_lldp(f"{DASHES}\nLocal Intf: Gi0/1\n{DASHES}\n") == []
        assert _parse_cisco_cdp(f"{DASHES}\nDevice ID: x\n{DASHES}\n") == []


def test_arista_lldp():
    text = (
        "Interface Ethernet1 detected 1 LLDP neighbors:\n\n"
        "  Neighbor 001c.7300.0001/Ethernet49, age 12 seconds\n"
        "  Chassis ID type: MAC address (4)\n  Port ID type   : Interface name (5)\n"
        '  Port ID        : "Ethernet49"\n  System Name: "spine1.lab.local"\n'
        "  Management Address        : 10.1.1.1\n\n"
        "Interface Ethernet2 detected 1 LLDP neighbors:\n\n"
        "  Neighbor 001c.7300.0002/Ethernet50, age 3 seconds\n"
        '  Port ID        : "Ethernet50"\n  System Name: "spine2"\n'
    )
    a, b = _parse_arista_lldp(text)
    assert (a["neighbor"], a["local_intf"], a["remote_intf"], a["mgmt_ip"]) == ("SPINE1", "Ethernet1", "Ethernet49", "10.1.1.1")
    assert (b["neighbor"], b["local_intf"], b["remote_intf"]) == ("SPINE2", "Ethernet2", "Ethernet50")


def test_junos_lldp_skips_header():
    text = (
        "Local Interface    Parent Interface    Chassis Id          Port info          System Name\n"
        "ge-0/0/0           -                   00:11:22:33:44:55   ge-0/0/1           sw2.lab\n"
        "ge-0/0/1           -                   00:11:22:33:44:66   xe-0/1/0           core1\n"
    )
    recs = _parse_junos_lldp(text)
    assert [(r["neighbor"], r["local_intf"], r["remote_intf"]) for r in recs] == [
        ("SW2", "ge-0/0/0", "ge-0/0/1"), ("CORE1", "ge-0/0/1", "xe-0/1/0")]


def test_huawei_lldp_brief():
    text = (
        "Local Intf       Neighbor Dev             Neighbor Intf             Exptime(s)\n"
        "GE0/0/1          SW2                      GE0/0/2                   110\n"
        "GE0/0/3          edge.lab                 XGE0/0/1                  95\n"
    )
    recs = _parse_huawei_lldp(text)
    assert [(r["neighbor"], r["local_intf"], r["remote_intf"]) for r in recs] == [
        ("SW2", "GE0/0/1", "GE0/0/2"), ("EDGE", "GE0/0/3", "XGE0/0/1")]


def test_comware_lldp_list():
    text = (
        "Local Interface  Chassis ID       Port ID               System Name\n"
        "GE1/0/1          0011-2233-4455   GigabitEthernet1/0/2  SW3\n"
    )
    (rec,) = _parse_comware_lldp(text)
    assert (rec["neighbor"], rec["local_intf"], rec["remote_intf"]) == ("SW3", "GE1/0/1", "GigabitEthernet1/0/2")


def test_mikrotik_neighbors():
    text = (
        ' 0 interface=ether1 address=10.0.0.2 mac-address=AA:BB:CC:DD:EE:FF identity="SW4" '
        'platform="MikroTik" interface-name=ether2\n'
        ' 1 interface=ether5 address=10.0.0.9 identity=EDGE-9 port-id=sfp1\n'
    )
    a, b = _parse_mikrotik_nbr(text)
    assert (a["neighbor"], a["local_intf"], a["remote_intf"], a["mgmt_ip"]) == ("SW4", "ether1", "ether2", "10.0.0.2")
    assert (b["neighbor"], b["remote_intf"]) == ("EDGE-9", "sfp1")


def test_linux_lldpctl_keyvalue():
    text = (
        "lldp.eth0.via=LLDP\nlldp.eth0.chassis.name=sw5.lab\nlldp.eth0.chassis.mgmt-ip=10.0.0.5\n"
        "lldp.eth0.port.ifname=Gi0/5\nlldp.eth0.port.descr=uplink\n"
        "lldp.eth1.chassis.name=sw6\nlldp.eth1.port.id=aa:bb:cc:dd:ee:ff\nlldp.eth1.port.descr=eth-to-lab\n"
        "lldp.eth2.chassis.mgmt-ip=10.9.9.9\n"                         # no name -> dropped
    )
    a, b = _parse_linux_lldpctl(text)
    assert (a["neighbor"], a["local_intf"], a["remote_intf"], a["mgmt_ip"]) == ("SW5", "eth0", "Gi0/5", "10.0.0.5")
    assert (b["neighbor"], b["remote_intf"]) == ("SW6", "eth-to-lab")


@pytest.mark.parametrize("key", sorted(RAW_PARSERS))
def test_every_raw_parser_tolerates_empty_and_garbage(key):
    assert RAW_PARSERS[key]("") == []
    assert RAW_PARSERS[key]("% Invalid input detected at '^' marker.\n") == []


# ---------------------------------------------------------------- TextFSM normalization
class TestTextFsm:
    def test_field_name_variants_are_unified(self):
        rows = [
            {"neighbor_name": "SW2.lab", "local_interface": "Gi0/1", "neighbor_interface": "Gi0/2", "mgmt_ip": "10.0.0.2"},
            {"destination_host": "SW3", "local_port": "Gi0/2", "port_id": "Gi0/9", "management_ip": ["10.0.0.3"]},
            {"system_name": "SW4", "interface": "Gi0/3", "port_description": "uplink", "ip_address": ""},
        ]
        recs = normalize_textfsm(rows)
        assert [(r["neighbor"], r["local_intf"], r["remote_intf"], r["mgmt_ip"]) for r in recs] == [
            ("SW2", "Gi0/1", "Gi0/2", "10.0.0.2"),
            ("SW3", "Gi0/2", "Gi0/9", "10.0.0.3"),
            ("SW4", "Gi0/3", "uplink", ""),
        ]

    def test_rows_without_a_name_or_not_dicts_are_dropped(self):
        assert normalize_textfsm([{"local_interface": "Gi0/1"}, "junk", None, {"neighbor": ""}]) == []


# ---------------------------------------------------------------- _run_discovery_cmd
class TestRunDiscoveryCmd:
    def test_textfsm_list_is_normalized(self):
        conn = FakeConn(textfsm=[{"neighbor": "SW2", "local_interface": "Gi0/1", "neighbor_interface": "Gi0/2"}])
        assert _run_discovery_cmd(conn, "show lldp neighbors detail", "cisco_lldp")[0]["neighbor"] == "SW2"

    def test_raw_string_uses_named_parser(self):
        conn = FakeConn(raw=TestCisco.LLDP)
        assert [r["neighbor"] for r in _run_discovery_cmd(conn, "x", "cisco_lldp")] == ["SW2", "SW3"]

    def test_textfsm_exception_falls_back_to_raw(self):
        conn = FakeConn(textfsm=ValueError("no template"), raw=TestCisco.CDP)
        assert [r["neighbor"] for r in _run_discovery_cmd(conn, "x", "cisco_cdp")] == ["SW3", "ROUTER9"]

    @pytest.mark.parametrize("dtype", ["nokia_sros", "extreme_exos", "paloalto_panos"])
    def test_str_output_with_parser_key_none_returns_empty_instead_of_keyerror(self, dtype):
        (cmd, _proto, key), = VENDOR_PROFILES[dtype]["discovery"]
        assert key is None
        conn = FakeConn(raw="Local Port | ChassisType ChassisId  PortType PortId  SysName\n--- | ---\n")
        assert _run_discovery_cmd(conn, cmd, key) == []

    def test_unknown_parser_key_returns_empty_not_keyerror(self):
        assert _run_discovery_cmd(FakeConn(raw="whatever"), "x", "not_a_parser") == []

    def test_non_str_non_list_output_returns_empty(self):
        conn = FakeConn(textfsm={"unexpected": "dict"})
        assert _run_discovery_cmd(conn, "x", "cisco_lldp") == []

    def test_empty_textfsm_list_is_empty(self):
        assert _run_discovery_cmd(FakeConn(textfsm=[]), "x", "cisco_lldp") == []

    @pytest.mark.parametrize("dtype", ["nokia_sros", "extreme_exos", "paloalto_panos"])
    def test_whole_discovery_run_survives_parserless_profiles(self, fake_conn, dtype):
        fake_conn(FakeConn(raw="some unparsed output"))
        assert network.discover_neighbors_via_ssh({"device_type": dtype, "host": "1.1.1.1"}, ("u", "p", "")) == []

    def test_one_failing_protocol_does_not_stop_the_others(self, fake_conn):
        class CdpDisabled(FakeConn):
            def send_command(self, cmd, **kw):
                if "cdp" in cmd:
                    raise OSError("% CDP is not enabled")
                return self.raw
        fake_conn(CdpDisabled(raw=TestCisco.LLDP))
        got = network.discover_neighbors_via_ssh({"device_type": "cisco_ios", "host": "1.1.1.1"}, ("u", "p", ""))
        assert [r["neighbor"] for r in got] == ["SW2", "SW3"] and {r["protocol"] for r in got} == {"LLDP"}

    def test_single_protocol_failure_propagates(self, fake_conn):
        class Broken(FakeConn):
            def send_command(self, cmd, **kw):
                raise OSError("channel closed")
        fake_conn(Broken())
        with pytest.raises(OSError):
            network.discover_neighbors_via_ssh({"device_type": "arista_eos", "host": "1.1.1.1"}, ("u", "p", ""))

    def test_duplicate_neighbor_on_same_port_reported_once(self, fake_conn):
        both = TestCisco.LLDP + "\n" + TestCisco.CDP.replace("GigabitEthernet0/3,", "Gi0/3,")
        class Both(FakeConn):
            def send_command(self, cmd, **kw):
                return TestCisco.LLDP if "lldp" in cmd else TestCisco.CDP
        fake_conn(Both())
        got = network.discover_neighbors_via_ssh({"device_type": "cisco_ios", "host": "1.1.1.1"}, ("u", "p", ""))
        keys = [(r["neighbor"], r["local_intf"]) for r in got]
        assert len(keys) == len(set(keys)) and both

    def test_fortinet_has_no_discovery_and_never_connects(self, monkeypatch):
        monkeypatch.setattr(network, "open_connection", lambda *a, **k: pytest.fail("must not connect"))
        assert network.discover_neighbors_via_ssh({"device_type": "fortinet", "host": "1.1.1.1"}, ("u", "p", "")) == []


# ---------------------------------------------------------------- link resolution
def _inv():
    return {"A": make_device({"host": "1.1.1.1"}), "B": make_device({"host": "2.2.2.2"}),
            "C": make_device({"host": "3.3.3.3"})}


class TestResolveAndApply:
    def test_resolve_by_name_then_ip(self):
        d = _inv()
        assert resolve_neighbor(d, "A") == "A"
        assert resolve_neighbor(d, "OTHER", "2.2.2.2") == "B"
        assert resolve_neighbor(d, "OTHER", "9.9.9.9") is None
        assert resolve_neighbor(d, "OTHER") is None

    def test_links_applied_on_both_ends_via_mgmt_ip(self):
        d = _inv()
        lines = apply_discovered_links(d, "A", [{"neighbor": "SOMETHING", "local_intf": "Gi1",
                                                  "remote_intf": "Gi2", "mgmt_ip": "2.2.2.2", "protocol": "LLDP"}])
        assert d["A"]["peers"] == ["B"] and d["B"]["peers"] == ["A"]
        assert d["A"]["links"]["B"] == {"local_intf": "Gi1", "remote_intf": "Gi2", "protocol": "LLDP"}
        assert d["B"]["links"]["A"] == {"local_intf": "Gi2", "remote_intf": "Gi1", "protocol": "LLDP"}
        assert lines == ["A[Gi1] <-> B[Gi2] (LLDP)"]

    def test_unknown_neighbor_listed_but_not_linked(self):
        d = _inv()
        (line,) = apply_discovered_links(d, "A", [{"neighbor": "GHOST", "local_intf": "Gi1", "remote_intf": ""}])
        assert "[not in inventory]" in line and "GHOST[?]" in line and d["A"]["peers"] == []

    def test_self_link_ignored(self):
        d = _inv()
        apply_discovered_links(d, "A", [{"neighbor": "A", "local_intf": "Lo0", "remote_intf": "Lo1"}])
        assert d["A"]["peers"] == [] and d["A"]["links"] == {}

    def test_missing_source_is_noop(self):
        d = _inv()
        assert apply_discovered_links(d, "ZZZ", [{"neighbor": "A"}]) == []

    def test_existing_reverse_link_info_is_not_clobbered(self):
        d = _inv()
        d["B"]["links"]["A"] = {"local_intf": "keep", "remote_intf": "keep", "protocol": "CDP"}
        apply_discovered_links(d, "A", [{"neighbor": "B", "local_intf": "Gi1", "remote_intf": "Gi2", "protocol": "LLDP"}])
        assert d["B"]["links"]["A"]["local_intf"] == "keep"

    def test_peers_stay_sorted_and_unique(self):
        d = _inv()
        nbrs = [{"neighbor": "C", "local_intf": "1", "remote_intf": "1"}, {"neighbor": "B", "local_intf": "2", "remote_intf": "2"},
                {"neighbor": "C", "local_intf": "3", "remote_intf": "3"}]
        apply_discovered_links(d, "A", nbrs)
        assert d["A"]["peers"] == ["B", "C"]
