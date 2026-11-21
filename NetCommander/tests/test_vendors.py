"""Vendor-specific behaviour: Juniper, HPE/Aruba, Dell, Nokia, Cisco.

Sample outputs are written from vendor documentation (NOT device captures) - see tests/fixtures/parsers/README.
"""
from __future__ import annotations

import pytest

from netcommander import network
from netcommander.config import COMMIT_PLATFORMS, DISRUPTIVE_CMD, VENDOR_PROFILES, get_profile
from netcommander.parsers import RAW_PARSERS, _run_discovery_cmd
from netcommander.redact import redact_secrets
from netcommander.rollback import STRATEGIES

PROCURVE = """
 LLDP Remote Devices Information

  LocalPort | ChassisId                 PortId PortDescr SysName
  --------- + ------------------------- ------ --------- ----------------------
  1         | 00 11 22 33 44 55         1      Port 1    Core Switch 2
  24        | 00 aa bb cc dd ee         Trk1   Trk1      EDGE-3
"""
OS10 = """
Loc PortID      Rem Host Name   Rem Port Id        Rem Chassis Id
--------------------------------------------------------------------------
ethernet1/1/1   leaf2           ethernet1/1/5      aa:bb:cc:dd:ee:01
ethernet1/1/2   spine1          ethernet1/1/9      aa:bb:cc:dd:ee:02
"""
SRL = """
+---------------+------------+----------------------+---------------------+---------------+
| Name          | Neighbor   | Neighbor System Name | Neighbor Chassis ID | Neighbor Port |
+===============+============+======================+=====================+===============+
| ethernet-1/1  | AA:BB:CC:00:00:01 | leaf2         | AA:BB:CC:00:00:01   | ethernet-1/49 |
| ethernet-1/2  | AA:BB:CC:00:00:02 | spine1        | AA:BB:CC:00:00:02   | ethernet-1/3  |
+---------------+------------+----------------------+---------------------+---------------+
"""


class Conn:
    def __init__(self, raw): self.raw = raw
    def send_command(self, cmd, **kw): return self.raw


@pytest.mark.parametrize("key,text,names", [
    ("procurve_lldp", PROCURVE, ["CORESWITCH2", "EDGE-3"]),
    ("os10_lldp", OS10, ["LEAF2", "SPINE1"]),
    ("srl_lldp", SRL, ["LEAF2", "SPINE1"]),
])
def test_new_parsers(key, text, names):
    if key == "procurve_lldp":
        assert [r["local_intf"] for r in RAW_PARSERS[key](text)] == ["1", "24"]
    got = RAW_PARSERS[key](text)
    assert [r["neighbor"].upper() for r in got] == names
    assert all(r["local_intf"] and r["remote_intf"] for r in got)


@pytest.mark.parametrize("key", ["procurve_lldp", "os10_lldp", "srl_lldp"])
@pytest.mark.parametrize("junk", ["", "garbage\n\n", "| a | b |\n"])
def test_parsers_never_raise_on_junk(key, junk):
    assert RAW_PARSERS[key](junk) == []


def test_profiles_registered():
    for d in ("juniper_junos", "hp_procurve", "hp_comware", "dell_os10", "nokia_sros", "nokia_srl", "cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr"):
        p = get_profile(d)
        assert p["vendor"] != "Generic" and p["presets"] and p["config"]
    assert {"nokia_sros", "nokia_srl"} <= COMMIT_PLATFORMS


def test_discovery_through_profiles():
    for d, raw in (("hp_procurve", PROCURVE), ("dell_os10", OS10), ("nokia_srl", SRL)):
        (cmd, _p, key), = VENDOR_PROFILES[d]["discovery"]
        assert len(_run_discovery_cmd(Conn(raw), cmd, key)) == 2


def test_nokia_has_no_rollback_and_is_refused_not_pushed():
    for d in ("nokia_sros", "nokia_srl", "dell_os10", "hp_procurve", "hp_comware"):
        assert d not in STRATEGIES            # explicit: no device-side safety net -> refused up front


class CommitConn:
    def __init__(self): self.calls = []
    def send_command(self, c, **k): self.calls.append(("show", c)); return "cfg"
    def send_config_set(self, cmds, **k): self.calls.append(("cfg", tuple(cmds), k.get("exit_config_mode"))); return "ok"
    def commit(self): self.calls.append(("commit",)); return "committed"
    def exit_config_mode(self): self.calls.append(("exit",))
    def save_config(self): self.calls.append(("save",)); return "saved"
    def enable(self): pass
    def disconnect(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False


@pytest.mark.parametrize("dtype", ["nokia_sros", "nokia_srl", "juniper_junos"])
def test_candidate_config_platforms_commit(monkeypatch, dtype):
    conn = CommitConn()
    monkeypatch.setattr(network, "open_connection", lambda *a, **k: conn)
    network.run_multi_cli_commands({"device_type": dtype, "host": "h"}, ("u", "p", ""), ["set x"], config_mode=True, save_after=True)
    assert ("commit",) in conn.calls and ("save",) not in conn.calls


@pytest.mark.parametrize("dtype", ["dell_os10", "hp_procurve", "cisco_ios"])
def test_running_config_platforms_save(monkeypatch, dtype):
    conn = CommitConn()
    monkeypatch.setattr(network, "open_connection", lambda *a, **k: conn)
    network.run_multi_cli_commands({"device_type": dtype, "host": "h"}, ("u", "p", ""), ["hostname x"], config_mode=True, save_after=True)
    assert ("save",) in conn.calls and ("commit",) not in conn.calls


@pytest.mark.parametrize("cmd", ["load override x", "rollback 1", "admin reboot now", "boot system flash x", "redundancy force-switchover",
                                 "crypto key zeroize rsa", "reload", "request system reboot"])
def test_more_disruptive_commands_flagged(cmd):
    assert DISRUPTIVE_CMD.match(cmd)


@pytest.mark.parametrize("cmd", ["show version", "show router bgp summary", "info flat /", "display current-configuration"])
def test_read_commands_not_flagged(cmd):
    assert not DISRUPTIVE_CMD.match(cmd)


@pytest.mark.parametrize("line,secret", [
    ("password manager user-name admin sha1 deadbeef1234", "deadbeef1234"),
    ('radius-server host 10.0.0.5 key "rad-secret"', "rad-secret"),
    ('snmp-server community "public" operator', "public"),
    ('password "$2y$10$abcdefghijk" hash2', "$2y$10$abcdefghijk"),
    ('set system root-authentication encrypted-password "$9$abc.def"', "$9$abc.def"),
    ("username admin password $6$salt$hash role sysadmin", "$6$salt$hash"),
    ('authentication-key "m0nitor"', "m0nitor"),
])
def test_vendor_secrets_redacted(line, secret):
    assert secret not in redact_secrets(line)
