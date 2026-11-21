"""Read-only command allowlist used to separate RUN_SHOW from PUSH_CONFIG."""
from __future__ import annotations

import pytest

from netcommander.cmdpolicy import family_of, is_read_only, non_read_only
from netcommander.config import VENDOR_PROFILES

READ_ONLY = [
    ("cisco_ios", "show version"), ("cisco_ios", "sh ip int br"), ("cisco_ios", "sho run | include hostname"),
    ("cisco_ios", "ping 10.0.0.1"), ("cisco_ios", "traceroute 10.0.0.1"), ("cisco_ios", "terminal length 0"),
    ("cisco_ios", "term len 0"), ("cisco_nxos", "show interface status | json"), ("arista_eos", "show lldp neighbors"),
    ("juniper_junos", "show interfaces terse"), ("juniper_junos", "show configuration | display set"),
    ("juniper_junos", "show route | match 10.0"), ("huawei", "display version"), ("huawei", "dis cur"),
    ("hp_comware", "display lldp neighbor-information list"), ("fortinet", "get system status"),
    ("paloalto_panos", "show system info"), ("mikrotik_routeros", "/interface print"),
    ("mikrotik_routeros", "/ip route print detail"), ("mikrotik_routeros", "/routing bgp session print"),
    ("mikrotik_routeros", "/ping 10.0.0.1 count=3"), ("linux", "ip -br addr"), ("linux", "ip route"),
    ("linux", "ip -s link"), ("linux", "uname -a"), ("linux", "uptime"), ("linux", "lldpctl"), ("linux", "df -h"),
    ("linux", "cat /proc/loadavg"), ("linux", "hostname"), ("linux", "ss -tlnp"), ("linux", "ip neigh show"),
    (None, "show version"),
]

NOT_READ_ONLY = [
    # IOS abbreviations a deny-list misses
    ("cisco_ios", "confi t"), ("cisco_ios", "configu t"), ("cisco_ios", "conf t"), ("cisco_ios", "relo"),
    ("cisco_ios", "wr er"), ("cisco_ios", "wr"), ("cisco_ios", "copy run start"), ("cisco_ios", "clear ip bgp *"),
    ("cisco_ios", "username x privilege 15 secret y"), ("cisco_ios", "debug all"), ("cisco_ios", "do show run"),
    ("cisco_ios", "shutdown"), ("cisco_ios", "show run | redirect tftp://1.2.3.4/r1"),
    ("cisco_ios", "show run | tee flash:x"), ("cisco_ios", "show run | append flash:x"),
    ("cisco_nxos", "show run > bootflash:x"), ("cisco_ios", "terminal monitor"),
    ("juniper_junos", "configure"), ("juniper_junos", "edit"), ("juniper_junos", "req sys reb"),
    ("juniper_junos", "request system reboot"), ("juniper_junos", "show configuration | save /tmp/x"),
    ("juniper_junos", "file delete /var/tmp/x"), ("huawei", "system-view"), ("huawei", "reboot"),
    ("huawei", "save"), ("fortinet", "execute reboot"), ("fortinet", "config system global"),
    ("fortinet", "diagnose sys kill 11 1"), ("paloalto_panos", "configure"),
    ("paloalto_panos", "request restart system"), ("mikrotik_routeros", "/system reboot"),
    ("mikrotik_routeros", "/sys reboot"), ("mikrotik_routeros", "/ip address add address=1.1.1.1/32 interface=lo"),
    ("mikrotik_routeros", "/interface set ether1 disabled=yes print"), ("mikrotik_routeros", "/export"),
    ("mikrotik_routeros", "/system reset-configuration"),
    ("linux", "sudo reboot"), ("linux", "reboot"), ("linux", "systemctl reboot"), ("linux", "init 6"),
    ("linux", "uptime; reboot"), ("linux", "uptime && rm -rf /"), ("linux", "cat /etc/shadow"),
    ("linux", "cat /proc/../etc/shadow"), ("linux", "echo x > /etc/motd"), ("linux", "ls $(reboot)"),
    ("linux", "ip addr add 10.0.0.1/24 dev eth0"), ("linux", "ip link set eth0 down"), ("linux", "ip route flush all"),
    ("linux", "hostname evil"), ("linux", "date -s 2020-01-01"), ("linux", "ss -K dst 1.2.3.4"),
    ("linux", "ss -tK"), ("linux", "/bin/sh -c id"), ("linux", "lldpcli configure system hostname x"),
    ("linux", "uname -a; uptime"), (None, "reload"), (None, "configure terminal"),
]


@pytest.mark.parametrize("dtype,cmd", READ_ONLY)
def test_read_only(dtype, cmd):
    assert is_read_only(cmd, dtype), (dtype, cmd)


@pytest.mark.parametrize("dtype,cmd", NOT_READ_ONLY)
def test_not_read_only(dtype, cmd):
    assert not is_read_only(cmd, dtype), (dtype, cmd)


def test_every_vendor_preset_is_read_only():
    """Quick-command buttons must work for operators on every platform."""
    for dtype, profile in VENDOR_PROFILES.items():
        for _label, cmd in profile.get("presets", ()):
            assert is_read_only(cmd, dtype), (dtype, cmd)


def test_mixed_targets_require_read_only_on_every_platform():
    assert non_read_only(["show version"], ["cisco_ios", "juniper_junos"]) == []
    assert non_read_only(["display version"], ["huawei", "cisco_ios"]) == ["display version"]
    assert non_read_only(["show version"], []) == []


def test_family_mapping_defaults_to_generic():
    assert family_of("cisco_xr") == "cisco" and family_of("something_new") == "generic" and family_of(None) == "generic"
