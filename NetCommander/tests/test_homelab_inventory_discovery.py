"""Unified inventory (manual + observed + network mirror) and agentless discovery."""
from __future__ import annotations

import pytest
from conftest import FakeClock

from netcommander.homelab import discovery
from netcommander.homelab.core.db import Database
from netcommander.homelab.core.errors import NotFound, ValidationError
from netcommander.homelab.core.events import EventBus
from netcommander.homelab.inventory import AssetStore, network_assets, network_kind
from netcommander.homelab.models import Asset, merge_observation, normalize_ip, normalize_mac
from netcommander.store import make_device


@pytest.fixture
def store(tmp_path):
    bus, events = EventBus(), []
    bus.subscribe("*", events.append)
    devs = {"core-sw": make_device({"host": "10.0.0.2", "device_type": "cisco_ios"}, peers=["edge"]),
            "edge": make_device({"host": "10.0.0.1", "device_type": "juniper_junos"}, peers=["core-sw"])}
    s = AssetStore(Database(tmp_path / "h.db"), bus, network_source=lambda: devs, clock=FakeClock(1000))
    s.events = events
    return s


def test_mac_ip_normalisation():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_ip(" 10.0.0.01 ".replace("01", "1")) == "10.0.0.1"
    assert normalize_ip("[fe80::1]") == "fe80::1"
    with pytest.raises(ValidationError):
        normalize_mac("zz:zz")
    with pytest.raises(ValidationError):
        normalize_ip("999.1.1.1")


def test_asset_validation_lists_all_problems():
    a = Asset(name="", kind="spaceship", ip="bad", mac="bad", mem_total=-1, management={"ssh": {"password": "x"}})
    with pytest.raises(ValidationError) as ei:
        a.validate()
    text = " ".join(ei.value.problems)
    for frag in ("name", "kind", "IP", "MAC", "mem_total", "password_ref"):
        assert frag in text


def test_manual_create_locks_fields_and_discovery_respects_them(store):
    a = store.create({"name": "nas01", "kind": "nas", "ip": "10.0.0.20", "os": "Hand-written OS"}, actor="alice")
    assert set(a.locked) == {"name", "kind", "ip", "os"}
    obs, created = store.upsert_observed({"ip": "10.0.0.20", "os": "Discovered OS", "kind": "server",
                                          "manufacturer": "Synology", "status": "online"})
    assert not created and obs.id == a.id
    assert obs.os == "Hand-written OS" and obs.kind == "nas" and obs.manufacturer == "Synology"
    store.unlock(a.id, ["os"])
    obs, _ = store.upsert_observed({"ip": "10.0.0.20", "os": "Discovered OS"})
    assert obs.os == "Discovered OS"
    assert any(e.kind == "asset.created" for e in store.events)


def test_observation_matching_order(store):
    a, created = store.upsert_observed({"ip": "10.0.0.30", "mac": "AA:BB:CC:00:00:01", "name": "srv", "status": "online"})
    assert created
    b, created = store.upsert_observed({"ip": "10.0.0.31", "mac": "aa:bb:cc:00:00:01"})        # DHCP moved: same MAC
    assert not created and b.id == a.id and b.ip == "10.0.0.31"
    vm1, c1 = store.upsert_observed({"integration": "pve", "external_id": "pve1/qemu/101", "name": "web", "kind": "vm",
                                     "ip": "10.0.0.31"})
    assert c1 and vm1.id != a.id                                                           # integration objects match by id only
    vm2, c2 = store.upsert_observed({"integration": "pve", "external_id": "pve1/qemu/101", "status": "stopped"})
    assert not c2 and vm2.id == vm1.id and vm2.status == "stopped"
    assert any(e.kind == "asset.status" for e in store.events)
    bad, _ = store.upsert_observed({"ip": "not-an-ip", "name": "weird", "kind": "toaster"})  # bad fields dropped
    assert bad.ip == "" and bad.kind == "unknown"


def test_mark_missing_never_deletes(store):
    store.upsert_observed({"integration": "pve", "external_id": "a", "name": "a", "status": "online"})
    store.upsert_observed({"integration": "pve", "external_id": "b", "name": "b", "status": "online"})
    changed = store.mark_missing("pve", {"a"})
    assert len(changed) == 1 and store.get(changed[0]).status == "offline"
    assert len([x for x in store.all(False)]) == 2


def test_network_mirror_is_read_only(store):
    net = {a.name: a for a in store.network()}
    assert net["core-sw"].kind == "switch" and net["edge"].kind == "router" and net["edge"].ip == "10.0.0.1"
    assert store.get("net-edge").source == "network"
    with pytest.raises(ValidationError):
        store.update("net-edge", {"name": "x"})
    srv = store.create({"name": "pve1", "kind": "hypervisor"})
    store.link(srv.id, "net-core-sw", "connected_to", "Gi1/0/5")
    assert store.get(srv.id).links == [{"to": "net-core-sw", "type": "connected_to", "port": "Gi1/0/5"}]
    with pytest.raises(ValidationError):
        store.link("net-edge", srv.id, "connected_to")
    with pytest.raises(ValidationError):
        store.link(srv.id, "net-edge", "bogus")
    store.unlink(srv.id, "net-core-sw")
    assert store.get(srv.id).links == []
    assert network_kind("fortinet") == "firewall" and network_kind(None) == "switch"
    assert network_assets({"x": make_device({"host": "r1.lan"})})[0].hostname == "r1.lan"


def test_search_update_delete_children(store):
    host = store.create({"name": "pve1", "kind": "hypervisor", "tags": ["prod"]})
    vm, _ = store.upsert_observed({"integration": "pve", "external_id": "1", "name": "web01", "kind": "vm",
                                   "parent": host.id, "os": "Debian 12"})
    assert [a.name for a in store.search("web debian")] == ["web01"]
    assert [a.name for a in store.search(kind="hypervisor", tag="prod")] == ["pve1"]
    assert store.search(parent=host.id)[0].id == vm.id
    store.update(host.id, {"location": "rack 1"})
    assert "location" in store.get(host.id).locked
    with pytest.raises(ValidationError):
        store.update(host.id, {"first_seen": 0})
    assert store.delete(host.id)
    assert store.get(vm.id).parent == ""
    with pytest.raises(NotFound):
        store.get(host.id)


def test_csv_round_trip_and_formula_safety(store):
    created, problems = store.import_csv("name,kind,ip,tags,cpu_cores\nsrv1,server,10.1.1.1,a;b,8\n"
                                         "=cmd|calc,server,,,\nbad,martian,,,\n")
    assert created == 2 and len(problems) == 1 and "row 4" in problems[0]
    out = store.export_csv()
    assert "srv1" in out and "a;b" in out and "'=cmd|calc" in out


def test_merge_observation_does_not_blank_known_values():
    a = Asset(name="x", os="Debian")
    b = merge_observation(a, {"os": "", "cpu_pct": None, "extra": {"k": 1}, "id": "hijack"}, now=5)
    assert b.os == "Debian" and b.id == a.id and b.extra == {"k": 1} and b.last_seen == 5


# ---------------------------------------------------------------- discovery
def test_expand_targets():
    assert discovery.expand_targets(["10.0.0.0/30"]) == ["10.0.0.1", "10.0.0.2"]
    assert discovery.expand_targets(["10.0.0.5", "10.0.0.5"]) == ["10.0.0.5"]
    assert discovery.expand_targets(["10.0.0.10-12"]) == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
    assert len(discovery.expand_targets(["10.0.0.250-10.0.1.2"])) == 9
    for bad in (["10.0.0.0/16"], ["nope"], ["10.0.0.9-10.0.0.1"], ["10.0.0.1-10.0.9.1"]):
        with pytest.raises(ValidationError):
            discovery.expand_targets(bad, max_hosts=1024)
    assert discovery.expand_targets(["192.168.1.7/32"]) == ["192.168.1.7"]


def test_neighbor_table_parsers():
    proc = ("IP address       HW type     Flags       HW address            Mask     Device\n"
            "10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n"
            "10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n")
    assert discovery.parse_proc_net_arp(proc) == {"10.0.0.1": "aa:bb:cc:dd:ee:01"}
    neigh = ("10.0.0.2 dev eth0 lladdr 00:11:32:aa:bb:cc REACHABLE\n10.0.0.3 dev eth0  FAILED\n"
             "fe80::1 dev eth0 lladdr 52:54:00:12:34:56 STALE\n")
    assert discovery.parse_ip_neigh(neigh) == {"10.0.0.2": "00:11:32:aa:bb:cc", "fe80::1": "52:54:00:12:34:56"}
    win = "  10.0.0.4          b8-27-eb-01-02-03     dynamic\n  10.0.0.255   ff-ff-ff-ff-ff-ff   static\n"
    mac = "? (10.0.0.5) at 0:11:32:a:b:c on en0 ifscope [ethernet]\n"
    assert discovery.parse_arp_a(win) == {"10.0.0.4": "b8:27:eb:01:02:03"}
    assert discovery.parse_arp_a(mac) == {"10.0.0.5": "00:11:32:0a:0b:0c"}


def test_vendor_lookup():
    assert discovery.vendor_for_mac("00:11:32:01:02:03") == "Synology"
    assert discovery.vendor_for_mac("02:42:ac:11:00:02") == "Docker"
    assert discovery.vendor_for_mac("06:00:00:00:00:01") == "(locally administered)"
    assert discovery.vendor_for_mac("") == "" and discovery.vendor_for_mac("junk") == ""


@pytest.mark.parametrize("ports,banners,vendor,host,kind,platform", [
    ([22, 8006], {22: "SSH-2.0-OpenSSH_9.2p1 Debian-2"}, "", "", "hypervisor", "proxmox"),
    ([443, 902], {}, "", "", "hypervisor", "esxi"),
    ([5000, 5001, 445], {}, "Synology", "", "nas", "synology"),
    ([80, 443, 445], {80: "TrueNAS"}, "", "", "nas", "truenas"),
    ([22, 445, 2049], {}, "", "ugreen-nas", "nas", "ugreen"),
    ([22, 2376], {}, "", "", "docker_host", "docker"),
    ([3389, 5985, 445], {}, "", "", "server", "windows"),
    ([3389, 445], {}, "", "", "desktop", "windows"),
    ([9100, 631], {}, "", "", "printer", ""),
    ([22], {22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "", "", "server", "linux"),
    ([8291, 22], {}, "", "", "router", "mikrotik"),
    ([8123], {}, "", "", "appliance", "home-assistant"),
    ([22, 445, 2049, 3260], {}, "", "", "nas", "generic"),
    ([], {}, "VMware", "", "vm", "vmware"),
])
def test_classifier(ports, banners, vendor, host, kind, platform):
    c = discovery.classify(ports, banners, vendor, host)
    assert (c.kind, c.platform) == (kind, platform)
    assert len(c.services) == len(ports)


def test_classifier_os_from_ssh_banner():
    assert discovery.classify([22], {22: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"}).os == "Debian"
    assert discovery.classify([22], {22: "SSH-2.0-OpenSSH_for_Windows_8.1"}).os in ("", "Windows")


def test_discovery_engine_with_fakes():
    world = {("10.0.0.1", 22): "open", ("10.0.0.1", 8006): "open", ("10.0.0.2", 445): "closed"}
    eng = discovery.DiscoveryEngine(
        ports=[22, 445, 8006], probe=lambda h, p, t: world.get((h, p), "filtered"),
        banner=lambda h, p, t: "SSH-2.0-OpenSSH_9.2p1 Debian-2" if p == 22 else "",
        neighbors=lambda: {"10.0.0.1": "bc:24:11:00:00:01"}, resolver=lambda ip: "pve1.lan" if ip == "10.0.0.1" else "")
    progress = []
    found = eng.scan(["10.0.0.0/29"], progress=lambda d, t: progress.append((d, t)))
    assert [h.ip for h in found] == ["10.0.0.1", "10.0.0.2"]           # closed port = alive
    pve = found[0].observation()
    assert pve["kind"] == "hypervisor" and pve["name"] == "pve1" and pve["manufacturer"] == "Proxmox"
    assert pve["extra"]["open_ports"] == [22, 8006] and progress[-1] == (6, 6)
    assert found[1].observation()["kind"] == "unknown"


def test_real_tcp_probe_against_local_socket():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        assert discovery.tcp_probe("127.0.0.1", port, 1.0) == "open"
    finally:
        s.close()
    assert discovery.tcp_probe("127.0.0.1", port, 1.0) in ("closed", "filtered")
