"""Docker Engine API adapter and NAS/storage adapters, connectivity checks and forecasting."""
from __future__ import annotations

import json
import socket
import struct
import threading

import pytest
from test_homelab_servers_virt import Api

from netcommander.homelab import containers
from netcommander.homelab.containers import DockerAdapter, container_observation, decode_log_stream
from netcommander.homelab.core.errors import IntegrationError, ValidationError
from netcommander.homelab.core.runners import CommandResult, FakeRunner
from netcommander.homelab.storage import base as sbase
from netcommander.homelab.storage import linux as slinux
from netcommander.homelab.storage.synology import SynologyAdapter
from netcommander.homelab.storage.truenas import TrueNasAdapter

CONTAINERS = [
    {"Id": "a" * 64, "Names": ["/web"], "Image": "nginx:1.25", "State": "running", "Status": "Up 2 hours (healthy)",
     "Labels": {"com.docker.compose.project": "site", "com.docker.compose.service": "web"},
     "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
     "NetworkSettings": {"Networks": {"site_default": {}}}, "Mounts": [{"Type": "volume", "Name": "data", "Destination": "/d"}]},
    {"Id": "b" * 64, "Names": ["/db"], "Image": "postgres:16", "State": "running", "Status": "Up 1 hour (unhealthy)",
     "Labels": {"com.docker.compose.project": "site", "com.docker.compose.service": "db"}, "Ports": [{"PrivatePort": 5432, "Type": "tcp"}]},
    {"Id": "c" * 64, "Names": ["/old"], "Image": "busybox", "State": "exited", "Status": "Exited (0) 3 days ago", "Labels": {}},
]
STATS = {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000}, "system_cpu_usage": 20_000_000, "online_cpus": 4},
         "precpu_stats": {"cpu_usage": {"total_usage": 1_000_000}, "system_cpu_usage": 10_000_000},
         "memory_stats": {"usage": 300, "limit": 1000, "stats": {"inactive_file": 100}},
         "networks": {"eth0": {"rx_bytes": 5, "tx_bytes": 7}},
         "blkio_stats": {"io_service_bytes_recursive": [{"op": "Read", "value": 11}, {"op": "write", "value": 13}]},
         "pids_stats": {"current": 3}}


def frame(stream, text):
    data = text.encode()
    return bytes([stream, 0, 0, 0]) + struct.pack(">I", len(data)) + data


def docker_api():
    routes = {
        ("GET", "/info"): {"Name": "dock1", "ServerVersion": "26.1", "NCPU": 4, "MemTotal": 8e9, "Containers": 3,
                           "ContainersRunning": 2, "Images": 5, "Swarm": {"LocalNodeState": "inactive"}},
        ("GET", "/containers/json"): CONTAINERS,
        ("GET", "/containers/web/json"): {"Config": {"Tty": False, "Env": ["DB_PASSWORD=hunter2", "TZ=UTC"]},
                                          "State": {"Status": "running", "Health": {"Status": "healthy"}}},
        ("GET", "/containers/web/stats"): STATS,
        ("GET", "/images/json"): [{"Id": "sha256:" + "f" * 64, "RepoTags": ["nginx:1.25"], "Size": 10, "Containers": 1}],
        ("GET", "/networks"): [{"Id": "n" * 64, "Name": "site_default", "Driver": "bridge", "Scope": "local",
                                "IPAM": {"Config": [{"Subnet": "172.18.0.0/16"}]}}],
        ("GET", "/volumes"): {"Volumes": [{"Name": "data", "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/data"}]},
    }
    api = Api(routes)
    orig = api.__call__

    def call(method, url, headers, body, timeout):
        if "/containers/web/logs" in url:
            api.calls.append((method, url, "", headers, body))
            return 200, {}, frame(1, "hello\nworld\n") + frame(2, "oops\n")
        if "/containers/web/restart" in url:
            api.calls.append((method, url, "", headers, body))
            return 204, {}, b""
        if "/containers/old/start" in url:
            return 304, {}, b""
        if "/containers/gone/stop" in url:
            return 404, {}, b'{"message":"No such container"}'
        return orig(method, url, headers, body, timeout)
    return api, call


def test_docker_reads():
    api, call = docker_api()
    d = DockerAdapter("unix:///var/run/docker.sock", transport=call)
    assert d.info()["running"] == 2
    cs = d.containers()
    assert [c["health"] for c in cs] == ["healthy", "unhealthy", "stopped"]
    assert cs[0]["ports"] == ["0.0.0.0:8080->80/tcp"] and cs[0]["compose_project"] == "site"
    proj = d.compose_projects(cs)
    assert proj == [{"project": "site", "services": ["db", "web"], "containers": 2, "running": 2, "unhealthy": 1,
                     "status": "degraded"}]
    st = d.stats("web")
    assert st["cpu_pct"] == 40.0 and st["mem_used"] == 200 and st["mem_pct"] == 20.0 and st["blk_write"] == 13
    insp = d.inspect("web")
    assert insp["Config"]["Env"] == ["DB_PASSWORD=********", "TZ=********"]
    logs = d.logs("web", tail=99999)
    assert logs == [{"stream": "stdout", "line": "hello"}, {"stream": "stdout", "line": "world"},
                    {"stream": "stderr", "line": "oops"}]
    assert "tail=5000" in [c for c in api.calls if "/logs" in c[1]][0][1]
    assert d.images()[0]["id"] == "f" * 12 and d.networks()[0]["subnets"] == ["172.18.0.0/16"]
    assert d.volumes()[0]["name"] == "data"
    obs = container_observation(cs[1], "dock", "host1", st)
    assert obs["status"] == "degraded" and obs["parent"] == "host1" and obs["kind"] == "container"


def test_docker_actions_and_validation():
    api, call = docker_api()
    d = DockerAdapter("unix:///run/docker.sock", transport=call)
    assert d.action("web", "restart") == "ok"
    assert "t=10" in api.calls[-1][1]
    assert d.action("old", "start") == "already in that state"
    with pytest.raises(IntegrationError):
        d.action("gone", "stop")
    for bad in ("../x", "a;b", "-rf"):
        with pytest.raises(ValidationError):
            d.action(bad, "start")
    with pytest.raises(ValidationError):
        d.action("web", "remove")


def test_docker_connection_security():
    with pytest.raises(ValidationError, match="unauthenticated"):
        DockerAdapter("tcp://dock1:2375")
    assert DockerAdapter("tcp://dock1:2375", allow_insecure_tcp=True, transport=lambda *a: (200, {}, b"{}")).http.insecure
    d = DockerAdapter("tcp://dock1:2376", ca_file="ca.pem", client_cert="c.pem", client_key="k.pem",
                      transport=lambda *a: (200, {}, b"{}"))
    assert d.http.base_url == "https://dock1:2376" and not d.http.insecure
    with pytest.raises(ValidationError):
        DockerAdapter("ftp://x")


def test_docker_over_real_unix_socket(tmp_path):
    """The stdlib Unix-socket transport speaks HTTP to a socket server (as dockerd does)."""
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("no AF_UNIX")
    path = str(tmp_path / "d.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            body = json.dumps({"Name": "sockhost", "Containers": 1}).encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                         str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        assert DockerAdapter(f"unix://{path}").info()["name"] == "sockhost"
    finally:
        srv.close()


def test_log_decoder_and_metrics_helpers():
    assert decode_log_stream(b"plain\ntext\n", tty=True) == [("stdout", "plain"), ("stdout", "text")]
    assert decode_log_stream(b"not multiplexed at all") == [("stdout", "not multiplexed at all")]
    assert containers.cpu_percent({}) is None
    assert containers.cpu_percent({"cpu_stats": {"cpu_usage": {"total_usage": 1}, "system_cpu_usage": 1},
                                   "precpu_stats": {"cpu_usage": {"total_usage": 1}, "system_cpu_usage": 1}}) == 0.0
    assert containers.memory_usage({"memory_stats": {"usage": 10, "stats": {"cache": 4}, "limit": 0}}) == (6, 0)
    assert containers.health_of({"State": "running", "Status": "Up (health: starting)"}) == "starting"
    assert containers.health_of({"State": "running", "Status": "Up 3 min"}) == "none"


# ---------------------------------------------------------------- TrueNAS
TOPO = {"data": [{"type": "RAIDZ1", "children": [{"type": "DISK", "disk": "sda"}, {"type": "DISK", "disk": "sdb"},
                                                 {"type": "DISK", "disk": "sdc"}]}], "cache": [{"type": "DISK", "disk": "nvme0n1"}]}
TRUENAS = {
    ("GET", "/api/v2.0/system/info"): {"hostname": "truenas", "version": "TrueNAS-SCALE-24.10", "physmem": 34359738368,
                                       "uptime_seconds": 3600, "system_product": "Mini X+"},
    ("GET", "/api/v2.0/pool"): [{"name": "tank", "status": "DEGRADED", "healthy": False, "size": 1000, "allocated": 900,
                                 "topology": TOPO}],
    ("GET", "/api/v2.0/disk"): [{"name": "sda", "serial": "S1", "model": "WD Red", "size": 4e12, "type": "HDD"},
                                {"name": "sdb", "serial": "S2", "model": "WD Red", "size": 4e12, "type": "HDD"}],
    ("POST", "/api/v2.0/disk/temperatures"): {"sda": 38, "sdb": None},
    ("GET", "/api/v2.0/smart/test/results"): [{"disk": "sda", "tests": [{"status": "SUCCESS"}]},
                                              {"disk": "sdb", "tests": [{"status": "FAILED"}]}],
    ("GET", "/api/v2.0/sharing/smb"): [{"name": "media", "path": "/mnt/tank/media", "enabled": True}],
    ("GET", "/api/v2.0/sharing/nfs"): [{"paths": ["/mnt/tank/vm"], "enabled": False, "networks": ["10.0.0.0/24"]}],
    ("GET", "/api/v2.0/iscsi/global"): {"basename": "iqn.2005-10.org.freenas.ctl"},
    ("GET", "/api/v2.0/iscsi/target"): [{"name": "esx", "alias": "vmfs"}],
    ("GET", "/api/v2.0/replication"): [{"name": "tank->backup", "enabled": True,
                                        "state": {"state": "FINISHED", "datetime": {"$date": 1700000000000}}}],
    ("GET", "/api/v2.0/cloudsync"): [{"description": "b2", "job": {"state": "FAILED", "time_finished": {"$date": 1700000100000}}}],
}


def test_truenas_report():
    api = Api(TRUENAS)
    tn = TrueNasAdapter("https://truenas.lan", api_key="key-1", transport=api)
    r = tn.report()
    assert r.system["hostname"] == "truenas" and r.pools[0].layout == "RAIDZ1"
    assert r.pools[0].disks == ["sda", "sdb", "sdc", "nvme0n1"] and r.pools[0].pct == 90.0
    d = {x.name: x for x in r.disks}
    assert d["sda"].temperature_c == 38 and d["sda"].smart_ok and d["sda"].pool == "tank"
    assert d["sdb"].smart_ok is False and d["sdb"].health == "failing"
    assert {(s.protocol, s.name) for s in r.shares} == {("smb", "media"), ("nfs", "/mnt/tank/vm"),
                                                         ("iscsi", "iqn.2005-10.org.freenas.ctl:esx")}
    assert r.health == "critical"
    m = r.metrics()
    assert m["pool.tank.pct"] == 90.0 and m["pools_unhealthy"] == 1 and m["disks_failing"] == 1 and m["disk_temp_max"] == 38
    obs = r.observation("tn", "10.0.0.10")
    assert obs["kind"] == "nas" and obs["status"] == "degraded" and obs["mem_total"] == 34359738368
    assert api.calls[0][3]["Authorization"] == "Bearer key-1"
    tasks = tn.replication_tasks()
    assert tasks[0]["state"] == "FINISHED" and tasks[1]["state"] == "FAILED"


def test_truenas_partial_failure_is_reported_not_fatal():
    routes = dict(TRUENAS)
    del routes[("GET", "/api/v2.0/sharing/nfs")]
    r = TrueNasAdapter("https://t", "k", transport=Api(routes)).report()
    assert any("sharing/nfs" in e for e in r.errors) and r.pools
    with pytest.raises(IntegrationError):
        TrueNasAdapter("https://t", "k", transport=Api({})).report()


# ---------------------------------------------------------------- Synology
def syno_api(login_ok=True):
    def entry_get(query, body):
        from urllib.parse import parse_qs
        q = {k: v[0] for k, v in parse_qs(query).items()}
        api = q.get("api")
        if api == "SYNO.API.Auth":
            return {"success": True}
        assert q.get("_sid") == "SID123"
        if api == "SYNO.DSM.Info":
            return {"success": True, "data": {"hostname": "ds920", "model": "DS920+", "version_string": "DSM 7.2", "ram": 4096}}
        if api == "SYNO.Storage.CGI.Storage":
            return {"success": True, "data": {
                "disks": [{"id": "sata1", "name": "Drive 1", "model": "IronWolf ", "serial": "Z1", "size_total": 4e12, "temp": 35,
                           "smart_status": "normal", "status": "normal"},
                          {"id": "sata2", "name": "Drive 2", "temp": -1, "smart_status": "failing"}],
                "storagePools": [{"id": "reuse_1", "device_type": "shr_without_disk_protect", "status": "normal",
                                  "size": {"total": 100, "used": 40}, "disks": ["sata1", "sata2"]}]}}
        if api == "SYNO.Core.Share":
            return {"success": True, "data": {"shares": [{"name": "photo", "vol_path": "/volume1"}]}}
        return {"success": False, "error": {"code": 102}}

    def login(query, body):
        assert b"passwd=pw" in body                    # POST body, never the URL
        return {"success": login_ok, "data": {"sid": "SID123"}, "error": {"code": 403}}
    return Api({("GET", "/webapi/entry.cgi"): entry_get, ("POST", "/webapi/entry.cgi"): login})


def test_synology_report():
    api = syno_api()
    r = SynologyAdapter("https://ds920:5001", "monitor", "pw", transport=api).report()
    assert r.system["model"] == "DS920+" and r.system["mem_total"] == 4096 * 1024 * 1024
    assert r.pools[0].pct == 40.0 and r.pools[0].healthy and r.pools[0].disks == ["Drive 1", "Drive 2"]
    d = {x.name: x for x in r.disks}
    assert d["Drive 1"].temperature_c == 35 and d["Drive 2"].temperature_c is None and d["Drive 2"].health == "failing"
    assert r.shares[0].path == "/volume1/photo"
    assert all("passwd" not in c[2] for c in api.calls)
    assert any("method=logout" in c[2] for c in api.calls)


def test_synology_login_failure_hints_2fa():
    with pytest.raises(IntegrationError, match="2FA"):
        SynologyAdapter("https://ds", "u", "pw", transport=syno_api(False)).report()


# ---------------------------------------------------------------- generic Linux / UGREEN / QNAP
LSBLK = json.dumps({"blockdevices": [
    {"name": "sda", "size": 4000787030016, "type": "disk", "model": "ST4000VN008", "serial": "ZDH1", "rota": True, "tran": "sata"},
    {"name": "sdb", "size": 4000787030016, "type": "disk", "model": "ST4000VN008", "serial": "ZDH2", "rota": True, "tran": "sata"},
    {"name": "nvme0n1", "size": 500107862016, "type": "disk", "model": "Samsung 980", "serial": "N1", "rota": False, "tran": "nvme"},
    {"name": "loop0", "size": 1, "type": "loop"}, {"name": "zram0", "size": 1, "type": "disk"}]})
MDSTAT = """Personalities : [raid1] [raid5]
md0 : active raid1 sdb1[1] sda1[0]
      3906886464 blocks super 1.2 [2/2] [UU]

md1 : active raid5 sdc1[2](F) sdd1[1] sde1[0]
      7813772288 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/2] [UU_]
      [=>...................]  recovery =  8.5% (332153728/3906886144) finish=313.1min speed=190244K/sec

unused devices: <none>
"""
ZLIST = "tank\t8000000000000\t2000000000000\tONLINE\n"
ZSTATUS = """  pool: tank
 state: ONLINE
config:

        NAME        STATE     READ WRITE CKSUM
        tank        ONLINE       0     0     0
          mirror-0  ONLINE       0     0     0
            sda     ONLINE       0     0     0
            sdb     ONLINE       0     0     0

errors: No known data errors
"""
SMART_OK = json.dumps({"model_name": "ST4000VN008", "serial_number": "ZDH1", "smart_status": {"passed": True},
                       "temperature": {"current": 34}, "power_on_time": {"hours": 20000},
                       "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 0}}, {"id": 197, "raw": {"value": 0}}]}})
SMART_BAD = json.dumps({"smart_status": {"passed": True}, "temperature": {"current": 41},
                        "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 8}}, {"id": 197, "raw": {"value": 2}}]}})
SMART_NVME = json.dumps({"smart_status": {"passed": True}, "nvme_smart_health_information_log": {"temperature": 45,
                                                                                                  "power_on_hours": 100}})
TESTPARM = "[global]\n\tworkgroup = WG\n[media]\n\tpath = /srv/media\n\tread only = no\n[backup]\n\tpath = /srv/backup\n\tavailable = no\n[printers]\n\tpath=/var/spool\n"


def test_linux_storage_parsers():
    assert [d["name"] for d in slinux.parse_lsblk(LSBLK)] == ["sda", "sdb", "nvme0n1"]
    md = slinux.parse_mdstat(MDSTAT)
    assert md[0].healthy and md[0].layout == "RAID1" and md[0].disks == ["sda", "sdb"]
    assert not md[1].healthy and "rebuilding" in md[1].status and md[1].layout == "RAID5"
    assert slinux.parse_zpool_list(ZLIST)[0].pct == 25.0
    assert slinux.parse_zpool_status(ZSTATUS) == {"tank": {"layout": "MIRROR", "disks": ["sda", "sdb"]}}
    s = slinux.parse_smartctl(SMART_BAD)
    assert s["reallocated"] == 8 and s["pending"] == 2
    assert slinux.parse_smartctl(SMART_NVME)["temperature_c"] == 45 and slinux.parse_smartctl("x") == {}
    shares = slinux.parse_testparm(TESTPARM)
    assert [(x.name, x.enabled) for x in shares] == [("media", True), ("backup", False)]
    assert slinux.parse_exports("# c\n/srv/nfs 10.0.0.0/24(rw)\n")[0].extra["clients"] == ["10.0.0.0/24(rw)"]


def _ugreen_runner():
    c = slinux.COMMANDS
    return FakeRunner({
        c["hostname"]: "ugreen-dxp4800", c["os"]: 'PRETTY_NAME="UGOS Pro 1.0"\n', c["lsblk"]: LSBLK,
        c["df"]: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/md0 100 50 50 50% /volume1\n",
        c["mdstat"]: MDSTAT.split("\n\nmd1")[0] + "\n", c["zpool"]: CommandResult(c["zpool"], 127, "", "not found"),
        c["zstatus"]: CommandResult(c["zstatus"], 127, "", ""), c["exports"]: "", c["smb"]: TESTPARM,
        c["iscsi"]: "iqn.2024-01.com.ugreen:t1 discovery_auth\n", c["meminfo"]: "MemTotal: 8000000 kB\n",
        c["uptime"]: "100.0 1.0",
        "sudo -n smartctl -j -H -A -i /dev/sda": SMART_OK, "sudo -n smartctl -j -H -A -i /dev/sdb": SMART_BAD,
        "sudo -n smartctl -j -H -A -i /dev/nvme0n1": CommandResult("x", 1, "", "permission denied"),
    }, policy=slinux.STORAGE_POLICY)


def test_ugreen_report_via_ssh():
    r = slinux.UgreenAdapter(_ugreen_runner()).report()
    assert r.system["vendor"] == "UGREEN" and r.system["version"] == "UGOS Pro 1.0"
    assert r.pools[0].name == "md0" and r.pools[0].total == 100 * 1024 and r.pools[0].pct == 50.0
    d = {x.name: x for x in r.disks}
    assert d["sda"].health == "ok" and d["sdb"].health == "failing" and d["nvme0n1"].type == "NVMe"
    assert d["sda"].pool == "md0" and any("nvme0n1" in e for e in r.errors)
    assert {(s.protocol, s.name) for s in r.shares} >= {("smb", "media"), ("iscsi", "iqn.2024-01.com.ugreen:t1")}
    assert r.health == "critical"


def test_storage_policy_blocks_injection():
    assert slinux.STORAGE_POLICY.allows("smartctl -j -H -A -i /dev/sda")
    assert not slinux.STORAGE_POLICY.allows("smartctl -j -H -A -i /dev/sda;reboot")
    assert not slinux.STORAGE_POLICY.allows("sudo -n reboot")


def test_qnap_zfs_and_unreachable():
    c = slinux.COMMANDS
    runner = FakeRunner({c["hostname"]: "qnap", c["zpool"]: ZLIST, c["zstatus"]: ZSTATUS, c["lsblk"]: LSBLK, "*": ""})
    r = slinux.QnapAdapter(runner, smart=False).report()
    assert r.pools[0].layout == "MIRROR" and r.system["vendor"] == "QNAP"
    with pytest.raises(IntegrationError):
        slinux.LinuxStorageAdapter(FakeRunner({"*": IntegrationError("no route")})).report()


# ---------------------------------------------------------------- connectivity + forecast
def test_smb2_packet_shape_and_parser():
    pkt = sbase.smb2_negotiate_packet()
    assert pkt[4:8] == b"\xfeSMB" and int.from_bytes(pkt[1:4], "big") == len(pkt) - 4
    reply = b"\x00\x00\x00\x50" + b"\xfeSMB" + b"\x00" * 60 + struct.pack("<HHH", 65, 1, 0x0302)
    assert sbase.parse_smb2_negotiate_response(reply) == "3.0.2"
    assert sbase.parse_smb2_negotiate_response(b"\x00\x00\x00\x10\xffSMB") is None


def test_smb_check_against_fake_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        with conn:
            data = conn.recv(1024)
            assert data[4:8] == b"\xfeSMB"
            conn.sendall(b"\x00\x00\x00\x50" + b"\xfeSMB" + b"\x00" * 60 + struct.pack("<HHH", 65, 1, 0x0311))
    threading.Thread(target=serve, daemon=True).start()
    try:
        res = sbase.smb_check("127.0.0.1", port)
    finally:
        srv.close()
    assert res["ok"] and res["detail"] == "SMB 3.1.1"
    assert not sbase.smb_check("127.0.0.1", port, timeout=0.5)["ok"]


def test_share_checks():
    out = sbase.share_checks("nas", ["smb", "nfs", "iscsi"], lambda h, p, t: "open" if p == 2049 else "filtered",
                             smb=lambda h: {"protocol": "smb", "ok": True})
    assert [(o["protocol"], o["ok"]) for o in out] == [("smb", True), ("nfs", True), ("iscsi", False)]


def test_forecast():
    day = 86400.0
    pts = [(i * day, 100.0 + 10 * i) for i in range(10)]           # +10 bytes/day, used=190 at day 9
    f = sbase.forecast(pts, total=300, now=9 * day)
    assert f["growth_per_day"] == 10 and f["days_until"]["80%"] == 5.0 and f["days_until"]["100%"] == 11.0
    flat = sbase.forecast([(0, 50.0), (day, 50.0)], total=100, now=day)
    assert flat["days_until"]["80%"] is None
    full = sbase.forecast([(0, 95.0), (day, 96.0)], total=100, now=day)
    assert full["days_until"]["90%"] == 0.0
    assert sbase.forecast([(0, 1.0)], 10, 0)["growth_per_day"] is None
    assert sbase.linear_fit([(1, 1), (1, 2)]) is None
