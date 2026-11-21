"""Server collectors (Linux/Windows parsers) and the five hypervisor adapters (against fakes)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace as NS

import pytest

from netcommander.homelab import servers
from netcommander.homelab.core.errors import IntegrationError, ValidationError
from netcommander.homelab.core.runners import CommandResult, FakeRunner
from netcommander.homelab.virtualization.base import HostInfo, VirtualMachine, check_action, safe_id
from netcommander.homelab.virtualization.esxi import EsxiAdapter
from netcommander.homelab.virtualization.hyperv import HyperVAdapter
from netcommander.homelab.virtualization.libvirt import LibvirtAdapter, parse_domstats
from netcommander.homelab.virtualization.proxmox import ProxmoxAdapter
from netcommander.homelab.virtualization.virtualbox import VirtualBoxAdapter, parse_list_vms

MEMINFO = "MemTotal:       16303428 kB\nMemFree:         1000000 kB\nMemAvailable:    8151714 kB\nSwapTotal: 2097148 kB\nSwapFree: 2097148 kB\n"
STAT1 = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\n"
STAT2 = "cpu  150 0 150 900 0 0 0 0 0 0\n"
DF = ("Filesystem     1024-blocks      Used Available Capacity Mounted on\n"
      "/dev/sda1         100000000  25000000  75000000      25% /\n"
      "tmpfs                 1000         0      1000       0% /run\n"
      "/dev/sdb1         200000000 150000000  50000000      75% /data\n"
      "/dev/sda1         100000000  25000000  75000000      25% /var/lib/docker/overlay\n")
NETDEV = ("Inter-|   Receive                                                |  Transmit\n"
          " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
          "    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n"
          "  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 0 0 0 0 0\n")
IPJ = json.dumps([{"ifname": "lo"}, {"ifname": "eth0", "address": "aa:bb:cc:dd:ee:ff", "operstate": "UP", "mtu": 1500,
                                     "addr_info": [{"local": "10.0.0.5", "prefixlen": 24}]}])
PS = ("  PID USER     %CPU %MEM   RSS COMMAND\n    1 root      0.1  0.1  1000 systemd\n"
      "  999 www      55.0  3.2 99999 nginx: worker process\n")
SYSTEMCTL = ("ssh.service loaded active running OpenBSD Secure Shell server\n"
             "nginx.service loaded failed failed A high performance web server\n"
             "foo.service loaded inactive dead Foo\n")


def linux_runner(**over):
    c = servers.LINUX_COMMANDS
    responses = {c["hostname"]: "srv01\n", c["os_release"]: 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
                 c["uname"]: "Linux 6.1.0 x86_64", c["loadavg"]: "0.50 0.40 0.30 1/200 999", c["meminfo"]: MEMINFO,
                 c["uptime"]: "86400.55 1000.0", c["stat"]: STAT1, c["cpuinfo"]: "processor : 0\nmodel name : Intel N100\nprocessor : 1\n",
                 c["df"]: DF, c["netdev"]: NETDEV, c["ipaddr"]: IPJ, c["ps"]: PS, c["services"]: SYSTEMCTL,
                 c["vendor"]: "Intel Corporation\n", c["product"]: "NUC12\n"}
    responses.update(over)
    calls = {"n": 0}

    class R(FakeRunner):
        def run(self, command, timeout=30.0):
            if command == c["stat"]:
                calls["n"] += 1
                if calls["n"] > 1:
                    return CommandResult(command, 0, STAT2)
            return super().run(command, timeout)
    return R(responses, policy=servers.LINUX_POLICY)


def test_linux_parsers():
    m = servers.parse_meminfo(MEMINFO)
    assert m["mem_total"] == 16303428 * 1024 and m["mem_used"] == (16303428 - 8151714) * 1024
    assert servers.parse_loadavg("1 2 3") == {"load1": 1.0, "load5": 2.0, "load15": 3.0} and servers.parse_loadavg("") == {}
    assert servers.parse_uptime("12.5 3") == 12 and servers.parse_uptime("") is None
    assert servers.cpu_percent(servers.parse_proc_stat_cpu(STAT1), servers.parse_proc_stat_cpu(STAT2)) == 50.0
    assert servers.cpu_percent(None, (1, 1)) is None
    disks = servers.parse_df(DF)
    assert [d["mount"] for d in disks] == ["/", "/data", "/var/lib/docker/overlay"] and disks[1]["pct"] == 75.0
    assert servers.parse_net_dev(NETDEV) == {"eth0": {"rx_bytes": 1000, "rx_errors": 1, "rx_drop": 2, "tx_bytes": 2000, "tx_errors": 3}}
    assert servers.parse_ip_addr_json(IPJ)[0]["addresses"] == ["10.0.0.5/24"] and servers.parse_ip_addr_json("x") == []
    assert servers.parse_os_release('NAME="Alpine"\nVERSION_ID=3.19\n') == "Alpine 3.19"
    assert servers.parse_ps(PS)[0]["command"].startswith("nginx")
    assert [s["name"] for s in servers.parse_systemctl(SYSTEMCTL)] == ["ssh", "nginx", "foo"]


def test_collect_linux_end_to_end():
    res = servers.collect_linux(linux_runner(), sleep=lambda s: None)
    o = res.observation
    assert o["hostname"] == "srv01" and o["os"].startswith("Debian") and o["cpu_pct"] == 50.0
    assert o["cpu_model"] == "Intel N100" and o["cpu_cores"] == 2 and o["manufacturer"] == "Intel Corporation"
    assert o["storage_total"] == 300000000 * 1024                         # /dev/sda1 counted once
    assert {s["name"] for s in o["services"]} == {"ssh", "nginx"}
    assert res.metrics["failed_services"] == 1 and res.metrics["mem_pct"] == 50.0
    assert res.metrics["net_rx_bytes"] == 1000 and res.details["failed_services"] == ["nginx"]
    assert o["interfaces"][0]["rx_bytes"] == 1000


def test_collect_linux_degrades_and_detects_unreachable():
    c = servers.LINUX_COMMANDS
    partial = servers.collect_linux(linux_runner(**{c["ipaddr"]: CommandResult(c["ipaddr"], 127, "", "ip: not found")}),
                                    sleep=lambda s: None)
    assert partial.observation["interfaces"][0]["name"] == "eth0" and any("ip -j addr" in e for e in partial.errors)
    down = servers.collect_linux(FakeRunner({k + "*": IntegrationError("SSH host 10.0.0.5 is not trusted yet")
                                             for k in ["", ]}), sleep=lambda s: None)
    assert not down.reachable and "not trusted" in down.errors[0]


def test_linux_policy_rejects_other_commands():
    with pytest.raises(ValidationError):
        servers.LINUX_POLICY.check("cat /etc/shadow")


WIN = {"hostname": "WIN01", "os": "Microsoft Windows Server 2022 Standard 10.0.20348", "manufacturer": "Dell Inc.",
       "model": "PowerEdge T140", "cpu_model": "Intel Xeon E-2224 ", "cpu_cores": 4, "cpu_pct": 12, "mem_total": 17179869184,
       "mem_free": 8589934592, "uptime_s": 3600,
       "disks": {"DeviceID": "C:", "Size": 100, "FreeSpace": 25, "FileSystem": "NTFS"},
       "nics": [{"Description": "Intel NIC", "MACAddress": "AA:BB:CC:DD:EE:01", "IPAddress": ["10.0.0.9", "fe80::1"]}],
       "net": [{"Name": "Intel NIC", "BytesReceivedPersec": 10, "BytesSentPersec": 20}],
       "services": [{"Name": "W32Time", "DisplayName": "Time", "Status": "Running", "StartType": "Automatic"},
                    {"Name": "Spooler", "DisplayName": "Print", "Status": "Stopped", "StartType": "Automatic"}],
       "processes": {"Id": 4, "ProcessName": "System", "CPU": 1.5, "WorkingSet64": 100}}


def test_windows_collector():
    res = servers.collect_windows(FakeRunner({servers.WINDOWS_SCRIPT: "﻿" + json.dumps(WIN)}, policy=servers.WINDOWS_POLICY))
    o = res.observation
    assert o["hostname"] == "WIN01" and o["mem_used"] == 8589934592 and o["storage_used"] == 75
    assert res.metrics["disk_pct"] == 75.0 and res.metrics["failed_services"] == 1 and res.metrics["cpu_pct"] == 12
    assert res.details["failed_services"] == ["Spooler"] and o["interfaces"][0]["addresses"] == ["10.0.0.9", "fe80::1"]
    assert [s["name"] for s in o["services"]] == ["W32Time"]
    assert servers.parse_windows("not json").errors
    down = servers.collect_windows(FakeRunner({servers.WINDOWS_SCRIPT: IntegrationError("WinRM refused")}))
    assert not down.reachable


def test_connectivity():
    res = servers.connectivity("10.0.0.5", lambda h, p, t: "open" if p == 22 else "filtered")
    assert res["reachable"] and res["ports"]["ssh"] == "open" and "rtt_ms" in res
    assert not servers.connectivity("10.0.0.6", lambda h, p, t: "filtered")["reachable"]


# ---------------------------------------------------------------- virtualization
def test_safe_ids_and_actions():
    assert safe_id("pve1/qemu/101") == "pve1/qemu/101"
    for bad in ("../etc", "a b", "x;y", ""):
        with pytest.raises(ValidationError):
            safe_id(bad)
    with pytest.raises(ValidationError):
        check_action("destroy")


def test_host_allocation():
    h = HostInfo("pve1", cpus=8, mem_total=32)
    vms = [VirtualMachine("a", "a", host="pve1", cpus=4, mem_total=16, status="running"),
           VirtualMachine("b", "b", host="pve1", cpus=8, mem_total=32), VirtualMachine("t", "t", host="pve1", cpus=99, template=True)]
    assert h.allocation(vms) == {"vms": 2, "running": 1, "vcpus": 12, "vcpu_ratio": 1.5, "mem_assigned": 48, "mem_ratio": 1.5}


class Api:
    """Fake HTTP transport routing by (method, path-without-query)."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, headers, body, timeout):
        import urllib.parse
        u = urllib.parse.urlsplit(url)
        self.calls.append((method, u.path, u.query, dict(headers), body))
        res = self.routes.get((method, u.path))
        if res is None:
            return 404, {}, b'{"errors": "no route"}'
        if callable(res):
            res = res(u.query, body)
        return 200, {}, json.dumps(res).encode()


PVE = {
    ("GET", "/api2/json/nodes"): {"data": [{"node": "pve1", "status": "online", "cpu": 0.25, "maxcpu": 8, "mem": 8e9,
                                            "maxmem": 32e9, "uptime": 100}, {"node": "pve2", "status": "offline"}]},
    ("GET", "/api2/json/nodes/pve1/storage"): {"data": [{"storage": "local-zfs", "type": "zfspool", "total": 1000, "used": 400}]},
    ("GET", "/api2/json/cluster/resources"): {"data": [
        {"id": "qemu/101", "vmid": 101, "name": "web", "node": "pve1", "type": "qemu", "status": "running", "cpu": 0.1,
         "maxcpu": 2, "mem": 1e9, "maxmem": 2e9, "disk": 0, "maxdisk": 32e9, "uptime": 50},
        {"id": "lxc/200", "vmid": 200, "name": "dns", "node": "pve1", "type": "lxc", "status": "stopped", "maxcpu": 1},
        {"id": "qemu/9000", "vmid": 9000, "name": "tmpl", "node": "pve1", "type": "qemu", "status": "stopped", "template": 1}]},
    ("GET", "/api2/json/nodes/pve1/qemu/101/config"): {"data": {"scsi0": "local-zfs:vm-101-disk-0,size=32G", "ide2": "none,media=cdrom",
                                                                 "cores": 2, "cipassword": "secret"}},
    ("GET", "/api2/json/nodes/pve1/qemu/101/snapshot"): {"data": [{"name": "pre-upgrade", "snaptime": 1700000000, "description": "x"},
                                                                   {"name": "current", "parent": "pre-upgrade"}]},
    ("POST", "/api2/json/nodes/pve1/qemu/101/status/shutdown"): {"data": "UPID:pve1:0001"},
    ("GET", "/api2/json/nodes/pve1/tasks"): {"data": [{"id": "101", "starttime": 10, "endtime": 20, "status": "OK", "upid": "U1"}]},
}


def test_proxmox_adapter():
    api = Api(PVE)
    pve = ProxmoxAdapter("https://pve1:8006", "monitor@pve!nc", "tok-secret", transport=api)
    hosts = pve.hosts()
    assert hosts[0].cpu_pct == 25.0 and hosts[0].storage[0]["name"] == "local-zfs" and hosts[1].status == "offline"
    vms = pve.list_vms()
    assert [v.id for v in vms] == ["pve1/qemu/101", "pve1/lxc/200", "pve1/qemu/9000"]
    assert vms[1].type == "lxc" and vms[2].template and vms[0].cpu_pct == 10.0
    obs = vms[1].observation("pve", "host-asset")
    assert obs["kind"] == "container" and obs["status"] == "stopped" and obs["parent"] == "host-asset"
    assert "cipassword" not in pve.vm_config("pve1/qemu/101")
    assert pve.disks("pve1/qemu/101")[0].size == 32 * 1024 ** 3 and len(pve.disks("pve1/qemu/101")) == 1
    assert [s.name for s in pve.snapshots("pve1/qemu/101")] == ["pre-upgrade"]
    assert pve.power("pve1/qemu/101", "shutdown") == "UPID:pve1:0001"
    assert api.calls[0][3]["Authorization"] == "PVEAPIToken=monitor@pve!nc=tok-secret"
    assert pve.backup_tasks()[0]["status"] == "OK"
    with pytest.raises(ValueError):
        pve.vm_config("pve1/bhyve/1")
    with pytest.raises(ValidationError):
        pve.power("pve1/qemu/101", "delete")


def _esxi_world():
    host = NS(name="esx1", summary=NS(
        config=NS(name="esx1", product=NS(fullName="VMware ESXi 8.0.2")), runtime=NS(connectionState="connected"),
        hardware=NS(cpuMhz=2000, numCpuCores=8, numCpuThreads=16, memorySize=64 * 1024 ** 3),
        quickStats=NS(overallCpuUsage=4000, overallMemoryUsage=16 * 1024, uptime=1000)),
        datastore=[NS(summary=NS(name="ds1", type="VMFS", capacity=1000, freeSpace=300))])
    snap = NS(name="s1", description="first", createTime=datetime(2024, 1, 1, tzinfo=timezone.utc),
              childSnapshotList=[NS(name="s2", description="", createTime=datetime(2024, 2, 1, tzinfo=timezone.utc),
                                    childSnapshotList=[])])
    calls = []
    vm = NS(_moId="vm-42", snapshot=NS(rootSnapshotList=[snap]),
            summary=NS(config=NS(name="db01", numCpu=4, memorySizeMB=8192, instanceUuid="u-1", guestFullName="Ubuntu",
                                 template=False, vmPathName="[ds1] db01/db01.vmx"),
                       runtime=NS(powerState="poweredOn", host=host, maxCpuUsage=8000),
                       quickStats=NS(overallCpuUsage=2000, guestMemoryUsage=4096, uptimeSeconds=77),
                       storage=NS(committed=50, uncommitted=50), guest=NS(toolsStatus="toolsOk", ipAddress="10.0.0.42")),
            config=NS(hardware=NS(device=[NS(deviceInfo=NS(label="Hard disk 1"), capacityInBytes=100)])),
            ShutdownGuest=lambda: calls.append("shutdown"), PowerOnVM_Task=lambda: NS(info=NS(key="task-1")))

    class View:
        def __init__(self, objs): self.view = objs
        def Destroy(self): calls.append("destroy-view")

    content = NS(rootFolder="root", viewManager=NS(CreateContainerView=lambda root, kinds, rec: View(
        [vm] if kinds == ["VM"] else [host])))
    si = NS(RetrieveContent=lambda: content)
    return si, calls


def test_esxi_adapter_with_fake_pyvmomi():
    si, calls = _esxi_world()
    esx = EsxiAdapter("esx1", "ro", "pw", connect=lambda *a: si, types=lambda: ("VM", "HOST"))
    h = esx.hosts()[0]
    assert h.cpu_pct == 25.0 and h.mem_used == 16 * 1024 ** 3 and h.storage[0]["used"] == 700 and h.cpus == 16
    v = esx.list_vms()[0]
    assert (v.id, v.status, v.cpu_pct, v.mem_used, v.host) == ("vm-42", "running", 25.0, 4096 * 1024 ** 2, "esx1")
    assert [s.name for s in esx.snapshots("vm-42")] == ["s1", "s2"] and esx.snapshots("vm-42")[1].parent == "s1"
    assert esx.vm_config("vm-42")["disks"][0]["size"] == 100
    esx.power("vm-42", "shutdown")
    assert "shutdown" in calls and esx.power("vm-42", "start") == "task-1"
    with pytest.raises(IntegrationError):
        esx.power("vm-99", "start")
    assert calls.count("destroy-view") >= 3                      # container views are always released


GUID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"


def test_hyperv_adapter_and_injection_guard():
    from netcommander.homelab.virtualization import hyperv
    runner = FakeRunner({
        hyperv.LIST_VMS: json.dumps({"Name": "dc01", "Id": GUID, "State": "Running", "CPUUsage": 3, "ProcessorCount": 2,
                                     "MemoryAssigned": 2048, "MemoryStartup": 4096, "Uptime": 99, "Generation": 2}),
        hyperv.HOST_INFO: json.dumps({"name": "HV1", "cpus": 16, "mem_total": 1000, "mem_free": 250, "cpu_pct": 7}),
        f"Stop-VM -VM (Get-VM -Id '{GUID}') -Force": "",
        "Get-VMSnapshot*": json.dumps([{"Name": "cp1", "ParentSnapshotName": None, "Created": 1700000000}]),
    })
    hv = HyperVAdapter(runner, "HV1")
    vm = hv.list_vms()[0]
    assert (vm.id, vm.status, vm.mem_used) == (GUID, "running", 2048)
    assert hv.hosts()[0].mem_used == 750
    assert hv.snapshots(GUID)[0].name == "cp1"
    assert hv.power(GUID, "shutdown") == "ok"
    with pytest.raises(ValidationError):
        hv.power("dc01'; Remove-VM *", "stop")
    with pytest.raises(IntegrationError):
        HyperVAdapter(FakeRunner({hyperv.LIST_VMS: "garbage"})).list_vms()


VBOX_UUID = "e3f1b3a2-1111-2222-3333-444455556666"


def test_virtualbox_adapter():
    runner = FakeRunner({
        "VBoxManage list vms": f'"lab vm" {{{VBOX_UUID}}}\n',
        f"VBoxManage showvminfo {VBOX_UUID} --machinereadable": 'name="lab vm"\nVMState="running"\ncpus=2\nmemory=2048\nostype="Ubuntu_64"\n',
        "VBoxManage list hostinfo": "Processor count: 8\nMemory size: 16384 MByte\nMemory available: 4096 MByte\n",
        f"VBoxManage snapshot {VBOX_UUID} list --machinereadable": 'SnapshotName="clean"\nSnapshotDescription="fresh"\n',
        f"VBoxManage controlvm {VBOX_UUID} acpipowerbutton": "",
    })
    vb = VirtualBoxAdapter(runner)
    v = vb.list_vms()[0]
    assert (v.name, v.status, v.cpus, v.mem_total) == ("lab vm", "running", 2, 2048 * 1024 ** 2)
    assert vb.hosts()[0].mem_used == 12288 * 1024 ** 2
    assert vb.snapshots(VBOX_UUID)[0].description == "fresh"
    assert vb.power(VBOX_UUID, "shutdown") == "ok"
    with pytest.raises(ValidationError):
        vb.power("lab vm", "start")
    with pytest.raises(ValidationError):
        VirtualBoxAdapter(runner, vboxmanage="VBoxManage; rm -rf /")
    assert parse_list_vms('"x" {bad}\n') == []


DOMSTATS = """Domain: 'web'
  state.state=1
  vcpu.current=2
  balloon.current=2097152
  balloon.maximum=4194304
  balloon.unused=1048576
  block.count=1
  block.0.name=vda
  block.0.path=/var/lib/libvirt/images/web.qcow2
  block.0.capacity=21474836480
  block.0.allocation=5368709120
  cpu.time=123

Domain: 'old'
  state.state=5
"""


def test_libvirt_adapter():
    u = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    runner = FakeRunner({
        "virsh -c qemu:///system domstats --raw": DOMSTATS,
        "virsh -c qemu:///system list --all --uuid --name": f"{u} web\n",
        "virsh -c qemu:///system nodeinfo": "CPU model: x86_64\nCPU(s): 12\nMemory size: 32000000 KiB\n",
        "virsh -c qemu:///system nodememstats": "total  : 32000000 KiB\nfree   : 8000000 KiB\nbuffers: 0 KiB\ncached : 0 KiB\n",
        f"virsh -c qemu:///system snapshot-list {u} --parent": " Name   Creation Time   Parent\n----\n snap1  2024-01-01  -\n snap2  2024-02-01  snap1\n",
        f"virsh -c qemu:///system destroy {u}": "Domain destroyed",
    })
    lv = LibvirtAdapter(runner, "kvm1")
    vms = {v.name: v for v in lv.list_vms()}
    assert vms["web"].id == u and vms["web"].status == "running" and vms["web"].mem_used == 1024 ** 3
    assert vms["web"].disk_total == 21474836480 and vms["old"].status == "stopped"
    assert lv.hosts()[0].cpus == 12 and lv.hosts()[0].mem_used == 24000000 * 1024
    assert [s.parent for s in lv.snapshots(u)] == ["", "snap1"]
    assert lv.power(u, "stop") == "ok" and runner.calls[-1].endswith(f"destroy {u}")
    with pytest.raises(ValidationError):
        lv.power("web", "stop")
    with pytest.raises(ValidationError):
        LibvirtAdapter(runner, uri="qemu:///system; reboot")
    assert parse_domstats("junk") == {}
