"""IPAM/diagnostics/topology, monitoring + alerting, automation (approvals, policies) and backups."""
from __future__ import annotations

import time

import pytest
from conftest import FakeClock

from netcommander.homelab import backups, monitoring, netmgmt
from netcommander.homelab.automation import AutomationCenter, Script, scan_risk
from netcommander.homelab.core.db import Database
from netcommander.homelab.core.errors import NotFound, ValidationError
from netcommander.homelab.core.events import EventBus
from netcommander.homelab.core.notify import Notifier
from netcommander.homelab.core.runners import CommandResult, FakeRunner
from netcommander.homelab.models import Asset
from netcommander.rbac import PermissionDenied, Role


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "h.db")


# ---------------------------------------------------------------- IPAM
def test_ipam_subnets_overlap_and_usage(db):
    ipam = netmgmt.Ipam(db)
    s = ipam.add_subnet("10.0.0.0/24", "lan", vlan=10, gateway="10.0.0.1")
    for bad in (("10.0.0.128/25",), ("10.0.1.0/24", "x", None, "10.0.0.1"), ("nope",), ("10.9.0.0/24", "", 5000)):
        with pytest.raises(ValidationError):
            ipam.add_subnet(*bad)
    ipam.add_subnet("10.0.1.0/24", "iot")
    ipam.reserve("10.0.0.50", "printer")
    with pytest.raises(ValidationError):
        ipam.reserve("10.0.0.50", "dup")
    with pytest.raises(ValidationError):
        ipam.reserve("192.168.9.9", "outside")
    assets = [Asset(name="a", ip="10.0.0.2", mac="aa:aa:aa:aa:aa:01"), Asset(name="b", ip="10.0.0.2", mac="aa:aa:aa:aa:aa:02"),
              Asset(name="c", ip="10.0.0.3", interfaces=[{"addresses": ["10.0.1.9/24"]}])]
    u = {x["cidr"]: x for x in ipam.usage(assets)}
    lan = u["10.0.0.0/24"]
    assert lan["size"] == 254 and lan["used"] == 4 and lan["conflicts"][0]["ip"] == "10.0.0.2"
    assert lan["next_free"][0] == "10.0.0.4" and "10.0.0.50" not in lan["next_free"]
    assert u["10.0.1.0/24"]["used"] == 1
    assert ipam.subnet_for("10.0.1.5")["name"] == "iot" and ipam.subnet_for("8.8.8.8") is None
    ipam.set_vlan(10, "LAN")
    assert ipam.vlans()[0]["subnets"] == ["10.0.0.0/24"]
    with pytest.raises(ValidationError):
        ipam.set_vlan(0, "bad")
    assert ipam.delete_vlan(10) and ipam.delete_subnet(s["id"])
    with pytest.raises(NotFound):
        ipam.get_subnet(s["id"])


def test_diagnostics_validation_and_parsing():
    for bad in ("-oProxyCommand=evil", "a b", "x;y", "", "$(id)"):
        with pytest.raises(ValidationError):
            netmgmt.valid_target(bad)
    assert netmgmt.valid_target("nas.lan") == "nas.lan" and netmgmt.valid_target("10.0.0.1") == "10.0.0.1"
    assert netmgmt.ping_command("10.0.0.1", 99).split()[2] in ("20",)
    linux = "4 packets transmitted, 4 received, 0% packet loss, time 3004ms\nrtt min/avg/max/mdev = 0.3/0.5/0.9/0.1 ms"
    assert netmgmt.parse_ping(linux) == {"loss_pct": 0.0, "min_ms": 0.3, "avg_ms": 0.5, "max_ms": 0.9}
    win = "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n    Minimum = 1ms, Maximum = 3ms, Average = 2ms"
    assert netmgmt.parse_ping(win)["avg_ms"] == 2.0
    d = netmgmt.Diagnostics(runner=FakeRunner({"ping*": linux}), probe=lambda h, p, t: "open",
                            resolver=lambda h: ["10.0.0.9"])
    assert d.ping("10.0.0.1")["avg_ms"] == 0.5
    assert d.tcp("nas.lan", 445)["ok"] and d.dns("nas.lan")["addresses"] == ["10.0.0.9"]
    with pytest.raises(ValidationError):
        d.tcp("nas", 70000)


def test_topology_merges_links_and_parents():
    sw = Asset(id="net-sw", name="sw", kind="switch")
    host = Asset(id="h", name="pve", kind="hypervisor", links=[{"to": "net-sw", "type": "connected_to", "port": "Gi1"}])
    vm = Asset(id="v", name="vm", kind="vm", parent="h")
    back = Asset(id="net-sw2", name="sw2", kind="switch", links=[{"to": "h", "type": "connected_to", "port": ""},
                                                                  {"to": "missing", "type": "connected_to"}])
    t = netmgmt.topology([sw, host, vm, back])
    assert {(e["from"], e["to"], e["type"]) for e in t["edges"]} == {("h", "net-sw", "connected_to"), ("v", "h", "runs_on"),
                                                                     ("net-sw2", "h", "connected_to")}
    assert {n["id"]: n["tier"] for n in t["nodes"]} == {"net-sw": 1, "h": 2, "v": 4, "net-sw2": 1}


# ---------------------------------------------------------------- monitoring
@pytest.fixture
def mon(db):
    clock = FakeClock(10_000)
    bus, events, notes = EventBus(), [], []
    bus.subscribe("*", events.append)

    class Ch:
        name, min_severity = "t", "info"

        def send(self, n):
            notes.append(n)
    assets = {"srv": Asset(id="srv", name="srv01", kind="server", tags=["prod"]),
              "nas": Asset(id="nas", name="nas01", kind="nas")}
    eng = monitoring.MonitoringEngine(db, bus, Notifier([Ch()], dedup_window=0, clock=clock), assets.get, clock=clock,
                                      probe=lambda h, p, t: "open" if h == "10.0.0.5" else "filtered",
                                      http=lambda c: {"up": 1.0, "latency_ms": 5.0, "cert_days": 3.0})
    eng.events, eng.notes, eng.clock = events, notes, clock
    return eng


def test_rule_validation_and_levels():
    r = monitoring.Rule("cpu_pct", "above", 80, 90).validate()
    assert (r.level(50), r.level(85), r.level(95)) == ("ok", "warning", "critical")
    b = monitoring.Rule("up", "below", None, 1).validate()
    assert b.level(0) == "critical" and b.level(1) == "ok"
    for bad in (dict(metric=""), dict(metric="x", warning=None, critical=None), dict(metric="x", warning=95, critical=90),
                dict(metric="x", direction="sideways", warning=1)):
        with pytest.raises(ValidationError):
            monitoring.Rule(**bad).validate()
    r2 = monitoring.Rule("cpu_pct", warning=1, scope_kind="nas")
    assert not r2.applies(Asset(name="s", kind="server"), "s") and r2.applies(Asset(name="n", kind="nas"), "n")
    assert not monitoring.Rule("x", warning=1, scope_tag="prod").applies(None, "t")


def test_alert_lifecycle_with_hysteresis(mon):
    assert mon.ingest("srv", {"cpu_pct": 99}) == []                   # for_count=3
    mon.ingest("srv", {"cpu_pct": 99})
    raised = mon.ingest("srv", {"cpu_pct": 99})
    assert raised[0]["severity"] == "critical" and raised[0]["target_name"] == "srv01"
    assert mon.ingest("srv", {"cpu_pct": 99}) == []                   # still active: no duplicate
    assert mon.ingest("srv", {"cpu_pct": 10}) == []                   # one good sample is not enough
    resolved = mon.ingest("srv", {"cpu_pct": 10})
    assert resolved[0]["state"] == "resolved"
    kinds = [e.kind for e in mon.events]
    assert kinds.count("alert.raised") == 1 and kinds.count("alert.resolved") == 1
    assert [n.severity for n in mon.notes] == ["critical", "info"]
    assert mon.alerts() == [] and len(mon.alerts(include_resolved=True)) == 1


def test_disk_alert_immediate_and_ack(mon):
    a = mon.ingest("nas", {"disk_pct": 90, "pools_unhealthy": 1})
    assert {x["metric"] for x in a} == {"disk_pct", "pools_unhealthy"}
    top = mon.alerts()[0]
    assert top["severity"] == "critical"
    acked = mon.acknowledge(top["id"], "alice")
    assert acked["acked_by"] == "alice"
    with pytest.raises(NotFound):
        mon.acknowledge("nope", "alice")
    escalated = mon.ingest("nas", {"disk_pct": 97})
    assert escalated and escalated[0]["severity"] == "critical"


def test_checks_sweep_and_metrics(mon, db):
    mon.add_check({"target": "srv", "type": "reachability", "host": "10.0.0.5", "attempts": 2})
    mon.add_check({"target": "nas", "type": "reachability", "host": "10.0.0.6"})
    mon.add_check({"target": "srv", "type": "http", "url": "https://srv/health", "name": "web"})
    with pytest.raises(ValidationError):
        mon.add_check({"target": "srv", "type": "tcp", "host": "-x", "port": 22})
    with pytest.raises(ValidationError):
        mon.add_check({"target": "srv", "type": "http", "url": "ftp://x"})
    res = mon.sweep()
    assert len(res) == 3
    latest = db.latest_metrics("srv")
    assert latest["up"][1] == 1.0 and "latency_ms" in latest and latest["cert_days"][1] == 3.0
    assert db.latest_metrics("nas")["up"][1] == 0.0
    mon.clock.advance(60)
    mon.sweep()
    assert any(a["metric"] == "up" and a["target"] == "nas" for a in mon.alerts())      # down twice -> critical
    assert any(a["metric"] == "cert_days" for a in mon.alerts())


def test_custom_rules_and_prune(mon, db):
    r = mon.set_rule({"metric": "temp", "warning": 40, "scope_asset": "srv", "name": "Room temp"})
    assert mon.ingest("srv", {"temp": 45})[0]["rule_name"] == "Room temp"
    assert mon.remove_rule(r.id)
    mon.clock.advance(40 * 86400)
    m, _e = mon.prune(30, 90)
    assert m >= 1


def test_reachability_measurement():
    states = iter(["open", "open", "filtered", "open"])
    res = monitoring.run_reachability("h", [22], 3, 1.0, probe=lambda h, p, t: next(states))
    assert res["up"] == 1.0 and res["loss_pct"] == 33.3 and "jitter_ms" in res
    assert monitoring.run_reachability("h", [22, 80], 3, 1.0, probe=lambda *a: "filtered") == {"up": 0.0, "loss_pct": 100.0}


def test_http_check_with_fake_opener():
    class Resp:
        status = 200
        def read(self, n): return b"ok healthy"
        def __enter__(self): return self
        def __exit__(self, *a): pass
    c = monitoring.Check(target="t", type="http", url="https://x/health", keyword="healthy")
    assert monitoring.run_http(c, opener=lambda *a, **k: Resp())["up"] == 1.0
    c.keyword = "missing"
    assert monitoring.run_http(c, opener=lambda *a, **k: Resp())["up"] == 0.0


def test_scores_reports_rates(db):
    a = Asset(id="a", name="a", kind="nas", status="online")
    off = Asset(id="b", name="b", kind="server", status="offline")
    alerts = [{"target": "a", "severity": "critical", "state": "active"}, {"target": "a", "severity": "warning", "state": "active"}]
    assert monitoring.health_score(a, alerts) == 45 and monitoring.health_score(off, []) == 0
    assert monitoring.infrastructure_score([a, off], alerts) == round((45 * 3 + 0 * 2) / 5)
    assert monitoring.infrastructure_score([], []) is None
    now = time.time()
    db.add_metrics("a", {"cpu_pct": 10}, now - 100)
    db.add_metrics("a", {"cpu_pct": 30}, now - 50)
    rep = monitoring.utilization_report(db, [a, off], 24, now)
    assert rep == [{"id": "a", "name": "a", "kind": "nas", "status": "online", "cpu_pct": {"last": 30.0, "avg": 20.0, "max": 30.0}}]
    assert monitoring.counter_rate([(0, 0), (10, 100), (20, 50), (30, 150)]) == [(10, 10.0), (30, 10.0)]


# ---------------------------------------------------------------- automation
@pytest.fixture
def auto(db):
    audit, runners = [], {}

    def factory(target, kind):
        return runners.setdefault(target, FakeRunner({"*": "done"}))
    a = AutomationCenter(db, EventBus(), factory, lambda *x: audit.append(x),
                         {"require_approval_for": ["change", "destructive"], "max_output_kb": 64},
                         python_exec=lambda body, t, m: CommandResult("python", 0, "py-ok password=hunter2"))
    a.audit_log, a.runners = audit, runners
    return a


def test_risk_scanner():
    assert scan_risk("df -h")[0] == "read_only"
    assert scan_risk("systemctl restart nginx")[0] == "change"
    assert scan_risk("rm -rf /srv/old")[0] == "destructive"
    assert scan_risk("Restart-Computer -Force")[0] == "destructive"
    assert scan_risk("echo hi > /etc/motd")[0] == "change"
    assert scan_risk("ls 2>/dev/null")[0] == "read_only"


def test_script_validation(auto):
    with pytest.raises(ValidationError, match="looks 'destructive'"):
        auto.save_script("admin", Role.ADMIN, {"name": "sneaky", "kind": "ssh", "risk": "read_only", "body": "rm -rf /"})
    with pytest.raises(ValidationError, match="placeholder"):
        auto.save_script("admin", Role.ADMIN, {"name": "p", "kind": "ssh", "risk": "read_only", "body": "echo {{x}}"})
    with pytest.raises(PermissionDenied):
        auto.save_script("op", Role.OPERATOR, {"name": "x", "kind": "ssh", "risk": "read_only", "body": "uptime"})
    with pytest.raises(ValidationError):
        auto.save_script("admin", Role.ADMIN, {"id": "builtin-disk-report", "name": "x", "kind": "ssh", "risk": "read_only",
                                               "body": "uptime"})
    with pytest.raises(ValidationError):
        auto.delete_script("admin", Role.ADMIN, "builtin-disk-report")
    s = auto.save_script("admin", Role.ADMIN, {"name": "uptime", "kind": "ssh", "risk": "read_only", "body": "uptime"})
    assert any(x["id"] == s.id and not x["needs_approval"] for x in auto.scripts())
    assert len([x for x in auto.scripts() if x["builtin"]]) >= 6


def test_parameter_validation_blocks_injection():
    s = Script(name="r", kind="ssh", risk="change", body="systemctl restart {{service}}",
               params=[{"name": "service", "pattern": r"^[a-z]+$"}]).validate()
    assert s.render({"service": "nginx"}) == "systemctl restart nginx"
    for bad in ({"service": "nginx; reboot"}, {"service": "$(id)"}, {"service": "x", "other": "y"}):
        with pytest.raises(ValidationError):
            s.render(bad)


def test_read_only_runs_immediately_and_redacts(auto):
    run = auto.request("op", Role.OPERATOR, "builtin-disk-report", ["srv1", "srv2"])
    assert run["status"] == "approved"
    done = auto.execute("op", Role.OPERATOR, run["id"])
    assert done["status"] == "succeeded" and set(done["results"]) == {"srv1", "srv2"}
    with pytest.raises(PermissionDenied):
        auto.request("v", Role.VIEWER, "builtin-disk-report", ["srv1"])
    with pytest.raises(ValidationError):
        auto.request("op", Role.OPERATOR, "builtin-disk-report", [])
    s = auto.save_script("admin", Role.ADMIN, {"name": "report", "kind": "python", "risk": "read_only", "body": "print(1)"})
    r = auto.execute("admin", Role.ADMIN, auto.request("admin", Role.ADMIN, s.id, [])["id"])
    assert "hunter2" not in r["results"]["local"]["stdout"]
    with pytest.raises(ValidationError):
        auto.request("admin", Role.ADMIN, s.id, ["srv1"])


def test_change_requires_second_person_and_is_bound_to_content(auto):
    run = auto.request("op", Role.OPERATOR, "builtin-restart-service", ["srv1"], {"service": "nginx"})
    assert run["status"] == "pending_approval"
    with pytest.raises(ValidationError):
        auto.execute("op", Role.OPERATOR, run["id"])
    with pytest.raises(PermissionDenied):
        auto.decide("op2", Role.OPERATOR, run["id"], True)
    admin_run = auto.request("boss", Role.ADMIN, "builtin-restart-service", ["srv1"], {"service": "nginx"})
    with pytest.raises(PermissionDenied, match="own request"):
        auto.decide("boss", Role.ADMIN, admin_run["id"], True)
    auto.decide("boss", Role.ADMIN, run["id"], True, "ok")
    with pytest.raises(ValidationError):
        auto.decide("boss", Role.ADMIN, run["id"], True)
    with pytest.raises(PermissionError):
        auto.execute("someone", Role.OPERATOR, run["id"])
    done = auto.execute("op", Role.OPERATOR, run["id"])
    assert done["status"] == "succeeded" and auto.runners["srv1"].calls[-1] == "systemctl restart nginx && systemctl is-active nginx"
    s = auto.save_script("boss", Role.ADMIN, {"name": "restart", "kind": "ssh", "risk": "change", "body": "systemctl restart x"})
    r2 = auto.request("op", Role.OPERATOR, s.id, ["srv1"])
    auto.decide("boss", Role.ADMIN, r2["id"], True)
    auto.save_script("boss", Role.ADMIN, {"id": s.id, "name": "restart", "kind": "ssh", "risk": "change",
                                          "body": "systemctl restart y"})
    assert auto.execute("op", Role.OPERATOR, r2["id"])["status"] == "failed"            # edited after approval
    actions = [a[1] for a in auto.audit_log]
    assert "automation.approve" in actions and ("boss", "automation.decide", admin_run["id"], "denied", "self-approval") in auto.audit_log


def test_reject_and_cancel(auto):
    r = auto.request("op", Role.OPERATOR, "builtin-restart-service", ["s"], {"service": "x"})
    assert auto.decide("boss", Role.ADMIN, r["id"], False, "no")["status"] == "rejected"
    r2 = auto.request("op", Role.OPERATOR, "builtin-restart-service", ["s"], {"service": "x"})
    with pytest.raises(PermissionError):
        auto.cancel("other", r2["id"])
    assert auto.cancel("op", r2["id"])["status"] == "cancelled"


def test_target_failure_is_captured(auto):
    auto.runners["bad"] = FakeRunner({"*": ConnectionError("ssh refused password=x")})
    r = auto.execute("op", Role.OPERATOR, auto.request("op", Role.OPERATOR, "builtin-disk-report", ["bad", "ok"])["id"])
    assert r["status"] == "failed" and r["results"]["ok"]["ok"] and not r["results"]["bad"]["ok"]


def test_workflows(auto):
    wf = auto.save_workflow("boss", Role.ADMIN, "check", [
        {"script_id": "builtin-disk-report", "targets": ["a"]},
        {"script_id": "builtin-restart-service", "targets": ["a"], "params": {"service": "nginx"}},
        {"script_id": "builtin-failed-units", "targets": ["a"]}])
    assert wf["risk"] == "change"
    runs = auto.run_workflow("op", Role.OPERATOR, wf["id"])
    assert [r["status"] for r in runs] == ["succeeded", "pending_approval"]
    with pytest.raises(ValidationError):
        auto.save_workflow("boss", Role.ADMIN, "", [])


def test_remediation_policy(auto):
    clock = FakeClock(1000)
    auto._clock = clock
    with pytest.raises(PermissionDenied):
        auto.add_policy("op", Role.OPERATOR, {"script_id": "builtin-restart-service", "alert_metric": "failed_services"})
    with pytest.raises(ValidationError):
        auto.add_policy("boss", Role.ADMIN, {"script_id": "builtin-restart-service", "alert_metric": "x", "valid_days": 400,
                                             "params": {"service": "nginx"}})
    d = auto.save_script("boss", Role.ADMIN, {"name": "nuke", "kind": "ssh", "risk": "destructive", "body": "reboot"})
    with pytest.raises(ValidationError, match="allow_destructive"):
        auto.add_policy("boss", Role.ADMIN, {"script_id": d.id, "alert_metric": "up"})
    p = auto.add_policy("boss", Role.ADMIN, {"script_id": "builtin-restart-service", "alert_metric": "failed_services",
                                             "params": {"service": "nginx"}, "min_severity": "warning", "valid_days": 1})
    alert = {"id": "r-svc:srv1", "metric": "failed_services", "severity": "warning", "target": "srv1"}
    fired = auto.on_alert(alert, "server")
    assert fired[0]["status"] == "succeeded" and fired[0]["approved_by"] == f"policy:{p.id}"
    assert auto.on_alert(alert, "server") == []                  # cooldown
    clock.advance(2 * 86400)
    assert auto.on_alert(alert, "server") == []                  # expired
    assert auto.on_alert({**alert, "metric": "cpu_pct"}, "server") == []
    assert auto.remove_policy("boss", Role.ADMIN, p.id)


def test_real_python_executor_is_isolated(monkeypatch):
    from netcommander.homelab.automation import run_python
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", "leak-me")
    r = run_python("import os, sys; print(os.environ.get('NETCOMMANDER_VAULT_PASSWORD')); print(sys.flags.isolated)", 30, 4096)
    assert r.ok and r.stdout.split() == ["None", "1"]
    slow = run_python("import time; time.sleep(5)", 1, 100)
    assert slow.exit_code == 124


# ---------------------------------------------------------------- backups
def test_backup_job_validation(db):
    bc = backups.BackupCenter(db)
    for bad in ({"name": "", "platform": "file"}, {"name": "x", "platform": "tape"}, {"name": "x", "platform": "proxmox"},
                {"name": "x", "platform": "file", "match": "/srv/back ups; rm"}, {"name": "x", "platform": "file", "match": "/a/../b"}):
        with pytest.raises(ValidationError):
            bc.save_job(bad)
    j = bc.save_job({"name": "vm backups", "platform": "proxmox", "integration": "pve", "match": "101", "bogus": 1})
    assert bc.job(j.id).match == "101"


def test_backup_evaluation():
    now = 100 * 3600.0
    job = backups.BackupJob("j", "file", max_age_hours=24, min_size=100)
    ok = backups.evaluate(job, [{"ts": now - 3600, "size": 1000}, {"ts": now - 90000, "size": 900}], now)
    assert ok.state == "ok" and ok.age_hours == 1.0 and ok.verified == {"age_ok": True, "size_ok": True, "no_size_drop": True}
    stale = backups.evaluate(job, [{"ts": now - 30 * 3600, "size": 1000}], now)
    assert stale.state == "stale"
    small = backups.evaluate(job, [{"ts": now - 90000, "size": 1000}, {"ts": now - 60, "size": 200}], now)
    assert small.state == "failed" and "small" in small.message
    failed = backups.evaluate(job, [{"ts": now - 7200, "size": 500}], now, [{"ts": now - 60, "message": "ERROR"}])
    assert failed.state == "failed" and failed.message == "ERROR"
    assert backups.evaluate(job, [], now).state == "unknown"
    assert backups.evaluate(job, [], now, [{"ts": 1}]).state == "failed"


def test_backup_sources(tmp_path):
    d = tmp_path / "bk"
    d.mkdir()
    (d / "old.tar").write_bytes(b"x" * 10)
    newest = d / "new.tar"
    newest.write_bytes(b"y" * 20)
    import os
    os.utime(d / "old.tar", (1000, 1000))
    pts = backups.file_points_local(str(d), checksum=True)
    assert pts[0]["name"] == "new.tar" and pts[0]["size"] == 20 and len(pts[0]["sha256"]) == 64
    with pytest.raises(ValidationError):
        backups.file_points_local(str(tmp_path / "missing"))
    r = FakeRunner({"stat -c '%Y %s %n' /srv/bk/*": "1700000000 100 /srv/bk/a.tar\n1700000100 120 /srv/bk/b.tar\njunk\n"})
    assert [p["name"] for p in backups.file_points_remote(r, "/srv/bk/")] == ["b.tar", "a.tar"]
    with pytest.raises(ValidationError):
        backups.file_points_remote(r, "/srv/bk;reboot")
    good, bad = backups.proxmox_points([{"vmid": "101", "end": 5, "status": "OK"}, {"vmid": "101", "end": 6, "status": "ERROR: x"},
                                        {"vmid": "102", "end": 7, "status": "OK"}, {"vmid": "101", "status": "running"}], "101")
    assert len(good) == 1 and bad[0]["message"] == "ERROR: x"
    g2, b2 = backups.truenas_points([{"name": "r", "state": "FINISHED", "last": 1700000000000}, {"name": "r", "state": "ERROR", "last": 5}], "r")
    assert g2[0]["ts"] == 1700000000.0 and len(b2) == 1


def test_manual_runs_status_and_runbook(db):
    bc = backups.BackupCenter(db)
    j = bc.save_job({"name": "offsite disk", "platform": "manual", "max_age_hours": 24 * 7, "source_asset": "nas",
                     "destination": "USB disk in safe", "notes": "Plug in, run restore.sh"})
    bc.record_manual(j.id, True, 5000)
    bc.record_manual(j.id, False, message="disk full")
    good, bad = bc.manual_points(j.id)
    st = backups.evaluate(j, good, time.time(), bad)
    bc.store_status(st)
    assert bc.statuses()[0]["status"]["state"] == "failed"
    with pytest.raises(NotFound):
        bc.record_manual("nope", True)
    assets = [Asset(id="sw", name="core-sw", kind="switch", ip="10.0.0.2"),
              Asset(id="nas", name="nas01", kind="nas", ip="10.0.0.10", links=[{"to": "sw", "type": "connected_to", "port": "Gi1/0/3"}],
                    management={"ssh": {"username": "admin", "host": "10.0.0.10", "password_ref": "x"}}),
              Asset(id="vm", name="web", kind="vm", parent="nas")]
    md = backups.recovery_runbook(assets, bc.statuses(), "alice")
    assert md.index("Switch") < md.index("Nass") if "Nass" in md else md.index("core-sw") < md.index("nas01")
    assert "offsite disk" in md and "Plug in, run restore.sh" in md and "connected to core-sw (Gi1/0/3)" in md
    assert "Hosts:** web" in md and "none registered" in md and "password_ref" not in md


def test_config_bundle_has_no_secrets(db):
    db.put("integrations", "pve", {"id": "pve", "config": {"url": "https://pve", "token_ref": "pve.tok", "password": "oops"}})
    b = backups.config_bundle(db, {"api": {"bind": "127.0.0.1"}}, "4.0.0")
    cfg = b["collections"]["integrations"][0]["config"]
    assert cfg["token_ref"] == "pve.tok" and cfg["password"] == "********"


def test_unknown_status_does_not_count_as_healthy():
    assert monitoring.infrastructure_score([Asset(name="sw", kind="switch", status="unknown")], []) is None
    mixed = [Asset(name="sw", kind="switch", status="unknown"), Asset(id="s", name="s", kind="server", status="offline")]
    assert monitoring.infrastructure_score(mixed, []) == 0
