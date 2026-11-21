"""HomelabPlatform end to end with real adapters over simulated devices."""
from __future__ import annotations

import time

import pytest
from homelab_fixtures import ADMIN, OPER, VIEWER, build_platform, populate

from netcommander.homelab.core.errors import AuthorizationRequired, IntegrationError, ValidationError
from netcommander.rbac import PermissionDenied


@pytest.fixture
def plat(tmp_path):
    p = build_platform(tmp_path)
    yield p
    p.stop()


def test_integrations_store_secrets_encrypted_and_enforce_rbac(plat, tmp_path):
    with pytest.raises(PermissionDenied):
        plat.add_integration(OPER, "docker", "docker", "x", {"url": "unix:///x"})
    with pytest.raises(ValidationError):
        plat.add_integration(ADMIN, "hypervisor", "proxmox", "pve", {"url": "https://p", "token_id": "a"}, {"url": "nope"})
    populate(plat)
    assert plat.seen_secrets["proxmox"] == "pve-token-value"
    raw = (tmp_path / "homelab_secrets.json").read_text() + (tmp_path / "homelab.db").read_bytes().decode("latin-1")
    assert "pve-token-value" not in raw and "tn-key-value" not in raw
    recs = {r["id"]: r for r in plat.integrations(VIEWER)}
    assert recs["pve"]["config"]["token_ref"] == "int.pve.token" and recs["pve"]["ok"]
    assert recs["tn"]["summary"]["health"] == "critical"
    assert any(e["action"] == "integration.save" for e in plat.audit_log.entries())


def test_polling_builds_unified_inventory(plat):
    populate(plat)
    assets = {a["name"]: a for a in plat.assets(VIEWER)}
    host = assets["pve1"]
    assert host["kind"] == "hypervisor" and host["extra"]["allocation"]["vms"] == 2
    assert assets["web"]["kind"] == "vm" and assets["web"]["parent"] == host["id"]
    assert assets["dns"]["kind"] == "container" and assets["dns"]["status"] == "stopped"
    assert assets["dock1"]["kind"] == "docker_host" and assets["db"]["status"] == "degraded"
    nas = assets["truenas"]
    assert nas["kind"] == "nas" and nas["ip"] == "10.0.0.10" and nas["status"] == "degraded"
    assert assets["core-sw"]["source"] == "network"
    alerts = plat.monitor.alerts()
    assert any(a["metric"] == "pools_unhealthy" and a["severity"] == "critical" for a in alerts)
    assert any(a["metric"] == "disk_pct" for a in alerts)                 # pool at 90%
    plat.poll_integration("pve")
    assert len([a for a in plat.assets(VIEWER) if a["kind"] == "vm"]) == 2  # web + template  # idempotent


def test_integration_failure_marks_host_offline(plat):
    populate(plat)
    plat.test_apis["pve"].routes.clear()
    with pytest.raises(IntegrationError):
        plat.poll_integration("pve")
    rec = plat.integration("pve")
    assert rec["ok"] is False and "404" in rec["last_error"]
    assert plat.inventory.get(rec["host_asset"]).status == "offline"


def test_vm_power_needs_permission_and_confirmation(plat):
    populate(plat)
    with pytest.raises(PermissionDenied):
        plat.vm_power(OPER, "pve", "pve1/qemu/101", "shutdown")
    with pytest.raises(AuthorizationRequired) as ei:
        plat.vm_power(ADMIN, "pve", "pve1/qemu/101", "shutdown")
    assert not any(c[0] == "POST" for c in plat.test_apis["pve"].calls)       # nothing sent before confirmation
    res = plat.vm_power(ADMIN, "pve", "pve1/qemu/101", "shutdown", ei.value.token)
    assert res["result"] == "UPID:pve1:0001"
    with pytest.raises(ValidationError):
        plat.vm_power(ADMIN, "pve", "pve1/qemu/101", "destroy")
    details = plat.vm_details(VIEWER, "pve", "pve1/qemu/101")
    assert details["snapshots"][0]["name"] == "pre-upgrade" and "cipassword" not in details["config"]
    acts = [(e["action"], e["outcome"]) for e in plat.audit_log.entries()]
    assert ("deny.vm.shutdown", "denied") in acts and ("vm.shutdown", "ok") in acts


def test_container_operations(plat):
    populate(plat)
    with pytest.raises(PermissionDenied):
        plat.container_logs(VIEWER, "dock", "web")
    logs = plat.container_logs(OPER, "dock", "web")
    assert logs[0]["line"] == "hello"
    assert plat.container_inspect(VIEWER, "dock", "web")["inspect"]["Config"]["Env"][0] == "DB_PASSWORD=********"
    with pytest.raises(AuthorizationRequired) as ei:
        plat.container_action(ADMIN, "dock", "web", "restart")
    assert plat.container_action(ADMIN, "dock", "web", "restart", ei.value.token)["result"] == "ok"
    ov = plat.docker_overview(VIEWER, "dock")
    assert ov["projects"][0]["status"] == "degraded"
    with pytest.raises(ValidationError):
        plat.docker_overview(VIEWER, "pve")


def test_storage_overview_forecast_and_checks(plat):
    populate(plat)
    s = plat.storage_overview(VIEWER)[0]
    assert s["pools"][0]["name"] == "tank" and "forecast" in s["pools"][0] and s["health"] == "critical"
    plat.inventory.update(s["asset"], {"ip": "10.0.0.20"})
    checks = plat.storage_connectivity(OPER, s["asset"], ["nfs", "iscsi"])
    assert all(c["ok"] for c in checks)
    with pytest.raises(ValidationError):
        plat.storage_connectivity(OPER, s["asset"], ["ftp"])


def test_discovery_and_server_collection(plat):
    with pytest.raises(PermissionDenied):
        plat.run_discovery(VIEWER, ["10.0.0.0/28"])
    res = plat.run_discovery(OPER, ["10.0.0.0/27"])
    assert res == {"scanned": ["10.0.0.0/27"], "alive": 3, "new": 3}
    by_ip = {a["ip"]: a for a in plat.assets(VIEWER) if a["source"] == "discovery"}
    assert by_ip["10.0.0.1"]["kind"] == "hypervisor" and by_ip["10.0.0.20"]["manufacturer"] == "Synology"
    srv = by_ip["10.0.0.5"]
    plat.update_asset(OPER, srv["id"], {"management": {"ssh": {"host": "10.0.0.5", "username": "mon"}}})
    out = plat.collect_server(srv["id"])
    assert out["reachable"] and out["metrics"]["cpu_pct"] == 50.0
    detail = plat.server_details(VIEWER, srv["id"])
    assert detail["details"]["failed_services"] == ["nginx"]
    assert plat.asset(VIEWER, srv["id"])["metrics"]["mem_pct"] == 50.0
    assert plat.server_connectivity(VIEWER, srv["id"])["ports"]["ssh"] == "open"
    with pytest.raises(ValidationError):
        plat.update_asset(OPER, srv["id"], {"management": {"ssh": {"password": "plaintext"}}})
    t = plat.start_discovery(OPER, ["10.0.0.4/32"])
    assert plat.tasks.wait(t.id, 10).status == "done"
    with pytest.raises(ValidationError):
        plat.start_discovery(OPER, ["10.0.0.0/8"])


def test_monitor_cycle_auto_checks_and_dashboard(plat):
    populate(plat)
    plat.run_discovery(OPER, ["10.0.0.0/27"])
    plat.monitor_cycle()
    targets = {c.target for c in plat.monitor.checks()}
    assert "net-core-sw" in targets
    d = plat.dashboard(VIEWER)
    assert d["totals"]["devices"] >= 10 and d["vms"]["total"] == 1 and d["containers"]["unhealthy"] == 1
    assert d["alerts"]["critical"] >= 1 and d["storage"]["total"] == 1000 and isinstance(d["health"], int)
    assert any(e["kind"] == "asset.discovered" for e in plat.db.events(200))
    rep = plat.report(VIEWER)
    assert any(r["kind"] == "hypervisor" for r in rep["rows"])
    a = plat.monitor.alerts()[0]
    with pytest.raises(PermissionDenied):
        plat.acknowledge_alert(VIEWER, a["id"])
    assert plat.acknowledge_alert(OPER, a["id"])["acked_by"] == "op@example.com"
    with pytest.raises(PermissionDenied):
        plat.set_rule(OPER, {"metric": "x", "warning": 1})


def test_asset_crud_through_platform(plat):
    a = plat.create_asset(OPER, {"name": "printer", "kind": "printer", "ip": "10.0.0.99"})
    with pytest.raises(PermissionDenied):
        plat.create_asset(VIEWER, {"name": "x"})
    with pytest.raises(AuthorizationRequired) as ei:
        plat.delete_asset(OPER, a["id"])
    assert plat.delete_asset(OPER, a["id"], ei.value.token)
    r = plat.import_assets_csv(OPER, "name,kind\nnas2,nas\n")
    assert r["created"] == 1
    assert "nas2" in plat.export_inventory(VIEWER, "csv")


def test_automation_through_platform(plat):
    populate(plat)
    srv = plat.create_asset(ADMIN, {"name": "srv", "kind": "server", "ip": "10.0.0.5",
                                    "management": {"ssh": {"host": "10.0.0.5", "username": "root"}}})
    run = plat.run_script(OPER, "builtin-disk-report", [srv["id"]])
    def wait(rid):
        deadline = time.time() + 10
        while plat.automation.run_record(rid)["status"] in ("approved", "running") and time.time() < deadline:
            time.sleep(0.05)
        return plat.automation.run_record(rid)
    assert wait(run["id"])["status"] == "succeeded"
    pending = plat.run_script(OPER, "builtin-restart-service", [srv["id"]], {"service": "nginx"})
    assert pending["status"] == "pending_approval"
    plat.approve_run(ADMIN, pending["id"], True)
    done = wait(pending["id"])
    assert done["status"] == "succeeded" and done["approved_by"] == "admin@example.com"


def test_backups_runbook_and_config_export(plat, tmp_path):
    populate(plat)
    d = tmp_path / "dumps"
    d.mkdir()
    (d / "vzdump-1.tar.zst").write_bytes(b"x" * 100)
    with pytest.raises(PermissionDenied):
        plat.save_backup_job(OPER, {"name": "x", "platform": "manual"})
    now = time.time()
    plat.test_apis["pve"].routes[("GET", "/api2/json/nodes/pve1/tasks")] = {"data": [
        {"id": "101", "starttime": now - 600, "endtime": now - 300, "status": "OK"}]}
    pve_job = plat.save_backup_job(ADMIN, {"name": "web vm", "platform": "proxmox", "integration": "pve", "match": "101",
                                           "max_age_hours": 26, "source_asset": plat.inventory.search("web")[0].id})
    plat.save_backup_job(ADMIN, {"name": "dumps", "platform": "file", "match": str(d), "checksum": True})
    plat.save_backup_job(ADMIN, {"name": "never", "platform": "manual"})
    out = {s["job_id"]: s for s in plat.backup_cycle()}
    assert out[pve_job["id"]]["state"] == "ok"
    states = sorted(s["state"] for s in out.values())
    assert states == ["ok", "ok", "unknown"]
    md = plat.runbook(VIEWER)
    assert "web vm" in md and "pve1" in md
    bundle = plat.config_bundle(ADMIN)
    assert "pve-token-value" not in str(bundle) and bundle["collections"]["integrations"]
    with pytest.raises(PermissionDenied):
        plat.config_bundle(OPER)


def test_remove_integration_deletes_its_secrets(plat):
    populate(plat)
    with pytest.raises(AuthorizationRequired) as ei:
        plat.remove_integration(ADMIN, "pve")
    assert plat.remove_integration(ADMIN, "pve", ei.value.token)
    assert not plat.secrets.has("int.pve.token")


def test_invalid_homelab_config_is_rejected(tmp_path):
    from netcommander.homelab.core.errors import ConfigError
    with pytest.raises(ConfigError):
        build_platform(tmp_path, config={"monitoring": {"interval_seconds": 1}})


def test_discovery_merges_with_integration_host_not_vms(plat):
    plat.test_apis["pve"].routes[("GET", "/api2/json/nodes")] = {"data": [
        {"node": "pve1", "status": "online", "cpu": 0.25, "maxcpu": 8, "mem": 8e9, "maxmem": 32e9}]}
    plat.add_integration(ADMIN, "hypervisor", "proxmox", "pve", {"url": "https://10.0.0.1:8006", "token_id": "m@pve!x"},
                         {"token": "t"}, iid="pve")
    plat.poll_integration("pve")
    host = [a for a in plat.assets(VIEWER) if a["kind"] == "hypervisor"]
    assert len(host) == 1 and host[0]["ip"] == "10.0.0.1"
    plat.run_discovery(OPER, ["10.0.0.1/32"])
    hosts = [a for a in plat.assets(VIEWER) if a["ip"] == "10.0.0.1"]
    assert len(hosts) == 1 and hosts[0]["integration"] == "pve"           # merged, not duplicated
    assert hosts[0]["extra"]["open_ports"] == [22, 8006]
    vm = plat.inventory.upsert_observed({"integration": "pve", "external_id": "pve1/qemu/7", "name": "v", "kind": "vm",
                                         "ip": "10.0.0.77"})[0]
    found, created = plat.inventory.upsert_observed({"ip": "10.0.0.77", "name": "10.0.0.77"})
    assert created and found.id != vm.id                                     # discovery never overwrites a VM
