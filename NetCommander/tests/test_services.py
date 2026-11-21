from __future__ import annotations

import pytest
from conftest import FAST_KDF

from netcommander import network
from netcommander.config import Paths, RuntimeSettings
from netcommander.rbac import Permission as P
from netcommander.rbac import PermissionDenied
from netcommander.security import AuthManager
from netcommander.services import Services
from netcommander.store import DeviceStore

PW = "longpassword1"


@pytest.fixture
def svc(tmp_path, vault, fake_netmiko):
    paths = Paths.for_root(tmp_path)
    auth = AuthManager(paths.auth, iterations=FAST_KDF)
    auth.create_account("adm@example.com", PW)
    auth.create_account("op@example.com", PW, created_by="adm@example.com")
    auth.create_account("view@example.com", PW, role="viewer", created_by="adm@example.com")
    store = DeviceStore()
    store.add("R1", {"device_type": "cisco_ios", "host": "10.0.0.1", "username": "admin"})
    store.add("R2", {"device_type": "cisco_ios", "host": "10.0.0.2", "username": "admin"})
    vault.set_secret("R1", "admin", "pw1"); vault.set_secret("R2", "admin", "pw2")

    def make(user):
        return Services(paths, user, vault, store, RuntimeSettings(env={}), auth)
    make.paths, make.auth, make.store = paths, auth, store
    return make


def test_roles_resolved(svc):
    assert svc("adm@example.com").role.value == "admin"
    assert svc("op@example.com").role.value == "operator"
    assert svc("view@example.com").role.value == "viewer"


def test_guest_keeps_single_user_workflow_only_without_accounts(tmp_path, guest_vault, svc):
    from netcommander.services import Services
    fresh = Paths.for_root(tmp_path / "fresh")
    g = Services(fresh, "whoever", guest_vault, svc.store, RuntimeSettings(env={}), None)
    assert g.user == "guest" and g.role.value == "guest"
    assert g.can(P.BACKUP) and g.can(P.PUSH_CONFIG) and g.can(P.RUN_SHOW)
    assert not g.can(P.APPROVE_DEPLOY) and not g.can(P.EXPORT_VAULT) and not g.can(P.MANAGE_USERS)


def test_guest_is_read_only_once_accounts_exist(svc, guest_vault):
    from netcommander.services import Services
    for auth in (None, svc.auth):                       # with or without an AuthManager handed in
        g = Services(svc.paths, "whoever", guest_vault, svc.store, RuntimeSettings(env={}), auth)
        assert g.user == "guest" and g.role.value == "viewer"
        assert not g.can(P.PUSH_CONFIG) and not g.can(P.RUN_SHOW) and not g.can(P.EDIT_INVENTORY)


def test_guest_fails_closed_when_accounts_file_is_unreadable(tmp_path, guest_vault, svc):
    from netcommander.services import Services
    paths = Paths.for_root(tmp_path / "damaged")
    paths.auth.parent.mkdir(parents=True, exist_ok=True)
    paths.auth.write_text("{not json")
    g = Services(paths, "x", guest_vault, svc.store, RuntimeSettings(env={}), None)
    assert g.role.value == "viewer" and paths.auth.read_text() == "{not json"     # nothing quarantined


class TestExecAuthorization:
    @pytest.mark.parametrize("cmds", [["show version"], ["sh ip int br", "ping 10.0.0.1"],
                                      ["show run | include hostname"], ["terminal length 0"]])
    def test_operator_may_run_read_only(self, svc, cmds):
        assert svc("op@example.com").authorize_exec(["R1", "R2"], cmds, False) is P.RUN_SHOW

    @pytest.mark.parametrize("cmd", ["confi t", "configu t", "relo", "wr er", "write memory", "username x priv 15",
                                     "show run | redirect tftp://1.2.3.4/x", "show run > flash:x", "clear counters",
                                     "copy run start", "debug all", "do show run"])
    def test_operator_cannot_sneak_changes_through_exec_mode(self, svc, cmd):
        s = svc("op@example.com")
        with pytest.raises(PermissionDenied, match="read-only"):
            s.authorize_exec(["R1"], ["show version", cmd], False)
        e = s.audit_log.entries()[-1]
        assert e["action"] == "deny.push_config" and e["outcome"] == "denied"

    def test_config_mode_always_needs_push(self, svc):
        with pytest.raises(PermissionDenied):
            svc("op@example.com").authorize_exec(["R1"], ["show version"], True)
        assert svc("adm@example.com").authorize_exec(["R1"], ["hostname X"], True) is P.PUSH_CONFIG

    def test_admin_may_run_anything_in_exec_mode(self, svc):
        assert svc("adm@example.com").authorize_exec(["R1"], ["reload"], False) is P.PUSH_CONFIG

    def test_viewer_cannot_run_even_show(self, svc):
        s = svc("view@example.com")
        with pytest.raises(PermissionDenied):
            s.authorize_exec(["R1"], ["show version"], False)
        assert s.audit_log.entries()[-1]["action"] == "deny.run_show"


class TestSchedulePermissions:
    SPEC = {"name": "nightly", "type": "daily", "at": "02:00"}

    @pytest.mark.parametrize("user", ["op@example.com", "view@example.com"])
    def test_non_admins_cannot_add_remove_or_pause(self, svc, user):
        admin = svc("adm@example.com")
        sid = admin.add_schedule(dict(self.SPEC))["id"]
        s = svc(user)
        with pytest.raises(PermissionDenied):
            s.add_schedule(dict(self.SPEC, name="mine"))
        with pytest.raises(PermissionDenied):
            s.remove_schedule(sid)
        with pytest.raises(PermissionDenied):
            s.set_schedule_enabled(sid, False)
        assert [x["enabled"] for x in admin.scheduler.list()] == [True]
        assert [x["name"] for x in s.scheduler.list()] == ["nightly"]

    def test_admin_changes_are_audited(self, svc):
        s = svc("adm@example.com")
        sid = s.add_schedule(dict(self.SPEC))["id"]
        s.set_schedule_enabled(sid, False)
        s.remove_schedule(sid)
        assert [e["action"] for e in s.audit_log.entries()] == ["schedule.add", "schedule.pause", "schedule.remove"]


def test_denial_is_audited(svc):
    s = svc("view@example.com")
    with pytest.raises(PermissionDenied):
        s.run_backup(["R1"])
    assert [e["action"] for e in s.audit_log.entries()] == ["deny.backup"]


def test_backup_uses_retention_pref(svc):
    s = svc("adm@example.com")
    s.prefs.set(retention_keep=2)
    for _ in range(4):
        out = s.run_backup(["R1"])
        assert out[0].ok
    assert len(network.list_snapshots("R1", s.paths.backups)) == 2


def test_full_deployment_flow_with_real_pusher(svc, fake_netmiko):
    req, adm = svc("op@example.com"), svc("adm@example.com")
    events = []
    adm.on_event(lambda k, p: events.append(k))
    plan = req.deployments.create(req.user, "ntp", {"R1": ["ntp server 1.1.1.1"], "R2": ["ntp server 1.1.1.1"]},
                                  [["R1"], ["R2"]])
    req.deployments.submit(req.user, plan["id"])
    adm.deployments.decide(adm.user, plan["id"], True)
    out = adm.execute_plan(plan["id"])
    assert out["status"] == "completed" and events == ["stage_start", "stage_done", "stage_start", "stage_done"]
    assert fake_netmiko.conn.pushed                               # config was really sent through the connection
    assert len(network.list_snapshots("R1", adm.paths.backups)) == 2   # pre + post snapshots
    assert adm.audit_log.verify()[0]


def test_operator_cannot_execute(svc):
    req = svc("op@example.com")
    plan = req.deployments.create(req.user, "x", {"R1": ["a"]}, [["R1"]])
    with pytest.raises(PermissionDenied):
        req.execute_plan(plan["id"])


def test_pusher_reports_failures_and_clears_vault_on_auth_error(svc, fake_netmiko):
    adm = svc("adm@example.com")

    def bad(**kw): raise fake_netmiko.NetmikoAuthenticationException("denied")
    fake_netmiko.ConnectHandler = bad
    plan = {"commands": {"R1": ["a"]}, "checks": [], "auto_rollback": False, "save_after": True}
    ok, msg = adm.make_pusher(plan)("R1", ["a"])
    assert not ok and "Authentication failed" in msg and not adm.vault.has_password("R1")


def test_rollback_gate_lists_unsupported_platforms(svc):
    svc.store.add("A1", {"device_type": "arista_eos", "host": "10.0.0.9", "username": "a"})
    assert svc("adm@example.com").rollback_supported(["R1", "A1"]) == ["A1"]


def test_scheduled_backup_runs_and_notifies(svc):
    s = svc("adm@example.com")
    seen = []
    s.on_event(lambda k, p: seen.append(p))
    spec = {"name": "nightly", "kind": "backup", "targets": []}
    assert "2/2 backed up" in s._run_schedule(spec) and any("nightly" in x for x in seen)
    assert s._run_schedule({**spec, "targets": ["GONE"]}) == "no devices"


class TestAdminReset:
    def test_admin_resets_user_who_then_signs_in_with_new_key(self, svc):
        import pyotp

        from netcommander.security import CredentialVault
        old_vault = CredentialVault.path_for_user("op@example.com", svc.paths.vault_dir)
        old_vault.parent.mkdir(parents=True, exist_ok=True)
        old_vault.write_text("{}")
        for _ in range(6):
            svc.auth.verify_login("op@example.com", "forgotten?", "000000")       # locked out
        secret, _uri, moved = svc("adm@example.com").reset_user("op@example.com", "temporary-pass1")
        assert moved is not None and moved.exists() and not old_vault.exists()
        assert svc.auth.must_change_password("op@example.com") and svc.auth.recovery_codes_left("op@example.com") == 0
        assert svc.auth.verify_login("op@example.com", "temporary-pass1", pyotp.TOTP(secret).now())[0]
        assert svc.auth.role_of("op@example.com") == "operator"

    def test_only_admins_reset_and_not_themselves(self, svc):
        with pytest.raises(PermissionDenied):
            svc("op@example.com").reset_user("view@example.com", "temporary-pass1")
        with pytest.raises(PermissionError):
            svc("adm@example.com").reset_user("adm@example.com", "temporary-pass1")
        with pytest.raises(ValueError):
            svc("adm@example.com").reset_user("ghost@example.com", "temporary-pass1")
        with pytest.raises(PermissionError):
            svc.auth.admin_reset("view@example.com", "temporary-pass1", reset_by="op@example.com")
