"""Headless wiring tests for the enterprise UI (stub widgets; no display - look and feel is NOT covered)."""
from __future__ import annotations

import json
import time

import pytest

pytest.importorskip("networkx")
pytest.importorskip("matplotlib")

from test_ui_smoke import W, app, paths, ui, wait_for  # noqa: F401  (fixtures)

from netcommander import network
from netcommander.config import RuntimeSettings
from netcommander.rbac import Role


def sys_mod(name):
    import sys
    return sys.modules[name]


def test_every_panel_is_built_and_services_use_guest_role(app):
    for attr in ("monitor_panel", "compliance_panel", "templates_panel", "deploy_panel", "schedules_panel", "audit_panel"):
        assert hasattr(app, attr), attr
    assert app.services.role is Role.GUEST and app.services.user == "guest"
    assert not app.services.scheduler.running                      # no background schedules in guest mode
    assert [e["action"] for e in app.services.audit_log.entries()] == ["session.start"]


def test_viewer_cannot_push_run_or_edit(ui, paths, guest_vault, monkeypatch):
    a = ui.app.NetworkManagerApp("guest", guest_vault, settings=RuntimeSettings(env={}), paths=paths)
    a.services.role = Role.VIEWER
    a.cmd_text._text = "show version"
    a.send_commands()
    assert ui.mb.shown[-1][0] == "showwarning" and "viewer" in ui.mb.shown[-1][1][1]
    n = len(a.store)
    a.remove_device()
    assert len(a.store) == n
    acts = [e["action"] for e in a.services.audit_log.entries()]
    assert "deny.run_show" in acts and "deny.edit_inventory" in acts


def test_operator_cannot_push_config_but_can_run_show(ui, paths, guest_vault, monkeypatch, fake_netmiko):
    a = ui.app.NetworkManagerApp("guest", guest_vault, settings=RuntimeSettings(env={}), paths=paths)
    a.services.role = Role.OPERATOR
    a.exec_mode_var.set("Config Set"); a.cmd_text._text = "hostname X"
    a.send_commands()
    assert "operator" in ui.mb.shown[-1][1][1] and not fake_netmiko.conn.pushed
    a.cmd_text._text = "reload"; a.exec_mode_var.set("Show / Exec")
    a.send_commands()                                               # disruptive exec also needs push rights
    assert "operator" in ui.mb.shown[-1][1][1]


def test_push_is_audited_with_redacted_detail(app, ui, monkeypatch, fake_netmiko):
    monkeypatch.setattr(network, "open_connection", lambda *a, **k: fake_netmiko.conn)
    app.vault.set_secret("CORE-R1", "u", "p")
    app.scope_var.set("Selected Device"); app.exec_mode_var.set("Config Set")
    app.cmd_text._text = "username a secret 9 hunter2\nhostname B"
    app.send_commands()
    wait_for(app, "enable_run")
    e = [x for x in app.services.audit_log.entries() if x["action"] == "push_config"][0]
    assert "hunter2" not in json.dumps(e) and e["target"] == "CORE-R1"


def test_dry_run_preview_does_not_touch_the_device_and_hides_secrets(app, monkeypatch):
    monkeypatch.setattr(network, "open_connection", lambda *a, **k: pytest.fail("dry-run must not connect"))
    network.save_config_snapshot("CORE-R1", "hostname CORE\nntp server 1.1.1.1\n", app.paths.backups)
    app.cmd_text._text = "ntp server 1.1.1.1\nntp server 2.2.2.2\nusername a secret 9 hunter2\nreload"
    app.preview_script()
    out = app.output_box._text
    assert "Dry-run for CORE-R1" in out and "2.2.2.2" in out and "hunter2" not in out and "reload" in out


def test_dry_run_without_backup_explains(app, ui):
    app.cmd_text._text = "ntp server 1.1.1.1"
    app.preview_script()
    assert ui.mb.shown[-1][0] == "showinfo" and "Backup Config" in ui.mb.shown[-1][1][1]


def test_device_filter_and_links_export(app, tmp_path, monkeypatch):
    app.filter_ent._text = "core"
    app._refresh_device_list()
    labels = [c._children[1]._kw.get("text", "") for c in app.device_list_frame._children if len(c._children) > 1]
    assert labels and all("CORE" in t.upper() for t in labels)
    fd = sys_mod("tkinter.filedialog")
    out = tmp_path / "l.csv"
    monkeypatch.setattr(fd, "asksaveasfilename", lambda **k: str(out))
    app.export_links()
    assert out.exists() and out.read_text().startswith("device_a,")


def test_retention_and_redact_preferences_persist(app, paths):
    app._on_retention("Keep 10")
    app.redact_var.set(False); app._on_redact()
    from netcommander.prefs import Prefs
    p = Prefs(paths.prefs)
    assert p.get("retention_keep") == 10 and p.get("redact_diffs") is False
    app._on_retention("Keep all")
    assert Prefs(paths.prefs).get("retention_keep") == 0


def test_backup_applies_retention(app, monkeypatch, fake_netmiko):
    monkeypatch.setattr(network, "open_connection", lambda *a, **k: fake_netmiko.conn)
    app.vault.set_secret("CORE-R1", "u", "p")
    app._on_retention("Keep 5")
    app.services.prefs.set(retention_keep=2)
    app.scope_var.set("Selected Device")
    for _ in range(4):
        app.backup_configs(); wait_for(app, "enable_backup")
    assert len(network.list_snapshots("CORE-R1", app.paths.backups)) == 2


def test_hostkey_prompt_flow_trusts_only_after_confirmation(app, ui, monkeypatch, tmp_path):
    kh = tmp_path / "known_hosts"
    monkeypatch.setattr("netcommander.network.known_hosts_path", lambda home=None: kh)
    real = network.trust_host_key
    monkeypatch.setattr(sys_mod("netcommander.ui.app"), "trust_host_key", lambda h, p, t, b: real(h, p, t, b, kh))
    info = {"type": "ssh-ed25519", "fingerprint": "SHA256:abc", "base64": "AAAA"}
    ui.mb.answer = False
    app._on_hostkey_prompt(("R1", "10.0.0.1", 22, info, ""))
    assert not kh.exists()
    ui.mb.answer = True
    app._on_hostkey_prompt(("R1", "10.0.0.1", 22, info, ""))
    assert kh.read_text() == "10.0.0.1 ssh-ed25519 AAAA\n"
    assert any(e["action"] == "hostkey.trust" for e in app.services.audit_log.entries())
    app._on_hostkey_prompt(("R1", "10.0.0.2", 22, None, "refused"))
    assert "Could not read the host key" in app.output_box._text


def test_hostkey_event_from_batch_failure_reaches_ui(app, monkeypatch):
    from netcommander.batch import BatchRunner
    seen = []
    BatchRunner(lambda k, p: seen.append((k, p)), "done").fail("R1", {"host": "10.0.0.1", "port": 22},
                                                                 RuntimeError("Server '10.0.0.1' not found in known_hosts"))
    assert ("hostkey_unknown", ("R1", "10.0.0.1", 22)) in seen


def test_compliance_panel_runs_against_latest_backup(app):
    network.save_config_snapshot("CORE-R1", "hostname CORE\nip http server\n", app.paths.backups)
    app.compliance_panel.run()
    text = app.compliance_panel.box._text
    assert "✗ CORE-R1" in text and "no-http" in text and "not checked" in text   # other devices have no backup
    assert app.paths.policy.exists()


def test_deployment_panel_end_to_end_with_two_people(app, ui, monkeypatch, fake_netmiko):
    """requester (operator) drafts+submits; admin approves; executes through the panel."""
    import netcommander.ui.enterprise as ent
    monkeypatch.setattr(network, "open_connection", lambda *a, **k: fake_netmiko.conn)
    svc = app.services
    svc.role = Role.OPERATOR
    app.scope_var.set("Selected Device"); app.cmd_text._text = "ntp server 1.1.1.1"
    monkeypatch.setattr(ent, "ask_form", lambda *a, **k: {"title": "NTP", "canary": "1", "batch": "", "approvals": "1",
                                                          "rollback": "no", "check_cmd": "", "check_expect": ""})
    app.deploy_panel.new_plan()
    plan = svc.deployments.list()[0]
    pid = plan["id"]
    app.deploy_panel.sel.set(f"{pid}  [draft]  NTP")
    app.deploy_panel._act("submit")
    assert svc.deployments.get(pid)["status"] == "pending_approval"
    ui.mb.answer = True
    app.deploy_panel._act("approve")                               # operator may not approve
    assert svc.deployments.get(pid)["status"] == "pending_approval"
    svc.role = Role.ADMIN
    svc.user = "boss@example.com"
    svc.auth = None
    svc._role_of = lambda a: "admin" if a == "boss@example.com" else "operator"
    svc.deployments._role_of = svc._role_of
    app.deploy_panel._act("approve")
    assert svc.deployments.get(pid)["status"] == "approved"
    app.vault.set_secret("CORE-R1", "u", "p")
    app.deploy_panel.execute()
    deadline = time.time() + 5
    while time.time() < deadline and svc.deployments.get(pid)["status"] == "running":
        time.sleep(0.02)
    for _ in range(50):
        if svc.deployments.get(pid)["status"] == "completed":
            break
        time.sleep(0.02)
    assert svc.deployments.get(pid)["status"] == "completed" and fake_netmiko.conn.pushed


def test_deploy_rollback_refused_for_unsupported_platform(app, ui, monkeypatch):
    import netcommander.ui.enterprise as ent
    app.store.add("A1", {"device_type": "arista_eos", "host": "10.9.9.9", "username": "a"})
    app.scope_var.set("All Devices"); app.cmd_text._text = "x"
    monkeypatch.setattr(ent, "ask_form", lambda *a, **k: {"title": "t", "canary": "1", "batch": "", "approvals": "1",
                                                          "rollback": "yes", "check_cmd": "", "check_expect": ""})
    monkeypatch.setattr(app, "_resolve_targets", lambda: ["A1"])
    app.deploy_panel.new_plan()
    assert ui.mb.shown[-1][0] == "showerror" and "A1" in ui.mb.shown[-1][1][1]
    assert app.services.deployments.list() == []


def test_audit_panel_and_schedules_panel(app, monkeypatch):
    import netcommander.ui.enterprise as ent
    app.audit_panel.refresh()
    assert "session.start" in app.audit_panel.box._text
    app.services.role = Role.ADMIN
    app.services.guest = False
    monkeypatch.setattr(ent, "ask_form", lambda *a, **k: {"name": "nightly", "type": "daily", "every": "", "at": "02:00", "targets": ""})
    app.schedules_panel.add()
    assert "nightly" in app.schedules_panel.box._text and "daily at 02:00" in app.schedules_panel.box._text
    assert any(e["action"] == "schedule.add" for e in app.services.audit_log.entries())


def test_monitor_panel_adds_rest_monitor_polls_and_renders(app, monkeypatch):
    import io

    import netcommander.ui.enterprise as ent
    monkeypatch.setattr(ent, "ask_form", lambda *a, **k: {"name": "fw", "url": "https://fw/api", "metrics": "cpu=data.cpu",
                                                          "auth": "none", "user": "", "secret": "", "verify": "yes"})
    mp = app.monitor_panel
    mp.runner._opener = lambda req, timeout=None, context=None: type("R", (io.BytesIO,), {
        "__enter__": lambda s: s, "__exit__": lambda s, *a: False})(b'{"data": {"cpu": 42}}')
    mp.add_rest()
    deadline = time.time() + 5
    while time.time() < deadline and mp.history.last("fw") is None:
        time.sleep(0.02)
    wait_for(app, "monitors_updated")
    assert "UP" in mp.box._text and "cpu=42" in mp.box._text


def test_account_dialog_for_guest_shows_notice_only(app):
    from netcommander.ui.account import AccountDialog
    d = AccountDialog(app, app.services)
    assert len(d.body._children) == 1                                  # just the "sign in" notice, no action buttons


def test_account_dialog_change_password_flow(ui, paths, vault, monkeypatch):
    from conftest import FAST_KDF

    import netcommander.ui.account as acc
    from netcommander.security import AuthManager
    auth = AuthManager(paths.auth, iterations=FAST_KDF)
    secret, _ = auth.create_account("me@example.com", "longpassword1")
    from netcommander.security import CredentialVault
    vault = CredentialVault(paths.vault_dir / "x", iterations=FAST_KDF)
    assert vault.unlock_or_init("longpassword1", path=CredentialVault.path_for_user("me@example.com", paths.vault_dir))
    a = ui.app.NetworkManagerApp("me@example.com", vault, settings=RuntimeSettings(env={}), paths=paths, auth=auth)
    assert a.services.role is Role.ADMIN
    d = acc.AccountDialog(a, a.services)
    import pyotp
    monkeypatch.setattr(acc, "ask_form", lambda *x, **k: {"old": "longpassword1", "new": "another-long-pass", "new2": "different-one!",
                                                          "otp": pyotp.TOTP(secret).now()})
    d.change_password()
    assert "do not match" in d.status.cget("text")
    monkeypatch.setattr(acc, "ask_form", lambda *x, **k: {"old": "longpassword1", "new": "another-long-pass", "new2": "another-long-pass",
                                                          "otp": pyotp.TOTP(secret).now()})
    d.change_password()
    assert d.status.cget("text") == "Password changed."
    assert [e["action"] for e in a.services.audit_log.entries()][-1] == "account.change_password"


def test_admin_adds_user_who_must_change_temporary_password(ui, paths, monkeypatch):
    import pyotp
    from conftest import FAST_KDF

    import netcommander.ui.account as acc
    from netcommander.security import AuthManager, CredentialVault
    auth = AuthManager(paths.auth, iterations=FAST_KDF)
    auth.create_account("boss@example.com", "longpassword1")
    vault = CredentialVault(paths.vault_dir / "x", iterations=FAST_KDF)
    assert vault.unlock_or_init("longpassword1", path=CredentialVault.path_for_user("boss@example.com", paths.vault_dir))
    a = ui.app.NetworkManagerApp("boss@example.com", vault, settings=RuntimeSettings(env={}), paths=paths, auth=auth)
    d = acc.AccountDialog(a, a.services)
    monkeypatch.setattr(acc, "ask_form", lambda *x, **k: {"email": "New@Example.com", "pw": "temporary-pass1", "role": "viewer"})
    d.add_user()
    assert auth.role_of("new@example.com") == "viewer" and auth.must_change_password("new@example.com")
    assert [e["action"] for e in a.services.audit_log.entries()][-1] == "user.create"

    # the new user signs in, is told to change the temporary password, and the flag clears when they do
    secret = auth.rotate_totp("new@example.com", "temporary-pass1")[0]
    v2 = CredentialVault(paths.vault_dir / "y", iterations=FAST_KDF)
    assert v2.unlock_or_init("temporary-pass1", path=CredentialVault.path_for_user("new@example.com", paths.vault_dir))
    b = ui.app.NetworkManagerApp("new@example.com", v2, settings=RuntimeSettings(env={}), paths=paths, auth=auth)
    b._prompt_password_change()
    assert "Temporary password" in b.output_box._text
    from netcommander.security import change_account_password
    change_account_password(auth, v2, "new@example.com", "temporary-pass1", "my-own-password", pyotp.TOTP(secret).now())
    assert not auth.must_change_password("new@example.com")


def test_operator_cannot_add_users_from_account_dialog(ui, paths, monkeypatch):
    from conftest import FAST_KDF

    import netcommander.ui.account as acc
    from netcommander.security import AuthManager, CredentialVault
    auth = AuthManager(paths.auth, iterations=FAST_KDF)
    auth.create_account("boss@example.com", "longpassword1")
    auth.create_account("op@example.com", "longpassword1", created_by="boss@example.com")
    vault = CredentialVault(paths.vault_dir / "x", iterations=FAST_KDF)
    assert vault.unlock_or_init("longpassword1", path=CredentialVault.path_for_user("op@example.com", paths.vault_dir))
    a = ui.app.NetworkManagerApp("op@example.com", vault, settings=RuntimeSettings(env={}), paths=paths, auth=auth)
    d = acc.AccountDialog(a, a.services)
    monkeypatch.setattr(acc, "ask_form", lambda *x, **k: {"email": "x@example.com", "pw": "temporary-pass1", "role": "admin"})
    d.add_user()
    assert not auth.user_exists("x@example.com") and "not allowed" in d.status.cget("text")


def test_schedules_panel_enforces_manage_schedules(app, ui, monkeypatch):
    import netcommander.ui.enterprise as ent
    app.services.role = Role.OPERATOR
    app.services.guest = False
    monkeypatch.setattr(ent, "ask_form", lambda *x, **k: pytest.fail("operator must not reach the form"))
    app.schedules_panel.add()
    app.schedules_panel.remove()
    app.schedules_panel.toggle()
    assert app.services.scheduler.list() == []
    assert [e["action"] for e in app.services.audit_log.entries()].count("deny.manage_schedules") == 3


def test_operator_exec_abbreviation_is_refused_in_ui(ui, paths, guest_vault, fake_netmiko):
    a = ui.app.NetworkManagerApp("guest", guest_vault, settings=RuntimeSettings(env={}), paths=paths)
    a.services.role = Role.OPERATOR
    a.exec_mode_var.set("Show / Exec"); a.cmd_text._text = "confi t\nusername x privilege 15 secret y"
    a.send_commands()
    assert ui.mb.shown[-1][0] == "showwarning" and "read-only" in ui.mb.shown[-1][1][1]
    assert not fake_netmiko.conn.pushed
