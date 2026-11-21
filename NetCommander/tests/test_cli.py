from __future__ import annotations

import json

import pytest
from conftest import FAST_KDF

from netcommander import network
from netcommander.__main__ import main
from netcommander.audit import AuditLog
from netcommander.config import Paths
from netcommander.security import AuthManager, CredentialVault

EMAIL, PW = "ops@example.com", "longpassword1"
TOTP: dict[str, str] = {}


@pytest.fixture
def env(tmp_path, monkeypatch, fake_netmiko):
    paths = Paths.for_root(tmp_path)
    auth = AuthManager(paths.auth, iterations=FAST_KDF)
    TOTP["secret"] = auth.create_account(EMAIL, PW)[0]
    auth.create_account("viewer@example.com", PW, role="viewer", created_by=EMAIL)
    v = CredentialVault(paths.vault_dir / "x", iterations=FAST_KDF)
    assert v.unlock_or_init(PW, path=CredentialVault.path_for_user(EMAIL, paths.vault_dir))
    network.save_inventory_json(
        {"R1": {"device_type": "cisco_ios", "host": "10.0.0.1", "ip": "10.0.0.1", "username": "admin",
                "peers": [], "links": {}}}, paths.topology)
    v.set_secret("R1", "admin", "devpw")
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", PW)
    return paths


def run(paths, *argv):
    return main(["--data-dir", str(paths.root), *argv])


def test_data_dir(env, capsys):
    assert run(env, "data-dir") == 0 and str(env.root) in capsys.readouterr().out


def test_backup_all_writes_encrypted_snapshot_and_audits(env, capsys):
    assert run(env, "backup", "--user", EMAIL, "--keep", "3") == 0
    assert "1/1 backed up" in capsys.readouterr().out
    snaps = list((env.backups / "R1").glob("*.cfg.enc"))
    assert len(snaps) == 1 and "hostname" not in snaps[0].read_text()
    log = AuditLog(env.audit)
    assert [e["action"] for e in log.entries()] == ["auth.password_check", "backup"] and log.verify()[0]


def test_wrong_vault_password_is_exit_3(env, monkeypatch, capsys):
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", "wrong-wrong-wrong")
    assert run(env, "backup", "--user", EMAIL) == 3
    assert "password" in capsys.readouterr().err.lower()


def test_unknown_account_and_unknown_device(env, capsys):
    assert run(env, "backup", "--user", "ghost@example.com") == 3
    assert run(env, "backup", "--user", EMAIL, "NOPE") == 2
    assert "NOPE" in capsys.readouterr().err


def test_viewer_role_cannot_back_up_and_denial_is_audited(env, tmp_path, capsys):
    v = CredentialVault(env.vault_dir / "x", iterations=FAST_KDF)
    assert v.unlock_or_init(PW, path=CredentialVault.path_for_user("viewer@example.com", env.vault_dir))
    assert run(env, "backup", "--user", "viewer@example.com") == 3
    assert "not allowed" in capsys.readouterr().err
    assert any(e["action"] == "deny.backup" for e in AuditLog(env.audit).entries())


def test_compliance_flow(env, capsys):
    run(env, "backup", "--user", EMAIL); capsys.readouterr()
    env.policy.write_text(json.dumps([{"id": "host", "type": "must_contain", "pattern": "^hostname"},
                                      {"id": "ntp", "type": "must_contain", "pattern": "^ntp server", "severity": "high"}]))
    csv_path = env.root / "r.csv"
    assert run(env, "compliance", "--user", EMAIL, "--csv", str(csv_path)) == 1
    out = capsys.readouterr().out
    assert "✗ R1" in out and "ntp" in out and "non-compliant" in csv_path.read_text()
    env.policy.write_text("not json")
    assert run(env, "compliance", "--user", EMAIL) == 2


def _code(offset_steps=0):
    import time

    import pyotp
    return pyotp.TOTP(TOTP["secret"]).at(time.time() + 30 * offset_steps)


def test_vault_export_then_import_restores_backups(env, monkeypatch, capsys, tmp_path):
    run(env, "backup", "--user", EMAIL)
    monkeypatch.setenv("NETCOMMANDER_EXPORT_PASSPHRASE", "export-passphrase-1")
    monkeypatch.setenv("NETCOMMANDER_OTP", _code())
    export = tmp_path / "rec.json"
    assert run(env, "vault-export", "--user", EMAIL, str(export)) == 0 and export.exists()
    CredentialVault.path_for_user(EMAIL, env.vault_dir).unlink()                      # simulate a lost vault
    monkeypatch.setenv("NETCOMMANDER_OTP", _code(1))                                  # the used code cannot be replayed
    assert run(env, "vault-import", "--user", EMAIL, str(export)) == 0
    v = CredentialVault(env.vault_dir / "x")
    # the restored vault opens with the ACCOUNT password, so the app can unlock it at sign-in
    assert v.unlock_existing(PW, path=CredentialVault.path_for_user(EMAIL, env.vault_dir))
    snap = next((env.backups / "R1").glob("*.cfg.enc"))
    assert "hostname" in network.read_snapshot(snap, v)
    monkeypatch.setenv("NETCOMMANDER_OTP", _code(-1))
    assert run(env, "vault-import", "--user", EMAIL, str(export)) == 1                # never overwrites


def test_vault_export_needs_second_factor(env, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("NETCOMMANDER_EXPORT_PASSPHRASE", "export-passphrase-1")
    monkeypatch.setenv("NETCOMMANDER_OTP", "000000")
    export = tmp_path / "rec.json"
    assert run(env, "vault-export", "--user", EMAIL, str(export)) == 3 and not export.exists()
    acts = [(e["action"], e["outcome"]) for e in AuditLog(env.audit).entries()]
    assert ("vault.export", "denied") in acts and ("auth.login", "failed") in acts


def test_vault_import_needs_password_and_second_factor(env, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("NETCOMMANDER_EXPORT_PASSPHRASE", "export-passphrase-1")
    monkeypatch.setenv("NETCOMMANDER_OTP", _code())
    export = tmp_path / "rec.json"
    assert run(env, "vault-export", "--user", EMAIL, str(export)) == 0
    CredentialVault.path_for_user(EMAIL, env.vault_dir).unlink()
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", "not-the-account-password")
    monkeypatch.setenv("NETCOMMANDER_OTP", _code(1))
    assert run(env, "vault-import", "--user", EMAIL, str(export)) == 3
    assert not CredentialVault.path_for_user(EMAIL, env.vault_dir).exists()


def test_cli_failures_count_toward_lockout(env, monkeypatch, capsys):
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", "wrong-wrong-wrong")
    for _ in range(5):
        assert run(env, "backup", "--user", EMAIL) == 3
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", PW)
    assert run(env, "backup", "--user", EMAIL) == 3                                   # locked, even with the right password
    assert "Too many failed attempts" in capsys.readouterr().err
    assert AuthManager(env.auth).users[EMAIL]["fails"] == 5


def test_cli_success_does_not_reset_lockout_counter(env, monkeypatch, capsys):
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", "wrong-wrong-wrong")
    run(env, "backup", "--user", EMAIL)
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", PW)
    assert run(env, "backup", "--user", EMAIL) == 0
    assert AuthManager(env.auth).users[EMAIL]["fails"] == 1


def test_schedule_run_once(env, capsys):
    from netcommander.scheduler import Scheduler
    s = Scheduler(env.schedules, lambda sp: "")
    s.add({"name": "nightly", "type": "interval", "every_minutes": 1})
    data = json.loads(env.schedules.read_text()); data["schedules"][0]["last_run"] = 1.0
    env.schedules.write_text(json.dumps(data))
    assert run(env, "schedule-run", "--user", EMAIL, "--once") == 0
    assert "nightly: 1/1 backed up" in capsys.readouterr().out


def test_audit_verify_detects_tampering(env, capsys):
    run(env, "backup", "--user", EMAIL); capsys.readouterr()
    assert run(env, "audit-verify") == 0
    env.audit.write_text(env.audit.read_text().replace('"ok"', '"fail"'))
    assert run(env, "audit-verify") == 1
    assert "modified" in capsys.readouterr().err


def test_no_subcommand_still_launches_gui_path(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr("netcommander.__main__.run_gui", lambda p, s: called.setdefault("gui", 0))
    assert main(["--data-dir", str(tmp_path)]) == 0 and "gui" in called


def test_compliance_live_uses_running_config_not_backups(env, capsys):
    # no backup exists, but --live fetches the config straight from the (fake) device
    env.policy.write_text(json.dumps([{"id": "host", "type": "must_contain", "pattern": "^hostname"}]))
    assert run(env, "compliance", "--user", EMAIL, "--live") == 0
    assert "✓ R1" in capsys.readouterr().out


def test_failed_unlock_is_audited_and_sinks_get_it(env, monkeypatch, tmp_path, capsys):
    copy = tmp_path / "offbox.jsonl"
    monkeypatch.setenv("NETCOMMANDER_AUDIT_COPY", str(copy))
    monkeypatch.setenv("NETCOMMANDER_VAULT_PASSWORD", "wrong-wrong-wrong")
    assert run(env, "backup", "--user", EMAIL) == 3
    acts = [(e["action"], e["outcome"]) for e in AuditLog(env.audit).entries()]
    assert ("cli.unlock", "failed") in acts and "cli.unlock" in copy.read_text()
