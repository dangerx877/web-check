"""`netcommander homelab ...` and `netcommander serve` (headless entry points)."""
from __future__ import annotations

import json

from test_cli import EMAIL, TOTP, env, run  # noqa: F401  (fixtures)

from netcommander.audit import AuditLog


def test_check_config_and_adapters_need_no_sign_in(env, capsys, tmp_path):
    assert run(env, "homelab", "check-config") == 0
    assert "defaults apply" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"api": {"port": 0}, "nope": {}}))
    assert run(env, "homelab", "check-config", "--file", str(bad)) == 2
    err = capsys.readouterr().err
    assert "api.port" in err and "nope" in err
    assert run(env, "homelab", "adapters") == 0
    out = capsys.readouterr().out
    assert "proxmox" in out and "token (secret) *" in out


def test_inventory_status_runbook_export(env, capsys, tmp_path):
    assert run(env, "homelab", "inventory", "--user", EMAIL) == 0
    out = capsys.readouterr().out
    assert "R1" in out and "network" in out                     # classic inventory mirrored read-only
    csv_file = tmp_path / "inv.csv"
    assert run(env, "homelab", "inventory", "--user", EMAIL, "--format", "csv", "--output", str(csv_file)) == 0
    assert csv_file.read_text().startswith("id,name,kind")
    assert run(env, "homelab", "status", "--user", EMAIL) == 0
    assert "devices 1" in capsys.readouterr().out
    assert run(env, "homelab", "status", "--user", EMAIL, "--json") == 0
    assert json.loads(capsys.readouterr().out)["totals"]["devices"] == 1
    rb = tmp_path / "rb.md"
    assert run(env, "homelab", "runbook", "--user", EMAIL, "--output", str(rb)) == 0
    assert "R1" in rb.read_text()
    cfg = tmp_path / "cfg.json"
    assert run(env, "homelab", "export-config", "--user", EMAIL, "--output", str(cfg)) == 0
    assert json.loads(cfg.read_text())["format"] == "netcommander-homelab-config"
    actions = [e["action"] for e in AuditLog(env.audit).entries()]
    assert "inventory.export" in actions and "recovery.runbook" in actions and "config.export" in actions


def test_viewer_cannot_discover_or_add_integrations(env, capsys):
    assert run(env, "homelab", "discover", "--user", "viewer@example.com", "127.0.0.1/32") == 3
    assert "discover" in capsys.readouterr().err
    assert run(env, "homelab", "add-integration", "--user", "viewer@example.com", "--category", "docker",
               "--kind", "docker", "--name", "d", "--set", "url=unix:///nonexistent.sock") == 3


def test_add_integration_validates_and_reports_first_poll(env, capsys, monkeypatch):
    assert run(env, "homelab", "add-integration", "--user", EMAIL, "--category", "docker", "--kind", "docker",
               "--name", "d", "--set", "bogus") == 2
    assert run(env, "homelab", "add-integration", "--user", EMAIL, "--category", "hypervisor", "--kind", "proxmox",
               "--name", "p", "--set", "url=https://127.0.0.1:1", "--set", "token_id=a@pve!b") == 1
    assert "token_ref is required" in capsys.readouterr().err
    monkeypatch.setenv("NETCOMMANDER_SECRET_TOKEN", "S3cret-Value-xyz")
    assert run(env, "homelab", "add-integration", "--user", EMAIL, "--category", "hypervisor", "--kind", "proxmox",
               "--name", "p", "--set", "url=https://127.0.0.1:1", "--set", "token_id=a@pve!b", "--secret", "token") == 1
    out = capsys.readouterr()
    assert "saved" in out.out and "first poll failed" in out.err
    assert "S3cret-Value-xyz" not in (env.root / "homelab_secrets.json").read_text()


def test_discover_and_monitor_once(env, capsys):
    assert run(env, "homelab", "discover", "--user", EMAIL, "127.0.0.1/32") == 0
    assert "hosts answered" in capsys.readouterr().out
    assert run(env, "homelab", "monitor", "--user", EMAIL) == 0
    assert "checks" in capsys.readouterr().out


def test_serve_requires_second_factor_and_refuses_insecure_bind(env, capsys, monkeypatch):
    monkeypatch.setenv("NETCOMMANDER_OTP", "000000")
    assert run(env, "serve", "--user", EMAIL) == 3
    assert any(e["action"] == "serve.start" and e["outcome"] == "denied" for e in AuditLog(env.audit).entries())
    assert run(env, "serve", "--user", EMAIL, "--unattended", "--bind", "0.0.0.0", "--port", "0") == 2
    assert "without TLS" in capsys.readouterr().err
