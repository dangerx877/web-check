"""run_multi_cli_commands: pre/post hooks, pre-backup abort, COMMIT_PLATFORMS, open_connection policy."""
from __future__ import annotations

import pytest
from conftest import FakeCommitConn, FakeConn

from netcommander import network
from netcommander.config import RuntimeSettings
from netcommander.network import PreChangeBackupError, diff_snapshots, run_multi_cli_commands, save_config_snapshot

CREDS = ("u", "p", "")


def push(params, conn, fake_conn, **kw):
    fake_conn(conn)
    got: list[tuple[str, str]] = []
    out = run_multi_cli_commands(params, CREDS, kw.pop("commands", ["interface lo0"]), config_mode=True,
                                 on_config=lambda t, x: got.append((t, x)), **kw)
    return out, got


class TestPrePost:
    def test_snapshots_taken_before_and_after_the_push(self, fake_conn):
        conn = FakeConn()
        conn.send_command = lambda cmd, **k: conn.log.append("show") or (
            "hostname BEFORE\n" if conn.log.count("show") == 1 else "hostname AFTER\n")
        out, got = push({"device_type": "cisco_ios"}, conn, fake_conn, save_after=True)
        assert got == [("pre", "hostname BEFORE\n"), ("post", "hostname AFTER\n")]
        assert conn.log.index("show") < conn.log.index("config_set") < conn.log.index("save_config") < len(conn.log) - 1
        assert conn.pushed == ["interface lo0"] and "saved" in out and conn.closed

    def test_pre_backup_failure_aborts_before_anything_is_pushed(self, fake_conn):
        conn = FakeConn(fail_show_on={1})
        fake_conn(conn)
        with pytest.raises(PreChangeBackupError, match="nothing was pushed"):
            run_multi_cli_commands({"device_type": "cisco_ios"}, CREDS, ["x"], config_mode=True, on_config=lambda t, x: None)
        assert conn.pushed == [] and "config_set" not in conn.log and conn.closed

    def test_empty_running_config_aborts_push(self, fake_conn):
        conn = FakeConn(config="   \n")
        fake_conn(conn)
        with pytest.raises(RuntimeError, match="empty configuration"):
            run_multi_cli_commands({"device_type": "cisco_ios"}, CREDS, ["x"], config_mode=True, on_config=lambda t, x: None)
        assert conn.pushed == []

    def test_failure_to_store_the_pre_backup_aborts_push(self, fake_conn):
        conn = FakeConn()
        fake_conn(conn)

        def disk_full(tag, text):
            raise OSError("no space left on device")

        with pytest.raises(PreChangeBackupError, match="no space left"):
            run_multi_cli_commands({"device_type": "cisco_ios"}, CREDS, ["x"], config_mode=True, on_config=disk_full)
        assert conn.pushed == []

    def test_post_snapshot_failure_is_reported_but_push_stands(self, fake_conn):
        conn = FakeConn(fail_show_on={2})
        out, got = push({"device_type": "cisco_ios"}, conn, fake_conn)
        assert [t for t, _ in got] == ["pre"] and conn.pushed == ["interface lo0"]
        assert "[Post-change snapshot failed]" in out

    def test_without_hook_there_is_no_backup_traffic(self, fake_conn):
        conn = fake_conn(FakeConn())
        out = run_multi_cli_commands({"device_type": "cisco_ios"}, CREDS, ["a", "b"], config_mode=True)
        assert conn.pushed == ["a", "b"] and not any(x.startswith("send:") for x in conn.log) and out == "ok"

    def test_save_failure_becomes_warning(self, fake_conn):
        conn = FakeConn(save_error=RuntimeError("flash busy"))
        out, _ = push({"device_type": "cisco_ios"}, conn, fake_conn, save_after=True)
        assert "[Save Config Warning]: flash busy" in out

    def test_no_save_when_not_requested(self, fake_conn):
        conn = FakeConn()
        push({"device_type": "cisco_ios"}, conn, fake_conn, save_after=False)
        assert "save_config" not in conn.log

    def test_uses_vendor_specific_show_command(self, fake_conn):
        conn = FakeConn()
        push({"device_type": "huawei"}, conn, fake_conn)
        assert "send:display current-configuration" in conn.log

    def test_end_to_end_with_encrypted_backups_and_diff(self, fake_conn, vault, tmp_path):
        conn = FakeConn()
        seq = iter(["hostname A\n", "hostname B\n"])
        conn.send_command = lambda cmd, **k: next(seq)
        fake_conn(conn)
        saved = {}
        run_multi_cli_commands({"device_type": "cisco_ios"}, CREDS, ["hostname B"], config_mode=True,
                               on_config=lambda tag, text: saved.__setitem__(tag, save_config_snapshot("R1", text, tmp_path, vault, tag)))
        assert saved["pre"].name.endswith("_pre.cfg.enc") and saved["post"].name.endswith("_post.cfg.enc")
        d = diff_snapshots(saved["pre"], saved["post"], vault)
        assert "-hostname A" in d and "+hostname B" in d


class TestCommitPlatforms:
    @pytest.mark.parametrize("dtype", ["juniper_junos", "cisco_xr", "paloalto_panos"])
    def test_commits_when_save_requested(self, fake_conn, dtype):
        conn = FakeCommitConn()
        out, got = push({"device_type": dtype}, conn, fake_conn, save_after=True)
        assert conn.config_kwargs["exit_config_mode"] is False
        assert conn.log.index("config_set") < conn.log.index("commit") < conn.log.index("exit_config_mode")
        assert "committed" in out and [t for t, _ in got] == ["pre", "post"] and "save_config" not in conn.log

    @pytest.mark.parametrize("dtype", ["juniper_junos", "cisco_xr", "paloalto_panos"])
    def test_discards_with_notice_when_save_off(self, fake_conn, dtype):
        conn = FakeCommitConn()
        out, _ = push({"device_type": dtype}, conn, fake_conn, save_after=False)
        assert "commit" not in conn.log and "exit_config_mode" in conn.log
        assert "NOT committed" in out

    def test_driver_without_commit_uses_normal_path(self, fake_conn):
        conn = FakeConn()
        push({"device_type": "juniper_junos"}, conn, fake_conn, save_after=True)
        assert "save_config" in conn.log and "exit_config_mode" not in conn.config_kwargs

    def test_non_commit_platform_ignores_commit_method(self, fake_conn):
        conn = FakeCommitConn()
        push({"device_type": "cisco_ios"}, conn, fake_conn, save_after=True)
        assert "commit" not in conn.log and "save_config" in conn.log


class TestShowMode:
    def test_runs_each_command_and_labels_output(self, fake_conn):
        conn = fake_conn(FakeConn(config="OUT"))
        called = []
        out = run_multi_cli_commands({"device_type": "cisco_ios"}, CREDS, ["show a", "show b"], on_config=lambda *a: called.append(a))
        assert out == "$ show a\nOUT\n\n$ show b\nOUT" and not called and conn.pushed == []

    def test_enable_only_when_secret_and_profile_wants_it(self, fake_conn):
        conn = fake_conn(FakeConn())
        run_multi_cli_commands({"device_type": "cisco_ios"}, ("u", "p", "en"), ["x"])
        assert conn.log[0] == "enable"
        conn2 = fake_conn(FakeConn())
        run_multi_cli_commands({"device_type": "cisco_ios"}, ("u", "p", ""), ["x"])
        run_multi_cli_commands({"device_type": "juniper_junos"}, ("u", "p", "en"), ["x"])
        assert "enable" not in conn2.log

    def test_fetch_running_config(self, fake_conn):
        fake_conn(FakeConn(config="hostname Z\n"))
        assert network.fetch_running_config({"device_type": "linux"}, CREDS) == "hostname Z\n"


class TestOpenConnection:
    def test_translates_params(self, fake_netmiko):
        conn = network.open_connection(
            {"device_type": "cisco_ios", "host": "1.1.1.1", "username": "ignored", "timeout": 15, "port": 2222,
             "password": "leak"}, "bob", "pw", "en", settings=RuntimeSettings(env={}))
        kw = fake_netmiko.calls[0]
        assert conn is fake_netmiko.conn
        assert (kw["username"], kw["password"], kw["secret"], kw["port"]) == ("bob", "pw", "en", 2222)
        assert (kw["conn_timeout"], kw["auth_timeout"], kw["banner_timeout"]) == (15, 30, 30)
        assert "timeout" not in kw and "ssh_strict" not in kw and "system_host_keys" not in kw

    def test_omits_empty_port_and_secret_and_expands_key_file(self, fake_netmiko):
        network.open_connection({"host": "h", "port": None, "use_keys": True, "key_file": "~/k"}, "u", "", "",
                                settings=RuntimeSettings(env={}))
        kw = fake_netmiko.calls[0]
        assert "port" not in kw and "secret" not in kw and kw["use_keys"] is True
        assert kw["key_file"].endswith("/k") and not kw["key_file"].startswith("~")

    def test_runtime_strict_hostkeys(self, fake_netmiko):
        s = RuntimeSettings(env={})
        s.strict_hostkeys = True
        network.open_connection({"host": "h"}, "u", "p", settings=s)
        assert fake_netmiko.calls[0]["ssh_strict"] is True and fake_netmiko.calls[0]["system_host_keys"] is True

    def test_env_var_strict_hostkeys(self, fake_netmiko):
        network.open_connection({"host": "h"}, "u", "p", settings=RuntimeSettings(env={"NET_SSH_STRICT_HOSTKEYS": "1"}))
        assert fake_netmiko.calls[0]["ssh_strict"] is True

    def test_policy_is_read_per_connection_not_cached(self, fake_netmiko):
        s = RuntimeSettings(env={})
        network.open_connection({"host": "h"}, "u", "p", settings=s)
        s.strict_hostkeys = True
        network.open_connection({"host": "h"}, "u", "p", settings=s)
        s.strict_hostkeys = False
        network.open_connection({"host": "h"}, "u", "p", settings=s)
        assert ["ssh_strict" in c for c in fake_netmiko.calls] == [False, True, False]

    def test_default_settings_still_honour_environment(self, fake_netmiko, monkeypatch):
        monkeypatch.setenv("NET_SSH_STRICT_HOSTKEYS", "1")
        network.open_connection({"host": "h"}, "u", "p")
        assert fake_netmiko.calls[0]["ssh_strict"] is True

    def test_run_helpers_pass_settings_through(self, fake_netmiko):
        s = RuntimeSettings(strict_hostkeys=True, env={})
        run_multi_cli_commands({"device_type": "cisco_ios", "host": "h"}, CREDS, ["show x"], settings=s)
        assert fake_netmiko.calls[0]["ssh_strict"] is True


class TestClassifyError:
    def test_kinds(self, fake_netmiko):
        assert network.classify_ssh_error(fake_netmiko.NetmikoAuthenticationException("bad"))[0] == "auth"
        kind, msg = network.classify_ssh_error(fake_netmiko.NetmikoTimeoutException("slow"))
        assert kind == "timeout" and "slow" in msg
        kind, msg = network.classify_ssh_error(ValueError("weird"))
        assert (kind, msg) == ("other", "ValueError: weird")

    def test_known_hosts_hint(self, fake_netmiko):
        kind, msg = network.classify_ssh_error(RuntimeError("Server 'x' not found in known_hosts"))
        assert kind == "hostkey"
        assert "not trusted" in msg
