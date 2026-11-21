"""Per-OS paths and openers, connect retries, host-key trust, push preview, link CSV, prefs."""
from __future__ import annotations

import csv
import stat
import sys
from pathlib import Path

import pytest

from netcommander import config, network, utils
from netcommander.config import RuntimeSettings
from netcommander.prefs import DEFAULTS, Prefs


# ---------------------------------------------------------------- per-OS data dirs
class TestDataDirs:
    H = Path("/home/u")

    def test_linux_xdg_and_default(self):
        assert config.platform_data_dir("linux", {}, self.H) == self.H / ".local/share/netcommander"
        assert config.platform_data_dir("linux", {"XDG_DATA_HOME": "/data/xdg"}, self.H) == Path("/data/xdg/netcommander")
        assert config.platform_data_dir("linux", {"XDG_DATA_HOME": "relative"}, self.H) == self.H / ".local/share/netcommander"

    def test_macos(self):
        assert config.platform_data_dir("darwin", {}, self.H) == self.H / "Library/Application Support/NetCommander"

    def test_windows_appdata_and_fallback(self):
        assert config.platform_data_dir("win32", {"APPDATA": "C:/Users/u/AppData/Roaming"}, self.H) == Path("C:/Users/u/AppData/Roaming/NetCommander")
        assert config.platform_data_dir("win32", {}, self.H) == self.H / "AppData/Roaming/NetCommander"

    def test_resolution_order(self, tmp_path):
        pkg = tmp_path / "site-packages" / "netcommander"; pkg.mkdir(parents=True)
        home = tmp_path / "home"; home.mkdir()
        assert config.resolve_data_dir({"NETCOMMANDER_HOME": str(tmp_path / "x")}, pkg, "linux", home) == (tmp_path / "x").resolve()
        assert config.resolve_data_dir({}, pkg, "linux", home) == home / ".local/share/netcommander"
        (home / ".netcommander").mkdir()                                            # legacy folder wins over the new default
        assert config.resolve_data_dir({}, pkg, "linux", home) == home / ".netcommander"
        (pkg.parent / "pyproject.toml").write_text("")                              # source checkout wins over everything but the env var
        assert config.resolve_data_dir({}, pkg, "linux", home) == pkg.parent

    def test_paths_cover_all_new_files(self, tmp_path):
        p = config.Paths.for_root(tmp_path)
        assert p.audit.name == "audit.jsonl" and p.templates == tmp_path / "templates" and p.prefs.parent == tmp_path


# ---------------------------------------------------------------- openers / csv safety
class TestOpeners:
    def test_commands(self):
        assert utils.opener_command(Path("/x"), "linux") == ["xdg-open", "/x"]
        assert utils.opener_command(Path("/x"), "darwin") == ["open", "/x"]
        assert utils.opener_command(Path("C:/x"), "win32") is None

    def test_missing_xdg_open_is_a_message_not_a_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(utils.shutil, "which", lambda c: None)
        monkeypatch.setattr(utils, "opener_command", lambda p, s=None: ["xdg-open", str(p)])
        msg = utils.open_folder(tmp_path / "bk")
        assert "xdg-open" in msg and str(tmp_path / "bk") in msg and (tmp_path / "bk").is_dir()

    def test_popen_used_when_available(self, tmp_path, monkeypatch):
        calls = []
        monkeypatch.setattr(utils.shutil, "which", lambda c: "/usr/bin/" + c)
        monkeypatch.setattr(utils.subprocess, "Popen", lambda *a, **k: calls.append(a[0]))
        monkeypatch.setattr(utils, "opener_command", lambda p, s=None: ["open", str(p)])
        assert utils.open_folder(tmp_path) is None and calls == [["open", str(tmp_path)]]

    @pytest.mark.parametrize("v,out", [("=SUM(A1)", "'=SUM(A1)"), ("+1", "'+1"), ("-2", "'-2"), ("@x", "'@x"), ("ok", "ok"), (None, "")])
    def test_csv_safe(self, v, out):
        assert utils.csv_safe(v) == out


# ---------------------------------------------------------------- retries
class TestRetries:
    def test_timeouts_retry_with_backoff_then_succeed(self, fake_netmiko, monkeypatch):
        sleeps, tries = [], {"n": 0}
        monkeypatch.setattr(network, "_sleep", sleeps.append)
        good = fake_netmiko.ConnectHandler

        def flaky(**kw):
            tries["n"] += 1
            if tries["n"] < 3:
                raise fake_netmiko.NetmikoTimeoutException("slow")
            return good(**kw)
        fake_netmiko.ConnectHandler = flaky
        s = RuntimeSettings(connect_attempts=3, connect_backoff=2, env={})
        assert network.open_connection({"device_type": "cisco_ios", "host": "h"}, "u", "p", settings=s) is fake_netmiko.conn
        assert tries["n"] == 3 and sleeps == [2.0, 4.0]

    def test_gives_up_after_configured_attempts(self, fake_netmiko, monkeypatch):
        monkeypatch.setattr(network, "_sleep", lambda s: None)
        n = {"c": 0}
        def always(**kw):
            n["c"] += 1; raise fake_netmiko.NetmikoTimeoutException("down")
        fake_netmiko.ConnectHandler = always
        with pytest.raises(fake_netmiko.NetmikoTimeoutException):
            network.open_connection({"host": "h"}, "u", "p", settings=RuntimeSettings(connect_attempts=2, env={}))
        assert n["c"] == 2

    def test_auth_failures_never_retry(self, fake_netmiko, monkeypatch):
        monkeypatch.setattr(network, "_sleep", lambda s: pytest.fail("must not sleep"))
        n = {"c": 0}
        def bad(**kw):
            n["c"] += 1; raise fake_netmiko.NetmikoAuthenticationException("denied")
        fake_netmiko.ConnectHandler = bad
        with pytest.raises(fake_netmiko.NetmikoAuthenticationException):
            network.open_connection({"host": "h"}, "u", "p", settings=RuntimeSettings(connect_attempts=5, env={}))
        assert n["c"] == 1

    def test_settings_are_clamped(self):
        s = RuntimeSettings(connect_attempts=99, connect_backoff=999, env={})
        assert (s.connect_attempts, s.connect_backoff) == (5, 30.0)
        s.connect_attempts = 0; assert s.connect_attempts == 1
        assert s.snapshot()["connect_attempts"] == 1


# ---------------------------------------------------------------- host keys
class TestHostKeys:
    def test_entry_format(self):
        assert network.known_hosts_entry("10.0.0.1", 22, "ssh-ed25519", "AAAA") == "10.0.0.1 ssh-ed25519 AAAA"
        assert network.known_hosts_entry("10.0.0.1", None, "ssh-rsa", "B") == "10.0.0.1 ssh-rsa B"
        assert network.known_hosts_entry("10.0.0.1", 2222, "ssh-rsa", "B") == "[10.0.0.1]:2222 ssh-rsa B"

    def test_fingerprint_matches_openssh_style(self):
        fp = network.fingerprint_sha256(b"abc")
        assert fp == "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"

    def test_trust_appends_idempotently_and_preserves_existing(self, tmp_path):
        kh = tmp_path / ".ssh" / "known_hosts"
        kh.parent.mkdir(); kh.write_text("# mine\nold ssh-rsa XXXX")             # no trailing newline
        network.trust_host_key("10.0.0.1", 22, "ssh-ed25519", "AAAA", kh)
        network.trust_host_key("10.0.0.1", 22, "ssh-ed25519", "AAAA", kh)
        assert kh.read_text().splitlines() == ["# mine", "old ssh-rsa XXXX", "10.0.0.1 ssh-ed25519 AAAA"]
        if sys.platform != "win32":
            assert stat.S_IMODE(kh.stat().st_mode) == 0o600

    def test_trust_creates_ssh_dir(self, tmp_path):
        p = network.trust_host_key("h", 22, "ssh-rsa", "K", tmp_path / "new" / ".ssh" / "known_hosts")
        assert p.read_text() == "h ssh-rsa K\n"

    def test_known_hosts_location(self, tmp_path):
        assert network.known_hosts_path(tmp_path) == tmp_path / ".ssh" / "known_hosts"

    @pytest.mark.parametrize("msg", ["Server '10.0.0.1' not found in known_hosts", "Host key for server x does not match: got A, expected B",
                                     "Host key verification failed"])
    def test_hostkey_kind(self, msg, fake_netmiko):
        assert network.classify_ssh_error(RuntimeError(msg))[0] == "hostkey"


# ---------------------------------------------------------------- preview
class TestPreview:
    CFG = "hostname R1\nntp server 1.1.1.1\ninterface Gi0/1\n description old\n"

    def test_buckets(self):
        out = network.preview_push(self.CFG, ["ntp server 1.1.1.1", "ntp server 2.2.2.2", "no description old", "no vlan 99",
                                              "reload", "interface Gi0/2", "# comment", ""])
        assert out["present"] == ["ntp server 1.1.1.1", "no vlan 99"]
        assert out["new"] == ["ntp server 2.2.2.2", "reload", "interface Gi0/2"]
        assert out["negations"] == ["no description old"]
        assert out["disruptive"] == ["reload"]                 # 'interface' is a config entry, not disruptive

    def test_empty(self):
        assert network.preview_push("", []) == {"new": [], "present": [], "negations": [], "disruptive": []}

    def test_redact_config(self):
        assert "hunter2" not in network.redact_config("username a secret 9 hunter2")


# ---------------------------------------------------------------- link csv
class TestLinksCsv:
    def test_merges_directions_and_neutralises_formulas(self, tmp_path):
        devs = {
            "R1": {"peers": ["R2", "R3"], "links": {"R2": {"local_intf": "Gi0/1", "remote_intf": "Gi0/2", "protocol": "LLDP"}}},
            "R2": {"peers": ["R1"], "links": {"R1": {"local_intf": "Gi0/2", "remote_intf": "Gi0/1", "protocol": "LLDP"}}},
            "=cmd": {"peers": ["R1"], "links": {}},
            "R3": {"peers": ["R1"], "links": {}},
        }
        devs["R1"]["peers"].append("=cmd")
        out = network.export_links_csv(devs, tmp_path / "sub" / "links.csv")
        rows = list(csv.reader(open(out, encoding="utf-8")))
        assert rows[0] == ["device_a", "interface_a", "device_b", "interface_b", "protocol"]
        body = {tuple(r[:4]): r[4] for r in rows[1:]}
        assert body[("R1", "Gi0/1", "R2", "Gi0/2")] == "LLDP"
        assert len(rows) == 4 and any(r[0] == "'=cmd" or r[2] == "'=cmd" for r in rows)

    def test_empty(self, tmp_path):
        assert len(list(csv.reader(open(network.export_links_csv({}, tmp_path / "l.csv"))))) == 1


# ---------------------------------------------------------------- prefs
class TestPrefs:
    def test_defaults_roundtrip_and_validation(self, tmp_path):
        p = Prefs(tmp_path / "prefs.json")
        assert p.all() == DEFAULTS
        p.set(appearance="light", retention_keep=10)
        again = Prefs(tmp_path / "prefs.json")
        assert again.get("appearance") == "light" and again.get("retention_keep") == 10
        for bad in ({"appearance": "neon"}, {"retention_keep": -1}, {"retention_keep": True}, {"nope": 1}, {"connect_attempts": 9}):
            with pytest.raises(ValueError):
                p.set(**bad)

    def test_garbage_and_unknown_values_ignored(self, tmp_path):
        (tmp_path / "prefs.json").write_text('{"appearance": "pink", "retention_keep": 5, "evil": 1}')
        p = Prefs(tmp_path / "prefs.json")
        assert p.get("appearance") == "dark" and p.get("retention_keep") == 5
        (tmp_path / "prefs.json").write_text("not json")
        assert Prefs(tmp_path / "prefs.json").all() == DEFAULTS

    def test_failed_write_leaves_memory_unchanged(self, tmp_path, monkeypatch):
        from netcommander import prefs
        p = Prefs(tmp_path / "p.json")
        monkeypatch.setattr(prefs, "_write_private", lambda *a: (_ for _ in ()).throw(OSError("ro")))
        with pytest.raises(OSError):
            p.set(retention_keep=3)
        assert p.get("retention_keep") == 0
