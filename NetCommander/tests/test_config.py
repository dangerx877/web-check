"""config.py: RuntimeSettings, data-dir resolution, vendor profiles, regex tables."""
from __future__ import annotations

import threading

import pytest

from netcommander import config
from netcommander.config import (
    COMMIT_PLATFORMS,
    CONFIG_NOISE,
    DISRUPTIVE_CMD,
    GENERIC_PROFILE,
    VENDOR_PROFILES,
    Paths,
    RuntimeSettings,
    get_profile,
    resolve_data_dir,
)
from netcommander.parsers import RAW_PARSERS


# ---------------------------------------------------------------- RuntimeSettings
class TestRuntimeSettings:
    def test_defaults_off(self):
        s = RuntimeSettings(env={})
        assert not s.strict_hostkeys and not s.effective_strict_hostkeys
        assert not s.guest_disabled
        assert s.ssh_security_kwargs() == {}

    def test_runtime_flag_enables_strict(self):
        s = RuntimeSettings(env={})
        s.strict_hostkeys = True
        assert s.effective_strict_hostkeys
        assert s.ssh_security_kwargs() == {"ssh_strict": True, "system_host_keys": True}
        s.strict_hostkeys = False
        assert not s.effective_strict_hostkeys

    @pytest.mark.parametrize("value", ["1", "true", "YES", " on "])
    def test_env_var_forces_strict_even_when_runtime_off(self, value):
        s = RuntimeSettings(strict_hostkeys=False, env={"NET_SSH_STRICT_HOSTKEYS": value})
        assert s.effective_strict_hostkeys and not s.strict_hostkeys
        assert s.ssh_security_kwargs()["ssh_strict"] is True

    @pytest.mark.parametrize("value", ["", "0", "no", "off", "maybe"])
    def test_env_var_falsey_values(self, value):
        s = RuntimeSettings(env={"NET_SSH_STRICT_HOSTKEYS": value, "NET_DISABLE_GUEST": value})
        assert not s.effective_strict_hostkeys and not s.guest_disabled

    def test_guest_disabled_env(self):
        assert RuntimeSettings(env={"NET_DISABLE_GUEST": "1"}).guest_disabled

    def test_env_is_read_live(self):
        env: dict[str, str] = {}
        s = RuntimeSettings(env=env)
        assert not s.effective_strict_hostkeys
        env["NET_SSH_STRICT_HOSTKEYS"] = "1"
        assert s.effective_strict_hostkeys

    def test_snapshot(self):
        s = RuntimeSettings(strict_hostkeys=True, env={"NET_DISABLE_GUEST": "1"})
        assert s.snapshot() == {
            "strict_hostkeys": True, "effective_strict_hostkeys": True, "guest_disabled": True,
            "connect_attempts": 2, "connect_backoff": 1.5,
        }

    def test_instances_do_not_share_state(self):
        a, b = RuntimeSettings(env={}), RuntimeSettings(env={})
        a.strict_hostkeys = True
        assert not b.strict_hostkeys

    def test_concurrent_toggling_is_safe(self):
        s = RuntimeSettings(env={})
        errors: list[BaseException] = []

        def flip(n):
            try:
                for i in range(500):
                    s.strict_hostkeys = (i + n) % 2 == 0
                    s.ssh_security_kwargs()
                    s.snapshot()
            except BaseException as exc:             # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=flip, args=(n,)) for n in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors

    def test_no_module_level_strict_global(self):
        assert not hasattr(config, "STRICT_HOSTKEYS")


# ---------------------------------------------------------------- paths
class TestPaths:
    def test_env_override_wins(self, tmp_path):
        got = resolve_data_dir({"NETCOMMANDER_HOME": str(tmp_path / "x")}, package_dir=tmp_path / "pkg")
        assert got == (tmp_path / "x").resolve()

    def test_source_checkout_uses_project_root(self, tmp_path):
        pkg = tmp_path / "proj" / "netcommander"
        pkg.mkdir(parents=True)
        (tmp_path / "proj" / "pyproject.toml").write_text("")
        assert resolve_data_dir({}, package_dir=pkg) == tmp_path / "proj"

    def test_installed_copy_uses_home_dir(self, tmp_path):
        pkg = tmp_path / "site-packages" / "netcommander"
        pkg.mkdir(parents=True)
        home = tmp_path / "home"
        home.mkdir()
        assert resolve_data_dir({}, package_dir=pkg, system="linux", home=home) == home / ".local" / "share" / "netcommander"

    def test_for_root_layout(self, tmp_path):
        p = Paths.for_root(tmp_path)
        assert p.topology == tmp_path / "topology.json"
        assert p.auth == tmp_path / "users_auth.json"
        assert p.vault_dir == tmp_path / "vaults"
        assert p.legacy_vault == tmp_path / "vault.enc"
        assert p.backups == tmp_path / "backups"

    def test_paths_are_immutable(self, tmp_path):
        import dataclasses
        with pytest.raises(dataclasses.FrozenInstanceError):
            Paths.for_root(tmp_path).root = tmp_path / "other"      # type: ignore[misc]


# ---------------------------------------------------------------- profiles
class TestProfiles:
    @pytest.mark.parametrize("dtype", sorted(VENDOR_PROFILES))
    def test_profile_is_complete(self, dtype):
        p = get_profile(dtype)
        assert p["vendor"] and p["config"]
        assert isinstance(p["enable"], bool)
        assert all(len(item) == 2 for item in p["presets"])
        for cmd, proto, parser_key in p["discovery"]:
            assert cmd and proto
            assert parser_key is None or parser_key in RAW_PARSERS

    def test_every_raw_parser_is_used_by_a_profile(self):
        used = {k for p in VENDOR_PROFILES.values() for _, _, k in p["discovery"] if k}
        assert used == set(RAW_PARSERS)

    def test_profiles_without_raw_parser_exist(self):
        none_keys = {n for n, p in VENDOR_PROFILES.items() if any(k is None for *_, k in p["discovery"])}
        assert {"extreme_exos", "paloalto_panos", "nokia_sros"} <= none_keys

    @pytest.mark.parametrize("dtype", [None, "", "no_such_vendor"])
    def test_unknown_type_falls_back_to_generic(self, dtype):
        assert get_profile(dtype) == GENERIC_PROFILE

    def test_get_profile_returns_fresh_dict(self):
        p = get_profile("cisco_ios")
        p["vendor"] = "tampered"
        assert get_profile("cisco_ios")["vendor"] == "Cisco IOS"

    def test_commit_platforms(self):
        assert COMMIT_PLATFORMS == {"juniper_junos", "cisco_xr", "paloalto_panos", "nokia_sros", "nokia_srl"}
        assert all(d in VENDOR_PROFILES for d in COMMIT_PLATFORMS)


# ---------------------------------------------------------------- regexes
@pytest.mark.parametrize("cmd", [
    "reload", "reload in 5", "configure terminal", "conf t", "shutdown", "write erase",
    "erase flash:", "delete flash:x", "clear counters", "debug ip packet", "commit",
    "set system host-name x", "no shutdown", "copy run start", "rm -rf /", "sudo reboot",
    "/system reboot", "  reboot", "RELOAD",
])
def test_disruptive_commands_detected(cmd):
    assert DISRUPTIVE_CMD.match(cmd)


@pytest.mark.parametrize("cmd", [
    "show version", "show ip route", "display current-configuration", "get system status",
    "/ip route print", "ping 1.1.1.1", "show running-config", "uname -a; uptime", "notconf",
])
def test_safe_commands_not_flagged(cmd):
    assert not DISRUPTIVE_CMD.match(cmd)


@pytest.mark.parametrize("line", [
    "! Last configuration change at 12:00:00 UTC",
    "! NVRAM config last updated at 12:00",
    "Building configuration...",
    "Current configuration : 1234 bytes",
    "ntp clock-period 17179869",
    "## Last commit: 2021-01-01",
    "# jan/01/2021 by RouterOS 7.1",
    "! Time: Mon Jan 1",
])
def test_config_noise_lines_match(line):
    assert any(rx.match(line) for rx in CONFIG_NOISE)


def test_real_config_lines_are_not_noise():
    for line in ("hostname R1", "interface Gi0/1", " ip address 10.0.0.1 255.255.255.0", "!"):
        assert not any(rx.match(line) for rx in CONFIG_NOISE)
