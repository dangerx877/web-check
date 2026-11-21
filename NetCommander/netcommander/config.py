"""Static configuration, filesystem layout and thread-safe runtime settings.

Nothing in this module performs I/O at import time and nothing here is mutated
after import; all mutable run-time state lives in :class:`RuntimeSettings`.
"""
from __future__ import annotations

import os
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "APP_NAME", "AUTH_FAIL_ABORT", "COMMIT_PLATFORMS", "CONFIG_NOISE",
    "DEFAULT_AUTH_PATH", "DEFAULT_BACKUP_DIR", "DEFAULT_TOPOLOGY_PATH",
    "DEFAULT_VAULT_PATH", "DISRUPTIVE_CMD", "platform_data_dir", "GENERIC_PROFILE", "GUEST_USER",
    "KDF_ITERATIONS", "LEGACY_KDF_ITERATIONS", "MAX_FREE_LOGIN_ATTEMPTS",
    "MAX_OUTPUT_LINES", "MONO_FONT", "PARAM_KEYS", "Paths", "RuntimeSettings",
    "VAULT_DIR", "VENDOR_PROFILES", "get_profile", "resolve_data_dir",
]

APP_NAME = "NetCommander"
PACKAGE_DIR = Path(__file__).resolve().parent
ENV_HOME = "NETCOMMANDER_HOME"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# PBKDF2 work factor for newly created records. Older files used 310_000 and are
# still readable because the iteration count is stored next to the data.
KDF_ITERATIONS = 600_000
LEGACY_KDF_ITERATIONS = 310_000

MAX_FREE_LOGIN_ATTEMPTS = 5
AUTH_FAIL_ABORT = 3          # stop a batch after this many SSH auth failures (lockout guard)
MAX_OUTPUT_LINES = 20_000
GUEST_USER = "guest"

if sys.platform.startswith("win"):
    MONO_FONT = "Consolas"
elif sys.platform == "darwin":
    MONO_FONT = "Menlo"
else:
    MONO_FONT = "DejaVu Sans Mono"

PARAM_KEYS = frozenset({
    "device_type", "host", "username", "password", "secret", "port",
    "timeout", "key_file", "use_keys", "global_delay_factor", "fast_cli",
})

# Platforms where config changes must be committed (or they are discarded on exit).
COMMIT_PLATFORMS = frozenset({"juniper_junos", "cisco_xr", "paloalto_panos", "nokia_sros", "nokia_srl"})


# ======================================================================
# Filesystem layout
# ======================================================================
def platform_data_dir(
    system: str | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """The conventional per-user data folder for this OS.

    * Windows: ``%APPDATA%\\NetCommander``
    * macOS:   ``~/Library/Application Support/NetCommander``
    * Linux/BSD: ``$XDG_DATA_HOME/netcommander`` (default ``~/.local/share/netcommander``)
    """
    system = (system or sys.platform).lower()
    env = os.environ if env is None else env
    home = Path(home) if home is not None else Path.home()
    if system.startswith("win"):
        base = (env.get("APPDATA") or "").strip()
        return (Path(base) if base else home / "AppData" / "Roaming") / "NetCommander"
    if system == "darwin":
        return home / "Library" / "Application Support" / "NetCommander"
    xdg = (env.get("XDG_DATA_HOME") or "").strip()
    return (Path(xdg) if xdg and Path(xdg).is_absolute() else home / ".local" / "share") / "netcommander"


def resolve_data_dir(
    env: Mapping[str, str] | None = None,
    package_dir: Path = PACKAGE_DIR,
    system: str | None = None,
    home: Path | None = None,
) -> Path:
    """Where users_auth.json, vaults/, backups/ and topology.json live.

    1. ``$NETCOMMANDER_HOME`` when set.
    2. The project folder when running from a source checkout (pyproject.toml
       sits next to the package), so existing installs keep their data in place.
    3. An existing ``~/.netcommander`` (earlier versions) so nothing is orphaned.
    4. The OS-conventional per-user folder (:func:`platform_data_dir`).
       Never writes into site-packages.
    """
    env = os.environ if env is None else env
    override = (env.get(ENV_HOME) or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if (package_dir.parent / "pyproject.toml").exists():
        return package_dir.parent
    h = Path(home) if home is not None else Path.home()
    if (h / ".netcommander").is_dir():
        return h / ".netcommander"
    return platform_data_dir(system, env, h)


@dataclass(frozen=True)
class Paths:
    """All data locations in one immutable object (easy to point at a tmp dir in tests)."""

    root: Path
    topology: Path
    vault_dir: Path
    legacy_vault: Path
    auth: Path
    backups: Path
    prefs: Path
    audit: Path
    deployments: Path
    schedules: Path
    monitors: Path
    templates: Path
    policy: Path

    @classmethod
    def for_root(cls, root: Path | str) -> "Paths":
        root = Path(root)
        return cls(
            root=root,
            topology=root / "topology.json",
            vault_dir=root / "vaults",
            legacy_vault=root / "vault.enc",      # legacy single-vault location
            auth=root / "users_auth.json",
            backups=root / "backups",
            prefs=root / "prefs.json",
            audit=root / "audit.jsonl",
            deployments=root / "deployments.json",
            schedules=root / "schedules.json",
            monitors=root / "monitors.json",
            templates=root / "templates",
            policy=root / "compliance_policy.json",
        )

    @classmethod
    def default(cls, env: Mapping[str, str] | None = None) -> "Paths":
        return cls.for_root(resolve_data_dir(env))


_DEFAULT_PATHS = Paths.default()
DEFAULT_TOPOLOGY_PATH = _DEFAULT_PATHS.topology
DEFAULT_VAULT_PATH = _DEFAULT_PATHS.legacy_vault
VAULT_DIR = _DEFAULT_PATHS.vault_dir
DEFAULT_AUTH_PATH = _DEFAULT_PATHS.auth
DEFAULT_BACKUP_DIR = _DEFAULT_PATHS.backups


# ======================================================================
# Runtime settings (replaces the old module-level STRICT_HOSTKEYS global)
# ======================================================================
class RuntimeSettings:
    """Thread-safe, injectable run-time switches.

    ``strict_hostkeys`` is the checkbox in the UI; the ``NET_SSH_STRICT_HOSTKEYS``
    environment variable can force it on regardless. ``env`` is injectable so
    tests never depend on the real process environment.
    """

    ENV_STRICT = "NET_SSH_STRICT_HOSTKEYS"
    ENV_DISABLE_GUEST = "NET_DISABLE_GUEST"

    def __init__(self, strict_hostkeys: bool = False, env: Mapping[str, str] | None = None,
                 connect_attempts: int = 2, connect_backoff: float = 1.5):
        self._lock = threading.RLock()
        self._strict = bool(strict_hostkeys)
        self._attempts = max(1, min(5, int(connect_attempts)))
        self._backoff = max(0.0, min(30.0, float(connect_backoff)))
        self._env: Mapping[str, str] = os.environ if env is None else env

    def _env_flag(self, name: str) -> bool:
        return (self._env.get(name) or "").strip().lower() in _TRUTHY

    @property
    def strict_hostkeys(self) -> bool:
        """The run-time (checkbox) value only."""
        with self._lock:
            return self._strict

    @strict_hostkeys.setter
    def strict_hostkeys(self, value: bool) -> None:
        with self._lock:
            self._strict = bool(value)

    @property
    def connect_attempts(self) -> int:
        """Total tries for a *transient* connect failure (timeouts). Authentication failures never retry."""
        with self._lock:
            return self._attempts

    @connect_attempts.setter
    def connect_attempts(self, value: int) -> None:
        with self._lock:
            self._attempts = max(1, min(5, int(value)))

    @property
    def connect_backoff(self) -> float:
        """Seconds before the first retry; doubles each time."""
        with self._lock:
            return self._backoff

    @connect_backoff.setter
    def connect_backoff(self, value: float) -> None:
        with self._lock:
            self._backoff = max(0.0, min(30.0, float(value)))

    @property
    def effective_strict_hostkeys(self) -> bool:
        """Run-time flag OR environment variable: what a new SSH connection must obey."""
        with self._lock:
            return self._strict or self._env_flag(self.ENV_STRICT)

    @property
    def guest_disabled(self) -> bool:
        with self._lock:
            return self._env_flag(self.ENV_DISABLE_GUEST)

    def ssh_security_kwargs(self) -> dict[str, Any]:
        """Extra Netmiko arguments implied by the current host-key policy."""
        if self.effective_strict_hostkeys:
            return {"ssh_strict": True, "system_host_keys": True}
        return {}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "connect_attempts": self._attempts,
                "connect_backoff": self._backoff,
                "strict_hostkeys": self._strict,
                "effective_strict_hostkeys": self._strict or self._env_flag(self.ENV_STRICT),
                "guest_disabled": self._env_flag(self.ENV_DISABLE_GUEST),
            }


# ======================================================================
# Vendor profiles
# ======================================================================
_CISCO_DISCOVERY = (
    ("show lldp neighbors detail", "LLDP", "cisco_lldp"),
    ("show cdp neighbors detail", "CDP", "cisco_cdp"),
)
_CISCO_PRESETS = (
    ("Interfaces", "show ip interface brief"),
    ("Routes", "show ip route"),
    ("BGP", "show ip bgp summary"),
    ("Version", "show version"),
    ("OSPF", "show ip ospf neighbor"),
)
_COMWARE_PRESETS = (
    ("Interfaces", "display ip interface brief"),
    ("Routes", "display ip routing-table"),
    ("BGP", "display bgp peer ipv4"),
    ("Version", "display version"),
    ("OSPF", "display ospf peer"),
)

GENERIC_PROFILE: dict[str, Any] = {
    "vendor": "Generic",
    "enable": False,
    "config": "show running-config",
    "discovery": _CISCO_DISCOVERY,
    "presets": (
        ("Version", "show version"),
        ("Interfaces", "show ip interface brief"),
        ("Routes", "show ip route"),
    ),
}

VENDOR_PROFILES: dict[str, dict[str, Any]] = {
    "cisco_ios": {
        "vendor": "Cisco IOS", "enable": True, "config": "show running-config",
        "discovery": _CISCO_DISCOVERY, "presets": _CISCO_PRESETS,
    },
    "cisco_xe": {
        "vendor": "Cisco IOS-XE", "enable": True, "config": "show running-config",
        "discovery": _CISCO_DISCOVERY, "presets": _CISCO_PRESETS,
    },
    "cisco_nxos": {
        "vendor": "Cisco NX-OS", "enable": False, "config": "show running-config",
        "discovery": _CISCO_DISCOVERY,
        "presets": (
            ("Interfaces", "show ip interface brief"), ("Routes", "show ip route"),
            ("BGP", "show ip bgp summary"), ("Version", "show version"),
            ("OSPF", "show ip ospf neighbors"),
        ),
    },
    "cisco_xr": {
        "vendor": "Cisco IOS-XR", "enable": False, "config": "show running-config",
        "discovery": _CISCO_DISCOVERY,
        "presets": (
            ("Interfaces", "show ip interface brief"), ("Routes", "show route"),
            ("BGP", "show bgp summary"), ("Version", "show version"),
            ("OSPF", "show ospf neighbor"),
        ),
    },
    "arista_eos": {
        "vendor": "Arista EOS", "enable": True, "config": "show running-config",
        "discovery": (("show lldp neighbors detail", "LLDP", "arista_lldp"),),
        "presets": _CISCO_PRESETS,
    },
    "juniper_junos": {
        "vendor": "Juniper Junos", "enable": False,
        "config": "show configuration | display set",
        "discovery": (("show lldp neighbors", "LLDP", "junos_lldp"),),
        "presets": (
            ("Interfaces", "show interfaces terse"), ("Routes", "show route"),
            ("BGP", "show bgp summary"), ("Version", "show version"),
            ("OSPF", "show ospf neighbor"), ("Alarms", "show system alarms"),
            ("Chassis", "show chassis alarms"),
        ),
    },
    "huawei": {
        "vendor": "Huawei VRP", "enable": False, "config": "display current-configuration",
        "discovery": (("display lldp neighbor brief", "LLDP", "huawei_lldp"),),
        "presets": _COMWARE_PRESETS,
    },
    "hp_comware": {
        "vendor": "HPE Comware", "enable": False, "config": "display current-configuration",
        "discovery": (("display lldp neighbor-information list", "LLDP", "comware_lldp"),),
        "presets": _COMWARE_PRESETS,
    },
    "hp_procurve": {
        "vendor": "HPE/Aruba ProCurve", "enable": True, "config": "show running-config",
        "discovery": (("show lldp info remote-device", "LLDP", "procurve_lldp"),),
        "presets": (
            ("Interfaces", "show interfaces brief"), ("Routes", "show ip route"),
            ("System", "show system"), ("LLDP", "show lldp info remote-device"),
        ),
    },
    "dell_os10": {
        "vendor": "Dell OS10", "enable": False, "config": "show running-configuration",
        "discovery": (("show lldp neighbors", "LLDP", "os10_lldp"),),
        "presets": (
            ("Interfaces", "show interface status"), ("Routes", "show ip route"),
            ("Version", "show version"), ("BGP", "show ip bgp summary"),
            ("OSPF", "show ip ospf neighbor"), ("LLDP", "show lldp neighbors"),
        ),
    },
    "nokia_sros": {
        "vendor": "Nokia SR OS", "enable": False, "config": "admin show configuration",
        "discovery": (("show system lldp neighbor", "LLDP", None),),
        "presets": (
            ("Interfaces", "show router interface"), ("Routes", "show router route-table"),
            ("BGP", "show router bgp summary"), ("OSPF", "show router ospf neighbor"),
            ("Version", "show version"),
        ),
    },
    "nokia_srl": {
        "vendor": "Nokia SR Linux", "enable": False, "config": "info flat /",
        "discovery": (("show system lldp neighbor", "LLDP", "srl_lldp"),),
        "presets": (
            ("Interfaces", "show interface brief"), ("Version", "show version"),
            ("Routes", "show network-instance default route-table"),
            ("BGP", "show network-instance default protocols bgp neighbor"),
            ("LLDP", "show system lldp neighbor"),
        ),
    },
    "extreme_exos": {
        "vendor": "Extreme EXOS", "enable": False, "config": "show configuration",
        "discovery": (("show lldp neighbors detailed", "LLDP", None),),
        "presets": (("Ports", "show ports"), ("Version", "show version"),
                    ("Routes", "show iproute")),
    },
    "fortinet": {
        "vendor": "Fortinet FortiOS", "enable": False, "config": "show full-configuration",
        "discovery": (),
        "presets": (
            ("Status", "get system status"), ("Interfaces", "get system interface physical"),
            ("Routes", "get router info routing-table all"),
            ("BGP", "get router info bgp summary"), ("OSPF", "get router info ospf neighbor"),
        ),
    },
    "paloalto_panos": {
        "vendor": "Palo Alto PAN-OS", "enable": False, "config": "show config running",
        "discovery": (("show lldp neighbors all", "LLDP", None),),
        "presets": (
            ("System", "show system info"), ("Interfaces", "show interface all"),
            ("Routes", "show routing route"),
        ),
    },
    "mikrotik_routeros": {
        "vendor": "MikroTik RouterOS", "enable": False, "config": "/export",
        "discovery": (("/ip neighbor print detail without-paging", "MNDP/LLDP", "mikrotik_nbr"),),
        "presets": (
            ("Interfaces", "/interface print"), ("Routes", "/ip route print"),
            ("BGP", "/routing bgp session print"), ("Resource", "/system resource print"),
            ("Neighbors", "/ip neighbor print"),
        ),
    },
    "linux": {
        "vendor": "Linux (lldpd)", "enable": False, "config": "cat /etc/network/interfaces",
        "discovery": (("lldpctl -f keyvalue", "LLDP", "linux_lldpctl"),),
        "presets": (
            ("Addresses", "ip -br addr"), ("Routes", "ip route"),
            ("Link stats", "ip -s link"), ("Kernel", "uname -a"), ("Uptime", "uptime"), ("LLDP", "lldpctl"),
        ),
    },
}


def get_profile(device_type: str | None) -> dict[str, Any]:
    """Vendor profile merged over the generic one (always a fresh dict)."""
    profile = dict(GENERIC_PROFILE)
    profile.update(VENDOR_PROFILES.get(device_type or "", {}))
    return profile


DISRUPTIVE_CMD = re.compile(
    r"^\s*(conf(?:ig(?:ure)?)?\b|reload\b|reboot\b|shutdown\b|halt\b|poweroff\b|"
    r"write\s+erase|erase\b|delete\b|format\b|clear\b|debug\b|undebug\b|request\s+system\b|"
    r"commit\b|set\b|no\s|copy\b|archive\b|reset\b|rm\b|sudo\b|"
    r"rollback\b|load\b|boot\b|upgrade\b|factory\b|crypto\s+key\s+zeroize|redundancy\s+force|"
    r"admin\s+(reboot|factory|reload)|"
    r"/system\s+(reset|reboot|shutdown))",
    re.I,
)

CONFIG_NOISE = tuple(
    re.compile(p, re.I)
    for p in (
        r"^\s*!\s*(last configuration change|nvram config last updated|time:)",
        r"^\s*!\s*(running configuration last done|config last modified|last commit)",
        r"^\s*building configuration",
        r"^\s*current configuration\s*:",
        r"^\s*ntp clock-period",
        r"^\s*##\s*last (commit|changed)",
        r"^\s*#.*by routeros",
        r"^\s*!\s*last configuration change at",
        r"^\s*#\s*(generated|finished)\s+\d{4}-",
        r"^\s*;\s*.*configuration editor;\s*created on",
    )
)
