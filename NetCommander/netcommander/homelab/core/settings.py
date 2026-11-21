"""``homelab.json``: validated, non-secret platform configuration.

Unknown keys and wrong types are reported together (``ConfigError.problems``) instead of being
silently ignored, and every value has a safe default, so an empty or missing file is valid.
Secrets never appear here - only ``*_ref`` names that point into the SecretStore.
"""
from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ...security import _write_private
from .errors import ConfigError

DEFAULTS: dict[str, Any] = {
    "monitoring": {
        "interval_seconds": 60,          # availability / metric sweep
        "collect_interval_seconds": 300,  # SSH/WinRM/API resource collection
        "retention_days": 30,
        "event_retention_days": 90,
        "workers": 16,
        "ping_timeout": 2.0,
    },
    "discovery": {
        "max_hosts": 1024,               # refuse to sweep more than this many addresses in one run
        "ports": [22, 53, 80, 443, 445, 2049, 3260, 5000, 5001, 5985, 5986, 8006, 8080, 8443, 9000, 9443,
                  2375, 2376, 902, 161, 3389, 9100, 1883, 8123],
        "timeout": 0.8,
        "workers": 64,
        "reverse_dns": True,
    },
    "api": {
        "bind": "127.0.0.1",
        "port": 8765,
        "tls_cert": "",
        "tls_key": "",
        "session_idle_minutes": 15,
        "session_max_hours": 8,
        "allow_remote_without_tls": False,
    },
    "automation": {
        "require_approval_for": ["change", "destructive"],   # risk levels needing a second person
        "default_timeout": 120,
        "max_output_kb": 512,
        "allow_self_approval_when_single_admin": False,
    },
    "notifications": {
        "dedup_minutes": 15,
        "channels": [],                  # [{"type": "webhook", "url": "...", "token_ref": "...", "min_severity": "warning"}]
    },
    "plugins": {"enabled": False, "allow": []},
}

_TYPES: dict[str, dict[str, tuple[type, ...]]] = {
    "monitoring": {"interval_seconds": (int,), "collect_interval_seconds": (int,), "retention_days": (int,),
                   "event_retention_days": (int,), "workers": (int,), "ping_timeout": (int, float)},
    "discovery": {"max_hosts": (int,), "ports": (list,), "timeout": (int, float), "workers": (int,),
                  "reverse_dns": (bool,)},
    "api": {"bind": (str,), "port": (int,), "tls_cert": (str,), "tls_key": (str,), "session_idle_minutes": (int,),
            "session_max_hours": (int,), "allow_remote_without_tls": (bool,)},
    "automation": {"require_approval_for": (list,), "default_timeout": (int,), "max_output_kb": (int,),
                   "allow_self_approval_when_single_admin": (bool,)},
    "notifications": {"dedup_minutes": (int,), "channels": (list,)},
    "plugins": {"enabled": (bool,), "allow": (list,)},
}
_RANGES: dict[tuple[str, str], tuple[float, float]] = {
    ("monitoring", "interval_seconds"): (10, 86400), ("monitoring", "collect_interval_seconds"): (30, 86400),
    ("monitoring", "retention_days"): (1, 3650), ("monitoring", "event_retention_days"): (1, 3650),
    ("monitoring", "workers"): (1, 128), ("monitoring", "ping_timeout"): (0.1, 30),
    ("discovery", "max_hosts"): (1, 65536), ("discovery", "timeout"): (0.05, 30), ("discovery", "workers"): (1, 512),
    ("api", "port"): (1, 65535), ("api", "session_idle_minutes"): (1, 1440), ("api", "session_max_hours"): (1, 168),
    ("automation", "default_timeout"): (1, 86400), ("automation", "max_output_kb"): (1, 65536),
    ("notifications", "dedup_minutes"): (0, 10080),
}
CHANNEL_TYPES = ("log", "file", "webhook", "email")
RISKS = ("read_only", "change", "destructive")


def validate(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ConfigError("homelab.json must contain a JSON object.")
    problems: list[str] = []
    cfg = copy.deepcopy(DEFAULTS)
    for section, values in raw.items():
        if section not in DEFAULTS:
            problems.append(f"unknown section {section!r}")
            continue
        if not isinstance(values, Mapping):
            problems.append(f"{section} must be an object")
            continue
        for key, val in values.items():
            types = _TYPES[section].get(key)
            if types is None:
                problems.append(f"unknown setting {section}.{key}")
                continue
            if isinstance(val, bool) and bool not in types:
                problems.append(f"{section}.{key} must be {types[0].__name__}")
                continue
            if not isinstance(val, types):
                problems.append(f"{section}.{key} must be {types[0].__name__}")
                continue
            rng = _RANGES.get((section, key))
            if rng and not rng[0] <= val <= rng[1]:
                problems.append(f"{section}.{key} must be between {rng[0]:g} and {rng[1]:g}")
                continue
            cfg[section][key] = val
    for p in cfg["discovery"]["ports"]:
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            problems.append(f"discovery.ports contains an invalid port {p!r}")
    for r in cfg["automation"]["require_approval_for"]:
        if r not in RISKS:
            problems.append(f"automation.require_approval_for: unknown risk {r!r}")
    for i, ch in enumerate(cfg["notifications"]["channels"]):
        if not isinstance(ch, Mapping) or ch.get("type") not in CHANNEL_TYPES:
            problems.append(f"notifications.channels[{i}].type {ch.get('type') if isinstance(ch, Mapping) else ch!r} must be one of {', '.join(CHANNEL_TYPES)}")
            continue
        for k in ch:
            if k in ("token", "password", "secret"):
                problems.append(f"notifications.channels[{i}].{k}: put secrets in the secret store and use {k}_ref")
    api = cfg["api"]
    if bool(api["tls_cert"]) != bool(api["tls_key"]):
        problems.append("api.tls_cert and api.tls_key must be set together")
    if problems:
        raise ConfigError("Invalid homelab configuration: " + "; ".join(problems), problems)
    return cfg


def load(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return copy.deepcopy(DEFAULTS)
    except ValueError as exc:
        raise ConfigError(f"{p} is not valid JSON: {exc}") from None
    return validate(raw)


def save(path: Path | str, cfg: Mapping[str, Any]) -> dict[str, Any]:
    clean = validate(cfg)
    _write_private(Path(path), json.dumps(clean, indent=2, sort_keys=True))
    return clean
