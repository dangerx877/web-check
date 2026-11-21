"""Which exec-mode commands count as *read-only* (allowed with the RUN_SHOW permission).

This is an **allowlist**: a command is read-only only if it matches one of the known-safe forms
for the device's platform. Everything else - including abbreviations such as ``confi t``,
``relo`` or ``wr er`` that a deny-list cannot keep up with - needs PUSH_CONFIG.

Rules
* Network OSes: ``show``-style commands (``display`` on Huawei/Comware, ``get``/``show`` on
  FortiOS, ``/... print`` on RouterOS), plus ``ping`` / ``traceroute`` and terminal paging.
* Output may be filtered with pipes (``| include``, ``| match``) but never sent anywhere:
  ``| redirect``, ``| tee``, ``| append``, ``| save``, ``>`` and friends are refused.
* Linux: a small set of inspection commands with no shell metacharacters at all (no ``;``,
  ``&&``, ``|``, ``$()``, redirections) and none of their state-changing options.

Keep this module free of GUI imports; it is used by :mod:`netcommander.services`.
"""
from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Sequence

__all__ = ["is_read_only", "non_read_only", "family_of"]

_SHOW = r"(?:sh|sho|show)"
_COMMON = (
    rf"{_SHOW}\b",
    r"ping\b",
    r"traceroute\b",
    r"ter(?:m(?:i(?:n(?:a(?:l)?)?)?)?)?\s+(?:len(?:g(?:t(?:h)?)?)?|wid(?:t(?:h)?)?)\s+\d+\s*$",
)
_FAMILY_RULES: dict[str, tuple[str, ...]] = {
    "cisco": _COMMON + (r"trace\b", r"dir\b"),
    "junos": (rf"{_SHOW}\b", r"ping\b", r"traceroute\b"),
    "huawei": (r"dis(?:p(?:l(?:a(?:y)?)?)?)?\b", r"ping\b", r"tracert\b"),
    "fortinet": (r"get\b", r"show\b"),
    "panos": (r"show\b", r"ping\b", r"traceroute\b"),
    "nokia": (rf"{_SHOW}\b", r"ping\b", r"traceroute\b"),
    "generic": (rf"{_SHOW}\b", r"ping\b", r"traceroute\b"),
}
_FAMILY_RULES_RX = {k: re.compile(r"^\s*(?:" + "|".join(v) + ")", re.I) for k, v in _FAMILY_RULES.items()}

# Output may be filtered, never written or sent somewhere (IOS "| redirect", Junos "| save", NX-OS ">").
_EXFIL = re.compile(r"\|\s*(?:redirect|tee|append|save|copy|exec|ftp|tftp|scp|write)\b|>", re.I)

# RouterOS: "/path [path ...] print [args]" - and no state-changing verb anywhere before "print".
_ROS_PRINT = re.compile(r"^\s*/[a-z0-9 /_-]*?\bprint\b", re.I)
_ROS_PING = re.compile(r"^\s*/(?:ping|tool\s+traceroute)\b", re.I)
_ROS_VERBS = re.compile(r"\b(?:set|add|remove|disable|enable|reset|reset-configuration|reboot|shutdown|"
                        r"export|import|run|execute|upgrade|install|unset|move|edit|comment|monitor-traffic)\b", re.I)

# Linux: tokens are checked after shlex parsing; any metacharacter disqualifies the whole line.
_SHELL_META = re.compile(r"[;&|`$<>(){}\\\n*?\[\]!~]")
_IP_OBJECTS = {"a", "addr", "address", "r", "ro", "route", "l", "link", "n", "neigh", "neighbour", "neighbor",
               "rule", "maddr", "tunnel", "-br", "-brief"}
_IP_VERBS_BAD = {"add", "del", "delete", "change", "replace", "flush", "set", "append", "prepend", "save",
                 "restore", "up", "down", "exec", "monitor"}
_LINUX_SIMPLE = {"uptime", "whoami", "id", "df", "free", "ps", "lsb_release", "netstat", "uname", "ls",
                 "ping", "traceroute", "lldpctl", "lsblk", "lscpu", "w", "who"}


def family_of(device_type: str | None) -> str:
    d = (device_type or "").lower()
    if d.startswith(("cisco_", "arista", "dell", "extreme", "hp_procurve", "ruckus", "brocade")):
        return "cisco"
    if d.startswith("juniper"):
        return "junos"
    if d.startswith(("huawei", "hp_comware")):
        return "huawei"
    if d.startswith("fortinet"):
        return "fortinet"
    if d.startswith("paloalto"):
        return "panos"
    if d.startswith("nokia"):
        return "nokia"
    if d.startswith("mikrotik"):
        return "mikrotik"
    if d == "linux":
        return "linux"
    return "generic"


def _linux_read_only(cmd: str) -> bool:
    if _SHELL_META.search(cmd):
        return False
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return False
    if not argv:
        return False
    prog, args = argv[0], argv[1:]
    if "/" in prog:
        return False
    if prog in ("hostname", "date"):
        return not args or (prog == "hostname" and all(a in ("-f", "-i", "-I", "-s", "-d") for a in args))
    if prog == "ss":
        return not any(a in ("-K", "--kill") or (a.startswith("-") and not a.startswith("--") and "K" in a)
                       for a in args)
    if prog == "cat":
        return bool(args) and all(a.startswith("/proc/") or a in ("/etc/os-release", "/etc/hostname") for a in args) \
            and not any(".." in a for a in args)
    if prog == "lldpcli":
        return bool(args) and args[0] == "show"
    if prog == "ip":
        words = [a for a in args if not re.fullmatch(r"-(?:[46sdjcp]|br|brief|stats|details|json|color)", a)]
        if not words:
            return False
        if words[0] not in _IP_OBJECTS:
            return False
        return not any(w in _IP_VERBS_BAD for w in words[1:])
    return prog in _LINUX_SIMPLE


def is_read_only(command: str, device_type: str | None = None) -> bool:
    """True if `command` is a known read-only exec command on this platform."""
    cmd = (command or "").strip()
    if not cmd:
        return True
    fam = family_of(device_type)
    if fam == "linux":
        return _linux_read_only(cmd)
    if _EXFIL.search(cmd):
        return False
    if fam == "mikrotik":
        if _ROS_PING.match(cmd):
            return True
        if not _ROS_PRINT.match(cmd):
            return False
        before_print = cmd.split("print", 1)[0]
        return not _ROS_VERBS.search(before_print)
    return bool(_FAMILY_RULES_RX[fam].match(cmd))


def non_read_only(commands: Iterable[str], device_types: Sequence[str | None]) -> list[str]:
    """Commands that are not read-only on at least one of the given platforms."""
    types = list(device_types) or [None]
    return [c for c in commands if not all(is_read_only(c, t) for t in types)]
