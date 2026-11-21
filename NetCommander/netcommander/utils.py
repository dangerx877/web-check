"""Small GUI-free helpers shared by the UI and the tests."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .config import MAX_OUTPUT_LINES

__all__ = ["excess_lines", "open_folder", "parse_commands", "parse_host_port"]


def parse_host_port(text: str) -> tuple[str, int | None]:
    """Split ``host``, ``host:port`` or ``[v6]:port``. Raises ValueError on bad input.

    A bare IPv6 address (several colons, no brackets) is returned unchanged.
    """
    text = (text or "").strip()
    if not text or re.search(r"\s", text):
        raise ValueError("Enter a management IP or hostname (no spaces).")
    bad_port = ValueError("Use the format IP or IP:port (port 1-65535).")

    if text.startswith("["):
        m = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", text)
        if not m:
            raise bad_port
        host, port_s = m.group(1), m.group(2)
    elif text.count(":") == 1:
        host, port_s = text.split(":")
        if not port_s:
            raise bad_port
    else:
        return text, None

    if not host:
        raise bad_port
    if port_s is None:
        return host, None
    if not (port_s.isdigit() and 1 <= int(port_s) <= 65535):
        raise bad_port
    return host, int(port_s)


def parse_commands(script: str) -> list[str]:
    """Commands from a script box: one per line, blank lines and ``#`` comments dropped."""
    return [
        ln.strip() for ln in script.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


def excess_lines(total_lines: int, limit: int = MAX_OUTPUT_LINES, slack: int = 1000) -> int:
    """How many leading lines to delete so a log pane stays bounded (0 = nothing to do)."""
    if total_lines <= limit:
        return 0
    return total_lines - limit + slack


def opener_command(path: Path, system: str | None = None) -> list[str] | None:
    """argv that opens ``path`` in the OS file manager; ``None`` means "use os.startfile" (Windows)."""
    system = (system or sys.platform).lower()
    if system.startswith("win"):
        return None
    if system == "darwin":
        return ["open", str(path)]
    return ["xdg-open", str(path)]


def open_folder(path: Path) -> str | None:
    """Open `path` in the OS file manager. Returns an error message, or None on success."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        cmd = opener_command(path)
        if cmd is None:
            os.startfile(str(path))  # type: ignore[attr-defined]  # Windows only
        else:
            if shutil.which(cmd[0]) is None:
                return (f"'{cmd[0]}' is not installed, so the folder cannot be opened automatically. "
                        f"It is here: {path}")
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return str(exc)
    return None


def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection (=, +, -, @, tab, CR) in exported cells."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
