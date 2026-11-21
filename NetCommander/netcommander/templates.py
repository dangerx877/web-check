"""Device configuration templates.

Syntax is deliberately tiny and safe (no code execution, unlike Jinja2 in sandbox-less hands):

    hostname {{hostname}}
    interface {{uplink|GigabitEthernet0/1}}      <- default after '|'
    ntp server {{ntp_server}}

Variables come from the device record (``name``, ``ip``, ``device_type``, ``username``…) merged
with per-device overrides and global variables. A missing variable without a default is an error
that names the device and variable, so nothing half-rendered is ever pushed.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

from .security import safe_filename

_VAR = re.compile(r"\{\{\s*([A-Za-z_][\w.-]*)\s*(?:\|([^}]*))?\}\}")
BUILTIN_KEYS = ("name", "ip", "device_type", "port", "username")


class TemplateError(ValueError):
    pass


def variables_in(template: str) -> dict[str, str | None]:
    """Map of variable → default (None when required)."""
    out: dict[str, str | None] = {}
    for m in _VAR.finditer(template):
        name, default = m.group(1), m.group(2)
        if name not in out or out[name] is None:
            out[name] = default.strip() if default is not None else None
    return out


def render(template: str, variables: Mapping[str, object], who: str = "") -> str:
    missing: list[str] = []

    def sub(m: re.Match[str]) -> str:
        name, default = m.group(1), m.group(2)
        if name in variables and str(variables[name]) != "":
            return str(variables[name])
        if default is not None:
            return default.strip()
        if name not in missing:
            missing.append(name)
        return m.group(0)

    out = _VAR.sub(sub, template)
    if missing:
        raise TemplateError(f"{who + ': ' if who else ''}missing variable(s): {', '.join(missing)}")
    return out


def render_for_devices(
    template: str,
    devices: Mapping[str, Mapping[str, object]],
    global_vars: Mapping[str, object] | None = None,
    overrides: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, list[str]]:
    """Render per device → ``{name: [command lines]}``. Raises one TemplateError listing *every* problem."""
    result: dict[str, list[str]] = {}
    problems: list[str] = []
    for name in sorted(devices):
        ctx: dict[str, object] = {k: devices[name].get(k, "") for k in BUILTIN_KEYS}
        ctx.update(global_vars or {})
        ctx.update((overrides or {}).get(name, {}))
        ctx["name"] = name
        try:
            text = render(template, ctx, who=name)
        except TemplateError as exc:
            problems.append(str(exc))
            continue
        result[name] = [ln for ln in text.splitlines() if ln.strip()]
    if problems:
        raise TemplateError("\n".join(problems))
    return result


class TemplateLibrary:
    """Named templates stored as ``<name>.tmpl`` text files (easy to review in git)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def names(self) -> list[str]:
        return sorted(p.stem for p in self.root.glob("*.tmpl")) if self.root.is_dir() else []

    def _path(self, name: str) -> Path:
        return self.root / f"{safe_filename(name)}.tmpl"

    def save(self, name: str, text: str) -> Path:
        if not name.strip() or not text.strip():
            raise TemplateError("A template needs a name and some content.")
        self.root.mkdir(parents=True, exist_ok=True)
        p = self._path(name)
        p.write_text(text.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        return p

    def load(self, name: str) -> str:
        try:
            return self._path(name).read_text(encoding="utf-8")
        except OSError as exc:
            raise TemplateError(f"Cannot read template {name!r}: {exc}") from None

    def delete(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)


def load_vars_file(path: str | Path) -> dict[str, dict[str, object]]:
    """JSON: ``{"global": {...}, "devices": {"R1": {...}}}``."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TemplateError(f"Cannot read variables file: {exc}") from None
    return {"global": dict(data.get("global", {})), "devices": dict(data.get("devices", {}))}
