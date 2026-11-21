"""Adapter / plugin registry.

Every integration (hypervisor, NAS, container host, backup platform, notifier) is registered under a
``(category, kind)`` key with a factory and a schema of its configuration fields. Adding support for
new hardware means writing one adapter and registering it - nothing else in the platform changes.

Third-party plugins can register through the ``netcommander.adapters`` entry-point group, but they run
arbitrary code with the user's privileges, so loading them is **off by default** and must be enabled
in ``homelab.json`` (``"plugins": {"enabled": true, "allow": ["name", ...]}``).
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import NotFound, ValidationError

log = logging.getLogger(__name__)
ENTRY_POINT_GROUP = "netcommander.adapters"


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str = ""
    required: bool = False
    secret: bool = False                 # value lives in the SecretStore; config keeps ``<name>_ref``
    default: Any = None
    kind: str = "str"                    # str | int | bool | float | list
    help: str = ""


@dataclass(frozen=True)
class AdapterSpec:
    category: str                        # hypervisor | docker | storage | backup | notifier | server
    kind: str                            # proxmox | truenas | ...
    title: str
    factory: Callable[..., Any]
    fields: tuple[FieldSpec, ...] = ()
    capabilities: frozenset[str] = field(default_factory=frozenset)
    maturity: str = "stable"             # stable | beta | experimental
    notes: str = ""

    def public(self) -> dict[str, Any]:
        return {"category": self.category, "kind": self.kind, "title": self.title, "maturity": self.maturity,
                "capabilities": sorted(self.capabilities), "notes": self.notes,
                "fields": [{"name": f.name, "label": f.label or f.name, "required": f.required, "secret": f.secret,
                            "default": f.default, "kind": f.kind, "help": f.help} for f in self.fields]}


_CASTS: dict[str, Callable[[Any], Any]] = {"str": str, "int": int, "float": float,
                                           "bool": lambda v: v if isinstance(v, bool) else str(v).lower() in
                                           ("1", "true", "yes", "on"),
                                           "list": lambda v: list(v) if isinstance(v, (list, tuple)) else
                                           [x.strip() for x in str(v).split(",") if x.strip()]}


class Registry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._specs: dict[tuple[str, str], AdapterSpec] = {}

    def register(self, spec: AdapterSpec) -> AdapterSpec:
        with self._lock:
            self._specs[(spec.category, spec.kind)] = spec
        return spec

    def get(self, category: str, kind: str) -> AdapterSpec:
        with self._lock:
            spec = self._specs.get((category, kind))
        if spec is None:
            raise NotFound(f"No {category} adapter named {kind!r}.")
        return spec

    def list(self, category: str | None = None) -> list[AdapterSpec]:
        with self._lock:
            return sorted((s for s in self._specs.values() if category in (None, s.category)),
                          key=lambda s: (s.category, s.kind))

    def validate_config(self, category: str, kind: str, config: Mapping[str, Any]) -> dict[str, Any]:
        """Return a cleaned config (types cast, defaults applied, secrets only as ``*_ref``); lists every problem."""
        spec = self.get(category, kind)
        out: dict[str, Any] = {}
        problems: list[str] = []
        known = {f.name for f in spec.fields} | {f"{f.name}_ref" for f in spec.fields if f.secret}
        for key in config:
            if key not in known:
                problems.append(f"unknown field {key!r}")
        for f in spec.fields:
            if f.secret:
                ref = config.get(f"{f.name}_ref")
                if f.name in config:
                    problems.append(f"{f.name}: store secrets with the secret store and pass {f.name}_ref")
                if ref:
                    out[f"{f.name}_ref"] = str(ref)
                elif f.required:
                    problems.append(f"{f.name}_ref is required")
                continue
            val = config.get(f.name, f.default)
            if val is None or val == "":
                if f.required:
                    problems.append(f"{f.name} is required")
                elif f.default is not None:
                    out[f.name] = f.default
                continue
            try:
                out[f.name] = _CASTS[f.kind](val)
            except (TypeError, ValueError):
                problems.append(f"{f.name} must be {f.kind}")
        if problems:
            raise ValidationError(f"Invalid {spec.title} configuration: " + "; ".join(problems), problems)
        return out

    def load_entry_points(self, allow: list[str] | None) -> list[str]:
        """Load allowed plugins (by entry-point name). Returns the names loaded."""
        loaded: list[str] = []
        if not allow:
            return loaded
        try:
            from importlib.metadata import entry_points
            eps: Any = entry_points()
            group = eps.select(group=ENTRY_POINT_GROUP) if hasattr(eps, "select") else eps.get(ENTRY_POINT_GROUP, [])
        except Exception:                                 # pragma: no cover
            return loaded
        for ep in group:
            if ep.name not in allow:
                log.info("plugin %s is installed but not allowed in homelab.json; skipped", ep.name)
                continue
            try:
                hook = ep.load()
                hook(self)
                loaded.append(ep.name)
            except Exception:
                log.exception("plugin %s failed to load", ep.name)
        return loaded


def build_adapter(registry: Registry, category: str, kind: str, config: Mapping[str, Any],
                  resolve_secret: Callable[[str], str], **extra: Any) -> Any:
    """Instantiate an adapter: validated config + resolved secrets are passed as keyword arguments."""
    spec = registry.get(category, kind)
    cfg = registry.validate_config(category, kind, config)
    kwargs: dict[str, Any] = {}
    for f in spec.fields:
        if f.secret:
            ref = cfg.get(f"{f.name}_ref")
            kwargs[f.name] = resolve_secret(ref) if ref else ""
        elif f.name in cfg:
            kwargs[f.name] = cfg[f.name]
    kwargs.update(extra)
    return spec.factory(**kwargs)
