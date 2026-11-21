"""Small, validated per-user UI preferences (theme, retention, filters...). Never holds secrets."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from .security import _write_private

log = logging.getLogger(__name__)

DEFAULTS: dict[str, Any] = {
    "appearance": "dark",            # dark | light | system
    "strict_hostkeys": False,
    "retention_keep": 0,             # 0 = keep everything
    "redact_diffs": True,
    "connect_attempts": 2,
    "geometry": "",
    "telemetry_interval": 30,
}
_VALIDATORS = {
    "appearance": lambda v: v in ("dark", "light", "system"),
    "strict_hostkeys": lambda v: isinstance(v, bool),
    "retention_keep": lambda v: isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 1000,
    "redact_diffs": lambda v: isinstance(v, bool),
    "connect_attempts": lambda v: isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 5,
    "geometry": lambda v: isinstance(v, str) and len(v) < 40,
    "telemetry_interval": lambda v: isinstance(v, int) and not isinstance(v, bool) and 5 <= v <= 3600,
}


class Prefs:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._data = dict(DEFAULTS)
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            log.warning("ignoring unreadable preferences: %s", exc)
            return
        if isinstance(raw, dict):
            for k, v in raw.items():
                if k in _VALIDATORS and _VALIDATORS[k](v):
                    self._data[k] = v                      # unknown keys / bad values are dropped silently

    def get(self, key: str) -> Any:
        with self._lock:
            return self._data[key]

    def set(self, **values: Any) -> None:
        """Validate, persist, then publish. Raises ValueError for bad input, OSError if unwritable."""
        for k, v in values.items():
            if k not in _VALIDATORS or not _VALIDATORS[k](v):
                raise ValueError(f"Invalid preference {k}={v!r}")
        with self._lock:
            candidate = {**self._data, **values}
            _write_private(self.path, json.dumps(candidate, indent=2, sort_keys=True))
            self._data = candidate

    def all(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)
