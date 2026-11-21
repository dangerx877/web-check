"""In-process event bus.

Modules publish facts (``asset.discovered``, ``alert.raised``, ``vm.power``...) without knowing who
listens; the platform attaches subscribers (persist to the timeline, notify, push to the UI).
Dispatch is synchronous and every subscriber is isolated: one failing handler never prevents the
others from running or breaks the publisher. Handlers must therefore be quick - heavy work belongs
in :class:`netcommander.homelab.core.tasks.TaskRunner`.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

SEVERITIES = ("debug", "info", "warning", "critical")


@dataclass
class Event:
    kind: str
    source: str
    target: str = ""
    message: str = ""
    severity: str = "info"
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "info"


Handler = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subs: dict[str, list[Handler]] = {}

    def subscribe(self, kind: str, handler: Handler) -> Callable[[], None]:
        """``kind`` is an exact kind, a prefix ending in ``.*`` (``alert.*``) or ``*``. Returns an unsubscribe."""
        with self._lock:
            self._subs.setdefault(kind, []).append(handler)

        def unsubscribe() -> None:
            with self._lock:
                handlers = self._subs.get(kind, [])
                if handler in handlers:
                    handlers.remove(handler)
        return unsubscribe

    def _handlers_for(self, kind: str) -> list[Handler]:
        with self._lock:
            out = list(self._subs.get(kind, [])) + list(self._subs.get("*", []))
            for key, handlers in self._subs.items():
                if key.endswith(".*") and kind.startswith(key[:-1]):
                    out.extend(handlers)
            return out

    def publish(self, event: Event) -> None:
        for handler in self._handlers_for(event.kind):
            try:
                handler(event)
            except Exception:
                log.exception("event handler failed for %s", event.kind)

    def emit(self, kind: str, source: str, target: str = "", message: str = "", severity: str = "info",
             **data: Any) -> Event:
        ev = Event(kind=kind, source=source, target=target, message=message, severity=severity, data=data)
        self.publish(ev)
        return ev
