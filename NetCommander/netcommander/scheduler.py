"""Scheduled jobs (e.g. nightly backups).

Schedules are plain data persisted to JSON; a single daemon thread wakes every ``tick`` seconds and
runs whatever is due. All time handling goes through an injectable clock so behaviour is testable.

Types
  * ``interval`` – every ``every_minutes``
  * ``daily``    – once a day at ``at`` (``HH:MM``, local time)

A missed run (app was closed) is *not* replayed in bulk: at most one catch-up run happens on the
next tick. Jobs never overlap with themselves. The scheduler only runs while the app (or
``netcommander schedule-run``) is running; for unattended 24/7 use, run the CLI under systemd /
launchd / Task Scheduler (see docs/SCHEDULING.md).
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

from .filelock import FileLock
from .security import _write_private

log = logging.getLogger(__name__)
_HHMM = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
KINDS = ("backup", "compliance")


class ScheduleError(ValueError):
    pass


def validate(s: dict) -> dict:
    out = {
        "id": str(s.get("id") or ""), "name": str(s.get("name") or "").strip(),
        "kind": s.get("kind", "backup"), "type": s.get("type", "interval"),
        "every_minutes": int(s.get("every_minutes", 0) or 0), "at": str(s.get("at") or ""),
        "targets": list(s.get("targets") or []),            # [] = all devices
        "enabled": bool(s.get("enabled", True)), "last_run": float(s.get("last_run", 0) or 0),
        "last_result": str(s.get("last_result", "")),
    }
    if not out["name"]:
        raise ScheduleError("A schedule needs a name.")
    if out["kind"] not in KINDS:
        raise ScheduleError(f"kind must be one of {KINDS}")
    if out["type"] == "interval":
        if not 1 <= out["every_minutes"] <= 60 * 24 * 30:
            raise ScheduleError("every_minutes must be between 1 and 43200.")
    elif out["type"] == "daily":
        if not _HHMM.match(out["at"]):
            raise ScheduleError("'at' must be HH:MM (24-hour).")
    else:
        raise ScheduleError("type must be 'interval' or 'daily'.")
    return out


def next_due(s: dict, now: float) -> float:
    """Epoch seconds at which the schedule is next due (<= now means due now)."""
    last = float(s.get("last_run", 0))
    if s["type"] == "interval":
        return last + s["every_minutes"] * 60 if last else 0.0
    h, m = map(int, s["at"].split(":"))
    today = datetime.fromtimestamp(now).replace(hour=h, minute=m, second=0, microsecond=0)
    scheduled = today if today.timestamp() <= now else today - timedelta(days=1)   # latest slot not in the future
    return scheduled.timestamp() if last < scheduled.timestamp() else (scheduled + timedelta(days=1)).timestamp()


class Scheduler:
    def __init__(
        self, path: Path, runner: Callable[[dict], str],
        clock: Callable[[], float] = time.time, tick: float = 20.0,
    ) -> None:
        self.path, self._runner, self._clock, self._tick = Path(path), runner, clock, tick
        self._lock = threading.RLock()
        self._flock = FileLock(self.path)
        self._running: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._items: dict[str, dict] = {}
        self._load()

    # ---- persistence (shared with other processes) ------------------------
    # The GUI and ``netcommander schedule-run`` may use the same file at the same time. Every change
    # is a read-modify-write under the cross-process file lock that starts from the file's current
    # contents, and the file always wins over memory - so a schedule deleted or paused in one
    # process is never resurrected or re-run by another.
    def _read(self) -> dict[str, dict] | None:
        """Schedules on disk ({} if there is no file); None if the file cannot be read at all."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("could not read schedules: %s", exc)
            return None
        items: dict[str, dict] = {}
        for raw in data.get("schedules", []) if isinstance(data, dict) else []:
            try:
                sched = validate(raw)
                items[sched["id"]] = sched
            except (ScheduleError, ValueError, TypeError) as exc:
                log.warning("ignoring invalid schedule: %s", exc)
        return items

    def _stat(self) -> int | None:
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return None

    def _load(self) -> None:
        items = self._read()
        self._mtime = self._stat()
        self._items = items or {}

    def _sync(self, force: bool = False) -> None:
        """Adopt the file's contents if another process changed it (always, when ``force``)."""
        m = self._stat()
        if not force and m == self._mtime:
            return
        items = self._read()
        if items is not None:
            self._items, self._mtime = items, m

    def _save(self, items: dict[str, dict]) -> None:
        _write_private(self.path, json.dumps({"schedules": list(items.values())}, indent=2))

    def _publish(self, items: dict[str, dict]) -> None:
        self._save(items)
        self._items = items
        self._mtime = self._stat()

    def list(self) -> List[dict]:
        with self._lock:
            self._sync()
            return [dict(s) for s in sorted(self._items.values(), key=lambda s: s["name"].lower())]

    def add(self, spec: dict) -> dict:
        with self._lock, self._flock:
            self._sync(force=True)
            sid = spec.get("id") or f"S{int(self._clock() * 1000)}-{secrets.token_hex(2)}"
            s = validate({**spec, "id": sid, "last_run": self._clock()})
            self._publish({**self._items, s["id"]: s})
            return dict(s)

    def remove(self, sid: str) -> None:
        with self._lock, self._flock:
            self._sync(force=True)
            items = dict(self._items)
            items.pop(sid, None)
            self._publish(items)

    def set_enabled(self, sid: str, enabled: bool) -> None:
        with self._lock, self._flock:
            self._sync(force=True)
            if sid not in self._items:
                raise ScheduleError("No such schedule.")
            self._publish({**self._items, sid: {**self._items[sid], "enabled": enabled}})

    def due(self) -> List[dict]:
        now = self._clock()
        with self._lock:
            self._sync()
            return [dict(s) for s in self._items.values()
                    if s["enabled"] and s["id"] not in self._running and next_due(s, now) <= now]

    def run_due(self) -> List[Tuple[str, str]]:
        """Run every due schedule once (synchronously). Returns ``[(name, result)]``."""
        results = []
        for s in self.due():
            with self._lock:
                if s["id"] in self._running:
                    continue
                self._running.add(s["id"])
            if not self._claim(s["id"]):                  # another process (GUI / schedule-run) got it first
                with self._lock:
                    self._running.discard(s["id"])
                continue
            try:
                try:
                    result = self._runner(s)
                except Exception as exc:                    # a failing job must not kill the scheduler
                    log.exception("scheduled job %s failed", s["name"])
                    result = f"ERROR: {type(exc).__name__}: {exc}"
                self._finish(s["id"], result)
                results.append((s["name"], result))
            finally:
                with self._lock:
                    self._running.discard(s["id"])
        return results

    def _finish(self, sid: str, result: str) -> None:
        """Record the result - only if the schedule still exists (it may have been deleted meanwhile)."""
        try:
            with self._lock, self._flock:
                self._sync(force=True)
                if sid not in self._items:
                    return
                done = {**self._items[sid], "last_run": self._clock(), "last_result": result[:500]}
                try:
                    self._publish({**self._items, sid: done})
                except OSError as exc:
                    log.warning("could not persist schedule state: %s", exc)
                    self._items[sid] = done               # keep in memory so it does not re-fire every tick
        except TimeoutError as exc:
            log.warning("could not lock schedules to record a result: %s", exc)

    def _claim(self, sid: str) -> bool:
        """Cross-process: re-read the file under a lock; if still due, stamp last_run so nobody else runs it."""
        try:
            with self._lock, self._flock:
                self._sync(force=True)
                cur = self._items.get(sid)
                now = self._clock()
                if cur is None or not cur["enabled"] or next_due(cur, now) > now:
                    return False
                try:
                    self._publish({**self._items, sid: {**cur, "last_run": now, "last_result": "running…"}})
                except OSError as exc:
                    log.warning("could not persist schedule claim: %s", exc)
                    self._items[sid] = {**cur, "last_run": now}
                return True
        except TimeoutError as exc:
            log.warning("could not lock schedules to claim %s: %s", sid, exc)
            return False

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="scheduler", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_due()
            except Exception:                               # pragma: no cover - defensive
                log.exception("scheduler tick failed")
            self._stop.wait(self._tick)
