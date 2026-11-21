"""Background task execution.

:class:`TaskRunner` runs work on a bounded thread pool and keeps a short, inspectable history
(status, timings, result or error) so the UI and API can show progress without ever blocking.
:class:`PeriodicScheduler` fires recurring jobs (monitoring sweeps, discovery refreshes) onto the
runner; a job never overlaps with itself, and a slow job delays only its own next run.
"""
from __future__ import annotations

import itertools
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class TaskInfo:
    id: str
    name: str
    owner: str = ""
    status: str = "queued"              # queued | running | done | failed
    created: float = field(default_factory=time.time)
    started: float | None = None
    finished: float | None = None
    result: Any = None
    error: str = ""

    def public(self) -> dict[str, Any]:
        res = self.result
        if not isinstance(res, (str, int, float, bool, type(None), dict, list)):
            res = str(res)
        return {"id": self.id, "name": self.name, "owner": self.owner, "status": self.status,
                "created": self.created, "started": self.started, "finished": self.finished,
                "result": res, "error": self.error}


class TaskRunner:
    def __init__(self, max_workers: int = 8, history: int = 200,
                 on_change: Callable[[TaskInfo], None] | None = None) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max(1, max_workers), thread_name_prefix="nc-task")
        self._lock = threading.RLock()
        self._tasks: OrderedDict[str, TaskInfo] = OrderedDict()
        self._futures: dict[str, Future] = {}
        self._history = history
        self._ids = itertools.count(1)
        self._on_change = on_change
        self._closed = False

    def submit(self, name: str, fn: Callable[..., Any], *args: Any, owner: str = "", **kwargs: Any) -> TaskInfo:
        with self._lock:
            if self._closed:
                raise RuntimeError("task runner is shut down")
            info = TaskInfo(id=f"T{next(self._ids)}", name=name, owner=owner)
            self._tasks[info.id] = info
            while len(self._tasks) > self._history:
                old_id, old = next(iter(self._tasks.items()))
                if old.status in ("queued", "running"):
                    break
                self._tasks.pop(old_id)
                self._futures.pop(old_id, None)

        def run() -> Any:
            self._update(info, status="running", started=time.time())
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                log.warning("task %s (%s) failed: %s", info.id, name, exc)
                self._update(info, status="failed", finished=time.time(), error=f"{type(exc).__name__}: {exc}"[:1000])
                raise
            self._update(info, status="done", finished=time.time(), result=result)
            return result

        fut = self._pool.submit(run)
        with self._lock:
            self._futures[info.id] = fut
        return info

    def _update(self, info: TaskInfo, **changes: Any) -> None:
        with self._lock:
            for k, v in changes.items():
                setattr(info, k, v)
        if self._on_change:
            try:
                self._on_change(info)
            except Exception:
                log.exception("task change callback failed")

    def get(self, tid: str) -> TaskInfo | None:
        with self._lock:
            return self._tasks.get(tid)

    def wait(self, tid: str, timeout: float | None = None) -> TaskInfo:
        with self._lock:
            fut = self._futures.get(tid)
            info = self._tasks[tid]
        if fut is not None:
            try:
                fut.result(timeout)
            except Exception:
                pass
        return info

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [t.public() for t in list(self._tasks.values())[-limit:]][::-1]

    def shutdown(self, wait: bool = False) -> None:
        with self._lock:
            self._closed = True
        self._pool.shutdown(wait=wait)


@dataclass
class _Job:
    name: str
    interval: float
    fn: Callable[[], Any]
    next_run: float = 0.0
    running: bool = False
    enabled: bool = True


class PeriodicScheduler:
    def __init__(self, runner: TaskRunner, clock: Callable[[], float] = time.monotonic, tick: float = 1.0) -> None:
        self._runner, self._clock, self._tick = runner, clock, tick
        self._jobs: dict[str, _Job] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def every(self, name: str, seconds: float, fn: Callable[[], Any], start_now: bool = True) -> None:
        if seconds < 1:
            raise ValueError("interval must be at least 1 second")
        with self._lock:
            self._jobs[name] = _Job(name, float(seconds), fn, 0.0 if start_now else self._clock() + seconds)

    def cancel(self, name: str) -> None:
        with self._lock:
            self._jobs.pop(name, None)

    def jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{"name": j.name, "interval": j.interval, "running": j.running, "enabled": j.enabled}
                    for j in self._jobs.values()]

    def tick(self) -> list[str]:
        """Dispatch every due job once; returns the names dispatched (used by the loop and by tests)."""
        now, fired = self._clock(), []
        with self._lock:
            due = [j for j in self._jobs.values() if j.enabled and not j.running and j.next_run <= now]
            for j in due:
                j.running = True
        for j in due:
            def run(job: _Job = j) -> Any:
                try:
                    return job.fn()
                finally:
                    with self._lock:
                        job.running = False
                        job.next_run = self._clock() + job.interval
            try:
                self._runner.submit(f"periodic:{j.name}", run, owner="scheduler")
                fired.append(j.name)
            except RuntimeError:
                with self._lock:
                    j.running = False
        return fired

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.tick()
                except Exception:                       # pragma: no cover - defensive
                    log.exception("periodic scheduler tick failed")
                self._stop.wait(self._tick)
        self._thread = threading.Thread(target=loop, name="nc-periodic", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
