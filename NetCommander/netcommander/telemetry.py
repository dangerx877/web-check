"""Health probing: TCP latency + SSH banner, rolling statistics and the sweep engine.

No GUI imports: the UI consumes results through an ``emit(kind, payload)``
callback, which keeps this module fully unit-testable.
"""
from __future__ import annotations

import logging
import socket
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, Mapping, Protocol

__all__ = [
    "DEFAULT_LATENCY_WARN_MS", "DEFAULT_LOSS_WARN_PCT", "HealthMonitor", "classify_status",
    "compute_stats", "deep_probe", "filter_devices", "format_table", "parse_thresholds", "sort_devices", "SORT_MODES",
]

log = logging.getLogger(__name__)

DEFAULT_LATENCY_WARN_MS = 120.0
DEFAULT_LOSS_WARN_PCT = 10.0

Emit = Callable[[str, Any], None]
ProbeFn = Callable[[str, int, float], "tuple[bool, float | None, str]"]


def deep_probe(host: str, port: int = 22, timeout: float = 2.5) -> tuple[bool, float | None, str]:
    """TCP connect time (latency in ms) plus the SSH server banner, if one is sent."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            latency = (time.perf_counter() - start) * 1000.0
            banner = "TCP open"
            sock.settimeout(1.2)
            try:
                raw = sock.recv(128).decode("utf-8", errors="ignore").strip().splitlines()
                if raw:
                    banner = raw[0]
            except OSError:
                pass
            return True, latency, banner
    except Exception:
        return False, None, ""


def compute_stats(history: Iterable[tuple[bool, float | None]]) -> tuple[float, float]:
    """(loss %, jitter ms) over a rolling window of (ok, latency) probe results."""
    items = list(history)
    if not items:
        return 0.0, 0.0
    failures = sum(1 for ok, _ in items if not ok)
    loss_pct = failures / len(items) * 100.0
    rtts = [ms for ok, ms in items if ok and ms is not None]
    jitter = statistics.pstdev(rtts) if len(rtts) >= 2 else 0.0
    return loss_pct, jitter


def classify_status(
    ok: bool, latency_ms: float | None, loss_pct: float, lat_warn: float, loss_warn: float
) -> str:
    """'up' | 'degraded' | 'down'."""
    if not ok:
        return "down"
    if (latency_ms is not None and latency_ms > lat_warn) or loss_pct > loss_warn:
        return "degraded"
    return "up"


def parse_thresholds(lat_text: str, loss_text: str) -> tuple[float, float]:
    """Parse the two threshold entry boxes, falling back to defaults on bad input."""
    try:
        lat = float(lat_text)
    except (TypeError, ValueError):
        lat = DEFAULT_LATENCY_WARN_MS
    try:
        loss = float(loss_text)
    except (TypeError, ValueError):
        loss = DEFAULT_LOSS_WARN_PCT
    return lat, loss


def format_table(devices: Mapping[str, dict], order: Iterable[str] | None = None) -> str:
    """Fixed-width telemetry report for a store snapshot (optionally in a given ``order``)."""
    lines = [
        f"{'DEVICE':<14} {'IP ADDRESS':<16} {'STATE':<10} {'LATENCY':<10} {'JITTER':<10} {'LOSS %':<8} {'SSH BANNER / LAST SEEN'}",
        "-" * 105,
    ]
    for name in (order if order is not None else devices):
        info = devices[name]
        lat = f"{info['latency_ms']:.1f} ms" if info.get("latency_ms") is not None else "--"
        jit = f"{info['jitter_ms']:.1f} ms" if info.get("jitter_ms") is not None else "--"
        loss = f"{info.get('loss_pct', 0.0):.1f}%"
        seen = info.get("last_seen") or "never"
        banner = (info.get("banner") or "")[:32]
        host = info.get("params", {}).get("host", "?")
        lines.append(
            f"{name:<14} {host:<16} {info.get('status', 'unknown').upper():<10} "
            f"{lat:<10} {jit:<10} {loss:<8} {banner} ({seen})"
        )
    return "\n".join(lines)


class _TargetSource(Protocol):
    def probe_targets(self) -> dict[str, tuple[str, int]]: ...


class HealthMonitor:
    """Runs reachability sweeps on demand or on a timer.

    A sweep that is still running makes further sweep requests no-ops, because
    overlapping sweeps distort loss/jitter. ``emit('telemetry', (name, ok, ms,
    banner))`` is called from worker threads; the receiver must be thread-safe
    (a ``queue.Queue.put`` is).
    """

    def __init__(
        self,
        source: _TargetSource,
        emit: Emit,
        probe: ProbeFn = deep_probe,
        interval: float = 8.0,
        max_workers: int = 16,
        timeout: float = 2.5,
    ):
        self._source = source
        self._emit = emit
        self._probe = probe
        self.interval = interval
        self.max_workers = max_workers
        self.timeout = timeout
        self._sweep_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        with self._state_lock:
            return self._stop is not None and not self._stop.is_set()

    def sweep(self) -> bool:
        """Probe every device once. Returns False when skipped (sweep already running / empty)."""
        if not self._sweep_lock.acquire(blocking=False):
            return False
        try:
            targets = self._source.probe_targets()
            if not targets:
                return False
            with ThreadPoolExecutor(max_workers=max(1, min(self.max_workers, len(targets)))) as pool:
                futures = {
                    pool.submit(self._safe_probe, host, port): name
                    for name, (host, port) in targets.items()
                }
                for fut in as_completed(futures):
                    ok, ms, banner = fut.result()
                    self._emit("telemetry", (futures[fut], ok, ms, banner))
            return True
        finally:
            self._sweep_lock.release()

    def _safe_probe(self, host: str, port: int) -> tuple[bool, float | None, str]:
        try:
            return self._probe(host, port, self.timeout)
        except Exception as exc:                   # a broken probe must not kill the sweep
            log.debug("probe of %s:%s raised %r", host, port, exc)
            return False, None, ""

    def poll_async(self) -> threading.Thread:
        thread = threading.Thread(target=self.sweep, name="nc-poll", daemon=True)
        thread.start()
        return thread

    def start(self) -> None:
        with self._state_lock:
            if self.running:
                return
            stop = threading.Event()
            self._stop = stop
            self._thread = threading.Thread(
                target=self._loop, args=(stop,), name="nc-monitor", daemon=True
            )
            self._thread.start()

    def stop(self, join_timeout: float | None = None) -> None:
        with self._state_lock:
            stop, thread = self._stop, self._thread
            if stop is not None:
                stop.set()
        if thread is not None and join_timeout:
            thread.join(join_timeout)

    def _loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.sweep()
            stop.wait(self.interval)


SORT_MODES = ("Name", "Status (worst first)", "Latency (slowest first)", "Packet loss (worst first)")
_STATUS_RANK = {"down": 0, "degraded": 1, "unknown": 2, "up": 3}


def sort_devices(devices: Mapping[str, dict], mode: str = "Name") -> list[str]:
    """Device names ordered for display. Unknown modes fall back to name order."""
    names = sorted(devices, key=str.lower)
    if mode == SORT_MODES[1]:
        return sorted(names, key=lambda n: _STATUS_RANK.get(devices[n].get("status", "unknown"), 2))
    if mode == SORT_MODES[2]:
        return sorted(names, key=lambda n: -(devices[n].get("latency_ms") or -1.0))
    if mode == SORT_MODES[3]:
        return sorted(names, key=lambda n: -float(devices[n].get("loss_pct") or 0.0))
    return names


def filter_devices(devices: Mapping[str, dict], text: str) -> list[str]:
    """Case-insensitive substring match on name, host, device type and status."""
    q = (text or "").strip().lower()
    names = sorted(devices, key=str.lower)
    if not q:
        return names
    out = []
    for n in names:
        info = devices[n]
        p = info.get("params", {})
        hay = " ".join(str(x) for x in (n, p.get("host", ""), p.get("device_type", ""), info.get("status", ""))).lower()
        if q in hay:
            out.append(n)
    return out
