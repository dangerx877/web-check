"""Device model and the thread-safe :class:`DeviceStore`.

All access to the device table goes through ``DeviceStore``; its ``RLock``
makes background probes, ``ThreadPoolExecutor`` workers and main-thread UI
actions (add/remove/load/save) safe to interleave. Readers get *copies*
(``snapshot()``/``get_params()``), never live references.
"""
from __future__ import annotations

import copy
import threading
from collections import deque
from datetime import datetime
from typing import Any, Iterable, Mapping, NamedTuple

from .config import PARAM_KEYS
from .parsers import apply_discovered_links
from .telemetry import classify_status, compute_stats

__all__ = ["DeviceStore", "ProbeResult", "make_device", "reciprocate_peers", "sanitize_params"]

HISTORY_LEN = 20


def sanitize_params(params: Mapping[str, Any], default_username: str = "admin") -> dict:
    """Keep only known connection keys and never persist passwords (they live in the vault)."""
    clean = {
        k: v for k, v in dict(params).items()
        if k in PARAM_KEYS and k not in ("password", "secret")
    }
    clean.setdefault("device_type", "cisco_ios")
    clean.setdefault("username", default_username)
    clean.setdefault("timeout", 10)
    return clean


def make_device(
    params: Mapping[str, Any],
    peers: Iterable[str] | None = None,
    links: Mapping[str, dict] | None = None,
) -> dict:
    return {
        "params": sanitize_params(params),
        "peers": sorted(set(peers or [])),
        "links": dict(links or {}),
        "status": "unknown",        # up | degraded | down | unknown
        "latency_ms": None,
        "jitter_ms": None,
        "loss_pct": 0.0,
        "banner": "",
        "last_seen": None,
        "history": deque(maxlen=HISTORY_LEN),  # rolling probe results (ok, ms)
    }


def reciprocate_peers(devices: dict) -> None:
    """Make every peer relationship symmetric."""
    for name, info in devices.items():
        for peer in list(info["peers"]):
            if peer in devices and name not in devices[peer]["peers"]:
                devices[peer]["peers"].append(name)
                devices[peer]["peers"].sort()


class ProbeResult(NamedTuple):
    previous: str
    status: str
    loss_pct: float
    latency_ms: float | None


class DeviceStore:
    """Thread-safe container for the inventory."""

    def __init__(self, devices: Mapping[str, dict] | None = None):
        self._lock = threading.RLock()
        self._devices: dict[str, dict] = dict(devices or {})

    @property
    def lock(self) -> threading.RLock:
        """Take this to make a multi-step read-modify-write atomic."""
        return self._lock

    # ---- reads -------------------------------------------------------
    def __len__(self) -> int:
        with self._lock:
            return len(self._devices)

    def __contains__(self, name: object) -> bool:
        with self._lock:
            return name in self._devices

    def names(self) -> list[str]:
        with self._lock:
            return list(self._devices)

    def first(self) -> str | None:
        with self._lock:
            return next(iter(self._devices), None)

    def snapshot(self) -> dict[str, dict]:
        """A consistent deep copy, safe to read from any thread without the lock."""
        with self._lock:
            return copy.deepcopy(self._devices)

    def get_params(self, name: str) -> dict | None:
        with self._lock:
            dev = self._devices.get(name)
            return dict(dev["params"]) if dev else None

    def device_type(self, name: str) -> str | None:
        with self._lock:
            dev = self._devices.get(name)
            return dev["params"].get("device_type") if dev else None

    def status(self, name: str) -> str | None:
        with self._lock:
            dev = self._devices.get(name)
            return dev["status"] if dev else None

    def probe_targets(self) -> dict[str, tuple[str, int]]:
        with self._lock:
            return {
                n: (d["params"].get("host", ""), int(d["params"].get("port") or 22))
                for n, d in self._devices.items()
            }

    # ---- structural writes -------------------------------------------
    def add(self, name: str, params: Mapping[str, Any], peers: Iterable[str] | None = None) -> None:
        """Add or replace a device and keep peer links symmetric."""
        with self._lock:
            self._devices[name] = make_device(params, peers)
            reciprocate_peers(self._devices)

    def remove(self, name: str) -> bool:
        with self._lock:
            if name not in self._devices:
                return False
            del self._devices[name]
            for info in self._devices.values():
                info["peers"] = [p for p in info["peers"] if p != name]
                info["links"].pop(name, None)
            return True

    def replace_all(self, devices: Mapping[str, dict]) -> None:
        with self._lock:
            self._devices = dict(devices)

    def merge(self, devices: Mapping[str, dict]) -> None:
        with self._lock:
            self._devices.update(devices)
            reciprocate_peers(self._devices)

    def set_username(self, name: str, username: str) -> None:
        with self._lock:
            if name in self._devices:
                self._devices[name]["params"]["username"] = username

    def apply_discovery(self, name: str, neighbors: list[dict]) -> list[str] | None:
        """Apply LLDP/CDP results and mark the device up. None if the device vanished."""
        with self._lock:
            if name not in self._devices:
                return None
            lines = apply_discovered_links(self._devices, name, neighbors)
            self._devices[name]["status"] = "up"
            self._devices[name]["last_seen"] = datetime.now().strftime("%H:%M:%S")
            return lines

    # ---- telemetry writes --------------------------------------------
    def mark_up(self, name: str) -> bool:
        with self._lock:
            dev = self._devices.get(name)
            if not dev:
                return False
            dev["status"] = "up"
            dev["last_seen"] = datetime.now().strftime("%H:%M:%S")
            return True

    def record_probe(
        self,
        name: str,
        ok: bool,
        latency_ms: float | None,
        banner: str,
        lat_warn: float,
        loss_warn: float,
    ) -> ProbeResult | None:
        """Fold one probe result into the device. None if the device was removed meanwhile."""
        with self._lock:
            dev = self._devices.get(name)
            if dev is None:
                return None
            previous = dev["status"]
            dev["history"].append((ok, latency_ms))
            loss_pct, jitter = compute_stats(dev["history"])
            dev["latency_ms"] = latency_ms
            dev["jitter_ms"] = jitter
            dev["loss_pct"] = loss_pct
            if banner:
                dev["banner"] = banner
            if ok:
                dev["last_seen"] = datetime.now().strftime("%H:%M:%S")
            dev["status"] = classify_status(ok, latency_ms, loss_pct, lat_warn, loss_warn)
            return ProbeResult(previous, dev["status"], loss_pct, latency_ms)
