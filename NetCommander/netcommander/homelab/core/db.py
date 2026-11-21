"""SQLite persistence for the homelab platform (stdlib ``sqlite3``; no server, no extra dependency).

Three tables cover every module:

* ``records``  - a small document store: ``(collection, id) -> JSON``. Inventory assets, integrations,
  scripts, backup jobs, IPAM data... (homelab scale: thousands of rows, filtered in Python).
* ``metrics``  - time series ``(target, metric, ts, value)`` with retention pruning and downsampling.
* ``events``   - the infrastructure event timeline.

Concurrency: one connection per thread (``check_same_thread`` stays on), WAL journal so readers do
not block the writer, ``busy_timeout`` for cross-process writers (GUI + ``netcommander serve``).
The file is created owner-only (0600). Secrets are never written here - see :mod:`.secrets`.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """CREATE TABLE IF NOT EXISTS records (
               collection TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
               created REAL NOT NULL, updated REAL NOT NULL, PRIMARY KEY (collection, id))""",
        """CREATE TABLE IF NOT EXISTS metrics (
               target TEXT NOT NULL, metric TEXT NOT NULL, ts REAL NOT NULL, value REAL NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS metrics_idx ON metrics (target, metric, ts)",
        "CREATE INDEX IF NOT EXISTS metrics_ts ON metrics (ts)",
        """CREATE TABLE IF NOT EXISTS events (
               id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, severity TEXT NOT NULL,
               source TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, message TEXT NOT NULL,
               data TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS events_ts ON events (ts)",
    ),
}


class Database:
    def __init__(self, path: Path | str, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._all_lock = threading.Lock()
        self._write_lock = threading.RLock()
        self._migrate()

    # ---- connections ---------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            memory = str(self.path) == ":memory:"
            if not memory:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fresh = not self.path.exists()
            conn = sqlite3.connect(str(self.path), timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 15000")
            if not memory:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                if fresh:
                    try:
                        os.chmod(self.path, 0o600)
                    except OSError:
                        pass
            self._local.conn = conn
            with self._all_lock:
                self._all.append(conn)
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """A write transaction (serialised within the process; SQLite serialises across processes)."""
        with self._write_lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._all_lock:
            for c in self._all:
                try:
                    c.close()
                except sqlite3.Error:
                    pass
            self._all.clear()
        self._local = threading.local()

    def _migrate(self) -> None:
        with self.tx() as c:
            current = int(c.execute("PRAGMA user_version").fetchone()[0])
            if current > SCHEMA_VERSION:
                raise RuntimeError(f"{self.path} was created by a newer Uptime Funk (schema {current}); "
                                   "upgrade the application instead of downgrading the data.")
            for version in range(current + 1, SCHEMA_VERSION + 1):
                for stmt in _MIGRATIONS[version]:
                    c.execute(stmt)
                c.execute(f"PRAGMA user_version = {int(version)}")
                log.info("homelab database migrated to schema %d", version)

    @property
    def schema_version(self) -> int:
        return int(self._conn().execute("PRAGMA user_version").fetchone()[0])

    # ---- records -------------------------------------------------------
    def put(self, collection: str, rid: str, data: dict[str, Any]) -> dict[str, Any]:
        now = self._clock()
        body = json.dumps(data, sort_keys=True, default=str)
        with self.tx() as c:
            c.execute(
                "INSERT INTO records (collection, id, data, created, updated) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(collection, id) DO UPDATE SET data = excluded.data, updated = excluded.updated",
                (collection, rid, body, now, now))
        return data

    def put_many(self, collection: str, items: Iterable[tuple[str, dict[str, Any]]]) -> int:
        now, n = self._clock(), 0
        with self.tx() as c:
            for rid, data in items:
                c.execute(
                    "INSERT INTO records (collection, id, data, created, updated) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(collection, id) DO UPDATE SET data = excluded.data, updated = excluded.updated",
                    (collection, rid, json.dumps(data, sort_keys=True, default=str), now, now))
                n += 1
        return n

    def get(self, collection: str, rid: str) -> dict[str, Any] | None:
        row = self._conn().execute("SELECT data FROM records WHERE collection = ? AND id = ?",
                                   (collection, rid)).fetchone()
        return json.loads(row["data"]) if row else None

    def all(self, collection: str) -> list[dict[str, Any]]:
        rows = self._conn().execute("SELECT data FROM records WHERE collection = ? ORDER BY id",
                                    (collection,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def ids(self, collection: str) -> list[str]:
        return [r[0] for r in self._conn().execute(
            "SELECT id FROM records WHERE collection = ? ORDER BY id", (collection,)).fetchall()]

    def delete(self, collection: str, rid: str) -> bool:
        with self.tx() as c:
            return c.execute("DELETE FROM records WHERE collection = ? AND id = ?", (collection, rid)).rowcount > 0

    def count(self, collection: str) -> int:
        return int(self._conn().execute("SELECT COUNT(*) FROM records WHERE collection = ?",
                                        (collection,)).fetchone()[0])

    # ---- metrics -------------------------------------------------------
    def add_metrics(self, target: str, values: dict[str, float], ts: float | None = None) -> None:
        ts = self._clock() if ts is None else ts
        rows = [(target, k, ts, float(v)) for k, v in values.items() if _finite(v)]
        if not rows:
            return
        with self.tx() as c:
            c.executemany("INSERT INTO metrics (target, metric, ts, value) VALUES (?, ?, ?, ?)", rows)

    def series(self, target: str, metric: str, since: float = 0.0, until: float | None = None,
               max_points: int = 500) -> list[tuple[float, float]]:
        """Points in ``[since, until]``; averaged into at most ``max_points`` buckets for graphs."""
        until = self._clock() if until is None else until
        rows = self._conn().execute(
            "SELECT ts, value FROM metrics WHERE target = ? AND metric = ? AND ts >= ? AND ts <= ? ORDER BY ts",
            (target, metric, since, until)).fetchall()
        pts = [(float(r[0]), float(r[1])) for r in rows]
        return downsample(pts, max_points)

    def latest_metrics(self, target: str) -> dict[str, tuple[float, float]]:
        rows = self._conn().execute(
            "SELECT metric, ts, value FROM metrics m WHERE target = ? AND ts = "
            "(SELECT MAX(ts) FROM metrics WHERE target = m.target AND metric = m.metric)", (target,)).fetchall()
        return {r[0]: (float(r[1]), float(r[2])) for r in rows}

    def metric_targets(self) -> list[str]:
        return [r[0] for r in self._conn().execute("SELECT DISTINCT target FROM metrics ORDER BY target")]

    def prune_metrics(self, older_than: float) -> int:
        with self.tx() as c:
            return c.execute("DELETE FROM metrics WHERE ts < ?", (older_than,)).rowcount

    # ---- events --------------------------------------------------------
    def add_event(self, severity: str, source: str, kind: str, target: str, message: str,
                  data: dict[str, Any] | None = None, ts: float | None = None) -> int:
        ts = self._clock() if ts is None else ts
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO events (ts, severity, source, kind, target, message, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, severity, source, kind, target, message[:2000], json.dumps(data or {}, default=str)))
            return int(cur.lastrowid or 0)

    def events(self, limit: int = 200, since: float = 0.0, target: str | None = None,
               severity: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM events WHERE ts >= ?"
        args: list[Any] = [since]
        if target:
            q += " AND target = ?"
            args.append(target)
        if severity:
            q += " AND severity = ?"
            args.append(severity)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        out = []
        for r in self._conn().execute(q, args).fetchall():
            d = dict(r)
            d["data"] = json.loads(d["data"] or "{}")
            out.append(d)
        return out

    def prune_events(self, older_than: float) -> int:
        with self.tx() as c:
            return c.execute("DELETE FROM events WHERE ts < ?", (older_than,)).rowcount


def _finite(v: Any) -> bool:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return False
    return f == f and f not in (float("inf"), float("-inf"))


def downsample(points: list[tuple[float, float]], max_points: int) -> list[tuple[float, float]]:
    """Average consecutive points into ``max_points`` equal-count buckets (keeps the time order)."""
    if max_points <= 0 or len(points) <= max_points:
        return points
    size = len(points) / max_points
    out = []
    for i in range(max_points):
        chunk = points[int(i * size):int((i + 1) * size)] or [points[min(int(i * size), len(points) - 1)]]
        out.append((sum(p[0] for p in chunk) / len(chunk), sum(p[1] for p in chunk) / len(chunk)))
    return out
