"""Tamper-evident audit log.

Append-only JSON Lines; every entry carries ``prev`` (hash of the previous line) and ``hash``
(SHA-256 over the entry), so any edit, deletion or reordering is detected by :meth:`AuditLog.verify`.
A small *anchor* file next to the log (``audit.jsonl.head``) records the entry count and the
latest hash after every append, so cutting entries off the end of the log - which a hash chain
alone cannot reveal - is reported by :meth:`AuditLog.verify` too.

This is *tamper-evident*, not tamper-proof: someone with write access could rewrite the whole
chain and its anchor together, so ship entries to remote storage / syslog (see
:func:`sinks_from_env`) if you need stronger guarantees.

Never log secrets: :func:`netcommander.redact.redact_secrets` is applied to every detail string.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .filelock import FileLock, LockTimeout
from .redact import redact_secrets
from .security import _write_private

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time,
                 sinks: list[Callable[[dict], None]] | None = None) -> None:
        self.path = Path(path)
        self._flock = FileLock(self.path)
        self.sinks: list[Callable[[dict], None]] = list(sinks or [])
        self._clock = clock
        self._lock = threading.RLock()
        self.anchor_path = self.path.with_name(self.path.name + ".head")
        self._size = -1
        self._last, self._count = self._load_state()
        self._size = self._file_size()

    def _file_size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def _load_state(self) -> tuple[str, int]:
        """(hash of the last entry, number of entries) as found on disk."""
        last, count = "", 0
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last, count = line, count + 1
        except FileNotFoundError:
            return GENESIS, 0
        except OSError:
            return GENESIS, count
        try:
            return (json.loads(last)["hash"] if last else GENESIS), count
        except (ValueError, KeyError, TypeError):
            return GENESIS, count   # damaged tail: verify() will report it; new entries start a fresh link

    def _read_anchor(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self.anchor_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("count"), int) and isinstance(data.get("hash"), str):
                return data
        except (OSError, ValueError):
            pass
        return None

    def record(self, actor: str, action: str, target: str = "", outcome: str = "ok", detail: str = "") -> dict | None:
        """Append one event. Auditing must never break the operation being audited, so I/O errors
        are swallowed (and reported by the return value ``None``)."""
        try:
            with self._lock, self._flock:
                return self._record_locked(actor, action, target, outcome, detail)
        except (LockTimeout, OSError):
            return None

    def _record_locked(self, actor: str, action: str, target: str, outcome: str, detail: str) -> dict | None:
        if True:
            if self._file_size() != self._size:           # another AuditLog/process appended: continue its chain
                self._last, self._count = self._load_state()
            entry: dict[str, Any] = {
                "ts": round(self._clock(), 3), "actor": actor or "?", "action": action,
                "target": target, "outcome": outcome, "detail": redact_secrets(detail)[:2000],
                "prev": self._last,
            }
            entry["hash"] = _digest(entry)
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fresh = not self.path.exists()
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                if fresh:
                    try:
                        os.chmod(self.path, 0o600)
                    except OSError:
                        pass
            except OSError:
                return None
            self._last = entry["hash"]
            self._count += 1
            self._size = self._file_size()
            try:
                _write_private(self.anchor_path, json.dumps({"count": self._count, "hash": self._last}))
            except OSError:
                pass                                       # verify() tolerates a lagging anchor
            for sink in self.sinks:                       # off-box copies; a broken sink never blocks auditing
                try:
                    sink(entry)
                except Exception:
                    pass
            return entry

    def entries(self, limit: int | None = None) -> list[dict]:
        """Readable entries, oldest first. A damaged line is skipped (verify() reports it), not fatal."""
        rows: list[dict] = []
        with self._lock:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    for line in fh:
                        if not line.strip():
                            continue
                        try:
                            row = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(row, dict):
                            rows.append(row)
            except FileNotFoundError:
                return []
        return rows[-limit:] if limit else rows

    def verify(self) -> tuple[bool, str]:
        """Return ``(ok, message)``; message names the first broken line."""
        with self._lock:
            anchor = self._read_anchor()
            prev, count, hash_at_anchor = GENESIS, 0, None
            try:
                with open(self.path, encoding="utf-8") as fh:
                    for n, line in enumerate(fh, 1):
                        if not line.strip():
                            continue
                        try:
                            e = json.loads(line)
                        except ValueError:
                            return False, f"line {n}: not valid JSON"
                        if not isinstance(e, dict):
                            return False, f"line {n}: not an audit entry"
                        if e.get("prev") != prev:
                            return False, f"line {n}: chain broken (entry removed, reordered or inserted)"
                        if e.get("hash") != _digest(e):
                            return False, f"line {n}: entry was modified"
                        prev = e["hash"]
                        count += 1
                        if anchor is not None and count == anchor["count"]:
                            hash_at_anchor = prev
            except FileNotFoundError:
                if anchor is not None and anchor["count"] > 0:
                    return False, f"audit log is missing but its anchor records {anchor['count']} entries"
                return True, "no audit log yet"
            if anchor is not None:
                if count < anchor["count"]:
                    return False, (f"log has {count} entries but its anchor records {anchor['count']}: "
                                   "entries were removed from the end (or the file was replaced)")
                if hash_at_anchor != anchor["hash"]:
                    return False, f"entry {anchor['count']} does not match the anchor: the log was rewritten"
            return True, "chain intact"


# ---------------------------------------------------------------- off-box sinks
def file_sink(path: Path | str) -> Callable[[dict], None]:
    """Append each entry (JSON line) to another file - e.g. a network share or a write-once mount."""
    target = Path(path)

    def sink(entry: dict) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
    return sink


def syslog_sink(host: str, port: int = 514, tcp: bool = False, tag: str = "netcommander") -> Callable[[dict], None]:
    """Send each entry as a syslog message (RFC 3164 framing, facility local0, severity notice/warning).

    UDP is fire-and-forget (silent loss is possible); choose TCP where delivery matters. Connections
    are made per message so a restarted collector never wedges the app.
    """
    import socket

    def sink(entry: dict) -> None:
        sev = 4 if entry.get("outcome") not in ("ok",) else 5
        pri = 16 * 8 + sev                                     # local0
        body = json.dumps({k: entry[k] for k in ("ts", "actor", "action", "target", "outcome", "detail", "hash")},
                          sort_keys=True)
        msg = f"<{pri}>{tag}: {body}"
        if tcp:
            with socket.create_connection((host, port), timeout=3) as s:
                s.sendall(msg.encode("utf-8") + b"\n")
        else:
            with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(msg.encode("utf-8"), (host, port))
    return sink


def sinks_from_env(env: Mapping[str, str] | None = None) -> list[Callable[[dict], None]]:
    """``NETCOMMANDER_AUDIT_COPY=<file>``; ``NETCOMMANDER_AUDIT_SYSLOG=host[:port]`` (``tcp://host:port`` for TCP)."""
    env = os.environ if env is None else env
    out: list[Callable[[dict], None]] = []
    copy = (env.get("NETCOMMANDER_AUDIT_COPY") or "").strip()
    if copy:
        out.append(file_sink(copy))
    sl = (env.get("NETCOMMANDER_AUDIT_SYSLOG") or "").strip()
    if sl:
        tcp = sl.lower().startswith("tcp://")
        hostport = sl.split("://", 1)[-1]
        host, _, port = hostport.rpartition(":") if hostport.count(":") == 1 else (hostport, "", "")
        host = host or hostport
        out.append(syslog_sink(host, int(port) if port.isdigit() else 514, tcp))
    return out
