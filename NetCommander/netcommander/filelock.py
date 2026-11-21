"""Cross-process advisory file lock (POSIX ``fcntl`` / Windows ``msvcrt``), re-entrant per thread.

Used so the GUI and a headless ``schedule-run`` (or two CLIs) cannot interleave read-modify-write
cycles on the same state file. It is advisory: it protects cooperating NetCommander processes, not
against other programs editing the files.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

try:                                    # POSIX
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
except ImportError:                     # Windows
    import msvcrt

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]


class LockTimeout(TimeoutError):
    pass


class FileLock:
    """``with FileLock(path):`` - blocks (polling) up to ``timeout`` seconds, then raises LockTimeout."""

    def __init__(self, target: Path | str, timeout: float = 15.0, poll: float = 0.05) -> None:
        self.path = Path(str(target) + ".lock")
        self.timeout, self.poll = timeout, poll
        self._tlock = threading.RLock()          # serialises threads of this process, allows re-entry
        self._depth = 0
        self._fd: int | None = None

    def __enter__(self) -> FileLock:
        self._tlock.acquire()
        try:
            if self._depth == 0:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
                deadline = time.monotonic() + self.timeout
                while True:
                    try:
                        _lock(fd)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            os.close(fd)
                            raise LockTimeout(f"could not lock {self.path} within {self.timeout:g}s") from None
                        time.sleep(self.poll)
                self._fd = fd
            self._depth += 1
        except BaseException:
            self._tlock.release()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self._depth -= 1
            if self._depth == 0 and self._fd is not None:
                try:
                    _unlock(self._fd)
                finally:
                    os.close(self._fd)
                    self._fd = None
        finally:
            self._tlock.release()
