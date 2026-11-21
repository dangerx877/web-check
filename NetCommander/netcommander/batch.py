"""Parallel batch execution with an authentication-failure circuit breaker.

One :class:`BatchRunner` instance represents one batch, so concurrent batches
(e.g. discovery while a backup runs) never share a failure counter. The class
has no GUI dependency: results travel through ``emit(kind, payload)``.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, Mapping, Protocol, Tuple

from .config import AUTH_FAIL_ABORT
from .network import Credentials, classify_ssh_error

__all__ = ["BatchRunner", "Job", "build_jobs"]

log = logging.getLogger(__name__)

Emit = Callable[[str, Any], None]
Job = Tuple[dict, Credentials]
Worker = Callable[[str, dict, Credentials, "BatchRunner"], None]


class _ParamSource(Protocol):
    def get_params(self, name: str) -> dict | None: ...


class _CredentialSource(Protocol):
    def get_decrypted(self, device: str) -> Credentials: ...
    def has_password(self, device: str) -> bool: ...


def build_jobs(
    store: _ParamSource, vault: _CredentialSource, targets: Iterable[str]
) -> dict[str, Job]:
    """Snapshot (params, credentials) for each target at call time.

    Taking the snapshot up front means worker threads never touch the live
    store or vault, and later UI edits cannot change a batch that is running.
    """
    jobs: dict[str, Job] = {}
    for name in targets:
        params = store.get_params(name)
        if params is None:
            continue
        creds = vault.get_decrypted(name)
        if not vault.has_password(name):               # key login: use the device's own username
            creds = (params.get("username") or "admin", "", creds[2])
        jobs[name] = (params, creds)
    return jobs


class BatchRunner:
    """Runs one worker per device on a thread pool; stops early after repeated auth failures."""

    def __init__(
        self,
        emit: Emit,
        done_kind: str,
        workers: int = 8,
        abort_after: int = AUTH_FAIL_ABORT,
    ):
        self._emit = emit
        self.done_kind = done_kind
        self.workers = max(1, int(workers))
        self.abort_after = abort_after
        self._lock = threading.Lock()
        self._auth_failures = 0

    # ---- circuit breaker ---------------------------------------------
    @property
    def auth_failures(self) -> int:
        with self._lock:
            return self._auth_failures

    @property
    def tripped(self) -> bool:
        return self.auth_failures >= self.abort_after

    def fail(self, name: str, params: Mapping[str, Any], exc: BaseException) -> None:
        """Report a worker's SSH failure: counts auth failures and tells the UI what happened."""
        kind, msg = classify_ssh_error(exc)
        if kind == "auth":
            with self._lock:
                self._auth_failures += 1
            self._emit("auth_failed", name)
        elif kind == "timeout":
            self._emit("telemetry", (name, False, None, ""))
        elif kind == "hostkey":
            self._emit("hostkey_unknown", (name, str(params.get("host", "")), params.get("port")))
        self._emit("output", f"\n--- [{name} ({params.get('host', '')})] ERROR: {msg} ---\n")

    # ---- execution ---------------------------------------------------
    def run(self, jobs: Mapping[str, Job], worker: Worker) -> None:
        """Blocking; always emits ``done_kind`` at the end, even if the pool fails."""

        def guarded(name: str, params: dict, creds: Credentials) -> None:
            if self.tripped:
                self._emit(
                    "output",
                    f"[{name}] Skipped: batch stopped after {self.abort_after} authentication "
                    f"failures (prevents account lockouts).\n",
                )
                return
            worker(name, params, creds, self)

        try:
            if not jobs:
                return
            with ThreadPoolExecutor(max_workers=min(self.workers, len(jobs))) as pool:
                futures = {
                    pool.submit(guarded, name, params, creds): name
                    for name, (params, creds) in jobs.items()
                }
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as exc:
                        log.exception("batch worker for %s crashed", futures[fut])
                        self._emit("output", f"[{futures[fut]}] Unexpected error: {exc}\n")
        finally:
            self._emit(self.done_kind, None)

    def start(self, jobs: Mapping[str, Job], worker: Worker) -> threading.Thread:
        thread = threading.Thread(
            target=self.run, args=(jobs, worker), name=f"nc-batch-{self.done_kind}", daemon=True
        )
        thread.start()
        return thread
