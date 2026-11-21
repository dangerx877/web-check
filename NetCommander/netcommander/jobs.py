"""Headless, UI-free operations shared by the GUI, the scheduler and the CLI."""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import network
from .audit import AuditLog
from .config import RuntimeSettings
from .redact import redact_secrets
from .security import CredentialVault

log = logging.getLogger(__name__)
Fetch = Callable[..., str]


@dataclass
class BackupOutcome:
    device: str
    ok: bool
    changed: bool = False          # config differs from the previous snapshot (drift)
    path: Path | None = None
    message: str = ""


def backup_devices(
    jobs: Mapping[str, tuple[dict, tuple[str, str, str]]],
    backup_root: Path,
    vault: CredentialVault | None,
    settings: RuntimeSettings | None = None,
    *,
    keep: int = 0,
    workers: int = 8,
    actor: str = "system",
    audit: AuditLog | None = None,
    fetch: Fetch = network.fetch_running_config,
    tag: str = "",
) -> list[BackupOutcome]:
    """Back up every job in parallel. ``keep`` > 0 prunes older snapshots per device."""

    def one(item: tuple[str, tuple[dict, tuple[str, str, str]]]) -> BackupOutcome:
        name, (params, creds) = item
        try:
            text = fetch(params, creds, settings=settings)
            if not str(text).strip():
                raise RuntimeError("device returned an empty configuration")
            previous = network.list_snapshots(name, backup_root)
            path = network.save_config_snapshot(name, text, backup_root, vault=vault, tag=tag)
            changed = True
            if previous:
                try:
                    changed = network.read_snapshot(previous[-1], vault).strip() != text.strip()
                except Exception:                 # unreadable previous snapshot: treat as changed
                    changed = True
            if keep > 0:
                network.prune_snapshots(name, keep, backup_root)
            out = BackupOutcome(name, True, changed, path, "changed" if changed else "unchanged")
        except Exception as exc:
            kind, msg = network.classify_ssh_error(exc)
            out = BackupOutcome(name, False, message=redact_secrets(msg))
        if audit:
            audit.record(actor, "backup", name, "ok" if out.ok else "failed", out.message)
        return out

    if not jobs:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs)))) as pool:
        return list(pool.map(one, sorted(jobs.items())))


def summarize_backups(outcomes: list[BackupOutcome]) -> str:
    ok = [o for o in outcomes if o.ok]
    bad = [o for o in outcomes if not o.ok]
    drift = [o.device for o in ok if o.changed]
    parts = [f"{len(ok)}/{len(outcomes)} backed up"]
    if drift:
        parts.append(f"changed: {', '.join(drift)}")
    if bad:
        parts.append("FAILED: " + "; ".join(f"{o.device} ({o.message})" for o in bad))
    return " | ".join(parts)


def live_config_getter(
    jobs_map: Mapping[str, tuple[dict, tuple[str, str, str]]],
    settings: RuntimeSettings | None = None,
    fetch: Fetch = network.fetch_running_config,
) -> Callable[[str], str]:
    """``get_config(name)`` that fetches the *running* config over SSH (for compliance against live state)."""
    def get(name: str) -> str:
        if name not in jobs_map:
            raise LookupError("no credentials / not in inventory")
        params, creds = jobs_map[name]
        try:
            text = str(fetch(params, creds, settings=settings))
        except Exception as exc:
            kind, msg = network.classify_ssh_error(exc)
            raise RuntimeError(redact_secrets(msg)) from None
        if not text.strip():
            raise RuntimeError("device returned an empty configuration")
        return text
    return get
