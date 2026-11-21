"""Application services shared by the GUI and tests: audit, RBAC, deployments, schedules, templates, prefs.

No GUI imports here, so everything is unit-testable. The GUI is a thin shell over these.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from . import jobs, network
from .audit import AuditLog, sinks_from_env
from .batch import build_jobs
from .cmdpolicy import non_read_only
from .config import GUEST_USER, Paths, RuntimeSettings
from .deploy import DeploymentStore, PushFn
from .prefs import Prefs
from .rbac import Permission, PermissionDenied, Role, can, require
from .rollback import Check, push_with_rollback, supports_rollback
from .scheduler import Scheduler
from .security import AuthManager, CredentialVault
from .store import DeviceStore
from .templates import TemplateLibrary

log = logging.getLogger(__name__)


def accounts_exist(paths: Paths, auth: AuthManager | None = None) -> bool:
    """True if this installation has any account (then guest mode is closed / read-only)."""
    if auth is not None:
        return auth.has_accounts()
    import json
    try:
        data = json.loads(paths.auth.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False
    except (OSError, ValueError):                       # unreadable or damaged: fail closed
        return True
    return bool(data) if isinstance(data, dict) else True


class Services:
    def __init__(
        self, paths: Paths, user: str, vault: CredentialVault, store: DeviceStore,
        settings: RuntimeSettings, auth: AuthManager | None = None,
    ) -> None:
        self.paths, self.vault, self.store, self.settings = paths, vault, store, settings
        self.auth = auth
        self.guest = bool(vault.ephemeral)
        self.user = GUEST_USER if self.guest else user
        # Guest = the original single-user workflow, and only on an installation with no accounts: once
        # accounts (and therefore roles) exist, a guest session is read-only so it can never bypass RBAC.
        # Accounts that predate RBAC keep admin (AuthManager.role_of).
        if self.guest:
            self.role = Role.VIEWER if accounts_exist(paths, auth) else Role.GUEST
        else:
            self.role = Role.OPERATOR if auth is None else Role.parse(auth.role_of(user), Role.VIEWER)
        self.audit_log = AuditLog(paths.audit, sinks=sinks_from_env())
        self.prefs = Prefs(paths.prefs)
        self.templates = TemplateLibrary(paths.templates)
        self.deployments = DeploymentStore(paths.deployments, self._role_of, audit=self.audit_log)
        self.scheduler = Scheduler(paths.schedules, self._run_schedule)
        self._notify: Callable[[str, Any], None] = lambda k, p: None

    # ---- RBAC / audit --------------------------------------------------
    def _role_of(self, actor: str) -> str:
        if actor == self.user:
            return self.role.value
        return self.auth.role_of(actor) if self.auth else "viewer"

    def can(self, perm: Permission) -> bool:
        return can(self.role, perm)

    def require(self, perm: Permission) -> None:
        try:
            require(self.role, perm)
        except PermissionDenied:
            self.audit_log.record(self.user, f"deny.{perm.value}", outcome="denied")
            raise

    def authorize_exec(self, targets: list[str], commands: list[str], config_mode: bool) -> Permission:
        """Check (and audit a denial of) the right to send `commands` to `targets`.

        Config mode always needs PUSH_CONFIG. In exec mode, only commands on the read-only
        allowlist (:mod:`netcommander.cmdpolicy`) for *every* target's platform are allowed with
        RUN_SHOW; anything else needs PUSH_CONFIG. Returns the permission that was required.
        """
        risky = [] if config_mode else non_read_only(commands, [self.store.device_type(t) for t in targets])
        perm = Permission.PUSH_CONFIG if (config_mode or risky) else Permission.RUN_SHOW
        try:
            require(self.role, perm)
        except PermissionDenied as exc:
            self.audit_log.record(self.user, f"deny.{perm.value}", ",".join(targets)[:200], "denied",
                                  "; ".join(risky[:3]))
            if risky:
                raise PermissionDenied(self.role, perm, f"not on the read-only list: {risky[0]}") from exc
            raise
        return perm

    # ---- users (MANAGE_USERS) ------------------------------------------
    def reset_user(self, email: str, temp_password: str) -> tuple[str, str, Path | None]:
        """Admin reset of another account. Returns (totp_secret, uri, path the old vault was moved to).

        The old vault can only be opened with the forgotten password, so it is moved aside (never
        deleted): the user can restore credentials and backups with ``netcommander vault-import``
        from a recovery file, or the old file can be put back if the password turns up.
        """
        self.require(Permission.MANAGE_USERS)
        if self.auth is None:
            raise PermissionError("No account store in this session.")
        secret, uri = self.auth.admin_reset(email, temp_password, reset_by=self.user)
        old = CredentialVault.path_for_user(email, self.paths.vault_dir)
        moved: Path | None = None
        if old.exists():
            moved = old.with_name(f"{old.name}.before-reset-{int(time.time())}")
            os.replace(old, moved)
        self.audit("user.reset", email.strip().lower(), detail=f"vault set aside: {moved.name}" if moved else "no vault")
        return secret, uri, moved

    # ---- schedules (MANAGE_SCHEDULES) ---------------------------------
    def add_schedule(self, spec: dict) -> dict:
        self.require(Permission.MANAGE_SCHEDULES)
        out = self.scheduler.add(spec)
        self.audit("schedule.add", out["name"], detail=out["id"])
        return out

    def remove_schedule(self, sid: str) -> None:
        self.require(Permission.MANAGE_SCHEDULES)
        self.scheduler.remove(sid)
        self.audit("schedule.remove", sid)

    def set_schedule_enabled(self, sid: str, enabled: bool) -> None:
        self.require(Permission.MANAGE_SCHEDULES)
        self.scheduler.set_enabled(sid, enabled)
        self.audit("schedule.resume" if enabled else "schedule.pause", sid)

    def audit(self, action: str, target: str = "", outcome: str = "ok", detail: str = "") -> None:
        self.audit_log.record(self.user, action, target, outcome, detail)

    def on_event(self, notify: Callable[[str, Any], None]) -> None:
        self._notify = notify

    # ---- backups -------------------------------------------------------
    def backup_vault(self) -> CredentialVault | None:
        return None if self.vault.ephemeral else self.vault

    def run_backup(self, names: list[str], keep: int | None = None, tag: str = "") -> list[jobs.BackupOutcome]:
        self.require(Permission.BACKUP)
        keep = self.prefs.get("retention_keep") if keep is None else keep
        outcomes = jobs.backup_devices(
            build_jobs(self.store, self.vault, names), self.paths.backups, self.backup_vault(), self.settings,
            keep=keep, actor=self.user, audit=self.audit_log, tag=tag)
        return outcomes

    def _run_schedule(self, spec: dict) -> str:
        if spec["kind"] != "backup":
            return "unsupported schedule kind"
        names = [n for n in (spec["targets"] or self.store.names()) if self.store.get_params(n) is not None]
        if not names:
            return "no devices"
        # Scheduled jobs run unattended with the signed-in user's role; viewers cannot schedule backups.
        res = jobs.backup_devices(build_jobs(self.store, self.vault, names), self.paths.backups, self.backup_vault(),
                                  self.settings, keep=self.prefs.get("retention_keep"),
                                  actor=f"schedule:{spec['name']}", audit=self.audit_log)
        summary = jobs.summarize_backups(res)
        self._notify("output", f"[Schedule {spec['name']}] {summary}\n")
        return summary

    # ---- deployments ---------------------------------------------------
    def make_pusher(self, plan: Mapping[str, Any]) -> PushFn:
        """Return ``push(device, commands) -> (ok, message)`` honouring the plan's rollback settings."""
        job_map = build_jobs(self.store, self.vault, list(plan["commands"]))
        checks = [Check(c["command"], c["expect"]) for c in plan.get("checks", [])]
        auto, save = bool(plan["auto_rollback"]), bool(plan["save_after"])
        backups, vault, settings = self.paths.backups, self.backup_vault(), self.settings

        def push(device: str, commands: list[str]) -> tuple[bool, str]:
            if device not in job_map:
                return False, "device is no longer in the inventory or has no credentials"
            params, creds = job_map[device]
            saved: dict[str, Any] = {}

            def on_config(tag: str, text: str) -> None:
                saved[tag] = network.save_config_snapshot(device, text, backups, vault=vault, tag=tag)
            try:
                if auto:
                    res = push_with_rollback(params, creds, commands, checks, save_after=save,
                                             on_config=on_config, settings=settings)
                    ok = res.ok
                    msg = "; ".join(res.messages[-3:])
                else:
                    network.run_multi_cli_commands(params, creds, commands, config_mode=True, save_after=save,
                                                   on_config=on_config, settings=settings)
                    ok, msg = True, "applied"
            except Exception as exc:
                kind, text = network.classify_ssh_error(exc)
                if kind == "auth":
                    try:
                        self.vault.clear_device(device)
                    except OSError:
                        pass
                return False, text
            return ok, msg
        return push

    def execute_plan(self, plan_id: str, workers: int = 4,
                     stage_gate: Callable[[int, list[str]], bool] | None = None) -> dict:
        plan = self.deployments.get(plan_id)
        return self.deployments.execute(self.user, plan_id, self.make_pusher(plan), workers=workers,
                                        on_event=self._notify, stage_gate=stage_gate)

    def execute_plan_async(self, plan_id: str, stage_gate: Callable[[int, list[str]], bool] | None = None) -> threading.Thread:
        def run() -> None:
            try:
                out = self.execute_plan(plan_id, stage_gate=stage_gate)
                self._notify("output", f"[Deployment {plan_id}] finished: {out['status']}\n")
            except Exception as exc:
                self._notify("output", f"[Deployment {plan_id}] could not run: {exc}\n")
            finally:
                self._notify("deployments_changed", None)
        t = threading.Thread(target=run, name=f"nc-deploy-{plan_id}", daemon=True)
        t.start()
        return t

    def rollback_supported(self, names: list[str]) -> list[str]:
        """Names of devices whose platform has NO automatic rollback strategy."""
        return [n for n in names if not supports_rollback(self.store.device_type(n))]
