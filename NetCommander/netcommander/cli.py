"""Headless subcommands (cron / systemd / Task Scheduler friendly).

Exit codes: 0 success, 1 operation finished with failures, 2 usage/configuration error,
3 authentication/permission problem.

The account password (which is also the vault master password) is read from
``NETCOMMANDER_VAULT_PASSWORD`` or prompted for (``getpass``). An env var is visible to anything
running as the same user - prefer a prompt, or a service manager's credential store, on shared machines.

Security model
* Every command checks the password through :meth:`AuthManager.verify_password`, so failures
  count toward the same lockout as the sign-in window, and a locked account is refused.
* Unattended commands (``backup``, ``compliance``, ``schedule-run``) need only the password, so
  they can run from cron/systemd.
* ``vault-export`` and ``vault-import`` hand out or replace every stored credential, so they also
  need an authenticator (or recovery) code - prompted for, or ``NETCOMMANDER_OTP``.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable

from . import compliance, jobs, network
from .audit import AuditLog, sinks_from_env
from .batch import build_jobs
from .config import Paths, RuntimeSettings
from .rbac import Permission, PermissionDenied, require
from .scheduler import Scheduler
from .security import AuthManager, CredentialVault
from .store import DeviceStore

ENV_VAULT_PASSWORD = "NETCOMMANDER_VAULT_PASSWORD"
ENV_OTP = "NETCOMMANDER_OTP"
Prompt = Callable[[str], str]


def add_subcommands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    def user(p: argparse.ArgumentParser) -> None:
        p.add_argument("--user", required=True, metavar="EMAIL", help="account whose vault and role to use")

    b = sub.add_parser("backup", help="back up running configs of all (or named) devices")
    user(b)
    b.add_argument("devices", nargs="*", help="device names (default: all)")
    b.add_argument("--keep", type=int, default=0, metavar="N", help="keep only the newest N snapshots per device")
    b.add_argument("--workers", type=int, default=8)

    c = sub.add_parser("compliance", help="check saved configs against a policy file (no device contact)")
    user(c)
    c.add_argument("--policy", metavar="FILE", help="JSON policy (default: <data-dir>/compliance_policy.json)")
    c.add_argument("--csv", metavar="FILE", help="also write a CSV report")
    c.add_argument("--live", action="store_true", help="fetch each device's running config over SSH instead of using the latest backup")
    c.add_argument("--workers", type=int, default=8, help="parallel devices for --live")

    ve = sub.add_parser("vault-export", help="write an encrypted recovery file (credentials + backup key)")
    user(ve)
    ve.add_argument("file")

    vi = sub.add_parser("vault-import", help="recreate a vault from a recovery file")
    user(vi)
    vi.add_argument("file")

    sr = sub.add_parser("schedule-run", help="run the scheduler in the foreground (for services)")
    user(sr)
    sr.add_argument("--once", action="store_true", help="run whatever is due now, then exit")

    sub.add_parser("audit-verify", help="verify the audit log's hash chain")
    sub.add_parser("data-dir", help="print the data directory in use")


def _secret(prompt_text: str, env: dict[str, str], prompt: Prompt) -> str:
    return env.get(ENV_VAULT_PASSWORD) or prompt(prompt_text)


def _auth(paths: Paths, audit: AuditLog) -> AuthManager:
    """AuthManager whose sign-in events (successes, failures, lockouts) go to the audit log."""
    def hook(action: str, who: str, outcome: str, detail: str) -> None:
        audit.record(who, action, "cli", outcome, detail)
    return AuthManager(paths.auth, on_event=hook)


def _second_factor(auth: AuthManager, user: str, password: str, env: dict[str, str], prompt: Prompt,
                   err: Callable[[str], None]) -> bool:
    """Full sign-in check (password + authenticator/recovery code) for the most sensitive commands."""
    code = env.get(ENV_OTP) or prompt(f"Authenticator code (or a recovery code) for {user}: ")
    ok, msg = auth.verify_login(user, password, code)
    if not ok:
        err(msg)
    return ok


def _unlock(args: argparse.Namespace, paths: Paths, env: dict[str, str], prompt: Prompt,
            err: Callable[[str], None], audit: AuditLog,
            ) -> tuple[CredentialVault, AuthManager, str] | None:
    auth = _auth(paths, audit)
    if auth.load_warning and not auth.user_exists(args.user):
        err(auth.load_warning)
        return None
    if not auth.user_exists(args.user):
        err("Unknown account.")
        return None
    pw = _secret(f"Password for {args.user}: ", env, prompt)
    ok, msg = auth.verify_password(args.user, pw)
    if not ok:
        err(msg)
        audit.record(args.user, "cli.unlock", args.command, "failed")
        return None
    vault = CredentialVault(paths.vault_dir / "unused")
    if not vault.unlock_existing(pw, path=CredentialVault.path_for_user(args.user, paths.vault_dir)):
        err(vault.last_error or "Could not unlock the vault.")
        audit.record(args.user, "cli.unlock", args.command, "failed")
        return None
    return vault, auth, pw


def _load_store(paths: Paths) -> DeviceStore:
    store = DeviceStore()
    if paths.topology.exists():
        store.replace_all(network.load_inventory_json(paths.topology))
    return store


def run(args: argparse.Namespace, paths: Paths, settings: RuntimeSettings, *, env: dict[str, str] | None = None,
        prompt: Prompt = getpass.getpass, out: Callable[[str], None] = print,
        err: Callable[[str], None] | None = None) -> int:
    env = dict(os.environ) if env is None else env
    err = err or (lambda m: print(m, file=sys.stderr))
    cmd = args.command

    if cmd == "data-dir":
        out(str(paths.root))
        return 0
    if cmd == "audit-verify":
        ok, msg = AuditLog(paths.audit).verify()
        (out if ok else err)(f"audit log: {msg}")
        return 0 if ok else 1

    audit = AuditLog(paths.audit, sinks=sinks_from_env(env))
    unlocked = _unlock(args, paths, env, prompt, err, audit)
    if unlocked is None:
        return 3
    vault, auth, password = unlocked
    role = auth.role_of(args.user)

    def need(p: Permission) -> bool:
        try:
            require(role, p)
            return True
        except PermissionDenied as exc:
            audit.record(args.user, f"deny.{p.value}", outcome="denied")
            err(str(exc))
            return False

    if cmd == "backup":
        if not need(Permission.BACKUP):
            return 3
        store = _load_store(paths)
        names = args.devices or store.names()
        unknown = [n for n in names if store.get_params(n) is None]
        if unknown:
            err(f"Unknown device(s): {', '.join(unknown)}")
            return 2
        outcomes = jobs.backup_devices(build_jobs(store, vault, names), paths.backups, vault, settings,
                                       keep=args.keep, workers=args.workers, actor=args.user, audit=audit)
        out(jobs.summarize_backups(outcomes))
        return 0 if outcomes and all(o.ok for o in outcomes) else 1

    if cmd == "compliance":
        if not need(Permission.VIEW):
            return 3
        try:
            rules = compliance.load_policy(args.policy or paths.policy)
        except compliance.PolicyError as exc:
            err(str(exc))
            return 2
        store = _load_store(paths)

        def latest(name: str) -> str:
            snaps = network.list_snapshots(name, paths.backups)
            if not snaps:
                raise FileNotFoundError("no saved backup yet")
            return network.read_snapshot(snaps[-1], vault)
        if args.live:
            if not need(Permission.RUN_SHOW):
                return 3
            get = jobs.live_config_getter(build_jobs(store, vault, store.names()), settings)
            results = compliance.run_compliance(store.snapshot(), rules, get, workers=max(1, args.workers))
        else:
            results = compliance.run_compliance(store.snapshot(), rules, latest)
        out(compliance.report_text(results))
        if args.csv:
            import csv
            with open(args.csv, "w", newline="", encoding="utf-8") as fh:
                from .utils import csv_safe
                csv.writer(fh).writerows([[csv_safe(c) for c in row] for row in compliance.report_csv_rows(results)])
        audit.record(args.user, "compliance", outcome="ok", detail=str(compliance.summarize(results)["score"]))
        return 0 if all(r.compliant for r in results) else 1

    if cmd == "vault-export":
        if not need(Permission.EXPORT_VAULT):
            return 3
        if not _second_factor(auth, args.user, password, env, prompt, err):
            audit.record(args.user, "vault.export", str(args.file), "denied", "second factor failed")
            return 3
        phrase = env.get("NETCOMMANDER_EXPORT_PASSPHRASE") or prompt("Passphrase to protect the export: ")
        try:
            path = vault.export_encrypted(args.file, phrase)
        except (ValueError, OSError) as exc:
            err(str(exc))
            return 2
        audit.record(args.user, "vault.export", str(path))
        out(f"Recovery file written: {path}  (keep it offline; it unlocks every stored credential and backup)")
        return 0

    if cmd == "schedule-run":
        if not need(Permission.BACKUP):
            return 3
        store = _load_store(paths)

        def runner(spec: dict) -> str:
            names = spec["targets"] or store.names()
            if spec["kind"] == "compliance":
                return "compliance via the CLI: use `netcommander compliance`"
            res = jobs.backup_devices(build_jobs(store, vault, names), paths.backups, vault, settings,
                                      actor=f"schedule:{spec['name']}", audit=audit)
            return jobs.summarize_backups(res)
        sched = Scheduler(paths.schedules, runner)
        if args.once:
            for name, result in sched.run_due():
                out(f"{name}: {result}")
            return 0
        sched.start()
        try:
            while sched.running:
                sched._stop.wait(1.0)
        except KeyboardInterrupt:
            pass
        finally:
            sched.stop()
        return 0

    err(f"Unknown command {cmd!r}")
    return 2


def run_vault_import(args: argparse.Namespace, paths: Paths, *, env: dict[str, str] | None = None,
                     prompt: Prompt = getpass.getpass, out: Callable[[str], None] = print,
                     err: Callable[[str], None] | None = None) -> int:
    """Separate from :func:`run` because there is no vault to unlock yet.

    The restored vault is protected by the account's own password (verified together with an
    authenticator or recovery code), so the app can open it at the next sign-in.
    """
    env = dict(os.environ) if env is None else env
    err = err or (lambda m: print(m, file=sys.stderr))
    audit = AuditLog(paths.audit, sinks=sinks_from_env(env))
    auth = _auth(paths, audit)
    if not auth.user_exists(args.user):
        err("Unknown account. Register it in the app first (the recovery file restores the vault, not the account).")
        return 3
    target = CredentialVault.path_for_user(args.user, paths.vault_dir)
    if target.exists():
        err(f"A vault already exists at {target}; it was not overwritten.")
        return 1
    pw = _secret(f"Password for {args.user}: ", env, prompt)
    if not _second_factor(auth, args.user, pw, env, prompt, err):
        audit.record(args.user, "vault.import", str(args.file), "denied", "sign-in check failed")
        return 3
    phrase = env.get("NETCOMMANDER_EXPORT_PASSPHRASE") or prompt("Export passphrase: ")
    vault = CredentialVault(paths.vault_dir / "unused")
    if not vault.import_export(args.file, phrase, pw, path=target):
        err(vault.last_error or "Import failed.")
        audit.record(args.user, "vault.import", str(args.file), "failed", vault.last_error[:200])
        return 1
    vault.close()
    audit.record(args.user, "vault.import", str(args.file))
    out(f"Vault restored for {args.user}. Old encrypted backups are readable again.")
    return 0
