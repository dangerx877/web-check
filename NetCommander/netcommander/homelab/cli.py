"""Headless homelab commands: ``netcommander serve`` and ``netcommander homelab <command>``.

Authentication follows the existing CLI (:mod:`netcommander.cli`): the account password unlocks the
vault (and counts toward lockout). ``serve`` hands every stored integration secret to the web service,
so it also requires an authenticator/recovery code unless ``--unattended`` is given deliberately
(for systemd; protect the password with the service manager's credential store).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import Paths
from ..rbac import Role
from ..security import AuthManager, CredentialVault
from .core import settings as cfgmod
from .core.errors import AuthorizationRequired, ConfigError, HomelabError

Out = Callable[[str], None]
NO_AUTH = {"check-config"}


def add_subcommands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    s = sub.add_parser("serve", help="run the homelab platform: management API, web dashboard, monitoring")
    s.add_argument("--user", required=True, metavar="EMAIL", help="account whose vault holds the integration secrets")
    s.add_argument("--bind", help="address to listen on (default from homelab.json: 127.0.0.1)")
    s.add_argument("--port", type=int, help="port (default 8765)")
    s.add_argument("--no-monitoring", action="store_true", help="do not start background monitoring/collection")
    s.add_argument("--unattended", action="store_true",
                   help="start with the password only (no authenticator code) - for service managers")

    h = sub.add_parser("homelab", help="homelab inventory, discovery, monitoring and reports (headless)")
    hs = h.add_subparsers(dest="hl_command", metavar="ACTION", required=True)

    def user(p: argparse.ArgumentParser) -> None:
        p.add_argument("--user", required=True, metavar="EMAIL")

    d = hs.add_parser("discover", help="sweep networks (read-only) and add what answers to the inventory")
    user(d)
    d.add_argument("targets", nargs="+", help="CIDR, range or address")
    inv = hs.add_parser("inventory", help="print or export the unified inventory")
    user(inv)
    inv.add_argument("--format", choices=("table", "csv", "json"), default="table")
    inv.add_argument("--output", metavar="FILE")
    st = hs.add_parser("status", help="dashboard summary (health, alerts, counts)")
    user(st)
    st.add_argument("--json", action="store_true")
    mo = hs.add_parser("monitor", help="run collection, monitoring and backup checks once (cron-friendly)")
    user(mo)
    ad = hs.add_parser("add-integration", help="add a hypervisor / Docker / NAS integration")
    user(ad)
    ad.add_argument("--category", required=True, choices=("hypervisor", "docker", "storage"))
    ad.add_argument("--kind", required=True)
    ad.add_argument("--name", required=True)
    ad.add_argument("--set", action="append", default=[], metavar="FIELD=VALUE", help="non-secret setting (repeatable)")
    ad.add_argument("--secret", action="append", default=[], metavar="FIELD",
                    help="secret field to prompt for (repeatable; never pass secrets on the command line)")
    po = hs.add_parser("poll", help="poll integrations now")
    user(po)
    po.add_argument("integration", nargs="*")
    hs.add_parser("adapters", help="list available adapters and their fields")
    rb = hs.add_parser("runbook", help="write the recovery runbook (Markdown)")
    user(rb)
    rb.add_argument("--output", metavar="FILE")
    ex = hs.add_parser("export-config", help="export the homelab configuration bundle (no secrets)")
    user(ex)
    ex.add_argument("--output", required=True, metavar="FILE")
    tr = hs.add_parser("trust-host", help="show an SSH host key fingerprint and add it to known_hosts")
    user(tr)
    tr.add_argument("host")
    tr.add_argument("--port", type=int, default=22)
    tr.add_argument("--yes", action="store_true", help="skip the interactive confirmation (still prints the fingerprint)")
    cc = hs.add_parser("check-config", help="validate homelab.json")
    cc.add_argument("--file", metavar="FILE")


def needs_auth(args: argparse.Namespace) -> bool:
    return not (args.command == "homelab" and args.hl_command in NO_AUTH | {"adapters"})


def run_unauthenticated(args: argparse.Namespace, paths: Paths, out: Out, err: Out) -> int:
    if args.hl_command == "check-config":
        path = Path(args.file) if args.file else paths.root / "homelab.json"
        try:
            cfg = cfgmod.load(path)
        except ConfigError as exc:
            for p in exc.problems:
                err(f"  - {p}")
            err(f"{path}: invalid")
            return 2
        out(f"{path}: OK{' (file not found - defaults apply)' if not path.exists() else ''}")
        out(json.dumps(cfg, indent=2))
        return 0
    from .adapters import builtin_registry
    for spec in builtin_registry().list():
        out(f"{spec.category:<10} {spec.kind:<11} {spec.title} [{spec.maturity}]")
        for f in spec.fields:
            out(f"    {f.name}{' (secret)' if f.secret else ''}{' *' if f.required else ''}  {f.help}")
    return 0


def _table(rows: list[dict[str, Any]]) -> str:
    cols = ("name", "kind", "status", "ip", "os", "source")
    widths = {c: max([len(c)] + [len(str(r.get(c) or "")) for r in rows]) for c in cols}
    lines = ["  ".join(c.upper().ljust(widths[c]) for c in cols)]
    lines += ["  ".join(str(r.get(c) or "").ljust(widths[c]) for c in cols) for r in rows]
    return "\n".join(lines)


def _write(text: str, output: str | None, out: Out) -> None:
    if output:
        from ..security import _write_private
        _write_private(Path(output), text)
        out(f"written: {output}")
    else:
        out(text)


def run(args: argparse.Namespace, paths: Paths, vault: CredentialVault, auth: AuthManager, *,
        env: dict[str, str], prompt: Callable[[str], str], out: Out, err: Out,
        second_factor: Callable[[], bool]) -> int:
    from .platform import Ctx, HomelabPlatform
    role = Role.parse(auth.role_of(args.user), Role.VIEWER)
    ctx = Ctx(args.user.strip().lower(), role)
    try:
        platform = HomelabPlatform(paths, vault)
    except ConfigError as exc:
        err(str(exc))
        for p in exc.problems:
            err(f"  - {p}")
        return 2
    try:
        return _dispatch(args, platform, ctx, auth, env=env, prompt=prompt, out=out, err=err, second_factor=second_factor)
    except PermissionError as exc:
        err(str(exc))
        return 3
    except HomelabError as exc:
        err(str(exc))
        return 1
    finally:
        if args.command != "serve":
            platform.stop()


def _dispatch(args: argparse.Namespace, p: Any, ctx: Any, auth: AuthManager, *, env: dict[str, str],
              prompt: Callable[[str], str], out: Out, err: Out, second_factor: Callable[[], bool]) -> int:
    if args.command == "serve":
        if not args.unattended and not second_factor():
            p._audit(ctx.user, "serve.start", "", "denied", "second factor failed")
            return 3
        from .api.server import ApiServer
        try:
            srv = ApiServer(p, auth, bind=args.bind, port=args.port)
        except ConfigError as exc:
            err(str(exc))
            return 2
        if not args.no_monitoring:
            p.start()
        p._audit(ctx.user, "serve.start", srv.url, "ok", "unattended" if args.unattended else "2fa")
        out(f"Uptime Funk homelab platform listening on {srv.url}  (Ctrl+C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.stop()
            p.stop()
            p._audit(ctx.user, "serve.stop")
        return 0

    cmd = args.hl_command
    if cmd == "discover":
        res = p.run_discovery(ctx, args.targets)
        out(f"{res['alive']} hosts answered, {res['new']} new assets added")
        return 0
    if cmd == "inventory":
        if args.format == "table":
            _write(_table(p.assets(ctx)), args.output, out)
        else:
            _write(p.export_inventory(ctx, args.format), args.output, out)
        return 0
    if cmd == "status":
        d = p.dashboard(ctx)
        if args.json:
            out(json.dumps(d, indent=2, default=str))
            return 0
        t = d["totals"]
        out(f"Health {d['health'] if d['health'] is not None else '-'} | devices {t['devices']} "
            f"({t['online']} online, {t['offline']} offline, {t['degraded']} degraded)")
        out(f"VMs {d['vms']['running']}/{d['vms']['total']} running | containers {d['containers']['running']}/"
            f"{d['containers']['total']} | alerts {d['alerts']['critical']} critical, {d['alerts']['warning']} warning | "
            f"backups {d['backups']['ok']}/{d['backups']['total']} OK")
        for a in d["alerts"]["items"]:
            out(f"  [{a['severity'].upper()}] {a['message']}")
        return 1 if d["alerts"]["critical"] else 0
    if cmd == "monitor":
        c = p.collect_cycle()
        m = p.monitor_cycle()
        b = p.backup_cycle()
        out(f"collected {c['ok']} ok / {c['failed']} failed; {m['checks']} checks; {len(b)} backup jobs evaluated")
        return 0 if not c["failed"] else 1
    if cmd == "add-integration":
        config: dict[str, Any] = {}
        for item in args.set:
            if "=" not in item:
                err(f"--set expects FIELD=VALUE, got {item!r}")
                return 2
            k, v = item.split("=", 1)
            config[k.strip()] = v
        secrets = {}
        for field in args.secret:
            secrets[field] = env.get(f"NETCOMMANDER_SECRET_{field.upper()}") or prompt(f"{field}: ")
        rec = p.add_integration(ctx, args.category, args.kind, args.name, config, secrets)
        out(f"integration {rec['id']} saved; testing...")
        try:
            out(json.dumps(p.test_integration(ctx, rec["id"])))
        except HomelabError as exc:
            err(f"saved, but the first poll failed: {exc}")
            return 1
        return 0
    if cmd == "poll":
        ids = args.integration or [i["id"] for i in p.integrations(ctx)]
        failed = 0
        for iid in ids:
            try:
                out(f"{iid}: {json.dumps(p.test_integration(ctx, iid))}")
            except HomelabError as exc:
                failed += 1
                err(f"{iid}: {exc}")
        return 1 if failed else 0
    if cmd == "runbook":
        _write(p.runbook(ctx), args.output, out)
        return 0
    if cmd == "export-config":
        from .backups import write_json
        write_json(args.output, p.config_bundle(ctx))
        out(f"written: {args.output} (contains no secrets)")
        return 0
    if cmd == "trust-host":
        key = p.host_key(ctx, args.host, args.port)
        out(f"{args.host}:{args.port} presents {key['type']} {key['fingerprint']}")
        if not args.yes:
            answer = input("Does this match the fingerprint shown on the device itself? [y/N] ") if sys.stdin.isatty() else ""
            if answer.strip().lower() not in ("y", "yes"):
                err("Not trusted.")
                return 1
        try:
            p.trust_host(ctx, args.host, args.port, key["fingerprint"])
        except AuthorizationRequired as exc:              # the CLI confirmation above *is* the explicit consent
            res = p.trust_host(ctx, args.host, args.port, key["fingerprint"], exc.token)
            out(f"trusted; written to {res['known_hosts']}")
        return 0
    err(f"Unknown homelab command {cmd!r}")
    return 2


def wait_forever(stop: Callable[[], bool]) -> None:                      # pragma: no cover - helper for services
    while not stop():
        time.sleep(1)
