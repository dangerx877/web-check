"""Command-line entry point: ``python -m netcommander`` / ``netcommander`` / ``python netcommander.py``.

Optional environment variables:
    NETCOMMANDER_HOME                            where accounts, vaults, backups and topology.json live
    NET_SSH_USER, NET_SSH_PASS, NET_SSH_ENABLE   default device credentials
    NET_SSH_STRICT_HOSTKEYS=1                    reject SSH hosts not in ~/.ssh/known_hosts
    NET_DISABLE_GUEST=1                          remove the "Continue as Guest" option
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import ENV_HOME, Paths, RuntimeSettings

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(threadName)s %(name)s: %(message)s"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netcommander",
        description="NetCommander Pro - multi-vendor CLI/config runner with encrypted vault and MFA.",
    )
    parser.add_argument("--version", action="version", version=f"NetCommander {__version__}")
    parser.add_argument(
        "--data-dir", metavar="DIR",
        help=f"folder for accounts, vaults, backups and topology.json (default: ${ENV_HOME}, "
             "the project folder, or ~/.netcommander)",
    )
    parser.add_argument(
        "--strict-hostkeys", action="store_true",
        help="start with strict SSH host-key checking enabled",
    )
    parser.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="diagnostic log level (never logs passwords, TOTP keys or config text)",
    )
    parser.add_argument(
        "--log-file", metavar="FILE",
        help="also write the diagnostic log to FILE (rotating, 1 MB x 3)",
    )
    from . import cli
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    cli.add_subcommands(sub)
    return parser


def configure_logging(level: str, log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.handlers.RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        ))
    logging.basicConfig(level=getattr(logging, level), format=LOG_FORMAT, handlers=handlers, force=True)


def run_gui(paths: Paths, settings: RuntimeSettings) -> int:
    """Sign-in dialog, then the main window. The GUI stack is imported only here."""
    import customtkinter as ctk

    from .security import AuthManager, CredentialVault
    from .ui.app import NetworkManagerApp
    from .ui.dialogs import LoginMFADialog

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.withdraw()

    from .audit import AuditLog, sinks_from_env
    audit = AuditLog(paths.audit, sinks=sinks_from_env())
    auth_manager = AuthManager(
        paths.auth, on_event=lambda action, who, outcome, detail: (audit.record(who, action, "", outcome, detail), None)[1])
    vault = CredentialVault(paths.legacy_vault)

    login = LoginMFADialog(root, auth_manager, vault, settings=settings, paths=paths)
    root.wait_window(login)

    if not login.authenticated_user:
        root.destroy()
        return 0

    root.destroy()
    app = NetworkManagerApp(login.authenticated_user, vault, settings=settings, paths=paths, auth=auth_manager)
    app.mainloop()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, args.log_file)

    paths = Paths.for_root(Path(args.data_dir).expanduser().resolve()) if args.data_dir else Paths.default()
    settings = RuntimeSettings(strict_hostkeys=args.strict_hostkeys)
    logging.getLogger(__name__).info("data directory: %s", paths.root)

    if args.command:
        from . import cli
        if args.command == "vault-import":
            return cli.run_vault_import(args, paths)
        return cli.run(args, paths, settings)

    try:
        return run_gui(paths, settings)
    except ImportError as exc:
        print(
            f"NetCommander could not start because a dependency is missing: {exc}\n"
            "Install them with:  pip install -r requirements.txt   (see docs/INSTALL.md)",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
