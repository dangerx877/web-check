"""Account dialog: change password, recovery codes, rotate 2FA, vault export, user roles."""
from __future__ import annotations

import logging
from tkinter import filedialog

import customtkinter as ctk

from ..config import MONO_FONT
from ..rbac import Permission
from ..security import change_account_password
from . import theme
from .dialogs import SecretReveal, ask_form

log = logging.getLogger(__name__)


class AccountDialog(ctk.CTkToplevel):
    def __init__(self, parent, services):
        super().__init__(parent)
        self.svc = services
        self.title("Account & Security")
        self._reveal = None
        ctk.CTkLabel(self, text=f"{services.user}  ·  role: {services.role.value}",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(padx=14, pady=(12, 6), anchor="w")
        self.status = ctk.CTkLabel(self, text="", wraplength=420, justify="left", text_color=theme.MUTED)
        self.status.pack(padx=14, anchor="w")
        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(fill="both", expand=True, padx=14, pady=8)
        if services.guest or services.auth is None:
            ctk.CTkLabel(self.body, text="Guest mode has no account. Sign in to manage security settings.",
                         wraplength=420).pack(anchor="w")
            return
        for text, cmd in (("Change Password", self.change_password), ("Generate Recovery Codes", self.recovery_codes),
                          ("Rotate 2FA Key", self.rotate_2fa), ("Export Encrypted Vault Recovery File", self.export_vault)):
            ctk.CTkButton(self.body, text=text, fg_color=theme.BTN_NEUTRAL, command=cmd).pack(fill="x", pady=3)
        if services.can(Permission.MANAGE_USERS):
            ctk.CTkButton(self.body, text="Add User", fg_color=theme.BTN_NEUTRAL,
                          command=self.add_user).pack(fill="x", pady=3)
            ctk.CTkButton(self.body, text="Manage Users & Roles", fg_color=theme.BTN_NEUTRAL,
                          command=self.manage_users).pack(fill="x", pady=3)
            ctk.CTkButton(self.body, text="Reset User (forgotten password / lost phone)", fg_color=theme.BTN_NEUTRAL,
                          command=self.reset_user).pack(fill="x", pady=3)
        self.codes_box = ctk.CTkTextbox(self.body, height=0, font=ctk.CTkFont(family=MONO_FONT, size=12))

    def _say(self, text: str, color: str = theme.MUTED) -> None:
        self.status.configure(text=text, text_color=color)

    # ---- actions -------------------------------------------------------
    def change_password(self) -> None:
        r = ask_form(self, "Change Password", [
            ("old", "Current password", "", True), ("new", "New password (10+ characters)", "", True),
            ("new2", "Repeat new password", "", True), ("otp", "Authenticator code (or a recovery code)", "", False)],
            "Change", "This changes your sign-in password AND re-wraps the vault key. Existing backups stay readable.")
        if not r:
            return
        if r["new"] != r["new2"]:
            self._say("The new passwords do not match.", theme.ERROR)
            return
        try:
            change_account_password(self.svc.auth, self.svc.vault, self.svc.user, r["old"], r["new"], r["otp"])
        except (ValueError, PermissionError, RuntimeError, OSError) as exc:
            self.svc.audit("account.change_password", outcome="failed", detail=type(exc).__name__)
            self._say(str(exc), theme.ERROR)
            return
        self.svc.audit("account.change_password")
        self._say("Password changed.", theme.OK)

    def recovery_codes(self) -> None:
        r = ask_form(self, "Recovery Codes", [("pw", "Account password", "", True)], "Generate",
                     "Creates 8 single-use codes that replace the authenticator once each. Old codes stop working.")
        if not r:
            return
        try:
            codes = self.svc.auth.generate_recovery_codes(self.svc.user, r["pw"])
        except (ValueError, OSError) as exc:
            self._say(str(exc), theme.ERROR)
            return
        self.svc.audit("account.recovery_codes")
        # Shown exactly once in a window of their own; never written to a log or the main output.
        win = ctk.CTkToplevel(self)
        win.title("Your recovery codes - shown once")
        box = ctk.CTkTextbox(win, width=300, height=200, font=ctk.CTkFont(family=MONO_FONT, size=14))
        box.insert("1.0", "\n".join(codes))
        box.pack(padx=14, pady=12)
        ctk.CTkLabel(win, text="Store these offline. Each works once.", text_color=theme.MUTED).pack()

        def close() -> None:
            box.delete("1.0", "end")
            win.destroy()
        ctk.CTkButton(win, text="I have saved them", command=close).pack(pady=10)
        win.protocol("WM_DELETE_WINDOW", close)

    def rotate_2fa(self) -> None:
        r = ask_form(self, "Rotate 2FA Key", [("pw", "Account password", "", True)], "Rotate",
                     "Creates a new authenticator key. The old one stops working immediately.")
        if not r:
            return
        try:
            secret, uri = self.svc.auth.rotate_totp(self.svc.user, r["pw"])
        except (ValueError, OSError) as exc:
            self._say(str(exc), theme.ERROR)
            return
        self.svc.audit("account.rotate_2fa")
        win = ctk.CTkToplevel(self)
        win.title("New 2FA key")
        reveal = SecretReveal(win, "New authenticator key (hidden):", secret, uri)
        reveal.pack(fill="x", padx=10, pady=10)

        def close() -> None:
            reveal.wipe()
            win.destroy()
        ctk.CTkButton(win, text="Done", command=close).pack(pady=8)
        win.protocol("WM_DELETE_WINDOW", close)

    def export_vault(self) -> None:
        try:
            self.svc.require(Permission.EXPORT_VAULT)
        except PermissionError as exc:
            self._say(str(exc), theme.ERROR)
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile="netcommander-vault-recovery.json")
        if not path:
            return
        r = ask_form(self, "Protect Recovery File", [("p", "Passphrase (10+ characters)", "", True),
                                                      ("p2", "Repeat passphrase", "", True)], "Export",
                     "Anyone with this file AND the passphrase can read every stored credential and backup. Keep it offline.")
        if not r:
            return
        if r["p"] != r["p2"]:
            self._say("Passphrases do not match.", theme.ERROR)
            return
        try:
            out = self.svc.vault.export_encrypted(path, r["p"])
        except (ValueError, RuntimeError, OSError) as exc:
            self._say(str(exc), theme.ERROR)
            return
        self.svc.audit("vault.export", str(out))
        self._say(f"Recovery file written to {out}")

    def add_user(self) -> None:
        """Admins create accounts (self-registration is only for the very first account)."""
        r = ask_form(self, "Add User", [
            ("email", "Email", "", False), ("pw", "Temporary password (10+ characters)", "", True),
            ("role", "Role (viewer / operator / admin)", "operator", False)], "Create",
            "Give the user the temporary password and the authenticator key shown next, over a safe channel.\n"
            "They will be asked to choose their own password at first sign-in.")
        if not r:
            return
        try:
            self.svc.require(Permission.MANAGE_USERS)
            secret, uri = self.svc.auth.create_account(r["email"], r["pw"], r["role"].strip().lower() or None,
                                                       created_by=self.svc.user)
        except (ValueError, PermissionError, OSError) as exc:
            self.svc.audit("user.create", r["email"], outcome="failed", detail=type(exc).__name__)
            self._say(str(exc), theme.ERROR)
            return
        self.svc.audit("user.create", r["email"].strip().lower(), detail=r["role"].strip().lower() or "operator")
        self._say(f"Account {r['email'].strip().lower()} created.", theme.OK)
        win = ctk.CTkToplevel(self)
        win.title("New user's authenticator key")
        reveal = SecretReveal(win, "Authenticator setup key for the new user (hidden):", secret, uri)
        reveal.pack(fill="x", padx=10, pady=10)

        def close() -> None:
            reveal.wipe()
            win.destroy()
        ctk.CTkButton(win, text="Done", command=close).pack(pady=8)
        win.protocol("WM_DELETE_WINDOW", close)

    def reset_user(self) -> None:
        r = ask_form(self, "Reset User", [
            ("email", "User email", "", False), ("pw", "Temporary password (10+ characters)", "", True)], "Reset",
            "Gives the user a temporary password and a NEW authenticator key. Their old vault only opens with the\n"
            "old password, so it is set aside: they re-enter device passwords or run 'netcommander vault-import'.")
        if not r:
            return
        try:
            secret, uri, moved = self.svc.reset_user(r["email"], r["pw"])
        except (ValueError, PermissionError, OSError) as exc:
            self._say(str(exc), theme.ERROR)
            return
        note = f" Old vault kept as {moved.name}." if moved else ""
        self._say(f"{r['email'].strip().lower()} was reset.{note}", theme.OK)
        win = ctk.CTkToplevel(self)
        win.title("New authenticator key for the user")
        reveal = SecretReveal(win, "New authenticator key (hidden):", secret, uri)
        reveal.pack(fill="x", padx=10, pady=10)

        def close() -> None:
            reveal.wipe()
            win.destroy()
        ctk.CTkButton(win, text="Done", command=close).pack(pady=8)
        win.protocol("WM_DELETE_WINDOW", close)

    def manage_users(self) -> None:
        users = self.svc.auth.list_users()
        lines = "\n".join(f"{e}  —  {r}" for e, r in users)
        r = ask_form(self, "Users & Roles", [("email", "User email", "", False), ("role", "New role (viewer / operator / admin)", "operator", False)],
                     "Set Role", f"Current users:\n{lines}")
        if not r:
            return
        try:
            self.svc.require(Permission.MANAGE_USERS)
            self.svc.auth.set_role(r["email"], r["role"])
        except (ValueError, PermissionError, OSError) as exc:
            self._say(str(exc), theme.ERROR)
            return
        self.svc.audit("user.set_role", r["email"], detail=r["role"])
        self._say(f"{r['email']} is now {r['role'].strip().lower()}.")
