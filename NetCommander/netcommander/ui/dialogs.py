"""Sign-in / MFA dialog and the masked SSH credential prompt."""
from __future__ import annotations

from tkinter import messagebox

import customtkinter as ctk

from ..config import GUEST_USER, MONO_FONT, Paths, RuntimeSettings
from ..security import AuthManager, CredentialVault
from . import theme

SECRET_AUTOHIDE_MS = 30_000
CLIPBOARD_CLEAR_MS = 60_000
MASK = "•"


class SecretReveal(ctk.CTkFrame):
    """Shows a secret masked; Reveal/Copy on demand; auto re-hides; wipes on request.

    The secret lives only in this object (and the masked entry); it is never
    written to a log, a file or a plain text box.
    """

    def __init__(self, parent, title: str, secret: str, uri: str):
        super().__init__(parent)
        self._secret, self._uri = secret, uri
        self._hide_job = None
        self._clip_job = None
        self._copied = ""

        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=8, pady=(6, 2))
        self.entry = ctk.CTkEntry(self, font=ctk.CTkFont(family=MONO_FONT, size=12))
        self.entry.insert(0, secret)
        self.entry.configure(show=MASK, state="readonly")
        self.entry.pack(fill="x", padx=8, pady=2)

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=(2, 6))
        row.grid_columnconfigure((0, 1, 2), weight=1)
        self.reveal_btn = ctk.CTkButton(row, text="Reveal", width=70, fg_color=theme.BTN_NEUTRAL, command=self.toggle)
        self.reveal_btn.grid(row=0, column=0, padx=(0, 3), sticky="ew")
        ctk.CTkButton(row, text="Copy Key", width=70, fg_color=theme.BTN_NEUTRAL,
                      command=lambda: self.copy(self._secret, "Key")).grid(row=0, column=1, padx=3, sticky="ew")
        ctk.CTkButton(row, text="Copy URI", width=70, fg_color=theme.BTN_NEUTRAL,
                      command=lambda: self.copy(self._uri, "URI")).grid(row=0, column=2, padx=(3, 0), sticky="ew")
        self.note = ctk.CTkLabel(self, text="Hidden. Shown once - store it in your authenticator app.",
                                 text_color=theme.MUTED, font=ctk.CTkFont(size=11))
        self.note.pack(anchor="w", padx=8, pady=(0, 6))

    @property
    def revealed(self) -> bool:
        return self.entry.cget("show") == ""

    def toggle(self) -> None:
        self.hide() if self.revealed else self.reveal()

    def reveal(self) -> None:
        self.entry.configure(show="")
        self.reveal_btn.configure(text="Hide")
        self.note.configure(text="Visible for 30 seconds - make sure nobody is watching.")
        self._cancel(self._hide_job)
        self._hide_job = self.after(SECRET_AUTOHIDE_MS, self.hide)

    def hide(self) -> None:
        self.entry.configure(show=MASK)
        self.reveal_btn.configure(text="Reveal")
        self.note.configure(text="Hidden. Shown once - store it in your authenticator app.")
        self._cancel(self._hide_job)
        self._hide_job = None

    def copy(self, text: str, what: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            self.note.configure(text="Could not access the clipboard.")
            return
        self._copied = text
        self.note.configure(text=f"{what} copied; the clipboard is cleared in 60 seconds.")
        self._cancel(self._clip_job)
        self._clip_job = self.after(CLIPBOARD_CLEAR_MS, self.clear_clipboard)

    def clear_clipboard(self) -> None:
        """Clear the clipboard, but only if it still holds what we put there."""
        try:
            if self._copied and self.clipboard_get() == self._copied:
                self.clipboard_clear()
        except Exception:
            pass
        self._copied = ""

    def wipe(self) -> None:
        self.clear_clipboard()
        self._cancel(self._hide_job)
        self._cancel(self._clip_job)
        self._secret = self._uri = ""
        try:
            self.entry.configure(state="normal")
            self.entry.delete(0, "end")
        except Exception:
            pass

    def _cancel(self, job) -> None:
        if job is not None:
            try:
                self.after_cancel(job)
            except Exception:
                pass


class LoginMFADialog(ctk.CTkToplevel):
    """Startup Email + MFA gate. A successful sign-in also unlocks that user's vault."""

    def __init__(self, parent, auth_mgr: AuthManager, vault: CredentialVault,
                 settings: RuntimeSettings | None = None, paths: Paths | None = None):
        super().__init__(parent)
        self.auth_mgr = auth_mgr
        self.vault = vault
        self.settings = settings or RuntimeSettings()
        self.paths = paths or Paths.default()
        self.authenticated_user: str | None = None
        self._secret_widget: SecretReveal | None = None

        self.title("Uptime Funk — Sign-In & MFA")
        self.geometry("470x680")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        ctk.CTkLabel(self, text="Uptime Funk Secure Sign-In",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(18, 4))
        ctk.CTkLabel(self, text="Sign in with your email, password and authenticator code.\n"
                                "Your password also unlocks your encrypted SSH credential vault.",
                     text_color=theme.MUTED, font=ctk.CTkFont(size=12)).pack(pady=(0, 12))

        self.email_ent = ctk.CTkEntry(self, placeholder_text="Email (e.g. alex@company.com)")
        self.email_ent.pack(fill="x", padx=32, pady=5)
        self.pw_ent = ctk.CTkEntry(self, placeholder_text="Password (min 10 characters)", show=MASK)
        self.pw_ent.pack(fill="x", padx=32, pady=5)
        self.pw2_ent = ctk.CTkEntry(self, placeholder_text="Confirm password (registration only)", show=MASK)
        self.pw2_ent.pack(fill="x", padx=32, pady=5)
        self.otp_ent = ctk.CTkEntry(self, placeholder_text="6-digit authenticator code")
        self.otp_ent.pack(fill="x", padx=32, pady=5)
        self.otp_ent.bind("<Return>", lambda _e: self._handle_signin())

        self.status_lbl = ctk.CTkLabel(self, text="", text_color=theme.ERROR, wraplength=400)
        self.status_lbl.pack(pady=(4, 6))
        if auth_mgr.load_warning:
            self.status_lbl.configure(text=auth_mgr.load_warning, text_color=theme.WARN)

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=32, pady=6)
        btn_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(btn_row, text="Sign In (MFA)", fg_color=theme.BTN_PRIMARY,
                      command=self._handle_signin).grid(row=0, column=0, padx=(0, 6), sticky="ew")
        self.register_btn = ctk.CTkButton(btn_row, text="Register + Setup 2FA", fg_color=theme.BTN_TEAL,
                                          command=self._handle_register)
        self.register_btn.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        self.guest_btn = ctk.CTkButton(self, text="Continue as Guest (no saved passwords)",
                                       fg_color=theme.BTN_NEUTRAL, command=self._handle_guest)
        self.guest_btn.pack(fill="x", padx=32, pady=(2, 0))
        self._apply_bootstrap_state()

        self.mfa_box = ctk.CTkTextbox(self, height=110, font=ctk.CTkFont(family=MONO_FONT, size=11))
        self.mfa_box.pack(fill="x", padx=32, pady=(8, 4))
        self._set_mfa_info(
            "First time? Enter your email, choose a password, type it again in\n"
            "'Confirm password' and click 'Register + Setup 2FA'. You will get a\n"
            "key for Google/Microsoft Authenticator, Authy, 1Password, etc."
        )
        self.secret_holder = ctk.CTkFrame(self, fg_color="transparent")
        self.secret_holder.pack(fill="x", padx=32, pady=(0, 10))
        self.after(150, self._focus_self)

    # ---- helpers -----------------------------------------------------
    def _apply_bootstrap_state(self) -> None:
        """Self-registration and guest mode exist only to set up a brand-new installation.

        Once any account exists, new accounts are created by an administrator and guest mode
        is closed, so neither can be used to get around roles.
        """
        accounts = self.auth_mgr.has_accounts()
        if accounts:
            self.register_btn.configure(state="disabled", text="Ask an admin for an account")
            self.pw2_ent.configure(placeholder_text="(not needed to sign in)")
        if self.settings.guest_disabled:                       # admins can force sign-in
            self.guest_btn.configure(state="disabled", text="Guest mode disabled by administrator")
        elif accounts:
            self.guest_btn.configure(state="disabled", text="Guest mode is off: accounts exist on this computer")

    def _focus_self(self):
        try:
            self.lift()
            self.grab_set()
            self.email_ent.focus_set()
        except Exception:
            pass

    def _set_mfa_info(self, text: str):
        self.mfa_box.configure(state="normal")
        self.mfa_box.delete("1.0", "end")
        self.mfa_box.insert("1.0", text)
        self.mfa_box.configure(state="disabled")

    def _status(self, text: str, color: str = theme.ERROR):
        self.status_lbl.configure(text=text, text_color=color)

    def _drop_secret_widget(self):
        if self._secret_widget is not None:
            self._secret_widget.wipe()
            self._secret_widget.destroy()
            self._secret_widget = None

    # ---- actions -----------------------------------------------------
    def _handle_register(self):
        email = self.email_ent.get().strip()
        pw = self.pw_ent.get()
        if pw != self.pw2_ent.get():
            self._status("Passwords do not match.")
            return
        try:
            secret, uri = self.auth_mgr.create_account(email, pw)
        except (ValueError, PermissionError) as exc:
            self._status(str(exc))
            return
        except OSError as exc:
            self._status(f"Could not save account: {exc}")
            return
        self._status("Account created. Add the key below to your authenticator app (Reveal or Copy it), "
                     "then enter the 6-digit code it shows and click Sign In.", theme.OK)
        self._set_mfa_info(f"Account: {email}\nThe setup key is hidden by default. Use 'Copy Key' to paste it into your\n"
                           "authenticator app, or 'Copy URI' for apps that accept an otpauth link.")
        self._drop_secret_widget()
        self._secret_widget = SecretReveal(self.secret_holder, "Authenticator setup key (shown once)", secret, uri)
        self._secret_widget.pack(fill="x")
        self.otp_ent.delete(0, "end")
        self.otp_ent.focus_set()
        self._apply_bootstrap_state()

    def _handle_signin(self):
        email = self.email_ent.get().strip()
        pw = self.pw_ent.get()
        ok, msg = self.auth_mgr.verify_login(email, pw, self.otp_ent.get().strip())
        if not ok:
            self._status(msg)
            return
        if not self.vault.unlock_or_init(pw, path=CredentialVault.path_for_user(email, self.paths.vault_dir),
                                         legacy_path=self.paths.legacy_vault):
            self._status(f"MFA passed, but the vault could not be opened. {self.vault.last_error}")
            return
        self.authenticated_user = email.lower()
        self._finish()

    def _handle_guest(self):
        if self.settings.guest_disabled or self.auth_mgr.has_accounts():
            return
        if not messagebox.askyesno(
            "Continue as Guest",
            "Guest mode has no account or 2FA.\n\n"
            "• Device passwords are kept in memory only and forgotten when you close the app\n"
            "• Nothing is saved to the encrypted vault\n"
            "• Config backups are saved as PLAIN TEXT files\n"
            "• Anyone who can open this app on this computer can use it\n\nContinue?",
        ):
            return
        self.vault.unlock_ephemeral()
        self.authenticated_user = GUEST_USER
        self._finish()

    def _on_cancel(self):
        self.authenticated_user = None
        self._finish()

    def _finish(self):
        """Clear every sensitive widget buffer, then close."""
        self._drop_secret_widget()
        for entry in (self.pw_ent, self.pw2_ent, self.otp_ent):
            entry.delete(0, "end")
        self.destroy()


class CredentialDialog(ctk.CTkToplevel):
    """Masked SSH credential prompt; never displays passwords."""

    def __init__(self, parent, title: str, default_user: str = "admin",
                 prompt_secret: bool = False, offer_apply_all: bool = False):
        super().__init__(parent)
        self._title = title
        self.title(title)
        self.geometry("400x295")
        self.resizable(False, False)
        self.transient(parent)
        self.after(150, self._late_init)
        self.after(300, lambda: self.title(self._title))   # work around icon/title reset on Windows
        self.result = None

        ctk.CTkLabel(self, text="Encrypted Vault SSH Credentials",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(pady=(14, 2))
        ctk.CTkLabel(self, text="Passwords are encrypted immediately and never shown.",
                     text_color=theme.MUTED, font=ctk.CTkFont(size=11)).pack(pady=(0, 8))

        self.user_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.user_entry.insert(0, default_user or "admin")
        self.user_entry.pack(fill="x", padx=24, pady=4)
        self.pass_entry = ctk.CTkEntry(self, placeholder_text="SSH Password", show=MASK)
        self.pass_entry.pack(fill="x", padx=24, pady=4)

        self.secret_entry = None
        if prompt_secret:
            self.secret_entry = ctk.CTkEntry(self, placeholder_text="Enable Secret (optional)", show=MASK)
            self.secret_entry.pack(fill="x", padx=24, pady=4)

        self.apply_all_var = ctk.BooleanVar(value=False)
        if offer_apply_all:
            ctk.CTkCheckBox(self, text="Save to vault for all remaining devices",
                            variable=self.apply_all_var).pack(padx=24, pady=(6, 0), anchor="w")

        self.pass_entry.bind("<Return>", lambda _e: self._on_ok())
        ctk.CTkButton(self, text="Encrypt & Connect", command=self._on_ok).pack(pady=(12, 10))

    def _late_init(self):
        try:
            self.lift()
            self.grab_set()
            self.pass_entry.focus_set()
        except Exception:
            pass

    def _on_ok(self):
        pwd = self.pass_entry.get()
        if not pwd:
            return
        self.result = {
            "username": self.user_entry.get().strip() or "admin",
            "password": pwd,
            "secret": self.secret_entry.get() if self.secret_entry else "",
            "apply_all": bool(self.apply_all_var.get()),
        }
        self.pass_entry.delete(0, "end")                    # clear widget buffers immediately
        if self.secret_entry:
            self.secret_entry.delete(0, "end")
        self.destroy()


class FormDialog(ctk.CTkToplevel):
    """Small modal form. ``fields`` = ``[(key, label, default, secret?)]``; ``result`` is a dict or None."""

    def __init__(self, parent, title: str, fields, ok_text: str = "OK", note: str = ""):
        super().__init__(parent)
        self.title(title)
        self.result: dict | None = None
        self._entries: dict = {}
        if note:
            ctk.CTkLabel(self, text=note, wraplength=380, justify="left", text_color=theme.MUTED).pack(
                padx=14, pady=(10, 2), anchor="w")
        for key, label, default, secret in fields:
            ctk.CTkLabel(self, text=label).pack(anchor="w", padx=14, pady=(8, 0))
            ent = ctk.CTkEntry(self, width=360, show=MASK if secret else "")
            if default not in (None, ""):
                ent.insert(0, str(default))
            ent.pack(padx=14, pady=(2, 0))
            self._entries[key] = ent
        ctk.CTkButton(self, text=ok_text, command=self._ok).pack(pady=12)
        self.after(150, self._late_init)

    def _late_init(self):
        try:
            self.lift()
            self.grab_set()
        except Exception:
            pass

    def _ok(self):
        self.result = {k: e.get() for k, e in self._entries.items()}
        for e in self._entries.values():                    # do not leave secrets in widget buffers
            e.delete(0, "end")
        self.destroy()


def ask_form(parent, title, fields, ok_text="OK", note="") -> dict | None:
    dlg = FormDialog(parent, title, fields, ok_text, note)
    parent.wait_window(dlg)
    return dlg.result
