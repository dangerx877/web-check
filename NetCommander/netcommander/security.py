"""Secrets handling: atomic private writes, the encrypted vault and MFA accounts.

Concurrency model
-----------------
``CredentialVault`` and ``AuthManager`` each own a private ``threading.RLock``
that guards every read and write of their in-memory state. Mutations are
*transactional*: the new state is persisted first and only then published to
memory, so a failed disk write never leaves memory and disk disagreeing.
No lock in this package is ever held while acquiring another one.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, NamedTuple

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from . import BRAND
from .config import (
    DEFAULT_AUTH_PATH,
    DEFAULT_VAULT_PATH,
    KDF_ITERATIONS,
    LEGACY_KDF_ITERATIONS,
    MAX_FREE_LOGIN_ATTEMPTS,
    VAULT_DIR,
)
from .filelock import FileLock

__all__ = [
    "AuthManager", "CredentialVault", "_write_private", "change_account_password",
    "credentials_from_env", "safe_filename",
]

log = logging.getLogger(__name__)


# ======================================================================
# File helpers
# ======================================================================
def _write_private(path: Path | str, text: str) -> None:
    """Atomic write with owner-only permissions (where the OS supports them).

    The data goes to a uniquely named temp file in the same directory, is
    flushed to disk, then ``os.replace``d over the target. A crash or an error
    therefore never leaves a half-written file, and the temp file is removed.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.I)


def safe_filename(name: str) -> str:
    """Make a device name safe to use as a single path component on every OS.

    Besides stripping separators and traversal, names that Windows reserves
    (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without an extension) get a
    prefix, because a device called "CON" would otherwise be unwritable there.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "").strip("._")
    if not cleaned:
        return "device"
    if _WINDOWS_RESERVED.match(cleaned):
        cleaned = f"_{cleaned}"
    return cleaned


def credentials_from_env(env: Mapping[str, str] | None = None) -> tuple[str, str, str] | None:
    """(username, password, enable) from NET_SSH_*; None when NET_SSH_PASS is unset.

    The username may be empty, meaning "use each device's own username".
    """
    env = os.environ if env is None else env
    password = env.get("NET_SSH_PASS", "")
    if not password:
        return None
    return env.get("NET_SSH_USER", ""), password, env.get("NET_SSH_ENABLE", "")


# ======================================================================
# Encrypted Credential Vault (no plaintext passwords at rest or in the UI)
# ======================================================================
VAULT_VERSION = 3
EXPORT_FORMAT = "netcommander-vault-export"


class _Loaded(NamedTuple):
    salt: bytes
    iterations: int
    kek_key: bytes          # urlsafe-b64 key derived from the master password
    dek_key: bytes          # urlsafe-b64 key that encrypts entries AND config backups
    entries: dict
    legacy: bool            # True for pre-v3 files, where the password-derived key IS the data key


class CredentialVault:
    """Encrypts SSH passwords and enable secrets (PBKDF2 + Fernet/AES).

    Format v3 uses *key wrapping*: a random data key (DEK) encrypts the entries and
    the ``.cfg.enc`` backups; the DEK is stored encrypted under a key derived from
    the master password (KEK). Changing the password only re-wraps the DEK, so
    existing backups stay readable. Older (v1/v2) vaults, where the password-derived
    key was the data key, are upgraded in place on first unlock and keep that same
    key as their DEK - nothing already encrypted becomes unreadable.

    Thread-safe. In guest mode (:meth:`unlock_ephemeral`) nothing is ever written to
    disk and the key is a random throw-away.
    """

    MIN_PASSWORD_LEN = 10

    def __init__(self, vault_path: Path = DEFAULT_VAULT_PATH, iterations: int = KDF_ITERATIONS):
        self.vault_path = Path(vault_path)
        self.last_error = ""
        self.ephemeral = False
        self._target_iterations = int(iterations)
        self._lock = threading.RLock()
        self._salt: bytes = secrets.token_bytes(16)
        self._iterations = self._target_iterations
        self._kek_key: bytes | None = None
        self._dek_key: bytes | None = None
        self._fernet: Fernet | None = None            # data Fernet built from the DEK
        # device_name -> {"username": str, "password_enc": str, "secret_enc": str}
        self._entries: dict[str, dict[str, str]] = {}

    # ---- construction helpers ---------------------------------------
    @staticmethod
    def path_for_user(email: str, vault_dir: Path = VAULT_DIR) -> Path:
        digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:16]
        return Path(vault_dir) / f"{digest}.enc"

    @staticmethod
    def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
        dk = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, iterations, dklen=32)
        return base64.urlsafe_b64encode(dk)

    @staticmethod
    def _derive_fernet(master_password: str, salt: bytes, iterations: int) -> Fernet:
        return Fernet(CredentialVault._derive_key(master_password, salt, iterations))

    # ---- state -------------------------------------------------------
    @property
    def iterations(self) -> int:
        """Work factor protecting the data key (the KEK's PBKDF2 rounds)."""
        with self._lock:
            return self._iterations

    @property
    def unlocked(self) -> bool:
        with self._lock:
            return self._fernet is not None

    def _load(self, path: Path, master_password: str) -> _Loaded:
        """Decrypt `path`. Raises InvalidToken / ValueError / KeyError / OSError.

        Pure with respect to ``self``: the caller decides whether to adopt the result.
        """
        blob = json.loads(path.read_text(encoding="utf-8"))
        salt = base64.b64decode(blob["salt"])
        iterations = int(blob.get("iterations", LEGACY_KDF_ITERATIONS))
        kek_key = self._derive_key(master_password, salt, iterations)
        if int(blob.get("version", 1)) >= 3:
            dek_key = Fernet(kek_key).decrypt(blob["wrapped_key"].encode("ascii"))
            legacy = False
        else:
            dek_key, legacy = kek_key, True
        entries = json.loads(Fernet(dek_key).decrypt(blob["ciphertext"].encode("utf-8")).decode("utf-8"))
        if not isinstance(entries, dict):
            raise ValueError("vault payload is not a dictionary")
        return _Loaded(salt, iterations, kek_key, dek_key, entries, legacy)

    def _adopt(self, loaded: _Loaded) -> None:
        self._salt, self._iterations = loaded.salt, loaded.iterations
        self._kek_key, self._dek_key = loaded.kek_key, loaded.dek_key
        self._fernet = Fernet(loaded.dek_key)
        self._entries = loaded.entries

    def _new_kek(self, master_password: str) -> tuple[bytes, bytes, int]:
        salt = secrets.token_bytes(16)
        return salt, self._derive_key(master_password, salt, self._target_iterations), self._target_iterations

    def _rewrap(self, master_password: str) -> None:
        """Protect the (unchanged) data key with a fresh salt at the current work factor."""
        self._salt, self._kek_key, self._iterations = self._new_kek(master_password)

    def unlock_or_init(
        self,
        master_password: str,
        path: Path | None = None,
        legacy_path: Path | None = None,
    ) -> bool:
        """Unlock this user's vault, migrate a legacy vault.enc, or create a new vault.

        Returns False (with ``last_error`` set and the vault left locked) on a wrong
        password, a corrupt file, or an unwritable location. An existing vault is
        never overwritten by a failed unlock.
        """
        with self._lock:
            self.last_error = ""
            self.ephemeral = False
            if path is not None:
                self.vault_path = Path(path)

            if self.vault_path.exists():
                return self._unlock_existing(master_password)

            if legacy_path is not None and Path(legacy_path).exists():
                try:
                    loaded = self._load(Path(legacy_path), master_password)
                    self._adopt(loaded)
                    self._rewrap(master_password)
                    self._persist(self._entries)           # migrate into the per-user location (v3)
                    return True
                except OSError as exc:
                    self._reset()
                    self.last_error = f"Could not migrate the legacy vault: {exc}"
                    return False
                except (InvalidToken, ValueError, KeyError, TypeError):
                    self._reset()                          # belongs to someone else - start fresh

            return self._create_new(master_password)

    def unlock_existing(self, master_password: str, path: Path | None = None) -> bool:
        """Like :meth:`unlock_or_init` but never creates a vault (for headless use)."""
        with self._lock:
            self.last_error = ""
            self.ephemeral = False
            if path is not None:
                self.vault_path = Path(path)
            if not self.vault_path.exists():
                self.last_error = f"No vault found at {self.vault_path}."
                return False
            return self._unlock_existing(master_password)

    def _unlock_existing(self, master_password: str) -> bool:
        try:
            loaded = self._load(self.vault_path, master_password)
        except InvalidToken:
            self.last_error = "Vault password does not match this vault."
            return False
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.last_error = f"Vault file is unreadable or corrupt: {exc}"
            return False
        self._adopt(loaded)
        if loaded.legacy:
            # Upgrade to the wrapped-key format. The data key is kept, so earlier
            # .cfg.enc backups remain readable. A failed write is not fatal: the old
            # file still works and the upgrade is retried on the next save.
            self._rewrap(master_password)
            try:
                self._persist(self._entries)
            except OSError as exc:
                log.warning("vault format upgrade could not be saved yet: %s", exc)
        return True

    def _create_new(self, master_password: str) -> bool:
        self._dek_key = Fernet.generate_key()
        self._fernet = Fernet(self._dek_key)
        self._rewrap(master_password)
        self._entries = {}
        try:
            self._persist(self._entries)
        except OSError as exc:
            self._reset()
            self.last_error = f"Could not create the vault file: {exc}"
            return False
        return True

    def unlock_ephemeral(self) -> None:
        """Guest mode: a throw-away random key, kept in memory only, never saved."""
        with self._lock:
            self.ephemeral = True
            self._dek_key = Fernet.generate_key()
            self._kek_key = None
            self._fernet = Fernet(self._dek_key)
            self._entries = {}

    def close(self) -> None:
        """Forget the keys and all entries held in memory."""
        with self._lock:
            self._reset()

    def _reset(self) -> None:
        self._fernet = None
        self._kek_key = self._dek_key = None
        self._entries = {}

    # ---- persistence -------------------------------------------------
    def _persist(
        self,
        entries: dict[str, dict[str, str]],
        *,
        salt: bytes | None = None,
        kek_key: bytes | None = None,
        iterations: int | None = None,
    ) -> None:
        """Write `entries` to disk (no-op for guests). Raises OSError; memory is untouched."""
        if not self._fernet or self.ephemeral or self._dek_key is None:
            return
        kek_key = kek_key or self._kek_key
        if kek_key is None:
            return
        blob = {
            "version": VAULT_VERSION,
            "iterations": iterations if iterations is not None else self._iterations,
            "salt": base64.b64encode(salt if salt is not None else self._salt).decode("ascii"),
            "wrapped_key": Fernet(kek_key).encrypt(self._dek_key).decode("ascii"),
            "ciphertext": self._fernet.encrypt(json.dumps(entries).encode("utf-8")).decode("utf-8"),
        }
        _write_private(self.vault_path, json.dumps(blob, indent=2))

    def save(self) -> None:
        with self._lock:
            self._persist(self._entries)

    # ---- password change / export / import -----------------------------
    def change_password(self, old_password: str, new_password: str) -> None:
        """Re-wrap the data key under a new master password.

        Raises ValueError (wrong old password / weak new one) or OSError (could not
        write); memory and disk are unchanged on failure. Backups stay readable.
        """
        with self._lock:
            if not self._fernet or self.ephemeral or self._kek_key is None:
                raise RuntimeError("Only a signed-in (non-guest) vault can change its password.")
            current = self._derive_key(old_password, self._salt, self._iterations)
            if not hmac.compare_digest(current, self._kek_key):
                raise ValueError("The current password is incorrect.")
            if len(new_password) < self.MIN_PASSWORD_LEN:
                raise ValueError(f"Password must be at least {self.MIN_PASSWORD_LEN} characters.")
            salt, kek_key, iterations = self._new_kek(new_password)
            self._persist(self._entries, salt=salt, kek_key=kek_key, iterations=iterations)
            self._salt, self._kek_key, self._iterations = salt, kek_key, iterations

    def export_encrypted(self, path: Path | str, passphrase: str) -> Path:
        """Write a passphrase-protected recovery file (credentials AND the backup key).

        Anyone with the file and passphrase can read every stored device password and
        every encrypted config backup: store it offline.
        """
        if len(passphrase) < self.MIN_PASSWORD_LEN:
            raise ValueError(f"Passphrase must be at least {self.MIN_PASSWORD_LEN} characters.")
        with self._lock:
            if not self._fernet or self.ephemeral or self._dek_key is None:
                raise RuntimeError("Only a signed-in (non-guest) vault can be exported.")
            payload = json.dumps({"dek": self._dek_key.decode("ascii"), "entries": self._entries})
            salt = secrets.token_bytes(16)
            key = self._derive_fernet(passphrase, salt, self._target_iterations)
            blob = {
                "format": EXPORT_FORMAT, "version": 1, "iterations": self._target_iterations,
                "salt": base64.b64encode(salt).decode("ascii"),
                "ciphertext": key.encrypt(payload.encode("utf-8")).decode("ascii"),
            }
        _write_private(Path(path), json.dumps(blob, indent=2))
        return Path(path)

    def import_export(
        self, export_path: Path | str, passphrase: str, master_password: str, path: Path | None = None
    ) -> bool:
        """Create a NEW vault at `path` from a recovery file, protected by `master_password`.

        Refuses to overwrite an existing vault. On success the vault is unlocked and
        old ``.cfg.enc`` backups are readable again. Returns False with ``last_error`` set.
        """
        with self._lock:
            self.last_error = ""
            self.ephemeral = False
            if path is not None:
                self.vault_path = Path(path)
            if len(master_password) < self.MIN_PASSWORD_LEN:
                self.last_error = f"Password must be at least {self.MIN_PASSWORD_LEN} characters."
                return False
            if self.vault_path.exists():
                self.last_error = f"A vault already exists at {self.vault_path}; it was not overwritten."
                return False
            try:
                blob = json.loads(Path(export_path).read_text(encoding="utf-8"))
                if blob.get("format") != EXPORT_FORMAT:
                    raise ValueError("not a NetCommander vault export")
                key = self._derive_fernet(passphrase, base64.b64decode(blob["salt"]), int(blob["iterations"]))
                data = json.loads(key.decrypt(blob["ciphertext"].encode("ascii")).decode("utf-8"))
                dek_key = data["dek"].encode("ascii")
                Fernet(dek_key)                                 # validates the key format
                entries = data["entries"]
                if not isinstance(entries, dict):
                    raise ValueError("entries are not a dictionary")
            except InvalidToken:
                self.last_error = "Export passphrase does not match."
                return False
            except (OSError, ValueError, KeyError, TypeError) as exc:
                self.last_error = f"Export file is unreadable or corrupt: {exc}"
                return False
            self._dek_key, self._fernet, self._entries = dek_key, Fernet(dek_key), entries
            self._rewrap(master_password)
            try:
                self._persist(self._entries)
            except OSError as exc:
                self._reset()
                self.last_error = f"Could not write the restored vault: {exc}"
                return False
            return True

    # ---- entries -----------------------------------------------------
    def set_secret(self, device: str, username: str, password: str, secret: str = "") -> None:
        with self._lock:
            if not self._fernet:
                raise RuntimeError("Vault is locked.")
            entry = {
                "username": username or "admin",
                "password_enc": self._fernet.encrypt(password.encode("utf-8")).decode("ascii") if password else "",
                "secret_enc": self._fernet.encrypt(secret.encode("utf-8")).decode("ascii") if secret else "",
            }
            updated = dict(self._entries)
            updated[device] = entry
            self._persist(updated)
            self._entries = updated

    def has_password(self, device: str) -> bool:
        with self._lock:
            return bool(self._entries.get(device, {}).get("password_enc"))

    def devices(self) -> list[str]:
        with self._lock:
            return sorted(self._entries)

    def encrypt_text(self, text: str) -> str:
        with self._lock:
            if not self._fernet:
                raise RuntimeError("Vault is locked.")
            fernet = self._fernet
        return fernet.encrypt(text.encode("utf-8")).decode("ascii")

    def decrypt_text(self, token: str) -> str:
        with self._lock:
            if not self._fernet:
                raise RuntimeError("Vault is locked.")
            fernet = self._fernet
        return fernet.decrypt(token.strip().encode("ascii")).decode("utf-8")

    def get_decrypted(self, device: str) -> tuple[str, str, str]:
        """Returns (username, password, secret); only call right before an SSH connect."""
        with self._lock:
            if not self._fernet or device not in self._entries:
                return ("admin", "", "")
            rec = dict(self._entries[device])
            fernet = self._fernet
        try:
            pwd = fernet.decrypt(rec["password_enc"].encode("ascii")).decode("utf-8") if rec.get("password_enc") else ""
            sec = fernet.decrypt(rec["secret_enc"].encode("ascii")).decode("utf-8") if rec.get("secret_enc") else ""
        except InvalidToken:
            return (rec.get("username") or "admin", "", "")
        return (rec.get("username") or "admin", pwd, sec)

    def clear_device(self, device: str) -> None:
        """Forget a device's stored passwords (keeps its username)."""
        with self._lock:
            if device not in self._entries:
                return
            updated = dict(self._entries)
            updated[device] = {**updated[device], "password_enc": "", "secret_enc": ""}
            self._persist(updated)
            self._entries = updated

    def remove_device(self, device: str) -> None:
        with self._lock:
            if device not in self._entries:
                return
            updated = {k: v for k, v in self._entries.items() if k != device}
            self._persist(updated)
            self._entries = updated


# ======================================================================
# Email + Multi-Factor Authentication (TOTP)
# ======================================================================
class AuthManager:
    """Email registration & login with TOTP 2FA, lockout and replay protection.

    Every state change is committed atomically: the updated record is written to
    disk first and only then published in ``self.users``. If the write fails
    (``OSError``), memory is left exactly as it was and the login attempt is
    refused ("fail closed"), so replay and lockout counters can never be ahead
    of - or behind - what is on disk.

    Several processes (two GUI windows, the CLI, a scheduler service) may share one
    accounts file. Every read-modify-write therefore runs under a cross-process
    :class:`~netcommander.filelock.FileLock` and starts from the file's current
    contents, so one process never overwrites another's role change, lockout
    counter or used-code marker with a stale copy.
    """

    EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    MIN_PASSWORD_LEN = 10
    GENERIC_FAILURE = "Invalid email, password or MFA code."
    RECOVERY_CODE_COUNT = 8
    _RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"        # no 0/O/1/I

    def __init__(
        self,
        auth_path: Path = DEFAULT_AUTH_PATH,
        iterations: int = KDF_ITERATIONS,
        clock: Callable[[], float] = time.time,
        on_event: Callable[[str, str, str, str], None] | None = None,
    ):
        self.auth_path = Path(auth_path)
        self.on_event = on_event           # (action, email, outcome, detail) - e.g. AuditLog.record wrapper
        self.load_warning = ""
        self._iterations = int(iterations)
        self._clock = clock
        self._lock = threading.RLock()
        self._flock = FileLock(self.auth_path)
        self._mtime: int | None = None
        self._readable = True              # False after an I/O error: never overwrite a file we could not read
        self._dummy_salt = secrets.token_bytes(16)       # burns equal time for unknown accounts
        self.users: dict[str, dict] = self._load()

    # ---- persistence -------------------------------------------------
    def _read_disk(self) -> dict[str, dict]:
        """Current file contents. FileNotFoundError -> {}; raises OSError (I/O) or ValueError (damaged)."""
        try:
            mtime = self.auth_path.stat().st_mtime_ns
            text = self.auth_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._mtime = None
            return {}
        data = json.loads(text)
        if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
            raise ValueError("unexpected file structure")
        self._mtime = mtime
        return data

    def _load(self) -> dict[str, dict]:
        try:
            return self._read_disk()
        except OSError as exc:
            # A transient I/O problem (e.g. a Windows sharing violation) is NOT corruption: keep the
            # file where it is and refuse every change until it can be read again.
            self._readable = False
            self.load_warning = f"Accounts file could not be read ({exc}); sign-in is unavailable until it can be."
            log.error("accounts file unreadable: %s", exc)
            return {}
        except ValueError as exc:
            # Never silently overwrite a damaged accounts file - keep a copy.
            stamp = int(self._clock())
            backup = self.auth_path.with_suffix(f".corrupt-{stamp}")
            counter = 1
            while backup.exists():
                backup = self.auth_path.with_suffix(f".corrupt-{stamp}-{counter}")
                counter += 1
            try:
                os.replace(self.auth_path, backup)
                self.load_warning = f"Accounts file was unreadable ({exc}); moved to {backup.name}."
            except OSError:
                self.load_warning = f"Accounts file was unreadable: {exc}"
            return {}

    def _refresh(self, strict: bool = False) -> None:
        """Pick up changes another process wrote since we last looked.

        ``strict`` (used before every change, under the file lock) raises OSError when the file
        cannot be read, so a change is never written on top of data we have not seen. A damaged
        file found later (not at start-up) is left alone and the last good copy is kept.
        """
        try:
            try:
                mtime: int | None = self.auth_path.stat().st_mtime_ns
            except FileNotFoundError:
                mtime = None
            if self._readable and mtime == self._mtime:
                return
            self.users = self._read_disk()
            self._readable = True
            self.load_warning = "" if self.load_warning.startswith("Accounts file could not be read") else self.load_warning
        except OSError as exc:
            if strict:
                raise OSError(f"accounts file could not be read: {exc}") from exc
            log.warning("could not re-read accounts file: %s", exc)
        except ValueError as exc:
            log.error("accounts file changed on disk but is damaged (%s); keeping the last good copy", exc)
            if strict:
                raise OSError(f"accounts file is damaged: {exc}") from exc

    def _commit(self, norm: str, record: dict) -> None:
        """Persist the users table with `record` applied; publish to memory only on success.

        Callers hold ``self._lock`` and ``self._flock`` and have called ``_refresh(strict=True)``.
        """
        if not self._readable:
            raise OSError("accounts file could not be read; refusing to overwrite it")
        candidate = dict(self.users)
        candidate[norm] = record
        _write_private(self.auth_path, json.dumps(candidate, indent=2))
        self.users = candidate
        try:
            self._mtime = self.auth_path.stat().st_mtime_ns
        except OSError:
            self._mtime = None

    # ---- helpers -----------------------------------------------------
    @classmethod
    def valid_email(cls, email: str) -> bool:
        return bool(cls.EMAIL_RX.match((email or "").strip()))

    @staticmethod
    def _derive(password: str, salt: bytes, iterations: int) -> tuple[str, Fernet]:
        """One PBKDF2 run -> (password verifier, Fernet key that protects the TOTP secret)."""
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=64)
        return base64.b64encode(dk[:32]).decode("ascii"), Fernet(base64.urlsafe_b64encode(dk[32:]))

    def role_of(self, email: str) -> str:
        """Role for an account; records created before RBAC existed keep full (admin) access."""
        with self._lock:
            self._refresh()
            rec = self.users.get(email.strip().lower())
            return str(rec.get("role", "admin")) if rec else "viewer"

    def list_users(self) -> list[tuple[str, str]]:
        with self._lock:
            self._refresh()
            return sorted((e, str(r.get("role", "admin"))) for e, r in self.users.items())

    def set_role(self, email: str, role: str) -> None:
        """Change a user's role. Refuses to remove the last admin. Caller enforces MANAGE_USERS."""
        from .rbac import Role
        new = Role.parse_assignable(role)
        norm = email.strip().lower()
        with self._lock, self._flock:
            self._refresh(strict=True)
            rec = self.users.get(norm)
            if not rec:
                raise ValueError("No such user.")
            admins = [e for e, r in self.users.items() if str(r.get("role", "admin")) == "admin"]
            if str(rec.get("role", "admin")) == "admin" and new is not Role.ADMIN and admins == [norm]:
                raise ValueError("Cannot demote the last administrator.")
            work = copy.deepcopy(rec)
            work["role"] = new.value
            self._commit(norm, work)

    def user_exists(self, email: str) -> bool:
        with self._lock:
            self._refresh()
            return email.strip().lower() in self.users

    def has_accounts(self) -> bool:
        """True once any account exists (guest mode and self-registration are then closed)."""
        with self._lock:
            self._refresh()
            return bool(self.users) or not self._readable

    def must_change_password(self, email: str) -> bool:
        """True for an account an administrator created with a temporary password."""
        with self._lock:
            self._refresh()
            return bool(self.users.get(email.strip().lower(), {}).get("must_change_password"))

    # ---- registration ------------------------------------------------
    def create_account(
        self, email: str, password: str, role: str | None = None, *, created_by: str | None = None,
    ) -> tuple[str, str]:
        """Creates an account and returns (totp_secret, provisioning_uri).

        The first account on a machine bootstraps the installation and is always ``admin``
        (self-registration). Every later account must be created by an existing administrator,
        named in ``created_by``; it defaults to ``operator`` and is flagged so its owner is asked
        to replace the temporary password at first sign-in.

        Raises ValueError for invalid input, PermissionError when ``created_by`` is missing or is
        not an administrator, and OSError if the account cannot be saved.
        """
        norm = email.strip().lower()
        if not self.valid_email(norm):
            raise ValueError("Please enter a valid work or personal email address.")
        if len(password) < self.MIN_PASSWORD_LEN:
            raise ValueError(f"Password must be at least {self.MIN_PASSWORD_LEN} characters.")

        with self._lock, self._flock:
            self._refresh(strict=True)
            if norm in self.users:
                raise ValueError("An account for this email already exists. Use Sign In instead.")
            from .rbac import Role
            bootstrap = not self.users
            if bootstrap:
                chosen = Role.ADMIN
            else:
                creator = self.users.get((created_by or "").strip().lower())
                if creator is None or str(creator.get("role", "admin")) != Role.ADMIN.value:
                    raise PermissionError(
                        "Accounts already exist on this computer. Ask an administrator to create yours "
                        "(Account & Security -> Manage Users).")
                chosen = Role.parse_assignable(role or Role.OPERATOR.value)
            salt = secrets.token_bytes(16)
            verifier, totp_key = self._derive(password, salt, self._iterations)
            totp_secret = pyotp.random_base32()
            record = {
                "version": 2,
                "role": chosen.value,
                "email": norm,
                "salt": base64.b64encode(salt).decode("ascii"),
                "iterations": self._iterations,
                "pw_hash": verifier,
                "totp_enc": totp_key.encrypt(totp_secret.encode("ascii")).decode("ascii"),
                "last_totp_step": -1,
                "fails": 0,
                "locked_until": 0,
                "created_at": datetime.fromtimestamp(self._clock()).isoformat(timespec="seconds"),
            }
            if not bootstrap:
                record["created_by"] = (created_by or "").strip().lower()
                record["must_change_password"] = True
            self._commit(norm, record)
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=norm, issuer_name=BRAND)
        return totp_secret, uri

    # ---- login -------------------------------------------------------
    def _match_totp(self, secret: str, code: str, last_step: int) -> int | None:
        """Return the matching time step, or None. Steps already used are rejected (replay)."""
        code = re.sub(r"\s+", "", code or "")
        if not re.fullmatch(r"\d{6}", code):
            return None
        totp = pyotp.TOTP(secret)
        now_step = int(self._clock() // totp.interval)
        for step in (now_step - 1, now_step, now_step + 1):
            if step > last_step and hmac.compare_digest(totp.generate_otp(step), code):
                return step
        return None

    def _record_failure(self, norm: str, work: dict) -> tuple[bool, str]:
        work["fails"] = int(work.get("fails", 0)) + 1
        if work["fails"] >= MAX_FREE_LOGIN_ATTEMPTS:
            delay = min(900, 30 * 2 ** (work["fails"] - MAX_FREE_LOGIN_ATTEMPTS))
            work["locked_until"] = self._clock() + delay
        try:
            self._commit(norm, work)
        except OSError as exc:
            log.warning("could not persist failed-login state: %s", exc)
            return False, f"{self.GENERIC_FAILURE} (This attempt could not be recorded: {exc})"
        return False, self.GENERIC_FAILURE

    def verify_login(self, email: str, password: str, otp_code: str) -> tuple[bool, str]:
        """Check credentials. Every attempt (success, failure, lockout) is reported to ``on_event``;
        passwords and codes are never included."""
        ok, msg = self._verify_login(email, password, otp_code)
        if self.on_event:
            outcome = "ok" if ok else ("locked" if msg.startswith("Too many failed") else "failed")
            detail = "recovery code used" if ok and "recovery code" in msg else ""
            try:
                self.on_event("auth.login", email.strip().lower()[:120], outcome, detail)
            except Exception:                       # auditing must never break sign-in
                log.warning("auth event hook failed")
        return ok, msg

    def _verify_login(self, email: str, password: str, otp_code: str) -> tuple[bool, str]:
        norm = email.strip().lower()
        try:
            with self._lock, self._flock:
                return self._verify_login_locked(norm, password, otp_code)
        except (OSError, TimeoutError) as exc:
            log.error("sign-in state unavailable: %s", exc)
            return False, f"Sign-in is unavailable because account data could not be read ({exc})."

    def _verify_login_locked(self, norm: str, password: str, otp_code: str) -> tuple[bool, str]:
        self._refresh(strict=True)
        rec = self.users.get(norm)
        if not rec:
            # Same message and (roughly) same cost as a wrong password, so neither the
            # reply nor its timing reveals whether an account exists.
            self._derive(password, self._dummy_salt, self._iterations)
            return False, self.GENERIC_FAILURE

        try:
            remaining = float(rec.get("locked_until", 0)) - self._clock()
            if remaining > 0:
                return False, f"Too many failed attempts. Try again in {int(remaining) + 1} seconds."

            work = copy.deepcopy(rec)               # mutate a copy; publish only after the disk write
            salt = base64.b64decode(work["salt"])
            iterations = int(work.get("iterations", LEGACY_KDF_ITERATIONS))
            verifier, totp_key = self._derive(password, salt, iterations)
            if not hmac.compare_digest(str(work["pw_hash"]), verifier):
                return self._record_failure(norm, work)

            if work.get("totp_enc"):
                secret = totp_key.decrypt(work["totp_enc"].encode("ascii")).decode("ascii")
            else:                                   # legacy record: plaintext secret
                secret = work["totp_secret"]
        except InvalidToken:
            return False, "Stored MFA secret is damaged. Remove this account from users_auth.json and register again."
        except (KeyError, ValueError, TypeError):
            return False, "Stored account record is damaged. Remove this account from users_auth.json and register again."

        step = self._match_totp(secret, otp_code, int(work.get("last_totp_step", -1)))
        used_recovery = False
        if step is None:
            used_recovery = self._consume_recovery_code(work, otp_code)
            if not used_recovery:
                return self._record_failure(norm, work)

        work["fails"], work["locked_until"] = 0, 0
        if step is not None:
            work["last_totp_step"] = step
        if work.get("totp_secret") or iterations < self._iterations:
            self._upgrade_record(work, password, secret)
        try:
            self._commit(norm, work)
        except OSError as exc:
            # Fail closed: if the used-code marker cannot be stored, the same code
            # could be replayed after a restart, so do not let this login succeed.
            log.error("could not persist sign-in state: %s", exc)
            return False, f"Sign-in could not be completed because account data could not be saved ({exc})."
        if used_recovery:
            left = len(work["recovery"]["hashes"])
            return True, f"Authenticated with a recovery code ({left} left). Regenerate codes and 2FA from Account."
        return True, "Authenticated"

    def verify_password(self, email: str, password: str) -> tuple[bool, str]:
        """Password-only check for unattended (headless) use, with the same lockout as sign-in.

        A failure counts toward the lockout and a locked account is refused. A success does NOT
        reset the failure counter: otherwise someone who knows the password could use it to clear
        the lockout and keep guessing authenticator codes in the full sign-in.
        """
        norm = email.strip().lower()
        try:
            with self._lock, self._flock:
                self._refresh(strict=True)
                rec = self.users.get(norm)
                if not rec:
                    self._derive(password, self._dummy_salt, self._iterations)
                    ok, msg = False, self.GENERIC_FAILURE
                else:
                    remaining = float(rec.get("locked_until", 0)) - self._clock()
                    if remaining > 0:
                        ok, msg = False, f"Too many failed attempts. Try again in {int(remaining) + 1} seconds."
                    elif self._check_password(rec, password) is None:
                        ok, msg = self._record_failure(norm, copy.deepcopy(rec))
                    else:
                        ok, msg = True, "Password verified"
        except (OSError, TimeoutError) as exc:
            ok, msg = False, f"Account data could not be read ({exc})."
        if self.on_event:
            outcome = "ok" if ok else ("locked" if msg.startswith("Too many failed") else "failed")
            try:
                self.on_event("auth.password_check", norm[:120], outcome, "headless")
            except Exception:
                log.warning("auth event hook failed")
        return ok, msg

    # ---- recovery codes ----------------------------------------------
    @staticmethod
    def _normalize_recovery(code: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", code or "").upper()

    @staticmethod
    def _recovery_hash(salt: bytes, code: str) -> str:
        return hashlib.sha256(salt + AuthManager._normalize_recovery(code).encode("ascii")).hexdigest()

    def _consume_recovery_code(self, work: dict, submitted: str) -> bool:
        """If `submitted` is an unused recovery code, remove it from `work` and return True."""
        norm = self._normalize_recovery(submitted)
        rec = work.get("recovery")
        if len(norm) != 10 or not isinstance(rec, dict):
            return False
        salt = base64.b64decode(rec["salt"])
        candidate = self._recovery_hash(salt, norm)
        match = None
        for i, stored in enumerate(rec["hashes"]):               # compare against all: no early exit
            if hmac.compare_digest(stored, candidate):
                match = i
        if match is None:
            return False
        rec["hashes"].pop(match)
        return True

    def recovery_codes_left(self, email: str) -> int:
        with self._lock:
            self._refresh()
            rec = self.users.get(email.strip().lower(), {}).get("recovery") or {}
            return len(rec.get("hashes", []))

    def _check_password(self, rec: dict, password: str) -> Fernet | None:
        """The record's TOTP-protecting key if `password` is right, else None."""
        try:
            salt = base64.b64decode(rec["salt"])
            iterations = int(rec.get("iterations", LEGACY_KDF_ITERATIONS))
            verifier, key = self._derive(password, salt, iterations)
            return key if hmac.compare_digest(str(rec["pw_hash"]), verifier) else None
        except (KeyError, ValueError, TypeError):
            return None

    def generate_recovery_codes(self, email: str, password: str) -> list[str]:
        """Create a fresh set of single-use codes (replacing any old set).

        Each code can stand in for the authenticator code once, if the phone is lost.
        Only salted hashes are stored; the plain codes are returned this one time.
        Raises ValueError for a wrong password and OSError if the change cannot be saved.
        """
        norm = email.strip().lower()
        with self._lock, self._flock:
            self._refresh(strict=True)
            rec = self.users.get(norm)
            if not rec or self._check_password(rec, password) is None:
                raise ValueError("Incorrect email or password.")
            alphabet = self._RECOVERY_ALPHABET
            codes = ["".join(secrets.choice(alphabet) for _ in range(10)) for _ in range(self.RECOVERY_CODE_COUNT)]
            salt = secrets.token_bytes(16)
            work = copy.deepcopy(rec)
            work["recovery"] = {
                "salt": base64.b64encode(salt).decode("ascii"),
                "hashes": [self._recovery_hash(salt, c) for c in codes],
            }
            self._commit(norm, work)
        return [f"{c[:5]}-{c[5:]}" for c in codes]

    # ---- credential changes ------------------------------------------
    def set_password(self, email: str, old_password: str, new_password: str) -> None:
        """Re-hash the account under a new password (TOTP secret and recovery codes kept).

        Callers normally use :func:`change_account_password`, which also re-wraps the
        vault key and verifies the authenticator code first.
        """
        if len(new_password) < self.MIN_PASSWORD_LEN:
            raise ValueError(f"Password must be at least {self.MIN_PASSWORD_LEN} characters.")
        norm = email.strip().lower()
        with self._lock, self._flock:
            self._refresh(strict=True)
            rec = self.users.get(norm)
            key = self._check_password(rec, old_password) if rec else None
            if rec is None or key is None:
                raise ValueError("The current password is incorrect.")
            secret = (key.decrypt(rec["totp_enc"].encode("ascii")).decode("ascii")
                      if rec.get("totp_enc") else rec["totp_secret"])
            work = copy.deepcopy(rec)
            self._upgrade_record(work, new_password, secret)
            work.pop("must_change_password", None)
            self._commit(norm, work)

    def rotate_totp(self, email: str, password: str) -> tuple[str, str]:
        """Replace the authenticator secret (e.g. after a lost phone). Returns (secret, uri)."""
        norm = email.strip().lower()
        with self._lock, self._flock:
            self._refresh(strict=True)
            rec = self.users.get(norm)
            key = self._check_password(rec, password) if rec else None
            if rec is None or key is None:
                raise ValueError("Incorrect email or password.")
            secret = pyotp.random_base32()
            work = copy.deepcopy(rec)
            work.pop("totp_secret", None)
            work["totp_enc"] = key.encrypt(secret.encode("ascii")).decode("ascii")
            work["last_totp_step"] = -1
            self._commit(norm, work)
        return secret, pyotp.TOTP(secret).provisioning_uri(name=norm, issuer_name=BRAND)

    def admin_reset(self, email: str, temp_password: str, *, reset_by: str) -> tuple[str, str]:
        """An administrator resets another user's sign-in (forgotten password / lost phone).

        Sets a temporary password and a NEW authenticator key, drops recovery codes and clears the
        lockout; the user must change the password at next sign-in. Returns (totp_secret, uri).
        The user's vault was encrypted with the old password, so the caller must set it aside
        (see :meth:`netcommander.services.Services.reset_user`).
        Raises ValueError, PermissionError (not an admin / own account) or OSError.
        """
        from .rbac import Role
        if len(temp_password) < self.MIN_PASSWORD_LEN:
            raise ValueError(f"Password must be at least {self.MIN_PASSWORD_LEN} characters.")
        norm, admin = email.strip().lower(), (reset_by or "").strip().lower()
        if norm == admin:
            raise PermissionError("Use Change Password / Rotate 2FA for your own account.")
        with self._lock, self._flock:
            self._refresh(strict=True)
            actor = self.users.get(admin)
            if actor is None or str(actor.get("role", "admin")) != Role.ADMIN.value:
                raise PermissionError("Only an administrator can reset another user.")
            rec = self.users.get(norm)
            if rec is None:
                raise ValueError("No such user.")
            secret = pyotp.random_base32()
            work = copy.deepcopy(rec)
            self._upgrade_record(work, temp_password, secret)
            work.update({"last_totp_step": -1, "fails": 0, "locked_until": 0, "must_change_password": True,
                         "reset_by": admin})
            work.pop("recovery", None)
            self._commit(norm, work)
        return secret, pyotp.TOTP(secret).provisioning_uri(name=norm, issuer_name=BRAND)

    def _upgrade_record(self, rec: dict, password: str, secret: str) -> None:
        """Re-hash with the current work factor and encrypt a legacy plaintext TOTP secret."""
        salt = secrets.token_bytes(16)
        verifier, totp_key = self._derive(password, salt, self._iterations)
        rec.update({
            "version": 2,
            "salt": base64.b64encode(salt).decode("ascii"),
            "iterations": self._iterations,
            "pw_hash": verifier,
            "totp_enc": totp_key.encrypt(secret.encode("ascii")).decode("ascii"),
        })
        rec.pop("totp_secret", None)


def change_account_password(
    auth: AuthManager,
    vault: CredentialVault,
    email: str,
    old_password: str,
    new_password: str,
    otp_code: str,
) -> None:
    """Change the account password AND re-wrap the vault key, all-or-nothing.

    Requires the current password and a valid authenticator (or recovery) code.
    Raises ValueError (bad input), PermissionError (sign-in check failed) or OSError.
    If the account update fails after the vault was re-wrapped, the vault is rolled back
    so the two can never end up with different passwords.
    """
    if len(new_password) < AuthManager.MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {AuthManager.MIN_PASSWORD_LEN} characters.")
    if new_password == old_password:
        raise ValueError("The new password must differ from the current one.")
    if vault.ephemeral or not vault.unlocked:
        raise RuntimeError("Guest sessions have no account to change.")
    ok, msg = auth.verify_login(email, old_password, otp_code)
    if not ok:
        raise PermissionError(msg)
    vault.change_password(old_password, new_password)
    try:
        auth.set_password(email, old_password, new_password)
    except BaseException:
        try:
            vault.change_password(new_password, old_password)
        except Exception as rollback_exc:                      # pragma: no cover - double fault
            log.critical("vault rollback after failed password change also failed: %s", rollback_exc)
        raise
