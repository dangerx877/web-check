"""Encrypted storage for integration secrets (API tokens, NAS passwords, SSH passwords, SMTP...).

Secrets are encrypted with the signed-in user's :class:`~netcommander.security.CredentialVault`
data key (Fernet / AES-128-CBC + HMAC-SHA256; the key itself is wrapped by a PBKDF2-derived key from
the account password). Only the ciphertext is written to ``homelab_secrets.json`` (owner-only,
atomic writes, cross-process lock). Everything else in the platform stores a *reference*
(``secret_ref``) and resolves it at the moment a connection is opened.

A guest session (ephemeral vault) keeps secrets in memory only and never writes them to disk.
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from ...filelock import FileLock
from ...security import CredentialVault, _write_private
from .errors import NotFound, ValidationError

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")


class SecretStore:
    def __init__(self, path: Path | str, vault: CredentialVault) -> None:
        self.path = Path(path)
        self.vault = vault
        self._lock = threading.RLock()
        self._flock = FileLock(self.path)
        self._memory: dict[str, str] = {}            # guest sessions only (ciphertext under the throw-away key)

    @property
    def persistent(self) -> bool:
        return not self.vault.ephemeral

    @staticmethod
    def validate_ref(ref: str) -> str:
        if not isinstance(ref, str) or not _REF.match(ref):
            raise ValidationError("A secret reference may use letters, digits and _ . : @ - (max 128).")
        return ref

    def _read(self) -> dict[str, str]:
        if not self.persistent:
            return dict(self._memory)
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise OSError(f"secret store {self.path} is unreadable: {exc}") from exc
        return {str(k): str(v) for k, v in (data.get("secrets") or {}).items()} if isinstance(data, dict) else {}

    def _write(self, items: dict[str, str]) -> None:
        if not self.persistent:
            self._memory = dict(items)
            return
        _write_private(self.path, json.dumps({"format": "netcommander-secrets", "version": 1,
                                              "secrets": items}, indent=2, sort_keys=True))

    def put(self, ref: str, value: str) -> None:
        self.validate_ref(ref)
        if not isinstance(value, str) or not value:
            raise ValidationError("A secret cannot be empty.")
        token = self.vault.encrypt_text(value)               # raises RuntimeError when the vault is locked
        with self._lock, self._flock:
            items = self._read()
            items[ref] = token
            self._write(items)

    def get(self, ref: str) -> str:
        with self._lock:
            token = self._read().get(ref)
        if token is None:
            raise NotFound(f"No stored secret named {ref!r}.")
        return self.vault.decrypt_text(token)

    def has(self, ref: str) -> bool:
        with self._lock:
            return ref in self._read()

    def delete(self, ref: str) -> bool:
        with self._lock, self._flock:
            items = self._read()
            if ref not in items:
                return False
            items.pop(ref)
            self._write(items)
            return True

    def refs(self) -> list[str]:
        """Names only - the API never returns secret values."""
        with self._lock:
            return sorted(self._read())
