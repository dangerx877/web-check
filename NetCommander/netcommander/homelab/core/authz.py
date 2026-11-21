"""Explicit authorization for anything that changes infrastructure.

Policy (enforced here, used by the platform, API and CLI alike):

1. Discovery and monitoring are read-only and need only :attr:`Permission.VIEW` / ``DISCOVER``.
2. Every action declares a **risk**: ``read_only``, ``change`` or ``destructive``.
3. The caller's role must hold the action's permission (RBAC, :mod:`netcommander.rbac`).
4. ``change`` and ``destructive`` actions additionally need an explicit confirmation: the first
   attempt raises :class:`AuthorizationRequired` with a one-time token bound to *(user, action,
   target, parameters)* that expires after ``ttl`` seconds; repeating the call with the token performs
   exactly that action once. A token cannot be reused, transferred to another user, or applied to a
   different target or parameter set.
5. Every grant, denial and confirmation is written to the tamper-evident audit log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ...rbac import Permission, PermissionDenied, Role, require
from .errors import AuthorizationRequired

RISKS = ("read_only", "change", "destructive")


@dataclass(frozen=True)
class Action:
    name: str                      # e.g. "vm.stop"
    permission: Permission
    risk: str = "read_only"
    target: str = ""
    params: Mapping[str, Any] | None = None
    description: str = ""

    def digest(self) -> str:
        body = json.dumps({"n": self.name, "t": self.target, "p": self.params or {}}, sort_keys=True, default=str)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


AuditFn = Callable[[str, str, str, str, str], Any]        # (actor, action, target, outcome, detail)


class ActionGuard:
    def __init__(self, audit: AuditFn | None = None, ttl: float = 120.0, clock: Callable[[], float] = time.time) -> None:
        self._audit = audit or (lambda *a: None)
        self._ttl, self._clock = ttl, clock
        self._key = secrets.token_bytes(32)
        self._pending: dict[str, tuple[str, str, float]] = {}       # token -> (user, digest, expiry)
        self._lock = threading.Lock()

    def _sign(self, user: str, digest: str, nonce: str) -> str:
        return hmac.new(self._key, f"{user}|{digest}|{nonce}".encode(), hashlib.sha256).hexdigest()[:32]

    def authorize(self, user: str, role: Role | str, action: Action, confirm_token: str = "") -> None:
        """Return normally if ``action`` may run now; otherwise raise PermissionDenied / AuthorizationRequired."""
        if action.risk not in RISKS:
            raise ValueError(f"unknown risk {action.risk!r}")
        try:
            require(role, action.permission)
        except PermissionDenied:
            self._audit(user, f"deny.{action.name}", action.target, "denied", f"needs {action.permission.value}")
            raise
        if action.risk == "read_only":
            return
        digest = action.digest()
        now = self._clock()
        with self._lock:
            for tok, (_u, _d, exp) in list(self._pending.items()):
                if exp < now:
                    self._pending.pop(tok, None)
            if confirm_token:
                rec = self._pending.pop(confirm_token, None)
                if rec and rec[0] == user and hmac.compare_digest(rec[1], digest) and rec[2] >= now:
                    self._audit(user, f"confirm.{action.name}", action.target, "ok", action.risk)
                    return
                self._audit(user, f"confirm.{action.name}", action.target, "denied", "invalid or expired token")
                raise AuthorizationRequired("The confirmation is invalid or expired; confirm the action again.")
            nonce = secrets.token_hex(8)
            token = f"{nonce}.{self._sign(user, digest, nonce)}"
            self._pending[token] = (user, digest, now + self._ttl)
        raise AuthorizationRequired(
            f"{action.description or action.name} on {action.target or 'the target'} is a {action.risk} action "
            "and needs explicit confirmation.",
            token=token,
            details={"action": action.name, "target": action.target, "risk": action.risk,
                     "expires_in": int(self._ttl)})
