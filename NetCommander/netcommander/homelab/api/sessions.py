"""Server-side web sessions.

* 256-bit random session ids; only their SHA-256 is kept in memory, so a memory dump of the session
  table cannot be replayed as cookies.
* Idle timeout and absolute lifetime (``api.session_idle_minutes`` / ``api.session_max_hours``).
* A per-session CSRF token that must accompany every state-changing request (``X-CSRF-Token``).
* Administrators can list and revoke sessions; signing out revokes immediately.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ...rbac import Role


@dataclass
class Session:
    key: str                      # sha256(session id)
    user: str
    role: Role
    csrf: str
    created: float
    last_seen: float
    remote: str = ""
    user_agent: str = ""
    must_change_password: bool = False
    id: str = field(default_factory=lambda: secrets.token_hex(6))       # public handle for admin views

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "user": self.user, "role": self.role.value, "created": self.created,
                "last_seen": self.last_seen, "remote": self.remote, "user_agent": self.user_agent[:120]}


def _h(sid: str) -> str:
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


class SessionManager:
    def __init__(self, idle_seconds: float = 900, max_seconds: float = 8 * 3600,
                 clock: Callable[[], float] = time.time) -> None:
        self.idle, self.max, self._clock = idle_seconds, max_seconds, clock
        self._lock = threading.Lock()
        self._by_key: dict[str, Session] = {}

    def create(self, user: str, role: Role, remote: str = "", user_agent: str = "",
               must_change_password: bool = False) -> tuple[str, Session]:
        sid = secrets.token_urlsafe(32)
        now = self._clock()
        s = Session(_h(sid), user, role, secrets.token_urlsafe(24), now, now, remote, user_agent, must_change_password)
        with self._lock:
            self._by_key[s.key] = s
        return sid, s

    def get(self, sid: str | None, touch: bool = True) -> Session | None:
        if not sid:
            return None
        now = self._clock()
        with self._lock:
            s = self._by_key.get(_h(sid))
            if s is None:
                return None
            if now - s.last_seen > self.idle or now - s.created > self.max:
                self._by_key.pop(s.key, None)
                return None
            if touch:
                s.last_seen = now
            return s

    @staticmethod
    def csrf_ok(s: Session, token: str | None) -> bool:
        return bool(token) and hmac.compare_digest(s.csrf, token or "")

    def revoke(self, sid: str) -> bool:
        with self._lock:
            return self._by_key.pop(_h(sid), None) is not None

    def revoke_id(self, public_id: str) -> bool:
        with self._lock:
            for k, s in list(self._by_key.items()):
                if s.id == public_id:
                    self._by_key.pop(k)
                    return True
        return False

    def revoke_user(self, user: str) -> int:
        with self._lock:
            keys = [k for k, s in self._by_key.items() if s.user == user]
            for k in keys:
                self._by_key.pop(k)
            return len(keys)

    def list(self) -> list[dict[str, Any]]:
        now = self._clock()
        with self._lock:
            for k, s in list(self._by_key.items()):
                if now - s.last_seen > self.idle or now - s.created > self.max:
                    self._by_key.pop(k)
            return [s.public() for s in self._by_key.values()]
