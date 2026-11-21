"""Alert notifications: log, file, webhook (JSON POST) and e-mail (SMTP with STARTTLS/SSL).

Channels have a minimum severity and the :class:`Notifier` suppresses repeats of the same
``dedup_key`` within a window, so a flapping device cannot flood a phone. A failing channel is logged
and never blocks monitoring. Channel secrets (webhook tokens, SMTP passwords) come from the
SecretStore via references.
"""
from __future__ import annotations

import json
import logging
import smtplib
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from .errors import ValidationError
from .httpclient import HttpClient
from .sanitize import redact_text

log = logging.getLogger(__name__)
LEVELS = {"debug": 0, "info": 1, "warning": 2, "critical": 3}


@dataclass
class Notification:
    title: str
    message: str
    severity: str = "warning"
    target: str = ""
    dedup_key: str = ""
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {"title": self.title, "message": redact_text(self.message), "severity": self.severity,
                "target": self.target, "ts": self.ts}


class Channel(Protocol):
    name: str
    min_severity: str

    def send(self, n: Notification) -> None: ...


class LogChannel:
    def __init__(self, name: str = "log", min_severity: str = "info") -> None:
        self.name, self.min_severity = name, min_severity

    def send(self, n: Notification) -> None:
        log.log(logging.WARNING if LEVELS.get(n.severity, 1) >= 2 else logging.INFO,
                "[%s] %s: %s", n.severity.upper(), n.title, redact_text(n.message))


class FileChannel:
    def __init__(self, path: str, name: str = "file", min_severity: str = "warning") -> None:
        self.path, self.name, self.min_severity = Path(path), name, min_severity

    def send(self, n: Notification) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(n.as_dict()) + "\n")


class WebhookChannel:
    """POST ``{"title","message","severity","target","ts"}`` (works with ntfy, Gotify, Home Assistant, Slack-compatible relays)."""

    def __init__(self, url: str, token: str = "", name: str = "webhook", min_severity: str = "warning",
                 allow_http: bool = False, transport: Any = None) -> None:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.client = HttpClient(url, headers, allow_http=allow_http, transport=transport, timeout=10)
        self.name, self.min_severity = name, min_severity

    def send(self, n: Notification) -> None:
        self.client.post("", json_body=n.as_dict())


class SmtpChannel:
    def __init__(self, host: str, sender: str, recipients: list[str], port: int = 587, username: str = "",
                 password: str = "", security: str = "starttls", name: str = "email",
                 min_severity: str = "critical", smtp_factory: Callable[..., Any] | None = None) -> None:
        if security not in ("starttls", "ssl"):
            raise ValidationError("SMTP security must be 'starttls' or 'ssl' (plaintext SMTP is not supported).")
        if not recipients:
            raise ValidationError("SMTP channel needs at least one recipient.")
        self.host, self.port, self.sender, self.recipients = host, port, sender, recipients
        self.username, self.password, self.security = username, password, security
        self.name, self.min_severity = name, min_severity
        self._factory = smtp_factory

    def send(self, n: Notification) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"[Uptime Funk {n.severity.upper()}] {n.title}"
        msg["From"], msg["To"] = self.sender, ", ".join(self.recipients)
        msg.set_content(redact_text(n.message))
        ctx = ssl.create_default_context()
        if self._factory:
            smtp = self._factory(self.host, self.port)
        elif self.security == "ssl":
            smtp = smtplib.SMTP_SSL(self.host, self.port, context=ctx, timeout=15)
        else:
            smtp = smtplib.SMTP(self.host, self.port, timeout=15)
        with smtp:
            if self.security == "starttls":
                smtp.starttls(context=ctx)
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(msg)


class Notifier:
    def __init__(self, channels: list[Any] | None = None, dedup_window: float = 900.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.channels: list[Any] = list(channels or [LogChannel()])
        self.dedup_window, self._clock = dedup_window, clock
        self._sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self.history: list[dict[str, Any]] = []

    def notify(self, n: Notification) -> list[str]:
        """Deliver to every channel whose threshold is met. Returns the channel names that succeeded."""
        now = self._clock()
        if n.dedup_key:
            with self._lock:
                last = self._sent.get(n.dedup_key)
                if last is not None and now - last < self.dedup_window:
                    return []
                self._sent[n.dedup_key] = now
        delivered = []
        for ch in self.channels:
            if LEVELS.get(n.severity, 1) < LEVELS.get(getattr(ch, "min_severity", "info"), 1):
                continue
            try:
                ch.send(n)
                delivered.append(ch.name)
            except Exception as exc:
                log.warning("notification channel %s failed: %s", getattr(ch, "name", ch), redact_text(str(exc)))
        with self._lock:
            self.history.append({**n.as_dict(), "delivered": delivered})
            del self.history[:-200]
        return delivered
