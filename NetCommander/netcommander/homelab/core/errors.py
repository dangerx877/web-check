"""Exception types shared by the homelab modules (the API maps them to HTTP status codes)."""
from __future__ import annotations

from typing import Any


class HomelabError(Exception):
    """Base class. ``str(exc)`` is always safe to show to a user (no secrets)."""


class ValidationError(HomelabError, ValueError):
    """Bad input. ``problems`` lists every issue found, not just the first."""

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        super().__init__(message)
        self.problems = list(problems or [message])


class ConfigError(ValidationError):
    pass


class NotFound(HomelabError, KeyError):
    def __str__(self) -> str:                      # KeyError would add quotes
        return str(self.args[0]) if self.args else "not found"


class IntegrationError(HomelabError):
    """A remote system could not be reached or answered with an error."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AuthorizationRequired(HomelabError):
    """A change/destructive action needs explicit confirmation (or an approval).

    ``token`` is a short-lived confirmation token bound to the user, action, target and parameters;
    repeating the call with it authorises exactly that action once.
    """

    def __init__(self, message: str, token: str = "", details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.token = token
        self.details = dict(details or {})
