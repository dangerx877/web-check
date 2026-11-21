"""Shared infrastructure used by every homelab module."""
from .errors import (
    AuthorizationRequired,
    ConfigError,
    IntegrationError,
    NotFound,
    ValidationError,
)

__all__ = ["AuthorizationRequired", "ConfigError", "IntegrationError", "NotFound", "ValidationError"]
