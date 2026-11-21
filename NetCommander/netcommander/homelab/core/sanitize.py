"""Sensitive-information redaction for structured data, logs and remote output."""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ...redact import redact_secrets

MASK = "********"
_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd|phrase)?|secret|token|api[_-]?key|apikey|private[_-]?key|credential|auth(orization)?|"
    r"cookie|session|sid|otp|totp|community|psk)", re.I)
_INLINE = (
    re.compile(r"(?i)(authorization:\s*)(?:\S+\s+)?\S+"),
    re.compile(r"(?i)(PVEAPIToken=)[^\s'\"]+"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)([?&](?:_sid|sid|token|api_key|apikey|passwd|password)=)[^&\s]+"),
)
_URL_PASSWORD = re.compile(r"(?i)(://[^:/\s@]+:)[^@/\s]+(@)")


def is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY.search(key or ""))


def redact_text(text: str) -> str:
    """Mask secrets in free text: device-config secrets plus HTTP auth headers, tokens and URL passwords."""
    out = redact_secrets(text or "")
    for pat in _INLINE:
        out = pat.sub(lambda m: m.group(1) + MASK, out)
    return _URL_PASSWORD.sub(lambda m: m.group(1) + MASK + m.group(2), out)


def redact_mapping(data: Any, depth: int = 0) -> Any:
    """Deep copy of ``data`` with values under sensitive-looking keys masked."""
    if depth > 20:
        return MASK
    if isinstance(data, Mapping):
        out = {}
        for k, v in data.items():
            if is_sensitive_key(str(k)) and not str(k).endswith("_ref") and v not in (None, "", False):
                out[k] = MASK
            else:
                out[k] = redact_mapping(v, depth + 1)
        return out
    if isinstance(data, (list, tuple)):
        return [redact_mapping(v, depth + 1) for v in data]
    if isinstance(data, str):
        return redact_text(data) if len(data) < 100_000 else data
    return data
