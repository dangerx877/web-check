"""Best-effort secret scrubbing for logs, audit details and exported diffs."""
from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # HPE ProCurve first: "password manager user-name x sha1 <hash>" (whole tail is secret material)
    (re.compile(r"(?im)^(\s*password\s+(?:manager|operator)\b).*$"), r"\1 <redacted>"),
    (re.compile(r"(?im)^(\s*username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:secret|password)(?:\s+\d+)?)\s+\S+"), r"\1 <redacted>"),
    # Cisco-style: "enable secret 5 $1$...", "username x password 7 0822...", "snmp-server community foo"
    (re.compile(r"(?im)^(\s*(?:enable\s+(?:secret|password)|username\s+\S+\s+(?:secret|password)|"
                r"password|secret|key|key-string|pre-shared-key|tacacs-server\s+key|radius-server\s+key|"
                r"snmp-server\s+community|snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+\S+|"
                r"(?:auth|priv)(?:-password|-key)?)\b(?:\s+\d+)?)\s+\S+(.*)$"), r"\1 <redacted>\2"),
    # Juniper-style: encrypted-password "$9$..."; authentication-key "..."
    (re.compile(r'(?i)((?:encrypted-password|authentication-key|secret|pre-shared-key\s+ascii-text)\s+)"?[^";\s]+"?'), r"\1<redacted>"),
    # generic key=value / key: value
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|community|auth[_-]?pass|priv[_-]?pass)\b(\s*[=:]\s*)\S+"), r"\1\2<redacted>"),
    # HPE ProCurve: "password manager user-name x sha1 <hash>", radius/tacacs "... key <k>"
    (re.compile(r"(?im)^(\s*(?:radius|tacacs)-server\s+host\s+\S+.*?\bkey\s+)\S+"), r"\1<redacted>"),
    # Nokia SR OS / SR Linux and Dell OS10 quoted or hashed secrets
    (re.compile(r'(?i)\b(hash2?-key|hashed-password|authentication-key|private-key|password|community)(\s+)"[^"]*"'), r'\1\2"<redacted>"'),
    (re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <redacted>"),
]


def redact_secrets(text: str) -> str:
    for rx, repl in _PATTERNS:
        text = rx.sub(repl, text)
    return text
