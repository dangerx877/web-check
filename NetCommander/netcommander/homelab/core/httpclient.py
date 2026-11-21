"""Minimal JSON-over-HTTP(S) client for integration adapters (stdlib only).

Security defaults
* TLS certificates are verified. For self-signed homelab gear, prefer ``ca_file`` (trust that CA)
  or ``pin_sha256`` (accept exactly one certificate, checked *before* any request or credential is
  sent). ``verify_tls=False`` exists but is reported as insecure in the UI and audit trail.
* Plain ``http://`` is refused unless ``allow_http=True`` (or the host is loopback).
* Error messages never contain request headers, bodies or credentials.

``transport`` is the test seam: ``transport(method, url, headers, body, timeout) -> (status, headers, bytes)``.
A Unix-socket transport is provided for the Docker Engine API.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

from .errors import IntegrationError, ValidationError
from .sanitize import redact_text

Transport = Callable[[str, str, Mapping[str, str], "bytes | None", float], "tuple[int, dict[str, str], bytes]"]
MAX_RESPONSE = 32 * 1024 * 1024


def is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def normalize_fingerprint(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").strip().lower()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that compares the leaf certificate's SHA-256 with a pin right after the handshake."""

    def __init__(self, host: str, port: int | None, pin: str, timeout: float) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._pin = normalize_fingerprint(pin)

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True) if self.sock else None
        got = hashlib.sha256(der or b"").hexdigest()
        if got != self._pin:
            self.close()
            raise IntegrationError(f"TLS certificate fingerprint mismatch (got sha256 {got[:16]}...); "
                                   "nothing was sent. Re-check the device certificate.")


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._socket_path)
        self.sock = s


def stdlib_transport(verify_tls: bool = True, ca_file: str | None = None, pin_sha256: str | None = None,
                     unix_socket: str | None = None, client_cert: str | None = None,
                     client_key: str | None = None) -> Transport:
    def transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None,
                  timeout: float) -> tuple[int, dict[str, str], bytes]:
        u = urllib.parse.urlsplit(url)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        conn: http.client.HTTPConnection
        if unix_socket:
            conn = UnixHTTPConnection(unix_socket, timeout)
        elif u.scheme == "https":
            if pin_sha256:
                conn = _PinnedHTTPSConnection(u.hostname or "", u.port, pin_sha256, timeout)
            else:
                ctx = ssl.create_default_context(cafile=ca_file) if verify_tls else ssl._create_unverified_context()
                if client_cert:                         # mutual TLS (e.g. Docker daemon on tcp://:2376)
                    ctx.load_cert_chain(client_cert, client_key or None)
                conn = http.client.HTTPSConnection(u.hostname or "", u.port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname or "", u.port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=dict(headers))
            resp = conn.getresponse()
            data = resp.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise IntegrationError("response too large")
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()
    return transport


class HttpClient:
    def __init__(self, base_url: str, headers: Mapping[str, str] | None = None, *, verify_tls: bool = True,
                 ca_file: str | None = None, pin_sha256: str | None = None, allow_http: bool = False,
                 timeout: float = 15.0, transport: Transport | None = None, unix_socket: str | None = None,
                 client_cert: str | None = None, client_key: str | None = None) -> None:
        u = urllib.parse.urlsplit(base_url)
        if not unix_socket:
            if u.scheme not in ("http", "https") or not u.hostname:
                raise ValidationError(f"Invalid base URL {base_url!r}: use https://host[:port].")
            if u.scheme == "http" and not allow_http and not is_loopback(u.hostname):
                raise ValidationError("Plain http:// would send credentials unencrypted; use https:// "
                                      "(or explicitly allow http for this integration).")
        self.base_url = base_url.rstrip("/")
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.insecure = not unix_socket and ((not verify_tls and not pin_sha256) or u.scheme == "http")
        self._transport = transport or stdlib_transport(verify_tls, ca_file, pin_sha256, unix_socket,
                                                        client_cert, client_key)

    def url(self, path: str, params: Mapping[str, Any] | None = None) -> str:
        url = self.base_url + ("" if path.startswith("/") else "/") + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
                [(k, v) for k, v in params.items() if v is not None], doseq=True)
        return url

    def request_raw(self, method: str, path: str, *, params: Mapping[str, Any] | None = None,
                    json_body: Any = None, form: Mapping[str, Any] | None = None,
                    headers: Mapping[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        hdrs = {"Accept": "application/json", "User-Agent": "NetCommander-Homelab", **self.headers, **(headers or {})}
        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode("utf-8")
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        url = self.url(path, params)
        try:
            return self._transport(method, url, hdrs, body, self.timeout)
        except IntegrationError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise IntegrationError(f"{method} {redact_text(self.url(path))} failed: "
                                   f"{redact_text(str(exc)) or type(exc).__name__}") from None

    def request(self, method: str, path: str, **kw: Any) -> Any:
        status, _h, data = self.request_raw(method, path, **kw)
        if status >= 400:
            snippet = redact_text(data[:300].decode("utf-8", "replace")).strip()
            raise IntegrationError(f"{method} {path} -> HTTP {status}" + (f": {snippet}" if snippet else ""), status)
        if not data:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except ValueError:
            return data.decode("utf-8", "replace")

    def get(self, path: str, **kw: Any) -> Any:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Any:
        return self.request("POST", path, **kw)
