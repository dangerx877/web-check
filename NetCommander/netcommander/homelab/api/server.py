"""The management HTTP API and web dashboard host (stdlib ``http.server``; no web framework dependency).

Security
* Binds to ``127.0.0.1`` by default. Binding to any other address requires TLS (``api.tls_cert`` /
  ``api.tls_key``) unless ``api.allow_remote_without_tls`` is set explicitly.
* Sign-in = account password + authenticator code through the existing :class:`AuthManager` (lockout,
  replay protection and audit included). The cookie is ``HttpOnly; SameSite=Strict`` (+ ``Secure``
  with TLS).
* State-changing requests need the session's CSRF token **and** a same-origin ``Origin``/``Referer``.
* Strict security headers (CSP without inline script, no framing, no sniffing, no caching of API data).
* Request bodies are size-limited; errors never include stack traces or secrets.
* Every route checks permissions in :class:`HomelabPlatform` (one policy for GUI, CLI and API).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import ssl
import threading
import urllib.parse
from collections.abc import Callable
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ... import __version__
from ...rbac import Permission, PermissionDenied, Role, can
from ...security import AuthManager
from ..core.errors import AuthorizationRequired, ConfigError, IntegrationError, NotFound, ValidationError
from ..platform import Ctx, HomelabPlatform
from .sessions import Session, SessionManager

log = logging.getLogger(__name__)
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
COOKIE = "nc_session"
MAX_BODY = 5 * 1024 * 1024
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".ico": "image/x-icon"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

Handler = Callable[["Request"], Any]


class Request:
    def __init__(self, ctx: Ctx, session: Session, match: re.Match[str], query: dict[str, str], body: Any) -> None:
        self.ctx, self.session, self.match, self.query, self.body = ctx, session, match, query, body

    def arg(self, name: str, default: Any = None, required: bool = False) -> Any:
        if isinstance(self.body, dict) and name in self.body:
            return self.body[name]
        if name in self.query:
            return self.query[name]
        if required:
            raise ValidationError(f"Missing parameter {name!r}.")
        return default

    @property
    def confirm(self) -> str:
        return str(self.arg("confirm", "") or "")


class Routes:
    def __init__(self) -> None:
        self.table: list[tuple[str, re.Pattern[str], Handler]] = []

    def add(self, method: str, pattern: str, fn: Handler) -> None:
        self.table.append((method, re.compile("^" + pattern + "$"), fn))

    def find(self, method: str, path: str) -> tuple[Handler | None, re.Match[str] | None, bool]:
        path_known = False
        for m, pat, fn in self.table:
            mt = pat.match(path)
            if mt:
                path_known = True
                if m == method:
                    return fn, mt, True
        return None, None, path_known


def build_routes(p: HomelabPlatform, sessions: SessionManager) -> Routes:
    r = Routes()

    def viewing(q: Request, perm: Permission, fn: Callable[[], Any]) -> Any:
        p._need(q.ctx, perm)
        return fn()
    ID = r"([A-Za-z0-9_.:@-]{1,128})"

    def session_info(q: Request) -> dict[str, Any]:
        return {"user": q.ctx.user, "role": q.ctx.role.value, "csrf": q.session.csrf,
                "permissions": sorted(perm.value for perm in Permission if can(q.ctx.role, perm)),
                "must_change_password": q.session.must_change_password, "version": __version__,
                "persistent_secrets": p.secrets.persistent}
    r.add("GET", "/api/session", session_info)
    r.add("GET", "/api/dashboard", lambda q: p.dashboard(q.ctx))
    # ---- inventory
    r.add("GET", "/api/assets", lambda q: p.assets(q.ctx, text=q.arg("q", ""), kind=q.arg("kind") or None,
                                                   status=q.arg("status") or None, tag=q.arg("tag") or None,
                                                   source=q.arg("source") or None))
    r.add("POST", "/api/assets", lambda q: p.create_asset(q.ctx, q.body or {}))
    r.add("POST", "/api/assets/import", lambda q: p.import_assets_csv(q.ctx, str(q.arg("csv", required=True))))
    r.add("GET", "/api/inventory/export", lambda q: p.export_inventory(q.ctx, q.arg("format", "json")))
    r.add("GET", f"/api/assets/{ID}", lambda q: p.asset(q.ctx, q.match.group(1)))
    r.add("PATCH", f"/api/assets/{ID}", lambda q: p.update_asset(q.ctx, q.match.group(1),
                                                                 {k: v for k, v in (q.body or {}).items() if k != "confirm"}))
    r.add("DELETE", f"/api/assets/{ID}", lambda q: {"deleted": p.delete_asset(q.ctx, q.match.group(1), q.confirm)})
    r.add("POST", f"/api/assets/{ID}/link", lambda q: p.link_assets(q.ctx, q.match.group(1), q.arg("to", required=True),
                                                                     q.arg("type", "connected_to"), q.arg("port", "")))
    r.add("POST", f"/api/assets/{ID}/collect", lambda q: p.collect_now(q.ctx, q.match.group(1)).public())
    r.add("GET", f"/api/assets/{ID}/connectivity", lambda q: p.server_connectivity(q.ctx, q.match.group(1)))
    r.add("GET", f"/api/assets/{ID}/server", lambda q: p.server_details(q.ctx, q.match.group(1)))
    r.add("POST", f"/api/assets/{ID}/storage-check", lambda q: p.storage_connectivity(
        q.ctx, q.match.group(1), list(q.arg("protocols", ["smb", "nfs", "iscsi"]))))
    # ---- discovery / tasks
    r.add("POST", "/api/discovery", lambda q: p.start_discovery(q.ctx, [str(t) for t in q.arg("targets", required=True)]).public())
    r.add("GET", "/api/tasks", lambda q: p.tasks.list())

    def task(q: Request) -> Any:
        t = p.tasks.get(q.match.group(1))
        if t is None or (t.owner not in (q.ctx.user, "scheduler") and not can(q.ctx.role, Permission.READ_AUDIT)):
            raise NotFound("No such task.")
        return t.public()
    r.add("GET", f"/api/tasks/{ID}", task)
    # ---- integrations
    r.add("GET", "/api/adapters", lambda q: [s.public() for s in p.registry.list()])
    r.add("GET", "/api/integrations", lambda q: p.integrations(q.ctx))
    r.add("POST", "/api/integrations", lambda q: p.add_integration(
        q.ctx, q.arg("category", required=True), q.arg("kind", required=True), q.arg("name", required=True),
        q.arg("config", {}) or {}, q.arg("secrets", {}) or {}, q.arg("id", "") or ""))
    r.add("DELETE", f"/api/integrations/{ID}", lambda q: {"deleted": p.remove_integration(q.ctx, q.match.group(1), q.confirm)})
    r.add("POST", f"/api/integrations/{ID}/poll", lambda q: p.submit(q.ctx, f"poll {q.match.group(1)}", p.test_integration,
                                                                     q.ctx, q.match.group(1)).public())
    # ---- virtualization
    r.add("GET", "/api/vm", lambda q: p.vm_details(q.ctx, q.arg("integration", required=True), q.arg("vm", required=True)))
    r.add("POST", "/api/vm/power", lambda q: p.vm_power(q.ctx, q.arg("integration", required=True), q.arg("vm", required=True),
                                                        q.arg("action", required=True), q.confirm))
    # ---- docker
    r.add("GET", f"/api/docker/{ID}", lambda q: p.docker_overview(q.ctx, q.match.group(1)))
    r.add("GET", f"/api/docker/{ID}/logs", lambda q: p.container_logs(q.ctx, q.match.group(1), q.arg("container", required=True),
                                                                        int(q.arg("tail", 200))))
    r.add("GET", f"/api/docker/{ID}/inspect", lambda q: p.container_inspect(q.ctx, q.match.group(1), q.arg("container", required=True)))
    r.add("POST", f"/api/docker/{ID}/action", lambda q: p.container_action(q.ctx, q.match.group(1), q.arg("container", required=True),
                                                                             q.arg("action", required=True), q.confirm))
    # ---- storage
    r.add("GET", "/api/storage", lambda q: p.storage_overview(q.ctx))
    # ---- network
    def ipam(q: Request) -> Any:
        p._need(q.ctx, Permission.VIEW)
        return {"subnets": p.ipam.usage(p.inventory.all()), "vlans": p.ipam.vlans()}

    def edit_net(q: Request, fn: Callable[[], Any], what: str) -> Any:
        p._need(q.ctx, Permission.EDIT_INVENTORY, what)
        out = fn()
        p._audit(q.ctx.user, what, json.dumps(q.body or {}, default=str)[:150])
        return out
    r.add("GET", "/api/network/ipam", ipam)
    r.add("POST", "/api/network/subnets", lambda q: edit_net(q, lambda: p.ipam.add_subnet(
        str(q.arg("cidr", required=True)), str(q.arg("name", "")), q.arg("vlan") or None, str(q.arg("gateway", "") or ""),
        str(q.arg("dns", "") or ""), str(q.arg("description", "") or ""), str(q.arg("site", "") or "")), "ipam.subnet.add"))
    r.add("DELETE", f"/api/network/subnets/{ID}", lambda q: edit_net(q, lambda: {"deleted": p.ipam.delete_subnet(q.match.group(1))},
                                                                     "ipam.subnet.delete"))
    r.add("POST", "/api/network/reservations", lambda q: edit_net(q, lambda: p.ipam.reserve(
        str(q.arg("ip", required=True)), str(q.arg("name", required=True)), str(q.arg("note", "") or "")), "ipam.reserve"))
    r.add("DELETE", f"/api/network/reservations/{ID}", lambda q: edit_net(q, lambda: {"deleted": p.ipam.release(q.match.group(1))},
                                                                          "ipam.release"))
    r.add("POST", "/api/network/vlans", lambda q: edit_net(q, lambda: p.ipam.set_vlan(
        int(q.arg("vid", required=True)), str(q.arg("name", required=True)), str(q.arg("description", "") or "")), "vlan.save"))
    r.add("DELETE", r"/api/network/vlans/(\d{1,4})", lambda q: edit_net(q, lambda: {"deleted": p.ipam.delete_vlan(int(q.match.group(1)))},
                                                                         "vlan.delete"))

    def topo(q: Request) -> Any:
        p._need(q.ctx, Permission.VIEW)
        from ..netmgmt import topology
        return topology(p.inventory.all())
    r.add("GET", "/api/network/topology", topo)

    def diag(q: Request) -> Any:
        p._need(q.ctx, Permission.DISCOVER, "diagnostics")
        tool, host = str(q.arg("tool", required=True)), str(q.arg("host", required=True))
        p._audit(q.ctx.user, f"diag.{tool}", host[:100])
        if tool == "ping":
            return p.diag.ping(host, int(q.arg("count", 4)))
        if tool == "traceroute":
            return p.diag.traceroute(host)
        if tool == "dns":
            return p.diag.dns(host)
        if tool == "tcp":
            return p.diag.tcp(host, int(q.arg("port", required=True)))
        raise ValidationError("tool must be ping, traceroute, dns or tcp")
    r.add("POST", "/api/network/diag", diag)
    # ---- monitoring
    r.add("GET", "/api/monitoring/alerts", lambda q: viewing(q, Permission.VIEW, lambda: p.monitor.alerts(bool(q.arg("all")))))
    r.add("POST", f"/api/monitoring/alerts/{ID}/ack", lambda q: p.acknowledge_alert(q.ctx, q.match.group(1)))
    r.add("GET", "/api/monitoring/rules", lambda q: viewing(q, Permission.VIEW, lambda: [r_.__dict__ for r_ in p.monitor.rules()]))
    r.add("POST", "/api/monitoring/rules", lambda q: p.set_rule(q.ctx, q.body or {}))
    r.add("GET", "/api/monitoring/checks", lambda q: viewing(q, Permission.VIEW, lambda: [c.__dict__ for c in p.monitor.checks()]))
    r.add("POST", "/api/monitoring/checks", lambda q: p.add_check(q.ctx, q.body or {}))
    r.add("DELETE", f"/api/monitoring/checks/{ID}", lambda q: {"deleted": p.remove_check(q.ctx, q.match.group(1))})
    r.add("GET", "/api/metrics", lambda q: p.metrics(q.ctx, q.arg("target", required=True), q.arg("metric", required=True),
                                                     float(q.arg("hours", 24))))
    r.add("GET", "/api/events", lambda q: viewing(q, Permission.VIEW, lambda: p.db.events(
        limit=min(int(q.arg("limit", 200)), 1000), target=q.arg("target") or None, severity=q.arg("severity") or None)))
    r.add("GET", "/api/report", lambda q: p.report(q.ctx, int(q.arg("hours", 24))))
    # ---- automation
    a = p.automation
    r.add("GET", "/api/automation/scripts", lambda q: viewing(q, Permission.VIEW, lambda: a.scripts()))
    r.add("POST", "/api/automation/scripts", lambda q: a.save_script(q.ctx.user, q.ctx.role, q.body or {}).__dict__)
    r.add("DELETE", f"/api/automation/scripts/{ID}", lambda q: {"deleted": a.delete_script(q.ctx.user, q.ctx.role, q.match.group(1))})
    r.add("GET", "/api/automation/runs", lambda q: viewing(q, Permission.VIEW, lambda: a.runs()))
    r.add("POST", "/api/automation/runs", lambda q: p.run_script(q.ctx, q.arg("script_id", required=True),
                                                                 list(q.arg("targets", []) or []), q.arg("params", {}) or {},
                                                                 str(q.arg("note", "") or "")))
    r.add("POST", f"/api/automation/runs/{ID}/decide", lambda q: p.approve_run(q.ctx, q.match.group(1), bool(q.arg("approve")),
                                                                                 str(q.arg("comment", "") or "")))
    r.add("POST", f"/api/automation/runs/{ID}/cancel", lambda q: a.cancel(q.ctx.user, q.match.group(1)))
    r.add("GET", "/api/automation/workflows", lambda q: viewing(q, Permission.VIEW, lambda: a.workflows()))
    r.add("POST", "/api/automation/workflows", lambda q: a.save_workflow(q.ctx.user, q.ctx.role, str(q.arg("name", required=True)),
                                                                         list(q.arg("steps", required=True)), str(q.arg("id", "") or "")))
    r.add("POST", f"/api/automation/workflows/{ID}/run", lambda q: p.submit(q.ctx, "workflow", a.run_workflow, q.ctx.user,
                                                                             q.ctx.role, q.match.group(1)).public())
    r.add("GET", "/api/automation/policies", lambda q: viewing(q, Permission.VIEW, lambda: a.policies()))
    r.add("POST", "/api/automation/policies", lambda q: a.add_policy(q.ctx.user, q.ctx.role, q.body or {}).__dict__)
    r.add("DELETE", f"/api/automation/policies/{ID}", lambda q: {"deleted": a.remove_policy(q.ctx.user, q.ctx.role, q.match.group(1))})
    # ---- backups / recovery
    r.add("GET", "/api/backups", lambda q: viewing(q, Permission.VIEW, lambda: p.backups.statuses()))
    r.add("POST", "/api/backups", lambda q: p.save_backup_job(q.ctx, q.body or {}))
    r.add("DELETE", f"/api/backups/{ID}", lambda q: {"deleted": p.delete_backup_job(q.ctx, q.match.group(1))})
    r.add("POST", f"/api/backups/{ID}/record", lambda q: p.record_backup(q.ctx, q.match.group(1), bool(q.arg("ok", True)),
                                                                           q.arg("size"), str(q.arg("message", "") or "")))
    r.add("POST", "/api/backups/check", lambda q: viewing(q, Permission.BACKUP, lambda: p.submit(q.ctx, "backup check", p.backup_cycle).public()))
    r.add("GET", "/api/recovery/runbook", lambda q: p.runbook(q.ctx))
    r.add("GET", "/api/config/export", lambda q: p.config_bundle(q.ctx))
    # ---- security
    r.add("GET", "/api/security/audit", lambda q: p.audit_entries(q.ctx, min(int(q.arg("limit", 200)), 2000)))

    def list_sessions(q: Request) -> Any:
        p._need(q.ctx, Permission.MANAGE_USERS, "sessions.list")
        return sessions.list()

    def revoke_session(q: Request) -> Any:
        p._need(q.ctx, Permission.MANAGE_USERS, "sessions.revoke")
        ok = sessions.revoke_id(q.match.group(1))
        p._audit(q.ctx.user, "session.revoke", q.match.group(1), "ok" if ok else "failed")
        return {"revoked": ok}
    r.add("GET", "/api/security/sessions", list_sessions)
    r.add("DELETE", f"/api/security/sessions/{ID}", revoke_session)
    r.add("GET", "/api/security/hostkey", lambda q: p.host_key(q.ctx, q.arg("host", required=True), int(q.arg("port", 22))))
    r.add("POST", "/api/security/trust", lambda q: p.trust_host(q.ctx, q.arg("host", required=True), int(q.arg("port", 22)),
                                                                q.arg("fingerprint", required=True), q.confirm))
    r.add("GET", "/api/secrets", lambda q: viewing(q, Permission.MANAGE_INTEGRATIONS, lambda: p.secrets.refs()))
    r.add("POST", "/api/secrets", lambda q: p.set_secret(q.ctx, str(q.arg("ref", required=True)), str(q.arg("value", required=True))))
    return r


class ApiServer:
    def __init__(self, platform: HomelabPlatform, auth: AuthManager, bind: str | None = None, port: int | None = None,
                 sessions: SessionManager | None = None, web_dir: Path = WEB_DIR) -> None:
        api = platform.cfg["api"]
        self.platform, self.auth = platform, auth
        self.bind = bind or api["bind"]
        self.port = api["port"] if port is None else port
        self.tls = bool(api["tls_cert"])
        self._check_bind(api)
        self.sessions = sessions or SessionManager(api["session_idle_minutes"] * 60, api["session_max_hours"] * 3600)
        self.routes = build_routes(platform, self.sessions)
        self.web_dir = web_dir
        self.httpd = ThreadingHTTPServer((self.bind, self.port), self._handler())
        self.httpd.daemon_threads = True
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(api["tls_cert"], api["tls_key"])
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    def _check_bind(self, api: dict[str, Any]) -> None:
        try:
            loopback = ipaddress.ip_address(self.bind).is_loopback
        except ValueError:
            loopback = self.bind == "localhost"
        if not loopback and not self.tls and not api["allow_remote_without_tls"]:
            raise ConfigError(f"Refusing to serve on {self.bind} without TLS: passwords and session cookies would cross "
                              "the network in clear text. Set api.tls_cert/api.tls_key (or bind to 127.0.0.1 and use a "
                              "TLS reverse proxy).")

    @property
    def url(self) -> str:
        host = self.bind if ":" not in self.bind else f"[{self.bind}]"
        return f"{'https' if self.tls else 'http'}://{host}:{self.port}/"

    def serve_forever(self) -> None:
        self.httpd.serve_forever(poll_interval=0.5)

    def start(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, name="nc-api", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    # ------------------------------------------------------------------ handler
    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class H(BaseHTTPRequestHandler):
            server_version = "UptimeFunk"
            sys_version = ""
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                log.debug("%s %s", self.address_string(), fmt % args)

            # ---- responses
            def _headers(self, status: int, ctype: str, length: int, extra: dict[str, str] | None = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(length))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", CSP)
                self.send_header("Cross-Origin-Opener-Policy", "same-origin")
                self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                if server.tls:
                    self.send_header("Strict-Transport-Security", "max-age=31536000")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()

            def _json(self, status: int, data: Any, extra: dict[str, str] | None = None) -> None:
                body = json.dumps(data, default=str).encode("utf-8")
                self._headers(status, "application/json; charset=utf-8", len(body),
                              {"Cache-Control": "no-store", **(extra or {})})
                self.wfile.write(body)

            def _error(self, status: int, message: str, **more: Any) -> None:
                self._json(status, {"error": message, **more})

            # ---- request helpers
            def _cookie(self) -> str | None:
                raw = self.headers.get("Cookie")
                if not raw:
                    return None
                c = SimpleCookie()
                try:
                    c.load(raw)
                except Exception:
                    return None
                return c[COOKIE].value if COOKIE in c else None

            def _body(self) -> Any:
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    raise ValidationError("Request body too large.")
                if n == 0:
                    return None
                raw = self.rfile.read(n)
                ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
                if ctype != "application/json":
                    raise ValidationError("Send JSON (Content-Type: application/json).")
                try:
                    return json.loads(raw.decode("utf-8"))
                except ValueError:
                    raise ValidationError("Body is not valid JSON.") from None

            def _same_origin(self) -> bool:
                host = self.headers.get("Host", "")
                origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
                if not origin:
                    return False
                return urllib.parse.urlsplit(origin).netloc == host

            # ---- dispatch
            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

            def do_PATCH(self) -> None:
                self._dispatch("PATCH")

            def do_DELETE(self) -> None:
                self._dispatch("DELETE")

            def _dispatch(self, method: str) -> None:
                u = urllib.parse.urlsplit(self.path)
                path = u.path
                try:
                    if not path.startswith("/api/"):
                        if method != "GET":
                            return self._error(405, "Method not allowed.")
                        return self._static(path)
                    if path == "/api/login" and method == "POST":
                        return self._login()
                    if path == "/api/health" and method == "GET":
                        return self._json(200, {"status": "ok"})
                    s = server.sessions.get(self._cookie())
                    if s is None:
                        return self._error(401, "Sign in required.")
                    if method != "GET":
                        if not self._same_origin():
                            return self._error(403, "Cross-origin request refused.")
                        if not server.sessions.csrf_ok(s, self.headers.get("X-CSRF-Token")):
                            return self._error(403, "Missing or invalid CSRF token.")
                    if path == "/api/logout" and method == "POST":
                        server.sessions.revoke(self._cookie() or "")
                        server.platform._audit(s.user, "web.logout", self.client_address[0])
                        return self._json(200, {"ok": True}, {"Set-Cookie": self._cookie_header("", 0)})
                    if s.must_change_password and path != "/api/session":
                        return self._error(403, "Change your temporary password in Uptime Funk first.")
                    fn, match, known = server.routes.find(method, path)
                    if fn is None or match is None:
                        return self._error(405 if known else 404, "Method not allowed." if known else "Not found.")
                    query = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
                    body = self._body() if method in ("POST", "PATCH", "DELETE") else None
                    ctx = Ctx(s.user, s.role)
                    result = fn(Request(ctx, s, match, query, body))
                    if isinstance(result, str):
                        data = result.encode("utf-8")
                        ctype = "text/csv; charset=utf-8" if query.get("format") == "csv" else (
                            "text/markdown; charset=utf-8" if path.endswith("runbook") else "application/json; charset=utf-8")
                        self._headers(200, ctype, len(data), {"Cache-Control": "no-store"})
                        self.wfile.write(data)
                        return None
                    return self._json(200, result)
                except AuthorizationRequired as exc:
                    return self._error(409, str(exc), confirm_token=exc.token, details=exc.details)
                except PermissionDenied as exc:
                    return self._error(403, str(exc))
                except PermissionError as exc:
                    return self._error(403, str(exc))
                except ValidationError as exc:
                    return self._error(400, str(exc), problems=exc.problems)
                except NotFound as exc:
                    return self._error(404, str(exc))
                except IntegrationError as exc:
                    return self._error(502, str(exc))
                except (ValueError, TypeError) as exc:
                    return self._error(400, f"Bad request: {exc}"[:300])
                except BrokenPipeError:
                    return None
                except Exception:
                    log.exception("API error on %s %s", method, path)
                    return self._error(500, "Internal error (see the server log).")

            def _cookie_header(self, value: str, max_age: int) -> str:
                attrs = f"{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
                return attrs + ("; Secure" if server.tls else "")

            def _login(self) -> None:
                body = self._body() or {}
                email, password, otp = (str(body.get(k) or "") for k in ("email", "password", "otp"))
                if not self._same_origin():
                    return self._error(403, "Cross-origin request refused.")
                ok, msg = server.auth.verify_login(email, password, otp)
                if not ok:
                    return self._error(401, msg or "Sign-in failed.")
                role = Role.parse(server.auth.role_of(email), Role.VIEWER)
                must = server.auth.must_change_password(email)
                sid, s = server.sessions.create(email.strip().lower(), role, self.client_address[0],
                                                self.headers.get("User-Agent", ""), must)
                server.platform._audit(s.user, "web.login", self.client_address[0], "ok", role.value)
                self._json(200, {"user": s.user, "role": role.value, "csrf": s.csrf, "must_change_password": must},
                           {"Set-Cookie": self._cookie_header(sid, int(server.sessions.max))})

            def _static(self, path: str) -> None:
                rel = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
                if rel.startswith("static/"):
                    rel = rel[len("static/"):]
                target = (server.web_dir / rel).resolve()
                if server.web_dir.resolve() not in target.parents or not target.is_file() or \
                        target.suffix not in STATIC_TYPES:
                    return self._error(404, "Not found.")
                data = target.read_bytes()
                self._headers(200, STATIC_TYPES[target.suffix], len(data), {"Cache-Control": "no-cache"})
                self.wfile.write(data)
        return H
