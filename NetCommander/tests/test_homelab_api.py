"""Management API over real HTTP: authentication, sessions, CSRF/origin checks, confirmations, headers."""
from __future__ import annotations

import http.client
import json

import pytest
from conftest import FakeClock
from homelab_fixtures import build_platform, make_auth, otp, populate

from netcommander.homelab.api.server import ApiServer
from netcommander.homelab.api.sessions import SessionManager
from netcommander.homelab.core.errors import ConfigError
from netcommander.rbac import Role


class Client:
    def __init__(self, port):
        self.port, self.cookie, self.csrf, self.origin = port, "", "", f"http://127.0.0.1:{port}"

    def req(self, method, path, body=None, headers=None, raw=None, csrf=True, origin=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": f"127.0.0.1:{self.port}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if method != "GET":
            if csrf and self.csrf:
                h["X-CSRF-Token"] = self.csrf
            if origin:
                h["Origin"] = self.origin
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        payload = r.read()
        c.close()
        ctype = r.getheader("Content-Type", "")
        return r.status, (json.loads(payload) if "json" in ctype and payload else payload.decode()), r

    def login(self, email, password, code):
        st, data, r = self.req("POST", "/api/login", {"email": email, "password": password, "otp": code}, csrf=False)
        if st == 200:
            self.cookie = r.getheader("Set-Cookie").split(";")[0]
            self.csrf = data["csrf"]
        return st, data, r


@pytest.fixture
def server(tmp_path):
    p = build_platform(tmp_path)
    populate(p)
    auth, secrets = make_auth(tmp_path)
    srv = ApiServer(p, auth, bind="127.0.0.1", port=0)
    srv.start()
    srv.secrets_ = secrets
    yield srv
    srv.stop()
    p.stop()


def admin(server):
    c = Client(server.port)
    st, _d, _r = c.login("admin@example.com", "correct-horse-1", otp(server.secrets_["admin@example.com"]))
    assert st == 200
    return c


def test_static_assets_and_security_headers(server):
    c = Client(server.port)
    st, body, r = c.req("GET", "/")
    assert st == 200 and "<title>Uptime Funk</title>" in body
    csp = r.getheader("Content-Security-Policy")
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.getheader("X-Content-Type-Options") == "nosniff" and r.getheader("X-Frame-Options") == "DENY"
    assert c.req("GET", "/static/app.js")[0] == 200
    for bad in ("/static/../platform.py", "/static/%2e%2e/platform.py", "/../../etc/passwd", "/static/nope.js"):
        assert c.req("GET", bad)[0] == 404, bad
    assert c.req("POST", "/")[0] == 405
    assert c.req("GET", "/api/health")[1] == {"status": "ok"}


def test_login_flow_cookie_flags_and_logout(server):
    c = Client(server.port)
    assert c.req("GET", "/api/session")[0] == 401
    st, data, _ = c.login("admin@example.com", "correct-horse-1", "000000")
    assert st == 401 and "csrf" not in data
    assert c.login("nobody@example.com", "x", "1")[0] == 401
    st, data, r = c.login("admin@example.com", "correct-horse-1", otp(server.secrets_["admin@example.com"]))
    assert st == 200 and data["role"] == "admin"
    cookie = r.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Secure" not in cookie
    st, sess, r = c.req("GET", "/api/session")
    assert st == 200 and "control_workloads" in sess["permissions"] and r.getheader("Cache-Control") == "no-store"
    st, _d, _r = c.req("POST", "/api/logout", {})
    assert st == 200 and c.req("GET", "/api/session")[0] == 401
    acts = [(e["action"], e["outcome"]) for e in server.platform.audit_log.entries()]
    assert ("web.login", "ok") in acts and ("web.logout", "ok") in acts


def test_login_replay_protection(server):
    code = otp(server.secrets_["admin@example.com"])
    assert Client(server.port).login("admin@example.com", "correct-horse-1", code)[0] == 200
    assert Client(server.port).login("admin@example.com", "correct-horse-1", code)[0] == 401      # same TOTP code twice


def test_csrf_and_origin_enforced(server):
    c = admin(server)
    body = {"name": "x", "kind": "server"}
    assert c.req("POST", "/api/assets", body, csrf=False)[0] == 403
    assert c.req("POST", "/api/assets", body, origin=False)[0] == 403
    assert c.req("POST", "/api/assets", body, headers={"Origin": "http://evil.example"})[0] == 403
    assert c.req("POST", "/api/assets", body, headers={"X-CSRF-Token": "wrong"})[0] == 403
    st, a, _ = c.req("POST", "/api/assets", body)
    assert st == 200 and a["name"] == "x"


def test_login_refuses_cross_origin(server):
    c = Client(server.port)
    st, _d, _r = c.req("POST", "/api/login", {"email": "admin@example.com", "password": "correct-horse-1",
                                               "otp": otp(server.secrets_["admin@example.com"])}, headers={"Origin": "http://evil"})
    assert st == 403


def test_rbac_and_confirmation_over_http(server):
    op = Client(server.port)
    assert op.login("op@example.com", "correct-horse-1", otp(server.secrets_["op@example.com"]))[0] == 200
    st, data, _ = op.req("POST", "/api/vm/power", {"integration": "pve", "vm": "pve1/qemu/101", "action": "shutdown"})
    assert st == 403 and "control workloads" in data["error"]
    adm = admin(server)
    st, data, _ = adm.req("POST", "/api/vm/power", {"integration": "pve", "vm": "pve1/qemu/101", "action": "shutdown"})
    assert st == 409 and data["details"]["risk"] == "destructive"
    st, data, _ = adm.req("POST", "/api/vm/power", {"integration": "pve", "vm": "pve1/qemu/101", "action": "shutdown",
                                                    "confirm": data["confirm_token"]})
    assert st == 200 and data["result"].startswith("UPID")
    st, data, _ = op.req("POST", "/api/vm/power", {"integration": "pve", "vm": "pve1/qemu/101", "action": "shutdown",
                                                   "confirm": "forged.token"})
    assert st == 403


def test_reads_and_error_mapping(server):
    c = admin(server)
    st, d, _ = c.req("GET", "/api/dashboard")
    assert st == 200 and d["vms"]["total"] == 1
    st, assets, _ = c.req("GET", "/api/assets?kind=vm")
    assert st == 200 and {a["name"] for a in assets} == {"web", "tmpl"}
    assert c.req("GET", "/api/assets/does-not-exist")[0] == 404
    assert c.req("GET", "/api/nope")[0] == 404
    assert c.req("PUT", "/api/assets")[0] in (404, 405, 501)
    assert c.req("DELETE", "/api/dashboard", {})[0] == 405
    assert c.req("POST", "/api/assets", raw=b"{not json", headers={"Content-Type": "application/json"})[0] == 400
    assert c.req("POST", "/api/assets", raw=b"name=x", headers={"Content-Type": "application/x-www-form-urlencoded"})[0] == 400
    st, err, _ = c.req("POST", "/api/assets", {"name": "", "kind": "toaster"})
    assert st == 400 and len(err["problems"]) >= 2
    st, refs, _ = c.req("GET", "/api/secrets")
    assert "int.pve.token" in refs and "pve-token-value" not in json.dumps(refs)
    st, md, r = c.req("GET", "/api/recovery/runbook")
    assert st == 200 and md.startswith("# Infrastructure recovery runbook") and "markdown" in r.getheader("Content-Type")
    st, csv_text, r = c.req("GET", "/api/inventory/export?format=csv")
    assert st == 200 and csv_text.startswith("id,name,kind")
    st, topo, _ = c.req("GET", "/api/network/topology")
    assert any(e["type"] == "runs_on" for e in topo["edges"])
    st, audit, _ = c.req("GET", "/api/security/audit")
    assert audit["verified"] is True
    st, sessions, _ = c.req("GET", "/api/security/sessions")
    assert sessions and sessions[0]["user"] == "admin@example.com" and "key" not in sessions[0]


def test_task_polling_and_ownership(server):
    adm = admin(server)
    st, t, _ = adm.req("POST", "/api/discovery", {"targets": ["10.0.0.0/30"]})
    assert st == 200
    import time
    for _ in range(100):
        st, info, _ = adm.req("GET", f"/api/tasks/{t['id']}")
        if info["status"] in ("done", "failed"):
            break
        time.sleep(0.05)
    assert info["status"] == "done"
    op = Client(server.port)
    op.login("op@example.com", "correct-horse-1", otp(server.secrets_["op@example.com"]))
    assert op.req("GET", f"/api/tasks/{t['id']}")[0] == 404                  # not their task
    assert adm.req("POST", "/api/discovery", {"targets": ["10.0.0.0/8"]})[0] == 400


def test_temporary_password_blocks_api(tmp_path):
    p = build_platform(tmp_path)
    auth, secrets = make_auth(tmp_path)
    s2, _ = auth.create_account("new@example.com", "temporary-pw-9", "viewer", created_by="admin@example.com")
    srv = ApiServer(p, auth, port=0)
    srv.start()
    try:
        c = Client(srv.port)
        st, data, _ = c.login("new@example.com", "temporary-pw-9", otp(s2))
        assert st == 200 and data["must_change_password"]
        assert c.req("GET", "/api/session")[0] == 200
        assert c.req("GET", "/api/dashboard")[0] == 403
    finally:
        srv.stop()
        p.stop()


def test_refuses_remote_bind_without_tls(tmp_path):
    p = build_platform(tmp_path)
    auth, _ = make_auth(tmp_path)
    try:
        with pytest.raises(ConfigError, match="without TLS"):
            ApiServer(p, auth, bind="0.0.0.0", port=0)
    finally:
        p.stop()


def test_session_manager_timeouts_and_revocation():
    clock = FakeClock(0)
    sm = SessionManager(idle_seconds=60, max_seconds=300, clock=clock)
    sid, s = sm.create("a@example.com", Role.ADMIN)
    assert sm.get(sid) is s and sm.csrf_ok(s, s.csrf) and not sm.csrf_ok(s, "x") and not sm.csrf_ok(s, None)
    clock.advance(59)
    assert sm.get(sid) is s
    clock.advance(61)
    assert sm.get(sid) is None                                        # idle
    sid, s = sm.create("a@example.com", Role.ADMIN)
    for _ in range(6):
        clock.advance(55)
        sm.get(sid)
    assert sm.get(sid) is None                                        # absolute lifetime
    sid, s = sm.create("b@example.com", Role.VIEWER)
    assert sm.list()[0]["user"] == "b@example.com" and sm.revoke_id(s.id) and sm.get(sid) is None
    sid1, _ = sm.create("c@example.com", Role.VIEWER)
    sm.create("c@example.com", Role.VIEWER)
    assert sm.revoke_user("c@example.com") == 2 and sm.get(sid1) is None
    assert sm.get(None) is None and sm.get("garbage") is None
