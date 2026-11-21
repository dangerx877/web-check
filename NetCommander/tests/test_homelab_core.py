"""Shared homelab infrastructure: database, events, tasks, secrets, HTTP client, runners, registry,
notifications, configuration validation and action authorization."""
from __future__ import annotations

import hashlib
import json
import threading
import time

import pytest
from conftest import FakeClock

from netcommander.homelab.core import authz, settings
from netcommander.homelab.core.db import Database, downsample
from netcommander.homelab.core.errors import (
    AuthorizationRequired,
    ConfigError,
    IntegrationError,
    NotFound,
    ValidationError,
)
from netcommander.homelab.core.events import EventBus
from netcommander.homelab.core.httpclient import HttpClient, normalize_fingerprint
from netcommander.homelab.core.notify import Notification, Notifier, SmtpChannel, WebhookChannel
from netcommander.homelab.core.registry import AdapterSpec, FieldSpec, Registry, build_adapter
from netcommander.homelab.core.runners import CommandPolicy, FakeRunner, LocalRunner, run_all
from netcommander.homelab.core.sanitize import redact_mapping, redact_text
from netcommander.homelab.core.secrets import SecretStore
from netcommander.homelab.core.tasks import PeriodicScheduler, TaskRunner
from netcommander.rbac import Permission, PermissionDenied, Role


# ---------------------------------------------------------------- database
def test_db_records_roundtrip_and_permissions(tmp_path):
    db = Database(tmp_path / "h.db")
    db.put("assets", "a1", {"name": "srv"})
    db.put("assets", "a1", {"name": "srv2"})
    assert db.get("assets", "a1") == {"name": "srv2"}
    assert db.count("assets") == 1 and db.ids("assets") == ["a1"]
    assert db.delete("assets", "a1") and not db.delete("assets", "a1")
    assert db.get("assets", "missing") is None
    assert db.schema_version == 1
    import os
    import stat
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "h.db").stat().st_mode) == 0o600


def test_db_metrics_series_latest_and_prune(tmp_path):
    clock = FakeClock(1000.0)
    db = Database(tmp_path / "h.db", clock=clock)
    for i in range(10):
        db.add_metrics("srv", {"cpu": i, "bad": float("nan")}, ts=1000.0 + i)
    assert len(db.series("srv", "cpu", until=2000)) == 10
    assert db.series("srv", "bad", until=2000) == []                   # non-finite values are dropped
    assert db.latest_metrics("srv")["cpu"] == (1009.0, 9.0)
    assert len(db.series("srv", "cpu", until=2000, max_points=5)) == 5
    assert db.prune_metrics(1005.0) == 5
    assert db.metric_targets() == ["srv"]


def test_db_events_filter(tmp_path):
    db = Database(tmp_path / "h.db")
    db.add_event("info", "mon", "up", "a", "a up")
    db.add_event("critical", "mon", "down", "b", "b down", {"x": 1})
    assert [e["target"] for e in db.events()] == ["b", "a"]
    assert db.events(severity="critical")[0]["data"] == {"x": 1}
    assert db.events(target="a")[0]["message"] == "a up"


def test_db_threads_share_file(tmp_path):
    db = Database(tmp_path / "h.db")

    def writer(n):
        for i in range(20):
            db.put("c", f"{n}-{i}", {"i": i})
    ts = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert db.count("c") == 80


def test_db_refuses_newer_schema(tmp_path):
    import sqlite3
    p = tmp_path / "h.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA user_version = 99")
    c.close()
    with pytest.raises(RuntimeError, match="newer"):
        Database(p)


def test_downsample_keeps_order():
    pts = [(float(i), float(i)) for i in range(100)]
    out = downsample(pts, 10)
    assert len(out) == 10 and out == sorted(out)


# ---------------------------------------------------------------- events / tasks
def test_event_bus_wildcards_and_isolation():
    bus, seen = EventBus(), []
    bus.subscribe("alert.raised", lambda e: seen.append(("exact", e.kind)))
    bus.subscribe("alert.*", lambda e: seen.append(("prefix", e.kind)))
    bus.subscribe("*", lambda e: 1 / 0)                                   # failing handler is isolated
    unsub = bus.subscribe("*", lambda e: seen.append(("all", e.kind)))
    bus.emit("alert.raised", "mon", "srv", severity="bogus")
    assert ("exact", "alert.raised") in seen and ("prefix", "alert.raised") in seen and ("all", "alert.raised") in seen
    unsub()
    seen.clear()
    bus.emit("other", "x")
    assert seen == []


def test_task_runner_success_failure_and_history():
    changes = []
    r = TaskRunner(max_workers=2, history=3, on_change=lambda t: changes.append(t.status))
    ok = r.submit("ok", lambda x: x * 2, 21)
    bad = r.submit("bad", lambda: 1 / 0)
    assert r.wait(ok.id, 5).result == 42 and r.get(ok.id).status == "done"
    assert r.wait(bad.id, 5).status == "failed" and "ZeroDivisionError" in r.get(bad.id).error
    for i in range(5):
        r.wait(r.submit(f"t{i}", lambda: None).id, 5)
    assert len(r.list()) <= 3
    r.shutdown(wait=True)
    with pytest.raises(RuntimeError):
        r.submit("late", lambda: None)
    assert "running" in changes


def test_periodic_scheduler_no_overlap():
    clock = FakeClock(0.0)
    r = TaskRunner(max_workers=2)
    gate, calls = threading.Event(), []
    s = PeriodicScheduler(r, clock=clock)
    s.every("job", 10, lambda: (calls.append(1), gate.wait(5)))
    assert s.tick() == ["job"]
    assert s.tick() == []                     # still running -> never overlaps
    gate.set()
    deadline = time.time() + 5
    while s.jobs()[0]["running"] and time.time() < deadline:
        time.sleep(0.01)
    assert s.tick() == []                     # not due yet
    clock.advance(11)
    assert s.tick() == ["job"]
    with pytest.raises(ValueError):
        s.every("fast", 0.1, lambda: None)
    r.shutdown(wait=True)


# ---------------------------------------------------------------- secrets / redaction
def test_secret_store_encrypts_at_rest(tmp_path, vault):
    st = SecretStore(tmp_path / "s.json", vault)
    st.put("pve.token", "super-secret-value")
    raw = (tmp_path / "s.json").read_text()
    assert "super-secret-value" not in raw
    assert st.get("pve.token") == "super-secret-value"
    assert st.refs() == ["pve.token"] and st.has("pve.token")
    assert SecretStore(tmp_path / "s.json", vault).get("pve.token") == "super-secret-value"
    assert st.delete("pve.token") and not st.delete("pve.token")
    with pytest.raises(NotFound):
        st.get("pve.token")
    with pytest.raises(ValidationError):
        st.put("bad ref;", "x")
    with pytest.raises(ValidationError):
        st.put("ok", "")


def test_secret_store_guest_never_writes(tmp_path, guest_vault):
    st = SecretStore(tmp_path / "s.json", guest_vault)
    st.put("a", "b")
    assert st.get("a") == "b" and not (tmp_path / "s.json").exists()


def test_secret_store_locked_vault(tmp_path, vault):
    st = SecretStore(tmp_path / "s.json", vault)
    vault.close()
    with pytest.raises(RuntimeError):
        st.put("a", "b")


def test_redaction():
    t = redact_text("Authorization: PVEAPIToken=root@pam!x=abc and https://u:pw@h/x?token=zz&a=1")
    assert "abc" not in t and "pw@" not in t and "zz" not in t
    m = redact_mapping({"password": "x", "token_ref": "t1", "n": [{"api_key": "k", "host": "h"}], "empty": ""})
    assert m == {"password": "********", "token_ref": "t1", "n": [{"api_key": "********", "host": "h"}], "empty": ""}


# ---------------------------------------------------------------- HTTP client
class FakeTransport:
    def __init__(self, status=200, body=b'{"ok": true}', exc=None):
        self.status, self.body, self.exc, self.calls = status, body, exc, []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers), body))
        if self.exc:
            raise self.exc
        return self.status, {}, self.body


def test_http_client_json_and_errors():
    t = FakeTransport()
    c = HttpClient("https://nas.lan:8443/api", {"Authorization": "Bearer secret"}, transport=t)
    assert c.get("/x", params={"a": 1, "b": None}) == {"ok": True}
    assert t.calls[0][1] == "https://nas.lan:8443/api/x?a=1"
    c.post("y", json_body={"k": 1})
    assert t.calls[1][3] == b'{"k": 1}' and t.calls[1][2]["Content-Type"] == "application/json"
    t.status, t.body = 401, b"denied token=abc"
    with pytest.raises(IntegrationError) as ei:
        c.get("/x")
    assert ei.value.status == 401 and "abc" not in str(ei.value)
    t.exc = OSError("connection refused")
    with pytest.raises(IntegrationError, match="refused"):
        c.get("/x")


def test_http_client_refuses_plain_http_except_loopback():
    with pytest.raises(ValidationError):
        HttpClient("http://nas.lan")
    assert HttpClient("http://127.0.0.1:2375", transport=FakeTransport()).insecure
    assert HttpClient("http://nas.lan", allow_http=True, transport=FakeTransport()).insecure
    with pytest.raises(ValidationError):
        HttpClient("ftp://x")
    assert not HttpClient("https://x", transport=FakeTransport()).insecure
    assert HttpClient("https://x", verify_tls=False, transport=FakeTransport()).insecure
    assert not HttpClient("https://x", verify_tls=False, pin_sha256="ab", transport=FakeTransport()).insecure


def test_pinned_tls_rejects_wrong_certificate(tmp_path):
    """Real TLS server with a self-signed cert: the right pin connects, a wrong pin sends nothing."""
    import http.server
    import ssl
    import subprocess
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out",
                        str(cert), "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl not available")
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"v": 1}')

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        der = ssl.PEM_cert_to_DER_cert(cert.read_text())
        good = hashlib.sha256(der).hexdigest()
        url = f"https://127.0.0.1:{srv.server_address[1]}"
        assert HttpClient(url, pin_sha256=":".join(good[i:i + 2] for i in range(0, 64, 2))).get("/") == {"v": 1}
        with pytest.raises(IntegrationError, match="fingerprint mismatch"):
            HttpClient(url, {"Authorization": "Bearer s3cret"}, pin_sha256="00" * 32).get("/")
        assert "Bearer s3cret" not in seen                # the credential never reached the server
        with pytest.raises(IntegrationError):            # default verification rejects the self-signed cert
            HttpClient(url).get("/")
    finally:
        srv.shutdown()
    assert normalize_fingerprint("AA:bb cc") == "aabbcc"


# ---------------------------------------------------------------- runners
def test_command_policy_exact_and_prefix():
    p = CommandPolicy(["cat /proc/loadavg"], ["smartctl -j -a /dev/"])
    assert p.allows("cat  /proc/loadavg")
    assert p.allows("smartctl -j -a /dev/sda")
    for bad in ("smartctl -j -a /dev/sda; reboot", "smartctl -j -a /dev/", "smartctl -j -a /dev/../etc",
                "cat /proc/loadavg && rm -rf /", "rm -rf /", "smartctl -j -a /dev/$(id)"):
        assert not p.allows(bad), bad
    with pytest.raises(ValidationError):
        p.check("reboot")


def test_fake_runner_and_run_all():
    r = FakeRunner({"a": "1", "b*": "prefix", "c": IntegrationError("down")})
    res = run_all(r, ["a", "bx", "c", "zzz"])
    assert res["a"].stdout == "1" and res["bx"].stdout == "prefix"
    assert res["c"].exit_code == 255 and res["zzz"].exit_code == 127
    with pytest.raises(ValidationError):
        run_all(FakeRunner({}, policy=CommandPolicy(["a"])), ["b"])


def test_local_runner_no_shell():
    import sys
    r = LocalRunner()
    res = r.run(f'"{sys.executable}" -c "print(1)"')
    assert res.ok and res.stdout.strip() == "1"
    assert r.run("definitely-not-a-command-xyz").exit_code == 127
    res = r.run(f'"{sys.executable}" -c "print(1); import sys" ; echo pwned')
    assert "pwned" not in res.stdout                    # ';' is an argument, not a shell operator


def test_ssh_runner_rejects_unknown_host_keys():
    import paramiko

    from netcommander.homelab.core.runners import SshRunner, SshTarget

    class FakeClient:
        policy = None

        def load_system_host_keys(self): pass
        def load_host_keys(self, p): pass
        def set_missing_host_key_policy(self, pol): FakeClient.policy = pol

        def connect(self, **kw):
            raise paramiko.SSHException("Server 'x' not found in known_hosts")
    r = SshRunner(SshTarget("10.0.0.5", password="pw"), client_factory=FakeClient)
    with pytest.raises(IntegrationError, match="not trusted"):
        r.run("uptime")
    assert isinstance(FakeClient.policy, paramiko.RejectPolicy)
    assert "pw" not in repr(r.target)


# ---------------------------------------------------------------- registry
def _reg():
    reg = Registry()
    reg.register(AdapterSpec("hypervisor", "demo", "Demo", lambda **kw: kw, (
        FieldSpec("url", required=True), FieldSpec("port", kind="int", default=8006),
        FieldSpec("verify", kind="bool", default=True), FieldSpec("token", secret=True, required=True))))
    return reg


def test_registry_validation_reports_everything():
    reg = _reg()
    with pytest.raises(ValidationError) as ei:
        reg.validate_config("hypervisor", "demo", {"token": "plain", "port": "x", "zzz": 1})
    probs = " ".join(ei.value.problems)
    assert "unknown field 'zzz'" in probs and "url is required" in probs and "port must be int" in probs
    assert "secret store" in probs
    cfg = reg.validate_config("hypervisor", "demo", {"url": "https://h", "token_ref": "t", "verify": "false"})
    assert cfg == {"url": "https://h", "port": 8006, "verify": False, "token_ref": "t"}
    with pytest.raises(NotFound):
        reg.get("hypervisor", "nope")


def test_build_adapter_resolves_secrets():
    out = build_adapter(_reg(), "hypervisor", "demo", {"url": "https://h", "token_ref": "t"},
                        lambda ref: f"value-of-{ref}", extra=1)
    assert out == {"url": "https://h", "port": 8006, "verify": True, "token": "value-of-t", "extra": 1}


def test_registry_plugins_disabled_without_allowlist():
    assert Registry().load_entry_points(None) == []


# ---------------------------------------------------------------- notifications
def test_notifier_threshold_dedup_and_failure_isolation():
    clock = FakeClock(0)
    sent = []

    class Ch:
        def __init__(self, name, sev, fail=False):
            self.name, self.min_severity, self.fail = name, sev, fail

        def send(self, n):
            if self.fail:
                raise OSError("down")
            sent.append((self.name, n.title))
    n = Notifier([Ch("all", "info"), Ch("crit", "critical"), Ch("broken", "info", fail=True)],
                 dedup_window=60, clock=clock)
    assert n.notify(Notification("disk", "80% token=abc", "warning", dedup_key="k")) == ["all"]
    assert n.notify(Notification("disk", "again", "warning", dedup_key="k")) == []
    clock.advance(61)
    assert n.notify(Notification("disk", "crit", "critical", dedup_key="k")) == ["all", "crit"]
    assert "abc" not in json.dumps(n.history)


def test_webhook_and_smtp_channels():
    t = FakeTransport()
    WebhookChannel("https://ntfy.lan/topic", token="tok", transport=t).send(Notification("t", "m"))
    assert t.calls[0][2]["Authorization"] == "Bearer tok" and json.loads(t.calls[0][3])["title"] == "t"
    with pytest.raises(ValidationError):
        WebhookChannel("http://ntfy.lan/topic")
    with pytest.raises(ValidationError):
        SmtpChannel("mail", "a@b", ["c@d"], security="none")
    log = []

    class S:
        def __init__(self, h, p): log.append(("open", h, p))
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def starttls(self, context): log.append("tls")
        def login(self, u, p): log.append(("login", u))
        def send_message(self, m): log.append(m["Subject"])
    SmtpChannel("mail", "a@b", ["c@d"], username="u", password="p", smtp_factory=S).send(
        Notification("Disk", "x", "critical"))
    assert log[1] == "tls" and log[2] == ("login", "u") and "CRITICAL" in log[3]


# ---------------------------------------------------------------- settings
def test_settings_defaults_and_validation(tmp_path):
    assert settings.load(tmp_path / "none.json")["api"]["bind"] == "127.0.0.1"
    with pytest.raises(ConfigError) as ei:
        settings.validate({"api": {"port": 0, "bind": 5, "nope": 1}, "bogus": {},
                           "discovery": {"ports": [22, 70000]}, "monitoring": {"workers": True},
                           "notifications": {"channels": [{"type": "webhook", "token": "x"}, {"type": "sms"}]}})
    p = " ".join(ei.value.problems)
    for frag in ("api.port", "api.bind", "api.nope", "bogus", "70000", "monitoring.workers", "token_ref", "sms"):
        assert frag in p, frag
    with pytest.raises(ConfigError):
        settings.validate({"api": {"tls_cert": "c"}})
    saved = settings.save(tmp_path / "h.json", {"api": {"port": 9000}})
    assert settings.load(tmp_path / "h.json")["api"]["port"] == 9000 == saved["api"]["port"]
    (tmp_path / "bad.json").write_text("{")
    with pytest.raises(ConfigError):
        settings.load(tmp_path / "bad.json")


# ---------------------------------------------------------------- authorization
def test_action_guard_flow():
    clock, log = FakeClock(0), []
    g = authz.ActionGuard(lambda *a: log.append(a), ttl=60, clock=clock)
    read = authz.Action("vm.list", Permission.VIEW)
    g.authorize("alice", Role.VIEWER, read)                          # read-only: no confirmation
    stop = authz.Action("vm.stop", Permission.CONTROL_WORKLOADS, "destructive", "pve/101", {"force": False})
    with pytest.raises(PermissionDenied):
        g.authorize("bob", Role.OPERATOR, stop)
    with pytest.raises(AuthorizationRequired) as ei:
        g.authorize("alice", Role.ADMIN, stop)
    tok = ei.value.token
    assert ei.value.details["risk"] == "destructive"
    other = authz.Action("vm.stop", Permission.CONTROL_WORKLOADS, "destructive", "pve/102", {"force": False})
    with pytest.raises(AuthorizationRequired):
        g.authorize("alice", Role.ADMIN, other, tok)                 # token bound to the target (and consumed)
    with pytest.raises(AuthorizationRequired) as ei:
        g.authorize("alice", Role.ADMIN, stop)
    tok = ei.value.token
    with pytest.raises(AuthorizationRequired):
        g.authorize("carol", Role.ADMIN, stop, tok)                  # bound to the user
    with pytest.raises(AuthorizationRequired) as ei:
        g.authorize("alice", Role.ADMIN, stop)
    tok = ei.value.token
    g.authorize("alice", Role.ADMIN, stop, tok)                      # confirmed once
    with pytest.raises(AuthorizationRequired):
        g.authorize("alice", Role.ADMIN, stop, tok)                  # never twice
    with pytest.raises(AuthorizationRequired) as ei:
        g.authorize("alice", Role.ADMIN, stop)
    clock.advance(61)
    with pytest.raises(AuthorizationRequired):
        g.authorize("alice", Role.ADMIN, stop, ei.value.token)       # expired
    assert any(a[1] == "deny.vm.stop" for a in log) and any(a[1] == "confirm.vm.stop" and a[3] == "ok" for a in log)


def test_rbac_new_permissions_preserve_old_roles():
    from netcommander.rbac import ROLE_PERMISSIONS, can
    assert ROLE_PERMISSIONS[Role.VIEWER] == frozenset({Permission.VIEW})
    assert can(Role.OPERATOR, Permission.DISCOVER) and can(Role.OPERATOR, Permission.RUN_AUTOMATION)
    assert not can(Role.OPERATOR, Permission.CONTROL_WORKLOADS)
    assert not can(Role.OPERATOR, Permission.MANAGE_INTEGRATIONS)
    assert can(Role.ADMIN, Permission.APPROVE_AUTOMATION)
    assert not can(Role.GUEST, Permission.MANAGE_INTEGRATIONS) and not can(Role.GUEST, Permission.APPROVE_AUTOMATION)
    assert can(Role.GUEST, Permission.PUSH_CONFIG)                    # 3.x guest workflow unchanged
