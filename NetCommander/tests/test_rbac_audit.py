from __future__ import annotations

import json

import pytest
from conftest import FAST_KDF

from netcommander.audit import AuditLog
from netcommander.rbac import Permission as P
from netcommander.rbac import PermissionDenied, Role, can, require
from netcommander.redact import redact_secrets


class TestRbac:
    def test_matrix(self):
        assert can("viewer", P.VIEW) and not can("viewer", P.RUN_SHOW)
        assert can("operator", P.BACKUP) and can("operator", P.REQUEST_DEPLOY)
        assert not can("operator", P.PUSH_CONFIG) and not can("operator", P.APPROVE_DEPLOY)
        assert all(can("admin", p) for p in P)

    def test_require_raises_with_readable_message(self):
        with pytest.raises(PermissionDenied, match="viewer.*push config"):
            require("viewer", P.PUSH_CONFIG)

    def test_role_members_are_accepted_directly(self):
        assert Role.parse(Role.ADMIN) is Role.ADMIN and can(Role.OPERATOR, P.BACKUP)

    def test_unknown_role(self):
        with pytest.raises(ValueError):
            Role.parse("root")
        assert Role.parse("root", Role.VIEWER) is Role.VIEWER

    def test_first_account_is_admin_next_default_operator(self, auth):
        auth.create_account("a@example.com", "longpassword1", role="viewer")   # role ignored for the first user
        auth.create_account("b@example.com", "longpassword1", created_by="a@example.com")
        auth.create_account("c@example.com", "longpassword1", role="viewer", created_by="a@example.com")
        assert auth.role_of("a@example.com") == "admin"
        assert auth.role_of("b@example.com") == "operator"
        assert auth.role_of("c@example.com") == "viewer"
        assert auth.role_of("ghost@example.com") == "viewer"                   # unknown = least privilege

    def test_legacy_records_without_role_keep_admin(self, auth):
        auth.create_account("a@example.com", "longpassword1")
        del auth.users["a@example.com"]["role"]
        assert auth.role_of("a@example.com") == "admin"

    def test_set_role_persists_and_protects_last_admin(self, auth):
        auth.create_account("a@example.com", "longpassword1")
        auth.create_account("b@example.com", "longpassword1", created_by="a@example.com")
        with pytest.raises(ValueError, match="last administrator"):
            auth.set_role("a@example.com", "viewer")
        auth.set_role("b@example.com", "admin")
        auth.set_role("a@example.com", "viewer")
        assert auth.list_users() == [("a@example.com", "viewer"), ("b@example.com", "admin")]
        from netcommander.security import AuthManager
        assert AuthManager(auth.auth_path, iterations=FAST_KDF).role_of("a@example.com") == "viewer"

    def test_guest_role_is_never_assignable(self, auth):
        auth.create_account("a@example.com", "longpassword1")
        with pytest.raises(ValueError):
            auth.create_account("b@example.com", "longpassword1", role="guest", created_by="a@example.com")
        with pytest.raises(ValueError):
            auth.set_role("a@example.com", "guest")

    def test_bad_role_rejected_on_create(self, auth):
        auth.create_account("a@example.com", "longpassword1")
        with pytest.raises(ValueError):
            auth.create_account("b@example.com", "longpassword1", role="superuser", created_by="a@example.com")


class TestAudit:
    def make(self, tmp_path):
        t = iter(range(1000, 2000))
        return AuditLog(tmp_path / "audit.jsonl", clock=lambda: next(t))

    def test_chain_verifies_and_survives_restart(self, tmp_path):
        log = self.make(tmp_path)
        log.record("a@x.com", "login"); log.record("a@x.com", "push", "R1", detail="ok")
        assert log.verify() == (True, "chain intact")
        again = AuditLog(log.path)
        again.record("a@x.com", "logout")
        assert again.verify()[0] and len(again.entries()) == 3

    def test_modification_deletion_and_reorder_detected(self, tmp_path):
        log = self.make(tmp_path)
        for i in range(4):
            log.record("a", f"act{i}")
        lines = log.path.read_text().splitlines()
        edited = json.loads(lines[1]); edited["actor"] = "mallory"
        log.path.write_text("\n".join([lines[0], json.dumps(edited), *lines[2:]]) + "\n")
        ok, msg = log.verify(); assert not ok and "line 2" in msg and "modified" in msg
        log.path.write_text("\n".join([lines[0], lines[2], lines[3]]) + "\n")
        ok, msg = log.verify(); assert not ok and "line 2" in msg and "chain" in msg
        log.path.write_text("\n".join([lines[0], lines[2], lines[1], lines[3]]) + "\n")
        assert not log.verify()[0]

    def test_tail_truncation_detected_by_anchor(self, tmp_path):
        log = self.make(tmp_path)
        for i in range(5):
            log.record("a", f"act{i}")
        lines = log.path.read_text().splitlines()
        log.path.write_text("\n".join(lines[:3]) + "\n")               # cut the last two entries off
        ok, msg = log.verify()
        assert not ok and "removed from the end" in msg

    def test_rewritten_log_with_same_length_detected(self, tmp_path):
        log = self.make(tmp_path)
        for i in range(3):
            log.record("a", f"act{i}")
        log.path.unlink()
        fresh = self.make(tmp_path / "other")                           # a consistent chain, but not ours
        for i in range(3):
            fresh.record("mallory", f"fake{i}")
        log.path.write_text(fresh.path.read_text())
        ok, msg = log.verify()
        assert not ok and "anchor" in msg

    def test_deleted_log_detected_by_anchor(self, tmp_path):
        log = self.make(tmp_path)
        log.record("a", "x")
        log.path.unlink()
        ok, msg = log.verify()
        assert not ok and "missing" in msg

    def test_lagging_anchor_after_crash_is_tolerated(self, tmp_path):
        log = self.make(tmp_path)
        log.record("a", "one")
        anchor = log.anchor_path.read_text()
        log.record("a", "two")
        log.anchor_path.write_text(anchor)                              # crash between log write and anchor write
        assert log.verify() == (True, "chain intact")

    def test_logs_without_anchor_still_verify(self, tmp_path):
        log = self.make(tmp_path)
        log.record("a", "one")
        log.anchor_path.unlink()
        assert log.verify() == (True, "chain intact")

    def test_one_damaged_line_does_not_hide_the_rest(self, tmp_path):
        log = self.make(tmp_path)
        for i in range(3):
            log.record("a", f"act{i}")
        lines = log.path.read_text().splitlines()
        log.path.write_text("\n".join([lines[0], "{garbage", lines[2]]) + "\n")
        assert [e["action"] for e in log.entries()] == ["act0", "act2"]
        assert not log.verify()[0]

    def test_secrets_redacted_in_detail(self, tmp_path):
        log = self.make(tmp_path)
        e = log.record("a", "push", detail="enable secret 5 $1$abc\npassword=hunter2")
        assert "hunter2" not in log.path.read_text() and "$1$abc" not in e["detail"]

    def test_io_failure_never_raises(self, tmp_path):
        blocker = tmp_path / "file"; blocker.write_text("x")
        assert AuditLog(blocker / "sub" / "audit.jsonl").record("a", "x") is None

    def test_empty_and_limit(self, tmp_path):
        log = self.make(tmp_path)
        assert log.entries() == [] and log.verify()[0]
        for i in range(5):
            log.record("a", str(i))
        assert [e["action"] for e in log.entries(2)] == ["3", "4"]

    def test_two_writers_on_one_file_keep_one_chain(self, tmp_path):
        a, b = AuditLog(tmp_path / "a.jsonl"), AuditLog(tmp_path / "a.jsonl")
        for i in range(3):
            a.record("a", f"a{i}"); b.record("b", f"b{i}")
        assert len(a.entries()) == 6 and a.verify()[0]

    def test_concurrent_writers_keep_chain_valid(self, tmp_path):
        import threading
        log = AuditLog(tmp_path / "a.jsonl")
        ts = [threading.Thread(target=lambda: [log.record("t", "x") for _ in range(25)]) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        assert len(log.entries()) == 150 and log.verify()[0]


class TestRedact:
    @pytest.mark.parametrize("line,secret", [
        ("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "$1$mERr"),
        ("username admin privilege 15 secret 9 $9$abcdef", "$9$abcdef"),
        ("snmp-server community public RO", "public"),
        ('encrypted-password "$6$salty$hash";', "$6$salty"),
        ("api_key: abc123def456", "abc123def456"),
        ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
    ])
    def test_secret_removed(self, line, secret):
        out = redact_secrets(line)
        assert secret not in out and "<redacted>" in out

    def test_normal_lines_untouched(self):
        text = "interface Gi0/1\n description uplink\n ip address 10.0.0.1 255.255.255.0"
        assert redact_secrets(text) == text
