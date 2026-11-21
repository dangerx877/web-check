"""AuthManager: TOTP replay blocking, lockout backoff, corrupt-file recovery, disk-failure atomicity."""
from __future__ import annotations

import base64
import hashlib
import json
import os

import pyotp
import pytest
from conftest import FAST_KDF
from cryptography.fernet import Fernet

from netcommander import security
from netcommander.config import KDF_ITERATIONS, LEGACY_KDF_ITERATIONS, MAX_FREE_LOGIN_ATTEMPTS
from netcommander.security import AuthManager

EMAIL, PW = "Me@Example.com", "longpassword1"
NORM = "me@example.com"


def code_for(secret: str, clock, step_offset: int = 0) -> str:
    return pyotp.TOTP(secret).generate_otp(int(clock() // 30) + step_offset)


@pytest.fixture
def registered(auth):
    secret, _uri = auth.create_account(EMAIL, PW)
    return auth, secret


def fail_n_times(auth, n):
    for _ in range(n):
        ok, _ = auth.verify_login(EMAIL, "bad-password", "000000")
        assert not ok


# ---------------------------------------------------------------- registration
class TestRegistration:
    def test_returns_secret_and_provisioning_uri(self, auth):
        secret, uri = auth.create_account(EMAIL, PW)
        assert len(secret) >= 16 and uri.startswith("otpauth://totp/") and secret in uri
        assert "issuer=Uptime%20Funk" in uri          # product renamed to Uptime Funk in 4.0

    def test_totp_secret_is_encrypted_at_rest(self, registered):
        auth, secret = registered
        assert "totp_secret" not in auth.users[NORM]
        assert secret not in auth.auth_path.read_text()
        assert PW not in auth.auth_path.read_text()

    @pytest.mark.parametrize("email", ["", "no-at-sign", "a@b", "a b@c.com", "@c.com"])
    def test_invalid_email_rejected(self, auth, email):
        with pytest.raises(ValueError, match="valid"):
            auth.create_account(email, PW)

    def test_short_password_rejected(self, auth):
        with pytest.raises(ValueError, match="at least 10"):
            auth.create_account(EMAIL, "short")

    def test_duplicate_email_case_insensitive(self, registered):
        auth, _ = registered
        with pytest.raises(ValueError, match="already exists"):
            auth.create_account("ME@example.COM", PW)

    def test_persists_across_restart(self, registered, clock):
        auth, secret = registered
        again = AuthManager(auth.auth_path, iterations=1_000, clock=clock)
        assert again.user_exists(NORM)
        assert again.verify_login(EMAIL, PW, code_for(secret, clock))[0]

    def test_default_work_factor(self, tmp_path):
        a = AuthManager(tmp_path / "u.json")
        a.create_account(EMAIL, PW)
        assert a.users[NORM]["iterations"] == KDF_ITERATIONS == 600_000


# ---------------------------------------------------------------- login & TOTP
class TestLogin:
    def test_success_resets_counters(self, registered, clock):
        auth, secret = registered
        fail_n_times(auth, 2)
        assert auth.users[NORM]["fails"] == 2
        ok, msg = auth.verify_login(EMAIL, PW, code_for(secret, clock))
        assert ok and msg == "Authenticated" and auth.users[NORM]["fails"] == 0

    def test_replay_of_same_code_blocked(self, registered, clock):
        auth, secret = registered
        code = code_for(secret, clock)
        assert auth.verify_login(EMAIL, PW, code)[0]
        ok, msg = auth.verify_login(EMAIL, PW, code)
        assert not ok and msg == AuthManager.GENERIC_FAILURE

    def test_replay_blocked_after_restart(self, registered, clock):
        auth, secret = registered
        code = code_for(secret, clock)
        assert auth.verify_login(EMAIL, PW, code)[0]
        restarted = AuthManager(auth.auth_path, iterations=1_000, clock=clock)
        assert not restarted.verify_login(EMAIL, PW, code)[0]

    def test_older_step_than_last_used_is_rejected(self, registered, clock):
        auth, secret = registered
        assert auth.verify_login(EMAIL, PW, code_for(secret, clock, +1))[0]      # uses step now+1
        assert not auth.verify_login(EMAIL, PW, code_for(secret, clock, 0))[0]   # now < last step
        assert not auth.verify_login(EMAIL, PW, code_for(secret, clock, -1))[0]

    def test_next_period_code_accepted_after_replay_block(self, registered, clock):
        auth, secret = registered
        assert auth.verify_login(EMAIL, PW, code_for(secret, clock))[0]
        clock.advance(30)
        assert auth.verify_login(EMAIL, PW, code_for(secret, clock))[0]

    def test_clock_skew_window_is_one_step_each_way(self, registered, clock):
        auth, secret = registered
        assert not auth.verify_login(EMAIL, PW, code_for(secret, clock, +2))[0]
        assert not auth.verify_login(EMAIL, PW, code_for(secret, clock, -2))[0]
        assert auth.verify_login(EMAIL, PW, code_for(secret, clock, -1))[0]

    def test_whitespace_in_code_is_ignored(self, registered, clock):
        auth, secret = registered
        c = code_for(secret, clock)
        assert auth.verify_login(EMAIL, PW, f" {c[:3]} {c[3:]} ")[0]

    @pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 5x"])
    def test_malformed_codes_rejected(self, registered, bad):
        auth, _ = registered
        assert not auth.verify_login(EMAIL, PW, bad)[0]

    def test_email_is_case_and_space_insensitive(self, registered, clock):
        auth, secret = registered
        assert auth.verify_login("  ME@EXAMPLE.COM ", PW, code_for(secret, clock))[0]

    def test_wrong_password_and_wrong_code_look_identical(self, registered, clock):
        auth, secret = registered
        bad_pw = auth.verify_login(EMAIL, "wrong-password", code_for(secret, clock))
        bad_code = auth.verify_login(EMAIL, PW, "000000")
        assert bad_pw == bad_code == (False, AuthManager.GENERIC_FAILURE)

    def test_unknown_user(self, auth):
        assert auth.verify_login("ghost@example.com", PW, "123456") == (False, AuthManager.GENERIC_FAILURE)


# ---------------------------------------------------------------- lockout
class TestLockout:
    def test_lockout_after_max_free_attempts(self, registered, clock):
        auth, secret = registered
        fail_n_times(auth, MAX_FREE_LOGIN_ATTEMPTS - 1)
        assert auth.users[NORM]["locked_until"] == 0
        fail_n_times(auth, 1)
        assert auth.users[NORM]["locked_until"] == clock() + 30

    def test_locked_account_rejects_even_correct_credentials(self, registered, clock):
        auth, secret = registered
        fail_n_times(auth, MAX_FREE_LOGIN_ATTEMPTS)
        ok, msg = auth.verify_login(EMAIL, PW, code_for(secret, clock))
        assert not ok and "Try again in 31 seconds" in msg
        clock.advance(10)
        assert "Try again in 21 seconds" in auth.verify_login(EMAIL, PW, code_for(secret, clock))[1]

    def test_lock_expires_and_login_works_again(self, registered, clock):
        auth, secret = registered
        fail_n_times(auth, MAX_FREE_LOGIN_ATTEMPTS)
        clock.advance(31)
        assert auth.verify_login(EMAIL, PW, code_for(secret, clock))[0]
        assert auth.users[NORM]["fails"] == 0 and auth.users[NORM]["locked_until"] == 0

    def test_backoff_doubles_each_further_failure(self, registered, clock):
        auth, _ = registered
        expected = [30, 60, 120, 240, 480, 900, 900]            # capped at 15 minutes
        for delay in expected:
            fail_n_times(auth, MAX_FREE_LOGIN_ATTEMPTS if delay == 30 else 1)
            assert auth.users[NORM]["locked_until"] - clock() == delay
            clock.advance(delay + 1)

    def test_failures_during_lock_do_not_extend_it(self, registered, clock):
        auth, _ = registered
        fail_n_times(auth, MAX_FREE_LOGIN_ATTEMPTS)
        locked_until = auth.users[NORM]["locked_until"]
        fail_n_times(auth, 3)
        assert auth.users[NORM]["locked_until"] == locked_until
        assert auth.users[NORM]["fails"] == MAX_FREE_LOGIN_ATTEMPTS

    def test_lockout_survives_restart(self, registered, clock):
        auth, secret = registered
        fail_n_times(auth, MAX_FREE_LOGIN_ATTEMPTS)
        again = AuthManager(auth.auth_path, iterations=1_000, clock=clock)
        assert "Too many failed attempts" in again.verify_login(EMAIL, PW, code_for(secret, clock))[1]


# ---------------------------------------------------------------- corrupt / damaged data
class TestCorruptFiles:
    def test_invalid_json_is_preserved_not_overwritten(self, tmp_path, clock):
        f = tmp_path / "u.json"
        f.write_text("{oops")
        a = AuthManager(f, iterations=1_000, clock=clock)
        backups = list(tmp_path.glob("u.corrupt-*"))
        assert a.users == {} and a.load_warning and len(backups) == 1
        assert backups[0].read_text() == "{oops" and not f.exists()

    @pytest.mark.parametrize("content", ["[1, 2]", '{"a": 5}', '"text"', ""])
    def test_wrong_structure_treated_as_corrupt(self, tmp_path, clock, content):
        f = tmp_path / "u.json"
        f.write_text(content)
        a = AuthManager(f, iterations=1_000, clock=clock)
        assert a.users == {} and "unreadable" in a.load_warning and list(tmp_path.glob("u.corrupt-*"))

    def test_repeated_corruption_never_clobbers_earlier_backup(self, tmp_path, clock):
        f = tmp_path / "u.json"
        for n in range(3):
            f.write_text(f"{{bad{n}")
            AuthManager(f, iterations=1_000, clock=clock)        # frozen clock: same timestamp each time
        contents = sorted(p.read_text() for p in tmp_path.glob("u.corrupt-*"))
        assert contents == ["{bad0", "{bad1", "{bad2"]

    def test_can_register_after_recovery(self, tmp_path, clock):
        f = tmp_path / "u.json"
        f.write_text("{oops")
        a = AuthManager(f, iterations=1_000, clock=clock)
        a.create_account(EMAIL, PW)
        assert AuthManager(f, iterations=1_000, clock=clock).user_exists(NORM)

    def test_missing_file_is_just_empty(self, tmp_path, clock):
        a = AuthManager(tmp_path / "nope.json", iterations=1_000, clock=clock)
        assert a.users == {} and a.load_warning == ""

    def test_record_missing_fields_reports_damage(self, registered, clock):
        auth, secret = registered
        del auth.users[NORM]["salt"]
        ok, msg = auth.verify_login(EMAIL, PW, code_for(secret, clock))
        assert not ok and "damaged" in msg

    def test_garbled_totp_blob_reports_damage(self, registered, clock):
        auth, secret = registered
        auth.users[NORM]["totp_enc"] = "garbage"
        ok, msg = auth.verify_login(EMAIL, PW, code_for(secret, clock))
        assert not ok and "MFA secret is damaged" in msg


# ---------------------------------------------------------------- disk failure atomicity
@pytest.fixture
def broken_disk(monkeypatch):
    """Context-like toggle: call .fail() / .heal() to break / repair auth-file writes."""
    real = security._write_private
    state = {"broken": False}

    def flaky(path, text):
        if state["broken"]:
            raise OSError("read-only file system")
        return real(path, text)

    monkeypatch.setattr(security, "_write_private", flaky)

    class Switch:
        fail = staticmethod(lambda: state.update(broken=True))
        heal = staticmethod(lambda: state.update(broken=False))

    return Switch


class TestSaveFailureConsistency:
    def test_successful_login_refused_when_state_cannot_be_saved(self, registered, clock, broken_disk):
        auth, secret = registered
        before_mem = json.loads(json.dumps(auth.users))
        before_disk = auth.auth_path.read_text()
        code = code_for(secret, clock)

        broken_disk.fail()
        ok, msg = auth.verify_login(EMAIL, PW, code)
        assert not ok and "could not be saved" in msg
        assert auth.users == before_mem                             # memory untouched
        assert auth.users[NORM]["last_totp_step"] == -1             # code NOT marked as used
        assert auth.auth_path.read_text() == before_disk            # disk untouched

        broken_disk.heal()
        assert auth.verify_login(EMAIL, PW, code)[0]                # same code works once disk is fixed
        assert not auth.verify_login(EMAIL, PW, code)[0]            # and is then burned
        on_disk = json.loads(auth.auth_path.read_text())
        assert on_disk[NORM]["last_totp_step"] == auth.users[NORM]["last_totp_step"] >= 0

    def test_failed_attempt_not_counted_in_memory_when_it_cannot_be_saved(self, registered, broken_disk):
        auth, _ = registered
        broken_disk.fail()
        ok, msg = auth.verify_login(EMAIL, "bad-password", "000000")
        assert not ok and "could not be recorded" in msg
        assert auth.users[NORM]["fails"] == 0
        assert json.loads(auth.auth_path.read_text())[NORM]["fails"] == 0   # still agree

    def test_lock_state_never_ahead_of_disk(self, registered, clock, broken_disk):
        auth, _ = registered
        fail_n_times(auth, MAX_FREE_LOGIN_ATTEMPTS - 1)
        broken_disk.fail()
        auth.verify_login(EMAIL, "bad-password", "000000")           # would have been the locking one
        assert auth.users[NORM]["locked_until"] == 0 and auth.users[NORM]["fails"] == MAX_FREE_LOGIN_ATTEMPTS - 1
        assert json.loads(auth.auth_path.read_text())[NORM] == auth.users[NORM]

    def test_registration_failure_leaves_no_phantom_account(self, auth, broken_disk):
        broken_disk.fail()
        with pytest.raises(OSError):
            auth.create_account(EMAIL, PW)
        assert not auth.user_exists(NORM) and not auth.auth_path.exists()
        broken_disk.heal()
        auth.create_account(EMAIL, PW)                                # retry succeeds
        assert auth.user_exists(NORM)

    def test_does_not_mutate_record_object_held_by_caller(self, registered, clock, broken_disk):
        auth, secret = registered
        held = auth.users[NORM]
        broken_disk.fail()
        auth.verify_login(EMAIL, PW, code_for(secret, clock))
        assert held["last_totp_step"] == -1 and held is auth.users[NORM]


# ---------------------------------------------------------------- legacy account upgrade
def make_legacy_account(path, secret, password, iterations=LEGACY_KDF_ITERATIONS):
    """Version-1 record: plaintext TOTP secret and no 'iterations' field."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=64)
    path.write_text(json.dumps({NORM: {
        "email": NORM, "salt": base64.b64encode(salt).decode(),
        "pw_hash": base64.b64encode(dk[:32]).decode(), "totp_secret": secret,
    }}))


def test_legacy_plaintext_account_is_upgraded_on_first_login(tmp_path, clock):
    secret = pyotp.random_base32()
    path = tmp_path / "u.json"
    make_legacy_account(path, secret, PW)
    auth = AuthManager(path, clock=clock)                       # real 600k target work factor
    assert auth.verify_login(EMAIL, PW, code_for(secret, clock))[0]

    rec = auth.users[NORM]
    assert "totp_secret" not in rec and rec["totp_enc"] and rec["iterations"] == 600_000
    assert secret not in path.read_text()                       # no longer plaintext on disk
    clock.advance(30)
    assert auth.verify_login(EMAIL, PW, code_for(secret, clock))[0]   # new hash + encrypted secret work


def test_legacy_account_wrong_password_not_upgraded(tmp_path, clock):
    secret = pyotp.random_base32()
    path = tmp_path / "u.json"
    make_legacy_account(path, secret, PW)
    auth = AuthManager(path, clock=clock)
    assert not auth.verify_login(EMAIL, "wrong-password-1", code_for(secret, clock))[0]
    assert "totp_secret" in auth.users[NORM]


def test_pbkdf2_verifier_and_totp_key_are_independent(auth):
    verifier, key = AuthManager._derive("pw", b"salt" * 4, 1_000)
    assert isinstance(key, Fernet) and verifier and len(base64.b64decode(verifier)) == 32


# ---------------------------------------------------------------- several processes, one file
class TestSharedAccountsFile:
    """Two AuthManagers on one file stand in for two app windows / the CLI (separate memory and locks)."""

    def pair(self, tmp_path, clock):
        a = AuthManager(tmp_path / "u.json", iterations=FAST_KDF, clock=clock)
        secret, _ = a.create_account(EMAIL, PW)
        a.create_account("b@example.com", PW, created_by=EMAIL)
        b = AuthManager(tmp_path / "u.json", iterations=FAST_KDF, clock=clock)
        return a, b, secret

    def test_role_change_is_not_reverted_by_a_stale_process(self, tmp_path, clock):
        a, b, _ = self.pair(tmp_path, clock)
        a.set_role("b@example.com", "viewer")
        b.verify_login("b@example.com", "wrong-password!!", "000000")      # b writes with its old copy
        assert AuthManager(tmp_path / "u.json", iterations=FAST_KDF).role_of("b@example.com") == "viewer"

    def test_lockout_counts_failures_from_every_process(self, tmp_path, clock):
        a, b, secret = self.pair(tmp_path, clock)
        for mgr in (a, b, a, b, a):
            mgr.verify_login(EMAIL, "wrong-password!!", "000000")
        ok, msg = b.verify_login(EMAIL, PW, pyotp.TOTP(secret).at(clock()))
        assert not ok and "Too many failed" in msg

    def test_code_used_in_one_process_cannot_be_replayed_in_another(self, tmp_path, clock):
        a, b, secret = self.pair(tmp_path, clock)
        code = pyotp.TOTP(secret).at(clock())
        assert a.verify_login(EMAIL, PW, code)[0]
        assert not b.verify_login(EMAIL, PW, code)[0]

    def test_account_created_elsewhere_is_seen(self, tmp_path, clock):
        a, b, _ = self.pair(tmp_path, clock)
        a.create_account("c@example.com", PW, created_by=EMAIL)
        assert b.user_exists("c@example.com") and b.role_of("c@example.com") == "operator"


# ---------------------------------------------------------------- registration is admin-only after bootstrap
class TestAdminOnlyRegistration:
    def test_second_account_needs_an_admin_creator(self, auth):
        auth.create_account(EMAIL, PW)
        with pytest.raises(PermissionError):
            auth.create_account("b@example.com", PW)
        auth.create_account("op@example.com", PW, created_by=EMAIL)
        with pytest.raises(PermissionError):                                   # operators cannot create users
            auth.create_account("c@example.com", PW, created_by="op@example.com")
        with pytest.raises(PermissionError):
            auth.create_account("d@example.com", PW, created_by="nobody@example.com")
        assert sorted(auth.users) == [EMAIL.lower(), "op@example.com"]

    def test_admin_created_account_must_change_password(self, auth):
        auth.create_account(EMAIL, PW)
        assert not auth.must_change_password(EMAIL)
        auth.create_account("b@example.com", PW, created_by=EMAIL)
        assert auth.must_change_password("b@example.com") and auth.users["b@example.com"]["created_by"] == EMAIL.lower()
        auth.set_password("b@example.com", PW, "brand-new-password")
        assert not auth.must_change_password("b@example.com")


# ---------------------------------------------------------------- password-only (headless) check
class TestVerifyPassword:
    def test_right_and_wrong_password(self, auth):
        auth.create_account(EMAIL, PW)
        assert auth.verify_password(EMAIL, PW)[0]
        ok, msg = auth.verify_password(EMAIL, "wrong-password!!")
        assert not ok and msg == AuthManager.GENERIC_FAILURE and auth.users[EMAIL.lower()]["fails"] == 1
        assert not auth.verify_password("ghost@example.com", PW)[0]

    def test_failures_lock_and_success_does_not_clear_them(self, auth, clock):
        secret, _ = auth.create_account(EMAIL, PW)
        for _ in range(4):
            auth.verify_login(EMAIL, PW, "000000")                             # wrong 2FA codes
        assert auth.verify_password(EMAIL, PW)[0] and auth.users[EMAIL.lower()]["fails"] == 4
        auth.verify_login(EMAIL, PW, "000000")
        assert "Too many failed" in auth.verify_password(EMAIL, PW)[1]

    def test_events_are_reported(self, tmp_path, clock):
        events = []
        a = AuthManager(tmp_path / "u.json", iterations=FAST_KDF, clock=clock, on_event=lambda *e: events.append(e))
        a.create_account(EMAIL, PW)
        a.verify_password(EMAIL, PW)
        a.verify_password(EMAIL, "nope-nope-nope")
        assert [(e[0], e[2]) for e in events] == [("auth.password_check", "ok"), ("auth.password_check", "failed")]


# ---------------------------------------------------------------- transient read errors are not corruption
class TestUnreadableAccountsFile:
    def test_io_error_at_start_keeps_file_and_refuses_changes(self, tmp_path, clock, monkeypatch):
        path = tmp_path / "u.json"
        AuthManager(path, iterations=FAST_KDF, clock=clock).create_account(EMAIL, PW)
        original = path.read_text()
        real = type(path).read_text

        def flaky(self, *a, **k):
            if self == path:
                raise PermissionError("sharing violation")
            return real(self, *a, **k)
        monkeypatch.setattr(type(path), "read_text", flaky)
        a = AuthManager(path, iterations=FAST_KDF, clock=clock)
        assert a.users == {} and "could not be read" in a.load_warning
        assert not list(tmp_path.glob("u.corrupt-*")) and a.has_accounts()          # not "fresh install"
        with pytest.raises(OSError):
            a.create_account("attacker@example.com", PW)                          # would have become admin
        ok, msg = a.verify_login(EMAIL, PW, "123456")
        assert not ok and "could not be read" in msg
        monkeypatch.setattr(type(path), "read_text", real)                         # the problem goes away
        assert path.read_text() == original
        assert a.user_exists(EMAIL) and a.role_of(EMAIL) == "admin" and a.load_warning == ""
