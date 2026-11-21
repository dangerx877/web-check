"""CredentialVault: standard, legacy 310k, ephemeral guest, encrypt/decrypt_text, thread safety."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import threading

import pytest
from conftest import FAST_KDF, PASSWORD
from cryptography.fernet import Fernet, InvalidToken

from netcommander.config import KDF_ITERATIONS, LEGACY_KDF_ITERATIONS
from netcommander.security import CredentialVault, _write_private, credentials_from_env, safe_filename


def write_legacy_vault(path, password, entries_plain, iterations=LEGACY_KDF_ITERATIONS, store_iterations=False):
    """Create a vault file the way version-1 (310k, no 'iterations' key) did."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    f = Fernet(base64.urlsafe_b64encode(dk))
    entries = {
        dev: {"username": u, "password_enc": f.encrypt(p.encode()).decode(), "secret_enc": ""}
        for dev, (u, p) in entries_plain.items()
    }
    blob = {"version": 1, "salt": base64.b64encode(salt).decode(),
            "ciphertext": f.encrypt(json.dumps(entries).encode()).decode()}
    if store_iterations:
        blob["iterations"] = iterations
    path.write_text(json.dumps(blob))
    return f


class TestStandardVault:
    def test_roundtrip_and_no_plaintext_on_disk(self, tmp_path):
        p = tmp_path / "v.enc"
        v = CredentialVault(p, iterations=FAST_KDF)
        assert v.unlock_or_init(PASSWORD, path=p)
        v.set_secret("R1", "admin", "s3cret-pw", "enable-pw")
        raw = p.read_text()
        assert "s3cret-pw" not in raw and "enable-pw" not in raw and "admin" not in json.loads(raw)["ciphertext"]

        v2 = CredentialVault(p, iterations=FAST_KDF)
        assert v2.unlock_or_init(PASSWORD, path=p)
        assert v2.get_decrypted("R1") == ("admin", "s3cret-pw", "enable-pw")
        assert v2.has_password("R1") and not v2.has_password("R9")

    def test_new_vault_records_its_iteration_count(self, tmp_path):
        p = tmp_path / "v.enc"
        v = CredentialVault(p, iterations=FAST_KDF)
        v.unlock_or_init(PASSWORD)
        assert json.loads(p.read_text())["iterations"] == FAST_KDF == v.iterations

    def test_default_work_factor_is_600k(self, tmp_path):
        assert CredentialVault(tmp_path / "v.enc").iterations == KDF_ITERATIONS == 600_000

    def test_wrong_password_fails_and_never_overwrites(self, vault, tmp_path):
        vault.set_secret("R1", "admin", "pw")
        before = (tmp_path / "v.enc").read_text()
        bad = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        assert not bad.unlock_or_init("wrong-password", path=tmp_path / "v.enc")
        assert "does not match" in bad.last_error and not bad.unlocked
        assert (tmp_path / "v.enc").read_text() == before

    def test_corrupt_file_reported_not_overwritten(self, tmp_path):
        p = tmp_path / "v.enc"
        p.write_text("{not json")
        v = CredentialVault(p, iterations=FAST_KDF)
        assert not v.unlock_or_init(PASSWORD, path=p)
        assert "corrupt" in v.last_error
        assert p.read_text() == "{not json"

    def test_wrong_shape_payload_rejected(self, tmp_path):
        p = tmp_path / "v.enc"
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, FAST_KDF, dklen=32)
        f = Fernet(base64.urlsafe_b64encode(dk))
        p.write_text(json.dumps({"salt": base64.b64encode(salt).decode(), "iterations": FAST_KDF,
                                 "ciphertext": f.encrypt(b"[1,2,3]").decode()}))
        v = CredentialVault(p, iterations=FAST_KDF)
        assert not v.unlock_or_init(PASSWORD) and "corrupt" in v.last_error

    def test_unwritable_location_fails_cleanly(self, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("x")
        v = CredentialVault(blocker / "v.enc", iterations=FAST_KDF)   # parent is a file
        assert not v.unlock_or_init(PASSWORD)
        assert "Could not create" in v.last_error and not v.unlocked

    def test_vault_file_is_owner_only(self, vault, tmp_path):
        if sys.platform.startswith("win"):
            pytest.skip("POSIX permissions only")
        assert stat.S_IMODE(os.stat(tmp_path / "v.enc").st_mode) == 0o600

    def test_set_secret_requires_unlock(self, tmp_path):
        with pytest.raises(RuntimeError):
            CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF).set_secret("R1", "u", "p")

    def test_default_username_and_empty_password(self, vault):
        vault.set_secret("R1", "", "")
        assert vault.get_decrypted("R1") == ("admin", "", "")
        assert not vault.has_password("R1")

    def test_unknown_device_defaults(self, vault):
        assert vault.get_decrypted("nope") == ("admin", "", "")

    def test_clear_device_keeps_username_drops_secrets(self, vault, tmp_path):
        vault.set_secret("R1", "alice", "pw", "en")
        vault.clear_device("R1")
        assert vault.get_decrypted("R1") == ("alice", "", "")
        assert not vault.has_password("R1")
        reopened = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        reopened.unlock_or_init(PASSWORD)
        assert not reopened.has_password("R1")
        vault.clear_device("missing")                 # no-op, no error

    def test_remove_device(self, vault):
        vault.set_secret("R1", "u", "p")
        vault.remove_device("R1")
        vault.remove_device("R1")
        assert vault.devices() == []

    def test_per_user_paths_differ_and_are_case_insensitive(self, tmp_path):
        a = CredentialVault.path_for_user("a@x.com", tmp_path)
        assert a != CredentialVault.path_for_user("b@x.com", tmp_path)
        assert a == CredentialVault.path_for_user("  A@X.com ", tmp_path)
        assert a.parent == tmp_path and a.suffix == ".enc"

    def test_close_forgets_key_and_entries(self, vault):
        vault.set_secret("R1", "u", "p")
        vault.close()
        assert not vault.unlocked and vault.get_decrypted("R1") == ("admin", "", "")
        with pytest.raises(RuntimeError):
            vault.encrypt_text("x")

    def test_failed_write_leaves_memory_and_disk_consistent(self, vault, monkeypatch):
        vault.set_secret("R1", "u", "old")
        from netcommander import security
        monkeypatch.setattr(security, "_write_private", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError):
            vault.set_secret("R1", "u", "new")
        with pytest.raises(OSError):
            vault.set_secret("R2", "u", "x")
        with pytest.raises(OSError):
            vault.clear_device("R1")
        with pytest.raises(OSError):
            vault.remove_device("R1")
        assert vault.get_decrypted("R1") == ("u", "old", "") and vault.devices() == ["R1"]


class TestLegacyVault310k:
    def test_legacy_file_without_iterations_key_opens_and_is_upgraded_in_place(self, tmp_path):
        p = tmp_path / "v.enc"
        write_legacy_vault(p, PASSWORD, {"R1": ("admin", "legacy-pw")})
        v = CredentialVault(p)                                    # default target is 600k
        assert v.unlock_or_init(PASSWORD)
        assert v.get_decrypted("R1") == ("admin", "legacy-pw", "")
        blob = json.loads(p.read_text())
        assert blob["version"] == 3 and blob["iterations"] == KDF_ITERATIONS == v.iterations
        assert "wrapped_key" in blob and "legacy-pw" not in p.read_text()

    def test_legacy_wrong_password_rejected_and_file_untouched(self, tmp_path):
        p = tmp_path / "v.enc"
        write_legacy_vault(p, PASSWORD, {"R1": ("admin", "x")})
        before = p.read_text()
        assert not CredentialVault(p).unlock_or_init("nope-nope-nope")
        assert p.read_text() == before

    def test_upgrade_keeps_the_data_key_so_old_backups_stay_readable(self, tmp_path):
        p = tmp_path / "v.enc"
        f = write_legacy_vault(p, PASSWORD, {"R1": ("admin", "legacy-pw")})
        old_backup = f.encrypt(b"hostname OLD\n").decode()           # a pre-existing .cfg.enc payload
        v = CredentialVault(p)
        v.unlock_or_init(PASSWORD)
        assert v.decrypt_text(old_backup) == "hostname OLD\n"
        v.set_secret("R2", "u", "new-pw")
        again = CredentialVault(p)
        assert again.unlock_or_init(PASSWORD) and again.decrypt_text(old_backup) == "hostname OLD\n"
        assert again.get_decrypted("R1")[1] == "legacy-pw" and again.get_decrypted("R2")[1] == "new-pw"

    def test_failed_upgrade_write_is_not_fatal_and_retried_on_next_save(self, tmp_path, monkeypatch):
        from netcommander import security
        p = tmp_path / "v.enc"
        write_legacy_vault(p, PASSWORD, {"R1": ("admin", "pw")})
        real = security._write_private
        monkeypatch.setattr(security, "_write_private", lambda *a: (_ for _ in ()).throw(OSError("ro")))
        v = CredentialVault(p, iterations=FAST_KDF)
        assert v.unlock_or_init(PASSWORD) and v.get_decrypted("R1")[1] == "pw"
        assert "version" in json.loads(p.read_text()) and json.loads(p.read_text())["version"] == 1
        monkeypatch.setattr(security, "_write_private", real)
        v.set_secret("R2", "u", "p2")
        assert json.loads(p.read_text())["version"] == 3

    def test_stored_iterations_key_is_honoured_when_reading(self, tmp_path):
        p = tmp_path / "v.enc"
        write_legacy_vault(p, PASSWORD, {"R1": ("a", "b")}, iterations=5_000, store_iterations=True)
        v = CredentialVault(p, iterations=FAST_KDF)
        assert v.unlock_or_init(PASSWORD) and v.get_decrypted("R1") == ("a", "b", "") and v.iterations == FAST_KDF

    def test_single_shared_legacy_vault_migrates_into_per_user_path(self, tmp_path):
        legacy = tmp_path / "vault.enc"
        write_legacy_vault(legacy, PASSWORD, {"R1": ("admin", "pw")})
        user_path = CredentialVault.path_for_user("me@example.com", tmp_path / "vaults")
        v = CredentialVault(legacy)
        assert v.unlock_or_init(PASSWORD, path=user_path, legacy_path=legacy)
        assert user_path.exists() and v.get_decrypted("R1")[1] == "pw"

    def test_someone_elses_legacy_vault_is_ignored(self, tmp_path):
        legacy = tmp_path / "vault.enc"
        write_legacy_vault(legacy, "other-persons-password", {"R1": ("admin", "pw")})
        before = legacy.read_text()
        user_path = tmp_path / "vaults" / "me.enc"
        v = CredentialVault(legacy, iterations=FAST_KDF)
        assert v.unlock_or_init(PASSWORD, path=user_path, legacy_path=legacy)
        assert v.devices() == [] and legacy.read_text() == before


class TestEphemeralGuestVault:
    def test_nothing_ever_touches_disk(self, tmp_path):
        p = tmp_path / "g.enc"
        v = CredentialVault(p, iterations=FAST_KDF)
        v.unlock_ephemeral()
        v.set_secret("R1", "admin", "pw", "en")
        v.save(); v.clear_device("R1"); v.remove_device("R1")
        assert v.ephemeral and not p.exists() and list(tmp_path.iterdir()) == []

    def test_secrets_work_in_memory(self, guest_vault):
        guest_vault.set_secret("R2", "u", "pw2")
        assert guest_vault.get_decrypted("R2") == ("u", "pw2", "") and guest_vault.has_password("R2")

    def test_each_guest_session_gets_a_different_key(self, tmp_path):
        a, b = CredentialVault(tmp_path / "a"), CredentialVault(tmp_path / "b")
        a.unlock_ephemeral(); b.unlock_ephemeral()
        token = a.encrypt_text("secret")
        with pytest.raises(InvalidToken):
            b.decrypt_text(token)

    def test_unlocking_a_real_vault_clears_ephemeral_flag(self, tmp_path):
        v = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        v.unlock_ephemeral()
        assert v.unlock_or_init(PASSWORD, path=tmp_path / "v.enc")
        assert not v.ephemeral and (tmp_path / "v.enc").exists()


class TestEncryptDecryptText:
    def test_roundtrip_unicode_and_multiline(self, vault):
        text = "hostname R1\n!\ninterface Gi0/1\n description café ✓\n"
        token = vault.encrypt_text(text)
        assert text not in token and vault.decrypt_text(token) == text

    def test_decrypt_strips_whitespace(self, vault):
        assert vault.decrypt_text("  " + vault.encrypt_text("x") + "\n") == "x"

    def test_tokens_are_non_deterministic(self, vault):
        assert vault.encrypt_text("same") != vault.encrypt_text("same")

    def test_wrong_key_raises_invalid_token(self, vault, tmp_path):
        other = CredentialVault(tmp_path / "o.enc", iterations=FAST_KDF)
        other.unlock_or_init("another-password-1")
        with pytest.raises(InvalidToken):
            other.decrypt_text(vault.encrypt_text("x"))

    def test_garbage_raises_invalid_token(self, vault):
        with pytest.raises(InvalidToken):
            vault.decrypt_text("not-a-token")

    def test_locked_vault_refuses(self, tmp_path):
        v = CredentialVault(tmp_path / "v.enc")
        with pytest.raises(RuntimeError):
            v.encrypt_text("x")
        with pytest.raises(RuntimeError):
            v.decrypt_text("x")


class TestThreadSafety:
    def test_parallel_writers_lose_nothing(self, vault, tmp_path):
        errors: list[BaseException] = []

        def writer(n: int):
            try:
                for i in range(10):
                    vault.set_secret(f"R{n}-{i}", f"user{n}", f"pw{n}-{i}", "")
                    vault.get_decrypted(f"R{n}-{i}")
                    vault.has_password(f"R{n}-{i}")
                    vault.encrypt_text("x")
            except BaseException as exc:                 # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors
        assert len(vault.devices()) == 80

        reopened = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        assert reopened.unlock_or_init(PASSWORD)
        assert len(reopened.devices()) == 80                    # disk matches memory
        assert reopened.get_decrypted("R3-7") == ("user3", "pw3-7", "")

    def test_readers_during_clear_and_remove(self, vault):
        for i in range(20):
            vault.set_secret(f"D{i}", "u", "p")
        errors: list[BaseException] = []

        def churn():
            try:
                for i in range(20):
                    vault.clear_device(f"D{i}")
                    vault.remove_device(f"D{i}")
            except BaseException as exc:                 # pragma: no cover
                errors.append(exc)

        def read():
            try:
                for _ in range(200):
                    for i in range(20):
                        vault.get_decrypted(f"D{i}")
                        vault.has_password(f"D{i}")
            except BaseException as exc:                 # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=churn)] + [threading.Thread(target=read) for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors and vault.devices() == []


# ---------------------------------------------------------------- small helpers
class TestHelpers:
    @pytest.mark.parametrize("raw,expected", [
        ("R1", "R1"), ("../../evil", "evil"), ("a/b\\c", "a_b_c"), ("", "device"),
        ("..", "device"), ("core sw 1", "core_sw_1"), ("ok-name_1.2", "ok-name_1.2"), (None, "device"),
    ])
    def test_safe_filename(self, raw, expected):
        assert safe_filename(raw) == expected

    def test_write_private_is_atomic_and_leaves_no_temp_files(self, tmp_path):
        target = tmp_path / "sub" / "f.txt"
        _write_private(target, "one")
        _write_private(target, "two")
        assert target.read_text() == "two" and [p.name for p in target.parent.iterdir()] == ["f.txt"]

    def test_write_private_cleans_up_when_replace_fails(self, tmp_path, monkeypatch):
        target = tmp_path / "f.txt"
        target.write_text("keep")
        monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("nope")))
        with pytest.raises(OSError):
            _write_private(target, "new")
        monkeypatch.undo()
        assert target.read_text() == "keep" and [p.name for p in tmp_path.iterdir()] == ["f.txt"]

    def test_credentials_from_env(self):
        assert credentials_from_env({}) is None
        assert credentials_from_env({"NET_SSH_USER": "u"}) is None
        assert credentials_from_env({"NET_SSH_PASS": "p"}) == ("", "p", "")
        assert credentials_from_env(
            {"NET_SSH_USER": "u", "NET_SSH_PASS": "p", "NET_SSH_ENABLE": "e"}) == ("u", "p", "e")
