"""Enumeration resistance, recovery codes, password change (account + vault), 2FA rotation, vault export/import."""
from __future__ import annotations

import pyotp
import pytest
from conftest import FAST_KDF, PASSWORD
from cryptography.fernet import InvalidToken

from netcommander import security
from netcommander.network import read_snapshot, save_config_snapshot
from netcommander.security import AuthManager, CredentialVault, change_account_password

EMAIL, PW = "me@example.com", "longpassword1"


def code(secret, clock, offset=0):
    return pyotp.TOTP(secret).generate_otp(int(clock() // 30) + offset)


@pytest.fixture
def account(auth, clock, tmp_path):
    secret, _ = auth.create_account(EMAIL, PW)
    vault = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
    assert vault.unlock_or_init(PW)
    return auth, vault, secret


# ---------------------------------------------------------------- enumeration
class TestNoEnumeration:
    def test_unknown_and_known_accounts_get_identical_messages(self, account, clock):
        auth, _, secret = account
        unknown = auth.verify_login("ghost@example.com", PW, "123456")
        wrong_pw = auth.verify_login(EMAIL, "wrong-password", "123456")
        wrong_code = auth.verify_login(EMAIL, PW, "000000")
        assert unknown == wrong_pw == wrong_code == (False, AuthManager.GENERIC_FAILURE)

    def test_unknown_account_does_the_same_expensive_work(self, tmp_path, clock, monkeypatch):
        auth = AuthManager(tmp_path / "u.json", iterations=FAST_KDF, clock=clock)
        calls = []
        real = AuthManager._derive
        monkeypatch.setattr(AuthManager, "_derive", staticmethod(lambda *a: calls.append(a) or real(*a)))
        auth.verify_login("ghost@example.com", PW, "123456")
        assert len(calls) == 1 and calls[0][2] == FAST_KDF

    def test_unknown_account_never_touches_disk(self, auth):
        auth.verify_login("ghost@example.com", PW, "123456")
        assert not auth.auth_path.exists()


# ---------------------------------------------------------------- recovery codes
class TestRecoveryCodes:
    def test_generate_returns_formatted_codes_and_stores_only_hashes(self, account):
        auth, _, _ = account
        codes = auth.generate_recovery_codes(EMAIL, PW)
        assert len(codes) == 8 and len(set(codes)) == 8
        assert all(len(c) == 11 and c[5] == "-" for c in codes)
        text = auth.auth_path.read_text()
        assert all(c.replace("-", "") not in text for c in codes)
        assert auth.recovery_codes_left(EMAIL) == 8

    def test_wrong_password_cannot_generate(self, account):
        auth, _, _ = account
        with pytest.raises(ValueError):
            auth.generate_recovery_codes(EMAIL, "wrong-password")
        with pytest.raises(ValueError):
            auth.generate_recovery_codes("ghost@example.com", PW)

    def test_code_replaces_authenticator_exactly_once(self, account, clock):
        auth, _, _ = account
        codes = auth.generate_recovery_codes(EMAIL, PW)
        ok, msg = auth.verify_login(EMAIL, PW, codes[0])
        assert ok and "recovery code" in msg and "7 left" in msg
        assert not auth.verify_login(EMAIL, PW, codes[0])[0]               # single use
        assert auth.verify_login(EMAIL, PW, codes[1].lower().replace("-", " "))[0]   # forgiving format
        assert auth.recovery_codes_left(EMAIL) == 6

    def test_recovery_code_still_needs_the_password(self, account):
        auth, _, _ = account
        codes = auth.generate_recovery_codes(EMAIL, PW)
        assert not auth.verify_login(EMAIL, "wrong-password", codes[0])[0]
        assert auth.recovery_codes_left(EMAIL) == 8

    def test_wrong_recovery_codes_count_towards_lockout(self, account):
        auth, _, _ = account
        auth.generate_recovery_codes(EMAIL, PW)
        for _ in range(5):
            assert not auth.verify_login(EMAIL, PW, "AAAAA-BBBBB")[0]
        assert "Too many failed attempts" in auth.verify_login(EMAIL, PW, "AAAAA-BBBBB")[1]

    def test_regenerating_invalidates_old_codes(self, account):
        auth, _, _ = account
        old = auth.generate_recovery_codes(EMAIL, PW)
        auth.generate_recovery_codes(EMAIL, PW)
        assert not auth.verify_login(EMAIL, PW, old[0])[0]

    def test_codes_survive_restart(self, account, clock):
        auth, _, _ = account
        codes = auth.generate_recovery_codes(EMAIL, PW)
        again = AuthManager(auth.auth_path, iterations=FAST_KDF, clock=clock)
        assert again.verify_login(EMAIL, PW, codes[3])[0]

    def test_disk_failure_refuses_login_and_keeps_code_unspent(self, account, monkeypatch):
        auth, _, _ = account
        codes = auth.generate_recovery_codes(EMAIL, PW)
        real = security._write_private
        monkeypatch.setattr(security, "_write_private", lambda *a: (_ for _ in ()).throw(OSError("ro")))
        assert not auth.verify_login(EMAIL, PW, codes[0])[0]
        monkeypatch.setattr(security, "_write_private", real)
        assert auth.recovery_codes_left(EMAIL) == 8 and auth.verify_login(EMAIL, PW, codes[0])[0]

    def test_generate_failure_leaves_old_codes_valid(self, account, monkeypatch):
        auth, _, _ = account
        old = auth.generate_recovery_codes(EMAIL, PW)
        monkeypatch.setattr(security, "_write_private", lambda *a: (_ for _ in ()).throw(OSError("ro")))
        with pytest.raises(OSError):
            auth.generate_recovery_codes(EMAIL, PW)
        monkeypatch.undo()
        assert auth.verify_login(EMAIL, PW, old[0])[0]


# ---------------------------------------------------------------- vault password change
class TestVaultPasswordChange:
    def test_change_password_rewraps_without_orphaning_backups(self, tmp_path):
        v = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        v.unlock_or_init(PASSWORD)
        v.set_secret("R1", "u", "pw1", "en")
        backup = save_config_snapshot("R1", "hostname A\n", tmp_path, vault=v)
        v.change_password(PASSWORD, "brand-new-password")

        again = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        assert not again.unlock_or_init(PASSWORD)                         # old password dead
        assert again.unlock_or_init("brand-new-password")
        assert again.get_decrypted("R1") == ("u", "pw1", "en")
        assert read_snapshot(backup, again) == "hostname A\n"             # old backup still readable

    def test_validation(self, vault):
        with pytest.raises(ValueError, match="current password"):
            vault.change_password("wrong", "another-long-password")
        with pytest.raises(ValueError, match="at least 10"):
            vault.change_password(PASSWORD, "short")

    def test_guest_vault_cannot_change_password(self, guest_vault):
        with pytest.raises(RuntimeError):
            guest_vault.change_password("a", "b" * 12)

    def test_write_failure_changes_nothing(self, vault, tmp_path, monkeypatch):
        before = (tmp_path / "v.enc").read_text()
        monkeypatch.setattr(security, "_write_private", lambda *a: (_ for _ in ()).throw(OSError("ro")))
        with pytest.raises(OSError):
            vault.change_password(PASSWORD, "brand-new-password")
        monkeypatch.undo()
        assert (tmp_path / "v.enc").read_text() == before
        vault.change_password(PASSWORD, "brand-new-password")             # in-memory state was untouched

    def test_new_vault_uses_random_data_key_not_password_derived(self, tmp_path):
        a, b = CredentialVault(tmp_path / "a.enc", iterations=FAST_KDF), CredentialVault(tmp_path / "b.enc", iterations=FAST_KDF)
        a.unlock_or_init(PASSWORD); b.unlock_or_init(PASSWORD)             # same password, different vaults
        with pytest.raises(InvalidToken):
            b.decrypt_text(a.encrypt_text("x"))


class TestChangeAccountPassword:
    def test_changes_account_and_vault_together(self, account, clock):
        auth, vault, secret = account
        vault.set_secret("R1", "u", "devpw")
        change_account_password(auth, vault, EMAIL, PW, "a-brand-new-pass", code(secret, clock))
        clock.advance(30)
        assert not auth.verify_login(EMAIL, PW, code(secret, clock))[0]
        assert auth.verify_login(EMAIL, "a-brand-new-pass", code(secret, clock))[0]     # 2FA secret kept
        assert vault.get_decrypted("R1")[1] == "devpw"

    def test_requires_current_password_and_code(self, account, clock):
        auth, vault, secret = account
        with pytest.raises(PermissionError):
            change_account_password(auth, vault, EMAIL, PW, "a-brand-new-pass", "000000")
        with pytest.raises(PermissionError):
            change_account_password(auth, vault, EMAIL, "wrong-password", "a-brand-new-pass", code(secret, clock))

    def test_input_validation_does_not_burn_the_code(self, account, clock):
        auth, vault, secret = account
        c = code(secret, clock)
        for bad in ("short", PW):
            with pytest.raises(ValueError):
                change_account_password(auth, vault, EMAIL, PW, bad, c)
        assert auth.verify_login(EMAIL, PW, c)[0]

    def test_guest_refused(self, auth, guest_vault):
        with pytest.raises(RuntimeError):
            change_account_password(auth, guest_vault, EMAIL, PW, "a-brand-new-pass", "123456")

    def test_account_write_failure_rolls_the_vault_back(self, account, clock, tmp_path, monkeypatch):
        auth, vault, secret = account
        calls = {"n": 0}
        real = security._write_private

        def flaky(path, text):
            # let the vault re-wrap and its rollback succeed; fail only the account file
            if str(path) == str(auth.auth_path) and calls["n"] >= 1:
                raise OSError("disk full")
            if str(path) == str(auth.auth_path):
                calls["n"] += 1                       # the verify_login commit
            return real(path, text)

        monkeypatch.setattr(security, "_write_private", flaky)
        with pytest.raises(OSError):
            change_account_password(auth, vault, EMAIL, PW, "a-brand-new-pass", code(secret, clock))
        monkeypatch.setattr(security, "_write_private", real)
        reopened = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        assert reopened.unlock_or_init(PW) and not CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF).unlock_or_init("a-brand-new-pass")
        clock.advance(30)
        assert auth.verify_login(EMAIL, PW, code(secret, clock))[0]       # account still has the old password


# ---------------------------------------------------------------- 2FA rotation
class TestRotateTotp:
    def test_new_secret_works_old_one_dies(self, account, clock):
        auth, _, old_secret = account
        new_secret, uri = auth.rotate_totp(EMAIL, PW)
        assert new_secret != old_secret and uri.startswith("otpauth://") and new_secret not in auth.auth_path.read_text()
        assert not auth.verify_login(EMAIL, PW, code(old_secret, clock))[0]
        assert auth.verify_login(EMAIL, PW, code(new_secret, clock))[0]

    def test_requires_password(self, account):
        auth, _, _ = account
        with pytest.raises(ValueError):
            auth.rotate_totp(EMAIL, "wrong-password")


# ---------------------------------------------------------------- export / import
class TestVaultExportImport:
    def test_recover_vault_and_backups_after_losing_the_vault_password(self, tmp_path):
        v = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        v.unlock_or_init(PASSWORD)
        v.set_secret("R1", "alice", "devpw", "en")
        backup = save_config_snapshot("R1", "hostname KEEPME\n", tmp_path, vault=v)
        export = v.export_encrypted(tmp_path / "recovery.json", "export-passphrase-1")
        assert "devpw" not in export.read_text() and "KEEPME" not in export.read_text()

        restored = CredentialVault(tmp_path / "new.enc", iterations=FAST_KDF)
        assert restored.import_export(export, "export-passphrase-1", "my-new-master-pw", path=tmp_path / "new.enc")
        assert restored.get_decrypted("R1") == ("alice", "devpw", "en")
        assert read_snapshot(backup, restored) == "hostname KEEPME\n"
        reopened = CredentialVault(tmp_path / "new.enc", iterations=FAST_KDF)
        assert reopened.unlock_or_init("my-new-master-pw") and reopened.has_password("R1")

    def test_wrong_passphrase_and_garbage(self, vault, tmp_path):
        export = vault.export_encrypted(tmp_path / "r.json", "export-passphrase-1")
        target = CredentialVault(tmp_path / "n.enc", iterations=FAST_KDF)
        assert not target.import_export(export, "wrong-passphrase!", "my-new-master-pw", path=tmp_path / "n.enc")
        assert "does not match" in target.last_error and not (tmp_path / "n.enc").exists()
        junk = tmp_path / "junk.json"; junk.write_text('{"format": "other"}')
        assert not target.import_export(junk, "x" * 12, "my-new-master-pw", path=tmp_path / "n.enc")
        assert "corrupt" in target.last_error

    def test_import_never_overwrites_an_existing_vault(self, vault, tmp_path):
        export = vault.export_encrypted(tmp_path / "r.json", "export-passphrase-1")
        before = (tmp_path / "v.enc").read_text()
        other = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
        assert not other.import_export(export, "export-passphrase-1", "my-new-master-pw", path=tmp_path / "v.enc")
        assert "already exists" in other.last_error and (tmp_path / "v.enc").read_text() == before

    def test_weak_secrets_rejected_and_guest_cannot_export(self, vault, guest_vault, tmp_path):
        with pytest.raises(ValueError):
            vault.export_encrypted(tmp_path / "r.json", "short")
        with pytest.raises(RuntimeError):
            guest_vault.export_encrypted(tmp_path / "r.json", "export-passphrase-1")
        export = vault.export_encrypted(tmp_path / "r.json", "export-passphrase-1")
        t = CredentialVault(tmp_path / "n.enc", iterations=FAST_KDF)
        assert not t.import_export(export, "export-passphrase-1", "short", path=tmp_path / "n.enc")

    def test_unlock_existing_never_creates(self, tmp_path):
        v = CredentialVault(tmp_path / "none.enc", iterations=FAST_KDF)
        assert not v.unlock_existing(PASSWORD) and "No vault found" in v.last_error and not (tmp_path / "none.enc").exists()


# ---------------------------------------------------------------- Windows reserved names
@pytest.mark.parametrize("name", ["CON", "con", "NUL", "aux.txt", "COM1", "lpt9", "PRN.cfg"])
def test_windows_reserved_device_names_are_prefixed(name):
    out = security.safe_filename(name)
    assert out.startswith("_") and out.lstrip("_").lower().startswith(name[:3].lower())


@pytest.mark.parametrize("name", ["CONSOLE", "COM10", "LPT", "console1", "NULL1"])
def test_names_merely_starting_with_reserved_words_are_untouched(name):
    assert security.safe_filename(name) == name
