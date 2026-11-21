"""Encrypted/plain config backups, listing, pruning and diffing."""
from __future__ import annotations

import re

import pytest
from conftest import FAST_KDF

from netcommander.network import (
    diff_snapshots,
    list_snapshots,
    prune_snapshots,
    read_snapshot,
    save_config_snapshot,
)
from netcommander.security import CredentialVault


def test_encrypted_backup_roundtrip_and_diff(tmp_path, vault):
    a = save_config_snapshot("R1", "hostname A\nenable secret 5 abc\n", tmp_path, vault=vault, tag="pre")
    b = save_config_snapshot("R1", "hostname B\nenable secret 5 abc\n", tmp_path, vault=vault, tag="post")
    assert a.name.endswith("_pre.cfg.enc") and b.name.endswith("_post.cfg.enc")
    assert "hostname" not in a.read_text() and "secret" not in a.read_text()
    assert list_snapshots("R1", tmp_path) == [a, b]
    assert read_snapshot(a, vault) == "hostname A\nenable secret 5 abc\n"
    d = diff_snapshots(a, b, vault)
    assert "-hostname A" in d and "+hostname B" in d and "enable secret" not in d.replace(" enable secret", "")


def test_encrypted_backup_needs_the_right_key(tmp_path, vault):
    f = save_config_snapshot("R1", "hostname A\n", tmp_path, vault=vault)
    with pytest.raises(RuntimeError, match="not Guest"):
        read_snapshot(f, None)
    other = CredentialVault(tmp_path / "o.enc", iterations=FAST_KDF)
    other.unlock_or_init("another-password-1")
    with pytest.raises(RuntimeError, match="different account"):
        read_snapshot(f, other)


def test_guest_backups_are_plain_text_and_readable_without_a_vault(tmp_path, guest_vault):
    f = save_config_snapshot("R1", "hostname B\n", tmp_path, vault=guest_vault)
    assert f.name.endswith(".cfg") and not f.name.endswith(".enc")
    assert read_snapshot(f, None) == "hostname B\n"


def test_guest_cannot_read_a_real_accounts_encrypted_backup(tmp_path, vault, guest_vault):
    f = save_config_snapshot("R1", "hostname A\n", tmp_path, vault=vault)
    with pytest.raises(RuntimeError, match="different account"):
        read_snapshot(f, guest_vault)


def test_mixed_plain_and_encrypted_diff(tmp_path, vault):
    plain = save_config_snapshot("R1", "hostname A\n", tmp_path, vault=None)
    enc = save_config_snapshot("R1", "hostname B\n", tmp_path, vault=vault)
    assert "+hostname B" in diff_snapshots(plain, enc, vault)


def test_diff_ignores_noise_lines(tmp_path):
    a = save_config_snapshot("R1", "! Last configuration change at 1\nBuilding configuration...\nhostname A\n", tmp_path)
    b = save_config_snapshot("R1", "! Last configuration change at 2\nBuilding configuration...\nhostname A\n", tmp_path)
    assert diff_snapshots(a, b) == ""


@pytest.mark.parametrize("name", ["../../evil", "..\\..\\evil", "/etc/passwd", "a/b/c", "", ".."])
def test_device_names_cannot_escape_the_backup_root(tmp_path, name):
    root = tmp_path / "backups"
    out = save_config_snapshot(name, "cfg", root)
    assert root.resolve() in out.resolve().parents and out.exists()
    assert not (tmp_path / "evil").exists()


def test_filenames_never_collide_even_with_identical_timestamps(tmp_path, monkeypatch):
    from netcommander import network

    class FrozenDT(network.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2024, 1, 2, 3, 4, 5, 6)

    monkeypatch.setattr(network, "datetime", FrozenDT)
    files = {save_config_snapshot("R1", f"cfg{i}", tmp_path, tag="pre") for i in range(4)}
    assert len(files) == 4 and len(list_snapshots("R1", tmp_path)) == 4


def test_list_snapshots_sorted_oldest_first_across_formats(tmp_path):
    d = tmp_path / "R1"
    d.mkdir()
    names = ["R1_20240102_000000_000001_post.cfg.enc", "R1_20240101_235959.cfg", "R1_20240102_000000_000001_pre.cfg",
             "R1_20240101_235959_500000.cfg.enc"]
    for n in names:
        (d / n).write_text("x")
    (d / "notes.txt").write_text("ignored")
    got = [p.name for p in list_snapshots("R1", tmp_path)]
    assert got == ["R1_20240101_235959.cfg", "R1_20240101_235959_500000.cfg.enc",
                   "R1_20240102_000000_000001_post.cfg.enc", "R1_20240102_000000_000001_pre.cfg"]


def test_device_name_containing_a_timestamp_does_not_confuse_ordering(tmp_path):
    first = save_config_snapshot("R_20990101_000000", "a", tmp_path)
    second = save_config_snapshot("R_20990101_000000", "b", tmp_path)
    assert list_snapshots("R_20990101_000000", tmp_path) == [first, second]


def test_list_snapshots_missing_folder(tmp_path):
    assert list_snapshots("nobody", tmp_path) == []


def test_prune_keeps_newest(tmp_path):
    files = [save_config_snapshot("R1", str(i), tmp_path) for i in range(5)]
    removed = prune_snapshots("R1", 2, tmp_path)
    assert removed == files[:3] and list_snapshots("R1", tmp_path) == files[3:]
    assert prune_snapshots("R1", 10, tmp_path) == []
    with pytest.raises(ValueError):
        prune_snapshots("R1", 0, tmp_path)


def test_backups_are_owner_only(tmp_path, vault):
    import os
    import stat
    import sys
    f = save_config_snapshot("R1", "x", tmp_path, vault=vault)
    if not sys.platform.startswith("win"):
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert re.search(r"R1_\d{8}_\d{6}_\d{6}\.cfg\.enc$", f.name)


class TestBackupFolderUniqueness:
    def test_names_that_sanitise_alike_get_separate_folders(self, tmp_path):
        from netcommander.network import device_dirname, list_snapshots, prune_snapshots, save_config_snapshot
        assert device_dirname("R1_A") == "R1_A"                       # safe names keep their folder
        assert device_dirname("R1/A") != device_dirname("R1_A")
        a = save_config_snapshot("R1/A", "hostname slash", tmp_path)
        b = save_config_snapshot("R1_A", "hostname under", tmp_path)
        assert a.parent != b.parent and a.parent.parent == tmp_path    # still inside the backup root
        assert [p.read_text() for p in list_snapshots("R1/A", tmp_path, include_legacy=False)] == ["hostname slash"]
        assert [p.read_text() for p in list_snapshots("R1_A", tmp_path)] == ["hostname under"]
        prune_snapshots("R1/A", 1, tmp_path)
        assert b.exists()

    def test_traversal_names_stay_inside_root(self, tmp_path):
        from netcommander.network import save_config_snapshot
        p = save_config_snapshot("../../etc/passwd", "x", tmp_path)
        assert tmp_path in p.resolve().parents

    def test_legacy_folder_is_listed_but_never_pruned(self, tmp_path):
        from netcommander.network import list_snapshots, prune_snapshots, save_config_snapshot
        legacy = tmp_path / "R1_A"
        legacy.mkdir()
        old = legacy / "R1_A_20200101_000000.cfg"
        old.write_text("old")
        save_config_snapshot("R1/A", "new1", tmp_path)
        save_config_snapshot("R1/A", "new2", tmp_path)
        assert [p.read_text() for p in list_snapshots("R1/A", tmp_path)] == ["old", "new1", "new2"]
        prune_snapshots("R1/A", 1, tmp_path)
        assert old.exists() and [p.read_text() for p in list_snapshots("R1/A", tmp_path)] == ["old", "new2"]
