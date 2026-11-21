"""Inventory JSON/CSV load & save, including key_file import."""
from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from netcommander.network import import_inventory_csv, load_inventory_json, save_inventory_json
from netcommander.store import make_device, reciprocate_peers


def test_json_roundtrip_never_persists_passwords(tmp_path):
    d = {"A": make_device({"host": "1.1.1.1", "password": "x", "secret": "y"}, ["B"]),
         "B": make_device({"host": "2.2.2.2"})}
    reciprocate_peers(d)
    d["A"]["links"]["B"] = {"local_intf": "Gi1", "remote_intf": "Gi2", "protocol": "LLDP"}
    f = save_inventory_json(d, tmp_path / "t.json")
    text = f.read_text()
    assert "password" not in text and '"x"' not in text and '"y"' not in text
    loaded = load_inventory_json(f)
    assert loaded["B"]["peers"] == ["A"] and loaded["A"]["links"]["B"]["protocol"] == "LLDP"
    assert loaded["A"]["status"] == "unknown" and not list(tmp_path.glob("*.tmp"))


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permissions")
def test_saved_inventory_is_owner_only(tmp_path):
    f = save_inventory_json({"A": make_device({"host": "h"})}, tmp_path / "t.json")
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600


def test_json_load_normalizes_names_and_tolerates_junk(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({
        " r1 ": {"params": {"host": "1.1.1.1"}, "peers": [" r2 ", 5, ""], "links": {"r2": {"local_intf": "1"}, "x": 3}},
        "r2": {"params": "not-a-dict", "peers": "nope", "links": []},
        "bad": 7, "": {"params": {}},
    }))
    d = load_inventory_json(f, default_username="ops")
    assert set(d) == {"R1", "R2"}
    assert d["R1"]["peers"] == ["R2"] and list(d["R1"]["links"]) == ["R2"]
    assert d["R2"]["params"]["username"] == "ops" and d["R2"]["peers"] == ["R1"]


@pytest.mark.parametrize("content", ["[]", '"x"', "5"])
def test_json_top_level_must_be_object(tmp_path, content):
    f = tmp_path / "t.json"
    f.write_text(content)
    with pytest.raises(ValueError):
        load_inventory_json(f)


def test_json_invalid_syntax_raises(tmp_path):
    f = tmp_path / "t.json"
    f.write_text("{oops")
    with pytest.raises(ValueError):
        load_inventory_json(f)


class TestCsv:
    def write(self, tmp_path, text, encoding="utf-8"):
        f = tmp_path / "d.csv"
        f.write_bytes(text.encode(encoding))
        return f

    def test_port_and_peers(self, tmp_path):
        d = import_inventory_csv(self.write(tmp_path, "name,host,device_type,port,peers\nr1.lab,10.0.0.1,cisco_ios,2222,\"R2;R3|r4,r5\"\n"))
        assert d["R1"]["params"]["port"] == 2222
        assert d["R1"]["peers"] == ["R2", "R3", "R4", "R5"]

    def test_key_file_switches_device_to_key_login(self, tmp_path):
        p = import_inventory_csv(self.write(tmp_path, "name,host,key_file\nr1,10.0.0.1,/home/me/.ssh/id_ed25519\nr2,10.0.0.2,\n"))
        assert p["R1"]["params"]["use_keys"] is True and p["R1"]["params"]["key_file"] == "/home/me/.ssh/id_ed25519"
        assert "use_keys" not in p["R2"]["params"] and "key_file" not in p["R2"]["params"]

    def test_key_file_survives_json_roundtrip(self, tmp_path):
        d = import_inventory_csv(self.write(tmp_path, "name,host,key_file\nr1,10.0.0.1,~/.ssh/id_rsa\n"))
        loaded = load_inventory_json(save_inventory_json(d, tmp_path / "t.json"))
        assert loaded["R1"]["params"]["use_keys"] is True and loaded["R1"]["params"]["key_file"] == "~/.ssh/id_rsa"

    def test_aliases_bom_and_header_case(self, tmp_path):
        d = import_inventory_csv(self.write(tmp_path, "﻿Hostname,IP,Type,Username\nsw9,10.9.9.9,arista_eos,bob\n"))
        assert d["SW9"]["params"] == {"device_type": "arista_eos", "host": "10.9.9.9", "username": "bob", "timeout": 10}

    def test_rows_missing_name_or_host_skipped_and_defaults_applied(self, tmp_path):
        d = import_inventory_csv(self.write(tmp_path, "name,host,port\n,1.1.1.1,22\nx,,22\nok,2.2.2.2,abc\n"), default_username="ops")
        assert list(d) == ["OK"] and d["OK"]["params"]["username"] == "ops" and "port" not in d["OK"]["params"]
        assert d["OK"]["params"]["device_type"] == "cisco_ios"

    def test_ragged_rows_do_not_crash(self, tmp_path):
        assert list(import_inventory_csv(self.write(tmp_path, "name,host\na,1.1.1.1,extra,more\nb\n"))) == ["A"]

    def test_sample_file_in_repo_parses(self):
        from pathlib import Path
        d = import_inventory_csv(Path(__file__).resolve().parent.parent / "sample_inventory.csv")
        assert len(d) == 4 and d["ACC-SW1"]["params"]["use_keys"] is True
