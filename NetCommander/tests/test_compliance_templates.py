from __future__ import annotations

import json

import pytest

from netcommander import compliance as C
from netcommander import templates as T

CFG_OK = "hostname R1\nntp server 10.0.0.1\nservice password-encryption\nlogging host 10.0.0.9\n"
CFG_BAD = "hostname R2\nsnmp-server community public RO\nip http server\n"
POLICY = [
    {"id": "ntp", "type": "must_contain", "pattern": r"^ntp server", "severity": "high", "description": "NTP"},
    {"id": "no-http", "type": "must_not_contain", "pattern": r"^ip http server", "severity": "critical"},
    {"id": "syslog", "type": "must_match_count", "pattern": r"^logging host", "min": 1, "max": 2},
    {"id": "ios-only", "type": "must_contain", "pattern": "service password-encryption", "device_types": ["cisco_ios"]},
]


class TestCompliance:
    def test_pass_and_fail(self):
        rules = C.load_policy(POLICY)
        ok = C.evaluate("R1", "cisco_ios", CFG_OK, rules)
        bad = C.evaluate("R2", "cisco_ios", CFG_BAD, rules)
        assert ok.compliant and ok.checked == 4
        assert {f.rule_id for f in bad.findings} == {"ntp", "no-http", "syslog", "ios-only"}

    def test_device_type_scoping(self):
        rules = C.load_policy(POLICY)
        res = C.evaluate("J1", "juniper_junos", CFG_BAD, rules)
        assert res.checked == 3 and "ios-only" not in {f.rule_id for f in res.findings}

    def test_count_bounds(self):
        r = C.load_policy([{"id": "c", "type": "must_match_count", "pattern": "^x", "max": 1}])[0]
        assert r.check("x\n")[0] and not r.check("x\nx\n")[0]

    def test_run_over_inventory_with_missing_snapshot(self):
        devs = {"R1": {"device_type": "cisco_ios"}, "R2": {"device_type": "cisco_ios"}, "R3": {}}
        cfgs = {"R1": CFG_OK, "R2": CFG_BAD}

        def get(n):
            if n not in cfgs:
                raise FileNotFoundError("no snapshot yet")
            return cfgs[n]

        res = C.run_compliance(devs, C.load_policy(POLICY), get)
        s = C.summarize(res)
        assert [r.device for r in res] == ["R1", "R2", "R3"]
        assert s["devices"] == 3 and s["compliant"] == 1 and s["non_compliant"] == 1 and s["errors"] == 1
        assert s["findings_by_severity"]["critical"] == 1 and s["score"] == 33.3
        text = C.report_text(res)
        assert "✓ R1" in text and "✗ R2" in text and "? R3" in text and text.index("CRITICAL") < text.index("HIGH")
        rows = C.report_csv_rows(res)
        assert rows[0][0] == "device" and any(r[1] == "unchecked" for r in rows)

    def test_empty_inventory_is_100(self):
        assert C.summarize([])["score"] == 100.0

    @pytest.mark.parametrize("bad", [
        [{"id": "a", "type": "nope", "pattern": "x"}],
        [{"id": "a", "type": "must_contain", "pattern": "("}],
        [{"id": "a", "type": "must_contain", "pattern": "x", "severity": "meh"}],
        [{"id": "a", "type": "must_match_count", "pattern": "x"}],
        [{"id": "a", "type": "must_contain", "pattern": "x"}, {"id": "a", "type": "must_contain", "pattern": "y"}],
        [{"type": "must_contain", "pattern": "x"}],
        "not-a-list",
    ])
    def test_invalid_policies_rejected(self, bad):
        with pytest.raises(C.PolicyError):
            C.load_policy(bad)

    def test_load_from_file_and_wrapped_form(self, tmp_path):
        p = tmp_path / "p.json"
        p.write_text(json.dumps({"rules": POLICY}))
        assert len(C.load_policy(p)) == 4
        with pytest.raises(C.PolicyError):
            C.load_policy(tmp_path / "missing.json")


class TestTemplates:
    def test_render_defaults_and_required(self):
        tpl = "hostname {{name}}\nntp server {{ntp}}\ninterface {{up|Gi0/1}}"
        assert T.render(tpl, {"name": "R1", "ntp": "1.1.1.1"}) == "hostname R1\nntp server 1.1.1.1\ninterface Gi0/1"
        with pytest.raises(T.TemplateError, match="ntp"):
            T.render(tpl, {"name": "R1"}, who="R1")
        assert T.variables_in(tpl) == {"name": None, "ntp": None, "up": "Gi0/1"}

    def test_empty_value_falls_back_to_default(self):
        assert T.render("{{a|x}}", {"a": ""}) == "x"

    def test_no_code_execution(self):
        with pytest.raises(T.TemplateError):
            T.render("{{ x }} {{y}}", {})                      # only plain names are supported

    def test_render_for_devices_merges_scopes_and_reports_all_problems(self):
        devs = {"R1": {"ip": "10.0.0.1"}, "R2": {"ip": "10.0.0.2"}, "R3": {"ip": "10.0.0.3"}}
        tpl = "hostname {{name}}\nsnmp location {{site}}\n\nntp server {{ntp}}"
        out = T.render_for_devices(tpl, devs, {"ntp": "9.9.9.9", "site": "HQ"}, {"R2": {"site": "DC"}})
        assert out["R1"] == ["hostname R1", "snmp location HQ", "ntp server 9.9.9.9"]
        assert out["R2"][1] == "snmp location DC"
        with pytest.raises(T.TemplateError) as e:
            T.render_for_devices(tpl, devs, {"ntp": "x"})
        assert str(e.value).count("missing") == 3 and "R1" in str(e.value) and "R3" in str(e.value)

    def test_library_roundtrip_and_safe_names(self, tmp_path):
        lib = T.TemplateLibrary(tmp_path / "t")
        assert lib.names() == []
        lib.save("baseline", "hostname {{name}}\r\n")
        lib.save("../evil", "x")
        assert lib.names() == sorted(lib.names()) and "baseline" in lib.names()
        assert not (tmp_path / "evil.tmpl").exists() and lib.load("baseline") == "hostname {{name}}\n"
        lib.delete("baseline")
        with pytest.raises(T.TemplateError):
            lib.load("baseline")
        with pytest.raises(T.TemplateError):
            lib.save("", "x")

    def test_vars_file(self, tmp_path):
        p = tmp_path / "v.json"; p.write_text('{"global": {"a": 1}, "devices": {"R1": {"b": 2}}}')
        assert T.load_vars_file(p) == {"global": {"a": 1}, "devices": {"R1": {"b": 2}}}
        with pytest.raises(T.TemplateError):
            T.load_vars_file(tmp_path / "none.json")
