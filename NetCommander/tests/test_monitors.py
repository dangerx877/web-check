from __future__ import annotations

import io
import json
import urllib.error

import pytest

from netcommander import monitors as M


class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def opener_for(payload, capture=None, exc=None):
    def op(req, timeout=None, context=None):
        if capture is not None:
            capture.append((req, context))
        if exc:
            raise exc
        return Resp(json.dumps(payload).encode())
    return op


class TestDig:
    def test_paths(self):
        d = {"a": {"b": [{"c": 5}, {"c": "7.5"}]}, "t": True}
        assert M.dig(d, "a.b.0.c") == 5 and M.dig(d, "a.b.1.c") == 7.5 and M.dig(d, "t") == 1.0

    @pytest.mark.parametrize("path", ["a.x", "a.b.9.c", "a.b.q", "a"])
    def test_errors_name_the_path(self, path):
        with pytest.raises(M.MonitorError, match="path"):
            M.dig({"a": {"b": [{"c": 5}]}}, path)


class TestRest:
    def mon(self, **kw):
        return M.RestMonitor("fw1", "https://fw1/api/stats", {"cpu": "data.cpu", "mem": "data.mem"}, **kw)

    def test_success(self):
        s = self.mon().poll(opener_for({"data": {"cpu": 12, "mem": 55.5}}), clock=lambda: 1.0)
        assert s.ok and s.metrics == {"cpu": 12.0, "mem": 55.5}

    def test_auth_headers(self):
        cap = []
        self.mon(auth="bearer", secret="tok123").poll(opener_for({"data": {"cpu": 1, "mem": 1}}, cap))
        assert cap[0][0].get_header("Authorization") == "Bearer tok123"
        self.mon(auth="basic", user="u", secret="p").poll(opener_for({"data": {"cpu": 1, "mem": 1}}, cap))
        assert cap[1][0].get_header("Authorization") == "Basic dTpw"

    def test_tls_verification_on_by_default_and_opt_out(self):
        cap = []
        self.mon().poll(opener_for({"data": {"cpu": 1, "mem": 1}}, cap))
        assert cap[0][1] is None                                         # default context = verified
        self.mon(verify_tls=False).poll(opener_for({"data": {"cpu": 1, "mem": 1}}, cap))
        assert cap[1][1] is not None and cap[1][1].verify_mode == 0

    @pytest.mark.parametrize("exc,text", [
        (urllib.error.HTTPError("u", 503, "x", {}, None), "HTTP 503"),
        (urllib.error.URLError("refused"), "URLError"),
        (TimeoutError("slow"), "TimeoutError"),
    ])
    def test_failures_become_failed_samples(self, exc, text):
        s = self.mon().poll(opener_for({}, exc=exc))
        assert not s.ok and text in s.error

    def test_bad_payload_reported(self):
        assert "not found" in self.mon().poll(opener_for({"data": {}})).error

    @pytest.mark.parametrize("kw,msg", [
        ({"url": "ftp://x"}, "http"), ({"metrics": {}}, "metric"), ({"auth": "bearer"}, "secret"), ({"auth": "weird"}, "auth"),
    ])
    def test_validation(self, kw, msg):
        base = dict(name="n", url="https://x", metrics={"a": "b"}); base.update(kw)
        with pytest.raises(M.MonitorError, match=msg):
            M.RestMonitor(**base).validate()


class TestSnmp:
    def mon(self, **kw):
        base = dict(name="sw1", host="10.0.0.1", user="monitor", auth_key="authpass123", priv_proto="AES", priv_key="privpass123",
                    oids={"uptime": M.STD_OIDS["uptime"], "in": "1.3.6.1.2.1.31.1.1.1.6.1", "name": M.STD_OIDS["sysname"]},
                    counters=("in",))
        base.update(kw)
        return M.SnmpV3Monitor(**base)

    def test_levels(self):
        assert self.mon().level == "authPriv" and self.mon(priv_proto="", priv_key="").level == "authNoPriv"

    @pytest.mark.parametrize("kw,msg", [
        ({"user": ""}, "user"), ({"auth_key": "short"}, "at least 8"), ({"priv_key": "short"}, "Privacy"),
        ({"auth_proto": "CRC"}, "auth protocol"), ({"priv_proto": "ROT13"}, "privacy protocol"),
        ({"oids": {}}, "OID"), ({"oids": {"x": "sysUpTime"}}, "numeric OID"),
    ])
    def test_validation(self, kw, msg):
        with pytest.raises(M.MonitorError, match=msg):
            self.mon(**kw).validate()

    def test_poll_extracts_numbers_skips_text_and_computes_counter_rate(self):
        t = {"now": 100.0}
        values = iter([1000, 4000])
        def get(mon, oids):
            return {M.STD_OIDS["uptime"]: 555, "1.3.6.1.2.1.31.1.1.1.6.1": next(values), M.STD_OIDS["sysname"]: "sw1"}
        p = M.SnmpPoller(get, clock=lambda: t["now"])
        a = p.poll(self.mon()); t["now"] = 110.0; b = p.poll(self.mon())
        assert a.ok and a.metrics == {"uptime": 555.0, "in": 1000.0}          # no rate on first sample; text skipped
        assert b.metrics["in_rate"] == 300.0

    def test_agent_error_is_a_failed_sample_with_no_secret_in_it(self):
        def get(mon, oids): raise M.MonitorError("requestTimedOut")
        s = M.SnmpPoller(get).poll(self.mon())
        assert not s.ok and "requestTimedOut" in s.error and "authpass123" not in s.error

    def test_invalid_config_never_hits_the_network(self):
        def get(mon, oids): raise AssertionError("must not call")
        assert not M.SnmpPoller(get).poll(self.mon(auth_key="x")).ok

    def test_missing_pysnmp_gives_actionable_message(self, monkeypatch):
        import sys
        monkeypatch.setitem(sys.modules, "pysnmp", None)
        monkeypatch.setitem(sys.modules, "pysnmp.hlapi", None)
        s = M.SnmpPoller().poll(self.mon())
        assert not s.ok and "pysnmp" in s.error


class TestCounterRate:
    def test_basic_wrap_and_reset(self):
        assert M.counter_rate((0, 100), (10, 600)) == 50
        assert M.counter_rate((0, 2**32 - 100), (10, 100), bits=32) == 20           # wrapped
        assert M.counter_rate((0, 10**9), (10, 5)) is None                          # reset
        assert M.counter_rate(None, (1, 1)) is None and M.counter_rate((5, 1), (5, 2)) is None


class TestHistoryAlertsRunner:
    def test_history_bounded_and_availability(self):
        h = M.History(maxlen=3)
        for i in range(5):
            h.add("a", M.Sample(i, i % 2 == 0, {"cpu": float(i)}))
        assert len(h.series("a", "cpu")) <= 3 and h.last("a").ts == 4 and h.targets() == ["a"]
        assert h.availability("a") == pytest.approx(66.666, abs=0.1) and h.availability("zz") is None

    def test_thresholds(self):
        assert M.check_thresholds({"cpu": 95, "mem": 5}, {"cpu": (None, 90), "mem": (10, None), "x": (1, 2)}) == [
            "cpu=95 above 90", "mem=5 below 10"]

    def test_runner_polls_all_records_history_and_alerts(self):
        alerts = []
        rest = M.RestMonitor("fw", "https://fw/x", {"cpu": "cpu"})
        snmp = M.SnmpV3Monitor("sw", "h", "u", auth_key="authpass123", oids={"cpu": "1.3.6.1"})
        poller = M.SnmpPoller(lambda m, o: {"1.3.6.1": 99})
        r = M.MonitorRunner([rest, snmp], limits={"cpu": (None, 90)}, on_alert=lambda n, b: alerts.append((n, b)),
                            snmp=poller, rest_opener=opener_for({"cpu": 10}))
        out = r.poll_all()
        assert out["fw"].ok and out["sw"].ok and alerts == [("sw", ["cpu=99 above 90"])]
        assert r.history.targets() == ["fw", "sw"]

    def test_set_monitors_and_sweep_callback(self):
        sweeps = []
        r = M.MonitorRunner([], on_sweep=lambda: sweeps.append(1), rest_opener=opener_for({"cpu": 1}))
        assert r.poll_all() == {} and not sweeps
        r.set_monitors([M.RestMonitor("fw", "https://fw/x", {"cpu": "cpu"})])
        assert r.poll_all()["fw"].ok and sweeps == [1]

    def test_runner_thread(self):
        import threading
        ev = threading.Event()
        rest = M.RestMonitor("fw", "https://fw/x", {"cpu": "cpu"})
        r = M.MonitorRunner([rest], rest_opener=lambda *a, **k: (ev.set(), Resp(b'{"cpu": 1}'))[1], interval=0.01)
        r.start(); r.start(); assert ev.wait(5); r.stop()


class TestStore:
    def test_secrets_encrypted_on_disk_and_round_trip(self, vault, tmp_path):
        ms = [M.RestMonitor("fw", "https://fw/x", {"cpu": "c"}, auth="bearer", secret="tok-SECRET"),
              M.SnmpV3Monitor("sw", "h", "u", auth_key="authpass-SECRET", priv_proto="AES", priv_key="privpass-SECRET",
                              counters=("in",))]
        st = M.MonitorStore(tmp_path / "m.json", vault)
        st.save(ms)
        raw = (tmp_path / "m.json").read_text()
        assert "SECRET" not in raw
        back = st.load()
        assert back[0].secret == "tok-SECRET" and back[1].priv_key == "privpass-SECRET" and back[1].counters == ("in",)

    def test_guest_cannot_persist_secrets_but_can_persist_secretless(self, guest_vault, tmp_path):
        st = M.MonitorStore(tmp_path / "m.json", guest_vault)
        with pytest.raises(M.MonitorError, match="Guest"):
            st.save([M.RestMonitor("fw", "https://x", {"a": "b"}, auth="bearer", secret="t")])
        st.save([M.RestMonitor("fw", "https://x", {"a": "b"})])
        assert st.load()[0].name == "fw"

    def test_damaged_entries_skipped(self, vault, tmp_path):
        (tmp_path / "m.json").write_text(json.dumps({"monitors": [{"kind": "rest", "bogus": 1}]}))
        assert M.MonitorStore(tmp_path / "m.json", vault).load() == []
        (tmp_path / "m.json").write_text("garbage")
        assert M.MonitorStore(tmp_path / "m.json", vault).load() == []
