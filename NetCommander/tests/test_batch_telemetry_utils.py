"""BatchRunner circuit breaker, HealthMonitor, probes, formatting helpers and the CLI."""
from __future__ import annotations

import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from netcommander import __main__ as cli
from netcommander import __version__
from netcommander.batch import BatchRunner, build_jobs
from netcommander.store import DeviceStore
from netcommander.telemetry import (
    HealthMonitor,
    classify_status,
    compute_stats,
    deep_probe,
    format_table,
    parse_thresholds,
)
from netcommander.utils import excess_lines, parse_commands, parse_host_port

ROOT = Path(__file__).resolve().parent.parent


class Sink:
    def __init__(self):
        self.events: list[tuple[str, object]] = []
        self._lock = threading.Lock()

    def __call__(self, kind, payload):
        with self._lock:
            self.events.append((kind, payload))

    def of(self, kind):
        return [p for k, p in self.events if k == kind]


# ---------------------------------------------------------------- BatchRunner
class TestBatchRunner:
    jobs = {f"R{i}": ({"host": f"10.0.0.{i}"}, ("u", "p", "")) for i in range(1, 6)}

    def test_runs_every_job_and_signals_done_once(self):
        sink, seen = Sink(), []
        BatchRunner(sink, "done", workers=3).run(self.jobs, lambda n, p, c, b: seen.append((n, p["host"], c)))
        assert sorted(n for n, *_ in seen) == sorted(self.jobs) and sink.of("done") == [None]
        assert sink.events[-1][0] == "done"

    def test_empty_batch_still_signals_done(self):
        sink = Sink()
        BatchRunner(sink, "done").run({}, lambda *a: None)
        assert sink.events == [("done", None)]

    def test_auth_failure_circuit_breaker_skips_the_rest(self, fake_netmiko):
        sink, ran = Sink(), []

        def worker(name, params, creds, batch):
            ran.append(name)
            batch.fail(name, params, fake_netmiko.NetmikoAuthenticationException("denied"))

        batch = BatchRunner(sink, "done", workers=1, abort_after=3)
        batch.run(self.jobs, worker)
        assert ran == ["R1", "R2", "R3"] and batch.tripped and batch.auth_failures == 3
        assert sink.of("auth_failed") == ["R1", "R2", "R3"]
        skipped = [o for o in sink.of("output") if "Skipped" in o]
        assert len(skipped) == 2 and "R4" in skipped[0] and sink.of("done") == [None]

    def test_non_auth_errors_do_not_trip_the_breaker(self, fake_netmiko):
        sink = Sink()

        def worker(name, params, creds, batch):
            batch.fail(name, params, fake_netmiko.NetmikoTimeoutException("no route"))

        batch = BatchRunner(sink, "done", workers=1, abort_after=2)
        batch.run(self.jobs, worker)
        assert not batch.tripped and len(sink.of("telemetry")) == 5
        assert sink.of("telemetry")[0] == ("R1", False, None, "")
        assert all("ERROR: Timed out" in o for o in sink.of("output"))

    def test_each_batch_has_its_own_counter(self, fake_netmiko):
        a, b = BatchRunner(Sink(), "d"), BatchRunner(Sink(), "d")
        a.fail("R1", {}, fake_netmiko.NetmikoAuthenticationException("x"))
        assert a.auth_failures == 1 and b.auth_failures == 0

    def test_crashing_worker_is_reported_and_others_continue(self):
        sink, ok = Sink(), []

        def worker(name, params, creds, batch):
            if name == "R2":
                raise RuntimeError("kaboom")
            ok.append(name)

        BatchRunner(sink, "done", workers=2).run(self.jobs, worker)
        assert sorted(ok) == ["R1", "R3", "R4", "R5"]
        assert any("R2" in o and "kaboom" in o for o in sink.of("output")) and sink.of("done") == [None]

    def test_start_runs_in_background_thread(self):
        sink, gate = Sink(), threading.Event()
        t = BatchRunner(sink, "done").start(self.jobs, lambda *a: gate.wait(2))
        assert t.is_alive() and not sink.of("done")
        gate.set(); t.join(5)
        assert sink.of("done") == [None]

    def test_worker_count_clamped(self):
        assert BatchRunner(Sink(), "d", workers=0).workers == 1


class FakeVault:
    def __init__(self, with_pw): self.with_pw = set(with_pw)
    def has_password(self, d): return d in self.with_pw
    def get_decrypted(self, d): return ("vaultuser", "pw", "en") if d in self.with_pw else ("admin", "", "")


def test_build_jobs_snapshots_params_and_handles_key_login():
    store = DeviceStore()
    store.add("PW", {"host": "1.1.1.1", "username": "x"})
    store.add("KEY", {"host": "2.2.2.2", "username": "keyuser", "use_keys": True})
    jobs = build_jobs(store, FakeVault({"PW"}), ["PW", "KEY", "GONE"])
    assert set(jobs) == {"PW", "KEY"}
    assert jobs["PW"][1] == ("vaultuser", "pw", "en") and jobs["KEY"][1] == ("keyuser", "", "")
    store.set_username("PW", "changed")
    assert jobs["PW"][0]["username"] == "x"                     # batch unaffected by later edits


# ---------------------------------------------------------------- telemetry
class TestTelemetryMath:
    def test_stats(self):
        assert compute_stats([]) == (0.0, 0.0)
        loss, jit = compute_stats([(True, 10.0), (False, None), (True, 20.0), (True, 30.0)])
        assert loss == 25.0 and jit == pytest.approx(8.1649, rel=1e-3)

    @pytest.mark.parametrize("ok,lat,loss,expected", [
        (False, None, 0, "down"), (True, 5, 0, "up"), (True, 500, 0, "degraded"),
        (True, 5, 50, "degraded"), (True, None, 0, "up"), (True, 120, 10, "up"),
    ])
    def test_classify(self, ok, lat, loss, expected):
        assert classify_status(ok, lat, loss, 120, 10) == expected

    def test_thresholds_fall_back(self):
        assert parse_thresholds("50", "5") == (50.0, 5.0)
        assert parse_thresholds("x", "") == (120.0, 10.0)
        assert parse_thresholds(None, "2.5") == (120.0, 2.5)

    def test_format_table(self):
        store = DeviceStore()
        store.add("R1", {"host": "10.0.0.1"})
        store.record_probe("R1", True, 12.34, "SSH-2.0-OpenSSH_9", 120, 10)
        store.add("R2", {"host": "10.0.0.2"})
        text = format_table(store.snapshot())
        lines = text.splitlines()
        assert lines[0].startswith("DEVICE") and "R1" in lines[2] and "12.3 ms" in lines[2] and "UP" in lines[2]
        assert "UNKNOWN" in lines[3] and "--" in lines[3] and "never" in lines[3]


class TestDeepProbe:
    def test_open_port_returns_banner_and_latency(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)

        def serve():
            c, _ = srv.accept(); c.sendall(b"SSH-2.0-TestServer\r\n"); c.close()

        threading.Thread(target=serve, daemon=True).start()
        ok, ms, banner = deep_probe("127.0.0.1", srv.getsockname()[1], 2.0)
        srv.close()
        assert ok and ms is not None and ms >= 0 and banner == "SSH-2.0-TestServer"

    def test_closed_port(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        assert deep_probe("127.0.0.1", port, 0.5) == (False, None, "")

    def test_silent_server_reports_tcp_open(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        threading.Thread(target=lambda: (srv.accept(), None), daemon=True).start()
        ok, _, banner = deep_probe("127.0.0.1", srv.getsockname()[1], 2.0)
        srv.close()
        assert ok and banner == "TCP open"


class TestHealthMonitor:
    def make(self, probe, n=3, **kw):
        store = DeviceStore()
        for i in range(n):
            store.add(f"D{i}", {"host": f"10.0.0.{i}", "port": 2200 + i})
        sink = Sink()
        return HealthMonitor(store, sink, probe=probe, **kw), sink

    def test_sweep_emits_one_result_per_device(self):
        mon, sink = self.make(lambda h, p, t: (p != 2201, 1.5, "b"))
        assert mon.sweep() is True
        res = {n: ok for n, ok, *_ in sink.of("telemetry")}
        assert res == {"D0": True, "D1": False, "D2": True}

    def test_empty_inventory_is_noop(self):
        mon, sink = self.make(lambda *a: (True, 1, ""), n=0)
        assert mon.sweep() is False and not sink.events

    def test_overlapping_sweeps_are_skipped(self):
        gate, started = threading.Event(), threading.Event()

        def slow(h, p, t):
            started.set(); gate.wait(5); return True, 1.0, ""

        mon, sink = self.make(slow, n=1)
        first = threading.Thread(target=mon.sweep); first.start()
        assert started.wait(2)
        assert mon.sweep() is False                         # second request refused while first runs
        gate.set(); first.join(5)
        assert len(sink.of("telemetry")) == 1 and mon.sweep() is True

    def test_probe_exception_counts_as_down(self):
        def boom(h, p, t): raise RuntimeError("x")
        mon, sink = self.make(boom, n=1)
        mon.sweep()
        assert sink.of("telemetry") == [("D0", False, None, "")]

    def test_background_loop_starts_and_stops(self):
        count = threading.Semaphore(0)
        mon, _ = self.make(lambda *a: (count.release(), (True, 1.0, ""))[1], n=1, interval=0.01)
        mon.start(); mon.start()                            # second start is a no-op
        assert mon.running and count.acquire(timeout=2) and count.acquire(timeout=2)
        mon.stop(join_timeout=2)
        assert not mon.running
        mon.start()
        assert mon.running
        mon.stop(join_timeout=2)

    def test_poll_async(self):
        mon, sink = self.make(lambda *a: (True, 1.0, ""))
        mon.poll_async().join(3)
        assert len(sink.of("telemetry")) == 3


# ---------------------------------------------------------------- utils
class TestUtils:
    @pytest.mark.parametrize("text,expected", [
        ("10.0.0.1", ("10.0.0.1", None)), ("10.0.0.1:2222", ("10.0.0.1", 2222)), ("sw1.lab:22", ("sw1.lab", 22)),
        ("[2001:db8::1]:830", ("2001:db8::1", 830)), ("[::1]", ("::1", None)), ("2001:db8::1", ("2001:db8::1", None)),
        ("  r1  ", ("r1", None)), ("host:65535", ("host", 65535)),
    ])
    def test_parse_host_port_ok(self, text, expected):
        assert parse_host_port(text) == expected

    @pytest.mark.parametrize("text", ["", "  ", "a b", "h:", ":22", "h:0", "h:65536", "h:abc", "[::1", "[::1]:x", "[]:22", "h:-1"])
    def test_parse_host_port_bad(self, text):
        with pytest.raises(ValueError):
            parse_host_port(text)

    def test_parse_commands(self):
        assert parse_commands("# c\n\n  show a  \n#x\nshow b\n   \n") == ["show a", "show b"]
        assert parse_commands("") == []

    def test_excess_lines(self):
        assert excess_lines(100, limit=200) == 0 and excess_lines(200, limit=200) == 0
        assert excess_lines(250, limit=200, slack=10) == 60

    def test_open_folder_reports_errors(self, tmp_path):
        from netcommander.utils import open_folder
        f = tmp_path / "file"; f.write_text("x")
        assert open_folder(f / "sub") is not None


# ---------------------------------------------------------------- CLI
def test_pyproject_version_matches_package_version():
    tomllib = pytest.importorskip("tomllib")      # Python 3.11+
    from netcommander import __version__
    assert tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"] == __version__


class TestCli:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as e:
            cli.main(["--version"])
        assert e.value.code == 0 and f"Uptime Funk {__version__}" in capsys.readouterr().out

    def test_missing_dependency_gives_friendly_exit_code(self, monkeypatch, capsys):
        def boom(paths, settings): raise ImportError("No module named 'customtkinter'")
        monkeypatch.setattr(cli, "run_gui", boom)
        assert cli.main([]) == 2 and "customtkinter" in capsys.readouterr().err

    def test_flags_reach_gui(self, monkeypatch, tmp_path):
        got = {}
        monkeypatch.setattr(cli, "run_gui", lambda paths, settings: got.update(p=paths, s=settings) or 0)
        assert cli.main(["--data-dir", str(tmp_path), "--strict-hostkeys"]) == 0
        assert got["p"].root == tmp_path.resolve() and got["s"].strict_hostkeys

    @pytest.mark.parametrize("args", [["-m", "netcommander", "--version"], ["netcommander.py", "--version"]])
    def test_module_and_thin_entry_point(self, args):
        r = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and f"Uptime Funk {__version__}" in r.stdout, r.stderr

    def test_package_import_does_not_pull_in_gui_stack(self):
        code = "import sys, netcommander, netcommander.network, netcommander.batch, netcommander.store;" \
               "sys.exit(any(m in sys.modules for m in ('tkinter','customtkinter','matplotlib','netmiko')))"
        assert subprocess.run([sys.executable, "-c", code], cwd=ROOT, env={**__import__('os').environ, "PYTHONPATH": str(ROOT) + __import__('os').pathsep + __import__('os').environ.get("PYTHONPATH", "")}).returncode == 0
