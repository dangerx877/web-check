from __future__ import annotations

import json
import threading
from datetime import datetime

import pytest

from netcommander import jobs
from netcommander.audit import AuditLog
from netcommander.scheduler import ScheduleError, Scheduler, next_due


def ts(y, mo, d, h=0, mi=0):
    return datetime(y, mo, d, h, mi).timestamp()


class TestBackupJobs:
    def make_jobs(self, *names):
        return {n: ({"device_type": "cisco_ios", "host": n}, ("u", "p", "")) for n in names}

    def test_backup_detects_drift_prunes_and_audits(self, tmp_path, vault):
        cfg = {"R1": "hostname R1\n"}
        fetch = lambda params, creds, settings=None: cfg[params["host"]]
        audit = AuditLog(tmp_path / "a.jsonl")
        first = jobs.backup_devices(self.make_jobs("R1"), tmp_path / "bk", vault, fetch=fetch, audit=audit, keep=2)
        assert first[0].ok and first[0].changed and first[0].path.suffix == ".enc"
        same = jobs.backup_devices(self.make_jobs("R1"), tmp_path / "bk", vault, fetch=fetch, keep=2)
        assert same[0].ok and not same[0].changed
        cfg["R1"] = "hostname R1\nntp server 1.1.1.1\n"
        third = jobs.backup_devices(self.make_jobs("R1"), tmp_path / "bk", vault, fetch=fetch, keep=2)
        assert third[0].changed
        from netcommander.network import list_snapshots
        assert len(list_snapshots("R1", tmp_path / "bk")) == 2          # pruned to keep=2
        assert [e["action"] for e in audit.entries()] == ["backup"]

    def test_failures_are_isolated_and_secrets_never_leak(self, tmp_path, vault):
        def fetch(params, creds, settings=None):
            if params["host"] == "R2":
                raise RuntimeError("login failed password=hunter2")
            return "hostname R1\n"
        out = jobs.backup_devices(self.make_jobs("R1", "R2"), tmp_path, vault, fetch=fetch)
        by = {o.device: o for o in out}
        assert by["R1"].ok and not by["R2"].ok and "hunter2" not in by["R2"].message
        assert "1/2 backed up" in jobs.summarize_backups(out) and "FAILED: R2" in jobs.summarize_backups(out)

    def test_empty_config_is_a_failure_not_an_empty_file(self, tmp_path, vault):
        out = jobs.backup_devices(self.make_jobs("R1"), tmp_path, vault, fetch=lambda *a, **k: "  \n")
        assert not out[0].ok and "empty" in out[0].message and not list(tmp_path.glob("**/*.cfg.enc"))

    def test_no_jobs(self, tmp_path, vault):
        assert jobs.backup_devices({}, tmp_path, vault) == []


class TestNextDue:
    def test_interval(self):
        s = {"type": "interval", "every_minutes": 60, "last_run": 1000.0}
        assert next_due(s, 2000) == 1000 + 3600
        assert next_due({**s, "last_run": 0}, 5) == 0

    def test_daily_before_and_after_slot(self):
        s = {"type": "daily", "at": "02:00", "last_run": ts(2026, 11, 19, 2, 0)}
        assert next_due(s, ts(2026, 11, 20, 1, 0)) == ts(2026, 11, 20, 2, 0)        # not yet
        assert next_due(s, ts(2026, 11, 20, 3, 0)) <= ts(2026, 11, 20, 3, 0)        # due now
        s2 = {**s, "last_run": ts(2026, 11, 20, 2, 5)}
        assert next_due(s2, ts(2026, 11, 20, 3, 0)) == ts(2026, 11, 21, 2, 0)       # already ran today

    def test_missed_days_catch_up_once(self):
        s = {"type": "daily", "at": "02:00", "last_run": ts(2026, 11, 10, 2, 0)}
        now = ts(2026, 11, 20, 9, 0)
        assert next_due(s, now) <= now


class TestScheduler:
    @pytest.fixture
    def clock(self):
        class C:
            t = 10_000.0
            def __call__(self): return self.t
        return C()

    def test_add_validates_and_persists(self, tmp_path, clock):
        s = Scheduler(tmp_path / "s.json", lambda s: "ok", clock=clock)
        added = s.add({"name": "nightly", "type": "daily", "at": "02:30", "kind": "backup"})
        assert Scheduler(tmp_path / "s.json", lambda s: "", clock=clock).list()[0]["id"] == added["id"]
        for bad in ({"name": ""}, {"name": "x", "type": "weekly"}, {"name": "x", "type": "interval", "every_minutes": 0},
                    {"name": "x", "type": "daily", "at": "25:00"}, {"name": "x", "kind": "nuke", "every_minutes": 5}):
            with pytest.raises(ScheduleError):
                s.add(bad)

    def test_interval_job_fires_when_due_and_records_result(self, tmp_path, clock):
        ran = []
        s = Scheduler(tmp_path / "s.json", lambda sp: ran.append(sp["name"]) or "3/3 backed up", clock=clock)
        s.add({"name": "hourly", "type": "interval", "every_minutes": 60})
        assert s.run_due() == [] and not ran
        clock.t += 3601
        assert s.run_due() == [("hourly", "3/3 backed up")] and ran == ["hourly"]
        assert s.list()[0]["last_result"] == "3/3 backed up" and s.run_due() == []

    def test_failing_job_is_contained_and_not_retried_every_tick(self, tmp_path, clock):
        def boom(sp): raise RuntimeError("vault locked")
        s = Scheduler(tmp_path / "s.json", boom, clock=clock)
        s.add({"name": "x", "type": "interval", "every_minutes": 1})
        clock.t += 61
        assert "ERROR: RuntimeError: vault locked" in s.run_due()[0][1]
        assert s.run_due() == []

    def test_disabled_and_removed(self, tmp_path, clock):
        s = Scheduler(tmp_path / "s.json", lambda sp: "ok", clock=clock)
        sid = s.add({"name": "x", "type": "interval", "every_minutes": 1})["id"]
        s.set_enabled(sid, False); clock.t += 120
        assert s.due() == []
        s.set_enabled(sid, True); assert len(s.due()) == 1
        s.remove(sid); assert s.list() == []
        with pytest.raises(ScheduleError):
            s.set_enabled("nope", True)

    def test_no_overlap_with_itself(self, tmp_path, clock):
        gate, started, calls = threading.Event(), threading.Event(), []
        def slow(sp):
            calls.append(1); started.set(); gate.wait(5); return "ok"
        s = Scheduler(tmp_path / "s.json", slow, clock=clock)
        s.add({"name": "x", "type": "interval", "every_minutes": 1}); clock.t += 61
        t = threading.Thread(target=s.run_due); t.start(); started.wait(5)
        assert s.run_due() == []                         # second tick while the first is still running
        gate.set(); t.join(5)
        assert len(calls) == 1

    def test_background_thread_start_stop(self, tmp_path, clock):
        done = threading.Event()
        s = Scheduler(tmp_path / "s.json", lambda sp: done.set() or "ok", clock=clock, tick=0.01)
        s.add({"name": "x", "type": "interval", "every_minutes": 1}); clock.t += 61
        s.start(); s.start()
        assert done.wait(5); s.stop()
        assert not s.running

    def test_corrupt_file_and_invalid_entries_are_skipped(self, tmp_path, clock):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({"schedules": [{"name": ""}, {"id": "A", "name": "ok", "every_minutes": 5}]}))
        assert [x["name"] for x in Scheduler(p, lambda s: "", clock=clock).list()] == ["ok"]
        p.write_text("{not json")
        assert Scheduler(p, lambda s: "", clock=clock).list() == []


class TestSchedulerAcrossProcesses:
    """Two Scheduler objects on one file stand in for the GUI and `schedule-run` (separate locks/memory)."""

    SPEC = {"name": "nightly", "type": "interval", "every_minutes": 5}

    def make(self, tmp_path, clock, runs):
        from netcommander.scheduler import Scheduler
        return Scheduler(tmp_path / "s.json", lambda s: runs.append(s["name"]) or "ok", clock=clock)

    def test_deleted_schedule_is_not_run_or_resurrected(self, tmp_path, clock):
        runs = []
        gui, svc = self.make(tmp_path, clock, runs), None
        sid = gui.add(dict(self.SPEC))["id"]
        svc = self.make(tmp_path, clock, runs)              # service loads it into memory
        gui.remove(sid)
        clock.advance(600)
        assert svc.run_due() == [] and runs == []
        svc.add({"name": "other", "type": "daily", "at": "02:00"})   # a later write must not bring it back
        assert [s["name"] for s in gui.list()] == ["other"]

    def test_paused_schedule_is_not_run_by_other_process(self, tmp_path, clock):
        runs = []
        gui = self.make(tmp_path, clock, runs)
        sid = gui.add(dict(self.SPEC))["id"]
        svc = self.make(tmp_path, clock, runs)
        gui.set_enabled(sid, False)
        clock.advance(600)
        assert svc.run_due() == [] and runs == []

    def test_schedule_added_while_job_runs_survives_result_write(self, tmp_path, clock):
        from netcommander.scheduler import Scheduler
        runs = []
        gui = self.make(tmp_path, clock, runs)
        gui.add(dict(self.SPEC))
        clock.advance(600)

        def runner(spec):
            gui.add({"name": "added-meanwhile", "type": "daily", "at": "03:00"})
            return "done"
        svc = Scheduler(tmp_path / "s.json", runner, clock=clock)
        assert svc.run_due() == [("nightly", "done")]
        names = sorted(s["name"] for s in self.make(tmp_path, clock, runs).list())
        assert names == ["added-meanwhile", "nightly"]

    def test_schedule_deleted_while_running_is_not_written_back(self, tmp_path, clock):
        from netcommander.scheduler import Scheduler
        runs = []
        gui = self.make(tmp_path, clock, runs)
        sid = gui.add(dict(self.SPEC))["id"]
        clock.advance(600)
        svc = Scheduler(tmp_path / "s.json", lambda s: gui.remove(sid) or "done", clock=clock)
        assert svc.run_due() == [("nightly", "done")]
        assert self.make(tmp_path, clock, runs).list() == [] and svc.list() == []

    def test_job_runs_once_when_both_processes_tick(self, tmp_path, clock):
        runs = []
        a = self.make(tmp_path, clock, runs)
        a.add(dict(self.SPEC))
        b = self.make(tmp_path, clock, runs)
        clock.advance(600)
        a.run_due(); b.run_due()
        assert runs == ["nightly"]

    def test_ids_are_unique_even_within_one_millisecond(self, tmp_path, clock):
        a = self.make(tmp_path, clock, [])
        ids = {a.add({"name": f"n{i}", "type": "daily", "at": "01:00"})["id"] for i in range(20)}
        assert len(ids) == 20
