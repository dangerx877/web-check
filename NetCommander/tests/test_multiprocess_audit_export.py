"""Cross-process locking (real subprocesses), off-box audit sinks, sign-in auditing, live compliance."""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from conftest import FAST_KDF

from netcommander import compliance, jobs
from netcommander.audit import AuditLog, file_sink, sinks_from_env, syslog_sink
from netcommander.deploy import DeploymentStore
from netcommander.filelock import FileLock, LockTimeout
from netcommander.scheduler import Scheduler
from netcommander.security import AuthManager

ROOT = Path(__file__).resolve().parent.parent
PY = [sys.executable, "-I", "-c"]
ENV = {"PYTHONPATH": str(ROOT)}


def spawn(code: str, *args: str) -> subprocess.Popen:
    import os
    pp = os.pathsep.join(x for x in (str(ROOT), os.environ.get("PYTHONPATH", "")) if x)
    return subprocess.Popen([sys.executable, "-c", code, *args], env={**os.environ, "PYTHONPATH": pp},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


# ---------------------------------------------------------------- FileLock
class TestFileLock:
    def test_mutual_exclusion_between_real_processes(self, tmp_path):
        target = tmp_path / "state.json"
        target.write_text("0")
        code = (
            "import sys,time\nfrom pathlib import Path\nfrom netcommander.filelock import FileLock\n"
            "p=Path(sys.argv[1])\nfor _ in range(40):\n  with FileLock(p):\n    v=int(p.read_text()); time.sleep(0.001); p.write_text(str(v+1))\n")
        procs = [spawn(code, str(target)) for _ in range(4)]
        for pr in procs:
            out, err = pr.communicate(timeout=60)
            assert pr.returncode == 0, err
        assert int(target.read_text()) == 160                         # no lost updates

    def test_timeout_when_another_holder_keeps_it(self, tmp_path):
        target = tmp_path / "x"
        holder = spawn("import sys,time\nfrom netcommander.filelock import FileLock\n"
                       "with FileLock(sys.argv[1]):\n  print('held',flush=True); time.sleep(3)\n", str(target))
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(LockTimeout):
            with FileLock(target, timeout=0.3):
                pass
        holder.kill(); holder.wait()
        with FileLock(target, timeout=2):                             # released when the holder died
            pass

    def test_reentrant_and_thread_safe(self, tmp_path):
        lock = FileLock(tmp_path / "t")
        with lock, lock:
            pass
        counter = {"n": 0}

        def work():
            for _ in range(50):
                with lock:
                    v = counter["n"]; counter["n"] = v + 1
        ts = [threading.Thread(target=work) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        assert counter["n"] == 300


# ---------------------------------------------------------------- audit across processes
def test_audit_chain_survives_concurrent_processes(tmp_path):
    path = tmp_path / "audit.jsonl"
    code = ("import sys\nfrom netcommander.audit import AuditLog\nl=AuditLog(sys.argv[1])\n"
            "for i in range(30): l.record(sys.argv[2],'act%d'%i)\n")
    procs = [spawn(code, str(path), f"p{i}") for i in range(4)]
    for pr in procs:
        _, err = pr.communicate(timeout=60)
        assert pr.returncode == 0, err
    log = AuditLog(path)
    assert len(log.entries()) == 120 and log.verify() == (True, "chain intact")


# ---------------------------------------------------------------- deployments across processes
def test_two_processes_cannot_both_execute_one_deployment(tmp_path):
    roles = {"req@x.com": "operator", "adm@x.com": "admin", "adm2@x.com": "admin"}
    store = DeploymentStore(tmp_path / "d.json", lambda e: roles.get(e, "viewer"))
    p = store.create("req@x.com", "t", {"R1": ["a"]}, [["R1"]])
    store.submit("req@x.com", p["id"]); store.decide("adm@x.com", p["id"], True)
    code = (
        "import sys,time\nfrom netcommander.deploy import DeploymentStore, DeployError\n"
        "s=DeploymentStore(sys.argv[1], lambda e:'admin')\n"
        "def push(d,c):\n  time.sleep(0.4); print('PUSHED',flush=True); return True,'ok'\n"
        "try:\n  s.execute('adm2@x.com', sys.argv[2], push)\nexcept DeployError as e:\n  print('REFUSED',flush=True)\n")
    a, b = spawn(code, str(tmp_path / "d.json"), p["id"]), spawn(code, str(tmp_path / "d.json"), p["id"])
    outs = [x.communicate(timeout=60)[0] for x in (a, b)]
    verdicts = sorted("PUSHED" if "PUSHED" in o else "REFUSED" if "REFUSED" in o else f"CRASHED:{o!r}" for o in outs)
    assert verdicts == ["PUSHED", "REFUSED"]


# ---------------------------------------------------------------- schedules across schedulers
def test_only_one_scheduler_runs_a_due_job(tmp_path):
    class C:
        t = 1000.0
        def __call__(self): return self.t
    clock, ran = C(), []
    a = Scheduler(tmp_path / "s.json", lambda s: ran.append("a") or "ok", clock=clock)
    b = Scheduler(tmp_path / "s.json", lambda s: ran.append("b") or "ok", clock=clock)
    a.add({"name": "x", "type": "interval", "every_minutes": 1})
    clock.t += 61
    ra, rb = a.run_due(), b.run_due()
    assert len(ran) == 1 and (ra == [] or rb == [])


# ---------------------------------------------------------------- sinks
class TestSinks:
    def test_file_sink_receives_each_entry_and_failures_never_break_auditing(self, tmp_path):
        copy = tmp_path / "off" / "copy.jsonl"
        broken = lambda e: (_ for _ in ()).throw(RuntimeError("down"))
        log = AuditLog(tmp_path / "a.jsonl", sinks=[broken, file_sink(copy)])
        e = log.record("a", "x", detail="password=hunter2")
        rows = [json.loads(ln) for ln in copy.read_text().splitlines()]
        assert rows == [e] and "hunter2" not in copy.read_text() and log.verify()[0]

    def test_udp_syslog(self, tmp_path):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0)); srv.settimeout(3)
        port = srv.getsockname()[1]
        log = AuditLog(tmp_path / "a.jsonl", sinks=[syslog_sink("127.0.0.1", port)])
        log.record("alice", "push_config", "R1", "failed")
        data = srv.recvfrom(4096)[0].decode()
        assert data.startswith("<132>netcommander: ") and '"actor": "alice"' in data      # local0.warning for non-ok
        log.record("alice", "backup", "R1", "ok")
        assert srv.recvfrom(4096)[0].decode().startswith("<133>")                          # local0.notice

    def test_tcp_syslog(self, tmp_path):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); srv.settimeout(3)
        got = []
        t = threading.Thread(target=lambda: got.append(srv.accept()[0].recv(4096)))
        t.start()
        AuditLog(tmp_path / "a.jsonl", sinks=[syslog_sink("127.0.0.1", srv.getsockname()[1], tcp=True)]).record("a", "x")
        t.join(5)
        assert got and got[0].startswith(b"<133>netcommander: ") and got[0].endswith(b"\n")

    def test_unreachable_syslog_is_harmless(self, tmp_path):
        log = AuditLog(tmp_path / "a.jsonl", sinks=[syslog_sink("127.0.0.1", 1, tcp=True)])
        assert log.record("a", "x") is not None and log.verify()[0]

    def test_sinks_from_env(self, tmp_path):
        assert sinks_from_env({}) == []
        s = sinks_from_env({"NETCOMMANDER_AUDIT_COPY": str(tmp_path / "c.jsonl"), "NETCOMMANDER_AUDIT_SYSLOG": "tcp://10.0.0.5:6514"})
        assert len(s) == 2
        assert len(sinks_from_env({"NETCOMMANDER_AUDIT_SYSLOG": "collector.lab"})) == 1


# ---------------------------------------------------------------- sign-in auditing
class TestLoginAudit:
    def test_success_failure_lockout_and_recovery_are_reported_without_secrets(self, tmp_path):
        import pyotp
        events = []
        t = {"now": 1_000_000.0}
        auth = AuthManager(tmp_path / "u.json", iterations=FAST_KDF, clock=lambda: t["now"],
                           on_event=lambda *a: events.append(a))
        secret, _ = auth.create_account("me@example.com", "longpassword1")
        auth.verify_login("ME@example.com", "wrong-password", "000000")
        auth.verify_login("ghost@example.com", "x" * 12, "000000")
        ok, _ = auth.verify_login("me@example.com", "longpassword1", pyotp.TOTP(secret).at(t["now"]))
        assert ok
        codes = auth.generate_recovery_codes("me@example.com", "longpassword1")
        auth.verify_login("me@example.com", "longpassword1", codes[0])
        for _ in range(6):
            auth.verify_login("me@example.com", "wrong-password", "000000")
        outcomes = [(e[1], e[2]) for e in events]
        assert outcomes[0] == ("me@example.com", "failed") and outcomes[1] == ("ghost@example.com", "failed")
        assert ("me@example.com", "ok") in outcomes and ("me@example.com", "locked") in outcomes
        assert any(e[3] == "recovery code used" for e in events)
        flat = json.dumps(events)
        assert "longpassword1" not in flat and "wrong-password" not in flat and codes[0] not in flat

    def test_hook_failure_never_breaks_login(self, tmp_path):
        import pyotp
        auth = AuthManager(tmp_path / "u.json", iterations=FAST_KDF, on_event=lambda *a: 1 / 0)
        secret, _ = auth.create_account("me@example.com", "longpassword1")
        assert auth.verify_login("me@example.com", "longpassword1", pyotp.TOTP(secret).now())[0]


# ---------------------------------------------------------------- live compliance
class TestLiveCompliance:
    RULES = compliance.load_policy([{"id": "ntp", "type": "must_contain", "pattern": "^ntp server"}])

    def test_getter_fetches_running_config_and_hides_secrets_in_errors(self):
        def fetch(params, creds, settings=None):
            if params["host"] == "bad":
                raise RuntimeError("login failed password=hunter2")
            return "ntp server 1.1.1.1\n" if params["host"] == "ok" else "  \n"
        jm = {"R1": ({"host": "ok"}, ("u", "p", "")), "R2": ({"host": "bad"}, ("u", "p", "")), "R3": ({"host": "empty"}, ("u", "p", ""))}
        get = jobs.live_config_getter(jm, fetch=fetch)
        devs = {n: {"device_type": "cisco_ios"} for n in ("R1", "R2", "R3", "R4")}
        res = {r.device: r for r in compliance.run_compliance(devs, self.RULES, get, workers=4)}
        assert res["R1"].compliant
        assert "hunter2" not in res["R2"].error and res["R2"].error
        assert "empty" in res["R3"].error and "no credentials" in res["R4"].error

    def test_parallel_results_stay_sorted_and_actually_parallel(self):
        barrier = threading.Barrier(3, timeout=5)

        def get(name):
            barrier.wait()
            return "ntp server x"
        res = compliance.run_compliance({"C": {}, "A": {}, "B": {}}, self.RULES, get, workers=3)
        assert [r.device for r in res] == ["A", "B", "C"]
