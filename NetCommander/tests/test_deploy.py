from __future__ import annotations

import json
import threading

import pytest

from netcommander.audit import AuditLog
from netcommander.deploy import DeployError, DeploymentStore, make_stages, plan_digest
from netcommander.rbac import PermissionDenied

ROLES = {"req@x.com": "operator", "adm@x.com": "admin", "adm2@x.com": "admin", "view@x.com": "viewer"}
CMDS = {"R1": ["a"], "R2": ["b"], "R3": ["c"], "R4": ["d"]}


@pytest.fixture
def store(tmp_path):
    return DeploymentStore(tmp_path / "d.json", lambda e: ROLES.get(e, "viewer"),
                           audit=AuditLog(tmp_path / "audit.jsonl"))


def approved(store, stages=(("R1",), ("R2", "R3", "R4")), **kw):
    p = store.create("req@x.com", "NTP change", CMDS, stages, **kw)
    store.submit("req@x.com", p["id"])
    return store.decide("adm@x.com", p["id"], True)


def test_make_stages():
    assert make_stages(["a", "b", "c", "d", "e"], canary=1, batch_size=2) == [["a"], ["b", "c"], ["d", "e"]]
    assert make_stages(["a", "a", "b"], canary=0) == [["a", "b"]]
    assert make_stages(["a"], canary=5) == [["a"]]
    with pytest.raises(ValueError):
        make_stages([])


class TestWorkflow:
    def test_happy_path_and_audit(self, store, tmp_path):
        p = approved(store)
        assert p["status"] == "approved"
        pushed = []
        out = store.execute("adm@x.com", p["id"], lambda d, c: (pushed.append(d) or True, "ok"))
        assert out["status"] == "completed" and pushed[0] == "R1" and sorted(pushed[1:]) == ["R2", "R3", "R4"]
        actions = [e["action"] for e in AuditLog(tmp_path / "audit.jsonl").entries()]
        assert actions == ["deploy.create", "deploy.submit", "deploy.approve", "deploy.execute", "deploy.finish"]
        assert AuditLog(tmp_path / "audit.jsonl").verify()[0]

    def test_operator_cannot_approve_or_push(self, store):
        p = store.create("req@x.com", "t", CMDS, [["R1"]])
        store.submit("req@x.com", p["id"])
        with pytest.raises(PermissionDenied):
            store.decide("req@x.com", p["id"], True)
        with pytest.raises(PermissionDenied):
            store.execute("req@x.com", p["id"], lambda d, c: (True, ""))

    def test_viewer_cannot_request(self, store):
        with pytest.raises(PermissionDenied):
            store.create("view@x.com", "t", CMDS, [["R1"]])

    def test_separation_of_duties(self, store):
        p = store.create("adm@x.com", "t", CMDS, [["R1"]])
        store.submit("adm@x.com", p["id"])
        with pytest.raises(DeployError, match="Separation of duties"):
            store.decide("adm@x.com", p["id"], True)
        assert store.decide("adm2@x.com", p["id"], True)["status"] == "approved"

    def test_self_approval_can_be_enabled_explicitly(self, tmp_path):
        s = DeploymentStore(tmp_path / "d.json", lambda e: "admin", allow_self_approval=True)
        p = s.create("a@x.com", "t", CMDS, [["R1"]]); s.submit("a@x.com", p["id"])
        assert s.decide("a@x.com", p["id"], True)["status"] == "approved"

    def test_two_person_rule(self, store):
        p = approved(store, required_approvals=2)
        assert p["status"] == "pending_approval"
        with pytest.raises(DeployError, match="already reviewed"):
            store.decide("adm@x.com", p["id"], True)
        assert store.decide("adm2@x.com", p["id"], True)["status"] == "approved"

    def test_reject_blocks_execution(self, store):
        p = store.create("req@x.com", "t", CMDS, [["R1"]]); store.submit("req@x.com", p["id"])
        assert store.decide("adm@x.com", p["id"], False, "no")["status"] == "rejected"
        with pytest.raises(DeployError):
            store.execute("adm@x.com", p["id"], lambda d, c: (True, ""))

    def test_unapproved_cannot_run(self, store):
        p = store.create("req@x.com", "t", CMDS, [["R1"]])
        with pytest.raises(DeployError, match="approved"):
            store.execute("adm@x.com", p["id"], lambda d, c: (True, ""))

    def test_tampering_after_approval_is_refused(self, store, tmp_path):
        p = approved(store)
        data = json.loads((tmp_path / "d.json").read_text())
        data["plans"][0]["commands"]["R1"] = ["erase startup-config"]
        (tmp_path / "d.json").write_text(json.dumps(data))
        s2 = DeploymentStore(tmp_path / "d.json", lambda e: ROLES.get(e, "viewer"))
        called = []
        with pytest.raises(DeployError, match="does not match"):
            s2.execute("adm@x.com", p["id"], lambda d, c: (called.append(d), (True, ""))[1])
        assert not called

    def test_changing_safety_options_after_approval_is_refused(self, store, tmp_path):
        p = approved(store, auto_rollback=True)
        data = json.loads((tmp_path / "d.json").read_text())
        data["plans"][0]["auto_rollback"] = False
        (tmp_path / "d.json").write_text(json.dumps(data))
        s2 = DeploymentStore(tmp_path / "d.json", lambda e: "admin")
        with pytest.raises(DeployError, match="does not match"):
            s2.execute("adm@x.com", p["id"], lambda d, c: (True, ""))

    def test_cannot_run_twice(self, store):
        p = approved(store)
        store.execute("adm@x.com", p["id"], lambda d, c: (True, ""))
        with pytest.raises(DeployError):
            store.execute("adm@x.com", p["id"], lambda d, c: (True, ""))

    def test_cancel(self, store):
        p = store.create("req@x.com", "t", CMDS, [["R1"]])
        assert store.cancel("req@x.com", p["id"])["status"] == "cancelled"
        with pytest.raises(DeployError):
            store.submit("req@x.com", p["id"])

    def test_validation(self, store):
        for stages in ([], [["R1"], ["R1"]], [["R9"]]):
            with pytest.raises(ValueError):
                store.create("req@x.com", "t", CMDS, stages)
        with pytest.raises(ValueError):
            store.create("req@x.com", " ", CMDS, [["R1"]])
        with pytest.raises(DeployError):
            store.get("nope")


class TestStagedExecution:
    def test_canary_failure_halts_remaining_stages(self, store):
        p = approved(store)
        seen = []
        def push(d, c): seen.append(d); return (d != "R1", "boom" if d == "R1" else "ok")
        out = store.execute("adm@x.com", p["id"], push)
        assert out["status"] == "halted" and seen == ["R1"]
        assert out["results"]["R1"]["status"] == "failed"
        assert all(out["results"][d]["status"] == "skipped" for d in ("R2", "R3", "R4"))

    def test_continue_after_failure_when_not_halting(self, store):
        p = approved(store, halt_on_failure=False)
        out = store.execute("adm@x.com", p["id"], lambda d, c: (d != "R2", ""))
        assert out["status"] == "halted"                       # something failed -> not "completed"
        assert out["results"]["R3"]["status"] == "ok" and out["results"]["R2"]["status"] == "failed"

    def test_push_exception_is_a_failure_not_a_crash(self, store):
        p = approved(store, stages=(("R1", "R2"),))
        def push(d, c):
            if d == "R1": raise RuntimeError("kaboom")
            return True, "ok"
        out = store.execute("adm@x.com", p["id"], push)
        assert out["results"]["R1"]["message"].startswith("RuntimeError") and out["results"]["R2"]["status"] == "ok"

    def test_stage_gate_can_stop_rollout(self, store):
        p = approved(store)
        out = store.execute("adm@x.com", p["id"], lambda d, c: (True, ""), stage_gate=lambda i, devs: False)
        assert out["status"] == "halted" and out["results"]["R1"]["status"] == "ok"
        assert out["results"]["R2"]["status"] == "skipped"

    def test_events_and_parallelism_within_stage(self, store):
        p = approved(store, stages=(("R1", "R2", "R3", "R4"),))
        barrier = threading.Barrier(4, timeout=5)
        events = []
        def push(d, c): barrier.wait(); return True, ""       # deadlocks unless all four run concurrently
        store.execute("adm@x.com", p["id"], push, workers=4, on_event=lambda k, x: events.append(k))
        assert events == ["stage_start", "stage_done"]


class TestPersistence:
    def test_survives_restart_and_interrupted_run_is_halted_not_resumed(self, store, tmp_path):
        p = approved(store)
        data = json.loads((tmp_path / "d.json").read_text())
        data["plans"][0]["status"] = "running"
        (tmp_path / "d.json").write_text(json.dumps(data))
        again = DeploymentStore(tmp_path / "d.json", lambda e: "admin")
        got = again.get(p["id"])
        assert got["status"] == "halted" and "Interrupted" in got["log"][-1]["msg"]

    def test_failed_write_changes_nothing(self, store, monkeypatch):
        from netcommander import deploy
        p = store.create("req@x.com", "t", CMDS, [["R1"]])
        monkeypatch.setattr(deploy, "_write_private", lambda *a: (_ for _ in ()).throw(OSError("ro")))
        with pytest.raises(OSError):
            store.submit("req@x.com", p["id"])
        assert store.get(p["id"])["status"] == "draft"

    def test_list_filter_and_digest_stability(self, store):
        a = store.create("req@x.com", "a", CMDS, [["R1"]]); store.create("req@x.com", "b", CMDS, [["R2"]])
        store.submit("req@x.com", a["id"])
        assert [p["title"] for p in store.list("pending_approval")] == ["a"] and len(store.list()) == 2
        assert plan_digest({"R1": ["a"]}, [["R1"]]) == plan_digest({"R1": ["a"]}, [("R1",)])


def test_second_instance_sees_changes_made_by_another_process(tmp_path):
    roles = lambda e: ROLES.get(e, "viewer")
    a, b = DeploymentStore(tmp_path / "d.json", roles), DeploymentStore(tmp_path / "d.json", roles)
    p = a.create("req@x.com", "t", CMDS, [["R1"]])
    assert b.get(p["id"])["status"] == "draft"
    a.submit("req@x.com", p["id"])
    assert b.decide("adm@x.com", p["id"], True)["status"] == "approved"
    assert a.get(p["id"])["status"] == "approved"
