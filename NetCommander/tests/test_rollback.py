from __future__ import annotations

import pytest

from netcommander.network import PreChangeBackupError
from netcommander.rollback import Check, RollbackUnsupported, push_with_rollback, supports_rollback

CREDS = ("u", "p", "")


class RBConn:
    def __init__(self, outputs=None, alive=True, fail_cmds=(), commit_error=None):
        self.outputs = outputs or {}
        self.alive, self.fail_cmds, self.commit_error = alive, set(fail_cmds), commit_error
        self.log = []

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def enable(self): self.log.append("enable")
    def is_alive(self): return self.alive

    def send_command(self, cmd, **kw):
        self.log.append(f"send:{cmd}")
        if cmd in self.fail_cmds:
            raise OSError("session dropped")
        return self.outputs.get(cmd, "hostname R1\n")

    def send_command_timing(self, cmd, **kw):
        self.log.append(f"timing:{cmd}"); return ""

    def send_config_set(self, cmds, **kw):
        self.log.append(f"cfg:{kw.get('config_mode_command', '-')}:{'|'.join(cmds)}"); return "ok"

    def commit(self, **kw):
        self.log.append(f"commit:{kw}")
        if self.commit_error: raise self.commit_error
        return "committed"

    def exit_config_mode(self): self.log.append("exit")
    def save_config(self): self.log.append("save"); return "saved"


def go(conn, dtype, checks=None, **kw):
    hooks = []
    r = push_with_rollback({"device_type": dtype}, CREDS, ["ntp server 1.1.1.1"], checks, connect=lambda *a, **k: conn,
                           sleep=lambda s: None, on_config=lambda t, x: hooks.append(t), **kw)
    return r, hooks


def test_support_table():
    assert supports_rollback("cisco_ios") and supports_rollback("juniper_junos") and not supports_rollback("arista_eos")


def test_unsupported_platform_refused_before_connecting():
    def boom(*a, **k): raise AssertionError("must not connect")
    with pytest.raises(RollbackUnsupported, match="Nothing was pushed"):
        push_with_rollback({"device_type": "arista_eos"}, CREDS, ["x"], connect=boom)


def test_ios_success_confirms_and_saves():
    c = RBConn({"show ping": "Success rate is 100 percent"})
    r, hooks = go(c, "cisco_ios", [Check("show ping", r"100 percent")], timer_minutes=3)
    assert r.ok and not r.rolled_back and hooks == ["pre", "post"]
    assert "cfg:configure terminal revert timer 3:ntp server 1.1.1.1" in c.log
    assert "timing:configure confirm" in c.log and "save" in c.log
    assert not any("revert now" in x for x in c.log)


def test_ios_failed_check_reverts_and_does_not_confirm_or_save():
    c = RBConn({"show ping": "Success rate is 0 percent"})
    r, hooks = go(c, "cisco_ios", [Check("show ping", r"100 percent")])
    assert r.rolled_back and not r.confirmed and r.rollback_method == "explicit" and hooks == ["pre"]
    assert "timing:configure revert now" in c.log and "timing:configure confirm" not in c.log and "save" not in c.log
    assert any("did not match" in m for m in r.messages)


def test_lost_session_relies_on_device_timer_when_revert_also_fails():
    class Dead(RBConn):
        def send_command_timing(self, cmd, **kw):
            raise OSError("socket closed")
    c = Dead(alive=False)
    r, _ = go(c, "cisco_ios")
    assert r.rolled_back and r.rollback_method == "device-timer" and any("device-side timer" in m for m in r.messages)
    assert not r.confirmed


def test_check_command_exception_counts_as_failure():
    c = RBConn(fail_cmds={"show x"})
    r, _ = go(c, "cisco_ios", [Check("show x", "ok")])
    assert r.rolled_back and any("session dropped" in m for m in r.messages)


def test_junos_commit_confirmed_then_confirm():
    c = RBConn({"run show system uptime": "up"})
    r, _ = go(c, "juniper_junos", [Check("show system uptime", "up")], timer_minutes=2)
    assert r.ok
    assert "commit:{'confirm': True, 'confirm_delay': 2}" in c.log and "commit:{}" in c.log
    assert "send:run show system uptime" in c.log                 # operational command from config mode


def test_junos_failure_rolls_back_explicitly():
    c = RBConn({"run show x": "bad"})
    r, _ = go(c, "juniper_junos", [Check("show x", "good")])
    assert r.rolled_back and r.rollback_method == "explicit"
    assert any(x.startswith("cfg:-:rollback 1") for x in c.log) and c.log.count("commit:{}") == 1


def test_xr_failure_leaves_it_to_the_timer():
    r, _ = go(RBConn({"show x": "bad"}), "cisco_xr", [Check("show x", "good")])
    assert r.rolled_back and r.rollback_method == "device-timer"


def test_confirm_failure_triggers_revert():
    c = RBConn(commit_error=None)
    calls = {"n": 0}
    orig = c.commit
    def commit(**kw):
        calls["n"] += 1
        if calls["n"] == 2: raise RuntimeError("commit failed")
        return orig(**kw)
    c.commit = commit
    r, _ = go(c, "juniper_junos")
    assert r.rolled_back and any("confirming the change failed" in m for m in r.messages)


def test_pre_backup_failure_pushes_nothing():
    c = RBConn(fail_cmds={"show running-config"})
    with pytest.raises(PreChangeBackupError):
        go(c, "cisco_ios")
    assert not any(x.startswith("cfg:") for x in c.log)


def test_timer_bounds():
    with pytest.raises(ValueError):
        go(RBConn(), "cisco_ios", timer_minutes=0)


# ---- IOS-XR timer units and config-mode checks ---------------------------------------------
def test_xr_commit_confirmed_uses_seconds_and_do_prefix():
    c = RBConn({"do show bgp summary": "Established"})
    r, _ = go(c, "cisco_xr", [Check("show bgp summary", "Established")], timer_minutes=5)
    assert r.ok
    assert "commit:{'confirm': True, 'confirm_delay': 300}" in c.log      # XR counts seconds (min 30)
    assert "send:do show bgp summary" in c.log


def test_existing_prefix_is_not_doubled():
    c = RBConn({"run show x": "good"})
    r, _ = go(c, "juniper_junos", [Check("run show x", "good")])
    assert r.ok and "send:run run show x" not in c.log


def test_ios_checks_run_without_prefix():
    c = RBConn({"show x": "good"})
    r, _ = go(c, "cisco_ios", [Check("show x", "good")])
    assert r.ok and "send:show x" in c.log


# ---- failures while applying: result returned, revert matches what is known ---------------
class ApplyFails(RBConn):
    def send_config_set(self, cmds, **kw):
        super().send_config_set(cmds, **kw)
        if cmds != ["rollback 0"]:
            raise RuntimeError("syntax error")
        return "ok"


def test_junos_apply_failure_discards_candidate_and_never_rolls_back_older_change():
    c = ApplyFails()
    r, hooks = go(c, "juniper_junos")
    assert r.rolled_back and not r.ok and r.rollback_method == "discarded"
    assert not any("rollback 1" in x for x in c.log) and not any(x.startswith("commit") for x in c.log)
    assert "cfg:-:rollback 0" in c.log and "exit" in c.log and hooks == ["pre"]
    assert any("applying the change failed" in m for m in r.messages)
    assert any("Nothing changed" in m for m in r.messages)


def test_junos_commit_error_leaves_it_to_timer_after_discarding_candidate():
    c = RBConn(commit_error=RuntimeError("commit failed: timeout"))
    r, _ = go(c, "juniper_junos")
    assert r.rolled_back and r.rollback_method == "device-timer"
    assert not any("rollback 1" in x for x in c.log) and "cfg:-:rollback 0" in c.log
    assert any("reverts on its own" in m for m in r.messages)


def test_xr_apply_failure_exits_without_commit():
    c = ApplyFails()
    r, _ = go(c, "cisco_xr")
    assert r.rollback_method == "discarded" and "exit" in c.log and not any(x.startswith("commit") for x in c.log)


def test_ios_apply_failure_triggers_revert_now():
    class IOSFails(RBConn):
        def send_config_set(self, cmds, **kw):
            super().send_config_set(cmds, **kw)
            raise OSError("socket closed mid-push")
    c = IOSFails()
    r, _ = go(c, "cisco_ios")
    assert r.rolled_back and r.rollback_method == "explicit" and "timing:configure revert now" in c.log
    assert "timing:configure confirm" not in c.log and "save" not in c.log
