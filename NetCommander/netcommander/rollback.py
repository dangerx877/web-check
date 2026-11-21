"""Config push with automatic rollback.

The safety net is *device-side* wherever the platform supports it, so a change that cuts
off our own management access still reverts even though we can no longer talk to the box:

* ``commit_confirmed`` (Junos, IOS-XR) - ``commit confirmed N``; not confirmed = auto-rollback.
* ``revert_timer`` (IOS / IOS-XE) - ``configure terminal revert timer N`` + ``configure confirm``.
  Requires the Configuration Replace/Rollback feature (an ``archive`` path) on the device.

After applying, ``checks`` (``command`` + ``expect`` regex) run; only if *all* pass, and the
session is still alive, is the change confirmed. On commit platforms the session is still in
configuration mode at that point, so checks are sent as operational commands (``run ...`` on
Junos, ``do ...`` on IOS-XR). IOS-XR's ``commit confirmed`` takes **seconds**; the timer is
converted from minutes.

If applying the change itself fails, the push is treated like a failed check: an uncommitted
candidate is discarded, an armed revert timer is triggered, and the result (with its messages)
is returned rather than lost in an exception. Otherwise an explicit revert is attempted and the
device-side timer is the backstop. Platforms with no strategy are refused up front
(:class:`RollbackUnsupported`) rather than pushed without a net, unless the caller opts out.

NOTE: command sequences follow vendor documentation and are covered by fake-connection tests;
they have not been exercised against physical devices - lab-test before relying on them.
"""
from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .config import RuntimeSettings, get_profile
from .network import ConfigHook, Credentials, PreChangeBackupError, _enter_enable, open_connection

STRATEGIES: dict[str, str] = {
    "juniper_junos": "commit_confirmed",
    "cisco_xr": "commit_confirmed",
    "cisco_ios": "revert_timer",
    "cisco_xe": "revert_timer",
}


# Prefix that runs an operational command from configuration mode (commit platforms only).
CHECK_PREFIX: dict[str, str] = {"juniper_junos": "run ", "cisco_xr": "do "}


class RollbackUnsupported(RuntimeError):
    """No automatic rollback strategy for this platform; nothing was pushed."""


@dataclass(frozen=True)
class Check:
    command: str
    expect: str                      # regex that must match the output

    def run(self, conn: Any, prefix: str = "") -> tuple[bool, str]:
        cmd = self.command.strip()
        if prefix and not cmd.lower().startswith(prefix.lower()):
            cmd = prefix + cmd
        try:
            out = str(conn.send_command(cmd, read_timeout=60))
        except Exception as exc:
            return False, f"'{self.command}' failed: {type(exc).__name__}: {exc}"
        if re.search(self.expect, out, re.MULTILINE | re.IGNORECASE):
            return True, f"'{self.command}' ok"
        return False, f"'{self.command}' output did not match /{self.expect}/"


@dataclass
class PushResult:
    output: str = ""
    confirmed: bool = False
    rolled_back: bool = False
    rollback_method: str = ""        # "explicit", "device-timer" or "" when nothing was reverted
    messages: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.confirmed and not self.rolled_back


def supports_rollback(device_type: str | None) -> bool:
    return (device_type or "") in STRATEGIES


def push_with_rollback(
    params: Mapping[str, Any],
    creds: Credentials,
    commands: list[str],
    checks: list[Check] | None = None,
    *,
    save_after: bool = True,
    timer_minutes: int = 5,
    settle_seconds: float = 3.0,
    on_config: ConfigHook | None = None,
    settings: RuntimeSettings | None = None,
    sleep: Callable[[float], None] = time.sleep,
    connect: Callable[..., Any] = open_connection,
) -> PushResult:
    dtype = str(params.get("device_type") or "")
    strategy = STRATEGIES.get(dtype)
    if strategy is None:
        raise RollbackUnsupported(
            f"Automatic rollback is not available for '{dtype or 'generic'}'. Nothing was pushed. "
            f"Supported: {', '.join(sorted(STRATEGIES))}.")
    if not 1 <= timer_minutes <= 60:
        raise ValueError("timer_minutes must be between 1 and 60")
    checks = checks or []
    user, pwd, sec = creds
    show_cmd = get_profile(dtype)["config"]
    res = PushResult()

    with connect(params, user, pwd, sec, settings=settings) as conn:
        _enter_enable(conn, params, sec)
        try:
            before = conn.send_command(show_cmd, read_timeout=120)
            if not str(before).strip():
                raise RuntimeError("empty configuration returned")
            if on_config:
                on_config("pre", before)
        except Exception as exc:
            raise PreChangeBackupError(f"Pre-change backup failed ({exc}); nothing was pushed.") from exc

        # ---- arm + apply -------------------------------------------------
        failures: list[str] = []
        commit_state = "none"            # commit platforms: "none" -> "unknown" (commit sent) -> "done"
        try:
            if strategy == "commit_confirmed":
                res.output = conn.send_config_set(commands, exit_config_mode=False, read_timeout=90)
                delay = timer_minutes * 60 if dtype == "cisco_xr" else timer_minutes   # XR counts seconds
                commit_state = "unknown"
                res.output += "\n" + str(conn.commit(confirm=True, confirm_delay=delay))
                commit_state = "done"
            else:
                res.output = conn.send_config_set(
                    commands, config_mode_command=f"configure terminal revert timer {timer_minutes}", read_timeout=90)
            res.messages.append(f"Applied with a {timer_minutes}-minute device-side revert timer.")
        except Exception as exc:
            failures.append(f"applying the change failed: {type(exc).__name__}: {exc}")

        # ---- verify --------------------------------------------------------
        if not failures:
            sleep(settle_seconds)
            alive = getattr(conn, "is_alive", None)
            try:
                if callable(alive) and not alive():
                    failures.append("management session was lost after the change")
            except Exception as exc:
                failures.append(f"liveness check failed: {exc}")
        if not failures:
            prefix = CHECK_PREFIX.get(dtype, "") if strategy == "commit_confirmed" else ""
            for chk in checks:
                ok, msg = chk.run(conn, prefix)
                (res.messages if ok else failures).append(msg)
                if not ok:
                    break

        # ---- confirm or revert ------------------------------------------
        if not failures:
            try:
                if strategy == "commit_confirmed":
                    res.output += "\n" + str(conn.commit())
                    conn.exit_config_mode()
                else:
                    conn.send_command_timing("configure confirm")
                    if save_after:
                        res.output += "\n" + str(conn.save_config())
                res.confirmed = True
                res.messages.append("All checks passed; change confirmed.")
            except Exception as exc:
                failures.append(f"confirming the change failed: {exc}")

        if failures:
            res.messages.extend(f"FAILED: {f}" for f in failures)
            _revert(conn, dtype, strategy, commit_state, res)
            res.rolled_back = True
            res.messages.append({
                "explicit": "Rolled back.",
                "discarded": "The change was never committed; the candidate was discarded. Nothing changed on the device.",
            }.get(res.rollback_method,
                  f"Change was NOT confirmed; the device reverts on its own within {timer_minutes} minute(s)."))
            return res

        if on_config:
            try:
                on_config("post", conn.send_command(show_cmd, read_timeout=120))
            except Exception as exc:
                res.messages.append(f"Post-change snapshot failed: {exc}")
    return res


def _revert(conn: Any, dtype: str, strategy: str, commit_state: str, res: PushResult) -> None:
    """Undo a failed push as precisely as the known state allows; the device timer is the backstop.

    Never runs ``rollback 1`` unless our confirmed commit is known to have happened: otherwise it
    would undo the change *before* ours.
    """
    try:
        if strategy == "commit_confirmed":
            if commit_state == "done":
                if dtype == "juniper_junos":
                    conn.send_config_set(["rollback 1"], exit_config_mode=False)
                    conn.commit()
                    conn.exit_config_mode()
                    res.rollback_method = "explicit"
                else:
                    conn.exit_config_mode()
                    res.rollback_method = "device-timer"
                return
            # Nothing (or possibly nothing) committed: drop the candidate. If the commit did go
            # through ("unknown"), it was a *confirmed* commit, so the device timer still reverts it.
            if dtype == "juniper_junos":
                conn.send_config_set(["rollback 0"], exit_config_mode=False)
            conn.exit_config_mode()                       # netmiko answers "no" to XR's uncommitted-changes prompt
            res.rollback_method = "discarded" if commit_state == "none" else "device-timer"
        else:
            conn.send_command_timing("configure revert now")
            res.rollback_method = "explicit"
    except Exception as exc:
        res.rollback_method = "device-timer"
        res.messages.append(f"Explicit revert failed ({exc}); relying on the device-side timer.")
