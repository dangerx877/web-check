"""Shared fixtures. Nothing here needs a display, a network, or a real SSH device."""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netcommander.security import AuthManager, CredentialVault  # noqa: E402

FAST_KDF = 1_000          # PBKDF2 rounds for tests that are not about the work factor
PASSWORD = "pw-correct-1"


class FakeClock:
    """Controllable replacement for time.time()."""

    def __init__(self, now: float = 1_700_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def vault(tmp_path) -> CredentialVault:
    v = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
    assert v.unlock_or_init(PASSWORD, path=tmp_path / "v.enc")
    return v


@pytest.fixture
def guest_vault(tmp_path) -> CredentialVault:
    v = CredentialVault(tmp_path / "guest.enc", iterations=FAST_KDF)
    v.unlock_ephemeral()
    return v


@pytest.fixture
def auth(tmp_path, clock) -> AuthManager:
    return AuthManager(tmp_path / "users.json", iterations=FAST_KDF, clock=clock)


# ---------------------------------------------------------------------
# Fake SSH layer
# ---------------------------------------------------------------------
class FakeConn:
    """Netmiko-like connection double that records everything done to it."""

    def __init__(
        self,
        config: str = "hostname R1\n",
        fail_show_on: set[int] | None = None,
        save_error: Exception | None = None,
        textfsm=None,
        raw: str = "",
    ):
        self.config = config
        self.fail_show_on = fail_show_on or set()
        self.save_error = save_error
        self.textfsm, self.raw = textfsm, raw
        self.show_calls = 0
        self.log: list[str] = []
        self.pushed: list[str] = []
        self.config_kwargs: dict = {}
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def enable(self):
        self.log.append("enable")

    def send_command(self, cmd, **kwargs):
        self.log.append(f"send:{cmd}")
        self.show_calls += 1
        if self.show_calls in self.fail_show_on:
            raise OSError("boom")
        if "use_textfsm" in kwargs:
            if isinstance(self.textfsm, Exception):
                raise self.textfsm
            if self.textfsm is not None:
                return self.textfsm
        if self.raw:
            return self.raw
        return self.config

    def send_config_set(self, cmds, **kwargs):
        self.log.append("config_set")
        self.pushed += list(cmds)
        self.config_kwargs = kwargs
        return "ok"

    def save_config(self):
        self.log.append("save_config")
        if self.save_error:
            raise self.save_error
        return "saved"


class FakeCommitConn(FakeConn):
    """Adds the candidate-config API that Junos / IOS-XR / PAN-OS drivers expose."""

    def commit(self):
        self.log.append("commit")
        return "committed"

    def exit_config_mode(self):
        self.log.append("exit_config_mode")


@pytest.fixture
def fake_conn(monkeypatch):
    """Patch network.open_connection to hand out one FakeConn; returns a factory."""
    from netcommander import network

    def install(conn: FakeConn) -> FakeConn:
        monkeypatch.setattr(network, "open_connection", lambda *a, **k: conn)
        return conn

    return install


@pytest.fixture
def fake_netmiko(monkeypatch):
    """A stand-in ``netmiko`` module (so tests run with or without the real package)."""
    mod = types.ModuleType("netmiko")

    class NetmikoAuthenticationException(Exception):
        pass

    class NetmikoTimeoutException(Exception):
        pass

    mod.calls = []
    mod.conn = FakeConn()

    def ConnectHandler(**kwargs):
        mod.calls.append(kwargs)
        return mod.conn

    mod.ConnectHandler = ConnectHandler
    mod.NetmikoAuthenticationException = NetmikoAuthenticationException
    mod.NetmikoTimeoutException = NetmikoTimeoutException
    monkeypatch.setitem(sys.modules, "netmiko", mod)
    return mod
