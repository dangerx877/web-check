"""Command execution seams: local processes, SSH (strict host-key verification) and WinRM/PowerShell.

All collectors and adapters receive a :class:`Runner`, never a raw SSH client, so tests substitute a
fake and production code shares one hardened implementation:

* **SSH host keys are verified.** Unknown or changed keys are rejected (paramiko ``RejectPolicy``)
  against ``~/.ssh/known_hosts`` (plus the system known_hosts). Trusting a new host is an explicit,
  audited action that shows the SHA-256 fingerprint first (``netcommander homelab trust-host`` or the
  web UI), reusing :func:`netcommander.network.fetch_host_key` / ``trust_host_key``.
* **Command validation.** A runner can carry a :class:`CommandPolicy`; read-only collectors use an
  exact allowlist, so a compromised inventory record cannot smuggle ``; rm -rf`` into a "status" probe.
* **No shell for local commands** (argument vectors only), output size caps and timeouts everywhere.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .errors import IntegrationError, ValidationError
from .sanitize import redact_text

log = logging.getLogger(__name__)
MAX_OUTPUT = 4 * 1024 * 1024
_SHELL_META = set(";|&`$<>\n\r")


@dataclass
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class Runner(Protocol):
    description: str

    def run(self, command: str, timeout: float = 30.0) -> CommandResult: ...


class CommandPolicy:
    """Exact-match allowlist (after whitespace normalisation) plus optional safe prefixes.

    A prefix match additionally requires the remaining arguments to be free of shell metacharacters,
    e.g. prefix ``"smartctl -j -a /dev/"`` accepts ``smartctl -j -a /dev/sda`` but not ``.../sda; reboot``.
    """

    def __init__(self, exact: Iterable[str] = (), prefixes: Iterable[str] = ()) -> None:
        self.exact = {self._norm(c) for c in exact}
        self.prefixes = tuple(self._norm(p) for p in prefixes)

    @staticmethod
    def _norm(cmd: str) -> str:
        return " ".join(cmd.split())

    def allows(self, command: str) -> bool:
        cmd = self._norm(command)
        if cmd in self.exact:
            return True
        for p in self.prefixes:
            if cmd.startswith(p):
                rest = cmd[len(p):]
                if rest and not (_SHELL_META & set(rest)) and ".." not in rest:
                    return True
        return False

    def check(self, command: str) -> None:
        if not self.allows(command):
            raise ValidationError(f"Command refused by the read-only policy: {command[:80]!r}")


class LocalRunner:
    """Runs a command on this machine without a shell."""

    description = "local"

    def __init__(self, policy: CommandPolicy | None = None) -> None:
        self.policy = policy

    def run(self, command: str, timeout: float = 30.0) -> CommandResult:
        if self.policy:
            self.policy.check(command)
        argv = shlex.split(command)
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)  # noqa: S603 - no shell
        except FileNotFoundError:
            return CommandResult(command, 127, "", f"{argv[0]}: not found")
        except subprocess.TimeoutExpired:
            return CommandResult(command, 124, "", f"timed out after {timeout:g}s")
        return CommandResult(command, p.returncode, p.stdout[:MAX_OUTPUT].decode("utf-8", "replace"),
                             p.stderr[:MAX_OUTPUT].decode("utf-8", "replace"))


@dataclass
class SshTarget:
    host: str
    port: int = 22
    username: str = "root"
    password: str = ""
    key_file: str = ""
    timeout: float = 10.0

    def __repr__(self) -> str:                     # never print the password
        return f"SshTarget({self.username}@{self.host}:{self.port})"


def _known_hosts_files() -> list[Path]:
    from ...network import known_hosts_path
    return [p for p in (known_hosts_path(),) if p.exists()]


class SshRunner:
    """One SSH session (paramiko) reused for several commands; use as a context manager."""

    def __init__(self, target: SshTarget, policy: CommandPolicy | None = None, client_factory: Any = None) -> None:
        self.target, self.policy = target, policy
        self.description = f"ssh://{target.username}@{target.host}:{target.port}"
        self._factory = client_factory
        self._client: Any = None

    def _connect(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import paramiko
        except ImportError as exc:                    # pragma: no cover - paramiko ships with netmiko
            raise IntegrationError("SSH needs paramiko (installed with netmiko).") from exc
        client = self._factory() if self._factory else paramiko.SSHClient()
        client.load_system_host_keys()
        for kh in _known_hosts_files():
            try:
                client.load_host_keys(str(kh))
            except OSError:
                pass
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        t = self.target
        kw: dict[str, Any] = {"hostname": t.host, "port": t.port, "username": t.username, "timeout": t.timeout,
                              "banner_timeout": t.timeout * 2, "auth_timeout": t.timeout * 2,
                              "allow_agent": False, "look_for_keys": False}
        if t.key_file:
            kw["key_filename"] = str(Path(t.key_file).expanduser())
        if t.password:
            kw["password"] = t.password
        try:
            client.connect(**kw)
        except paramiko.BadHostKeyException:
            raise IntegrationError(f"SSH host key for {t.host} has CHANGED - refusing to connect "
                                   "(possible man-in-the-middle). Verify and re-trust the host deliberately.") from None
        except paramiko.AuthenticationException:
            raise IntegrationError(f"SSH authentication to {t.host} failed.") from None
        except paramiko.SSHException as exc:
            if "known_hosts" in str(exc) or "not found" in str(exc).lower():
                raise IntegrationError(f"SSH host {t.host} is not trusted yet. Review its fingerprint and trust it "
                                       "(netcommander homelab trust-host / Security page).") from None
            raise IntegrationError(f"SSH to {t.host} failed: {redact_text(str(exc))}") from None
        except OSError as exc:
            raise IntegrationError(f"SSH to {t.host}:{t.port} failed: {exc}") from None
        self._client = client
        return client

    def run(self, command: str, timeout: float = 30.0) -> CommandResult:
        if self.policy:
            self.policy.check(command)
        client = self._connect()
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read(MAX_OUTPUT).decode("utf-8", "replace")
            err = stderr.read(MAX_OUTPUT).decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
        except OSError as exc:
            raise IntegrationError(f"command on {self.target.host} failed: {exc}") from None
        return CommandResult(command, int(code), out, err)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    def __enter__(self) -> SshRunner:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


@dataclass
class WinRmTarget:
    host: str
    username: str
    password: str = ""
    port: int = 5986
    transport: str = "ntlm"              # ntlm | kerberos | credssp
    https: bool = True
    ca_file: str = ""
    timeout: float = 30.0

    def __repr__(self) -> str:
        return f"WinRmTarget({self.username}@{self.host}:{self.port})"


class WinRmRunner:
    """PowerShell remoting over WinRM (optional ``pywinrm``). HTTPS with certificate validation by default."""

    def __init__(self, target: WinRmTarget, policy: CommandPolicy | None = None, session_factory: Any = None) -> None:
        if not target.https:
            log.warning("WinRM over HTTP to %s: payload encryption depends on the transport (use HTTPS)", target.host)
        self.target, self.policy = target, policy
        self.description = f"winrm://{target.username}@{target.host}:{target.port}"
        self._factory = session_factory
        self._session: Any = None

    def _connect(self) -> Any:
        if self._session is None:
            if self._factory is not None:
                self._session = self._factory(self.target)
            else:
                try:
                    import winrm  # type: ignore[import-not-found]
                except ImportError as exc:
                    raise IntegrationError("Windows management needs the optional 'pywinrm' package: "
                                           "pip install 'netcommander[windows]'.") from exc
                t = self.target
                scheme = "https" if t.https else "http"
                kw: dict[str, Any] = {"auth": (t.username, t.password), "transport": t.transport,
                                      "operation_timeout_sec": int(t.timeout), "read_timeout_sec": int(t.timeout) + 10}
                if t.https:
                    kw["server_cert_validation"] = "validate"
                    if t.ca_file:
                        kw["ca_trust_path"] = t.ca_file
                self._session = winrm.Session(f"{scheme}://{t.host}:{t.port}/wsman", **kw)
        return self._session

    def run(self, command: str, timeout: float = 60.0) -> CommandResult:
        """``command`` is a PowerShell script."""
        if self.policy:
            self.policy.check(command)
        try:
            r = self._connect().run_ps(command)
        except IntegrationError:
            raise
        except Exception as exc:
            raise IntegrationError(f"WinRM to {self.target.host} failed: {redact_text(str(exc))}") from None
        out = r.std_out.decode("utf-8", "replace") if isinstance(r.std_out, bytes) else str(r.std_out)
        err = r.std_err.decode("utf-8", "replace") if isinstance(r.std_err, bytes) else str(r.std_err)
        return CommandResult(command[:200], int(r.status_code), out[:MAX_OUTPUT], err[:MAX_OUTPUT])

    def close(self) -> None:
        self._session = None


class FakeRunner:
    """Scripted runner for tests and demos: maps exact commands (or prefixes ending in ``*``) to output."""

    def __init__(self, responses: dict[str, str | CommandResult | Exception], description: str = "fake",
                 policy: CommandPolicy | None = None) -> None:
        self.responses, self.description, self.policy = dict(responses), description, policy
        self.calls: list[str] = []

    def run(self, command: str, timeout: float = 30.0) -> CommandResult:
        if self.policy:
            self.policy.check(command)
        self.calls.append(command)
        resp: Any = self.responses.get(command)
        if resp is None:
            for key, val in self.responses.items():
                if key.endswith("*") and command.startswith(key[:-1]):
                    resp = val
                    break
        if resp is None:
            return CommandResult(command, 127, "", "command not found")
        if isinstance(resp, Exception):
            raise resp
        if isinstance(resp, CommandResult):
            return resp
        return CommandResult(command, 0, str(resp))


def run_all(runner: Runner, commands: Sequence[str], timeout: float = 30.0) -> dict[str, CommandResult]:
    """Run several commands; a failing one is recorded, not raised (collectors degrade gracefully)."""
    out: dict[str, CommandResult] = {}
    for cmd in commands:
        try:
            out[cmd] = runner.run(cmd, timeout)
        except ValidationError:
            raise
        except IntegrationError as exc:
            out[cmd] = CommandResult(cmd, 255, "", str(exc))
    return out
