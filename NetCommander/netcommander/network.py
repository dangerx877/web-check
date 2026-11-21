"""Inventory persistence, SSH connections, command/config execution and config snapshots.

Netmiko is imported lazily inside :func:`open_connection` / :func:`classify_ssh_error`,
so this module (and therefore the whole test-suite) imports and runs without it.
"""
from __future__ import annotations

import csv
import difflib
import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Tuple

from cryptography.fernet import InvalidToken

from .config import (
    COMMIT_PLATFORMS,
    CONFIG_NOISE,
    DEFAULT_BACKUP_DIR,
    RuntimeSettings,
    get_profile,
)
from .parsers import _run_discovery_cmd, normalize_hostname
from .redact import redact_secrets
from .security import CredentialVault, _write_private, safe_filename
from .store import make_device, reciprocate_peers, sanitize_params
from .utils import csv_safe

__all__ = [
    "Credentials", "PreChangeBackupError", "export_links_csv", "fetch_host_key", "known_hosts_path",
    "preview_push", "redact_config", "trust_host_key", "classify_ssh_error", "diff_snapshots",
    "discover_neighbors_via_ssh", "fetch_running_config", "import_inventory_csv",
    "list_snapshots", "load_inventory_json", "open_connection", "prune_snapshots",
    "read_snapshot", "run_multi_cli_commands", "save_config_snapshot", "save_inventory_json",
]

log = logging.getLogger(__name__)

Credentials = Tuple[str, str, str]            # (username, password, enable secret)
ConfigHook = Callable[[str, str], None]


# ======================================================================
# Inventory persistence
# ======================================================================
def save_inventory_json(devices: Mapping[str, dict], filepath: str | Path) -> Path:
    """Atomically write the inventory. Passwords are never written."""
    path = Path(filepath)
    serializable = {}
    for name, info in devices.items():
        serializable[name] = {
            "params": sanitize_params(info.get("params", {})),
            "peers": sorted(set(info.get("peers", []))),
            "links": info.get("links", {}),
        }
    _write_private(path, json.dumps(serializable, indent=2))
    return path


def load_inventory_json(filepath: str | Path, default_username: str = "admin") -> dict:
    data = json.loads(Path(filepath).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Inventory file must contain a JSON object of devices.")
    restored = {}
    for raw_name, entry in data.items():
        if not isinstance(entry, dict):
            continue
        name = str(raw_name).strip().upper()
        if not name:
            continue
        raw_peers = entry.get("peers", [])
        peers = [p.strip().upper() for p in raw_peers if isinstance(p, str) and p.strip()] \
            if isinstance(raw_peers, list) else []
        raw_links = entry.get("links", {})
        links = {
            k.strip().upper(): v for k, v in raw_links.items() if isinstance(v, dict)
        } if isinstance(raw_links, dict) else {}
        raw_params = entry.get("params", {})
        restored[name] = make_device(
            sanitize_params(raw_params if isinstance(raw_params, dict) else {}, default_username),
            peers, links,
        )
    reciprocate_peers(restored)
    return restored


def import_inventory_csv(filepath: str | Path, default_username: str = "admin") -> dict:
    """CSV columns: name, host, device_type, username, port, peers, key_file (optional).

    Peers are separated by ; , or |. A ``key_file`` path switches that device to SSH
    key login (``use_keys=True``) so no password is ever requested for it.
    """
    imported = {}
    with open(filepath, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if isinstance(v, str) or v is None}
            name = normalize_hostname(row.get("name") or row.get("hostname") or "")
            host = row.get("host") or row.get("ip") or row.get("mgmt_ip") or ""
            if not name or not host:
                continue
            peers = [
                normalize_hostname(p)
                for p in re.split(r"[;,|]", row.get("peers", ""))
                if p.strip()
            ]
            params: dict[str, Any] = {
                "device_type": row.get("device_type") or row.get("type") or "cisco_ios",
                "host": host,
                "username": row.get("username") or default_username,
            }
            if row.get("port", "").isdigit():
                params["port"] = int(row["port"])
            if row.get("key_file"):                       # SSH key login (no password)
                params["use_keys"] = True
                params["key_file"] = row["key_file"]
            imported[name] = make_device(params, peers)
    return imported


# ======================================================================
# Connections
# ======================================================================
def open_connection(
    params: Mapping[str, Any],
    username: str,
    password: str,
    secret: str = "",
    settings: RuntimeSettings | None = None,
):
    """Open a Netmiko session honoring the current host-key policy.

    `settings` is the injected :class:`RuntimeSettings`; when omitted a fresh one is used,
    which still honors ``NET_SSH_STRICT_HOSTKEYS`` from the environment.
    """
    from netmiko import ConnectHandler  # lazy: keeps the module importable without netmiko

    settings = settings or RuntimeSettings()
    p = sanitize_params(params)
    timeout = p.pop("timeout", 10)
    p["username"] = username
    p["password"] = password
    p["conn_timeout"] = timeout
    p["auth_timeout"] = max(timeout * 2, 20)
    p["banner_timeout"] = max(timeout * 2, 20)
    if secret:
        p["secret"] = secret
    if not p.get("port"):
        p.pop("port", None)
    if p.get("key_file"):
        p["key_file"] = os.path.expanduser(str(p["key_file"]))
    p.update(settings.ssh_security_kwargs())

    attempts, delay = settings.connect_attempts, settings.connect_backoff
    for attempt in range(1, attempts + 1):
        try:
            return ConnectHandler(**p)
        except Exception as exc:
            kind, _ = classify_ssh_error(exc)
            # Only timeouts are worth retrying. Auth failures must NOT be (account lockout), and
            # host-key problems are a security decision, not a transient fault.
            if kind != "timeout" or attempt == attempts:
                raise
            log.info("connect to %s timed out (attempt %d/%d); retrying in %.1fs", p.get("host"), attempt, attempts, delay)
            _sleep(delay)
            delay *= 2
    raise AssertionError("unreachable")                    # pragma: no cover


_sleep: Callable[[float], None] = time.sleep               # patched in tests


def classify_ssh_error(exc: BaseException) -> tuple[str, str]:
    """Return ``(kind, message)``; kind is 'auth', 'timeout', 'hostkey' or 'other'."""
    auth_exc: tuple[type[BaseException], ...] = ()
    timeout_exc: tuple[type[BaseException], ...] = ()
    try:
        from netmiko import NetmikoAuthenticationException, NetmikoTimeoutException
        auth_exc, timeout_exc = (NetmikoAuthenticationException,), (NetmikoTimeoutException,)
    except ImportError:                                   # pragma: no cover - netmiko is a hard dependency
        pass

    if auth_exc and isinstance(exc, auth_exc):
        return "auth", "Authentication failed — stored vault password cleared; you will be prompted next time."
    if timeout_exc and isinstance(exc, timeout_exc):
        return "timeout", f"Timed out / unreachable: {exc}"
    msg = f"{type(exc).__name__}: {exc}"
    low = str(exc).lower()
    if "known_hosts" in low or ("host key" in low and ("not" in low or "verif" in low or "mismatch" in low)):
        return "hostkey", msg + " (Strict SSH host keys is on and this device's key is not trusted yet.)"
    return "other", msg


def _enter_enable(conn: Any, params: Mapping[str, Any], secret: str) -> None:
    profile = get_profile(params.get("device_type"))
    if secret and profile["enable"]:
        conn.enable()


def discover_neighbors_via_ssh(
    params: Mapping[str, Any],
    creds: Credentials,
    settings: RuntimeSettings | None = None,
) -> list[dict]:
    profile = get_profile(params.get("device_type"))
    result: list[dict] = []
    seen: set[tuple[str, str]] = set()
    if not profile["discovery"]:
        return result

    user, pwd, sec = creds
    with open_connection(params, user, pwd, sec, settings=settings) as conn:
        _enter_enable(conn, params, sec)
        for cmd, proto, parser_key in profile["discovery"]:
            try:
                records = _run_discovery_cmd(conn, cmd, parser_key)
            except Exception as exc:
                # e.g. CDP disabled on a device - keep going with the other protocols
                if len(profile["discovery"]) > 1:
                    log.info("discovery command %r failed: %s", cmd, exc)
                    continue
                raise
            for rec in records:
                key = (rec["neighbor"], rec["local_intf"])
                if key in seen:
                    continue
                seen.add(key)
                rec["protocol"] = proto
                result.append(rec)
    return result


# ======================================================================
# Multi-command execution & config pushing
# ======================================================================
class PreChangeBackupError(RuntimeError):
    """The pre-change snapshot failed, so nothing was pushed to the device."""


def run_multi_cli_commands(
    params: Mapping[str, Any],
    creds: Credentials,
    commands: list[str],
    config_mode: bool = False,
    save_after: bool = False,
    on_config: ConfigHook | None = None,
    settings: RuntimeSettings | None = None,
) -> str:
    """Executes show commands sequentially OR pushes a configuration set.

    ``on_config(tag, text)`` is called with the running config before (``"pre"``)
    and after (``"post"``) a config push. If the ``"pre"`` snapshot cannot be
    fetched or stored, :class:`PreChangeBackupError` is raised and *nothing is pushed*.
    """
    user, pwd, sec = creds
    with open_connection(params, user, pwd, sec, settings=settings) as conn:
        _enter_enable(conn, params, sec)
        if not config_mode:
            blocks = []
            for cmd in commands:
                res = conn.send_command(cmd, read_timeout=60)
                blocks.append(f"$ {cmd}\n{res}")
            return "\n\n".join(blocks)

        show_cmd = get_profile(params.get("device_type"))["config"]
        if on_config:
            try:
                before = conn.send_command(show_cmd, read_timeout=120)
                if not before.strip():
                    raise RuntimeError("empty configuration returned")
                on_config("pre", before)
            except Exception as exc:
                raise PreChangeBackupError(
                    f"Pre-change backup failed ({exc}); nothing was pushed."
                ) from exc

        if params.get("device_type") in COMMIT_PLATFORMS and hasattr(conn, "commit"):
            # Candidate-config platforms: stay in config mode, commit explicitly.
            # Leaving config mode without a commit discards the changes.
            out = conn.send_config_set(commands, exit_config_mode=False, read_timeout=90)
            if save_after:
                out += "\n" + str(conn.commit())
            else:
                out += "\n[Notice] 'Write/Save on Config' is off - changes were NOT committed and were discarded."
            conn.exit_config_mode()
        else:
            out = conn.send_config_set(commands, read_timeout=90)
            if save_after:
                try:
                    out += "\n" + conn.save_config()
                except Exception as exc:
                    out += f"\n[Save Config Warning]: {exc}"

        if on_config:
            try:
                on_config("post", conn.send_command(show_cmd, read_timeout=120))
            except Exception as exc:
                out += f"\n[Post-change snapshot failed]: {exc}"
        return out


def fetch_running_config(
    params: Mapping[str, Any],
    creds: Credentials,
    settings: RuntimeSettings | None = None,
) -> str:
    cmd = get_profile(params.get("device_type"))["config"]
    user, pwd, sec = creds
    with open_connection(params, user, pwd, sec, settings=settings) as conn:
        _enter_enable(conn, params, sec)
        return conn.send_command(cmd, read_timeout=120)


# ======================================================================
# Config snapshots, listing and diffing
# ======================================================================
_STAMP_RX = re.compile(r"\d{8}_\d{6}(?:_\d{6})?")


def device_dirname(device_name: str) -> str:
    """Folder/file prefix for a device's backups: filesystem-safe AND unique per device name.

    :func:`safe_filename` alone maps different names to one string (``R1/A`` and ``R1_A`` both
    become ``R1_A``), which would mix two devices' backups. When sanitising changed the name, a
    short hash of the original name is appended, so every distinct name gets its own folder.
    Names that are already safe (the common case) keep exactly the folder they always had.
    """
    import hashlib
    safe = safe_filename(device_name)
    if safe == device_name:
        return safe
    return f"{safe}-{hashlib.sha256((device_name or '').encode('utf-8')).hexdigest()[:8]}"


def save_config_snapshot(
    device_name: str,
    config_text: str,
    backup_root: Path = DEFAULT_BACKUP_DIR,
    vault: CredentialVault | None = None,
    tag: str = "",
) -> Path:
    """Save a config backup. With a (non-guest) vault the file is encrypted (``.cfg.enc``).

    Guest vaults use a throw-away key, so a guest backup is written as plain
    ``.cfg``: an encrypted one would be unreadable after the session.
    """
    if vault is not None and vault.ephemeral:
        vault = None
    backup_root = Path(backup_root)
    safe = device_dirname(device_name)          # blocks path traversal; unique per device name
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    label = f"_{safe_filename(tag)}" if tag else ""
    suffix = ".cfg.enc" if vault is not None else ".cfg"
    target_dir = backup_root / safe
    target_dir.mkdir(parents=True, exist_ok=True)

    out_file = target_dir / f"{safe}_{stamp}{label}{suffix}"
    counter = 1
    while out_file.exists():
        out_file = target_dir / f"{safe}_{stamp}{label}_{counter}{suffix}"
        counter += 1

    if vault is not None:
        _write_private(out_file, vault.encrypt_text(config_text))
    else:
        _write_private(out_file, config_text)
    return out_file


def read_snapshot(path: Path, vault: CredentialVault | None = None) -> str:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name.endswith(".enc"):
        if vault is None:
            raise RuntimeError("This backup is encrypted; sign in with your account (not Guest) to read it.")
        try:
            return vault.decrypt_text(text)
        except InvalidToken:
            raise RuntimeError(f"{path.name} was encrypted with a different account's key.") from None
    return text


def list_snapshots(device_name: str, backup_root: Path = DEFAULT_BACKUP_DIR,
                   include_legacy: bool = True) -> list[Path]:
    """Backups for a device, oldest first.

    ``include_legacy`` also returns files from the pre-3.3 folder name (only differs for names that
    needed sanitising). Those may be shared with another device whose name sanitised the same way,
    so they are shown but never pruned.
    """
    folders = [Path(backup_root) / device_dirname(device_name)]
    legacy = Path(backup_root) / safe_filename(device_name)
    if include_legacy and legacy != folders[0]:
        folders.append(legacy)
    files: list[Path] = []
    for folder in folders:
        if folder.is_dir():
            files += list(folder.glob("*.cfg")) + list(folder.glob("*.cfg.enc"))

    prefix = re.compile(rf"(?:{re.escape(device_dirname(device_name))}|{re.escape(safe_filename(device_name))})"
                        rf"_({_STAMP_RX.pattern})")

    def sort_key(p: Path) -> tuple[str, str]:
        m = prefix.match(p.name)
        stamp = m.group(1) if m else (_STAMP_RX.search(p.name) or [""])[0]
        return (stamp.ljust(22, "0"), p.name)

    return sorted(files, key=sort_key)


def prune_snapshots(device_name: str, keep: int, backup_root: Path = DEFAULT_BACKUP_DIR) -> list[Path]:
    """Delete all but the newest `keep` backups of a device; returns the deleted paths."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    snaps = list_snapshots(device_name, backup_root, include_legacy=False)
    doomed = snaps[:-keep] if len(snaps) > keep else []
    removed = []
    for path in doomed:
        try:
            path.unlink()
            removed.append(path)
        except OSError as exc:
            log.warning("could not delete old backup %s: %s", path, exc)
    return removed


def diff_snapshots(old: Path, new: Path, vault: CredentialVault | None = None) -> str:
    """Unified diff of two backups with timestamp/noise lines filtered out."""
    def clean(p: Path) -> list[str]:
        lines = read_snapshot(p, vault).splitlines()
        return [ln for ln in lines if not any(rx.match(ln) for rx in CONFIG_NOISE)]

    diff = difflib.unified_diff(
        clean(Path(old)), clean(Path(new)),
        fromfile=Path(old).name, tofile=Path(new).name, lineterm="", n=2,
    )
    return "\n".join(diff)


# ======================================================================
# SSH host-key trust (TOFU with an explicit, user-visible fingerprint)
# ======================================================================
def known_hosts_path(home: Path | None = None) -> Path:
    """``~/.ssh/known_hosts`` (same location OpenSSH and Netmiko's system_host_keys use, on every OS)."""
    return (Path(home) if home is not None else Path.home()) / ".ssh" / "known_hosts"


def known_hosts_entry(host: str, port: int | None, key_type: str, key_b64: str) -> str:
    target = f"[{host}]:{port}" if port and int(port) != 22 else host
    return f"{target} {key_type} {key_b64}"


def fingerprint_sha256(key_bytes: bytes) -> str:
    import base64
    import hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(key_bytes).digest()).decode("ascii").rstrip("=")


def fetch_host_key(host: str, port: int = 22, timeout: float = 8.0) -> dict[str, str]:
    """Read (not trust) the server's host key. Returns type, fingerprint and base64 body."""
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("paramiko is required to read host keys (it is installed with netmiko).") from exc
    import socket
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return {"type": key.get_name(), "fingerprint": fingerprint_sha256(key.asbytes()), "base64": key.get_base64()}
    finally:
        transport.close()


def trust_host_key(host: str, port: int | None, key_type: str, key_b64: str, path: Path | None = None) -> Path:
    """Append one entry to known_hosts (never rewrites existing lines). Idempotent."""
    path = Path(path) if path is not None else known_hosts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    line = known_hosts_entry(host, port, key_type, key_b64)
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    if line in existing.splitlines():
        return path
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(line + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


# ======================================================================
# Dry-run preview, link export
# ======================================================================
def preview_push(current_config: str, commands: list[str]) -> dict[str, list[str]]:
    """Heuristic preview of a config push against a known config (no device contact).

    ``new``      - commands whose exact line is not in the current config (will probably change something)
    ``present``  - commands already present verbatim (probably no-ops)
    ``disruptive`` - commands matching :data:`DISRUPTIVE_CMD` (reload, erase, shutdown ...)
    ``negations`` - ``no ...`` commands that remove something currently configured

    This is a *text* comparison, not a device simulation: hierarchy, defaults and ordering are not
    modelled. Treat it as a review aid, never as proof of what the device will do.
    """
    have = {ln.strip() for ln in current_config.splitlines()}
    new: list[str] = []
    present: list[str] = []
    disruptive: list[str] = []
    negations: list[str] = []
    for cmd in commands:
        c = cmd.strip()
        if not c or c.startswith("#"):
            continue
        if c.startswith("no ") or c.startswith("delete "):
            target = c.split(None, 1)[1] if " " in c else c
            (negations if target in have or any(h.endswith(target) for h in have) else present).append(c)
        elif c in have:
            present.append(c)
        else:
            new.append(c)
        if _DISRUPTIVE.match(c) and not _CONFIG_ENTRY.match(c):
            disruptive.append(c)
    return {"new": new, "present": present, "negations": negations, "disruptive": disruptive}


_DISRUPTIVE = re.compile(r"^\s*(reload|reboot|shutdown|halt|poweroff|write\s+erase|erase|delete|format|"
                         r"request\s+system|reset|/system\s+(reset|reboot|shutdown))\b", re.I)
_CONFIG_ENTRY = re.compile(r"^\s*(interface|router|line|vlan)\b", re.I)


def export_links_csv(devices: Mapping[str, dict], filepath: str | Path) -> Path:
    """Write one row per discovered link (deduplicated, both directions merged)."""
    rows: dict[tuple[str, str], dict] = {}
    for name, info in devices.items():
        for peer, link in (info.get("links") or {}).items():
            lo, hi = sorted((name, peer))
            row = rows.setdefault((lo, hi), {"a": lo, "b": hi, "a_if": "", "b_if": "", "protocol": ""})
            row["protocol"] = row["protocol"] or link.get("protocol", "")
            if name == row["a"]:
                row["a_if"] = link.get("local_intf", "") or row["a_if"]
                row["b_if"] = link.get("remote_intf", "") or row["b_if"]
            else:
                row["b_if"] = link.get("local_intf", "") or row["b_if"]
                row["a_if"] = link.get("remote_intf", "") or row["a_if"]
    for name, info in devices.items():                     # peers without interface detail still count as links
        for peer in info.get("peers", []):
            if peer in devices:
                lo, hi = sorted((name, peer))
                rows.setdefault((lo, hi), {"a": lo, "b": hi, "a_if": "", "b_if": "", "protocol": ""})
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["device_a", "interface_a", "device_b", "interface_b", "protocol"])
        for key in sorted(rows):
            r = rows[key]
            w.writerow([csv_safe(r["a"]), csv_safe(r["a_if"]), csv_safe(r["b"]), csv_safe(r["b_if"]), csv_safe(r["protocol"])])
    return path


def redact_config(text: str) -> str:
    """Scrub secrets from config text before it is shown/shared (never applied to stored backups)."""
    return redact_secrets(text)
