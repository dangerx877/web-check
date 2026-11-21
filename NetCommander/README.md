# NetCommander Pro

A desktop tool for network engineers: run commands or push config to many routers, switches and firewalls over SSH, auto-discover links (LLDP/CDP), watch device health, back up and diff configs, and view a live topology map. Sign-in uses email + password + authenticator-app (2FA) codes, and device passwords are kept in an encrypted vault.

## Quick start

**Windows:** double-click `install.bat`, then `run.bat`.
**Linux / macOS:** `./install.sh`, then `./run.sh`.

Or by hand:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python netcommander.py
```

Works on Windows, macOS and Linux. Requires Python 3.9+ with Tk (Linux: `sudo apt install python3-tk` or your distro's equivalent). Full steps and troubleshooting: [docs/INSTALL.md](docs/INSTALL.md). How to use every screen: [docs/HELP.md](docs/HELP.md).

## What's in this folder

| Path | Purpose |
|---|---|
| `netcommander/` | The application package (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) |
| `netcommander.py` | Thin launcher used by `run.sh` / `run.bat` |
| `pyproject.toml` | Packaging (`pip install .` gives a `netcommander` command), pytest/ruff/mypy config |
| `requirements.txt`, `requirements-dev.txt` | Runtime / development packages |
| `install.sh` / `install.bat`, `run.sh` / `run.bat` | Setup and launchers |
| `docs/` | INSTALL, HELP, SECURITY, ARCHITECTURE |
| `tests/` | pytest suite (no display, network or devices needed) |
| `sample_inventory.csv`, `sample_commands.txt` | Examples to import / load |

Created at first run (git-ignored): `users_auth.json`, `vaults/`, `topology.json`, `backups/`, `audit.jsonl`, ... in the project folder when run from a checkout, otherwise in your OS data folder (Windows `%APPDATA%\NetCommander`, macOS `~/Library/Application Support/NetCommander`, Linux `~/.local/share/netcommander`; an existing `~/.netcommander` is still used). Override with `NETCOMMANDER_HOME` / `--data-dir`; `netcommander data-dir` prints the one in use.

## Development

```bash
pip install -e ".[dev]"
python -m pytest            # whole suite, headless
python -m netcommander --help
pip install reportlab && python docs/build_pdfs.py   # after editing docs/*/*.txt: rebuilds the guide + PDFs
```

## Features

**Enterprise additions (3.1):** roles (viewer/operator/admin), tamper-evident audit log, staged deployments with approvals and automatic rollback, scheduled backups, compliance checks, config templates, SNMPv3 + REST monitoring, headless CLI. See [docs/ENTERPRISE.md](docs/ENTERPRISE.md).

- Email + password + TOTP 2FA sign-in with lockout and code-replay protection; admin-created accounts after the first; optional Guest mode on a fresh install (no saved passwords)
- Per-user encrypted credential vault (PBKDF2 + Fernet/AES)
- 14 vendor profiles: Cisco IOS/XE/NX-OS/XR, Arista, Junos, Huawei, HPE Comware/ProCurve, Dell OS10, Extreme, Fortinet, Palo Alto, MikroTik, Linux
- Show/exec batches and config pushes, in parallel, with confirmation for risky commands
- LLDP/CDP auto-discovery and interactive topology map (export PNG)
- Health monitor: latency, jitter, packet loss, state-change alerts
- Encrypted config backups with a noise-filtered diff; automatic before/after backup and change diff on every config push
- SSH key login and optional strict host-key checking

## Safety notes

Config pushes change real devices. Test on a lab device first. The app backs up the config before each push, but review what you send. See [docs/SECURITY.md](docs/SECURITY.md).
