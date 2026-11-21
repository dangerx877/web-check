# Installation Guide

## 1. Requirements

- Python **3.9 or newer** (3.11+ recommended)
- Tk support for Python (bundled on Windows/macOS python.org installers; a separate package on Linux)
- Network access from your computer to the devices' SSH port (default 22)
- Internet access once, to download packages

Check your version: `python --version` (or `python3 --version`).

## 2. Easy install

| OS | Install | Run |
|---|---|---|
| Windows | double-click `install.bat` | double-click `run.bat` |
| Linux / macOS | `./install.sh` | `./run.sh` |

The installer creates a private `.venv` folder, installs `requirements.txt`, then `pip install -e .` (adds the `netcommander` command).

## 3. Manual install

```bash
cd NetCommander
python -m venv .venv

# activate it
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows (cmd or PowerShell)

pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

python netcommander.py      # or: python -m netcommander / netcommander
```

The two packages you asked about:

```
pip install cryptography pyotp
```

- `cryptography` encrypts the credential vault.
- `pyotp` generates and checks the 6-digit authenticator codes.

## 4. Install Python / Tk if missing

- **Windows:** https://www.python.org/downloads/ — tick *Add python.exe to PATH*.
- **Ubuntu/Debian:** `sudo apt install python3 python3-venv python3-tk`
- **Fedora:** `sudo dnf install python3 python3-tkinter`
- **macOS:** `brew install python python-tk`

## 5. Troubleshooting

| Problem | Fix |
|---|---|
| `No module named tkinter` | Install Tk (section 4) and recreate `.venv` |
| `No module named pyotp` / `cryptography` | Activate `.venv`, then `pip install cryptography pyotp` |
| `externally-managed-environment` error | Use the `.venv` (don't `pip install` into system Python) |
| pip can't download packages | Check proxy/firewall; set `HTTPS_PROXY` if your network needs one |
| Window is blank / tiny on Linux | Install a Tk 8.6 build; try `python -c "import tkinter; tkinter._test()"` |
| `Authentication failed` on every device | Wrong SSH credentials; see HELP.md, "Stored password cleared" |
| Netmiko can't connect to an old device | Old gear may need legacy SSH algorithms; test with plain `ssh` first |

## 6. Optional settings (environment variables)

| Variable | Effect |
|---|---|
| `NET_SSH_USER`, `NET_SSH_PASS`, `NET_SSH_ENABLE` | Default device credentials, saved into the vault the first time they're needed |
| `NET_DISABLE_GUEST=1` | Disable "Continue as Guest" even before any account exists (it is always off once one does) |
| `NET_SSH_STRICT_HOSTKEYS=1` | Refuse SSH hosts missing from `~/.ssh/known_hosts` |
| `NETCOMMANDER_HOME` | Folder for accounts, vaults, backups and topology.json |

## 7. Run the tests (optional)

```bash
pip install -r requirements-dev.txt
python -m pytest tests
```

## 8. Updating / uninstalling

- Update: replace the `netcommander/` folder and `netcommander.py`, then `pip install -r requirements.txt`.
- Uninstall: delete the folder. To keep your data, first copy `users_auth.json`, `vaults/`, `topology.json` and `backups/`.

## 9. Platform notes

| | Windows | macOS | Linux |
|---|---|---|---|
| Install | `install.bat` (uses `py -3` if `python` is not on PATH) | `./install.sh` (`brew install python-tk` if Tk is missing) | `./install.sh` (Tk: `apt install python3-tk`, `dnf install python3-tkinter`, `pacman -S tk`, `zypper install python3-tk`) |
| Data folder | `%APPDATA%\NetCommander` | `~/Library/Application Support/NetCommander` | `~/.local/share/netcommander` (or `$XDG_DATA_HOME`) |
| Run command | Cmd+Return is not used; **Ctrl+Enter** runs a batch | **Cmd+Return** or Ctrl+Enter | **Ctrl+Enter** |
| Open backups folder | Explorer | Finder (`open`) | `xdg-open` (a message shows the path if it is missing) |
| Strict host keys use | `%USERPROFILE%\.ssh\known_hosts` | `~/.ssh/known_hosts` | `~/.ssh/known_hosts` |

Linux: run under X11 or Wayland with XWayland; headless servers can use every CLI command (`netcommander backup ...`) without a display.
Optional SNMPv3 monitoring: `pip install "netcommander[snmp]"`. Standalone binaries: `pip install ".[build]" && pyinstaller packaging/netcommander.spec` (build on each target OS).
