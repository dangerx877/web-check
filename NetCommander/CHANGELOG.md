# Changelog

## 4.0.0 - Uptime Funk: homelab & infrastructure platform

> **Renamed:** NetCommander Pro is now **Uptime Funk**. The `uptimefunk` command is new; `netcommander` still works.
> The Python package (`netcommander`), data folder, environment variables (`NETCOMMANDER_*`) and file formats are
> unchanged, so existing installs need no migration. New authenticator entries are labelled "Uptime Funk".

> **Upgrade note:** additive - no existing file is converted. New data lives in `homelab.db`,
> `homelab_secrets.json` (encrypted) and the optional `homelab.json`. See [docs/homelab/UPGRADE.md](docs/homelab/UPGRADE.md).

NetCommander grows into Uptime Funk, from a network tool into a homelab and infrastructure management platform while keeping every
3.x feature, file format and command. All 2,103 existing tests pass unchanged; ~140 tests were added.

### New
- **Unified inventory** of servers, desktops, laptops, network gear, NAS, hypervisors, VMs, containers and
  services; manual entries (edited fields are locked against discovery), CSV import/export, relationships, and a
  read-only mirror of the existing network inventory.
- **Agentless discovery**: TCP probes (no root), SSH/HTTP banners, ARP/NDP + vendor lookup, reverse DNS, classifier.
- **Server management**: Linux over SSH and Windows over PowerShell remoting - CPU, memory, disks, network,
  services, processes, uptime - with fixed read-only command sets; connectivity tests.
- **Virtualization**: Proxmox VE (REST), VMware ESXi/vCenter (pyVmomi, beta), Hyper-V (PowerShell, beta),
  VirtualBox, KVM/libvirt - VMs, resources, configuration, disks, snapshots, host allocation, confirmed power actions.
- **Docker**: containers, health, stats, logs, images, networks, volumes, Compose projects, confirmed start/stop/restart.
- **Storage**: TrueNAS, Synology (beta), UGREEN and QNAP over SSH (beta), generic Linux/ZFS/mdadm - pools, RAID,
  disks with SMART, shares, SMB/NFS/iSCSI checks, growth forecasting.
- **Network**: IPAM (subnets, reservations, conflicts, next free), VLANs, diagnostics, unified topology.
- **Monitoring center**: reachability/TCP/HTTP checks, 13 default thresholds, alerts with hysteresis and
  acknowledgement, notifications (file, webhook, e-mail), event timeline, graphs, health scores, utilisation report.
- **Automation center**: Python/SSH/PowerShell scripts, built-ins, parameters, risk scan, second-person approval
  bound to the script hash, execution history, workflows, expiring remediation policies.
- **Backup & DR**: backup job monitoring (Proxmox, TrueNAS, files, NetCommander config backups, manual),
  verification, recovery points, recovery runbook, configuration export.
- **Management API + web dashboard** (`uptimefunk serve`): TOTP sign-in, sessions, CSRF, strict CSP,
  responsive dark/light UI. **Homelab tab** in the desktop window. **CLI**: `uptimefunk homelab …`.
- Shared core: SQLite persistence, event bus, task runner, encrypted secret store, hardened HTTP/SSH/WinRM
  transports, adapter registry with opt-in plugins, validated configuration.

### Security
- New SSH paths reject unknown host keys; trust is explicit and audited.
- TLS verified by default with CA-file or certificate pinning; plain HTTP and unauthenticated Docker TCP refused.
- Change/destructive actions need RBAC **and** a one-time confirmation bound to user, action, target and parameters.
- No plaintext secrets in config, inventory or API responses; redaction of logs, outputs and exports.
- Details: [docs/homelab/SECURITY-ASSESSMENT.md](docs/homelab/SECURITY-ASSESSMENT.md).

### Known limitations
- Adapters are verified against simulated devices only in this release (see docs/homelab/INTEGRATIONS.md).
- Python automation scripts are isolated but not sandboxed; Docker socket access is root-equivalent.
- Sessions are in memory (sign in again after a restart); no SSO/WebAuthn yet.

## 3.3.0 - access-control and rollback hardening

> **Behaviour changes:** after the first account, new accounts are created by an admin (*Account & Security → Add User*); *Continue as Guest* is only offered while no account exists; operators can run only read-only commands from the allowlist; `vault-export` / `vault-import` ask for an authenticator code and `vault-import` uses the account password.

### Security
- **Read-only allowlist for operators** (`cmdpolicy.py`, enforced in `Services.authorize_exec`): replaces the deny-list that abbreviations (`confi t`, `relo`, `wr er`, `req sys reb`), Linux shells and `| redirect` could get past.
- **Guest mode can no longer bypass roles:** offered only on an installation with no accounts; otherwise disabled in the sign-in window and downgraded to viewer in the service layer.
- **No open registration:** only the first account self-registers; later accounts need an admin creator (`AuthManager.create_account(..., created_by=)`) and start with a temporary password the user is prompted to change.
- **Schedules:** adding, removing and pausing now really require `manage_schedules` (operators could add/remove and anyone could pause). Changes are audited.
- **CLI:** password checks count toward the sign-in lockout and a locked account is refused; a password-only success does not clear failures. `vault-export` / `vault-import` require a 2FA or recovery code. `vault-import` refuses an existing vault before asking for a code.
- **Accounts file:** cross-process lock + re-read before every change (role changes, lockout counters and replay markers are no longer lost between app windows / CLI); a transient I/O error no longer quarantines the file (which let the next registrant become admin).
- **Audit:** anchor file detects truncated, deleted or replaced logs; one damaged line no longer hides the whole log in the UI.
- **Admin Reset User** (*Account & Security*): temporary password + new authenticator key for someone who forgot the password or lost the phone; the old vault is set aside (never deleted) for `vault-import`.

### Fixes
- **IOS-XR rollback:** `commit confirmed` timer sent in seconds (was minutes, below XR's 30 s minimum).
- **Verify checks on Junos / IOS-XR** run as `run …` / `do …` because the session is still in config mode.
- **Failures while applying** a rollback-protected push are handled: uncommitted candidates are discarded (`rollback 0` / XR abort), an armed IOS timer is reverted, `rollback 1` is only used once our commit is known to have happened, and the result is returned with its messages.
- **Scheduler:** schedules deleted or paused in one process are no longer run or written back by another; a schedule added while a job runs survives; ids are unique within one millisecond.
- **Backups:** device names that sanitise to the same string (`R1/A`, `R1_A`) get separate folders; older shared folders are still listed but never pruned.
- Linux quick-command preset split into `uname -a` and `uptime` (no shell chaining).
- `ruff check .` and `mypy netcommander` pass; the release workflow installs the test dependencies it runs.
- Docs updated for all of the above; `docs/build_pdfs.py` regenerates the combined guide and every PDF from the `.txt` sources. `ARCHITECTURE.md` no longer claims there is no cross-process lock.

## 3.2.0 - vendor hardening

- Nokia SR OS and SR Linux profiles (`nokia_sros`, `nokia_srl`); both commit explicitly like Junos.
- LLDP parsers for HPE ProCurve, Dell OS10 and Nokia SR Linux (written from vendor documentation, not device captures).
- Redaction for HPE `password manager`, RADIUS/TACACS host keys, quoted Nokia/Dell secrets.
- More commands treated as disruptive (`load`, `rollback`, `boot`, `admin reboot`, `crypto key zeroize`, ...).
- Config-noise filters for Dell, Nokia and ProCurve timestamps/headers.
- Platforms without a device-side rollback (Nokia, Dell, HPE) are refused when rollback is requested.

## 3.1.1 — multi-process safety and audit export

- **Cross-process file locking** (`filelock.py`, POSIX `flock` / Windows `msvcrt`): the audit log, deployment store and scheduler are safe to share between the GUI and headless `schedule-run`/CLI. Two processes can no longer both execute one deployment, or both run one due schedule; audit chains stay intact under concurrent writers (tested with real subprocesses).
- **Sign-in auditing:** every login attempt (success, failure, lockout, recovery-code use) and failed CLI unlock is recorded - never with passwords or codes.
- **Off-box audit copies:** `NETCOMMANDER_AUDIT_COPY=<file>` and `NETCOMMANDER_AUDIT_SYSLOG=host[:port]` / `tcp://host:port` forward each entry (local0, notice/warning). Sink failures never block auditing; UDP can lose messages - use TCP where delivery matters.
- **Compliance against live configs:** `netcommander compliance --live` and *Compliance → Run Check (live)* fetch running configs in parallel instead of reading backups.

## 3.1.0 — enterprise features, recovery, every-OS support

> **Upgrade note:** on first unlock, existing vaults are upgraded in place to format v3 (stronger key derivation, wrapped data key). Your device passwords and old encrypted backups keep working, but **older NetCommander versions cannot open an upgraded vault** - copy `vaults/` somewhere safe before the first run if you may need to go back.

### New: governance and safety
- **Role-based access control** (`viewer` / `operator` / `admin`; guest = the original single-user workflow without approvals, user management, vault export or schedules). Enforced in the GUI, the CLI and background jobs through one policy (`rbac.py`). The first account is admin; accounts created before this release keep admin.
- **Tamper-evident audit log** (`audit.jsonl`, hash-chained, secrets redacted, verified by `netcommander audit-verify` / the Audit Log tab). Tamper-*evident*, not tamper-proof: ship it off-box if you need more.
- **Staged deployments with approvals**: canary-first stages, separation of duties (you cannot approve your own plan), optional two-person rule, approval bound to the exact commands *and* safety options, halt-on-failure, restart-safe.
- **Automatic rollback** (device-side timer): Junos / IOS-XR `commit confirmed`, IOS / IOS-XE `configure terminal revert timer`; post-change verify commands; platforms without a strategy are refused instead of pushed unprotected.
- **Dry-run preview** of a script against the latest backup (text comparison; no device contact), secrets hidden.

### New: operations
- **Scheduled backups** (interval or daily) in the GUI or headless (`netcommander schedule-run`), drift detection (changed/unchanged), retention (`Keep N`), audit entries.
- **Network-wide compliance**: JSON policy (must contain / must not contain / count), per-device-type scoping, report + CSV, from saved backups.
- **Config templates**: `{{var}}` / `{{var|default}}` with global + per-device variables; every problem reported at once; no code execution.
- **Monitoring**: SNMPv3 (authPriv/authNoPriv only) and REST/JSON pollers, rolling history, counter rates, thresholds/alerts, sparkline dashboard. Secrets are vault-encrypted.
- **Headless CLI**: `backup`, `compliance`, `vault-export`, `vault-import`, `schedule-run`, `audit-verify`, `data-dir`.
- Device filter, telemetry sorting, links CSV export (formula-injection safe), SSH connect retry with backoff for timeouts only (never auth), click-through **host-key trust** with fingerprint, persisted preferences.

### New: account recovery and hardening
- Vault format v3: random data key wrapped by the password-derived key -> **password change no longer orphans encrypted backups**; legacy 310k vaults are strengthened to 600k on unlock.
- Single-use **recovery codes** replace the authenticator; **2FA key rotation**; account+vault **password change** (rolls back if the second write fails); passphrase-protected **vault recovery file** export/import.
- Login no longer reveals whether an account exists (same message and cost).
- Windows reserved filenames (`CON`, `NUL`, ...) handled in device names.

### Every OS
- Per-OS data folders (Windows `%APPDATA%`, macOS `Application Support`, Linux XDG) with automatic reuse of an existing `~/.netcommander`; file-manager opener per OS with a clear message when `xdg-open` is missing; executable `.sh`, CRLF `.bat`, `.gitattributes`; `py -3` fallback; Cmd+Return on macOS; distro-specific Tk hints.
- CI matrix (3 OS x 3 Python), real-display job under Xvfb, ruff/mypy, pre-commit, PyInstaller spec and release workflow.

### Fixed along the way
- `Role.parse` mishandled enum members on Python >= 3.11; audit chain could fork with two writers; deployment store ignored changes from another process; monitors added in the UI were not polled.

## 3.0.0 — modular package

### Architecture
- `netcommander.py` (2,500 lines) is now the `netcommander/` package: `config`, `security`, `parsers`, `network`, `store`, `batch`, `telemetry`, `topology`, `utils`, and a `ui/` sub-package (dialogs, topology canvas, telemetry tab, main window). `netcommander.py` remains as a thin launcher for `run.sh` / `run.bat`; `python -m netcommander` and the `netcommander` console command also work.
- The core imports without Tk, matplotlib or Netmiko (Netmiko loads lazily at connect time).
- The module-level `STRICT_HOSTKEYS` global is replaced by an injectable, lock-guarded `RuntimeSettings`; `NET_SSH_STRICT_HOSTKEYS` still forces strict mode on.
- Data location: project folder when run from a checkout (existing installs keep working), `~/.netcommander` for pip installs; override with `NETCOMMANDER_HOME` or `--data-dir`.

### Thread safety
- New `DeviceStore` guards the inventory with an `RLock`; readers get deep-copy snapshots. Probes, the thread pool and UI actions can no longer race ("dict changed size during iteration", half-removed nodes).
- `CredentialVault`, `AuthManager` and `RuntimeSettings` each have their own `RLock`; no lock is ever held while taking another.
- Each batch has its own auth-failure circuit breaker (it was one shared counter), and workers receive a snapshot of params/credentials instead of touching live state.
- Vault and account changes are transactional: written to disk first, published to memory only on success.

### Fixes
- `_run_discovery_cmd` no longer raises `KeyError: None` for profiles without a raw parser (hp_procurve, dell_os10, extreme_exos, paloalto_panos) or an unknown parser key.
- `AuthManager.verify_login` handles a failing disk write cleanly: it fails closed (a login that cannot be recorded is refused), rolls back in-memory replay/lockout state, and the same code works again once the disk is fixed. Registration no longer leaves a phantom account.
- Corrupt accounts files are never overwritten, even twice within one second; wrong-shaped files are treated as corrupt.
- Vault creation/migration failures return `False` with a message instead of crashing the sign-in window; vault key is not re-keyed on unlock (that would orphan encrypted backups).
- Backups from a Guest session are always plain `.cfg` (enforced in `save_config_snapshot`, not only in the UI); same-microsecond filename collisions are impossible; snapshot ordering no longer confused by timestamp-like device names.
- Atomic writes use unique temp files, fsync, and clean up on failure.
- IPv6 and `[v6]:port` addresses are accepted when adding a node.

### UX / security
- The authenticator setup key and otpauth URI are hidden by default in the registration window: **Reveal** (auto-hides after 30 s), **Copy Key**, **Copy URI** (clipboard cleared after 60 s if unchanged); wiped on sign-in/close.
- `~` in `key_file` paths is expanded at connect time; SSH-key devices show 🔑 in the list.
- New: `--version`, `--data-dir`, `--strict-hostkeys`, `--log-level`, `--log-file`; `prune_snapshots()` helper; CI workflow, Makefile, ruff/mypy config.

### Tests
- ~400 pytest cases: vault (standard, legacy 310k, guest, text encryption, concurrency), auth (replay, lockout back-off, corrupt files, disk failure atomicity, legacy upgrade), parsers, `key_file` CSV, `.cfg.enc` backup/diff, pre/post config push incl. pre-backup abort and COMMIT_PLATFORMS, batch circuit breaker, health monitor, CLI, and headless UI smoke tests.

## 2.0.0 — improved release
(see git history / previous CHANGELOG: MFA + guest mode, encrypted backups, pre/post snapshots with diff, key_file import, strict host keys, per-user vaults, commit-platform fixes.)
