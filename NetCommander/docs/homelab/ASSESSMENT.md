# NetCommander 3.3.0 → Uptime Funk 4.0: pre-implementation assessment

This is the analysis done **before** writing the homelab platform. It is kept in the repository so
the design decisions can be traced.

## 1. What the existing application is

NetCommander Pro 3.3.0 is a Python 3.9+ desktop application (CustomTkinter) plus a headless CLI for
network engineers. ~14,000 lines including ~2,100 pytest cases that need no display, network or devices.

| Layer | Modules | Notes |
|---|---|---|
| Security core | `security.py` (CredentialVault, AuthManager), `filelock.py`, `audit.py`, `rbac.py`, `redact.py`, `cmdpolicy.py` | Vault v3 (PBKDF2-600k KEK wrapping a random Fernet DEK), TOTP MFA with lockout + replay protection, hash-chained audit log with anchor, 3 roles, read-only command allowlist |
| Network core | `config.py`, `network.py`, `parsers.py`, `store.py`, `batch.py`, `telemetry.py`, `topology.py` | 16 vendor profiles over Netmiko, LLDP/CDP discovery, encrypted config backups + diff, thread-safe DeviceStore, TCP health monitor |
| Enterprise | `services.py`, `deploy.py`, `rollback.py`, `scheduler.py`, `jobs.py`, `compliance.py`, `templates.py`, `monitors.py`, `prefs.py` | Staged deployments with approvals and device-side rollback, schedules, compliance, SNMPv3/REST monitors |
| Front ends | `ui/` (Tk), `cli.py`, `__main__.py` | UI is a thin shell over `Services` |

## 2. Architecture strengths worth keeping

* Headless core, GUI-only `ui/` package; every policy decision lives below the UI and is unit-tested.
* Injectable seams everywhere (clocks, KDF work factor, `open_connection`, environment, data paths).
* Explicit concurrency rules (one lock at a time, snapshot readers, queue to the Tk thread).
* Transactional persistence (write to disk first, then publish to memory) and cross-process file locks.
* One RBAC policy shared by GUI, CLI and background jobs; audit on denials.

## 3. Reusable modules (reused as-is by 4.0)

| 3.3 module | Reused for |
|---|---|
| `CredentialVault.encrypt_text/decrypt_text` | Encrypting every integration secret (`homelab/core/secrets.py`) |
| `AuthManager.verify_login` | Web sign-in (password + TOTP, lockout, replay protection) |
| `AuditLog` (+ syslog/file sinks) | All homelab actions are audited in the same chain |
| `rbac.Permission/Role/require` | Extended with 6 permissions; enforcement unchanged |
| `security._write_private`, `filelock.FileLock` | Secret store and config writes |
| `redact.redact_secrets` | Base of `homelab/core/sanitize.py` |
| `network.fetch_host_key/trust_host_key/known_hosts_path` | Explicit SSH host-key trust for servers/NAS |
| `network.load_inventory_json`, `DeviceStore.snapshot` | Read-only mirror of network devices into the unified inventory |
| `network.list_snapshots` | Backup Center watches the built-in config backups |
| `utils.csv_safe` | Formula-injection-safe inventory CSV export |

## 4. Security and reliability weaknesses found

| # | Finding | Severity | 4.0 action |
|---|---|---|---|
| W1 | SSH host keys for **network devices** are auto-accepted unless *Strict SSH host keys* is ticked (Netmiko default). | Medium | Unchanged for backward compatibility (documented). All **new** SSH paths (servers, NAS, libvirt, VirtualBox) use paramiko `RejectPolicy` and require explicit, audited trust. Recommendation: enable strict mode. |
| W2 | Audit log is tamper-evident, not tamper-proof. | Low | Documented; off-box sinks recommended. Homelab actions use the same chain. |
| W3 | Headless password via `NETCOMMANDER_VAULT_PASSWORD` is readable by same-user processes. | Low | `serve` additionally requires a TOTP unless `--unattended` is chosen explicitly. |
| W4 | No multi-user server: every user needed a local desktop session. | Design gap | Management API with per-user TOTP sign-in, sessions, CSRF. |
| W5 | Scheduler runs only while a process runs. | Operational | `uptimefunk serve` is the long-running process (systemd unit provided). |
| W6 | JSON-file state does not scale to metric history. | Scalability | Homelab data in SQLite (WAL); network data stays in JSON (compatibility). |
| W7 | SNMP/REST monitors verified only against fakes. | Verification | Same honest labelling applies to new adapters (see INTEGRATIONS.md). |
| W8 | `mypy` with `python_version = 3.10` fails on newer numpy stubs in some environments. | Tooling | Not caused by Uptime Funk; CI lint job uses 3.12 where it passes. |

## 5. Integration plan

1. **Shared core first** (`homelab/core`): database, events, background tasks, secret store, HTTP/SSH/WinRM
   transports with security defaults, adapter registry, notifications, config validation, action guard.
2. **Domain modules** against that core, each with a pure parsing layer tested on captured/realistic output.
3. **Platform facade** (`HomelabPlatform`) - like `Services` in 3.x - so the GUI, CLI and API share one
   permission/confirmation/audit path.
4. **Front ends**: management API + web dashboard (multi-user, responsive, themes), `uptimefunk serve` and
   `uptimefunk homelab …` CLI, a Homelab tab in the existing desktop window.

## 6. Backward-compatibility requirements

* Every 3.3 test must keep passing unchanged (verified: 2,103 → 2,103 pass, plus new tests).
* Data files and formats untouched: `users_auth.json`, `vaults/`, `topology.json`, `backups/`, `audit.jsonl`,
  schedules/deployments/monitors JSON. New data lives in new files only.
* Role semantics unchanged for existing permissions; guest keeps its 3.x workflow.
* No new **required** dependency (stdlib `sqlite3`, `http.server`, `ssl`); optional extras for VMware/Windows.
* CLI commands, flags and exit codes unchanged; new commands are additions.

## 7. Migration strategy

Additive, zero-touch migration: the first run of 4.0 creates `homelab.db` (schema v1, versioned with
`PRAGMA user_version`, forward-only migrations, refuses to open a newer schema) next to the existing data.
Nothing is converted or rewritten. Rolling back to 3.3 is possible by reinstalling it; the new files are
simply ignored. See [UPGRADE.md](UPGRADE.md).
