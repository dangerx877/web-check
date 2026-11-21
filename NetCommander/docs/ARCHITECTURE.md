# Architecture

```
netcommander/
  config.py     constants, Paths, VENDOR_PROFILES, COMMIT_PLATFORMS, DISRUPTIVE_CMD, CONFIG_NOISE, RuntimeSettings
  security.py   _write_private, safe_filename, CredentialVault, AuthManager
  parsers.py    TextFSM normalization, vendor parsers, _run_discovery_cmd, resolve_neighbor, apply_discovered_links
  store.py      device model + thread-safe DeviceStore
  network.py    inventory JSON/CSV, open_connection, run_multi_cli_commands, snapshots, diff
  batch.py      BatchRunner (thread pool + auth-failure circuit breaker), build_jobs
  telemetry.py  deep_probe, stats, HealthMonitor, table formatting
  topology.py   pure graph helpers (edges, colours, edge labels, click hit-testing)
  utils.py      parse_host_port, parse_commands, open_folder
  ui/           CustomTkinter front-end (the only code that needs a display)
```

Dependency direction: `ui` → everything; `batch`/`network` → `store`, `security`, `parsers`, `config`; `config` imports nothing local.

## Concurrency rules
1. Shared state lives in exactly three lock-guarded objects: `DeviceStore`, `CredentialVault`, `RuntimeSettings` (plus `AuthManager`).
2. **Locks are never nested.** Code takes one lock, copies what it needs, releases it, then takes the next.
3. Readers get copies (`DeviceStore.snapshot()`, `get_params()`); worker threads receive an immutable job snapshot (`build_jobs`).
4. Background threads never touch widgets: they call `emit(kind, payload)`, which is `queue.Queue.put`; the Tk thread drains the queue every 100 ms.
5. Persistent state changes are transactional: write to disk, then publish to memory.

## Testing seams
`open_connection` is the single place Netmiko is imported; tests patch it (or inject a fake `netmiko` module). Clocks (`AuthManager(clock=...)`), KDF work factor (`iterations=...`), environment (`RuntimeSettings(env=...)`) and data paths (`Paths.for_root(tmp)`) are all injectable.

## 3.1 additions

`services.py` wires audit, RBAC, deployments, schedules, templates and prefs for the GUI; `cli.py` does the same for headless runs. Headless modules (no GUI imports): `audit`, `rbac`, `redact`, `compliance`, `templates`, `rollback`, `deploy`, `scheduler`, `jobs`, `monitors`, `prefs`. UI panels in `ui/enterprise.py` and `ui/account.py` are thin views: permission checks, approvals and rollback decisions live in the headless layer so they are unit-tested without a display.
Several processes (GUI windows, a CLI schedule) may share the same files. The accounts file, scheduler, deployment store and audit log take a cross-process advisory lock (`filelock.py`) and re-read the file inside it before every change, so no process writes back a stale copy. `cmdpolicy.py` holds the read-only command allowlist that separates RUN_SHOW from PUSH_CONFIG; `Services.authorize_exec` is the single place the GUI asks.

## 4.0 homelab platform

```
netcommander/homelab/
  core/          shared infrastructure (no domain knowledge)
    db.py          SQLite (WAL): records (document store), metrics (time series), events (timeline); versioned schema
    events.py      in-process EventBus (exact, prefix.* and * subscriptions; failing handlers isolated)
    tasks.py       TaskRunner (bounded pool, inspectable history) + PeriodicScheduler (no self-overlap)
    secrets.py     SecretStore: integration secrets encrypted with the user's vault key; refs only elsewhere
    httpclient.py  HTTPS JSON client: TLS verify by default, CA file or SHA-256 pinning, mTLS, Unix sockets, http refused
    runners.py     Runner seam: LocalRunner (no shell), SshRunner (RejectPolicy host keys), WinRmRunner, CommandPolicy allowlists
    registry.py    adapter registry with field schemas (secrets separated) + opt-in entry-point plugins
    notify.py      log / file / webhook / SMTP(STARTTLS) channels with severity filters and de-duplication
    settings.py    homelab.json validation (every problem reported, safe defaults)
    authz.py       ActionGuard: RBAC + one-time confirmation tokens for change/destructive actions
    sanitize.py    redaction of secrets in text and structured data
  models.py      Asset (unified inventory record), validation, merge rules (hand-edited fields are locked)
  inventory.py   AssetStore: manual CRUD, observation upserts/matching, read-only mirror of the network inventory, CSV
  discovery.py   agentless TCP sweep, banners, ARP/NDP, OUI vendors, reverse DNS, classifier
  servers.py     Linux (SSH) / Windows (WinRM) read-only collectors + parsers, connectivity checks
  virtualization/ base model + Proxmox (REST), ESXi (pyVmomi), Hyper-V (PowerShell), VirtualBox (VBoxManage), libvirt (virsh)
  containers.py  Docker Engine API (Unix socket or mTLS), logs, stats, compose projects, guarded actions
  storage/       base model, SMB/NFS/iSCSI checks, forecasting; TrueNAS (REST), Synology (DSM API), Linux/UGREEN/QNAP (SSH)
  netmgmt.py     IPAM, VLANs, diagnostics (validated targets), unified topology graph
  monitoring.py  checks, threshold rules with hysteresis, alerts, health scores, reports
  automation.py  scripts, risk scan, parameter validation, approvals bound to script hash, workflows, remediation policies
  backups.py     backup jobs, verification, recovery points, runbook generator, config bundle
  adapters.py    built-in registrations
  platform.py    HomelabPlatform facade: every public method takes Ctx(user, role); RBAC + confirmation + audit
  api/           sessions.py, server.py (stdlib HTTP server, JSON API, static web UI)
  web/           index.html, app.js, app.css (no external resources; CSP-compatible)
  cli.py         `netcommander serve`, `netcommander homelab ...`
ui/homelab.py    Homelab tab in the desktop window (thin view over HomelabPlatform)
```

Dependency direction: `api`, `cli`, `ui/homelab` → `platform` → domain modules → `core` → 3.x security/audit/rbac.
Domain modules never import each other's internals except shared models (`servers.parse_df` is reused by storage).

### Data flow

1. **Integrations** (hypervisor, Docker, storage) are polled on `monitoring.collect_interval_seconds`; results are
   upserted into the inventory (matched by `(integration, external_id)`) and metrics are ingested.
2. **Servers** with SSH/WinRM management settings are collected with allowlisted read-only commands.
3. **Checks** (reachability, TCP, HTTP) run every `monitoring.interval_seconds`, concurrently.
4. `MonitoringEngine.ingest()` stores metrics and evaluates rules → alerts → events → notifications →
   remediation policies (if an admin created one).
5. Every state change emits an event (persisted to the timeline) and every user action is audited.

### Concurrency (additions to the 3.x rules)

* SQLite: one connection per thread, WAL, `BEGIN IMMEDIATE` write transactions, 15 s busy timeout (several
  processes - desktop + `serve` - may share `homelab.db`).
* Background work only through `TaskRunner`; the web UI polls `/api/tasks/<id>`, the desktop tab receives
  results through the existing `ui_queue` (`homelab_text`).
* Event handlers must be quick; they run on the publishing thread.

### Testing seams

`HomelabPlatform(adapter_factory=, runner_factory=, discovery_factory=, probe=, clock=)`; HTTP transports
(`transport=`), command runners (`FakeRunner`), pyVmomi `connect=`/`types=`, WinRM `session_factory=`, SMTP
`smtp_factory=`. `tests/homelab_fixtures.py` builds a simulated homelab from *real adapters* over fake transports.
