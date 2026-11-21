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
