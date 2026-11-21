# Upgrading from 3.x to 4.0

## Summary
4.0 is **additive**. Your accounts, vaults, network inventory (`topology.json`), config backups, audit log,
deployments, schedules, monitors and preferences are read and written exactly as before. The homelab platform
stores its own data in new files next to them.

| New file | Contents | Secret? |
|---|---|---|
| `homelab.db` (+ `-wal`, `-shm`) | inventory, integrations (secret *references* only), metrics, events, alerts, IPAM, automation, backup jobs | no secrets |
| `homelab_secrets.json` | integration/server secrets, encrypted with your vault key | encrypted |
| `homelab.json` | optional configuration you create | no secrets |
| `alerts.jsonl` | optional file notification channel | no secrets |

## Steps
1. **Back up the data folder** (`netcommander data-dir` prints it) - as for any upgrade.
2. Install 4.0 (`pip install -U netcommander` or pull the checkout and `pip install -r requirements.txt`).
   Optional: `pip install 'netcommander[homelab]'` for ESXi/Hyper-V/Windows.
3. Start the app as usual. Nothing is migrated on start-up; the Homelab tab and `netcommander serve` create
   `homelab.db` on first use (schema version 1).
4. Optional: write `homelab.json` (see examples) and validate it: `netcommander homelab check-config`.

## Behaviour changes
* New **Homelab** tab in the desktop window (last tab).
* New RBAC permissions. Existing roles keep every permission they had. Operators additionally get *discover*
  and *run automation* (read-only scripts run immediately; change/destructive scripts need an admin's approval).
  Admins get all new permissions. Guests get the new ones except approving automation and managing integrations.
* `netcommander --help` lists two new commands: `serve` and `homelab`.
* Health scores ignore assets whose status is still unknown.

## Rolling back
Reinstall 3.3.0. It ignores the new files. If you later return to 4.0, the homelab data is still there.
A `homelab.db` written by a **newer** NetCommander is refused (never downgraded in place).

## Database migrations
`homelab.db` carries `PRAGMA user_version`. Future releases apply forward-only migrations inside one transaction
on first open; a failed migration rolls back and leaves the file untouched.
