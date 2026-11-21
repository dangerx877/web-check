# Homelab modules

Each section: what it does, where it lives, the permission it needs and what is verified.
Permissions: `viewer` = VIEW; `operator` = + DISCOVER, RUN_SHOW, RUN_AUTOMATION, EDIT_INVENTORY, BACKUP; `admin` = all.

## Dashboard (`platform.dashboard`, web *Dashboard*, desktop *Homelab* tab)
Infrastructure health score (0-100, weighted by asset importance; unknown/stopped assets excluded), device totals
by status and type, server/network/NAS group health, VM and container counts, storage used/total, active alerts,
backup status, recent events, top CPU, integration status. Refreshes every 30 s in the browser.

## Inventory (`models.py`, `inventory.py`)
One record type (`Asset`) for servers, desktops, laptops, routers, switches, firewalls, access points, NAS,
hypervisors, VMs, containers, Docker hosts, appliances, printers, IoT and services. Fields: hostname, IP, MAC,
OS, manufacturer/model, CPU model/cores/utilisation, memory, storage, interfaces, uptime, services, status,
tags, location, notes, parent (host) and typed links (`connected_to`, `runs_on`, `stores_on`, `depends_on`,
`backs_up_to`, `member_of`).
* Manual entries and CSV import (EDIT_INVENTORY). Fields you edit are **locked** against automatic overwrite
  (unlock to let discovery manage them again).
* Network devices from the classic inventory appear read-only with id `net-<name>`.
* Exports: CSV (formula-injection safe) and JSON.

## Discovery (`discovery.py`) - DISCOVER
TCP connect probes to configured ports (refused = alive, no root needed), SSH/HTTP banners, local ARP/NDP
table, OUI vendor lookup, reverse DNS, classification with a confidence label. Capped at `discovery.max_hosts`.
Results are merged: by MAC, then by IP (also onto hosts already reported by an integration; never onto VMs/containers).

## Servers (`servers.py`) - VIEW to read, DISCOVER to trigger collection
Linux over SSH (15 fixed read-only commands: `/proc` files, `df`, `ip -j addr`, `ps`, `systemctl`, DMI) and
Windows over WinRM (one fixed PowerShell/CIM script). Collected: hostname, OS, hardware, CPU % (two `/proc/stat`
samples), memory, disks, network counters (throughput is derived from counter rates), interfaces, running and
failed services, top processes, uptime. Connectivity test against SSH/WinRM/RDP/HTTPS ports.

## Virtualization (`virtualization/`) - VIEW; power actions CONTROL_WORKLOADS + confirmation
Common model (VM, host, snapshot, disk) and five adapters. Discovers VMs (and Proxmox LXC containers), status,
resources, configuration, virtual disks, snapshots, host resources and **allocation** (vCPU and RAM over-commit
ratios). Actions: start, shutdown (graceful), stop (hard), reboot.

## Containers (`containers.py`) - VIEW; logs RUN_SHOW; actions CONTROL_WORKLOADS + confirmation
Docker Engine API: hosts, containers, health (HEALTHCHECK), CPU/memory/network/block I/O, logs (redacted),
images, networks, volumes, Compose project status. Actions: start, stop, restart. Never removes anything.
Container environment variable values are masked in *inspect*.

## Storage (`storage/`) - VIEW; connectivity tests DISCOVER
Pools (state, RAID layout, capacity), disks (model, serial, temperature, SMART verdict, power-on hours,
reallocated/pending sectors), shares (SMB, NFS, iSCSI), capacity forecasting (least-squares growth, days until
80/90/100 %), SMB2 negotiate / NFS / iSCSI reachability checks (no login, nothing written).

## Network (`netmgmt.py`) - VIEW; edits EDIT_INVENTORY; diagnostics DISCOVER
IPAM (overlap-checked subnets, reservations, utilisation from the live inventory, duplicate-IP detection, next free
addresses), VLAN inventory, diagnostics (ping, traceroute, DNS, TCP) with strict target validation, and the unified
topology (network devices + LLDP/CDP links + homelab links + VM/container placement). The 3.x network tools
(command runner, config push with rollback, LLDP/CDP discovery, config backups, compliance) are unchanged.

## Monitoring (`monitoring.py`)
Checks: reachability (TCP-connect latency/jitter/loss), TCP port, HTTP(S) status/keyword/latency/certificate expiry.
13 default rules (device down, CPU, memory, disk, latency, loss, disk temperature, failed services, SMART, pool
health, container health, certificate expiry, backup overdue). Rules support warning/critical, above/below,
"for N samples", and scope (asset, type, tag). Alerts: raise after N breaches, resolve after 2 good samples,
acknowledge, notifications with de-duplication, event timeline, historical graphs (downsampled), 24 h utilisation report.
Thresholds: CHANGE_SETTINGS; checks: EDIT_INVENTORY; acknowledge: RUN_SHOW.

## Automation (`automation.py`)
Scripts (Python on the NetCommander host, SSH commands, PowerShell), 8 built-ins, parameters with validation,
declared risk + static risk scan, approvals by a second person bound to the script's SHA-256, execution history
with captured (redacted, size-capped) output, workflows, and expiring remediation policies.
Run: RUN_AUTOMATION; author: MANAGE_AUTOMATION; approve: APPROVE_AUTOMATION.

## Backups (`backups.py`)
Backup jobs for Proxmox vzdump, TrueNAS replication/cloud sync, files in a local or SSH directory, the built-in
network config backups, or manual records. Status (ok/stale/failed/unknown), verification (age, minimum size,
size drop, SHA-256 for local files), recovery points, "backup overdue" alerts, Markdown recovery runbook,
configuration bundle export (no secrets). Jobs: MANAGE_SCHEDULES; manual records: BACKUP.

## Security (`core/authz.py`, `api/sessions.py`, existing 3.x modules)
See [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md).

## Test suite
`python -m pytest` (2,240+ tests; the homelab adds ~140) runs without network, devices or display.
`tests/homelab_fixtures.py` simulates a homelab with the real adapters. Browser check:
`python tests/e2e/demo_server.py /tmp/nc-demo 8799` then `node tests/e2e/ui_smoke.cjs http://127.0.0.1:8799/ /tmp/nc-demo/demo-credentials.json /tmp/shots`
(needs Node + Playwright). Real Tk window: `xvfb-run -a python -m pytest -m display`.
