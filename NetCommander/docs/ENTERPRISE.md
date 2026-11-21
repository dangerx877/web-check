# Enterprise features

Everything here is also reachable without the GUI (see "Headless" below). Defaults are conservative: nothing runs unattended unless you schedule it, and nothing is pushed without the confirmations you already know.

## Roles

| Permission | viewer | operator | admin | guest¹ |
|---|:-:|:-:|:-:|:-:|
| View inventory, topology, health, compliance | ✔ | ✔ | ✔ | ✔ |
| Run **read-only** commands², back up configs, edit inventory, request deployments | | ✔ | ✔ | ✔ |
| Push config, or run any command not on the read-only list | | | ✔ | ✔ |
| Approve deployments, manage users, export vault, add/remove/pause schedules, change settings | | | ✔ | |

¹ Guest exists only on an installation **with no accounts** (the original single-user workflow). As soon as the first account is registered, *Continue as Guest* is switched off; a guest session that is somehow opened anyway (e.g. by an older build) gets **viewer** rights, so guest mode can never be used to get around roles. `NET_DISABLE_GUEST=1` switches it off even on a fresh install.

² "Read-only" is an **allowlist** per platform (`netcommander/cmdpolicy.py`): `show`/`sh` (`display` on Huawei/Comware, `get`/`show` on FortiOS, `/… print` on RouterOS), `ping`, `traceroute` and terminal paging, optionally filtered with pipes such as `| include`. Output may never be sent anywhere (`| redirect`, `| tee`, `| append`, `| save`, `>` are refused). On Linux devices only a small set of inspection commands is allowed, with no shell metacharacters. Everything else - including abbreviations such as `confi t`, `relo` or `wr er` - needs push rights. Denials are audited (`deny.push_config`).

**Accounts.** The first account registered on a machine bootstraps it and is **admin**. After that, the sign-in window no longer offers registration: an admin creates accounts in *Account & Security → Add User* (role viewer/operator/admin, a temporary password, and an authenticator key to hand over). The new user is asked to change the temporary password at first sign-in. *Reset User* handles a forgotten password or lost phone: a new temporary password and authenticator key, recovery codes dropped, lockout cleared. The user's old vault only opens with the old password, so it is renamed to `<id>.enc.before-reset-<time>` (never deleted); restore credentials and backups with `netcommander vault-import` from a recovery file. Accounts created before 3.1 keep admin. An admin can change roles in *Account → Manage Users & Roles* (the last admin cannot be demoted).

**Trust boundary.** Roles, approvals and the deployment digest live in local files (`users_auth.json`, `deployments.json`). They stop *cooperating users of the app*; they cannot stop someone who can edit those files directly with an editor (the digest is a plain SHA-256, not a signature, because any key would sit on the same disk). Keep the data folder writable only by the people who are allowed to administer NetCommander, and use the off-box audit copy below to detect after-the-fact edits.

## Audit log

`audit.jsonl` records sign-in sessions, commands run, config pushes, backups, approvals, denied actions, user creation, schedule/monitor changes and host-key trust decisions. Each line carries the hash of the previous one; `netcommander audit-verify` (or *Audit Log → Verify Chain*) reports the first line that was edited, removed or reordered. A small anchor file, `audit.jsonl.head`, holds the entry count and latest hash, so entries **cut off the end** of the log, a deleted log, or a log replaced by a different chain are reported too. Secrets are redacted before writing. Set `NETCOMMANDER_AUDIT_COPY=/path/file.jsonl` and/or `NETCOMMANDER_AUDIT_SYSLOG=host:514` (or `tcp://host:6514`) to also send every entry off the machine. Failed sign-ins and failed CLI unlocks are logged too. It is tamper-**evident**: someone who can rewrite the whole file can rewrite the whole chain, so copy it to write-once storage or syslog if you need more.

## Staged deployments and approvals

1. Put the commands in the Runner script box, choose the scope, open **Deployments → New from Runner**. Choose canary count, batch size, approvals needed, rollback and an optional verify command.
2. The requester **Submits**; a *different* admin **Approves** (or Rejects) after seeing the commands. Approval is bound to the exact commands, stages and safety options - any edit voids it.
3. An admin **Executes**. Stages run in order; a failed stage halts the rollout and later stages are marked *skipped*. A rollout interrupted by closing the app is marked *halted*, never silently resumed.

## Automatic rollback

When enabled on a plan, changes are applied with a **device-side timer** so they revert even if the change cuts off management access:

| Platform | Mechanism | Needs |
|---|---|---|
| Junos, IOS-XR | `commit confirmed N`, then `commit` after the checks pass | - |
| IOS, IOS-XE | `configure terminal revert timer N`, then `configure confirm` | Configuration Replace/Rollback (an `archive` path) enabled |

If a verify command fails (or the session is lost) the change is not confirmed and an explicit revert is attempted. Other platforms are **refused** when rollback is on. **These command sequences follow vendor documentation and are tested against simulated connections only - validate them on a lab device of each platform before relying on them.**

## Scheduled backups

*Schedules → Add Schedule* (interval or daily at HH:MM). They run while NetCommander is open. For unattended 24/7 backups run the CLI under your service manager:

```bash
# password via a prompt, or the NETCOMMANDER_VAULT_PASSWORD environment variable (visible to the same OS user)
netcommander schedule-run --user you@example.com            # foreground loop
netcommander backup --user you@example.com --keep 30        # one-shot, e.g. from cron / Task Scheduler / launchd
```

Each run reports *changed* devices (config drift) and prunes to the retention you chose.

## Compliance

`compliance_policy.json` (created with a sample on first use) is a list of rules:

```json
[{"id": "ntp", "type": "must_contain", "pattern": "^ntp server", "severity": "high", "device_types": ["cisco_ios"]},
 {"id": "no-http", "type": "must_not_contain", "pattern": "^ip http server"},
 {"id": "syslog", "type": "must_match_count", "pattern": "^logging host", "min": 1, "max": 2}]
```

Checks run against each device's **latest saved backup** (no device contact), so back up first - or add `--live` (GUI: *Run Check (live)*) to fetch running configs over SSH. `netcommander compliance --user ... --csv report.csv` exits 1 when anything fails (handy for CI/monitoring).

## Templates

`hostname {{name}}` / `ntp server {{ntp}}` / `interface {{uplink|GigabitEthernet0/1}}`. Built-in variables: `name ip device_type port username`. Add JSON variables: `{"global": {"ntp": "10.0.0.1"}, "devices": {"R1": {"site": "HQ"}}}`. Missing variables are reported for every device before anything is sent.

## Monitoring

* **SNMPv3 only** (authPriv/authNoPriv; SHA/SHA-2, AES). v1/v2c community strings are intentionally not supported. Requires `pip install pysnmp` (the `snmp` extra).
* **REST**: GET a JSON endpoint, pull numbers by dotted path (`data.cpu.0.usage`); none/basic/bearer auth; TLS verification on unless you turn it off per monitor.
* Secrets are encrypted with your vault; guest sessions refuse to save them. Counter metrics also get a `_rate` (per second, wrap-aware).
* Not verified against real SNMP agents or REST devices in development - see the lab checklist below.

## Headless

`backup`, `compliance`, `vault-export`, `vault-import`, `schedule-run`, `audit-verify`, `data-dir`. Exit codes: 0 ok, 1 completed with failures, 2 usage/config error, 3 authentication/permission.

* The account password (prompt, or `NETCOMMANDER_VAULT_PASSWORD`) is checked with the **same lockout** as the sign-in window: failed CLI attempts count, and a locked account is refused. A successful password-only check does not reset the counter.
* `backup`, `compliance` and `schedule-run` need only the password so they can run unattended.
* `vault-export` and `vault-import` hand out or replace every stored credential, so they also need an **authenticator or recovery code** (prompt, or `NETCOMMANDER_OTP`).
* `vault-import` protects the restored vault with the **account password**, so the app opens it at the next sign-in.

## Lab checklist (things automated tests cannot prove)

- Rollback: apply a deliberately bad change on a lab IOS-XE / Junos / IOS-XR box and confirm it reverts, with and without losing the session.
- SNMPv3: poll `sysUpTime` and an interface counter from a real agent; check pysnmp version compatibility.
- REST: confirm your JSON paths against the real API.
- Host-key trust: connect to a device with strict mode on, compare the shown fingerprint with the device's.
- GUI: open the app on each OS you use (the real-window test runs only where a display exists).

## Several processes at once

The GUI and a headless `schedule-run` (or two app windows) may run together: the accounts file, schedules, deployments and audit log are protected by advisory locks and every change starts from the file's current contents. A due schedule runs once; a schedule deleted or paused in one process is never run or resurrected by another; a role change, lockout counter or used 2FA code recorded by one process is never overwritten by another; and a deployment can only be executed by one process. The locks protect cooperating NetCommander processes only (not other programs editing the files) and lock files (`*.lock`) sit beside the data.
