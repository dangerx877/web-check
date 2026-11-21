# NetCommander Help

## First run: create your account

Registration in the sign-in window is only available for the **first** account on a computer (it becomes the administrator). Everyone else gets an account from an administrator (*Account & Security → Add User*) together with a temporary password and an authenticator key, and is asked to choose their own password at first sign-in.

1. Start the app. In the sign-in window enter your **email**, a **password** (10+ characters) and the same password under **Confirm password**.
2. Click **Register + Setup 2FA**. A setup key appears. Add it to an authenticator app (Google/Microsoft Authenticator, Authy, 1Password…) using "enter setup key manually". It is shown once, so save it somewhere safe.
3. Type the 6-digit code from the app and click **Sign In (MFA)**.

Your password also unlocks your private credential vault. **If you forget it, the vault cannot be opened**: an administrator can *Reset User* to get you signed in again, and you restore device passwords and backups with `netcommander vault-import` from a recovery file (*Account → Export Encrypted Vault Recovery File* - make one now). Without the recovery file you re-enter device passwords.

After 5 failed attempts the account locks for a short, growing delay. A code can only be used once.

## Guest mode (no sign-in)

Click **Continue as Guest** on the sign-in window to use the app without an account or 2FA. Guest mode is only offered while **no account exists** on this computer; after the first registration the button is switched off.

- Device passwords are kept in memory only and forgotten when you close the app, so you re-enter them each session.
- Nothing is saved to the vault.
- Config backups are saved as **plain text** (encrypted backups from a normal account can't be read in guest mode).
- Anyone who can open the app on this computer can use it, so use it only on a computer you trust.
- Your device list (`topology.json`) is still saved and loaded; it contains no passwords.

Administrators can turn guest mode off by setting the environment variable `NET_DISABLE_GUEST=1`.

## Adding devices

- **Manually:** fill the *Add Router / Switch / Firewall* box: hostname, IP (or `IP:port`), vendor type, optional peers (comma-separated), username and password. Passwords go straight into the encrypted vault.
- **CSV:** *Import CSV* (see `sample_inventory.csv`). Columns: `name, host, device_type, username, port, peers` (+ optional `key_file`); separate peers with `;`.
- **SSH keys:** add a `key_file` column to the CSV with the path to your private key; that device logs in with the key and no password is asked for.
- **JSON:** *Save JSON* / *Load JSON*; *Quick Save* writes `topology.json`, which loads automatically next start. Passwords are never saved in these files.

If no `topology.json` exists, a sample topology is shown. Remove those nodes and add yours.

## Running commands

Tab **Multi-Command & Config Runner**:

1. Choose **Scope**: *Selected Device* or *All Devices*.
2. Choose **Mode**: *Show / Exec* runs commands as typed; *Config Set* enters configuration mode and pushes the lines.
3. Type one command per line (`#` starts a comment) or use the **+ preset** buttons or **Load Script**.
4. Click **Run Batch** (or Ctrl+Enter).

You'll be asked to confirm config pushes and risky commands (reload, clear, delete…). Before every config push the app saves an encrypted backup of the device's running config (if that fails, nothing is pushed), saves another afterwards and prints the difference, so you can see exactly what changed.

With **Write/Save on Config** on, the config is saved afterwards. On Junos, IOS-XR and PAN-OS it is committed; with the box off, those changes are discarded rather than left pending.

If 3 devices in a batch reject the login, the rest are skipped to avoid locking out your account.

**Parallel** sets how many devices run at once (default 8).

## Auto-discovery and the map

**Auto-Discover Links** reads LLDP/CDP neighbors from every device and draws links with interface names. Neighbors not in your inventory are listed in the output as `[not in inventory]`. Click a node to select it; **Re-layout** reshuffles; **Export PNG** saves the picture.

Node colors: cyan = selected, green = healthy, amber = degraded, red = down, grey = unknown.

## Health monitor

**Start Health Monitor** probes every device's SSH port every 8 seconds (TCP connect time, SSH banner, jitter, loss over the last 20 probes). Set the warning thresholds on the *Advanced Health & Telemetry* tab. Alerts print in the output pane when a state changes. This tests reachability of the SSH port, not ICMP ping.

## Backups and diffs

**Backup Config** saves each device's running config, encrypted, to `backups/<device>/<device>_<timestamp>.cfg.enc` (readable only inside the app after sign-in). **Diff Last 2** compares the two newest backups, ignoring timestamp lines. **Backups** opens the folder. Because backups are encrypted with your vault key, losing your password means losing access to them.

## FAQ

**"Stored password cleared"?** A device rejected the login, so the saved password was removed. You'll be prompted next time.

**"Vault password does not match this vault"?** You signed in with a password different from the one that created that vault.

**Vendor not in the list?** Pick the closest Netmiko `device_type`; the generic profile uses Cisco-style commands.

**Upgrading from the original script?** Existing accounts and `vault.enc` are upgraded automatically on first successful sign-in. Your old `vault.enc` is copied into the new per-user `vaults/` folder and left in place.

**The Enterprise SSO button is gone?** It only opened a browser and never completed a sign-in, so it was removed rather than imply protection it didn't provide.

## Homelab (4.0)

The **Homelab** tab summarises the homelab platform (health, devices, VMs, containers, alerts, backups) and has
*Discover…*, *Collect & Check* and *Open Web Dashboard*. The web dashboard is the full interface for servers,
virtualization, containers, storage, IPAM/VLANs, monitoring, automation, backups and security. See
[homelab/MODULES.md](homelab/MODULES.md) and [homelab/DEPLOYMENT.md](homelab/DEPLOYMENT.md).
