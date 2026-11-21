# Installing and deploying the homelab platform

## 1. Install

Same requirements as 3.x (Python 3.9+; Tk only for the desktop window). From a checkout:

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                           # or: pip install .
pip install '.[homelab]'                                  # optional: pyvmomi (ESXi) + pywinrm (Windows/Hyper-V)
```

No database server, web server or Node.js is needed: SQLite and the HTTP server are in the Python standard library
and the web UI is plain static files shipped in the package.

## 2. First run

1. Start the desktop app once (`python netcommander.py`) and create the first account (it becomes admin; scan the
   authenticator QR). Existing installations keep their accounts.
2. Optional: `uptimefunk homelab check-config` validates `homelab.json` (defaults apply when it is absent).
3. Start the platform:

```bash
uptimefunk serve --user you@example.com          # prompts for password + authenticator code
# → Uptime Funk homelab platform listening on http://127.0.0.1:8765/
```

Open the URL and sign in with e-mail, password and authenticator code. The desktop window's **Homelab** tab
can also start the web dashboard locally (*Open Web Dashboard*).

4. Add integrations (*Integrations*), run *Discovery* on your LAN, give servers management access, trust SSH
   host keys (*Security*), create subnets/VLANs (*Network*), add backup jobs (*Backups*).

## 3. Configuration (`<data-dir>/homelab.json`)

See [examples/homelab.json](examples/homelab.json). Every key is optional; unknown keys and wrong types are
errors (all reported at once). Secrets never go in this file - use `*_ref` names created in *Security → Secrets*
or via the API (`POST /api/secrets`).

| Section | Key settings |
|---|---|
| `monitoring` | `interval_seconds` (60), `collect_interval_seconds` (300), `retention_days` (30), `auto_checks` (true) |
| `discovery` | `max_hosts` (1024), `ports`, `timeout`, `workers`, `reverse_dns` |
| `api` | `bind` (127.0.0.1), `port` (8765), `tls_cert`/`tls_key`, `session_idle_minutes` (15), `session_max_hours` (8) |
| `automation` | `require_approval_for` (["change","destructive"]), `default_timeout`, `max_output_kb` |
| `notifications` | `dedup_minutes`, `channels` (`log`, `file`, `webhook` with `token_ref`, `email` with `password_ref`) |
| `plugins` | `enabled` (false), `allow` (entry-point names) |

## 4. Running as a service (Linux, systemd)

[examples/netcommander-homelab.service](examples/netcommander-homelab.service) runs
`uptimefunk serve --unattended` as a dedicated user, with the account password supplied through systemd
credentials (`LoadCredentialEncrypted=`), not a plain environment file. `--unattended` skips the authenticator
check at start-up - required for unattended restarts; protect the credential accordingly.

```bash
sudo useradd --system --create-home --home-dir /var/lib/netcommander netcommander
sudo -u netcommander python3 -m venv /opt/netcommander && sudo -u netcommander /opt/netcommander/bin/pip install 'uptime-funk[homelab]'
# create the account on that data dir (desktop app with --data-dir, or copy users_auth.json + vaults/)
echo -n 'account-password' | sudo systemd-creds encrypt --name=nc-password - /etc/credstore.encrypted/nc-password
sudo cp docs/homelab/examples/netcommander-homelab.service /etc/systemd/system/ && sudo systemctl enable --now netcommander-homelab
```

Windows: run `uptimefunk serve --user … --unattended` from Task Scheduler ("run whether user is logged on or not")
with `NETCOMMANDER_VAULT_PASSWORD` set only for that task, or keep it interactive.

## 5. Remote access

The API refuses non-loopback binds without TLS. Either:
* **Reverse proxy** (recommended): keep `bind: 127.0.0.1`, terminate TLS in nginx/Caddy/Traefik. See
  [examples/nginx.conf](examples/nginx.conf). Pass the original `Host` header (the CSRF origin check compares
  `Origin` with `Host`).
* **Direct TLS**: set `api.tls_cert` / `api.tls_key` and `api.bind` to the LAN address.

Never expose the dashboard to the internet without an additional layer (VPN, SSO proxy).

## 6. Headless operations (cron friendly)

```bash
uptimefunk homelab status  --user you@example.com            # exit 1 when critical alerts exist
uptimefunk homelab monitor --user you@example.com            # one collection + checks + backup evaluation
uptimefunk homelab discover --user you@example.com 192.168.1.0/24
uptimefunk homelab inventory --user you@example.com --format csv --output inventory.csv
uptimefunk homelab runbook --user you@example.com --output recovery.md
uptimefunk homelab export-config --user you@example.com --output nc-config.json
```

## 7. Scaling notes
* Single computer to a few hundred assets: defaults are fine (SQLite WAL, 16 workers).
* Larger: raise `monitoring.workers`, lengthen `collect_interval_seconds`, shorten `retention_days`.
* Remote sites: run one `uptimefunk serve` per site (agentless adapters reach only what the host can reach);
  a federated view is on the roadmap. Optional lightweight agents are not part of 4.0 - a Linux server needs only SSH.
