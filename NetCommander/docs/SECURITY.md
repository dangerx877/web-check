# Security Notes

## How data is protected

| Item | Protection |
|---|---|
| Account password | PBKDF2-SHA256, 600,000 iterations, random salt; never stored |
| Authenticator secret | Encrypted (Fernet) with a key derived from your password |
| Device passwords / enable secrets | Encrypted (Fernet/AES) in a per-user vault in `vaults/` |
| Login attempts | 5 failures → increasing lockout (30 s up to 15 min), shared by the GUI and the CLI |
| 2FA codes | Single use (replay blocked), ±30 s clock tolerance |
| Data files | Written atomically, owner-only permissions where the OS supports it |
| Config backups | Encrypted with your vault key (`.cfg.enc`); device names are sanitized so they cannot write outside `backups/` |

## Failure behaviour

- If the accounts file cannot be written, sign-in is **refused** (fail closed) and in-memory lockout/replay state is rolled back so it never disagrees with disk.
- Vault and account files are written atomically (unique temp file, fsync, rename).
- The authenticator setup key is hidden in the registration window until you press Reveal/Copy; Reveal auto-hides after 30 s and a copied key is cleared from the clipboard after 60 s.
- The vault is deliberately not re-keyed when you sign in: encrypted `.cfg.enc` backups are tied to its key.

## Guest mode

Guest mode skips authentication entirely: no password, no 2FA, no vault. Credentials live in memory only; backups are plain text. It is offered **only while no account exists** on the installation (first-run / single-user use). Once an account exists the option is switched off, and any guest session gets viewer rights, so it cannot be used to bypass roles. Set `NET_DISABLE_GUEST=1` to remove it even on a fresh install.

## Accounts and roles

- Only the **first** account is self-registered (and becomes admin). Later accounts are created by an admin, start with a temporary password the user is prompted to replace, and cannot be created by operators or viewers - the check is in `AuthManager.create_account`, not only in the window.
- Operators may run only commands on a per-platform **read-only allowlist** (see [ENTERPRISE.md](ENTERPRISE.md)); anything else, including CLI abbreviations, needs push rights.
- A transient read error on `users_auth.json` (e.g. a Windows sharing violation) is **not** treated as corruption: the file is left in place and sign-in/registration are refused until it can be read, so nobody can become the "first" admin by accident. Only a file that cannot be parsed is moved aside to `users_auth.corrupt-*`.
- Roles live in a local file: anyone who can edit `users_auth.json` directly can change them. Restrict write access to the data folder.

## Limits to be aware of

- Anyone who has your password **and** your authenticator can open your vault.
- Passwords are decrypted in memory while connecting to devices.
- Backups are encrypted, but only with your vault key: if you lose your password you lose the backups too. Older plain `.cfg` backups and `topology.json` (hostnames/IPs, no passwords) are **not** encrypted.
- By default SSH host keys are accepted automatically (Netmiko default). Tick **Strict SSH host keys** (or set `NET_SSH_STRICT_HOSTKEYS=1`) to require devices already in `~/.ssh/known_hosts`.
- This tool does not replace central AAA (TACACS+/RADIUS) or a PAM/secret manager in large environments.
- Never commit `users_auth.json`, `vaults/`, `backups/` or `topology.json` (see `.gitignore`).

## Reporting a problem

Open an issue with the steps to reproduce. Do not include real passwords, setup keys or configs.

## Added in 3.1

- **Vault v3:** a random data key encrypts entries and `.cfg.enc` backups; your password only wraps that key. Changing the password re-wraps it, so backups stay readable. Losing the password *and* the recovery file means the vault and its backups are unrecoverable: export a recovery file (*Account → Export Encrypted Vault Recovery File*) and keep it offline.
- **Recovery codes** are stored only as salted hashes, are single use, and still require the account password.
- **Account enumeration:** unknown accounts and wrong passwords return the same message after the same key-derivation work.
- **Audit log, RBAC and approvals** are described in [ENTERPRISE.md](ENTERPRISE.md).
- **Windows file permissions:** `chmod 0600` has no effect on Windows; files inherit the permissions of your user profile folder, so keep the data folder inside your profile and use full-disk encryption.
- `NETCOMMANDER_VAULT_PASSWORD` (headless) is readable by any process of the same OS user; prefer the interactive prompt where possible.

## Added in 3.3

- Headless commands use the sign-in lockout; `vault-export` / `vault-import` additionally require an authenticator or recovery code.
- The audit log has an anchor file (`audit.jsonl.head`) so truncation is detected, not only edits.
- Automatic rollback: IOS-XR's `commit confirmed` timer is sent in seconds (it was sent in minutes); verify commands run as operational commands from config mode (`run` / `do`); a failure while applying discards the uncommitted candidate instead of running `rollback 1`, which could have undone an older change.

## Added in 4.0 (homelab platform)

- Integration and server secrets are encrypted with your vault key (`homelab_secrets.json`); configuration,
  inventory and the API only ever contain references.
- New SSH connections (servers, NAS, hypervisors) **reject unknown host keys**; trust is explicit and audited.
- HTTPS APIs are verified by default (CA file or certificate pin for self-signed devices); plain HTTP refused.
- Power, container and other change actions need the permission **and** a one-time confirmation.
- Remote scripts that change things need approval by a second person; approval is tied to the exact script.
- The web dashboard uses password + authenticator sign-in, short sessions, CSRF protection and a strict CSP, and
  listens on 127.0.0.1 unless TLS is configured.
- Full assessment, including residual risks: [homelab/SECURITY-ASSESSMENT.md](homelab/SECURITY-ASSESSMENT.md).
