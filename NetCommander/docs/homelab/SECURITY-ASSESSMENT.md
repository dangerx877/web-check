# Security assessment - Uptime Funk 4.0 homelab platform

Scope: everything added in 4.0 (`netcommander/homelab`, `netcommander/ui/homelab.py`, CLI additions) and how it
interacts with the 3.x security core. Method: design review, threat modelling per entry point, and tests that
exercise the controls (all listed tests run in CI without devices).

## Assets and trust boundaries
* **Secrets**: integration tokens/passwords (SecretStore), server credentials (SecretStore refs), vault (3.x).
* **Control**: VM/container power, automation (remote command execution), IPAM/inventory edits.
* **Boundaries**: browser ↔ API server; Uptime Funk ↔ managed devices; Uptime Funk ↔ local OS (files, subprocess).

## Controls

| Requirement | Implementation | Evidence (tests) |
|---|---|---|
| Encrypted credential vault | Secrets encrypted with the vault DEK (Fernet); file 0600, atomic, locked; guest = memory only | `test_secret_store_*`, `test_integrations_store_secrets_encrypted_and_enforce_rbac` (secret absent from DB and secret file) |
| No plaintext secrets | Config/asset validators reject `password`/`token`/`secret` fields (must be `*_ref`); API never returns values | `test_asset_validation_lists_all_problems`, `test_settings_defaults_and_validation`, `test_reads_and_error_mapping` |
| SSH host-key verification | paramiko `RejectPolicy`; explicit audited trust with fingerprint comparison | `test_ssh_runner_rejects_unknown_host_keys` |
| TLS | Verified by default; CA file; SHA-256 pinning checked **before** sending credentials; mTLS for Docker; plain HTTP refused | `test_pinned_tls_rejects_wrong_certificate` (real TLS server), `test_http_client_refuses_plain_http_except_loopback`, `test_docker_connection_security` |
| RBAC / least privilege | 6 new permissions; read-only defaults; every platform method checks | `test_rbac_new_permissions_preserve_old_roles`, platform/API tests |
| Explicit authorization for changes | ActionGuard one-time tokens bound to user+action+target+params, 120 s TTL, single use | `test_action_guard_flow`, `test_vm_power_needs_permission_and_confirmation`, `test_rbac_and_confirmation_over_http` |
| MFA | Web sign-in = password + TOTP via AuthManager (lockout, replay protection) | `test_login_flow_*`, `test_login_replay_protection` |
| Session management | 256-bit ids, hashed at rest, idle 15 min, absolute 8 h, revocation, HttpOnly + SameSite=Strict (+Secure with TLS) | `test_session_manager_timeouts_and_revocation`, `test_login_flow_cookie_flags_and_logout` |
| CSRF | Per-session token header + same-origin check on every state change and on login | `test_csrf_and_origin_enforced`, `test_login_refuses_cross_origin` |
| Browser hardening | CSP without inline script/style, frame-ancestors none, nosniff, no-referrer, COOP, no-store | `test_static_assets_and_security_headers`, browser e2e (no CSP violations) |
| Secure communications | API binds 127.0.0.1; any other bind requires TLS (min TLS 1.2) unless explicitly overridden | `test_refuses_remote_bind_without_tls` |
| Command validation | Collector allowlists (exact + metachar-free prefixes); ids validated before use in paths/commands; Hyper-V by GUID only; no shell for local commands; parameter regexes; target validation for diagnostics | `test_command_policy_exact_and_prefix`, `test_storage_policy_blocks_injection`, `test_hyperv_adapter_and_injection_guard`, `test_local_runner_no_shell`, `test_parameter_validation_blocks_injection`, `test_diagnostics_validation_and_parsing` |
| Remote execution approval | Risk declaration + static scan; second-person approval bound to SHA-256; edits invalidate approval | `test_change_requires_second_person_and_is_bound_to_content`, `test_script_validation` |
| No automatic destructive remediation | Only via expiring admin policies; destructive needs `allow_destructive`; cooldown; audited | `test_remediation_policy` |
| Audit logging | All homelab actions + denials + web sign-in/out into the 3.x hash-chained log | platform/API tests assert audit entries |
| Redaction | Secrets masked in logs, outputs, events, errors, container env/logs, exports | `test_redaction`, `test_read_only_runs_immediately_and_redacts`, `test_config_bundle_has_no_secrets` |
| Path traversal | Static files resolved and contained; backup paths validated | `test_static_assets_and_security_headers`, `test_backup_job_validation` |
| DoS limits | Request body 5 MB; discovery host cap; output caps; timeouts everywhere; bounded pools | unit tests per module |

## Residual risks (accepted / to address)

1. **The service account holds every integration secret.** `uptimefunk serve` unlocks one account's vault;
   any web user with the right permission causes actions with those credentials (authorised and audited per user).
   Mitigate with least-privilege device accounts (see INTEGRATIONS.md).
2. **Python automation scripts run on the Uptime Funk host** as the service user. They are approved and
   isolated (separate interpreter, scrubbed environment, temp dir, timeout) but this is **not a sandbox**.
3. **Risk scan is heuristic.** It catches obvious mismatches; the second-person approval is the real control.
4. **Docker socket access is root-equivalent** on the Docker host.
5. **Network devices (3.x) still default to Netmiko's host-key auto-accept** unless strict mode is enabled.
6. **Single-process session store**: sessions are lost on restart (users sign in again); not shared across replicas.
7. **SQLite file permissions on Windows** follow the profile folder ACLs (0600 has no effect).
8. **Adapters not yet validated against live hardware** in CI (see INTEGRATIONS.md verification status).
9. **No WebAuthn/SSO yet**; TOTP is the second factor. Put the API behind your SSO proxy if you need more.

## Recommendations for deployment
Keep the API on 127.0.0.1 behind a TLS reverse proxy (or give it a certificate), enable *Strict SSH host keys*,
ship the audit log off-box (`NETCOMMANDER_AUDIT_SYSLOG=tcp://…`), use dedicated read-only device accounts, keep
`automation.require_approval_for` at its default, and back up `vaults/` + a vault recovery file offline.
