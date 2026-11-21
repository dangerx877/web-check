# Integrations

Add integrations in the web UI (*Integrations → Add integration*) or the CLI:

```bash
netcommander homelab adapters                       # list adapters and their fields
netcommander homelab add-integration --user you@example.com --category hypervisor --kind proxmox \
    --name pve --set url=https://pve.lan:8006 --set token_id='monitor@pve!netcommander' --secret token
```

Secrets are prompted for (or read from `NETCOMMANDER_SECRET_<FIELD>`), encrypted with your vault key and never
returned by the API. Every adapter is **read-only** except the explicit, confirmed power/container actions.

## Verification status - read this

All adapters are tested in this release against **simulated devices**: HTTP payloads and command output shaped
after the vendors' documentation and typical real output (see `tests/test_homelab_*`). They have **not** been run
against live hardware in this release's CI. "beta" marks adapters whose vendor API is undocumented or that need
optional libraries. Before relying on an adapter, run the lab checklist at the end of this page.

| Adapter | API used | Maturity | Least-privilege setup |
|---|---|---|---|
| Proxmox VE | REST `/api2/json` + API token | stable | Token with **PVEAuditor** on `/`; add **PVEVMUser** only for power actions. Privilege separation on. |
| VMware ESXi / vCenter | vSphere API via pyVmomi (`pip install 'netcommander[vmware]'`) | beta | Read-only role; *VirtualMachine.Interaction.PowerOn/PowerOff/Reset* for actions. |
| Microsoft Hyper-V | Hyper-V PowerShell module over WinRM HTTPS (`pip install 'netcommander[windows]'`) | beta | Member of *Hyper-V Administrators* (Hyper-V has no read-only role); WinRM HTTPS listener with a trusted certificate. |
| VirtualBox | `VBoxManage` locally or over SSH | stable | The user that owns the VMs (VirtualBox VMs are per user). |
| KVM / libvirt | `virsh` locally or over SSH | stable | Member of the `libvirt` group (read + power). Use `qemu:///system`. |
| Docker Engine | Engine API over `unix:///var/run/docker.sock` or `tcp://host:2376` with mutual TLS | stable | Socket access is root-equivalent: run NetCommander on the host, or expose the daemon with TLS client certificates. `tcp://…:2375` is refused unless explicitly allowed. |
| TrueNAS SCALE/CORE | REST v2.0 with API key | stable | API key for a dedicated read-only user (24.10+). REST is deprecated from 25.04 in favour of JSON-RPC; still functional. |
| Synology DSM | DSM Web API (`SYNO.API.Auth`, `SYNO.Storage.CGI.Storage`, `SYNO.Core.Share`) | beta | Dedicated non-admin account **without** 2FA (unattended polling). Storage API fields are not publicly documented. |
| UGREEN NAS | SSH + standard Linux tools (`lsblk`, `mdstat`, `df`, `smartctl`, `testparm`) | beta | UGREEN publishes no management API. Enable SSH in UGOS, use a dedicated account; allow `sudo -n smartctl` for SMART. |
| QNAP NAS | SSH + standard Linux tools | beta | No public stable API; enable SSH (admin group required by QTS). |
| Generic Linux storage | SSH + standard Linux tools (+ ZFS `zpool`) | stable | Read-only user; `smartctl` needs root (`use_sudo` + NOPASSWD rule for smartctl only). |

### Servers (not integrations)
Open the server in *Inventory → Management…* and give SSH (Linux) or WinRM (Windows) access. The account needs
no special rights for the read-only collector on Linux; on Windows, membership of *Remote Management Users* and
read access to CIM (or local admin).

### SSH host keys
NetCommander never auto-accepts host keys for servers, NAS or hypervisors. Trust a host once:
*Security → SSH host keys* (compare the fingerprint with the one on the device console) or
`netcommander homelab trust-host --user you@example.com 10.0.0.5`.

### TLS for HTTPS APIs
Default: full certificate validation. For self-signed devices use `ca_file` (trust the device's CA/certificate)
or `pin_sha256` (exactly one certificate; checked before any credential is sent). `verify_tls=false` works but is
shown as "not verified" in the UI and recorded in the audit log.

## Writing a new adapter
1. Implement the protocol for its category (`HypervisorAdapter` in `virtualization/base.py`, `report()` for
   storage, the `DockerAdapter` surface for containers). Use `HttpClient` or a `Runner` - never raw sockets,
   `requests` or `subprocess(shell=True)`.
2. Keep parsing in pure functions and test them with captured output.
3. Register an `AdapterSpec` (fields; mark secrets `secret=True`) in `adapters.py`, or ship it as a plugin:
   entry point group `netcommander.adapters`, a callable receiving the `Registry`. Plugins load only when listed in
   `homelab.json` → `plugins.allow` with `plugins.enabled: true`.

## Lab checklist (per adapter, before production use)
1. Add the integration with a least-privilege account; *Poll now* succeeds; the inventory shows hosts and workloads.
2. Compare 3 values (CPU, memory, a disk/pool size) with the vendor UI.
3. Disconnect the device: the integration turns red, the host goes *offline*, a *Device down* alert fires.
4. Power actions (if used): stop a test VM/container → confirmation dialog → action → audit entry.
5. Revoke the credential on the device: polling fails with an authentication error, no lockout loop.
