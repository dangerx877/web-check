"""Built-in adapter registrations. Each entry declares its configuration fields (secrets separately)
so the CLI, API and web UI can build forms and validate input without knowing the adapter."""
from __future__ import annotations

from typing import Any

from .core.registry import AdapterSpec, FieldSpec, Registry
from .core.runners import CommandPolicy, LocalRunner, Runner, SshRunner, SshTarget, WinRmRunner, WinRmTarget

F = FieldSpec
TLS = (F("verify_tls", "Verify TLS certificate", kind="bool", default=True),
       F("ca_file", "CA certificate file", help="PEM file to trust for a self-signed device"),
       F("pin_sha256", "Certificate SHA-256 pin", help="Accept exactly this certificate (hex fingerprint)"))
SSH = (F("host", "Host", required=True, help="'local' runs on the NetCommander machine"),
       F("port", "SSH port", kind="int", default=22), F("username", "Username", default="root"),
       F("password", "Password", secret=True), F("key_file", "Private key file"))


def ssh_runner(host: str, port: int = 22, username: str = "root", password: str = "", key_file: str = "",
               policy: CommandPolicy | None = None) -> Runner:
    if host in ("local", "localhost") and not password and not key_file:
        return LocalRunner(policy)
    return SshRunner(SshTarget(host, int(port), username, password, key_file), policy)


def _proxmox(**kw: Any) -> Any:
    from .virtualization.proxmox import ProxmoxAdapter
    return ProxmoxAdapter(**kw)


def _esxi(**kw: Any) -> Any:
    from .virtualization.esxi import EsxiAdapter
    return EsxiAdapter(**kw)


def _hyperv(host: str, username: str, password: str = "", port: int = 5986, transport: str = "ntlm",
            https: bool = True, ca_file: str = "") -> Any:
    from .virtualization.hyperv import HyperVAdapter
    return HyperVAdapter(WinRmRunner(WinRmTarget(host, username, password, port, transport, https, ca_file)), host)


def _vbox(host: str, port: int = 22, username: str = "root", password: str = "", key_file: str = "",
          vboxmanage: str = "VBoxManage") -> Any:
    from .virtualization.virtualbox import VirtualBoxAdapter
    return VirtualBoxAdapter(ssh_runner(host, port, username, password, key_file), host, vboxmanage)


def _libvirt(host: str, port: int = 22, username: str = "root", password: str = "", key_file: str = "",
             uri: str = "qemu:///system") -> Any:
    from .virtualization.libvirt import LibvirtAdapter
    return LibvirtAdapter(ssh_runner(host, port, username, password, key_file), host, uri)


def _docker(**kw: Any) -> Any:
    from .containers import DockerAdapter
    return DockerAdapter(**kw)


def _truenas(**kw: Any) -> Any:
    from .storage.truenas import TrueNasAdapter
    return TrueNasAdapter(**kw)


def _synology(**kw: Any) -> Any:
    from .storage.synology import SynologyAdapter
    return SynologyAdapter(**kw)


def _linux_storage(cls_name: str) -> Any:
    def make(host: str, port: int = 22, username: str = "root", password: str = "", key_file: str = "",
             use_sudo: bool = False, smart: bool = True) -> Any:
        from .storage import linux
        cls = getattr(linux, cls_name)
        runner = ssh_runner(host, port, username, password, key_file, linux.STORAGE_POLICY)
        return cls(runner, use_sudo=use_sudo, smart=smart)
    return make


def builtin_registry() -> Registry:
    r = Registry()
    hv = frozenset({"inventory", "metrics", "power", "snapshots", "config"})
    r.register(AdapterSpec("hypervisor", "proxmox", "Proxmox VE", _proxmox, (
        F("url", "API URL", required=True, help="https://pve.lan:8006"),
        F("token_id", "API token id", required=True, help="user@realm!tokenname"),
        F("token", "API token secret", secret=True, required=True)) + TLS, hv | {"backups"}))
    r.register(AdapterSpec("hypervisor", "esxi", "VMware ESXi / vCenter", _esxi, (
        F("host", "Host", required=True), F("username", "Username", required=True), F("password", "Password", secret=True),
        F("port", "Port", kind="int", default=443), TLS[0], TLS[1]), hv, "beta",
        "Needs the optional pyvmomi package."))
    r.register(AdapterSpec("hypervisor", "hyperv", "Microsoft Hyper-V", _hyperv, (
        F("host", "Host", required=True), F("username", "Username", required=True), F("password", "Password", secret=True),
        F("port", "WinRM port", kind="int", default=5986), F("transport", "WinRM transport", default="ntlm"),
        F("https", "Use HTTPS", kind="bool", default=True), F("ca_file", "CA certificate file")), hv, "beta",
        "PowerShell remoting; needs the optional pywinrm package."))
    r.register(AdapterSpec("hypervisor", "virtualbox", "Oracle VirtualBox", _vbox,
                           SSH + (F("vboxmanage", "VBoxManage path", default="VBoxManage"),), hv))
    r.register(AdapterSpec("hypervisor", "libvirt", "KVM / libvirt", _libvirt,
                           SSH + (F("uri", "libvirt URI", default="qemu:///system"),), hv))
    r.register(AdapterSpec("docker", "docker", "Docker Engine", _docker, (
        F("url", "Docker URL", required=True, default="unix:///var/run/docker.sock",
          help="unix:///var/run/docker.sock or tcp://host:2376 (TLS)"),
        F("ca_file", "CA file"), F("client_cert", "Client certificate"), F("client_key", "Client key"),
        F("allow_insecure_tcp", "Allow unauthenticated TCP (2375)", kind="bool", default=False)),
        frozenset({"inventory", "metrics", "logs", "control", "compose"})))
    st = frozenset({"pools", "disks", "smart", "shares"})
    r.register(AdapterSpec("storage", "truenas", "TrueNAS", _truenas, (
        F("url", "URL", required=True), F("api_key", "API key", secret=True, required=True)) + TLS, st | {"backups"}))
    r.register(AdapterSpec("storage", "synology", "Synology DSM", _synology, (
        F("url", "URL", required=True, help="https://nas.lan:5001"), F("username", "Username", required=True),
        F("password", "Password", secret=True, required=True)) + TLS, st, "beta"))
    extra = (F("use_sudo", "Use sudo -n for smartctl", kind="bool", default=False),
             F("smart", "Read SMART data", kind="bool", default=True))
    r.register(AdapterSpec("storage", "ugreen", "UGREEN NAS (SSH)", _linux_storage("UgreenAdapter"), SSH + extra, st, "beta",
                           "UGREEN publishes no management API; NetCommander uses SSH and standard Linux tools."))
    r.register(AdapterSpec("storage", "qnap", "QNAP NAS (SSH)", _linux_storage("QnapAdapter"), SSH + extra, st, "beta",
                           "Uses SSH and standard Linux tools (QTS/QuTS hero)."))
    r.register(AdapterSpec("storage", "linux", "Linux storage server (SSH)", _linux_storage("LinuxStorageAdapter"),
                           SSH + extra, st))
    return r
