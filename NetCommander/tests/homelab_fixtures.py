"""A small simulated homelab (real adapters over fake transports) shared by platform/API/UI tests."""
from __future__ import annotations

import pyotp
from conftest import FAST_KDF
from test_homelab_containers_storage import TRUENAS, docker_api
from test_homelab_servers_virt import PVE, Api, linux_runner

from netcommander.config import Paths
from netcommander.homelab.containers import DockerAdapter
from netcommander.homelab.core.runners import FakeRunner
from netcommander.homelab.discovery import DiscoveryEngine
from netcommander.homelab.platform import Ctx, HomelabPlatform
from netcommander.homelab.storage.truenas import TrueNasAdapter
from netcommander.homelab.virtualization.proxmox import ProxmoxAdapter
from netcommander.rbac import Role
from netcommander.security import AuthManager, CredentialVault
from netcommander.store import make_device

ADMIN, OPER, VIEWER = Ctx("admin@example.com", Role.ADMIN), Ctx("op@example.com", Role.OPERATOR), Ctx("viewer@example.com", Role.VIEWER)
PW = "correct-horse-1"


def build_platform(tmp_path, config=None):
    paths = Paths.for_root(tmp_path)
    vault = CredentialVault(tmp_path / "v.enc", iterations=FAST_KDF)
    assert vault.unlock_or_init(PW, path=tmp_path / "v.enc")
    pve_api, tn_api = Api(dict(PVE)), Api(dict(TRUENAS))
    dk_api, dk_call = docker_api()
    seen_secrets = {}

    def factory(rec):
        cfg = rec["config"]
        if rec["kind"] == "proxmox":
            seen_secrets["proxmox"] = platform.secrets.get(cfg["token_ref"])
            return ProxmoxAdapter(cfg["url"], cfg["token_id"], seen_secrets["proxmox"], transport=pve_api)
        if rec["kind"] == "docker":
            return DockerAdapter(cfg["url"], transport=dk_call)
        if rec["kind"] == "truenas":
            return TrueNasAdapter(cfg["url"], platform.secrets.get(cfg["api_key_ref"]), transport=tn_api)
        raise AssertionError(rec)

    world = {("10.0.0.1", 22): "open", ("10.0.0.1", 8006): "open", ("10.0.0.20", 445): "open", ("10.0.0.20", 2049): "open",
             ("10.0.0.20", 3260): "open", ("10.0.0.5", 22): "open"}

    def probe(h, p, t):
        return world.get((h, p), "filtered")

    def disc(cfg):
        return DiscoveryEngine([22, 445, 2049, 3260, 8006], probe=probe, banner=lambda h, p, t: "",
                               neighbors=lambda: {"10.0.0.20": "00:11:32:aa:bb:cc"}, resolver=lambda ip: "")

    devices = {"core-sw": make_device({"host": "10.0.0.2", "device_type": "cisco_ios"})}
    platform = HomelabPlatform(paths, vault, device_source=lambda: devices, config=config or {}, adapter_factory=factory,
                               probe=probe, runner_factory=lambda asset, kind, ro: linux_runner() if ro else FakeRunner({"*": "ok"}),
                               discovery_factory=disc)
    platform.test_apis = {"pve": pve_api, "truenas": tn_api, "docker": dk_api}
    platform.seen_secrets = seen_secrets
    return platform


def populate(platform):
    p = platform
    p.add_integration(ADMIN, "hypervisor", "proxmox", "pve", {"url": "https://pve1:8006", "token_id": "mon@pve!nc"},
                      {"token": "pve-token-value"}, iid="pve")
    p.add_integration(ADMIN, "docker", "docker", "dock1", {"url": "unix:///var/run/docker.sock"}, iid="dock")
    p.add_integration(ADMIN, "storage", "truenas", "truenas", {"url": "https://10.0.0.10"}, {"api_key": "tn-key-value"}, iid="tn")
    for iid in ("pve", "dock", "tn"):
        p.poll_integration(iid)
    return p


def make_auth(tmp_path):
    auth = AuthManager(tmp_path / "users_auth.json", iterations=FAST_KDF)
    admin_secret, _ = auth.create_account("admin@example.com", PW)
    op_secret, _ = auth.create_account("op@example.com", "temporary-pw-1", "operator", created_by="admin@example.com")
    auth.set_password("op@example.com", "temporary-pw-1", PW)
    return auth, {"admin@example.com": admin_secret, "op@example.com": op_secret}


def otp(secret, offset=0):
    import time
    return pyotp.TOTP(secret).generate_otp(int(time.time() // 30) + offset)
