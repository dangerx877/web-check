"""Builds the REAL window with real customtkinter/Tk. Skipped unless a display and customtkinter exist.

Run locally with a desktop session, or in CI:  xvfb-run -a python -m pytest -m display
"""
from __future__ import annotations

import os
import sys

import pytest

pytestmark = pytest.mark.display
ctk = pytest.importorskip("customtkinter")
pytest.importorskip("matplotlib")
pytest.importorskip("networkx")

if sys.platform.startswith("linux") and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
    pytest.skip("no display available (use xvfb-run)", allow_module_level=True)


def test_real_window_builds_all_tabs_and_closes(tmp_path):
    from netcommander.config import Paths, RuntimeSettings
    from netcommander.security import CredentialVault
    from netcommander.ui.app import NetworkManagerApp

    vault = CredentialVault(tmp_path / "v.enc")
    vault.unlock_ephemeral()
    try:
        app = NetworkManagerApp("guest", vault, settings=RuntimeSettings(env={}), paths=Paths.for_root(tmp_path))
    except Exception as exc:                                      # e.g. Tk cannot open the display
        if "display" in str(exc).lower():
            pytest.skip(str(exc))
        raise
    try:
        app.update_idletasks()
        app.update()
        assert app.services.role.value == "guest" and len(app.store) >= 1
        for panel in ("monitor_panel", "compliance_panel", "templates_panel", "deploy_panel", "schedules_panel", "audit_panel",
                      "homelab_panel"):
            assert getattr(app, panel) is not None
        import time
        app.homelab_panel.refresh()                               # 4.0: background refresh reaches the real textbox
        deadline = time.time() + 10
        while time.time() < deadline and "Infrastructure health" not in app.homelab_panel.box.get("1.0", "end"):
            app.update()
            time.sleep(0.05)
        assert "Infrastructure health" in app.homelab_panel.box.get("1.0", "end")
        app.compliance_panel.run()
        app.audit_panel.refresh()
        app.update()
    finally:
        app._on_close()


def test_real_sign_in_window_closes_registration_and_guest_after_first_account(tmp_path):
    from conftest import FAST_KDF

    from netcommander.config import Paths, RuntimeSettings
    from netcommander.security import AuthManager, CredentialVault
    from netcommander.ui.dialogs import LoginMFADialog

    try:
        root = ctk.CTk()
    except Exception as exc:
        if "display" in str(exc).lower():
            pytest.skip(str(exc))
        raise
    root.withdraw()
    try:
        auth = AuthManager(tmp_path / "users_auth.json", iterations=FAST_KDF)
        fresh = LoginMFADialog(root, auth, CredentialVault(tmp_path / "v.enc"), settings=RuntimeSettings(env={}),
                               paths=Paths.for_root(tmp_path))
        root.update()
        assert fresh.register_btn.cget("state") == "normal" and fresh.guest_btn.cget("state") == "normal"
        fresh.destroy()

        auth.create_account("admin@example.com", "longpassword1")
        gated = LoginMFADialog(root, auth, CredentialVault(tmp_path / "v.enc"), settings=RuntimeSettings(env={}),
                               paths=Paths.for_root(tmp_path))
        root.update()
        assert gated.register_btn.cget("state") == "disabled" and gated.guest_btn.cget("state") == "disabled"
        assert "accounts exist" in gated.guest_btn.cget("text")
        gated.destroy()
    finally:
        root.destroy()
