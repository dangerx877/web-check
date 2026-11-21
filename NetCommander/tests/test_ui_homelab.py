"""Headless wiring test for the desktop Homelab tab (stub widgets; look and feel NOT covered)."""
from __future__ import annotations

import pytest

pytest.importorskip("networkx")
pytest.importorskip("matplotlib")

from test_ui_smoke import app, paths, ui, wait_for  # noqa: F401  (fixtures)

from netcommander.rbac import Role


def test_homelab_tab_refresh_discover_and_guest_web_refusal(app, ui, monkeypatch):
    import netcommander.ui.homelab as hl
    panel = app.homelab_panel
    panel.refresh()
    wait_for(app, "homelab_text")
    assert "Infrastructure health" in panel.box._text and "Devices:" in panel.box._text
    assert panel.platform is not None and panel.platform.secrets.persistent is False      # guest: memory only
    app.services.role = Role.VIEWER
    panel.discover()
    assert ui.mb.shown[-1][0] == "showwarning"                                            # viewers cannot scan
    app.services.role = Role.OPERATOR
    monkeypatch.setattr(hl, "ask_form", lambda *a, **k: {"targets": "127.0.0.1/32"})
    panel.platform.cfg["discovery"]["ports"] = [1]
    panel.platform._discovery_factory = lambda cfg: __import__("netcommander.homelab.discovery", fromlist=["x"]).DiscoveryEngine(
        [1], probe=lambda h, p, t: "filtered", neighbors=dict, resolver=lambda ip: "")
    panel.discover()
    wait_for(app, "homelab_text")
    assert "Discovery finished: 0 hosts" in panel.box._text
    panel.open_web()
    assert ui.mb.shown[-1][0] == "showinfo" and "Guest" in ui.mb.shown[-1][1][1]          # web needs an account
    app._on_close()                                                                       # stops platform cleanly


def test_format_summary_handles_empty_platform(ui):
    from netcommander.ui.homelab import format_summary
    d = {"totals": {"devices": 0, "online": 0, "offline": 0, "degraded": 0}, "health": None,
         "servers": {"online": 0, "total": 0}, "network": {"online": 0, "total": 0}, "storage_health": {"online": 0, "total": 0},
         "vms": {"running": 0, "total": 0}, "containers": {"running": 0, "total": 0, "unhealthy": 0},
         "alerts": {"critical": 0, "warning": 0, "items": []}, "backups": {"ok": 0, "total": 0}, "integrations": [], "events": []}
    text = format_summary(d)
    assert "health: - / 100" in text and "(none)" in text
