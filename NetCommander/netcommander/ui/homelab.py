"""Homelab tab in the desktop window: a summary of the unified platform plus shortcuts.

The full homelab interface is the web dashboard (served on 127.0.0.1 by the same process, sign-in
with your Uptime Funk account + authenticator code). All logic lives in
:class:`netcommander.homelab.platform.HomelabPlatform`; this panel only displays it.
"""
from __future__ import annotations

import logging
import threading
import webbrowser
from tkinter import messagebox

from ..rbac import Permission
from . import theme
from .dialogs import ask_form
from .enterprise import _Panel

log = logging.getLogger(__name__)


def format_summary(d: dict) -> str:
    t = d["totals"]
    lines = [
        f"Infrastructure health: {d['health'] if d['health'] is not None else '-'} / 100",
        f"Devices: {t['devices']}  (online {t['online']}, offline {t['offline']}, degraded {t['degraded']})",
        f"Servers: {d['servers']['online']}/{d['servers']['total']} online   Network: {d['network']['online']}/"
        f"{d['network']['total']}   NAS: {d['storage_health']['online']}/{d['storage_health']['total']}",
        f"VMs: {d['vms']['running']}/{d['vms']['total']} running   Containers: {d['containers']['running']}/"
        f"{d['containers']['total']} ({d['containers']['unhealthy']} unhealthy)",
        f"Alerts: {d['alerts']['critical']} critical, {d['alerts']['warning']} warning   "
        f"Backups: {d['backups']['ok']}/{d['backups']['total']} OK",
        "",
        "Active alerts:",
    ]
    lines += [f"  [{a['severity'].upper():8}] {a['message']}" for a in d["alerts"]["items"]] or ["  (none)"]
    lines += ["", "Integrations:"]
    lines += [f"  {i['name']:<20} {i['kind']:<10} {'OK' if i['ok'] else ('FAILED: ' + i['last_error'][:80]) if i['ok'] is False else 'not polled'}"
              for i in d["integrations"]] or ["  (none - add them in the web dashboard or with `uptimefunk homelab add-integration`)"]
    lines += ["", "Recent events:"]
    lines += [f"  {e['severity']:<8} {e['message'][:110]}" for e in d["events"][:10]] or ["  (none)"]
    return "\n".join(lines)


class HomelabPanel(_Panel):
    def __init__(self, tab, app):
        super().__init__(tab, app)
        self.platform = None
        self.server = None
        self._lock = threading.Lock()
        self.btn("Refresh", self.refresh, theme.BTN_PRIMARY)
        self.btn("Discover…", self.discover)
        self.btn("Collect & Check", self.cycle, width=130)
        self.btn("Open Web Dashboard", self.open_web, theme.BTN_PRIMARY, width=165)
        self.show("Homelab platform: press Refresh (or open the web dashboard for the full interface).")

    # ---- platform lifecycle ---------------------------------------------------
    def _ctx(self):
        from ..homelab.platform import Ctx
        return Ctx(self.svc.user, self.svc.role)

    def _platform(self):
        with self._lock:
            if self.platform is None:
                from ..homelab.platform import HomelabPlatform
                self.platform = HomelabPlatform(self.app.paths, self.app.vault, device_source=self.app.store.snapshot,
                                                audit=self.svc.audit_log)
            return self.platform

    def stop(self) -> None:
        try:
            if self.server is not None:
                self.server.stop()
            if self.platform is not None:
                self.platform.stop()
        except Exception:                                  # closing must never fail
            log.exception("homelab shutdown")

    def _background(self, label: str, fn) -> None:
        def work():
            try:
                text = fn()
            except Exception as exc:
                text = f"{label} failed: {exc}"
            self.app._emit("homelab_text", text)
        threading.Thread(target=work, name=f"nc-homelab-{label}", daemon=True).start()

    # ---- actions --------------------------------------------------------------
    def refresh(self) -> None:
        self._background("refresh", lambda: format_summary(self._platform().dashboard(self._ctx())))

    def discover(self) -> None:
        if not self.guard(Permission.DISCOVER):
            return
        vals = ask_form(self.tab, "Discover infrastructure",
                        [("targets", "Networks / ranges (comma separated)", "192.168.1.0/24", False)])
        if not vals or not vals.get("targets", "").strip():
            return
        targets = [t.strip() for t in vals["targets"].split(",") if t.strip()]
        self.show(f"Discovering {', '.join(targets)} (read-only TCP probes)…")

        def run():
            res = self._platform().run_discovery(self._ctx(), targets)
            return f"Discovery finished: {res['alive']} hosts answered, {res['new']} new.\n\n" + \
                format_summary(self._platform().dashboard(self._ctx()))
        self._background("discovery", run)

    def cycle(self) -> None:
        if not self.guard(Permission.DISCOVER):
            return
        self.show("Collecting from integrations and servers, running checks…")

        def run():
            p = self._platform()
            c = p.collect_cycle()
            p.monitor_cycle()
            p.backup_cycle()
            return f"Collected {c['ok']} OK / {c['failed']} failed.\n\n" + format_summary(p.dashboard(self._ctx()))
        self._background("cycle", run)

    def open_web(self) -> None:
        auth = getattr(self.svc, "auth", None)
        if auth is None or self.app.vault.ephemeral:
            messagebox.showinfo("Web dashboard", "The web dashboard needs a signed-in account (not Guest mode): "
                                                 "it asks for your password and authenticator code.")
            return
        try:
            if self.server is None:
                from ..homelab.api.server import ApiServer
                self.server = ApiServer(self._platform(), auth, bind="127.0.0.1", port=0)
                self.server.start()
                self.svc.audit("web.start", self.server.url)
            webbrowser.open(self.server.url)
            self.show(f"Web dashboard running at {self.server.url} (this computer only).\n"
                      "Sign in with your Uptime Funk e-mail, password and authenticator code.")
        except Exception as exc:
            messagebox.showerror("Web dashboard", str(exc))
