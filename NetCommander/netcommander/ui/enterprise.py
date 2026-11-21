"""Enterprise tabs. Each panel is a thin view over :class:`netcommander.services.Services`;
all decisions (permissions, approvals, rollback) live there and in the headless modules."""
from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .. import compliance, templates
from ..config import MONO_FONT
from ..deploy import DeployError, make_stages
from ..monitors import History, MonitorError, MonitorRunner, MonitorStore, RestMonitor, SnmpV3Monitor
from ..rbac import Permission
from ..scheduler import ScheduleError
from ..utils import csv_safe, parse_commands
from . import theme
from .dialogs import ask_form

log = logging.getLogger(__name__)

SAMPLE_POLICY = [
    {"id": "ntp", "type": "must_contain", "pattern": "^ntp server", "severity": "medium", "description": "NTP configured"},
    {"id": "no-http", "type": "must_not_contain", "pattern": "^ip http server", "severity": "high",
     "description": "Plain HTTP management disabled"},
    {"id": "logging", "type": "must_contain", "pattern": "^logging (host|server)", "severity": "low",
     "description": "Remote syslog"},
]


def _mono():
    return ctk.CTkFont(family=MONO_FONT, size=12)


class _Panel:
    def __init__(self, tab, app):
        self.tab, self.app, self.svc = tab, app, app.services
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        self.bar = ctk.CTkFrame(tab)
        self.bar.grid(row=0, column=0, padx=8, pady=6, sticky="ew")
        self.box = ctk.CTkTextbox(tab, font=_mono())
        self.box.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")

    def btn(self, text, cmd, color=theme.BTN_NEUTRAL, side="left", width=110):
        ctk.CTkButton(self.bar, text=text, width=width, fg_color=color, command=cmd).pack(side=side, padx=4)

    def show(self, text: str) -> None:
        self.box.delete("1.0", "end")
        self.box.insert("1.0", text)

    def guard(self, perm: Permission) -> bool:
        try:
            self.svc.require(perm)
            return True
        except PermissionError as exc:
            messagebox.showwarning("Not allowed", str(exc))
            return False


# ---------------------------------------------------------------------- compliance
class CompliancePanel(_Panel):
    def __init__(self, tab, app):
        super().__init__(tab, app)
        self.btn("Run Check (backups)", self.run, theme.BTN_PRIMARY, width=150)
        self.btn("Run Check (live)", self.run_live, theme.BTN_NEUTRAL, width=130)
        self.btn("Edit Policy", self.edit_policy)
        self.btn("Export CSV", self.export_csv)
        self.results: list = []
        self.show("Checks the latest saved backup of every device against your policy (no device contact).\n"
                  "Back up first, then press Run Check.")

    def _load_rules(self):
        p = self.app.paths.policy
        if not p.exists():
            p.write_text(json.dumps(SAMPLE_POLICY, indent=2), encoding="utf-8")
        return compliance.load_policy(p)

    def run(self) -> None:
        if not self.guard(Permission.VIEW):
            return
        try:
            rules = self._load_rules()
        except compliance.PolicyError as exc:
            messagebox.showerror("Policy error", str(exc))
            return
        from ..network import list_snapshots, read_snapshot

        def latest(name: str) -> str:
            snaps = list_snapshots(name, self.app.paths.backups)
            if not snaps:
                raise FileNotFoundError("no saved backup yet")
            return read_snapshot(snaps[-1], self.app._backup_vault())
        self.results = compliance.run_compliance(self.app.store.snapshot(), rules, latest)
        self.show(compliance.report_text(self.results))
        self.svc.audit("compliance.run", detail=f"score={compliance.summarize(self.results)['score']}")

    def run_live(self) -> None:
        """Fetch running configs over SSH (background thread), then show the report."""
        if not self.guard(Permission.RUN_SHOW):
            return
        try:
            rules = self._load_rules()
        except compliance.PolicyError as exc:
            messagebox.showerror("Policy error", str(exc))
            return
        names = self.app.store.names()
        if not names or not self.app._ensure_credentials(names):
            return
        from .. import jobs
        from ..batch import build_jobs
        get = jobs.live_config_getter(build_jobs(self.app.store, self.app.vault, names), self.app.settings)
        devices = self.app.store.snapshot()
        self.show("Fetching running configs from every device…")
        import threading

        def work() -> None:
            res = compliance.run_compliance(devices, rules, get, workers=8)
            self.results = res
            self.app._emit("compliance_done", None)
        threading.Thread(target=work, name="nc-compliance-live", daemon=True).start()
        self.svc.audit("compliance.run_live", detail=f"{len(names)} devices")

    def edit_policy(self) -> None:
        if not self.guard(Permission.CHANGE_SETTINGS):
            return
        try:
            self._load_rules()
        except compliance.PolicyError:
            pass
        from ..utils import open_folder
        msg = open_folder(self.app.paths.root)
        messagebox.showinfo("Edit policy", f"Edit this file in any editor, then press Run Check:\n{self.app.paths.policy}"
                            + (f"\n\n{msg}" if msg else ""))

    def export_csv(self) -> None:
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run a check first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="compliance.csv")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerows([[csv_safe(c) for c in r] for r in compliance.report_csv_rows(self.results)])


# ---------------------------------------------------------------------- deployments
class DeploymentsPanel(_Panel):
    def __init__(self, tab, app):
        super().__init__(tab, app)
        self.sel = ctk.StringVar(value="")
        self.combo = ctk.CTkComboBox(self.bar, values=[""], variable=self.sel, width=190)
        self.combo.pack(side="left", padx=4)
        self.btn("New from Runner", self.new_plan, theme.BTN_PRIMARY, width=125)
        self.btn("Submit", lambda: self._act("submit"), width=70)
        self.btn("Approve", lambda: self._act("approve"), theme.BTN_TEAL, width=75)
        self.btn("Reject", lambda: self._act("reject"), theme.BTN_DANGER, width=70)
        self.btn("Execute", self.execute, theme.BTN_PRIMARY, width=75)
        self.btn("Cancel", lambda: self._act("cancel"), width=70)
        self.btn("↻", self.refresh, width=36)
        self.refresh()

    def _id(self) -> str:
        return (self.sel.get() or "").split()[0] if (self.sel.get() or "").strip() else ""

    def refresh(self) -> None:
        plans = self.svc.deployments.list()
        self.combo.configure(values=[f"{p['id']}  [{p['status']}]  {p['title']}" for p in plans] or [""])
        lines = []
        for p in plans:
            appr = f"{sum(a['approve'] for a in p['approvals'])}/{p['required_approvals']} approvals"
            lines.append(f"{p['id']}  {p['status'].upper():<17} {p['title']}  (by {p['created_by']}, {appr}, "
                         f"{len(p['stages'])} stage(s){', auto-rollback' if p['auto_rollback'] else ''})")
            for i, st in enumerate(p["stages"], 1):
                for d in st:
                    r = p["results"].get(d)
                    lines.append(f"     stage {i}: {d:<16} {r['status'] + ' - ' + r['message'][:70] if r else '-'}")
        self.show("\n".join(lines) or "No deployments yet. Write commands in the Runner tab, then 'New from Runner'.")

    def new_plan(self) -> None:
        if not self.guard(Permission.REQUEST_DEPLOY):
            return
        commands = parse_commands(self.app.cmd_text.get("1.0", "end"))
        targets = self.app._resolve_targets()
        if not commands or not targets:
            messagebox.showinfo("Nothing to deploy", "Put config commands in the Runner script box and choose a scope.")
            return
        r = ask_form(self.tab, "New Staged Deployment", [
            ("title", "Title", "", False), ("canary", "Canary devices first", "1", False),
            ("batch", "Batch size after canary (blank = all remaining)", "", False),
            ("approvals", "Approvals required", "1", False),
            ("rollback", "Automatic rollback? (yes/no)", "yes", False),
            ("check_cmd", "Verify command after change (optional)", "", False),
            ("check_expect", "…output must match regex", "", False)], "Create Draft",
            "Rollback uses a device-side timer on Cisco IOS/IOS-XE, Junos and IOS-XR. Other platforms are refused when rollback is on.")
        if not r:
            return
        try:
            auto = r["rollback"].strip().lower() in ("y", "yes", "true", "1")
            unsupported = self.svc.rollback_supported(targets) if auto else []
            if unsupported:
                raise ValueError("No automatic rollback for: " + ", ".join(unsupported) + ". Turn rollback off or remove them.")
            stages = make_stages(targets, int(r["canary"] or 0), int(r["batch"]) if r["batch"].strip() else None)
            checks = [{"command": r["check_cmd"].strip(), "expect": r["check_expect"].strip() or "."}] if r["check_cmd"].strip() else []
            plan = self.svc.deployments.create(
                self.svc.user, r["title"] or f"Deployment {datetime.now():%Y-%m-%d %H:%M}",
                {d: commands for d in targets}, stages, save_after=bool(self.app.save_cfg_var.get()),
                required_approvals=int(r["approvals"] or 1), auto_rollback=auto, checks=checks)
        except (ValueError, PermissionError, OSError) as exc:
            messagebox.showerror("Cannot create deployment", str(exc))
            return
        self.refresh()
        self.sel.set(f"{plan['id']}  [draft]  {plan['title']}")

    def _act(self, what: str) -> None:
        pid = self._id()
        if not pid:
            messagebox.showinfo("Select a deployment", "Choose one from the drop-down.")
            return
        d, u = self.svc.deployments, self.svc.user
        try:
            if what == "submit":
                d.submit(u, pid)
            elif what in ("approve", "reject"):
                plan = d.get(pid)
                preview = "\n".join(f"{dev}: {', '.join(cmds[:3])}{'…' if len(cmds) > 3 else ''}"
                                    for dev, cmds in plan["commands"].items())
                if not messagebox.askyesno("Review deployment", f"{plan['title']}\nby {plan['created_by']}\n\n{preview[:900]}\n\n"
                                           f"{what.capitalize()}?"):
                    return
                d.decide(u, pid, what == "approve")
            elif what == "cancel":
                d.cancel(u, pid)
        except (DeployError, PermissionError, OSError) as exc:
            messagebox.showerror("Not allowed", str(exc))
        self.refresh()

    def execute(self) -> None:
        pid = self._id()
        if not pid or not self.guard(Permission.PUSH_CONFIG):
            return
        try:
            plan = self.svc.deployments.get(pid)
        except DeployError as exc:
            messagebox.showerror("Error", str(exc))
            return
        if plan["status"] != "approved":
            messagebox.showinfo("Not approved", f"This deployment is '{plan['status']}'. Only approved plans can run.")
            return
        if not self.app._ensure_credentials(list(plan["commands"])):
            return
        if not messagebox.askyesno("Execute deployment", f"Run '{plan['title']}' on {sum(len(s) for s in plan['stages'])} "
                                   f"device(s) in {len(plan['stages'])} stage(s)?\nA failed stage stops the rollout."):
            return
        self.app._append_output(f"\n=== Deployment {pid} started ===\n")
        self.svc.execute_plan_async(pid, stage_gate=None)


# ---------------------------------------------------------------------- audit
class AuditPanel(_Panel):
    def __init__(self, tab, app):
        super().__init__(tab, app)
        self.btn("Refresh", self.refresh, theme.BTN_PRIMARY)
        self.btn("Verify Chain", self.verify)
        self.refresh()

    def refresh(self) -> None:
        if not self.svc.can(Permission.READ_AUDIT):
            self.show("Your role cannot read the audit log.")
            return
        rows = self.svc.audit_log.entries(500)
        self.show("\n".join(
            f"{datetime.fromtimestamp(e['ts']):%Y-%m-%d %H:%M:%S}  {e['actor']:<22} {e['action']:<22} "
            f"{e['target'][:28]:<28} {e['outcome']:<7} {e['detail'][:60]}" for e in reversed(rows)) or "(empty)")

    def verify(self) -> None:
        ok, msg = self.svc.audit_log.verify()
        (messagebox.showinfo if ok else messagebox.showerror)("Audit log", msg)


# ---------------------------------------------------------------------- schedules
class SchedulesPanel(_Panel):
    def __init__(self, tab, app):
        super().__init__(tab, app)
        self.btn("Add Schedule", self.add, theme.BTN_PRIMARY, width=115)
        self.btn("Remove…", self.remove)
        self.btn("Pause/Resume…", self.toggle, width=125)
        self.btn("↻", self.refresh, width=36)
        ctk.CTkLabel(self.bar, text="Runs only while Uptime Funk (or `netcommander schedule-run`) is running.",
                     text_color=theme.MUTED).pack(side="right", padx=8)
        self.refresh()

    def refresh(self) -> None:
        rows = []
        for s in self.svc.scheduler.list():
            when = f"every {s['every_minutes']} min" if s["type"] == "interval" else f"daily at {s['at']}"
            last = datetime.fromtimestamp(s["last_run"]).strftime("%Y-%m-%d %H:%M") if s["last_run"] else "never"
            rows.append(f"{s['id']}  {'ON ' if s['enabled'] else 'OFF'} {s['name']:<18} {s['kind']:<8} {when:<18} "
                        f"last: {last}  {s['last_result'][:70]}")
        self.show("\n".join(rows) or "No schedules. Add one to back up configs automatically.")

    def add(self) -> None:
        if not self.guard(Permission.MANAGE_SCHEDULES):
            return
        if self.svc.guest:
            messagebox.showinfo("Guest mode", "Schedules need stored credentials; sign in with an account.")
            return
        r = ask_form(self.tab, "New Scheduled Backup", [
            ("name", "Name", "nightly backup", False), ("type", "interval or daily", "daily", False),
            ("every", "Every N minutes (interval)", "60", False), ("at", "Time HH:MM (daily)", "02:00", False),
            ("targets", "Devices (comma separated, blank = all)", "", False)], "Create")
        if not r:
            return
        try:
            self.svc.add_schedule({"name": r["name"], "kind": "backup", "type": r["type"].strip().lower(),
                                   "every_minutes": int(r["every"] or 0), "at": r["at"].strip(),
                                   "targets": [t.strip() for t in r["targets"].split(",") if t.strip()]})
        except (ScheduleError, ValueError, OSError, PermissionError) as exc:
            messagebox.showerror("Cannot add schedule", str(exc))
        self.refresh()

    def _pick(self, title):
        r = ask_form(self.tab, title, [("id", "Schedule id (from the list)", "", False)], "OK")
        return (r or {}).get("id", "").strip()

    def remove(self) -> None:
        if not self.guard(Permission.MANAGE_SCHEDULES):
            return
        sid = self._pick("Remove schedule")
        if sid:
            try:
                self.svc.remove_schedule(sid)
            except (ScheduleError, OSError, PermissionError) as exc:
                messagebox.showerror("Cannot remove schedule", str(exc))
            self.refresh()

    def toggle(self) -> None:
        if not self.guard(Permission.MANAGE_SCHEDULES):
            return
        sid = self._pick("Pause / resume schedule")
        cur = {s["id"]: s for s in self.svc.scheduler.list()}.get(sid)
        if cur:
            try:
                self.svc.set_schedule_enabled(sid, not cur["enabled"])
            except (ScheduleError, OSError, PermissionError) as exc:
                messagebox.showerror("Cannot change schedule", str(exc))
            self.refresh()


# ---------------------------------------------------------------------- templates
class TemplatesPanel(_Panel):
    def __init__(self, tab, app):
        super().__init__(tab, app)
        self.name = ctk.CTkEntry(self.bar, width=150, placeholder_text="template name")
        self.name.pack(side="left", padx=4)
        self.btn("Save", self.save, width=60)
        self.btn("Load", self.load, width=60)
        self.btn("Preview", self.preview, theme.BTN_PRIMARY, width=75)
        self.btn("To Runner", self.to_runner, width=85)
        self.vars_ent = ctk.CTkEntry(tab, placeholder_text='variables JSON, e.g. {"global": {"ntp": "10.0.0.1"}, "devices": {"R1": {"site": "HQ"}}}')
        self.vars_ent.grid(row=2, column=0, padx=8, pady=(0, 8), sticky="ew")
        self.box.insert("1.0", "hostname {{name}}\nntp server {{ntp}}\ninterface {{uplink|GigabitEthernet0/1}}\n description uplink to core\n")

    def _vars(self):
        raw = self.vars_ent.get().strip()
        data = json.loads(raw) if raw else {}
        return dict(data.get("global", {})), dict(data.get("devices", {}))

    def save(self) -> None:
        try:
            self.svc.templates.save(self.name.get(), self.box.get("1.0", "end"))
            self.svc.audit("template.save", self.name.get())
            messagebox.showinfo("Saved", f"Templates available: {', '.join(self.svc.templates.names())}")
        except (templates.TemplateError, OSError) as exc:
            messagebox.showerror("Cannot save", str(exc))

    def load(self) -> None:
        try:
            self.show(self.svc.templates.load(self.name.get()))
        except templates.TemplateError as exc:
            messagebox.showerror("Cannot load", f"{exc}\nAvailable: {', '.join(self.svc.templates.names()) or '(none)'}")

    def render(self) -> dict | None:
        targets = self.app._resolve_targets()
        if not targets:
            return None
        try:
            g, per = self._vars()
            devs = {n: self.app.store.get_params(n) or {} for n in targets}
            return templates.render_for_devices(self.box.get("1.0", "end"), devs, g, per)
        except (templates.TemplateError, ValueError) as exc:
            messagebox.showerror("Template problem", str(exc))
            return None

    def preview(self) -> None:
        out = self.render()
        if out:
            messagebox.showinfo("Rendered", "\n\n".join(f"[{n}]\n" + "\n".join(c) for n, c in list(out.items())[:6])[:1800])

    def to_runner(self) -> None:
        out = self.render()
        if not out:
            return
        if len({tuple(v) for v in out.values()}) > 1:
            messagebox.showinfo("Per-device differences", "Rendered commands differ per device, so they cannot share one script box. "
                                "Use Deployments (stage them) or run one device at a time.")
            return
        first = next(iter(out.values()))
        self.app.cmd_text.delete("1.0", "end")
        self.app.cmd_text.insert("1.0", "\n".join(first))
        self.app.exec_mode_var.set("Config Set")


# ---------------------------------------------------------------------- monitoring dashboard
class MonitorPanel:
    """SNMPv3 / REST monitors with a rolling sparkline dashboard."""

    def __init__(self, tab, app):
        self.app, self.svc = app, app.services
        tab.grid_rowconfigure(2, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        self.history = History()
        self.store = MonitorStore(app.paths.monitors, app.vault)
        self.monitors = self._load()
        self.runner = MonitorRunner(self.monitors, self.history, on_alert=self._alert, interval=30,
                                    on_sweep=lambda: app._emit("monitors_updated", None))
        self.sel = ctk.StringVar(value="")
        bar = ctk.CTkFrame(tab)
        bar.grid(row=0, column=0, padx=8, pady=6, sticky="ew")
        for text, cmd in (("+ REST", self.add_rest), ("+ SNMPv3", self.add_snmp), ("Remove…", self.remove),
                          ("Poll Now", self.poll_now)):
            ctk.CTkButton(bar, text=text, width=90, fg_color=theme.BTN_PRIMARY if "Poll" in text else theme.BTN_NEUTRAL,
                          command=cmd).pack(side="left", padx=4)
        self.metric = ctk.CTkEntry(bar, width=110, placeholder_text="metric")
        self.metric.pack(side="right", padx=4)
        self.canvas = ctk.CTkCanvas(tab, height=130, highlightthickness=0, bg="#0f172a")
        self.canvas.grid(row=1, column=0, padx=8, sticky="ew")
        self.box = ctk.CTkTextbox(tab, font=_mono())
        self.box.grid(row=2, column=0, padx=8, pady=8, sticky="nsew")
        self.render()

    def _load(self):
        try:
            return self.store.load()
        except Exception as exc:                            # unreadable secrets must not stop the app
            log.warning("monitor definitions not loaded: %s", type(exc).__name__)
            return []

    def _persist(self) -> None:
        try:
            self.store.save(self.monitors)
        except (MonitorError, OSError) as exc:
            messagebox.showwarning("Monitors not saved", str(exc))

    def _alert(self, name: str, breaches: list[str]) -> None:
        self.app._emit("output", f"[ALERT] {name}: {', '.join(breaches)}\n")

    def add_rest(self) -> None:
        if not self.svc.can(Permission.EDIT_INVENTORY):
            messagebox.showwarning("Not allowed", "Your role cannot add monitors.")
            return
        r = ask_form(self.box, "Add REST monitor", [
            ("name", "Name", "", False), ("url", "URL (https://…)", "https://", False),
            ("metrics", "Metrics: name=json.path, comma separated", "cpu=data.cpu.usage", False),
            ("auth", "Auth: none / basic / bearer", "none", False), ("user", "User (basic)", "", False),
            ("secret", "Password or token", "", True), ("verify", "Verify TLS certificate? (yes/no)", "yes", False)], "Add")
        if not r:
            return
        try:
            m = RestMonitor(r["name"].strip(), r["url"].strip(), dict(p.split("=", 1) for p in r["metrics"].split(",") if "=" in p),
                            r["auth"].strip().lower(), r["user"], r["secret"], r["verify"].strip().lower() != "no")
            m.validate()
        except (MonitorError, ValueError) as exc:
            messagebox.showerror("Invalid monitor", str(exc))
            return
        self._add(m)

    def add_snmp(self) -> None:
        if not self.svc.can(Permission.EDIT_INVENTORY):
            messagebox.showwarning("Not allowed", "Your role cannot add monitors.")
            return
        r = ask_form(self.box, "Add SNMPv3 monitor", [
            ("name", "Name", "", False), ("host", "Host", "", False), ("user", "Security user", "", False),
            ("auth_proto", "Auth protocol (SHA/SHA256…)", "SHA", False), ("auth_key", "Auth passphrase", "", True),
            ("priv_proto", "Privacy protocol (AES/AES256, blank = none)", "AES", False), ("priv_key", "Privacy passphrase", "", True),
            ("oids", "OIDs: name=oid, comma separated", "uptime=1.3.6.1.2.1.1.3.0", False),
            ("counters", "Counter metrics (rates), comma separated", "", False)], "Add",
            "SNMPv3 only; v1/v2c community strings are not supported on purpose. Needs: pip install pysnmp")
        if not r:
            return
        try:
            m = SnmpV3Monitor(r["name"].strip(), r["host"].strip(), r["user"].strip(), r["auth_proto"].strip().upper(), r["auth_key"],
                              r["priv_proto"].strip().upper(), r["priv_key"],
                              dict(p.split("=", 1) for p in r["oids"].split(",") if "=" in p),
                              tuple(c.strip() for c in r["counters"].split(",") if c.strip()))
            m.validate()
        except (MonitorError, ValueError) as exc:
            messagebox.showerror("Invalid monitor", str(exc))
            return
        self._add(m)

    def _add(self, m) -> None:
        if any(x.name == m.name for x in self.monitors):
            messagebox.showerror("Duplicate", f"A monitor named {m.name!r} exists.")
            return
        self.monitors.append(m)
        self.runner.set_monitors(self.monitors)
        self._persist()
        self.svc.audit("monitor.add", m.name, detail=m.kind)
        self.runner.start()                                  # no-op when already running
        self.poll_now()

    def remove(self) -> None:
        r = ask_form(self.box, "Remove monitor", [("name", "Monitor name", "", False)], "Remove")
        if r:
            self.monitors[:] = [m for m in self.monitors if m.name != r["name"].strip()]
            self.runner.set_monitors(self.monitors)
            self._persist()
            self.render()

    def poll_now(self) -> None:
        import threading

        def work() -> None:
            self.runner.poll_all()
            self.app._emit("monitors_updated", None)
        threading.Thread(target=work, name="nc-monitor-poll", daemon=True).start()

    def start(self) -> None:
        if self.monitors:
            self.runner.start()

    def stop(self) -> None:
        self.runner.stop()

    def render(self) -> None:
        lines = []
        for m in self.monitors:
            s = self.history.last(m.name)
            avail = self.history.availability(m.name)
            state = "—" if s is None else ("UP  " + "  ".join(f"{k}={v:g}" for k, v in s.metrics.items()) if s.ok else "DOWN " + s.error)
            lines.append(f"{m.name:<18} {m.kind:<7} {'' if avail is None else f'{avail:5.1f}%':>7}  {state}")
        self.box.delete("1.0", "end")
        self.box.insert("1.0", "\n".join(lines) or "No monitors yet. Add a REST endpoint or an SNMPv3 agent.")
        self._spark()

    def _spark(self) -> None:
        c = self.canvas
        c.delete("all")
        name = self.monitors[0].name if self.monitors else ""
        metric = (self.metric.get() or "").strip()
        if name and not metric:
            last = self.history.last(name)
            metric = next(iter(last.metrics), "") if last else ""
        pts = self.history.series(name, metric) if name and metric else []
        if len(pts) < 2:
            return
        w, h = max(int(c.winfo_width()), 400), max(int(c.winfo_height()), 120)
        ys = [p[1] for p in pts]
        lo, hi = min(ys), max(ys)
        span = (hi - lo) or 1.0
        coords = []
        for i, (_, y) in enumerate(pts):
            coords += [10 + i * (w - 20) / (len(pts) - 1), h - 14 - (y - lo) / span * (h - 28)]
        c.create_line(*coords, fill="#38bdf8", width=2)
        c.create_text(12, 8, anchor="nw", fill="#94a3b8", text=f"{name} · {metric}   min {lo:g}  max {hi:g}")
