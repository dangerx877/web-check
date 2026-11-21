"""Main application window. All device/credential state goes through the thread-safe
``DeviceStore`` / ``CredentialVault``; background threads talk to the UI only via ``ui_queue``."""
from __future__ import annotations

import logging
import queue
import sys
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .. import __version__
from ..batch import BatchRunner, build_jobs
from ..compliance import report_text
from ..config import (
    DISRUPTIVE_CMD,
    MAX_OUTPUT_LINES,
    MONO_FONT,
    VENDOR_PROFILES,
    Paths,
    RuntimeSettings,
    get_profile,
)
from ..network import (
    diff_snapshots,
    discover_neighbors_via_ssh,
    export_links_csv,
    fetch_host_key,
    fetch_running_config,
    import_inventory_csv,
    list_snapshots,
    load_inventory_json,
    preview_push,
    prune_snapshots,
    redact_config,
    run_multi_cli_commands,
    save_config_snapshot,
    save_inventory_json,
    trust_host_key,
)
from ..parsers import normalize_hostname
from ..rbac import Permission
from ..security import CredentialVault, credentials_from_env
from ..services import Services
from ..store import DeviceStore, make_device
from ..telemetry import HealthMonitor, filter_devices
from ..utils import excess_lines, open_folder, parse_commands, parse_host_port
from . import theme
from .account import AccountDialog
from .dialogs import CredentialDialog
from .enterprise import AuditPanel, CompliancePanel, DeploymentsPanel, MonitorPanel, SchedulesPanel, TemplatesPanel
from .homelab import HomelabPanel
from .telemetry_tab import TelemetryTab
from .topology import TopologyCanvas

log = logging.getLogger(__name__)
EXAMPLE_HEADER = "# Example multi-command batch:"


class NetworkManagerApp(ctk.CTk):
    def __init__(self, current_user: str, vault: CredentialVault,
                 settings: RuntimeSettings | None = None, paths: Paths | None = None,
                 store: DeviceStore | None = None, auth=None):
        super().__init__()
        self.current_user = current_user
        self.vault = vault
        self.settings = settings or RuntimeSettings()
        self.paths = paths or Paths.default()
        self.store = store or DeviceStore()
        self.services = Services(self.paths, current_user, vault, self.store, self.settings, auth)
        self.services.on_event(self._emit)
        self.settings.strict_hostkeys = bool(self.settings.strict_hostkeys or self.services.prefs.get("strict_hostkeys"))
        self.settings.connect_attempts = self.services.prefs.get("connect_attempts")

        self.guest = bool(vault.ephemeral)
        if self.guest:
            self.title(f"Uptime Funk {__version__} — GUEST MODE (passwords in memory only)")
        else:
            self.title(f"Uptime Funk {__version__} — Signed in as {current_user} [Vault Unlocked]")
        self.geometry("1420x890")

        self.ui_queue: queue.Queue = queue.Queue()
        self.selected_device: str | None = None
        self._closing = False
        self._preset_dtype = None
        self.monitor = HealthMonitor(self.store, self._emit)

        self._handlers = {
            "telemetry": self._on_telemetry,
            "mark_up": self._on_mark_up,
            "auth_failed": self._on_auth_failed,
            "discovered": self._on_discovered,
            "discovery_done": self._on_discovery_done,
            "output": lambda payload: self._append_output(payload),
            "compliance_done": lambda _p: self.compliance_panel.show(report_text(self.compliance_panel.results)),
            "hostkey_unknown": self._on_hostkey_unknown,
            "hostkey_prompt": self._on_hostkey_prompt,
            "deployments_changed": lambda _p: self.deploy_panel.refresh(),
            "monitors_updated": lambda _p: self.monitor_panel.render(),
            "stage_start": lambda _p: self.deploy_panel.refresh(),
            "stage_done": lambda _p: self.deploy_panel.refresh(),
            "enable_run": lambda _p: self.run_btn.configure(state="normal"),
            "homelab_text": lambda text: self.homelab_panel.show(text),
            "enable_backup": lambda _p: self.backup_btn.configure(state="normal", text="Backup Config"),
        }

        self._build_ui()
        self._load_default_inventory_on_startup()
        self._refresh_device_list()
        self._draw_topology()
        self.after(100, self._process_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if auth is not None and not self.guest and auth.must_change_password(current_user):
            self.after(300, self._prompt_password_change)

    # ------------------------------------------------------------------
    # lifecycle / small helpers
    # ------------------------------------------------------------------
    def _prompt_password_change(self) -> None:
        """Accounts created by an admin start with a temporary password the admin knows."""
        messagebox.showwarning(
            "Choose your own password",
            "Your account was created by an administrator with a temporary password.\n\n"
            "Open Account & Security -> Change Password now and choose one only you know.")
        self._append_output("[Account] Temporary password in use - change it in Account & Security.\n")

    def _emit(self, kind: str, payload) -> None:
        """Thread-safe: the only way background threads reach the UI."""
        self.ui_queue.put((kind, payload))

    def _on_close(self):
        self._closing = True
        self.monitor.stop()
        self.monitor_panel.stop()
        self.services.scheduler.stop()
        self.homelab_panel.stop()
        self.services.audit("session.end")
        try:
            self.services.prefs.set(strict_hostkeys=self.settings.strict_hostkeys,
                                    connect_attempts=self.settings.connect_attempts)
        except (OSError, ValueError) as exc:
            log.warning("could not save preferences: %s", exc)
        try:
            self.vault.save()
        except OSError as exc:
            log.warning("vault save on exit failed: %s", exc)
        self.vault.close()
        self.destroy()

    def _backup_vault(self):
        """Vault used to encrypt backups; None in guest mode (a throw-away key would make
        the backups unreadable after the session, so they are saved as plain files)."""
        return None if self.vault.ephemeral else self.vault

    def _error(self, title: str, exc: BaseException | str) -> None:
        messagebox.showerror(title, str(exc))

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1, minsize=345)
        self.grid_columnconfigure(1, weight=3, minsize=680)
        self.grid_rowconfigure(0, weight=1)
        self._build_left_panel()
        tabs = ctk.CTkTabview(self)
        tabs.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="nsew")
        self._build_topology_tab(tabs.add("Network Topology"))
        self._build_runner_tab(tabs.add("Multi-Command & Config Runner"))
        self.telemetry_tab = TelemetryTab(tabs.add("Advanced Health & Telemetry"), self.poll_all_devices)
        self.monitor_panel = MonitorPanel(tabs.add("Monitoring"), self)
        self.compliance_panel = CompliancePanel(tabs.add("Compliance"), self)
        self.templates_panel = TemplatesPanel(tabs.add("Templates"), self)
        self.deploy_panel = DeploymentsPanel(tabs.add("Deployments"), self)
        self.schedules_panel = SchedulesPanel(tabs.add("Schedules"), self)
        self.audit_panel = AuditPanel(tabs.add("Audit Log"), self)
        self.homelab_panel = HomelabPanel(tabs.add("Homelab"), self)
        self.monitor_panel.start()
        if not self.guest:
            self.services.scheduler.start()
        self.services.audit("session.start")

    def _build_left_panel(self):
        ephemeral = self.vault.ephemeral
        left = ctk.CTkFrame(self)
        left.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        left.grid_rowconfigure(5, weight=1)
        left.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(left, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=12, pady=(12, 4), sticky="ew")
        ctk.CTkLabel(hdr, text="Network Inventory", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="👤 Guest: not saved" if ephemeral else "🔒 Vault Active",
                     text_color=theme.WARN if ephemeral else theme.OK,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(side="right")

        mon_bar = ctk.CTkFrame(left, fg_color="transparent")
        mon_bar.grid(row=1, column=0, padx=10, pady=4, sticky="ew")
        mon_bar.grid_columnconfigure((0, 1), weight=1)
        self.mon_btn = ctk.CTkButton(mon_bar, text="Start Health Monitor", command=self.toggle_monitoring)
        self.mon_btn.grid(row=0, column=0, padx=(0, 4), sticky="ew")
        ctk.CTkButton(mon_bar, text="Deep Poll Now", fg_color="#2b6cb0",
                      command=self.poll_all_devices).grid(row=0, column=1, padx=(4, 0), sticky="ew")

        opts = ctk.CTkFrame(left, fg_color="transparent")
        opts.grid(row=2, column=0, padx=10, pady=(2, 4), sticky="ew")
        opts.grid_columnconfigure(0, weight=1)
        self.auto_save_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(opts, text="Auto-save after discovery", variable=self.auto_save_var).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(opts, text="Parallel:").grid(row=0, column=1, padx=(6, 2))
        self.workers_box = ctk.CTkComboBox(opts, values=["1", "4", "8", "16"], width=64)
        self.workers_box.set("8")
        self.workers_box.grid(row=0, column=2)
        self.strict_var = ctk.BooleanVar(value=self.settings.strict_hostkeys)
        ctk.CTkCheckBox(opts, text="Strict SSH host keys (only known hosts)", variable=self.strict_var,
                        command=self._toggle_strict).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        self.retention_box = ctk.CTkComboBox(opts, values=["Keep all", "Keep 5", "Keep 10", "Keep 30", "Keep 90"], width=96,
                                             command=self._on_retention)
        keep = self.services.prefs.get("retention_keep")
        self.retention_box.set("Keep all" if not keep else f"Keep {keep}")
        ctk.CTkLabel(opts, text="Backups:").grid(row=2, column=0, sticky="e", pady=(4, 0))
        self.retention_box.grid(row=2, column=1, columnspan=2, sticky="w", pady=(4, 0))
        self.redact_var = ctk.BooleanVar(value=self.services.prefs.get("redact_diffs"))
        ctk.CTkCheckBox(opts, text="Hide secrets in diffs / previews", variable=self.redact_var,
                        command=self._on_redact).grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 0))
        self.filter_ent = ctk.CTkEntry(left, placeholder_text="Filter devices (name, IP, vendor, status)…")
        self.filter_ent.grid(row=7, column=0, padx=10, pady=(0, 6), sticky="ew")
        self.filter_ent.bind("<KeyRelease>", lambda _e: self._refresh_device_list())

        file_bar = ctk.CTkFrame(left, fg_color="transparent")
        file_bar.grid(row=3, column=0, padx=10, pady=(0, 2), sticky="ew")
        file_bar.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(file_bar, text="Quick Save", fg_color=theme.BTN_PRIMARY,
                      command=self.quick_save_topology).grid(row=0, column=0, padx=(0, 3), sticky="ew")
        ctk.CTkButton(file_bar, text="Save JSON", fg_color=theme.BTN_NEUTRAL,
                      command=self.save_inventory).grid(row=0, column=1, padx=3, sticky="ew")
        ctk.CTkButton(file_bar, text="Load JSON", fg_color=theme.BTN_NEUTRAL,
                      command=self.load_inventory).grid(row=0, column=2, padx=(3, 0), sticky="ew")

        file_bar2 = ctk.CTkFrame(left, fg_color="transparent")
        file_bar2.grid(row=4, column=0, padx=10, pady=(0, 4), sticky="ew")
        file_bar2.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(file_bar2, text="Import CSV", fg_color=theme.BTN_NEUTRAL,
                      command=self.import_csv).grid(row=0, column=0, padx=(0, 3), sticky="ew")
        ctk.CTkButton(file_bar2, text="Remove Node", fg_color=theme.BTN_DANGER,
                      command=self.remove_device).grid(row=0, column=1, padx=3, sticky="ew")
        ctk.CTkButton(file_bar2, text="Export PNG", fg_color=theme.BTN_NEUTRAL,
                      command=self.export_map_png).grid(row=0, column=2, padx=(3, 0), sticky="ew")

        self.device_list_frame = ctk.CTkScrollableFrame(left, label_text="Devices (Click to Select)")
        self.device_list_frame.grid(row=5, column=0, padx=10, pady=6, sticky="nsew")
        self.device_list_frame.grid_columnconfigure(0, weight=1)

        add_box = ctk.CTkFrame(left)
        add_box.grid(row=6, column=0, padx=10, pady=(4, 10), sticky="ew")
        add_box.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(add_box, text="Add Router / Switch / Firewall",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, columnspan=2, padx=8, pady=(8, 4), sticky="w")
        self.ent_name = ctk.CTkEntry(add_box, placeholder_text="Hostname (e.g. R2)")
        self.ent_name.grid(row=1, column=0, padx=4, pady=4, sticky="ew")
        self.ent_ip = ctk.CTkEntry(add_box, placeholder_text="Mgmt IP or IP:port")
        self.ent_ip.grid(row=1, column=1, padx=4, pady=4, sticky="ew")
        self.ent_dtype = ctk.CTkComboBox(add_box, values=sorted(VENDOR_PROFILES))
        self.ent_dtype.set("cisco_ios")
        self.ent_dtype.grid(row=2, column=0, padx=4, pady=4, sticky="ew")
        self.ent_peers = ctk.CTkEntry(add_box, placeholder_text="Peer names (comma sep)")
        self.ent_peers.grid(row=2, column=1, padx=4, pady=4, sticky="ew")
        self.ent_user = ctk.CTkEntry(add_box, placeholder_text="SSH Username")
        self.ent_user.grid(row=3, column=0, padx=4, pady=4, sticky="ew")
        self.ent_pass = ctk.CTkEntry(add_box, placeholder_text="SSH Password (Masked)", show="•")
        self.ent_pass.grid(row=3, column=1, padx=4, pady=4, sticky="ew")
        self.ent_secret = ctk.CTkEntry(add_box, placeholder_text="Enable Secret (Masked)", show="•")
        self.ent_secret.grid(row=4, column=0, padx=4, pady=4, sticky="ew")
        ctk.CTkButton(add_box, text="+ Add Node", command=self.add_device).grid(row=4, column=1, padx=4, pady=(4, 8), sticky="ew")

    def _build_topology_tab(self, tab):
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(tab, fg_color="transparent")
        header.grid(row=0, column=0, padx=8, pady=6, sticky="ew")
        self.lbl_selected = ctk.CTkLabel(header, text="Selected Node: None", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_selected.pack(side="left", padx=6)
        ctk.CTkButton(header, text="Export Links CSV", width=130, fg_color=theme.BTN_NEUTRAL,
                      command=self.export_links).pack(side="right", padx=6)
        ctk.CTkButton(header, text="Re-layout", width=100,
                      command=lambda: self._draw_topology(relayout=True)).pack(side="right", padx=6)
        self.discover_btn = ctk.CTkButton(header, text="Auto-Discover Links", width=145, command=self.discover_topology)
        self.discover_btn.pack(side="right", padx=6)
        self.show_interfaces_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(header, text="Show Interfaces", variable=self.show_interfaces_var,
                        command=self._draw_topology).pack(side="right", padx=8)

        container = ctk.CTkFrame(tab)
        container.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.topology = TopologyCanvas(container, on_select=self.select_device)
        self.topology.widget.grid(row=0, column=0, sticky="nsew")

    def _build_runner_tab(self, tab):
        tab.grid_rowconfigure(2, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        bar = ctk.CTkFrame(tab)
        bar.grid(row=0, column=0, padx=8, pady=6, sticky="ew")
        ctk.CTkLabel(bar, text="Scope:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(10, 4))
        self.scope_var = ctk.StringVar(value="Selected Device")
        ctk.CTkSegmentedButton(bar, values=["Selected Device", "All Devices"], variable=self.scope_var).pack(side="left", padx=4)
        ctk.CTkLabel(bar, text="Mode:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(12, 4))
        self.exec_mode_var = ctk.StringVar(value="Show / Exec")
        ctk.CTkSegmentedButton(bar, values=["Show / Exec", "Config Set"], variable=self.exec_mode_var).pack(side="left", padx=4)
        self.save_cfg_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(bar, text="Write/Save on Config", variable=self.save_cfg_var).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="Account", width=75, fg_color=theme.BTN_NEUTRAL,
                      command=lambda: AccountDialog(self, self.services)).pack(side="right", padx=4)
        ctk.CTkButton(bar, text="Dry-run Preview", width=120, fg_color=theme.BTN_NEUTRAL,
                      command=self.preview_script).pack(side="right", padx=4)
        self.backup_btn = ctk.CTkButton(bar, text="Backup Config", width=115, fg_color=theme.BTN_TEAL, command=self.backup_configs)
        self.backup_btn.pack(side="right", padx=4)
        ctk.CTkButton(bar, text="Diff Last 2", width=90, fg_color=theme.BTN_NEUTRAL, command=self.diff_backups).pack(side="right", padx=4)
        ctk.CTkButton(bar, text="Backups", width=80, fg_color=theme.BTN_NEUTRAL, command=self.open_backups).pack(side="right", padx=4)

        self.quick_bar = ctk.CTkFrame(tab, fg_color="transparent")
        self.quick_bar.grid(row=1, column=0, padx=8, pady=(0, 6), sticky="ew")

        cmd_box = ctk.CTkFrame(tab)
        cmd_box.grid(row=2, column=0, padx=8, pady=(0, 6), sticky="nsew")
        cmd_box.grid_rowconfigure(2, weight=1)
        cmd_box.grid_columnconfigure(0, weight=1)

        multi_hdr = ctk.CTkFrame(cmd_box, fg_color="transparent")
        multi_hdr.grid(row=0, column=0, padx=8, pady=(6, 2), sticky="ew")
        ctk.CTkLabel(multi_hdr, text="Multi-Command Script (one command per line; lines starting with # are comments):",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
        ctk.CTkButton(multi_hdr, text="Load Script", width=95, fg_color=theme.BTN_NEUTRAL,
                      command=self.load_command_script).pack(side="right", padx=3)
        ctk.CTkButton(multi_hdr, text="Clear Script", width=95, fg_color=theme.BTN_NEUTRAL,
                      command=lambda: self.cmd_text.delete("1.0", "end")).pack(side="right", padx=3)

        script_row = ctk.CTkFrame(cmd_box, fg_color="transparent")
        script_row.grid(row=1, column=0, padx=8, pady=(0, 6), sticky="ew")
        script_row.grid_columnconfigure(0, weight=1)
        self.cmd_text = ctk.CTkTextbox(script_row, height=110, font=ctk.CTkFont(family=MONO_FONT, size=12))
        self.cmd_text.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        self.cmd_text.insert("1.0", f"{EXAMPLE_HEADER}\nshow version\nshow ip interface brief")
        self.cmd_text.bind("<Control-Return>", lambda _e: self.send_commands())
        if sys.platform == "darwin":                      # Cmd+Return is the native "run" chord on macOS
            self.cmd_text.bind("<Command-Return>", lambda _e: self.send_commands())
        self.run_btn = ctk.CTkButton(script_row, text="Run Batch\n(Ctrl+Enter)", width=130, height=110,
                                     fg_color=theme.BTN_PRIMARY, command=self.send_commands)
        self.run_btn.grid(row=0, column=1, sticky="ns")

        self.output_box = ctk.CTkTextbox(cmd_box, font=ctk.CTkFont(family=MONO_FONT, size=12))
        self.output_box.grid(row=2, column=0, padx=8, pady=(0, 4), sticky="nsew")
        out_btns = ctk.CTkFrame(cmd_box, fg_color="transparent")
        out_btns.grid(row=3, column=0, padx=8, pady=(0, 8), sticky="e")
        ctk.CTkButton(out_btns, text="Save Output", width=110, fg_color=theme.BTN_NEUTRAL, command=self.save_output).pack(side="left", padx=4)
        ctk.CTkButton(out_btns, text="Clear Output", width=95, fg_color=theme.BTN_NEUTRAL,
                      command=lambda: self.output_box.delete("1.0", "end")).pack(side="left", padx=4)

    # ------------------------------------------------------------------
    # presets / output
    # ------------------------------------------------------------------
    def _rebuild_presets(self):
        dtype = self.store.device_type(self.selected_device) if self.selected_device else None
        if dtype == self._preset_dtype and self.quick_bar.winfo_children():
            return
        self._preset_dtype = dtype
        for w in self.quick_bar.winfo_children():
            w.destroy()
        for label, cmd in get_profile(dtype)["presets"]:
            ctk.CTkButton(self.quick_bar, text=f"+ {label}", width=96, fg_color=theme.BTN_NEUTRAL,
                          command=lambda c=cmd: self._append_command_line(c)).pack(side="left", padx=3)

    def _allowed(self, perm: Permission) -> bool:
        try:
            self.services.require(perm)
            return True
        except PermissionError as exc:
            messagebox.showwarning("Not allowed", str(exc))
            return False

    def _on_retention(self, value: str):
        keep = 0 if value == "Keep all" else int(value.split()[1])
        try:
            self.services.prefs.set(retention_keep=keep)
        except (OSError, ValueError) as exc:
            self._append_output(f"[Prefs] Could not save retention: {exc}\n")

    def _on_redact(self):
        try:
            self.services.prefs.set(redact_diffs=bool(self.redact_var.get()))
        except (OSError, ValueError) as exc:
            self._append_output(f"[Prefs] Could not save setting: {exc}\n")

    def export_links(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="links.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            export_links_csv(self.store.snapshot(), path)
            self._append_output(f"[Export] Links written to {path}\n")
        except OSError as exc:
            self._error("Export Failed", exc)

    def preview_script(self):
        """Dry-run: compare the script with the latest saved backup of the selected device. No device contact."""
        if not self._allowed(Permission.VIEW):
            return
        name = self.selected_device
        commands = parse_commands(self.cmd_text.get("1.0", "end"))
        if not name or not commands:
            messagebox.showinfo("Dry-run", "Select a device and enter commands first.")
            return
        snaps = list_snapshots(name, self.paths.backups)
        if not snaps:
            messagebox.showinfo("Dry-run", f"{name} has no saved backup yet. Press 'Backup Config' first so there is something to compare with.")
            return
        try:
            from ..network import read_snapshot
            current = read_snapshot(snaps[-1], self._backup_vault())
        except Exception as exc:
            self._error("Dry-run", f"Could not read the latest backup:\n{exc}")
            return
        r = preview_push(current, commands)
        def text(xs):
            return "\n    ".join(redact_config("\n".join(xs)).splitlines() if self.redact_var.get() else xs) or "(none)"
        self._append_output(
            f"\n=== Dry-run for {name} (vs backup {snaps[-1].name}) — text comparison only, nothing was sent ===\n"
            f"  Would add/change ({len(r['new'])}):\n    {text(r['new'])}\n"
            f"  Already present ({len(r['present'])}):\n    {text(r['present'])}\n"
            f"  Removes existing config ({len(r['negations'])}):\n    {text(r['negations'])}\n"
            f"  ⚠ Disruptive ({len(r['disruptive'])}):\n    {text(r['disruptive'])}\n")

    # ---- SSH host-key trust (explicit TOFU) -----------------------------------
    def _on_hostkey_unknown(self, payload):
        name, host, port = payload
        if not host or getattr(self, "_hostkey_busy", set()) & {host}:
            return False
        self._hostkey_busy = getattr(self, "_hostkey_busy", set()) | {host}
        import threading

        def work():
            try:
                info = fetch_host_key(host, int(port or 22))
                self._emit("hostkey_prompt", (name, host, port, info, ""))
            except Exception as exc:
                self._emit("hostkey_prompt", (name, host, port, None, f"{type(exc).__name__}: {exc}"))
        threading.Thread(target=work, name="nc-hostkey", daemon=True).start()
        return False

    def _on_hostkey_prompt(self, payload):
        name, host, port, info, err = payload
        self._hostkey_busy = getattr(self, "_hostkey_busy", set()) - {host}
        if info is None:
            self._append_output(f"[SSH] Could not read the host key of {host}: {err}\n")
            return False
        if not messagebox.askyesno(
                "Trust this SSH host key?",
                f"{name} ({host}) is not in known_hosts and strict checking is on.\n\nKey type: {info['type']}\n"
                f"Fingerprint: {info['fingerprint']}\n\nOnly trust it if this matches what the device shows "
                f"(e.g. 'show ssh' / 'show crypto key') or you are on a trusted network. Trust and add to known_hosts?"):
            return False
        try:
            path = trust_host_key(host, int(port) if port else None, info["type"], info["base64"])
        except OSError as exc:
            self._error("known_hosts", exc)
            return False
        self.services.audit("hostkey.trust", f"{name} {host}", detail=info["fingerprint"])
        self._append_output(f"[SSH] Trusted {info['fingerprint']} for {host} -> {path}. Re-run your action.\n")
        return False

    def _toggle_strict(self):
        self.settings.strict_hostkeys = bool(self.strict_var.get())
        if self.settings.strict_hostkeys:
            self._append_output("[SSH] Strict host keys ON: connect once with a normal `ssh` client so each "
                                "device is in ~/.ssh/known_hosts, or connections will be refused.\n")

    def _append_command_line(self, cmd: str):
        current = self.cmd_text.get("1.0", "end").strip()
        if current.startswith(EXAMPLE_HEADER):
            self.cmd_text.delete("1.0", "end")
            current = ""
        self.cmd_text.insert("end", f"{chr(10) if current else ''}{cmd}")

    def load_command_script(self):
        path = filedialog.askopenfilename(title="Load Multi-Command Script",
                                          filetypes=[("Text / Config files", "*.txt *.cfg *.ios"), ("All files", "*.*")])
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._error("Load Script Failed", exc)
            return
        self.cmd_text.delete("1.0", "end")
        self.cmd_text.insert("1.0", content)

    def _append_output(self, text: str):
        self.output_box.insert("end", text)
        try:                                   # keep the widget from growing without limit
            total = int(self.output_box.index("end-1c").split(".")[0])
            drop = excess_lines(total, MAX_OUTPUT_LINES)
            if drop:
                self.output_box.delete("1.0", f"{drop}.0")
        except Exception:
            pass
        self.output_box.see("end")

    def save_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                                            initialfile=f"output_{datetime.now():%Y%m%d_%H%M%S}.txt")
        if path:
            try:
                Path(path).write_text(self.output_box.get("1.0", "end"), encoding="utf-8")
            except OSError as exc:
                self._error("Save Failed", exc)

    def open_backups(self):
        err = open_folder(self.paths.backups)
        if err:
            messagebox.showinfo("Open Folder", f"Could not open the folder automatically:\n{err}\n\n{self.paths.backups}")

    # ------------------------------------------------------------------
    # inventory management
    # ------------------------------------------------------------------
    def _load_default_inventory_on_startup(self):
        path = self.paths.topology
        if path.exists():
            try:
                loaded = load_inventory_json(path)
                if loaded:
                    self.store.replace_all(loaded)
                    self.selected_device = self.store.first()
                    self._append_output(f"[Inventory] Auto-loaded {len(loaded)} devices from {path.name}.\n")
                    return
            except Exception as exc:
                self._append_output(f"[Inventory] Could not auto-load {path.name}: {exc}\n")
        self._seed_sample_topology()

    def _seed_sample_topology(self):
        sample = [
            ("CORE-R1", "192.168.1.1", "cisco_ios", ["DIST-SW1", "DIST-SW2"]),
            ("DIST-SW1", "192.168.1.2", "arista_eos", ["CORE-R1", "ACC-SW1"]),
            ("DIST-SW2", "192.168.1.3", "juniper_junos", ["CORE-R1", "ACC-SW2"]),
            ("ACC-SW1", "192.168.1.11", "cisco_ios", ["DIST-SW1"]),
            ("ACC-SW2", "192.168.1.12", "hp_procurve", ["DIST-SW2"]),
        ]
        self.store.merge({n: make_device({"device_type": t, "host": ip}, peers) for n, ip, t, peers in sample})
        self.selected_device = "CORE-R1"
        self._append_output("[Inventory] No topology.json found - loaded a sample topology. Replace it with your own devices.\n")

    def add_device(self):
        if not self._allowed(Permission.EDIT_INVENTORY):
            return
        name = normalize_hostname(self.ent_name.get())
        raw_ip = self.ent_ip.get().strip()
        if not name or not raw_ip:
            messagebox.showwarning("Missing Info", "Please enter both a Hostname and Management IP.")
            return
        try:
            host, port = parse_host_port(raw_ip)
        except ValueError as exc:
            messagebox.showwarning("Invalid Address", str(exc))
            return

        user = self.ent_user.get().strip() or "admin"
        pwd, sec = self.ent_pass.get(), self.ent_secret.get()
        params = {"device_type": self.ent_dtype.get().strip() or "cisco_ios", "username": user, "host": host}
        if port:
            params["port"] = port

        if name in self.store and not messagebox.askyesno("Replace Device", f"{name} already exists. Replace it?"):
            return
        if pwd:
            try:
                self.vault.set_secret(name, user, pwd, sec)
            except OSError as exc:
                self._error("Vault Error", f"Could not save the password to the vault:\n{exc}")
                return

        peers = [normalize_hostname(p) for p in self.ent_peers.get().split(",") if p.strip()]
        self.store.add(name, params, peers)
        self.selected_device = name
        for entry in (self.ent_name, self.ent_ip, self.ent_peers, self.ent_pass, self.ent_secret):
            entry.delete(0, "end")
        self._refresh_device_list()
        self._draw_topology()

    def remove_device(self):
        if not self._allowed(Permission.EDIT_INVENTORY):
            return
        name = self.selected_device
        if not name or name not in self.store:
            return
        if not messagebox.askyesno("Remove Node", f"Remove {name} from the inventory?"):
            return
        self.store.remove(name)
        try:
            self.vault.remove_device(name)
        except OSError as exc:
            self._error("Vault Error", f"{name} was removed, but its vault entry could not be deleted:\n{exc}")
        self.selected_device = self.store.first()
        self._refresh_device_list()
        self._draw_topology()

    def import_csv(self):
        if not self._allowed(Permission.EDIT_INVENTORY):
            return
        path = filedialog.askopenfilename(title="Import devices from CSV",
                                          filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            imported = import_inventory_csv(path)
        except Exception as exc:
            self._error("Import Failed", exc)
            return
        if not imported:
            messagebox.showwarning("Empty File", "No valid rows (need name + host columns).")
            return
        self.store.merge(imported)
        self.selected_device = next(iter(imported))
        self._refresh_device_list()
        self._draw_topology()
        self._append_output(f"\n[Inventory] Imported {len(imported)} devices from {path}.\n")

    def select_device(self, name: str):
        self.selected_device = name
        self._refresh_device_list()
        self._draw_topology()

    def _refresh_device_list(self):
        snap = self.store.snapshot()
        for widget in self.device_list_frame.winfo_children():
            widget.destroy()
        shown = filter_devices(snap, self.filter_ent.get())
        for idx, name in enumerate(shown):
            info = snap[name]
            row = ctk.CTkFrame(self.device_list_frame, corner_radius=6,
                               fg_color=theme.ROW_SELECTED if name == self.selected_device else theme.ROW_NORMAL)
            row.grid(row=idx, column=0, padx=2, pady=3, sticky="ew")
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text="●", text_color=theme.STATUS_DOT.get(info["status"], theme.STATUS_DOT["unknown"]),
                         font=ctk.CTkFont(size=16), width=24).grid(row=0, column=0, padx=(8, 2), pady=6)
            lat = f"{info['latency_ms']:.1f}ms" if info["latency_ms"] is not None else "--"
            loss = f" ({info['loss_pct']:.0f}% loss)" if info["loss_pct"] > 0 else ""
            tag = "🔒" if self.vault.has_password(name) else ("🔑" if info["params"].get("use_keys") else "🔓")
            vendor = get_profile(info["params"].get("device_type"))["vendor"]
            ctk.CTkButton(row, text=f"{tag} {name} ({info['params'].get('host', '?')}) • {vendor} • {lat}{loss}",
                          anchor="w", fg_color="transparent", hover_color=theme.BTN_NEUTRAL,
                          command=lambda n=name: self.select_device(n)).grid(row=0, column=1, padx=(0, 8), pady=6, sticky="ew")

        sel = snap.get(self.selected_device) if self.selected_device else None
        if sel:
            self.lbl_selected.configure(
                text=f"Selected: {self.selected_device} [{sel['params'].get('host', '?')}] — {sel['status'].upper()}")
        else:
            self.lbl_selected.configure(text="Selected Node: None")
        self._rebuild_presets()
        self.telemetry_tab.render(snap)

    def _draw_topology(self, relayout: bool = False):
        self.topology.draw(self.store.snapshot(), self.selected_device, bool(self.show_interfaces_var.get()), relayout)

    # ------------------------------------------------------------------
    # save / load
    # ------------------------------------------------------------------
    def quick_save_topology(self):
        try:
            saved = save_inventory_json(self.store.snapshot(), self.paths.topology)
            self._append_output(f"\n[Inventory] Quick-saved {len(self.store)} devices to {saved.name}.\n")
        except Exception as exc:
            self._error("Quick Save Failed", f"Could not save {self.paths.topology.name}:\n{exc}")

    def save_inventory(self):
        path = filedialog.asksaveasfilename(title="Save Network Inventory", defaultextension=".json",
                                            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            save_inventory_json(self.store.snapshot(), path)
            self._append_output(f"\n[Inventory] Saved topology to {path} (credentials stored only in encrypted vault).\n")
        except Exception as exc:
            self._error("Save Failed", f"Could not save inventory:\n{exc}")

    def load_inventory(self):
        path = filedialog.askopenfilename(title="Load Network Inventory",
                                          filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            loaded = load_inventory_json(path)
        except Exception as exc:
            self._error("Load Failed", f"Could not load inventory:\n{exc}")
            return
        if not loaded:
            messagebox.showwarning("Empty File", "No devices found in the selected JSON file.")
            return
        self.store.replace_all(loaded)
        self.selected_device = self.store.first()
        self._refresh_device_list()
        self._draw_topology(relayout=True)
        self._append_output(f"\n[Inventory] Loaded {len(loaded)} devices from {path}.\n")

    def export_map_png(self):
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")],
                                            initialfile=f"topology_{datetime.now():%Y%m%d_%H%M%S}.png")
        if path:
            try:
                self.topology.export_png(path)
                self._append_output(f"\n[Map] Exported topology image to {path}.\n")
            except Exception as exc:
                self._error("Export Failed", exc)

    # ------------------------------------------------------------------
    # health monitoring
    # ------------------------------------------------------------------
    def toggle_monitoring(self):
        if self.monitor.running:
            self.monitor.stop()
            self.mon_btn.configure(text="Start Health Monitor", fg_color=["#3B8ED0", "#1F6AA5"])
        else:
            self.monitor.start()
            self.mon_btn.configure(text="Stop Health Monitor", fg_color="#b91c1c")

    def poll_all_devices(self):
        self.monitor.poll_async()

    # ------------------------------------------------------------------
    # credentials
    # ------------------------------------------------------------------
    def _ensure_credentials(self, targets: list[str]) -> bool:
        snap = {n: p for n in targets if (p := self.store.get_params(n)) is not None}
        missing = [n for n, p in snap.items() if not self.vault.has_password(n) and not p.get("use_keys")]
        if not missing:
            return True
        try:
            env = credentials_from_env()
            if env:
                env_user, env_pass, env_enable = env
                for name in missing:
                    user = env_user or snap[name].get("username") or "admin"
                    self.vault.set_secret(name, user, env_pass, env_enable)
                return True

            shared = None
            for idx, name in enumerate(missing):
                params = snap[name]
                if shared is None:
                    dialog = CredentialDialog(
                        self, title=f"Vault Credentials — {name} ({params.get('host', '')})",
                        default_user=params.get("username") or "admin",
                        prompt_secret=get_profile(params.get("device_type"))["enable"],
                        offer_apply_all=(len(missing) - idx > 1))
                    self.wait_window(dialog)
                    if not dialog.result:
                        self._append_output(f"[Vault] Cancelled — missing encrypted password for {name}.\n")
                        return False
                    res = dialog.result
                    if res["apply_all"]:
                        shared = res
                else:
                    res = shared
                self.store.set_username(name, res["username"])
                self.vault.set_secret(name, res["username"], res["password"], res["secret"])
        except OSError as exc:
            self._error("Vault Error", f"Could not save credentials to the vault:\n{exc}")
            return False
        return True

    # ------------------------------------------------------------------
    # batch plumbing
    # ------------------------------------------------------------------
    def _workers(self) -> int:
        try:
            return max(1, min(32, int(self.workers_box.get())))
        except ValueError:
            return 8

    def _start_batch(self, targets: list[str], make_worker, done_kind: str) -> None:
        jobs = build_jobs(self.store, self.vault, targets)
        batch = BatchRunner(self._emit, done_kind, workers=self._workers())
        batch.start(jobs, make_worker)

    def _resolve_targets(self) -> list[str] | None:
        if self.scope_var.get() == "All Devices":
            return self.store.names()
        if not self.selected_device or self.selected_device not in self.store:
            messagebox.showwarning("No Target", "Select a device first or choose 'All Devices'.")
            return None
        return [self.selected_device]

    # ------------------------------------------------------------------
    # discovery
    # ------------------------------------------------------------------
    def discover_topology(self):
        targets = self.store.names()
        if not targets or not self._ensure_credentials(targets):
            return
        self.discover_btn.configure(state="disabled", text="Discovering...")
        self._append_output("\n=== Starting LLDP/CDP Neighbor Discovery ===\n")
        settings = self.settings

        def worker(name, params, creds, batch):
            try:
                self._emit("discovered", (name, discover_neighbors_via_ssh(params, creds, settings)))
            except Exception as exc:
                batch.fail(name, params, exc)

        self._start_batch(targets, worker, "discovery_done")

    # ------------------------------------------------------------------
    # run / backup / diff
    # ------------------------------------------------------------------
    def send_commands(self):
        commands = parse_commands(self.cmd_text.get("1.0", "end"))
        if not commands:
            return
        targets = self._resolve_targets()
        if not targets:
            return

        is_config = self.exec_mode_var.get() == "Config Set"
        save_after = bool(self.save_cfg_var.get())
        try:
            needed = self.services.authorize_exec(targets, commands, is_config)
        except PermissionError as exc:
            messagebox.showwarning("Not allowed", str(exc))
            return
        if needed is Permission.PUSH_CONFIG or any(DISRUPTIVE_CMD.match(c) for c in commands):
            preview = "\n".join(commands[:6]) + ("\n..." if len(commands) > 6 else "")
            warn = "⚠ THIS WILL RUN ON ALL DEVICES\n\n" if len(targets) > 1 else ""
            if not messagebox.askyesno(
                "Confirm Multi-Command / Config Push",
                f"{warn}Mode: {self.exec_mode_var.get()}\nTargets ({len(targets)}): {', '.join(targets)}\n\n"
                f"Commands:\n{preview}\n\nProceed?"):
                return
        if not self._ensure_credentials(targets):
            return

        self.services.audit("push_config" if is_config else "run_commands", ",".join(targets)[:200],
                            detail=f"{len(commands)} command(s):\n" + "\n".join(commands[:5]))
        self._append_output(f"\n=== [{self.exec_mode_var.get()}] Running {len(commands)} command(s) on {', '.join(targets)} ===\n")
        self.run_btn.configure(state="disabled")
        vault, settings, backups = self._backup_vault(), self.settings, self.paths.backups
        redact = bool(self.redact_var.get())

        def worker(name, params, creds, batch):
            saved: dict[str, Path] = {}

            def on_config(tag: str, text: str):
                saved[tag] = save_config_snapshot(name, text, backups, vault=vault, tag=tag)

            try:
                out = run_multi_cli_commands(params, creds, commands, config_mode=is_config, save_after=save_after,
                                             on_config=on_config if is_config else None, settings=settings)
                extra = ""
                if is_config and "pre" in saved:
                    extra += f"\n[Backup] Config before change: {saved['pre']}"
                    if "post" in saved:
                        try:
                            d = diff_snapshots(saved["pre"], saved["post"], vault)
                        except Exception as exc:
                            d = f"(could not diff: {exc})"
                        if redact:
                            d = redact_config(d)
                        extra += "\n[Change diff]\n" + (d or "(no differences - nothing changed on the device)")
                self._emit("mark_up", name)
                self._emit("output", f"\n--- [{name} ({params.get('host', '')})] ---\n{out}{extra}\n")
            except Exception as exc:
                batch.fail(name, params, exc)

        self._start_batch(targets, worker, "enable_run")

    def backup_configs(self):
        if not self._allowed(Permission.BACKUP):
            return
        targets = self._resolve_targets()
        if not targets or not self._ensure_credentials(targets):
            return
        self.backup_btn.configure(state="disabled", text="Backing Up...")
        self._append_output(f"\n=== Backing up configs for {', '.join(targets)} ===\n")
        vault, settings, backups = self._backup_vault(), self.settings, self.paths.backups

        def worker(name, params, creds, batch):
            try:
                cfg = fetch_running_config(params, creds, settings)
                if not cfg.strip():
                    raise RuntimeError("device returned an empty configuration")
                saved = save_config_snapshot(name, cfg, backups, vault=vault)
                keep = self.services.prefs.get("retention_keep")
                if keep:
                    prune_snapshots(name, keep, backups)
                self.services.audit("backup", name)
                self._emit("mark_up", name)
                self._emit("output", f"[{name}] Saved config -> {saved}\n")
            except Exception as exc:
                batch.fail(name, params, exc)

        self._start_batch(targets, worker, "enable_backup")

    def diff_backups(self):
        name = self.selected_device
        if not name:
            messagebox.showwarning("No Target", "Select a device first.")
            return
        snaps = list_snapshots(name, self.paths.backups)
        if len(snaps) < 2:
            messagebox.showinfo("Not enough backups", f"{name} needs at least two backups to diff.")
            return
        try:
            text = diff_snapshots(snaps[-2], snaps[-1], self._backup_vault())
        except Exception as exc:
            self._error("Diff Failed", f"Could not read the backups:\n{exc}")
            return
        if self.redact_var.get():
            text = redact_config(text)
        self._append_output(f"\n=== Config diff for {name}: {snaps[-2].name} -> {snaps[-1].name} ===\n"
                            f"{text if text else '(no differences after ignoring timestamp/noise lines)'}\n")

    # ------------------------------------------------------------------
    # queue consumer (main thread only)
    # ------------------------------------------------------------------
    def _on_telemetry(self, payload):
        name, ok, lat, banner = payload
        lat_warn, loss_warn = self.telemetry_tab.thresholds()
        res = self.store.record_probe(name, ok, lat, banner, lat_warn, loss_warn)
        if res is None:
            return False
        if res.previous != "unknown" and res.previous != res.status:
            self._append_output(f"[ALERT {datetime.now():%H:%M:%S}] {name} changed state: {res.previous.upper()} -> "
                                f"{res.status.upper()} (loss={res.loss_pct:.0f}%, lat={res.latency_ms or 0:.1f}ms)\n")
        return True

    def _on_mark_up(self, name):
        return self.store.mark_up(name)

    def _on_auth_failed(self, name):
        try:
            self.vault.clear_device(name)
        except OSError as exc:
            self._append_output(f"[Vault] Could not clear the stored password for {name}: {exc}\n")
        return True

    def _on_discovered(self, payload):
        name, nbrs = payload
        lines = self.store.apply_discovery(name, nbrs)
        if lines is None:
            return False
        body = "\n    ".join(lines) if lines else "no neighbors reported"
        self._append_output(f"[{name}]\n    {body}\n")
        return True

    def _on_discovery_done(self, _payload):
        self.discover_btn.configure(state="normal", text="Auto-Discover Links")
        self._append_output("=== Discovery finished ===\n")
        if self.auto_save_var.get():
            self.quick_save_topology()

    def _process_ui_queue(self):
        refresh = False
        try:
            while True:
                try:
                    kind, payload = self.ui_queue.get_nowait()
                except queue.Empty:
                    break
                handler = self._handlers.get(kind)
                if handler is None:
                    continue
                try:
                    if handler(payload) not in (None, False) and kind in ("telemetry", "mark_up", "discovered", "auth_failed"):
                        refresh = True
                except Exception as exc:
                    log.exception("UI handler %r failed", kind)
                    self._append_output(f"[UI] Error handling '{kind}': {exc}\n")
            if refresh:
                self._refresh_device_list()
                self._draw_topology()
        finally:
            if not self._closing:
                self.after(100, self._process_ui_queue)
