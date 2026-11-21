"""Headless smoke tests for the UI layer.

customtkinter/tkinter are replaced by permissive stand-ins, so these tests verify the
*wiring* (imports, attribute names, event flow, secret hiding) without a display. They do
not replace trying the real window: widget look-and-feel is not covered.
"""
from __future__ import annotations

import sys
import time
import types

import pyotp
import pytest

pytest.importorskip("networkx")
pytest.importorskip("matplotlib")

from conftest import FAST_KDF, FakeConn

from netcommander.config import Paths, RuntimeSettings
from netcommander.security import AuthManager, CredentialVault


class W:
    clipboard = ""

    def __init__(self, *args, **kw):
        self._kw = dict(kw)
        self._text = ""
        self._children = []
        self._parent = args[0] if args and isinstance(args[0], W) else None
        if self._parent is not None:
            self._parent._children.append(self)
        self.destroyed = False

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a, **k: None

    def configure(self, **kw): self._kw.update(kw)
    def cget(self, key): return self._kw.get(key, "")
    def get(self, *a): return self._text
    def insert(self, index, text, *a): self._text += text
    def delete(self, *a): self._text = ""
    def index(self, *a): return "1.0"
    def winfo_children(self): return list(self._children)
    def add(self, name): return W(self)
    def after(self, ms, fn=None, *a): return "job"
    def clipboard_clear(self): W.clipboard = ""
    def clipboard_append(self, t): W.clipboard += t
    def clipboard_get(self): return W.clipboard

    def destroy(self):
        self.destroyed = True
        if self._parent is not None and self in self._parent._children:
            self._parent._children.remove(self)


class Var:
    def __init__(self, value=None, **kw): self.v = value
    def get(self): return self.v
    def set(self, v): self.v = v


@pytest.fixture
def ui(monkeypatch):
    ctk = types.ModuleType("customtkinter")
    for n in ("CTk", "CTkToplevel", "CTkFrame", "CTkLabel", "CTkEntry", "CTkButton", "CTkTextbox", "CTkCheckBox",
              "CTkComboBox", "CTkScrollableFrame", "CTkTabview", "CTkSegmentedButton", "CTkCanvas"):
        setattr(ctk, n, type(n, (W,), {}))
    ctk.CTkFont = lambda **k: W()
    ctk.BooleanVar = ctk.StringVar = Var
    tk = types.ModuleType("tkinter")
    fd, mb = types.ModuleType("tkinter.filedialog"), types.ModuleType("tkinter.messagebox")
    mb.answer = True
    mb.shown = []
    mb.askyesno = lambda *a, **k: mb.answer
    for fn in ("showinfo", "showwarning", "showerror"):
        setattr(mb, fn, lambda *a, _fn=fn, **k: mb.shown.append((_fn, a)))
    fd.askopenfilename = fd.asksaveasfilename = lambda **k: ""
    tk.filedialog, tk.messagebox = fd, mb
    agg = types.ModuleType("matplotlib.backends.backend_tkagg")

    class Canvas:
        def __init__(self, fig, master=None): self.w = W()
        def get_tk_widget(self): return self.w
        def mpl_connect(self, *a): pass
        def draw(self): pass

    agg.FigureCanvasTkAgg = Canvas
    for name, mod in {"customtkinter": ctk, "tkinter": tk, "tkinter.filedialog": fd, "tkinter.messagebox": mb,
                      "matplotlib.backends.backend_tkagg": agg}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    for m in [m for m in sys.modules if m.startswith("netcommander.ui")]:
        monkeypatch.delitem(sys.modules, m)
    W.clipboard = ""
    import importlib
    ns = types.SimpleNamespace(
        dialogs=importlib.import_module("netcommander.ui.dialogs"),
        app=importlib.import_module("netcommander.ui.app"), mb=mb)
    yield ns
    for m in [m for m in sys.modules if m.startswith("netcommander.ui")]:
        sys.modules.pop(m, None)


@pytest.fixture
def paths(tmp_path): return Paths.for_root(tmp_path)


def make_login(ui, tmp_path, clock, env=None):
    auth = AuthManager(tmp_path / "users.json", iterations=FAST_KDF, clock=clock)
    vault = CredentialVault(tmp_path / "legacy.enc", iterations=FAST_KDF)
    dlg = ui.dialogs.LoginMFADialog(W(), auth, vault, settings=RuntimeSettings(env=env or {}), paths=Paths.for_root(tmp_path))
    return dlg, auth, vault


def fill(dlg, email="me@example.com", pw="longpassword1", pw2=None, otp=""):
    dlg.email_ent._text, dlg.pw_ent._text = email, pw
    dlg.pw2_ent._text = pw if pw2 is None else pw2
    dlg.otp_ent._text = otp


class TestLoginDialog:
    def test_setup_key_hidden_by_default_and_revealed_on_demand(self, ui, tmp_path, clock):
        dlg, auth, _ = make_login(ui, tmp_path, clock)
        fill(dlg)
        dlg._handle_register()
        sw = dlg._secret_widget
        assert sw is not None and not sw.revealed and sw.entry.cget("show") == "•"
        secret = sw._secret
        assert secret not in dlg.mfa_box._text and secret not in dlg.status_lbl.cget("text")   # never in plain view
        sw.toggle()
        assert sw.revealed and sw.reveal_btn.cget("text") == "Hide"
        sw.toggle()
        assert not sw.revealed and sw.reveal_btn.cget("text") == "Reveal"
        sw.reveal(); sw.hide()
        assert sw.entry.cget("show") == "•"

    def test_copy_key_and_uri_then_clipboard_cleared_only_if_unchanged(self, ui, tmp_path, clock):
        dlg, *_ = make_login(ui, tmp_path, clock)
        fill(dlg); dlg._handle_register()
        sw = dlg._secret_widget
        sw.copy(sw._secret, "Key")
        assert W.clipboard == sw._secret
        sw.clear_clipboard()
        assert W.clipboard == ""
        sw.copy(sw._uri, "URI")
        W.clipboard = "something the user copied later"
        sw.clear_clipboard()
        assert W.clipboard == "something the user copied later"

    def test_full_register_then_sign_in_wipes_secret(self, ui, tmp_path, clock):
        dlg, auth, vault = make_login(ui, tmp_path, clock)
        fill(dlg); dlg._handle_register()
        secret = dlg._secret_widget._secret
        sw = dlg._secret_widget
        dlg.otp_ent._text = pyotp.TOTP(secret).generate_otp(int(clock() // 30))
        dlg._handle_signin()
        assert dlg.authenticated_user == "me@example.com" and dlg.destroyed and vault.unlocked and not vault.ephemeral
        assert sw._secret == "" and sw.entry._text == "" and dlg.pw_ent._text == "" and dlg.otp_ent._text == ""

    def test_validation_messages(self, ui, tmp_path, clock):
        dlg, *_ = make_login(ui, tmp_path, clock)
        fill(dlg, pw2="different-password"); dlg._handle_register()
        assert "do not match" in dlg.status_lbl.cget("text") and dlg._secret_widget is None
        fill(dlg); dlg.otp_ent._text = "000000"; dlg._handle_signin()
        assert dlg.authenticated_user is None and not dlg.destroyed

    def test_register_reports_disk_errors(self, ui, tmp_path, clock, monkeypatch):
        dlg, auth, _ = make_login(ui, tmp_path, clock)
        monkeypatch.setattr(auth, "create_account", lambda *a: (_ for _ in ()).throw(OSError("read-only")))
        fill(dlg); dlg._handle_register()
        assert "read-only" in dlg.status_lbl.cget("text") and dlg._secret_widget is None

    def test_guest_mode_and_admin_disable(self, ui, tmp_path, clock):
        dlg, _, vault = make_login(ui, tmp_path, clock)
        dlg._handle_guest()
        assert dlg.authenticated_user == "guest" and vault.ephemeral and dlg.destroyed
        dlg2, _, vault2 = make_login(ui, tmp_path, clock, env={"NET_DISABLE_GUEST": "1"})
        assert dlg2.guest_btn.cget("state") == "disabled"
        dlg2._handle_guest()
        assert dlg2.authenticated_user is None and not vault2.ephemeral

    def test_register_and_guest_close_once_an_account_exists(self, ui, tmp_path, clock):
        dlg, auth, vault = make_login(ui, tmp_path, clock)
        assert dlg.register_btn.cget("state") != "disabled" and dlg.guest_btn.cget("state") != "disabled"
        fill(dlg); dlg._handle_register()                          # first account bootstraps the install
        assert auth.role_of("me@example.com") == "admin"
        assert dlg.register_btn.cget("state") == "disabled" and dlg.guest_btn.cget("state") == "disabled"
        fill(dlg, email="intruder@example.com"); dlg._handle_register()
        assert "administrator" in dlg.status_lbl.cget("text") and not auth.user_exists("intruder@example.com")
        dlg._handle_guest()                                         # even if the button were clicked
        assert dlg.authenticated_user is None and not vault.ephemeral
        dlg2, *_ = make_login(ui, tmp_path, clock)                  # a later start-up sees the same
        assert dlg2.register_btn.cget("state") == "disabled" and "accounts exist" in dlg2.guest_btn.cget("text")

    def test_guest_declined_and_cancel(self, ui, tmp_path, clock):
        dlg, _, vault = make_login(ui, tmp_path, clock)
        ui.mb.answer = False
        dlg._handle_guest()
        assert dlg.authenticated_user is None and not dlg.destroyed
        dlg._on_cancel()
        assert dlg.authenticated_user is None and dlg.destroyed

    def test_credential_dialog_result_and_buffer_clearing(self, ui):
        d = ui.dialogs.CredentialDialog(W(), "t", prompt_secret=True, offer_apply_all=True)
        d._on_ok()
        assert d.result is None                                 # empty password ignored
        d.pass_entry._text, d.secret_entry._text, d.user_entry._text = "pw", "en", ""
        d.apply_all_var.set(True)
        d._on_ok()
        assert d.result == {"username": "admin", "password": "pw", "secret": "en", "apply_all": True}
        assert d.pass_entry._text == "" and d.secret_entry._text == "" and d.destroyed


@pytest.fixture
def app(ui, paths, guest_vault):
    a = ui.app.NetworkManagerApp("guest", guest_vault, settings=RuntimeSettings(env={}), paths=paths)
    return a


def wait_for(app, kind, timeout=5):
    """Wait until a background batch posts `kind`, then run the real queue consumer."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with app.ui_queue.mutex:
            ready = any(k == kind for k, _ in app.ui_queue.queue)
        if ready:
            app._process_ui_queue()
            return
        time.sleep(0.01)
    raise AssertionError(f"no {kind!r} event arrived")


class TestApp:
    def test_starts_with_sample_topology_and_renders(self, app):
        assert len(app.store) == 5 and app.selected_device == "CORE-R1"
        assert "CORE-R1" in app.telemetry_tab.box._text and "sample topology" in app.output_box._text

    def test_loads_saved_topology_instead_of_sample(self, ui, paths, guest_vault):
        from netcommander.network import save_inventory_json
        from netcommander.store import make_device
        save_inventory_json({"X1": make_device({"host": "9.9.9.9"})}, paths.topology)
        a = ui.app.NetworkManagerApp("guest", guest_vault, paths=paths, settings=RuntimeSettings(env={}))
        assert a.store.names() == ["X1"]

    def test_add_device_validates_and_stores_secret(self, app):
        app.ent_name._text, app.ent_ip._text = "r9.lab", "10.9.9.9:2200"
        app.ent_user._text, app.ent_pass._text, app.ent_dtype._text = "bob", "pw", ""
        app.ent_dtype.set = lambda v: None
        app.ent_peers._text = "core-r1"
        app.add_device()
        assert app.store.get_params("R9")["port"] == 2200 and app.vault.get_decrypted("R9")[:2] == ("bob", "pw")
        assert "R9" in app.store.snapshot()["CORE-R1"]["peers"] and app.selected_device == "R9"
        assert app.ent_pass._text == ""

    def test_add_device_rejects_bad_port(self, app, ui):
        app.ent_name._text, app.ent_ip._text = "bad", "10.0.0.1:99999"
        app.add_device()
        assert "BAD" not in app.store and ui.mb.shown[-1][0] == "showwarning"

    def test_remove_device_cleans_vault(self, app, ui):
        app.vault.set_secret("CORE-R1", "u", "p")
        app.remove_device()
        assert "CORE-R1" not in app.store and not app.vault.has_password("CORE-R1")
        assert app.selected_device == app.store.first()

    def test_telemetry_event_updates_store_and_alerts_on_change(self, app):
        app._emit("telemetry", ("CORE-R1", True, 5.0, "SSH-2.0-x"))
        app._process_ui_queue()
        assert app.store.status("CORE-R1") == "up"
        app._emit("telemetry", ("CORE-R1", False, None, ""))
        app._process_ui_queue()
        assert app.store.status("CORE-R1") == "down" and "UP -> DOWN" in app.output_box._text

    def test_unknown_events_and_vanished_devices_are_ignored(self, app):
        app._emit("nonsense", 1)
        app._emit("telemetry", ("GONE", True, 1.0, ""))
        app._process_ui_queue()
        assert "Error handling" not in app.output_box._text

    def test_auth_failed_clears_vault_entry(self, app):
        app.vault.set_secret("CORE-R1", "u", "p")
        app._emit("auth_failed", "CORE-R1")
        app._process_ui_queue()
        assert not app.vault.has_password("CORE-R1")

    def test_strict_toggle_updates_runtime_settings(self, app):
        app.strict_var.set(True)
        app._toggle_strict()
        assert app.settings.strict_hostkeys and "Strict host keys ON" in app.output_box._text
        app.strict_var.set(False)
        app._toggle_strict()
        assert not app.settings.strict_hostkeys

    def test_batch_run_flows_through_store_vault_and_queue(self, app, monkeypatch):
        monkeypatch.setenv("NET_SSH_PASS", "envpw")
        monkeypatch.setattr(sys.modules["netcommander.ui.app"], "run_multi_cli_commands", lambda params, creds, cmds, **k: f"OUT for {params['host']} as {creds[0]}")
        app.scope_var.set("All Devices")
        app.cmd_text._text = "show version"
        app.exec_mode_var.set("Show / Exec")
        app.send_commands()
        wait_for(app, "enable_run")
        assert "OUT for 192.168.1.1" in app.output_box._text and app.run_btn.cget("state") == "normal"
        assert app.store.status("CORE-R1") == "up" and app.vault.has_password("ACC-SW2")

    def test_config_push_shows_backup_and_diff(self, app, monkeypatch, ui):
        monkeypatch.setenv("NET_SSH_PASS", "envpw")
        mod = sys.modules["netcommander.ui.app"]
        seq = iter(["hostname A\n", "hostname B\n"])
        conn = FakeConn()
        conn.send_command = lambda cmd, **k: next(seq)
        from netcommander import network
        monkeypatch.setattr(network, "open_connection", lambda *a, **k: conn)
        app.scope_var.set("Selected Device")
        app.exec_mode_var.set("Config Set")
        app.cmd_text._text = "hostname B"
        app.send_commands()
        wait_for(app, "enable_run")
        out = app.output_box._text
        assert "[Backup] Config before change" in out and "-hostname A" in out and "+hostname B" in out
        assert list(app.paths.backups.glob("CORE-R1/*_pre.cfg")) and mod

    def test_discovery_applies_links(self, app, monkeypatch):
        monkeypatch.setenv("NET_SSH_PASS", "envpw")
        mod = sys.modules["netcommander.ui.app"]
        monkeypatch.setattr(mod, "discover_neighbors_via_ssh", lambda params, creds, settings=None: (
            [{"neighbor": "ACC-SW2", "local_intf": "Gi1", "remote_intf": "Gi2", "mgmt_ip": "", "protocol": "LLDP"}]
            if params["host"] == "192.168.1.1" else []))
        app.discover_topology()
        wait_for(app, "discovery_done")
        assert "ACC-SW2" in app.store.snapshot()["CORE-R1"]["peers"]
        assert app.paths.topology.exists()                      # auto-save after discovery
        assert app.discover_btn.cget("state") == "normal"

    def test_auth_failures_trip_the_breaker_and_clear_vault(self, app, monkeypatch, fake_netmiko):
        monkeypatch.setenv("NET_SSH_PASS", "envpw")
        mod = sys.modules["netcommander.ui.app"]
        def deny(*a, **k): raise fake_netmiko.NetmikoAuthenticationException("denied")
        monkeypatch.setattr(mod, "run_multi_cli_commands", deny)
        app.workers_box.set = lambda v: None
        app.workers_box._text = "1"
        app.workers_box.get = lambda: "1"
        app.scope_var.set("All Devices")
        app.cmd_text._text = "show version"
        app.send_commands()
        wait_for(app, "enable_run")
        assert "Skipped: batch stopped after 3 authentication failures" in app.output_box._text
        assert not app.vault.has_password("CORE-R1")

    def test_topology_draw_with_real_networkx(self, app):
        app.store.record_probe("DIST-SW1", False, None, "", 120, 10)
        app._draw_topology(relayout=True)
        assert app.topology._pos and set(app.topology._pos) == set(app.store.names())

    def test_close_stops_everything_and_locks_vault(self, app):
        app.toggle_monitoring()
        assert app.monitor.running
        app._on_close()
        assert app._closing and not app.monitor.running and not app.vault.unlocked and app.destroyed
