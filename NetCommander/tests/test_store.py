"""store.py (DeviceStore, device model) and topology.py (pure graph helpers)."""
from __future__ import annotations

import threading

import pytest

from netcommander.store import DeviceStore, make_device, reciprocate_peers, sanitize_params
from netcommander.topology import (
    build_edge_label,
    edge_color,
    edges_from,
    layout_key,
    nearest_node,
    node_color,
)


# ---------------------------------------------------------------- model helpers
class TestModel:
    def test_sanitize_strips_passwords_and_unknown_keys(self):
        p = sanitize_params({"host": "1.1.1.1", "password": "x", "secret": "y", "evil": 1, "port": 22})
        assert p == {"host": "1.1.1.1", "port": 22, "device_type": "cisco_ios", "username": "admin", "timeout": 10}

    def test_sanitize_keeps_existing_values(self):
        p = sanitize_params({"device_type": "juniper_junos", "username": "bob", "timeout": 3, "use_keys": True,
                             "key_file": "/k"}, default_username="zed")
        assert (p["device_type"], p["username"], p["timeout"], p["key_file"], p["use_keys"]) == ("juniper_junos", "bob", 3, "/k", True)
        assert sanitize_params({}, "zed")["username"] == "zed"

    def test_make_device_defaults(self):
        d = make_device({"host": "1.1.1.1"}, ["B", "A", "A"])
        assert d["peers"] == ["A", "B"] and d["status"] == "unknown" and d["loss_pct"] == 0.0
        assert d["history"].maxlen == 20 and d["links"] == {}

    def test_make_device_copies_links(self):
        links = {"B": {"local_intf": "1"}}
        d = make_device({"host": "h"}, links=links)
        d["links"]["C"] = {}
        assert "C" not in links

    def test_reciprocate(self):
        devs = {"A": make_device({"host": "a"}, ["B", "GHOST"]), "B": make_device({"host": "b"})}
        reciprocate_peers(devs)
        assert devs["B"]["peers"] == ["A"] and "GHOST" not in devs


# ---------------------------------------------------------------- DeviceStore
@pytest.fixture
def store() -> DeviceStore:
    s = DeviceStore()
    s.add("A", {"host": "10.0.0.1"}, ["B"])
    s.add("B", {"host": "10.0.0.2", "port": 2222})
    s.add("C", {"host": "10.0.0.3", "device_type": "juniper_junos"})
    return s


class TestDeviceStore:
    def test_add_reciprocates_peers(self, store):
        assert store.snapshot()["B"]["peers"] == ["A"]

    def test_basic_reads(self, store):
        assert len(store) == 3 and "A" in store and "Z" not in store
        assert store.names() == ["A", "B", "C"] and store.first() == "A"
        assert store.device_type("C") == "juniper_junos" and store.device_type("Z") is None
        assert store.status("A") == "unknown" and store.status("Z") is None
        assert DeviceStore().first() is None

    def test_probe_targets_default_port_22(self, store):
        assert store.probe_targets() == {"A": ("10.0.0.1", 22), "B": ("10.0.0.2", 2222), "C": ("10.0.0.3", 22)}

    def test_get_params_is_a_copy(self, store):
        p = store.get_params("A")
        p["host"] = "tampered"
        assert store.get_params("A")["host"] == "10.0.0.1" and store.get_params("nope") is None

    def test_snapshot_is_isolated_deep_copy(self, store):
        snap = store.snapshot()
        snap["A"]["peers"].append("HACK")
        snap["A"]["history"].append((True, 1.0))
        snap["Z"] = {}
        live = store.snapshot()
        assert live["A"]["peers"] == ["B"] and len(live["A"]["history"]) == 0 and "Z" not in live

    def test_remove_cleans_peers_and_links(self, store):
        store.merge({})
        with store.lock:
            store._devices["B"]["links"]["A"] = {"local_intf": "1"}
        assert store.remove("A") is True and store.remove("A") is False
        snap = store.snapshot()
        assert "A" not in snap and snap["B"]["peers"] == [] and snap["B"]["links"] == {}

    def test_replace_all_and_merge(self, store):
        store.replace_all({"X": make_device({"host": "x"}, ["Y"])})
        assert store.names() == ["X"]
        store.merge({"Y": make_device({"host": "y"})})
        assert store.snapshot()["Y"]["peers"] == ["X"]

    def test_set_username(self, store):
        store.set_username("A", "alice")
        store.set_username("ghost", "x")
        assert store.get_params("A")["username"] == "alice"

    def test_apply_discovery_links_and_marks_up(self, store):
        lines = store.apply_discovery("A", [{"neighbor": "C", "local_intf": "Gi1", "remote_intf": "Gi2", "protocol": "LLDP"}])
        snap = store.snapshot()
        assert lines == ["A[Gi1] <-> C[Gi2] (LLDP)"] and snap["A"]["status"] == "up" and snap["A"]["last_seen"]
        assert snap["C"]["peers"] == ["A"]
        assert store.apply_discovery("ghost", []) is None

    def test_mark_up(self, store):
        assert store.mark_up("A") and store.status("A") == "up" and not store.mark_up("ghost")


class TestRecordProbe:
    def test_up_then_down_transition(self, store):
        r1 = store.record_probe("A", True, 5.0, "SSH-2.0-X", 120, 10)
        assert (r1.previous, r1.status, r1.loss_pct, r1.latency_ms) == ("unknown", "up", 0.0, 5.0)
        r2 = store.record_probe("A", False, None, "", 120, 10)
        assert (r2.previous, r2.status) == ("up", "down") and r2.loss_pct == 50.0
        snap = store.snapshot()["A"]
        assert snap["banner"] == "SSH-2.0-X" and snap["latency_ms"] is None and snap["last_seen"]

    def test_degraded_on_latency_or_loss(self, store):
        assert store.record_probe("A", True, 500.0, "", 120, 10).status == "degraded"
        store.record_probe("B", True, 1.0, "", 120, 10)
        assert store.record_probe("B", False, None, "", 120, 10).status == "down"
        assert store.record_probe("B", True, 1.0, "", 120, 10).status == "degraded"      # 33% loss > 10%

    def test_jitter_needs_two_samples(self, store):
        store.record_probe("A", True, 10.0, "", 120, 10)
        assert store.snapshot()["A"]["jitter_ms"] == 0.0
        store.record_probe("A", True, 20.0, "", 120, 10)
        assert store.snapshot()["A"]["jitter_ms"] == pytest.approx(5.0)

    def test_history_window_is_bounded(self, store):
        for _ in range(50):
            store.record_probe("A", True, 1.0, "", 120, 10)
        assert len(store.snapshot()["A"]["history"]) == 20

    def test_removed_device_returns_none(self, store):
        assert store.record_probe("ghost", True, 1.0, "", 120, 10) is None


class TestConcurrency:
    def test_mixed_workload_has_no_races(self):
        store = DeviceStore()
        for i in range(30):
            store.add(f"D{i}", {"host": f"10.0.0.{i}"}, [f"D{(i + 1) % 30}"])
        errors: list[BaseException] = []
        stop = threading.Event()

        def guard(fn):
            def run():
                try:
                    fn()
                except BaseException as exc:            # pragma: no cover
                    errors.append(exc)
            return run

        def churn():
            for n in range(150):
                name = f"X{n % 10}"
                store.add(name, {"host": "9.9.9.9"}, ["D1", "D2"])
                store.remove(name)

        def probes():
            while not stop.is_set():
                for name in store.names():
                    store.record_probe(name, True, 1.0, "b", 120, 10)

        def readers():
            while not stop.is_set():
                store.snapshot(); store.probe_targets(); len(store); store.first()

        def discoverers():
            for n in range(150):
                store.apply_discovery(f"D{n % 30}", [{"neighbor": f"D{(n + 3) % 30}", "local_intf": "1", "remote_intf": "2"}])
                store.mark_up(f"D{n % 30}")

        workers = [threading.Thread(target=guard(churn)) for _ in range(2)] + \
                  [threading.Thread(target=guard(discoverers))]
        background = [threading.Thread(target=guard(probes)) for _ in range(2)] + \
                     [threading.Thread(target=guard(readers)) for _ in range(2)]
        [t.start() for t in workers + background]
        [t.join() for t in workers]
        stop.set()
        [t.join() for t in background]

        assert not errors
        snap = store.snapshot()
        assert len(snap) == 30 and all(len(d["history"]) <= 20 for d in snap.values())
        assert not any(name.startswith("X") for name in snap)
        assert not any(p.startswith("X") for d in snap.values() for p in d["peers"])      # removals fully cleaned


# ---------------------------------------------------------------- topology helpers
class TestTopology:
    def devices(self):
        d = {"A": make_device({"host": "a"}, ["B", "GHOST"]), "B": make_device({"host": "b"}, ["A", "C"]),
             "C": make_device({"host": "c"}, ["C"])}
        d["A"]["links"]["B"] = {"local_intf": "GigabitEthernet0/1", "remote_intf": "TenGigabitEthernet1/1"}
        return d

    def test_edges_unique_sorted_and_inventory_only(self):
        assert edges_from(self.devices()) == [("A", "B"), ("B", "C")]

    def test_layout_key_changes_only_with_structure(self):
        d = self.devices()
        k = layout_key(d)
        d["A"]["status"] = "down"
        assert layout_key(d) == k
        d["D"] = make_device({"host": "d"})
        assert layout_key(d) != k

    def test_colors(self):
        assert node_color("up") == "#22c55e" and node_color("weird") == node_color("unknown")
        assert node_color("down", selected=True) == "#38bdf8"
        assert edge_color("up", "down") == "#ef4444" and edge_color("degraded", "up") == "#f59e0b"
        assert edge_color("up", "unknown") == "#64748b"

    def test_edge_label_uses_either_end_and_shortens(self):
        d = self.devices()
        assert build_edge_label(d, "A", "B") == "Gi0/1 ↔ Te1/1"
        assert build_edge_label(d, "B", "A") == "Te1/1 ↔ Gi0/1"
        assert build_edge_label(d, "B", "C") == ""

    def test_nearest_node_hit_testing(self):
        pos = {"A": (0.0, 0.0), "B": (1.0, 1.0), "C": (-1.0, 0.5)}
        assert nearest_node(pos, 0.02, 0.01) == "A"
        assert nearest_node(pos, 0.95, 1.05) == "B"
        assert nearest_node(pos, 0.5, -1.0) is None           # too far from everything
        assert nearest_node({}, 0, 0) is None
        assert nearest_node({"only": (3.0, 3.0)}, 3.0, 3.0) == "only"
