"""Pure topology helpers (no matplotlib/networkx/Tk) so they can be unit-tested.

The drawing itself lives in ``netcommander.ui.topology``.
"""
from __future__ import annotations

from typing import Mapping

from .parsers import shorten_intf

__all__ = [
    "build_edge_label", "edge_color", "edges_from", "layout_key", "nearest_node", "node_color",
]

STATUS_COLORS = {
    "up": "#22c55e",
    "degraded": "#f59e0b",
    "down": "#ef4444",
    "unknown": "#94a3b8",
}
SELECTED_COLOR = "#38bdf8"
EDGE_OK, EDGE_DEGRADED, EDGE_DOWN = "#64748b", "#f59e0b", "#ef4444"


def edges_from(devices: Mapping[str, dict]) -> list[tuple[str, str]]:
    """Unique undirected edges between devices that are both in the inventory."""
    edges: set[tuple[str, str]] = set()
    for name, info in devices.items():
        for peer in info.get("peers", []):
            if peer in devices and peer != name:
                lo, hi = sorted((name, peer))
                edges.add((lo, hi))
    return sorted(edges)


def layout_key(devices: Mapping[str, dict]) -> tuple:
    """Changes only when the graph structure changes (so layouts are not recomputed needlessly)."""
    return tuple(sorted(devices)), tuple(edges_from(devices))


def node_color(status: str, selected: bool = False) -> str:
    return SELECTED_COLOR if selected else STATUS_COLORS.get(status, STATUS_COLORS["unknown"])


def edge_color(status_u: str, status_v: str) -> str:
    if "down" in (status_u, status_v):
        return EDGE_DOWN
    if "degraded" in (status_u, status_v):
        return EDGE_DEGRADED
    return EDGE_OK


def build_edge_label(devices: Mapping[str, dict], u: str, v: str) -> str:
    u_info = devices.get(u, {}).get("links", {}).get(v)
    v_info = devices.get(v, {}).get("links", {}).get(u)
    u_if = (u_info or {}).get("local_intf") or (v_info or {}).get("remote_intf") or ""
    v_if = (v_info or {}).get("local_intf") or (u_info or {}).get("remote_intf") or ""
    u_if, v_if = shorten_intf(u_if), shorten_intf(v_if)
    if u_if and v_if:
        return f"{u_if} ↔ {v_if}"
    return u_if or v_if


def nearest_node(
    pos: Mapping[str, tuple[float, float]], x: float, y: float, tolerance: float = 0.09
) -> str | None:
    """Node closest to a click, if within `tolerance` x the layout span."""
    if not pos:
        return None
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    span = max(max(xs) - min(xs), max(ys) - min(ys), 1e-6)
    best, best_d = None, float("inf")
    for node, (nx_, ny_) in pos.items():
        d = ((nx_ - x) ** 2 + (ny_ - y) ** 2) ** 0.5
        if d < best_d:
            best, best_d = node, d
    return best if best is not None and best_d < tolerance * span else None
