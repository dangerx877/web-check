"""Matplotlib/networkx topology canvas. Pure logic lives in ``netcommander.topology``."""
from __future__ import annotations

from typing import Callable, Mapping

import networkx as nx
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from .. import topology as topo
from . import theme


class TopologyCanvas:
    def __init__(self, master, on_select: Callable[[str], None]):
        self._on_select = on_select
        self._pos: dict = {}
        self._layout_key: tuple | None = None
        self.fig = Figure(figsize=(8, 5), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.fig.patch.set_facecolor(theme.CANVAS_BG)
        self.canvas = FigureCanvasTkAgg(self.fig, master=master)
        self.widget = self.canvas.get_tk_widget()
        self.canvas.mpl_connect("button_press_event", self._on_click)

    def _on_click(self, event) -> None:
        if event.inaxes is not self.ax or event.xdata is None:
            return
        node = topo.nearest_node(self._pos, event.xdata, event.ydata)
        if node:
            self._on_select(node)

    def draw(self, devices: Mapping[str, dict], selected: str | None,
             show_interfaces: bool = True, relayout: bool = False) -> None:
        self.ax.clear()
        self.ax.set_facecolor(theme.CANVAS_BG)
        if not devices:
            self.ax.axis("off")
            self.canvas.draw()
            return

        graph = nx.Graph()
        graph.add_nodes_from(devices)
        graph.add_edges_from(topo.edges_from(devices))

        key = topo.layout_key(devices)
        if relayout or key != self._layout_key or not self._pos:
            n = len(graph.nodes)
            self._pos = nx.spring_layout(graph, seed=42, k=1.8 if n <= 12 else 4.0 / (n ** 0.5))
            self._layout_key = key
        pos = self._pos

        node_colors = [topo.node_color(devices[n]["status"], n == selected) for n in graph.nodes]
        edge_colors, edge_labels = [], {}
        for u, v in graph.edges:
            edge_colors.append(topo.edge_color(devices[u]["status"], devices[v]["status"]))
            label = topo.build_edge_label(devices, u, v)
            if label:
                edge_labels[(u, v)] = label

        big = len(graph.nodes) <= 15
        nx.draw_networkx_edges(graph, pos, ax=self.ax, edge_color=edge_colors, width=2.2, alpha=0.85)
        nx.draw_networkx_nodes(graph, pos, ax=self.ax, node_color=node_colors,
                               node_size=1400 if big else 700, edgecolors="white", linewidths=1.5)
        nx.draw_networkx_labels(graph, pos, ax=self.ax, font_color="#0f172a", font_weight="bold",
                                font_size=9 if big else 7)
        if edge_labels and show_interfaces:
            nx.draw_networkx_edge_labels(
                graph, pos, edge_labels=edge_labels, ax=self.ax, font_size=8, font_color="#e2e8f0",
                label_pos=0.5, rotate=False,
                bbox=dict(boxstyle="round,pad=0.2", facecolor="#0f172a", edgecolor="#475569", alpha=0.9))

        self.ax.set_title("Network Map — Cyan = Selected, Green = Healthy, Amber = Degraded, Red = Down",
                          color="white", fontsize=10)
        self.ax.axis("off")
        self.fig.tight_layout()
        self.canvas.draw()

    def export_png(self, path: str) -> None:
        self.fig.savefig(path, dpi=150, facecolor=self.fig.get_facecolor())
