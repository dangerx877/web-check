"""Health & telemetry tab: threshold inputs and the live table."""
from __future__ import annotations

from typing import Callable, Mapping

import customtkinter as ctk

from ..config import MONO_FONT
from ..telemetry import (
    DEFAULT_LATENCY_WARN_MS,
    DEFAULT_LOSS_WARN_PCT,
    SORT_MODES,
    format_table,
    parse_thresholds,
    sort_devices,
)
from . import theme


class TelemetryTab:
    def __init__(self, tab, on_audit: Callable[[], None]):
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        bar = ctk.CTkFrame(tab)
        bar.grid(row=0, column=0, padx=8, pady=6, sticky="ew")
        ctk.CTkLabel(bar, text="Latency Warn (ms):").pack(side="left", padx=(10, 4))
        self.lat_warn_ent = ctk.CTkEntry(bar, width=65)
        self.lat_warn_ent.insert(0, f"{DEFAULT_LATENCY_WARN_MS:g}")
        self.lat_warn_ent.pack(side="left", padx=4)
        ctk.CTkLabel(bar, text="Packet Loss Warn (%):").pack(side="left", padx=(12, 4))
        self.loss_warn_ent = ctk.CTkEntry(bar, width=65)
        self.loss_warn_ent.insert(0, f"{DEFAULT_LOSS_WARN_PCT:g}")
        self.loss_warn_ent.pack(side="left", padx=4)
        ctk.CTkLabel(bar, text="Sort:").pack(side="left", padx=(12, 4))
        self.sort_var = ctk.StringVar(value=SORT_MODES[0])
        self.sort_box = ctk.CTkComboBox(bar, values=list(SORT_MODES), variable=self.sort_var, width=190,
                                        command=lambda _v: self.render(self._last))
        self.sort_box.pack(side="left", padx=4)
        self._last: Mapping[str, dict] = {}
        ctk.CTkButton(bar, text="Run Deep Health Audit Now", fg_color=theme.BTN_PRIMARY,
                      command=on_audit).pack(side="right", padx=8)
        self.box = ctk.CTkTextbox(tab, font=ctk.CTkFont(family=MONO_FONT, size=12))
        self.box.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")

    def thresholds(self) -> tuple[float, float]:
        return parse_thresholds(self.lat_warn_ent.get(), self.loss_warn_ent.get())

    def render(self, devices: Mapping[str, dict]) -> None:
        self._last = devices
        self.box.delete("1.0", "end")
        self.box.insert("1.0", format_table(devices, sort_devices(devices, self.sort_var.get())))
