"""The unified inventory: assets persisted in the homelab database.

* Manual entries (``source="manual"``) are created and edited by people; edited fields are locked.
* Observations from discovery and integrations are *upserted*: matched to an existing asset by
  ``(integration, external_id)``, then MAC, then IP (for discovery), otherwise created.
* The original network device inventory (``topology.json`` / :class:`~netcommander.store.DeviceStore`)
  is mirrored read-only (:func:`network_assets`), so routers and switches appear in the same views and can be
  linked to servers, VMs and storage without moving their data or changing the network workflows.
"""
from __future__ import annotations

import csv
import io
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from ..utils import csv_safe
from .core.db import Database
from .core.errors import NotFound, ValidationError
from .core.events import EventBus
from .models import EDITABLE, KINDS, LINK_TYPES, Asset, merge_observation

COLLECTION = "assets"

_NETWORK_KIND = {
    "fortinet": "firewall", "paloalto_panos": "firewall",
    "juniper_junos": "router", "cisco_xr": "router", "mikrotik_routeros": "router", "nokia_sros": "router",
    "linux": "server",
}


def network_kind(device_type: str | None) -> str:
    return _NETWORK_KIND.get(device_type or "", "switch")


def network_assets(devices: Mapping[str, dict]) -> list[Asset]:
    """Read-only Asset views of the classic network inventory (``DeviceStore.snapshot()``)."""
    out = []
    for name, dev in sorted(devices.items()):
        params = dev.get("params", {})
        status = {"up": "online", "down": "offline", "degraded": "degraded"}.get(dev.get("status", ""), "unknown")
        a = Asset(
            id=f"net-{name}", name=name, kind=network_kind(params.get("device_type")), status=status,
            hostname=name, source="network",
            links=[{"to": f"net-{p}", "type": "connected_to",
                    "port": (dev.get("links", {}).get(p) or {}).get("local_port", "")} for p in dev.get("peers", [])],
            extra={"device_type": params.get("device_type", ""), "latency_ms": dev.get("latency_ms"),
                   "loss_pct": dev.get("loss_pct"), "mgmt_host": params.get("host", "")},
            last_seen=_ts(dev.get("last_seen")),
        )
        host = str(params.get("host", ""))
        try:
            from .models import normalize_ip
            a.ip = normalize_ip(host)
        except ValidationError:
            a.hostname = host or name
        out.append(a)
    return out


def _ts(v: Any) -> float | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(v)).timestamp()
    except ValueError:
        return None


class AssetStore:
    def __init__(self, db: Database, bus: EventBus | None = None,
                 network_source: Callable[[], Mapping[str, dict]] | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.db, self.bus = db, bus or EventBus()
        self._network_source = network_source
        self._clock = clock
        self._lock = threading.RLock()

    # ---- reads -----------------------------------------------------------
    def _stored(self) -> list[Asset]:
        return [Asset.from_dict(d) for d in self.db.all(COLLECTION)]

    def network(self) -> list[Asset]:
        if self._network_source is None:
            return []
        try:
            return network_assets(self._network_source())
        except Exception:                                 # never let the mirror break the inventory
            return []

    def all(self, include_network: bool = True) -> list[Asset]:
        items = self._stored()
        return items + self.network() if include_network else items

    def get(self, aid: str) -> Asset:
        d = self.db.get(COLLECTION, aid)
        if d is not None:
            return Asset.from_dict(d)
        for a in self.network():
            if a.id == aid:
                return a
        raise NotFound(f"No asset with id {aid!r}.")

    def search(self, text: str = "", kind: str | None = None, status: str | None = None,
               tag: str | None = None, parent: str | None = None, source: str | None = None) -> list[Asset]:
        t = (text or "").strip().lower()
        out = []
        for a in self.all():
            if kind and a.kind != kind:
                continue
            if status and a.status != status:
                continue
            if tag and tag not in a.tags:
                continue
            if parent is not None and a.parent != parent:
                continue
            if source and a.source != source:
                continue
            if t:
                hay = " ".join(str(x) for x in (a.name, a.hostname, a.ip, a.mac, a.os, a.manufacturer, a.model,
                                                a.kind, a.location, " ".join(a.tags), a.notes)).lower()
                if not all(part in hay for part in t.split()):
                    continue
            out.append(a)
        return sorted(out, key=lambda a: (a.kind, a.name.lower()))

    def children(self, aid: str) -> list[Asset]:
        return [a for a in self._stored() if a.parent == aid]

    # ---- manual edits ------------------------------------------------------
    def create(self, data: Mapping[str, Any], actor: str = "") -> Asset:
        unknown = set(data) - set(EDITABLE) - {"links", "extra"}
        if unknown:
            raise ValidationError(f"Unknown or read-only fields: {', '.join(sorted(unknown))}")
        a = Asset(**{k: v for k, v in data.items()})
        a.source = "manual"
        a.locked = sorted(k for k in data if k in EDITABLE)
        a.validate()
        with self._lock:
            self.db.put(COLLECTION, a.id, a.to_dict())
        self.bus.emit("asset.created", "inventory", a.id, f"{a.name} added", actor=actor)
        return a

    def update(self, aid: str, changes: Mapping[str, Any], actor: str = "") -> Asset:
        if aid.startswith("net-"):
            raise ValidationError("Network devices are edited in the Network Commander inventory.")
        unknown = set(changes) - set(EDITABLE) - {"links"}
        if unknown:
            raise ValidationError(f"Unknown or read-only fields: {', '.join(sorted(unknown))}")
        with self._lock:
            a = self.get(aid)
            data = a.to_dict()
            data.update(changes)
            data["locked"] = sorted(set(a.locked) | {k for k in changes if k in EDITABLE})
            new = Asset.from_dict(data).validate()
            self.db.put(COLLECTION, aid, new.to_dict())
        self.bus.emit("asset.updated", "inventory", aid, f"{new.name} updated", actor=actor, fields=sorted(changes))
        return new

    def unlock(self, aid: str, fields_: Iterable[str]) -> Asset:
        """Let discovery manage these fields again."""
        with self._lock:
            a = self.get(aid)
            a.locked = sorted(set(a.locked) - set(fields_))
            self.db.put(COLLECTION, aid, a.to_dict())
            return a

    def delete(self, aid: str, actor: str = "") -> bool:
        with self._lock:
            ok = self.db.delete(COLLECTION, aid)
            if ok:
                for child in self.children(aid):           # orphaned VMs/containers keep their data
                    child.parent = ""
                    self.db.put(COLLECTION, child.id, child.to_dict())
        if ok:
            self.bus.emit("asset.deleted", "inventory", aid, "asset removed", actor=actor)
        return ok

    def link(self, src: str, dst: str, link_type: str, port: str = "") -> Asset:
        if link_type not in LINK_TYPES:
            raise ValidationError(f"link type must be one of {', '.join(LINK_TYPES)}")
        self.get(dst)
        with self._lock:
            a = self.get(src)
            if src.startswith("net-"):
                raise ValidationError("Link from the server/VM/storage side; network devices are read-only here.")
            links = [lk for lk in a.links if not (lk["to"] == dst and lk["type"] == link_type)]
            links.append({"to": dst, "type": link_type, "port": port})
            a.links = links
            self.db.put(COLLECTION, a.id, a.to_dict())
            return a

    def unlink(self, src: str, dst: str, link_type: str | None = None) -> Asset:
        with self._lock:
            a = self.get(src)
            a.links = [lk for lk in a.links if not (lk["to"] == dst and (link_type in (None, lk["type"])))]
            self.db.put(COLLECTION, a.id, a.to_dict())
            return a

    # ---- observations (discovery / integrations) ----------------------------------
    def _match(self, obs: Mapping[str, Any], stored: list[Asset]) -> Asset | None:
        integ, ext = obs.get("integration"), obs.get("external_id")
        if integ and ext:
            for a in stored:
                if a.integration == integ and a.external_id == ext:
                    return a
            return None                                   # integration objects match only by their own id
        mac = obs.get("mac")
        if mac:
            for a in stored:
                if a.mac and a.mac == mac:
                    return a
        ip = obs.get("ip")
        if ip:
            for a in stored:
                # discovery may land on a host an integration already reports (same management IP);
                # never on a VM/container, whose IPs can repeat across isolated networks
                if a.ip == ip and a.kind not in ("vm", "container") and \
                        (not a.external_id or a.kind in ("hypervisor", "docker_host", "nas")):
                    return a
        return None

    def upsert_observed(self, obs: Mapping[str, Any], source: str = "discovery") -> tuple[Asset, bool]:
        """Returns ``(asset, created)``. Validation problems in observed data drop the bad field, not the asset."""
        clean = dict(obs)
        for k in ("ip", "mac"):
            if clean.get(k):
                try:
                    from .models import normalize_ip, normalize_mac
                    clean[k] = (normalize_ip if k == "ip" else normalize_mac)(clean[k])
                except ValidationError:
                    clean.pop(k)
        if clean.get("kind") not in KINDS:
            clean["kind"] = "unknown"
        now = self._clock()
        with self._lock:
            stored = self._stored()
            cur = self._match(clean, stored)
            if cur is None:
                name = str(clean.get("name") or clean.get("hostname") or clean.get("ip") or "unnamed")[:128]
                a = Asset(name=name, source=source, first_seen=now)
                a = merge_observation(a, {**clean, "name": name}, now)
                a.source = source
                created = True
            else:
                prev_status = cur.status
                if cur.kind != "unknown" and clean.get("kind") == "unknown":
                    clean.pop("kind")
                a = merge_observation(cur, clean, now)
                created = False
            a.validate()
            self.db.put(COLLECTION, a.id, a.to_dict())
        if created:
            self.bus.emit("asset.discovered", source, a.id, f"new {a.kind}: {a.name} ({a.ip or a.external_id})")
        elif prev_status != a.status:
            sev = "warning" if a.status in ("offline", "degraded") else "info"
            self.bus.emit("asset.status", source, a.id, f"{a.name}: {prev_status} -> {a.status}", severity=sev,
                          previous=prev_status, status=a.status)
        return a, created

    def observe(self, aid: str, obs: Mapping[str, Any]) -> Asset:
        """Apply collector data to a known asset (respecting locked fields)."""
        with self._lock:
            cur = self.get(aid)
            if aid.startswith("net-"):
                return cur
            prev = cur.status
            a = merge_observation(cur, dict(obs), self._clock()).validate()
            self.db.put(COLLECTION, aid, a.to_dict())
        if prev != a.status:
            sev = "warning" if a.status in ("offline", "degraded") else "info"
            self.bus.emit("asset.status", "collector", aid, f"{a.name}: {prev} -> {a.status}", severity=sev)
        return a

    def mark_missing(self, integration: str, seen_external_ids: set[str]) -> list[str]:
        """Assets an integration no longer reports are marked offline (never deleted automatically)."""
        changed = []
        with self._lock:
            for a in self._stored():
                if a.integration == integration and a.external_id not in seen_external_ids and a.status != "offline":
                    a.status = "offline"
                    self.db.put(COLLECTION, a.id, a.to_dict())
                    changed.append(a.id)
        for aid in changed:
            self.bus.emit("asset.status", integration, aid, "no longer reported by its integration", severity="warning")
        return changed

    # ---- import / export -------------------------------------------------
    def export_rows(self) -> list[dict[str, Any]]:
        return [a.summary() for a in self.all()]

    CSV_COLUMNS = ("id", "name", "kind", "status", "hostname", "ip", "mac", "os", "manufacturer", "model",
                   "cpu_model", "cpu_cores", "mem_total", "storage_total", "location", "parent", "source", "tags")

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(self.CSV_COLUMNS)
        for a in self.all():
            row = a.to_dict()
            row["tags"] = ";".join(a.tags)
            w.writerow([csv_safe(str(row.get(c, "") if row.get(c) is not None else "")) for c in self.CSV_COLUMNS])
        return buf.getvalue()

    def import_csv(self, text: str, actor: str = "") -> tuple[int, list[str]]:
        """Manual bulk entry. Returns ``(created, problems)``; a bad row is reported and skipped."""
        created, problems = 0, []
        for n, row in enumerate(csv.DictReader(io.StringIO(text)), 2):
            data: dict[str, Any] = {k: (v or "").strip() for k, v in row.items()
                                    if k in EDITABLE and k not in ("management",) and (v or "").strip()}
            if "tags" in data:
                data["tags"] = [t for t in str(data["tags"]).split(";") if t]
            for k in ("cpu_cores", "mem_total", "storage_total"):
                if k in data:
                    data[k] = int(data[k]) if str(data[k]).isdigit() else data[k]
            try:
                self.create(data, actor)
                created += 1
            except (ValidationError, TypeError) as exc:
                problems.append(f"row {n}: {exc}")
        return created, problems
