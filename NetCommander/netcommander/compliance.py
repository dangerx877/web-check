"""Network-wide configuration compliance.

A *policy* is a list of rules checked against a device's config text (usually the latest saved
snapshot, so a sweep needs no SSH). Rules are plain data (JSON-serialisable) so they can be
stored, reviewed and shared:

    {"id": "ntp", "description": "NTP configured", "type": "must_contain", "pattern": "ntp server",
     "severity": "high", "device_types": ["cisco_ios"]}

Types: ``must_contain`` / ``must_not_contain`` (regex, multiline) and ``must_match_count``
(``min``/``max`` occurrences). ``device_types`` optionally scopes a rule.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
RULE_TYPES = ("must_contain", "must_not_contain", "must_match_count")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    type: str
    pattern: str
    description: str = ""
    severity: str = "medium"
    device_types: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    _rx: Any = field(init=False, repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self.type not in RULE_TYPES:
            raise PolicyError(f"rule {self.id!r}: unknown type {self.type!r}")
        if self.severity not in SEVERITIES:
            raise PolicyError(f"rule {self.id!r}: severity must be one of {SEVERITIES}")
        try:
            object.__setattr__(self, "_rx", re.compile(self.pattern, re.MULTILINE | re.IGNORECASE))
        except re.error as exc:
            raise PolicyError(f"rule {self.id!r}: bad regex ({exc})") from None
        if self.type == "must_match_count" and self.min is None and self.max is None:
            raise PolicyError(f"rule {self.id!r}: must_match_count needs min and/or max")

    def applies_to(self, device_type: str | None) -> bool:
        return not self.device_types or (device_type or "") in self.device_types

    def check(self, config: str) -> tuple[bool, str]:
        n = len(self._rx.findall(config))
        if self.type == "must_contain":
            return n > 0, "" if n else f"missing: /{self.pattern}/"
        if self.type == "must_not_contain":
            return n == 0, "" if n == 0 else f"forbidden pattern present ({n}×): /{self.pattern}/"
        lo, hi = self.min, self.max
        ok = (lo is None or n >= lo) and (hi is None or n <= hi)
        return ok, "" if ok else f"found {n}, expected min={lo} max={hi}: /{self.pattern}/"


def load_policy(source: str | Path | list[Mapping[str, Any]]) -> list[Rule]:
    """Accepts a path to a JSON file, or an already-parsed list of dicts."""
    if isinstance(source, (str, Path)):
        try:
            data = json.loads(Path(source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise PolicyError(f"cannot read policy {source}: {exc}") from None
    else:
        data = source
    if isinstance(data, dict):
        data = data.get("rules", [])
    if not isinstance(data, list):
        raise PolicyError("policy must be a list of rules")
    rules, seen = [], set()
    for i, d in enumerate(data, 1):
        if not isinstance(d, Mapping) or not d.get("id") or "type" not in d or "pattern" not in d:
            raise PolicyError(f"rule #{i}: needs id, type and pattern")
        if d["id"] in seen:
            raise PolicyError(f"duplicate rule id {d['id']!r}")
        seen.add(d["id"])
        rules.append(Rule(
            id=str(d["id"]), type=str(d["type"]), pattern=str(d["pattern"]),
            description=str(d.get("description", "")), severity=str(d.get("severity", "medium")),
            device_types=tuple(d.get("device_types", ()) or ()),
            min=d.get("min"), max=d.get("max"),
        ))
    return rules


@dataclass
class Finding:
    device: str
    rule_id: str
    severity: str
    description: str
    detail: str


@dataclass
class DeviceResult:
    device: str
    checked: int = 0
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    @property
    def compliant(self) -> bool:
        return not self.error and not self.findings


def evaluate(device: str, device_type: str | None, config: str, rules: list[Rule]) -> DeviceResult:
    res = DeviceResult(device)
    for r in rules:
        if not r.applies_to(device_type):
            continue
        res.checked += 1
        ok, detail = r.check(config)
        if not ok:
            res.findings.append(Finding(device, r.id, r.severity, r.description, detail))
    return res


def run_compliance(
    devices: Mapping[str, Mapping[str, Any]],
    rules: list[Rule],
    get_config: Callable[[str], str],
    workers: int = 1,
) -> list[DeviceResult]:
    """``get_config(name)`` returns config text or raises (e.g. no snapshot yet → reported, not fatal).
    ``workers`` > 1 fetches in parallel (useful for live checks). Results stay sorted by device name."""
    def one(name: str) -> DeviceResult:
        try:
            cfg = get_config(name)
        except Exception as exc:
            return DeviceResult(name, error=str(exc) or type(exc).__name__)
        return evaluate(name, devices[name].get("device_type"), cfg, rules)

    names = sorted(devices)
    if workers <= 1 or len(names) <= 1:
        return [one(n) for n in names]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(workers, len(names))) as pool:
        return list(pool.map(one, names))


def summarize(results: list[DeviceResult]) -> dict[str, Any]:
    total = len(results)
    good = sum(r.compliant for r in results)
    by_sev = {s: 0 for s in SEVERITIES}
    for r in results:
        for f in r.findings:
            by_sev[f.severity] += 1
    return {"devices": total, "compliant": good, "non_compliant": sum(1 for r in results if r.findings),
            "errors": sum(1 for r in results if r.error), "findings_by_severity": by_sev,
            "score": round(100 * good / total, 1) if total else 100.0}


def report_text(results: list[DeviceResult]) -> str:
    s = summarize(results)
    lines = [f"Compliance: {s['compliant']}/{s['devices']} devices compliant ({s['score']}%), "
             f"{s['errors']} unchecked", ""]
    for r in results:
        if r.error:
            lines.append(f"? {r.device}: not checked — {r.error}")
        elif r.findings:
            lines.append(f"✗ {r.device}: {len(r.findings)} finding(s) of {r.checked} rules")
            for f in sorted(r.findings, key=lambda f: -SEVERITIES.index(f.severity)):
                lines.append(f"    [{f.severity.upper()}] {f.rule_id}: {f.detail}"
                             + (f"  — {f.description}" if f.description else ""))
        else:
            lines.append(f"✓ {r.device}: all {r.checked} rules pass")
    return "\n".join(lines)


def report_csv_rows(results: list[DeviceResult]) -> list[list[str]]:
    rows = [["device", "status", "rule", "severity", "detail"]]
    for r in results:
        if r.error:
            rows.append([r.device, "unchecked", "", "", r.error])
        elif not r.findings:
            rows.append([r.device, "compliant", "", "", ""])
        for f in r.findings:
            rows.append([r.device, "non-compliant", f.rule_id, f.severity, f.detail])
    return rows
