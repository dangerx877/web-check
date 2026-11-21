"""Seeded randomized property tests (no extra dependency; deterministic, so failures reproduce)."""
from __future__ import annotations

import random
import string

import pytest

from netcommander import monitors, templates
from netcommander.deploy import plan_digest
from netcommander.parsers import RAW_PARSERS
from netcommander.redact import redact_secrets
from netcommander.security import safe_filename
from netcommander.utils import parse_host_port

RNG = random.Random(20261120)
ALPHABET = string.printable + "éß漢字‮\x00"


def rand_text(n=60):
    return "".join(RNG.choice(ALPHABET) for _ in range(RNG.randint(0, n)))


@pytest.mark.parametrize("_", range(300))
def test_safe_filename_is_always_a_single_safe_component(_):
    out = safe_filename(rand_text())
    assert out and "/" not in out and "\\" not in out and "\x00" not in out and out not in (".", "..")
    assert not out.endswith((" ", "."))
    assert safe_filename(out) == out                                  # idempotent


@pytest.mark.parametrize("_", range(200))
def test_redaction_is_idempotent_and_never_raises(_):
    t = rand_text(200)
    once = redact_secrets(t)
    assert redact_secrets(once) == once


@pytest.mark.parametrize("key", sorted(RAW_PARSERS))
def test_parsers_never_raise_on_garbage(key):
    for _ in range(150):
        out = RAW_PARSERS[key](rand_text(400))
        assert isinstance(out, list) and all(isinstance(r, dict) and r.get("neighbor") for r in out)


@pytest.mark.parametrize("_", range(200))
def test_parse_host_port_roundtrip_or_clean_error(_):
    host = RNG.choice(["10.0.0.1", "router.lab", "R1", "fe80::1", "2001:db8::2"])
    port = RNG.choice([None, 22, 2222, 65535, 0, 70000])
    text = host if port is None else (f"[{host}]:{port}" if ":" in host else f"{host}:{port}")
    try:
        h, p = parse_host_port(text)
    except ValueError:
        assert port in (0, 70000)                                    # only out-of-range ports are rejected
        return
    assert h == host and p == port


@pytest.mark.parametrize("_", range(200))
def test_template_render_never_executes_or_crashes(_):
    tpl = "".join(RNG.choice(["{{a}}", "{{b|x}}", "{{ c }}", "text ", "{{", "}}", "\n", rand_text(5)]) for _ in range(12))
    try:
        out = templates.render(tpl, {"a": "1", "c": "3"})
    except templates.TemplateError:
        return
    assert "{{a}}" not in out and "{{ c }}" not in out


@pytest.mark.parametrize("_", range(200))
def test_counter_rate_is_never_negative(_):
    bits = RNG.choice([32, 64])
    a, b = RNG.randrange(2 ** bits), RNG.randrange(2 ** bits)
    r = monitors.counter_rate((0.0, float(a)), (RNG.uniform(0.1, 60), float(b)), bits)
    assert r is None or r >= 0


@pytest.mark.parametrize("_", range(100))
def test_plan_digest_is_order_independent_for_devices_but_not_for_commands(_):
    cmds = {f"R{i}": [rand_text(10) for _ in range(RNG.randint(1, 3))] for i in range(RNG.randint(1, 5))}
    stages = [list(cmds)]
    shuffled = dict(RNG.sample(sorted(cmds.items()), len(cmds)))
    assert plan_digest(cmds, stages) == plan_digest(shuffled, stages)
    first = next(iter(cmds))
    changed = {**cmds, first: cmds[first] + ["extra"]}
    assert plan_digest(changed, stages) != plan_digest(cmds, stages)
