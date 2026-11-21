"""Golden-file tests: every fixtures/parsers/<key>__<case>.txt must parse to its .expected.json."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from netcommander.parsers import RAW_PARSERS

FIX = Path(__file__).parent / "fixtures" / "parsers"
CASES = sorted(FIX.glob("*.txt"))


def test_fixtures_exist():
    assert len(CASES) >= 6


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_fixture_parses_to_expected(path):
    key = path.stem.split("__")[0]
    assert key in RAW_PARSERS, f"unknown parser key {key!r}"
    expected = json.loads(path.with_suffix(".expected.json").read_text())
    assert RAW_PARSERS[key](path.read_text()) == expected


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_fixture_with_windows_line_endings_parses_identically(path):
    key = path.stem.split("__")[0]
    crlf = path.read_text().replace("\n", "\r\n")
    assert RAW_PARSERS[key](crlf) == RAW_PARSERS[key](path.read_text())
