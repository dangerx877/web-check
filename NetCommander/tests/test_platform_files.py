"""Guards for the cross-OS launcher files (cheap, catches the classic 'works on my OS' regressions)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(not (ROOT / "pyproject.toml").exists(), reason="not a source checkout")


@pytest.mark.parametrize("name", ["install.bat", "run.bat"])
def test_batch_files_use_crlf(name):
    raw = (ROOT / name).read_bytes()
    assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")


@pytest.mark.parametrize("name", ["install.sh", "run.sh"])
def test_shell_scripts_are_lf_with_shebang(name):
    raw = (ROOT / name).read_bytes()
    assert raw.startswith(b"#!/usr/bin/env bash\n") and b"\r" not in raw


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.parametrize("name", ["install.sh", "run.sh"])
def test_shell_scripts_are_executable(name):
    assert os.access(ROOT / name, os.X_OK)


@pytest.mark.skipif(sys.platform == "win32", reason="needs bash")
@pytest.mark.parametrize("name", ["install.sh", "run.sh"])
def test_shell_scripts_parse(name):
    assert subprocess.run(["bash", "-n", str(ROOT / name)], capture_output=True).returncode == 0


def test_gitattributes_pins_line_endings():
    text = (ROOT / ".gitattributes").read_text()
    assert "*.sh text eol=lf" in text and "*.bat text eol=crlf" in text


def test_windows_installer_falls_back_to_py_launcher():
    assert "py -3" in (ROOT / "install.bat").read_text()
