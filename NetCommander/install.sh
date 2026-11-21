#!/usr/bin/env bash
# Uptime Funk (formerly NetCommander) installer for Linux / macOS
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || { echo "Python 3.9+ not found. See docs/INSTALL.md"; exit 1; }
"$PY" -c 'import sys; sys.exit(sys.version_info < (3,9))' || { echo "Python 3.9 or newer is required."; exit 1; }
"$PY" -c 'import tkinter' 2>/dev/null || {
  echo "Python's Tk support is missing. Install it first:"
  echo "  Debian/Ubuntu/Mint: sudo apt install python3-tk"
  echo "  Fedora/RHEL:        sudo dnf install python3-tkinter"
  echo "  Arch/Manjaro:       sudo pacman -S tk"
  echo "  openSUSE:           sudo zypper install python3-tk"
  echo "  Alpine:             sudo apk add py3-tkinter"
  echo "  macOS (brew):       brew install python-tk"
  exit 1; }
"$PY" -m venv .venv || { echo "Could not create a virtual environment (Debian/Ubuntu: sudo apt install python3-venv)."; exit 1; }
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
# Installs the `netcommander` console command too:
pip install -e .
echo
echo "Done. Start the app with:  ./run.sh   (or: .venv/bin/netcommander)"
echo "Optional SNMPv3 monitoring:  .venv/bin/pip install 'pysnmp>=6'"
