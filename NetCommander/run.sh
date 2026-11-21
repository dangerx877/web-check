#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
[ -d .venv ] || { echo "Run ./install.sh first."; exit 1; }
. .venv/bin/activate
exec python -m netcommander "$@"
