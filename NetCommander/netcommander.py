#!/usr/bin/env python3
"""Thin launcher kept for run.sh / run.bat. All code lives in the ``netcommander/`` package."""
import sys

from netcommander.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
