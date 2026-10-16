#!/usr/bin/env python3
"""Toshiba Strata CIX SNMP reader — CLI shim.

Usage:
    python3 reader.py <ip> [--community communityName] [--json out.json]
                           [--report out.txt]

Pure stdlib; runs on a bare Raspberry Pi RSM. The real code lives in the
importable :mod:`toshiba_cix` package next to this file.
"""

from __future__ import annotations

import os
import sys

# Allow running as `python3 reader.py ...` from anywhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from toshiba_cix.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
