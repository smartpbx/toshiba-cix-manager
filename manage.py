#!/usr/bin/env python3
"""Toshiba CIX catalog backup / view / diff / restore — CLI shim.

Usage:
    python3 manage.py backup  <ip> [--out b.json] [--text b.txt]
    python3 manage.py view    <backup.json> [--program 200]
    python3 manage.py diff    <a.json> <b.json>
    python3 manage.py restore <backup.json> <ip> [--confirm]

Pure stdlib. ``backup`` is read-only; ``restore`` previews unless ``--confirm``
(and is gated by the write-enable flag). The real code lives in the importable
:mod:`toshiba_cix` package next to this file.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from toshiba_cix.manage_cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
