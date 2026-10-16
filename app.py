#!/usr/bin/env python3
"""Toshiba CIX Manager — local web app entry point.

Run on any laptop with stock Python 3 (no pip installs):

    python3 app.py                 # serve the UI on http://127.0.0.1:8765
    python3 app.py --port 9000     # pick a port
    python3 app.py --no-browser    # don't auto-open a browser

Then open the printed URL. Works offline: plug straight into the PBX voice-LAN
port (direct) or reach it over an RSM/ZeroTier (remote) — it is just SNMP to an
IP either way. Read-only; writes are stubbed pending the SET-protocol capture.

The importable code lives in the :mod:`toshiba_cix` package next to this file.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from toshiba_cix.launcher import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
