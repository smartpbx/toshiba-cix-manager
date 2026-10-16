"""Vendored data loader for the voicemail modules.

Mirrors ``catalog._load_data_text`` (base64-embedded global in the single-file
build → PyInstaller ``_MEIPASS`` bundle → packaged ``data/``), degrading
gracefully: a build that forgot a sidecar still runs, just without it. The
embedded-global names (``EMBEDDED_VM_CATALOG_JSON`` etc.) are injected by
``build_standalone.py`` so the amalgam is self-contained offline.
"""

from __future__ import annotations

import os
import sys
from typing import Optional


def _candidate_paths(filename: str):
    paths = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        paths.append(os.path.join(meipass, "toshiba_cix", "data", filename))
        paths.append(os.path.join(meipass, "data", filename))
        paths.append(os.path.join(meipass, filename))
    here = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(here, "data", filename))
    return paths


def load_vm_data_text(filename: str, embedded_global: str) -> Optional[str]:
    """Return a vendored ``data/<filename>`` text, or ``None`` if unavailable."""
    embedded = globals().get(embedded_global)
    if embedded:
        return embedded
    for path in _candidate_paths(filename):
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    return fh.read()
            except OSError:
                return None
    return None


__all__ = ["load_vm_data_text"]
