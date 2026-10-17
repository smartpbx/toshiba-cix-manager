"""Toshiba Strata CIX SNMP reader/decoder.

A dependency-free (pure-stdlib) reader for the Toshiba Strata CIX / CTX
enterprise SNMP MIB (``1.3.6.1.4.1.186.1.22``). It walks a CIX processor
over SNMPv1 (read-only, GET/GETNEXT — never SET) and decodes the
programming — stations, equipment, system numbering, network/FTP access —
into a structured dict plus a human-readable report.

Reverse-engineered from a live eManager ↔ CIX packet capture
(2026-10-14) and validated against a production CIX.

Public surface
--------------
    from toshiba_cix import CIXReader, SnmpV1, render_report

    reader = CIXReader(SnmpV1("192.168.254.253", "communityName"))
    doc = reader.read()               # structured dict (json-ready)
    text = render_report(doc)         # human-readable report

Everything is importable and I/O-injected (the SNMP client is passed in),
so the core slots into a Conduit backup/probe adapter without change.
"""

from __future__ import annotations

# Defined BEFORE the submodule imports below: backup.py does
# ``from . import __version__`` at import time, so the name must already exist
# on the package when that import runs.
__version__ = "2.4.2"

# NOTE: ``backup`` and ``restore`` are intentionally *not* re-exported as
# functions here — that would shadow the ``toshiba_cix.backup`` /
# ``toshiba_cix.restore`` submodules of the same name. Reach the live
# orchestrators as ``toshiba_cix.backup.backup`` / ``toshiba_cix.restore.restore``
# (that is how webapp and the CLI import them). The pure helpers are exported.
from .backup import build_backup, render_backup_text  # noqa: E402
from .catalog import Catalog, load_catalog  # noqa: E402
from .diff import diff_backups, render_diff_text  # noqa: E402
from .discover import discover_cix  # noqa: E402
from .report import render as render_report  # noqa: E402
from .restore import plan_restore  # noqa: E402
from .scan import CIXReader  # noqa: E402
from .snmp import SnmpError, SnmpV1, Value  # noqa: E402
# Export the ``writes_enabled`` *function*, not the ``WRITES_ENABLED`` value:
# re-exporting the value would freeze a snapshot of the master switch at package
# import time. Callers read the live flag via ``writes_enabled()``.
from .write import writes_enabled, CIXWriter, WriteError  # noqa: E402

__all__ = [
    "CIXReader", "SnmpV1", "SnmpError", "Value", "render_report",
    "discover_cix", "CIXWriter", "writes_enabled", "WriteError",
    "Catalog", "load_catalog",
    "build_backup", "render_backup_text",
    "diff_backups", "render_diff_text", "plan_restore",
]
