"""Snapshot-on-connect: read a CIX core-first, then the rest, with progress.

DESIGN_PLAN 5.1/11-P1: Connect starts a snapshot job that reads ``core`` first
— identity and the station/trunk programs a tech almost always wants — so the
Stations page opens in seconds, then walks the rest to a complete ``all``
snapshot saved automatically as *Snapshot on connect*. The two phases are what
make a remote site feel like a direct one.

:func:`read_snapshot` is that job's engine: pure orchestration over the already
tested read path (``backup.collect`` + ``enrich.build_program_views``), I/O
only through the injected ``client``. It reports progress through a
``report(done, total, message)`` callback (wired to the server's SSE
``job.progress`` channel) and hands each phase's :func:`enrich` views to an
``on_phase(views, phase)`` callback so the caller can populate a session working
copy incrementally — the core programs become browsable before the full walk
finishes. The return value is a cold-start-ready snapshot dict
(``identity`` + ``meta`` + the full ``program_views`` contract).

Read-only: every pass is GETNEXT. A transport failure on either phase degrades
to a partial snapshot plus a ``walk_error`` in ``meta`` rather than losing the
whole read.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import __version__
from .backup import build_backup, collect, read_identity
from .catalog import Catalog, load_catalog
from .enrich import build_program_views

# The core-first read: identity + stations (200/204/205/208/214/216) and the
# trunk block (300-329). These are the programs behind most site visits, so the
# Stations and Trunk pages open before the full walk completes (DESIGN_PLAN 5.1).
CORE_PROGRAM_NUMBERS = (
    "200", "201", "203", "204", "205", "206", "207", "208", "214", "216", "260",
    "103", "104", "105",
    "300", "301", "302", "303", "304", "305", "306", "307", "308", "309",
    "310", "311", "312", "313",
)


def core_program_keys(catalog: Catalog) -> list:
    """Catalog keys for the core-first read, in catalog order, de-duplicated."""
    out = []
    seen = set()
    for num in CORE_PROGRAM_NUMBERS:
        prog = catalog.program(num)
        if prog and prog.key not in seen:
            seen.add(prog.key)
            out.append(prog.key)
    return out


def read_snapshot(client, catalog: Catalog = None, *, report=None,
                  on_phase=None, site=None, transport=None, width: int = 10,
                  max_total: int = 500000) -> dict:
    """Read a CIX core-first then whole; return a cold-start snapshot dict.

    ``report(done, total, message)`` drives the UI progress bar; ``on_phase(
    program_views, phase)`` (``phase`` ∈ ``{"core", "all"}``) lets the caller
    ingest each phase's views into a working copy as they land. Both optional.

    Returns ``{identity, meta, program_views, backup}`` — ``program_views`` is
    the live render contract for the session working copy, and ``backup`` is the
    v2 ``toshiba-cix-backup`` document (raw values, hashes, provenance) the
    snapshot store persists. Both come from the one read, so there is no second
    walk."""
    catalog = catalog or load_catalog()
    all_keys = [p.key for p in catalog.programs.values()]
    total = len(all_keys)

    def _report(done, message):
        if report:
            report(done, total, message)

    identity = read_identity(client)
    _report(0, "Reading core programs (stations, trunks)…")

    core_keys = core_program_keys(catalog)
    core_pairs, core_err = collect(client, catalog, programs=core_keys,
                                   width=width, max_total=max_total)
    if on_phase:
        on_phase(build_program_views(core_pairs, catalog), "core")
    _report(len(core_keys),
             "Core ready — stations & trunks open. Reading the rest…")

    rest_keys = [k for k in all_keys if k not in set(core_keys)]
    rest_pairs, rest_err = collect(client, catalog, programs=rest_keys,
                                   width=width, max_total=max_total)

    all_pairs = core_pairs + rest_pairs
    views = build_program_views(all_pairs, catalog)
    if on_phase:
        on_phase(views, "all")
    _report(total, "Snapshot complete.")

    walk_error = core_err or rest_err
    meta = {
        "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_version": catalog.version,
        "tool_version": __version__,
        "source_ip": getattr(client, "host", None),
        "site": site,
        "scope": "all",
        "oids_read": len(all_pairs),
        "walk_error": walk_error,
    }
    doc = build_backup(all_pairs, catalog, meta={
        "swid": identity.get("swid"), "chassis_mac": identity.get("chassis_mac"),
        "site": site, "source_ip": getattr(client, "host", None),
        "scope": "all", "walk_error": walk_error, "transport": transport,
    }, snapshot={"kind": "snapshot", "transport": transport})
    return {"identity": identity, "meta": meta, "program_views": views,
            "backup": doc}


__all__ = ["CORE_PROGRAM_NUMBERS", "core_program_keys", "read_snapshot"]
