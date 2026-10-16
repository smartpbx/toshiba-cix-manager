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
from .backup import build_backup, collect, collect_program, read_identity
from .catalog import Catalog, load_catalog
from .enrich import build_program_views

# Per-program budgets for the background "rest" walk (DESIGN_PLAN 5.1). Each
# non-core program is read on its own with a wall-clock timeout and an OID cap
# so one slow / huge / non-terminating subtree cannot stall the whole snapshot
# (the bug this fixes): a program over budget is recorded as a partial read and
# the walk moves on. Generous enough that every legitimate large table on a
# production CIX (LCR route plans, system speed dial, PAD table, call forward)
# completes; tight enough that a genuinely stuck program costs seconds, not the
# ten-minute silent stall it used to.
PROGRAM_TIMEOUT_SECS = 45.0
PROGRAM_MAX_OIDS = 20000

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


def _core_status(catalog: Catalog, key: str, present: bool,
                 core_err: str | None) -> dict:
    """Per-program status for a core-phase program (read concurrently).

    The core phase is one fast batched walk, so a program's outcome is read off
    the result: data → ``ok``, none → ``empty`` (or ``error`` if the batched
    walk itself failed). Same shape as :func:`backup.collect_program` emits."""
    prog = catalog.program(key)
    if present:
        outcome, error = "ok", None
    elif core_err:
        outcome, error = "error", core_err
    else:
        outcome, error = "empty", None
    return {"key": key,
            "number": prog.number if prog is not None else None,
            "name": prog.name if prog is not None else key,
            "oids": 0, "rounds": 0, "elapsed": None,
            "outcome": outcome, "error": error}


def read_snapshot(client, catalog: Catalog = None, *, report=None,
                  on_phase=None, on_program=None, site=None, transport=None,
                  width: int = 10, max_total: int = 500000,
                  program_timeout: float = PROGRAM_TIMEOUT_SECS,
                  program_max_oids: int = PROGRAM_MAX_OIDS) -> dict:
    """Read a CIX core-first then whole; return a cold-start snapshot dict.

    ``report(done, total, message, detail=None)`` drives the UI progress bar
    (``detail`` is an optional dict with the current program, cumulative OIDs
    and per-program errors — additive, so a three-arg callback still works);
    ``on_phase(program_views, phase)`` (``phase`` ∈ ``{"core", "all"}``) lets
    the caller ingest each phase's views as they land; ``on_program(status)``
    fires once per program with its :func:`backup.collect_program` status so
    the caller can track read progress and failures live. All optional.

    The whole ("all") phase reads every non-core program **one at a time**, each
    bounded by ``program_timeout`` (wall clock) and ``program_max_oids`` (OID
    cap), so a single slow / huge / non-terminating program is recorded as a
    partial read and skipped instead of stalling the entire snapshot.

    Returns ``{identity, meta, program_views, backup, program_status}`` —
    ``program_views`` is the live render contract for the session working copy,
    ``backup`` is the v2 ``toshiba-cix-backup`` document the snapshot store
    persists, and ``program_status`` maps every program key to how its read
    ended. ``meta.program_problems`` carries just the non-clean ones so a saved
    snapshot shows which programs failed even on cold start."""
    catalog = catalog or load_catalog()
    all_keys = [p.key for p in catalog.programs.values()]
    total = len(all_keys)
    program_status: dict[str, dict] = {}

    def _report(done, message, detail=None):
        if not report:
            return
        try:
            report(done, total, message, detail)
        except TypeError:
            # A pre-existing three-arg report(done, total, message) callback.
            report(done, total, message)

    def _note(status):
        program_status[status["key"]] = status
        if on_program:
            on_program(status)

    identity = read_identity(client)
    _report(0, "Reading core programs (stations, trunks)…")

    # -- core phase: one fast batched walk so stations/trunks open quickly ----
    core_keys = core_program_keys(catalog)
    core_set = set(core_keys)
    core_pairs, core_err = collect(client, catalog, programs=core_keys,
                                   width=width, max_total=max_total)
    core_views = build_program_views(core_pairs, catalog)
    present = {pv["catalog_key"] for pv in core_views.get("programs", [])}

    # A single dropped packet makes the one concurrent core walk raise, which
    # would otherwise fail-mark the whole station/trunk set at once. If that
    # happened, re-read just the core programs that produced nothing, one at a
    # time (each bounded) — the happy path still does no extra work.
    core_recovery: dict[str, dict] = {}
    if core_err:
        extra: list = []
        for key in core_keys:
            if key in present:
                continue
            pairs, st = collect_program(client, catalog, key, width=width,
                                        max_oids=program_max_oids,
                                        max_seconds=program_timeout)
            core_recovery[key] = st
            extra.extend(pairs)
        if extra:
            core_pairs = core_pairs + extra
            core_views = build_program_views(core_pairs, catalog)
            present = {pv["catalog_key"] for pv in core_views.get("programs", [])}

    if on_phase:
        on_phase(core_views, "core")
    for key in core_keys:
        if key in present:
            _note(_core_status(catalog, key, True, None))
        elif key in core_recovery:
            _note(core_recovery[key])          # the per-program retry's outcome
        else:
            _note(_core_status(catalog, key, False, core_err))
    _report(len(core_keys),
            "Core ready — stations & trunks open. Reading the rest…")

    # -- all phase: the rest, one program at a time, each bounded ------------
    rest_keys = [k for k in all_keys if k not in core_set]
    rest_total = len(rest_keys)
    rest_pairs: list = []
    done = len(core_keys)
    cum_oids = len(core_pairs)
    for n, key in enumerate(rest_keys, start=1):
        prog = catalog.program(key)
        label = f"{prog.number} {prog.name}".strip() if prog and prog.number \
            else (prog.name if prog else key)
        _report(done, f"Reading {label}… (program {n} of {rest_total})",
                {"phase": "all", "program": prog.number if prog else None,
                 "program_key": key,
                 "program_name": prog.name if prog else key,
                 "index": n, "rest_total": rest_total, "oids": cum_oids})
        pairs, status = collect_program(
            client, catalog, key, width=width, max_oids=program_max_oids,
            max_seconds=program_timeout)
        rest_pairs.extend(pairs)
        cum_oids += status["oids"]
        done += 1
        _note(status)

    all_pairs = core_pairs + rest_pairs
    views = build_program_views(all_pairs, catalog)
    if on_phase:
        on_phase(views, "all")

    problems = [s for s in program_status.values()
                if s["outcome"] in ("timeout", "capped", "error")]
    _report(total,
            "Snapshot complete." if not problems else
            f"Snapshot complete — {len(problems)} program(s) did not read fully.",
            {"phase": "all", "oids": cum_oids, "problems": len(problems)})

    # walk_error reflects the FINAL per-program outcomes: a transient blip that
    # the per-program recovery fully healed leaves no problems and no warning.
    walk_error = None
    if problems:
        walk_error = (f"{len(problems)} program(s) did not read completely "
                      "(see the Problems panel)")
    meta = {
        "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_version": catalog.version,
        "tool_version": __version__,
        "source_ip": getattr(client, "host", None),
        "site": site,
        "scope": "all",
        "oids_read": len(all_pairs),
        "walk_error": walk_error,
        "program_problems": problems,
    }
    doc = build_backup(all_pairs, catalog, meta={
        "swid": identity.get("swid"), "chassis_mac": identity.get("chassis_mac"),
        "site": site, "source_ip": getattr(client, "host", None),
        "scope": "all", "walk_error": walk_error, "transport": transport,
        "program_problems": problems,
    }, snapshot={"kind": "snapshot", "transport": transport})
    return {"identity": identity, "meta": meta, "program_views": views,
            "backup": doc, "program_status": program_status}


__all__ = ["CORE_PROGRAM_NUMBERS", "PROGRAM_TIMEOUT_SECS", "PROGRAM_MAX_OIDS",
           "core_program_keys", "read_snapshot"]
