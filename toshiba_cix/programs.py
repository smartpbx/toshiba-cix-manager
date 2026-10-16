"""Generic single-program read: the engine half of the P1 browse app.

eManager had 208 hand-written pages. Switchroom renders all 186 programs from
one data file (``data/ui_schema.json``) and reads each one through the same two
functions here, so a new program is a catalog entry, never code (DESIGN_PLAN
3.3, 10.2):

* :func:`list_rows` — read **one** program's table over SNMP (read-only
  GETNEXT) and return it as a single ``<program_view>`` — the exact per-program
  shape :mod:`toshiba_cix.enrich` emits for a full backup, so the grid renderer
  is identical whether a program arrives from a snapshot or a scoped re-read.
* :func:`get_row` — read **one** row (one instance) of a program with a
  targeted GET of just that row's field OIDs (the record pane's ``⟳`` re-read),
  cheap even on a 1,000-station 200.

Both are I/O-injected (``client`` is any object with ``get`` / ``bulk_walk``)
and lean on the pure assembly in :func:`toshiba_cix.enrich.build_program_views`,
so the whole module is unit-tested offline against a fake client. Nothing here
writes — the two-phase plan→apply write path (``plan_row_update``) lands in P2.

A ``<program_view>`` always carries its catalog metadata (``program_number``,
``program_name``, ``menu_area``, ``menu_path``, ``label``) and never a bare OID
for a cataloged field; a program that returned no rows comes back as an empty
view (``row_count == 0``) rather than disappearing, so the UI can say "no rows
in this snapshot" instead of greying the page.
"""

from __future__ import annotations

from .backup import collect
from .catalog import Catalog, load_catalog
from .decode import MISSING
from .enrich import build_program_views

__all__ = [
    "resolve_program",
    "empty_program_view",
    "build_program_view",
    "list_rows",
    "get_row",
]


def resolve_program(catalog: Catalog, prog):
    """The catalog :class:`Program` for a key / number / name, or ``None``.

    ``prog`` may already be a resolved program (it is returned unchanged) or any
    identifier :meth:`Catalog.program` accepts (``"200StationAssign"``, ``"200"``,
    ``"StationAssign"``).
    """
    if prog is None:
        return None
    if hasattr(prog, "key") and hasattr(prog, "fields"):
        return prog
    return catalog.program(prog)


def empty_program_view(catalog: Catalog, prog_key: str) -> dict:
    """The ``<program_view>`` for a program that returned no cells.

    Same keys a populated view has (so the renderer needs no special case), with
    ``row_count == 0`` and ``rows == []``. Raises ``KeyError`` if the key is not
    in the catalog — callers resolve the program first.
    """
    prog = catalog.programs[prog_key]
    info = catalog.menu_info(prog_key)
    return {
        "catalog_key": prog_key,
        "program_number": prog.number,
        "program_name": prog.name,
        "menu_area": info["area"],
        "menu_path": info["menu_path"],
        "label": info["label"],
        "group_oid": prog.group_oid,
        "row_count": 0,
        "rows": [],
    }


def build_program_view(catalog: Catalog, pairs, prog_key: str) -> dict:
    """Assemble the single ``<program_view>`` for ``prog_key`` from ``pairs``. Pure.

    Reuses :func:`toshiba_cix.enrich.build_program_views` (so labels, enum
    captions, columns and the five required cell keys are identical to a full
    read) and extracts the one program. If that program contributed no cells —
    an empty table, or ``pairs`` that attributed elsewhere — an empty view is
    synthesised so the program never silently vanishes.
    """
    views = build_program_views(pairs, catalog)
    for pv in views["programs"]:
        if pv["catalog_key"] == prog_key:
            return pv
    return empty_program_view(catalog, prog_key)


def list_rows(client, catalog: Catalog, prog, *, width: int = 10,
              max_total: int = 500000):
    """Read one program's table over SNMP. Returns ``(program_view, error)``.

    Read-only (GETNEXT only, via :func:`toshiba_cix.backup.collect`). A transport
    failure degrades to whatever was collected plus an ``error`` string rather
    than losing a partial read — the same contract the full backup uses. Raises
    ``ValueError`` if ``prog`` is not a program this catalog knows.
    """
    catalog = catalog or load_catalog()
    program = resolve_program(catalog, prog)
    if program is None:
        raise ValueError("unknown program %r" % (prog,))
    pairs, error = collect(client, catalog, programs=[program.key],
                           width=width, max_total=max_total)
    return build_program_view(catalog, pairs, program.key), error


def _usable(value) -> bool:
    """A GET var-bind worth keeping: a present value, not a missing sentinel."""
    if value is None:
        return False
    if getattr(value, "is_missing", False):
        return False
    if getattr(value, "kind", None) in ("endofmib", "nosuchobject",
                                        "nosuchinstance"):
        return False
    return True


def get_row(client, catalog: Catalog, prog, index, *, as_view: bool = False):
    """Read one row (one instance) of a program with a targeted GET.

    ``index`` is the instance tail exactly as a row carries it (``"2"``,
    ``"1.3.50.48.48"``, or ``"0"`` / ``""`` for a scalar Form program). Every
    field's instance OID is built with :meth:`Catalog.instance_oid` and GET in
    one request, so this is cheap even on a program with a thousand rows.

    Returns ``(row, error)`` where ``row`` is the ``<row>`` dict
    (``{"index", "key", "cells"}``) or ``None`` when that instance holds no
    value (every field missing → the row does not exist). With ``as_view=True``
    the single-row ``<program_view>`` is returned in place of the bare row, for
    callers that want the program metadata alongside it.
    """
    catalog = catalog or load_catalog()
    program = resolve_program(catalog, prog)
    if program is None:
        raise ValueError("unknown program %r" % (prog,))

    oids = [catalog.instance_oid(fld, index)
            for fld in program.fields if fld.get("oid")]
    error = None
    pairs = []
    if oids:
        try:
            vbs = client.get(oids)
        except Exception as exc:  # noqa: BLE001 — SnmpError or transport; degrade
            error = str(exc)
            vbs = []
        pairs = [(vb.oid, vb.value) for vb in vbs if _usable(vb.value)]

    view = build_program_view(catalog, pairs, program.key)
    if as_view:
        return view, error
    want = str(index) if index is not None else "0"
    for row in view["rows"]:
        if row["index"] == want or (want in ("", "0") and row["index"] in ("", "0")):
            return row, error
    # A single scoped GET attributes to exactly one instance; if any cell
    # survived it is this row regardless of how the tail normalised.
    if view["rows"]:
        return view["rows"][0], error
    return None, error
