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
from .write import WriteOp

__all__ = [
    "resolve_program",
    "empty_program_view",
    "build_program_view",
    "list_rows",
    "get_row",
    "plan_row_update",
    "writable_fields",
    "HARD_EXCLUDE_PROGRAMS",
]

# Programs that are NEVER written from this tool (DESIGN_PLAN §9 layer 7). 116
# is the vendor image / block-load program; a SET there is a system-level
# operation, not a field edit.
HARD_EXCLUDE_PROGRAMS = frozenset({"116"})

# Catalog syntaxes whose native ASN.1 type is a plain integer. The capture only
# ever proved OCTET STRING for data writes (WRITE_FORMAT.md), so an integer
# field is written as its literal string (the proven wire form) and flagged
# ``wire_proven=False`` so the review can say the INTEGER form is catalog-derived.
_INTEGER_SYNTAXES = frozenset({
    "INTEGER", "INTEGER32", "ENUMERATEDINTEGER", "COUNTER", "COUNTER32",
    "COUNTER64", "GAUGE", "GAUGE32", "TIMETICKS", "UNSIGNED32",
})


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


def _cells_by_name(row: dict) -> dict:
    return {c.get("field_name"): c for c in (row.get("cells") or [])}


def writable_fields(program) -> set:
    """Field names a tech may edit on this program: ``access == 'rw'``, not a
    key/index column, not a hard-exclusion program. Pure — drives the editable
    record pane's field picking on the engine side (the UI reads the same from
    ``ui_schema``). ``program`` is a catalog :class:`Program`."""
    if program is None:
        return set()
    if getattr(program, "number", None) in HARD_EXCLUDE_PROGRAMS:
        return set()
    out = set()
    for f in program.fields:
        if f.get("access") == "rw" and not f.get("key"):
            out.add(f.get("name"))
    return out


def plan_row_update(row: dict, changes: dict, *, program=None,
                    program_number: str | None = None) -> list:
    """Plan the :class:`~toshiba_cix.write.WriteOp` list for editing one row — the
    generic form of ``CIXWriter.plan_station_update`` for all 186 programs
    (DESIGN_PLAN 5.5, 10.2). Pure: no network, no catalog read required.

    ``row`` is an enriched ``<row>`` (``{index, key, cells}``) — each cell
    already carries its exact instance ``oid``, ``syntax`` and ``access``, so a
    planned edit addresses the precise instance it was read from and no OID is
    ever invented. ``changes`` is ``{field_name: new_value}``. ``program`` (a
    catalog :class:`Program`, optional) supplies key columns and the program
    number for the hard-exclusion / key-column checks; without it those checks
    fall back to the per-cell ``access`` flag alone.

    Every op is returned — a field that cannot be written (read-only, key
    column, hard-exclusion program, or absent from the row so its write OID
    can't be derived) comes back non-sendable with an explanatory ``note``,
    so the review tells the tech *why* rather than silently dropping it.
    """
    cells = _cells_by_name(row)
    prog_num = program_number
    if prog_num is None and program is not None:
        prog_num = getattr(program, "number", None)
    key_fields = set()
    if program is not None:
        for f in program.fields:
            if f.get("key"):
                key_fields.add(f.get("name"))

    ops: list[WriteOp] = []
    for field, new_value in changes.items():
        cell = cells.get(field)
        old_value = None
        target_oid = None
        native = ""
        column = None
        if cell is not None:
            old_value = cell.get("display_value")
            if (old_value is None or old_value == "") and cell.get("raw_value") is not None:
                old_value = str(cell.get("raw_value"))
            target_oid = cell.get("oid")
            native = (cell.get("syntax") or "").upper()
            column = cell.get("col")

        note = ""
        sendable_oid = target_oid
        if prog_num in HARD_EXCLUDE_PROGRAMS:
            note = (f"program {prog_num} is a hard exclusion — never written "
                    "(DESIGN_PLAN §9 layer 7)")
            sendable_oid = None
        elif field in key_fields:
            note = "key / index column — identifies the row, never written"
            sendable_oid = None
        elif cell is None:
            note = ("field is not present on this row; its write OID cannot be "
                    "derived from a read (row-create is unproven)")
            sendable_oid = None
        elif cell.get("access") == "r":
            note = "read-only field — never written"
            sendable_oid = None

        is_int = native in _INTEGER_SYNTAXES
        native_wire = "INTEGER" if is_int else "OCTET STRING"
        # Every data field is written as its literal string (OCTET STRING) — the
        # only data wire type the capture proved. An INTEGER-native field keeps
        # that proven encoding but is flagged catalog-derived so the operator
        # sees it (layer 8; "default risky toggles OFF").
        if is_int and note == "":
            note = ("catalog-derived wire type: native INTEGER written as the "
                    "literal OCTET STRING (the proven wire form)")

        ops.append(WriteOp(
            field=field, label=field,
            new_value="" if new_value is None else str(new_value),
            old_value=(str(old_value) if old_value is not None else None),
            target_oid=sendable_oid, program=prog_num, column=column,
            ber_type="OCTET STRING", native_wire=native_wire,
            wire_proven=not is_int, note=note,
        ))
    return ops
