"""Catalog-driven enrichment: turn a raw SNMP walk into named, menu-grouped
program views — the stable JSON contract the web UI / React frontend consume.

The reverse-engineering already named every field (186 programs, 2366 fields,
787 enumerated with value labels) and recorded how eManager groups each program
into a menu area. This module is the thin, **pure** layer that wires that model
onto the bytes a CIX returns, so nothing renders as a bare OID for any cataloged
field.

The contract (``build_program_views`` / ``program_views_from_backup`` both emit
exactly this shape; keep it stable)::

    {
      "programs": [ <program_view>, ... ],   # every cataloged program that
                                             #   returned data, menu-ordered
      "menu_areas": [                        # the same programs grouped by the
        {"area": "Trunk",                    #   eManager menu area
         "programs": ["300TrunkAssign", ...],
         "row_count": N, "cell_count": N}, ...
      ],
      "feature_views": [                     # curated high-value groupings
        {"key": "trunks", "title": "Incoming lines, CO trunks & DID",
         "programs": ["300TrunkAssign", ...], "present": true}, ...
      ],
      "uncataloged": [ {"oid": "...", "raw_value": ...}, ... ],  # genuinely
                                             #   outside the catalog (should be
                                             #   rare); the only bare OIDs left
      "stats": {"programs": N, "rows": N, "cells": N,
                "named_cells": N, "raw_oid_cells": 0, "uncataloged": N}
    }

    <program_view> = {
      "catalog_key":   "300TrunkAssign",     # the only stable program id
      "program_number":"300",                # may be null (31 programs)
      "program_name":  "TrunkAssign",
      "menu_area":     "Trunk",
      "menu_path":     "Trunk - Trunk Assignment - Basic (300,301*)",
      "label":         "300 Trunk Assign",   # friendly eManager label
      "group_oid":     "1.3.6.1.4.1.186.1.22.3.300",
      "row_count":     N,
      "rows": [ <row>, ... ]
    }

    <row>  = {"index": "1", "key": "1", "cells": [ <cell>, ... ]}
    <cell> = {"col": 1, "field_name": "trunkNo",
              "oid": "1.3.6.1.4.1.186.1.22.3.300.1.1.1.1",
              "raw_value": 7, "display_value": "7",
              "syntax": "INTEGER", "access": "rw",
              "is_enum": false, "is_secret": false}

``raw_value`` is the value as read (int / str / the ``<MISSING>`` sentinel);
``display_value`` is the human string — the enum label for an enumerated field,
else the formatted scalar. The required five keys per cell are
``col, field_name, oid, raw_value, display_value``; the rest are additive.
"""

from __future__ import annotations

import re

from .catalog import MENU_AREA_ORDER, Catalog
from .decode import ENTERPRISE_ROOT, MISSING, decode_value, parse_row_index

# OIDs the catalog does not model but the reader already surfaces in their own
# dedicated views: the system-identity scalars (.7 → System / Overview), the
# equipment table (.1.1.1 → Equipment) and the live DN directory (.3.1200 →
# Stations). They are deliberately kept OUT of ``uncataloged`` so the Programs
# tab is not flooded with hundreds of directory rows shown elsewhere.
_LEGACY_PREFIXES = (
    f"{ENTERPRISE_ROOT}.7",
    f"{ENTERPRISE_ROOT}.1.1.1",
    f"{ENTERPRISE_ROOT}.3.1200",
)


def _handled_elsewhere(oid: str) -> bool:
    return any(oid == p or oid.startswith(p + ".") for p in _LEGACY_PREFIXES)

# Field names whose value is a live secret the frontend may want to mask. The
# value is still returned (this tool deliberately surfaces credentials); the
# flag is advisory. ``passw`` catches ftpPassWord / password / passwd.
_SECRET_RE = re.compile(r"(passw|pwd|secret)", re.IGNORECASE)


# --------------------------------------------------------------------------
# curated feature groupings (eManager program numbers; filtered to the catalog)
# --------------------------------------------------------------------------
FEATURE_GROUPS = [
    {"key": "trunks", "title": "Incoming lines, CO trunks & DID",
     "numbers": ["300", "301", "302", "303", "304", "305", "306", "307",
                 "308", "309", "312", "316", "317", "318", "320", "164",
                 "326", "327", "328", "329"]},
    {"key": "groups", "title": "Hunt, pilot & call groups",
     "numbers": ["209", "218", "540", "541", "210", "517", "519", "502",
                 "503", "404"]},
    {"key": "phantom", "title": "Phantom DNs",
     "numbers": ["206"]},
    {"key": "voicemail", "title": "Voicemail & VMID ports",
     "numbers": ["579", "580"]},
    {"key": "stations", "title": "Stations, keys & COS",
     "numbers": ["200", "204", "205", "207", "214", "220", "103"]},
    {"key": "licensing", "title": "Licensing & entitlements",
     "keys": ["licenseControl"]},
]


def _resolve_group(catalog: Catalog, group: dict) -> list[str]:
    """Catalog keys for a feature group, in a stable order, catalog-filtered."""
    out: list[str] = []
    seen: set[str] = set()
    for num in group.get("numbers", []):
        p = catalog.program(num)
        if p and p.key not in seen:
            seen.add(p.key)
            out.append(p.key)
    for key in group.get("keys", []):
        p = catalog.program(key)
        if p and p.key not in seen:
            seen.add(p.key)
            out.append(p.key)
    return out


# --------------------------------------------------------------------------
# scan scope → the programs a walk should cover (used by scan.CIXReader)
# --------------------------------------------------------------------------
def program_idents_for_scope(catalog: Catalog, scope: str):
    """Program idents a named scope should read, or ``None`` for core/all/unknown.

    Scopes: a feature-group key (``trunks``/``groups``/``phantom``/
    ``voicemail``/``stations``/``licensing``), ``features`` (every feature
    group at once), or a menu-area name (``trunk``, ``ip-telephony`` …). Unknown
    strings return ``None`` so the caller falls back to its core/all logic.
    """
    s = (scope or "").strip().lower()
    if s in ("", "core", "all"):
        return None
    groups = {g["key"]: g for g in FEATURE_GROUPS}
    if s in groups:
        return _resolve_group(catalog, groups[s]) or None
    if s in ("features", "standard"):
        out: list[str] = []
        seen: set[str] = set()
        for g in FEATURE_GROUPS:
            for k in _resolve_group(catalog, g):
                if k not in seen:
                    seen.add(k)
                    out.append(k)
        return out or None
    area = [p.key for p in catalog.programs.values()
            if catalog.menu_area(p.key).lower() == s]
    return area or None


def scope_roots(catalog: Catalog, scope: str):
    """GETNEXT roots for a named scope (field OIDs of its programs), or ``None``.

    Imported lazily by :class:`toshiba_cix.scan.CIXReader`. Reuses the backup
    planner so the walk makes as few passes as possible.
    """
    idents = program_idents_for_scope(catalog, scope)
    if not idents:
        return None
    from .backup import walk_roots
    return walk_roots(catalog, idents)


# --------------------------------------------------------------------------
# cell / value rendering
# --------------------------------------------------------------------------
def _is_enum(fld: dict) -> bool:
    return fld.get("syntax") == "EnumeratedINTEGER"


def _display_value(catalog: Catalog, fld: dict, raw_value, is_enum: bool) -> str:
    if raw_value is None or raw_value == MISSING:
        return ""
    if is_enum and isinstance(raw_value, int) and not isinstance(raw_value, bool):
        label = catalog.enum_label(fld, raw_value)
        if label:
            return label
    return str(raw_value)


def _make_cell(catalog: Catalog, fld: dict, oid: str, raw_value) -> dict:
    is_enum = _is_enum(fld)
    name = fld.get("name") or ""
    return {
        "col": fld.get("col"),
        "field_name": name,
        "oid": oid,
        "raw_value": raw_value,
        "display_value": _display_value(catalog, fld, raw_value, is_enum),
        "syntax": fld.get("syntax"),
        "access": fld.get("access"),
        "is_enum": is_enum,
        "is_secret": bool(_SECRET_RE.search(name)),
    }


def _row_sort_key(index: str):
    try:
        arcs = [int(a) for a in index.split(".")] if index else []
    except ValueError:
        return (1, len(index), index)
    return (0, len(arcs), arcs)


def _human_key(index: str) -> str:
    if not index:
        return "_"
    try:
        arcs = tuple(int(a) for a in index.split("."))
    except ValueError:
        return index
    return parse_row_index(arcs).key


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------
def _assemble(catalog: Catalog, by_prog: dict, uncataloged: list[dict]) -> dict:
    """Shared tail: build program views + menu / feature groupings + stats."""
    programs: list[dict] = []
    cell_total = 0
    row_total = 0
    for prog_key, rows_by_index in by_prog.items():
        prog = catalog.programs[prog_key]
        info = catalog.menu_info(prog_key)
        rows = []
        for index in sorted(rows_by_index, key=_row_sort_key):
            cells = sorted(rows_by_index[index].values(),
                           key=lambda c: (c["col"] is None, c["col"] or 0,
                                          c["field_name"]))
            cell_total += len(cells)
            rows.append({"index": index, "key": _human_key(index),
                         "cells": cells})
        row_total += len(rows)
        programs.append({
            "catalog_key": prog_key,
            "program_number": prog.number,
            "program_name": prog.name,
            "menu_area": info["area"],
            "menu_path": info["menu_path"],
            "label": info["label"],
            "group_oid": prog.group_oid,
            "row_count": len(rows),
            "rows": rows,
        })

    def _area_rank(area: str) -> int:
        return MENU_AREA_ORDER.index(area) if area in MENU_AREA_ORDER \
            else len(MENU_AREA_ORDER)

    def _num_key(pv: dict):
        n = pv["program_number"]
        try:
            return (0, int(n))
        except (TypeError, ValueError):
            return (1, pv["catalog_key"])

    programs.sort(key=lambda pv: (_area_rank(pv["menu_area"]), _num_key(pv)))

    # menu areas (in canonical order, only areas that returned data)
    areas: dict[str, dict] = {}
    for pv in programs:
        a = areas.setdefault(pv["menu_area"],
                             {"area": pv["menu_area"], "programs": [],
                              "row_count": 0, "cell_count": 0})
        a["programs"].append(pv["catalog_key"])
        a["row_count"] += pv["row_count"]
        a["cell_count"] += sum(len(r["cells"]) for r in pv["rows"])
    menu_areas = sorted(areas.values(), key=lambda a: _area_rank(a["area"]))

    # feature views (only programs that actually returned data)
    present_keys = {pv["catalog_key"] for pv in programs}
    feature_views = []
    for g in FEATURE_GROUPS:
        keys = [k for k in _resolve_group(catalog, g) if k in present_keys]
        feature_views.append({"key": g["key"], "title": g["title"],
                              "programs": keys, "present": bool(keys)})

    return {
        "programs": programs,
        "menu_areas": menu_areas,
        "feature_views": feature_views,
        "uncataloged": uncataloged,
        "stats": {
            "programs": len(programs),
            "rows": row_total,
            "cells": cell_total,
            "named_cells": cell_total,   # every cell here carries a field name
            "raw_oid_cells": 0,          # by construction: named or uncataloged
            "uncataloged": len(uncataloged),
        },
    }


def build_program_views(pairs, catalog: Catalog) -> dict:
    """Named, menu-grouped program views from raw ``(oid, Value)`` pairs. Pure.

    Every OID is attributed to its catalog field by longest-prefix match; the
    field's name, column, syntax, access and enum label are attached. OIDs with
    no catalog field survive verbatim in ``uncataloged`` — the only bare OIDs
    the frontend ever sees.
    """
    by_prog: dict[str, dict[str, dict]] = {}
    uncataloged: list[dict] = []
    for oid, val in pairs:
        attr = catalog.attribute_oid(oid)
        if attr is None:
            if not _handled_elsewhere(oid):
                dv = decode_value(val)
                uncataloged.append({"oid": oid, "value": dv, "raw_value": dv})
            continue
        prog_key, fld, tail = attr
        raw_value = catalog.decode_field_value(fld, val)
        index = tail or "0"
        rows = by_prog.setdefault(prog_key, {})
        row = rows.setdefault(index, {})
        # Key the cell by field OID so two columns never collapse onto one.
        row[fld.get("oid", fld.get("name"))] = _make_cell(
            catalog, fld, oid, raw_value)
    return _assemble(catalog, by_prog, uncataloged)


def program_views_from_backup(backup_doc: dict, catalog: Catalog) -> dict:
    """The same contract, rebuilt from a saved ``toshiba-cix-backup`` doc. Pure.

    A backup stores ``program → rows → {field_name: value}`` (no per-cell OID),
    so each cell's OID is reconstructed as ``field.oid + "." + row index`` and
    the field's catalog metadata re-attached. Lets the frontend render an opened
    backup file with exactly the shape a live read produces.
    """
    by_prog: dict[str, dict[str, dict]] = {}
    uncataloged = list(backup_doc.get("unmatched", []))
    for prog_key, bucket in (backup_doc.get("programs") or {}).items():
        prog = catalog.program(prog_key)
        if prog is None:
            continue
        for row in bucket.get("rows", []):
            index = row.get("index") or "0"
            cells: dict[str, dict] = {}
            for fieldkey, value in (row.get("fields") or {}).items():
                fld = prog.field(fieldkey.split("#", 1)[0])
                if fld is None:
                    continue
                base = fld.get("oid", "")
                oid = base if index in ("", "0") else f"{base}.{index}"
                cells[base] = _make_cell(catalog, fld, oid, value)
            if cells:
                by_prog.setdefault(prog.key, {})[index] = cells
    return _assemble(catalog, by_prog, uncataloged)


def empty_program_views() -> dict:
    """The contract's shape with nothing in it (catalog unavailable)."""
    return {"programs": [], "menu_areas": [], "feature_views": [],
            "uncataloged": [],
            "stats": {"programs": 0, "rows": 0, "cells": 0, "named_cells": 0,
                      "raw_oid_cells": 0, "uncataloged": 0}}


__all__ = [
    "FEATURE_GROUPS", "program_idents_for_scope", "scope_roots",
    "build_program_views", "program_views_from_backup", "empty_program_views",
]
