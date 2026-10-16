"""Catalog-driven full backup of a Toshiba Strata CIX.

A backup walks every program table the catalog knows (read-only GETNEXT) plus
the system-identity scalars, decodes each value by its field's syntax, and
writes the app's **own openable format** — a single JSON that the viewer, the
diff and the restore planner all read back.

Three layers, I/O isolated so the whole build is unit-tested offline:

* :func:`collect` — the only network step: GETNEXT-walk the catalog's field
  OIDs (reusing :meth:`SnmpV1.bulk_walk`) and return ``[(oid, Value)]``.
* :func:`build_backup` — **pure**: attribute each OID to its catalog field,
  group into program → rows → named fields, decode by syntax. Tested against
  fixtures, no device.
* :func:`backup` — orchestration: read the identity scalars for ``meta`` then
  ``collect`` + ``build_backup``.

Backup file schema (``format == "toshiba-cix-backup"``)::

    {
      "format": "toshiba-cix-backup",
      "format_version": 1,
      "meta": {
        "swid": "<software id>", "chassis_mac": "...", "site": "<label|null>",
        "read_at": "<iso8601>", "catalog_version": "re-xxxxxxxxxxxx",
        "source_ip": "...", "tool_version": "...", "scope": "all"|[programs],
        "oids_read": N, "programs_count": N, "rows_count": N, "walk_error": null
      },
      "programs": {
        "<catalog key>": {               # keyed by catalog key — program
          "number": "200",               #   numbers are null/duplicated, the
          "name": "StationAssign",       #   key is the only unique id
          "group_oid": "...",
          "rows": [
            {"index": "1.3.50.48.48",    # exact instance tail (restores the OID)
             "key": "200",               # human row key (the DN, when present)
             "fields": {"stationStationName": "Front Desk", ...}}
          ]
        }
      },
      "unmatched": [{"oid": "...", "value": ...}]   # anything outside the catalog
    }

Programs are keyed by the **catalog key** (e.g. ``"200StationAssign"``), not the
program number: 31 programs have a null number and numbers repeat, so the key
is the only stable identifier. Each entry still carries ``number`` and ``name``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import __version__
from .catalog import Catalog, load_catalog
from .decode import ENTERPRISE_ROOT, decode_value, parse_row_index
from .snmp import SnmpError, Value

FORMAT = "toshiba-cix-backup"
FORMAT_VERSION = 1

SOFTWARE_ID_OID = f"{ENTERPRISE_ROOT}.7.2.1.0"
CHASSIS_MAC_OID = f"{ENTERPRISE_ROOT}.7.9.1.0"


# --------------------------------------------------------------------------
# root planning (pure)
# --------------------------------------------------------------------------
def walk_roots(catalog: Catalog, programs=None) -> list[str]:
    """The minimal set of GETNEXT roots that covers the selected programs.

    Collects the chosen programs' field (column) OIDs, then drops any OID that
    is a descendant of another kept OID — walking the ancestor already sweeps
    the descendant's instances — so the live read makes as few passes as it can.
    """
    if programs:
        progs = catalog.programs_for(programs)
    else:
        progs = list(catalog.programs.values())
    oids = sorted({f["oid"] for p in progs for f in p.fields if f.get("oid")},
                  key=lambda o: [int(x) for x in o.split(".")])
    roots: list[str] = []
    for oid in oids:
        if any(oid == r or oid.startswith(r + ".") for r in roots):
            continue
        roots.append(oid)
    return roots


# --------------------------------------------------------------------------
# collection (I/O)
# --------------------------------------------------------------------------
def collect(client, catalog: Catalog, *, programs=None,
            width: int = 10, max_total: int = 500000
            ) -> tuple[list[tuple[str, Value]], str | None]:
    """GETNEXT-walk the catalog's field subtrees. Returns ``(pairs, error)``.

    Read-only: emits only GETNEXT. Reuses the device-hardened
    :meth:`SnmpV1.bulk_walk` (adaptive batch size, tooBig recovery). A transport
    failure degrades to whatever was collected plus an ``error`` string rather
    than losing the partial read.
    """
    roots = walk_roots(catalog, programs)
    error: str | None = None
    pairs: list[tuple[str, Value]] = []
    try:
        pairs = client.bulk_walk(roots, width=width, max_total=max_total)
    except SnmpError as exc:
        error = str(exc)
    # de-dup (bulk_walk can revisit an overlap)
    seen: set[str] = set()
    out: list[tuple[str, Value]] = []
    for oid, val in pairs:
        if oid not in seen:
            seen.add(oid)
            out.append((oid, val))
    return out, error


def read_identity(client) -> dict:
    """Read the two identity scalars for ``meta`` (software id, chassis MAC)."""
    out: dict = {"swid": None, "chassis_mac": None}
    try:
        vbs = client.get([SOFTWARE_ID_OID, CHASSIS_MAC_OID])
    except SnmpError:
        return out
    by_oid = {vb.oid: vb.value for vb in vbs}
    sw = by_oid.get(SOFTWARE_ID_OID)
    if sw is not None and not sw.is_missing and sw.kind == "octet" and sw.raw:
        out["swid"] = decode_value(sw)
    mac = by_oid.get(CHASSIS_MAC_OID)
    if mac is not None and not mac.is_missing and mac.kind == "octet" and mac.raw:
        out["chassis_mac"] = decode_value(mac, as_mac=True)
    return out


# --------------------------------------------------------------------------
# build (pure)
# --------------------------------------------------------------------------
def _row_sort_key(index: str):
    arcs = [int(a) for a in index.split(".")] if index else []
    return (len(arcs), arcs)


def _human_key(index: str) -> str:
    """A readable row key from the instance tail (the DN when there is one)."""
    if not index:
        return "_"
    try:
        arcs = tuple(int(a) for a in index.split("."))
    except ValueError:
        return index
    ri = parse_row_index(arcs)
    return ri.key


def build_backup(pairs, catalog: Catalog, *, meta: dict | None = None) -> dict:
    """Assemble a backup dict from collected ``(oid, Value)`` pairs. Pure.

    Every OID is attributed to its catalog field by longest-prefix match and
    filed under ``program key → row (by instance tail) → field``. OIDs with no
    catalog field survive verbatim in ``unmatched`` so a backup never silently
    drops data the device returned.
    """
    programs: dict[str, dict] = {}
    rows_by_prog: dict[str, dict[str, dict]] = {}
    unmatched: list[dict] = []
    row_count = 0

    for oid, val in pairs:
        attr = catalog.attribute_oid(oid)
        if attr is None:
            unmatched.append({"oid": oid, "value": decode_value(val)})
            continue
        prog_key, fld, tail = attr
        prog = catalog.programs[prog_key]
        bucket = programs.get(prog_key)
        if bucket is None:
            bucket = programs[prog_key] = {
                "number": prog.number, "name": prog.name,
                "group_oid": prog.group_oid, "rows": [],
            }
            rows_by_prog[prog_key] = {}
        index = tail or "0"
        row = rows_by_prog[prog_key].get(index)
        if row is None:
            row = {"index": index, "key": _human_key(index), "fields": {}}
            rows_by_prog[prog_key][index] = row
            row_count += 1
        row["fields"][prog.field_key(fld)] = catalog.decode_field_value(fld, val)

    # finalise: deterministic row order per program
    for prog_key, bucket in programs.items():
        bucket["rows"] = sorted(rows_by_prog[prog_key].values(),
                                key=lambda r: _row_sort_key(r["index"]))

    full_meta = {
        "swid": None, "chassis_mac": None, "site": None,
        "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_version": catalog.version,
        "source_ip": None, "tool_version": __version__,
        "scope": "all", "oids_read": len(pairs), "walk_error": None,
    }
    if meta:
        full_meta.update(meta)
    full_meta["programs_count"] = len(programs)
    full_meta["rows_count"] = row_count
    full_meta["unmatched_count"] = len(unmatched)

    return {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "meta": full_meta,
        "programs": dict(sorted(programs.items())),
        "unmatched": unmatched,
    }


# --------------------------------------------------------------------------
# orchestration (I/O)
# --------------------------------------------------------------------------
def backup(client, catalog: Catalog | None = None, *, site: str | None = None,
           programs=None, width: int = 10, max_total: int = 500000) -> dict:
    """Read a live CIX and return a backup dict (read-only)."""
    catalog = catalog or load_catalog()
    ident = read_identity(client)
    pairs, error = collect(client, catalog, programs=programs, width=width,
                           max_total=max_total)
    meta = {
        "swid": ident.get("swid"),
        "chassis_mac": ident.get("chassis_mac"),
        "site": site,
        "source_ip": getattr(client, "host", None),
        "scope": "all" if not programs else list(programs),
        "walk_error": error,
    }
    return build_backup(pairs, catalog, meta=meta)


# --------------------------------------------------------------------------
# rendering (pure)
# --------------------------------------------------------------------------
def _hr(title: str, char: str = "=") -> str:
    return f"{title}\n{char * max(len(title), 8)}"


def _render_value(catalog, prog_key, fieldkey, value) -> str:
    if value is None:
        return ""
    if catalog is not None and isinstance(value, int) and not isinstance(value, bool):
        prog = catalog.program(prog_key)
        if prog is not None:
            fld = prog.field(fieldkey.split("#", 1)[0])
            if fld is not None and fld.get("syntax") == "EnumeratedINTEGER":
                label = catalog.enum_label(fld, value)
                if label:
                    return f"{value} ({label})"
    return str(value)


def render_backup_text(backup_doc: dict, *, catalog: Catalog | None = None,
                       program: str | None = None,
                       max_rows: int | None = None) -> str:
    """Human-readable rendering of a backup file: programs → rows → fields.

    ``program`` limits output to one program (catalog key, number or name);
    ``max_rows`` caps rows shown per program. When a ``catalog`` is supplied,
    EnumeratedINTEGER values are annotated with their label (once labels ship).
    """
    meta = backup_doc.get("meta", {})
    lines: list[str] = []
    lines.append(_hr("Toshiba Strata CIX — catalog backup"))
    lines.append(f"Software id     : {meta.get('swid', '?')}")
    lines.append(f"Chassis MAC     : {meta.get('chassis_mac', '?')}")
    lines.append(f"Site            : {meta.get('site') or '-'}")
    lines.append(f"Source IP       : {meta.get('source_ip') or '-'}")
    lines.append(f"Read at         : {meta.get('read_at', '?')}")
    lines.append(f"Catalog version : {meta.get('catalog_version', '?')}")
    lines.append(f"Tool version    : {meta.get('tool_version', '?')}")
    lines.append(f"Scope           : {meta.get('scope', '?')}")
    lines.append(f"Programs / rows : {meta.get('programs_count', '?')}"
                 f" / {meta.get('rows_count', '?')}")
    if meta.get("walk_error"):
        lines.append(f"WALK ERROR      : {meta['walk_error']} (partial)")
    lines.append("")

    progs = backup_doc.get("programs", {})
    want = None
    if program is not None:
        want = str(program)
    for prog_key in sorted(progs):
        bucket = progs[prog_key]
        if want is not None and want not in (
                prog_key, str(bucket.get("number")), bucket.get("name")):
            continue
        title = f"{prog_key}"
        num = bucket.get("number")
        if num:
            title += f"  (Program {num})"
        rows = bucket.get("rows", [])
        lines.append(_hr(f"{title} — {len(rows)} row(s)", "-"))
        shown = rows if max_rows is None else rows[:max_rows]
        for row in shown:
            lines.append(f"  [{row.get('key') or row.get('index')}]")
            for fk in sorted(row.get("fields", {})):
                lines.append(f"      {fk:<34} = "
                             f"{_render_value(catalog, prog_key, fk, row['fields'][fk])}")
        if max_rows is not None and len(rows) > max_rows:
            lines.append(f"  … {len(rows) - max_rows} more row(s)")
        lines.append("")

    unmatched = backup_doc.get("unmatched", [])
    if unmatched and program is None:
        lines.append(_hr(f"Unmatched OIDs (outside the catalog) — "
                         f"{len(unmatched)}", "-"))
        for e in unmatched[:50]:
            lines.append(f"  {e['oid']} = {e['value']}")
        if len(unmatched) > 50:
            lines.append(f"  … {len(unmatched) - 50} more")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "FORMAT", "FORMAT_VERSION", "SOFTWARE_ID_OID", "CHASSIS_MAC_OID",
    "walk_roots", "collect", "read_identity", "build_backup", "backup",
    "render_backup_text",
]
