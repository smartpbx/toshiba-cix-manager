"""Presentation layer over :func:`toshiba_cix.diff.diff_backups` — pure.

``diff.py`` stays a pure three-level structural diff keyed on row match. This
module is everything the Backups-page diff pane (backups.md §4.2, the same
component the P2 review dialog reuses) and the ticket/Conduit exporters layer on
top of it, with **no I/O** so it is unit-tested against the fixture backups:

* :func:`annotate` — group the changes by eManager **menu path**, attach the
  field's display number + title and enum labels (``raw (label)``), name the row
  by its key, and **mask every sensitive field** so a password never appears in
  the structure (and therefore in any exporter).
* :func:`group_by_dn` — the station-centric re-grouping (everything that changed
  about DN 2001 across 200 / 204 / 205), on ``row.key``.
* :func:`attribute` — "blame": match each changed line against ``activity.jsonl``
  records so a line reads *ⓘ by cmannerow* or *⚠ changed outside this app*
  (backups.md §4.5).
* exporters — :func:`to_json`, :func:`to_text`, :func:`to_csv`,
  :func:`to_markdown`; none can leak a masked value.

The engine default already hides read-only and (when a ``volatile`` set is
passed) volatile changes, reporting their counts; this module never un-hides
them. A sensitive value is shown only as ``••••`` and its ``old``/``new`` are
dropped from the annotated line entirely.
"""

from __future__ import annotations

import copy
import csv
import io

from .backup import is_redacted_value, is_sensitive_field
from .catalog import Catalog
from .diff import render_diff_text  # re-exported as the text exporter

MASK = "••••"


# --------------------------------------------------------------------------
# field / value helpers (pure)
# --------------------------------------------------------------------------
def _field(catalog: Catalog | None, prog_key: str, fieldkey: str):
    if catalog is None:
        return None
    prog = catalog.program(prog_key)
    if prog is None:
        return None
    return prog.field(fieldkey.split("#", 1)[0])


def _display_no(fld) -> str:
    """The eManager-style column number shown before the title (``05``)."""
    col = fld.get("col") if fld else None
    if isinstance(col, int):
        return f"{col:02d}"
    return ""


def _title(fieldkey: str, fld) -> str:
    return (fld.get("name") if fld else None) or fieldkey.split("#", 1)[0]


def _is_sensitive(catalog, prog_key, fieldkey, sensitive_set) -> bool:
    base = fieldkey.split("#", 1)[0]
    if sensitive_set is not None and (prog_key, base) in sensitive_set:
        return True
    return is_sensitive_field(base)


def _render(catalog, prog_key, fieldkey, value):
    """``raw (label)`` for an enum, dotted value otherwise; never for secrets."""
    if value is None:
        return ""
    if is_redacted_value(value):
        return MASK
    fld = _field(catalog, prog_key, fieldkey)
    if fld is not None and fld.get("syntax") == "EnumeratedINTEGER" \
            and isinstance(value, int) and not isinstance(value, bool):
        label = catalog.enum_label(fld, value)
        if label:
            return f"{value} ({label})"
    return str(value)


def _sensitive_set_from_meta(diff: dict) -> set:
    """``{(prog_key, field_name)}`` from the two files' ``meta.sensitive_fields``."""
    out: set = set()
    for side in ("a_meta", "b_meta"):
        for ref in (diff.get(side, {}) or {}).get("sensitive_fields", []):
            parts = str(ref).split("/")
            if len(parts) == 3:
                out.add((parts[0], parts[2]))
    return out


# --------------------------------------------------------------------------
# annotate (pure)
# --------------------------------------------------------------------------
def _field_line(catalog, prog_key, kind, ch, sensitive_set) -> dict:
    fieldkey = ch["field"]
    fld = _field(catalog, prog_key, fieldkey)
    sensitive = _is_sensitive(catalog, prog_key, fieldkey, sensitive_set)
    line = {
        "kind": kind,                       # field_changed | field_added | field_removed
        "program": prog_key,
        "index": ch.get("index"),
        "row_key": ch.get("key"),
        "field": fieldkey,
        "display_no": _display_no(fld),
        "title": _title(fieldkey, fld),
        "sensitive": sensitive,
    }
    if sensitive:
        # Never carry the raw value: mask in the structure so no exporter leaks.
        if "old" in ch:
            line["old_display"] = MASK
        if "new" in ch:
            line["new_display"] = MASK
    else:
        if "old" in ch:
            line["old_display"] = _render(catalog, prog_key, fieldkey, ch["old"])
        if "new" in ch:
            line["new_display"] = _render(catalog, prog_key, fieldkey, ch["new"])
    return line


def _row_line(catalog, prog_key, kind, row, sensitive_set) -> dict:
    """An added/removed row: a summary of its non-secret fields for [expand]."""
    fields = row.get("fields", {}) if isinstance(row, dict) else {}
    preview = []
    for fk in sorted(fields):
        if _is_sensitive(catalog, prog_key, fk, sensitive_set):
            preview.append({"field": fk, "display": MASK, "sensitive": True})
        else:
            preview.append({"field": fk,
                            "display": _render(catalog, prog_key, fk, fields[fk]),
                            "sensitive": False})
    return {
        "kind": kind,                        # row_added | row_removed
        "program": prog_key,
        "index": row.get("index") if isinstance(row, dict) else row,
        "row_key": (row.get("key") if isinstance(row, dict) else None),
        "fields": preview,
    }


def annotate(diff: dict, catalog: Catalog | None = None) -> dict:
    """Group a diff by eManager menu path with labels, display numbers, masking.

    Returns ``{a_meta, b_meta, summary, match_rows_on, excluded_*, groups,
    programs_added, programs_removed}`` where each group is one program with its
    menu placement and an ordered list of lines (rows added/removed first, then
    field changes). Sensitive fields are already masked here, so
    :func:`group_by_dn` and every exporter inherit the masking for free."""
    sensitive_set = _sensitive_set_from_meta(diff)
    groups = []
    for prog_key in sorted(diff.get("programs_changed", {})):
        c = diff["programs_changed"][prog_key]
        info = catalog.menu_info(prog_key) if catalog is not None else {}
        lines = []
        for row in c.get("rows_added", []):
            lines.append(_row_line(catalog, prog_key, "row_added", row, sensitive_set))
        for row in c.get("rows_removed", []):
            lines.append(_row_line(catalog, prog_key, "row_removed", row, sensitive_set))
        for ch in c.get("fields_changed", []):
            lines.append(_field_line(catalog, prog_key, "field_changed", ch, sensitive_set))
        for ch in c.get("fields_added", []):
            lines.append(_field_line(catalog, prog_key, "field_added", ch, sensitive_set))
        for ch in c.get("fields_removed", []):
            lines.append(_field_line(catalog, prog_key, "field_removed", ch, sensitive_set))
        groups.append({
            "program": prog_key,
            "number": c.get("number"),
            "name": c.get("name"),
            "menu_area": info.get("area"),
            "menu_path": info.get("menu_path"),
            "label": info.get("label") or prog_key,
            "rows_changed": len(c.get("rows_added", [])) + len(c.get("rows_removed", [])),
            "fields_changed": (len(c.get("fields_changed", []))
                               + len(c.get("fields_added", []))
                               + len(c.get("fields_removed", []))),
            "lines": lines,
        })
    # Menu-area order mirrors the nav tree (System, Station, Trunk, …).
    from .catalog import MENU_AREA_ORDER

    def _area_rank(area):
        return MENU_AREA_ORDER.index(area) if area in MENU_AREA_ORDER \
            else len(MENU_AREA_ORDER)
    groups.sort(key=lambda g: (_area_rank(g["menu_area"]), str(g["number"] or g["program"])))
    return {
        "a_meta": diff.get("a_meta", {}),
        "b_meta": diff.get("b_meta", {}),
        "summary": diff.get("summary", {}),
        "match_rows_on": diff.get("match_rows_on", "index"),
        "excluded_programs": diff.get("excluded_programs", []),
        "excluded_fields": diff.get("excluded_fields", []),
        "programs_added": diff.get("programs_added", []),
        "programs_removed": diff.get("programs_removed", []),
        "groups": groups,
    }


def group_by_dn(annotated: dict) -> dict:
    """Re-group an annotated diff by row key (DN) across programs (backups.md §4.2)."""
    buckets: dict = {}
    for g in annotated.get("groups", []):
        for line in g["lines"]:
            key = line.get("row_key") or line.get("index") or "—"
            b = buckets.setdefault(key, {"row_key": key, "lines": []})
            b["lines"].append(dict(line, label=g["label"], menu_path=g["menu_path"]))
    order = sorted(buckets.values(), key=lambda b: str(b["row_key"]))
    return {**{k: annotated[k] for k in ("a_meta", "b_meta", "summary")},
            "by_dn": order}


# --------------------------------------------------------------------------
# attribution / blame (pure)
# --------------------------------------------------------------------------
def attribute(annotated: dict, activity) -> dict:
    """Stamp each field line with who changed it, from ``activity.jsonl`` records.

    ``activity`` is an iterable of records (as :meth:`SnapshotStore.read_activity`
    yields): a write whose ops include ``(program, index, field)`` stamps the
    line ``{"by": operator, "at": when, "changeset": id}``; no match stamps
    ``{"outside": true}`` — the signal that eManager or DKT programming touched
    the switch (backups.md §4.5). Operates on the annotated structure in place
    and returns it."""
    by_target: dict = {}
    for rec in activity or []:
        if rec.get("event") not in ("write", "restore", "changeset"):
            continue
        who = rec.get("operator")
        when = rec.get("at") or rec.get("ts")
        cs = rec.get("changeset") or rec.get("id")
        for op in rec.get("ops", []):
            tgt = (op.get("program"), str(op.get("index")), op.get("field"))
            by_target[tgt] = {"by": who, "at": when, "changeset": cs}
    for g in annotated.get("groups", []):
        for line in g["lines"]:
            if not line.get("kind", "").startswith("field"):
                continue
            tgt = (line["program"], str(line.get("index")), line.get("field"))
            line["attribution"] = by_target.get(tgt, {"outside": True})
    return annotated


# --------------------------------------------------------------------------
# masking the raw diff (so even the "verbatim" JSON/text exports are safe)
# --------------------------------------------------------------------------
def mask_diff(diff: dict, catalog: Catalog | None = None) -> dict:
    """A deep copy of a raw diff with every sensitive field value masked.

    The in-memory diff carries plaintext (it is built over the local plaintext
    store); an *export* must not. This masks ``old``/``new`` on sensitive field
    lines and sensitive values inside added/removed rows, so even the
    ``toshiba-cix-diff`` JSON and :func:`render_diff_text` are safe to hand
    out (backups.md §1.3)."""
    sensitive_set = _sensitive_set_from_meta(diff)
    out = copy.deepcopy(diff)
    for prog_key, c in (out.get("programs_changed") or {}).items():
        for bucket in ("fields_changed", "fields_added", "fields_removed"):
            for ch in c.get(bucket, []):
                if _is_sensitive(catalog, prog_key, ch.get("field", ""), sensitive_set):
                    if "old" in ch:
                        ch["old"] = MASK
                    if "new" in ch:
                        ch["new"] = MASK
        for bucket in ("rows_added", "rows_removed"):
            for row in c.get(bucket, []):
                if not isinstance(row, dict):
                    continue
                for fk in list(row.get("fields", {})):
                    if _is_sensitive(catalog, prog_key, fk, sensitive_set):
                        row["fields"][fk] = MASK
    return out


# --------------------------------------------------------------------------
# exporters (pure) — none can leak a sensitive value
# --------------------------------------------------------------------------
def to_json(diff: dict, catalog: Catalog | None = None) -> dict:
    """The structured diff as a masked ``toshiba-cix-diff`` document body."""
    from .backup import FORMAT_DIFF
    masked = mask_diff(diff, catalog)
    return {
        "format": FORMAT_DIFF, "format_version": 1,
        "a_snapshot": (diff.get("a_meta", {}) or {}).get("snapshot", {}).get("id"),
        "b_snapshot": (diff.get("b_meta", {}) or {}).get("snapshot", {}).get("id"),
        "diff": masked,
    }


def to_text(diff: dict, catalog: Catalog | None = None) -> str:
    """Plain text (reuses :func:`toshiba_cix.diff.render_diff_text`), masked."""
    return render_diff_text(mask_diff(diff, catalog))


def _annotated(diff_or_annotated: dict, catalog):
    return diff_or_annotated if "groups" in diff_or_annotated \
        else annotate(diff_or_annotated, catalog)


def to_csv(diff: dict, catalog: Catalog | None = None) -> str:
    """One row per changed line (masked). Spreadsheet-friendly."""
    ann = _annotated(diff, catalog)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["menu_path", "program", "row", "display_no", "field",
                "kind", "old", "new"])
    for g in ann["groups"]:
        for ln in g["lines"]:
            if ln["kind"].startswith("row_"):
                w.writerow([g["menu_path"], g["label"], ln.get("row_key") or ln.get("index"),
                            "", "(whole row)", ln["kind"], "", ""])
            else:
                w.writerow([g["menu_path"], g["label"], ln.get("row_key"),
                            ln.get("display_no"), ln["title"], ln["kind"],
                            ln.get("old_display", ""), ln.get("new_display", "")])
    return buf.getvalue()


def to_markdown(diff: dict, catalog: Catalog | None = None) -> str:
    """Markdown for a ticket / Conduit ``entity_notes`` ``change`` entry (masked)."""
    ann = _annotated(diff, catalog)
    am, bm = ann.get("a_meta", {}), ann.get("b_meta", {})
    s = ann.get("summary", {})
    out = ["## Configuration change",
           f"- **A:** {am.get('site') or am.get('source_ip') or '?'} "
           f"({(am.get('snapshot') or {}).get('id', '?')})",
           f"- **B:** {bm.get('site') or bm.get('source_ip') or '?'} "
           f"({(bm.get('snapshot') or {}).get('id', '?')})",
           f"- rows +{s.get('rows_added', 0)} −{s.get('rows_removed', 0)} · "
           f"fields ~{s.get('fields_changed', 0)} "
           f"(+{s.get('fields_added', 0)} −{s.get('fields_removed', 0)}) · "
           f"read-only hidden {s.get('ignored_readonly', 0)} · "
           f"volatile hidden {s.get('volatile_hidden', 0)}", ""]
    for g in ann["groups"]:
        out.append(f"### {g['label']}")
        for ln in g["lines"]:
            if ln["kind"] == "row_added":
                out.append(f"- **+ row** {ln.get('row_key') or ln.get('index')}")
            elif ln["kind"] == "row_removed":
                out.append(f"- **− row** {ln.get('row_key') or ln.get('index')}")
            elif ln["kind"] == "field_changed":
                out.append(f"- `{ln.get('display_no')}` {ln['title']} "
                           f"({ln.get('row_key')}): "
                           f"{ln.get('old_display')} → {ln.get('new_display')}")
            elif ln["kind"] == "field_added":
                out.append(f"- `{ln.get('display_no')}` {ln['title']} "
                           f"({ln.get('row_key')}): + {ln.get('new_display')}")
            else:
                out.append(f"- `{ln.get('display_no')}` {ln['title']} "
                           f"({ln.get('row_key')}): − {ln.get('old_display')}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


__all__ = [
    "MASK", "annotate", "group_by_dn", "attribute", "mask_diff",
    "to_json", "to_text", "to_csv", "to_markdown",
]
