"""Structured, human-readable diff between two catalog backups.

Compares two backup documents (see :mod:`toshiba_cix.backup`) at three levels —
programs added/removed, rows added/removed within a program, and fields changed
/ added / removed within a row. Rows are matched on their exact instance tail
(``index``), so a diff survives re-ordering and only reports real changes.

With a :class:`~toshiba_cix.catalog.Catalog`, ``ignore_readonly`` (default) drops
field *changes* on read-only fields — status counters, live timers and the like
that move on their own and would otherwise bury the programming changes a tech
cares about. Row add/remove is always reported. Without a catalog the diff
cannot tell read-only from read-write, so everything is reported.
"""

from __future__ import annotations

import json

from .catalog import Catalog, _load_data_text

_ABSENT = object()

VOLATILE_FIELDS_FILENAME = "volatile_fields.json"


def load_volatile_oids() -> set:
    """Field OIDs that move on their own — hidden by default in diffs.

    Reads the vendored ``data/volatile_fields.json`` (backups.md §4.2) through
    the same embedded → bundle → packaged resolution the catalog uses, so the
    single-file build carries it too. An absent file degrades to an empty set
    (volatile hiding simply off), never a crash."""
    text = _load_data_text(VOLATILE_FIELDS_FILENAME, "EMBEDDED_VOLATILE_FIELDS_JSON")
    if not text:
        return set()
    try:
        return set((json.loads(text).get("fields") or {}).keys())
    except (ValueError, AttributeError):
        return set()


def _programs(doc: dict) -> dict:
    return doc.get("programs", {}) or {}


def _rows_by(bucket: dict, on: str) -> dict:
    """Index a program's rows by ``index`` (same system) or ``key`` (cross-site).

    Matching on ``key`` lets a diff across two different switches line up
    station 2001 with station 2001 even though the instance tails embed a
    length-prefixed DN (backups.md §4.4). A duplicate key keeps the first row."""
    out: dict = {}
    for r in bucket.get("rows", []):
        k = r.get(on)
        if k is not None:
            out.setdefault(k, r)
    return out


def _is_readonly(catalog: Catalog | None, prog_key: str, fieldkey: str) -> bool:
    fld = _field(catalog, prog_key, fieldkey)
    return fld is not None and fld.get("access") != "rw"


def _field(catalog: Catalog | None, prog_key: str, fieldkey: str):
    if catalog is None:
        return None
    prog = catalog.program(prog_key)
    if prog is None:
        return None
    return prog.field(fieldkey.split("#", 1)[0])


def _field_oid(catalog: Catalog | None, prog_key: str, fieldkey: str):
    fld = _field(catalog, prog_key, fieldkey)
    return fld.get("oid") if fld else None


def _row_dict(row: dict, match_index) -> dict:
    """The full-row payload the UI expands for an added/removed row."""
    return {"index": row.get("index"), "key": row.get("key"),
            "match": match_index, "fields": dict(row.get("fields", {}))}


def diff_backups(a: dict, b: dict, *, catalog: Catalog | None = None,
                 ignore_readonly: bool = True, exclude_programs=None,
                 exclude_fields=None, volatile=None,
                 match_rows_on: str = "index") -> dict:
    """Diff backup ``a`` (old) against ``b`` (new). Pure.

    * ``exclude_programs`` — program keys dropped whole (cross-system identity).
    * ``exclude_fields`` — field names dropped from every row (per-row identity
      like station names / MACs on a cross-site diff).
    * ``volatile`` — a set of field OIDs that move on their own; changes to them
      are counted under ``volatile_hidden`` and withheld, exactly like read-only,
      so a programming change is never buried under the clock (backups.md §4.2).
    * ``match_rows_on`` — ``"index"`` (same system) or ``"key"`` (cross-site).

    ``rows_added`` / ``rows_removed`` carry the full row dict (``{index, key,
    match, fields}``) so the UI can expand a new row without a second fetch.
    """
    pa, pb = _programs(a), _programs(b)
    exclude_programs = set(exclude_programs or ())
    exclude_fields = set(exclude_fields or ())
    volatile = set(volatile or ())
    keys_a = set(pa) - exclude_programs
    keys_b = set(pb) - exclude_programs

    programs_added = sorted(keys_b - keys_a)
    programs_removed = sorted(keys_a - keys_b)
    programs_changed: dict[str, dict] = {}

    counts = {"programs_added": len(programs_added),
              "programs_removed": len(programs_removed),
              "rows_added": 0, "rows_removed": 0,
              "fields_changed": 0, "fields_added": 0, "fields_removed": 0,
              "ignored_readonly": 0, "volatile_hidden": 0}

    def _visible(fk: str) -> bool:
        return fk.split("#", 1)[0] not in exclude_fields

    for key in sorted(keys_a & keys_b):
        ra = _rows_by(pa[key], match_rows_on)
        rb = _rows_by(pb[key], match_rows_on)
        mk_a, mk_b = set(ra), set(rb)

        rows_added = [_row_dict(rb[m], m) for m in sorted(mk_b - mk_a, key=_idx_key)]
        rows_removed = [_row_dict(ra[m], m) for m in sorted(mk_a - mk_b, key=_idx_key)]
        fields_changed: list[dict] = []
        fields_added: list[dict] = []
        fields_removed: list[dict] = []

        for m in sorted(mk_a & mk_b, key=_idx_key):
            fa = ra[m].get("fields", {})
            fb = rb[m].get("fields", {})
            index = rb[m].get("index") or ra[m].get("index")
            human = rb[m].get("key") or ra[m].get("key") or index
            for fk in sorted(set(fa) | set(fb)):
                if not _visible(fk):
                    continue
                va = fa.get(fk, _ABSENT)
                vb = fb.get(fk, _ABSENT)
                if va is _ABSENT and vb is not _ABSENT:
                    fields_added.append({"index": index, "key": human,
                                         "field": fk, "new": vb})
                elif vb is _ABSENT and va is not _ABSENT:
                    fields_removed.append({"index": index, "key": human,
                                           "field": fk, "old": va})
                elif va != vb:
                    if ignore_readonly and _is_readonly(catalog, key, fk):
                        counts["ignored_readonly"] += 1
                        continue
                    if volatile and _field_oid(catalog, key, fk) in volatile:
                        counts["volatile_hidden"] += 1
                        continue
                    fields_changed.append({"index": index, "key": human,
                                           "field": fk, "old": va, "new": vb})

        if rows_added or rows_removed or fields_changed or fields_added \
                or fields_removed:
            programs_changed[key] = {
                "number": pb[key].get("number"),
                "name": pb[key].get("name"),
                "rows_added": rows_added,
                "rows_removed": rows_removed,
                "fields_changed": fields_changed,
                "fields_added": fields_added,
                "fields_removed": fields_removed,
            }
            counts["rows_added"] += len(rows_added)
            counts["rows_removed"] += len(rows_removed)
            counts["fields_changed"] += len(fields_changed)
            counts["fields_added"] += len(fields_added)
            counts["fields_removed"] += len(fields_removed)

    return {
        "a_meta": a.get("meta", {}),
        "b_meta": b.get("meta", {}),
        "ignore_readonly": ignore_readonly and catalog is not None,
        "match_rows_on": match_rows_on,
        "excluded_programs": sorted(exclude_programs),
        "excluded_fields": sorted(exclude_fields),
        "programs_added": programs_added,
        "programs_removed": programs_removed,
        "programs_changed": programs_changed,
        "summary": counts,
    }


def _idx_key(index: str):
    try:
        arcs = [int(a) for a in index.split(".")]
    except (ValueError, AttributeError):
        return (1, [], str(index))
    return (0, arcs, "")


def has_changes(diff: dict) -> bool:
    s = diff.get("summary", {})
    return any(s.get(k) for k in ("programs_added", "programs_removed",
                                  "rows_added", "rows_removed",
                                  "fields_changed", "fields_added",
                                  "fields_removed"))


def _hr(title: str, char: str = "=") -> str:
    return f"{title}\n{char * max(len(title), 8)}"


def _v(x) -> str:
    return "∅" if x is _ABSENT or x is None else str(x)


def _row_label(row) -> str:
    """A diff row's human label (v2 dict) or the bare index (older diff)."""
    if isinstance(row, dict):
        return str(row.get("key") or row.get("index") or "?")
    return str(row)


def render_diff_text(diff: dict) -> str:
    """Render a diff as plain text: a summary then per-program changes."""
    lines: list[str] = []
    am, bm = diff.get("a_meta", {}), diff.get("b_meta", {})
    lines.append(_hr("Toshiba Strata CIX — backup diff"))
    lines.append(f"A (old) : {am.get('site') or am.get('source_ip') or '?'}"
                 f"  read {am.get('read_at', '?')}")
    lines.append(f"B (new) : {bm.get('site') or bm.get('source_ip') or '?'}"
                 f"  read {bm.get('read_at', '?')}")
    if diff.get("ignore_readonly"):
        lines.append("Read-only field changes are hidden (catalog-aware).")
    lines.append("")

    s = diff.get("summary", {})
    lines.append(_hr("Summary", "-"))
    for k in ("programs_added", "programs_removed", "rows_added",
              "rows_removed", "fields_changed", "fields_added",
              "fields_removed", "ignored_readonly", "volatile_hidden"):
        lines.append(f"  {k:<18}: {s.get(k, 0)}")
    lines.append("")

    if not has_changes(diff):
        lines.append("No programming differences.")
        return "\n".join(lines) + "\n"

    if diff.get("programs_added"):
        lines.append(_hr("Programs only in B (added)", "-"))
        for k in diff["programs_added"]:
            lines.append(f"  + {k}")
        lines.append("")
    if diff.get("programs_removed"):
        lines.append(_hr("Programs only in A (removed)", "-"))
        for k in diff["programs_removed"]:
            lines.append(f"  - {k}")
        lines.append("")

    changed = diff.get("programs_changed", {})
    for key in sorted(changed):
        c = changed[key]
        title = key + (f"  (Program {c['number']})" if c.get("number") else "")
        lines.append(_hr(title, "-"))
        for row in c.get("rows_added", []):
            lines.append(f"  + row [{_row_label(row)}]")
        for row in c.get("rows_removed", []):
            lines.append(f"  - row [{_row_label(row)}]")
        for ch in c.get("fields_changed", []):
            lines.append(f"  ~ [{ch['key']}] {ch['field']}: "
                         f"{_v(ch['old'])} -> {_v(ch['new'])}")
        for ch in c.get("fields_added", []):
            lines.append(f"  + [{ch['key']}] {ch['field']}: {_v(ch['new'])}")
        for ch in c.get("fields_removed", []):
            lines.append(f"  - [{ch['key']}] {ch['field']}: {_v(ch['old'])}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = ["diff_backups", "render_diff_text", "has_changes",
           "load_volatile_oids", "VOLATILE_FIELDS_FILENAME"]
