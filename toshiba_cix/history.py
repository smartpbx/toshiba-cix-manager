"""Per-field and per-row history from the snapshot store (DESIGN_PLAN §6).

eManager showed only "now". Because Switchroom snapshots on every connect and
keeps them (``store.py``), the value of any field over time is already on disk —
this reads it out. ``field_history`` powers the hover history ("COS: 1 → 3,
changed 15 Oct by dknight"); ``row_history`` the record pane's timeline;
``session_diff`` the "what have I changed this session" view (working copy vs the
snapshot it was read from).

Pure stdlib, no I/O: callers pass the snapshots (oldest → newest) as a list of
``{sid, saved_at, program_views}`` (what the store hands back); this walks them.
"""

from __future__ import annotations

__all__ = ["field_history", "row_history", "session_diff"]


def _programs(snap) -> list:
    pv = snap.get("program_views") if isinstance(snap, dict) else None
    if isinstance(pv, dict):
        return pv.get("programs") or []
    if isinstance(pv, list):
        return pv
    # a bare program_views dict / list was passed as the snapshot itself
    if isinstance(snap, dict) and "programs" in snap:
        return snap.get("programs") or []
    return []


def _row(programs, program_key, index):
    for pv in programs:
        if pv.get("catalog_key") == program_key or str(pv.get("program_number")) == str(program_key):
            for r in pv.get("rows") or []:
                if str(r.get("index")) == str(index):
                    return r
    return None


def _cell_val(cell) -> str:
    if cell is None:
        return ""
    dv = cell.get("display_value")
    if (dv is None or dv == "") and cell.get("raw_value") is not None:
        return str(cell.get("raw_value"))
    return "" if dv is None else str(dv)


def _row_values(row) -> dict:
    return {c.get("field_name"): _cell_val(c) for c in (row.get("cells") or [])} if row else {}


def field_history(snapshots, program_key: str, index: str, field: str) -> list:
    """The value of one field across ``snapshots`` (oldest → newest). Each entry
    is ``{sid, saved_at, value, present, changed}`` where ``changed`` marks a
    difference from the previous snapshot that held the row."""
    out: list = []
    prev = None
    for snap in snapshots:
        row = _row(_programs(snap), program_key, index)
        present = row is not None and any(
            c.get("field_name") == field for c in (row.get("cells") or []))
        value = _row_values(row).get(field, "") if row else ""
        entry = {
            "sid": snap.get("sid") or snap.get("id"),
            "saved_at": snap.get("saved_at") or snap.get("read_at"),
            "value": value, "present": present,
            "changed": present and prev is not None and value != prev,
        }
        if present:
            prev = value
        out.append(entry)
    return out


def row_history(snapshots, program_key: str, index: str) -> dict:
    """Every field's change timeline for one row. Returns
    ``{fields, timeline}`` — ``fields`` maps a field to its value per snapshot;
    ``timeline`` is one entry per snapshot listing that snapshot's changes."""
    fields: dict = {}
    timeline: list = []
    prev: dict = {}
    for snap in snapshots:
        row = _row(_programs(snap), program_key, index)
        vals = _row_values(row)
        changes = {}
        for name, value in vals.items():
            fields.setdefault(name, []).append(value)
            if name in prev and prev[name] != value:
                changes[name] = {"old": prev[name], "new": value}
        timeline.append({
            "sid": snap.get("sid") or snap.get("id"),
            "saved_at": snap.get("saved_at") or snap.get("read_at"),
            "present": row is not None, "changes": changes,
        })
        if row is not None:
            prev = vals
    return {"fields": fields, "timeline": timeline}


def session_diff(working_views, base_views) -> dict:
    """What changed between the session working copy and the snapshot it was read
    from. Returns ``{changed, rows_added, rows_removed}`` — a light field-level
    compare (the full annotated diff is ``diff_view.py``)."""
    def index_rows(views):
        out = {}
        for pv in _programs({"program_views": views} if isinstance(views, (list,)) else views):
            key = pv.get("catalog_key")
            for r in pv.get("rows") or []:
                out[(key, str(r.get("index")))] = _row_values(r)
        return out

    now = index_rows(working_views)
    base = index_rows(base_views)
    changed: list = []
    rows_added: list = []
    rows_removed: list = []
    for loc, vals in now.items():
        if loc not in base:
            rows_added.append({"program": loc[0], "index": loc[1]})
            continue
        bvals = base[loc]
        for field, value in vals.items():
            old = bvals.get(field)
            if old is not None and old != value:
                changed.append({"program": loc[0], "index": loc[1],
                                "field": field, "old": old, "new": value})
    for loc in base:
        if loc not in now:
            rows_removed.append({"program": loc[0], "index": loc[1]})
    return {"changed": changed, "rows_added": rows_added,
            "rows_removed": rows_removed}
