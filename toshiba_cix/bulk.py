"""Bulk-edit planners — the moves eManager never had (improvements.md §2.3).

Each planner is a pure function over a program view (``{rows: [<row>, …]}``) and
a selection of row indices, and returns a **changes map** ``{index: {field:
new_value}}`` holding only the cells that actually change. The route turns that
map into :class:`~toshiba_cix.write.WriteOp` lists with
``plan_row_update`` (via :func:`changes_to_ops`), so bulk edits ride the exact
same plan → review → apply contract as a single-field edit — never a special
write path. No I/O, no network.

The five moves (DESIGN_PLAN 5.5):

* ``set_for_selection`` — one value into one field across every selected row.
* ``fill_down`` — the first selected row's value into the rest.
* ``pattern_fill`` — a numbered pattern (``"Desk {n}"`` → Desk 1, Desk 2, …, or
  a bare numeric field incremented from ``start``).
* ``find_replace`` — substring/regex replace within one field across the rows.
* ``paste`` — a 2-D grid of values (rows × columns) pasted onto a selection,
  the Excel-era workflow Strata Synch used.
"""

from __future__ import annotations

import re

__all__ = [
    "set_for_selection", "fill_down", "pattern_fill", "find_replace", "paste",
    "changes_to_ops", "cell_value",
]


def _rows_by_index(view: dict) -> dict:
    return {r.get("index"): r for r in (view.get("rows") or [])}


def cell_value(row: dict, field: str):
    """The current display value of ``field`` in ``row``, or ``None``."""
    for c in row.get("cells") or []:
        if c.get("field_name") == field:
            dv = c.get("display_value")
            if (dv is None or dv == "") and c.get("raw_value") is not None:
                return str(c.get("raw_value"))
            return dv
    return None


def _diff(row: dict, field: str, new_value) -> dict:
    """``{field: new_value}`` if it differs from the current cell, else ``{}``."""
    new_s = "" if new_value is None else str(new_value)
    cur = cell_value(row, field)
    cur_s = "" if cur is None else str(cur)
    return {field: new_s} if new_s != cur_s else {}


def set_for_selection(view: dict, indices, field: str, value) -> dict:
    by_index = _rows_by_index(view)
    out: dict = {}
    for idx in indices:
        row = by_index.get(idx)
        if row is None:
            continue
        ch = _diff(row, field, value)
        if ch:
            out[idx] = ch
    return out


def fill_down(view: dict, indices, field: str) -> dict:
    indices = list(indices)
    if len(indices) < 2:
        return {}
    by_index = _rows_by_index(view)
    source = by_index.get(indices[0])
    if source is None:
        return {}
    value = cell_value(source, field)
    out: dict = {}
    for idx in indices[1:]:
        row = by_index.get(idx)
        if row is None:
            continue
        ch = _diff(row, field, value)
        if ch:
            out[idx] = ch
    return out


def pattern_fill(view: dict, indices, field: str, pattern: str,
                 start: int = 1, step: int = 1) -> dict:
    """Fill ``field`` with a numbered pattern. ``{n}`` in ``pattern`` is the
    running counter; a pattern with no ``{n}`` is treated as a bare number and
    incremented (so ``pattern="100"`` → 100, 101, 102 …)."""
    by_index = _rows_by_index(view)
    out: dict = {}
    n = start
    has_ph = "{n}" in pattern
    for idx in indices:
        row = by_index.get(idx)
        if row is None:
            continue
        value = pattern.replace("{n}", str(n)) if has_ph else str(n)
        ch = _diff(row, field, value)
        if ch:
            out[idx] = ch
        n += step
    return out


def find_replace(view: dict, indices, field: str, find: str, replace: str,
                 *, regex: bool = False) -> dict:
    by_index = _rows_by_index(view)
    out: dict = {}
    matcher = re.compile(find) if regex else None
    for idx in indices:
        row = by_index.get(idx)
        if row is None:
            continue
        cur = cell_value(row, field)
        if cur is None:
            continue
        new_value = (matcher.sub(replace, cur) if regex
                     else cur.replace(find, replace))
        ch = _diff(row, field, new_value)
        if ch:
            out[idx] = ch
    return out


def paste(view: dict, indices, columns, grid) -> dict:
    """Paste a 2-D ``grid`` (list of rows, each a list of cell strings) onto the
    ``indices`` × ``columns`` block. Extra grid rows/cols beyond the selection
    are ignored; a short grid simply fills fewer cells."""
    by_index = _rows_by_index(view)
    indices = list(indices)
    columns = list(columns)
    out: dict = {}
    for r, idx in enumerate(indices):
        if r >= len(grid):
            break
        row = by_index.get(idx)
        if row is None:
            continue
        cells = grid[r]
        row_changes: dict = {}
        for c, field in enumerate(columns):
            if c >= len(cells):
                break
            row_changes.update(_diff(row, field, cells[c]))
        if row_changes:
            out[idx] = row_changes
    return out


def changes_to_ops(view: dict, changes_by_index: dict, *, program=None,
                   program_number: str | None = None) -> list:
    """Turn a planner's changes map into a flat :class:`WriteOp` list, routing
    every row through the generic ``plan_row_update`` so bulk edits are planned,
    validated and reviewed exactly like single edits."""
    from .programs import plan_row_update  # amalgam: same flattened namespace
    by_index = _rows_by_index(view)
    ops: list = []
    for idx, changes in changes_by_index.items():
        row = by_index.get(idx)
        if row is None or not changes:
            continue
        ops.extend(plan_row_update(row, changes, program=program,
                                   program_number=program_number))
    return ops
