"""Offline tests for bulk.py (bulk-edit planners) + changes_to_ops."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import bulk  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"


def _cell(name, col, val):
    return {"field_name": name, "col": col,
            "oid": f"{ROOT}.3.1200.1.1.{col}.1.{val}",
            "raw_value": val, "display_value": str(val),
            "syntax": "OCTET STRING", "access": "rw"}


def _view():
    rows = []
    for i, name in enumerate(["Desk A", "Desk B", "Desk C"], start=1):
        rows.append({"index": str(i), "key": str(2100 + i),
                     "cells": [_cell("name", 19, name), _cell("cos", 5, 1)]})
    return {"rows": rows, "row_count": 3}


def test_set_for_selection_only_changes():
    cmap = bulk.set_for_selection(_view(), ["1", "2"], "cos", "3")
    assert cmap == {"1": {"cos": "3"}, "2": {"cos": "3"}}


def test_set_noop_dropped():
    cmap = bulk.set_for_selection(_view(), ["1"], "cos", "1")  # already 1
    assert cmap == {}


def test_fill_down():
    cmap = bulk.fill_down(_view(), ["1", "2", "3"], "name")
    # row 1's "Desk A" filled into 2 and 3
    assert cmap == {"2": {"name": "Desk A"}, "3": {"name": "Desk A"}}


def test_pattern_fill_placeholder():
    cmap = bulk.pattern_fill(_view(), ["1", "2", "3"], "name", "Phone {n}", start=10)
    assert cmap["1"]["name"] == "Phone 10" and cmap["3"]["name"] == "Phone 12"


def test_pattern_fill_bare_numeric():
    cmap = bulk.pattern_fill(_view(), ["1", "2"], "cos", "4", start=4, step=1)
    assert cmap == {"1": {"cos": "4"}, "2": {"cos": "5"}}


def test_find_replace_substring():
    cmap = bulk.find_replace(_view(), ["1", "2", "3"], "name", "Desk", "Phone")
    assert cmap["1"]["name"] == "Phone A"


def test_find_replace_regex():
    cmap = bulk.find_replace(_view(), ["1"], "name", r"Desk (\w)", r"\1-desk", regex=True)
    assert cmap["1"]["name"] == "A-desk"


def test_paste_grid():
    cmap = bulk.paste(_view(), ["1", "2"], ["name", "cos"],
                      [["X", "2"], ["Y", "3"]])
    assert cmap == {"1": {"name": "X", "cos": "2"}, "2": {"name": "Y", "cos": "3"}}


def test_changes_to_ops_routes_through_plan():
    cmap = bulk.set_for_selection(_view(), ["1", "2"], "name", "Reception")
    ops = bulk.changes_to_ops(_view(), cmap, program_number="1200")
    assert len(ops) == 2 and all(o.sendable for o in ops)
    assert all(o.field == "name" and o.new_value == "Reception" for o in ops)


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {exc!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
