"""Offline tests for wizards.py — pure planners, NO network (DESIGN_PLAN 5.7).

Each planner returns WriteOps from a fixture snapshot with nothing attached that
could open a socket; row-create / deletion come back non-sendable and flagged.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import wizards  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"


def _cell(name, col, val):
    return {"field_name": name, "col": col,
            "oid": f"{ROOT}.3.{col}.1.{val}", "raw_value": val,
            "display_value": str(val), "syntax": "OCTET STRING", "access": "rw"}


def _snapshot():
    return {"programs": [
        {"catalog_key": "200StationAssign", "program_number": "200",
         "label": "Station Assign", "rows": [
             {"index": "2", "key": "2104",
              "cells": [_cell("extension", 2, "2104"), _cell("name", 19, "Desk")]},
             {"index": "3", "key": "2105",
              "cells": [_cell("extension", 2, "2105"), _cell("name", 19, "Lab")]},
         ]},
        # a hunt group (218) that references station 2104 — a dependent
        {"catalog_key": "218Hunt", "program_number": "218",
         "label": "Hunt Groups", "rows": [
             {"index": "1", "key": "1",
              "cells": [_cell("member1", 3, "2104"), _cell("member2", 4, "2105")]},
         ]},
    ]}


def test_add_station_returns_rowcreate_ops():
    ops = wizards.plan_add_station({"dn": "2200", "name": "New", "type": "4"})
    assert len(ops) == 2
    assert all(o.row_create and not o.sendable for o in ops)
    assert all("row-create is unproven" in o.note for o in ops)


def test_delete_station_clears_dependents_and_notes_deletion():
    ops = wizards.plan_delete_station({"dn": "2104"}, _snapshot())
    # the hunt-group member referencing 2104 is cleared …
    cleared = [o for o in ops if o.program == "218" and o.sendable and o.new_value == ""]
    assert cleared, "expected the dependent hunt-group member to be cleared"
    # … and no station-200 field was touched (that is the deletion itself)
    assert not any(o.program == "200" and o.sendable for o in ops)
    # … plus a non-sendable destructive note for the deletion
    assert any(o.field == "__delete__" and not o.sendable for o in ops)


def test_change_dn_repoints_references():
    ops = wizards.plan_change_dn({"old_dn": "2104", "new_dn": "2250"}, _snapshot())
    repoint = [o for o in ops if o.program == "218" and o.new_value == "2250"]
    assert repoint, "expected the hunt-group reference re-pointed to the new DN"
    assert any(o.program == "203" and not o.sendable for o in ops)


def test_pdn_vmid_range_sequential():
    ops = wizards.plan_pdn_vmid_range(
        {"program": "200", "field": "name", "rows": ["2", "3"],
         "value_start": 6000, "step": 1}, _snapshot())
    vals = [o.new_value for o in ops if o.sendable]
    assert vals == ["6000", "6001"]


def test_dispatch_by_name():
    ops = wizards.plan("add_station", {"dn": "2201"}, None)
    assert isinstance(ops, list)


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
