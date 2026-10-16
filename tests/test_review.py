"""Offline tests for review.py: three-way review, conflict guard, tiers, undo.

The whole point is that the review is PURE — Simulate builds a full plan +
three-way view with no network, and conflict detection is a pure comparison of
the op's base to the live re-read the caller hands in.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix.review import (classify_tier, inverse_plan,  # noqa: E402
                                three_way)
from toshiba_cix.write import WriteOp, conflict_guard

ROOT = "1.3.6.1.4.1.186.1.22"


def _cell(name, oid, val, syntax="OCTET STRING"):
    return {"field_name": name, "col": 1, "oid": oid, "raw_value": val,
            "display_value": str(val), "syntax": syntax, "access": "rw"}


def _row(cells):
    return {"index": "2", "key": "2104", "cells": cells}


def _op(field, new, old, oid, native=None, wire_proven=True):
    return WriteOp(field, field, new, old_value=old, target_oid=oid,
                   program="1200", native_wire=native, wire_proven=wire_proven)


def test_three_way_simulate_no_conflicts():
    base = [_row([_cell("name", "o1", "Desk")])]
    ops = [_op("name", "Reception", "Desk", "o1")]
    rev = three_way(ops, base, None, simulate=True)
    assert rev["simulate"] is True
    assert rev["summary"]["will_send"] == 1
    r = rev["rows"][0]
    assert r["base"] == "Desk" and r["live"] == "Desk" and r["proposed"] == "Reception"
    assert r["conflict"] is None and r["excluded"] is False


def test_conflict_default_keeps_live():
    base = [_row([_cell("name", "o1", "Desk")])]
    live = [_row([_cell("name", "o1", "Shipping")])]  # changed on device
    ops = [_op("name", "Reception", "Desk", "o1")]
    rev = three_way(ops, base, live, simulate=False)
    assert rev["conflicts"] and rev["conflicts"][0]["live"] == "Shipping"
    assert rev["rows"][0]["excluded"] is True
    assert rev["summary"]["will_send"] == 0  # conflict excluded by default


def test_conflict_guard_pure():
    ops = [_op("name", "X", "Desk", "o1"), _op("cos", "3", "1", "o2")]
    conflicts = conflict_guard(ops, {"o1": "Desk", "o2": "9"})
    assert len(conflicts) == 1 and conflicts[0]["oid"] == "o2"


def test_unproven_wire_counted():
    base = [_row([_cell("cos", "o1", "1", syntax="INTEGER")])]
    ops = [_op("cos", "3", "1", "o1", native="INTEGER", wire_proven=False)]
    rev = three_way(ops, base, None, simulate=True)
    assert rev["summary"]["skip_unproven_wire"] == 1
    assert rev["rows"][0]["proof"] == "catalog-derived"


def test_tier_ordinary_vs_wide_vs_destructive():
    small = [_op(f"f{i}", "x", "y", f"o{i}") for i in range(3)]
    assert classify_tier(small)["tier"] == 1
    wide = [_op(f"f{i}", "x", "y", f"o{i}") for i in range(25)]
    t = classify_tier(wide)
    assert t["tier"] == 2 and t["needs_typed_name"]
    rc = [WriteOp("x", "x", "1", target_oid="o1", row_create=True)]
    assert classify_tier(rc)["tier"] == 3
    destr = [WriteOp("x", "x", "1", target_oid="o1", program="118")]
    assert classify_tier(destr)["tier"] == 3


def test_remote_write_is_tier2():
    small = [_op("f", "x", "y", "o1")]
    assert classify_tier(small, transport="overlay")["tier"] == 2


def test_inverse_plan_swaps_and_drops_commit():
    from toshiba_cix.write import commit_write_op
    ops = [_op("name", "Reception", "Desk", "o1"), commit_write_op()]
    inv = inverse_plan(ops)
    assert len(inv) == 1  # commit not inverted
    assert inv[0].new_value == "Desk" and inv[0].old_value == "Reception"


def test_nonsendable_op_excluded():
    base = [_row([_cell("name", "o1", "Desk")])]
    ro = WriteOp("port", "port", "x", old_value="010101", target_oid=None,
                 note="read-only field — never written")
    rev = three_way([ro], base, None, simulate=True)
    assert rev["rows"][0]["excluded"] and rev["exclusions"]


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
