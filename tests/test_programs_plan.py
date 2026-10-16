"""Offline tests for the generic plan path, programs.plan_row_update.

Generalises CIXWriter.plan_station_update to any of the 186 programs: the write
OID comes from the row's own enriched cell (never invented), read-only / key /
hard-exclusion fields come back non-sendable with a reason, and an INTEGER-
native field is flagged catalog-derived. No network.

Run:  python3 tests/test_programs_plan.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix.programs import (HARD_EXCLUDE_PROGRAMS,  # noqa: E402
                                   plan_row_update, writable_fields)

ROOT = "1.3.6.1.4.1.186.1.22"


def _row():
    return {
        "index": "2", "key": "2104",
        "cells": [
            {"field_name": "name", "col": 19,
             "oid": f"{ROOT}.3.1200.1.1.19.1.2",
             "raw_value": "Front Desk", "display_value": "Front Desk",
             "syntax": "OCTET STRING", "access": "rw", "is_secret": False},
            {"field_name": "cos", "col": 5, "oid": f"{ROOT}.3.1200.1.1.5.1.2",
             "raw_value": 1, "display_value": "1", "syntax": "INTEGER",
             "access": "rw", "is_secret": False},
            {"field_name": "port", "col": 1, "oid": f"{ROOT}.3.1200.1.1.1.1.2",
             "raw_value": "010101", "display_value": "010101",
             "syntax": "OCTET STRING", "access": "r", "is_secret": False},
        ],
    }


class _Prog:
    number = "1200"
    fields = [
        {"name": "dn", "key": True, "access": "rw"},
        {"name": "name", "key": False, "access": "rw"},
        {"name": "cos", "key": False, "access": "rw"},
        {"name": "port", "key": False, "access": "r"},
    ]


def test_target_oid_from_cell():
    ops = {o.field: o for o in plan_row_update(_row(), {"name": "Reception"})}
    op = ops["name"]
    assert op.target_oid == f"{ROOT}.3.1200.1.1.19.1.2"
    assert op.old_value == "Front Desk" and op.new_value == "Reception"
    assert op.sendable and op.ber_type == "OCTET STRING" and op.wire_proven


def test_integer_field_is_octet_but_flagged():
    op = plan_row_update(_row(), {"cos": "3"})[0]
    assert op.sendable and op.ber_type == "OCTET STRING"  # proven wire form
    assert op.native_wire == "INTEGER" and op.wire_proven is False
    assert "catalog-derived" in op.note


def test_readonly_field_not_sendable():
    op = plan_row_update(_row(), {"port": "020202"})[0]
    assert op.sendable is False and "read-only" in op.note


def test_key_column_never_written():
    op = plan_row_update(_row(), {"dn": "2105"}, program=_Prog())[0]
    # dn is absent from the row's cells AND a key column — either way unsendable.
    assert op.sendable is False
    assert "key" in op.note or "not present" in op.note


def test_absent_field_unsendable_rowcreate_note():
    op = plan_row_update(_row(), {"brand_new": "x"})[0]
    assert op.sendable is False and "row-create is unproven" in op.note


def test_hard_exclusion_program():
    assert "116" in HARD_EXCLUDE_PROGRAMS
    op = plan_row_update(_row(), {"name": "x"}, program_number="116")[0]
    assert op.sendable is False and "hard exclusion" in op.note


def test_writable_fields_excludes_key_and_readonly():
    assert writable_fields(_Prog()) == {"name", "cos"}


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
