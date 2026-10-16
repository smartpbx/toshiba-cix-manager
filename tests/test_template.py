"""Offline tests for template.py (row templates, apply, drift, DESIGN_PLAN §7.6)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import template  # noqa: E402


def _cell(name, col, val, *, secret=False, access="rw"):
    return {"field_name": name, "col": col, "oid": f"x.{col}",
            "raw_value": val, "display_value": str(val),
            "syntax": "OCTET STRING", "access": access, "is_secret": secret}


def _view():
    return {
        "catalog_key": "200StationAssign", "program_number": "200",
        "label": "Station Assign",
        "rows": [{"index": "2", "key": "2104", "cells": [
            _cell("extension", 2, "2104"),             # equals key -> $dn
            _cell("name", 19, "Front Desk"),
            _cell("cos", 5, "3"),
            _cell("equipment_port", 1, "010101", access="r"),  # read-only
            _cell("security_code", 30, "4321", secret=True),   # stripped
        ]}],
    }


def test_capture_strips_identity_and_binds_dn():
    t = template.capture_row_template(_view(), "2", name="Standard DKT")
    assert t["kind"] == "row" and t["program_number"] == "200"
    # secret + read-only port are gone; the key value is bound to $dn
    assert "security_code" not in t["fields"]
    assert "equipment_port" not in t["fields"]
    assert t["fields"]["extension"] == "$dn"
    assert t["fields"]["name"] == "Front Desk" and t["fields"]["cos"] == "3"
    assert "security_code" in t["stripped"]


def test_apply_materialises_bindings():
    t = template.capture_row_template(_view(), "2")
    changes = template.apply_row_template(t, "5", {"dn": "2200"})
    assert changes["extension"] == "2200"        # $dn resolved
    assert changes["name"] == "Front Desk" and changes["cos"] == "3"


def test_drift_detects_difference():
    t = template.capture_row_template(_view(), "2")
    row = {"cells": [_cell("name", 19, "Reception"), _cell("cos", 5, "3"),
                     _cell("extension", 2, "2200")]}
    drift = template.template_drift(t, row, {"dn": "2200"})
    fields = {d["field"] for d in drift}
    assert "name" in fields and "cos" not in fields  # cos matches, name drifted
    assert "extension" not in fields                 # $dn resolved, no false hit


def test_capture_program_set():
    ps = template.capture_program_set(
        {"programs": [_view()]}, ["200StationAssign"], name="HQ COS")
    assert ps["kind"] == "program_set"
    rows = ps["programs"]["200StationAssign"]
    assert rows and "security_code" not in rows[0]["fields"]


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
