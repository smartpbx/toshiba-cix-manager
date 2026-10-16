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


def _system_views():
    return {"programs": [
        _view(),
        {"catalog_key": "103SystemOptions", "program_number": "103",
         "label": "System Options",
         "rows": [{"index": "1", "key": "1", "cells": [
             _cell("account_code_digits", 3, "6"),
             _cell("ip_address", 9, "192.168.1.1"),   # identity -> stripped
         ]}]},
        {"catalog_key": "999Empty", "program_number": "999", "label": "Empty",
         "rows": []},
    ]}


def test_capture_system_all_programs_stripped():
    syst = template.capture_system(_system_views(), name="Baseline")
    assert syst["kind"] == "system" and syst["name"] == "Baseline"
    # every program with rows is captured; the empty one is not
    assert set(syst["programs"]) == {"200StationAssign", "103SystemOptions"}
    assert syst["program_count"] == 2
    opts = syst["programs"]["103SystemOptions"][0]["fields"]
    assert opts["account_code_digits"] == "6"
    assert "ip_address" not in opts          # identity field stripped
    # secret / read-only still gone in the station rows
    st = syst["programs"]["200StationAssign"][0]["fields"]
    assert "security_code" not in st and "equipment_port" not in st


def test_capture_system_exclude():
    syst = template.capture_system(_system_views(), exclude=["200"])
    assert set(syst["programs"]) == {"103SystemOptions"}  # by program number


def test_capture_phone_profile_binds_and_drifts():
    prof = template.capture_phone_profile(
        _view(), "2", name="Standard DKT", profile="Front line DKT")
    assert prof["kind"] == "phone_profile" and prof["profile"] == "Front line DKT"
    assert prof["fields"]["extension"] == "$dn"         # re-targets on apply
    assert "security_code" not in prof["fields"]
    # applied onto a new DN, then badged against a drifted live row
    changes = template.apply_row_template(prof, "7", {"dn": "2300"})
    assert changes["extension"] == "2300"
    row = {"cells": [_cell("name", 19, "Changed"), _cell("cos", 5, "3"),
                     _cell("extension", 2, "2300")]}
    badge = template.drift_badge(prof, row, {"dn": "2300"})
    assert badge["count"] == 1 and badge["clean"] is False
    assert badge["fields"][0]["field"] == "name"


def test_drift_badge_clean_when_matching():
    t = template.capture_row_template(_view(), "2")
    row = {"cells": [_cell("name", 19, "Front Desk"), _cell("cos", 5, "3"),
                     _cell("extension", 2, "2104")]}
    badge = template.drift_badge(t, row, {"dn": "2104"})
    assert badge["clean"] is True and badge["count"] == 0


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
