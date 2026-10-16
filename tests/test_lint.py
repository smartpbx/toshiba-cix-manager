"""Offline tests for lint.py (config linter / Problems panel, DESIGN_PLAN §6)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import lint  # noqa: E402
from toshiba_cix.index import build_index_from_views  # noqa: E402


def _cell(name, col, val, *, secret=False, access="rw"):
    return {"field_name": name, "col": col, "oid": f"x.{col}.{val}",
            "raw_value": val, "display_value": "" if val is None else str(val),
            "syntax": "OCTET STRING", "access": access, "is_secret": secret}


def _views():
    return {
        "programs": [
            {"catalog_key": "800Snmp", "program_number": "800",
             "menu_path": "Maintenance > SNMP", "label": "SNMP",
             "rows": [{"index": "1", "key": "1", "cells": [
                 _cell("communityName", 2, "communityName"),
             ]}]},
            {"catalog_key": "200StationAssign", "program_number": "200",
             "menu_path": "Station > Assignments", "label": "Station Assign",
             "rows": [
                 {"index": "2", "key": "2104", "cells": [
                     _cell("name", 19, ""),               # empty name
                     _cell("comment", 20, "Front Desk"),
                 ]},
                 {"index": "3", "key": "2105", "cells": [
                     _cell("name", 19, "Reception"),
                     _cell("comment", 20, "Lobby"),        # name != comment
                 ]},
             ]},
            {"catalog_key": "vmBoxes", "program_number": "VM",
             "menu_path": "Voice Mail > Boxes", "label": "Mailboxes",
             "rows": [{"index": "2104", "key": "2104", "cells": [
                 _cell("security_code", 1, "0000", secret=True),  # weak secret
             ]}]},
        ]
    }


def _ids(findings):
    return sorted(f["rule"] for f in findings)


def test_default_rules_loaded():
    rules = lint.load_rules()
    assert isinstance(rules, list) and rules


def test_findings_on_fixture():
    res = lint.lint_views(_views())
    ids = _ids(res["findings"])
    assert "default-community" in ids
    assert "weak-secret" in ids
    assert "empty-station-name" in ids
    assert "name-comment-mismatch" in ids
    assert res["counts"]["error"] >= 1  # the default community is an error


def test_default_community_is_error_with_location():
    res = lint.lint_views(_views())
    hit = next(f for f in res["findings"] if f["rule"] == "default-community")
    assert hit["severity"] == "error"
    assert hit["program_number"] == "800" and hit["field"] == "communityName"


def test_clean_config_has_no_findings():
    clean = {"programs": [
        {"catalog_key": "800Snmp", "program_number": "800", "rows": [
            {"index": "1", "key": "1",
             "cells": [_cell("communityName", 2, "Zx9-secret")]}]},
    ]}
    res = lint.lint_views(clean)
    assert res["counts"]["error"] == 0
    assert not any(f["rule"] == "default-community" for f in res["findings"])


def test_orphan_rule_uses_index_when_given():
    views = {"programs": [
        {"catalog_key": "309Did", "program_number": "309", "rows": [
            {"index": "1", "key": "1",
             "cells": [_cell("vmid_target", 3, "6999")]}]},  # points nowhere
    ]}
    idx = build_index_from_views(views)
    res = lint.lint_views(views, index=idx)
    assert any(f["rule"] == "orphan-vmid" for f in res["findings"])


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
