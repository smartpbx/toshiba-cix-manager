"""Offline tests for history.py (per-field / per-row history + session diff)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import history  # noqa: E402


def _snap(sid, saved_at, name):
    return {
        "sid": sid, "saved_at": saved_at,
        "program_views": {"programs": [
            {"catalog_key": "200StationAssign", "program_number": "200",
             "rows": [{"index": "2", "key": "2104", "cells": [
                 {"field_name": "name", "col": 19, "raw_value": name,
                  "display_value": name},
                 {"field_name": "cos", "col": 5, "raw_value": "1",
                  "display_value": "1"},
             ]}]},
        ]},
    }


def _snaps():
    return [
        _snap("s1", "2026-01-01", "Desk A"),
        _snap("s2", "2026-02-01", "Desk A"),
        _snap("s3", "2026-03-01", "Reception"),
    ]


def test_field_history_marks_change():
    h = history.field_history(_snaps(), "200StationAssign", "2", "name")
    assert [e["value"] for e in h] == ["Desk A", "Desk A", "Reception"]
    assert [e["changed"] for e in h] == [False, False, True]


def test_field_history_by_program_number():
    h = history.field_history(_snaps(), "200", "2", "name")
    assert h[-1]["value"] == "Reception" and h[-1]["changed"] is True


def test_row_history_timeline():
    h = history.row_history(_snaps(), "200StationAssign", "2")
    assert h["fields"]["name"] == ["Desk A", "Desk A", "Reception"]
    # only the 3rd snapshot recorded a change
    changed = [t for t in h["timeline"] if t["changes"]]
    assert len(changed) == 1 and "name" in changed[0]["changes"]
    assert changed[0]["changes"]["name"] == {"old": "Desk A", "new": "Reception"}


def test_session_diff():
    base = _snap("s1", "2026-01-01", "Desk A")["program_views"]
    now = _snap("s3", "2026-03-01", "Reception")["program_views"]
    d = history.session_diff(now, base)
    assert len(d["changed"]) == 1
    c = d["changed"][0]
    assert c["field"] == "name" and c["old"] == "Desk A" and c["new"] == "Reception"
    assert d["rows_added"] == [] and d["rows_removed"] == []


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
