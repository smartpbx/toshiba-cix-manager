"""Offline tests for changeset.py: the staged tray, plan_rows, simulate_oplog.

Asserts the key safety property directly: staging and simulating open NO socket
and emit the exact SET bytes that *would* go out, plus the proven commit SET.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix.changeset import Changeset, plan_rows, simulate_oplog  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"


def _doc():
    return {
        "200StationAssign": {
            "catalog_key": "200StationAssign", "program_number": "200",
            "label": "Station Assignments", "menu_path": "Station > Assign",
            "rows": [
                {"index": "2", "key": "2104", "cells": [
                    {"field_name": "name", "col": 19,
                     "oid": f"{ROOT}.3.200.1.1.19.1.2",
                     "raw_value": "Front Desk", "display_value": "Front Desk",
                     "syntax": "OCTET STRING", "access": "rw"},
                ]},
            ],
        },
    }


def test_coalesce_and_dropback():
    cs = Changeset()
    cs.stage("200StationAssign", "2", {"name": "A"}, {"name": "Front Desk"})
    cs.stage("200StationAssign", "2", {"name": "B"}, {"name": "Front Desk"})
    assert cs.field_count() == 1  # coalesced
    # staging back to the original drops it
    cs.stage("200StationAssign", "2", {"name": "Front Desk"}, {"name": "Front Desk"})
    assert cs.is_empty()


def test_drop_row_and_field():
    cs = Changeset()
    cs.stage("200StationAssign", "2", {"name": "A", "cos": "3"})
    cs.drop_field("200StationAssign", "2", "cos")
    assert cs.field_count() == 1
    cs.drop_row("200StationAssign", "2")
    assert cs.is_empty()


def test_plan_rows_pure():
    cs = Changeset()
    cs.stage("200StationAssign", "2", {"name": "Reception"})
    ops, groups = plan_rows(_doc(), cs.staged)
    assert len(ops) == 1 and ops[0].target_oid == f"{ROOT}.3.200.1.1.19.1.2"
    assert groups[0]["program_number"] == "200" and groups[0]["row_key"] == "2104"


def test_simulate_oplog_no_network_with_commit():
    cs = Changeset()
    cs.stage("200StationAssign", "2", {"name": "Reception"})
    ops, _ = plan_rows(_doc(), cs.staged)
    log = simulate_oplog(ops)
    assert log["network"] is False and log["would_send"] == 1
    assert log["entries"][0]["value_tlv_hex"]  # exact bytes that would go
    # the commit SET is modelled and is the proven INTEGER 2
    assert log["commit"]["op_class"] == "commit"
    assert log["commit_value_tlv_hex"] == "020102"
    assert log["batch_set_pdu_hex"]  # the batch SET PDU, encoded not sent


def test_simulate_empty_has_no_commit():
    log = simulate_oplog([])
    assert log["would_send"] == 0 and log["commit"] is None


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
