"""Offline tests for the catalog-driven restore (planner + gated commit).

The planner is tested pure (which OIDs/values it would SET, read-only never
sent, wire-type flagged). The live commit is tested against an in-memory fake
agent that reflects SETs so read-back verifies — no PBX is ever touched, and
the gate (WRITES_ENABLED + confirm) is asserted.

Run:  python3 tests/test_restore.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.backup as B  # noqa: E402
import toshiba_cix.restore as R  # noqa: E402
import toshiba_cix.write as W  # noqa: E402
from test_backup import BackupFake, ROOT, _int, _octet, sample_capture  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402
from toshiba_cix.decode import MISSING  # noqa: E402
from toshiba_cix.diff import diff_backups  # noqa: E402
from toshiba_cix.snmp import Value  # noqa: E402


def _backup(cat=None):
    cat = cat or load_catalog()
    data, info = sample_capture(cat)
    doc = B.build_backup(list(data.items()), cat, meta={"site": "A"})
    return cat, doc, info


# -- planner (pure) ---------------------------------------------------------
def test_plan_marks_writable_and_readonly():
    cat, doc, info = _backup()
    ops = R.plan_restore(doc, cat)
    by_oid = {o.target_oid: o for o in ops if o.target_oid}
    name_oid = cat.program("200").field_by_column(18)["oid"]
    # the three station names are sendable, addressed at their exact instance
    sendable_names = [o for o in ops if o.field_name == "stationStationName"
                      and o.sendable]
    assert len(sendable_names) == 3
    assert all(o.target_oid.startswith(name_oid + ".") for o in sendable_names)
    # the read-only field is planned but NEVER sendable
    ro_name = info["ro_fld"]["name"]
    ro_ops = [o for o in ops if o.field_name == ro_name]
    assert ro_ops and all(not o.sendable and not o.writable for o in ro_ops)
    assert all("read-only" in o.note for o in ro_ops)


def test_plan_wire_type_flag():
    cat, doc, info = _backup()
    ops = R.plan_restore(doc, cat)
    names = [o for o in ops if o.field_name == "stationStationName"]
    assert all(o.ber_type == "OCTET STRING" and o.wire_type_proven
               for o in names)
    # the scalar INTEGER timer is sendable but its wire type is unproven
    timer = [o for o in ops if o.ber_type == "INTEGER" and o.sendable]
    assert timer and all(not o.wire_type_proven for o in timer)
    assert all("catalog-derived" in o.note for o in timer)


def test_plan_summary_counts():
    cat, doc, info = _backup()
    s = R.plan_summary(R.plan_restore(doc, cat))
    assert s["sendable"] >= 3           # the station names + the timer
    assert s["read_only"] >= 1
    assert s["unproven_wire_type"] >= 1


def test_plan_missing_value_not_sent():
    cat = load_catalog()
    name_oid = cat.program("200").field_by_column(18)["oid"]
    doc = B.build_backup([(f"{name_oid}.1.3.50.48.48", Value("missing"))], cat)
    ops = R.plan_restore(doc, cat)
    assert ops and all(not o.sendable for o in ops)
    assert any("absent" in o.note for o in ops)


def test_plan_program_filter():
    cat, doc, info = _backup()
    ops = R.plan_restore(doc, cat, programs=["200"])
    assert ops and all(o.program == "200StationAssign" for o in ops)


def test_plan_from_diff_restricts():
    cat, a, info = _backup()
    data_b, _ = sample_capture(cat, names=("Front Desk", "Reception", "Warehouse"))
    b = B.build_backup(list(data_b.items()), cat, meta={"site": "B"})
    d = diff_backups(a, b, catalog=cat)
    ops = R.plan_restore(b, cat, from_diff=d)
    sendable = [o for o in ops if o.sendable]
    # only the one renamed station is in the diff -> only it is planned sendable
    assert len(sendable) == 1
    assert sendable[0].new_value == "Reception"


# -- gated commit (fake agent) ---------------------------------------------
def test_preview_sends_nothing():
    cat, doc, info = _backup()
    agent = BackupFake({})          # empty: a real SET would be observable
    res = R.restore(agent, doc, cat, confirm=False)
    assert res["ok"] is True and res["mode"] == "preview"
    assert res["summary"]["sendable"] >= 3
    assert agent._data == {}        # nothing was written


def test_confirm_writes_verifies_and_skips_readonly():
    cat, doc, info = _backup()
    name_oid = cat.program("200").field_by_column(18)["oid"]
    ro_oid = info["ro_fld"]["oid"]
    # a live device holding DIFFERENT station names and a read-only value
    live = BackupFake({
        f"{name_oid}.1.3.50.48.48": _octet("OLD-A"),
        f"{name_oid}.1.3.50.48.49": _octet("OLD-B"),
        f"{name_oid}.1.3.50.48.50": _octet("OLD-C"),
        f"{ro_oid}.0": _int(7),
    })
    res = R.restore(live, doc, cat, confirm=True)
    assert res["ok"] is True and res["mode"] == "write"
    assert res["verified_all"] is True
    assert all(r["match"] for r in res["results"])
    # the station names were restored to the backup's values
    assert live._data[f"{name_oid}.1.3.50.48.48"].raw == b"Front Desk"
    assert live._data[f"{name_oid}.1.3.50.48.49"].raw == b"Lobby"
    # the read-only field was NEVER written (still the device's original)
    assert live._data[f"{ro_oid}.0"].int_value == 7


def test_confirm_batches():
    cat, doc, info = _backup()
    live = BackupFake({})
    res = R.restore(live, doc, cat, confirm=True, batch_size=2)
    assert res["ok"] is True
    assert len(res["batches"]) >= 2          # chunked into batches of 2
    assert res["wrote"] == res["summary"]["sendable"]


def test_confirm_requires_writes_enabled():
    cat, doc, info = _backup()
    live = BackupFake({})
    saved = W.WRITES_ENABLED
    W.WRITES_ENABLED = False
    try:
        R.restore(live, doc, cat, confirm=True)
    except W.WriteError as exc:
        assert "disabled" in str(exc).lower()
    else:
        raise AssertionError("restore must refuse when WRITES_ENABLED is False")
    finally:
        W.WRITES_ENABLED = saved


def test_nothing_sendable_raises():
    cat = load_catalog()
    ro_prog, ro_fld = next((p, f) for p in cat.programs.values()
                           for f in p.fields if f.get("access") == "r"
                           and ".1.1." in f.get("oid", ""))
    doc = B.build_backup([(f"{ro_fld['oid']}.0", _int(5))], cat)
    try:
        R.restore(BackupFake({}), doc, cat, confirm=True)
    except W.WriteError:
        pass
    else:
        raise AssertionError("restore with only read-only ops must raise")


def test_detects_failed_write():
    # an agent that accepts SETs but drops them -> read-back must flag it
    cat, doc, info = _backup()

    class Deaf(BackupFake):
        def set(self, varbinds):
            from toshiba_cix.snmp import Response
            return Response(1, 0, 0, [])

    res = R.restore(Deaf({}), doc, cat, confirm=True)
    assert res["ok"] is False
    assert any(not r["match"] for r in res["results"])


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
