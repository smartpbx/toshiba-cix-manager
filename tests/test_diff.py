"""Offline tests for the backup diff.

Builds two backups from the synthetic fixture (shared with the backup tests),
mutates B (a renamed station, an added station, and a changed *read-only*
field), and checks the structured diff and its text rendering. No network.

Run:  python3 tests/test_diff.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.backup as B  # noqa: E402
from test_backup import ROOT, _int, _octet, sample_capture  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402
from toshiba_cix.diff import diff_backups, has_changes, render_diff_text  # noqa: E402


def _ab():
    """Backup A (old) and B (new): B renames a station, adds one, and bumps a
    read-only field."""
    cat = load_catalog()
    data_a, info = sample_capture(cat)
    name_oid = info["name_oid"]
    ro_oid = info["ro_fld"]["oid"]
    data_b = dict(data_a)
    data_b[f"{name_oid}.1.3.50.48.49"] = _octet("Reception")      # rename DN 201
    data_b[f"{name_oid}.1.3.50.48.51"] = _octet("Dock")           # add DN 203
    data_b[f"{ro_oid}.0"] = _int(9)                               # read-only bump
    a = B.build_backup(list(data_a.items()), cat, meta={"site": "A"})
    b = B.build_backup(list(data_b.items()), cat, meta={"site": "B"})
    return cat, a, b, info


def test_identical_backups_no_changes():
    cat = load_catalog()
    data, _ = sample_capture(cat)
    a = B.build_backup(list(data.items()), cat)
    b = B.build_backup(list(data.items()), cat)
    d = diff_backups(a, b, catalog=cat)
    assert not has_changes(d)
    assert "No programming differences" in render_diff_text(d)


def test_field_change_and_row_add():
    cat, a, b, _ = _ab()
    d = diff_backups(a, b, catalog=cat)
    pc = d["programs_changed"]["200StationAssign"]
    changed = {(c["field"], c["old"], c["new"]) for c in pc["fields_changed"]}
    assert ("stationStationName", "Lobby", "Reception") in changed
    # the added DN 203 shows up as an added row, carrying its full fields (v2)
    added = pc["rows_added"]
    assert any(r["index"].endswith("50.48.51") for r in added)
    assert all(isinstance(r, dict) and "fields" in r for r in added)
    assert d["summary"]["fields_changed"] >= 1
    assert d["summary"]["rows_added"] >= 1


def test_readonly_change_hidden_by_default():
    cat, a, b, info = _ab()
    d = diff_backups(a, b, catalog=cat, ignore_readonly=True)
    assert d["ignore_readonly"] is True
    assert d["summary"]["ignored_readonly"] >= 1
    # the read-only field's program/field is NOT in fields_changed
    ro_name = info["ro_fld"]["name"]
    for pc in d["programs_changed"].values():
        assert all(c["field"].split("#")[0] != ro_name
                   for c in pc["fields_changed"])


def test_readonly_change_shown_when_requested():
    cat, a, b, info = _ab()
    d = diff_backups(a, b, catalog=cat, ignore_readonly=False)
    ro_name = info["ro_fld"]["name"]
    all_changed = [c["field"].split("#")[0]
                   for pc in d["programs_changed"].values()
                   for c in pc["fields_changed"]]
    assert ro_name in all_changed


def test_no_catalog_cannot_hide_readonly():
    cat, a, b, info = _ab()
    d = diff_backups(a, b, catalog=None, ignore_readonly=True)
    # without a catalog, read-only is indistinguishable, so the change shows
    assert d["ignore_readonly"] is False
    ro_name = info["ro_fld"]["name"]
    all_changed = [c["field"].split("#")[0]
                   for pc in d["programs_changed"].values()
                   for c in pc["fields_changed"]]
    assert ro_name in all_changed


def test_program_added_removed():
    cat = load_catalog()
    data, _ = sample_capture(cat)
    a = B.build_backup(list(data.items()), cat)
    b = B.build_backup(list(data.items()), cat)
    # drop a program from A, add a fake program to B
    removed = sorted(a["programs"])[0]
    a["programs"].pop(removed)
    b["programs"]["ZZZExtra"] = {"number": "999", "name": "Extra", "rows": []}
    d = diff_backups(a, b, catalog=cat)
    assert "ZZZExtra" in d["programs_added"]
    assert removed in d["programs_added"] or removed in d["programs_removed"]


def test_render_diff_text():
    cat, a, b, _ = _ab()
    text = render_diff_text(diff_backups(a, b, catalog=cat))
    assert "backup diff" in text
    assert "Reception" in text
    assert "Summary" in text


# -- v2 additions: exclusions, volatile, cross-site key matching ------------
def test_exclude_programs_drops_them_whole():
    cat, a, b, _ = _ab()
    d = diff_backups(a, b, catalog=cat,
                     exclude_programs={"200StationAssign"})
    assert "200StationAssign" not in d["programs_changed"]
    assert d["excluded_programs"] == ["200StationAssign"]


def test_exclude_fields_drops_per_row_identity():
    cat, a, b, _ = _ab()
    # the station name is the only changed rw field; excluding it hides it
    d = diff_backups(a, b, catalog=cat,
                     exclude_fields={"stationStationName"})
    changed = [c["field"].split("#")[0]
               for pc in d["programs_changed"].values()
               for c in pc["fields_changed"]]
    assert "stationStationName" not in changed


def test_volatile_fields_hidden_and_counted():
    cat = load_catalog()
    data_a, info = sample_capture(cat)
    # mutate the scalar timer (104) which we declare volatile for this test
    timer_oid = info["timer_oid"]
    data_b = dict(data_a)
    data_b[f"{timer_oid}.0"] = _int(45)
    a = B.build_backup(list(data_a.items()), cat)
    b = B.build_backup(list(data_b.items()), cat)
    shown = diff_backups(a, b, catalog=cat)
    assert shown["summary"]["fields_changed"] >= 1
    hidden = diff_backups(a, b, catalog=cat, volatile={timer_oid})
    assert hidden["summary"]["volatile_hidden"] >= 1
    assert hidden["summary"]["fields_changed"] == \
        shown["summary"]["fields_changed"] - 1


def test_cross_site_key_matching_equals_index_on_same_system():
    # On one system, matching on key must give the same field changes as index
    cat, a, b, _ = _ab()
    by_index = diff_backups(a, b, catalog=cat)
    by_key = diff_backups(a, b, catalog=cat, match_rows_on="key")
    assert by_key["match_rows_on"] == "key"
    assert by_index["summary"]["fields_changed"] == \
        by_key["summary"]["fields_changed"]


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
