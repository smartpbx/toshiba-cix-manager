"""Offline tests for the diff presentation layer (diff_view.py) and the
vendored volatile-field list.

No network: two backups from the shared fixture are diffed, then annotated,
grouped by DN, attributed against a synthetic activity log, and exported to
every format. The load-bearing assertion is that a **sensitive** field never
leaks its value into the annotated structure or any exporter.

Run:  python3 tests/test_diff_view.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.backup as B  # noqa: E402
import toshiba_cix.diff_view as DV  # noqa: E402
from test_backup import _int, _octet, sample_capture  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402
from toshiba_cix.diff import diff_backups, load_volatile_oids  # noqa: E402

SECRET = "SuperSecret123"


def _ab_with_secret():
    """A (old) and B (new): a renamed station, an added station, and a changed
    system password (110) — the sensitive field the renderers must mask."""
    cat = load_catalog()
    data_a, info = sample_capture(cat)
    name_oid = info["name_oid"]
    pw_oid = cat.program("110PassWord").field("password")["oid"]
    data_a[f"{pw_oid}.1"] = _octet("oldpass")
    data_b = dict(data_a)
    data_b[f"{name_oid}.1.3.50.48.49"] = _octet("Reception")   # rename DN 201
    data_b[f"{name_oid}.1.3.50.48.51"] = _octet("Dock")        # add DN 203
    data_b[f"{pw_oid}.1"] = _octet(SECRET)                     # change the password
    a = B.build_backup(list(data_a.items()), cat, meta={"site": "A"})
    b = B.build_backup(list(data_b.items()), cat, meta={"site": "B"})
    return cat, a, b


def test_annotate_groups_by_menu_and_labels_values():
    cat, a, b = _ab_with_secret()
    ann = DV.annotate(diff_backups(a, b, catalog=cat), cat)
    stn = next(g for g in ann["groups"] if g["program"] == "200StationAssign")
    assert stn["menu_area"] == "Station"
    assert "Station" in (stn["menu_path"] or "")
    # a field line carries a title and the rename as display values
    field_lines = [ln for ln in stn["lines"] if ln["kind"] == "field_changed"]
    assert any(ln["title"] == "stationStationName"
               and ln["new_display"] == "Reception" for ln in field_lines)
    # the added row is first-class with its fields available to expand
    assert any(ln["kind"] == "row_added" and ln["fields"] for ln in stn["lines"])


def test_sensitive_value_never_leaks_in_structure_or_exporters():
    cat, a, b = _ab_with_secret()
    diff = diff_backups(a, b, catalog=cat)
    ann = DV.annotate(diff, cat)
    pw = next(g for g in ann["groups"] if g["program"] == "110PassWord")
    line = next(ln for ln in pw["lines"] if ln["kind"] == "field_changed")
    assert line["sensitive"] is True
    assert line["old_display"] == DV.MASK and line["new_display"] == DV.MASK
    assert "old" not in line and "new" not in line
    # none of the exporters may contain the plaintext
    blobs = [json.dumps(DV.to_json(diff, cat)), DV.to_text(diff, cat),
             DV.to_csv(diff, cat), DV.to_markdown(diff, cat),
             json.dumps(ann), json.dumps(DV.group_by_dn(ann))]
    for blob in blobs:
        assert SECRET not in blob
    # and the mask is actually present (so it is masked, not just dropped)
    assert DV.MASK in DV.to_markdown(diff, cat)


def test_group_by_dn_collects_across_programs():
    cat, a, b = _ab_with_secret()
    ann = DV.annotate(diff_backups(a, b, catalog=cat), cat)
    by_dn = DV.group_by_dn(ann)
    # DN 201 (renamed) is one of the keys (row keys carry a seq prefix, e.g.
    # "seq1/201"), and that bucket holds the station-name change
    hit = [b for b in by_dn["by_dn"] if "201" in str(b["row_key"])]
    assert hit and any(ln["title"] == "stationStationName"
                       for b in hit for ln in b["lines"])


def test_attribute_marks_known_and_outside_changes():
    cat, a, b = _ab_with_secret()
    ann = DV.annotate(diff_backups(a, b, catalog=cat), cat)
    # claim the station rename in the activity log; leave the password change
    activity = [{"event": "write", "operator": "cmannerow", "at": "2026-10-16",
                 "changeset": "cs-1",
                 "ops": [{"program": "200StationAssign",
                          "index": "1.3.50.48.49",
                          "field": "stationStationName"}]}]
    DV.attribute(ann, activity)
    stn = next(g for g in ann["groups"] if g["program"] == "200StationAssign")
    rename = next(ln for ln in stn["lines"]
                  if ln["kind"] == "field_changed" and ln["index"] == "1.3.50.48.49")
    assert rename["attribution"] == {"by": "cmannerow", "at": "2026-10-16",
                                     "changeset": "cs-1"}
    pw = next(g for g in ann["groups"] if g["program"] == "110PassWord")
    pwline = next(ln for ln in pw["lines"] if ln["kind"] == "field_changed")
    assert pwline["attribution"] == {"outside": True}


def test_volatile_fields_file_resolves_to_catalog_fields():
    cat = load_catalog()
    oids = load_volatile_oids()
    assert oids, "volatile_fields.json should ship with entries"
    # every entry resolves to a real catalog field (design §12 test)
    assert all(cat.field_for_oid(o) is not None for o in oids)


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
