"""Offline tests for the value index + typed where-used (index.py).

Builds an index over a hand-built backup doc (real catalog keys / field names,
invented values) and over the shared fixture, then exercises lookup (exact /
prefix / substring), typed references_to (what points at a DN / a VMID), and the
palette query grammar (prg: / field: / cos: / bare value). Also checks every
references.json field name is a real catalog field. No network.

Run:  python3 tests/test_index.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.backup as B  # noqa: E402
import toshiba_cix.index as IX  # noqa: E402
from test_backup import sample_capture  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402

CAT = load_catalog()


def _doc():
    """A small doc: three stations, one with its voicemail id set to DN 2104,
    a hunt group whose member is DN 2104, and a 103 COS row 3."""
    return {
        "format": B.FORMAT, "format_version": 2,
        "meta": {"site": "WhereUsed", "snapshot": {"id": "wu-1"}},
        "programs": {
            "200StationAssign": {"number": "200", "name": "StationAssign", "rows": [
                {"index": "1.4.50.49.48.52", "key": "2104",
                 "fields": {"stationStationName": "Front Desk",
                            "stationVoiceMailId": "2104"}},
                {"index": "1.4.50.49.48.53", "key": "2105",
                 "fields": {"stationStationName": "Lobby",
                            "stationVoiceMailId": "2104"}}]},
            "209StationHuntGroup": {"number": "209", "name": "StationHuntGroup",
                "rows": [{"index": "3", "key": "3",
                          "fields": {"huntGrpMemberDn": "2104"}}]},
            "103ClassOfService": {"number": "103", "name": "ClassOfService",
                "rows": [{"index": "3", "key": "3", "fields": {"cosCos": "3"}}]},
        },
        "unmatched": [],
    }


def test_lookup_exact_prefix_substring():
    idx = IX.build_index(_doc(), CAT)
    # exact: DN 2104 appears in several fields
    hits = idx.lookup("2104")
    fields = {h["field"] for h in hits}
    assert "stationVoiceMailId" in fields and "huntGrpMemberDn" in fields
    # prefix: "Front" finds the station name
    assert any(h["field"] == "stationStationName"
               for h in idx.lookup("Front", match="prefix"))
    # substring, case-insensitive
    assert idx.lookup("lobby", match="substring")


def test_references_to_is_typed_where_used():
    idx = IX.build_index(_doc(), CAT)
    refs = idx.references_to("2104")
    # only reference fields (VMID + hunt member DN), not the plain name field
    kinds = {r["ref_kind"] for r in refs}
    assert kinds == {"dn", "vmid"}
    assert all(r["field"] in ("stationVoiceMailId", "huntGrpMemberDn") for r in refs)
    # scoped to one kind
    dn_only = idx.references_to("2104", kind="dn")
    assert dn_only and all(r["ref_kind"] == "dn" for r in dn_only)


def test_display_no_and_menu_path_attached():
    idx = IX.build_index(_doc(), CAT)
    name_hit = next(h for h in idx.lookup("Front Desk"))
    assert name_hit["menu_path"] and "Station" in name_hit["menu_path"]
    # stationStationName is column 18 -> display_no "18"
    assert name_hit["display_no"] == "18"


def test_palette_search_grammar():
    idx = IX.build_index(_doc(), CAT)
    # bare value -> grouped by program
    res = IX.search(idx, "2104")
    assert res["count"] >= 2
    progs = {g["program"] for g in res["groups"]}
    assert "200StationAssign" in progs
    # field-scoped
    res = IX.search(idx, "field:stationVoiceMailId")
    assert all(o["field"] == "stationVoiceMailId"
               for g in res["groups"] for o in g["occurrences"])
    # program-scoped
    res = IX.search(idx, "prg:209")
    assert res["count"] == 1
    # cos: resolves the 103 row and reverse references
    res = IX.search(idx, "cos:3")
    assert res["count"] >= 1


def test_index_over_fixture_resolves_station_name():
    data, _ = sample_capture(CAT)
    doc = B.build_backup(list(data.items()), CAT)
    idx = IX.build_index(doc, CAT)
    assert idx.lookup("Front Desk")
    assert len(idx) > 0


def test_references_json_fields_are_real_catalog_fields():
    refs = IX.load_references()
    assert refs, "references.json should ship with entries"
    known = {f.get("name") for p in CAT.programs.values() for f in p.fields}
    missing = [n for n in refs if n not in known]
    assert not missing, missing[:5]


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
