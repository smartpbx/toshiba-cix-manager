"""Offline tests for the UI-schema builder (``tools/build_ui_schema``).

Builds the schema from the vendored inputs in-process (no network, fast) and
asserts the contract the engine and the React UI both depend on: every one of
the 186 programs has an archetype and a menu placement, every field carries the
five required keys plus a human title, enum values are captioned, binary pairs
are segmented, and the committed ``toshiba_cix/data/ui_schema.json`` is a fresh
build (the freshness gate CI also runs).

Run:  python3 tests/test_build_ui_schema.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import build_ui_schema as B  # noqa: E402

_SCHEMA = None


def _schema():
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = B.build_schema(B.load_inputs())
    return _SCHEMA


_ARCHETYPES = {"form", "grid_record", "special", "action"}


def test_counts_match_catalog():
    s = _schema()
    assert s["counts"]["programs"] == 186
    assert s["counts"]["fields"] == 2366
    assert s["counts"]["enum_fields"] == 787
    assert s["counts"]["feature_keys"] == 79
    # archetypes partition the 186 programs
    c = s["counts"]
    assert c["grid_record"] + c["form"] + c["special"] + c["actions"] == 186


def test_every_program_has_archetype_and_menu():
    s = _schema()
    assert len(s["programs"]) == 186
    for key, p in s["programs"].items():
        assert p["archetype"] in _ARCHETYPES, key
        assert p["menu_area"] in s["menu_area_order"], key
        assert p["catalog_key"] == key
        assert isinstance(p["tier"], int) and p["tier"] >= 1
        assert isinstance(p["fields"], list)


def test_every_field_is_named_and_controlled():
    s = _schema()
    for key, p in s["programs"].items():
        for f in p["fields"]:
            # a human title, never a bare OID
            assert f["title"], (key, f["name"])
            assert f["oid"], (key, f["name"])
            assert f["display_no"] and len(f["display_no"]) >= 2
            assert f["control"], (key, f["name"])


def test_enum_fields_have_captioned_values():
    s = _schema()
    f = _find_field(s, "103ClassOfService", "cosAbr")
    assert f["is_enum"] and f["is_binary_pair"]
    assert f["control"] == "segmented"
    assert f["binary_pair"]["on"]["label"] == "Enable"
    assert f["binary_pair"]["off"]["label"] == "Disable"
    # a multi-value enum carries ascending raw -> caption
    g = _find_field(s, "100CardSlot", "cardSlotPCMhighway")
    assert g["enum_values"]["1"] == "None"
    assert set(g["enum_values"]) >= {"1", "2", "3", "4"}


def test_special_layouts_assigned():
    s = _schema()
    assert s["counts"]["special"] == 6
    assert s["programs"]["200StationAssign"]["special_layout"] == "station_key_strip"
    assert s["programs"]["103ClassOfService"]["special_layout"] == "cos_matrix"


def test_danger_and_never_write_flags():
    s = _schema()
    p = s["programs"]["116DataInitialize"]
    assert p["danger"] is True and p["tier"] == 3
    assert p["archetype"] == "action" and p["never_write"] is True
    # a 116 field is not writable even if the catalog marks it rw
    for f in p["fields"]:
        assert f["writable"] is False


def test_feature_keys_and_actions():
    s = _schema()
    assert s["feature_keys"][0] == {"code": "000", "name": "Unused Key"}
    keys = {a["catalog_key"] for a in s["actions"]}
    assert "116DataInitialize" in keys and "systemRestart" in keys


def test_menu_tree_grouping():
    s = _schema()
    areas = [a["area"] for a in s["menu_tree"]]
    assert areas == [a for a in s["menu_area_order"] if a in areas]
    # every program in the tree appears exactly once
    seen = []
    for a in s["menu_tree"]:
        for it in a["items"]:
            seen.extend(it["programs"])
    assert len(seen) == len(set(seen)) == 186


def test_build_is_byte_reproducible():
    a = B.dumps(B.build_schema(B.load_inputs()))
    b = B.dumps(B.build_schema(B.load_inputs()))
    assert a == b


def test_committed_schema_is_fresh():
    fresh = B.dumps(_schema())
    with open(B.OUT_PATH, encoding="utf-8") as fh:
        committed = fh.read()
    assert committed == fresh, (
        "toshiba_cix/data/ui_schema.json is stale — "
        "run: python3 tools/build_ui_schema.py")


def _find_field(schema, prog_key, field_name):
    for f in schema["programs"][prog_key]["fields"]:
        if f["name"] == field_name:
            return f
    raise AssertionError(f"{field_name} not in {prog_key}")


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
