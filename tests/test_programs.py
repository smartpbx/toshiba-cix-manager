"""Offline tests for the generic single-program read (toshiba_cix.programs).

Reuses the backup tests' lexical fake agent (``BackupFake`` + ``sample_capture``
— real catalog OIDs, invented values, no network) so ``list_rows`` /
``get_row`` are exercised against the same synthetic CIX the backup path uses,
plus a focused enum row so the enum-caption contract (no bare OIDs, raw value
kept) is checked explicitly.

Run:  python3 tests/test_programs.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.programs as P  # noqa: E402
from test_backup import BackupFake, sample_capture  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402
from toshiba_cix.snmp import Value  # noqa: E402

CAT = load_catalog()
DN200_INDEX = "1.3.50.48.48"   # rowseq 1, len 3, ascii "200" (sample_capture)


def _enum_capture():
    """sample_capture plus a stationType enum on DN 200's row."""
    data, info = sample_capture(CAT)
    type_oid = CAT.program("200").field("stationType")["oid"]
    data[f"{type_oid}.{DN200_INDEX}"] = Value("int", int_value=1)  # 1 -> DKT
    return data, info


# -- resolve ---------------------------------------------------------------
def test_resolve_program_by_key_number_name():
    assert P.resolve_program(CAT, "200StationAssign").key == "200StationAssign"
    assert P.resolve_program(CAT, "200").key == "200StationAssign"
    assert P.resolve_program(CAT, "StationAssign").key == "200StationAssign"
    assert P.resolve_program(CAT, "nope-not-a-program") is None
    # an already-resolved Program passes through unchanged
    prog = CAT.program("104")
    assert P.resolve_program(CAT, prog) is prog


# -- list_rows -------------------------------------------------------------
def test_list_rows_returns_single_enriched_view():
    data, _ = sample_capture(CAT)
    view, error = P.list_rows(BackupFake(data), CAT, "200")
    assert error is None
    assert view["catalog_key"] == "200StationAssign"
    assert view["program_number"] == "200"
    assert view["menu_area"] == "Station"
    assert view["menu_path"] and view["label"]
    assert view["row_count"] == 3          # three DNs in the capture
    names = {c["display_value"]
             for r in view["rows"] for c in r["cells"]
             if c["field_name"] == "stationStationName"}
    assert names == {"Front Desk", "Lobby", "Warehouse"}


def test_list_rows_cells_are_named_never_bare_oids():
    data, _ = sample_capture(CAT)
    view, _ = P.list_rows(BackupFake(data), CAT, "200")
    for row in view["rows"]:
        assert row["cells"], "a row must carry its cells"
        for cell in row["cells"]:
            # the five required contract keys, field_name always present
            for k in ("col", "field_name", "oid", "raw_value", "display_value"):
                assert k in cell
            assert cell["field_name"], "every cataloged cell is named"


def test_list_rows_enum_caption_with_raw_kept():
    # enrich emits the catalog's enum label (the MOF symbol, e.g. "dKT"); the
    # UI title-cases it to "DKT" via ui_schema's enum_values. What the contract
    # must guarantee here: a label, never the bare integer, and the raw kept.
    data, _ = _enum_capture()
    view, _ = P.list_rows(BackupFake(data), CAT, "200")
    row = next(r for r in view["rows"] if r["index"] == DN200_INDEX)
    type_cell = next(c for c in row["cells"] if c["field_name"] == "stationType")
    assert type_cell["is_enum"] is True
    assert type_cell["display_value"] == CAT.enum_label(
        CAT.program("200").field("stationType"), 1)
    assert type_cell["display_value"] != "1"     # a caption, not the raw int
    assert type_cell["raw_value"] == 1           # raw kept for diffs/hover


def test_list_rows_scalar_form_program():
    data, _ = sample_capture(CAT)          # sets one scalar timer in 104
    view, _ = P.list_rows(BackupFake(data), CAT, "104")
    assert view["catalog_key"] == "104SystemTimer"
    assert view["row_count"] == 1          # scalar programs are one row
    assert view["rows"][0]["cells"]


def test_list_rows_empty_program_is_a_shaped_view():
    data, _ = sample_capture(CAT)          # no 103 data in the capture
    view, error = P.list_rows(BackupFake(data), CAT, "103")
    assert error is None
    assert view["catalog_key"] == "103ClassOfService"
    assert view["row_count"] == 0 and view["rows"] == []
    assert view["menu_area"] == "System"   # metadata still present


def test_list_rows_unknown_program_raises():
    try:
        P.list_rows(BackupFake({}), CAT, "not-a-real-program")
    except ValueError:
        return
    raise AssertionError("expected ValueError for an unknown program")


# -- get_row (targeted GET) ------------------------------------------------
def test_get_row_reads_one_instance():
    data, _ = _enum_capture()
    row, error = P.get_row(BackupFake(data), CAT, "200", DN200_INDEX)
    assert error is None and row is not None
    assert row["index"] == DN200_INDEX
    by_name = {c["field_name"]: c for c in row["cells"]}
    assert by_name["stationStationName"]["display_value"] == "Front Desk"
    assert by_name["stationType"]["raw_value"] == 1
    assert by_name["stationType"]["is_enum"] is True


def test_get_row_missing_instance_returns_none():
    data, _ = sample_capture(CAT)
    row, error = P.get_row(BackupFake(data), CAT, "200", "9.9.9.9")
    assert error is None
    assert row is None


def test_get_row_scalar_index_zero():
    data, _ = sample_capture(CAT)
    row, error = P.get_row(BackupFake(data), CAT, "104", "0")
    assert error is None and row is not None
    assert row["cells"]


def test_get_row_as_view_carries_metadata():
    data, _ = _enum_capture()
    view, error = P.get_row(BackupFake(data), CAT, "200", DN200_INDEX,
                            as_view=True)
    assert error is None
    assert view["catalog_key"] == "200StationAssign"
    assert view["row_count"] == 1


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
