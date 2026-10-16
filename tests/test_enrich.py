"""Offline tests for catalog-driven enrichment (the frontend contract).

A synthetic capture is built on **real catalog OIDs** across several feature
areas (trunks, DID, phantom DNs, hunt groups, voicemail, licensing, an enum
field) with made-up values — no customer data. Asserts the headline guarantees:
nothing renders as a bare OID for a cataloged field, every feature view
populates, enum values carry their label, and the per-cell contract is stable.

Run:  python3 tests/test_enrich.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from toshiba_cix import enrich as E  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402
from toshiba_cix.scan import CIXReader  # noqa: E402
from toshiba_cix.snmp import Value  # noqa: E402
from test_backup import make_backup  # noqa: E402
from test_decode import FakeClient  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"
REQUIRED_CELL_KEYS = {"col", "field_name", "oid", "raw_value", "display_value"}


def _oc(s: str) -> Value:
    return Value("octet", raw=s.encode("ascii"))


def _int(n: int) -> Value:
    return Value("int", int_value=n)


def _feature_capture(cat):
    """OID→Value across feature areas, all on genuine catalog field OIDs."""
    enum_oid = cat.program("100").field_by_column(5)["oid"]   # cardSlotTEI enum
    return [
        (f"{ROOT}.3.300.1.1.1.1", _int(1)),                   # trunk 300 trunkNo
        (f"{ROOT}.3.309.1.1.1.1", _oc("5551234")),            # DID 309
        (f"{ROOT}.3.206.1.1.1.1.3.52.48.48", _oc("400")),     # phantom DN 206
        (f"{ROOT}.3.209.1.1.1.1", _oc("100")),                # hunt group 209
        (f"{ROOT}.3.580.1.1.1.1", _int(1)),                   # voicemail port 580
        (f"{ROOT}.10.3.1.0", _int(7)),                        # licensing .10.3
        (f"{enum_oid}.1", _int(3)),                           # enum value
        (f"{ROOT}.3.49999.1.1.9.0", _oc("mystery")),          # uncataloged
    ]


# -- build_program_views ----------------------------------------------------
def test_no_bare_oids_for_cataloged_fields():
    cat = load_catalog()
    pv = E.build_program_views(_feature_capture(cat), cat)
    assert pv["stats"]["raw_oid_cells"] == 0
    assert pv["stats"]["named_cells"] == pv["stats"]["cells"] > 0
    # every cell carries a non-empty field name and the required contract keys
    for prog in pv["programs"]:
        for row in prog["rows"]:
            for cell in row["cells"]:
                assert REQUIRED_CELL_KEYS <= set(cell)
                assert cell["field_name"]
                assert cell["oid"].startswith(ROOT)


def test_per_program_metadata_present():
    cat = load_catalog()
    pv = E.build_program_views(_feature_capture(cat), cat)
    by_key = {p["catalog_key"]: p for p in pv["programs"]}
    trunk = by_key["300TrunkAssign"]
    assert trunk["program_number"] == "300"
    assert trunk["program_name"] == "TrunkAssign"
    assert trunk["menu_area"] == "Trunk"
    assert "Trunk" in trunk["menu_path"]


def test_feature_views_populate():
    cat = load_catalog()
    pv = E.build_program_views(_feature_capture(cat), cat)
    present = {f["key"] for f in pv["feature_views"] if f["present"]}
    assert {"trunks", "groups", "phantom", "voicemail", "licensing"} <= present
    # 'stations' got no station program in this capture → not present
    stations = next(f for f in pv["feature_views"] if f["key"] == "stations")
    assert stations["present"] is False


def test_enum_value_carries_label():
    cat = load_catalog()
    pv = E.build_program_views(_feature_capture(cat), cat)
    card = next(p for p in pv["programs"] if p["catalog_key"] == "100CardSlot")
    cell = card["rows"][0]["cells"][0]
    assert cell["is_enum"] is True
    assert cell["raw_value"] == 3
    assert cell["display_value"] == "singleTEI"      # labelled, not "3"


def test_menu_areas_grouped_and_ordered():
    cat = load_catalog()
    pv = E.build_program_views(_feature_capture(cat), cat)
    areas = [a["area"] for a in pv["menu_areas"]]
    assert "Trunk" in areas and "Station" in areas and "Licensing" in areas
    # System sorts before Trunk sorts before Licensing (canonical order)
    assert areas.index("Station") < areas.index("Trunk") < areas.index("Licensing")


def test_only_genuine_unknowns_are_uncataloged():
    cat = load_catalog()
    pv = E.build_program_views(_feature_capture(cat), cat)
    assert pv["stats"]["uncataloged"] == 1
    assert pv["uncataloged"][0]["oid"].endswith("3.49999.1.1.9.0")


def test_legacy_branches_not_flooded_into_uncataloged():
    # Identity (.7), equipment (.1.1.1) and the DN directory (.3.1200) are shown
    # in their own tabs; they must NOT appear as uncataloged bare OIDs.
    cat = load_catalog()
    pairs = [
        (f"{ROOT}.7.2.1.0", _oc("NA520MT067PNDN2---EM.00")),
        (f"{ROOT}.1.1.1.1.2", _oc("010101")),
        (f"{ROOT}.3.1200.1.1.2.1.3.50.48.48", _oc("200")),
        (f"{ROOT}.3.49999.1.1.9.0", _oc("mystery")),       # genuinely unknown
    ]
    pv = E.build_program_views(pairs, cat)
    assert pv["stats"]["uncataloged"] == 1
    assert pv["uncataloged"][0]["oid"].endswith("3.49999.1.1.9.0")


# -- program_views_from_backup ----------------------------------------------
def test_program_views_from_backup_matches_contract():
    doc, _ = make_backup()
    cat = load_catalog()
    pv = E.program_views_from_backup(doc, cat)
    assert pv["stats"]["raw_oid_cells"] == 0
    stn = next(p for p in pv["programs"] if p["catalog_key"] == "200StationAssign")
    names = {c["display_value"] for r in stn["rows"] for c in r["cells"]
             if c["field_name"] == "stationStationName"}
    assert {"Front Desk", "Lobby", "Warehouse"} <= names
    # reconstructed OID points back into the station-name column subtree
    for r in stn["rows"]:
        for c in r["cells"]:
            assert REQUIRED_CELL_KEYS <= set(c)
            assert c["oid"].startswith(f"{ROOT}.3.200.")


# -- scope resolution -------------------------------------------------------
def test_program_idents_for_scope():
    cat = load_catalog()
    assert E.program_idents_for_scope(cat, "core") is None
    assert E.program_idents_for_scope(cat, "all") is None
    trunks = E.program_idents_for_scope(cat, "trunks")
    assert "300TrunkAssign" in trunks and "309DID" in trunks
    # a menu-area name also resolves
    area = E.program_idents_for_scope(cat, "trunk")
    assert "300TrunkAssign" in area
    # 'features' is the union of every feature group
    feats = E.program_idents_for_scope(cat, "features")
    assert "licenseControl" in feats and "580VoiceMailData" in feats
    assert E.program_idents_for_scope(cat, "nonsense-scope") is None


def test_scope_roots_cover_only_selected_programs():
    cat = load_catalog()
    roots = E.scope_roots(cat, "voicemail")
    assert roots
    assert all(r.startswith(f"{ROOT}.3.579") or r.startswith(f"{ROOT}.3.580")
               for r in roots)


def test_reader_feature_scope_filters_the_walk():
    cat = load_catalog()
    # trunk row + station row + identity: a 'trunks' scan must read the trunk
    # (and identity) but NOT the station program.
    data = {
        f"{ROOT}.3.300.1.1.1.1": _int(5),
        f"{ROOT}.3.200.1.1.18.1.3.50.48.48": _oc("Front Desk"),
        f"{ROOT}.7.2.1.0": _oc("NA520MT067PNDN2---EM.00"),
    }
    doc = CIXReader(FakeClient(data), scope="trunks").read()
    assert doc["device"]["scope"] == "trunks"
    pv = doc["program_views"]
    keys = {p["catalog_key"] for p in pv["programs"]}
    assert "300TrunkAssign" in keys
    assert "200StationAssign" not in keys      # station program out of scope
    assert pv["stats"]["raw_oid_cells"] == 0


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
