"""Offline tests for the vendored eManager catalog and its lookups.

Exercises loading the vendored JSON, program/field lookup (by key, number and
name), exact instance-OID construction and longest-prefix attribution, syntax-
aware decode/encode, the read-only/key flags, duplicate-field-name
disambiguation and the (empty-by-default) enum-label hook. No network, no live
CIX — just the vendored catalog file.

Run:  python3 tests/test_catalog.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import catalog as C  # noqa: E402
from toshiba_cix.catalog import Catalog, load_catalog  # noqa: E402
from toshiba_cix.decode import MISSING  # noqa: E402
from toshiba_cix.snmp import Value  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"


def _octet(s: str) -> Value:
    return Value("octet", raw=s.encode("ascii"))


def _int(n: int) -> Value:
    return Value("int", int_value=n)


def test_load_and_summary():
    cat = load_catalog()
    s = cat.summary()
    assert s["programs"] == 186
    assert s["fields"] == 2366
    assert s["writable"] == 1653
    assert s["catalog_version"].startswith("re-")
    assert cat.version == s["catalog_version"]


def test_version_is_content_hash():
    # Two loads of the same bytes agree; a byte change moves the version.
    cat = load_catalog()
    same = Catalog(C.load_catalog_text())
    assert same.version == cat.version
    other = Catalog('{"X":{"number":"9","name":"X","group_oid":"1.2","fields":[]}}')
    assert other.version != cat.version


def test_program_lookup_by_key_number_name():
    cat = load_catalog()
    by_key = cat.program("200StationAssign")
    by_num = cat.program("200")
    by_num_int = cat.program(200)
    by_name = cat.program("StationAssign")
    assert by_key is by_num is by_num_int is by_name
    assert by_key.key == "200StationAssign"
    assert by_key.number == "200"
    assert cat.program("nope-not-a-program") is None


def test_station_name_anchor():
    # The proven write anchor: station name = program 200 col 18.
    cat = load_catalog()
    fld = cat.program("200").field_by_column(18)
    assert fld["name"] == "stationStationName"
    assert fld["oid"] == f"{ROOT}.3.200.1.1.18"
    assert fld["syntax"] == "DisplayString"
    assert fld["access"] == "rw"
    assert Catalog.is_writable(fld)


def test_instance_oid_roundtrip():
    cat = load_catalog()
    fld = cat.program("200").field_by_column(18)
    inst = cat.instance_oid(fld, "1.3.50.48.48")
    assert inst == f"{ROOT}.3.200.1.1.18.1.3.50.48.48"
    prog_key, got, tail = cat.attribute_oid(inst)
    assert prog_key == "200StationAssign"
    assert got["name"] == "stationStationName"
    assert tail == "1.3.50.48.48"
    # tuple / list index and empty index also work
    assert cat.instance_oid(fld, (1, 3, 50)) == f"{fld['oid']}.1.3.50"
    assert cat.instance_oid(fld, "") == fld["oid"]


def test_attribute_unknown_oid_returns_none():
    cat = load_catalog()
    assert cat.attribute_oid("1.3.6.1.4.1.9999.1.2.3") is None


def test_attribute_longest_prefix_wins():
    # There exist field OIDs that are a prefix of another field OID; the more
    # specific (longer, exact) field must win so its value is not misattributed.
    cat = load_catalog()
    pairs = [(a, b) for a in cat.by_oid for b in cat.by_oid
             if b.startswith(a + ".")]
    assert pairs, "expected at least one prefix-overlap pair in the catalog"
    shorter, longer = pairs[0]
    pk, fld, tail = cat.attribute_oid(longer)
    assert fld["oid"] == longer and tail == ""      # exact match wins


def test_scalar_program_without_entry_marker():
    # Scalar tables (e.g. 104 System Timer) are group_oid.<col>, no ".1.1.".
    cat = load_catalog()
    p104 = cat.program("104")
    fld = p104.fields[0]
    assert ".1.1." not in fld["oid"]
    pk, got, tail = cat.attribute_oid(fld["oid"] + ".0")
    assert pk == p104.key and got["oid"] == fld["oid"] and tail == "0"


def test_decode_ipaddress():
    cat = load_catalog()
    ipf = next(f for p in cat.programs.values() for f in p.fields
               if f.get("syntax") == "IpAddress")
    out = cat.decode_field_value(ipf, Value("octet", raw=bytes([192, 168, 1, 50])))
    assert out == "192.168.1.50"


def test_decode_faithful_wire_type():
    cat = load_catalog()
    name = cat.program("200").field_by_column(18)
    assert cat.decode_field_value(name, _octet("Front Desk")) == "Front Desk"
    assert cat.decode_field_value(name, _int(7)) == 7
    assert cat.decode_field_value(name, Value("missing")) == MISSING
    assert cat.decode_field_value(name, None) == MISSING


def test_encode_dispatch():
    cat = load_catalog()
    name = cat.program("200").field_by_column(18)
    t_str, _ = cat.encode_field_value(name, "Front Desk")
    t_int, _ = cat.encode_field_value(name, 5)
    t_bool, _ = cat.encode_field_value(name, True)
    assert t_str == "OCTET STRING"
    assert t_int == "INTEGER"
    assert t_bool == "INTEGER"       # bools encode as integers, not octets
    # Only the OCTET-STRING-of-text path is pcap-proven.
    assert cat.wire_type_proven(name, "Front Desk") is True
    assert cat.wire_type_proven(name, 5) is False


def test_field_key_collapses_identical_duplicates():
    # Every duplicate field name in the shipped catalog is an identical-OID
    # entry, so both halves map to the same key (they are the same field).
    cat = load_catalog()
    prog = next(p for p in cat.programs.values()
                if any(len(p.fields_named(f["name"])) > 1 for f in p.fields))
    dupname = next(f["name"] for f in prog.fields
                   if len(prog.fields_named(f["name"])) > 1)
    fs = prog.fields_named(dupname)
    keys = {prog.field_key(f) for f in fs}
    assert len(keys) == 1                             # identical entries collapse
    assert next(iter(keys)).startswith(dupname)


def test_field_key_disambiguates_differing_oids():
    # Guard for a future catalog revision: same name, DIFFERENT oids -> the
    # per-row keys must stay distinct so one value cannot clobber the other.
    from toshiba_cix.catalog import Program
    prog = Program.from_entry("Fake", {"number": "9", "name": "Fake",
        "group_oid": f"{ROOT}.3.9", "fields": [
            {"name": "dup", "oid": f"{ROOT}.3.9.1.1.1", "col": 1,
             "syntax": "INTEGER", "enc": "INTEGER", "access": "rw", "key": False},
            {"name": "dup", "oid": f"{ROOT}.3.9.1.1.2", "col": 2,
             "syntax": "INTEGER", "enc": "INTEGER", "access": "rw", "key": False},
        ]})
    keys = {prog.field_key(f) for f in prog.fields_named("dup")}
    assert len(keys) == 2
    assert all(k.startswith("dup#") for k in keys)


def test_enum_label_bundled_and_override():
    # Labels now ship bundled: a known enum resolves out of the box, with no
    # setup. Construct a fresh catalog so the override below cannot leak into
    # the shared singleton that other modules' tests reuse.
    cat = Catalog(C.load_catalog_text())
    enum_fld = next(f for p in cat.programs.values() for f in p.fields
                    if f.get("syntax") == "EnumeratedINTEGER")
    assert cat.enum_label(enum_fld, 1) is not None     # bundled label present
    assert cat.enum_values(enum_fld)                   # full value map available
    # A per-OID override wins over the bundle; other raw values still fall back.
    bundled_1 = cat.enum_label(enum_fld, 1)
    cat.set_enum_labels({enum_fld["oid"]: {1: "Custom"}})
    assert cat.enum_label(enum_fld, 1) == "Custom"     # override wins
    assert cat.enum_label(enum_fld, 1) != bundled_1
    # a raw value with no label anywhere is still None
    assert cat.enum_label(enum_fld, 999) is None


def test_field_by_column_ambiguous_returns_none():
    # 50 programs reuse a column number; field_by_column must not guess.
    cat = load_catalog()
    prog = next(p for p in cat.programs.values()
                if any(len(p._by_col.get(c, [])) > 1 for c in p._by_col))
    dupcol = next(c for c in prog._by_col if len(prog._by_col[c]) > 1)
    assert prog.field_by_column(dupcol) is None


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
