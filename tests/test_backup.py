"""Offline tests for the catalog-driven backup.

A synthetic capture is built on **real catalog OIDs** (so attribution is
exercised for real) but with entirely made-up values — no customer data. The
fake agent is the decoder tests' lexical ``FakeClient`` plus a ``.get`` for the
identity scalars, so the full collect → build → render path runs with no
network. The fixture builders are reused by the diff and restore tests.

Run:  python3 tests/test_backup.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.backup as B  # noqa: E402  (submodule, not the backup() fn)
from test_decode import FakeClient  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402
from toshiba_cix.snmp import Value, VarBind  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"


def _octet(s: str) -> Value:
    return Value("octet", raw=s.encode("ascii"))


def _int(n: int) -> Value:
    return Value("int", int_value=n)


class BackupFake(FakeClient):
    """Lexical fake agent (walk/getnext/bulk_walk) + .get/.set for backup."""

    def get(self, oids):
        return [VarBind(o, self._data.get(o, Value("missing"))) for o in oids]

    def set(self, varbinds):
        from toshiba_cix.snmp import Response, _decode_value, _read_tlv
        for oid, tlv in varbinds:
            tag, content, _ = _read_tlv(tlv, 0)
            self._data[oid] = _decode_value(tag, content)
            if oid not in self._sorted:
                self._sorted.append(oid)
                self._sorted.sort(key=lambda o: [int(x) for x in o.split(".")])
        return Response(1, 0, 0, [])


def readonly_field(cat):
    """A real read-only catalog field (for 'never written' / 'ignored' tests)."""
    return next((p, f) for p in cat.programs.values() for f in p.fields
                if f.get("access") == "r" and ".1.1." in f.get("oid", ""))


def sample_capture(cat, *, names=("Front Desk", "Lobby", "Warehouse")):
    """Synthetic OID→Value table on genuine catalog OIDs. No real data."""
    name_oid = cat.program("200").field_by_column(18)["oid"]   # stationStationName
    timer_oid = cat.program("104").fields[0]["oid"]            # a scalar INTEGER
    ro_prog, ro_fld = readonly_field(cat)
    d: dict[str, Value] = {
        # identity scalars (meta)
        f"{ROOT}.7.2.1.0": _octet("LA520MT067PNDN2---EM.00"),
        f"{ROOT}.7.9.1.0": Value("octet", raw=bytes.fromhex("e8e0b7aabbcc")),
        # station names for three DNs (tail = <rowseq>.<len>.<ascii DN>)
        f"{name_oid}.1.3.50.48.48": _octet(names[0]),   # DN 200
        f"{name_oid}.1.3.50.48.49": _octet(names[1]),   # DN 201
        f"{name_oid}.1.3.50.48.50": _octet(names[2]),   # DN 202
        # a scalar timer
        f"{timer_oid}.0": _int(30),
        # a read-only field value (must never be restored)
        f"{ro_fld['oid']}.0": _int(7),
        # an OID the catalog does not know -> must survive in 'unmatched'
        f"{ROOT}.3.49999.1.1.9.0": _octet("mystery"),
    }
    return d, {"name_oid": name_oid, "timer_oid": timer_oid,
               "ro_prog": ro_prog, "ro_fld": ro_fld}


def make_backup(cat=None, **kw):
    cat = cat or load_catalog()
    data, meta = sample_capture(cat, **kw)
    return B.backup(BackupFake(data), cat, site="Example Site"), meta


# -- walk roots -------------------------------------------------------------
def test_walk_roots_are_minimal():
    cat = load_catalog()
    roots = B.walk_roots(cat)
    assert roots
    # no root is a descendant of another (that would be a wasted pass)
    for a in roots:
        assert not any(a != b and a.startswith(b + ".") for b in roots)


def test_walk_roots_program_filter():
    cat = load_catalog()
    roots = B.walk_roots(cat, ["200"])
    assert roots and all(r.startswith(f"{ROOT}.3.200.") for r in roots)


# -- build (pure) -----------------------------------------------------------
def test_build_backup_structure():
    cat = load_catalog()
    data, info = sample_capture(cat)
    pairs = [(o, v) for o, v in data.items()]
    doc = B.build_backup(pairs, cat, meta={"site": "Example Site"})
    assert doc["format"] == "toshiba-cix-backup"
    assert doc["format_version"] == 1
    assert doc["meta"]["site"] == "Example Site"
    assert doc["meta"]["catalog_version"] == cat.version
    # station program present with three rows, names promoted by field name
    stn = doc["programs"]["200StationAssign"]
    assert len(stn["rows"]) == 3
    names = {r["fields"]["stationStationName"] for r in stn["rows"]}
    assert names == {"Front Desk", "Lobby", "Warehouse"}
    # scalar timer program captured
    assert "104SystemTimer" in doc["programs"]
    # unmatched OID preserved, nothing dropped
    assert any(e["oid"].endswith("3.49999.1.1.9.0") for e in doc["unmatched"])
    assert doc["meta"]["unmatched_count"] == 1


def test_build_backup_rows_sorted_deterministic():
    cat = load_catalog()
    data, _ = sample_capture(cat)
    a = B.build_backup(list(data.items()), cat)
    b = B.build_backup(list(reversed(list(data.items()))), cat)
    assert a["programs"] == b["programs"]        # order-independent


def test_backup_live_roundtrip():
    doc, info = make_backup()
    m = doc["meta"]
    assert m["swid"] == "LA520MT067PNDN2---EM.00"
    assert m["chassis_mac"] == "e8:e0:b7:aa:bb:cc"
    assert m["source_ip"] == "192.168.254.253"
    assert m["programs_count"] >= 2 and m["rows_count"] >= 4
    assert m["oids_read"] > 0


def test_backup_json_serializable():
    doc, _ = make_backup()
    text = json.dumps(doc, default=str)
    assert json.loads(text)["format"] == "toshiba-cix-backup"


def test_backup_program_scope_filter():
    cat = load_catalog()
    data, _ = sample_capture(cat)
    doc = B.backup(BackupFake(data), cat, programs=["200"])
    assert set(doc["programs"]) == {"200StationAssign"}
    assert doc["meta"]["scope"] == ["200"]
    # identity still read for meta even though .7 was not walked
    assert doc["meta"]["swid"] == "LA520MT067PNDN2---EM.00"


def test_render_backup_text():
    doc, _ = make_backup()
    cat = load_catalog()
    text = B.render_backup_text(doc, catalog=cat)
    assert "catalog backup" in text
    assert "Front Desk" in text
    assert "LA520MT067PNDN2---EM.00" in text
    # program filter narrows the render
    only = B.render_backup_text(doc, catalog=cat, program="200")
    assert "200StationAssign" in only and "104SystemTimer" not in only


def test_collect_dedups():
    cat = load_catalog()
    data, _ = sample_capture(cat)
    pairs, error = B.collect(BackupFake(data), cat)
    assert error is None
    oids = [o for o, _ in pairs]
    assert len(oids) == len(set(oids))


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
