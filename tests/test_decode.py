"""Offline unit tests for the Toshiba CIX decoder.

All inputs are lifted from the real 2026-10-14 eManager packet capture
(`an on-site SNMP capture`), so passing these means the
decoder reproduces what eManager saw on the wire. No network needed.

Run:  python3 -m pytest tests/        (or: python3 tests/test_decode.py)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import CIXReader, render_report  # noqa: E402
from toshiba_cix import decode as D  # noqa: E402
from toshiba_cix.scan import _find_entry_marker  # noqa: E402
from toshiba_cix.snmp import Value, decode_oid, encode_oid  # noqa: E402


def _octet(s: str) -> Value:
    return Value("octet", raw=s.encode("ascii"))


def _mac(hexstr: str) -> Value:
    return Value("octet", raw=bytes.fromhex(hexstr))


def _int(n: int) -> Value:
    return Value("int", int_value=n)


# --------------------------------------------------------------------------
# value decoding
# --------------------------------------------------------------------------
def test_octet_digit_string():
    # 303130313031 on the wire == bytes b"010101".
    assert D.decode_octet(b"010101") == "010101"
    assert D.decode_value(_octet("200")) == "200"
    assert D.decode_value(_octet("sysadmin")) == "sysadmin"


def test_software_id_ascii():
    raw = bytes.fromhex("4e413532304d54303637504e444e322d2d2d454d2e3030")
    assert D.decode_octet(raw) == "NA520MT067PNDN2---EM.00"


def test_mac_formatting():
    v = _mac("e8e0b7cc58f5")
    assert D.decode_value(v, as_mac=True) == "e8:e0:b7:cc:58:f5"
    # Without the mac hint, binary bytes fall back to hex (never dropped).
    assert D.decode_value(v) == "e8e0b7cc58f5"


def test_missing_sentinel():
    assert D.decode_value(Value("missing")) == D.MISSING
    assert D.decode_value(Value("nosuchobject")) == D.MISSING


def test_port_helpers():
    assert D.looks_like_port("010101")
    assert not D.looks_like_port("200")
    assert D.format_port("010203") == "01-02-03"


# --------------------------------------------------------------------------
# OID encode/decode round trip
# --------------------------------------------------------------------------
def test_oid_roundtrip():
    oid = "1.3.6.1.4.1.186.1.22.3.1200.1.1.3.1.3.50.48.48"
    # encode_oid wraps in a TLV (tag 0x06, length, content); strip to content.
    tlv = encode_oid(oid)
    assert tlv[0] == 0x06
    content = tlv[2:] if tlv[1] < 0x80 else tlv[2 + (tlv[1] & 0x7F):]
    assert decode_oid(content) == oid


# --------------------------------------------------------------------------
# row-index parsing (the length-prefixed DN)
# --------------------------------------------------------------------------
def test_row_index_bare_dn():
    # .3.200.1.1.<col>.3.50.52.49  -> DN "241"
    idx = D.parse_row_index((3, 50, 52, 49))
    assert idx.dn == "241"
    assert idx.prefix == ()
    assert idx.suffix == ()


def test_row_index_with_rowseq_prefix():
    # Program 1200: .<col>.<rowseq=1>.3.50.48.48 -> DN "200", prefix (1,)
    idx = D.parse_row_index((1, 3, 50, 48, 48))
    assert idx.dn == "200"
    assert idx.prefix == (1,)


def test_row_index_with_key_suffix():
    # Program 205: .<col>.3.50.52.49.<key=1> -> DN "241", suffix (1,)
    idx = D.parse_row_index((3, 50, 52, 49, 1))
    assert idx.dn == "241"
    assert idx.suffix == (1,)


def test_row_index_no_dn_plain_integer():
    # Equipment table index is a plain integer, not a length-prefixed DN.
    idx = D.parse_row_index((2,))
    assert idx.dn is None
    assert idx.raw == (2,)


def test_entry_marker():
    assert _find_entry_marker([1200, 1, 1, 3, 1]) == 1
    assert _find_entry_marker([2, 3, 1, 1, 4]) == 2
    assert _find_entry_marker([579, 16, 0]) is None


# --------------------------------------------------------------------------
# end-to-end: feed captured varbinds through a fake agent
# --------------------------------------------------------------------------
class FakeClient:
    """Stands in for SnmpV1 with a real lexical agent.

    Implements .walk(), .getnext(), .enumerate_children() and .bulk_walk()
    against an in-memory OID table so BOTH the serial and the batched
    collection strategies are exercised offline.
    """

    def __init__(self, data: dict[str, Value]):
        self.host = "192.168.254.253"
        self.port = 161
        self.community = "communityName"
        self._data = data
        self._sorted = sorted(data, key=_oid_key)

    # serial walk
    def walk(self, root, *, max_oids=20000):
        for oid in self._sorted:
            if oid == root or oid.startswith(root + "."):
                yield oid, self._data[oid]

    # multi-varbind GETNEXT
    def getnext(self, oids):
        from toshiba_cix.snmp import Response, VarBind
        vbs = []
        for q in oids:
            nxt = self._successor(q)
            if nxt is None:
                vbs.append(VarBind(q, Value("endofmib")))
            else:
                vbs.append(VarBind(nxt, self._data[nxt]))
        return Response(1, 0, 0, vbs)

    def _successor(self, oid):
        key = _oid_key(oid)
        for cand in self._sorted:
            if _oid_key(cand) > key:
                return cand
        return None

    # reuse the real implementations by borrowing the methods
    def enumerate_children(self, base, *, max_children=8192):
        from toshiba_cix.snmp import SnmpV1
        return SnmpV1.enumerate_children(self, base, max_children=max_children)

    def bulk_walk(self, roots, *, width=20, max_total=500000):
        from toshiba_cix.snmp import SnmpV1
        return SnmpV1.bulk_walk(self, roots, width=width, max_total=max_total)


def _oid_key(oid: str):
    return [int(x) for x in oid.split(".")]


def _sample_capture() -> dict[str, Value]:
    R = D.ENTERPRISE_ROOT
    d: dict[str, Value] = {}
    # System identity.
    d[f"{R}.7.2.1.0"] = _octet("NA520MT067PNDN2---EM.00")
    d[f"{R}.7.9.1.0"] = _mac("e8e0b7cc58f5")
    d[f"{R}.7.12.1.0"] = _int(2)
    d[f"{R}.7.7.1.0"] = _int(2)
    # Station directory (Program 1200): DN 200 and DN 221.
    d[f"{R}.3.1200.1.1.2.1.3.50.48.48"] = _octet("200")      # ext
    d[f"{R}.3.1200.1.1.3.1.3.50.48.48"] = _octet("010101")   # port
    d[f"{R}.3.1200.1.1.2.7.3.50.50.49"] = _octet("221")
    d[f"{R}.3.1200.1.1.3.7.3.50.50.49"] = _octet("010207")
    d[f"{R}.3.1200.1.1.2.26.3.50.52.49"] = _octet("241")     # DN 241 ext
    d[f"{R}.3.1200.1.1.3.26.3.50.52.49"] = _octet("010113")  # DN 241 port
    d[f"{R}.3.1200.1.1.2.33.3.52.48.49"] = _octet("401")
    d[f"{R}.3.1200.1.1.3.33.3.52.48.49"] = _octet("010801")
    # Per-station Program 200 (DN 241): a column (attaches to the 1200 row).
    d[f"{R}.3.200.1.1.61.3.50.52.49"] = _octet("010113")
    # Program 205 key assignment for DN 241, key 1.
    d[f"{R}.3.205.1.1.2.3.50.52.49.1"] = _octet("241")
    d[f"{R}.3.205.1.1.1.3.50.52.49.1"] = _octet("100")
    # Network / FTP credentials table.
    d[f"{R}.3.2.3.1.1.2.1"] = _octet("sysadmin")
    d[f"{R}.3.2.3.1.1.3.1"] = _octet("wksi76dbga")
    d[f"{R}.3.2.3.1.1.4.1"] = _octet("/")
    # System numbering config (Program 579).
    d[f"{R}.3.579.1.0"] = _octet("400")
    # Equipment table index 2 (all missing in the capture).
    d[f"{R}.1.1.1.1.2"] = Value("missing")
    # An undocumented program with NO DN (plain integer index 7) -> must
    # survive as raw passthrough, with its raw OID preserved.
    d[f"{R}.3.9999.1.1.5.7"] = _octet("xyz")
    # An undocumented program WITH a DN -> stays in raw_programs (only
    # Program 1200 may create a station; unknown programs never attach).
    d[f"{R}.3.8888.1.1.4.3.50.48.48"] = _octet("zzz")  # looks like DN 200
    return d


def test_end_to_end():
    reader = CIXReader(FakeClient(_sample_capture()))
    doc = reader.read()

    # System.
    assert doc["system"]["software_id"] == "NA520MT067PNDN2---EM.00"
    assert doc["system"]["chassis_mac"] == "e8:e0:b7:cc:58:f5"
    assert doc["system"]["numbering_config"]["579.1.0"] == "400"

    # Stations: 200, 221, 241, 401 (241 arrives via Program 200, not 1200).
    dns = {s["dn"] for s in doc["stations"]}
    assert {"200", "221", "241", "401"} <= dns
    by_dn = {s["dn"]: s for s in doc["stations"]}
    assert by_dn["200"]["extension"] == "200"
    assert by_dn["200"]["equipment_port"] == "010101"
    assert by_dn["221"]["equipment_port"] == "010207"

    # Program 200 detail attached to its station with the raw OID preserved.
    assert "200" in by_dn["241"]["programs"]
    cells = by_dn["241"]["programs"]["200"]["rows"]["_"]
    assert cells["col61"]["value"] == "010113"
    assert cells["col61"]["oid"].endswith("3.200.1.1.61.3.50.52.49")

    # Program 205 key assignment.
    assert by_dn["241"]["keys"]
    assert by_dn["241"]["keys"][0]["key"] == 1

    # Network creds + security findings (default community + default FTP).
    net = {r["index"]: r for r in doc["network_access"]}
    assert net[1]["username"] == "sysadmin"
    assert net[1]["password"] == "wksi76dbga"
    codes = {f["code"] for f in doc["security_findings"]}
    assert "default_snmp_community" in codes
    assert "default_ftp_credentials" in codes

    # Undocumented program with no DN survived as raw passthrough (+ raw OID).
    assert "9999" in doc["raw_programs"]
    r9999 = doc["raw_programs"]["9999"]["rows"]
    some_row = next(iter(r9999.values()))
    assert some_row["col5"]["value"] == "xyz"
    assert some_row["col5"]["oid"].endswith("3.9999.1.1.5.7")
    # Undocumented program is never attached to a station, even with a DN.
    assert "8888" in doc["raw_programs"]
    assert "8888" not in by_dn["200"]["programs"]

    # Report renders without error and redacts when asked.
    text = render_report(doc, redact_secrets=True)
    assert "Station directory" in text
    assert "wksi76dbga" not in text          # redacted
    assert "NA520MT067PNDN2---EM.00" in text
    plain = render_report(doc)
    assert "wksi76dbga" in plain              # shown by default


def test_bulk_matches_serial():
    # The fast batched strategy must collect exactly the same OIDs as the
    # simple serial walk, and produce the same structured station set.
    data = _sample_capture()
    serial = CIXReader(FakeClient(data), strategy="serial").read()
    bulk = CIXReader(FakeClient(data), strategy="bulk").read()
    assert serial["device"]["oids_read"] == bulk["device"]["oids_read"] == len(data)
    assert {s["dn"] for s in serial["stations"]} == {s["dn"] for s in bulk["stations"]}
    assert serial["stats"] == bulk["stats"]


class TooBigClient(FakeClient):
    """Agent that answers 'tooBig' (error-status 1) above a varbind limit,
    like the real Strata agent. Verifies bulk_walk adapts and loses nothing."""

    def __init__(self, data, limit=4):
        super().__init__(data)
        self.limit = limit

    def getnext(self, oids):
        from toshiba_cix.snmp import Response
        if len(oids) > self.limit:
            return Response(1, 1, 0, [])   # tooBig, no data
        return super().getnext(oids)


def test_bulk_walk_handles_toobig():
    data = _sample_capture()
    # width far above the agent's limit; adaptive shrink must still get all.
    reader = CIXReader(TooBigClient(data, limit=3), strategy="bulk", width=16)
    doc = reader.read()
    assert doc["device"]["oids_read"] == len(data)
    assert doc["system"]["software_id"] == "NA520MT067PNDN2---EM.00"
    assert {s["dn"] for s in doc["stations"]} >= {"200", "221", "241", "401"}


def test_core_scope():
    data = _sample_capture()
    core = CIXReader(FakeClient(data), strategy="bulk", scope="core").read()
    # Documented programs are captured...
    assert {s["dn"] for s in core["stations"]} >= {"200", "221", "241", "401"}
    assert core["system"]["software_id"] == "NA520MT067PNDN2---EM.00"
    assert core["network_access"]
    # ...but the undocumented programs outside the core list are skipped.
    assert "8888" not in core["raw_programs"]
    assert "9999" not in core["raw_programs"]
    assert core["device"]["scope"] == "core"


def test_enumerate_children():
    data = _sample_capture()
    c = FakeClient(data)
    top = c.enumerate_children(D.ENTERPRISE_ROOT)
    assert "1" in top and "3" in top and "7" in top
    progs = c.enumerate_children(D.ENTERPRISE_ROOT + ".3")
    # programs present in the sample
    for p in ("2", "200", "205", "579", "1200", "8888", "9999"):
        assert p in progs, (p, progs)


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
