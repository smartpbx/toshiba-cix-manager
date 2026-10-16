"""Offline tests for the write path.

Covers the BER SET encoder (asserting the exact ground-truth bytes of frame 634
from the eManager pcap), the WriteOp planning, and the full commit + GET-verify
round-trip against an in-memory fake agent that accepts SETs and reflects them
on read-back. No live PBX is ever touched.

Run:  python3 tests/test_write.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import write as W  # noqa: E402
from toshiba_cix.snmp import (Response, Value, VarBind, _decode_value,  # noqa: E402
                              _read_tlv, ber_octet, encode_set_message)

ROOT = "1.3.6.1.4.1.186.1.22"

# Exact bytes of frame 634 (SetRequest v2c, community communityName, rid 6, the
# three FTP-table varbinds). Verified by hand against the BER structure; this is
# the ground truth the CIX accepted (frame 635 confirmed).
GOLDEN_634 = (
    "3074020101040d636f6d6d756e6974794e616d65a36002010602010002010030553015"
    "06102b06010401813a01160302030101040104012f301c06102b06010401813a011603"
    "020301010201040873797361646d696e301e06102b06010401813a0116030203010103"
    "01040a776b7369373664626761"
)


class FakeAgent:
    """Accepts SETs and reflects them so a read-back verifies (offline)."""

    def __init__(self, data=None):
        self.community = "communityName"
        self.host = "192.168.254.253"
        self.port = 161
        self._data = dict(data or {})

    def get(self, oids):
        return [VarBind(o, self._data.get(o, Value("missing"))) for o in oids]

    def set(self, varbinds):
        for oid, tlv in varbinds:
            tag, content, _ = _read_tlv(tlv, 0)
            self._data[oid] = _decode_value(tag, content)
        return Response(1, 0, 0, [])


class DeafAgent(FakeAgent):
    """Accepts the SET on the wire but does not actually store it — models a
    write that silently failed, so read-back verification must catch it."""

    def set(self, varbinds):
        return Response(1, 0, 0, [])


def _station():
    return {
        "dn": "200", "extension": "200", "equipment_port": "010101",
        "type": "4", "name": "Front Desk",
        "source_oids": {
            "extension": f"{ROOT}.3.1200.1.1.2.1.3.50.48.48",
            "type": f"{ROOT}.3.1200.1.1.4.1.3.50.48.48",
            "name": f"{ROOT}.3.1200.1.1.19.1.3.50.48.48",
        },
        "flags": {}, "keys": [], "programs": {},
    }


# -- encoder ----------------------------------------------------------------
def test_writes_enabled():
    assert W.WRITES_ENABLED is True


def test_golden_set_bytes_frame_634():
    base = f"{ROOT}.3.2.3.1.1"
    vbs = [(f"{base}.4.1", ber_octet("/")),
           (f"{base}.2.1", ber_octet("sysadmin")),
           (f"{base}.3.1", ber_octet("wksi76dbga"))]
    pkt = encode_set_message("communityName", vbs, 6, version=1)
    assert pkt.hex() == GOLDEN_634
    # v2c version field and SET PDU tag are present.
    assert pkt[2:5] == bytes([0x02, 0x01, 0x01])   # INTEGER version = 1
    assert 0xA3 in pkt                              # SetRequest PDU tag


def test_encode_set_request_from_ops():
    ops = W.CIXWriter().plan_station_update(_station(), {"name": "Reception"})
    pkt = W.encode_set_request("communityName", ops, 42)
    expect = encode_set_message(
        "communityName",
        [(f"{ROOT}.3.1200.1.1.19.1.3.50.48.48", ber_octet("Reception"))], 42)
    assert pkt == expect


def test_encode_set_request_empty_raises():
    ops = W.CIXWriter().plan_station_update(_station(), {"equipment_port": "x"})
    try:
        W.encode_set_request("communityName", ops, 1)
    except W.WriteError:
        pass
    else:
        raise AssertionError("encoding with no sendable ops must raise")


def test_writeop_value_encoding():
    assert W.WriteOp("name", "name", "Reception").encode_value() == ber_octet("Reception")
    from toshiba_cix.snmp import ber_integer
    assert W.WriteOp("x", "x", "2", ber_type="INTEGER").encode_value() == ber_integer(2)


# -- planning ---------------------------------------------------------------
def test_plan_derives_target_oid():
    ops = W.CIXWriter().plan_station_update(_station(), {"type": "7", "name": "Reception"})
    by_field = {o.field: o for o in ops}
    assert by_field["type"].target_oid.endswith("3.1200.1.1.4.1.3.50.48.48")
    assert by_field["type"].old_value == "4" and by_field["type"].sendable
    assert by_field["name"].new_value == "Reception"


def test_plan_rejects_readonly_port():
    ops = W.CIXWriter().plan_station_update(_station(), {"equipment_port": "020202"})
    assert len(ops) == 1 and ops[0].sendable is False
    assert "read-only" in ops[0].note


def test_plan_unknown_field_noted():
    ops = W.CIXWriter().plan_station_update(_station(), {"mystery": "x"})
    assert ops[0].sendable is False and ops[0].note


def test_plan_missing_source_oid_unsendable():
    st = _station()
    st["source_oids"].pop("type")
    ops = W.CIXWriter().plan_station_update(st, {"type": "7"})
    assert ops[0].target_oid is None and ops[0].sendable is False


# -- commit (round-trip against the fake agent) -----------------------------
def test_commit_requires_confirm():
    agent = FakeAgent()
    writer = W.CIXWriter(agent)
    ops = writer.plan_station_update(_station(), {"name": "Reception"})
    try:
        writer.commit(ops)                 # confirm defaults False
    except W.WriteError as exc:
        assert "confirm" in str(exc).lower()
    else:
        raise AssertionError("commit without confirm must raise")


def test_commit_disabled_gate(monkeypatch=None):
    agent = FakeAgent()
    writer = W.CIXWriter(agent)
    ops = writer.plan_station_update(_station(), {"name": "Reception"})
    saved = W.WRITES_ENABLED
    W.WRITES_ENABLED = False
    try:
        writer.commit(ops, confirm=True)
    except W.WriteError as exc:
        assert "disabled" in str(exc).lower()
    else:
        raise AssertionError("commit must raise when WRITES_ENABLED is False")
    finally:
        W.WRITES_ENABLED = saved


def test_commit_roundtrip_verifies():
    st = _station()
    # seed the agent with the current on-device values at the real OIDs
    agent = FakeAgent({
        st["source_oids"]["name"]: Value("octet", raw=b"Front Desk"),
        st["source_oids"]["type"]: Value("octet", raw=b"4"),
    })
    writer = W.CIXWriter(agent)
    result = writer.apply_station_update(st, {"name": "Reception"}, confirm=True)
    assert result["ok"] is True
    assert result["wrote"] == 1
    assert result["verified_all"] is True
    r0 = result["results"][0]
    assert r0["field"] == "name"
    assert r0["requested"] == "Reception"
    assert r0["read_back"] == "Reception"
    assert r0["match"] is True
    # the agent actually holds the new value now
    assert agent._data[st["source_oids"]["name"]].raw == b"Reception"


def test_commit_batches_multiple_fields():
    st = _station()
    agent = FakeAgent()
    result = W.CIXWriter(agent).apply_station_update(
        st, {"name": "Reception", "type": "7"}, confirm=True)
    assert result["wrote"] == 2 and result["verified_all"] is True
    got = {r["field"]: r["read_back"] for r in result["results"]}
    assert got == {"name": "Reception", "type": "7"}


def test_commit_detects_failed_write():
    # agent accepts the SET but drops it; read-back must flag the mismatch
    agent = DeafAgent()
    result = W.CIXWriter(agent).apply_station_update(
        _station(), {"name": "Reception"}, confirm=True)
    assert result["ok"] is False
    assert result["verified_all"] is False
    assert result["results"][0]["match"] is False


def test_commit_nothing_sendable_raises():
    try:
        W.CIXWriter(FakeAgent()).apply_station_update(
            _station(), {"equipment_port": "x"}, confirm=True)
    except W.WriteError:
        pass
    else:
        raise AssertionError("commit with only non-sendable ops must raise")


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
