"""Offline tests for the Call Flow adapter (callflow.py).

Builds representative ``program_views`` working copies (real catalog field names,
invented values) and asserts the emitted graph obeys the frozen Call Flow
contract (callflow-port/CONTRACT.md v1.0.0): entrypoints are DIDs AND line/trunk
groups, groups carry member ports with equipment, day/day2/night modes ride on
edge ``condition``, DISA is a terminal (no invented IVR menu), and an unresolved
destination becomes a counted ``unknown`` node — never a dropped edge.

No network, no catalog needed (the adapter works off the enriched cells + the
value index). Run:  python3 tests/test_callflow.py  (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.callflow as CF  # noqa: E402

ENTRYPOINT_KINDS = {"did", "trunk_group", "line_group"}
NODE_KINDS = {
    "did", "trunk_group", "line_group", "ivr_menu", "time_switch", "ring_group",
    "queue", "extension", "attendant", "voicemail", "fax", "conference",
    "recording", "external", "feature", "hangup", "unknown",
}
EDGE_KINDS = {"route", "option", "member", "open", "closed", "always",
              "cf_on", "cf_off", "timeout", "fwd", "vm"}
PORT_TYPES = {"loop_start", "ground_start", "e_and_m", "t1", "pri", "bri",
              "isdn", "sip", "did", "analog_co", "digital", "unknown"}


# -- program_views builders -------------------------------------------------
def _cell(name, raw, disp=None):
    return {"col": 1, "field_name": name, "oid": "x." + name, "raw_value": raw,
            "display_value": disp if disp is not None else str(raw),
            "is_enum": disp is not None}


def _row(index, key, **fields):
    cells = []
    for name, val in fields.items():
        if isinstance(val, tuple):   # (raw_int, enum_label)
            cells.append(_cell(name, val[0], val[1]))
        else:
            cells.append(_cell(name, val))
    return {"index": index, "key": key, "cells": cells}


def _prog(num, key, rows):
    return {"catalog_key": key, "program_number": num, "program_name": key,
            "menu_area": "Trunk", "menu_path": "", "label": key,
            "row_count": len(rows), "rows": rows}


def _by_id(graph):
    return {n["id"]: n for n in graph["nodes"]}


def _edges(graph, src=None, kind=None):
    out = graph["edges"]
    if src is not None:
        out = [e for e in out if e["src"] == src]
    if kind is not None:
        out = [e for e in out if e["kind"] == kind]
    return out


# A full owner's analog line group (the fixture-b case): three loop-start CO
# lines, no DID, ringing a hunt group by day and an after-hours mailbox by night.
def _line_group_views():
    return {"programs": [
        _prog("304", "304ILGAssign", [
            _row("1", "1", ilgGrpNo="1", ilgAnalogISDNType=(1, "analog"))]),
        _prog("300", "300TrunkAssign", [
            _row("1", "1", trunkNo="1", trunkIlg="1", trunkEquipment="010401",
                 trunkSignaling=(2, "lOOP"), trunkTrunkName="Loop CO 94000"),
            _row("2", "2", trunkNo="2", trunkIlg="1", trunkEquipment="010402",
                 trunkSignaling=(2, "lOOP"), trunkTrunkName="Loop CO 94001"),
            _row("3", "3", trunkNo="3", trunkIlg="1", trunkEquipment="010403",
                 trunkSignaling=(2, "lOOP"), trunkTrunkName="Loop CO 94002")]),
        _prog("310", "310DIT", [
            _row("1", "010401", ditEquipment="010401",
                 ditDay1AudioDestinationType=(2, "dialingDigits"),
                 ditDay1AudioDestination="500",
                 ditNightAudioDestinationType=(2, "dialingDigits"),
                 ditNightAudioDestination="9000")]),
        _prog("209", "209StationHunting", [
            _row("1", "1", stationHuntGrp="1", stationHuntPilotNumber="500",
                 stationHuntMethod=(1, "serial"))]),
        _prog("218", "218StationHuntingGroupMember", [
            _row("1.1", "1", huntGrpMemberNumber="1", huntGrpMemberIndex="1",
                 huntGrpMemberDn="201"),
            _row("1.2", "2", huntGrpMemberNumber="1", huntGrpMemberIndex="2",
                 huntGrpMemberDn="202")]),
        _prog("200", "200StationAssign", [
            _row("1.a", "201", stationDn="201", stationStationName="Reception Bob"),
            _row("1.b", "202", stationDn="202", stationStationName="Reception Carol")]),
        _prog("580", "580VoiceMailData", [_row("1", "9000", vmDataDN="9000")]),
    ]}


# -- the frozen contract invariants (run on every graph) --------------------
def assert_contract(graph):
    assert set(graph) >= {"entrypoints", "nodes", "edges", "stats"}, graph.keys()
    ids = set()
    for n in graph["nodes"]:
        for k in ("id", "kind", "num", "label", "meta"):
            assert k in n, f"node missing {k}: {n}"
        assert n["kind"] in NODE_KINDS, n["kind"]
        assert n["id"] not in ids, f"duplicate id {n['id']}"
        ids.add(n["id"])
        if "ports" in n:
            assert n["kind"] in ("trunk_group", "line_group"), n
            for p in n["ports"]:
                assert set(p) == {"id", "label", "equipment", "type"}, p
                assert p["type"] in PORT_TYPES, p["type"]
    for e in graph["edges"]:
        for k in ("src", "tgt", "kind", "label"):
            assert k in e, f"edge missing {k}: {e}"
        assert e["kind"] in EDGE_KINDS, e["kind"]
        assert e["src"] in ids, f"edge src not a node: {e}"   # never a dangling edge
        assert e["tgt"] in ids, f"edge tgt not a node: {e}"
    by = _by_id(graph)
    for ep in graph["entrypoints"]:
        assert ep in ids, f"entrypoint {ep} not in nodes"
        assert by[ep]["kind"] in ENTRYPOINT_KINDS, ep
    st = graph["stats"]
    assert st["nodes"] == len(graph["nodes"]) and st["edges"] == len(graph["edges"])
    assert st["unresolved"] == sum(1 for n in graph["nodes"] if n["kind"] == "unknown")


# -- tests ------------------------------------------------------------------
def test_line_group_entrypoint_with_ports():
    g = CF.build_callflow(_line_group_views())
    assert_contract(g)
    by = _by_id(g)
    assert "lg:1" in by, "analog line group entrypoint missing"
    lg = by["lg:1"]
    assert lg["kind"] == "line_group"
    assert "lg:1" in g["entrypoints"]
    # three member loop-start ports, each with a decoded cab/slot/ckt location
    assert len(lg["ports"]) == 3, lg["ports"]
    assert {p["type"] for p in lg["ports"]} == {"loop_start"}
    assert sorted(p["equipment"] for p in lg["ports"]) == ["1/4/1", "1/4/2", "1/4/3"]
    # day -> hunt group, night -> after-hours mailbox, both on the group edges
    day = [e for e in _edges(g, "lg:1") if e.get("condition") == "day"]
    night = [e for e in _edges(g, "lg:1") if e.get("condition") == "night"]
    assert len(day) == 1 and day[0]["tgt"] == "rg:500", day
    assert len(night) == 1 and night[0]["tgt"] == "vm:9000", night
    # the hunt group fans out to its two stations
    members = _edges(g, "rg:500", "member")
    assert {e["tgt"] for e in members} == {"ext:201", "ext:202"}, members


def test_did_disa_terminal_and_unresolved_is_counted():
    views = {"programs": [
        _prog("309", "309DID", [
            _row("1", "1", didNumber="5551000", didIlg="1",
                 didDay1AudioDestinationType=(3, "dISA"),
                 didDay1AudioDestination="700",
                 didNightAudioDestinationType=(2, "dialingDigits"),
                 didNightAudioDestination="124")]),  # 124 resolves to nothing
    ]}
    g = CF.build_callflow(views)
    assert_contract(g)
    by = _by_id(g)
    assert by["did:5551000"]["kind"] == "did" and "did:5551000" in g["entrypoints"]
    # DISA is a terminal ivr_menu with NO option edges (the menu is in the VM device)
    disa = next(n for n in g["nodes"] if n["kind"] == "ivr_menu")
    assert not _edges(g, disa["id"]), "DISA must be terminal — no invented menu"
    # the unresolvable night destination is drawn as a counted unknown node
    assert g["stats"]["unresolved"] == 1
    unk = next(n for n in g["nodes"] if n["kind"] == "unknown")
    assert unk["num"] == "124"
    assert any(e["tgt"] == unk["id"] for e in g["edges"]), "unresolved edge dropped"


def test_trunk_group_pri_members():
    views = {"programs": [
        _prog("304", "304ILGAssign", [
            _row("1", "2", ilgGrpNo="2", ilgAnalogISDNType=(2, "iSDN"))]),
        _prog("302", "302ISDNPrimaryTrunk", [
            _row("1", "1", isdnPrimaryTrunkChGrp="1", isdnPrimaryTrunkIlg="2",
                 isdnPrimaryTrunkEquipment="030101"),
            _row("2", "2", isdnPrimaryTrunkChGrp="2", isdnPrimaryTrunkIlg="2",
                 isdnPrimaryTrunkEquipment="030102")]),
    ]}
    g = CF.build_callflow(views)
    assert_contract(g)
    by = _by_id(g)
    assert "tg:2" in by and by["tg:2"]["kind"] == "trunk_group"
    assert {p["type"] for p in by["tg:2"]["ports"]} == {"pri"}
    assert sorted(p["equipment"] for p in by["tg:2"]["ports"]) == ["3/1/1", "3/1/2"]


def test_equipment_blank_is_flagged_not_faked():
    # trunkEquipment that decodes to a non-port hex blob -> equipment "" + note.
    views = {"programs": [
        _prog("304", "304ILGAssign", [
            _row("1", "1", ilgGrpNo="1", ilgAnalogISDNType=(1, "analog"))]),
        _prog("300", "300TrunkAssign", [
            _row("1", "1", trunkNo="1", trunkIlg="1", trunkEquipment="ab12cd",
                 trunkSignaling=(2, "lOOP"), trunkTrunkName="Mystery CO")]),
    ]}
    g = CF.build_callflow(views)
    assert_contract(g)
    lg = _by_id(g)["lg:1"]
    assert lg["ports"][0]["equipment"] == "", lg["ports"]
    assert "did not decode" in lg["meta"], lg["meta"]


def test_available_detects_core_only_snapshot():
    core_only = {"programs": [
        _prog("200", "200StationAssign", [_row("1", "100", stationDn="100")]),
        _prog("105", "105SystemData", [_row("0", "_", x="1")]),
    ]}
    assert CF.callflow_available(core_only) is False
    assert CF.callflow_available(_line_group_views()) is True
    # an empty graph is still a valid graph (a finding, not an error)
    g = CF.build_callflow(core_only)
    assert_contract(g)


def test_fallback_jsonschema_if_available():
    # When jsonschema happens to be installed locally, validate the full graph
    # against the frozen contract schema. CI runs stdlib-only, so this is a
    # best-effort extra, skipped when the package / schema file is absent.
    try:
        from jsonschema import Draft202012Validator  # type: ignore
    except Exception:  # noqa: BLE001
        print("  (jsonschema not installed — skipping schema validation)")
        return
    import json
    schema_path = os.path.join(
        os.path.dirname(HERE), "..", "callflow-port", "contract",
        "callflow.schema.json")
    if not os.path.exists(schema_path):
        print("  (contract schema not present — skipping)")
        return
    with open(schema_path) as fh:
        schema = json.load(fh)
    for views in (_line_group_views(),):
        g = CF.build_callflow(views)
        errs = list(Draft202012Validator(schema).iter_errors(g))
        assert not errs, [ (list(e.path), e.message) for e in errs ][:3]


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
