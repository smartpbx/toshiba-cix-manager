"""Config linter / Problems panel — the L3 semantic layer (DESIGN_PLAN §6).

eManager could tell you a field was out of range (L1) but never that the config
as a whole had a hole: a DID routed to a VMID that no mailbox owns, a station
with a blank name, the SNMP community still at its shipped default. The linter
is a small rule engine over a snapshot's ``program_views`` (plus the value index
for cross-reference checks); each rule is data in ``lint_rules.json`` and a pure
matcher here, so a new check is a JSON entry, not code.

A finding carries where it is (``program`` / ``index`` / ``row_key`` / ``field``)
so the Problems panel can jump to the row, and — when a rule has a safe, known
remedy — a ``fix`` ``{program_key, index, changes}`` the UI stages into the
pending tray (never an auto-write; the fix rides the same review as any edit).

Pure stdlib, no I/O: the engine and the CLI (``manage.py lint``) share it.
"""

from __future__ import annotations

import json
import re

from .catalog import _load_data_text

__all__ = ["load_rules", "lint_views", "DEFAULT_RULES"]

RULES_FILENAME = "lint_rules.json"

# Shipped defaults. ``lint_rules.json`` (dev) / the embedded global (amalgam)
# overrides this when present, so rules can be tuned without touching code.
DEFAULT_RULES: list = [
    {"id": "default-community", "type": "weak_value", "severity": "error",
     "field_contains": "communit",
     "bad_values": ["communityName", "public", "private", ""],
     "message": "SNMP community is a well-known default — change it"},
    {"id": "weak-secret", "type": "weak_value", "severity": "warn",
     "secret_only": True,
     "bad_values": ["", "0000", "1111", "1234", "000000", "123456",
                    "password", "admin"],
     "message": "password / security code is blank or a weak default"},
    {"id": "empty-station-name", "type": "empty_field", "severity": "warn",
     "programs": ["200", "1200"], "field_names": ["name", "station_name"],
     "message": "station has no name"},
    {"id": "name-comment-mismatch", "type": "fields_differ", "severity": "info",
     "a": "name", "b": "comment",
     "message": "station name and comment differ — one may be stale"},
    {"id": "orphan-vmid", "type": "orphan_reference", "severity": "warn",
     "field_contains": "vmid",
     "message": "VMID is referenced but no mailbox / station owns it"},
]


def load_rules() -> list:
    text = _load_data_text(RULES_FILENAME, "EMBEDDED_LINT_RULES_JSON")
    if not text:
        return list(DEFAULT_RULES)
    try:
        data = json.loads(text)
    except ValueError:
        return list(DEFAULT_RULES)
    rules = data.get("rules") if isinstance(data, dict) else data
    return rules if isinstance(rules, list) and rules else list(DEFAULT_RULES)


def _programs(program_views) -> list:
    if isinstance(program_views, dict):
        return program_views.get("programs") or []
    return program_views or []


def _cell_val(cell) -> str:
    dv = cell.get("display_value")
    if (dv is None or dv == "") and cell.get("raw_value") is not None:
        return str(cell.get("raw_value"))
    return "" if dv is None else str(dv)


def _finding(rule, pv, row, cell, value, *, fix=None) -> dict:
    return {
        "rule": rule.get("id"),
        "severity": rule.get("severity", "warn"),
        "message": rule.get("message", rule.get("id")),
        "program": pv.get("catalog_key"),
        "program_number": pv.get("program_number"),
        "menu_path": pv.get("menu_path"),
        "index": row.get("index") if row else None,
        "row_key": (row.get("key") or row.get("index")) if row else None,
        "field": cell.get("field_name") if cell else None,
        "value": value,
        "fix": fix,
    }


def _iter_cells(programs):
    for pv in programs:
        for row in pv.get("rows") or []:
            for cell in row.get("cells") or []:
                yield pv, row, cell


def _match_field(rule, cell) -> bool:
    if rule.get("secret_only") and not cell.get("is_secret"):
        return False
    fc = rule.get("field_contains")
    if fc and fc.lower() not in (cell.get("field_name") or "").lower():
        return False
    fn = rule.get("field_names")
    if fn and cell.get("field_name") not in fn:
        return False
    return True


def _rule_weak_value(rule, programs, index):
    bad = {str(v).lower() for v in rule.get("bad_values", [])}
    out = []
    for pv, row, cell in _iter_cells(programs):
        if not _match_field(rule, cell):
            continue
        val = _cell_val(cell)
        if val.lower() in bad:
            out.append(_finding(rule, pv, row, cell, val))
    return out


def _rule_empty_field(rule, programs, index):
    progs = set(str(p) for p in rule.get("programs", []))
    names = set(rule.get("field_names", []))
    out = []
    for pv in programs:
        if progs and str(pv.get("program_number")) not in progs:
            continue
        for row in pv.get("rows") or []:
            by_name = {c.get("field_name"): c for c in row.get("cells") or []}
            for name in names:
                cell = by_name.get(name)
                if cell is not None and _cell_val(cell) == "":
                    out.append(_finding(rule, pv, row, cell, ""))
    return out


def _rule_fields_differ(rule, programs, index):
    a, b = rule.get("a"), rule.get("b")
    out = []
    for pv in programs:
        for row in pv.get("rows") or []:
            by_name = {c.get("field_name"): c for c in row.get("cells") or []}
            ca, cb = by_name.get(a), by_name.get(b)
            if ca is None or cb is None:
                continue
            va, vb = _cell_val(ca), _cell_val(cb)
            if va and vb and va != vb:
                out.append(_finding(rule, pv, row, ca, f"{va!r} vs {vb!r}"))
    return out


def _rule_orphan_reference(rule, programs, index):
    if index is None:
        return []
    out = []
    for pv, row, cell in _iter_cells(programs):
        if not _match_field(rule, cell):
            continue
        val = _cell_val(cell)
        if not val:
            continue
        try:
            occ = index.lookup(val)
        except Exception:  # noqa: BLE001
            occ = []
        # Only this cell holds the value anywhere → nothing it points at exists.
        if len(occ) <= 1:
            out.append(_finding(rule, pv, row, cell, val))
    return out


_RULE_FUNCS = {
    "weak_value": _rule_weak_value,
    "empty_field": _rule_empty_field,
    "fields_differ": _rule_fields_differ,
    "orphan_reference": _rule_orphan_reference,
}


def lint_views(program_views, *, rules: list | None = None, index=None) -> dict:
    """Run the linter over a snapshot's program views. Returns
    ``{findings, counts, rule_count}``. Pure — ``index`` (a value index) is only
    needed by cross-reference rules; without it those rules are skipped."""
    rules = rules if rules is not None else load_rules()
    programs = _programs(program_views)
    findings: list = []
    for rule in rules:
        fn = _RULE_FUNCS.get(rule.get("type"))
        if fn is None:
            continue
        findings.extend(fn(rule, programs, index))
    counts = {"error": 0, "warn": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"findings": findings, "counts": counts, "rule_count": len(rules)}


# convenience regex kept for callers building ad-hoc field matchers
_WORD = re.compile(r"\w+")
