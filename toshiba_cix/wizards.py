"""Wizard planners (DESIGN_PLAN 5.7, 10.2 ``wizards/*.py``).

eManager's wizards are multi-step forms whose last step is a write. Here each is
a **pure planner**: ``plan(inputs, snapshot) -> [WriteOp]`` with no I/O and no
network — the UI collects the inputs, the planner turns them into the same
:class:`~toshiba_cix.write.WriteOp` list a hand edit makes, and the one write is
still the Review & Write dialog. (The design keeps one file per wizard; the
stdlib single-file build collapses them into this module.)

Covered: Add New Station, Delete Station (with dependents), Change DN,
PDN/VMID Range. Row creation and row deletion are **unproven** on the wire, so
those ops come back non-sendable and flagged (``row_create`` / a destructive
note) — the planner never invents a write OID.
"""

from __future__ import annotations

from .index import build_index_from_views
from .programs import plan_row_update
from .write import WriteOp

__all__ = [
    "plan_add_station", "plan_delete_station", "plan_change_dn",
    "plan_pdn_vmid_range", "PLANNERS", "plan",
]

STATION_PROGRAM = "200"


def _views(snapshot) -> list:
    if isinstance(snapshot, dict) and "programs" in snapshot:
        return snapshot.get("programs") or []
    if isinstance(snapshot, dict):
        return list(snapshot.values())
    return snapshot or []


def _find_view(snapshot, program):
    for pv in _views(snapshot):
        if pv.get("catalog_key") == program or str(pv.get("program_number")) == str(program):
            return pv
    return None


def _find_row(view, index):
    if not view:
        return None
    for r in view.get("rows") or []:
        if str(r.get("index")) == str(index):
            return r
    return None


def _row_by_key(view, key):
    if not view:
        return None
    for r in view.get("rows") or []:
        if str(r.get("key")) == str(key) or str(r.get("index")) == str(key):
            return r
    return None


def plan_add_station(inputs: dict, snapshot=None) -> list:
    """Add New Station. ``inputs``: ``{dn, name?, type?, program?}``. Station
    rows are created by the switch, not by writing an invented OID — so these
    come back non-sendable and ``row_create=True`` (unproven), which the review
    excludes by default. The planner exists to show *exactly* what the wizard
    would create and to let the reviewer see the blast radius."""
    dn = str(inputs.get("dn") or "").strip()
    program = str(inputs.get("program") or STATION_PROGRAM)
    ops: list = []
    if not dn:
        return ops
    fields = {}
    if inputs.get("name") is not None:
        fields["name"] = str(inputs["name"])
    if inputs.get("type") is not None:
        fields["type"] = str(inputs["type"])
    for field, value in fields.items():
        ops.append(WriteOp(
            field=field, label=field, new_value=value, old_value=None,
            target_oid=None, program=program, row_create=True,
            note=(f"Add New Station: creates DN {dn} in program {program} — "
                  "row-create is unproven; the switch assigns the instance"),
        ))
    return ops


def plan_delete_station(inputs: dict, snapshot=None) -> list:
    """Delete Station. ``inputs``: ``{dn}``. The point of the wizard is the
    **dependents** step: every other row that references the DN (keys, hunt
    groups, DID targets, the mailbox) is found via the value index and planned
    *cleared*; the station-row deletion itself is a destructive program-201
    operation, returned non-sendable so it is never auto-run."""
    dn = str(inputs.get("dn") or "").strip()
    ops: list = []
    if not dn or snapshot is None:
        return ops
    try:
        index = build_index_from_views(
            {"programs": _views(snapshot)})
        occ = index.lookup(dn)
    except Exception:  # noqa: BLE001
        occ = []
    seen = set()
    for o in occ:
        pkey, idx, field = o.get("program"), o.get("index"), o.get("field")
        if idx is None or field is None:
            continue
        # The station's own row is handled by the deletion itself; the wizard
        # clears the references on OTHER programs (keys, groups, DID, mailbox).
        if str(o.get("program_number")) == STATION_PROGRAM:
            continue
        loc = (pkey, idx, field)
        if loc in seen:
            continue
        seen.add(loc)
        view = _find_view(snapshot, pkey)
        row = _find_row(view, idx)
        if row is None:
            continue
        ops.extend(plan_row_update(row, {field: ""},
                                   program_number=view.get("program_number")))
    ops.append(WriteOp(
        field="__delete__", label=f"Delete station {dn}", new_value="",
        old_value=dn, target_oid=None, program="201", row_create=False,
        note="station deletion is a destructive program-201 operation — "
             "run it explicitly, never batched with ordinary edits"))
    return ops


def plan_change_dn(inputs: dict, snapshot=None) -> list:
    """Change DN. ``inputs``: ``{old_dn, new_dn}``. Re-points every reference to
    the old DN at the new one (via the value index); the DN-of-record change is
    eManager program 203 and is returned as its own non-sendable note op (the
    key column is never SET directly)."""
    old_dn = str(inputs.get("old_dn") or "").strip()
    new_dn = str(inputs.get("new_dn") or "").strip()
    ops: list = []
    if not old_dn or not new_dn or snapshot is None:
        return ops
    try:
        index = build_index_from_views({"programs": _views(snapshot)})
        occ = index.lookup(old_dn)
    except Exception:  # noqa: BLE001
        occ = []
    seen = set()
    for o in occ:
        pkey, idx, field = o.get("program"), o.get("index"), o.get("field")
        if idx is None or field is None:
            continue
        if str(o.get("program_number")) == STATION_PROGRAM:
            continue  # the DN of record moves via program 203, below
        loc = (pkey, idx, field)
        if loc in seen:
            continue
        seen.add(loc)
        view = _find_view(snapshot, pkey)
        row = _find_row(view, idx)
        if row is None:
            continue
        ops.extend(plan_row_update(row, {field: new_dn},
                                   program_number=view.get("program_number")))
    ops.append(WriteOp(
        field="dn", label=f"DN of record {old_dn} → {new_dn}",
        new_value=new_dn, old_value=old_dn, target_oid=None, program="203",
        note="the DN of record is changed via program 203, not by SETting the "
             "key column"))
    return ops


def plan_pdn_vmid_range(inputs: dict, snapshot=None) -> list:
    """PDN / VMID Range. ``inputs``: ``{program, field, start, count, value_start,
    rows?, step?}``. Assigns a sequential value to ``field`` across a block of
    existing rows (``rows`` indices, or the program's first ``count`` rows from
    ``start``). Pure — each row goes through ``plan_row_update``."""
    program = str(inputs.get("program") or STATION_PROGRAM)
    field = inputs.get("field")
    if not field or snapshot is None:
        return []
    view = _find_view(snapshot, program)
    if view is None:
        return []
    rows = inputs.get("rows")
    if not rows:
        start = int(inputs.get("start") or 0)
        count = int(inputs.get("count") or 0)
        all_idx = [r.get("index") for r in view.get("rows") or []]
        rows = all_idx[start:start + count] if count else all_idx
    value = int(inputs.get("value_start") or 0)
    step = int(inputs.get("step") or 1)
    ops: list = []
    for idx in rows:
        row = _find_row(view, idx)
        if row is None:
            continue
        ops.extend(plan_row_update(row, {field: str(value)},
                                   program_number=view.get("program_number")))
        value += step
    return ops


PLANNERS = {
    "add_station": plan_add_station,
    "delete_station": plan_delete_station,
    "change_dn": plan_change_dn,
    "pdn_vmid_range": plan_pdn_vmid_range,
}


def plan(name: str, inputs: dict, snapshot=None) -> list:
    """Dispatch to a named planner. Raises ``KeyError`` on an unknown wizard."""
    return PLANNERS[name](inputs, snapshot)
