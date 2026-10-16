"""The staged changeset — the pending-changes rail's data model.

DESIGN_PLAN §9 layer 2 ("stage, don't send"): edits are coalesced per field and
held per session; **nothing hits the wire** until the review dialog's explicit
apply. A :class:`Changeset` stores only intent — ``{program_key: {index:
{field: new_value}}}`` — never a plan, so the base and the write OID are always
re-derived from a fresh read of the working copy at review time (and a live
re-read at apply time). Staging the same field twice coalesces; staging a field
back to its original value drops it.

The pure orchestration here — :func:`plan_rows` and :func:`simulate_oplog` —
turns a changeset into :class:`WriteOp` lists and a Simulate op-log with **no
I/O**, so the Simulate path and all tests run with no network at all.
"""

from __future__ import annotations

from .programs import plan_row_update
from .snmp import ber_octet
from .write import WriteOp, commit_write_op, encode_set_request

__all__ = ["Changeset", "plan_rows", "simulate_oplog"]


class Changeset:
    def __init__(self):
        # program_key -> index -> field -> new_value (strings; coalesced)
        self._staged: dict[str, dict] = {}

    # -- mutation ----------------------------------------------------------
    def stage(self, program_key: str, index: str, changes: dict,
              originals: dict | None = None) -> None:
        """Stage ``{field: new_value}`` for one row. A change back to the
        field's original value (``originals[field]``) removes it rather than
        staging a no-op, so a round-trip edit leaves the tray clean."""
        originals = originals or {}
        by_index = self._staged.setdefault(program_key, {})
        row = by_index.setdefault(index, {})
        for field, value in changes.items():
            value = "" if value is None else str(value)
            orig = originals.get(field)
            if orig is not None and value == str(orig):
                row.pop(field, None)
            else:
                row[field] = value
        if not row:
            by_index.pop(index, None)
        if not by_index:
            self._staged.pop(program_key, None)

    def drop_field(self, program_key: str, index: str, field: str) -> None:
        row = self._staged.get(program_key, {}).get(index)
        if row is not None:
            row.pop(field, None)
            if not row:
                self._staged[program_key].pop(index, None)
                if not self._staged[program_key]:
                    self._staged.pop(program_key, None)

    def drop_row(self, program_key: str, index: str) -> None:
        by_index = self._staged.get(program_key)
        if by_index is not None:
            by_index.pop(index, None)
            if not by_index:
                self._staged.pop(program_key, None)

    def clear(self) -> None:
        self._staged = {}

    # -- query -------------------------------------------------------------
    @property
    def staged(self) -> dict:
        return self._staged

    def is_empty(self) -> bool:
        return not self._staged

    def field_count(self) -> int:
        return sum(len(fields) for by_index in self._staged.values()
                   for fields in by_index.values())

    def row_count(self) -> int:
        return sum(len(by_index) for by_index in self._staged.values())

    def as_dict(self) -> dict:
        return {"staged": self._staged, "field_count": self.field_count(),
                "row_count": self.row_count()}


def plan_rows(doc: dict, staged: dict, *, catalog=None) -> tuple:
    """Plan every staged row against the working copy ``doc``
    (``{program_key: program_view}``). Pure — re-derives each op's base, OID and
    wire type from the read, inventing nothing. Returns ``(ops, groups)`` where
    ``groups`` is the per-row grouping the tray renders."""
    ops: list[WriteOp] = []
    groups: list[dict] = []
    for pkey, by_index in staged.items():
        pv = doc.get(pkey) or {}
        rows_by_index = {r.get("index"): r for r in pv.get("rows") or []}
        program = None
        if catalog is not None:
            try:
                program = catalog.program(pkey)
            except Exception:  # noqa: BLE001
                program = None
        prog_num = pv.get("program_number") or (
            getattr(program, "number", None) if program else None)
        for index, changes in by_index.items():
            row = rows_by_index.get(index) or {"index": index, "key": index,
                                               "cells": []}
            row_ops = plan_row_update(row, changes, program=program,
                                      program_number=prog_num)
            ops.extend(row_ops)
            groups.append({
                "program_key": pkey,
                "program_number": prog_num,
                "menu_path": pv.get("menu_path"),
                "label": pv.get("label") or pkey,
                "index": index,
                "row_key": row.get("key") or index,
                "ops": [o.as_dict() for o in row_ops],
            })
    return ops, groups


def simulate_oplog(ops, *, community: str = "communityName",
                   include_commit: bool = True) -> dict:
    """A Simulate op-log for ``ops`` (DESIGN_PLAN §6.8): what *would* be sent, as
    the exact SNMP SET varbind bytes, with **no socket opened**. The final entry
    is the proven apply/commit SET, labelled unproven-persistence. Pure."""
    sendable = [op for op in ops if op.sendable and op.op_class != "commit"]
    entries: list[dict] = []
    for op in sendable:
        entries.append({
            "field": op.field,
            "oid": op.target_oid,
            "wire": op.ber_type,
            "wire_proven": op.wire_proven,
            "old_value": op.old_value,
            "new_value": op.new_value,
            "value_tlv_hex": op.encode_value().hex(),
            "note": op.note,
        })
    commit = commit_write_op() if (include_commit and sendable) else None
    batch_hex = None
    if sendable:
        batch_hex = encode_set_request(community, sendable, request_id=1).hex()
    return {
        "mode": "simulate",
        "would_send": len(sendable),
        "entries": entries,
        "commit": (commit.as_dict() if commit else None),
        "commit_value_tlv_hex": (commit.encode_value().hex() if commit else None),
        "batch_set_pdu_hex": batch_hex,
        "network": False,
        "note": ("Simulate — nothing was sent. The bytes above are exactly what "
                 "the SET would carry; the commit SET persists the batch "
                 "(persistence across reboot is unproven)."),
    }
