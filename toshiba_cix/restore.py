"""Catalog-driven **restore**: write a backup (or a subset / a diff) back to a CIX.

Restore turns a backup document (:mod:`toshiba_cix.backup`) into a set of SNMP
SETs — one per **writable** field — addressed at the exact instance OID the
value was read from, then sends them batched and GET-verifies each read-back.

Safety is inherited wholesale from :mod:`toshiba_cix.write`:

* :data:`toshiba_cix.write.WRITES_ENABLED` is the master switch.
* :meth:`toshiba_cix.write.CIXWriter.commit` requires ``confirm=True`` and
  GET-verifies every field (requested-vs-read-back). Restore reuses it — there
  is one write path, one gate.
* **Read-only fields are never SET.** The planner marks them non-sendable with
  a note; they never reach a SET.

The planner (:func:`plan_restore`) is pure (no I/O) and fully unit-tested — it
reports exactly which OIDs/values it *would* SET. :func:`restore` is the gated
live step; with ``confirm=False`` (the default) it previews and touches nothing.

**Persistence is unproven.** The eManager write capture proved a data SET lands
in the processor's running config and reads back; whether it survives a reboot
(a flash/commit step) was never identified. Treat restore as **apply-to-RAM,
verify** until a supervised live write confirms persistence. Non-OCTET-STRING
writes (INTEGER / IpAddress / Gauge32) are catalog-derived and likewise await
that first supervised write; each such op is flagged ``wire_type_proven=False``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .catalog import Catalog
from .decode import MISSING
from .snmp import SnmpError, ber_integer, ber_octet
from .write import CIXWriter, WriteError, WriteOp, writes_enabled

DEFAULT_BATCH = 20   # fields per SET PDU (eManager batches ~20)


@dataclass
class RestoreOp:
    """One intended field restore (planned; pure)."""

    program: str                 # catalog key
    index: str                   # instance tail (restores the exact OID)
    row_key: str                 # human row key (the DN, when present)
    field: str                   # per-row field key (may carry a #leaf suffix)
    field_name: str              # catalog field name
    target_oid: str | None
    new_value: object
    ber_type: str = "OCTET STRING"
    writable: bool = True
    wire_type_proven: bool = True
    note: str = ""

    @property
    def sendable(self) -> bool:
        return bool(self.target_oid) and self.writable

    def encode_value(self) -> bytes:
        if self.ber_type == "INTEGER":
            return ber_integer(int(self.new_value))
        return ber_octet(str(self.new_value))

    def to_writeop(self) -> WriteOp:
        """Convert to a :class:`WriteOp` so the one gated commit path sends it."""
        return WriteOp(
            field=f"{self.program}/{self.index}/{self.field}",
            label=f"{self.field_name} [{self.row_key}]",
            new_value=self.new_value,
            old_value=None,
            target_oid=self.target_oid,
            program=self.program,
            column=None,
            ber_type=self.ber_type,
            note=self.note,
        )

    def as_dict(self) -> dict:
        return {
            "program": self.program, "index": self.index,
            "row_key": self.row_key, "field": self.field,
            "field_name": self.field_name, "target_oid": self.target_oid,
            "new_value": self.new_value, "ber_type": self.ber_type,
            "writable": self.writable, "wire_type_proven": self.wire_type_proven,
            "sendable": self.sendable, "note": self.note,
        }


def _resolve_field(prog, fieldkey: str) -> dict | None:
    """Resolve a (possibly #leaf-disambiguated) field key to its catalog field."""
    name, _, leaf = fieldkey.partition("#")
    candidates = prog.fields_named(name)
    if not candidates:
        return None
    if leaf:
        for f in candidates:
            if f.get("oid", "").rsplit(".", 1)[-1] == leaf:
                return f
    return candidates[0]


def _diff_targets(from_diff: dict) -> set:
    """``{(program, index, field)}`` to restore from a diff (changed + added)."""
    targets: set = set()
    for key, c in (from_diff.get("programs_changed") or {}).items():
        for ch in c.get("fields_changed", []):
            targets.add((key, ch["index"], ch["field"]))
        for ch in c.get("fields_added", []):
            targets.add((key, ch["index"], ch["field"]))
        # a whole row that is new in B: restore every field of it
        for index in c.get("rows_added", []):
            targets.add((key, index, None))      # None = all fields in this row
    return targets


def plan_restore(backup: dict, catalog: Catalog, *, programs=None,
                 only=None, from_diff: dict | None = None,
                 include_readonly: bool = False) -> list[RestoreOp]:
    """Plan the SETs a restore would issue (no I/O).

    ``programs`` limits to those program idents; ``only`` is an iterable of
    ``(program, field_name)`` pairs; ``from_diff`` restricts to the fields a
    diff reports changed/added. Read-only fields are always planned as
    non-sendable (never SET) unless ``include_readonly`` is set *and* the field
    is in fact writable — a read-only field is never sent regardless.
    """
    want_progs = None
    if programs:
        want_progs = {p.key for p in catalog.programs_for(programs)}
    only_set = {(str(p), f) for p, f in only} if only else None
    diff_targets = _diff_targets(from_diff) if from_diff else None

    ops: list[RestoreOp] = []
    for prog_key, bucket in (backup.get("programs") or {}).items():
        if want_progs is not None and prog_key not in want_progs:
            continue
        prog = catalog.program(prog_key)
        for row in bucket.get("rows", []):
            index = row.get("index", "0")
            row_key = row.get("key") or index
            for fieldkey, value in (row.get("fields") or {}).items():
                fld = _resolve_field(prog, fieldkey) if prog else None
                field_name = fld.get("name") if fld else fieldkey
                if only_set is not None and (prog_key, field_name) not in only_set \
                        and (bucket.get("number"), field_name) not in only_set:
                    continue
                if diff_targets is not None and not (
                        (prog_key, index, fieldkey) in diff_targets
                        or (prog_key, index, None) in diff_targets):
                    continue

                if fld is None:
                    ops.append(RestoreOp(
                        program=prog_key, index=index, row_key=row_key,
                        field=fieldkey, field_name=field_name, target_oid=None,
                        new_value=value, writable=False,
                        note="field not in catalog — cannot restore"))
                    continue
                if value == MISSING or value is None:
                    ops.append(RestoreOp(
                        program=prog_key, index=index, row_key=row_key,
                        field=fieldkey, field_name=field_name, target_oid=None,
                        new_value=value, writable=Catalog.is_writable(fld),
                        note="value was absent at backup time — nothing to write"))
                    continue
                writable = Catalog.is_writable(fld)
                target_oid = catalog.instance_oid(fld, index) if writable else None
                ber_type, _tlv = catalog.encode_field_value(fld, value)
                note = ""
                if not writable:
                    note = "read-only field — never written"
                elif not catalog.wire_type_proven(fld, value):
                    note = (f"{ber_type} write is catalog-derived "
                            "(await supervised live write)")
                ops.append(RestoreOp(
                    program=prog_key, index=index, row_key=row_key,
                    field=fieldkey, field_name=field_name,
                    target_oid=target_oid, new_value=value, ber_type=ber_type,
                    writable=writable,
                    wire_type_proven=catalog.wire_type_proven(fld, value),
                    note=note))
    return ops


def plan_summary(ops: list[RestoreOp]) -> dict:
    sendable = [o for o in ops if o.sendable]
    return {
        "total": len(ops),
        "sendable": len(sendable),
        "skipped": len(ops) - len(sendable),
        "read_only": sum(1 for o in ops if not o.writable),
        "unproven_wire_type": sum(1 for o in sendable if not o.wire_type_proven),
    }


def restore(client, backup: dict, catalog: Catalog, *, confirm: bool = False,
            verify: bool = True, batch_size: int = DEFAULT_BATCH,
            programs=None, only=None, from_diff: dict | None = None) -> dict:
    """Plan, and (only with ``confirm=True``) apply a restore. Gated.

    With ``confirm=False`` this previews — it returns the full plan and sends
    **nothing**. With ``confirm=True`` it batches the sendable ops into SETs of
    ``batch_size`` and routes each batch through :meth:`CIXWriter.commit`, which
    enforces :data:`WRITES_ENABLED` + confirm and GET-verifies the read-back.

    Returns ``{ok, mode, writes_enabled, summary, planned_ops, [batches],
    [results], [verified_all]}``. A write is never silent and never persists a
    read-only field.
    """
    ops = plan_restore(backup, catalog, programs=programs, only=only,
                       from_diff=from_diff)
    summary = plan_summary(ops)
    base = {
        "writes_enabled": writes_enabled(),
        "summary": summary,
        "planned_ops": [o.as_dict() for o in ops],
    }
    if not confirm:
        base.update(ok=True, mode="preview",
                    message=("Preview only — nothing was sent. "
                             "Use confirm=True to apply to the live CIX (RAM; "
                             "persistence across reboot is unproven)."))
        return base

    if not writes_enabled():
        raise WriteError("writes are disabled (WRITES_ENABLED is False)")
    sendable = [o for o in ops if o.sendable]
    if not sendable:
        raise WriteError("nothing sendable to restore "
                         f"({summary['skipped']} skipped)")

    writer = CIXWriter(client)
    results: list[dict] = []
    batches: list[dict] = []
    verified_all = True
    wrote = 0
    for start in range(0, len(sendable), max(1, batch_size)):
        chunk = sendable[start:start + max(1, batch_size)]
        writeops = [o.to_writeop() for o in chunk]
        try:
            res = writer.commit(writeops, confirm=True, verify=verify)
        except (WriteError, SnmpError) as exc:
            batches.append({"ok": False, "size": len(chunk), "error": str(exc)})
            verified_all = False
            continue
        results.extend(res["results"])
        wrote += res["wrote"]
        verified_all = verified_all and res["verified_all"]
        batches.append({"ok": res["ok"], "size": len(chunk),
                        "verified_all": res["verified_all"]})

    base.update(
        ok=verified_all,
        mode="write",
        wrote=wrote,
        verified=verify,
        verified_all=verified_all,
        batches=batches,
        results=results,
        message=("Restore sent and verified (applied to RAM — persistence "
                 "across reboot is unproven)." if verified_all
                 else "Restore sent but some read-backs did not match — "
                      "see results."),
    )
    return base


__all__ = [
    "RestoreOp", "plan_restore", "plan_summary", "restore", "DEFAULT_BATCH",
]
