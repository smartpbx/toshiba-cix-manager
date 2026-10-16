"""Toshiba Strata CIX SNMP **write** path (implemented from the on-site pcap).

The SET protocol was decoded from ``emanager-session1-final.pcap`` (frame 634,
which the CIX accepted — frame 635 confirmed it):

* eManager writes a field with an SNMP **SetRequest**, sent as **v2c**
  (SNMP version field = 1; reads stay v1), community ``communityName``.
* The varbinds are the **data OIDs** of the fields — exactly the OIDs a read
  returns — set to the new value, **batched** (several fields in one SET).
* Value encoding is identical to a read: an ``OCTET STRING`` carrying the
  literal string (``"sysadmin"``, ``"010101"``, a station name); an ``INTEGER``
  for the genuinely-numeric fields.
* eManager then GETs the same OIDs back to confirm. We do the same.

Ground truth (frame 634)::

    SetRequest v2c community=communityName request-id=6
      1.3.6.1.4.1.186.1.22.3.2.3.1.1.4.1 = OctetString "/"
      1.3.6.1.4.1.186.1.22.3.2.3.1.1.2.1 = OctetString "sysadmin"
      1.3.6.1.4.1.186.1.22.3.2.3.1.1.3.1 = OctetString "wksi76dbga"

That is the FTP-credential table (``.3.2.3``), but the mechanism is identical
for any program/field — a station name / extension / trunk is the same SET to
that field's OID. We build the exact target OID from the ``source_oids`` the
reader already records per field, so a planned edit addresses the precise
instance it was read from.

Still to confirm on the first **supervised** live write (TODOs, not blockers —
the direct data SET at frame 634 succeeded with no immediately-preceding op):

* An operation/mode SET was seen once early (frame 334):
  ``1.3.6.1.4.1.186.1.22.7.7.1.0 = Integer 2``. Implemented here as an optional
  pre-op (:data:`OP_MODE_OID`), **off by default**; enable only if a bare data
  SET is ever refused.
* Any save/commit-to-flash step (so a write survives a processor reboot) is not
  yet identified. Re-read after a reboot during the supervised test.

Safety contract (kept strict):

* :data:`WRITES_ENABLED` is the master switch. A write also requires the caller
  to pass ``confirm=True`` to :meth:`CIXWriter.commit` — the web layer wires
  that to an explicit "Confirm & write" action, never a silent save.
* Every write is GET-verified: :meth:`CIXWriter.commit` reads the OIDs back and
  reports requested-vs-read-back per field. It never writes silently.
* A non-sendable planned op (unknown field, read-only port, or a field with no
  derivable OID) is never sent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .decode import decode_value
from .snmp import SnmpError, Value, ber_integer, ber_octet, encode_set_message

# Master switch. Writes are implemented and unit-tested offline against a fake
# agent; a supervised live write (reversible station-name set -> read-back ->
# re-read) is done with the owner present before trusting it in the field.
WRITES_ENABLED = True

# Optional operation/mode pre-op (frame 334). OFF by default: the data SET at
# frame 634 succeeded without it. Flip on only if a bare SET is ever refused.
SEND_OP_MODE = False
OP_MODE_OID = "1.3.6.1.4.1.186.1.22.7.7.1.0"
OP_MODE_VALUE = 2


def writes_enabled() -> bool:
    """The live master-switch value.

    Read this instead of importing :data:`WRITES_ENABLED` by value when the flag
    may be toggled at runtime (e.g. a test, or a future UI switch): a
    ``from .write import WRITES_ENABLED`` binding in another module is a snapshot
    taken at import time, whereas this always returns the current global.
    """
    return WRITES_ENABLED


class WriteError(RuntimeError):
    """A write could not be completed: disabled, not confirmed, nothing
    sendable, the agent rejected the SET, or read-back verification failed."""


# Fields of the station directory (Program 1200) a tech may edit in eManager.
# Maps the structured field name -> (program, column). The equipment port is
# deliberately absent: it is a physical cabinet/slot/circuit assignment, not a
# free-text field, and must never be SET from this tool.
#   col2 = extension (also the row DN), col4 = type, col19 = station name.
STATION_WRITE_COLUMNS: dict[str, tuple[str, int]] = {
    "extension": ("1200", 2),
    "type": ("1200", 4),
    "name": ("1200", 19),
}

# Columns that are read-only on purpose (shown but never writable).
STATION_READONLY_FIELDS = frozenset({"equipment_port", "dn", "source_oids",
                                     "flags", "keys", "programs"})


@dataclass
class WriteOp:
    """One intended field change.

    ``target_oid`` is the exact instance OID the SET addresses (derived from the
    read, so it is correct), ``new_value`` the desired value, ``old_value`` what
    the read saw. ``ber_type`` is the on-wire type (``OCTET STRING`` for every
    field proven so far; ``INTEGER`` is available for numeric fields that need
    it). ``sendable`` is ``False`` whenever we could not derive a target OID;
    such an op is never sent.
    """

    field: str
    label: str
    new_value: str
    old_value: str | None = None
    target_oid: str | None = None
    program: str | None = None
    column: int | None = None
    ber_type: str = "OCTET STRING"
    note: str = ""

    @property
    def sendable(self) -> bool:
        return bool(self.target_oid)

    def encode_value(self) -> bytes:
        """The BER value TLV for this op (same encoding reads use)."""
        if self.ber_type == "INTEGER":
            return ber_integer(int(self.new_value))
        return ber_octet(self.new_value)

    def as_dict(self) -> dict:
        return {
            "field": self.field,
            "label": self.label,
            "new_value": self.new_value,
            "old_value": self.old_value,
            "target_oid": self.target_oid,
            "program": self.program,
            "column": self.column,
            "ber_type": self.ber_type,
            "sendable": self.sendable,
            "note": self.note,
        }


def encode_set_request(community: str, ops: Iterable[WriteOp],
                       request_id: int = 1, *, version: int = 1) -> bytes:
    """Encode an SNMP ``SetRequest`` (v2c) for the sendable ``ops``.

    Raises :class:`WriteError` if nothing is sendable. This is a thin shim over
    :func:`toshiba_cix.snmp.encode_set_message` that turns :class:`WriteOp`
    records into ``(oid, value_tlv)`` varbinds.
    """
    sendable = [op for op in ops if op.sendable]
    if not sendable:
        raise WriteError("no sendable operations to encode")
    varbinds = [(op.target_oid, op.encode_value()) for op in sendable]
    return encode_set_message(community, varbinds, request_id, version=version)


class CIXWriter:
    """Plans (pure) and commits (live, GET-verified) station edits.

    ``plan_station_update`` is pure (no I/O) and safe to call anywhere.
    ``commit`` sends the batched SET and verifies the read-back. The ``client``
    is only needed by ``commit``.
    """

    def __init__(self, client=None):
        self.client = client

    def plan_station_update(self, station: dict, changes: dict) -> list[WriteOp]:
        """Build the intended :class:`WriteOp` list for a station edit (no I/O).

        ``station`` is one entry from ``doc["stations"]`` (it carries
        ``source_oids``); ``changes`` is ``{field: new_value}``. Only fields in
        :data:`STATION_WRITE_COLUMNS` are planned; anything else is returned as a
        non-sendable op with an explanatory note, so the UI can tell the tech why
        it was skipped rather than silently dropping it.
        """
        source_oids = station.get("source_oids", {}) or {}
        ops: list[WriteOp] = []
        for fieldname, new_value in changes.items():
            old_value = station.get(fieldname)
            if old_value is not None and not isinstance(old_value, str):
                old_value = str(old_value)
            if fieldname in STATION_READONLY_FIELDS:
                ops.append(WriteOp(
                    field=fieldname, label=fieldname, new_value=str(new_value),
                    old_value=old_value, note="read-only field — never written",
                ))
                continue
            spec = STATION_WRITE_COLUMNS.get(fieldname)
            if spec is None:
                ops.append(WriteOp(
                    field=fieldname, label=fieldname, new_value=str(new_value),
                    old_value=old_value,
                    note="no known writable column for this field",
                ))
                continue
            prog, col = spec
            target_oid = source_oids.get(fieldname)
            note = ""
            if not target_oid:
                note = ("field has no existing instance on the device; the write "
                        "OID cannot be derived from a read")
            ops.append(WriteOp(
                field=fieldname, label=fieldname, new_value=str(new_value),
                old_value=old_value, target_oid=target_oid,
                program=prog, column=col, note=note,
            ))
        return ops

    def commit(self, ops: Iterable[WriteOp], *, confirm: bool = False,
               verify: bool = True) -> dict:
        """Send the batched SET for the sendable ``ops`` and verify the read-back.

        Requires :data:`WRITES_ENABLED` and ``confirm=True`` (an explicit
        confirmation — the UI's "Confirm & write"). After the SET it GETs the
        same OIDs and compares each decoded value to what was requested.

        Returns a structured result::

            {ok, wrote, verified, verified_all,
             results: [{field, oid, requested, read_back, match}],
             skipped: [<non-sendable op dicts>]}

        Raises :class:`WriteError` on a gate failure / nothing sendable, and
        :class:`toshiba_cix.snmp.SnmpError` if the agent rejects the SET.
        """
        ops = list(ops)
        if not WRITES_ENABLED:
            raise WriteError("writes are disabled (WRITES_ENABLED is False)")
        if not confirm:
            raise WriteError("refusing to write without explicit confirm=True")
        if self.client is None:
            raise WriteError("no SNMP client to write with")

        sendable = [op for op in ops if op.sendable]
        skipped = [op for op in ops if not op.sendable]
        if not sendable:
            raise WriteError(
                "nothing sendable: " + "; ".join(
                    f"{op.field} ({op.note})" for op in skipped) or "no ops")

        # Optional operation/mode pre-op (see module docstring) — off by default.
        if SEND_OP_MODE:
            self.client.set([(OP_MODE_OID, ber_integer(OP_MODE_VALUE))])

        varbinds = [(op.target_oid, op.encode_value()) for op in sendable]
        self.client.set(varbinds)   # raises SnmpError if the CIX rejects it

        results: list[dict] = []
        verified_all = True
        if verify:
            vbs = self.client.get([op.target_oid for op in sendable])
            by_oid = {vb.oid: vb.value for vb in vbs}
            for op in sendable:
                read_back = decode_value(by_oid.get(op.target_oid, Value("missing")))
                match = str(read_back) == str(op.new_value)
                verified_all = verified_all and match
                results.append({
                    "field": op.field, "oid": op.target_oid,
                    "requested": op.new_value, "read_back": read_back,
                    "match": match,
                })
        return {
            "ok": verified_all if verify else True,
            "wrote": len(sendable),
            "verified": verify,
            "verified_all": verified_all,
            "results": results,
            "skipped": [op.as_dict() for op in skipped],
        }

    def apply_station_update(self, station: dict, changes: dict, *,
                             confirm: bool = False, verify: bool = True) -> dict:
        """Plan then commit a station edit (convenience)."""
        ops = self.plan_station_update(station, changes)
        return self.commit(ops, confirm=confirm, verify=verify)


__all__ = [
    "WRITES_ENABLED", "writes_enabled", "SEND_OP_MODE", "OP_MODE_OID",
    "OP_MODE_VALUE", "WriteError", "WriteOp", "CIXWriter", "encode_set_request",
    "STATION_WRITE_COLUMNS", "STATION_READONLY_FIELDS",
]
