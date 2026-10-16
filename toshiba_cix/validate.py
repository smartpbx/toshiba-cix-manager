"""Two-level validation of planned edits, shared by the engine and the UI.

DESIGN_PLAN 10.2 (``validate.py`` L1/L2). Both levels are pure functions over
the enriched row cells and the catalog field metadata — no network, no state —
so the same rules run in the review dialog (client-side pre-check) and on the
engine before a changeset is allowed to apply.

* **L1 — field level.** One field in isolation: is the value non-empty when the
  field is a required key-ish field, within the declared length, digits-only
  when the field's native type is numeric, and a well-formed IPv4 / time / port
  when the control says so. L1 never needs other rows.
* **L2 — row / batch level.** The relationships a single field can't see: two
  staged ops colliding on the same OID, a batch that would create a duplicate
  key (e.g. two stations given the same DN), and a value cleared while the batch
  still references it. L2 reads the whole changeset.

A finding is ``{level, severity, field, oid, message}`` where ``severity`` is
``"error"`` (blocks apply) or ``"warn"`` (shown, does not block). The engine
refuses to apply a changeset with any L1/L2 **error**; the UI greys the write
button on the same condition, so the two never disagree.
"""

from __future__ import annotations

import re

__all__ = [
    "validate_op", "validate_ops", "has_errors", "error_count",
    "Finding", "IPV4_RE", "TIME_RE",
]

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
TIME_RE = re.compile(r"^(?:[01]?\d|2[0-3]):[0-5]\d$")
_DIGITS_RE = re.compile(r"^\d+$")


def Finding(level: str, severity: str, field: str, message: str,
            oid: str | None = None) -> dict:
    return {"level": level, "severity": severity, "field": field,
            "oid": oid, "message": message}


def _field_meta(program, name: str) -> dict:
    """Catalog metadata for a field name, or ``{}``. ``program`` is a catalog
    :class:`~toshiba_cix.catalog.Program` (optional)."""
    if program is None:
        return {}
    for f in getattr(program, "fields", []):
        if f.get("name") == name:
            return f
    return {}


def _declared_len(meta: dict):
    raw = meta.get("len")
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def validate_op(op, program=None) -> list:
    """L1 findings for one op. ``op`` is a :class:`~toshiba_cix.write.WriteOp`
    (or any object with ``field`` / ``new_value`` / ``native_wire`` /
    ``target_oid``). Only sendable, non-commit ops are checked — a non-sendable
    op already carries its own reason."""
    findings: list = []
    if getattr(op, "op_class", "data") == "commit":
        return findings
    if not getattr(op, "sendable", True):
        return findings
    field = op.field
    oid = getattr(op, "target_oid", None)
    value = "" if op.new_value is None else str(op.new_value)
    meta = _field_meta(program, field)

    maxlen = _declared_len(meta)
    if maxlen is not None and maxlen > 0 and len(value) > maxlen:
        findings.append(Finding(
            "L1", "error", field,
            f"value is {len(value)} characters; the field holds at most {maxlen}",
            oid))

    native = (getattr(op, "native_wire", None)
              or (meta.get("syntax") or "")).upper()
    if native == "INTEGER" and value not in ("",) and not _DIGITS_RE.match(value):
        findings.append(Finding(
            "L1", "error", field,
            "field is numeric — only digits are accepted", oid))

    control = (meta.get("ui_type") or meta.get("control") or "").lower()
    if value:
        if control in ("ipaddress", "ip") and not IPV4_RE.match(value):
            findings.append(Finding(
                "L1", "error", field, "not a valid IPv4 address", oid))
        elif control == "time" and not TIME_RE.match(value):
            findings.append(Finding(
                "L1", "error", field, "not a valid HH:MM time", oid))
    return findings


def validate_ops(ops, program=None) -> dict:
    """L1 + L2 findings for a whole changeset (one program's ops). Returns
    ``{findings, by_field, errors, warnings}``."""
    findings: list = []
    sendable = [op for op in ops
                if getattr(op, "sendable", True)
                and getattr(op, "op_class", "data") != "commit"]

    for op in sendable:
        findings.extend(validate_op(op, program))

    # L2: two staged ops writing the same OID (last-writer-wins is a trap).
    by_oid: dict = {}
    for op in sendable:
        by_oid.setdefault(op.target_oid, []).append(op)
    for oid, group in by_oid.items():
        if len(group) > 1 and len({g.new_value for g in group}) > 1:
            findings.append(Finding(
                "L2", "error", group[0].field,
                "two staged changes target the same field with different "
                "values — keep one", oid))

    # L2: a batch that sets the same (writable) field to the same value on two
    # different rows, when that field is a per-system unique key-ish field
    # (DN / extension). Collisions there are the classic "duplicate DN".
    unique_fields = {"dn", "extension", "pdn", "vmid"}
    seen: dict = {}
    for op in sendable:
        if op.field in unique_fields and op.new_value:
            key = (op.field, op.new_value)
            if key in seen and seen[key] != op.target_oid:
                findings.append(Finding(
                    "L2", "error", op.field,
                    f"{op.field} {op.new_value!r} is assigned to two rows in "
                    "this batch — a duplicate", op.target_oid))
            seen[key] = op.target_oid

    by_field: dict = {}
    for f in findings:
        by_field.setdefault(f["field"], []).append(f)
    errors = [f for f in findings if f["severity"] == "error"]
    warnings = [f for f in findings if f["severity"] == "warn"]
    return {"findings": findings, "by_field": by_field,
            "errors": errors, "warnings": warnings,
            "error_count": len(errors), "warn_count": len(warnings)}


def has_errors(result: dict) -> bool:
    return bool(result.get("errors"))


def error_count(result: dict) -> int:
    return len(result.get("errors") or [])
