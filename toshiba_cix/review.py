"""The three-way review that every write passes through (the one modal).

DESIGN_PLAN 5.5 and §9 layer 5: before anything is sent, each planned op is
rendered as *base → live → proposed*, with its wire type + proof, any conflict
(the device changed since the read), and a one-line blast radius (what else
holds the value being changed). This module is the pure assembly of that view;
the dialog renders it and the engine gates on it. No I/O here — the live
re-read is done by the caller (the session, which holds the client) and handed
in as ``live_rows``; in **Simulate** mode the caller passes the working copy as
``live_rows`` so the whole review is produced with no network at all.

``three_way`` also classifies the confirmation **tier** (layer 6) and lists the
**exclusions** (layer 7 — read-only / key / hard-exclusion / unproven
row-create), and ``inverse_plan`` builds the Undo changeset (layer 9).
"""

from __future__ import annotations

from .write import WriteOp, conflict_guard

__all__ = [
    "three_way", "inverse_plan", "blast_radius", "classify_tier",
    "DESTRUCTIVE_PROGRAMS",
]

# Programs whose edits are always tier 3 (destructive): block load / init /
# restart style operations and the whole *Delete family (DESIGN_PLAN §9 layer 6,
# tier default 3 for names containing Delete/Initialize/Restart/Lock).
DESTRUCTIVE_PROGRAMS = frozenset({"116", "118", "119", "150", "916"})


def _rows_by_oid(rows) -> dict:
    """Map every cell OID in ``rows`` to its decoded display value."""
    out: dict = {}
    for r in rows or []:
        for c in r.get("cells") or []:
            if c.get("oid"):
                dv = c.get("display_value")
                if (dv is None or dv == "") and c.get("raw_value") is not None:
                    dv = str(c.get("raw_value"))
                out[c["oid"]] = dv
    return out


def blast_radius(op: WriteOp, index=None) -> dict:
    """How many other rows reference the value this op is changing.

    Uses the value index (``index.py``) — the same where-used mechanism behind
    the "used by 14 stations" chip. ``index`` may be ``None`` (no snapshot
    loaded), in which case the blast radius is simply unknown. Pure."""
    if index is None or op.old_value in (None, ""):
        return {"affects": None, "note": ""}
    try:
        occ = index.references_to(op.old_value)
    except Exception:  # noqa: BLE001 — a missing reference map is not fatal
        occ = []
    # Don't count the row being edited itself.
    others = [o for o in occ if o.get("field") != op.field]
    n = len(others)
    if not n:
        return {"affects": 0, "note": ""}
    kinds = sorted({o.get("ref_kind") or "row" for o in others})
    return {"affects": n, "note": f"referenced by {n} other "
            + ("place" if n == 1 else "places")
            + (f" ({', '.join(kinds)})" if kinds else "")}


def classify_tier(ops, *, danger: bool = False, transport: str | None = None,
                  programs_meta: dict | None = None) -> dict:
    """The confirmation tier for a changeset (DESIGN_PLAN §9 layer 6).

    * Tier 3 (destructive): any row-create, any op in a destructive program, a
      program flagged danger, or > 200 fields.
    * Tier 2 (wide / disruptive): 21–200 fields, a remote write, or ``danger``.
    * Tier 1 (ordinary): everything else.

    Returns ``{tier, reasons, needs_typed_name}``. Tiers 2 and 3 require the
    operator to type the site name to confirm."""
    programs_meta = programs_meta or {}
    sendable = [op for op in ops
                if getattr(op, "sendable", False)
                and getattr(op, "op_class", "data") != "commit"]
    n = len(sendable)
    reasons: list[str] = []
    tier = 1
    remote = transport in ("overlay", "agent", "remote")

    row_create = any(getattr(op, "row_create", False) for op in sendable)
    destructive_prog = any(
        (op.program in DESTRUCTIVE_PROGRAMS)
        or (programs_meta.get(op.program, {}).get("tier") == 3)
        for op in sendable)
    danger_prog = danger or any(
        programs_meta.get(op.program, {}).get("danger") for op in sendable)

    if row_create or destructive_prog or n > 200:
        tier = 3
        if row_create:
            reasons.append("adds a new row (row-create is unproven)")
        if destructive_prog:
            reasons.append("touches a destructive program")
        if n > 200:
            reasons.append(f"{n} fields")
    elif n > 20 or remote or danger_prog:
        tier = 2
        if n > 20:
            reasons.append(f"{n} fields")
        if remote:
            reasons.append("remote write")
        if danger_prog:
            reasons.append("danger program")
    return {"tier": tier, "reasons": reasons, "needs_typed_name": tier >= 2}


def three_way(ops, base_rows=None, live_rows=None, *, index=None,
              labels: dict | None = None, transport: str | None = None,
              programs_meta: dict | None = None, simulate: bool = False) -> dict:
    """Assemble the review for ``ops`` (DESIGN_PLAN 5.5). Pure.

    ``base_rows`` / ``live_rows`` are enriched ``<row>`` lists; ``live_rows`` is
    the fresh re-read (or, in Simulate / when omitted, the base itself, so no
    network is implied). ``labels`` maps a field name to ``{display_no, label}``
    from the UI schema. ``index`` is an optional value index for blast radius.
    """
    labels = labels or {}
    live_by_oid = _rows_by_oid(live_rows if live_rows is not None else base_rows)
    base_by_oid = _rows_by_oid(base_rows)

    conflicts = conflict_guard(ops, live_by_oid) if not simulate else []
    conflict_oids = {c["oid"]: c for c in conflicts}

    rows: list[dict] = []
    will_send = 0
    excluded: list[dict] = []
    for op in ops:
        label = labels.get(op.field, {})
        live_val = live_by_oid.get(op.target_oid, op.old_value)
        base_val = base_by_oid.get(op.target_oid, op.old_value)
        conflict = conflict_oids.get(op.target_oid)
        blast = blast_radius(op, index) if op.sendable else {"affects": None, "note": ""}
        # Default-exclude a conflicting op (layer 3: keep live) and anything
        # whose wire type is unproven INTEGER until the operator opts in.
        excluded_now = bool(conflict)
        exclude_reason = ""
        if not op.sendable:
            excluded_now = True
            exclude_reason = op.note or "not sendable"
        elif conflict:
            exclude_reason = "live value changed since the read — keeping live"
        row = {
            "field": op.field,
            "label": label.get("label") or op.label,
            "display_no": label.get("display_no"),
            "program": op.program,
            "op_class": op.op_class,
            "base": base_val,
            "live": live_val,
            "proposed": op.new_value,
            "wire": op.ber_type,
            "native_wire": op.native_wire,
            "wire_proven": op.wire_proven,
            "proof": "proven" if op.wire_proven else "catalog-derived",
            "sendable": op.sendable,
            "note": op.note,
            "conflict": conflict,
            "blast": blast,
            "excluded": excluded_now,
            "exclude_reason": exclude_reason,
        }
        rows.append(row)
        if op.sendable and not excluded_now:
            will_send += 1
        elif not op.sendable:
            excluded.append({"field": op.field, "reason": op.note})

    read_only = [r for r in rows if not r["sendable"]]
    unproven = [r for r in rows if r["sendable"] and not r["wire_proven"]]
    tier = classify_tier(ops, transport=transport, programs_meta=programs_meta)

    affected_programs = sorted({str(op.program) for op in ops
                                if op.sendable and op.program})
    summary = {
        "will_send": will_send,
        "skip_conflict": len(conflicts),
        "skip_unproven_wire": len(unproven),
        "read_only": len(read_only),
        "total": len(rows),
        "programs": affected_programs,
        "affects_line": (
            f"Will send {will_send} "
            + ("change" if will_send == 1 else "changes")
            + (f", skip {len(conflicts)} conflicting" if conflicts else "")
            + (f", {len(read_only)} read-only" if read_only else "")),
    }
    return {
        "rows": rows,
        "summary": summary,
        "conflicts": conflicts,
        "exclusions": excluded,
        "tier": tier["tier"],
        "tier_reasons": tier["reasons"],
        "needs_typed_name": tier["needs_typed_name"],
        "simulate": simulate,
    }


def inverse_plan(ops) -> list:
    """The Undo changeset for a set of applied ops (DESIGN_PLAN §9 layer 9):
    the inverse of every sendable data op, in reverse order. The commit op is
    not inverted — Undo is itself a new write that ends with its own commit."""
    out = [op.inverse() for op in reversed(list(ops))
           if getattr(op, "sendable", False) and getattr(op, "op_class", "data") != "commit"]
    return out
