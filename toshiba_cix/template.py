"""Templates: backup subsets with identity/secrets/ports stripped (DESIGN_PLAN
§7.6). A row template is a readable snapshot of one row's writable fields with
the row's own key bound to ``$dn`` — "Standard DKT user" as a file, not a hidden
StationCopyTemplate. Applying one materialises against a live key and goes
through the normal three-way review; *compare with template* is drift.

Pure stdlib, no I/O. The library ships empty; these are the capture / apply /
drift primitives the routes and the Add-Station wizard's Template step use.
"""

from __future__ import annotations

import re

__all__ = [
    "capture_row_template", "capture_program_set", "capture_system",
    "capture_phone_profile", "apply_row_template", "template_drift",
    "drift_badge", "STRIP_FIELD_RE",
]

# Field names never carried in a template (identity / secret / physical): a
# template is portable across sites, so a MAC, serial, port, IP or password is
# meaningless (and unsafe) in it.
STRIP_FIELD_RE = re.compile(
    r"(mac|serial|equipment|_port$|^port$|ip_?addr|ipaddr|address|"
    r"password|passcode|secur|secret|pin|token|key_?code)", re.I)


def _cell_val(cell) -> str:
    dv = cell.get("display_value")
    if (dv is None or dv == "") and cell.get("raw_value") is not None:
        return str(cell.get("raw_value"))
    return "" if dv is None else str(dv)


def _is_stripped(cell) -> bool:
    name = cell.get("field_name") or ""
    if cell.get("is_secret"):
        return True
    return bool(STRIP_FIELD_RE.search(name))


def _row_in(view, index):
    for r in view.get("rows") or []:
        if str(r.get("index")) == str(index):
            return r
    return None


def capture_row_template(view: dict, index, *, name: str = "",
                         program_key: str | None = None) -> dict:
    """Capture one row as a row template. Identity/secret/port fields are
    dropped; wherever a field's value equals the row key it is bound to
    ``$dn`` so the template re-targets on apply. ``view`` is a program view."""
    row = _row_in(view, index)
    if row is None:
        raise KeyError(f"no row {index!r} in this program")
    key = str(row.get("key") or row.get("index"))
    fields: dict = {}
    stripped: list = []
    for cell in row.get("cells") or []:
        fname = cell.get("field_name")
        if cell.get("access") == "r":
            continue  # read-only — not part of a writable template
        if _is_stripped(cell):
            stripped.append(fname)
            continue
        val = _cell_val(cell)
        fields[fname] = "$dn" if val == key and key else val
    return {
        "kind": "row",
        "program_key": program_key or view.get("catalog_key"),
        "program_number": view.get("program_number"),
        "name": name or f"{view.get('label') or view.get('catalog_key')} row {key}",
        "bindings": ["dn"],
        "stripped": stripped,
        "fields": fields,
    }


def _programs_list(program_views) -> list:
    return (program_views.get("programs")
            if isinstance(program_views, dict) else program_views) or []


def _capture_program_rows(pv) -> list:
    """Every row of one program view as ``{index, key, fields}`` with read-only
    and identity/secret/port fields stripped (the shared body of the program-set
    and system captures)."""
    rows = []
    for r in pv.get("rows") or []:
        fields = {}
        for cell in r.get("cells") or []:
            if cell.get("access") == "r" or _is_stripped(cell):
                continue
            fields[cell.get("field_name")] = _cell_val(cell)
        rows.append({"index": r.get("index"), "key": r.get("key"),
                     "fields": fields})
    return rows


def capture_program_set(program_views, program_keys, *, name: str = "") -> dict:
    """Capture several whole programs as a program-set template ("HQ COS
    table"). Each row keeps its writable, non-identity fields."""
    wanted = set(program_keys)
    out: dict = {}
    for pv in _programs_list(program_views):
        if pv.get("catalog_key") not in wanted and str(pv.get("program_number")) not in wanted:
            continue
        out[pv.get("catalog_key")] = _capture_program_rows(pv)
    return {"kind": "program_set", "name": name or "program set",
            "programs": out}


def capture_system(program_views, *, name: str = "", exclude=None) -> dict:
    """Capture the whole switch as a *system template* (DESIGN_PLAN §7.6): every
    program's writable, non-identity rows. Identity/secret/port fields are
    stripped like any template, so the result is a portable programming baseline
    — system/trunk options, COS and numbering tables — a new install can be
    seeded from and an existing one compared against. ``exclude`` drops programs
    by catalog key or program number (e.g. per-site station assignment)."""
    drop = {str(x) for x in (exclude or [])}
    out: dict = {}
    for pv in _programs_list(program_views):
        key = pv.get("catalog_key")
        if key in drop or str(pv.get("program_number")) in drop:
            continue
        rows = _capture_program_rows(pv)
        if rows:
            out[key] = rows
    return {"kind": "system", "name": name or "system template",
            "programs": out, "program_count": len(out)}


def capture_phone_profile(view: dict, index, *, name: str = "",
                          profile: str = "") -> dict:
    """Capture one station row as a named *phone profile* — the "Standard DKT
    user" the Add-Station wizard offers from a dropdown (DESIGN_PLAN §7.6, P4).
    A phone profile is a row template carrying a profile label: identity, secret
    and port fields are stripped and the extension is bound to ``$dn`` so the
    profile re-targets onto any new station. ``template_drift`` / ``drift_badge``
    against it is the record pane's drift badge."""
    t = capture_row_template(view, index, name=name)
    t["kind"] = "phone_profile"
    t["profile"] = profile or name or t["name"]
    return t


def apply_row_template(template: dict, target_index, bindings: dict) -> dict:
    """Materialise a row template into a ``{field: value}`` changes map for the
    target row. ``$dn`` (and any ``$binding``) is substituted from ``bindings``.
    The result feeds ``plan_row_update`` → the three-way review, so applying a
    template is never a special write path."""
    out: dict = {}
    for field, value in (template.get("fields") or {}).items():
        v = value
        if isinstance(v, str) and v.startswith("$"):
            v = bindings.get(v[1:], v)
        out[field] = "" if v is None else str(v)
    return out


def template_drift(template: dict, row: dict, bindings: dict | None = None) -> list:
    """Fields where ``row`` differs from what ``template`` would set — "Compare
    with template". Returns ``[{field, template, live}]``. ``$`` bindings are
    resolved first so the key field is not a false positive."""
    bindings = bindings or {}
    by_name = {c.get("field_name"): _cell_val(c) for c in (row.get("cells") or [])}
    drift: list = []
    for field, value in (template.get("fields") or {}).items():
        want = value
        if isinstance(want, str) and want.startswith("$"):
            want = bindings.get(want[1:], want)
        want = "" if want is None else str(want)
        live = by_name.get(field)
        if live is not None and live != want:
            drift.append({"field": field, "template": want, "live": live})
    return drift


def drift_badge(template: dict, row: dict, bindings: dict | None = None) -> dict:
    """The drift-badge summary the record pane shows for a row against its
    template / phone profile: ``{count, clean, fields}``. ``clean`` is True when
    the row matches (no badge); ``fields`` is the drift detail for the hover."""
    fields = template_drift(template, row, bindings)
    return {"count": len(fields), "clean": not fields, "fields": fields}
