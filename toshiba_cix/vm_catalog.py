"""The Stratagy mailbox field catalog (``data/stratagy_vm_catalog.json``).

The VM twin of the eManager program catalog: tab, label, tooltip, type, range,
wire location and **status** (`confirmed | inferred | unknown`). It drives the
read-only User Editor (status dots and inline help) and the write gate.

The one invariant (DESIGN_PLAN §8.4, voicemail-map §10): a field is editable
only when its status is ``confirmed`` **and** VM writes are enabled. P1 ships
read-only, so :func:`field_writable` returns ``False`` for everything until the
write path lands (P3); :func:`validate` proves no non-confirmed field could ever
present a writable control.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .vm_data import load_vm_data_text

# P1 master switch: voicemail writes are OFF until the supervised lab write
# (DESIGN_PLAN §11 P3, voicemail-map §6.4). Nothing in P1 flips this.
VM_WRITES_ENABLED = False

_CACHE: Optional[dict] = None


def load_vm_catalog() -> dict:
    """Load + index the catalog: ``{tabs, fields, by_name, by_tab}``."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    text = load_vm_data_text("stratagy_vm_catalog.json", "EMBEDDED_VM_CATALOG_JSON")
    data = json.loads(text) if text else {"tabs": [], "fields": []}
    fields = data.get("fields", [])
    by_name = {f["name"]: f for f in fields}
    by_tab: Dict[str, List[dict]] = {}
    for f in fields:
        by_tab.setdefault(f.get("tab", ""), []).append(f)
    _CACHE = {"tabs": data.get("tabs", list(by_tab.keys())),
              "fields": fields, "by_name": by_name, "by_tab": by_tab,
              "meta": data.get("_meta", {})}
    return _CACHE


def field_writable(field: dict, writes_enabled: bool = VM_WRITES_ENABLED) -> bool:
    """A field may be edited only if confirmed AND writes are globally on."""
    return bool(writes_enabled) and field.get("status") == "confirmed"


def status_dot(field: dict) -> str:
    """green (confirmed) | amber (inferred) | grey (unknown) — the editor dot."""
    return {"confirmed": "green", "inferred": "amber"}.get(
        field.get("status"), "grey")


def validate(catalog: Optional[dict] = None) -> List[str]:
    """Return catalog errors (empty = valid). Mirrors the design's test:

    every field has tab/label/type/status, and no non-``confirmed`` field is
    marked writable (it cannot present an editable control)."""
    cat = catalog or load_vm_catalog()
    errors: List[str] = []
    for f in cat.get("fields", []):
        for key in ("name", "tab", "label", "type", "status"):
            if not f.get(key):
                errors.append(f"field {f.get('name', '?')!r} missing {key}")
        if f.get("status") not in ("confirmed", "inferred", "unknown"):
            errors.append(f"field {f.get('name')!r} bad status {f.get('status')!r}")
        # the safety invariant: never writable unless confirmed
        if field_writable(f, writes_enabled=True) and f.get("status") != "confirmed":
            errors.append(f"field {f.get('name')!r} writable but not confirmed")
    return errors


def editor_model(writes_enabled: bool = VM_WRITES_ENABLED) -> dict:
    """The catalog shaped for the editor: tabs, each with its fields + dots."""
    cat = load_vm_catalog()
    tabs = []
    for tab in cat["tabs"]:
        fields = []
        for f in cat["by_tab"].get(tab, []):
            fields.append({**f, "dot": status_dot(f),
                           "writable": field_writable(f, writes_enabled)})
        tabs.append({"tab": tab, "fields": fields})
    return {"tabs": tabs, "writes_enabled": writes_enabled,
            "meta": cat.get("meta", {})}


__all__ = ["VM_WRITES_ENABLED", "load_vm_catalog", "field_writable",
           "status_dot", "validate", "editor_model"]
