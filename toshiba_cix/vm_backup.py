"""Backup to JSON + mailbox-level diff — the no-call-interruption read path.

The native Backup/Restore Utility halts call processing and its serialization
is not yet captured (voicemail-map §5.5, §9). This module is the app's own
alternative: it reads every box, the system parameters and the dial-code/
integration table over **confirmed** opcodes **without stopping calls**, into a
plain JSON document, and diffs two of them per mailbox — decoded fields first,
with a **raw-bytes fallback** ("record changed, N bytes differ at offsets …")
so a changed security code is spotted before every flag offset is mapped. Read
only; this never writes to a card.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from . import __version__
from . import vm_records
from . import vm_sysparams
from . import vm_pbxdb

BACKUP_KIND = "stratagy-vm-json"
BACKUP_VERSION = 1


def read_model(link, *, progress=None) -> dict:
    """Read a full voicemail model over a :class:`~toshiba_cix.vm_link.VMLink`.

    ``progress(done, total, message)`` is called as boxes stream in (the
    determinate "Reading box N of M" bar). Returns decoded, JSON-ready data."""
    firmware = getattr(link, "firmware", "")
    admin_box = getattr(link, "admin_box", "")

    install_text = link.read_file("INSTALL.CFG").decode("latin-1", "replace")
    sysparams = vm_sysparams.parse_install_cfg(install_text)

    pbx_type = _param(sysparams, "pbx_type") or "CIX100S"
    pbxdb = {"pbx_name": "", "dial_codes": [], "integration": [],
             "model": pbx_type}
    try:
        pbx_text = link.read_file(f"C:\\Stratagy\\PBX.DB\\{pbx_type}.PBX").decode(
            "latin-1", "replace")
        if not pbx_text.strip():
            pbx_text = link.read_file(f"{pbx_type}.PBX").decode("latin-1", "replace")
        parsed = vm_pbxdb.parse_pbx(pbx_text)
        parsed["model"] = pbx_type
        pbxdb = parsed
    except Exception:  # noqa: BLE001 — a missing .PBX leaves the table empty
        pass

    directory = link.read_directory()
    boxes: Dict[str, dict] = {}
    total = len(directory)
    for i, box in enumerate(sorted(directory, key=lambda b: (len(b), b)), 1):
        if progress:
            progress(i, total, f"Reading box {box} ({i} of {total})")
        try:
            mb = vm_records.read_mailbox(link, box)
            if not mb.name:
                mb.name = directory[box]
            boxes[box] = mb.as_dict()
        except Exception as exc:  # noqa: BLE001 — record a read error, keep going
            boxes[box] = {"box": box, "name": directory.get(box, ""),
                          "error": str(exc)}
    return {"firmware": firmware, "admin_box": admin_box,
            "sysparams": sysparams, "pbxdb": pbxdb,
            "directory": directory, "boxes": boxes}


def build_json_backup(link, *, site: Optional[str] = None, progress=None) -> dict:
    """A full JSON backup document (meta + the read model)."""
    model = read_model(link, progress=progress)
    return {
        "meta": {
            "kind": BACKUP_KIND,
            "backup_version": BACKUP_VERSION,
            "tool_version": __version__,
            "taken_at": datetime.utcnow().isoformat() + "Z",
            "site": site,
            "firmware": model.get("firmware", ""),
            "box_count": len(model.get("boxes", {})),
            "note": "read over confirmed opcodes without interrupting calls",
        },
        **model,
    }


# -- mailbox-level diff -----------------------------------------------------
_DIFF_FIELDS = ["name", "extension", "comment", "security_code",
                "created", "modified"]


def _raw_byte_diff(a_hex: str, b_hex: str) -> Optional[dict]:
    """Where two raw segments differ, for the fallback line."""
    if not a_hex or not b_hex:
        return None
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    if a == b:
        return None
    offsets = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    if len(a) != len(b):
        offsets.append(min(len(a), len(b)))
    return {"bytes_differ": len(offsets),
            "offsets": offsets[:16],
            "len_a": len(a), "len_b": len(b)}


def diff_mailbox(a: dict, b: dict) -> dict:
    """Per-box diff: decoded field changes first, raw-bytes fallback second."""
    changes = []
    for f in _DIFF_FIELDS:
        av, bv = a.get(f), b.get(f)
        if av != bv:
            sensitive = f == "security_code"
            changes.append({
                "field": f,
                "old": "••••" if sensitive and av else av,
                "new": "••••" if sensitive and bv else bv,
                "sensitive": sensitive,
            })
    raw = {}
    for seg in ("raw_props_hex", "raw_ua_hex"):
        rd = _raw_byte_diff(a.get(seg, ""), b.get(seg, ""))
        if rd:
            raw[seg] = rd
    return {"changes": changes, "raw": raw,
            "changed": bool(changes or raw)}


def diff_backups(a: dict, b: dict) -> dict:
    """Diff two JSON backups (or two read models) at the mailbox level."""
    a_boxes = a.get("boxes", {})
    b_boxes = b.get("boxes", {})
    added = sorted(set(b_boxes) - set(a_boxes), key=lambda x: (len(x), x))
    removed = sorted(set(a_boxes) - set(b_boxes), key=lambda x: (len(x), x))
    changed = {}
    for box in sorted(set(a_boxes) & set(b_boxes), key=lambda x: (len(x), x)):
        d = diff_mailbox(a_boxes[box], b_boxes[box])
        if d["changed"]:
            changed[box] = d
    sys_a = {p["name"]: p["value"] for p in a.get("sysparams", {}).get("params", [])}
    sys_b = {p["name"]: p["value"] for p in b.get("sysparams", {}).get("params", [])}
    sys_changed = [{"name": n, "old": sys_a.get(n), "new": sys_b.get(n)}
                   for n in sorted(set(sys_a) | set(sys_b))
                   if sys_a.get(n) != sys_b.get(n)]
    return {"added": added, "removed": removed, "boxes": changed,
            "sysparams": sys_changed,
            "summary": {"boxes_added": len(added), "boxes_removed": len(removed),
                        "boxes_changed": len(changed),
                        "sysparams_changed": len(sys_changed)}}


def _param(sysparams: dict, name: str) -> Optional[str]:
    for p in sysparams.get("params", []):
        if p["name"] == name and p["enabled"]:
            return p["value"]
    return None


__all__ = ["read_model", "build_json_backup", "diff_backups", "diff_mailbox",
           "BACKUP_KIND", "BACKUP_VERSION"]
