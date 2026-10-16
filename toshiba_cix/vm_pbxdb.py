"""`<pbx_type>.PBX` — dial codes + SMDI integration patterns (read + compare).

The live ``C:\\Stratagy\\PBX.DB\\<model>.PBX`` comes back as **confirmed**
plaintext (voicemail-map §2.9): ``dl_*`` dial codes (value in Token language,
label after ``#``), ``pbx_name`` and ``integration NN '…'`` SMDI/in-band
pattern templates. :func:`compare_with_default` diffs the live file against the
bundled vendor template for the model — the Plug-and-Play menu's value shown as
a diff, never a rewrite. Read-only; nothing here writes to the card.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from .vm_data import load_vm_data_text

_DL_RE = re.compile(r"^(dl_\w+)\s*([^#\r\n]*?)\s*(?:#\s*(.*?))?\s*$")
_INT_RE = re.compile(r"^integration\s+(\d+)\s+'([^']*)'")
_NAME_RE = re.compile(r"^pbx_name\s+'([^']*)'")

_DEFAULTS_CACHE: Optional[dict] = None


def _defaults() -> dict:
    global _DEFAULTS_CACHE
    if _DEFAULTS_CACHE is None:
        text = load_vm_data_text("stratagy_pbx_defaults.json",
                                 "EMBEDDED_VM_PBX_DEFAULTS_JSON")
        try:
            _DEFAULTS_CACHE = (json.loads(text).get("models", {})) if text else {}
        except (ValueError, AttributeError):
            _DEFAULTS_CACHE = {}
    return _DEFAULTS_CACHE


def parse_pbx(text: str) -> dict:
    """Parse a .PBX file into ``{pbx_name, dial_codes[], integration[]}``."""
    pbx_name = ""
    dial_codes: List[dict] = []
    integration: List[dict] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if not line:
            continue
        nm = _NAME_RE.match(line)
        if nm:
            pbx_name = nm.group(1)
            continue
        im = _INT_RE.match(line)
        if im:
            integration.append({"index": im.group(1), "pattern": im.group(2)})
            continue
        dm = _DL_RE.match(line)
        if dm and line.startswith("dl_"):
            dial_codes.append({
                "code": dm.group(1),
                "value": (dm.group(2) or "").strip(),
                "label": (dm.group(3) or "").strip().rstrip(":"),
            })
    return {"pbx_name": pbx_name, "dial_codes": dial_codes,
            "integration": integration}


def default_for(model: str) -> Optional[dict]:
    """The bundled vendor template for ``model``, parsed — or ``None``."""
    text = _defaults().get((model or "").strip())
    if text is None:
        # tolerate case / trailing-S variants
        for k, v in _defaults().items():
            if k.lower() == (model or "").strip().lower():
                text = v
                break
    return parse_pbx(text) if text is not None else None


def compare_with_default(live: dict, model: str) -> dict:
    """Diff a parsed live .PBX against the bundled model default.

    Returns per-section changes; ``available`` is False (with a reason) when no
    default is bundled for the model, so the UI says so rather than implying
    a clean match."""
    default = default_for(model)
    if default is None:
        return {"available": False,
                "reason": f"No bundled Toshiba default for model {model!r} yet.",
                "dial_codes": [], "integration": []}

    dl_changes = []
    live_dl = {d["code"]: d for d in live.get("dial_codes", [])}
    def_dl = {d["code"]: d for d in default.get("dial_codes", [])}
    for code in sorted(set(live_dl) | set(def_dl)):
        lv = (live_dl.get(code) or {}).get("value", "")
        dv = (def_dl.get(code) or {}).get("value", "")
        if code not in live_dl:
            dl_changes.append({"code": code, "kind": "removed",
                               "default": dv, "live": None})
        elif code not in def_dl:
            dl_changes.append({"code": code, "kind": "added",
                               "default": None, "live": lv})
        elif lv != dv:
            dl_changes.append({"code": code, "kind": "changed",
                               "default": dv, "live": lv,
                               "label": live_dl[code].get("label", "")})

    live_int = [i["pattern"] for i in live.get("integration", [])]
    def_int = [i["pattern"] for i in default.get("integration", [])]
    int_changes = []
    for p in live_int:
        if p not in def_int:
            int_changes.append({"pattern": p, "kind": "added"})
    for p in def_int:
        if p not in live_int:
            int_changes.append({"pattern": p, "kind": "removed"})

    return {"available": True, "model": model,
            "default_name": default.get("pbx_name", ""),
            "dial_codes": dl_changes, "integration": int_changes,
            "clean": not dl_changes and not int_changes}


def pbxdb_from_blob(blob_text: str) -> dict:
    """Parse the dial-code / integration lines out of a content blob."""
    return parse_pbx(blob_text)


__all__ = ["parse_pbx", "default_for", "compare_with_default", "pbxdb_from_blob"]
