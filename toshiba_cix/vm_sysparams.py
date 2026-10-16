"""INSTALL.CFG — Stratagy system parameters (read, decode, serialise).

The ``set <name> <value>`` / ``#set …`` lines come back as **confirmed**
plaintext (voicemail-map §2.9). This module parses them into the three-column
grid the old window shows — *Parameter Names | Values | Parameter Descriptions*
— preserving order, ``#``-disabled rows (shown as an "enabled" toggle) and the
``#- …`` group headings, joins each to its ``Install.dhp`` help entry, decodes
the shutdown schedule, and flags the cleartext default password. It can also
serialise the grid back to a byte-identical file for the (P3, gated) write path;
nothing here writes to the card.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from .vm_data import load_vm_data_text

_SET_RE = re.compile(r"^(#)?\s*set\s+(\w+)\s*(.*?)\s*$")
_GROUP_RE = re.compile(r"^#-\s*(.*?)\s*$")
_DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
         "Saturday"]

_HELP_CACHE: Optional[dict] = None


def _help() -> dict:
    global _HELP_CACHE
    if _HELP_CACHE is None:
        text = load_vm_data_text("stratagy_sysparams_help.json",
                                 "EMBEDDED_VM_SYSPARAMS_HELP_JSON")
        try:
            _HELP_CACHE = (json.loads(text).get("params", {})) if text else {}
        except (ValueError, AttributeError):
            _HELP_CACHE = {}
    return _HELP_CACHE


def _unquote(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def decode_shutdown(value: str) -> str:
    """'2 130' -> 'weekly, Tuesday 01:30' (day 0=Sunday, time HHMM)."""
    v = _unquote(value).split()
    if len(v) != 2 or not v[0].isdigit() or not v[1].isdigit():
        return value
    day = int(v[0])
    hhmm = v[1].zfill(4)
    day_name = _DAYS[day] if 0 <= day < 7 else f"day {day}"
    return f"weekly, {day_name} {hhmm[:2]}:{hhmm[2:]}"


def parse_install_cfg(text: str) -> dict:
    """Parse INSTALL.CFG into an ordered parameter grid + findings."""
    params: List[dict] = []
    groups: List[str] = []
    current_group = ""
    findings: List[dict] = []
    help_map = _help()

    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if not line:
            continue
        gm = _GROUP_RE.match(line)
        if gm and "set " not in line:
            current_group = gm.group(1)
            if current_group and current_group not in groups:
                groups.append(current_group)
            continue
        m = _SET_RE.match(line)
        if not m:
            continue
        disabled = bool(m.group(1))
        name = m.group(2)
        value = m.group(3)
        help_entry = help_map.get(name, {})
        params.append({
            "name": name,
            "value": _unquote(value),
            "raw_value": value,
            "enabled": not disabled,
            "group": current_group,
            "description": help_entry.get("description", ""),
            "possible": help_entry.get("possible", ""),
            "default": help_entry.get("default", ""),
            "decoded": decode_shutdown(value) if name == "shutdown" else None,
        })

    # security finding: cleartext default password left at the shipped value
    for p in params:
        if p["name"] == "password" and p["enabled"] and p["value"] == "Stratagy":
            findings.append({
                "severity": "high",
                "param": "password",
                "message": "System password is the shipped default 'Stratagy' "
                           "(stored in cleartext in INSTALL.CFG).",
            })

    return {"params": params, "groups": groups, "findings": findings,
            "help_status": "partial"}


def render_install_cfg(parsed: dict) -> str:
    """Serialise a parsed grid back to INSTALL.CFG text (P3 write path, gated).

    Preserves order, the `#`-disabled prefix and group headings; re-quotes a
    value that contains spaces, as the file does."""
    out: List[str] = []
    seen_groups = set()
    for p in parsed.get("params", []):
        group = p.get("group")
        if group and group not in seen_groups:
            seen_groups.add(group)
            out.append(f"#- {group}")
        value = p.get("raw_value")
        if value is None:
            v = p.get("value", "")
            value = f"'{v}'" if (" " in v) else v
        prefix = "" if p.get("enabled", True) else "#"
        out.append(f"{prefix}set {p['name']} {value}".rstrip())
    return "\r\n".join(out) + "\r\n"


def sysparams_from_blob(blob_text: str) -> dict:
    """Convenience: parse the `set` lines out of a reassembled content blob."""
    return parse_install_cfg(blob_text)


__all__ = ["parse_install_cfg", "render_install_cfg", "decode_shutdown",
           "sysparams_from_blob"]
