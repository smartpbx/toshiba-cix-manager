"""Deterministic label derivation for the generated UI schema (build-time only).

Switchroom renders eManager's own wording, never a bare OID or a raw MOF
symbol. The field→OID catalog and the reverse-engineered enum maps store the
vendor's machine symbols (``notAllowed``, ``dKT``, ``time80msec``); this module
turns each into a stable human caption with **one** deterministic function so
the engine and the UI can never disagree, and so a rebuild of
``ui_schema.json`` is byte-reproducible (the Web-UI-style freshness check in
CI depends on it).

It is pure and import-free of the package: it runs under ``tools/`` at build
time, next to :mod:`build_ui_schema`, and never ships in the lean stdlib
reader / AppImage / exe. All wording that a mechanical transform gets wrong is
corrected in ``enum_label_overrides.json`` rather than by special-casing here,
so the rules below stay small and testable.

The three public helpers:

* :func:`title_case_symbol` — a MOF enum symbol → caption
  (``dKT`` → ``DKT``, ``notAllowed`` → ``Not Allowed``, ``time80msec`` →
  ``80 ms``).
* :func:`humanize_name` — a camelCase catalog field/program name → a title
  (``stationStationName`` → ``Station Station Name``).
* :func:`enum_caption` — the override-aware wrapper the schema builder calls
  for an enum value.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# camelCase / acronym splitting (shared by symbols and field names)
# --------------------------------------------------------------------------
# Three boundaries, applied in order, cover every shape the MOF uses:
#   * lower/digit → Upper          stationName      -> station Name
#   * Upper       → Upper+lower     ANIAndDNIS       -> ANI And DNIS
#   * letter      → digit           bchannel2        -> bchannel 2
_B_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_B_ACRONYM = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_B_DIGIT = re.compile(r"(?<=[A-Za-z])(?=[0-9])")

# Known acronyms/initialisms that must stay fully capitalised when they appear
# as a stand-alone token after splitting. Everything else title-cases normally.
_ACRONYMS = frozenset({
    "DN", "DID", "DNIS", "ANI", "DKT", "DTMF", "DP", "CO", "COS", "DRL", "DR",
    "LCR", "PRI", "BRI", "ISDN", "IP", "IPU", "VM", "VMID", "PDN", "PBX",
    "SIP", "DSS", "MOH", "RBT", "SMDR", "T1", "VLAN", "FTP", "SNMP", "URL",
    "ILG", "OLG", "TEI", "CPN", "DID", "AMIS", "ACD", "QoS", "MAC", "DB",
    "DISA", "OPX", "CLASS", "LOOP", "DIT", "FX", "DDCB", "ESF", "ADM",
    "BIOU", "BIPU", "LIPU", "MIPU", "GIPU", "SM", "SD", "PAD", "DNS",
})

# Numeric-unit patterns the vendor bakes into a single symbol. Handled before
# the general splitter because "80 ms" is not a camelCase transform.
_UNIT_PATTERNS = (
    (re.compile(r"^time(\d+)msec$"), lambda m: f"{m.group(1)} ms"),
    (re.compile(r"^time(\d+)ms$"), lambda m: f"{m.group(1)} ms"),
    (re.compile(r"^time(\d+)sec$"), lambda m: f"{m.group(1)} s"),
    (re.compile(r"^time(\d+)min$"), lambda m: f"{m.group(1)} min"),
    (re.compile(r"^interval(\d+)ms$"), lambda m: f"{m.group(1)} ms"),
    (re.compile(r"^detect(\d+)ms$"), lambda m: f"Detect {m.group(1)} ms"),
    (re.compile(r"^echoCancel(\d+)ms$"), lambda m: f"Echo Cancel {m.group(1)} ms"),
    (re.compile(r"^minus(\d+)DB$"), lambda m: f"-{m.group(1)} dB"),
    (re.compile(r"^plus(\d+)DB$"), lambda m: f"+{m.group(1)} dB"),
)


def _split_words(s: str) -> list[str]:
    s = _B_CAMEL.sub(" ", s)
    s = _B_ACRONYM.sub(" ", s)
    s = _B_DIGIT.sub(" ", s)
    # Hyphen / underscore are word separators too (non-workingDay, no_data).
    s = s.replace("-", " ").replace("_", " ")
    return [w for w in s.split() if w]


def _cap_token(tok: str) -> str:
    up = tok.upper()
    if up in _ACRONYMS:
        return up
    if tok.isupper() and len(tok) > 1:
        # An all-caps run the splitter left intact (e.g. "DKT") stays caps.
        return tok
    if tok.isdigit():
        return tok
    return tok[:1].upper() + tok[1:]


def title_case_symbol(symbol: str) -> str:
    """A MOF enum symbol → a human caption, deterministically.

    ``dKT`` → ``DKT`` (leading char restored, all-caps run kept),
    ``notAllowed`` → ``Not Allowed``, ``time80msec`` → ``80 ms``,
    ``enable`` → ``Enable``. Unknown shapes degrade to a camelCase split.
    """
    if not symbol:
        return ""
    sym = symbol.strip()
    if not sym:
        return ""
    for pat, repl in _UNIT_PATTERNS:
        m = pat.match(sym)
        if m:
            return repl(m)
    # The MOF forces the first letter of every symbol lowercase; restore it so
    # a leading acronym ("dKT", "oFF", "iP-VM") is recognised by the splitter.
    sym = sym[:1].upper() + sym[1:]
    words = _split_words(sym)
    if not words:
        return symbol
    return " ".join(_cap_token(w) for w in words)


def humanize_name(name: str) -> str:
    """A camelCase catalog field/program name → a readable title.

    ``stationStationName`` → ``Station Station Name``; ``trunkNo`` →
    ``Trunk No``. Used as the fallback label when no native title is known.
    """
    if not name:
        return ""
    words = _split_words(name)
    if not words:
        return name
    return " ".join(_cap_token(w) for w in words)


def enum_caption(symbol: str, *, overrides: dict | None = None) -> str:
    """Caption for an enum value: an override wins, else the deterministic cast.

    ``overrides`` is the ``enum_label_overrides.json`` ``symbol → caption`` map
    (global symbol overrides), applied before the mechanical transform so a
    value the transform gets wrong (``oFF`` → ``Off``) is fixed in data.
    """
    if overrides and symbol in overrides:
        return overrides[symbol]
    return title_case_symbol(symbol)


__all__ = ["title_case_symbol", "humanize_name", "enum_caption"]
