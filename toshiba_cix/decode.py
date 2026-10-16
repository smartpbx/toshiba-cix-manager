"""Decoders for Toshiba Strata CIX enterprise-MIB values and OID row keys.

Two jobs:

1. **Value decoding.** On the wire every programming field is an
   ``OCTET STRING`` whose bytes happen to be printable ASCII — usually a
   decimal-digit string (``b"010101"`` for an equipment port, ``b"200"``
   for an extension), sometimes a word (``b"sysadmin"``). A few scalars are
   raw binary (the 6-byte chassis MAC). :func:`decode_value` renders each
   as the right Python type: printable bytes → ``str``; the MAC → colon
   hex; anything else → hex, so nothing is ever silently dropped.

2. **Row-key decoding.** Table instance OIDs encode the directory
   number / extension as a *length-prefixed* run of ASCII sub-identifiers
   in the OID tail — ``...3.50.48.48`` is ``len=3`` then ``50,48,48`` =
   ``"200"``. Some tables wrap that key with a leading row-sequence number
   (Program 1200) and/or trailing sub-indices (key/button number in
   Program 205). :func:`parse_row_index` finds the length-prefixed DN
   wherever it sits and reports the surrounding indices, without needing a
   per-program schema.

The field map in :data:`PROGRAMS` / :data:`SYSTEM_SCALARS` is what the
2026-10-14 eManager packet capture proves out
(``an on-site SNMP capture``). Everything the capture
does *not* explain is preserved verbatim as raw passthrough by the reader,
never discarded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .snmp import Value

# Toshiba enterprise MIB root (186 = Toshiba, .1.22 = Strata CIX).
ENTERPRISE_ROOT = "1.3.6.1.4.1.186.1.22"

MISSING = "<MISSING>"


def decode_value(value: Value, *, as_mac: bool = False) -> object:
    """Render an SNMP :class:`Value` as a Python scalar for the JSON output.

    * integers  → ``int``
    * absent    → :data:`MISSING` sentinel string (keeps batch columns aligned)
    * octets    → ``str`` if every byte is printable ASCII, else hex;
                  ``as_mac`` forces colon-hex MAC formatting for the one
                  scalar (chassis MAC) that is genuinely binary.
    """
    if value.kind == "int":
        return value.int_value
    if value.is_missing:
        return MISSING
    if value.kind == "endofmib":
        return MISSING
    if value.kind == "oid":
        from .snmp import decode_oid
        return "OID " + decode_oid(value.raw)
    if value.kind == "octet":
        raw = value.raw
        if as_mac:
            return ":".join(f"{b:02x}" for b in raw)
        return decode_octet(raw)
    # Unknown application type — preserve as hex so it is never lost.
    return value.raw.hex() if value.raw else MISSING


def decode_octet(raw: bytes) -> str:
    """Octet string → text when printable, else hex. Trailing NULs trimmed."""
    if raw == b"":
        return ""
    trimmed = raw.rstrip(b"\x00")
    if trimmed and all(0x20 <= b <= 0x7E for b in trimmed):
        return trimmed.decode("ascii")
    return raw.hex()


def looks_like_port(text: object) -> bool:
    """A Toshiba equipment/port id is 6 decimal digits (cabinet/slot/circuit)."""
    return isinstance(text, str) and len(text) == 6 and text.isdigit()


def format_port(text: str) -> str:
    """``"010203"`` → ``"01-02-03"`` (cabinet-slot-circuit) for the report."""
    if looks_like_port(text):
        return f"{text[0:2]}-{text[2:4]}-{text[4:6]}"
    return text


@dataclass
class RowIndex:
    """Decoded instance index of a table OID.

    ``dn`` is the extension / directory-number string (the human key).
    ``prefix`` are sub-ids before the length-prefixed DN (e.g. the Program
    1200 row-sequence number); ``suffix`` are sub-ids after it (e.g. a
    Program 205 key/button number). ``raw`` is the full numeric tail.
    """

    dn: str | None
    prefix: tuple[int, ...] = ()
    suffix: tuple[int, ...] = ()
    raw: tuple[int, ...] = ()

    @property
    def key(self) -> str:
        """A stable, human-ish key for grouping rows in the output."""
        parts: list[str] = []
        if self.prefix:
            parts.append("seq" + "-".join(str(p) for p in self.prefix))
        parts.append(self.dn if self.dn is not None else "idx"
                     + "-".join(str(r) for r in self.raw))
        if self.suffix:
            parts.append("k" + "-".join(str(s) for s in self.suffix))
        return "/".join(parts)


def parse_row_index(tail: tuple[int, ...]) -> RowIndex:
    """Find the length-prefixed ASCII DN inside an instance tail.

    Scans left to right for the first position ``p`` whose value ``L`` is a
    plausible length (1..32) with at least ``L`` following sub-ids that are
    all printable ASCII (0x20..0x7E). Those ``L`` sub-ids decode to the DN.
    Length prefixes are always small (<0x20) so they can never be mistaken
    for DN content, which makes the scan unambiguous for the real tables
    (1200 row-seq + DN, 200/204 bare DN, 205 DN + key#, 220 DN + 2 idx).

    When no length-prefixed DN is present (e.g. the equipment table
    ``.1.1.1.<col>.<idx>`` whose index is a plain integer), ``dn`` is
    ``None`` and ``raw`` carries the whole tail.
    """
    n = len(tail)
    for p in range(n):
        length = tail[p]
        if 1 <= length <= 32 and p + 1 + length <= n:
            chunk = tail[p + 1:p + 1 + length]
            if all(0x20 <= c <= 0x7E for c in chunk):
                dn = "".join(chr(c) for c in chunk)
                # Only accept digit-ish / word DNs — a run of printable bytes
                # that is really two short numeric indices (all < 0x20) can't
                # reach here because those bytes aren't printable.
                return RowIndex(
                    dn=dn,
                    prefix=tuple(tail[:p]),
                    suffix=tuple(tail[p + 1 + length:]),
                    raw=tuple(tail),
                )
    return RowIndex(dn=None, raw=tuple(tail))


# --------------------------------------------------------------------------
# Field map (what the capture proves). Unknown programs/columns fall through
# to raw passthrough in the reader; these just add names + structure.
# --------------------------------------------------------------------------

@dataclass
class Program:
    """A named CIX program (table) and the column meanings we know."""

    number: str                      # e.g. "1200"
    name: str
    # table OID segment that sits between the program number and the columns.
    # Every observed table uses ".1.1." (entry.1 / column.1). Scalars use "".
    columns: dict[int, str] = field(default_factory=dict)
    # optional: which decoded column is the port id / the extension, so the
    # reader can promote them into the structured station record.
    ext_col: int | None = None
    port_col: int | None = None
    type_col: int | None = None
    note: str = ""


# Known scalars under .7.* (system identity / status). Keyed by the OID tail
# after the enterprise root. Value 'mac' marks the one binary scalar.
SYSTEM_SCALARS: dict[str, tuple[str, str]] = {
    # oid_tail : (field_name, decode_hint)   hint in {"text","mac","int"}
    "7.2.1.0": ("software_id", "text"),       # "NA520MT067PNDN2---EM.00"
    "7.2.3.0": ("software_id_alt", "text"),
    "7.9.1.0": ("chassis_mac", "mac"),        # e8:e0:b7:cc:58:f5
    "7.12.1.0": ("status_7_12", "int"),
    "7.4.1.0": ("status_7_4_1", "int"),
    "7.4.2.0": ("status_7_4_2", "int"),
    "7.7.1.0": ("status_7_7_1", "int"),
    "7.7.2.0": ("status_7_7_2", "int"),
    "7.7.3.0": ("status_7_7_3", "int"),
    "7.7.4.0": ("status_7_7_4", "int"),
}

# Programs under .3.* and the equipment table under .1.*.
PROGRAMS: dict[str, Program] = {
    "EQUIP": Program(
        number="1.1.1",
        name="Equipment / cabinet table",
        columns={1: "col1", 2: "col2", 3: "col3", 4: "col4"},
        note="Cabinet/slot equipment; index is a plain integer, not a DN. "
             "Columns' exact meaning not established by the capture.",
    ),
    "1200": Program(
        number="1200",
        name="Directory Number (station) table",
        columns={2: "extension", 3: "equipment_port", 4: "type", 5: "flag5",
                 6: "flag6", 7: "flag7", 19: "name"},
        ext_col=2, port_col=3, type_col=4,
        note="col2=extension (= the row DN), col3=equipment port "
             "(cabinet/slot/circuit), col4=type, cols5-7 flags, col19=station "
             "name (observed in live reads; confirm per site).",
    ),
    "200": Program(
        number="200",
        name="Station (PDN) assignment detail",
        columns={},   # ~64 columns; meanings not in the capture -> passthrough
        note="Per-station programming, ~64 columns. One column holds the "
             "equipment port (6-digit) and one the extension; the rest are "
             "preserved as raw column numbers.",
    ),
    "204": Program(number="204", name="Station feature flags",
                   note="Per-station integer/text flags; column legend unknown."),
    "205": Program(number="205", name="Key / button assignments",
                   note="Indexed by DN then key/button number (suffix)."),
    "207": Program(number="207", name="Program 207 (per-station)",
                   note="Per-station; column legend unknown."),
    "214": Program(number="214", name="Program 214 (per-station)",
                   note="Per-station; column legend unknown."),
    "220": Program(number="220", name="Program 220 (per-station, 2 sub-indices)",
                   note="Indexed by DN then two trailing sub-indices."),
    "579": Program(number="579", name="System numbering / feature config",
                   note="System-wide scalars keyed .3.579.<field>.0."),
    "1250": Program(number="1250", name="Program 1250 (system)"),
    "1260": Program(number="1260", name="Program 1260 (system)"),
    "1322": Program(number="1322", name="Program 1322 (per-station)"),
    # The parser's program id is the OID path up to the ".1.1" table entry
    # marker, so the full OID .3.2.3.1.1.* keys as program "2.3".
    "2.3": Program(
        number="2.3.1.1",
        name="Network / FTP access table",
        columns={1: "col1", 2: "username", 3: "password", 4: "path"},
        note="col2=FTP username, col3=FTP password, col4=directory. "
             "SECURITY: these are live credentials.",
    ),
}

# Programs whose columns are sensitive (passwords / community-equivalent).
SECRET_PROGRAMS = {"2.3"}
SECRET_COLUMNS = {"2.3": {3}}  # column 3 = password


__all__ = [
    "ENTERPRISE_ROOT", "MISSING", "decode_value", "decode_octet",
    "looks_like_port", "format_port", "RowIndex", "parse_row_index",
    "Program", "SYSTEM_SCALARS", "PROGRAMS", "SECRET_PROGRAMS",
    "SECRET_COLUMNS",
]
