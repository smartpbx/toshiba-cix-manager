"""Stratagy mailbox record + directory decoders, and the mailbox model.

The confirmed facts (``STRATAGY_LVMU_SERIAL_PROTOCOL.md`` §4, test-backed in the
RE prototype) are decoded here byte-for-byte:

* the box directory, entries ``<NNN>H\\0<name>\\0`` (``parse_directory``);
* the mailbox **properties** segment — box number is a little-endian uint32 at
  record offset 14 (**confirmed**); extension (``"NNNH"``), directory name and
  comment are NUL-padded strings recovered by scanning;
* the **security code** — an ASCII digit field after the ``00 00 00 ff`` marker
  in the user-agent segment (**confirmed**; a ``241997 -> 9876`` write
  transition is captured in the RE data).

Everything whose offset is **not** byte-proven carries an explicit
``unproven`` note on the decoded object (DESIGN_PLAN §1.2 rule 7). The ~30 flag/
word fields of User Mode / Auto Attendant / Chains / Menus (voicemail-map §2.2–
2.5) are **not** decoded — their offsets are unmapped (Unknown A), so the model
reports them as not-yet-readable rather than guessing.

The ``build_*_segment`` helpers synthesise records for :class:`FakeLVMU` and the
tests; they emit the confirmed layout so the decoders round-trip, and contain
no customer bytes.
"""

from __future__ import annotations

from datetime import datetime
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Directory
# --------------------------------------------------------------------------
_DIR_RE = re.compile(rb"(\d{3,4})H\x00([A-Za-z][A-Za-z0-9 ]{0,13})?\x00")


def parse_directory(blob: bytes) -> Dict[str, str]:
    """Extract the ``box -> name`` directory from a reassembled dir/DB stream."""
    out: Dict[str, str] = {}
    for m in _DIR_RE.finditer(blob):
        box = m.group(1).decode()
        name = (m.group(2) or b"").decode("latin-1")
        if name and box not in out:
            out[box] = name
    return out


def box_list(blob: bytes) -> List[str]:
    """Every box id that appears as an ``NNNH`` token, in first-seen order."""
    seen = []
    for m in re.finditer(rb"(\d{3,4})H", blob):
        box = m.group(1).decode()
        if box not in seen:
            seen.append(box)
    return seen


# --------------------------------------------------------------------------
# Mailbox record
# --------------------------------------------------------------------------
@dataclass
class Mailbox:
    box: str
    name: str = ""
    extension: str = ""
    comment: str = ""
    security_code: str = ""
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    raw_props: bytes = b""
    raw_ua: bytes = b""
    unproven: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "box": self.box,
            "name": self.name,
            "extension": self.extension,
            "comment": self.comment,
            "security_code": self.security_code,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "raw_props_hex": self.raw_props.hex(),
            "raw_ua_hex": self.raw_ua.hex(),
            "record_len": len(self.raw_props) + len(self.raw_ua),
            "unproven": list(self.unproven),
        }


def _unix_le(b: bytes, off: int) -> Optional[datetime]:
    if off + 4 > len(b):
        return None
    v = struct.unpack_from("<I", b, off)[0]
    if 946684800 <= v <= 2524608000:  # 2000..2050 sanity window
        return datetime.utcfromtimestamp(v)
    return None


def parse_mailbox_record(rec: bytes) -> Mailbox:
    """Decode a mailbox **properties** segment (payload starting at the opcode).

    Confirmed: box number = LE32 at record offset 14. Extension and name are
    recovered by scanning (their widths are site-stable but only the box number
    is asserted byte-exact), so the decoded object records that caveat."""
    box = ""
    if len(rec) >= 18:
        box = str(struct.unpack_from("<I", rec, 14)[0])
    ext = ""
    scan_from = 18
    m = re.search(rb"(\d{3,4}H)\x00", rec)
    if m:
        ext = m.group(1).decode()
        scan_from = m.end()
    # The NUL-terminated letter-initial runs AFTER the extension token are, in
    # order, the directory name and the comment (offsets inferred; values
    # confirmed). Require >=2 chars so a stray tail letter is not mistaken.
    runs = []
    for m in re.finditer(rb"([A-Za-z][A-Za-z0-9 #]{1,30})\x00", rec[scan_from:]):
        cand = m.group(1).decode("latin-1").strip()
        if cand and cand != (ext or ""):
            runs.append(cand)
    name = runs[0] if runs else ""
    comment = runs[1] if len(runs) > 1 else ""
    return Mailbox(box=box, name=name, extension=ext, comment=comment,
                   raw_props=rec)


def extract_security_code(ua_segment: bytes) -> str:
    """Pull the numeric security code from a UserAgent/security segment.

    The code is the ASCII digit run that follows the 10 greeting/message slots
    and a ``00 00 00 ff`` marker (confirmed by the captured write transition)."""
    m = re.search(rb"\xff(\d{3,16})\x00", ua_segment)
    return m.group(1).decode() if m else ""


def _ua_timestamps(ua_segment: bytes) -> List[datetime]:
    """The LE32 unix timestamps that trail the security code (created/modified)."""
    out: List[datetime] = []
    m = re.search(rb"\xff(\d{3,16})\x00", ua_segment)
    start = m.end() if m else 0
    off = start
    while off + 4 <= len(ua_segment) and len(out) < 3:
        ts = _unix_le(ua_segment, off)
        if ts is not None:
            out.append(ts)
        off += 1
    return out


def decode_mailbox(box: str, props: bytes, ua: bytes,
                   comment: str = "", name: str = "") -> Mailbox:
    """Decode a full mailbox from its two segments into the model."""
    mb = parse_mailbox_record(props) if props else Mailbox(box=str(box))
    mb.box = str(box) if box else mb.box
    mb.raw_ua = ua
    mb.security_code = extract_security_code(ua)
    ts = _ua_timestamps(ua)
    if ts:
        mb.created = ts[0]
    if len(ts) > 1:
        mb.modified = ts[1]
    if comment and not mb.comment:
        mb.comment = comment
    if name and not mb.name:
        mb.name = name
    mb.unproven = [
        "name/extension/comment field *offsets* inferred (values confirmed, "
        "widths site-stable)",
        "User Mode / Auto Attendant / Chains / Menus flag-field offsets not "
        "mapped (Unknown A) — not decoded, shown as not-yet-readable",
    ]
    return mb


def read_mailbox(link, box: str) -> Mailbox:
    """High-level: read a box over a :class:`~toshiba_cix.vm_link.VMLink`."""
    props, ua = link.read_record(box)
    return decode_mailbox(str(box), props, ua)


# --------------------------------------------------------------------------
# Patch-in-place encoder (READ-path verified; WRITE is UNCONFIRMED & gated)
# --------------------------------------------------------------------------
def rewrite_security_code(ua_segment: bytes, new_code: str) -> bytes:
    """Return a copy of a captured UA segment with the security code replaced.

    Length-preserving (NUL-padded). **UNCONFIRMED against hardware** — this only
    edits a field inside a segment we already read; it never synthesises a
    record and is not used by any read screen. The write path that would emit it
    is P3 and gated behind the two-phase contract + a supervised lab write."""
    m = re.search(rb"\xff(\d{3,16})\x00", ua_segment)
    if not m:
        raise ValueError("no security-code field found in segment")
    start, end = m.start(1), m.end(1)
    field_len = end - start
    nc = new_code.encode("ascii")
    if len(nc) > field_len:
        raise ValueError("new code longer than captured field")
    nc = nc + b"\x00" * (field_len - len(nc))
    return ua_segment[:start] + nc + ua_segment[end:]


# --------------------------------------------------------------------------
# Segment builders for FakeLVMU / tests (confirmed layout; no customer bytes)
# --------------------------------------------------------------------------
def build_props_segment(box: str, ext: str = "", name: str = "",
                        comment: str = "EXTENSION") -> bytes:
    """Build a properties segment with the confirmed header + box@14 + strings.

    The header bytes 1–13 mirror the capture's shape (length LE16 at 1–2,
    a handle word, ``a4 00`` constant, a record handle) so a reader that keys on
    them sees a plausible record; only the box number (offset 14) is asserted by
    tests. Total width is padded to 500 like the real properties segment."""
    seg = bytearray()
    seg.append(0x42)                                   # 0: opcode (read)
    seg += struct.pack("<H", 500)                      # 1-2: segment length
    seg.append(0x2c)                                   # 3: seq counter (per-frame)
    seg += b"\x00\x00"                                 # 4-5: constant
    seg += b"\xfe\x84"                                 # 6-7: per-selection handle
    seg += b"\xa4\x00"                                 # 8-9: constant (164)
    seg += struct.pack("<I", int(box))                 # 10-13: record handle
    seg += struct.pack("<I", int(box))                 # 14-17: box number (LE32)
    # extension token (leads with a digit), then directory name, then comment —
    # the order the capture shows, NUL-padded between.
    seg += ext.encode("latin-1") + b"\x00\x00"
    seg += name.encode("latin-1") + b"\x00\x00"
    seg += comment.encode("latin-1") + b"\x00"
    # pad to the 500-byte properties width
    if len(seg) < 500:
        seg += b"\x00" * (500 - len(seg))
    return bytes(seg[:500])


def build_ua_segment(security_code: str = "0000", n_slots: int = 10) -> bytes:
    """Build a user-agent/security segment: 10 empty greeting slots, the
    ``00 00 00 ff`` marker, the ASCII security code, then two LE32 timestamps.
    Padded to 241 like the real UA segment."""
    seg = bytearray()
    seg += b"\xff\xff"
    empty_slot = bytes.fromhex("00000001000000000000007fffffffff")
    for _ in range(n_slots):
        seg += empty_slot
    seg += b"\x00\x00\x00\xff"                          # marker
    code = security_code.encode("ascii")
    seg += code + b"\x00"
    # two sane timestamps (create = 2012 firmware build, modified = recent)
    seg += struct.pack("<I", 1338836400)                # ~2012-06-04
    seg += struct.pack("<I", 1760400000)                # ~2025-10
    if len(seg) < 241:
        seg += b"\xff" * (241 - len(seg))
    return bytes(seg[:241])


__all__ = [
    "Mailbox", "parse_directory", "box_list", "parse_mailbox_record",
    "extract_security_code", "decode_mailbox", "read_mailbox",
    "rewrite_security_code", "build_props_segment", "build_ua_segment",
]
