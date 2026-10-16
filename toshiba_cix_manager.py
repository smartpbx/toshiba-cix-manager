#!/usr/bin/env python3
"""Toshiba CIX Manager — standalone web app (generated).

Generated from the toshiba_cix package by build_standalone.py.
Pure stdlib; runs unchanged on a bare Python 3 (Pi / laptop).
Edit the package, not this file.
"""
from __future__ import annotations
import argparse, json, logging, socket, sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
__version__ = "1.1.0"
import base64

# ===== snmp.py =====================================================
"""Pure-stdlib SNMPv1 client (BER GET / GETNEXT), no external dependencies.

This exists so the Toshiba CIX reader can run unmodified on a bare
Raspberry Pi RSM (which has python3 but no ``pysnmp`` / ``netsnmp``). It
implements exactly the slice of SNMPv1 the reader needs:

* ``GetRequest``  (tag ``0xA0``) — read named scalars / columns.
* ``GetNextRequest`` (tag ``0xA1``) — lexicographic walk of a subtree.
* multi-varbind requests (eManager batches ~20 OIDs per PDU; so do we).

For reads it is read-only: :meth:`SnmpV1.get` / :meth:`SnmpV1.getnext` and the
walks only ever emit GET / GETNEXT (v1), so the *reader* can never write.
Writes live behind :meth:`SnmpV1.set` (a ``SetRequest``, PDU tag ``0xA3``,
sent as **v2c** — SNMP version field ``1`` — which is what the CIX requires for
a write, proven by the on-site eManager pcap). The SET path is only reached
through :mod:`toshiba_cix.write`, which gates it behind an explicit switch and
confirmation and always GET-verifies the read-back.

The Toshiba Strata CIX agent is non-standard in one way that matters:
even inside a v1 (``version=0``) PDU it returns *per-varbind* exception
tags (``0x80`` noSuchObject / ``0x81`` noSuchInstance / ``0x82``
endOfMibView) rather than collapsing the whole response to
``error-status = noSuchName(2)``. We handle both shapes: per-varbind
exceptions become :data:`Value` objects of kind ``missing`` / ``endofmib``,
and a strict-v1 ``error-status`` is surfaced on the :class:`Response` so
callers can fall back to per-OID reads.
"""


import socket
from dataclasses import dataclass
from typing import Iterable

# ASN.1 / SNMP tags we encode or decode.
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_GET = 0xA0
TAG_GETNEXT = 0xA1
TAG_GET_RESPONSE = 0xA2
TAG_SET = 0xA3
# Counter/Gauge/TimeTicks/Opaque — application primitives we may meet.
TAG_IPADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
# SNMPv2-style per-varbind exceptions the Toshiba agent emits inside v1.
TAG_NO_SUCH_OBJECT = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB = 0x82

_EXCEPTION_TAGS = {
    TAG_NO_SUCH_OBJECT: "nosuchobject",
    TAG_NO_SUCH_INSTANCE: "missing",
    TAG_END_OF_MIB: "endofmib",
}


class SnmpError(Exception):
    """Transport / protocol failure that is not a normal per-varbind miss."""


@dataclass
class Value:
    """A decoded SNMP variable value.

    ``kind`` is one of ``int``, ``octet``, ``oid``, ``missing``,
    ``nosuchobject``, ``endofmib`` or ``unknown``. ``raw`` is the original
    value octets (empty for exceptions / integers). ``int_value`` is set for
    integer-family types. Higher-level decoding (hex-ASCII digit strings,
    MAC formatting, printable-text detection) lives in :mod:`decode`, not
    here — this module only separates the wire types.
    """

    kind: str
    raw: bytes = b""
    int_value: int | None = None

    @property
    def is_missing(self) -> bool:
        return self.kind in ("missing", "nosuchobject")

    @property
    def is_end(self) -> bool:
        return self.kind == "endofmib"


@dataclass
class VarBind:
    oid: str
    value: Value


@dataclass
class Response:
    request_id: int
    error_status: int
    error_index: int
    varbinds: list[VarBind]


# --------------------------------------------------------------------------
# BER encoding helpers
# --------------------------------------------------------------------------
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(body)]) + bytes(body)


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(content)) + content


def _enc_int(value: int) -> bytes:
    if value == 0:
        return _tlv(TAG_INTEGER, b"\x00")
    negative = value < 0
    # Two's-complement minimal encoding.
    v = value
    body = []
    if not negative:
        while v:
            body.insert(0, v & 0xFF)
            v >>= 8
        if body[0] & 0x80:
            body.insert(0, 0x00)
    else:
        # Encode as two's complement.
        bits = value.bit_length() + 1
        nbytes = (bits + 7) // 8
        v = (1 << (8 * nbytes)) + value
        for _ in range(nbytes):
            body.insert(0, v & 0xFF)
            v >>= 8
        if not (body[0] & 0x80):
            body.insert(0, 0xFF)
    return _tlv(TAG_INTEGER, bytes(body))


def encode_oid(oid: str) -> bytes:
    """Encode a dotted OID string to BER content bytes (sub-identifiers)."""
    parts = [int(p) for p in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError(f"OID too short: {oid!r}")
    out = bytes([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        if arc < 0:
            raise ValueError(f"negative OID arc in {oid!r}")
        if arc < 0x80:
            out += bytes([arc])
            continue
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        out += bytes(stack)
    return _tlv(TAG_OID, out)


def _encode_varbind(oid: str) -> bytes:
    # Request varbinds always carry a NULL value.
    return _tlv(TAG_SEQUENCE, encode_oid(oid) + _tlv(TAG_NULL, b""))


def _encode_message(pdu_tag: int, community: str, oids: Iterable[str],
                    request_id: int, version: int = 0) -> bytes:
    vbl = b"".join(_encode_varbind(o) for o in oids)
    pdu = _tlv(
        pdu_tag,
        _enc_int(request_id) + _enc_int(0) + _enc_int(0)
        + _tlv(TAG_SEQUENCE, vbl),
    )
    return _tlv(
        TAG_SEQUENCE,
        _enc_int(version) + _tlv(TAG_OCTET_STRING, community.encode("latin1")) + pdu,
    )


# --------------------------------------------------------------------------
# SET encoding (writes). Values carry their real BER value instead of NULL.
# The CIX accepts a SET only as v2c (version field 1); reads stay v1.
# --------------------------------------------------------------------------
def ber_octet(value) -> bytes:
    """Encode an OCTET STRING value TLV (``str`` -> latin1 bytes, or raw bytes).

    This is how every programming field goes on the wire for a write — the same
    encoding reads use: the literal string (``"sysadmin"``, ``"010101"``, a
    station name) as octets."""
    if isinstance(value, str):
        value = value.encode("latin1")
    return _tlv(TAG_OCTET_STRING, value)


def ber_integer(value: int) -> bytes:
    """Encode an INTEGER value TLV (for the genuinely-numeric fields)."""
    return _enc_int(int(value))


def _encode_set_varbind(oid: str, value_tlv: bytes) -> bytes:
    return _tlv(TAG_SEQUENCE, encode_oid(oid) + value_tlv)


def encode_set_message(community: str, varbinds, request_id: int, *,
                       version: int = 1) -> bytes:
    """Encode an SNMP ``SetRequest`` (PDU tag ``0xA3``).

    ``varbinds`` is a list of ``(oid_str, value_tlv_bytes)`` — the value TLV is
    built with :func:`ber_octet` / :func:`ber_integer`. ``version`` defaults to
    1 (**v2c**), which the CIX requires for a write (frame 634 of the eManager
    pcap). Multiple fields are batched into one SET, exactly as eManager does.
    """
    vbl = b"".join(_encode_set_varbind(o, v) for o, v in varbinds)
    pdu = _tlv(
        TAG_SET,
        _enc_int(request_id) + _enc_int(0) + _enc_int(0)
        + _tlv(TAG_SEQUENCE, vbl),
    )
    return _tlv(
        TAG_SEQUENCE,
        _enc_int(version) + _tlv(TAG_OCTET_STRING, community.encode("latin1")) + pdu,
    )


# --------------------------------------------------------------------------
# BER decoding helpers
# --------------------------------------------------------------------------
def _read_len(buf: bytes, i: int) -> tuple[int, int]:
    length = buf[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return length, i


def _read_tlv(buf: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, content, next_index) for the TLV at ``i``."""
    tag = buf[i]
    i += 1
    length, i = _read_len(buf, i)
    content = buf[i:i + length]
    return tag, content, i + length


def decode_oid(content: bytes) -> str:
    if not content:
        return ""
    first = content[0]
    arcs = [first // 40, first % 40]
    n = 0
    for b in content[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(n)
            n = 0
    return ".".join(str(a) for a in arcs)


def _decode_value(tag: int, content: bytes) -> Value:
    if tag == TAG_INTEGER:
        return Value("int", raw=content,
                     int_value=int.from_bytes(content, "big", signed=True))
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS):
        return Value("int", raw=content,
                     int_value=int.from_bytes(content, "big", signed=False))
    if tag == TAG_OCTET_STRING or tag == TAG_IPADDRESS:
        return Value("octet", raw=content)
    if tag == TAG_OID:
        return Value("oid", raw=content)
    if tag == TAG_NULL:
        return Value("missing", raw=b"")
    if tag in _EXCEPTION_TAGS:
        return Value(_EXCEPTION_TAGS[tag], raw=b"")
    return Value("unknown", raw=content, int_value=tag)


def _parse_response(data: bytes) -> Response:
    tag, content, _ = _read_tlv(data, 0)
    if tag != TAG_SEQUENCE:
        raise SnmpError(f"not an SNMP message (outer tag {tag:#x})")
    i = 0
    _, _, i = _read_tlv(content, i)          # version
    _, _, i = _read_tlv(content, i)          # community
    pdu_tag, pdu, _ = _read_tlv(content, i)  # PDU
    if pdu_tag != TAG_GET_RESPONSE:
        raise SnmpError(f"unexpected PDU tag {pdu_tag:#x}")
    j = 0
    _, rid_c, j = _read_tlv(pdu, j)
    _, err_c, j = _read_tlv(pdu, j)
    _, idx_c, j = _read_tlv(pdu, j)
    request_id = int.from_bytes(rid_c, "big", signed=True)
    error_status = int.from_bytes(err_c, "big", signed=True)
    error_index = int.from_bytes(idx_c, "big", signed=True)
    _, vbl, _ = _read_tlv(pdu, j)
    varbinds: list[VarBind] = []
    k = 0
    while k < len(vbl):
        _, vb, k = _read_tlv(vbl, k)
        m = 0
        _, oid_c, m = _read_tlv(vb, m)
        val_tag, val_c, m = _read_tlv(vb, m)
        varbinds.append(VarBind(decode_oid(oid_c), _decode_value(val_tag, val_c)))
    return Response(request_id, error_status, error_index, varbinds)


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------
class SnmpV1:
    """A minimal, read-only SNMPv1 client over UDP.

    Parameters
    ----------
    host, port, community : connection + auth.
    timeout : per-request socket timeout in seconds (eManager uses 3s;
        the agent must answer within ~3s or the real client gives up too).
    retries : extra attempts per request on timeout (UDP can drop).
    """

    def __init__(self, host: str, community: str = "communityName", *,
                 port: int = 161, timeout: float = 3.0, retries: int = 1):
        self.host = host
        self.port = port
        self.community = community
        self.timeout = timeout
        self.retries = retries
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id = (self._request_id + 1) & 0x7FFFFFFF
        return self._request_id or 1

    def _roundtrip(self, packet: bytes, rid: int) -> Response:
        """Send one pre-built packet and return the matching Response."""
        last_exc: Exception | None = None
        for _attempt in range(self.retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(packet, (self.host, self.port))
                while True:
                    data, _ = sock.recvfrom(65535)
                    try:
                        resp = _parse_response(data)
                    except (SnmpError, IndexError, ValueError):
                        # A malformed / truncated / stray datagram must not
                        # abort the whole walk. Under heavy batched load the
                        # Strata agent occasionally emits a junk packet; skip
                        # it and keep receiving until the socket times out,
                        # then the retry loop resends the request.
                        continue
                    # Ignore stale datagrams from a previous request id.
                    if resp.request_id == rid:
                        return resp
            except socket.timeout as exc:
                last_exc = exc
            finally:
                sock.close()
        raise SnmpError(
            f"no response from {self.host}:{self.port} "
            f"(community authorised? UDP 161 reachable?)"
        ) from last_exc

    def _exchange(self, pdu_tag: int, oids: list[str]) -> Response:
        rid = self._next_id()
        packet = _encode_message(pdu_tag, self.community, oids, rid)
        return self._roundtrip(packet, rid)

    def set(self, varbinds: list[tuple[str, bytes]]) -> Response:
        """Send a batched ``SetRequest`` (v2c) and return the Response.

        ``varbinds`` is ``[(oid_str, value_tlv_bytes), ...]`` — value TLVs built
        with :func:`ber_octet` / :func:`ber_integer`. A non-zero ``error_status``
        (the agent rejected the write) raises :class:`SnmpError`. This is the
        ONLY method that writes; it is reached only through
        :mod:`toshiba_cix.write`, which gates and GET-verifies it.
        """
        if not varbinds:
            raise SnmpError("set() called with no varbinds")
        rid = self._next_id()
        packet = encode_set_message(self.community, varbinds, rid, version=1)
        resp = self._roundtrip(packet, rid)
        if resp.error_status != 0:
            raise SnmpError(
                f"CIX rejected the SET: error-status={resp.error_status} "
                f"error-index={resp.error_index}"
            )
        return resp

    def get(self, oids: list[str]) -> list[VarBind]:
        """GET a batch of OIDs. Resilient to strict-v1 ``noSuchName``.

        A standards-strict agent fails the *whole* batch (error-status=2)
        when any single OID is absent. If that happens we transparently
        re-read each OID on its own so one missing instance never blanks
        the rest of the batch; truly-absent OIDs come back as ``missing``.
        """
        if not oids:
            return []
        resp = self._exchange(TAG_GET, oids)
        if resp.error_status == 0:
            return resp.varbinds
        # Strict-v1 single-error path: degrade to per-OID reads.
        out: list[VarBind] = []
        for oid in oids:
            r = self._exchange(TAG_GET, [oid])
            if r.error_status == 0 and r.varbinds:
                out.append(r.varbinds[0])
            else:
                out.append(VarBind(oid, Value("missing")))
        return out

    def get_one(self, oid: str) -> Value:
        vbs = self.get([oid])
        return vbs[0].value if vbs else Value("missing")

    def getnext(self, oids: list[str]) -> Response:
        """Raw multi-varbind GETNEXT (one round trip)."""
        return self._exchange(TAG_GETNEXT, oids)

    def enumerate_children(self, base: str, *, max_children: int = 8192
                           ) -> list[str]:
        """Return the distinct child sub-identifiers directly under ``base``.

        Uses the "max-arc jump": after seeing child ``C`` it GETNEXTs
        ``base.C.4294967295`` — an OID lexically past everything under ``C`` —
        so the agent answers with the first OID of the *next* child. That
        enumerates a level in one round trip per child instead of walking it,
        which is what lets the reader discover programs and columns cheaply.
        """
        base = base.strip(".")
        prefix = base + "."
        children: list[str] = []
        cur = base
        for _ in range(max_children):
            resp = self.getnext([cur])
            if resp.error_status != 0 or not resp.varbinds:
                break
            vb = resp.varbinds[0]
            if vb.value.is_end or not vb.oid.startswith(prefix):
                break
            child = vb.oid[len(prefix):].split(".", 1)[0]
            children.append(child)
            cur = f"{prefix}{child}.4294967295"
        return children

    def bulk_walk(self, roots: list[str], *, width: int = 10,
                  max_total: int = 500000):
        """Walk many disjoint subtrees concurrently, batching cursors per PDU.

        Each cursor is bounded to its own root, so one GETNEXT PDU advances up
        to ``width`` independent branches by one step — the same batching
        eManager uses, and what makes a full read of a large CIX finish in
        seconds rather than minutes.

        The Strata agent limits its response size: a GETNEXT of too many
        varbinds comes back ``tooBig`` (error-status 1) with no data. We learn
        the device's working batch size on the fly — halving the batch on each
        ``tooBig`` — so no cursor is ever lost to an oversized request (the
        bug that silently truncated early reads). A single OID is retired only
        on a genuine end-of-MIB or ``noSuchName``.

        Returns ``(oid, Value)`` pairs in no particular global order (the
        caller decodes by OID, not position). Deduplication is the caller's
        job.
        """
        cursors = []
        for r in roots:
            r = r.strip(".")
            cursors.append({"root": r, "prefix": r + ".", "cur": r,
                            "done": False})
        results: list[tuple[str, Value]] = []
        total = 0
        cap = max(1, width)
        while total < max_total:
            active = [c for c in cursors if not c["done"]]
            if not active:
                break
            batch = active[:cap]
            resp = self.getnext([c["cur"] for c in batch])

            if resp.error_status == 1:          # tooBig
                if len(batch) <= 1:
                    batch[0]["done"] = True     # one OID too big — give up on it
                else:
                    cap = max(1, len(batch) // 2)
                continue
            if resp.error_status == 2:          # noSuchName (strict v1)
                ei = resp.error_index
                if 1 <= ei <= len(batch):
                    batch[ei - 1]["done"] = True
                elif len(batch) <= 1:
                    batch[0]["done"] = True
                else:
                    cap = max(1, len(batch) // 2)
                continue
            if resp.error_status != 0:          # other error
                if len(batch) <= 1:
                    batch[0]["done"] = True
                else:
                    cap = max(1, len(batch) // 2)
                continue

            vbs = resp.varbinds
            for c, vb in zip(batch, vbs):
                if vb.value.is_end:
                    c["done"] = True
                    continue
                oid = vb.oid
                if not (oid == c["root"] or oid.startswith(c["prefix"])):
                    c["done"] = True
                    continue
                if oid == c["cur"]:             # agent failed to advance
                    c["done"] = True
                    continue
                results.append((oid, vb.value))
                total += 1
                c["cur"] = oid
            # A short response (agent returned fewer varbinds than asked)
            # means we're near its size limit — shrink so the unmapped
            # cursors are retried, never dropped.
            if len(vbs) < len(batch):
                cap = max(1, len(vbs) or 1)
        return results

    def walk(self, root: str, *, max_oids: int = 20000):
        """Yield (oid, Value) for every instance lexically under ``root``.

        Single-varbind GETNEXT loop — the simple, complete, order-preserving
        walk. Stops at end-of-MIB, on the first OID that leaves ``root``, or
        after ``max_oids`` (a guard against a misbehaving agent that loops).
        """
        root = root.strip(".")
        prefix = root + "."
        current = root
        seen = 0
        while seen < max_oids:
            resp = self.getnext([current])
            # Strict-v1 end-of-MIB.
            if resp.error_status == 2:
                return
            if resp.error_status != 0 or not resp.varbinds:
                return
            vb = resp.varbinds[0]
            if vb.value.is_end:
                return
            oid = vb.oid
            if not (oid == root or oid.startswith(prefix)):
                return
            if oid == current:
                # Agent failed to advance — bail rather than spin.
                return
            yield oid, vb.value
            current = oid
            seen += 1


__all__ = [
    "SnmpV1", "SnmpError", "Value", "VarBind", "Response",
    "encode_oid", "decode_oid",
    "ber_octet", "ber_integer", "encode_set_message",
]

# ===== decode.py ===================================================
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


from dataclasses import dataclass, field


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
D = sys.modules[__name__]  # 'decode as D' alias

# ===== scan.py =====================================================
"""High-level Toshiba Strata CIX reader: walk the MIB, build structured data.

:class:`CIXReader` is the importable core. It owns no I/O policy beyond the
SNMP client it is handed, so it unit-tests against captured varbinds and runs
unchanged on a Raspberry Pi RSM or inside a Conduit worker.

Flow
----
1. GETNEXT-walk the whole Toshiba enterprise subtree (read-only).
2. Classify every varbind by OID shape into: system scalars (``.7``),
   equipment table (``.1.1.1``), or program data (``.3``).
3. Promote what the capture proves — the station directory (Program 1200),
   network/FTP credentials (``.2.3.1.1``), system numbering (Program 579),
   key assignments (Program 205) — into named fields, and attach every other
   per-station program cell to its station by DN. Nothing is discarded:
   unclassified cells keep their raw OID in ``raw_programs`` / ``raw_unknown``.
4. Flag factory-default security postures (community string, FTP creds).

The result is a plain ``dict`` ready for ``json.dumps`` and for
:mod:`toshiba_cix.report`.
"""


import logging
from datetime import datetime, timezone



# Programs the capture shows are per-station detail. They attach to a station
# that Program 1200 (the authoritative directory) already created; a row whose
# DN has no 1200 entry is kept as an orphan in raw_programs rather than
# inventing a station. Undocumented programs never create stations at all.
PER_STATION_PROGRAMS = {"200", "204", "205", "207", "214", "220", "1322"}

# Top-level branches walked whole in CORE scope, and the ``.3`` programs that
# hold everything we decode or attach (station directory + per-station detail,
# system numbering, network/FTP). A CORE read skips the hundreds of other
# programs, so it finishes in a fraction of the time of a full ALL read while
# still capturing every documented structure.
CORE_TOP_BRANCHES = ("1", "7")                       # equipment, system
CORE_PROGRAMS = ("2", "200", "204", "205", "207",    # 2 = network/FTP table
                 "214", "220", "579", "1200", "1322")


class CIXReader:
    def __init__(self, client: SnmpV1, *, logger: logging.Logger | None = None,
                 max_oids: int = 200000, strategy: str = "bulk",
                 width: int = 10, scope: str = "all",
                 keep_raw_walk: bool = False):
        self.client = client
        self.log = logger or logging.getLogger(__name__)
        self.scope = scope            # "all" (whole tree) or "core" (fast)
        self.max_oids = max_oids
        self.strategy = strategy      # "bulk" (fast, batched) or "serial"
        self.width = width            # cursors per GETNEXT PDU in bulk mode
        # When True, the full flat (oid, value) walk is attached to the result
        # as doc["raw_oid_walk"]. Off by default so the CLI/adapter docs stay
        # lean; the web app turns it on so a backup export can include the raw
        # walk alongside the structured JSON and the report.
        self.keep_raw_walk = keep_raw_walk

    # -- public ------------------------------------------------------------
    def read(self) -> dict:
        """Walk the device and return the full structured document."""
        varbinds, walk_error = self._collect()
        records = [self._classify(oid, val) for oid, val in varbinds]
        doc = self._build(records)
        doc["device"] = {
            "ip": self.client.host,
            "port": self.client.port,
            "community": self.client.community,
            "enterprise_root": D.ENTERPRISE_ROOT,
            "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "oids_read": len(varbinds),
            "scope": self.scope,
            "walk_error": walk_error,
        }
        doc["security_findings"] = self._security_findings(doc)
        if self.keep_raw_walk:
            doc["raw_oid_walk"] = [
                {"oid": oid, "value": D.decode_value(val)}
                for oid, val in varbinds
            ]
        return doc

    # -- collection --------------------------------------------------------
    def _collect(self) -> tuple[list[tuple[str, Value]], str | None]:
        if self.strategy == "serial":
            return self._collect_serial()
        try:
            return self._collect_bulk()
        except SnmpError as exc:
            # The batched path needs several round trips to enumerate before
            # it reads anything; if the device is flaky, fall back to the
            # dead-simple serial walk rather than returning nothing.
            self.log.warning("bulk collect failed (%s); falling back to serial",
                             exc)
            return self._collect_serial()

    def _dedup(self, pairs) -> list[tuple[str, Value]]:
        seen: set[str] = set()
        out = []
        for oid, val in pairs:
            if oid not in seen:
                seen.add(oid)
                out.append((oid, val))
        return out

    def _collect_serial(self) -> tuple[list[tuple[str, Value]], str | None]:
        """Per-branch single-varbind GETNEXT walk — the simplest, most robust
        strategy. In ALL scope it walks every top-level branch (so the small
        ``.7`` identity branch is captured even if ``.3`` is huge); in CORE
        scope it walks only the documented branches/programs."""
        out: list[tuple[str, Value]] = []
        error: str | None = None
        if self.scope == "core":
            roots = [f"{D.ENTERPRISE_ROOT}.{b}" for b in CORE_TOP_BRANCHES]
            roots += [f"{D.ENTERPRISE_ROOT}.3.{p}" for p in CORE_PROGRAMS]
        else:
            roots = [f"{D.ENTERPRISE_ROOT}.{c}" for c in range(1, 11)]
        for root in roots:
            try:
                out.extend(self.client.walk(root, max_oids=self.max_oids))
            except SnmpError as exc:
                self.log.warning("branch %s interrupted: %s", root, exc)
                error = str(exc)
        return self._dedup(out), error

    def _collect_bulk(self) -> tuple[list[tuple[str, Value]], str | None]:
        """Enumerate program/column roots, then walk them all in parallel.

        Splitting each big table by column gives the batched walk many
        independent cursors. Enumeration itself is cheap (one round trip per
        discovered node)."""
        roots = self._discover_roots()
        pairs = self.client.bulk_walk(roots, width=self.width,
                                      max_total=self.max_oids)
        return self._dedup(pairs), None

    def _discover_roots(self) -> list[str]:
        """Build a disjoint set of subtree roots.

        ALL scope covers the whole MIB (every top-level branch; every program
        under ``.3`` split by column). CORE scope covers only the documented
        branches and programs — far fewer OIDs, so it is the fast option for a
        routine read. Under ``.3`` each program is descended through its
        singleton entry chain to the column dimension so columns walk
        concurrently."""
        root = D.ENTERPRISE_ROOT
        roots: list[str] = []
        if self.scope == "core":
            roots += [f"{root}.{b}" for b in CORE_TOP_BRANCHES]
            for prog in CORE_PROGRAMS:
                roots += self._roots_for_program(f"{root}.3", prog)
            return roots or [root]
        for child in self.client.enumerate_children(root):
            if child == "3":
                for prog in self.client.enumerate_children(f"{root}.3"):
                    roots += self._roots_for_program(f"{root}.3", prog)
            else:
                roots.append(f"{root}.{child}")
        # Defensive: if enumeration found nothing, fall back to whole-tree.
        return roots or [root]

    def _roots_for_program(self, base3: str, prog: str) -> list[str]:
        """Column-split roots for one ``.3.<prog>`` subtree (see _discover_roots)."""
        node = f"{base3}.{prog}"
        parent = node          # never fall back above the program itself
        children = self.client.enumerate_children(node)
        depth = 0
        while len(children) == 1 and depth < 24:
            parent = node
            node = f"{node}.{children[0]}"
            children = self.client.enumerate_children(node)
            depth += 1
        if children:
            # Fan-out level: one cursor per child (prefix) walks its rows.
            return [f"{node}.{c}" for c in children]
        # Singleton chain bottomed out at a leaf; GETNEXT never returns the
        # node it sits on, so walk from the PARENT prefix to capture the leaf.
        return [parent]

    # -- classification ----------------------------------------------------
    @staticmethod
    def _classify(oid: str, val: Value) -> dict:
        """Parse one OID into {section, program, col, index, oid, value}."""
        root = D.ENTERPRISE_ROOT + "."
        rec = {"oid": oid, "value": val, "section": "unknown"}
        if not oid.startswith(root):
            return rec
        tail = oid[len(root):]
        arcs = [int(a) for a in tail.split(".")]
        rec["tail"] = tuple(arcs)

        if arcs[0] == 7:
            rec["section"] = "system"
            rec["scalar_tail"] = tail
            return rec

        if arcs[0] == 1 and len(arcs) >= 4 and arcs[1] == 1 and arcs[2] == 1:
            rec["section"] = "equipment"
            rec["program"] = "EQUIP"
            rec["col"] = arcs[3]
            rec["index"] = D.parse_row_index(tuple(arcs[4:]))
            return rec

        if arcs[0] == 3:
            rest = arcs[1:]
            marker = _find_entry_marker(rest)
            if marker is not None:
                prog = ".".join(str(a) for a in rest[:marker]) or "3"
                after = rest[marker + 2:]
                rec["section"] = "program"
                rec["program"] = prog
                rec["col"] = after[0] if after else None
                rec["index"] = D.parse_row_index(tuple(after[1:]))
            else:
                # Scalar-style program (e.g. 579): .3.<prog>.<field>.<inst>
                rec["section"] = "program_scalar"
                rec["program"] = str(rest[0]) if rest else "3"
                rec["field"] = ".".join(str(a) for a in rest[1:])
            return rec

        return rec

    # -- build -------------------------------------------------------------
    def _build(self, records: list[dict]) -> dict:
        system: dict = {"status": {}, "numbering_config": {}}
        equipment: dict[str, dict] = {}
        stations: dict[str, dict] = {}
        network_access: dict[int, dict] = {}
        raw_programs: dict[str, dict] = {}
        raw_unknown: list[dict] = []

        # Per-station program rows are deferred to a second pass: Program 1200
        # (which creates the stations) sorts lexically *after* Programs 200/204
        # /205, so attaching in one pass would orphan every one of them.
        deferred: list[dict] = []
        for rec in records:
            sec = rec["section"]
            if sec == "system":
                self._add_system(system, rec)
            elif sec == "equipment":
                self._add_equipment(equipment, rec)
            elif sec == "program_scalar":
                self._add_program_scalar(system, raw_programs, rec)
            elif sec == "program":
                if rec["program"] in PER_STATION_PROGRAMS:
                    deferred.append(rec)
                else:
                    self._add_program(stations, network_access, raw_programs, rec)
            else:
                raw_unknown.append(
                    {"oid": rec["oid"],
                     "value": D.decode_value(rec["value"])}
                )

        # Second pass: attach per-station detail to the stations 1200 created.
        for rec in deferred:
            self._add_station_detail(stations, raw_programs, rec)

        return {
            "system": system,
            "equipment": [equipment[k] for k in sorted(equipment)],
            "stations": self._finalise_stations(stations),
            "network_access": [network_access[k] for k in sorted(network_access)],
            "raw_programs": raw_programs,
            "raw_unknown": raw_unknown,
            "stats": {
                "stations": len(stations),
                "equipment_rows": len(equipment),
                "network_access_rows": len(network_access),
                "raw_program_count": len(raw_programs),
                "raw_unknown_count": len(raw_unknown),
            },
        }

    # -- section writers ---------------------------------------------------
    @staticmethod
    def _add_system(system: dict, rec: dict) -> None:
        tail = rec["scalar_tail"]
        known = D.SYSTEM_SCALARS.get(tail)
        if known:
            name, hint = known
            value = D.decode_value(rec["value"], as_mac=(hint == "mac"))
            system[name] = value
        else:
            system["status"][tail] = D.decode_value(rec["value"])

    @staticmethod
    def _add_equipment(equipment: dict, rec: dict) -> None:
        idx = rec["index"]
        key = idx.key
        row = equipment.setdefault(key, {"index": list(idx.raw)})
        prog = D.PROGRAMS["EQUIP"]
        colname = prog.columns.get(rec["col"], f"col{rec['col']}")
        row[colname] = D.decode_value(rec["value"])

    @staticmethod
    def _add_program_scalar(system: dict, raw_programs: dict, rec: dict) -> None:
        prog = rec["program"]
        label = f"{prog}.{rec['field']}"
        value = D.decode_value(rec["value"])
        if prog == "579":
            system["numbering_config"][label] = value
        else:
            bucket = raw_programs.setdefault(prog, {"name": _prog_name(prog),
                                                    "rows": {}})
            bucket["rows"].setdefault("_scalar", {})[rec["field"]] = {
                "value": value, "oid": rec["oid"],
            }

    def _add_program(self, stations: dict, network_access: dict,
                     raw_programs: dict, rec: dict) -> None:
        """First-pass handler: network table, Program 1200, and raw passthrough.

        Per-station detail programs are NOT handled here — they are deferred
        to :meth:`_add_station_detail` so Program 1200 has already built the
        stations they attach to.
        """
        prog = rec["program"]
        col = rec["col"]
        idx = rec["index"]
        value = D.decode_value(rec["value"])

        # Network / FTP credential table (.3.2.3.1.1) — flat rows, no DN.
        if prog == "2.3":
            row_id = idx.raw[-1] if idx.raw else 0
            row = network_access.setdefault(row_id, {"index": row_id})
            colname = D.PROGRAMS["2.3"].columns.get(col, f"col{col}")
            row[colname] = value
            return

        # Station directory (Program 1200) — the authoritative DN list, and
        # the ONLY program allowed to create a station record.
        if prog == "1200" and idx.dn is not None:
            st = stations.setdefault(idx.dn, _new_station(idx.dn))
            colname = D.PROGRAMS["1200"].columns.get(col)
            if colname:
                st[colname] = value
                # Keep the exact source OID so the (stubbed) write path can
                # derive a precise SET target without re-reading the device.
                st["source_oids"][colname] = rec["oid"]
            else:
                st["flags"][f"col{col}"] = value
                st["source_oids"][f"col{col}"] = rec["oid"]
            return

        # Anything else (undocumented programs, DN-less rows) → raw passthrough
        # keyed by program, preserving the raw OID. Never invents a station.
        self._raw_cell(raw_programs, prog, idx.key, col, value, rec["oid"])

    def _add_station_detail(self, stations: dict, raw_programs: dict,
                            rec: dict) -> None:
        """Second-pass handler for the per-station detail programs."""
        prog = rec["program"]
        col = rec["col"]
        idx = rec["index"]
        value = D.decode_value(rec["value"])
        st = stations.get(idx.dn) if idx.dn is not None else None
        if st is None:
            # DN has no Program 1200 entry (or no DN) → keep as an orphan row
            # rather than fabricating a station. Nothing is lost.
            self._raw_cell(raw_programs, prog, idx.key, col, value, rec["oid"])
            return
        if prog == "205":
            # Key / button assignments: the trailing suffix is the key number.
            keynum = idx.suffix[0] if idx.suffix else 0
            entry = st["keys"].setdefault(keynum, {"key": keynum})
            entry[f"col{col}"] = value
            return
        detail = st["programs"].setdefault(
            prog, {"name": _prog_name(prog), "rows": {}}
        )
        subkey = "/".join(str(s) for s in idx.suffix) or "_"
        detail["rows"].setdefault(subkey, {})[f"col{col}"] = {
            "value": value, "oid": rec["oid"],
        }

    @staticmethod
    def _raw_cell(raw_programs: dict, prog: str, rowkey: str, col,
                  value, oid: str) -> None:
        bucket = raw_programs.setdefault(prog, {"name": _prog_name(prog),
                                                "rows": {}})
        bucket["rows"].setdefault(rowkey, {})[f"col{col}"] = {
            "value": value, "oid": oid,
        }

    @staticmethod
    def _finalise_stations(stations: dict) -> list[dict]:
        out = []
        for dn in sorted(stations, key=_dn_sort_key):
            st = stations[dn]
            st["keys"] = [st["keys"][k] for k in sorted(st["keys"])]
            out.append(st)
        return out

    # -- findings ----------------------------------------------------------
    @staticmethod
    def _security_findings(doc: dict) -> list[dict]:
        findings: list[dict] = []
        comm = doc["device"]["community"]
        if comm == "communityName":
            findings.append({
                "severity": "high",
                "code": "default_snmp_community",
                "detail": "SNMP community is the Toshiba factory default "
                          "'communityName'. Anyone on the LAN can read the "
                          "entire programming. Change it in eManager.",
            })
        for row in doc.get("network_access", []):
            user = row.get("username")
            pw = row.get("password")
            if user == "sysadmin" and pw == "wksi76dbga":
                findings.append({
                    "severity": "high",
                    "code": "default_ftp_credentials",
                    "detail": "SD-card FTP login is the Toshiba factory "
                              "default (user 'sysadmin' with the published "
                              "default password).",
                })
        return findings


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _find_entry_marker(arcs: list[int]) -> int | None:
    """Index of the first ``1,1`` table entry/column marker, else None."""
    for i in range(len(arcs) - 1):
        if arcs[i] == 1 and arcs[i + 1] == 1:
            return i
    return None


def _prog_name(prog: str) -> str:
    p = D.PROGRAMS.get(prog)
    return p.name if p else f"Program {prog} (undocumented)"


def _new_station(dn: str) -> dict:
    return {
        "dn": dn,
        "extension": None,
        "equipment_port": None,
        "type": None,
        "name": None,
        "flags": {},
        "keys": {},         # keynum -> {...}; finalised to a list
        "programs": {},     # prog -> {name, rows}
        "source_oids": {},  # colname -> exact source OID (for the write path)
    }


def _dn_sort_key(dn: str):
    return (0, int(dn)) if dn.isdigit() else (1, dn)


__all__ = ["CIXReader"]

# ===== catalog.py ==================================================
"""The eManager field→OID catalog that drives backup / view / diff / restore.

The catalog is the complete, machine-readable model of a Toshiba Strata CIX's
programming, reverse-engineered from the eManager MOF: **186 programs, 2366
fields (1653 writable)**. It is vendored verbatim (minified) into the app at
:data:`CATALOG_FILENAME` so the tool is self-contained — no network, no
eManager, no MOF files at runtime.

Shape of the vendored JSON (one entry per MOF table)::

    {"<catalog key>": {
        "number":    "200",                 # program number (may be null)
        "name":      "StationAssign",
        "group_oid": "1.3.6.1.4.1.186.1.22.3.200",
        "fields": [{
            "name":   "stationStationName",
            "oid":    "1.3.6.1.4.1.186.1.22.3.200.1.1.18",  # the COLUMN oid
            "col":    18,                    # may be null
            "syntax": "DisplayString",       # DisplayString|OCTETSTRING|INTEGER
                                             #   |EnumeratedINTEGER|IpAddress|Gauge32
            "enc":    "OCTETSTRING",         # on-wire family: OCTETSTRING|INTEGER
                                             #   |IpAddress|Gauge32
            "len":    "0..16",               # declared value range (advisory)
            "access": "rw",                  # "rw" writable | "r" read-only
            "key":    false,                 # part of the row key (index)
        }, ...]
    }, ...}

One hard-won fact drives the whole design: **the field ``oid`` is the only
authoritative locator.** The convenient
``ROOT.3.<program>.1.1.<column>.<index>`` shape holds for the station/line
tables but NOT in general — programs live under ``.3``, ``.4``, ``.6``,
``.11`` …; scalar tables (e.g. 104 System Timers) are ``group_oid.<col>`` with
no ``.1.1.``; a single program's fields can span sibling sub-trees (921); and
``col`` / ``number`` are often ``null``. So every lookup keys off the full
field OID, and an instance OID is attributed to its field by **longest-prefix
match**, never by reconstructing arcs.

The proven write anchor: station name = program **200 col 18**
(``stationStationName``, rw, DisplayString 0..16), OID ``…3.200.1.1.18.<DN>``.

EnumeratedINTEGER values are returned raw (the integer). Human labels are a
later deliverable (the UX-RE effort); :meth:`Catalog.enum_label` is the hook —
call :meth:`Catalog.set_enum_labels` with an ``{oid: {raw: label}}`` map and
renderers will light up with no other change.
"""


import hashlib
import json
import os
import sys
from dataclasses import dataclass, field as dc_field
from typing import Iterable


CATALOG_FILENAME = "emanager_catalog.json"

# On-wire encoding families (the MOF ``enc``) → how a restore SETs the value.
_INTEGER_ENCS = frozenset({"INTEGER", "Gauge32"})
_INTEGER_SYNTAXES = frozenset({"INTEGER", "EnumeratedINTEGER", "Gauge32"})

_CATALOG_CACHE: "Catalog | None" = None


# --------------------------------------------------------------------------
# loading (mirrors webapp.load_html: embedded → PyInstaller bundle → package)
# --------------------------------------------------------------------------
def _candidate_paths() -> list[str]:
    paths: list[str] = []
    meipass = getattr(sys, "_MEIPASS", None)          # PyInstaller one-file
    if meipass:
        paths.append(os.path.join(meipass, "toshiba_cix", "data",
                                  CATALOG_FILENAME))
        paths.append(os.path.join(meipass, "data", CATALOG_FILENAME))
        paths.append(os.path.join(meipass, CATALOG_FILENAME))
    here = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(here, "data", CATALOG_FILENAME))
    return paths


def load_catalog_text() -> str:
    """Return the raw vendored catalog JSON text, wherever we run from.

    Order: the base64-embedded copy (the ``toshiba_cix_manager.py`` standalone),
    a PyInstaller bundle, then the packaged ``data/`` file. Mirrors
    :func:`toshiba_cix.webapp.load_html` so the same code backs the single-file
    build, the frozen ``.exe`` / AppImage and a dev checkout.
    """
    embedded = globals().get("EMBEDDED_CATALOG_JSON")
    if embedded:
        return embedded
    for path in _candidate_paths():
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                return fh.read()
    raise FileNotFoundError(
        "emanager_catalog.json not found (looked in: "
        + ", ".join(_candidate_paths()) + ")")


def load_catalog(*, text: str | None = None, path: str | None = None,
                 cache: bool = True) -> "Catalog":
    """Load and index the catalog. Cached by default (it is read-only)."""
    global _CATALOG_CACHE
    if text is None and path is None and cache and _CATALOG_CACHE is not None:
        return _CATALOG_CACHE
    if path is not None:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    elif text is None:
        text = load_catalog_text()
    cat = Catalog(text)
    if text is None and path is None and cache:
        _CATALOG_CACHE = cat
    return cat


# --------------------------------------------------------------------------
# program / catalog views
# --------------------------------------------------------------------------
@dataclass
class Program:
    """One catalog program (MOF table) with per-field lookups."""

    key: str
    number: str | None
    name: str | None
    group_oid: str
    fields: list[dict]
    _by_name: dict[str, list[dict]] = dc_field(default_factory=dict)
    _by_col: dict[int, list[dict]] = dc_field(default_factory=dict)
    _dup_names: frozenset[str] = frozenset()

    @classmethod
    def from_entry(cls, key: str, entry: dict) -> "Program":
        fields = list(entry.get("fields", []))
        by_name: dict[str, list[dict]] = {}
        by_col: dict[int, list[dict]] = {}
        for f in fields:
            by_name.setdefault(f.get("name"), []).append(f)
            col = f.get("col")
            if col is not None:
                by_col.setdefault(col, []).append(f)
        dup = frozenset(n for n, fs in by_name.items() if n and len(fs) > 1)
        num = entry.get("number")
        return cls(
            key=key,
            number=str(num) if num is not None else None,
            name=entry.get("name"),
            group_oid=entry.get("group_oid", ""),
            fields=fields,
            _by_name=by_name,
            _by_col=by_col,
            _dup_names=dup,
        )

    def field(self, name: str) -> dict | None:
        """The field named ``name`` (the first, if the name is duplicated)."""
        fs = self._by_name.get(name)
        return fs[0] if fs else None

    def fields_named(self, name: str) -> list[dict]:
        return list(self._by_name.get(name, []))

    def field_by_column(self, col: int) -> dict | None:
        """The field at column ``col`` — only when that column is unambiguous.

        Many programs reuse a column number (50 of 186), and ``col`` is often
        ``null``, so this returns ``None`` rather than guess when more than one
        field claims the column.
        """
        fs = self._by_col.get(col)
        return fs[0] if fs and len(fs) == 1 else None

    def writable_fields(self) -> list[dict]:
        return [f for f in self.fields if f.get("access") == "rw"]

    def field_key(self, fld: dict) -> str:
        """A per-row-unique key for a field.

        The field name, unless the program reuses that name across *different*
        OIDs — then the distinguishing OID suffix is appended so two columns
        never collapse onto one row key. (Every duplicate name in the shipped
        catalog is an identical-OID entry, so both halves of such a pair map to
        the same key, which is correct — they are the same field.)
        """
        oid = fld.get("oid", "")
        name = fld.get("name") or f"oid_{oid.rsplit('.', 1)[-1]}"
        if name in self._dup_names:
            suffix = oid[len(ENTERPRISE_ROOT) + 1:] if oid.startswith(
                ENTERPRISE_ROOT) else oid
            return f"{name}#{suffix}"
        return name


class Catalog:
    """Loaded, indexed eManager catalog.

    Construction indexes the catalog three ways: by catalog key, by program
    number/name, and by full field OID (for longest-prefix attribution of an
    instance OID). All lookups are O(1)-ish; attribution strips arcs.
    """

    def __init__(self, text: str):
        self._raw: dict = json.loads(text)
        self.version = "re-" + hashlib.sha256(
            text.encode("utf-8")).hexdigest()[:12]
        self.programs: dict[str, Program] = {}
        self._by_number: dict[str, list[str]] = {}
        self._by_name: dict[str, list[str]] = {}
        self.by_oid: dict[str, tuple[str, dict]] = {}
        for key, entry in self._raw.items():
            prog = Program.from_entry(key, entry)
            self.programs[key] = prog
            if prog.number:
                self._by_number.setdefault(prog.number, []).append(key)
            if prog.name:
                self._by_name.setdefault(prog.name, []).append(key)
            for f in prog.fields:
                oid = f.get("oid")
                if oid:
                    # First writer wins on the rare exact-OID collision; the
                    # overlap set is tiny and in an obscure sub-tree.
                    self.by_oid.setdefault(oid, (key, f))
        self._enum_labels: dict[str, dict[int, str]] = {}

    # -- counts ------------------------------------------------------------
    @property
    def program_count(self) -> int:
        return len(self.programs)

    @property
    def field_count(self) -> int:
        return sum(len(p.fields) for p in self.programs.values())

    @property
    def writable_count(self) -> int:
        return sum(len(p.writable_fields()) for p in self.programs.values())

    def summary(self) -> dict:
        return {
            "catalog_version": self.version,
            "programs": self.program_count,
            "fields": self.field_count,
            "writable": self.writable_count,
        }

    # -- program lookup ----------------------------------------------------
    def program(self, ident) -> Program | None:
        """Look a program up by catalog key, program number, or name."""
        if ident is None:
            return None
        ident = str(ident)
        if ident in self.programs:
            return self.programs[ident]
        for index in (self._by_number, self._by_name):
            keys = index.get(ident)
            if keys:
                return self.programs[keys[0]]
        return None

    def programs_for(self, idents: Iterable) -> list[Program]:
        out: list[Program] = []
        seen: set[str] = set()
        for ident in idents:
            p = self.program(ident)
            if p and p.key not in seen:
                seen.add(p.key)
                out.append(p)
        return out

    # -- field / OID -------------------------------------------------------
    def field(self, program_ident, field_name: str) -> dict | None:
        p = self.program(program_ident)
        return p.field(field_name) if p else None

    def field_for_oid(self, oid: str) -> dict | None:
        hit = self.by_oid.get(oid)
        return hit[1] if hit else None

    def instance_oid(self, field_or_oid, index) -> str:
        """Build the exact instance OID ``<field oid>.<index>``.

        ``field_or_oid`` is a field dict or its column OID; ``index`` is the
        instance tail as it was read (a dotted string like ``"1.3.50.48.48"``,
        a tuple of arcs, or ``""`` / ``None`` / ``"0"`` for a scalar). This is
        the inverse of :meth:`attribute_oid`.
        """
        base = field_or_oid["oid"] if isinstance(field_or_oid, dict) \
            else str(field_or_oid)
        base = base.rstrip(".")
        if index is None or index == "":
            return base
        if isinstance(index, (list, tuple)):
            index = ".".join(str(a) for a in index)
        return f"{base}.{str(index).lstrip('.')}"

    def attribute_oid(self, oid: str) -> tuple[str, dict, str] | None:
        """Attribute an instance OID to ``(program key, field, index tail)``.

        Longest-prefix match: the field whose column OID is the longest prefix
        of ``oid`` owns it; the remaining arcs are the instance tail. Returns
        ``None`` if no catalog field matches (unknown program/column).
        """
        parts = oid.split(".")
        for cut in range(len(parts), 0, -1):
            cand = ".".join(parts[:cut])
            hit = self.by_oid.get(cand)
            if hit:
                return hit[0], hit[1], ".".join(parts[cut:])
        return None

    # -- type / writability ------------------------------------------------
    @staticmethod
    def is_writable(fld: dict) -> bool:
        return fld.get("access") == "rw"

    @staticmethod
    def is_key(fld: dict) -> bool:
        return bool(fld.get("key"))

    # -- value decode / encode --------------------------------------------
    def decode_field_value(self, fld: dict, value: Value):
        """Render a wire :class:`Value` for the backup, honouring the field's
        syntax where the raw wire type would mislead.

        The wire type is trusted first (so an INTEGER-declared field that the
        agent actually returns as an OCTET digit string round-trips byte-for-
        byte on restore). The one syntax that needs help is ``IpAddress`` — its
        four bytes are not printable — which is rendered dotted-quad.
        """
        if value is None:
            return MISSING
        if value.is_missing or value.kind == "endofmib":
            return MISSING
        if fld.get("syntax") == "IpAddress" and value.kind == "octet" \
                and len(value.raw) == 4:
            return ".".join(str(b) for b in value.raw)
        return decode_value(value)

    def encode_field_value(self, fld: dict, value) -> tuple[str, bytes]:
        """Encode a stored backup value back to a ``(ber_type, value TLV)`` for
        a restore SET.

        Faithful to how the value was read: a stored ``int`` is written as an
        INTEGER, a stored ``str`` as an OCTET STRING (the pcap-proven path —
        this is how eManager writes station names, extensions and the digit
        strings the CIX uses for most numeric fields). ``ber_type`` is reported
        so the UI/CLI can flag anything other than the proven OCTET-STRING path
        for the first supervised live write.
        """
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, int):
            return "INTEGER", ber_integer(value)
        return "OCTET STRING", ber_octet(str(value))

    @staticmethod
    def wire_type_proven(fld: dict, value) -> bool:
        """True when the planned SET uses the pcap-proven OCTET-STRING-of-text
        path; False for INTEGER / IpAddress / Gauge32 writes, which are
        catalog-derived and await a supervised live write to confirm."""
        if isinstance(value, bool) or isinstance(value, int):
            return False
        return fld.get("syntax") != "IpAddress"

    # -- enum labels (hook; populated by a later UX-RE deliverable) --------
    def set_enum_labels(self, labels: dict) -> None:
        """Install an ``{oid: {raw_int: label}}`` map (keys may be str OIDs).

        No labels ship with the catalog yet; this is the seam the UX-RE effort
        plugs into. Keys are normalised so an ``{raw: label}`` sub-map accepts
        int or str raw values.
        """
        norm: dict[str, dict[int, str]] = {}
        for oid, mapping in (labels or {}).items():
            sub: dict[int, str] = {}
            for raw, label in mapping.items():
                try:
                    sub[int(raw)] = label
                except (TypeError, ValueError):
                    continue
            norm[str(oid)] = sub
        self._enum_labels = norm

    def enum_label(self, fld: dict, raw) -> str | None:
        """Human label for an EnumeratedINTEGER raw value, or ``None`` until the
        labels are loaded (then renderers show ``raw (label)``)."""
        if not self._enum_labels:
            return None
        sub = self._enum_labels.get(fld.get("oid"))
        if not sub:
            return None
        try:
            return sub.get(int(raw))
        except (TypeError, ValueError):
            return None


__all__ = [
    "CATALOG_FILENAME", "Catalog", "Program",
    "load_catalog", "load_catalog_text",
]
EMBEDDED_CATALOG_JSON = base64.b64decode("eyIxMDBDYXJkU2xvdCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY2FyZFNsb3RURUkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMC4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiNCIsIm5hbWUiOiJjYXJkU2xvdEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDAuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMyIsIm5hbWUiOiJjYXJkU2xvdENhcmRUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDAuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYXJkU2xvdE5ld0RLVVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhcmRTbG90UENNaGlnaHdheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAwLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAwIiwibmFtZSI6IkNhcmRTbG90IiwibnVtYmVyIjoiMTAwIn0sIjEwMTA2RGF5TmlnaHRNb2RlUHJpdmF0ZURheSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoicHJpdmF0ZURheVBlclRlbmFudFRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlQZXJUZW5hbnRGcmlkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTA2LjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVBlclRlbmFudE1vbmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5UGVyVGVuYW50U3VuZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNi4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlQZXJUZW5hbnRUdWVzZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNi4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlQZXJUZW5hbnRTYXR1cmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5UGVyVGVuYW50VGh1cnNkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTA2LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVBlclRlbmFudFdlZG5lc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNiIsIm5hbWUiOiJEYXlOaWdodE1vZGVQcml2YXRlRGF5IiwibnVtYmVyIjoiMTAxMDYifSwiMTAxMTJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVDYWxlbmRhclBlclRlbmFudERheU1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEyLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoicHJpdmF0ZUNhbGVuZGFyUGVyVGVuYW50VGVuYW50TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiI4IiwibmFtZSI6InByaXZhdGVDYWxlbmRhclBlclRlbmFudERheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTIuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMiIsIm5hbWUiOiJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiLCJudW1iZXIiOiIxMDExMiJ9LCIxMDExM0RheU5pZ2h0TW9kZVNjaGVkdWxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50Tm9uV29ya2luZ0RheURheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEzLjEuMS41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVBlclRlbmFudE5vbldvcmtpbmdEYXlEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMy4xLjEuNiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVQZXJUZW5hbnRQcml2YXRlSG9saWRheURheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEzLjEuMS44Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVBlclRlbmFudFByaXZhdGVIb2xpZGF5RGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjkiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50Tm9uV29ya2luZ0RheU5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMy4xLjEuNyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50UHJpdmF0ZUhvbGlkYXlOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjEwIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoidHlwZVBlclRlbmFudFRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVQZXJUZW5hbnRXb3JraW5nRGF5RGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50V29ya2luZ0RheURheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEzLjEuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVBlclRlbmFudFdvcmtpbmdEYXlOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMyIsIm5hbWUiOiJEYXlOaWdodE1vZGVTY2hlZHVsZSIsIm51bWJlciI6IjEwMTEzIn0sIjEwMkZsZXhpYmxlTnVtYmVyaW5nUGxhbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImZsYXhpYmxlTnVtYmVybGluZ09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAyLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZmxheGlibGVOdW1iZXJsaW5nUGxhbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAyLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMyIsIm5hbWUiOiJmbGF4aWJsZU51bWJlcmxpbmdGZWF0dXJlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDIuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDIiLCJuYW1lIjoiRmxleGlibGVOdW1iZXJpbmdQbGFuIiwibnVtYmVyIjoiMTAyIn0sIjEwMzE5SW50ZXJjZXB0UG9zaXRpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6ImludGVyY2VwdFBlclRlbmFudFRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzMTkuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpbnRlcmNlcHRQZXJUZW5hbnREYXkxRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaW50ZXJjZXB0UGVyVGVuYW50RGF5MkRlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMxOS4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImludGVyY2VwdFBlclRlbmFudE5pZ2h0RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbnRlcmNlcHRQZXJUZW5hbnREYXkxRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMxOS4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImludGVyY2VwdFBlclRlbmFudERheTJEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaW50ZXJjZXB0UGVyVGVuYW50TmlnaHREZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzMTkiLCJuYW1lIjoiSW50ZXJjZXB0UG9zaXRpb24iLCJudW1iZXIiOiIxMDMxOSJ9LCIxMDNDbGFzc09mU2VydmljZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1ZlcmlmeUFjY291bnRDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRG5kT3ZlcnJpZGVJbnZva2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RuZE92ZXJyaWRlUGVybWl0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRGF5TmlnaHRNb2RlQ2hhbmdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0F1dG9EaXNjUGFnaW5nQ2FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEaXJlY3RlZEROUmV0cmlldmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSG9va2luZ1NpZ25hbE9uT2ZmIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RhdGFPcmlnaW5hdGluZ09jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NFeGVjdXRpdmVPdmVycmlkZU9yaWdpbmF0b3IiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSGFuZHNGcmVlQW5zd2VyQmFjayIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NDYWxsRm9yd2FyZE92ZXJyaWRlV2l0aERTU0tleSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NMY2REbmlzQW5pUHJpb3JpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNDQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSGVhcmluZ0JHTSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0NhbGxGb3J3YXJkT3ZlcnJpZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEaXJlY3RlZEdyb3VwUGlja3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0V4dGVybmFsQkdNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1RydW5rR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEbmRTZXRMb2NhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1JlbW90ZVJldHJpZXZlUGlja3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0FueUV4dGVybmFsQ2FsbFBpY2t1cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NPcmlnaW5hdGVyQWNjb3VudENvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zR3JvdXBQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zTENSRmVhdHVyZUF2YWlsYWJpbGl0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RuZFNldFJlbW90ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zQ2FsbFRyYW5zZmVyV2l0aENhbXBvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RpcmVjdGVkVGVybWluYWxQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NBYnIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJjb3NDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc09mZmhvb2tDYW1wb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRXhlY3V0aXZlT3ZlcnJpZGVPdmVycmlkZGVuUGFydHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zTG9uZ0ZsYXNoT25PZmYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSm9pbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NUaHJvdWdoRGlhbGluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NTaG9ydEZsYXNoT25PZmYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRGlzY1RhbGtpbmdPZk91dGdvaW5nQ2FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40MSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NFbWVyZ2VuY3lQYWdpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSW5kaXZpZHVhbFRydW5rIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1ByaXZhY3lPdmVycmlkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEaXJlY3RlZERuUGlja3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRGlzYVNlY3VyaXR5Q29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0NvUmV0cmlldmVQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zVGFuZGVtQ29ubmVjdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NVQ0RBZ2VudExvZ2luTG9jYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zVUNEQWdlbnRMb2dpblJlbW90ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40NyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMyIsIm5hbWUiOiJDbGFzc09mU2VydmljZSIsIm51bWJlciI6IjEwMyJ9LCIxMDRTeXN0ZW1UaW1lciI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzAiLCJuYW1lIjoic3lzdGVtVGltZXJUYWxraW5nT3V0cHV0VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjAiLCJuYW1lIjoic3lzdGVtVGltZXJEaWFsSW5wdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNDAiLCJuYW1lIjoic3lzdGVtVGltZXJQYWdpbmdBdXRvRGlzY1RpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjUuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckFjYk92ZXJhbGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckRlbGF5ZWQxUmluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckRlbGF5ZWQyUmluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1UaW1lckRpYWxTZW5kVGltZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMjAuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lck5ldHdvcmtEU1NSZWZyZXNoVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4yMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiNS4uMTgwIiwibmFtZSI6InN5c3RlbVRpbWVyQWNiIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMTAuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckVtZXJnZW5jeUNhbGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjAiLCJuYW1lIjoic3lzdGVtVGltZXJBdXRvRGlzY1RpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYwMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckxvc3RDYWxsVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzAiLCJuYW1lIjoic3lzdGVtVGltZXJVbmxvY2tpbmdUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEwLi42MDAiLCJuYW1lIjoic3lzdGVtVGltZXJQYXJrIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTgwIiwibmFtZSI6InN5c3RlbVRpbWVyU21kciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lclVzZXJJbnB1dFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiNjAuLjE4MDAiLCJuYW1lIjoic3lzdGVtVGltZXJPdXRnb2luZ0NhbGxUYWxrRGlzY1RpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMwMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckFuc3dlcldhaXRUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckRpYWxlZDkxMUp1ZGdtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjUuLjE1IiwibmFtZSI6InN5c3RlbVRpbWVyQ2FtcG9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtVGltZXJQcmVzZXRQYXVzZVRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMjAiLCJuYW1lIjoic3lzdGVtVGltZXJPdXRnb2luZ051bWJlckRpc3BsYXlUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjI0Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoic3lzdGVtVGltZXJTeXN0ZW1DYWxsRm9yd2FyZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM2MDAiLCJuYW1lIjoic3lzdGVtVGltZXJVc2VySW5wdXREdXJhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYwMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckxvc3RDYWxsRmluYWxUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMDAiLCJuYW1lIjoic3lzdGVtVGltZXJDYWxsZXJJZERpc3BsYXlUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjI2Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQiLCJuYW1lIjoiU3lzdGVtVGltZXIiLCJudW1iZXIiOiIxMDQifSwiMTA1U3lzdGVtRGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUU5MTFTZXJ2aWNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFQcmVmaXgxSW5DYWxsSGlzdG9yeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUROSVNvckNhbGxlcklERGlzcGxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVRST3ZlcnJpZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUp1bXBpbmdMZWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFNYW55TWVtYmVyQ29uZmVyZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVBsYXlNZWxvZHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFEaXNwbGF5Q2hlY2tTdW1FcnJvciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoic3lzdGVtRGF0YVNlY29uZGFyeUNsb2NrU291cmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFEcE1ha2VSYXRpbyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN5c3RlbURhdGFTZXJ2aWNlQ29kZUNyZWRpdENhcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhTXVzaWNPbkhvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUludGVybmFsUGFkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6InN5c3RlbURhdGFDb3NPdmVycmlkZUNvZGVEaWdpdHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoic3lzdGVtRGF0YUV4dGVybmFsUGFnaW5nWm9uZU51bSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhRGVmYXVsdENhbGxpbmdOdW1iZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQ0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN5c3RlbURhdGFMb3N0Q2FsbERlc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4xNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoic3lzdGVtRGF0YURvbWVzdGljQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjI3Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhU2VsZWN0TWVsb2R5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzeXN0ZW1EYXRhTWluRGlhbERpZ2l0c0NyZWRpdENhcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQXBwZW5kZWRCY2hJbnRvQ3N0YURldklkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhU3BpZE9wZXJhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUNhbGxlZEluZGljYXRpb25PZkRzc0JsZiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQ1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVJpbmdpbmdDYWRlbmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQ2hhbmdlQUxhd011TGF3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQ29udmVydEhvb2tpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFBcHBlbmRlZFNlbmRpbmdDb21wbGV0ZUlFIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoic3lzdGVtRGF0YU5ldHdvcmtpbmdUcmFuc2l0Q291bnRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjIwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhUmVjSW5jb21wbGV0ZU91dGdvaW5nRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoic3lzdGVtRGF0YUU5MTFTZW5kaW5nRGlnaXRzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFSaW5naW5nVHJhbnNmZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVByaXZhY3lPdmVycmlkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhVHJhbnNmZXJQcml2YWN5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoic3lzdGVtRGF0YU5pZ2h0UmVsYXlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUNhc2NhZGluZ1N5c3RlbUNGIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJzeXN0ZW1EYXRhSW50ZXJuYXRpb25hbENvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUV4ZWN1dGl2ZU92ZXJyaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFDTElERm9yVHJhbnNmZXJDYWxsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQW5hbG9nRElEIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhVGFuZGVtVGFsa0NvbnRpbnVlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQXV0b1N0YXRpb25SZWxlYXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJzeXN0ZW1EYXRhUHJpbWFyeUNsb2NrU291cmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFBbmFsb2dUcnVua0h1bnRpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoic3lzdGVtRGF0YU5pZ2h0QmVsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhTnVtYmVyaW5nUGxhbklkT25DUE4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFDYWxsZXJOdW1iZXJEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhVHlwZU9mTnVtYmVyT25DYWxsaW5nUGFydHlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS40NyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFOdW1iZXJpbmdQbGFuSWRPbkNhbGxpbmdQYXJ0eU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQ4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjQiLCJuYW1lIjoic3lzdGVtRGF0YUxDREtleXN0cmlwUmVmcmVzaEludGVydmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi44IiwibmFtZSI6InN5c3RlbURhdGFDYWxsSGlzdG9yeVJlY2FsbFByZWZpeCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjUxIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNCIsIm5hbWUiOiJzeXN0ZW1EYXRhU25tcElwQWRkcmVzc1dpbGRjYXJkQml0TGVuZ3RoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InN5c3RlbURhdGFDYXJyaWVyQmFzZWRWTVdJQ29Qb3NpdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjUzIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUiLCJuYW1lIjoiU3lzdGVtRGF0YSIsIm51bWJlciI6IjEwNSJ9LCIxMDZEYXlOaWdodE1vZGVQcml2YXRlRGF5Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5RnJpZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDYuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlNb25kYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVN1bmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2LjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5VHVlc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5U2F0dXJkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVRodXJzZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDYuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlXZWRuZXNkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2IiwibmFtZSI6IkRheU5pZ2h0TW9kZVByaXZhdGVEYXkiLCJudW1iZXIiOiIxMDYifSwiMTA3UGFkVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uMyIsIm5hbWUiOiJwYWRSZWNlaXZlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA3LjEuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwYWRWYWx1ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA3LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi4zIiwibmFtZSI6InBhZFNlbmRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA3LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDciLCJuYW1lIjoiUGFkVGFibGUiLCJudW1iZXIiOiIxMDcifSwiMTA4UGFkR3JvdXAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InBhZEdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJwYWRHcm91cERldmljZVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA4IiwibmFtZSI6IlBhZEdyb3VwIiwibnVtYmVyIjoiMTA4In0sIjEwOUV4dGVybmFsTXVzaWNPbkhvbGQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxNdXNpY09uSG9sZDEyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS4xOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQxNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxNdXNpY09uSG9sZDE1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkOEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZXh0ZXJuYWxNdXNpY09uSG9sZDlFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjEwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTBFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjEyIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTFFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE0Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTJFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE2Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTNFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTRFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjIwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTVFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjIyIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkiLCJuYW1lIjoiRXh0ZXJuYWxNdXNpY09uSG9sZCIsIm51bWJlciI6IjEwOSJ9LCIxMTBQYXNzV29yZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoicGFzc3dvcmRMZXZlbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMC4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEwIiwibmFtZSI6IlBhc3NXb3JkIiwibnVtYmVyIjoiMTEwIn0sIjExMURSTCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZHJsQ3JlZGl0Q2FyZENhbGxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMS4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJkcmxEcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMS4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTExIiwibmFtZSI6IkRSTCIsIm51bWJlciI6IjExMSJ9LCIxMTJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVDYWxlbmRhckRheU1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMi4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiOCIsIm5hbWUiOiJwcml2YXRlQ2FsZW5kYXJEYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMi4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMiIsIm5hbWUiOiJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiLCJudW1iZXIiOiIxMTIifSwiMTEzRGF5TmlnaHRNb2RlU2NoZWR1bGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVOb25Xb3JraW5nRGF5RGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEzLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlTm9uV29ya2luZ0RheURheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMy41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVByaXZhdGVIb2xpZGF5RGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEzLjciLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUHJpdmF0ZUhvbGlkYXlEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTMuOCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVOb25Xb3JraW5nRGF5TmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMy42Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVByaXZhdGVIb2xpZGF5TmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMy45Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVdvcmtpbmdEYXlEYXkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVXb3JraW5nRGF5RGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEzLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlV29ya2luZ0RheU5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMyIsIm5hbWUiOiJEYXlOaWdodE1vZGVTY2hlZHVsZSIsIm51bWJlciI6IjExMyJ9LCIxMTRQYWRDb25mZXJlbmNlVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBhZENvbmZWYWx1ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoicGFkQ29uZlRydW5rcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJwYWRDb25mVGVsZXBob25lcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE0LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTQiLCJuYW1lIjoiUGFkQ29uZmVyZW5jZVRhYmxlIiwibnVtYmVyIjoiMTE0In0sIjExNUFkdmlzb3J5TWVzc2FnZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjAuLjkiLCJuYW1lIjoiYWR2aXNvcnlNZXNzYWdlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTUuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJhZHZpc29yeU1lc3NhZ2VDaGFyYWN0ZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExNS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYWR2aXNvcnlNZXNzYWdlQWRkRGlnaXRzVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE1LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE1IiwibmFtZSI6IkFkdmlzb3J5TWVzc2FnZSIsIm51bWJlciI6IjExNSJ9LCIxMTZEYXRhSW5pdGlhbGl6ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMTAwLi45OTkiLCJuYW1lIjoiZGF0YUluaXRDb21tYW5kTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExNi4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTYiLCJuYW1lIjoiRGF0YUluaXRpYWxpemUiLCJudW1iZXIiOiIxMTYifSwiMTE3UHVibGljTnVtYmVyaW5nUGxhbkFuYWx5emVkRGlnaXRzIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJwdWJsaWNOdW1iZXJpbmdQbGFuQW5hbHl6ZWREaWdpdHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExNy4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi43IiwibmFtZSI6InB1YmxpY051bWJlcmluZ1BsYW5BbmFseXplZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE3LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTciLCJuYW1lIjoiUHVibGljTnVtYmVyaW5nUGxhbkFuYWx5emVkRGlnaXRzIiwibnVtYmVyIjoiMTE3In0sIjExOExvY2tQYXNzd29yZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImxvY2tQYXNzd29yZE1hc3RlcklkQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE4LjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExOCIsIm5hbWUiOiJMb2NrUGFzc3dvcmQiLCJudW1iZXIiOiIxMTgifSwiMTE5SW5pdGlhbGl6ZUxvY2tQYXNzd29yZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF0YUluaXRpYWxpemVMb2NrUGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExOS4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE5IiwibmFtZSI6IkluaXRpYWxpemVMb2NrUGFzc3dvcmQiLCJudW1iZXIiOiIxMTkifSwiMTIwVGVuYW50RGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InRlbmFudERhdGFEYXkxT3BlQ2FsbERlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJ0ZW5hbnREYXRhRGF5Mk9wZUNhbGxEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIwLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJ0ZW5hbnREYXRhVGVuYW50TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJ0ZW5hbnREYXRhTmlnaHRPcGVDYWxsRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMC4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVuYW50RGF0YURheTFPcGVDYWxsRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZW5hbnREYXRhRGF5Mk9wZUNhbGxEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoidGVuYW50RGF0YU5pZ2h0UmVsYXlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMC4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVuYW50RGF0YU5pZ2h0T3BlQ2FsbERlc3RpbmF0aW9uVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIwLjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJ0ZW5hbnREYXRhTmlnaHRCZWxsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMCIsIm5hbWUiOiJUZW5hbnREYXRhIiwibnVtYmVyIjoiMTIwIn0sIjEyMUF1dG9tYXRpY0RheWxpZ2h0U2F2aW5nQ2hhbmdlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMiIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ1dlZWtNb2RlRW5kTW9udGgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ0VuZFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4xMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImRheWxpZ2h0U2F2aW5nRGF0ZU1vZGVTdGFydERhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS45Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdXZWVrTW9kZVN0YXJ0TW9udGgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ1NoaWZ0VGltZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjEzIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdTdGFydFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4xMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRheWxpZ2h0U2F2aW5nV2Vla01vZGVFbmREYXlPZldlZWsiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdXZWVrTW9kZUVuZE51bU9mV2VlayIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkYXlsaWdodFNhdmluZ1dlZWtNb2RlU3RhcnREYXlPZldlZWsiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdXZWVrTW9kZVN0YXJ0TnVtT2ZXZWVrIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRheWxpZ2h0U2F2aW5nQXZhaWxhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjEuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRheWxpZ2h0U2F2aW5nTW9kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ0RhdGVNb2RlRW5kRGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjEwIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxIiwibmFtZSI6IkF1dG9tYXRpY0RheWxpZ2h0U2F2aW5nQ2hhbmdlIiwibnVtYmVyIjoiMTIxIn0sIjE1MFN5c3RlbUlQRGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBUb3NGaWVsZFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBUZXJtaW5hbEF1dGhlbnRpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwVG9zUHJlY2VkZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcFN0YXRpb25JREF1dG9Bc3NpZ25tZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwVG9zVGhyb3VnaHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42MyIsIm5hbWUiOiJzeXN0ZW1JcERzY3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcFRvc1JlbGlhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwR2FpbkNvbnRyb2xNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzeXN0ZW1JcElQQ1RYSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBJRUVFODAyMXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwVG9zRGVsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBEaWZmc2VydiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcENFRENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwRWNob0NhbmNlbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBJRUVFODAyMXBEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcElwUXNpZ0JNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi41IiwibmFtZSI6InN5c3RlbUlwRmF4TWF4SG9wIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwRWNob0NhbmNlbEZvck1JUFUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwU0lQVHJ1bmtEaWZmc2VydiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua1Rvc0ZpZWxkVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua1Rvc1ByZWNlZGVuY2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwU0lQVHJ1bmtUb3NEZWxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua1Rvc1Rocm91Z2hwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwU0lQVHJ1bmtUb3NSZWxpYWJpbGl0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjMiLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua0RzY3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yOSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwIiwibmFtZSI6IlN5c3RlbUlQRGF0YSIsIm51bWJlciI6IjE1MCJ9LCIxNTFCSVBVQ29uZml1cmF0aW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJpcHVEZWZhdWx0R1dBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEuMS4xLjQiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiaXB1SXBBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEuMS4xLjIiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoiYmlwdVZlcnNpb25OdW1iZXJEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmlwdVN1Yk5ldEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MS4xLjEuMyIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjQiLCJuYW1lIjoiYmlwdUNhcmRTbG90RXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MS4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjE2Mzg0Li42NTUwNCIsIm5hbWUiOiJiaXB1TWVkaWFDaGFubmVsQmFzZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUxLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEiLCJuYW1lIjoiQklQVUNvbmZpdXJhdGlvbiIsIm51bWJlciI6IjE1MSJ9LCIxNTJWb2ljZVBhY2tldENvbmZpZ3VyYXRpb25UYWJsZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJ2b2ljZVRibE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2b2ljZVRibFBhY2tldFRyYW5zbWlzc2lvbkludGVydmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlclR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1MCIsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlckxlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUyLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJ2b2ljZVRibFBhY2tldExvc3NUaHJlc2hvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm9pY2VUYmxQYWNrZXRUcmFuc21pc3Npb25JbnRlcnZhbEZvck1JUFUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlclR5cGVGb3JNSVBVIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIwMCIsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlckxlbmd0aEZvck1JUFUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJ2b2ljZVRibFBhY2tldExvc3NUaHJlc2hvbGRGb3JNSVBVIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIuMS4xLjE0Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIiLCJuYW1lIjoiVm9pY2VQYWNrZXRDb25maWd1cmF0aW9uVGFibGUiLCJudW1iZXIiOiIxNTIifSwiMTUzVm9pY2VQcm9jZXNzb3JDb250cm9sVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMyIsIm5hbWUiOiJ2cFZnY0lucHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJ2cEFkYXB0YXRpb25EdXJhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTMiLCJuYW1lIjoidnBWZ2NPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1My4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEzIiwibmFtZSI6InZwQ2djRGVjb2RlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMyIsIm5hbWUiOiJ2cENnY0VuY29kZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1My4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidnBBZGFwdGF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJ2cERldmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6InZwTmxwVGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZwQ29tZm9ydE5vaXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2cE5scCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidnBCeXBhc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1My4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MyIsIm5hbWUiOiJWb2ljZVByb2Nlc3NvckNvbnRyb2xUYWJsZSIsIm51bWJlciI6IjE1MyJ9LCIxNjFMSVBVQ29uZml1cmF0aW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVEZWZhdWx0R1dBZGRyZXNzMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS40Iiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdURlZmF1bHRHV0FkZHJlc3MyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjciLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1SXBBZGRyZXNzMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4yIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdUlwQWRkcmVzczIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuNSIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6OCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJsaXB1VmVyc2lvbk51bWJlckRpc3BsYXkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImxpcHVWZXJzaW9uTnVtYmVyRGlzcGxheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiI0IiwibmFtZSI6ImxpcHVDYXJkU2xvdEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaXB1SWRsZUlQUG9ydE51bWJlckRpc3BsYXkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJsaXB1SWRsZUlQUG9ydE51bWJlckRpc3BsYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVTdWJOZXRBZGRyZXNzMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4zIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdVN1Yk5ldEFkZHJlc3MyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjYiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXAxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXBEYXRhMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1SUVFRTgwMjFxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40MDk0IiwibmFtZSI6ImxpcHVJRUVFODAyMXFEYXRhMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXAyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXBEYXRhMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1SUVFRTgwMjFxMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40MDk0IiwibmFtZSI6ImxpcHVJRUVFODAyMXFEYXRhMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjE2Mzg0Li42NTUwNCIsIm5hbWUiOiJsaXB1TWVkaWFDaGFubmVsQmFzZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxNjM4NC4uNjU1MDQiLCJuYW1lIjoibGlwdU1lZGlhQ2hhbm5lbEJhc2UyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdURIQ1AxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdUROU1NlcnZlclByaW1hcnkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjIzIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVETlNTZXJ2ZXJTZWNvbmRhcnkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjI0Iiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoibGlwdUhvc3ROYW1lMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4yNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaXB1UHJpbWFyeUROU1N1ZmZpeDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1REhDUDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1RE5TU2VydmVyUHJpbWFyeTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjgiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdUROU1NlcnZlclNlY29uZGFyeTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjkiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaXB1SG9zdE5hbWUyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjMwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImxpcHVQcmltYXJ5RE5TU3VmZml4MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4zMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxIiwibmFtZSI6IkxJUFVDb25maXVyYXRpb24iLCJudW1iZXIiOiIxNjEifSwiMTYzTElQVVZvaWNlUHJvY2Vzc29yQ29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdVZwQnlwYXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNyIsIm5hbWUiOiJsaXB1VnBJcHRNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNiIsIm5hbWUiOiJsaXB1VnBSZWxhdGl2ZVRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdVZwRG91YmxlVGFsa0hhbmd0aW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTMiLCJuYW1lIjoibGlwdVZwVmdjSW5wdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVWcEFic29sdXRlVGhyZXNob2xkMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdVZwQWJzb2x1dGVUaHJlc2hvbGQyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJsaXB1VnBBZGFwdGF0aW9uRHVyYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEzIiwibmFtZSI6ImxpcHVWcFZnY091dHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTMiLCJuYW1lIjoibGlwdVZwQ2djRGVjb2RlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMyIsIm5hbWUiOiJsaXB1VnBDZ2NFbmNvZGVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVWcEFkYXB0YXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4zMjAiLCJuYW1lIjoibGlwdVZwRGV2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVWcEJldGFNYW50aXNzYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdVZwQmV0YUV4cG9uZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVWcE5scFRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1VnBDb21mb3J0Tm9pc2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVWcE5scCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzIiwibmFtZSI6IkxJUFVWb2ljZVByb2Nlc3NvckNvbnRyb2wiLCJudW1iZXIiOiIxNjMifSwiMTY0RnVsbElwUXNpZ0RUTUZEZXRlY3Rpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RXaWRlYmFuZFRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RBYnNvbHV0ZVRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RTbnJMaW1pdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RIb2xkT2ZmTGltaXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NC43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVEdG1mRGV0ZWN0Rm9yd2FyZFR3aXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjQuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNiIsIm5hbWUiOiJsaXB1RHRtZkRldGVjdFJldmVyc2VUd2lzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RGbGF0bmVzc0xpbWl0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjQuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNiIsIm5hbWUiOiJsaXB1RHRtZkRldGVjdEFkZGl0aW9uYWxUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjQuOCIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0IiwibmFtZSI6IkZ1bGxJcFFzaWdEVE1GRGV0ZWN0aW9uIiwibnVtYmVyIjoiMTY0In0sIjE2NUZheE92ZXJJcFN5c3RlbURhdGFBc3NpZ25tZW50Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zNCIsIm5hbWUiOiJmYXhPdmVySXBTeXN0ZW1DbmdEZXRlY3RUaHJlc2hvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMDAiLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ25nQmFuZFJhdGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTciLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ2VkRGV0ZWN0VGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ2VkTWFyZ2luVGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ2VkRmxhdG5lc3NUaHJlc2hvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJmYXhPdmVySXBTeXN0ZW1DZWRSZWxlYXNlVGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuNiIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY1IiwibmFtZSI6IkZheE92ZXJJcFN5c3RlbURhdGFBc3NpZ25tZW50IiwibnVtYmVyIjoiMTY1In0sIjE2NkZheE92ZXJJcFBhcmFtZXRlclRhYmxlQXNzaWdubWVudCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJmYXhPdmVySXBUYmxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZmF4T3ZlcklwVGJsU2xvd0RhdGFSZWR1bmRhbmN5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJmYXhPdmVySXBUYmxGYXN0RGF0YVJlZHVuZGFuY3kiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMiLCJuYW1lIjoiZmF4T3ZlcklwVGJsU2xvd0RhdGFGZWNOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMyIsIm5hbWUiOiJmYXhPdmVySXBUYmxGYXN0RGF0YUZlY051bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY2LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJmYXhPdmVySXBUYmxEYXRhZ3JhbVNpemUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImZheE92ZXJJcFRibE1heFJhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NiIsIm5hbWUiOiJGYXhPdmVySXBQYXJhbWV0ZXJUYWJsZUFzc2lnbm1lbnQiLCJudW1iZXIiOiIxNjYifSwiMjAwU3RhdGlvbkFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMCIsIm5hbWUiOiJzdGF0aW9uU3RhdGlvblNwZWVkRGlhbE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS40NCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25NV1dpdGhEaWFsaW5nIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjUwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvbkRybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvbkZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoic3RhdGlvbkNvcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvblFwbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uQ0VTSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uRGlhbGluZ0RpZ2l0UmVzdHJpY3Rpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkhvbGRJbmRpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQ4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uT3JpZ2luYXRpbmdPY2EiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJzdGF0aW9uRW1lcmdlbmN5R3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJzdGF0aW9uUmVtb3RlUGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40OCIsIm5hbWUiOiJzdGF0aW9uSW5kZXhDYWxsRm93YXJkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblRyYXZlbENvZGVDaGFuZ2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkN3dFJvYiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6InN0YXRpb25UZW5hbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InN0YXRpb25EcmxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQXV0b0NhbXBvbmFzRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJzdGF0aW9uRnJsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoic3RhdGlvbkNvc0RheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InN0YXRpb25RcGxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjE2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkJlYXJDYXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblNMVFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblBlcnNvbmFsQWRtaW5TZWN1cml0eUxldmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InN0YXRpb25EcmxOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkV4dGVuc2lvblBvcnRUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvbkZybE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzdGF0aW9uQ29zTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25SZWdTeXN0ZW1TcGVlZERpYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvblFwbE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblNlbmRlcml6ZWRNb2RlVG9uZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4yMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjI0Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkNhbGxGb3J3YXJkRGlhbFRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblJlbGVhc2VTdXBlcnZpc2lvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6InN0YXRpb25FcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQ2FsbFBpY2t1cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJzdGF0aW9uQ2VudGVyUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6InN0YXRpb25OZXR3b3JrQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblJlY2FsbEFmdGVyQ0hvbGRBbmRPTkgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6InN0YXRpb25Wb2ljZU1haWxJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4yOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25UR0FDT3ZlclJpZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbk5hbWVEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjM2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uU3RhdGlvbk5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMTgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uRG9vclBob25lRE5EIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25TdHV0dGVyZWREaWFsVG9uZVNlbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvblN0YXRpb25MY3JHcm91cE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uUGVyc29uYWxBZG1pblBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU2Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoic3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uT3JnSW52b2tlT2NhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25TZXJ2aWNlVG9uZVBlcm1pc3Npb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN0YXRpb25EZWZhdWx0Q2FsbGluZ051bWJlcklkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU1Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblBETkNvZGVEaWdpdHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblNMVEZTS01vZGVtU2lnbmFsVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41OCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uU0xUT2ZmSG9va0NPUHJlZmVyZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41OSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NDAiLCJuYW1lIjoic3RhdGlvblNMVENPUHJlZmVyZW5jZVRydW5rT3JPbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNjAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQ2FsbGluZ05hbWVUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjYxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25TeXN0ZW1TcGVlZERpYWxTdXBwbGVtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjYyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25BbmFsb2dTdGF0aW9uRGlzY29ubmVjdFNpZ25hbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS42MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQ2FsbFdhaXRpbmdTd2FwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjY0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwIiwibmFtZSI6IlN0YXRpb25Bc3NpZ24iLCJudW1iZXIiOiIyMDAifSwiMjAxU3RhdGlvbkRlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiZGVsZXRlU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAxIiwibmFtZSI6IlN0YXRpb25EZWxldGUiLCJudW1iZXIiOiIyMDEifSwiMjAySVNETlN0YXRpb25Bc3NpZ25tZW50Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjI5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25DRVNJRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4yOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25EaWFsaW5nRGlnaXRSZXN0cmljdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40NiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uT3JpZ2luYXRpbmdPY2EiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNDIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkxjckdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkNoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVm9pY2VDYWxsTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25TeXN0ZW1DYWxsRm9yd2FyZERpYWxUb25lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQ1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25TcGVlY2giLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25JbnRlcmRpZ2l0MVRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25JbnRlcmRpZ2l0MlRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVGVuYW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQ4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRHJsRGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkRybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQXV0b0NhbXBvbmFzRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40OSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRnJsRGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25GcmxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQ29zRGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQ29zRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvblFwbERheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uUXBsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4xNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkNvbm5lY3Rpb25Gb3JtYXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRHJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRnJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25Db3NOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvblJlZ1N5c3RlbVNwZWVkRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uUXBsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQmNoU2VsZWN0ZWRPcmlnaW5hdGluZ01ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4yNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25Qcm90b2NvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb243a0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbjMxa0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbk5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMzQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVEdBQ092ZXJSaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25TdHV0dGVyZWREaWFsVG9uZVNlbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNDciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVW5yZXN0NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25VbnJlc3Q1NmticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbk9yZ0ludm9rZU9jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uU2VydmljZVRvbmVQZXJtaXNzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25JZGxlQmNoU2VsZWN0aW9uTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRGVmYXVsdENhbGxpbmdOdW1iZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS41MSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25QRE5Db2RlRGlnaXRzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjUwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMCIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uU3RhdGlvblNwZWVkRGlhbE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40NCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25BZGRpdGlvbmFsRG4yIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjM1Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkFkZGl0aW9uYWxEbjMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMzYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQWRkaXRpb25hbERuNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4zNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25BZGRpdGlvbmFsRG41Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjM4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkFkZGl0aW9uYWxEbjYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMzkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQWRkaXRpb25hbERuNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40MCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25BZGRpdGlvbmFsRG44Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQxIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvblVucmVzdDJ4NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyIiwibmFtZSI6IklTRE5TdGF0aW9uQXNzaWdubWVudCIsIm51bWJlciI6IjIwMiJ9LCIyMDNETkNoYW5nZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiY2hhbmdlTmV3RE4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMy4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImNoYW5nZUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDMuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMyIsIm5hbWUiOiJETkNoYW5nZSIsIm51bWJlciI6IjIwMyJ9LCIyMDRES1REYXRhIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YURUTUYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVNwZWFrZXJDd3RSb2IiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUFkbWluaXN0cmF0b3JUZWxlcGhvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUJsaW5kVHJhbnNmZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVR5cGVPZlJpbmdpbmdQcmVmZXJlbmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFFeGNsdXNpdmVIb2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdE1pY3JvcGhvbmVJbml0aWFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFQcm9ncmFtbWluZ01vZGVTZWN1cml0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhVGV4dE1zZ0Rpc3BsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUhhbmRzRnJlZVNwbGFzaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhQ3JpdGVyaW9uT2ZCdXN5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFCUENJQkFUSSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhVHJ1bmtUZXN0VmVyaWZ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFSb2JSZXB0aXRpb25UaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YU9jYVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhU3RvcFNlbmRpbmdMQ0RJbmZvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFMQ0REaXNwbGF5TGFuZ3VhZ2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVJpbmdpbmdQcmVmZXJlbmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdEF1dG9MaW5lSG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTWFpbEJveFNlbGVjdE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI0IiwibmFtZSI6ImRrdERhdGFLZXlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUtleVBhdGVybiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVRvbmVGaXJzdFZvaWNlRmlyc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3RNaWNyb3Bob25lVXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFUeXBlT2ZJZGxlUHJlZmVyZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjksImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGt0RGF0YU92ZXJmbG93RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFBZGRPbk1vZHVsZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVN0YXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUhhbmRzRnJlZU1pYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhRXh0ZXJuYWxSaW5naW5nUmVwZWF0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMCIsIm5hbWUiOiJka3REYXRhQ2FsbEhpc3RvcnlNZW1vcnlTaXplIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZGt0RGF0YURuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTm9SaW5nTm9GbGFzaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhRGlhbERpcmVjdG9yeVNwZWFrZXJTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhRGlhbERpcmVjdG9yeVNwZWFrZXJNYWtlQ2FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTGNkS2V5c3RyaXBLaW5kT2ZES1QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNDAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUxjZEtleXN0cmlwS2luZE9mQURNMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS40MSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTGNkS2V5c3RyaXBLaW5kT2ZBRE0yIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjQyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFLZWVwU3RhdGlvbk5hbWVEaXNwbGF5QWZ0ZXJBbnN3ZXJDYWxsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0IiwibmFtZSI6IkRLVERhdGEiLCJudW1iZXIiOiIyMDQifSwiMjA1RmVhdHVyZUtleSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMiLCJuYW1lIjoiZmVhdHVyZUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNS4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIwIiwibmFtZSI6ImZlYXR1cmVLZXlObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS44Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZmVhdHVyZURuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDUuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNSIsIm5hbWUiOiJGZWF0dXJlS2V5IiwibnVtYmVyIjoiMjA1In0sIjIwNlBoRE4iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGhETlBhcmFtZXRlclVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJwaEROUGFyYW1ldGVyRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBoRE5QYXJhbWV0ZXJUb25lRmlyc3RWb2ljZUZpcnN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjciLCJuYW1lIjoicGhETlBhcmFtZXRlckNlbnRlclBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuMTAiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJwaEROUGFyYW1ldGVyVm9pY2VNYWlsSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6InBoRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoicGhETlBhcmFtZXRlck93bmVyU2hpcERuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwaEROUGFyYW1ldGVyTmFtZURpc3BsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40OCIsIm5hbWUiOiJwaEROUGFyYW1ldGVyQ2FsbEZvcndhcmRJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA2LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYiLCJuYW1lIjoiUGhETiIsIm51bWJlciI6IjIwNiJ9LCIyMDdTaW5nbGVUb3VjaEJ1dHRvbkRhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yODYwIiwibmFtZSI6InNpbmdsZVRvdWNoQnV0dG9uRmtObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA3LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoic2luZ2xlVG91Y2hCdXR0b25SZWdpc3RyYXRpb25EYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDcuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzaW5nbGVUb3VjaEJ1dHRvblByaW1lRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNy4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA3IiwibmFtZSI6IlNpbmdsZVRvdWNoQnV0dG9uRGF0YSIsIm51bWJlciI6IjIwNyJ9LCIyMDhTdGF0aW9uVGltZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uVGltZXJEbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA4LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MDAiLCJuYW1lIjoic3RhdGlvblRpbWVyTm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA4LjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi4yMCIsIm5hbWUiOiJzdGF0aW9uVGltZXJBYnJSZXRyeUNvdW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjUuLjYwIiwibmFtZSI6InN0YXRpb25UaW1lckFiclJlY2FsbFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJzdGF0aW9uVGltZXJIb2xkUmVjYWxsVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6InN0YXRpb25UaW1lckludGVyZGlnaXQxVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6InN0YXRpb25UaW1lckludGVyZGlnaXQyVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMzAuLjE4MCIsIm5hbWUiOiJzdGF0aW9uVGltZXJBYnJJbnRlcnZhbFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6InN0YXRpb25UaW1lclZtd2lTZW5kaW5nVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyMCIsIm5hbWUiOiJzdGF0aW9uVGltZXJBbmFsb2dTdGF0aW9uRGlzY29ubmVjdFNpZ25hbFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDgiLCJuYW1lIjoiU3RhdGlvblRpbWVyIiwibnVtYmVyIjoiMjA4In0sIjIwOVN0YXRpb25IdW50aW5nIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSHVudERpc3BsYXlETiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uSHVudENGIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSHVudFBpbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25IdW50VUNEIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTEwMCIsIm5hbWUiOiJzdGF0aW9uSHVudEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkh1bnRVQ0RNdXNpY09uSG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25IdW50QXV0b21hdGljQ2FtcG9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAiLCJuYW1lIjoic3RhdGlvbkh1bnRVQ0RSZXNwb25zZVRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzYwMCIsIm5hbWUiOiJzdGF0aW9uSHVudFVDRE92ZXJmbG93VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOS4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ4IiwibmFtZSI6InN0YXRpb25IdW50Q2FsbEZvcndhcmRJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uSHVudE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5IiwibmFtZSI6IlN0YXRpb25IdW50aW5nIiwibnVtYmVyIjoiMjA5In0sIjIxMFBpY2tVcEdycCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImNhbGxQaWNrdXBHcm91cERuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYWxsUGlja3VwR3JvdXBQaWNrdXA5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDExIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwIiwibmFtZSI6IlBpY2tVcEdycCIsIm51bWJlciI6IjIxMCJ9LCIyMTFTdGF0aW9uSHVudGluZ0dyb3VwRGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMTAwIiwibmFtZSI6ImRlbGV0ZVN0YXRpb25IdW50aW5nR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTEiLCJuYW1lIjoiU3RhdGlvbkh1bnRpbmdHcm91cERlbGV0ZSIsIm51bWJlciI6IjIxMSJ9LCIyMTNBZGRPbk1vZHVsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoiYWRkT25Ebk1vZHVsZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEzLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJhZGRPblBhcmFtZXRlcjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMy4xLjEuNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiYWRkT25QYXJhbWV0ZXIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTMuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImFkZE9uUGFyYW1ldGVyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEzLjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJhZGRPblBhcmFtZXRlcjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMy4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiYWRkT25QYXJhbWV0ZXI1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTMuMS4xLjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zIiwibmFtZSI6ImFkZE9uRmVhdHVyZUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMy4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIwIiwibmFtZSI6ImFkZE9uRmVhdHVyZUtleU5vIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTMuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMyIsIm5hbWUiOiJBZGRPbk1vZHVsIiwibnVtYmVyIjoiMjEzIn0sIjIxNERTUyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImRzc1N0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE0LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3MxRXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNC4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZHNzMkVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTQuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6ImRzczNFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE0LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3M0RXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNC4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZHNzNUVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTQuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6ImRzczZFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE0LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3M3RXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNC4xLjEuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZHNzOEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTQuMS4xLjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNCIsIm5hbWUiOiJEU1MiLCJudW1iZXIiOiIyMTQifSwiMjE1RFNTa2V5Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS44Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMyIsIm5hbWUiOiJkc3NGZWF0dXJlQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNjAiLCJuYW1lIjoiZHNzRmVhdHVyZUtleU5vIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTUuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3NOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNS4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1IiwibmFtZSI6IkRTU2tleSIsIm51bWJlciI6IjIxNSJ9LCIyMTZFbWVyZ2VuY3lSaW5nRG93biI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiZW1nUmluZ0Rvd25EZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE2LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZW1nUmluZ0Rvd25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE2LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJlbWdSaW5nRG93bkFwcGxpY2FiaWxpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNi4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYwIiwibmFtZSI6ImVtZ1JpbmdEb3duVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNi4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE2IiwibmFtZSI6IkVtZXJnZW5jeVJpbmdEb3duIiwibnVtYmVyIjoiMjE2In0sIjIxN0lTRE5pbmRpdmlkdWFsU3RhdGlvbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblN0YXRpb25TZW5kZXJpemVkTW9kZVRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5TdGF0aW9uRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5TdGF0aW9uQ2hhbmdlQ09TT3ZlcnJpZGVDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImlzZG5TdGF0aW9uVm9pY2VNYWlsSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuMTAiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuU3RhdGlvbkNQTklFQ29udGVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE3LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuU3RhdGlvbk5hbWVEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImlzZG5TdGF0aW9uU3RhdGlvbk5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblN0YXRpb25Eb29yUGhvbmVETkQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpc2RuU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjgiLCJuYW1lIjoiaXNkblN0YXRpb25FbWVyZ2VuY3lHcm91cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE3LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJpc2RuU3RhdGlvblJlbW90ZVBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ4IiwibmFtZSI6ImlzZG5TdGF0aW9uSW5kZXhDYWxsRm93YXJkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNyIsIm5hbWUiOiJJU0ROaW5kaXZpZHVhbFN0YXRpb24iLCJudW1iZXIiOiIyMTcifSwiMjE4U3RhdGlvbkh1bnRpbmdHcm91cE1lbWJlciI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaHVudEdycE1lbWJlckRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTguMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMDAwIiwibmFtZSI6Imh1bnRHcnBNZW1iZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE4LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJodW50R3JwTWVtYmVyTW9kSW5zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTguMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTEwMCIsIm5hbWUiOiJodW50R3JwTWVtYmVyTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTguMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxOCIsIm5hbWUiOiJTdGF0aW9uSHVudGluZ0dyb3VwTWVtYmVyIiwibnVtYmVyIjoiMjE4In0sIjIxOU5ldHdvcmtEU1NOb3RpZnlEYXRhRGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJuZXR3b3JrRFNTbm90aWZ5Tm9kZUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTkuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE5IiwibmFtZSI6Ik5ldHdvcmtEU1NOb3RpZnlEYXRhRGVsZXRlIiwibnVtYmVyIjoiMjE5In0sIjIyMERLVEtleXN0cmlwTGFiZWwiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJka3RMY2RLZXlzdHJpcExhYmVsRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIyMC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6ImRrdExjZEtleXN0cmlwTGFiZWxEZXZpY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMjAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZGt0TGNkS2V5c3RyaXBMYWJlbEZrTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIyMC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyIiwibmFtZSI6ImRrdExjZEtleXN0cmlwTGFiZWxEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMjAuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIyMCIsIm5hbWUiOiJES1RLZXlzdHJpcExhYmVsIiwibnVtYmVyIjoiMjIwIn0sIjI1MFN0YXRpb25JUERhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uSXBWZXJzaW9uTnVtYmVyRGlzcGxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xMCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25JcE5BVFRyYXZlcnNhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSXBEbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN0YXRpb25JcFVSSSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwVGVybWluYWxBdXRoZW50aWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwSXBBZGRyZXNzVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJzdGF0aW9uSXBTZWNvbmRhcnlWUENvbmZpZ1RhYmxlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJzdGF0aW9uSXBWb2ljZVBhY2tldENvbmZpZ1RhYmxlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJzdGF0aW9uSXBQYXNzd29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwU3RhdGlvbklEQXV0b21hdGljQXNzaWdubWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSXBTdGF0aW9uSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uSXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuNCIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwU2Vjb25kYXJ5QXVkaW9Db2RlYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25JcEF1ZGlvQ29kZWMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMiIsIm5hbWUiOiJzdGF0aW9uSXBNYWNBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNTAuMS4xLjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxMDI2Li42NTUzMiIsIm5hbWUiOiJzdGF0aW9uSXBNZWRpYUNoYW5uZWxCYXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNTAuMS4xLjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwRFRNRlRyYW5zbGF0aW9uTW9kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MCIsIm5hbWUiOiJTdGF0aW9uSVBEYXRhIiwibnVtYmVyIjoiMjUwIn0sIjI2MElwU3RhdGlvbkFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblJlY2FsbEFmdGVyQ0hvbGRBbmRPTkgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImlwU3RhdGlvblZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjI4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uVEdBQ092ZXJSaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbk5hbWVEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJpcFN0YXRpb25TdGF0aW9uTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4xOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbkRvb3JQaG9uZURORCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TdHV0dGVyZWREaWFsVG9uZVNlbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uU3RhdGlvbkxjckdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImlwU3RhdGlvblBlcnNvbmFsQWRtaW5QYXNzd29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41MiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25PcmdJbnZva2VPY2EiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uU2VydmljZVRvbmVQZXJtaXNzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpcFN0YXRpb25EZWZhdWx0Q2FsbGluZ051bWJlcklkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjUxIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uUEROQ29kZURpZ2l0cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41MCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMDAiLCJuYW1lIjoiaXBTdGF0aW9uU3RhdGlvblNwZWVkRGlhbE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40MSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbk1XV2l0aERpYWxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpcFN0YXRpb25EcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaXBTdGF0aW9uQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpcFN0YXRpb25RcGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uQ0VTSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25EaWFsaW5nRGlnaXRSZXN0cmljdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25Ib2xkSW5kaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40NCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25PcmlnaW5hdGluZ09jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6ImlwU3RhdGlvbkVtZXJnZW5jeUdyb3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjI2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoiaXBTdGF0aW9uUmVtb3RlUGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40OCIsIm5hbWUiOiJpcFN0YXRpb25JbmRleENhbGxGb3dhcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25UcmF2ZWxDb2RlQ2hhbmdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbkN3dFJvYiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6ImlwU3RhdGlvblRlbmFudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40NyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkRybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25BdXRvQ2FtcG9uYXNEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjQ5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkZybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlwU3RhdGlvbkNvc0RheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvblFwbERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25CZWFyQ2FwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblBlcnNvbmFsQWRtaW5TZWN1cml0eUxldmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjUzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkRybE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uRnJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlwU3RhdGlvbkNvc05pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25SZWdTeXN0ZW1TcGVlZERpYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uUXBsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBTdGF0aW9uTGFuSW50ZXJmYWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TZW5kZXJpemVkTW9kZVRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXBTdGF0aW9uRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjI0Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uQ2FsbEZvcndhcmREaWFsVG9uZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25SZWxlYXNlU3VwZXJ2aXNpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uU3BlYWtlck9jYUFjY2VwdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImlwU3RhdGlvbkVxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbkNhbGxQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjciLCJuYW1lIjoiaXBTdGF0aW9uQ2VudGVyUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4yOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlwU3RhdGlvbk5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25UMzhQcm90b2NvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBTdGF0aW9uVDM4VGFibGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblQzOFN1YnN0aXR1dGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25Mb2dpblBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjU4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblRyYW5zZmVyUmVnaXN0cmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjU5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2MCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImlwU3RhdGlvbkNvbm5lY3RpbmdFcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNjAiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uc3RhdGlvbkNhbGxpbmdOYW1lVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS42MSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TcGVjaWZpZWRDYWxsZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS42MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TeXN0ZW1TcGVlZERpYWxTdXBwbGVtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjYzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblNpcEluYmFuZE1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAiLCJuYW1lIjoiSXBTdGF0aW9uQXNzaWduIiwibnVtYmVyIjoiMjYwIn0sIjMwMFRydW5rQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtSaW5nRG93bkNpcmN1aXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtTdXBwbHlPZlJpbmdpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua0RpYWxNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua0Fuc3dlclN1cGVydmlzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua1JlbGVhc2VTdXBlcnZpc2lvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRydW5rR3VhcmRUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJ0cnVua1RydW5rTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS4xMCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtTaWduYWxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6InRydW5rRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua1N0YXJ0TWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtEdG1mQmFja1RvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNDQwIiwibmFtZSI6InRydW5rTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjk5OSIsIm5hbWUiOiJ0cnVua0h1bnRpbmdPcmRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6InRydW5rSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJ0cnVua09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAiLCJuYW1lIjoiVHJ1bmtBc3NpZ24iLCJudW1iZXIiOiIzMDAifSwiMzAxVHJ1bmtEZWxldGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjQ0MCIsIm5hbWUiOiJ0cnVua0RlbGV0ZU5vIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAxIiwibmFtZSI6IlRydW5rRGVsZXRlIiwibnVtYmVyIjoiMzAxIn0sIjMwMklTRE5QcmltYXJ5VHJ1bmsiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVW5yZXN0Mng2NGticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1NwZWVjaENoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtUV2FpdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVmlkZW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdE11bHRpcmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtTcGVlY2giLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rUTkzMVByb3RvY29sVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVuazdrSHpBdWRpb0NoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtTZW5kTUNJRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rMzFrSHpBdWRpb0NoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtSZXN0cmljdERpZ2l0YWxJbmZvQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1FzaWdJbnRlcmZhY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjM4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0lmSWROdW1iZXJJbXBsaWNpdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtRc2lnUHJlZmVyZW5jZUxpbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0JjaFNlbGVjdGVkT3JpZ2luYXRpbmdNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rUHJvdG9jb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rN2tIekF1ZGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmszMWtIekF1ZGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtSZXN0cmljdERpZ2l0YWxJbmZvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjI3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0VxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3Q2NGticHNDaE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVW5yZXN0NTZrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjYiLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0lmSWROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3QzODRrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDE5MjBrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDE1MzZrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rRGNoUG9zaXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3QyeDY0a2Jwc0NoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtUQkNUQ29udHJhY3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1Nob3J0TGluZUJyZWFrU3VwcG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40MCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVW5yZXN0NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3Q1NmticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0lkbGVCY2hTZWxlY3Rpb25NZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDM4NGticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDE5MjBrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3QxNTM2a2JwcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4yMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVmlkZW9DaE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rUmJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtTZW5kQ2FsbGluZ05hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0VUU0lTZW5kaW5nVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMiIsIm5hbWUiOiJJU0ROUHJpbWFyeVRydW5rIiwibnVtYmVyIjoiMzAyIn0sIjMwM0lTRE5UcnVua0RlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImlzZG5EZWxldGVDaE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAzLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMyIsIm5hbWUiOiJJU0ROVHJ1bmtEZWxldGUiLCJudW1iZXIiOiIzMDMifSwiMzA0SUxHQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJpbGdDb250cmFjdEJlYW1Db3VudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0NhbGxpbmdOdW1iZXJJZGVudGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpbGdEcmxOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ0ZybE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjE2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaWxnQ29zTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdSZWdTeXN0ZW1TcGVlZERpYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaWxnUXBsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdTZW5kZXJpemVkTW9kZVRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnQ2F1c2VWYWx1ZU9mRmFpbHVyZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdJbnRlcmNlcHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNjAiLCJuYW1lIjoiaWxnRGVsYXkxUmluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYwIiwibmFtZSI6ImlsZ0RlbGF5MlJpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ1RydW5rVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlsZ05ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdDb3NPdmVycmlkZUNvZGVDaGFuZ2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnVEdBQ092ZXJSaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ1N0YXRpb25MY3JHcm91cE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ09yZ0ludm9rZU9jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpbGdHQ08iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ0RybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ0ZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaWxnQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpbGdRcGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0FuYWxvZ0lTRE5UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiaWxnUG9vbExpbmVHcm91cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnQ2FsbGVkRGlhbFRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdUcnVua1ByaXZhdGVTZXJ2aWNlVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjgiLCJuYW1lIjoiaWxnRW1lcmdlbmN5R3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiaWxnR3JwTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0F1dG9tYXRpY0NhbXBvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoiaWxnSW50ZXJkaWdpdDFUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE4MCIsIm5hbWUiOiJpbGdJbnRlcmRpZ2l0MlRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjI1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJpbGdUZW5hbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpbGdEcmxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaWxnRnJsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaWxnQ29zRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaWxnUXBsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0JlYXJDYXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdUcnVua1NlcnZpY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQiLCJuYW1lIjoiSUxHQXNzaWduIiwibnVtYmVyIjoiMzA0In0sIjMwNUlMR0RlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRlbGV0ZUlsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA1LjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNSIsIm5hbWUiOiJJTEdEZWxldGUiLCJudW1iZXIiOiIzMDUifSwiMzA2T0xHQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnQ3JlZGl0Q2FyZENhbGxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoib2xnRnJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJvbGdDb3NOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im9sZ1FwbE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnQ2VzaWRTZW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnVHJ1bmtUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoib2xnTmV0d29ya0NvcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4yNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ011c2ljT25Ib2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ0FjY291bnRDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1RyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im9sZ0ZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoib2xnQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJvbGdRcGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ0FuYWxvZ0lTRE5UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoib2xnR2NvMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoib2xnUG9vbExpbmVHcm91cDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6Im9sZ1Bvb2xMaW5lR3JvdXAyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1RydW5rUHJpdmF0ZVNlcnZpY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnQW5hbG9nRXhjbHVzaXZlTGluZUZsYXNoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJvbGdHcnBObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnUXNpZ1NlbmRpbmdUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im9sZ0ZybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJvbGdDb3NEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoib2xnUXBsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ0JlYXJDYXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYiLCJuYW1lIjoiT0xHQXNzaWduIiwibnVtYmVyIjoiMzA2In0sIjMwN09MR0RlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRlbGV0ZU9sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA3LjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNyIsIm5hbWUiOiJPTEdEZWxldGUiLCJudW1iZXIiOiIzMDcifSwiMzA4VHJ1blRpbWVyIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua1RpbWVyQWJhbmRvblN1cGVydmlzZVRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRydW5rVGltZXJEZXRlY3RBckNwYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA4LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAiLCJuYW1lIjoidHJ1bmtUaW1lckxvbmdGbGFzaFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTUiLCJuYW1lIjoidHJ1bmtUaW1lclNob3J0Rmxhc2hUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDguMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiNiIsIm5hbWUiOiJ0cnVua1RpbWVyUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA4LjEuMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAwMCIsIm5hbWUiOiJ0cnVua1RpbWVyRElEYW5kRE1JUmVzcG9uc2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJ0cnVua1RpbWVyUGF1c2VUaW1lQWZ0ZXJGbGFzaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA4LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDgiLCJuYW1lIjoiVHJ1blRpbWVyIiwibnVtYmVyIjoiMzA4In0sIjMwOURJRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaWREYXkxRGF0YURlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjEzIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImRpZERheTJEYXRhRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaWREYXkxQXVkaW9EZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGlkRGF5MkF1ZGlvRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaWROaWdodERhdGFEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4xNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJkaWRWb2ljZU1haWxJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4xOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGlkTXVzaWNPbkhvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGlkTmlnaHRBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZGlkR2NvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiZGlkSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTciLCJuYW1lIjoiZGlkVm1TZW5kaW5nRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4yMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpZERheTFEYXRhRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpZERheTJEYXRhRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImRpZFBvb2xMaW5lR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGlkRGF5MUF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkaWREYXkyQXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkaWROaWdodERhdGFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImRpZERlc3RpbmF0aW9uTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4xOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpZE5pZ2h0QXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjciLCJuYW1lIjoiZGlkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6ImRpZFRlbmFudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4yMyIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5IiwibmFtZSI6IkRJRCIsIm51bWJlciI6IjMwOSJ9LCIzMTBESVQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiNiIsIm5hbWUiOiJkaXRFcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaXREYXkxQXVkaW9EZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEwLjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGl0RGF5MkF1ZGlvRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGl0TXVzaWNPbkhvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaXROaWdodEF1ZGlvRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGl0RGF5MUF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkaXREYXkyQXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpdE5pZ2h0QXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMCIsIm5hbWUiOiJESVQiLCJudW1iZXIiOiIzMTAifSwiMzExRElTQSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjAiLCJuYW1lIjoiZGlzYUlkbGVUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzExLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpc2FOZWNlc3NpdHlTZWN1cml0eUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMS4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE1IiwibmFtZSI6ImRpc2FTZWN1cml0eUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMCIsIm5hbWUiOiJkaXNhUmVzcG9uc2VUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzExLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpc2FBY2Nlc3NUb1RpZUxpbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzExIiwibmFtZSI6IkRJU0EiLCJudW1iZXIiOiIzMTEifSwiMzEyRElETnVtYmVyRGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRpZERlbGV0ZUlsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJkaWREZWxldGVOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMi4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEyIiwibmFtZSI6IkRJRE51bWJlckRlbGV0ZSIsIm51bWJlciI6IjMxMiJ9LCIzMTNDYWxsZXJJRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY2FsbGVySWRJbW1lZGlhdGVDYWxsZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiY2FsbGVySWRDSVVFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzLjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYWxsZXJJZE5vdGljZUNvbnRlbnRzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTMuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYWxsZXJJZFJlY2VpdmluZ01ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjQ0MCIsIm5hbWUiOiJjYWxsZXJJZFRydW5rTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMy4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzIiwibmFtZSI6IkNhbGxlcklEIiwibnVtYmVyIjoiMzEzIn0sIjMxNVQxVHJ1bmtDYXJkRGF0YUFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidDFUcnVua1NlbmRQQUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNS4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InQxVHJ1bmtaZXJvQ29kZVN1cHByZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTUuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0MVRydW5rUmVjZWl2ZVBBRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiI0IiwibmFtZSI6InQxVHJ1bmtFcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNS4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InQxVHJ1bmtGcmFtZUZvcm1hdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1IiwibmFtZSI6IlQxVHJ1bmtDYXJkRGF0YUFzc2lnbiIsIm51bWJlciI6IjMxNSJ9LCIzMTZEY2hTaGFyZWRQUkkiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRjaFNoYXJlZEV4aXN0ZW5jZU9mRGNoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTYuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRjaFNoYXJlZENoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoiZGNoU2hhcmVkRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTYuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjYiLCJuYW1lIjoiZGNoU2hhcmVkSWZJZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE2LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTYiLCJuYW1lIjoiRGNoU2hhcmVkUFJJIiwibnVtYmVyIjoiMzE2In0sIjMxN0lTRE5iYXNpY1RydW5rIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1NwZWVjaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rU2VuZE1DSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImlzZG5CYXNpY1RydW5rU3Vic2NyaWJlck51bWJlcjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoiaXNkbkJhc2ljVHJ1bmtTdWJzY3JpYmVyTnVtYmVyMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4yMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1NQSURJbml0aWFsaXplIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rQmNoU2VsZWN0ZWRPcmlnaW5hdGluZ01ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rUHJvdG9jb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rN2tIekF1ZGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVuazMxa0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImlzZG5CYXNpY1RydW5rRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIwIiwibmFtZSI6ImlzZG5CYXNpY1RydW5rU3BpZFZhbHVlMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1NwaWRWYWx1ZTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMTgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNWb2ljZUNhbGxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljVHJ1bmtEZUFjdGl2ZU1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImlzZG5CYXNpY0NoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rU2hvcnRMaW5lQnJlYWtTdXBwb3J0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rVW5yZXN0NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rVW5yZXN0NTZrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rSWRsZUJjaFNlbGVjdGlvbk1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1RFSSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxNiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6ImlzZG5CYXNpY1NQSURJbml0aWFsaXplVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImlzZG5CYXNpY1RydW5rSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpc2RuQmFzaWNUcnVua09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljVHJ1bmtVbnJlc3QyeDY0a2JwcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1RXYWl0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rRVRTSVNlbmRpbmdUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjI3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3IiwibmFtZSI6IklTRE5iYXNpY1RydW5rIiwibnVtYmVyIjoiMzE3In0sIjMxOE5vQ3BuRElEIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6Im5vRGlkRGVzdGluYXRpb25OYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjE5Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWROaWdodEF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6Im5vRGlkTm9EaWRPck5vdERldGVybWluIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6Im5vRGlkRGF5MURhdGFEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJub0RpZERheTJEYXRhRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMTUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJub0RpZERheTFBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJub0RpZERheTJBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoibm9EaWROaWdodERhdGFEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJub0RpZFZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjE4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub0RpZE11c2ljT25Ib2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6Im5vRGlkTmlnaHRBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoibm9EaWRHY28iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJub0RpZElsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE3IiwibmFtZSI6Im5vRGlkVm1TZW5kaW5nRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4yMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im5vRGlkRGF5MURhdGFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWREYXkyRGF0YURlc3RpbmF0aW9uVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJub0RpZFBvb2xMaW5lR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWREYXkxQXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im5vRGlkRGF5MkF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWROaWdodERhdGFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMTYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTgiLCJuYW1lIjoiTm9DcG5ESUQiLCJudW1iZXIiOiIzMTgifSwiMzE5SW50ZXJjZXB0UG9zaXRpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImludGVyY2VwdE5pZ2h0RGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTkuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpbnRlcmNlcHREYXkxRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaW50ZXJjZXB0RGF5MkRlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTkuNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImludGVyY2VwdE5pZ2h0RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbnRlcmNlcHREYXkxRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTkuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImludGVyY2VwdERheTJEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE5IiwibmFtZSI6IkludGVyY2VwdFBvc2l0aW9uIiwibnVtYmVyIjoiMzE5In0sIjMyMElTRE5CY2hQb3NpdGlvbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb240Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb243Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4xMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24zMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjYiLCJuYW1lIjoiYmNoRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24zMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24yMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjI1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24yNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjE3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMjciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xOCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4xOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjI4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24yOSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMCIsIm5hbWUiOiJJU0ROQmNoUG9zaXRpb24iLCJudW1iZXIiOiIzMjAifSwiMzIxSVNETkNhbGxpbmdOdW1iZXJJZGVudGlmaWNhdGlvbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJjYWxsaW5nTnVtT2xnTnVtIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJjYWxsaW5nTnVtRGVmYXVsdENhbGxpbmdOdW0iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImNhbGxpbmdOdW1DYWxsaW5nTnVtYmVyUHJlZml4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxpbmdOdW1DYWxsaW5nTnVtYmVyVmVyaWZpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoiY2FsbGluZ051bURlZmF1bHRDYWxsaW5nTnVtMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIxLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTUiLCJuYW1lIjoiY2FsbGluZ051bURlZmF1bHRDYWxsaW5nTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIxLjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEiLCJuYW1lIjoiSVNETkNhbGxpbmdOdW1iZXJJZGVudGlmaWNhdGlvbiIsIm51bWJlciI6IjMyMSJ9LCIzMjJJU0ROQ2FsbGluZ051bWJlclRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiY2FsbGluZ051bURlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiY2FsbGluZ051bU9MRyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoiY2FsbGluZ051bURlc3RUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJjYWxsaW5nTnVtRElETnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNSIsIm5hbWUiOiJjYWxsaW5nTnVtRElETmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIyLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIiLCJuYW1lIjoiSVNETkNhbGxpbmdOdW1iZXJUYWJsZSIsIm51bWJlciI6IjMyMiJ9LCIzMjNDYWxsQnlDYWxsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMiIsIm5hbWUiOiJjYmNGYWNpbGl0eUNvZGVWYWx1ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NyIsIm5hbWUiOiJjYmNNaW5ab25lMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDciLCJuYW1lIjoiY2JjTWluWm9uZTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NyIsIm5hbWUiOiJjYmNNaW5ab25lMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ3IiwibmFtZSI6ImNiY01heFpvbmUxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjMuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDciLCJuYW1lIjoiY2JjTWF4Wm9uZTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NyIsIm5hbWUiOiJjYmNNYXhab25lMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiY2JjU2VydmljZVBhcmFtZXRlcnMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoiY2JjTmV0d29ya0lkZW50aWZpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjMuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJjYmNJbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImNiY09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImNiY0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiY2JjTGluZVNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYmNLaW5kT2ZMaW5lU2VydmljZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzIiwibmFtZSI6IkNhbGxCeUNhbGwiLCJudW1iZXIiOiIzMjMifSwiMzI0Q2FsbEJ5Q2FsbFRpbWVab25lIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJjYmNUaW1lWm9uZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNC4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImNiY1RpbWVab25lMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI0LjEuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoiY2JjVGltZVpvbmUzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjQuMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImNiY1RpbWVab25lQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI0IiwibmFtZSI6IkNhbGxCeUNhbGxUaW1lWm9uZSIsIm51bWJlciI6IjMyNCJ9LCIzMjVGdWxsSXBRc2lnIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFFzaWdUcnVuazMxa0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImlwUXNpZ1RydW5rRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiaXBRc2lnVHJ1bmtJbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImlwUXNpZ1RydW5rT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwUXNpZ1RydW5rUmJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJpcFFzaWdUcnVua0NoYW5uZWxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJpcFFzaWdUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwUXNpZ1RydW5rU3BlZWNoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBRc2lnVHJ1bmtROTMxUHJvdG9jb2xUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI1LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBRc2lnVHJ1bmtMYW5JbnRlcmZhY2VOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI1IiwibmFtZSI6IkZ1bGxJcFFzaWciLCJudW1iZXIiOiIzMjUifSwiMzI2U0lQVHJ1bmsiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoic2lwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJzaXBUcnVua0VxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI2LjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMSIsIm5hbWUiOiJzaXBUcnVua0xhbkludGVyZmFjZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI2LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzaXBUcnVua0NoYW5uZWxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNi4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtSYnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNi4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNiIsIm5hbWUiOiJTSVBUcnVuayIsIm51bWJlciI6IjMyNiJ9LCIzMjdTSVBUcnVua1NlcnZpY2VLaW5kQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUmVnaXN0cmF0aW9uTW9kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRUcnVua0lsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFRydW5rT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ0MCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVHJ1bmtDaGFubmVsTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kRG9tYWluTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uODYiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNlcnZlckxvY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVlBUYWJsZUluZGV4UHJpbWFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFZQVGFibGVJbmRleFNlY29uZGFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiNzAwLi42NTUzNSIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUmVnaXN0ZXJQZXJpb2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVGltZXJCIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTQ0MCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUmVjb3ZlcnlUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmROZXR3b3JrVHJhbnNmZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFVzZXJBZ2VudEhlYWRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2VydmVySGVhZGVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRQcm90b2NvbE9wdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiI5MC4uNjU1MzUiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNlc3Npb25UaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRBdWRpb0NvZGVjUHJpbWFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kQXVkaW9Db2RlY1NlY29uZGFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kRHRtZiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUnRjcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVDM4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRTZXJ2ZXJDYWNoZXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFEaWZmc2VydiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFUb3NGaWVsZFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZE1lZGlhVG9zUHJlY2VkZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFUb3NEZWxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFUb3NUaHJvdWdocHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRNZWRpYVRvc1JlbGlhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYzIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRNZWRpYURzY3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lnbmFsaW5nRGlmZnNlcnYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNpZ25hbGluZ1Rvc0ZpZWxkVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lnbmFsaW5nVG9zUHJlY2VkZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lnbmFsaW5nVG9zRGVsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNpZ25hbGluZ1Rvc1Rocm91Z2hwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNpZ25hbGluZ1Rvc1JlbGlhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjM2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYzIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRTaWduYWxpbmdEc2NwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjM3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZEVsZW1lbnRDYWxsUmVsZWFzZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxMC4uOTkiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZEVsZW1lbnRGYWlsdXJlVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi4zNjAwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRSZWNvdmVyeVJlZ2lzdGVyQ3ljbGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zNjAwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRPcHRpb25zSW50ZXJ2YWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lwTWVzc2FnZU9wdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS40MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lwTWVzc2FnZVRvSGVhZGVyT3B0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRSZWdpc3Rlck1lc3NhZ2VGcm9tSGVhZGVyT3B0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjQ0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRSZWdpc3Rlck1lc3NhZ2VUb0hlYWRlck9wdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS40NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kQXNzZXJ0SWRlbnRpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjciLCJuYW1lIjoiU0lQVHJ1bmtTZXJ2aWNlS2luZEFzc2lnbiIsIm51bWJlciI6IjMyNyJ9LCIzMjhTSVBUcnVua1NlcnZpY2VBc3NpZ24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyOC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjE2IiwibmFtZSI6InNpcFRydW5rU2VydmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI4LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyOC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI4LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI4LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjgiLCJuYW1lIjoiU0lQVHJ1bmtTZXJ2aWNlQXNzaWduIiwibnVtYmVyIjoiMzI4In0sIjMyOVNJUFVSSUFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBVcmlUcnVua1NlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTYwIiwibmFtZSI6InNpcFVyaUluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjkuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJzaXBVcmkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyOS4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUwIiwibmFtZSI6InNpcFVyaVVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjkuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJzaXBVcmlQYXNzV29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoic2lwVXJpUmVnaXN0ZXJDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBVcmlBdHRyaWJ1dGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5IiwibmFtZSI6IlNJUFVSSUFzc2lnbiIsIm51bWJlciI6IjMyOSJ9LCI0MDBFbWVyZ2VuY3lDYWxsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNCIsIm5hbWUiOiJlbWVyZ2VuY3lDYWxsQ2FsbGVkTnVtYmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZW1lcmdlbmN5Q2FsbENhbGxlZE51bWJlclNldFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4zIiwibmFtZSI6ImVtZXJnZW5jeUNhbGxEYXlOaWdodE1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImVtZXJnZW5jeUNhbGxDYWxsZWROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNDAwIiwibmFtZSI6IkVtZXJnZW5jeUNhbGwiLCJudW1iZXIiOiI0MDAifSwiNDA0QXR0ZW5kYW50R3JvdXAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6ImF0dGVuZGFudEdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40MDQuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImF0dGVuZGFudENhbGxEaXN0cmlidXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJhdHRlbmRhbnRBbHRlcm5hdGl2ZURlc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTgwIiwibmFtZSI6ImF0dGVuZGFudE92ZXJmbG93VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImF0dGVuZGFudE92ZXJmbG93RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImF0dGVuZGFudFZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40MDQuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNCIsIm5hbWUiOiJBdHRlbmRhbnRHcm91cCIsIm51bWJlciI6IjQwNCJ9LCI1MDBTeXN0ZW1DYWxsRm9yd2FyZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjQ4IiwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkRmlyc3REZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoic3lzdGVtQ2FsbEZvcndhcmRTZWNvbmREZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtQ2FsbEZvcndhcmRDYWxsVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkRGF5TmlnaHRNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDAuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDAiLCJuYW1lIjoiU3lzdGVtQ2FsbEZvcndhcmQiLCJudW1iZXIiOiI1MDAifSwiNTAxU3lzdGVtU3BlZWREaWFsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoic3lzdGVtU3BlZWREaWFsTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDEuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMyIsIm5hbWUiOiJzeXN0ZW1TcGVlZERpYWxzSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMS4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzeXN0ZW1TcGVlZERpYWxVc2VyTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAxLjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDEiLCJuYW1lIjoiU3lzdGVtU3BlZWREaWFsIiwibnVtYmVyIjoiNTAxIn0sIjUwMlRlcm1QYWdpbmdHcnAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmc1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmc4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzEwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4xMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzEzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcxNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMTUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMTYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzE2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBBbGxQYWdpbmdMaXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBBbGxFbWFyZ2VuY3lQYWdpbmdMaXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcxNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4yMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMTgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzE5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcyMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4yMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIiLCJuYW1lIjoiVGVybVBhZ2luZ0dycCIsIm51bWJlciI6IjUwMiJ9LCI1MDNEZXZpY2VQYWdpbmdHcnAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6InpvbmVSZWxheU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmczIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmc2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nOSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzExIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcxMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcxNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cEFsbFBhZ2luZ0xpc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cEFsbEVtYXJnZW5jeVBhZ2luZ0xpc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJleHRlcm5hbEdlbmVyaWNSZWxheU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcxNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzE5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcyMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMiLCJuYW1lIjoiRGV2aWNlUGFnaW5nR3JwIiwibnVtYmVyIjoiNTAzIn0sIjUwNFN5c3RlbUNhbGxGb3J3YXJkVHlwZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtQ0ZUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDQuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNDgiLCJuYW1lIjoic3lzdGVtQ0ZUeXBlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA0IiwibmFtZSI6IlN5c3RlbUNhbGxGb3J3YXJkVHlwZSIsIm51bWJlciI6IjUwNCJ9LCI1MDZWZXJpZmllZEFjY291bnRDb2RlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJ2ZXJpZmllZEFjY291bnRDb2RlRHJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDYuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6InZlcmlmaWVkQWNjb3VudENvZGVGcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNi4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidmVyaWZpZWRBY2NvdW50Q29kZUNvZGVGbGFnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjE1IiwibmFtZSI6InZlcmlmaWVkQWNjb3VudENvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNi4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoidmVyaWZpZWRBY2NvdW50Q29kZU5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNi4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA2IiwibmFtZSI6IlZlcmlmaWVkQWNjb3VudENvZGUiLCJudW1iZXIiOiI1MDYifSwiNTA3RG9vclBob25lIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZG9vclBob25lTmlnaHREZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkb29yUGhvbmVEYXkxRGVzdGluYXRpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImRvb3JQaG9uZURheTJEZXN0aW5hdGlvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA3LjEuMS4xMCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImRvb3JQaG9uZU5pZ2h0RGVzdGluYXRpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuMTIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJkb29yUGhvbmVOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjgiLCJuYW1lIjoiZG9vclBob25lVGVuYW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjMuLjMwIiwibmFtZSI6ImRvb3JQaG9uZUNhbGxUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRvb3JQaG9uZURheTFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRvb3JQaG9uZURheTJEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImRvb3JQaG9uZUVxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA3LjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjI0IiwibmFtZSI6ImRvb3JQaG9uZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA3LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDciLCJuYW1lIjoiRG9vclBob25lIiwibnVtYmVyIjoiNTA3In0sIjUwOERvb3JMb2NrQ29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJkb29yTG9ja1Bvc2l0aW9uT2ZCSU9VIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDguMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImRvb3JMb2NrUG9zaXRpb25PZnJERENCIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDguMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkb29yTG9ja0Nvbm5lY3Rpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDguMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZG9vckxvY2tOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwOC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA4IiwibmFtZSI6IkRvb3JMb2NrQ29udHJvbCIsIm51bWJlciI6IjUwOCJ9LCI1MDlUUk92ZXJyaWRlYnlTcGVlZERpYWwiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InRvbGxSZXN0cmljdGlvbk92ZXJyaWRlRHJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDkuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoidG9sbFJlc3RyaWN0aW9uT3ZlcnJpZGVGcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwOS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJ0b2xsUmVzdHJpY3Rpb25PdmVycmlkZUNvcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA5LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InRvbGxSZXN0cmljdGlvbk92ZXJyaWRlUXBsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDkuNCIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA5IiwibmFtZSI6IlRST3ZlcnJpZGVieVNwZWVkRGlhbCIsIm51bWJlciI6IjUwOSJ9LCI1MTBDT1NPdmVycmlkZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiY29zT3ZlcmlkZU5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiY29zT3ZlcmlkZURybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEwLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJjb3NPdmVyaWRlRnJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTAuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImNvc092ZXJpZGVDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiY29zT3ZlcmlkZVFwbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEwLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJjb3NPdmVyaWRlQ29zQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEwLjEuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiY29zT3ZlcmlkZUNvc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTAuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMCIsIm5hbWUiOiJDT1NPdmVycmlkZSIsIm51bWJlciI6IjUxMCJ9LCI1MTJTTURSZm9yU1lTVEVNIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzbWRyQW5pRmllbGRJbmRpY2F0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEyLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzbWRyVk1DYWxsSWRGaWVsZEluZGljYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTIuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNtZHJDYWxsZXJJZEZpZWxkSW5kaWNhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckNhcnJpYWdlUmV0dXJuQWRkaXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckFiYW5kb25lZENhbGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckJSZWNvcmRPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckF1dGhvcml6YXRpb25Db2RlT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTIuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMiIsIm5hbWUiOiJTTURSZm9yU1lTVEVNIiwibnVtYmVyIjoiNTEyIn0sIjUxM1NNRFJmb3JJTEciOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiaWxnU21kcklsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdTbWRyQlJlY29yZE91dHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnU21kckluY29taW5nQ2FsbFJlY29yZE91dHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEzLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnU21kckRpc3BsYXlTZWxlY3Rpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ1NtZHJEbmlzRmllbGRJbmRpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdTbWRyUW9zUmVjb3JkT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMiLCJuYW1lIjoiU01EUmZvcklMRyIsIm51bWJlciI6IjUxMyJ9LCI1MTRTTURSZm9yT0xHIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6Im9sZ1NtZHJPbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnU21kckJSZWNvcmRPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1NtZHJPdXRnb2luZ0NhbGxSZWNvcmRPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1NtZHJEaXNwbGF5U2VsZWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJvbGdTbWRyUW9zUmVjb3JkT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTQuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTQiLCJuYW1lIjoiU01EUmZvck9MRyIsIm51bWJlciI6IjUxNCJ9LCI1MTVSZWxheVNlcnZpY2UiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjExIiwibmFtZSI6ImJpb3VQb3J0VHlwZUdlbmVyaWNSZWxheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTEiLCJuYW1lIjoiYmlvdVBvcnRUeXBlR2VuZXJpY1JlbGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE1LjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMSIsIm5hbWUiOiJiaW91UG9ydFR5cGVHZW5lcmljUmVsYXkzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTUuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjExIiwibmFtZSI6ImJpb3VQb3J0VHlwZUdlbmVyaWNSZWxheTQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNS4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoiYmlvdUJJT1VDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTUuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNSIsIm5hbWUiOiJSZWxheVNlcnZpY2UiLCJudW1iZXIiOiI1MTUifSwiNTE2U3RhdGlvblNwZWVkRGlhbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN0YXRpb25TcGVlZERpYWxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNi4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIyIiwibmFtZSI6InN0YXRpb25TcGVlZERpYWxzSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNi4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uU3BlZWRETiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE2LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoic3RhdGlvblNwZWVkRGlhbFVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTYuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNiIsIm5hbWUiOiJTdGF0aW9uU3BlZWREaWFsIiwibnVtYmVyIjoiNTE2In0sIjUxN011bHRpcGxlQ2FsbGluZ0dyb3VwIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBWb2ljZU1haWxJRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBEZWxheTFUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBEZWxheTJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJtdWx0aXBsZUNhbGxpbmdHcm91cFBpbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTcuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ4IiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ0dyb3VwU3lzdGVtQ0ZJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOTYiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTciLCJuYW1lIjoiTXVsdGlwbGVDYWxsaW5nR3JvdXAiLCJudW1iZXIiOiI1MTcifSwiNTE4TXVsdGlwbGVDYWxsaW5nTWVtYmVycyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ01lbWJlcnNEZXN0aW5hdGlvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE4LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtdWx0aXBsZUNhbGxpbmdNZW1iZXJzRGVzdENhbGxUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTguMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjUiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nTWVtYmVyc0Rlc3RMaXN0SW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxOC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjk2IiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ01lbWJlcnNJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE4LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtdWx0aXBsZUNhbGxpbmdNZW1iZXJzRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTgiLCJuYW1lIjoiTXVsdGlwbGVDYWxsaW5nTWVtYmVycyIsIm51bWJlciI6IjUxOCJ9LCI1MTlNdWx0aXBsZUNhbGxpbmdEZWxldGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjk2IiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ0luZGV4RGVsZXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTkuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE5IiwibmFtZSI6Ik11bHRpcGxlQ2FsbGluZ0RlbGV0ZSIsIm51bWJlciI6IjUxOSJ9LCI1MjBMQ1JQYXJhbWV0ZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JQYXJhbURlZmF1bHRSb3V0aW5nUGxhbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIwLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxjclBhcmFtQ2FtcG9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjAuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zIiwibmFtZSI6ImxjclBhcmFtSG9tZUFyZWFDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjAuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIwIiwibmFtZSI6IkxDUlBhcmFtZXRlciIsIm51bWJlciI6IjUyMCJ9LCI1MjFMQ1JSb3V0aW5nUGxhbkFuYWx5c2lzVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyOCIsIm5hbWUiOiJsY3JBbmFseXNpc1BsYW5OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi4xOSIsIm5hbWUiOiJsY3JBbmFseXNpc0RpZ2l0cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIxLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjEiLCJuYW1lIjoiTENSUm91dGluZ1BsYW5BbmFseXNpc1RhYmxlIiwibnVtYmVyIjoiNTIxIn0sIjUyMkxDUkV4Um91dGluZ1BsYW5BbmFseXNpc1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyRXhjZXB0aW9uYWxSb3V0ZVBsYW5OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMi4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi4xOSIsIm5hbWUiOiJsY3JFeGNlcHRpb25hbERpZ2l0cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIyLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjIiLCJuYW1lIjoiTENSRXhSb3V0aW5nUGxhbkFuYWx5c2lzVGFibGUiLCJudW1iZXIiOiI1MjIifSwiNTIzTENSUm91dGVQbGFuU2NoZWR1bGVUYWJsZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjE2IiwibmFtZSI6ImxjclNjaGR1bGVTdGF0aW9uTGNyR3JvdXBOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMy4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTI4IiwibmFtZSI6ImxjclNjaGR1bGVSb3V0ZUNob2ljZVRhYmxlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjMuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JTY2hkdWxlVGFibGVUeXBlT2ZEYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMy4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoibGNyU2NoZHVsZVJvdXRlUGxhbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoibGNyU2NoZHVsZVRpbWVab25lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjMuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjMiLCJuYW1lIjoiTENSUm91dGVQbGFuU2NoZWR1bGVUYWJsZSIsIm51bWJlciI6IjUyMyJ9LCI1MjRMQ1JSb3V0ZUNob2ljZVRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5MyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5NCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5NSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5NiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VSb3V0ZURlZmluaXRpb25Qcmlvcml0eTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JSb3V0ZUNob2ljZVRhYmxlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjQuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNCIsIm5hbWUiOiJMQ1JSb3V0ZUNob2ljZVRhYmxlIiwibnVtYmVyIjoiNTI0In0sIjUyNUxDUlJvdXRlRGVmaW5pdGlvblRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoibGNyUm91dGVEZWZpbml0aW9uT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjUuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyOCIsIm5hbWUiOiJsY3JSb3V0ZURlZmluaXRpb25EaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI1LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImxjclJvdXRlRGVmaW5pdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI1LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjUiLCJuYW1lIjoiTENSUm91dGVEZWZpbml0aW9uVGFibGUiLCJudW1iZXIiOiI1MjUifSwiNTI2TENSRGlnaXRNb2RpZmljYXRpb25UYWJsZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JEaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjMiLCJuYW1lIjoibGNyRGlnaXRNb2RpZmljYXRpb25BZGRpdGlvbkF0VGFpbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI2LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjMiLCJuYW1lIjoibGNyRGlnaXRNb2RpZmljYXRpb25BZGRpdGlvbkluRnJvbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNi4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjAiLCJuYW1lIjoibGNyRGlnaXRNb2RpZmljYXRpb25EaWdpdFRvQmVEZWxldGVkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjYuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNiIsIm5hbWUiOiJMQ1JEaWdpdE1vZGlmaWNhdGlvblRhYmxlIiwibnVtYmVyIjoiNTI2In0sIjUyN0xDUlB1YmxpY0hvbGlkYXlDYWxlbmRhclRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjgiLCJuYW1lIjoicHVibGljSG9saWRheUNhbGVuZGFyRGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjcuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwdWJsaWNIb2xpZGF5Q2FsZW5kYXJGbGFnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjcuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjciLCJuYW1lIjoiTENSUHVibGljSG9saWRheUNhbGVuZGFyVGFibGUiLCJudW1iZXIiOiI1MjcifSwiNTI4TENSUHVibGljRGF5T2ZXZWVrTWFwcGluZ1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlTYXR1cmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlUaHVyc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlXZWRuZXNkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyOC4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGNyUHVibGljRGF5RnJpZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxjclB1YmxpY0RheU1vbmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlTdW5kYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyOC43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGNyUHVibGljRGF5VHVlc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjgiLCJuYW1lIjoiTENSUHVibGljRGF5T2ZXZWVrTWFwcGluZ1RhYmxlIiwibnVtYmVyIjoiNTI4In0sIjUyOUxDUlJvdXRlUGxhblNjaGVkdWxlVGFibGVUaW1lWm9uZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6ImxjclRpbWVab25lVHlwZU9mRGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjkuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoibGNyVGltZVpvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyOS4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImxjclRpbWVab25lVGltZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI5LjEuMS40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JUaW1lWm9uZVJvdXRlUGxhbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI5LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjkiLCJuYW1lIjoiTENSUm91dGVQbGFuU2NoZWR1bGVUYWJsZVRpbWVab25lIiwibnVtYmVyIjoiNTI5In0sIjUzMFRvbGxSZXN0cmljdGlvbkxDUlNjcmVlbmluZ1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjciLCJuYW1lIjoidHJMQ1J0YWJsZUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJMQ1J0YWJsZURtQWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ckxDUnRhYmxlU2V0Tm9TZXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyTENSdGFibGVUckFjdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJMQ1J0YWJsZUxjckFjdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJ0ckxDUnRhYmxlU2tpcExlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzAiLCJuYW1lIjoiVG9sbFJlc3RyaWN0aW9uTENSU2NyZWVuaW5nVGFibGUiLCJudW1iZXIiOiI1MzAifSwiNTMxVG9sbFJlc3RyaWN0aW9uTENSU2NyZWVuaW5nRm9yT0xHVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJ0ckxDUk9sZ0NvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoidHJMQ1JPbGdQYXVzZUluc2VydGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMxLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ckxDUk9sZ1RyQWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6InRyTENST2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoidHJMQ1JPbGdTa2lwTGVuZ3RoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyTENST2xnQ29kZVNldE5vU2V0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEiLCJuYW1lIjoiVG9sbFJlc3RyaWN0aW9uTENSU2NyZWVuaW5nRm9yT0xHVGFibGUiLCJudW1iZXIiOiI1MzEifSwiNTMyVG9sbFJlc3RyaWN0aW9uVGFibGVBbGxvd0RlbnkiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRvbGxSZXN0cmljdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMyLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjE2IiwibmFtZSI6InRvbGxSZXN0cmljdGlvbkRybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzIiLCJuYW1lIjoiVG9sbFJlc3RyaWN0aW9uVGFibGVBbGxvd0RlbnkiLCJudW1iZXIiOiI1MzIifSwiNTMzVG9sbFJlc3RyaWN0aW9uVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJ0clRhYmxlRHJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJ0clRhYmxlQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMzLjEuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0clRhYmxlQ29kZUZsYWciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMyIsIm5hbWUiOiJUb2xsUmVzdHJpY3Rpb25UYWJsZSIsIm51bWJlciI6IjUzMyJ9LCI1MzRFeGNlcHRpb25hbFRvbGxSZXN0cmljdGlvblRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleGNlcHRpb25hbFRyQ29kZUZsYWciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJleGNlcHRpb25hbERybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjEzIiwibmFtZSI6ImV4Y2VwdGlvbmFsVHJDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzQuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNCIsIm5hbWUiOiJFeGNlcHRpb25hbFRvbGxSZXN0cmljdGlvblRhYmxlIiwibnVtYmVyIjoiNTM0In0sIjUzNUxDUlBETkF1dGhDb2RlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIiLCJuYW1lIjoibGNyQWNjZXNzQ29kZUEwMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMiIsIm5hbWUiOiJsY3JBY2Nlc3NDb2RlQTAyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzUuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyIiwibmFtZSI6ImxjckFjY2Vzc0NvZGVBMDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIiLCJuYW1lIjoibGNyQWNjZXNzQ29kZUEwNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMiIsIm5hbWUiOiJsY3JBY2Nlc3NDb2RlQTA1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzUuNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyIiwibmFtZSI6ImxjckFjY2Vzc0NvZGVBMDYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIiLCJuYW1lIjoibGNyQWNjZXNzQ29kZUEwNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMiIsIm5hbWUiOiJsY3JBY2Nlc3NDb2RlQTA4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzUuOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibGNyQWNjZXNzQ29kZVBETiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNSIsIm5hbWUiOiJMQ1JQRE5BdXRoQ29kZSIsIm51bWJlciI6IjUzNSJ9LCI1NDBBQ0RQaWxvdEROQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiYWNkUGlsb3RBZnRlclNoaWZ0Rm9yd2FyZERlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJhY2RQaWxvdFZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImFjZFBpbG90QWZ0ZXJTaGlmdEZvcndhcmRUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiYWNkUGlsb3REbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTQwLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAiLCJuYW1lIjoiQUNEUGlsb3RETkFzc2lnbiIsIm51bWJlciI6IjU0MCJ9LCI1NDFBQ0RQaWxvdERORGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkZWxldGVBY2RQaWxvdERuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTQxIiwibmFtZSI6IkFDRFBpbG90RE5EZWxldGUiLCJudW1iZXIiOiI1NDEifSwiNTUwRW1lcmdlbmN5Q2FsbEdyb3VwIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE51bSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZW1lcmdlbmN5R3JvdXBPbGcxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTAuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE9sZzIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImVtZXJnZW5jeUdyb3VwT2xnMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZW1lcmdlbmN5R3JvdXBPbGc0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTAuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE9sZzUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImVtZXJnZW5jeUdyb3VwT2xnNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwLjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZW1lcmdlbmN5R3JvdXBPbGc3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTAuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE9sZzgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwIiwibmFtZSI6IkVtZXJnZW5jeUNhbGxHcm91cCIsIm51bWJlciI6IjU1MCJ9LCI1NTFFbWVyZ2VuY3lOZXR3b3JrQWNjZXNzQ29kZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiZW1lck5ldHdvcmtBY2Nlc3NDb2RlQWNjZXNzQ29kZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJlbWVyTmV0d29ya0FjY2Vzc0NvZGVBY2Nlc3NDb2RlMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUxLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImVtZXJOZXR3b3JrQWNjZXNzQ29kZUFjY2Vzc0NvZGUzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUxIiwibmFtZSI6IkVtZXJnZW5jeU5ldHdvcmtBY2Nlc3NDb2RlIiwibnVtYmVyIjoiNTUxIn0sIjU3MEFjY291bnRDb2RlRGlnaXRMZW5ndGgiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjQuLjE1IiwibmFtZSI6ImFjY291bnRDb2RlTGVuZ3RoSW5wdXREaWdpdExlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTcwLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjQuLjE1IiwibmFtZSI6ImFjY291bnRDb2RlTGVuZ3RoVmVyaWZpZWREaWdpdExlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTcwLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImFjY291bnRDb2RlTGVuZ3RoQ0ZFeHRlcm5hbFdpdGhGb3JjZWRBY2MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MC4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTcwIiwibmFtZSI6IkFjY291bnRDb2RlRGlnaXRMZW5ndGgiLCJudW1iZXIiOiI1NzAifSwiNTcxRXhOdW1iZXJPZkZvcmNlZEFjY291bnRDb2RlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzEiLCJuYW1lIjoiRXhOdW1iZXJPZkZvcmNlZEFjY291bnRDb2RlIiwibnVtYmVyIjoiNTcxIn0sIjU3M0Rvb3JQaG9uZURlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjQiLCJuYW1lIjoiZG9vclBob25lRGVsZXRlRG9vclBob25lTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzMuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTczIiwibmFtZSI6IkRvb3JQaG9uZURlbGV0ZSIsIm51bWJlciI6IjU3MyJ9LCI1NzZEb29yUGhvbmVSaW5nSW5OaWdodE1vZGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI0IiwibmFtZSI6ImRvb3JQaG9uZVJpbmdQYWdpbmdHcnBOdW0iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3Ni4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiZG9vclBob25lUmluZ1RlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzYiLCJuYW1lIjoiRG9vclBob25lUmluZ0luTmlnaHRNb2RlIiwibnVtYmVyIjoiNTc2In0sIjU3N0NhbGxIaXN0b3J5U3RvclRlcm1pbmFsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoiY2FsbEhpc3RvcnlDaXJjdWl0VHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc3LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJjYWxsSGlzdG9yeVRlcm1pbmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzcuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3NyIsIm5hbWUiOiJDYWxsSGlzdG9yeVN0b3JUZXJtaW5hbCIsIm51bWJlciI6IjU3NyJ9LCI1NzlWb2ljZU1haWxEYXRhRm9yU3lzdGVtIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2bVN5c3RlbUFwcGxpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6InZtU3lzdGVtTGVuZ3RoT2ZWbUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtT3V0cHV0Q2xhc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1EaWFsU2VuZFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidm1TeXN0ZW1DZkJ1c3lSZWNvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjciLCJuYW1lIjoidm1TeXN0ZW1UcmFuc2ZlclZtRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4xNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMi4uMjAiLCJuYW1lIjoidm1TeXN0ZW1DYWxsZXJOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJ2bVN5c3RlbUNlbnRyYWxpemVkVm1DYWxsQmFja0RuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTAiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtTWVzc2FnZURlc2tObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi4yMCIsIm5hbWUiOiJ2bVN5c3RlbUNsYXNzQW5pRG5pc0NhbGxlck51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjE5Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2bVN5c3RlbUNmQWxsQ2FsbFJlY29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2bVN5c3RlbURpcmVjdHJ5UmVjb3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InZtU3lzdGVtQ2ZOb0Fuc3dlclJlY29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjEzIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2bVN5c3RlbVJldHJpZXZpbmdNZXNzYWdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtQ2FuY2VsT2ZNdyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2bVN5c3RlbUF1dG9DYW5jZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1MY2RDb250cm9sT2ZWb2ljZU1haWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1WTWNhbGxpZEJ5REMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4xOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoidm1TeXN0ZW1CbGFua051bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtVk1Db21wYXRpYmlsaXR5Rm9yREtUNTAwMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1WbVNtZGlUaW1lU3RhbXBQYWNrZXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtVm1TbWRpVFJlY29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5IiwibmFtZSI6IlZvaWNlTWFpbERhdGFGb3JTeXN0ZW0iLCJudW1iZXIiOiI1NzkifSwiNTgwVm9pY2VNYWlsRGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1EYXRhQlRvbmVTZW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2bURhdGFBRFRvbmVTZW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoidm1EYXRhRE4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1EYXRhVk1Ub1ZNQmxvY2tpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtRGF0YUNvbnRyb2xNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtRGF0YUVuZFRvRW5kU2lnbmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAiLCJuYW1lIjoiVm9pY2VNYWlsRGF0YSIsIm51bWJlciI6IjU4MCJ9LCI2NTBCZWhpbmRDb25uZWN0aW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImJlaGluZE9sZ051bSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiZWhpbmRCZWhpbmRDb25uZWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiZWhpbmRBY2NvdW50Q2VudHJleEZlYXR1cmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MCIsIm5hbWUiOiJCZWhpbmRDb25uZWN0aW9uIiwibnVtYmVyIjoiNjUwIn0sIjY1MVByaXZhdGVSb3V0ZVBsYW5BbmFseXNpc1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoicHJpdmF0ZUFuYWx5c2lzTm9kZUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTEuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVBbmFseXNpc1JvdXRlQ2hvaWNlVGFibGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUxIiwibmFtZSI6IlByaXZhdGVSb3V0ZVBsYW5BbmFseXNpc1RhYmxlIiwibnVtYmVyIjoiNjUxIn0sIjY1M1ByaXZhdGVSb3V0ZUNob2ljZVRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlQ2hvaWNlVGJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVSb3V0ZUNob2ljZVRibERlZkluZGV4MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUzLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJwcml2YXRlUm91dGVDaG9pY2VUYmxEZWZJbmRleDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1My4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlQ2hvaWNlVGJsRGVmSW5kZXgzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTMuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVSb3V0ZUNob2ljZVRibERlZkluZGV4NCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUzLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJwcml2YXRlUm91dGVDaG9pY2VUYmxEZWZJbmRleDUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1My4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlQ2hvaWNlVGJsRGVmSW5kZXg2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTMuMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MyIsIm5hbWUiOiJQcml2YXRlUm91dGVDaG9pY2VUYWJsZSIsIm51bWJlciI6IjY1MyJ9LCI2NTRQcml2YXRlUm91dGVEZWZpbml0aW9uVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVSb3V0ZURlZmluaXRpb25EaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU0LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlRGVmaW5pdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoicHJpdmF0ZVJvdXRlRGVmaW5pdGlvbk9sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU0LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTQiLCJuYW1lIjoiUHJpdmF0ZVJvdXRlRGVmaW5pdGlvblRhYmxlIiwibnVtYmVyIjoiNjU0In0sIjY1NVByaXZhdGVEaWdpdE1vZGlmaWNhdGlvblRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjMiLCJuYW1lIjoicHJpdmF0ZURpZ2l0TW9kaWZpY2F0aW9uQWRkaXRpb25JbkZyb250Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTUuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6InByaXZhdGVEaWdpdE1vZGlmaWNhdGlvbkRpZ2l0VG9CZURlbGV0ZWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1NS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjY0IiwibmFtZSI6InByaXZhdGVEaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU1LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTUiLCJuYW1lIjoiUHJpdmF0ZURpZ2l0TW9kaWZpY2F0aW9uVGFibGUiLCJudW1iZXIiOiI2NTUifSwiNjU2Tm9kZUlkIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJub2RlSURQcmltYXJ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlEUHJpbWFyeU92ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoibm9kZUlEMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU2LjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6Im5vZGVJRDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1Ni41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJub2RlSUQ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlEMk92ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlEM092ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlENE92ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU2IiwibmFtZSI6Ik5vZGVJZCIsIm51bWJlciI6IjY1NiJ9LCI2NTduZXR3b3JrQ09TbWFwcGluZyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibmV0d29ya0Nvc1RHQUNPdmVyUmlkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU3LjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibmV0d29ya0Nvc09yZ0ludm9rZU9jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU3LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjMyIiwibmFtZSI6Im5ldHdvcmtDb3NNYXBwaW5nSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1Ny4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoibmV0d29ya0Nvc0xvY2FsQ29zSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1Ny4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibmV0d29ya0Nvc0Nvc092ZXJyaWRlQ2hhbmdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTcuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJuZXR3b3JrQ29zUmVnU3lzdGVtU3BlZWREaWFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTcuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTciLCJuYW1lIjoibmV0d29ya0NPU21hcHBpbmciLCJudW1iZXIiOiI2NTcifSwiNjU4bmV0d29ya0RSTG1hcHBpbmciOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21EcmwzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21Ecmw2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsOSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4xMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMTAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDExIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21EcmwxMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21EcmwxNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMTYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yIiwibmFtZSI6Im5ldHdvcmtEcmxUYWJsZVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4IiwibmFtZSI6Im5ldHdvcmtEUkxtYXBwaW5nIiwibnVtYmVyIjoiNjU4In0sIjY1OW5ldHdvcmtGUkxtYXBwaW5nIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21GcmwyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21Gcmw1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21Gcmw4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDEwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21GcmwxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsMTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDEzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjE0Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21GcmwxNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsMTUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDE2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMiIsIm5hbWUiOiJuZXR3b3JrRnJsVGFibGVUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OSIsIm5hbWUiOiJuZXR3b3JrRlJMbWFwcGluZyIsIm51bWJlciI6IjY1OSJ9LCI2NjBuZXR3b3JrUVBMbWFwcGluZyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGw0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGw3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsOCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGw5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsMTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDEyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsMTQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuMTUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDE1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjE2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoibmV0d29ya1FwbFRhYmxlVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAiLCJuYW1lIjoibmV0d29ya1FQTG1hcHBpbmciLCJudW1iZXIiOiI2NjAifSwiNjYxTmV0d29ya0RuVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6Im5ldHdvcmtEblRhYmxlTm9kZUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjEuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJuZXR3b3JrRG5UYWJsZU5ldHdvcmtEbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYxLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjEiLCJuYW1lIjoiTmV0d29ya0RuVGFibGUiLCJudW1iZXIiOiI2NjEifSwiNjcwUmVtb3RlTm9kZURhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJyZW1vdGVOb2RlSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjU1MzUiLCJuYW1lIjoicmVtb3RlTm9kZVBvcnRObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcwLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InJlbW90ZU5vZGVJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MC4xLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzAiLCJuYW1lIjoiUmVtb3RlTm9kZURhdGEiLCJudW1iZXIiOiI2NzAifSwiNjcxSXBBZGRyZXNzQ29udmVydEZvclByaXZhdGVOV092ZXJJUCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcEFkZHJlc3NDb252ZXJ0VGFibGVJcEFkZHJlc3NSb3V0ZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MS4xLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwQWRkcmVzc0NvbnZlcnRUYWJsZUlwQWRkcmVzc1JvdXRlMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcxLjEuMS4zIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBBZGRyZXNzQ29udmVydFRhYmxlSXBBZGRyZXNzUm91dGUzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzEuMS4xLjQiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcEFkZHJlc3NDb252ZXJ0VGFibGVJcEFkZHJlc3NSb3V0ZTQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MS4xLjEuNSIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwQWRkcmVzc0NvbnZlcnRUYWJsZUlwQWRkcmVzc1JvdXRlNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcxLjEuMS42Iiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBBZGRyZXNzQ29udmVydFRhYmxlSXBBZGRyZXNzUm91dGU2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzEuMS4xLjciLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi42IiwibmFtZSI6ImlwQWRkcmVzc0NvbnZlcnRUYWJsZU5vZGVJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcxLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzEiLCJuYW1lIjoiSXBBZGRyZXNzQ29udmVydEZvclByaXZhdGVOV092ZXJJUCIsIm51bWJlciI6IjY3MSJ9LCI2NzJOb2RlSWREZXRhaWxJbmZvcm1hdGlvbkZvclByaXZhdGVOV092ZXJJUCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb0lwUHJvdG9jb2xUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvRFRNRlRyYW5zbGF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb05vZGVJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb1ZvaWNlUGFja2V0Q29uZmlnVGFibGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvQ2hhbm5lbE5lZ290aWF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvQXVkaW9Db2RlYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb1RDUENvbm5lY3Rpb25SZWxlYXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6Im5vZGVJZERldGFpbEluZm9FOTExUHJpb3JpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3Mi4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb0Zhc3RDb25uZWN0aW9uUHJvY2VkdXJlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb1QzOFByb3RvY29sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvVDM4VGFibGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im5vZGVJZERldGFpbEluZm9UMzhTdWJzdGl0dXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3Mi4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIiLCJuYW1lIjoiTm9kZUlkRGV0YWlsSW5mb3JtYXRpb25Gb3JQcml2YXRlTldPdmVySVAiLCJudW1iZXIiOiI2NzIifSwiNjczTm9kZUlkQ2hlY2tBbmREZWxldGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNoZWNrRGVsZXRlTm9kZUlkU3RhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3My4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJjaGVja0RlbGV0ZU5vZGVJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjczLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzMiLCJuYW1lIjoiTm9kZUlkQ2hlY2tBbmREZWxldGUiLCJudW1iZXIiOiI2NzMifSwiNjc0UmVtb3RlTm9kZUlwdUlwQWRkcmVzcyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi42IiwibmFtZSI6InJlbW90ZU5vZGVJcHVOb2RlSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3NC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyZW1vdGVOb2RlSXB1SXBBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzQuMS4xLjIiLCJzeW50YXgiOiJJcEFkZHJlc3MifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjc0IiwibmFtZSI6IlJlbW90ZU5vZGVJcHVJcEFkZHJlc3MiLCJudW1iZXIiOiI2NzQifSwiODAxTEFOIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoibGFuV3JpdGVSZXRyeUNvdW50ZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3MxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3MyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3MzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3M0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNCIsIm5hbWUiOiJsYW5Qb3J0TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxhbkNvbm5lY3Rpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxhbkVtcGxveW1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NTUzNSIsIm5hbWUiOiJsYW5DbGllbnRQb3J0Tm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY1NTM1IiwibmFtZSI6ImxhblBvcnRObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAxLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsYW5TeW5jaHJvbml6YXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJsYW5SZWFkUmV0cnlDb3VudGVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGFuQ2FsbGVyTmFtZVNldCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAxLjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMSIsIm5hbWUiOiJMQU4iLCJudW1iZXIiOiI4MDEifSwiODAzSU9Mb2dpY2FsRGV2aWNlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNCIsIm5hbWUiOiJpb1BvcnROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMy4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIzIiwibmFtZSI6ImlvTG9naWNhbERldmljZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAzLjEuMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaW9QaHlzaWNhbERldmljZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAzIiwibmFtZSI6IklPTG9naWNhbERldmljZSIsIm51bWJlciI6IjgwMyJ9LCI4MDRSUzIzMkMiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InJzMjMyY1Bhcml0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicnMyMzJjQmF1ZFJhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwNC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi40IiwibmFtZSI6InJzMjMyY1BoeXNpY2FsUG9ydE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyczIzMmNEYXRhTGVuZ3RoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyczIzMmNGbG93Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InJzMjMyY01heFdhaXRUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDQiLCJuYW1lIjoiUlMyMzJDIiwibnVtYmVyIjoiODA0In0sIjkxOUFsYXJtQ29udHJvbEZvclN5c3RlbSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUxhYmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicmVzZXRDdXJyZW50QWxhcm1TdW1tYXJ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYWxhcm1TdW1tYXJ5VHJhcEF2YWlsYWJpbGl0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjYuMTEuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42IiwibmFtZSI6IkFsYXJtQ29udHJvbEZvclN5c3RlbSIsIm51bWJlciI6IjkxOSJ9LCI5MjBBbGFybUNvbnRyb2xGb3JTbG90Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjQiLCJuYW1lIjoiYWxhcm1QZXJjZXB0aW9uRXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjguMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYWxhcm1QZXJjZXB0aW9uQXZhaWxhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi44LjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjgiLCJuYW1lIjoiQWxhcm1Db250cm9sRm9yU2xvdCIsIm51bWJlciI6IjkyMCJ9LCI5MjFUcmFmZmljTWVhc3VyZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZURpZElsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlRGlkQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjMuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi43IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlRGlkRGlkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4zLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vRGlkSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi40LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlTm9EaWRPck5vdERldGVybWluZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuNC4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vRGlkQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjQuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVJbGdBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6InRyYWZmaWNNZWFzdXJlSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVPbGdBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMi4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6InRyYWZmaWNNZWFzdXJlT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4yLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTFBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vbldvcmtpbmdEYXlab25lMkFjdGl2YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlTm9uV29ya2luZ0RheVpvbmUzQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVNZW1vcnlDYXJkT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVIb2xpZGF5Wm9uZTFTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMlN0YXJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yNiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlSG9saWRheVpvbmUzU3RhcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjI5Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVXb3JraW5nRGF5Wm9uZTFFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjYiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVdvcmtpbmdEYXlab25lMkVuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuOSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlV29ya2luZ0RheVpvbmUzRW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4xMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUNvbmZlcmVuY2VBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMUFjdGl2YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlSG9saWRheVpvbmUyQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVIb2xpZGF5Wm9uZTNBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVdvcmtpbmdEYXlab25lMVN0YXJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVXb3JraW5nRGF5Wm9uZTJTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuOCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlV29ya2luZ0RheVpvbmUzU3RhcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjExIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTFFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE1Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTJFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE4Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTNFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjIxIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVEdG1mQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVXb3JraW5nRGF5Wm9uZTFBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlV29ya2luZ0RheVpvbmUyQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVdvcmtpbmdEYXlab25lM0FjdGl2YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlTm9uV29ya2luZ0RheVpvbmUxU3RhcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE0Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTJTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTciLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vbldvcmtpbmdEYXlab25lM1N0YXJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yMCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlSW50ZW5zaXR5VW5pdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMzEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMUVuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMkVuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjciLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lM0VuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMzAiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTEwMCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUh1bnRpbmdHcm91cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuNS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlSHVudGluZ0dyb3VwQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjUuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMyIsIm5hbWUiOiJUcmFmZmljTWVhc3VyZSIsIm51bWJlciI6IjkyMSJ9LCI5MjJUcmFmZmljUmVwb3J0Q29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoidHJhZmZpY1JlcG9ydExhc3REYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjIiLCJuYW1lIjoidHJhZmZpY1JlcG9ydExhc3RUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMy41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY1JlcG9ydEZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMy4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoidHJhZmZpY1JlcG9ydEZpcnN0RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIyIiwibmFtZSI6InRyYWZmaWNSZXBvcnRGaXJzdFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNSZXBvcnRTdGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjMuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4zIiwibmFtZSI6IlRyYWZmaWNSZXBvcnRDb250cm9sIiwibnVtYmVyIjoiOTIyIn0sIkNhU25tcFJlZyI6eyJmaWVsZHMiOltdLCJncm91cF9vaWQiOm51bGwsIm5hbWUiOiJDYVNubXBSZWciLCJudW1iZXIiOm51bGx9LCJNSVBVVlBDb25maWciOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZQQ29uZmlnRGF0YUZvclN5c3RlbSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJtaXB1VlBDb25maWdWZXJzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZwQ29uZmlnRGF0YUZvckVhY2hEZXZpY2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjkuMi4xLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xOSIsIm5hbWUiOiJtaXB1RGVzdERldmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4yLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNSIsIm5hbWUiOiJtaXB1U3JjRGV2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjIuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZQQ29uZmlnRGF0YUZvclN5c3RlbSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJtaXB1VlBDb25maWdWZXJzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZwQ29uZmlnRGF0YUZvckVhY2hEZXZpY2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjkuMi4xLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xOSIsIm5hbWUiOiJtaXB1RGVzdERldmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4yLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNSIsIm5hbWUiOiJtaXB1U3JjRGV2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjIuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjkuMSIsIm5hbWUiOiJNSVBVVlBDb25maWciLCJudW1iZXIiOm51bGx9LCJQZXJzb25hbEFkbWluIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQnVzeU5vQW5zd2VyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkV4dENhbGxDRkJ1c3lOb0Fuc3dlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZBbGxTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5FeHRDYWxsQ0ZBbGxTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZCdXN5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGQnVzeVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkRuZFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGTm9BbnN3ZXJEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjE3Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiOC4uNjAiLCJuYW1lIjoicGVyc29uYWxBZG1pbkFueUNhbGxDRk5vQW5zd2VyVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiI4Li42MCIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGTm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGTm9BbnN3ZXJEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjEzIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoicGVyc29uYWxBZG1pbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZOb0Fuc3dlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkV4dENhbGxDRk5vQW5zd2VyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6InBlcnNvbmFsQWRtaW5DYWxsSGlzdG9yeVJlY29yZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGQnVzeU5vQW5zd2VyRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQWxsRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGQWxsRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjguLjYwIiwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZCdXN5Tm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjguLjYwIiwibmFtZSI6InBlcnNvbmFsQWRtaW5FeHRDYWxsQ0ZCdXN5Tm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQnVzeU5vQW5zd2VyRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQnVzeURlc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMTIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoicGVyc29uYWxBZG1pbkV4dENhbGxDRkJ1c3lEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjE2Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoicGVyc29uYWxBZG1pbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5TGF0ZXN0Q2FsbGVyTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJwZXJzb25hbEFkbWluQ2FsbEhpc3RvcnlMYXRlc3RDYWxsZXJOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5TGF0ZXN0VGVybWluYXRlRGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5DYWxsSGlzdG9yeUxhdGVzdFRlcm1pbmF0ZVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJwZXJzb25hbEFkbWluRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQ2FsbEhpc3RvcnlQcmV2aW91c0NhbGxlck5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjAiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5UHJldmlvdXNDYWxsZXJOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5UHJldmlvdXNUZXJtaW5hdGVEYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjMwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5UHJldmlvdXNUZXJtaW5hdGVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMzEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQiLCJuYW1lIjoiUGVyc29uYWxBZG1pbiIsIm51bWJlciI6bnVsbH0sImFsYXJtIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImFsYXJtU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InJlc3RhcnRSZWFzb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NiIsIm5hbWUiOiJyZWFzb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjIuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InJlYXNvbk5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjIuMi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjU2IiwibmFtZSI6InJlYXNvbkluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi4yLjIuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiYWxhcm1UaW1lU3RhbXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjIuMi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNiIsIm5hbWUiOiJhbGFybSIsIm51bWJlciI6bnVsbH0sImJhY2t1cERhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmFja3VwU3RhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjcuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTA0ODU3NiIsIm5hbWUiOiJjdXJyZW50RGF0YSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNy4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiYWNrdXBGdW5jdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNy4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMDQ4NTc2IiwibmFtZSI6ImFsbERhdGEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjcuNCIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNyIsIm5hbWUiOiJiYWNrdXBEYXRhIiwibnVtYmVyIjpudWxsfSwiY29tbXVuaXR5TmFtZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMiIsIm5hbWUiOiJjbW5NYW5hZ2VFbXB0eVN0YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNubXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjMiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic25tcEFkbWluTGV2ZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzbm1wUHJpdmlsZWdlcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMS4yLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJzbm1wQ29tbXVuaXR5SUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoic25tcENvbW11bml0eU5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xIiwibmFtZSI6ImNvbW11bml0eU5hbWUiLCJudW1iZXIiOm51bGx9LCJjb21wb25lbnQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtYWluQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6Im1haW5DcHVDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNpcFRydW5rQ3BuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4yMS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2lwVHJ1bmtDcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua0NwblNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4yMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFRydW5rQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwVHJ1bmtDcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpcFN0YXRpb25DcG5EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTguMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE4LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiYmFja3VwTWVtb3J5Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImJhY2t1cE1lbW9yeVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMiIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJnZW5lcmFsTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImdlbmVyYWxNZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOSIsIm5hbWUiOiJkMUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQxQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkMUMySXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMUMySXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkMUMySXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMklwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMlBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMyUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUzU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1NFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU0Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkNEMxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJkNEMySXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkNEMySXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiZDVDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDVDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ1QzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDVDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzJJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImQ1QzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMklwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDVDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ1QzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUMyUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDVDMlBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1NkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU2U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzFJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImQ2QzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQ2QzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNkMxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ2QzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImQ2QzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMklwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguNC44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQ2QzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNkMySXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzJQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ2QzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJsYW5Db250cm9sbGVyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImxhbkNvbnRyb2xsZXJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJjdGlTZXJ2ZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4zLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImN0aVNlcnZlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4zLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY3RpU2VydmVyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4zLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJjb29saW5nRmFuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIwLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImNvb2xpbmdGYW5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIwLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21hcnRNZWRpYVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWFydE1lZGlhQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InByb2dyYW1NZW1vcnlTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicHJvZ3JhbU1lbW9yeUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzZXJpYWxTdWJDcHVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTAuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU3ViQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoic21kaVZtc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjMuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21kaVZtc1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC4zLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21kaVZtc0NvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTAuMy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNlcmlhbFNtZHJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtb2RlbVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtb2RlbUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwY21TdWJDcHVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwY21TdWJDcHVDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEiLCJuYW1lIjoiY29tcG9uZW50IiwibnVtYmVyIjpudWxsfSwiY29tcG9uZW50X0NfRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNpcFRydW5rQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoic2lwVHJ1bmtDcG5TZXJ2aWNlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBUcnVua0NwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImlwVHJ1bmtDcG5DaEdyb3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlwU3RhdGlvbkNwbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwU3RhdGlvbkNwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOSIsIm5hbWUiOiJkMUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQxQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDFDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDNDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDNDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDNDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDRDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDRDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMSIsIm5hbWUiOiJjb21wb25lbnRfQ19EIiwibnVtYmVyIjpudWxsfSwiY29tcG9uZW50X0QiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtYWluQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6Im1haW5DcHVDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNpcFRydW5rQ3BuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2lwVHJ1bmtDcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua0NwblNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFRydW5rQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwVHJ1bmtDcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpcFN0YXRpb25DcG5EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiYmFja3VwTWVtb3J5Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImJhY2t1cE1lbW9yeVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMiIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE1LjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTUuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJnZW5lcmFsTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImdlbmVyYWxNZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOSIsIm5hbWUiOiJkMUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQxQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkMUMySXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMUMySXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkMUMySXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMklwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMlBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMyUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUzU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1NFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU0Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkNEMxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibGFuQ29udHJvbGxlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJsYW5Db250cm9sbGVyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiY3RpU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJjdGlTZXJ2ZXJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImN0aVNlcnZlckNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY29vbGluZ0ZhblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJjb29saW5nRmFuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNtYXJ0TWVkaWFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21hcnRNZWRpYUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwcm9ncmFtTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicHJvZ3JhbU1lbW9yeUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNlcmlhbFN1YkNwdVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNlcmlhbFN1YkNwdUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoic21kaVZtc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWRpVm1zU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNtZGlWbXNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kckNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTIuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicGNtU3ViQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicGNtU3ViQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xIiwibmFtZSI6ImNvbXBvbmVudF9EIiwibnVtYmVyIjpudWxsfSwiY29tcG9uZW50X1BfRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJiYWNrdXBNZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjExLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiYmFja3VwTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjExLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImNvb2xpbmdGYW5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE4LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY29vbGluZ0ZhblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiY3RpU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY3RpU2VydmVyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4zLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6ImN0aVNlcnZlckluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE0LjMuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY3RpU2VydmVyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE0LjMuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkMUMxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQxQzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiZDFDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDFDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQyQzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQyQzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkM0MxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDNDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQ0QzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQ0QzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1M1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU0Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTRTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJnZW5lcmFsTWVtb3J5Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImdlbmVyYWxNZW1vcnlTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTAuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpcFN0YXRpb25DcG5EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBTdGF0aW9uQ3BuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXBTdGF0aW9uQ3BuRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTYuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBTdGF0aW9uQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwVHJ1bmtDcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBUcnVua0NwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6InNpcFRydW5rQ3BuU2VydmljZUluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzaXBUcnVua0NwbkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua0NwblNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzaXBUcnVua0NwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImxhbkNvbnRyb2xsZXJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE0LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibGFuQ29udHJvbGxlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtYWluQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6Im1haW5DcHVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTIuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoibmV0d29ya0Nsb2NrQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibmV0d29ya0Nsb2NrU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE1LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InBjbVN1YkNwdUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InBjbVN1YkNwdVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InByb2dyYW1NZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwcm9ncmFtTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kckNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU3ViQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU3ViQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21hcnRNZWRpYUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWFydE1lZGlhU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEzLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJzbWRpVm1zSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWRpVm1zQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoic21kaVZtc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWRpVm1zU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjExIiwibmFtZSI6ImNvbXBvbmVudF9QX0QiLCJudW1iZXIiOm51bGx9LCJjb25maWRlbnRpYWxDb250cm9sIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiY2hhbGxlbmdlU3RyaW5nIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjgiLCJuYW1lIjoiY29uZmlkZW50aWFsQ29udHJvbCIsIm51bWJlciI6bnVsbH0sImNvbmZsaWN0Q29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJjb25mbGljdFNlY3VyaXR5SW5mbyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEuMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb25mbGljdFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29uZmxpY3RTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yIiwibmFtZSI6ImNvbmZsaWN0R3JvdXBOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMSIsIm5hbWUiOiJjb25mbGljdENvbnRyb2wiLCJudW1iZXIiOm51bGx9LCJkb3NDb21tYW5kIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkb3NPcGVyYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjQuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoianVkZ2VPZkNvbXBsZXRpb25Eb3NDb21tYW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy40LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy40IiwibmFtZSI6ImRvc0NvbW1hbmQiLCJudW1iZXIiOm51bGx9LCJlcnJvckFsYXJtTG9nIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJleHBhbmRMb2dNYW5hZ2VtZW50SW5mbyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoibG9nTWFuYWdlbWVudEluZm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJrZXlPcmdDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEwLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQwOTYiLCJuYW1lIjoic2VhcmNoTmV4dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjEwIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjksImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDA5NiIsIm5hbWUiOiJzZWFyY2hGaXJzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjkiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi45OTk5OTk5OTkiLCJuYW1lIjoia2V5RXJyb3JDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjEyIiwibmFtZSI6ImtleVN0YXJ0RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMDAwIiwibmFtZSI6InNlYXJjaE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjk5IiwibmFtZSI6ImtleUVuZFJhbmtDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOTkiLCJuYW1lIjoia2V5U3RhcnRSYW5rQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoic2VhcmNoUmVzdWx0TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjEyIiwibmFtZSI6ImtleUVuZERhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMSIsIm5hbWUiOiJlcnJvckFsYXJtTG9nIiwibnVtYmVyIjpudWxsfSwiZXJyb3JTdGF0dXMiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDI5NDk2NzI5NSIsIm5hbWUiOiJlcnJvckNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4yLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4yIiwibmFtZSI6ImVycm9yU3RhdHVzIiwibnVtYmVyIjpudWxsfSwiZXZlbnRUcmFjZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY2hhbmdlU2lkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjIuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoianVkZ2VPZkNvbXBsZXRpb25DaGFuZ2VTaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjEuMi4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibWVzc2FnZVRyYWNlQ2F0ZWdvcnkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtZXNzYWdlVHJhY2VTdGFydFN0b3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMS4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoibWVzc2FnZVRyYWNlU2l6ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJqdWRnZU9mQ29tcGxldGlvbk1lc3NhZ2VUcmFjZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5UcnVua0FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjMuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOm51bGwsIm5hbWUiOiJldmVudFRyYWNlUG9ydFRyYWNlS2luZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4yLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXZlbnRUcmFjZVBvcnRUcmFjZUxldmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjIuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZXZlbnRUcmFjZVBvcnRTbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjIuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJldmVudFRyYWNlUG9ydFBvcnROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMi4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyIiwibmFtZSI6ImV2ZW50VHJhY2VQb3J0Q2FiaW5ldE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4yLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjEuMiIsIm5hbWUiOiJldmVudFRyYWNlIiwibnVtYmVyIjpudWxsfSwiZmlsZURhdGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6ImVyckFsbU5tbEZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6ImVyckFsbUV4cEZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6ImRrdEFkbUZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6InNucEFkbUZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMDAiLCJuYW1lIjoiZXJyQWxtTm1sRmlsZURhdGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC4yLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbU5tbEZpbGVOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjIuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbU5tbENyZWF0ZURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuMi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiZXJyQWxtTm1sTW9kaWZ5RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC4yLjEuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMDAiLCJuYW1lIjoiZXJyQWxtRXhwRmlsZURhdGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC40LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbUV4cEZpbGVOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjQuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbUV4cENyZWF0ZURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuNC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiZXJyQWxtRXhwTW9kaWZ5RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC40LjEuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJka3RBZG1GaWxlTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC44LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJka3RBZG1DcmVhdGVEYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImRrdEFkbU1vZGlmeURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuOC4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAwIiwibmFtZSI6ImRrdEFkbUZpbGVEYXRlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJzbnBBZG1GaWxlTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJzbnBBZG1DcmVhdGVEYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InNucEFkbU1vZGlmeURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuNi4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAwIiwibmFtZSI6InNucEFkbUZpbGVEYXRlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQiLCJuYW1lIjoiZmlsZURhdGUiLCJudW1iZXIiOm51bGx9LCJmbGFzaE1lbW9yeVRlc3QiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDI5NDk2NzI5NSIsIm5hbWUiOiJhY3RUZXN0RGF0YVJlYWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEwLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNieVRlc3REYXRhV3JpdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEwLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMCIsIm5hbWUiOiJmbGFzaE1lbW9yeVRlc3QiLCJudW1iZXIiOm51bGx9LCJpcHVGaWxlVHJhbnNmZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTk5IiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNvbW1hbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyU2xvdE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyIiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNhYmluZXROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNvbW1hbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyU2xvdE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyIiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNhYmluZXROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTk5IiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlclNsb3ROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMiIsIm5hbWUiOiJpcHVGaWxlVHJhbnNmZXJDYWJpbmV0TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJpcHVGaWxlVHJhbnNmZXJTZXJ2ZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyQ29tbWFuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJpcHVGaWxlVHJhbnNmZXJTbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyQ2FiaW5ldE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIxMiIsIm5hbWUiOiJpcHVGaWxlU2VydmVyVXJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaXB1RmlsZVNlcnZlclBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaXB1RmlsZVNlcnZlclVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVNlcnZlckluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjEyIiwibmFtZSI6ImlwdUZpbGVTZXJ2ZXJVcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMi4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJpcHVGaWxlU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyIiwibnVtYmVyIjpudWxsfSwibGljZW5zZUNvbnRyb2wiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTE1MiIsIm5hbWUiOiJsaWNlbnNlVXNlZFBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC42LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwMCIsIm5hbWUiOiJsaWNlbnNlVXNlZElwUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjYuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaWNlbnNlVXNlZEJWTVVDaGFubmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuNi4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE1OTIiLCJuYW1lIjoibGljZW5zZVVzZWRRU0lHQ2hhbm5lbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjYuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NDAiLCJuYW1lIjoibGljZW5zZVVzZWRTSVBUcnVua0NoYW5uZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC42LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTUyIiwibmFtZSI6ImxpY2Vuc2VVc2VkRFA1MDIyU0RNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuNi42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaWNlbnNlQ29tbWFuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjUuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwMCIsIm5hbWUiOiJ2YWxpZE51bWJlckNhbGxBZ2VudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoidmFsaWROdW1iZXJMVk1VQ2hhbm5lbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDQwIiwibmFtZSI6InZhbGlkTnVtYmVyUVNJR0NoYW5uZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjI1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ0MCIsIm5hbWUiOiJ2YWxpZE51bWJlclNJUFRydW5rQ2hhbm5lbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTUyIiwibmFtZSI6InZhbGlkTnVtYmVyRFA1MDIyU0RNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4yNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2YWxpZEJhc2ljTmV0d29ya2luZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMDAiLCJuYW1lIjoidmFsaWROdW1iZXJTb2Z0cGhvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkVHJhbnNmZXJEaXJlY3RWTSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2YWxpZE51bWJlclNlcmlhbFBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkU01ESXBsdXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkUHJpdmF0ZU5ldHdvcmtpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoidmFsaWRIYXJkd2FyZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDgiLCJuYW1lIjoidmFsaWROdW1iZXJEUkVDIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi45IiwibmFtZSI6InZhbGlkTnVtYmVyQ1NUQSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2YWxpZENvbmZpZ1R5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjExNTIiLCJuYW1lIjoidmFsaWROdW1iZXJQb3J0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2YWxpZEFDRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoidmFsaWRBQlIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMDAiLCJuYW1lIjoidmFsaWROdW1iZXJJcFBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkTUlTIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidmFsaWRBY2MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkU01ESSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidmFsaWRDZW50cmFsaXplZFZNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAwIiwibmFtZSI6InZhbGlkTnVtYmVyQUNEQWdlbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIxIiwibmFtZSI6InZhbGlkVXBkYXRlVmVyc2lvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJ2YWxpZFBDQVRUIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkQ2VudHJhbGl6ZWRTTURSIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGljZW5zZVRyYXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4xLjUiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaWNlbnNlU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGljZW5zZUZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjQiLCJuYW1lIjoibGljZW5zZURlbGF5VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTYiLCJuYW1lIjoibGljZW5zZVN0cmluZ0ZpZWxkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMS42Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImxpY2Vuc2VPcmRlck51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGljZW5zZUNvZGVEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMi4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjYiLCJuYW1lIjoibGljZW5zZUNvbnRyb2wiLCJudW1iZXIiOm51bGx9LCJtYWNBZGRyZXNzIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWFjQWRkcmVzc0RhdGEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjkuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjkiLCJuYW1lIjoibWFjQWRkcmVzcyIsIm51bWJlciI6bnVsbH0sIm1lbW9yeUFjY2VzcyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJtZW1vcnlEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoibWVtb3J5U2l6ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IkdhdWdlMzIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtZW1vcnlBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41LjIiLCJzeW50YXgiOiJHYXVnZTMyIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im1lbW9yeUZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41LjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41IiwibmFtZSI6Im1lbW9yeUFjY2VzcyIsIm51bWJlciI6bnVsbH0sIm1pZGRsZXdhcmUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBSb3V0aW5nTmV4dEhvc3RBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjIuMS4xLjQiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBSb3V0aW5nTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjIuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBSb3V0aW5nSUZOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMi4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFJvdXRpbmdJUEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMi4xLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwUm91dGluZ1N1Yk5ldE1hc2siLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMi4xLjEuMyIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImZ0cFVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjMuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImZ0cFBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjMuMS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImZ0cEhvbWVEaXJlY3RvcnkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMy4xLjEuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi40IiwibmFtZSI6ImZ0cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGNwSXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMS4xIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGNwSXBTdWJOZXRNYXNrIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRjcElwRGVmYXVsdEdhdGV3YXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMS4zIiwic3ludGF4IjoiSXBBZGRyZXNzIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMiIsIm5hbWUiOiJtaWRkbGV3YXJlIiwibnVtYmVyIjpudWxsfSwicmVhZFZlcnNpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJhY3RpdmVTaWRlVmVyc2lvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMi4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InN0YW5kYnlTaWRlVmVyc2lvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMi4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJzeXN0ZW1EZXRhaWxUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4yLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4yIiwibmFtZSI6InJlYWRWZXJzaW9uIiwibnVtYmVyIjpudWxsfSwicmVnaW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImN1cnJlbnRSZWdpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEyLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyZWdpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEyLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMiIsIm5hbWUiOiJyZWdpb24iLCJudW1iZXIiOm51bGx9LCJzZXJ2ZXJOdW1iZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJhY3RpdmVTaWRlQ2FsbGVkTnVtRGF0YVRvU2VydmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMy4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJzdGFuZGJ5U2lkZUNhbGxlZE51bURhdGFUb1NlcnZlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTMuMS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoiY2FsbGVkTnVtVG9TZXJ2ZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTMuMS4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMyIsIm5hbWUiOiJzZXJ2ZXJOdW1iZXIiLCJudW1iZXIiOm51bGx9LCJzZXRDYWxlbmRhciI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMxIiwibmFtZSI6ImRhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsZWFwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjk5IiwibmFtZSI6InllYXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMyIsIm5hbWUiOiJob3VyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoibW9udGgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41OSIsIm5hbWUiOiJzZWNvbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41OSIsIm5hbWUiOiJtaW51dGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEiLCJuYW1lIjoic2V0Q2FsZW5kYXIiLCJudW1iZXIiOm51bGx9LCJzeXN0ZW1BZG1pbkxvZyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJqdWRnZU9mQ29tcGxldGlvblN5c3RlbUFkbWluTG9nIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4zLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1BZG1pbkxvZ1N0YXJ0U3RvcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMy4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMyIsIm5hbWUiOiJzeXN0ZW1BZG1pbkxvZyIsIm51bWJlciI6bnVsbH0sInN5c3RlbVJlc3RhcnQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJvb3RNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xIiwibmFtZSI6InN5c3RlbVJlc3RhcnQiLCJudW1iZXIiOm51bGx9LCJ0cmFwU2VuZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJ0cmFwU2VuZElQT3JnQ29tbXVuaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJ0cmFwU2VuZElQTmV3Q29tbXVuaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS42Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMSIsIm5hbWUiOiJ0cmFwU2VuZElQTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFwU2VuZElQU2V0Q29tbWFuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoidHJhcFNlbmRJUE9yZ0FkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi45LjUiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InRyYXBTZW5kSVBOZXdBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS43Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjExIiwibmFtZSI6InRyYXBTZW5kSVBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkuMi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJ0cmFwU2VuZElQQWRkcmVzcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkuMi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoidHJhcFNlbmRDb21tdW5pdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi45LjIuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InRyYXBTZW5kSVBUaW1lU3RhbXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi45LjIuMS40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkiLCJuYW1lIjoidHJhcFNlbmQiLCJudW1iZXIiOm51bGx9LCJ1cGRhdGVwcm9ncmFtIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ1cEZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy42LjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJjaGVja0ZpbmlzaFdyaXRlRmxhc2giLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJ1cFRvdGFsRmlsZXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NTUzNiIsIm5hbWUiOiJ1cFRvdGFsQmxvY2tzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy42LjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjU1MzYiLCJuYW1lIjoidXBDb3BpZWRCbG9ja3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidXBBY3RpdmVTaWRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy42LjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ1cEFjdGl2ZVNpZGVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMSIsIm5hbWUiOiJ1cFZlcnNpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuOSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InVwU3RhbmRieVNpZGVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYiLCJuYW1lIjoidXBkYXRlcHJvZ3JhbSIsIm51bWJlciI6bnVsbH19").decode("utf-8")  # bundled eManager catalog

# ===== write.py ====================================================
"""Toshiba Strata CIX SNMP **write** path (implemented from the on-site pcap).

The SET protocol was decoded from ``emanager-session1-final.pcap`` (frame 634,
which the CIX accepted — frame 635 confirmed it):

* eManager writes a field with an SNMP **SetRequest**, sent as **v2c**
  (SNMP version field = 1; reads stay v1), community ``communityName``.
* The varbinds are the **data OIDs** of the fields — exactly the OIDs a read
  returns — set to the new value, **batched** (several fields in one SET).
* Value encoding is identical to a read: an ``OCTET STRING`` carrying the
  literal string (``"sysadmin"``, ``"010101"``, a station name); an ``INTEGER``
  for the genuinely-numeric fields.
* eManager then GETs the same OIDs back to confirm. We do the same.

Ground truth (frame 634)::

    SetRequest v2c community=communityName request-id=6
      1.3.6.1.4.1.186.1.22.3.2.3.1.1.4.1 = OctetString "/"
      1.3.6.1.4.1.186.1.22.3.2.3.1.1.2.1 = OctetString "sysadmin"
      1.3.6.1.4.1.186.1.22.3.2.3.1.1.3.1 = OctetString "wksi76dbga"

That is the FTP-credential table (``.3.2.3``), but the mechanism is identical
for any program/field — a station name / extension / trunk is the same SET to
that field's OID. We build the exact target OID from the ``source_oids`` the
reader already records per field, so a planned edit addresses the precise
instance it was read from.

Still to confirm on the first **supervised** live write (TODOs, not blockers —
the direct data SET at frame 634 succeeded with no immediately-preceding op):

* An operation/mode SET was seen once early (frame 334):
  ``1.3.6.1.4.1.186.1.22.7.7.1.0 = Integer 2``. Implemented here as an optional
  pre-op (:data:`OP_MODE_OID`), **off by default**; enable only if a bare data
  SET is ever refused.
* Any save/commit-to-flash step (so a write survives a processor reboot) is not
  yet identified. Re-read after a reboot during the supervised test.

Safety contract (kept strict):

* :data:`WRITES_ENABLED` is the master switch. A write also requires the caller
  to pass ``confirm=True`` to :meth:`CIXWriter.commit` — the web layer wires
  that to an explicit "Confirm & write" action, never a silent save.
* Every write is GET-verified: :meth:`CIXWriter.commit` reads the OIDs back and
  reports requested-vs-read-back per field. It never writes silently.
* A non-sendable planned op (unknown field, read-only port, or a field with no
  derivable OID) is never sent.
"""


from dataclasses import dataclass
from typing import Iterable


# Master switch. Writes are implemented and unit-tested offline against a fake
# agent; a supervised live write (reversible station-name set -> read-back ->
# re-read) is done with the owner present before trusting it in the field.
WRITES_ENABLED = True

# Optional operation/mode pre-op (frame 334). OFF by default: the data SET at
# frame 634 succeeded without it. Flip on only if a bare SET is ever refused.
SEND_OP_MODE = False
OP_MODE_OID = "1.3.6.1.4.1.186.1.22.7.7.1.0"
OP_MODE_VALUE = 2


def writes_enabled() -> bool:
    """The live master-switch value.

    Read this instead of importing :data:`WRITES_ENABLED` by value when the flag
    may be toggled at runtime (e.g. a test, or a future UI switch): a
    ``from .write import WRITES_ENABLED`` binding in another module is a snapshot
    taken at import time, whereas this always returns the current global.
    """
    return WRITES_ENABLED


class WriteError(RuntimeError):
    """A write could not be completed: disabled, not confirmed, nothing
    sendable, the agent rejected the SET, or read-back verification failed."""


# Fields of the station directory (Program 1200) a tech may edit in eManager.
# Maps the structured field name -> (program, column). The equipment port is
# deliberately absent: it is a physical cabinet/slot/circuit assignment, not a
# free-text field, and must never be SET from this tool.
#   col2 = extension (also the row DN), col4 = type, col19 = station name.
STATION_WRITE_COLUMNS: dict[str, tuple[str, int]] = {
    "extension": ("1200", 2),
    "type": ("1200", 4),
    "name": ("1200", 19),
}

# Columns that are read-only on purpose (shown but never writable).
STATION_READONLY_FIELDS = frozenset({"equipment_port", "dn", "source_oids",
                                     "flags", "keys", "programs"})


@dataclass
class WriteOp:
    """One intended field change.

    ``target_oid`` is the exact instance OID the SET addresses (derived from the
    read, so it is correct), ``new_value`` the desired value, ``old_value`` what
    the read saw. ``ber_type`` is the on-wire type (``OCTET STRING`` for every
    field proven so far; ``INTEGER`` is available for numeric fields that need
    it). ``sendable`` is ``False`` whenever we could not derive a target OID;
    such an op is never sent.
    """

    field: str
    label: str
    new_value: str
    old_value: str | None = None
    target_oid: str | None = None
    program: str | None = None
    column: int | None = None
    ber_type: str = "OCTET STRING"
    note: str = ""

    @property
    def sendable(self) -> bool:
        return bool(self.target_oid)

    def encode_value(self) -> bytes:
        """The BER value TLV for this op (same encoding reads use)."""
        if self.ber_type == "INTEGER":
            return ber_integer(int(self.new_value))
        return ber_octet(self.new_value)

    def as_dict(self) -> dict:
        return {
            "field": self.field,
            "label": self.label,
            "new_value": self.new_value,
            "old_value": self.old_value,
            "target_oid": self.target_oid,
            "program": self.program,
            "column": self.column,
            "ber_type": self.ber_type,
            "sendable": self.sendable,
            "note": self.note,
        }


def encode_set_request(community: str, ops: Iterable[WriteOp],
                       request_id: int = 1, *, version: int = 1) -> bytes:
    """Encode an SNMP ``SetRequest`` (v2c) for the sendable ``ops``.

    Raises :class:`WriteError` if nothing is sendable. This is a thin shim over
    :func:`toshiba_cix.snmp.encode_set_message` that turns :class:`WriteOp`
    records into ``(oid, value_tlv)`` varbinds.
    """
    sendable = [op for op in ops if op.sendable]
    if not sendable:
        raise WriteError("no sendable operations to encode")
    varbinds = [(op.target_oid, op.encode_value()) for op in sendable]
    return encode_set_message(community, varbinds, request_id, version=version)


class CIXWriter:
    """Plans (pure) and commits (live, GET-verified) station edits.

    ``plan_station_update`` is pure (no I/O) and safe to call anywhere.
    ``commit`` sends the batched SET and verifies the read-back. The ``client``
    is only needed by ``commit``.
    """

    def __init__(self, client=None):
        self.client = client

    def plan_station_update(self, station: dict, changes: dict) -> list[WriteOp]:
        """Build the intended :class:`WriteOp` list for a station edit (no I/O).

        ``station`` is one entry from ``doc["stations"]`` (it carries
        ``source_oids``); ``changes`` is ``{field: new_value}``. Only fields in
        :data:`STATION_WRITE_COLUMNS` are planned; anything else is returned as a
        non-sendable op with an explanatory note, so the UI can tell the tech why
        it was skipped rather than silently dropping it.
        """
        source_oids = station.get("source_oids", {}) or {}
        ops: list[WriteOp] = []
        for fieldname, new_value in changes.items():
            old_value = station.get(fieldname)
            if old_value is not None and not isinstance(old_value, str):
                old_value = str(old_value)
            if fieldname in STATION_READONLY_FIELDS:
                ops.append(WriteOp(
                    field=fieldname, label=fieldname, new_value=str(new_value),
                    old_value=old_value, note="read-only field — never written",
                ))
                continue
            spec = STATION_WRITE_COLUMNS.get(fieldname)
            if spec is None:
                ops.append(WriteOp(
                    field=fieldname, label=fieldname, new_value=str(new_value),
                    old_value=old_value,
                    note="no known writable column for this field",
                ))
                continue
            prog, col = spec
            target_oid = source_oids.get(fieldname)
            note = ""
            if not target_oid:
                note = ("field has no existing instance on the device; the write "
                        "OID cannot be derived from a read")
            ops.append(WriteOp(
                field=fieldname, label=fieldname, new_value=str(new_value),
                old_value=old_value, target_oid=target_oid,
                program=prog, column=col, note=note,
            ))
        return ops

    def commit(self, ops: Iterable[WriteOp], *, confirm: bool = False,
               verify: bool = True) -> dict:
        """Send the batched SET for the sendable ``ops`` and verify the read-back.

        Requires :data:`WRITES_ENABLED` and ``confirm=True`` (an explicit
        confirmation — the UI's "Confirm & write"). After the SET it GETs the
        same OIDs and compares each decoded value to what was requested.

        Returns a structured result::

            {ok, wrote, verified, verified_all,
             results: [{field, oid, requested, read_back, match}],
             skipped: [<non-sendable op dicts>]}

        Raises :class:`WriteError` on a gate failure / nothing sendable, and
        :class:`toshiba_cix.snmp.SnmpError` if the agent rejects the SET.
        """
        ops = list(ops)
        if not WRITES_ENABLED:
            raise WriteError("writes are disabled (WRITES_ENABLED is False)")
        if not confirm:
            raise WriteError("refusing to write without explicit confirm=True")
        if self.client is None:
            raise WriteError("no SNMP client to write with")

        sendable = [op for op in ops if op.sendable]
        skipped = [op for op in ops if not op.sendable]
        if not sendable:
            raise WriteError(
                "nothing sendable: " + "; ".join(
                    f"{op.field} ({op.note})" for op in skipped) or "no ops")

        # Optional operation/mode pre-op (see module docstring) — off by default.
        if SEND_OP_MODE:
            self.client.set([(OP_MODE_OID, ber_integer(OP_MODE_VALUE))])

        varbinds = [(op.target_oid, op.encode_value()) for op in sendable]
        self.client.set(varbinds)   # raises SnmpError if the CIX rejects it

        results: list[dict] = []
        verified_all = True
        if verify:
            vbs = self.client.get([op.target_oid for op in sendable])
            by_oid = {vb.oid: vb.value for vb in vbs}
            for op in sendable:
                read_back = decode_value(by_oid.get(op.target_oid, Value("missing")))
                match = str(read_back) == str(op.new_value)
                verified_all = verified_all and match
                results.append({
                    "field": op.field, "oid": op.target_oid,
                    "requested": op.new_value, "read_back": read_back,
                    "match": match,
                })
        return {
            "ok": verified_all if verify else True,
            "wrote": len(sendable),
            "verified": verify,
            "verified_all": verified_all,
            "results": results,
            "skipped": [op.as_dict() for op in skipped],
        }

    def apply_station_update(self, station: dict, changes: dict, *,
                             confirm: bool = False, verify: bool = True) -> dict:
        """Plan then commit a station edit (convenience)."""
        ops = self.plan_station_update(station, changes)
        return self.commit(ops, confirm=confirm, verify=verify)


__all__ = [
    "WRITES_ENABLED", "writes_enabled", "SEND_OP_MODE", "OP_MODE_OID",
    "OP_MODE_VALUE", "WriteError", "WriteOp", "CIXWriter", "encode_set_request",
    "STATION_WRITE_COLUMNS", "STATION_READONLY_FIELDS",
]

# ===== backup.py ===================================================
"""Catalog-driven full backup of a Toshiba Strata CIX.

A backup walks every program table the catalog knows (read-only GETNEXT) plus
the system-identity scalars, decodes each value by its field's syntax, and
writes the app's **own openable format** — a single JSON that the viewer, the
diff and the restore planner all read back.

Three layers, I/O isolated so the whole build is unit-tested offline:

* :func:`collect` — the only network step: GETNEXT-walk the catalog's field
  OIDs (reusing :meth:`SnmpV1.bulk_walk`) and return ``[(oid, Value)]``.
* :func:`build_backup` — **pure**: attribute each OID to its catalog field,
  group into program → rows → named fields, decode by syntax. Tested against
  fixtures, no device.
* :func:`backup` — orchestration: read the identity scalars for ``meta`` then
  ``collect`` + ``build_backup``.

Backup file schema (``format == "toshiba-cix-backup"``)::

    {
      "format": "toshiba-cix-backup",
      "format_version": 1,
      "meta": {
        "swid": "<software id>", "chassis_mac": "...", "site": "<label|null>",
        "read_at": "<iso8601>", "catalog_version": "re-xxxxxxxxxxxx",
        "source_ip": "...", "tool_version": "...", "scope": "all"|[programs],
        "oids_read": N, "programs_count": N, "rows_count": N, "walk_error": null
      },
      "programs": {
        "<catalog key>": {               # keyed by catalog key — program
          "number": "200",               #   numbers are null/duplicated, the
          "name": "StationAssign",       #   key is the only unique id
          "group_oid": "...",
          "rows": [
            {"index": "1.3.50.48.48",    # exact instance tail (restores the OID)
             "key": "200",               # human row key (the DN, when present)
             "fields": {"stationStationName": "Front Desk", ...}}
          ]
        }
      },
      "unmatched": [{"oid": "...", "value": ...}]   # anything outside the catalog
    }

Programs are keyed by the **catalog key** (e.g. ``"200StationAssign"``), not the
program number: 31 programs have a null number and numbers repeat, so the key
is the only stable identifier. Each entry still carries ``number`` and ``name``.
"""


from datetime import datetime, timezone


FORMAT = "toshiba-cix-backup"
FORMAT_VERSION = 1

SOFTWARE_ID_OID = f"{ENTERPRISE_ROOT}.7.2.1.0"
CHASSIS_MAC_OID = f"{ENTERPRISE_ROOT}.7.9.1.0"


# --------------------------------------------------------------------------
# root planning (pure)
# --------------------------------------------------------------------------
def walk_roots(catalog: Catalog, programs=None) -> list[str]:
    """The minimal set of GETNEXT roots that covers the selected programs.

    Collects the chosen programs' field (column) OIDs, then drops any OID that
    is a descendant of another kept OID — walking the ancestor already sweeps
    the descendant's instances — so the live read makes as few passes as it can.
    """
    if programs:
        progs = catalog.programs_for(programs)
    else:
        progs = list(catalog.programs.values())
    oids = sorted({f["oid"] for p in progs for f in p.fields if f.get("oid")},
                  key=lambda o: [int(x) for x in o.split(".")])
    roots: list[str] = []
    for oid in oids:
        if any(oid == r or oid.startswith(r + ".") for r in roots):
            continue
        roots.append(oid)
    return roots


# --------------------------------------------------------------------------
# collection (I/O)
# --------------------------------------------------------------------------
def collect(client, catalog: Catalog, *, programs=None,
            width: int = 10, max_total: int = 500000
            ) -> tuple[list[tuple[str, Value]], str | None]:
    """GETNEXT-walk the catalog's field subtrees. Returns ``(pairs, error)``.

    Read-only: emits only GETNEXT. Reuses the device-hardened
    :meth:`SnmpV1.bulk_walk` (adaptive batch size, tooBig recovery). A transport
    failure degrades to whatever was collected plus an ``error`` string rather
    than losing the partial read.
    """
    roots = walk_roots(catalog, programs)
    error: str | None = None
    pairs: list[tuple[str, Value]] = []
    try:
        pairs = client.bulk_walk(roots, width=width, max_total=max_total)
    except SnmpError as exc:
        error = str(exc)
    # de-dup (bulk_walk can revisit an overlap)
    seen: set[str] = set()
    out: list[tuple[str, Value]] = []
    for oid, val in pairs:
        if oid not in seen:
            seen.add(oid)
            out.append((oid, val))
    return out, error


def read_identity(client) -> dict:
    """Read the two identity scalars for ``meta`` (software id, chassis MAC)."""
    out: dict = {"swid": None, "chassis_mac": None}
    try:
        vbs = client.get([SOFTWARE_ID_OID, CHASSIS_MAC_OID])
    except SnmpError:
        return out
    by_oid = {vb.oid: vb.value for vb in vbs}
    sw = by_oid.get(SOFTWARE_ID_OID)
    if sw is not None and not sw.is_missing and sw.kind == "octet" and sw.raw:
        out["swid"] = decode_value(sw)
    mac = by_oid.get(CHASSIS_MAC_OID)
    if mac is not None and not mac.is_missing and mac.kind == "octet" and mac.raw:
        out["chassis_mac"] = decode_value(mac, as_mac=True)
    return out


# --------------------------------------------------------------------------
# build (pure)
# --------------------------------------------------------------------------
def _row_sort_key(index: str):
    arcs = [int(a) for a in index.split(".")] if index else []
    return (len(arcs), arcs)


def _human_key(index: str) -> str:
    """A readable row key from the instance tail (the DN when there is one)."""
    if not index:
        return "_"
    try:
        arcs = tuple(int(a) for a in index.split("."))
    except ValueError:
        return index
    ri = parse_row_index(arcs)
    return ri.key


def build_backup(pairs, catalog: Catalog, *, meta: dict | None = None) -> dict:
    """Assemble a backup dict from collected ``(oid, Value)`` pairs. Pure.

    Every OID is attributed to its catalog field by longest-prefix match and
    filed under ``program key → row (by instance tail) → field``. OIDs with no
    catalog field survive verbatim in ``unmatched`` so a backup never silently
    drops data the device returned.
    """
    programs: dict[str, dict] = {}
    rows_by_prog: dict[str, dict[str, dict]] = {}
    unmatched: list[dict] = []
    row_count = 0

    for oid, val in pairs:
        attr = catalog.attribute_oid(oid)
        if attr is None:
            unmatched.append({"oid": oid, "value": decode_value(val)})
            continue
        prog_key, fld, tail = attr
        prog = catalog.programs[prog_key]
        bucket = programs.get(prog_key)
        if bucket is None:
            bucket = programs[prog_key] = {
                "number": prog.number, "name": prog.name,
                "group_oid": prog.group_oid, "rows": [],
            }
            rows_by_prog[prog_key] = {}
        index = tail or "0"
        row = rows_by_prog[prog_key].get(index)
        if row is None:
            row = {"index": index, "key": _human_key(index), "fields": {}}
            rows_by_prog[prog_key][index] = row
            row_count += 1
        row["fields"][prog.field_key(fld)] = catalog.decode_field_value(fld, val)

    # finalise: deterministic row order per program
    for prog_key, bucket in programs.items():
        bucket["rows"] = sorted(rows_by_prog[prog_key].values(),
                                key=lambda r: _row_sort_key(r["index"]))

    full_meta = {
        "swid": None, "chassis_mac": None, "site": None,
        "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_version": catalog.version,
        "source_ip": None, "tool_version": __version__,
        "scope": "all", "oids_read": len(pairs), "walk_error": None,
    }
    if meta:
        full_meta.update(meta)
    full_meta["programs_count"] = len(programs)
    full_meta["rows_count"] = row_count
    full_meta["unmatched_count"] = len(unmatched)

    return {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "meta": full_meta,
        "programs": dict(sorted(programs.items())),
        "unmatched": unmatched,
    }


# --------------------------------------------------------------------------
# orchestration (I/O)
# --------------------------------------------------------------------------
def backup(client, catalog: Catalog | None = None, *, site: str | None = None,
           programs=None, width: int = 10, max_total: int = 500000) -> dict:
    """Read a live CIX and return a backup dict (read-only)."""
    catalog = catalog or load_catalog()
    ident = read_identity(client)
    pairs, error = collect(client, catalog, programs=programs, width=width,
                           max_total=max_total)
    meta = {
        "swid": ident.get("swid"),
        "chassis_mac": ident.get("chassis_mac"),
        "site": site,
        "source_ip": getattr(client, "host", None),
        "scope": "all" if not programs else list(programs),
        "walk_error": error,
    }
    return build_backup(pairs, catalog, meta=meta)


# --------------------------------------------------------------------------
# rendering (pure)
# --------------------------------------------------------------------------
def _hr(title: str, char: str = "=") -> str:
    return f"{title}\n{char * max(len(title), 8)}"


def _render_value(catalog, prog_key, fieldkey, value) -> str:
    if value is None:
        return ""
    if catalog is not None and isinstance(value, int) and not isinstance(value, bool):
        prog = catalog.program(prog_key)
        if prog is not None:
            fld = prog.field(fieldkey.split("#", 1)[0])
            if fld is not None and fld.get("syntax") == "EnumeratedINTEGER":
                label = catalog.enum_label(fld, value)
                if label:
                    return f"{value} ({label})"
    return str(value)


def render_backup_text(backup_doc: dict, *, catalog: Catalog | None = None,
                       program: str | None = None,
                       max_rows: int | None = None) -> str:
    """Human-readable rendering of a backup file: programs → rows → fields.

    ``program`` limits output to one program (catalog key, number or name);
    ``max_rows`` caps rows shown per program. When a ``catalog`` is supplied,
    EnumeratedINTEGER values are annotated with their label (once labels ship).
    """
    meta = backup_doc.get("meta", {})
    lines: list[str] = []
    lines.append(_hr("Toshiba Strata CIX — catalog backup"))
    lines.append(f"Software id     : {meta.get('swid', '?')}")
    lines.append(f"Chassis MAC     : {meta.get('chassis_mac', '?')}")
    lines.append(f"Site            : {meta.get('site') or '-'}")
    lines.append(f"Source IP       : {meta.get('source_ip') or '-'}")
    lines.append(f"Read at         : {meta.get('read_at', '?')}")
    lines.append(f"Catalog version : {meta.get('catalog_version', '?')}")
    lines.append(f"Tool version    : {meta.get('tool_version', '?')}")
    lines.append(f"Scope           : {meta.get('scope', '?')}")
    lines.append(f"Programs / rows : {meta.get('programs_count', '?')}"
                 f" / {meta.get('rows_count', '?')}")
    if meta.get("walk_error"):
        lines.append(f"WALK ERROR      : {meta['walk_error']} (partial)")
    lines.append("")

    progs = backup_doc.get("programs", {})
    want = None
    if program is not None:
        want = str(program)
    for prog_key in sorted(progs):
        bucket = progs[prog_key]
        if want is not None and want not in (
                prog_key, str(bucket.get("number")), bucket.get("name")):
            continue
        title = f"{prog_key}"
        num = bucket.get("number")
        if num:
            title += f"  (Program {num})"
        rows = bucket.get("rows", [])
        lines.append(_hr(f"{title} — {len(rows)} row(s)", "-"))
        shown = rows if max_rows is None else rows[:max_rows]
        for row in shown:
            lines.append(f"  [{row.get('key') or row.get('index')}]")
            for fk in sorted(row.get("fields", {})):
                lines.append(f"      {fk:<34} = "
                             f"{_render_value(catalog, prog_key, fk, row['fields'][fk])}")
        if max_rows is not None and len(rows) > max_rows:
            lines.append(f"  … {len(rows) - max_rows} more row(s)")
        lines.append("")

    unmatched = backup_doc.get("unmatched", [])
    if unmatched and program is None:
        lines.append(_hr(f"Unmatched OIDs (outside the catalog) — "
                         f"{len(unmatched)}", "-"))
        for e in unmatched[:50]:
            lines.append(f"  {e['oid']} = {e['value']}")
        if len(unmatched) > 50:
            lines.append(f"  … {len(unmatched) - 50} more")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "FORMAT", "FORMAT_VERSION", "SOFTWARE_ID_OID", "CHASSIS_MAC_OID",
    "walk_roots", "collect", "read_identity", "build_backup", "backup",
    "render_backup_text",
]

# ===== diff.py =====================================================
"""Structured, human-readable diff between two catalog backups.

Compares two backup documents (see :mod:`toshiba_cix.backup`) at three levels —
programs added/removed, rows added/removed within a program, and fields changed
/ added / removed within a row. Rows are matched on their exact instance tail
(``index``), so a diff survives re-ordering and only reports real changes.

With a :class:`~toshiba_cix.catalog.Catalog`, ``ignore_readonly`` (default) drops
field *changes* on read-only fields — status counters, live timers and the like
that move on their own and would otherwise bury the programming changes a tech
cares about. Row add/remove is always reported. Without a catalog the diff
cannot tell read-only from read-write, so everything is reported.
"""



_ABSENT = object()


def _programs(doc: dict) -> dict:
    return doc.get("programs", {}) or {}


def _rows_by_index(bucket: dict) -> dict:
    return {r.get("index"): r for r in bucket.get("rows", [])}


def _is_readonly(catalog: Catalog | None, prog_key: str, fieldkey: str) -> bool:
    if catalog is None:
        return False
    prog = catalog.program(prog_key)
    if prog is None:
        return False
    fld = prog.field(fieldkey.split("#", 1)[0])
    if fld is None:
        return False
    return fld.get("access") != "rw"


def diff_backups(a: dict, b: dict, *, catalog: Catalog | None = None,
                 ignore_readonly: bool = True) -> dict:
    """Diff backup ``a`` (old) against ``b`` (new). Pure."""
    pa, pb = _programs(a), _programs(b)
    keys_a, keys_b = set(pa), set(pb)

    programs_added = sorted(keys_b - keys_a)
    programs_removed = sorted(keys_a - keys_b)
    programs_changed: dict[str, dict] = {}

    counts = {"programs_added": len(programs_added),
              "programs_removed": len(programs_removed),
              "rows_added": 0, "rows_removed": 0,
              "fields_changed": 0, "fields_added": 0, "fields_removed": 0,
              "ignored_readonly": 0}

    for key in sorted(keys_a & keys_b):
        ra = _rows_by_index(pa[key])
        rb = _rows_by_index(pb[key])
        idx_a, idx_b = set(ra), set(rb)

        rows_added = sorted(idx_b - idx_a, key=_idx_key)
        rows_removed = sorted(idx_a - idx_b, key=_idx_key)
        fields_changed: list[dict] = []
        fields_added: list[dict] = []
        fields_removed: list[dict] = []

        for index in sorted(idx_a & idx_b, key=_idx_key):
            fa = ra[index].get("fields", {})
            fb = rb[index].get("fields", {})
            human = rb[index].get("key") or ra[index].get("key") or index
            for fk in sorted(set(fa) | set(fb)):
                va = fa.get(fk, _ABSENT)
                vb = fb.get(fk, _ABSENT)
                if va is _ABSENT and vb is not _ABSENT:
                    fields_added.append({"index": index, "key": human,
                                         "field": fk, "new": vb})
                elif vb is _ABSENT and va is not _ABSENT:
                    fields_removed.append({"index": index, "key": human,
                                           "field": fk, "old": va})
                elif va != vb:
                    if ignore_readonly and _is_readonly(catalog, key, fk):
                        counts["ignored_readonly"] += 1
                        continue
                    fields_changed.append({"index": index, "key": human,
                                           "field": fk, "old": va, "new": vb})

        if rows_added or rows_removed or fields_changed or fields_added \
                or fields_removed:
            programs_changed[key] = {
                "number": pb[key].get("number"),
                "name": pb[key].get("name"),
                "rows_added": rows_added,
                "rows_removed": rows_removed,
                "fields_changed": fields_changed,
                "fields_added": fields_added,
                "fields_removed": fields_removed,
            }
            counts["rows_added"] += len(rows_added)
            counts["rows_removed"] += len(rows_removed)
            counts["fields_changed"] += len(fields_changed)
            counts["fields_added"] += len(fields_added)
            counts["fields_removed"] += len(fields_removed)

    return {
        "a_meta": a.get("meta", {}),
        "b_meta": b.get("meta", {}),
        "ignore_readonly": ignore_readonly and catalog is not None,
        "programs_added": programs_added,
        "programs_removed": programs_removed,
        "programs_changed": programs_changed,
        "summary": counts,
    }


def _idx_key(index: str):
    try:
        arcs = [int(a) for a in index.split(".")]
    except (ValueError, AttributeError):
        return (1, [], str(index))
    return (0, arcs, "")


def has_changes(diff: dict) -> bool:
    s = diff.get("summary", {})
    return any(s.get(k) for k in ("programs_added", "programs_removed",
                                  "rows_added", "rows_removed",
                                  "fields_changed", "fields_added",
                                  "fields_removed"))


def _hr(title: str, char: str = "=") -> str:
    return f"{title}\n{char * max(len(title), 8)}"


def _v(x) -> str:
    return "∅" if x is _ABSENT or x is None else str(x)


def render_diff_text(diff: dict) -> str:
    """Render a diff as plain text: a summary then per-program changes."""
    lines: list[str] = []
    am, bm = diff.get("a_meta", {}), diff.get("b_meta", {})
    lines.append(_hr("Toshiba Strata CIX — backup diff"))
    lines.append(f"A (old) : {am.get('site') or am.get('source_ip') or '?'}"
                 f"  read {am.get('read_at', '?')}")
    lines.append(f"B (new) : {bm.get('site') or bm.get('source_ip') or '?'}"
                 f"  read {bm.get('read_at', '?')}")
    if diff.get("ignore_readonly"):
        lines.append("Read-only field changes are hidden (catalog-aware).")
    lines.append("")

    s = diff.get("summary", {})
    lines.append(_hr("Summary", "-"))
    for k in ("programs_added", "programs_removed", "rows_added",
              "rows_removed", "fields_changed", "fields_added",
              "fields_removed", "ignored_readonly"):
        lines.append(f"  {k:<18}: {s.get(k, 0)}")
    lines.append("")

    if not has_changes(diff):
        lines.append("No programming differences.")
        return "\n".join(lines) + "\n"

    if diff.get("programs_added"):
        lines.append(_hr("Programs only in B (added)", "-"))
        for k in diff["programs_added"]:
            lines.append(f"  + {k}")
        lines.append("")
    if diff.get("programs_removed"):
        lines.append(_hr("Programs only in A (removed)", "-"))
        for k in diff["programs_removed"]:
            lines.append(f"  - {k}")
        lines.append("")

    changed = diff.get("programs_changed", {})
    for key in sorted(changed):
        c = changed[key]
        title = key + (f"  (Program {c['number']})" if c.get("number") else "")
        lines.append(_hr(title, "-"))
        for index in c.get("rows_added", []):
            lines.append(f"  + row [{index}]")
        for index in c.get("rows_removed", []):
            lines.append(f"  - row [{index}]")
        for ch in c.get("fields_changed", []):
            lines.append(f"  ~ [{ch['key']}] {ch['field']}: "
                         f"{_v(ch['old'])} -> {_v(ch['new'])}")
        for ch in c.get("fields_added", []):
            lines.append(f"  + [{ch['key']}] {ch['field']}: {_v(ch['new'])}")
        for ch in c.get("fields_removed", []):
            lines.append(f"  - [{ch['key']}] {ch['field']}: {_v(ch['old'])}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = ["diff_backups", "render_diff_text", "has_changes"]

# ===== restore.py ==================================================
"""Catalog-driven **restore**: write a backup (or a subset / a diff) back to a CIX.

Restore turns a backup document (:mod:`toshiba_cix.backup`) into a set of SNMP
SETs — one per **writable** field — addressed at the exact instance OID the
value was read from, then sends them batched and GET-verifies each read-back.

Safety is inherited wholesale from :mod:`toshiba_cix.write`:

* :data:`toshiba_cix.write.WRITES_ENABLED` is the master switch.
* :meth:`toshiba_cix.write.CIXWriter.commit` requires ``confirm=True`` and
  GET-verifies every field (requested-vs-read-back). Restore reuses it — there
  is one write path, one gate.
* **Read-only fields are never SET.** The planner marks them non-sendable with
  a note; they never reach a SET.

The planner (:func:`plan_restore`) is pure (no I/O) and fully unit-tested — it
reports exactly which OIDs/values it *would* SET. :func:`restore` is the gated
live step; with ``confirm=False`` (the default) it previews and touches nothing.

**Persistence is unproven.** The eManager write capture proved a data SET lands
in the processor's running config and reads back; whether it survives a reboot
(a flash/commit step) was never identified. Treat restore as **apply-to-RAM,
verify** until a supervised live write confirms persistence. Non-OCTET-STRING
writes (INTEGER / IpAddress / Gauge32) are catalog-derived and likewise await
that first supervised write; each such op is flagged ``wire_type_proven=False``.
"""


from dataclasses import dataclass


DEFAULT_BATCH = 20   # fields per SET PDU (eManager batches ~20)


@dataclass
class RestoreOp:
    """One intended field restore (planned; pure)."""

    program: str                 # catalog key
    index: str                   # instance tail (restores the exact OID)
    row_key: str                 # human row key (the DN, when present)
    field: str                   # per-row field key (may carry a #leaf suffix)
    field_name: str              # catalog field name
    target_oid: str | None
    new_value: object
    ber_type: str = "OCTET STRING"
    writable: bool = True
    wire_type_proven: bool = True
    note: str = ""

    @property
    def sendable(self) -> bool:
        return bool(self.target_oid) and self.writable

    def encode_value(self) -> bytes:
        if self.ber_type == "INTEGER":
            return ber_integer(int(self.new_value))
        return ber_octet(str(self.new_value))

    def to_writeop(self) -> WriteOp:
        """Convert to a :class:`WriteOp` so the one gated commit path sends it."""
        return WriteOp(
            field=f"{self.program}/{self.index}/{self.field}",
            label=f"{self.field_name} [{self.row_key}]",
            new_value=self.new_value,
            old_value=None,
            target_oid=self.target_oid,
            program=self.program,
            column=None,
            ber_type=self.ber_type,
            note=self.note,
        )

    def as_dict(self) -> dict:
        return {
            "program": self.program, "index": self.index,
            "row_key": self.row_key, "field": self.field,
            "field_name": self.field_name, "target_oid": self.target_oid,
            "new_value": self.new_value, "ber_type": self.ber_type,
            "writable": self.writable, "wire_type_proven": self.wire_type_proven,
            "sendable": self.sendable, "note": self.note,
        }


def _resolve_field(prog, fieldkey: str) -> dict | None:
    """Resolve a (possibly #leaf-disambiguated) field key to its catalog field."""
    name, _, leaf = fieldkey.partition("#")
    candidates = prog.fields_named(name)
    if not candidates:
        return None
    if leaf:
        for f in candidates:
            if f.get("oid", "").rsplit(".", 1)[-1] == leaf:
                return f
    return candidates[0]


def _diff_targets(from_diff: dict) -> set:
    """``{(program, index, field)}`` to restore from a diff (changed + added)."""
    targets: set = set()
    for key, c in (from_diff.get("programs_changed") or {}).items():
        for ch in c.get("fields_changed", []):
            targets.add((key, ch["index"], ch["field"]))
        for ch in c.get("fields_added", []):
            targets.add((key, ch["index"], ch["field"]))
        # a whole row that is new in B: restore every field of it
        for index in c.get("rows_added", []):
            targets.add((key, index, None))      # None = all fields in this row
    return targets


def plan_restore(backup: dict, catalog: Catalog, *, programs=None,
                 only=None, from_diff: dict | None = None,
                 include_readonly: bool = False) -> list[RestoreOp]:
    """Plan the SETs a restore would issue (no I/O).

    ``programs`` limits to those program idents; ``only`` is an iterable of
    ``(program, field_name)`` pairs; ``from_diff`` restricts to the fields a
    diff reports changed/added. Read-only fields are always planned as
    non-sendable (never SET) unless ``include_readonly`` is set *and* the field
    is in fact writable — a read-only field is never sent regardless.
    """
    want_progs = None
    if programs:
        want_progs = {p.key for p in catalog.programs_for(programs)}
    only_set = {(str(p), f) for p, f in only} if only else None
    diff_targets = _diff_targets(from_diff) if from_diff else None

    ops: list[RestoreOp] = []
    for prog_key, bucket in (backup.get("programs") or {}).items():
        if want_progs is not None and prog_key not in want_progs:
            continue
        prog = catalog.program(prog_key)
        for row in bucket.get("rows", []):
            index = row.get("index", "0")
            row_key = row.get("key") or index
            for fieldkey, value in (row.get("fields") or {}).items():
                fld = _resolve_field(prog, fieldkey) if prog else None
                field_name = fld.get("name") if fld else fieldkey
                if only_set is not None and (prog_key, field_name) not in only_set \
                        and (bucket.get("number"), field_name) not in only_set:
                    continue
                if diff_targets is not None and not (
                        (prog_key, index, fieldkey) in diff_targets
                        or (prog_key, index, None) in diff_targets):
                    continue

                if fld is None:
                    ops.append(RestoreOp(
                        program=prog_key, index=index, row_key=row_key,
                        field=fieldkey, field_name=field_name, target_oid=None,
                        new_value=value, writable=False,
                        note="field not in catalog — cannot restore"))
                    continue
                if value == MISSING or value is None:
                    ops.append(RestoreOp(
                        program=prog_key, index=index, row_key=row_key,
                        field=fieldkey, field_name=field_name, target_oid=None,
                        new_value=value, writable=Catalog.is_writable(fld),
                        note="value was absent at backup time — nothing to write"))
                    continue
                writable = Catalog.is_writable(fld)
                target_oid = catalog.instance_oid(fld, index) if writable else None
                ber_type, _tlv = catalog.encode_field_value(fld, value)
                note = ""
                if not writable:
                    note = "read-only field — never written"
                elif not catalog.wire_type_proven(fld, value):
                    note = (f"{ber_type} write is catalog-derived "
                            "(await supervised live write)")
                ops.append(RestoreOp(
                    program=prog_key, index=index, row_key=row_key,
                    field=fieldkey, field_name=field_name,
                    target_oid=target_oid, new_value=value, ber_type=ber_type,
                    writable=writable,
                    wire_type_proven=catalog.wire_type_proven(fld, value),
                    note=note))
    return ops


def plan_summary(ops: list[RestoreOp]) -> dict:
    sendable = [o for o in ops if o.sendable]
    return {
        "total": len(ops),
        "sendable": len(sendable),
        "skipped": len(ops) - len(sendable),
        "read_only": sum(1 for o in ops if not o.writable),
        "unproven_wire_type": sum(1 for o in sendable if not o.wire_type_proven),
    }


def restore(client, backup: dict, catalog: Catalog, *, confirm: bool = False,
            verify: bool = True, batch_size: int = DEFAULT_BATCH,
            programs=None, only=None, from_diff: dict | None = None) -> dict:
    """Plan, and (only with ``confirm=True``) apply a restore. Gated.

    With ``confirm=False`` this previews — it returns the full plan and sends
    **nothing**. With ``confirm=True`` it batches the sendable ops into SETs of
    ``batch_size`` and routes each batch through :meth:`CIXWriter.commit`, which
    enforces :data:`WRITES_ENABLED` + confirm and GET-verifies the read-back.

    Returns ``{ok, mode, writes_enabled, summary, planned_ops, [batches],
    [results], [verified_all]}``. A write is never silent and never persists a
    read-only field.
    """
    ops = plan_restore(backup, catalog, programs=programs, only=only,
                       from_diff=from_diff)
    summary = plan_summary(ops)
    base = {
        "writes_enabled": writes_enabled(),
        "summary": summary,
        "planned_ops": [o.as_dict() for o in ops],
    }
    if not confirm:
        base.update(ok=True, mode="preview",
                    message=("Preview only — nothing was sent. "
                             "Use confirm=True to apply to the live CIX (RAM; "
                             "persistence across reboot is unproven)."))
        return base

    if not writes_enabled():
        raise WriteError("writes are disabled (WRITES_ENABLED is False)")
    sendable = [o for o in ops if o.sendable]
    if not sendable:
        raise WriteError("nothing sendable to restore "
                         f"({summary['skipped']} skipped)")

    writer = CIXWriter(client)
    results: list[dict] = []
    batches: list[dict] = []
    verified_all = True
    wrote = 0
    for start in range(0, len(sendable), max(1, batch_size)):
        chunk = sendable[start:start + max(1, batch_size)]
        writeops = [o.to_writeop() for o in chunk]
        try:
            res = writer.commit(writeops, confirm=True, verify=verify)
        except (WriteError, SnmpError) as exc:
            batches.append({"ok": False, "size": len(chunk), "error": str(exc)})
            verified_all = False
            continue
        results.extend(res["results"])
        wrote += res["wrote"]
        verified_all = verified_all and res["verified_all"]
        batches.append({"ok": res["ok"], "size": len(chunk),
                        "verified_all": res["verified_all"]})

    base.update(
        ok=verified_all,
        mode="write",
        wrote=wrote,
        verified=verify,
        verified_all=verified_all,
        batches=batches,
        results=results,
        message=("Restore sent and verified (applied to RAM — persistence "
                 "across reboot is unproven)." if verified_all
                 else "Restore sent but some read-backs did not match — "
                      "see results."),
    )
    return base


__all__ = [
    "RestoreOp", "plan_restore", "plan_summary", "restore", "DEFAULT_BATCH",
]

# ===== discover.py =================================================
"""Auto-discover a Toshiba Strata CIX processor on the local LAN (pure stdlib).

A tech plugs a laptop straight into the PBX voice-LAN port and wants the CIX's
IP without knowing it. This module finds it three cheap ways and verifies by
SNMP:

1. **Toshiba MAC OUI.** CIX processors answer ARP with a Toshiba OUI —
   ``E8:E0:B7`` or ``E8:9D:87`` (``TOSHIBA_OUIS``). We populate the ARP cache
   with a short ping sweep of the local /24 and then read the system ARP /
   neighbour table, keeping entries with a Toshiba OUI.
2. **Convention.** The processor is conventionally at ``<subnet>.253`` — always
   offered as a candidate even if ARP missed it.
3. **SNMP verification.** Each candidate is probed with a single SNMPv1 GET of
   the software-id OID using the given community; only a real reply (an octet
   string) marks it ``verified`` and carries the software id + chassis MAC back.

The OS-touching bits (``subprocess`` ping / arp, interface enumeration) are
isolated from the **parsers**, which are pure string→data functions so they
unit-test offline against captured command output on every platform.
"""


import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess


# Toshiba OUIs seen on CIX processors (lower-case, no separators).
TOSHIBA_OUIS = frozenset({"e8e0b7", "e89d87"})

# The software-id scalar — a cheap, unambiguous "is this a CIX?" probe.
SOFTWARE_ID_OID = f"{ENTERPRISE_ROOT}.7.2.1.0"
CHASSIS_MAC_OID = f"{ENTERPRISE_ROOT}.7.9.1.0"

_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
_WIN_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# --------------------------------------------------------------------------
# pure parsers (unit-tested offline)
# --------------------------------------------------------------------------
def normalize_mac(mac: str) -> str:
    """``E8-E0-B7-CC-58-F5`` / ``e8:e0:b7:cc:58:f5`` -> ``e8e0b7cc58f5``."""
    return re.sub(r"[^0-9a-fA-F]", "", mac).lower()


def mac_oui(mac: str) -> str:
    """First three octets of a MAC, normalised (``e8e0b7``)."""
    return normalize_mac(mac)[:6]


def is_toshiba_mac(mac: str) -> bool:
    return mac_oui(mac) in TOSHIBA_OUIS


def parse_arp_table(output: str) -> list[dict]:
    """Parse ``arp -a`` / ``ip neigh`` output into ``[{ip, mac}]``.

    Handles the three shapes seen in the field:
      * Linux ``ip neigh``:  ``192.168.254.253 dev eth0 lladdr e8:e0:b7:.. REACHABLE``
      * Unix ``arp -a``:     ``cix (192.168.254.253) at e8:e0:b7:.. [ether] on eth0``
      * Windows ``arp -a``:  ``  192.168.254.253   e8-e0-b7-..   dynamic``
    Incomplete / MAC-less lines are skipped.
    """
    rows: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        ipm = _IP_RE.search(line)
        macm = _MAC_RE.search(line)
        if not ipm or not macm:
            continue
        rows.append({"ip": ipm.group(0), "mac": normalize_mac(macm.group(0))})
    return rows


def parse_ip_addr(output: str) -> list[dict]:
    """Parse ``ip -o -4 addr show`` into ``[{iface, ip, prefixlen}]`` (Linux)."""
    out: list[dict] = []
    for line in output.splitlines():
        # e.g.: "2: eth0    inet 192.168.254.10/24 brd ... scope global eth0"
        m = re.search(r"^\s*\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
                      line)
        if m:
            out.append({"iface": m.group(1), "ip": m.group(2),
                        "prefixlen": int(m.group(3))})
    return out


def parse_ifconfig(output: str) -> list[dict]:
    """Parse BSD/macOS ``ifconfig`` output into ``[{iface, ip, prefixlen}]``."""
    out: list[dict] = []
    iface = "?"
    for line in output.splitlines():
        head = re.match(r"^(\S+):\s", line)
        if head:
            iface = head.group(1)
            continue
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", line)
        if m:
            ip = m.group(1)
            mask = m.group(2)
            if mask.startswith("0x"):
                bits = bin(int(mask, 16)).count("1")
            else:
                bits = _mask_to_prefix(mask)
            out.append({"iface": iface, "ip": ip, "prefixlen": bits})
    return out


def parse_ipconfig(output: str) -> list[dict]:
    """Parse Windows ``ipconfig`` output into ``[{iface, ip, prefixlen}]``."""
    out: list[dict] = []
    ip = None
    for line in output.splitlines():
        m = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            ip = m.group(1)
            continue
        m = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if m and ip:
            out.append({"iface": "?", "ip": ip,
                        "prefixlen": _mask_to_prefix(m.group(1))})
            ip = None
    return out


def _mask_to_prefix(mask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return 24


def toshiba_candidates(arp_rows: list[dict]) -> list[dict]:
    """Keep the ARP rows whose MAC is a Toshiba OUI."""
    return [{"ip": r["ip"], "mac": r["mac"], "oui": mac_oui(r["mac"]),
             "via": "arp-oui"}
            for r in arp_rows if is_toshiba_mac(r["mac"])]


def conventional_candidates(networks: list[dict]) -> list[dict]:
    """``<network>.253`` for each local /24-ish network (the CIX convention)."""
    out: list[dict] = []
    for net in networks:
        try:
            iface_net = ipaddress.ip_network(
                f"{net['ip']}/{net['prefixlen']}", strict=False)
        except ValueError:
            continue
        if iface_net.version != 4 or iface_net.prefixlen < 23:
            continue
        guess = str(iface_net.network_address + 253)
        if ipaddress.ip_address(guess) in iface_net:
            out.append({"ip": guess, "mac": None, "oui": None,
                        "via": "convention-.253"})
    return out


# --------------------------------------------------------------------------
# OS-touching helpers (not unit-tested against the live network)
# --------------------------------------------------------------------------
def primary_ipv4() -> str | None:
    """Best-effort local IPv4 via a connect-less UDP socket (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def local_networks() -> list[dict]:
    """Enumerate local IPv4 networks, best-effort and cross-platform."""
    system = platform.system().lower()
    nets: list[dict] = []
    try:
        if system == "windows":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=5).stdout
            nets = parse_ipconfig(out)
        elif system == "linux":
            out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                                 capture_output=True, text=True,
                                 timeout=5).stdout
            nets = parse_ip_addr(out)
        else:  # darwin / bsd
            out = subprocess.run(["ifconfig"], capture_output=True, text=True,
                                 timeout=5).stdout
            nets = parse_ifconfig(out)
    except (OSError, subprocess.SubprocessError):
        nets = []
    # Drop loopback / link-local and de-dup by (ip, prefixlen).
    seen = set()
    filtered = []
    for n in nets:
        if n["ip"].startswith(("127.", "169.254.")):
            continue
        key = (n["ip"], n["prefixlen"])
        if key in seen:
            continue
        seen.add(key)
        filtered.append(n)
    # Fallback: the connect-less primary IP as a /24 if enumeration found none.
    if not filtered:
        ip = primary_ipv4()
        if ip and not ip.startswith(("127.", "169.254.")):
            filtered.append({"iface": "?", "ip": ip, "prefixlen": 24})
    return filtered


def _ping_cmd(ip: str) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", "500", ip]
    if system == "darwin":
        return ["ping", "-c", "1", "-W", "500", "-t", "1", ip]
    return ["ping", "-c", "1", "-W", "1", ip]  # linux


def _ping(ip: str) -> bool:
    try:
        r = subprocess.run(_ping_cmd(ip), capture_output=True, timeout=3)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ping_sweep(network: str, *, workers: int = 64, max_hosts: int = 512) -> int:
    """Ping every host in ``network`` to populate the ARP cache. Returns count
    of responders. Bounded to ``max_hosts`` so a wide mask can't melt the NIC."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return 0
    hosts = list(net.hosts())
    if len(hosts) > max_hosts:
        return 0
    alive = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for ok in pool.map(_ping, [str(h) for h in hosts]):
            alive += 1 if ok else 0
    return alive


def read_arp() -> list[dict]:
    """Read the system ARP / neighbour table (best-effort, cross-platform)."""
    system = platform.system().lower()
    cmds = (["ip", "neigh"], ["arp", "-a"]) if system == "linux" else \
           (["arp", "-a"],)
    for cmd in cmds:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        rows = parse_arp_table(out)
        if rows:
            return rows
    return []


def snmp_verify(ip: str, community: str = "communityName", *, port: int = 161,
                timeout: float = 1.5, client_factory=SnmpV1) -> dict:
    """Probe one IP with a single SNMP GET of the software id.

    ``client_factory`` is injectable so tests can pass a fake. Returns
    ``{ip, verified, software_id?, chassis_mac?, error?}``.
    """
    result = {"ip": ip, "verified": False}
    try:
        client = client_factory(ip, community, port=port, timeout=timeout,
                                retries=0)
        vbs = client.get([SOFTWARE_ID_OID, CHASSIS_MAC_OID])
    except SnmpError as exc:
        result["error"] = str(exc)
        return result
    except Exception as exc:  # noqa: BLE001 - never let discovery crash
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    by_oid = {vb.oid: vb.value for vb in vbs}
    sw = by_oid.get(SOFTWARE_ID_OID)
    if sw is not None and not sw.is_missing and sw.kind == "octet" and sw.raw:
        result["verified"] = True
        result["software_id"] = decode_value(sw)
        mac = by_oid.get(CHASSIS_MAC_OID)
        if mac is not None and mac.kind == "octet" and mac.raw:
            result["chassis_mac"] = decode_value(mac, as_mac=True)
    return result


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------
def discover_cix(community: str = "communityName", *, port: int = 161,
                 do_ping: bool = True, verify: bool = True,
                 timeout: float = 1.5, client_factory=SnmpV1,
                 logger=None) -> dict:
    """Find candidate CIX processors on the local LAN.

    Returns ``{networks, candidates, verified}`` where ``candidates`` is the
    union of Toshiba-OUI ARP hits and the ``.253`` convention, each optionally
    SNMP-verified. Never raises — a discovery failure degrades to an empty list.
    """
    networks = local_networks()
    if do_ping:
        for net in networks:
            try:
                cidr = str(ipaddress.ip_network(
                    f"{net['ip']}/{net['prefixlen']}", strict=False))
                ping_sweep(cidr)
            except ValueError:
                continue

    arp_rows = read_arp()
    candidates: dict[str, dict] = {}
    for c in toshiba_candidates(arp_rows):
        candidates[c["ip"]] = c
    for c in conventional_candidates(networks):
        candidates.setdefault(c["ip"], c)

    cand_list = list(candidates.values())
    verified: list[dict] = []
    if verify:
        for c in cand_list:
            v = snmp_verify(c["ip"], community, port=port, timeout=timeout,
                            client_factory=client_factory)
            c.update({k: val for k, val in v.items() if k != "ip"})
            if v.get("verified"):
                verified.append(c)
    return {
        "networks": networks,
        "candidates": cand_list,
        "verified": verified,
    }


__all__ = [
    "TOSHIBA_OUIS", "SOFTWARE_ID_OID", "CHASSIS_MAC_OID",
    "normalize_mac", "mac_oui", "is_toshiba_mac",
    "parse_arp_table", "parse_ip_addr", "parse_ifconfig", "parse_ipconfig",
    "toshiba_candidates", "conventional_candidates",
    "primary_ipv4", "local_networks", "ping_sweep", "read_arp",
    "snmp_verify", "discover_cix",
]
DISC = sys.modules[__name__]  # 'discover as DISC' alias

# ===== report.py ===================================================
"""Render a :class:`CIXReader` document as a human-readable text report.

Plain monospace text so it drops straight into a Conduit Document, a
ticket, or a terminal. No dependencies.
"""




def _hr(title: str, char: str = "=") -> str:
    return f"{title}\n{char * max(len(title), 8)}"


def render(doc: dict, *, redact_secrets: bool = False) -> str:
    lines: list[str] = []
    dev = doc.get("device", {})
    sysd = doc.get("system", {})

    lines.append(_hr("Toshiba Strata CIX — programming read"))
    lines.append(f"Device       : {dev.get('ip')}:{dev.get('port')}")
    lines.append(f"Community    : {dev.get('community')}")
    lines.append(f"Read at      : {dev.get('read_at')}")
    lines.append(f"Software id  : {sysd.get('software_id', '?')}")
    lines.append(f"Chassis MAC  : {sysd.get('chassis_mac', '?')}")
    lines.append(f"OIDs read    : {dev.get('oids_read')}")
    if dev.get("walk_error"):
        lines.append(f"WALK ERROR   : {dev['walk_error']} (output may be partial)")
    lines.append("")

    # Security findings first — they are the point of a factory-default audit.
    findings = doc.get("security_findings", [])
    if findings:
        lines.append(_hr("Security findings", "-"))
        for f in findings:
            lines.append(f"  [{f['severity'].upper()}] {f['code']}: {f['detail']}")
        lines.append("")

    # Station directory.
    stations = doc.get("stations", [])
    lines.append(_hr(f"Station directory ({len(stations)} stations)", "-"))
    if stations:
        lines.append(f"  {'DN':<8}{'Extension':<12}{'Port':<12}{'Type':<8}"
                     f"{'Name':<20}Keys")
        lines.append(f"  {'-'*6:<8}{'-'*9:<12}{'-'*10:<12}{'-'*6:<8}"
                     f"{'-'*18:<20}{'-'*4}")
        for st in stations:
            port = st.get("equipment_port")
            port = D.format_port(port) if isinstance(port, str) else (port or "")
            name = st.get("name")
            name = "" if name in (None, D.MISSING) else str(name)
            lines.append(
                f"  {st.get('dn',''):<8}"
                f"{str(st.get('extension') or ''):<12}"
                f"{str(port):<12}"
                f"{str(st.get('type') or ''):<8}"
                f"{name:<20}"
                f"{len(st.get('keys', []))}"
            )
    else:
        lines.append("  (none returned)")
    lines.append("")

    # Equipment.
    equip = doc.get("equipment", [])
    lines.append(_hr(f"Equipment / cabinet rows ({len(equip)})", "-"))
    for row in equip:
        cols = ", ".join(f"{k}={v}" for k, v in row.items() if k != "index")
        lines.append(f"  index {row.get('index')}: {cols or '(all empty)'}")
    if not equip:
        lines.append("  (none returned)")
    lines.append("")

    # System numbering / feature config (Program 579).
    numbering = sysd.get("numbering_config", {})
    if numbering:
        lines.append(_hr("System numbering / feature config (Program 579)", "-"))
        for k in sorted(numbering):
            lines.append(f"  {k:<12} = {numbering[k]}")
        lines.append("")

    # System status scalars.
    status = sysd.get("status", {})
    if status:
        lines.append(_hr("System status scalars (.7.*)", "-"))
        for k in sorted(status):
            lines.append(f"  {k:<12} = {status[k]}")
        lines.append("")

    # Network / FTP access.
    net = doc.get("network_access", [])
    if net:
        lines.append(_hr("Network / FTP access (.2.3.1.1)", "-"))
        for row in net:
            user = row.get("username", "")
            pw = row.get("password", "")
            if redact_secrets and pw not in ("", D.MISSING):
                pw = "********"
            lines.append(
                f"  row {row.get('index')}: user={user}  "
                f"password={pw}  path={row.get('path','')}"
            )
        lines.append("")

    # Per-station detail cross-reference (which extra programs touch each DN).
    detailed = [st for st in stations if st.get("programs")]
    if detailed:
        lines.append(_hr("Per-station program detail (raw passthrough)", "-"))
        for st in detailed:
            progs = ", ".join(
                f"{p}({st['programs'][p].get('name','')})"
                for p in sorted(st["programs"])
            )
            lines.append(f"  DN {st['dn']}: {progs}")
        lines.append("")

    # Raw / undecoded programs.
    raw = doc.get("raw_programs", {})
    if raw:
        lines.append(_hr("Undocumented programs (raw passthrough)", "-"))
        for prog in sorted(raw):
            bucket = raw[prog]
            lines.append(f"  Program {prog} — {bucket.get('name','')}: "
                         f"{len(bucket.get('rows', {}))} row(s)")
        lines.append("")

    stats = doc.get("stats", {})
    lines.append(_hr("Totals", "-"))
    for k in sorted(stats):
        lines.append(f"  {k:<22}: {stats[k]}")

    return "\n".join(lines) + "\n"


__all__ = ["render"]
render_report = render  # 'render as render_report' alias

# ===== cli.py ======================================================
"""Command-line entry point for the Toshiba CIX reader.

    reader.py <ip> [--community communityName] [--json out.json]
                   [--report out.txt] [--timeout 3] [--redact-secrets]
                   [--quiet]

Writes JSON and/or a text report to files when asked; otherwise prints the
text report to stdout. Read-only and idempotent.
"""


import argparse
import json
import logging
import sys



def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reader.py",
        description="Read & decode a Toshiba Strata CIX over SNMPv1 "
                    "(read-only). Enterprise MIB 1.3.6.1.4.1.186.1.22.",
    )
    p.add_argument("ip", help="CIX processor IP (conventionally x.x.x.253)")
    p.add_argument("--community", default="communityName",
                   help="SNMP v1 community (default: Toshiba factory default)")
    p.add_argument("--port", type=int, default=161)
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-request timeout in seconds (default 3, as eManager)")
    p.add_argument("--retries", type=int, default=1,
                   help="extra attempts per request on UDP timeout")
    p.add_argument("--json", dest="json_out", metavar="PATH",
                   help="write the structured JSON document to PATH")
    p.add_argument("--report", dest="report_out", metavar="PATH",
                   help="write the text report to PATH")
    p.add_argument("--redact-secrets", action="store_true",
                   help="mask FTP passwords in the text report")
    p.add_argument("--quiet", action="store_true",
                   help="do not print the report to stdout")
    p.add_argument("--max-oids", type=int, default=200000,
                   help="safety cap on OIDs walked (default 200000)")
    p.add_argument("--scope", choices=("all", "core"), default="all",
                   help="'all' reads the entire MIB (complete backup, slow on "
                        "a big system); 'core' reads only the documented "
                        "programs (stations, system, network) — much faster")
    p.add_argument("--serial", action="store_true",
                   help="use the simple single-varbind walk instead of the "
                        "fast batched walk (slower, maximally robust)")
    p.add_argument("--width", type=int, default=10,
                   help="max cursors per GETNEXT PDU in batched mode "
                        "(default 10; auto-shrinks if the agent says tooBig)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    client = SnmpV1(
        args.ip, args.community,
        port=args.port, timeout=args.timeout, retries=args.retries,
    )
    reader = CIXReader(
        client,
        max_oids=args.max_oids,
        strategy="serial" if args.serial else "bulk",
        width=args.width,
        scope=args.scope,
    )
    try:
        doc = reader.read()
    except SnmpError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if not doc["stations"] and not doc["system"].get("software_id") \
            and doc["device"]["oids_read"] == 0:
        print(
            f"ERROR: no data returned from {args.ip} — wrong community "
            f"({args.community!r}), not a CIX, or UDP 161 blocked.",
            file=sys.stderr,
        )
        return 3

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, default=_json_default)
        print(f"wrote JSON  -> {args.json_out}", file=sys.stderr)

    text = render_report(doc, redact_secrets=args.redact_secrets)
    if args.report_out:
        with open(args.report_out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote report-> {args.report_out}", file=sys.stderr)

    if not args.quiet:
        print(text)
    return 0


def _json_default(obj):
    # RowIndex / tuples etc. should never reach here (doc is plain), but be safe.
    try:
        return list(obj)
    except TypeError:
        return str(obj)
reader_cli_main = main  # reader CLI entry (webapp redefines main)

# ===== webapp.py ===================================================
"""Local web app for the Toshiba CIX Manager (pure stdlib, no pip installs).

A tech runs ``python3 app.py`` (or the single-file build) on any laptop, opens
``http://localhost:<port>`` and reads/views the CIX over SNMP — working offline,
whether plugged straight into the PBX LAN (direct) or reaching it over an RSM
(remote). It is just SNMP to an IP either way; nothing here depends on the
internet, Conduit or ZeroTier.

Served endpoints (all JSON unless noted):
    GET  /                 the single-page UI (``webui.html``)
    GET  /api/health       {ok, version}
    GET  /api/discover     local-LAN auto-discovery of CIX processors
    POST /api/connect      {ip, community, port} -> test GET of the software id
    POST /api/read         {ip, community, port, scope} -> full structured doc
    POST /api/backup       {doc} -> a .zip (programming.json + report + oid walk)
    POST /api/save         {ip, station, changes} -> write PREVIEW (never sends)

The server binds to loopback by default so only the local browser can reach it.
All SNMP is read-only (GET/GETNEXT); ``/api/save`` goes through
:mod:`toshiba_cix.write`, which is stubbed and cannot emit a SET.
"""


import io
import json
import logging
import os
import socket
import sys
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Non-aliased so the single-file build (which flattens the package into one
# module and strips intra-package imports) resolves these as globals.

log = logging.getLogger("toshiba_cix.webapp")

_HTML_CACHE: str | None = None


def load_html() -> str:
    """Return the UI HTML, wherever this is running from.

    Order: the base64-embedded copy (the ``toshiba_cix_manager.py`` standalone)
    → a PyInstaller bundle (``sys._MEIPASS``) → the sibling ``webui.html`` (from
    the package / a dev checkout). This lets the same server code back the
    single-file build, the double-click ``.exe`` and ``python3 app.py``.
    """
    global _HTML_CACHE
    if _HTML_CACHE is not None:
        return _HTML_CACHE
    embedded = globals().get("EMBEDDED_WEBUI_HTML")
    if embedded:
        _HTML_CACHE = embedded
        return _HTML_CACHE
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)   # set when frozen by PyInstaller
    if meipass:
        candidates.append(os.path.join(meipass, "toshiba_cix", "webui.html"))
        candidates.append(os.path.join(meipass, "webui.html"))
    candidates.append(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui.html"))
    for path in candidates:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                _HTML_CACHE = fh.read()
            return _HTML_CACHE
    raise FileNotFoundError("webui.html not found (looked in: "
                            + ", ".join(candidates) + ")")


def _reader(params: dict, *, keep_raw_walk: bool) -> CIXReader:
    ip = (params.get("ip") or "").strip()
    if not ip:
        raise ValueError("missing CIX IP address")
    community = (params.get("community") or "communityName").strip() or "communityName"
    port = int(params.get("port") or 161)
    timeout = float(params.get("timeout") or 3.0)
    retries = int(params.get("retries") or 1)
    scope = params.get("scope") or "core"
    strategy = "serial" if params.get("serial") else "bulk"
    width = int(params.get("width") or 10)
    client = SnmpV1(ip, community, port=port, timeout=timeout, retries=retries)
    return CIXReader(client, scope=scope, strategy=strategy, width=width,
                     keep_raw_walk=keep_raw_walk)


class CIXHandler(BaseHTTPRequestHandler):
    server_version = f"ToshibaCIXManager/{__version__}"

    # Quiet the default noisy logging; route through our logger instead.
    def log_message(self, fmt, *args):  # noqa: N802
        log.debug("%s - %s", self.address_string(), fmt % args)

    # -- helpers ----------------------------------------------------------
    def _send_json(self, obj, status=200):
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body, content_type, status=200, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    # -- routing ----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            html = load_html().encode("utf-8")
            self._send_bytes(html, "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._send_json({"ok": True, "version": __version__,
                             "writes_enabled": WRITES_ENABLED})
            return
        if path == "/api/discover":
            self._handle_discover()
            return
        if path == "/api/catalog":
            self._handle_catalog()
            return
        self._send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        try:
            params = self._read_body()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": f"bad request body: {exc}"},
                            status=400)
            return
        if path == "/api/connect":
            self._handle_connect(params)
        elif path == "/api/read":
            self._handle_read(params)
        elif path == "/api/backup":
            self._handle_backup(params)
        elif path == "/api/save":
            self._handle_save(params)
        elif path == "/api/catalog-backup":
            self._handle_catalog_backup(params)
        elif path == "/api/view":
            self._handle_view(params)
        elif path == "/api/diff":
            self._handle_diff(params)
        elif path == "/api/restore":
            self._handle_restore(params)
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

    # -- handlers ---------------------------------------------------------
    def _handle_connect(self, params):
        try:
            reader = _reader(params, keep_raw_walk=False)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        client = reader.client
        try:
            vbs = client.get([DISC.SOFTWARE_ID_OID, DISC.CHASSIS_MAC_OID])
        except SnmpError as exc:
            self._send_json({"ok": False, "error": str(exc)})
            return
        by_oid = {vb.oid: vb.value for vb in vbs}
        sw = by_oid.get(DISC.SOFTWARE_ID_OID)
        if sw is None or sw.is_missing or sw.kind != "octet" or not sw.raw:
            self._send_json({"ok": False,
                             "error": "no CIX software-id reply (wrong community, "
                                      "not a CIX, or UDP 161 blocked)"})
            return
        out = {"ok": True, "software_id": D.decode_value(sw)}
        mac = by_oid.get(DISC.CHASSIS_MAC_OID)
        if mac is not None and mac.kind == "octet" and mac.raw:
            out["chassis_mac"] = D.decode_value(mac, as_mac=True)
        self._send_json(out)

    def _handle_read(self, params):
        try:
            reader = _reader(params, keep_raw_walk=True)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        try:
            doc = reader.read()
        except SnmpError as exc:
            self._send_json({"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("read failed")
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        if not doc.get("stations") and not doc["system"].get("software_id") \
                and doc["device"]["oids_read"] == 0:
            self._send_json({"ok": False,
                             "error": "no data returned — wrong community, not a "
                                      "CIX, or UDP 161 blocked"})
            return
        self._send_json({"ok": True, "doc": doc, "report": render_report(doc)})

    def _handle_backup(self, params):
        doc = params.get("doc")
        if not isinstance(doc, dict):
            self._send_json({"ok": False, "error": "missing doc"}, status=400)
            return
        try:
            body = build_backup_zip(doc)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        ip = (doc.get("device") or {}).get("ip") or "cix"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        fname = f"toshiba-cix-{str(ip).replace('/', '_')}-{ts}-backup.zip"
        self._send_bytes(body, "application/zip", filename=fname)

    def _handle_discover(self):
        try:
            result = DISC.discover_cix()
            result["ok"] = True
            self._send_json(result)
        except Exception as exc:  # noqa: BLE001
            log.exception("discover failed")
            self._send_json({"ok": False, "error": str(exc),
                             "candidates": []})

    def _handle_save(self, params):
        """Plan a station edit, and either PREVIEW it (default) or, with an
        explicit ``confirm: true``, send the live batched SET and GET-verify.

        The preview path never touches the network. The write path is gated by
        ``WRITES_ENABLED`` and ``confirm``; it always reads the values back and
        returns requested-vs-read-back so a write is never silent.
        """
        station = params.get("station") or {}
        changes = params.get("changes") or {}
        confirm = bool(params.get("confirm"))
        writer = CIXWriter()
        try:
            ops = writer.plan_station_update(station, changes)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return

        if not confirm:
            self._send_json({
                "ok": True,
                "mode": "preview",
                "writes_enabled": WRITES_ENABLED,
                "message": ("Preview only — nothing was sent. Use "
                            "“Confirm & write” to apply these SETs."),
                "planned_ops": [op.as_dict() for op in ops],
            })
            return

        # Live write path.
        try:
            reader = _reader(params, keep_raw_walk=False)   # builds the client
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        writer = CIXWriter(reader.client)
        try:
            result = writer.commit(ops, confirm=True, verify=True)
        except (WriteError, SnmpError) as exc:
            self._send_json({"ok": False, "mode": "write",
                             "error": str(exc),
                             "planned_ops": [op.as_dict() for op in ops]})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("write failed")
            self._send_json({"ok": False, "mode": "write",
                             "error": f"{type(exc).__name__}: {exc}"})
            return
        self._send_json({
            "ok": result["ok"],
            "mode": "write",
            "writes_enabled": WRITES_ENABLED,
            "message": ("Write sent and verified." if result["ok"]
                        else "Write sent but read-back did not match — check the "
                             "results below."),
            "result": result,
            "planned_ops": [op.as_dict() for op in ops],
        })


    # -- catalog-driven backup / view / diff / restore --------------------
    def _handle_catalog(self):
        """Report the vendored catalog's identity (version + counts)."""
        try:
            cat = load_catalog()
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        out = {"ok": True, "writes_enabled": WRITES_ENABLED}
        out.update(cat.summary())
        self._send_json(out)

    def _handle_catalog_backup(self, params):
        """Read a live CIX into a catalog backup (read-only). Returns the
        backup doc + a text rendering; the UI saves the JSON locally."""
        try:
            reader = _reader(params, keep_raw_walk=False)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        programs = params.get("programs") or None
        site = params.get("site")
        try:
            cat = load_catalog()
            doc = backup(reader.client, cat, site=site, programs=programs,
                            width=reader.width)
        except SnmpError as exc:
            self._send_json({"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("catalog backup failed")
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        if doc["meta"].get("oids_read", 0) == 0:
            self._send_json({"ok": False,
                             "error": "no data returned — wrong community, not a "
                                      "CIX, or UDP 161 blocked"})
            return
        self._send_json({"ok": True, "backup": doc,
                         "report": render_backup_text(doc, catalog=cat)})

    def _handle_view(self, params):
        doc = params.get("backup")
        if not isinstance(doc, dict):
            self._send_json({"ok": False, "error": "missing backup"}, status=400)
            return
        try:
            cat = load_catalog()
            report = render_backup_text(doc, catalog=cat,
                                        program=params.get("program"),
                                        max_rows=params.get("max_rows"))
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        self._send_json({"ok": True, "report": report,
                         "meta": doc.get("meta", {}),
                         "programs": sorted(doc.get("programs", {}).keys())})

    def _handle_diff(self, params):
        a, b = params.get("a"), params.get("b")
        if not isinstance(a, dict) or not isinstance(b, dict):
            self._send_json({"ok": False, "error": "need two backups (a, b)"},
                            status=400)
            return
        try:
            cat = load_catalog()
            d = diff_backups(a, b, catalog=cat,
                             ignore_readonly=not params.get("all"))
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        self._send_json({"ok": True, "diff": d, "report": render_diff_text(d)})

    def _handle_restore(self, params):
        """Plan a restore and either PREVIEW it (default) or, with an explicit
        ``confirm: true``, send the batched catalog-driven SETs and GET-verify.

        Gated by WRITES_ENABLED + confirm (reusing CIXWriter). Read-only fields
        are never sent; applies to RAM (reboot persistence unproven)."""
        doc = params.get("backup")
        if not isinstance(doc, dict):
            self._send_json({"ok": False, "error": "missing backup"}, status=400)
            return
        confirm = bool(params.get("confirm"))
        programs = params.get("programs") or None
        from_diff = params.get("from_diff") or None
        try:
            cat = load_catalog()
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        client = None
        if confirm:
            try:
                reader = _reader(params, keep_raw_walk=False)
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            client = reader.client
        try:
            result = restore(client, doc, cat, confirm=confirm,
                                programs=programs, from_diff=from_diff)
        except (WriteError, SnmpError) as exc:
            self._send_json({"ok": False, "mode": "write", "error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("restore failed")
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        self._send_json(result)


def build_backup_zip(doc: dict) -> bytes:
    """Pack a read into a .zip: programming.json + report.txt + raw OID walk."""
    buf = io.BytesIO()
    ip = (doc.get("device") or {}).get("ip") or "cix"
    read_at = (doc.get("device") or {}).get("read_at") or ""
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("programming.json", json.dumps(doc, indent=2, default=str))
        zf.writestr("report.txt", render_report(doc))
        walk = doc.get("raw_oid_walk")
        if walk:
            lines = [f"{e.get('oid')} = {e.get('value')}" for e in walk]
            zf.writestr("raw-oid-walk.txt", "\n".join(lines) + "\n")
        manifest = (
            "Toshiba Strata CIX backup\n"
            f"Device   : {ip}\n"
            f"Read at  : {read_at}\n"
            f"Software : {(doc.get('system') or {}).get('software_id', '?')}\n"
            f"Stations : {(doc.get('stats') or {}).get('stations', '?')}\n"
            f"OIDs     : {(doc.get('device') or {}).get('oids_read', '?')}\n"
            "\nFiles:\n"
            "  programming.json  structured programming (re-openable in this tool)\n"
            "  report.txt        human-readable report\n"
            + ("  raw-oid-walk.txt  every OID read, verbatim\n" if walk else "")
        )
        zf.writestr("MANIFEST.txt", manifest)
    return buf.getvalue()


def _pick_port(host: str, preferred: int) -> int:
    """Return ``preferred`` if free, else the next free port (up to +20)."""
    for port in range(preferred, preferred + 21):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    return preferred


def serve(host: str = "127.0.0.1", port: int = 8765, *,
          open_browser: bool = True) -> None:
    port = _pick_port(host, port)
    httpd = ThreadingHTTPServer((host, port), CIXHandler)
    url = f"http://{host}:{port}"
    print(f"Toshiba CIX Manager {__version__}")
    print(f"  Open: {url}")
    print("  Read-only SNMP. Writes are stubbed (not enabled). Ctrl-C to stop.")
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        httpd.server_close()


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="toshiba-cix-manager",
        description="Local web app to read/view a Toshiba Strata CIX over SNMP "
                    "(read-only). Serves a UI on localhost.",
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1 — local only)")
    p.add_argument("--port", type=int, default=8765,
                   help="port (default 8765; next free port if busy)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not auto-open the browser")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    serve(args.host, args.port, open_browser=not args.no_browser)
    return 0
EMBEDDED_WEBUI_HTML = base64.b64decode("PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KPHRpdGxlPlRvc2hpYmEgQ0lYIE1hbmFnZXI8L3RpdGxlPgo8c3R5bGU+CiAgOnJvb3R7CiAgICAtLWJnOiMwZjE3MjA7IC0tcGFuZWw6IzE3MjEyZTsgLS1wYW5lbDI6IzFlMmEzYTsgLS1saW5lOiMyYjNhNGU7CiAgICAtLWZnOiNlN2VlZjY7IC0tbXV0ZWQ6IzlmYjBjMzsgLS1hY2NlbnQ6IzRhYTNmZjsgLS1hY2NlbnQyOiMyYjc4ZDQ7CiAgICAtLW9rOiMzNmMwOGE7IC0td2FybjojZmZiNjQ4OyAtLWJhZDojZmY2YjZiOyAtLWNoaXA6IzI0MzQ0YTsKICB9CiAgQG1lZGlhIChwcmVmZXJzLWNvbG9yLXNjaGVtZTogbGlnaHQpewogICAgOnJvb3R7CiAgICAgIC0tYmc6I2YzZjZmYTsgLS1wYW5lbDojZmZmZmZmOyAtLXBhbmVsMjojZWVmM2Y5OyAtLWxpbmU6I2Q1ZGZlYTsKICAgICAgLS1mZzojMTMyMDJlOyAtLW11dGVkOiM1YjZiN2Q7IC0tYWNjZW50OiMxNzY5Yzk7IC0tYWNjZW50MjojMGY0ZjllOwogICAgICAtLW9rOiMxMTdhNTU7IC0td2FybjojOWE2NDAwOyAtLWJhZDojYzAzOTJiOyAtLWNoaXA6I2U1ZWRmNjsKICAgIH0KICB9CiAgKntib3gtc2l6aW5nOmJvcmRlci1ib3h9CiAgYm9keXttYXJnaW46MDtmb250OjE0cHgvMS40NSBzeXN0ZW0tdWksLWFwcGxlLXN5c3RlbSxTZWdvZSBVSSxSb2JvdG8sSGVsdmV0aWNhLEFyaWFsLHNhbnMtc2VyaWY7CiAgICAgICBiYWNrZ3JvdW5kOnZhcigtLWJnKTtjb2xvcjp2YXIoLS1mZyl9CiAgYXtjb2xvcjp2YXIoLS1hY2NlbnQpfQogIGhlYWRlcntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxNHB4O3BhZGRpbmc6MTBweCAxNnB4O2JhY2tncm91bmQ6dmFyKC0tcGFuZWwpOwogICAgICAgICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKTtwb3NpdGlvbjpzdGlja3k7dG9wOjA7ei1pbmRleDoxMDtmbGV4LXdyYXA6d3JhcH0KICBoZWFkZXIgaDF7Zm9udC1zaXplOjE2cHg7bWFyZ2luOjA7Zm9udC13ZWlnaHQ6NjUwO2xldHRlci1zcGFjaW5nOi4ycHh9CiAgLnJvLWJhZGdle2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjojMGIyMDMzO2JhY2tncm91bmQ6dmFyKC0td2Fybik7CiAgICAgICAgICAgIHBhZGRpbmc6M3B4IDhweDtib3JkZXItcmFkaXVzOjIwcHh9CiAgLnN0YXR1c3ttYXJnaW4tbGVmdDphdXRvO2NvbG9yOnZhcigtLW11dGVkKTtmb250LXNpemU6MTJweDt0ZXh0LWFsaWduOnJpZ2h0fQogIC5zdGF0dXMgYntjb2xvcjp2YXIoLS1mZyl9CiAgbWFpbntwYWRkaW5nOjE2cHg7bWF4LXdpZHRoOjExODBweDttYXJnaW46MCBhdXRvfQogIC5jYXJke2JhY2tncm91bmQ6dmFyKC0tcGFuZWwpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMnB4OwogICAgICAgIHBhZGRpbmc6MTZweDttYXJnaW4tYm90dG9tOjE2cHh9CiAgLmNhcmQgaDJ7Zm9udC1zaXplOjE0cHg7bWFyZ2luOjAgMCAxMnB4O3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouNXB4O2NvbG9yOnZhcigtLW11dGVkKX0KICBsYWJlbHtkaXNwbGF5OmJsb2NrO2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLW11dGVkKTttYXJnaW46MCAwIDRweH0KICBpbnB1dCxzZWxlY3R7d2lkdGg6MTAwJTtwYWRkaW5nOjhweCAxMHB4O2JhY2tncm91bmQ6dmFyKC0tcGFuZWwyKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpOwogICAgICAgICBib3JkZXItcmFkaXVzOjhweDtjb2xvcjp2YXIoLS1mZyk7Zm9udDppbmhlcml0fQogIGlucHV0OmZvY3VzLHNlbGVjdDpmb2N1c3tvdXRsaW5lOjJweCBzb2xpZCB2YXIoLS1hY2NlbnQpO291dGxpbmUtb2Zmc2V0Oi0xcHh9CiAgLmdyaWR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoYXV0by1maXQsbWlubWF4KDE1MHB4LDFmcikpO2dhcDoxMnB4fQogIC5yb3d7ZGlzcGxheTpmbGV4O2dhcDoxMHB4O2ZsZXgtd3JhcDp3cmFwO2FsaWduLWl0ZW1zOmZsZXgtZW5kfQogIC5idG57YXBwZWFyYW5jZTpub25lO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYWNjZW50Mik7YmFja2dyb3VuZDp2YXIoLS1hY2NlbnQpO2NvbG9yOiNmZmY7CiAgICAgICBmb250OmluaGVyaXQ7Zm9udC13ZWlnaHQ6NjAwO3BhZGRpbmc6OHB4IDE0cHg7Ym9yZGVyLXJhZGl1czo4cHg7Y3Vyc29yOnBvaW50ZXJ9CiAgLmJ0bjpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWFjY2VudDIpfQogIC5idG4uZ2hvc3R7YmFja2dyb3VuZDp0cmFuc3BhcmVudDtjb2xvcjp2YXIoLS1hY2NlbnQpO2JvcmRlci1jb2xvcjp2YXIoLS1saW5lKX0KICAuYnRuLmdob3N0OmhvdmVye2JhY2tncm91bmQ6dmFyKC0tcGFuZWwyKX0KICAuYnRuOmRpc2FibGVke29wYWNpdHk6LjU7Y3Vyc29yOm5vdC1hbGxvd2VkfQogIC5idG4uc21hbGx7cGFkZGluZzo1cHggMTBweDtmb250LXNpemU6MTJweH0KICAubXNne3BhZGRpbmc6MTBweCAxMnB4O2JvcmRlci1yYWRpdXM6OHB4O21hcmdpbi10b3A6MTJweDtmb250LXNpemU6MTNweDtkaXNwbGF5Om5vbmV9CiAgLm1zZy5zaG93e2Rpc3BsYXk6YmxvY2t9CiAgLm1zZy5va3tiYWNrZ3JvdW5kOnJnYmEoNTQsMTkyLDEzOCwuMTQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tb2spO2NvbG9yOnZhcigtLW9rKX0KICAubXNnLmVycntiYWNrZ3JvdW5kOnJnYmEoMjU1LDEwNywxMDcsLjE0KTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJhZCk7Y29sb3I6dmFyKC0tYmFkKX0KICAubXNnLmluZm97YmFja2dyb3VuZDpyZ2JhKDc0LDE2MywyNTUsLjEyKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWFjY2VudCk7Y29sb3I6dmFyKC0tZmcpfQogIC50YWJze2Rpc3BsYXk6ZmxleDtnYXA6NHB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbi1ib3R0b206MTRweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKX0KICAudGFie3BhZGRpbmc6OHB4IDE0cHg7Y3Vyc29yOnBvaW50ZXI7Y29sb3I6dmFyKC0tbXV0ZWQpO2JvcmRlci1ib3R0b206MnB4IHNvbGlkIHRyYW5zcGFyZW50OwogICAgICAgZm9udC13ZWlnaHQ6NjAwO2ZvbnQtc2l6ZToxM3B4fQogIC50YWIuYWN0aXZle2NvbG9yOnZhcigtLWZnKTtib3JkZXItYm90dG9tLWNvbG9yOnZhcigtLWFjY2VudCl9CiAgLnRhYiAuY291bnR7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tbXV0ZWQpO2ZvbnQtd2VpZ2h0OjUwMH0KICAudmlld3tkaXNwbGF5Om5vbmV9CiAgLnZpZXcuYWN0aXZle2Rpc3BsYXk6YmxvY2t9CiAgdGFibGV7d2lkdGg6MTAwJTtib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Zm9udC1zaXplOjEzcHh9CiAgdGgsdGR7dGV4dC1hbGlnbjpsZWZ0O3BhZGRpbmc6N3B4IDEwcHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbGluZSk7dmVydGljYWwtYWxpZ246dG9wfQogIHRoe2NvbG9yOnZhcigtLW11dGVkKTtmb250LXNpemU6MTFweDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6LjRweDsKICAgICBwb3NpdGlvbjpzdGlja3k7dG9wOjU0cHg7YmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7Y3Vyc29yOnBvaW50ZXI7dXNlci1zZWxlY3Q6bm9uZX0KICB0Ym9keSB0cjpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXBhbmVsMil9CiAgdHIuY2xpY2thYmxle2N1cnNvcjpwb2ludGVyfQogIC5tb25ve2ZvbnQtZmFtaWx5OnVpLW1vbm9zcGFjZSxTRk1vbm8tUmVndWxhcixNZW5sbyxDb25zb2xhcyxtb25vc3BhY2U7Zm9udC1zaXplOjEycHh9CiAgLmNoaXB7ZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDp2YXIoLS1jaGlwKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MjBweDsKICAgICAgICBwYWRkaW5nOjJweCA5cHg7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tbXV0ZWQpO21hcmdpbjowIDRweCA0cHggMH0KICAuZmluZGluZ3twYWRkaW5nOjEwcHggMTJweDtib3JkZXItcmFkaXVzOjhweDttYXJnaW4tYm90dG9tOjhweDtmb250LXNpemU6MTNweH0KICAuZmluZGluZy5oaWdoe2JhY2tncm91bmQ6cmdiYSgyNTUsMTA3LDEwNywuMTIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYmFkKX0KICAuZmluZGluZy5tZWRpdW17YmFja2dyb3VuZDpyZ2JhKDI1NSwxODIsNzIsLjEyKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXdhcm4pfQogIC5zZXZ7Zm9udC13ZWlnaHQ6NzAwO21hcmdpbi1yaWdodDo2cHh9CiAgLnRvb2xiYXJ7ZGlzcGxheTpmbGV4O2dhcDoxMHB4O2FsaWduLWl0ZW1zOmNlbnRlcjttYXJnaW4tYm90dG9tOjEycHg7ZmxleC13cmFwOndyYXB9CiAgLnRvb2xiYXIgaW5wdXRbdHlwZT1zZWFyY2hde21heC13aWR0aDozMjBweH0KICAubXV0ZWR7Y29sb3I6dmFyKC0tbXV0ZWQpfQogIC5rdntkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjIwMHB4IDFmcjtnYXA6NHB4IDE0cHg7Zm9udC1zaXplOjEzcHh9CiAgLmt2IGRpdi5re2NvbG9yOnZhcigtLW11dGVkKX0KICAvKiBkcmF3ZXIgKi8KICAub3ZlcmxheXtwb3NpdGlvbjpmaXhlZDtpbnNldDowO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwuNDUpO2Rpc3BsYXk6bm9uZTt6LWluZGV4OjQwfQogIC5vdmVybGF5LnNob3d7ZGlzcGxheTpibG9ja30KICAuZHJhd2Vye3Bvc2l0aW9uOmZpeGVkO3RvcDowO3JpZ2h0OjA7aGVpZ2h0OjEwMCU7d2lkdGg6bWluKDU2MHB4LDEwMCUpO2JhY2tncm91bmQ6dmFyKC0tcGFuZWwpOwogICAgICAgICAgYm9yZGVyLWxlZnQ6MXB4IHNvbGlkIHZhcigtLWxpbmUpO3RyYW5zZm9ybTp0cmFuc2xhdGVYKDEwMCUpO3RyYW5zaXRpb246dHJhbnNmb3JtIC4yczsKICAgICAgICAgIHotaW5kZXg6NTA7b3ZlcmZsb3cteTphdXRvO3BhZGRpbmc6MThweH0KICAuZHJhd2VyLnNob3d7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoMCl9CiAgLmRyYXdlciBoM3ttYXJnaW46MCAwIDRweH0KICAuZHJhd2VyIC5jbG9zZXtwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MTRweDtyaWdodDoxNnB4O2N1cnNvcjpwb2ludGVyO2NvbG9yOnZhcigtLW11dGVkKTsKICAgICAgICAgICAgICAgICBmb250LXNpemU6MjJweDtsaW5lLWhlaWdodDoxO2JhY2tncm91bmQ6bm9uZTtib3JkZXI6bm9uZX0KICAuZmllbGQtZWRpdHtkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjEyMHB4IDFmcjtnYXA6OHB4O2FsaWduLWl0ZW1zOmNlbnRlcjttYXJnaW4tYm90dG9tOjhweH0KICAuZmllbGQtZWRpdCBsYWJlbHttYXJnaW46MH0KICBkZXRhaWxze2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czo4cHg7bWFyZ2luLWJvdHRvbTo4cHg7cGFkZGluZzo2cHggMTBweH0KICBzdW1tYXJ5e2N1cnNvcjpwb2ludGVyO2ZvbnQtd2VpZ2h0OjYwMDtjb2xvcjp2YXIoLS1tdXRlZCl9CiAgLmhpZGV7ZGlzcGxheTpub25lIWltcG9ydGFudH0KICAuY2VudGVye3RleHQtYWxpZ246Y2VudGVyO3BhZGRpbmc6NDBweCAwO2NvbG9yOnZhcigtLW11dGVkKX0KICAuc3Bpbm5lcntkaXNwbGF5OmlubGluZS1ibG9jazt3aWR0aDoxOHB4O2hlaWdodDoxOHB4O2JvcmRlcjozcHggc29saWQgdmFyKC0tbGluZSk7CiAgICAgICAgICAgYm9yZGVyLXRvcC1jb2xvcjp2YXIoLS1hY2NlbnQpO2JvcmRlci1yYWRpdXM6NTAlO2FuaW1hdGlvbjpzcGluIC44cyBsaW5lYXIgaW5maW5pdGU7CiAgICAgICAgICAgdmVydGljYWwtYWxpZ246LTRweDttYXJnaW4tcmlnaHQ6OHB4fQogIEBrZXlmcmFtZXMgc3Bpbnt0b3t0cmFuc2Zvcm06cm90YXRlKDM2MGRlZyl9fQogIC5leHAtYnRuc3tkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7ZmxleC13cmFwOndyYXB9CiAgZm9vdGVye2NvbG9yOnZhcigtLW11dGVkKTtmb250LXNpemU6MTFweDt0ZXh0LWFsaWduOmNlbnRlcjtwYWRkaW5nOjE2cHh9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CjxoZWFkZXI+CiAgPGgxPlRvc2hpYmEgQ0lYIE1hbmFnZXI8L2gxPgogIDxzcGFuIGNsYXNzPSJyby1iYWRnZSIgaWQ9Im1vZGVCYWRnZSIgdGl0bGU9IlJlYWRzIGFyZSBwbGFpbiBTTk1QIEdFVHMuIFdyaXRlcyByZXF1aXJlIGFuIGV4cGxpY2l0IENvbmZpcm0gJmFtcDsgd3JpdGUgYW5kIGFyZSByZWFkLWJhY2sgdmVyaWZpZWQuIj5SRUFELU9OTFk8L3NwYW4+CiAgPGRpdiBjbGFzcz0ic3RhdHVzIiBpZD0ic3RhdHVzIj5Ob3QgY29ubmVjdGVkPC9kaXY+CjwvaGVhZGVyPgoKPG1haW4+CiAgPCEtLSBDT05ORUNUIC0tPgogIDxzZWN0aW9uIGlkPSJjb25uZWN0IiBjbGFzcz0iY2FyZCI+CiAgICA8aDI+Q29ubmVjdCB0byBhIFN0cmF0YSBDSVg8L2gyPgogICAgPHAgY2xhc3M9Im11dGVkIiBzdHlsZT0ibWFyZ2luLXRvcDotNnB4Ij4KICAgICAgUGx1ZyBzdHJhaWdodCBpbnRvIHRoZSBQQlggdm9pY2UtTEFOIHBvcnQgKGRpcmVjdCksIG9yIHJlYWNoIGl0IG92ZXIgYW4gUlNNL1plcm9UaWVyCiAgICAgIChyZW1vdGUpICZtZGFzaDsgZWl0aGVyIHdheSBpdCBpcyBqdXN0IFNOTVAgdG8gYW4gSVAuIE5vIGludGVybmV0IHJlcXVpcmVkLgogICAgPC9wPgogICAgPGRpdiBjbGFzcz0iZ3JpZCI+CiAgICAgIDxkaXY+PGxhYmVsPkNJWCBJUCBhZGRyZXNzPC9sYWJlbD48aW5wdXQgaWQ9ImlwIiBwbGFjZWhvbGRlcj0iMTkyLjE2OC4yNTQuMjUzIiBhdXRvY29tcGxldGU9Im9mZiI+PC9kaXY+CiAgICAgIDxkaXY+PGxhYmVsPlNOTVAgY29tbXVuaXR5PC9sYWJlbD48aW5wdXQgaWQ9ImNvbW11bml0eSIgdmFsdWU9ImNvbW11bml0eU5hbWUiIGF1dG9jb21wbGV0ZT0ib2ZmIj48L2Rpdj4KICAgICAgPGRpdj48bGFiZWw+UG9ydDwvbGFiZWw+PGlucHV0IGlkPSJwb3J0IiB2YWx1ZT0iMTYxIj48L2Rpdj4KICAgICAgPGRpdj48bGFiZWw+U2NvcGU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9InNjb3BlIj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImNvcmUiPmNvcmUgJm1kYXNoOyBmYXN0IChzdGF0aW9ucywgc3lzdGVtLCBuZXR3b3JrKTwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iYWxsIj5hbGwgJm1kYXNoOyBmdWxsIGJhY2t1cCAoc2xvdywgd2hvbGUgTUlCKTwvb3B0aW9uPgogICAgICAgIDwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0icm93IiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4Ij4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0iYnRuUmVhZCI+UmVhZCBzeXN0ZW08L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IiBpZD0iYnRuVGVzdCI+VGVzdCBjb25uZWN0aW9uPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9ImJ0bkRpc2NvdmVyIj5BdXRvLWRpc2NvdmVyPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9ImJ0bk9wZW4iPk9wZW4gYmFja3VwIGZpbGUmaGVsbGlwOzwvYnV0dG9uPgogICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImZpbGVJbnB1dCIgYWNjZXB0PSIuanNvbixhcHBsaWNhdGlvbi9qc29uIiBjbGFzcz0iaGlkZSI+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1zZyIgaWQ9ImNvbm5lY3RNc2ciPjwvZGl2PgogICAgPGRpdiBpZD0iZGlzY292ZXJCb3giIGNsYXNzPSJoaWRlIiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4Ij4KICAgICAgPGgyPkRpc2NvdmVyZWQgY2FuZGlkYXRlczwvaDI+CiAgICAgIDx0YWJsZT48dGhlYWQ+PHRyPjx0aD5JUDwvdGg+PHRoPk1BQzwvdGg+PHRoPkZvdW5kIHZpYTwvdGg+PHRoPlZlcmlmaWVkPC90aD48dGg+PC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJkaXNjb3ZlclJvd3MiPjwvdGJvZHk+PC90YWJsZT4KICAgIDwvZGl2PgogIDwvc2VjdGlvbj4KCiAgPCEtLSBDQVRBTE9HIEJBQ0tVUCAvIFZJRVcgLyBESUZGIC8gUkVTVE9SRSAtLT4KICA8c2VjdGlvbiBpZD0iY2F0YWxvZyIgY2xhc3M9ImNhcmQiPgogICAgPGgyPkNhdGFsb2cgYmFja3VwICZtaWRkb3Q7IHZpZXcgJm1pZGRvdDsgZGlmZiAmbWlkZG90OyByZXN0b3JlPC9oMj4KICAgIDxwIGNsYXNzPSJtdXRlZCIgc3R5bGU9Im1hcmdpbi10b3A6LTZweCI+CiAgICAgIEEgY29tcGxldGUsIGNhdGFsb2ctZHJpdmVuIGJhY2t1cCBvZiBldmVyeSBwcm9ncmFtIHRoZSBlTWFuYWdlciBtb2RlbCBrbm93cwogICAgICAoPHNwYW4gaWQ9ImNhdEluZm8iPmxvYWRpbmcgY2F0YWxvZyZoZWxsaXA7PC9zcGFuPikuIFVzZXMgdGhlIElQIC8gY29tbXVuaXR5IC8gcG9ydCBhYm92ZS4KICAgICAgUmVzdG9yZSBpcyBnYXRlZCBhbmQgcmVhZC1iYWNrIHZlcmlmaWVkICZtZGFzaDsgcmVhZC1vbmx5IGZpZWxkcyBhcmUgbmV2ZXIgd3JpdHRlbi4KICAgIDwvcD4KICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImJ0bkNhdEJhY2t1cCI+RnVsbCBjYXRhbG9nIGJhY2t1cCAobGl2ZSByZWFkKTwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJidG5PcGVuQSI+T3BlbiBiYWNrdXAgJnJhcnI7IEEmaGVsbGlwOzwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJidG5PcGVuQiI+T3BlbiBiYWNrdXAgJnJhcnI7IEImaGVsbGlwOzwvYnV0dG9uPgogICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImNhdEZpbGVBIiBhY2NlcHQ9Ii5qc29uLGFwcGxpY2F0aW9uL2pzb24iIGNsYXNzPSJoaWRlIj4KICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJjYXRGaWxlQiIgYWNjZXB0PSIuanNvbixhcHBsaWNhdGlvbi9qc29uIiBjbGFzcz0iaGlkZSI+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InJvdyIgc3R5bGU9Im1hcmdpbi10b3A6MTBweDthbGlnbi1pdGVtczpjZW50ZXIiPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCIgaWQ9InNsb3RBIj5BOiAoZW1wdHkpPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCIgaWQ9InNsb3RCIj5COiAoZW1wdHkpPC9zcGFuPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3Qgc21hbGwiIGlkPSJidG5DYXRWaWV3IiBkaXNhYmxlZD5WaWV3IEE8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IHNtYWxsIiBpZD0iYnRuQ2F0RGlmZiIgZGlzYWJsZWQ+RGlmZiBBICZyYXJyOyBCPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCBzbWFsbCIgaWQ9ImJ0bkNhdERvd25sb2FkIiBkaXNhYmxlZD5Eb3dubG9hZCBBICguanNvbik8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IHNtYWxsIiBpZD0iYnRuQ2F0UmVzdG9yZVByZXYiIGRpc2FibGVkPlByZXZpZXcgcmVzdG9yZSBvZiBBPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBzbWFsbCIgaWQ9ImJ0bkNhdFJlc3RvcmVHbyIgZGlzYWJsZWQ+Q29uZmlybSAmYW1wOyByZXN0b3JlIEE8L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ibXNnIiBpZD0iY2F0TXNnIj48L2Rpdj4KICAgIDxwcmUgaWQ9ImNhdE91dCIgY2xhc3M9Im1vbm8iIHN0eWxlPSJ3aGl0ZS1zcGFjZTpwcmUtd3JhcDttYXgtaGVpZ2h0OjQ2MHB4O292ZXJmbG93OmF1dG87YmFja2dyb3VuZDp2YXIoLS1wYW5lbDIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czo4cHg7cGFkZGluZzoxMnB4O21hcmdpbi10b3A6MTJweDtkaXNwbGF5Om5vbmUiPjwvcHJlPgogIDwvc2VjdGlvbj4KCiAgPCEtLSBSRVNVTFRTIC0tPgogIDxzZWN0aW9uIGlkPSJyZXN1bHRzIiBjbGFzcz0iaGlkZSI+CiAgICA8ZGl2IGNsYXNzPSJ0YWJzIiBpZD0idGFicyI+CiAgICAgIDxkaXYgY2xhc3M9InRhYiBhY3RpdmUiIGRhdGEtdmlldz0ib3ZlcnZpZXciPk92ZXJ2aWV3PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJzdGF0aW9ucyI+U3RhdGlvbnMgPHNwYW4gY2xhc3M9ImNvdW50IiBpZD0iY1N0YXRpb25zIj48L3NwYW4+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJlcXVpcG1lbnQiPkVxdWlwbWVudCA8c3BhbiBjbGFzcz0iY291bnQiIGlkPSJjRXF1aXAiPjwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0idGFiIiBkYXRhLXZpZXc9InN5c3RlbSI+U3lzdGVtPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJuZXR3b3JrIj5OZXR3b3JrIC8gRlRQPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJyYXciPlJhdyBwcm9ncmFtcyA8c3BhbiBjbGFzcz0iY291bnQiIGlkPSJjUmF3Ij48L3NwYW4+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJleHBvcnQiPkV4cG9ydDwvZGl2PgogICAgPC9kaXY+CgogICAgPGRpdiBjbGFzcz0idmlldyBhY3RpdmUiIGlkPSJ2aWV3LW92ZXJ2aWV3Ij48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InZpZXciIGlkPSJ2aWV3LXN0YXRpb25zIj4KICAgICAgPGRpdiBjbGFzcz0idG9vbGJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InNlYXJjaCIgaWQ9InN0YXRpb25TZWFyY2giIHBsYWNlaG9sZGVyPSJTZWFyY2ggRE4sIGV4dGVuc2lvbiwgcG9ydCwgdHlwZSwgbmFtZSZoZWxsaXA7Ij4KICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiIGlkPSJzdGF0aW9uQ291bnQiPjwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiIHN0eWxlPSJwYWRkaW5nOjA7b3ZlcmZsb3c6YXV0byI+CiAgICAgICAgPHRhYmxlIGlkPSJzdGF0aW9uVGFibGUiPgogICAgICAgICAgPHRoZWFkPjx0cj4KICAgICAgICAgICAgPHRoIGRhdGEtc29ydD0iZG4iPkROPC90aD48dGggZGF0YS1zb3J0PSJleHRlbnNpb24iPkV4dGVuc2lvbjwvdGg+CiAgICAgICAgICAgIDx0aCBkYXRhLXNvcnQ9ImVxdWlwbWVudF9wb3J0Ij5Qb3J0PC90aD48dGggZGF0YS1zb3J0PSJ0eXBlIj5UeXBlPC90aD4KICAgICAgICAgICAgPHRoIGRhdGEtc29ydD0ibmFtZSI+TmFtZTwvdGg+PHRoIGRhdGEtc29ydD0ia2V5Y291bnQiPktleXM8L3RoPgogICAgICAgICAgPC90cj48L3RoZWFkPgogICAgICAgICAgPHRib2R5IGlkPSJzdGF0aW9uUm93cyI+PC90Ym9keT4KICAgICAgICA8L3RhYmxlPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0idmlldyIgaWQ9InZpZXctZXF1aXBtZW50Ij48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InZpZXciIGlkPSJ2aWV3LXN5c3RlbSI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ2aWV3IiBpZD0idmlldy1uZXR3b3JrIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InZpZXciIGlkPSJ2aWV3LXJhdyI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ2aWV3IiBpZD0idmlldy1leHBvcnQiPjwvZGl2PgogIDwvc2VjdGlvbj4KPC9tYWluPgoKPGRpdiBjbGFzcz0ib3ZlcmxheSIgaWQ9Im92ZXJsYXkiPjwvZGl2Pgo8YXNpZGUgY2xhc3M9ImRyYXdlciIgaWQ9ImRyYXdlciI+PC9hc2lkZT4KCjxmb290ZXI+VG9zaGliYSBDSVggTWFuYWdlciAmbWRhc2g7IGxvY2FsIHRvb2wgb3ZlciBTTk1QLiBXcml0ZXMgcmVxdWlyZSBhbiBleHBsaWNpdCBDb25maXJtICZhbXA7IHdyaXRlIGFuZCBhcmUgcmVhZC1iYWNrIHZlcmlmaWVkLjwvZm9vdGVyPgoKPHNjcmlwdD4KInVzZSBzdHJpY3QiOwpjb25zdCAkID0gKHMsIHI9ZG9jdW1lbnQpPT5yLnF1ZXJ5U2VsZWN0b3Iocyk7CmNvbnN0ICQkID0gKHMsIHI9ZG9jdW1lbnQpPT5BcnJheS5mcm9tKHIucXVlcnlTZWxlY3RvckFsbChzKSk7CmNvbnN0IGVzYyA9IHMgPT4gU3RyaW5nKHM9PW51bGw/IiI6cykucmVwbGFjZSgvWyY8PiJdL2csYz0+KHsnJic6JyZhbXA7JywnPCc6JyZsdDsnLCc+JzonJmd0OycsJyInOicmcXVvdDsnfVtjXSkpOwpjb25zdCBNSVNTSU5HID0gIjxNSVNTSU5HPiI7CmxldCBET0MgPSBudWxsOyAgICAgICAgICAgIC8vIHRoZSBjdXJyZW50IHJlYWQgZG9jdW1lbnQKbGV0IFJFUE9SVCA9ICIiOyAgICAgICAgICAgLy8gc2VydmVyLXJlbmRlcmVkIHRleHQgcmVwb3J0CmxldCBTVEFUSU9OX1NPUlQgPSB7a2V5OiJkbiIsIGRpcjoxfTsKCmZ1bmN0aW9uIHNldFN0YXR1cyhodG1sKXsgJCgiI3N0YXR1cyIpLmlubmVySFRNTCA9IGh0bWw7IH0KZnVuY3Rpb24gc2hvd01zZyhlbCwga2luZCwgaHRtbCl7IGVsLmNsYXNzTmFtZSA9ICJtc2cgc2hvdyAiK2tpbmQ7IGVsLmlubmVySFRNTCA9IGh0bWw7IH0KZnVuY3Rpb24gaGlkZU1zZyhlbCl7IGVsLmNsYXNzTmFtZSA9ICJtc2ciOyB9CgpmdW5jdGlvbiBmbXRQb3J0KHApewogIGlmKHR5cGVvZiBwPT09InN0cmluZyIgJiYgL15cZHs2fSQvLnRlc3QocCkpIHJldHVybiBwLnNsaWNlKDAsMikrIi0iK3Auc2xpY2UoMiw0KSsiLSIrcC5zbGljZSg0LDYpOwogIHJldHVybiBwPT1udWxsfHxwPT09TUlTU0lORyA/ICIiIDogcDsKfQpmdW5jdGlvbiB2YWwodil7IHJldHVybiAodj09bnVsbHx8dj09PU1JU1NJTkcpID8gIiIgOiB2OyB9Cgphc3luYyBmdW5jdGlvbiBhcGkocGF0aCwgYm9keSl7CiAgY29uc3Qgb3B0ID0gYm9keSA/IHttZXRob2Q6IlBPU1QiLCBoZWFkZXJzOnsiQ29udGVudC1UeXBlIjoiYXBwbGljYXRpb24vanNvbiJ9LCBib2R5OkpTT04uc3RyaW5naWZ5KGJvZHkpfSA6IHt9OwogIGNvbnN0IHIgPSBhd2FpdCBmZXRjaChwYXRoLCBvcHQpOwogIGNvbnN0IGN0ID0gci5oZWFkZXJzLmdldCgiY29udGVudC10eXBlIil8fCIiOwogIGlmKGN0LmluY2x1ZGVzKCJhcHBsaWNhdGlvbi9qc29uIikpIHJldHVybiByLmpzb24oKTsKICByZXR1cm4gcjsKfQoKZnVuY3Rpb24gcmVhZEZvcm0oKXsKICByZXR1cm4gewogICAgaXA6ICQoIiNpcCIpLnZhbHVlLnRyaW0oKSwKICAgIGNvbW11bml0eTogJCgiI2NvbW11bml0eSIpLnZhbHVlLnRyaW0oKSB8fCAiY29tbXVuaXR5TmFtZSIsCiAgICBwb3J0OiBwYXJzZUludCgkKCIjcG9ydCIpLnZhbHVlLDEwKSB8fCAxNjEsCiAgICBzY29wZTogJCgiI3Njb3BlIikudmFsdWUsCiAgfTsKfQoKLyogLS0tLS0tLS0tLSBUZXN0IGNvbm5lY3Rpb24gLS0tLS0tLS0tLSAqLwokKCIjYnRuVGVzdCIpLm9uY2xpY2sgPSBhc3luYyAoKT0+ewogIGNvbnN0IGYgPSByZWFkRm9ybSgpOwogIGlmKCFmLmlwKXsgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJlcnIiLCJFbnRlciB0aGUgQ0lYIElQIGFkZHJlc3MgZmlyc3QuIik7IHJldHVybjsgfQogIHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiaW5mbyIsJzxzcGFuIGNsYXNzPSJzcGlubmVyIj48L3NwYW4+VGVzdGluZyBTTk1QIHRvICcrZXNjKGYuaXApKycmaGVsbGlwOycpOwogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgiL2FwaS9jb25uZWN0IiwgZik7CiAgICBpZihyZXMub2spIHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwib2siLCJDb25uZWN0ZWQuIFNvZnR3YXJlIGlkOiA8Yj4iK2VzYyhyZXMuc29mdHdhcmVfaWQpKyI8L2I+IisKICAgICAgICAocmVzLmNoYXNzaXNfbWFjPygiICZuYnNwOyBNQUM6IDxzcGFuIGNsYXNzPSdtb25vJz4iK2VzYyhyZXMuY2hhc3Npc19tYWMpKyI8L3NwYW4+Iik6IiIpKTsKICAgIGVsc2Ugc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJlcnIiLCJObyBDSVggYW5zd2VyZWQ6ICIrZXNjKHJlcy5lcnJvcnx8InVua25vd24gZXJyb3IiKSk7CiAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImVyciIsIlJlcXVlc3QgZmFpbGVkOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQp9OwoKLyogLS0tLS0tLS0tLSBSZWFkIC0tLS0tLS0tLS0gKi8KJCgiI2J0blJlYWQiKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICBjb25zdCBmID0gcmVhZEZvcm0oKTsKICBpZighZi5pcCl7IHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiZXJyIiwiRW50ZXIgdGhlIENJWCBJUCBhZGRyZXNzIGZpcnN0LiIpOyByZXR1cm47IH0KICBjb25zdCBzbG93ID0gZi5zY29wZT09PSJhbGwiID8gIiAoZnVsbCBNSUIgJm1kYXNoOyB0aGlzIGNhbiB0YWtlIGEgZmV3IG1pbnV0ZXMpIiA6ICIiOwogIHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiaW5mbyIsJzxzcGFuIGNsYXNzPSJzcGlubmVyIj48L3NwYW4+UmVhZGluZyAnK2VzYyhmLmlwKStzbG93KycmaGVsbGlwOycpOwogICQoIiNidG5SZWFkIikuZGlzYWJsZWQgPSB0cnVlOwogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgiL2FwaS9yZWFkIiwgZik7CiAgICBpZighcmVzLm9rKXsgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJlcnIiLCJSZWFkIGZhaWxlZDogIitlc2MocmVzLmVycm9yfHwidW5rbm93biIpKTsgcmV0dXJuOyB9CiAgICBET0MgPSByZXMuZG9jOyBSRVBPUlQgPSByZXMucmVwb3J0IHx8ICIiOwogICAgaGlkZU1zZygkKCIjY29ubmVjdE1zZyIpKTsKICAgIHJlbmRlckFsbCgpOwogIH1jYXRjaChlKXsgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJlcnIiLCJSZXF1ZXN0IGZhaWxlZDogIitlc2MoZS5tZXNzYWdlKSk7IH0KICBmaW5hbGx5eyAkKCIjYnRuUmVhZCIpLmRpc2FibGVkID0gZmFsc2U7IH0KfTsKCi8qIC0tLS0tLS0tLS0gRGlzY292ZXIgLS0tLS0tLS0tLSAqLwokKCIjYnRuRGlzY292ZXIiKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImluZm8iLCc8c3BhbiBjbGFzcz0ic3Bpbm5lciI+PC9zcGFuPlNjYW5uaW5nIHRoZSBsb2NhbCBuZXR3b3JrIChBUlAgKyBwaW5nIHN3ZWVwKSZoZWxsaXA7Jyk7CiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL2Rpc2NvdmVyIik7CiAgICBjb25zdCBjYW5kcyA9IChyZXMuY2FuZGlkYXRlc3x8W10pOwogICAgY29uc3QgYm94ID0gJCgiI2Rpc2NvdmVyQm94IiksIHJvd3MgPSAkKCIjZGlzY292ZXJSb3dzIik7CiAgICByb3dzLmlubmVySFRNTCA9ICIiOwogICAgaWYoIWNhbmRzLmxlbmd0aCl7IHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiaW5mbyIsIk5vIGNhbmRpZGF0ZXMgZm91bmQuIEVudGVyIHRoZSBJUCBtYW51YWxseSwgb3IgdHJ5IHRoZSAuMjUzIGNvbnZlbnRpb24uIik7IGJveC5jbGFzc0xpc3QuYWRkKCJoaWRlIik7IHJldHVybjsgfQogICAgY2FuZHMuZm9yRWFjaChjPT57CiAgICAgIGNvbnN0IHRyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgidHIiKTsKICAgICAgdHIuaW5uZXJIVE1MID0gIjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2MoYy5pcCkrIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyhjLm1hY3x8IiIpKyI8L3RkPiIrCiAgICAgICAgIjx0ZD4iK2VzYyhjLnZpYXx8IiIpKyI8L3RkPiIrCiAgICAgICAgIjx0ZD4iKyhjLnZlcmlmaWVkPygiPHNwYW4gc3R5bGU9J2NvbG9yOnZhcigtLW9rKSc+JiMxMDAwMzsgIitlc2MoYy5zb2Z0d2FyZV9pZHx8IkNJWCIpKyI8L3NwYW4+Iik6IjxzcGFuIGNsYXNzPSdtdXRlZCc+dW52ZXJpZmllZDwvc3Bhbj4iKSsiPC90ZD4iKwogICAgICAgICI8dGQ+PGJ1dHRvbiBjbGFzcz0nYnRuIHNtYWxsJz5Vc2U8L2J1dHRvbj48L3RkPiI7CiAgICAgIHRyLnF1ZXJ5U2VsZWN0b3IoImJ1dHRvbiIpLm9uY2xpY2sgPSAoKT0+eyAkKCIjaXAiKS52YWx1ZSA9IGMuaXA7IGhpZGVNc2coJCgiI2Nvbm5lY3RNc2ciKSk7IH07CiAgICAgIHJvd3MuYXBwZW5kQ2hpbGQodHIpOwogICAgfSk7CiAgICBib3guY2xhc3NMaXN0LnJlbW92ZSgiaGlkZSIpOwogICAgY29uc3QgbnZlcmlmaWVkID0gY2FuZHMuZmlsdGVyKGM9PmMudmVyaWZpZWQpLmxlbmd0aDsKICAgIHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwgbnZlcmlmaWVkPyJvayI6ImluZm8iLAogICAgICAiRm91bmQgIitjYW5kcy5sZW5ndGgrIiBjYW5kaWRhdGUocykiKyhudmVyaWZpZWQ/KCIsICIrbnZlcmlmaWVkKyIgdmVyaWZpZWQgYXMgYSBDSVgiKToiIikrIi4gUGljayBvbmUgYmVsb3cuIik7CiAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImVyciIsIkRpc2NvdmVyIGZhaWxlZDogIitlc2MoZS5tZXNzYWdlKSk7IH0KfTsKCi8qIC0tLS0tLS0tLS0gT3BlbiBiYWNrdXAgZmlsZSAob2ZmbGluZSB2aWV3ZXIpIC0tLS0tLS0tLS0gKi8KJCgiI2J0bk9wZW4iKS5vbmNsaWNrID0gKCk9PiAkKCIjZmlsZUlucHV0IikuY2xpY2soKTsKJCgiI2ZpbGVJbnB1dCIpLm9uY2hhbmdlID0gKGV2KT0+ewogIGNvbnN0IGZpbGUgPSBldi50YXJnZXQuZmlsZXNbMF07IGlmKCFmaWxlKSByZXR1cm47CiAgY29uc3QgZnIgPSBuZXcgRmlsZVJlYWRlcigpOwogIGZyLm9ubG9hZCA9ICgpPT57CiAgICB0cnl7CiAgICAgIGNvbnN0IGRvYyA9IEpTT04ucGFyc2UoZnIucmVzdWx0KTsKICAgICAgaWYoIWRvYy5zdGF0aW9ucyAmJiAhZG9jLnN5c3RlbSl7IHRocm93IG5ldyBFcnJvcigibm90IGEgQ0lYIGJhY2t1cCBKU09OIik7IH0KICAgICAgRE9DID0gZG9jOyBSRVBPUlQgPSAiIjsKICAgICAgaGlkZU1zZygkKCIjY29ubmVjdE1zZyIpKTsKICAgICAgcmVuZGVyQWxsKHRydWUpOwogICAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImVyciIsIkNvdWxkIG5vdCBsb2FkIGJhY2t1cDogIitlc2MoZS5tZXNzYWdlKSk7IH0KICB9OwogIGZyLnJlYWRBc1RleHQoZmlsZSk7CiAgZXYudGFyZ2V0LnZhbHVlID0gIiI7Cn07CgovKiAtLS0tLS0tLS0tIFRhYnMgLS0tLS0tLS0tLSAqLwokJCgiLnRhYiIpLmZvckVhY2godD0+IHQub25jbGljayA9ICgpPT57CiAgJCQoIi50YWIiKS5mb3JFYWNoKHg9PnguY2xhc3NMaXN0LnJlbW92ZSgiYWN0aXZlIikpOwogICQkKCIudmlldyIpLmZvckVhY2goeD0+eC5jbGFzc0xpc3QucmVtb3ZlKCJhY3RpdmUiKSk7CiAgdC5jbGFzc0xpc3QuYWRkKCJhY3RpdmUiKTsKICAkKCIjdmlldy0iK3QuZGF0YXNldC52aWV3KS5jbGFzc0xpc3QuYWRkKCJhY3RpdmUiKTsKfSk7CgovKiAtLS0tLS0tLS0tIFJlbmRlciAtLS0tLS0tLS0tICovCmZ1bmN0aW9uIHJlbmRlckFsbChmcm9tRmlsZSl7CiAgJCgiI2Nvbm5lY3QiKS5jbGFzc0xpc3QuYWRkKCJoaWRlIik7CiAgJCgiI3Jlc3VsdHMiKS5jbGFzc0xpc3QucmVtb3ZlKCJoaWRlIik7CiAgY29uc3QgZCA9IERPQy5kZXZpY2V8fHt9LCBzID0gRE9DLnN5c3RlbXx8e307CiAgc2V0U3RhdHVzKCI8Yj4iK2VzYyhkLmlwfHwiYmFja3VwIikrIjwvYj4gJm1pZGRvdDsgIitlc2ModmFsKHMuc29mdHdhcmVfaWQpfHwiPyIpKwogICAgICAgICAgICAiICZtaWRkb3Q7ICIrZXNjKHZhbChzLmNoYXNzaXNfbWFjKXx8IiIpICsKICAgICAgICAgICAgKGZyb21GaWxlPyIgJm1pZGRvdDsgPHNwYW4gY2xhc3M9J211dGVkJz5mcm9tIGZpbGU8L3NwYW4+IjoiIikpOwogICQoIiNjU3RhdGlvbnMiKS50ZXh0Q29udGVudCA9IChET0Muc3RhdGlvbnN8fFtdKS5sZW5ndGg7CiAgJCgiI2NFcXVpcCIpLnRleHRDb250ZW50ID0gKERPQy5lcXVpcG1lbnR8fFtdKS5sZW5ndGg7CiAgJCgiI2NSYXciKS50ZXh0Q29udGVudCA9IE9iamVjdC5rZXlzKERPQy5yYXdfcHJvZ3JhbXN8fHt9KS5sZW5ndGg7CiAgcmVuZGVyT3ZlcnZpZXcoKTsgcmVuZGVyU3RhdGlvbnMoKTsgcmVuZGVyRXF1aXBtZW50KCk7IHJlbmRlclN5c3RlbSgpOwogIHJlbmRlck5ldHdvcmsoKTsgcmVuZGVyUmF3KCk7IHJlbmRlckV4cG9ydChmcm9tRmlsZSk7CiAgd2luZG93LnNjcm9sbFRvKDAsMCk7Cn0KCmZ1bmN0aW9uIHJlbmRlck92ZXJ2aWV3KCl7CiAgY29uc3QgZCA9IERPQy5kZXZpY2V8fHt9LCBzID0gRE9DLnN5c3RlbXx8e307CiAgY29uc3QgZmluZGluZ3MgPSBET0Muc2VjdXJpdHlfZmluZGluZ3N8fFtdOwogIGxldCBodG1sID0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5EZXZpY2U8L2gyPjxkaXYgY2xhc3M9J2t2Jz4iKwogICAga3YoIklQIC8gcG9ydCIsICh2YWwoZC5pcCl8fCLigJQiKSsiOiIrKGQucG9ydHx8MTYxKSkrCiAgICBrdigiQ29tbXVuaXR5IiwgdmFsKGQuY29tbXVuaXR5KSkrCiAgICBrdigiU29mdHdhcmUgaWQiLCB2YWwocy5zb2Z0d2FyZV9pZCkpKwogICAga3YoIkNoYXNzaXMgTUFDIiwgdmFsKHMuY2hhc3Npc19tYWMpKSsKICAgIGt2KCJSZWFkIGF0IiwgdmFsKGQucmVhZF9hdCkpKwogICAga3YoIlNjb3BlIiwgdmFsKGQuc2NvcGUpKSsKICAgIGt2KCJPSURzIHJlYWQiLCB2YWwoZC5vaWRzX3JlYWQpKSsKICAgIChkLndhbGtfZXJyb3I/a3YoIldhbGsgZXJyb3IiLCAiPHNwYW4gc3R5bGU9J2NvbG9yOnZhcigtLXdhcm4pJz4iK2VzYyhkLndhbGtfZXJyb3IpKyI8L3NwYW4+Iik6IiIpKwogICAgIjwvZGl2PjwvZGl2PiI7CiAgaWYoZmluZGluZ3MubGVuZ3RoKXsKICAgIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5TZWN1cml0eSBmaW5kaW5nczwvaDI+IjsKICAgIGZpbmRpbmdzLmZvckVhY2goZj0+IGh0bWwgKz0gIjxkaXYgY2xhc3M9J2ZpbmRpbmcgIitlc2MoZi5zZXZlcml0eSkrIic+PHNwYW4gY2xhc3M9J3Nldic+IisKICAgICAgZXNjKChmLnNldmVyaXR5fHwiIikudG9VcHBlckNhc2UoKSkrIjwvc3Bhbj4iK2VzYyhmLmRldGFpbCkrIjwvZGl2PiIpOwogICAgaHRtbCArPSAiPC9kaXY+IjsKICB9CiAgY29uc3Qgc3QgPSBET0Muc3RhdHN8fHt9OwogIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5Ub3RhbHM8L2gyPjxkaXYgY2xhc3M9J2t2Jz4iKwogICAgT2JqZWN0LmtleXMoc3QpLnNvcnQoKS5tYXAoaz0+a3Yoaywgc3Rba10pKS5qb2luKCIiKSsiPC9kaXY+PC9kaXY+IjsKICAkKCIjdmlldy1vdmVydmlldyIpLmlubmVySFRNTCA9IGh0bWw7Cn0KZnVuY3Rpb24ga3Yoayx2KXsgcmV0dXJuICI8ZGl2IGNsYXNzPSdrJz4iK2VzYyhrKSsiPC9kaXY+PGRpdj4iKyAodj09bnVsbD8iIjooIiIrdikuc3RhcnRzV2l0aCgiPCIpP3Y6ZXNjKHYpKSArIjwvZGl2PiI7IH0KCmZ1bmN0aW9uIHN0YXRpb25LZXljb3VudChzdCl7IHJldHVybiAoc3Qua2V5c3x8W10pLmxlbmd0aDsgfQpmdW5jdGlvbiByZW5kZXJTdGF0aW9ucygpewogIGNvbnN0IHEgPSAkKCIjc3RhdGlvblNlYXJjaCIpLnZhbHVlLnRvTG93ZXJDYXNlKCk7CiAgbGV0IHJvd3MgPSAoRE9DLnN0YXRpb25zfHxbXSkuc2xpY2UoKTsKICBpZihxKXsKICAgIHJvd3MgPSByb3dzLmZpbHRlcihzdD0+W3N0LmRuLHN0LmV4dGVuc2lvbixzdC5lcXVpcG1lbnRfcG9ydCxzdC50eXBlLHN0Lm5hbWVdCiAgICAgIC5zb21lKHY9PiBTdHJpbmcodmFsKHYpKS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKHEpKSk7CiAgfQogIGNvbnN0IGsgPSBTVEFUSU9OX1NPUlQua2V5LCBkaXIgPSBTVEFUSU9OX1NPUlQuZGlyOwogIHJvd3Muc29ydCgoYSxiKT0+ewogICAgbGV0IHZhID0gaz09PSJrZXljb3VudCI/c3RhdGlvbktleWNvdW50KGEpOnZhbChhW2tdKSwgdmIgPSBrPT09ImtleWNvdW50Ij9zdGF0aW9uS2V5Y291bnQoYik6dmFsKGJba10pOwogICAgaWYoaz09PSJkbiJ8fGs9PT0iZXh0ZW5zaW9uIil7IGNvbnN0IG5hPXBhcnNlSW50KHZhLDEwKSwgbmI9cGFyc2VJbnQodmIsMTApOwogICAgICBpZighaXNOYU4obmEpJiYhaXNOYU4obmIpKSByZXR1cm4gKG5hLW5iKSpkaXI7IH0KICAgIHJldHVybiBTdHJpbmcodmEpLmxvY2FsZUNvbXBhcmUoU3RyaW5nKHZiKSkqZGlyOwogIH0pOwogICQoIiNzdGF0aW9uQ291bnQiKS50ZXh0Q29udGVudCA9IHJvd3MubGVuZ3RoKyIgb2YgIisoRE9DLnN0YXRpb25zfHxbXSkubGVuZ3RoKyIgc2hvd24iOwogIGNvbnN0IHRiID0gJCgiI3N0YXRpb25Sb3dzIik7IHRiLmlubmVySFRNTCA9ICIiOwogIHJvd3MuZm9yRWFjaChzdD0+ewogICAgY29uc3QgdHIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJ0ciIpOyB0ci5jbGFzc05hbWU9ImNsaWNrYWJsZSI7CiAgICB0ci5pbm5lckhUTUwgPSAiPHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwoc3QuZG4pKSsiPC90ZD4iKwogICAgICAiPHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwoc3QuZXh0ZW5zaW9uKSkrIjwvdGQ+IisKICAgICAgIjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2MoZm10UG9ydChzdC5lcXVpcG1lbnRfcG9ydCkpKyI8L3RkPiIrCiAgICAgICI8dGQ+Iitlc2ModmFsKHN0LnR5cGUpKSsiPC90ZD4iKwogICAgICAiPHRkPiIrZXNjKHZhbChzdC5uYW1lKSkrIjwvdGQ+IisKICAgICAgIjx0ZD4iK3N0YXRpb25LZXljb3VudChzdCkrIjwvdGQ+IjsKICAgIHRyLm9uY2xpY2sgPSAoKT0+IG9wZW5TdGF0aW9uKHN0KTsKICAgIHRiLmFwcGVuZENoaWxkKHRyKTsKICB9KTsKfQokKCIjc3RhdGlvblNlYXJjaCIpLm9uaW5wdXQgPSByZW5kZXJTdGF0aW9uczsKJCQoIiNzdGF0aW9uVGFibGUgdGgiKS5mb3JFYWNoKHRoPT4gdGgub25jbGljayA9ICgpPT57CiAgY29uc3Qga2V5ID0gdGguZGF0YXNldC5zb3J0OwogIGlmKFNUQVRJT05fU09SVC5rZXk9PT1rZXkpIFNUQVRJT05fU09SVC5kaXIqPS0xOyBlbHNlIFNUQVRJT05fU09SVD17a2V5LCBkaXI6MX07CiAgcmVuZGVyU3RhdGlvbnMoKTsKfSk7CgpmdW5jdGlvbiByZW5kZXJFcXVpcG1lbnQoKXsKICBjb25zdCBlcSA9IERPQy5lcXVpcG1lbnR8fFtdOwogIGxldCBodG1sID0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5FcXVpcG1lbnQgLyBjYWJpbmV0IHJvd3MgKCIrZXEubGVuZ3RoKyIpPC9oMj4iOwogIGlmKCFlcS5sZW5ndGgpeyBodG1sICs9ICI8cCBjbGFzcz0nbXV0ZWQnPk5vbmUgcmV0dXJuZWQuPC9wPjwvZGl2PiI7ICQoIiN2aWV3LWVxdWlwbWVudCIpLmlubmVySFRNTD1odG1sOyByZXR1cm47IH0KICBjb25zdCBjb2xzID0gbmV3IFNldCgpOyBlcS5mb3JFYWNoKHI9Pk9iamVjdC5rZXlzKHIpLmZvckVhY2goaz0+eyBpZihrIT09ImluZGV4IikgY29scy5hZGQoayk7IH0pKTsKICBjb25zdCBjb2xMaXN0ID0gQXJyYXkuZnJvbShjb2xzKTsKICBodG1sICs9ICI8ZGl2IHN0eWxlPSdvdmVyZmxvdzphdXRvJz48dGFibGU+PHRoZWFkPjx0cj48dGg+SW5kZXg8L3RoPiIrCiAgICBjb2xMaXN0Lm1hcChjPT4iPHRoPiIrZXNjKGMpKyI8L3RoPiIpLmpvaW4oIiIpKyI8L3RyPjwvdGhlYWQ+PHRib2R5PiI7CiAgZXEuZm9yRWFjaChyPT57CiAgICBodG1sICs9ICI8dHI+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyhKU09OLnN0cmluZ2lmeShyLmluZGV4KSkrIjwvdGQ+IisKICAgICAgY29sTGlzdC5tYXAoYz0+Ijx0ZCBjbGFzcz0nbW9ubyc+Iitlc2ModmFsKHJbY10pKSsiPC90ZD4iKS5qb2luKCIiKSsiPC90cj4iOwogIH0pOwogIGh0bWwgKz0gIjwvdGJvZHk+PC90YWJsZT48L2Rpdj48L2Rpdj4iOwogICQoIiN2aWV3LWVxdWlwbWVudCIpLmlubmVySFRNTCA9IGh0bWw7Cn0KCmZ1bmN0aW9uIHJlbmRlclN5c3RlbSgpewogIGNvbnN0IHMgPSBET0Muc3lzdGVtfHx7fTsKICBjb25zdCBudW1iZXJpbmcgPSBzLm51bWJlcmluZ19jb25maWd8fHt9LCBzdGF0dXMgPSBzLnN0YXR1c3x8e307CiAgbGV0IGh0bWwgPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPlN5c3RlbSBudW1iZXJpbmcgLyBmZWF0dXJlIGNvbmZpZyAoUHJvZ3JhbSA1NzkpPC9oMj4iOwogIGNvbnN0IG5rID0gT2JqZWN0LmtleXMobnVtYmVyaW5nKS5zb3J0KCk7CiAgaHRtbCArPSBuay5sZW5ndGggPyAiPGRpdiBjbGFzcz0na3YnPiIrbmsubWFwKGs9Pmt2KGssIHZhbChudW1iZXJpbmdba10pKSkuam9pbigiIikrIjwvZGl2PiIKICAgICAgICAgICAgICAgICAgICA6ICI8cCBjbGFzcz0nbXV0ZWQnPk5vbmUgcmV0dXJuZWQuPC9wPiI7CiAgaHRtbCArPSAiPC9kaXY+IjsKICBjb25zdCBzayA9IE9iamVjdC5rZXlzKHN0YXR1cykuc29ydCgpOwogIGlmKHNrLmxlbmd0aCl7CiAgICBodG1sICs9ICI8ZGl2IGNsYXNzPSdjYXJkJz48aDI+U3lzdGVtIHN0YXR1cyBzY2FsYXJzICguNy4qKTwvaDI+PGRpdiBjbGFzcz0na3YnPiIrCiAgICAgIHNrLm1hcChrPT5rdihrLCB2YWwoc3RhdHVzW2tdKSkpLmpvaW4oIiIpKyI8L2Rpdj48L2Rpdj4iOwogIH0KICAkKCIjdmlldy1zeXN0ZW0iKS5pbm5lckhUTUwgPSBodG1sOwp9CgpmdW5jdGlvbiByZW5kZXJOZXR3b3JrKCl7CiAgY29uc3QgbmV0ID0gRE9DLm5ldHdvcmtfYWNjZXNzfHxbXTsKICBsZXQgaHRtbCA9ICI8ZGl2IGNsYXNzPSdjYXJkJz48aDI+TmV0d29yayAvIEZUUCBhY2Nlc3MgKC4yLjMuMS4xKTwvaDI+IjsKICBpZighbmV0Lmxlbmd0aCl7IGh0bWwgKz0gIjxwIGNsYXNzPSdtdXRlZCc+Tm9uZSByZXR1cm5lZC48L3A+PC9kaXY+IjsgJCgiI3ZpZXctbmV0d29yayIpLmlubmVySFRNTD1odG1sOyByZXR1cm47IH0KICBodG1sICs9ICI8dGFibGU+PHRoZWFkPjx0cj48dGg+Um93PC90aD48dGg+VXNlcm5hbWU8L3RoPjx0aD5QYXNzd29yZDwvdGg+PHRoPlBhdGg8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+IjsKICBuZXQuZm9yRWFjaChyPT4gaHRtbCArPSAiPHRyPjx0ZD4iK2VzYyh2YWwoci5pbmRleCkpKyI8L3RkPjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2ModmFsKHIudXNlcm5hbWUpKSsKICAgICI8L3RkPjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2ModmFsKHIucGFzc3dvcmQpKSsiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKHZhbChyLnBhdGgpKSsiPC90ZD48L3RyPiIpOwogIGh0bWwgKz0gIjwvdGJvZHk+PC90YWJsZT48cCBjbGFzcz0nbXV0ZWQnIHN0eWxlPSdtYXJnaW4tYm90dG9tOjAnPlRoZXNlIGFyZSBsaXZlIGNyZWRlbnRpYWxzIHJlYWQgZnJvbSB0aGUgUEJYLjwvcD48L2Rpdj4iOwogICQoIiN2aWV3LW5ldHdvcmsiKS5pbm5lckhUTUwgPSBodG1sOwp9CgpmdW5jdGlvbiByZW5kZXJSYXcoKXsKICBjb25zdCByYXcgPSBET0MucmF3X3Byb2dyYW1zfHx7fTsKICBjb25zdCBrZXlzID0gT2JqZWN0LmtleXMocmF3KS5zb3J0KChhLGIpPT4ocGFyc2VJbnQoYSwxMCl8fDApLShwYXJzZUludChiLDEwKXx8MCkpOwogIGxldCBodG1sID0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5VbmRvY3VtZW50ZWQgcHJvZ3JhbXMgKHJhdyBwYXNzdGhyb3VnaCk8L2gyPiI7CiAgaWYoIWtleXMubGVuZ3RoKXsgaHRtbCArPSAiPHAgY2xhc3M9J211dGVkJz5Ob25lLjwvcD48L2Rpdj4iOyAkKCIjdmlldy1yYXciKS5pbm5lckhUTUw9aHRtbDsgcmV0dXJuOyB9CiAgaHRtbCArPSAiPHAgY2xhc3M9J211dGVkJz5Qcm9ncmFtcyB3aG9zZSBjb2x1bW4gbGVnZW5kIHRoZSBjYXB0dXJlIGRpZCBub3QgcHJvdmUuIEV2ZXJ5IGNlbGwga2VlcHMgaXRzIHJhdyBPSUQgc28gYSBsYXRlciBkZWNvZGUgY2FuIGJlIGFkZGVkLjwvcD4iOwogIGtleXMuZm9yRWFjaChwPT57CiAgICBjb25zdCBiID0gcmF3W3BdLCByb3dLZXlzID0gT2JqZWN0LmtleXMoYi5yb3dzfHx7fSk7CiAgICBodG1sICs9ICI8ZGV0YWlscz48c3VtbWFyeT5Qcm9ncmFtICIrZXNjKHApKyIgJm1kYXNoOyAiK2VzYyh2YWwoYi5uYW1lKSkrIiAoIityb3dLZXlzLmxlbmd0aCsiIHJvdyhzKSk8L3N1bW1hcnk+IjsKICAgIGh0bWwgKz0gIjx0YWJsZT48dGhlYWQ+PHRyPjx0aD5Sb3c8L3RoPjx0aD5Db2x1bW48L3RoPjx0aD5WYWx1ZTwvdGg+PHRoPk9JRDwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT4iOwogICAgcm93S2V5cy5mb3JFYWNoKHJrPT57CiAgICAgIGNvbnN0IHJvdyA9IGIucm93c1tya107CiAgICAgIE9iamVjdC5rZXlzKHJvdykuZm9yRWFjaChjb2w9PnsKICAgICAgICBodG1sICs9ICI8dHI+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyhyaykrIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyhjb2wpKyI8L3RkPiIrCiAgICAgICAgICAiPHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwocm93W2NvbF0udmFsdWUpKSsiPC90ZD48dGQgY2xhc3M9J21vbm8gbXV0ZWQnPiIrZXNjKHJvd1tjb2xdLm9pZCkrIjwvdGQ+PC90cj4iOwogICAgICB9KTsKICAgIH0pOwogICAgaHRtbCArPSAiPC90Ym9keT48L3RhYmxlPjwvZGV0YWlscz4iOwogIH0pOwogIGh0bWwgKz0gIjwvZGl2PiI7CiAgJCgiI3ZpZXctcmF3IikuaW5uZXJIVE1MID0gaHRtbDsKfQoKZnVuY3Rpb24gcmVuZGVyRXhwb3J0KGZyb21GaWxlKXsKICBsZXQgaHRtbCA9ICI8ZGl2IGNsYXNzPSdjYXJkJz48aDI+QmFja3VwIGV4cG9ydDwvaDI+IisKICAgICI8cCBjbGFzcz0nbXV0ZWQnPlNhdmUgYSBmdWxsIGJhY2t1cCBvZiB0aGlzIHJlYWQuIFlvdSBjaG9vc2Ugd2hlcmUgdGhlIGZpbGVzIGxhbmQgdmlhIHlvdXIgYnJvd3NlcidzIHNhdmUgZGlhbG9nLjwvcD4iKwogICAgIjxkaXYgY2xhc3M9J2V4cC1idG5zJz4iKwogICAgIjxidXR0b24gY2xhc3M9J2J0bicgaWQ9J2V4cFppcCc+RG93bmxvYWQgZnVsbCBiYWNrdXAgKC56aXApPC9idXR0b24+IisKICAgICI8YnV0dG9uIGNsYXNzPSdidG4gZ2hvc3QnIGlkPSdleHBKc29uJz5KU09OIG9ubHk8L2J1dHRvbj4iKwogICAgIjxidXR0b24gY2xhc3M9J2J0biBnaG9zdCcgaWQ9J2V4cFJlcG9ydCciKyhSRVBPUlQ/IiI6IiBkaXNhYmxlZCB0aXRsZT0nT3BlbiBhIGxpdmUgcmVhZCB0byBnZXQgdGhlIHRleHQgcmVwb3J0JyIpKyI+UmVwb3J0ICgudHh0KTwvYnV0dG9uPiIrCiAgICAiPGJ1dHRvbiBjbGFzcz0nYnRuIGdob3N0JyBpZD0nZXhwUmF3JyIrKChET0MucmF3X29pZF93YWxrKT8iIjoiIGRpc2FibGVkIHRpdGxlPSdSYXcgT0lEIHdhbGsgcHJlc2VudCBvbmx5IG9uIGEgbGl2ZSByZWFkJyIpKyI+UmF3IE9JRCB3YWxrICgudHh0KTwvYnV0dG9uPiIrCiAgICAiPC9kaXY+PC9kaXY+IjsKICAkKCIjdmlldy1leHBvcnQiKS5pbm5lckhUTUwgPSBodG1sOwogICQoIiNleHBKc29uIikub25jbGljayA9ICgpPT4gZG93bmxvYWQoYmFzZU5hbWUoKSsiLmpzb24iLCBKU09OLnN0cmluZ2lmeShET0MsbnVsbCwyKSwgImFwcGxpY2F0aW9uL2pzb24iKTsKICAkKCIjZXhwUmVwb3J0Iikub25jbGljayA9ICgpPT4gUkVQT1JUICYmIGRvd25sb2FkKGJhc2VOYW1lKCkrIi50eHQiLCBSRVBPUlQsICJ0ZXh0L3BsYWluIik7CiAgJCgiI2V4cFJhdyIpLm9uY2xpY2sgPSAoKT0+ewogICAgaWYoIURPQy5yYXdfb2lkX3dhbGspIHJldHVybjsKICAgIGNvbnN0IHR4dCA9IERPQy5yYXdfb2lkX3dhbGsubWFwKGU9PiBlLm9pZCsiID0gIitlLnZhbHVlKS5qb2luKCJcbiIpKyJcbiI7CiAgICBkb3dubG9hZChiYXNlTmFtZSgpKyItb2lkd2Fsay50eHQiLCB0eHQsICJ0ZXh0L3BsYWluIik7CiAgfTsKICAkKCIjZXhwWmlwIikub25jbGljayA9IGFzeW5jICgpPT57CiAgICBjb25zdCBidG4gPSAkKCIjZXhwWmlwIik7IGJ0bi5kaXNhYmxlZD10cnVlOyBjb25zdCBvbGQ9YnRuLnRleHRDb250ZW50OyBidG4udGV4dENvbnRlbnQ9IkJ1aWxkaW5n4oCmIjsKICAgIHRyeXsKICAgICAgY29uc3QgciA9IGF3YWl0IGZldGNoKCIvYXBpL2JhY2t1cCIsIHttZXRob2Q6IlBPU1QiLCBoZWFkZXJzOnsiQ29udGVudC1UeXBlIjoiYXBwbGljYXRpb24vanNvbiJ9LAogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHtkb2M6RE9DfSl9KTsKICAgICAgaWYoIXIub2speyBjb25zdCBqID0gYXdhaXQgci5qc29uKCkuY2F0Y2goKCk9Pih7fSkpOyB0aHJvdyBuZXcgRXJyb3Ioai5lcnJvcnx8KCJIVFRQICIrci5zdGF0dXMpKTsgfQogICAgICBjb25zdCBibG9iID0gYXdhaXQgci5ibG9iKCk7CiAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgIGNvbnN0IGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7IGEuaHJlZj11cmw7IGEuZG93bmxvYWQ9YmFzZU5hbWUoKSsiLWJhY2t1cC56aXAiOwogICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOyBhLmNsaWNrKCk7IGEucmVtb3ZlKCk7IFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICAgIH1jYXRjaChlKXsgYWxlcnQoIkJhY2t1cCBmYWlsZWQ6ICIrZS5tZXNzYWdlKTsgfQogICAgZmluYWxseXsgYnRuLmRpc2FibGVkPWZhbHNlOyBidG4udGV4dENvbnRlbnQ9b2xkOyB9CiAgfTsKfQpmdW5jdGlvbiBiYXNlTmFtZSgpewogIGNvbnN0IGlwID0gKERPQy5kZXZpY2UmJkRPQy5kZXZpY2UuaXApfHwiY2l4IjsKICBjb25zdCB3aGVuID0gKChET0MuZGV2aWNlJiZET0MuZGV2aWNlLnJlYWRfYXQpfHwiIikucmVwbGFjZSgvWzpUXS9nLCItIikuc2xpY2UoMCwxOSk7CiAgcmV0dXJuICJ0b3NoaWJhLWNpeC0iK1N0cmluZyhpcCkucmVwbGFjZSgvW15cdy5dL2csIl8iKSsod2hlbj8iLSIrd2hlbjoiIik7Cn0KZnVuY3Rpb24gZG93bmxvYWQobmFtZSwgdGV4dCwgdHlwZSl7CiAgY29uc3QgYmxvYiA9IG5ldyBCbG9iKFt0ZXh0XSwge3R5cGV9KTsgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICBjb25zdCBhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYSIpOyBhLmhyZWY9dXJsOyBhLmRvd25sb2FkPW5hbWU7CiAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTsgYS5jbGljaygpOyBhLnJlbW92ZSgpOyBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7Cn0KCi8qIC0tLS0tLS0tLS0gU3RhdGlvbiBkcmF3ZXIgKyBlZGl0IC0tLS0tLS0tLS0gKi8KZnVuY3Rpb24gY2xvc2VEcmF3ZXIoKXsgJCgiI2RyYXdlciIpLmNsYXNzTGlzdC5yZW1vdmUoInNob3ciKTsgJCgiI292ZXJsYXkiKS5jbGFzc0xpc3QucmVtb3ZlKCJzaG93Iik7IH0KJCgiI292ZXJsYXkiKS5vbmNsaWNrID0gY2xvc2VEcmF3ZXI7CgpmdW5jdGlvbiBvcGVuU3RhdGlvbihzdCl7CiAgY29uc3QgZHIgPSAkKCIjZHJhd2VyIik7CiAgY29uc3QgZWRpdGFibGUgPSB7ZXh0ZW5zaW9uOiJFeHRlbnNpb24iLCB0eXBlOiJUeXBlIiwgbmFtZToiU3RhdGlvbiBuYW1lIn07CiAgbGV0IGh0bWwgPSAiPGJ1dHRvbiBjbGFzcz0nY2xvc2UnIHRpdGxlPSdDbG9zZSc+JnRpbWVzOzwvYnV0dG9uPiI7CiAgaHRtbCArPSAiPGgzPkROICIrZXNjKHZhbChzdC5kbikpKyI8L2gzPjxwIGNsYXNzPSdtdXRlZCc+UG9ydCAiK2VzYyhmbXRQb3J0KHN0LmVxdWlwbWVudF9wb3J0KSkrIjwvcD4iOwoKICBodG1sICs9ICI8ZGl2IGNsYXNzPSdjYXJkJz48aDI+RWRpdCBzdGF0aW9uPC9oMj4iOwogIE9iamVjdC5rZXlzKGVkaXRhYmxlKS5mb3JFYWNoKGY9PnsKICAgIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2ZpZWxkLWVkaXQnPjxsYWJlbD4iK2VzYyhlZGl0YWJsZVtmXSkrIjwvbGFiZWw+IisKICAgICAgIjxpbnB1dCBkYXRhLWZpZWxkPSciK2YrIicgdmFsdWU9JyIrZXNjKHZhbChzdFtmXSkpKyInPjwvZGl2PiI7CiAgfSk7CiAgaHRtbCArPSAiPGRpdiBjbGFzcz0nZmllbGQtZWRpdCc+PGxhYmVsPlBvcnQ8L2xhYmVsPjxpbnB1dCB2YWx1ZT0nIitlc2MoZm10UG9ydChzdC5lcXVpcG1lbnRfcG9ydCkpKwogICAgICAgICAgIicgZGlzYWJsZWQgdGl0bGU9J3BoeXNpY2FsIGFzc2lnbm1lbnQg4oCUIHJlYWQtb25seSc+PC9kaXY+IjsKICBodG1sICs9ICI8ZGl2IGNsYXNzPSdyb3cnIHN0eWxlPSdtYXJnaW4tdG9wOjRweCc+IisKICAgICAgICAgICI8YnV0dG9uIGNsYXNzPSdidG4gZ2hvc3QnIGlkPSdwcmV2aWV3U3RhdGlvbic+UHJldmlldyBjaGFuZ2VzPC9idXR0b24+IisKICAgICAgICAgICI8YnV0dG9uIGNsYXNzPSdidG4nIGlkPSd3cml0ZVN0YXRpb24nPkNvbmZpcm0gJmFtcDsgd3JpdGU8L2J1dHRvbj48L2Rpdj4iOwogIGh0bWwgKz0gIjxwIGNsYXNzPSdtdXRlZCcgc3R5bGU9J21hcmdpbjo4cHggMCAwJz5QcmV2aWV3IHNob3dzIHRoZSBleGFjdCBTRVRzIHdpdGhvdXQgc2VuZGluZy4gIisKICAgICAgICAgICJDb25maXJtICZhbXA7IHdyaXRlIHNlbmRzIHRoZW0gb3ZlciBTTk1QIGFuZCByZWFkcyB0aGUgdmFsdWVzIGJhY2sgdG8gdmVyaWZ5LjwvcD4iOwogIGh0bWwgKz0gIjxkaXYgY2xhc3M9J21zZycgaWQ9J3NhdmVNc2cnPjwvZGl2PjwvZGl2PiI7CgogIGlmKChzdC5rZXlzfHxbXSkubGVuZ3RoKXsKICAgIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5LZXlzIC8gYnV0dG9ucyAoIitzdC5rZXlzLmxlbmd0aCsiKTwvaDI+PGRpdiBzdHlsZT0nb3ZlcmZsb3c6YXV0byc+PHRhYmxlPjx0aGVhZD48dHI+PHRoPktleTwvdGg+IjsKICAgIGNvbnN0IGtjb2xzID0gbmV3IFNldCgpOyBzdC5rZXlzLmZvckVhY2goaz0+T2JqZWN0LmtleXMoaykuZm9yRWFjaChjPT57IGlmKGMhPT0ia2V5Iikga2NvbHMuYWRkKGMpOyB9KSk7CiAgICBjb25zdCBrYyA9IEFycmF5LmZyb20oa2NvbHMpOwogICAgaHRtbCArPSBrYy5tYXAoYz0+Ijx0aD4iK2VzYyhjKSsiPC90aD4iKS5qb2luKCIiKSsiPC90cj48L3RoZWFkPjx0Ym9keT4iOwogICAgc3Qua2V5cy5mb3JFYWNoKGs9PnsgaHRtbCArPSAiPHRyPjx0ZD4iK2VzYyhrLmtleSkrIjwvdGQ+IitrYy5tYXAoYz0+Ijx0ZCBjbGFzcz0nbW9ubyc+Iitlc2ModmFsKGtbY10pKSsiPC90ZD4iKS5qb2luKCIiKSsiPC90cj4iOyB9KTsKICAgIGh0bWwgKz0gIjwvdGJvZHk+PC90YWJsZT48L2Rpdj48L2Rpdj4iOwogIH0KCiAgY29uc3QgcHJvZ3MgPSBzdC5wcm9ncmFtc3x8e307CiAgY29uc3QgcGsgPSBPYmplY3Qua2V5cyhwcm9ncyk7CiAgaWYocGsubGVuZ3RoKXsKICAgIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5QZXItc3RhdGlvbiBwcm9ncmFtIGRldGFpbDwvaDI+IjsKICAgIHBrLnNvcnQoKS5mb3JFYWNoKHA9PnsKICAgICAgY29uc3Qgcm93cyA9IHByb2dzW3BdLnJvd3N8fHt9OwogICAgICBodG1sICs9ICI8ZGV0YWlscz48c3VtbWFyeT5Qcm9ncmFtICIrZXNjKHApKyIgJm1kYXNoOyAiK2VzYyh2YWwocHJvZ3NbcF0ubmFtZSkpKyI8L3N1bW1hcnk+IjsKICAgICAgaHRtbCArPSAiPHRhYmxlPjx0aGVhZD48dHI+PHRoPlJvdzwvdGg+PHRoPkNvbDwvdGg+PHRoPlZhbHVlPC90aD48dGg+T0lEPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PiI7CiAgICAgIE9iamVjdC5rZXlzKHJvd3MpLmZvckVhY2gocms9PnsgY29uc3Qgcm93PXJvd3NbcmtdOwogICAgICAgIE9iamVjdC5rZXlzKHJvdykuZm9yRWFjaChjPT57IGh0bWwgKz0gIjx0cj48dGQgY2xhc3M9J21vbm8nPiIrZXNjKHJrKSsiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKGMpKwogICAgICAgICAgIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwocm93W2NdLnZhbHVlKSkrIjwvdGQ+PHRkIGNsYXNzPSdtb25vIG11dGVkJz4iK2VzYyhyb3dbY10ub2lkKSsiPC90ZD48L3RyPiI7IH0pOyB9KTsKICAgICAgaHRtbCArPSAiPC90Ym9keT48L3RhYmxlPjwvZGV0YWlscz4iOwogICAgfSk7CiAgICBodG1sICs9ICI8L2Rpdj4iOwogIH0KCiAgY29uc3Qgc28gPSBzdC5zb3VyY2Vfb2lkc3x8e307CiAgaWYoT2JqZWN0LmtleXMoc28pLmxlbmd0aCl7CiAgICBodG1sICs9ICI8ZGl2IGNsYXNzPSdjYXJkJz48aDI+U291cmNlIE9JRHM8L2gyPjxkaXYgY2xhc3M9J2t2Jz4iKwogICAgICBPYmplY3Qua2V5cyhzbykubWFwKGs9Pmt2KGssICI8c3BhbiBjbGFzcz0nbW9ubyBtdXRlZCc+Iitlc2Moc29ba10pKyI8L3NwYW4+IikpLmpvaW4oIiIpKyI8L2Rpdj48L2Rpdj4iOwogIH0KCiAgZHIuaW5uZXJIVE1MID0gaHRtbDsKICBkci5xdWVyeVNlbGVjdG9yKCIuY2xvc2UiKS5vbmNsaWNrID0gY2xvc2VEcmF3ZXI7CiAgZHIuY2xhc3NMaXN0LmFkZCgic2hvdyIpOyAkKCIjb3ZlcmxheSIpLmNsYXNzTGlzdC5hZGQoInNob3ciKTsKICAkKCIjcHJldmlld1N0YXRpb24iKS5vbmNsaWNrID0gKCk9PiBkb1NhdmUoc3QsIGRyLCBmYWxzZSk7CiAgJCgiI3dyaXRlU3RhdGlvbiIpLm9uY2xpY2sgPSAoKT0+IGRvU2F2ZShzdCwgZHIsIHRydWUpOwp9CgpmdW5jdGlvbiBjb2xsZWN0Q2hhbmdlcyhzdCwgZHIpewogIGNvbnN0IGNoYW5nZXMgPSB7fTsKICAkJCgiaW5wdXRbZGF0YS1maWVsZF0iLCBkcikuZm9yRWFjaChpbnA9PnsKICAgIGNvbnN0IGYgPSBpbnAuZGF0YXNldC5maWVsZCwgbnYgPSBpbnAudmFsdWU7CiAgICBpZihTdHJpbmcodmFsKHN0W2ZdKSkgIT09IG52KSBjaGFuZ2VzW2ZdID0gbnY7CiAgfSk7CiAgcmV0dXJuIGNoYW5nZXM7Cn0KCmZ1bmN0aW9uIG9wc1RhYmxlKG9wcyl7CiAgcmV0dXJuICI8dGFibGUgc3R5bGU9J21hcmdpbi10b3A6NnB4Jz48dGhlYWQ+PHRyPjx0aD5GaWVsZDwvdGg+PHRoPk9sZDwvdGg+PHRoPk5ldzwvdGg+PHRoPlRhcmdldCBPSUQ8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+IisKICAgIG9wcy5tYXAobz0+Ijx0cj48dGQ+Iitlc2Moby5maWVsZCkrIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwoby5vbGRfdmFsdWUpKSsKICAgICAgIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyhvLm5ld192YWx1ZSkrIjwvdGQ+PHRkIGNsYXNzPSdtb25vIG11dGVkJz4iK2VzYyhvLnRhcmdldF9vaWR8fChvLm5vdGV8fCLigJQiKSkrIjwvdGQ+PC90cj4iKS5qb2luKCIiKSsKICAgICI8L3Rib2R5PjwvdGFibGU+IjsKfQoKYXN5bmMgZnVuY3Rpb24gZG9TYXZlKHN0LCBkciwgY29uZmlybSl7CiAgY29uc3QgY2hhbmdlcyA9IGNvbGxlY3RDaGFuZ2VzKHN0LCBkcik7CiAgY29uc3QgbXNnID0gJCgiI3NhdmVNc2ciLCBkcik7CiAgaWYoIU9iamVjdC5rZXlzKGNoYW5nZXMpLmxlbmd0aCl7IHNob3dNc2cobXNnLCJpbmZvIiwiTm8gZmllbGRzIGNoYW5nZWQuIik7IHJldHVybjsgfQoKICBpZihjb25maXJtKXsKICAgIGNvbnN0IHN1bW1hcnkgPSBPYmplY3Qua2V5cyhjaGFuZ2VzKS5tYXAoZj0+ZisiIOKGkiBcIiIrY2hhbmdlc1tmXSsiXCIiKS5qb2luKCJcbiIpOwogICAgaWYoIXdpbmRvdy5jb25maXJtKCJXcml0ZSB0aGVzZSBjaGFuZ2VzIHRvIEROICIrdmFsKHN0LmRuKSsiIG92ZXIgU05NUD9cblxuIitzdW1tYXJ5KwogICAgICAgICJcblxuVGhlIHZhbHVlcyB3aWxsIGJlIHJlYWQgYmFjayB0byB2ZXJpZnkuIikpIHJldHVybjsKICB9CiAgY29uc3QgYm9keSA9IHtpcDooRE9DLmRldmljZXx8e30pLmlwIHx8ICQoIiNpcCIpLnZhbHVlLnRyaW0oKSwKICAgICAgICAgICAgICAgIGNvbW11bml0eTogJCgiI2NvbW11bml0eSIpLnZhbHVlLnRyaW0oKSB8fCAiY29tbXVuaXR5TmFtZSIsCiAgICAgICAgICAgICAgICBwb3J0OiBwYXJzZUludCgkKCIjcG9ydCIpLnZhbHVlLDEwKXx8MTYxLAogICAgICAgICAgICAgICAgc3RhdGlvbjogc3QsIGNoYW5nZXMsIGNvbmZpcm19OwogIHNob3dNc2cobXNnLCJpbmZvIiwnPHNwYW4gY2xhc3M9InNwaW5uZXIiPjwvc3Bhbj4nKyhjb25maXJtPyJXcml0aW5nIGFuZCB2ZXJpZnlpbmfigKYiOiJCdWlsZGluZyBwcmV2aWV34oCmIikpOwogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgiL2FwaS9zYXZlIiwgYm9keSk7CiAgICBpZighY29uZmlybSl7CiAgICAgIGxldCBodG1sID0gZXNjKHJlcy5tZXNzYWdlfHwiUHJldmlldyIpOwogICAgICBpZihyZXMucGxhbm5lZF9vcHMgJiYgcmVzLnBsYW5uZWRfb3BzLmxlbmd0aCkKICAgICAgICBodG1sICs9ICI8ZGl2IHN0eWxlPSdtYXJnaW4tdG9wOjhweCc+UGxhbm5lZCBTRVQgb3BlcmF0aW9ucyAoPGI+bm90IHNlbnQ8L2I+KToiK29wc1RhYmxlKHJlcy5wbGFubmVkX29wcykrIjwvZGl2PiI7CiAgICAgIHNob3dNc2cobXNnLCJpbmZvIixodG1sKTsKICAgICAgcmV0dXJuOwogICAgfQogICAgLy8gd3JpdGUgcGF0aAogICAgaWYoIXJlcy5vayAmJiByZXMuZXJyb3IpewogICAgICBsZXQgaHRtbCA9ICJXcml0ZSBmYWlsZWQ6ICIrZXNjKHJlcy5lcnJvcik7CiAgICAgIGlmKHJlcy5wbGFubmVkX29wcykgaHRtbCArPSAiPGRpdiBzdHlsZT0nbWFyZ2luLXRvcDo4cHgnPiIrb3BzVGFibGUocmVzLnBsYW5uZWRfb3BzKSsiPC9kaXY+IjsKICAgICAgc2hvd01zZyhtc2csImVyciIsaHRtbCk7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGxldCBodG1sID0gZXNjKHJlcy5tZXNzYWdlfHwiIik7CiAgICBjb25zdCByID0gcmVzLnJlc3VsdHx8e307CiAgICBpZihyLnJlc3VsdHMgJiYgci5yZXN1bHRzLmxlbmd0aCl7CiAgICAgIGh0bWwgKz0gIjxkaXYgc3R5bGU9J21hcmdpbi10b3A6OHB4Jz5SZWFkLWJhY2sgdmVyaWZpY2F0aW9uOjx0YWJsZSBzdHlsZT0nbWFyZ2luLXRvcDo2cHgnPiIrCiAgICAgICAgIjx0aGVhZD48dHI+PHRoPkZpZWxkPC90aD48dGg+UmVxdWVzdGVkPC90aD48dGg+UmVhZCBiYWNrPC90aD48dGg+TWF0Y2g8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+IisKICAgICAgICByLnJlc3VsdHMubWFwKHg9PiI8dHI+PHRkPiIrZXNjKHguZmllbGQpKyI8L3RkPjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2MoeC5yZXF1ZXN0ZWQpKwogICAgICAgICAgIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwoeC5yZWFkX2JhY2spKSsiPC90ZD48dGQ+IisKICAgICAgICAgICh4Lm1hdGNoPyI8c3BhbiBzdHlsZT0nY29sb3I6dmFyKC0tb2spJz4mIzEwMDAzOzwvc3Bhbj4iOiI8c3BhbiBzdHlsZT0nY29sb3I6dmFyKC0tYmFkKSc+JiMxMDAwNzs8L3NwYW4+IikrCiAgICAgICAgICAiPC90ZD48L3RyPiIpLmpvaW4oIiIpKyI8L3Rib2R5PjwvdGFibGU+PC9kaXY+IjsKICAgIH0KICAgIHNob3dNc2cobXNnLCByZXMub2s/Im9rIjoiZXJyIiwgaHRtbCk7CiAgICAvLyByZWZsZWN0IHRoZSB2ZXJpZmllZCB2YWx1ZXMgaW4gdGhlIGluLW1lbW9yeSBkb2MgKyB0YWJsZQogICAgaWYocmVzLm9rKXsKICAgICAgT2JqZWN0LmtleXMoY2hhbmdlcykuZm9yRWFjaChmPT57IHN0W2ZdID0gY2hhbmdlc1tmXTsgfSk7CiAgICAgIHJlbmRlclN0YXRpb25zKCk7CiAgICB9CiAgfWNhdGNoKGUpeyBzaG93TXNnKG1zZywiZXJyIiwiU2F2ZSByZXF1ZXN0IGZhaWxlZDogIitlc2MoZS5tZXNzYWdlKSk7IH0KfQoKLyogLS0tLS0tLS0tLSBDYXRhbG9nIGJhY2t1cCAvIHZpZXcgLyBkaWZmIC8gcmVzdG9yZSAtLS0tLS0tLS0tICovCmNvbnN0IEJLID0ge0E6bnVsbCwgQjpudWxsfTsKZnVuY3Rpb24gY2F0U2hvdyh0ZXh0KXsgY29uc3QgZWw9JCgiI2NhdE91dCIpOyBlbC50ZXh0Q29udGVudD10ZXh0OyBlbC5zdHlsZS5kaXNwbGF5PSJibG9jayI7IGVsLnNjcm9sbFRvcD0wOyB9CmZ1bmN0aW9uIGJhY2t1cExhYmVsKGIpeyBjb25zdCBtPWIubWV0YXx8e307CiAgcmV0dXJuIChtLnNpdGV8fG0uc291cmNlX2lwfHwiYmFja3VwIikrIiDCtyAiKyhtLnJvd3NfY291bnR8fDApKyIgcm93cyDCtyAiK1N0cmluZyhtLnJlYWRfYXR8fCIiKS5zbGljZSgwLDE5KTsgfQpmdW5jdGlvbiBjYXRCYXNlTmFtZShiKXsgY29uc3QgbT1iLm1ldGF8fHt9OwogIGNvbnN0IHdobyA9IFN0cmluZyhtLnNpdGV8fG0uc291cmNlX2lwfHwiY2l4IikucmVwbGFjZSgvW15cdy4tXS9nLCJfIik7CiAgY29uc3Qgd2hlbiA9IFN0cmluZyhtLnJlYWRfYXR8fCIiKS5yZXBsYWNlKC9bOlRdL2csIi0iKS5zbGljZSgwLDE5KTsKICByZXR1cm4gInRvc2hpYmEtY2l4LSIrd2hvKyh3aGVuPyItIit3aGVuOiIiKSsiLWNhdGFsb2ciOyB9CmZ1bmN0aW9uIHJlZnJlc2hTbG90cygpewogICQoIiNzbG90QSIpLnRleHRDb250ZW50ID0gIkE6ICIrKEJLLkE/YmFja3VwTGFiZWwoQksuQSk6IihlbXB0eSkiKTsKICAkKCIjc2xvdEIiKS50ZXh0Q29udGVudCA9ICJCOiAiKyhCSy5CP2JhY2t1cExhYmVsKEJLLkIpOiIoZW1wdHkpIik7CiAgJCgiI2J0bkNhdFZpZXciKS5kaXNhYmxlZCA9ICFCSy5BOwogICQoIiNidG5DYXREb3dubG9hZCIpLmRpc2FibGVkID0gIUJLLkE7CiAgJCgiI2J0bkNhdFJlc3RvcmVQcmV2IikuZGlzYWJsZWQgPSAhQksuQTsKICAkKCIjYnRuQ2F0UmVzdG9yZUdvIikuZGlzYWJsZWQgPSAhQksuQTsKICAkKCIjYnRuQ2F0RGlmZiIpLmRpc2FibGVkID0gIShCSy5BICYmIEJLLkIpOwp9CmZ1bmN0aW9uIGxvYWRCYWNrdXBJbnRvKHNsb3QsIGZpbGUpewogIGNvbnN0IGZyID0gbmV3IEZpbGVSZWFkZXIoKTsKICBmci5vbmxvYWQgPSAoKT0+ewogICAgdHJ5ewogICAgICBjb25zdCBkb2MgPSBKU09OLnBhcnNlKGZyLnJlc3VsdCk7CiAgICAgIGlmKGRvYy5mb3JtYXQgIT09ICJ0b3NoaWJhLWNpeC1iYWNrdXAiKSB0aHJvdyBuZXcgRXJyb3IoIm5vdCBhIGNhdGFsb2cgYmFja3VwIChmb3JtYXQgIT0gdG9zaGliYS1jaXgtYmFja3VwKSIpOwogICAgICBCS1tzbG90XSA9IGRvYzsgcmVmcmVzaFNsb3RzKCk7CiAgICAgIHNob3dNc2coJCgiI2NhdE1zZyIpLCJvayIsIkxvYWRlZCBzbG90ICIrc2xvdCsiOiAiK2VzYyhiYWNrdXBMYWJlbChkb2MpKSk7CiAgICB9Y2F0Y2goZSl7IHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLCJDb3VsZCBub3QgbG9hZCBiYWNrdXA6ICIrZXNjKGUubWVzc2FnZSkpOyB9CiAgfTsKICBmci5yZWFkQXNUZXh0KGZpbGUpOwp9CiQoIiNidG5PcGVuQSIpLm9uY2xpY2sgPSAoKT0+ICQoIiNjYXRGaWxlQSIpLmNsaWNrKCk7CiQoIiNidG5PcGVuQiIpLm9uY2xpY2sgPSAoKT0+ICQoIiNjYXRGaWxlQiIpLmNsaWNrKCk7CiQoIiNjYXRGaWxlQSIpLm9uY2hhbmdlID0gKGV2KT0+eyBjb25zdCBmPWV2LnRhcmdldC5maWxlc1swXTsgaWYoZikgbG9hZEJhY2t1cEludG8oIkEiLGYpOyBldi50YXJnZXQudmFsdWU9IiI7IH07CiQoIiNjYXRGaWxlQiIpLm9uY2hhbmdlID0gKGV2KT0+eyBjb25zdCBmPWV2LnRhcmdldC5maWxlc1swXTsgaWYoZikgbG9hZEJhY2t1cEludG8oIkIiLGYpOyBldi50YXJnZXQudmFsdWU9IiI7IH07CgokKCIjYnRuQ2F0QmFja3VwIikub25jbGljayA9IGFzeW5jICgpPT57CiAgY29uc3QgZiA9IHJlYWRGb3JtKCk7CiAgaWYoIWYuaXApeyBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIiwiRW50ZXIgdGhlIENJWCBJUCBhZGRyZXNzIGFib3ZlIGZpcnN0LiIpOyByZXR1cm47IH0KICBjb25zdCBidG49JCgiI2J0bkNhdEJhY2t1cCIpOyBidG4uZGlzYWJsZWQ9dHJ1ZTsgY29uc3Qgb2xkPWJ0bi50ZXh0Q29udGVudDsgYnRuLnRleHRDb250ZW50PSJSZWFkaW5n4oCmIjsKICBzaG93TXNnKCQoIiNjYXRNc2ciKSwiaW5mbyIsJzxzcGFuIGNsYXNzPSJzcGlubmVyIj48L3NwYW4+RnVsbCBjYXRhbG9nIHJlYWQgb2YgJytlc2MoZi5pcCkrJyAoZXZlcnkgcHJvZ3JhbSDigJQgdGhpcyBjYW4gdGFrZSBhIHdoaWxlKSZoZWxsaXA7Jyk7CiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL2NhdGFsb2ctYmFja3VwIiwge2lwOmYuaXAsIGNvbW11bml0eTpmLmNvbW11bml0eSwgcG9ydDpmLnBvcnR9KTsKICAgIGlmKCFyZXMub2speyBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIiwiQmFja3VwIGZhaWxlZDogIitlc2MocmVzLmVycm9yfHwidW5rbm93biIpKTsgcmV0dXJuOyB9CiAgICBCSy5BID0gcmVzLmJhY2t1cDsgcmVmcmVzaFNsb3RzKCk7CiAgICBzaG93TXNnKCQoIiNjYXRNc2ciKSwib2siLCJCYWNrdXAgcmVhZCBpbnRvIHNsb3QgQTogIitlc2MoYmFja3VwTGFiZWwocmVzLmJhY2t1cCkpKyIuIERvd25sb2FkIGl0IHRvIGtlZXAgaXQuIik7CiAgICBjYXRTaG93KHJlcy5yZXBvcnR8fCIiKTsKICB9Y2F0Y2goZSl7IHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLCJSZXF1ZXN0IGZhaWxlZDogIitlc2MoZS5tZXNzYWdlKSk7IH0KICBmaW5hbGx5eyBidG4uZGlzYWJsZWQ9ZmFsc2U7IGJ0bi50ZXh0Q29udGVudD1vbGQ7IH0KfTsKJCgiI2J0bkNhdFZpZXciKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICBpZighQksuQSkgcmV0dXJuOwogIHRyeXsgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL3ZpZXciLCB7YmFja3VwOkJLLkF9KTsKICAgIGlmKHJlcy5vaykgY2F0U2hvdyhyZXMucmVwb3J0KTsgZWxzZSBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIixlc2MocmVzLmVycm9yfHwidmlldyBmYWlsZWQiKSk7CiAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIiwiUmVxdWVzdCBmYWlsZWQ6ICIrZXNjKGUubWVzc2FnZSkpOyB9Cn07CiQoIiNidG5DYXREaWZmIikub25jbGljayA9IGFzeW5jICgpPT57CiAgaWYoIUJLLkEgfHwgIUJLLkIpIHJldHVybjsKICB0cnl7IGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgiL2FwaS9kaWZmIiwge2E6QksuQSwgYjpCSy5CfSk7CiAgICBpZihyZXMub2spIGNhdFNob3cocmVzLnJlcG9ydCk7IGVsc2Ugc2hvd01zZygkKCIjY2F0TXNnIiksImVyciIsZXNjKHJlcy5lcnJvcnx8ImRpZmYgZmFpbGVkIikpOwogIH1jYXRjaChlKXsgc2hvd01zZygkKCIjY2F0TXNnIiksImVyciIsIlJlcXVlc3QgZmFpbGVkOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQp9OwokKCIjYnRuQ2F0RG93bmxvYWQiKS5vbmNsaWNrID0gKCk9PiBCSy5BICYmIGRvd25sb2FkKGNhdEJhc2VOYW1lKEJLLkEpKyIuanNvbiIsIEpTT04uc3RyaW5naWZ5KEJLLkEsbnVsbCwyKSwgImFwcGxpY2F0aW9uL2pzb24iKTsKCmZ1bmN0aW9uIHJlbmRlclJlc3RvcmUocmVzKXsKICBjb25zdCBzID0gcmVzLnN1bW1hcnl8fHt9OwogIGxldCBodG1sID0gZXNjKHJlcy5tZXNzYWdlfHwiIikrIjxicj48YnI+IisKICAgICI8Yj5QbGFuOjwvYj4gIisocy5zZW5kYWJsZXx8MCkrIiBzZW5kYWJsZSwgIisocy5za2lwcGVkfHwwKSsiIHNraXBwZWQgKCIrKHMucmVhZF9vbmx5fHwwKSsKICAgICIgcmVhZC1vbmx5KSwgIisocy51bnByb3Zlbl93aXJlX3R5cGV8fDApKyIgdW5wcm92ZW4gd2lyZS10eXBlLiI7CiAgaWYocmVzLm1vZGU9PT0id3JpdGUiICYmIHJlcy5yZXN1bHRzKXsKICAgIGNvbnN0IGJhZCA9IHJlcy5yZXN1bHRzLmZpbHRlcihyPT4hci5tYXRjaCkubGVuZ3RoOwogICAgaHRtbCArPSAiPGJyPldyb3RlICIrKHJlcy53cm90ZXx8MCkrIiwgdmVyaWZpZWQgIisocmVzLnJlc3VsdHMubGVuZ3RoLWJhZCkrIi8iK3Jlcy5yZXN1bHRzLmxlbmd0aCsiLiI7CiAgfQogIHNob3dNc2coJCgiI2NhdE1zZyIpLCByZXMub2s/Im9rIjoocmVzLm1vZGU9PT0id3JpdGUiPyJlcnIiOiJpbmZvIiksIGh0bWwpOwogIGNvbnN0IGxpbmVzID0gW3Jlcy5tZXNzYWdlLCAiIl07CiAgKHJlcy5wbGFubmVkX29wc3x8W10pLmZvckVhY2gobz0+ewogICAgbGluZXMucHVzaCgoby5zZW5kYWJsZT8iU0VUICI6InNraXAgIikrKG8udGFyZ2V0X29pZHx8IihubyBvaWQpIikrIiA9ICIrSlNPTi5zdHJpbmdpZnkoby5uZXdfdmFsdWUpKwogICAgICAiICBbIitvLmJlcl90eXBlKyJdICIrby5maWVsZF9uYW1lKyhvLm5vdGU/KCIgIOKAlCAiK28ubm90ZSk6IiIpKTsKICB9KTsKICBpZihyZXMucmVzdWx0cyAmJiByZXMucmVzdWx0cy5sZW5ndGgpewogICAgbGluZXMucHVzaCgiIik7IGxpbmVzLnB1c2goIlJlYWQtYmFjayB2ZXJpZmljYXRpb246Iik7CiAgICByZXMucmVzdWx0cy5mb3JFYWNoKHI9PiBsaW5lcy5wdXNoKCIgIFsiKyhyLm1hdGNoPyJvayI6Ik1JU01BVENIIikrIl0gIityLmZpZWxkKyIgPSAiK0pTT04uc3RyaW5naWZ5KHIucmVhZF9iYWNrKSsiICh3YW50ZWQgIitKU09OLnN0cmluZ2lmeShyLnJlcXVlc3RlZCkrIikiKSk7CiAgfQogIGNhdFNob3cobGluZXMuam9pbigiXG4iKSk7Cn0KJCgiI2J0bkNhdFJlc3RvcmVQcmV2Iikub25jbGljayA9IGFzeW5jICgpPT57CiAgaWYoIUJLLkEpIHJldHVybjsKICB0cnl7IGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgiL2FwaS9yZXN0b3JlIiwge2JhY2t1cDpCSy5BLCBjb25maXJtOmZhbHNlfSk7CiAgICByZW5kZXJSZXN0b3JlKHJlcyk7CiAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIiwiUmVxdWVzdCBmYWlsZWQ6ICIrZXNjKGUubWVzc2FnZSkpOyB9Cn07CiQoIiNidG5DYXRSZXN0b3JlR28iKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICBpZighQksuQSkgcmV0dXJuOwogIGNvbnN0IGYgPSByZWFkRm9ybSgpOwogIGlmKCFmLmlwKXsgc2hvd01zZygkKCIjY2F0TXNnIiksImVyciIsIkVudGVyIHRoZSB0YXJnZXQgQ0lYIElQIGFkZHJlc3MgYWJvdmUgZmlyc3QuIik7IHJldHVybjsgfQogIGlmKCF3aW5kb3cuY29uZmlybSgiUmVzdG9yZSBiYWNrdXAgQSB0byAiK2YuaXArIiBvdmVyIFNOTVA/XG5cblRoaXMgd3JpdGVzIGV2ZXJ5IHdyaXRhYmxlIGZpZWxkIGJhY2sgdG8gdGhlIGxpdmUgQ0lYIChhcHBsaWVkIHRvIFJBTTsgIisKICAgICJwZXJzaXN0ZW5jZSBhY3Jvc3MgcmVib290IGlzIHVucHJvdmVuKSBhbmQgcmVhZHMgZWFjaCBvbmUgYmFjayB0byB2ZXJpZnkuIFJlYWQtb25seSBmaWVsZHMgYXJlIG5vdCB0b3VjaGVkLiIpKSByZXR1cm47CiAgY29uc3QgYnRuPSQoIiNidG5DYXRSZXN0b3JlR28iKTsgYnRuLmRpc2FibGVkPXRydWU7IGNvbnN0IG9sZD1idG4udGV4dENvbnRlbnQ7IGJ0bi50ZXh0Q29udGVudD0iUmVzdG9yaW5n4oCmIjsKICBzaG93TXNnKCQoIiNjYXRNc2ciKSwiaW5mbyIsJzxzcGFuIGNsYXNzPSJzcGlubmVyIj48L3NwYW4+UmVzdG9yaW5nIHRvICcrZXNjKGYuaXApKycgYW5kIHZlcmlmeWluZyZoZWxsaXA7Jyk7CiAgdHJ5eyBjb25zdCByZXMgPSBhd2FpdCBhcGkoIi9hcGkvcmVzdG9yZSIsIHtpcDpmLmlwLCBjb21tdW5pdHk6Zi5jb21tdW5pdHksIHBvcnQ6Zi5wb3J0LCBiYWNrdXA6QksuQSwgY29uZmlybTp0cnVlfSk7CiAgICBpZighcmVzLm9rICYmIHJlcy5lcnJvcil7IHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLCJSZXN0b3JlIGZhaWxlZDogIitlc2MocmVzLmVycm9yKSk7IHJldHVybjsgfQogICAgcmVuZGVyUmVzdG9yZShyZXMpOwogIH1jYXRjaChlKXsgc2hvd01zZygkKCIjY2F0TXNnIiksImVyciIsIlJlcXVlc3QgZmFpbGVkOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQogIGZpbmFsbHl7IGJ0bi5kaXNhYmxlZD1mYWxzZTsgYnRuLnRleHRDb250ZW50PW9sZDsgcmVmcmVzaFNsb3RzKCk7IH0KfTsKCi8qIGJvb3QgKi8KKGFzeW5jICgpPT57IHRyeXsgY29uc3QgYyA9IGF3YWl0IGFwaSgiL2FwaS9jYXRhbG9nIik7CiAgaWYoYyYmYy5vaykgJCgiI2NhdEluZm8iKS50ZXh0Q29udGVudCA9IGMucHJvZ3JhbXMrIiBwcm9ncmFtcywgIitjLmZpZWxkcysiIGZpZWxkcywgIitjLndyaXRhYmxlKyIgd3JpdGFibGUgwrcgY2F0YWxvZyAiK2MuY2F0YWxvZ192ZXJzaW9uOwp9Y2F0Y2goZSl7fSB9KSgpOwooYXN5bmMgKCk9PnsgdHJ5eyBjb25zdCBoID0gYXdhaXQgYXBpKCIvYXBpL2hlYWx0aCIpOwogIGlmKGgmJmgudmVyc2lvbikgZG9jdW1lbnQudGl0bGUgPSAiVG9zaGliYSBDSVggTWFuYWdlciAiK2gudmVyc2lvbjsKICBjb25zdCBiID0gJCgiI21vZGVCYWRnZSIpOwogIGlmKGggJiYgaC53cml0ZXNfZW5hYmxlZCl7IGIudGV4dENvbnRlbnQgPSAiV1JJVEVTOiBDT05GSVJNLUdBVEVEIjsgfQogIGVsc2UgeyBiLnRleHRDb250ZW50ID0gIlJFQUQtT05MWSI7IH0KfWNhdGNoKGUpe30gfSkoKTsKPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo=").decode("utf-8")  # bundled UI

if __name__ == "__main__":
    _argv = sys.argv[1:]
    if _argv and _argv[0] == "read":
        raise SystemExit(reader_cli_main(_argv[1:]))
    if _argv and _argv[0] in ("serve", "web"):
        _argv = _argv[1:]
    raise SystemExit(main(_argv))  # webapp.main — serves the UI
