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
                 keep_raw_walk: bool = False, enrich: bool = True,
                 catalog=None):
        self.client = client
        self.log = logger or logging.getLogger(__name__)
        # "all" (whole tree), "core" (fast), or a catalog-driven scope such as a
        # feature group (trunks/groups/voicemail/licensing/stations/phantom) or
        # a menu-area name — resolved against the catalog, falling back to a
        # whole-tree walk when the catalog is unavailable (e.g. the lean build).
        self.scope = scope
        self.max_oids = max_oids
        self.strategy = strategy      # "bulk" (fast, batched) or "serial"
        self.width = width            # cursors per GETNEXT PDU in bulk mode
        # Build the named, menu-grouped program_views from the walk (the
        # frontend contract). Off in the lean reader build, where the catalog
        # and enrich modules are not bundled.
        self._enrich = enrich
        self._catalog = catalog       # cached across the scope + enrich passes
        self.varbinds: list[tuple[str, Value]] = []
        # When True, the full flat (oid, value) walk is attached to the result
        # as doc["raw_oid_walk"]. Off by default so the CLI/adapter docs stay
        # lean; the web app turns it on so a backup export can include the raw
        # walk alongside the structured JSON and the report.
        self.keep_raw_walk = keep_raw_walk

    # -- public ------------------------------------------------------------
    def read(self) -> dict:
        """Walk the device and return the full structured document."""
        varbinds, walk_error = self._collect()
        self.varbinds = varbinds
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
        # Named, menu-grouped program views — the stable frontend contract.
        doc["program_views"] = self._program_views(varbinds)
        if self.keep_raw_walk:
            doc["raw_oid_walk"] = [
                {"oid": oid, "value": D.decode_value(val)}
                for oid, val in varbinds
            ]
        return doc

    def _program_views(self, varbinds) -> dict:
        """Catalog-driven enrichment; empty when the catalog is unavailable."""
        if self._enrich:
            try:
                # Lazy + guarded: in the lean reader build these submodules are
                # not bundled, so the names stay undefined and we degrade to
                # empty views instead of failing the read.
                cat = self._catalog or load_catalog()
                self._catalog = cat
                return build_program_views(varbinds, cat)
            except Exception as exc:  # noqa: BLE001
                self.log.debug("program_views unavailable: %r", exc)
        return {"programs": [], "menu_areas": [], "feature_views": [],
                "uncataloged": [],
                "stats": {"programs": 0, "rows": 0, "cells": 0,
                          "named_cells": 0, "raw_oid_cells": 0,
                          "uncataloged": 0}}

    # -- collection --------------------------------------------------------
    def _collect(self) -> tuple[list[tuple[str, Value]], str | None]:
        preset = self._preset_roots()
        if preset is not None:
            return self._collect_roots(preset)
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

    def _preset_roots(self) -> list[str] | None:
        """GETNEXT roots for a catalog-driven scope (feature group / menu area).

        Returns ``None`` for ``core`` / ``all`` (handled by the branch walkers)
        and for any scope the catalog cannot resolve — including the lean reader
        build, where the enrich/catalog submodules are not bundled, so the
        guarded import below leaves the names undefined and we fall back.
        """
        if self.scope in ("core", "all"):
            return None
        try:
            cat = self._catalog or load_catalog()
            self._catalog = cat
            roots = scope_roots(cat, self.scope)
            if roots:
                # Always include the identity branch so meta (software id,
                # chassis MAC) and security findings still populate.
                return list(roots) + [f"{D.ENTERPRISE_ROOT}.7"]
            return None
        except Exception as exc:  # noqa: BLE001
            self.log.debug("scope %r not catalog-resolvable: %r", self.scope, exc)
            return None

    def _collect_roots(self, roots: list[str]
                       ) -> tuple[list[tuple[str, Value]], str | None]:
        """Walk an explicit list of subtree roots (catalog-driven scopes).

        Bulk when possible (many cursors), with a serial fallback so a flaky
        device degrades to a partial read rather than nothing."""
        if self.strategy != "serial":
            try:
                pairs = self.client.bulk_walk(roots, width=self.width,
                                              max_total=self.max_oids)
                return self._dedup(pairs), None
            except SnmpError as exc:
                self.log.warning("bulk scope walk failed (%s); serial fallback",
                                 exc)
        out: list[tuple[str, Value]] = []
        error: str | None = None
        for root in roots:
            try:
                out.extend(self.client.walk(root, max_oids=self.max_oids))
            except SnmpError as exc:
                self.log.warning("root %s interrupted: %s", root, exc)
                error = str(exc)
        return self._dedup(out), error

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
ENUM_LABELS_FILENAME = "enum_labels.json"
PROGRAM_MENUS_FILENAME = "program_menus.json"

# Menu areas as eManager groups them, in the order the UI should show them.
# ``command_to_menu.json`` supplies the first ten; the last three are our
# buckets for the handful of internal MIB tables eManager never surfaced as a
# program (null-number entries: licensing, SNMP/FTP middleware, status trees).
MENU_AREA_ORDER = (
    "System", "Station", "Trunk", "IP-Telephony", "Networking", "LCR/DR",
    "External Devices", "Attendant", "Utilities", "Miscellaneous",
    "Licensing", "Maintenance", "Advanced",
)

# On-wire encoding families (the MOF ``enc``) → how a restore SETs the value.
_INTEGER_ENCS = frozenset({"INTEGER", "Gauge32"})
_INTEGER_SYNTAXES = frozenset({"INTEGER", "EnumeratedINTEGER", "Gauge32"})

_CATALOG_CACHE: "Catalog | None" = None


# --------------------------------------------------------------------------
# loading (mirrors webapp.load_html: embedded → PyInstaller bundle → package)
# --------------------------------------------------------------------------
def _data_candidate_paths(filename: str) -> list[str]:
    """Where a vendored ``data/<filename>`` may live, across every build.

    PyInstaller one-file (``sys._MEIPASS``) first, then the packaged ``data/``
    dir of a dev checkout. Same order as :func:`load_catalog_text`.
    """
    paths: list[str] = []
    meipass = getattr(sys, "_MEIPASS", None)          # PyInstaller one-file
    if meipass:
        paths.append(os.path.join(meipass, "toshiba_cix", "data", filename))
        paths.append(os.path.join(meipass, "data", filename))
        paths.append(os.path.join(meipass, filename))
    here = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(here, "data", filename))
    return paths


def _candidate_paths() -> list[str]:
    return _data_candidate_paths(CATALOG_FILENAME)


def _load_data_text(filename: str, embedded_global: str) -> str | None:
    """Return a vendored data file's text, or ``None`` if it is unavailable.

    Mirrors :func:`load_catalog_text` (embedded global → PyInstaller bundle →
    packaged ``data/``) but **degrades gracefully**: a build that forgot to
    bundle the enum-label / menu sidecar still runs — just without those
    annotations — instead of crashing.
    """
    embedded = globals().get(embedded_global)
    if embedded:
        return embedded
    for path in _data_candidate_paths(filename):
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    return fh.read()
            except OSError:
                return None
    return None


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
        # Per-call override hook (set_enum_labels); empty until a caller installs
        # one. The bundled labels below are the always-on base layer.
        self._enum_labels: dict[str, dict[int, str]] = {}
        self._bundled_enum_labels: dict[str, dict[int, str]] = \
            self._load_bundled_enum_labels()
        self._menu_by_number: dict[str, dict] = self._load_bundled_menus()

    # -- bundled annotations (enum labels + eManager menu areas) -----------
    @staticmethod
    def _load_bundled_enum_labels() -> dict[str, dict[int, str]]:
        text = _load_data_text(ENUM_LABELS_FILENAME, "EMBEDDED_ENUM_LABELS_JSON")
        if not text:
            return {}
        try:
            raw = json.loads(text)
        except ValueError:
            return {}
        out: dict[str, dict[int, str]] = {}
        for oid, mapping in raw.items():
            sub: dict[int, str] = {}
            for k, label in (mapping or {}).items():
                try:
                    sub[int(k)] = label
                except (TypeError, ValueError):
                    continue
            if sub:
                out[str(oid)] = sub
        return out

    @staticmethod
    def _load_bundled_menus() -> dict[str, dict]:
        text = _load_data_text(PROGRAM_MENUS_FILENAME, "EMBEDDED_PROGRAM_MENUS_JSON")
        if not text:
            return {}
        try:
            raw = json.loads(text)
        except ValueError:
            return {}
        by_number = raw.get("by_number") if isinstance(raw, dict) else None
        return by_number if isinstance(by_number, dict) else {}

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
        """Install an ``{oid: {raw_int: label}}`` **override** map.

        The reverse-engineered labels already ship bundled (see
        :meth:`enum_label`); this installs per-OID overrides that win over the
        bundle — for a site that renames a value, or a future catalog revision.
        Keys are normalised so an ``{raw: label}`` sub-map accepts int or str.
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
        """Human label for an EnumeratedINTEGER raw value, or ``None``.

        A per-call override installed with :meth:`set_enum_labels` wins; the
        bundled labels reverse-engineered from the MOF are the base layer, so
        787 enumerated fields resolve out of the box with no setup.
        """
        oid = fld.get("oid")
        try:
            r = int(raw)
        except (TypeError, ValueError):
            return None
        sub = self._enum_labels.get(oid)
        if sub and r in sub:
            return sub[r]
        sub = self._bundled_enum_labels.get(oid)
        if sub and r in sub:
            return sub[r]
        return None

    def enum_values(self, fld: dict) -> dict[int, str] | None:
        """The full ``{raw: label}`` map for an enumerated field, else ``None``.

        Override entries (if any) shadow the bundled map; the frontend uses this
        to render a dropdown of the allowed values for a writable enum field.
        """
        oid = fld.get("oid")
        merged: dict[int, str] = {}
        base = self._bundled_enum_labels.get(oid)
        if base:
            merged.update(base)
        over = self._enum_labels.get(oid)
        if over:
            merged.update(over)
        return merged or None

    # -- menu area (eManager grouping) -------------------------------------
    def menu_info(self, program_ident) -> dict:
        """eManager menu placement for a program: ``{area, menu_path, label}``.

        Resolved from the vendored ``program_menus.json`` by program number.
        The 31 internal MIB tables eManager never exposed as a program (null
        number — licensing, SNMP/FTP middleware, status trees) get a derived
        area so they are still reachable and grouped rather than orphaned.
        """
        prog = self.program(program_ident)
        if prog is None:
            return {"area": "Advanced", "menu_path": "", "label": str(program_ident)}
        if prog.number and prog.number in self._menu_by_number:
            info = self._menu_by_number[prog.number]
            return {"area": info.get("area") or "Advanced",
                    "menu_path": info.get("menu_path") or "",
                    "label": info.get("label") or prog.name or prog.number}
        return {"area": self._derived_area(prog),
                "menu_path": "", "label": prog.name or prog.key}

    def menu_area(self, program_ident) -> str:
        return self.menu_info(program_ident)["area"]

    @staticmethod
    def _derived_area(prog: "Program") -> str:
        """Area for a program the eManager menu map does not name (null number).

        Keyed off the field OID subtree so licensing, middleware and the status
        trees land somewhere sensible instead of a generic bucket.
        """
        g = prog.group_oid or ""
        root = ENTERPRISE_ROOT + "."
        if g.startswith(root):
            tail = g[len(root):]
            top = tail.split(".", 1)[0]
            if top == "10":
                return "Licensing"
            if top in ("2", "5", "6", "8"):
                return "Maintenance"
            if top in ("4",):
                return "System"
        key = (prog.key or "").lower()
        if "ftp" in key or "community" in key or "middleware" in key:
            return "Networking"
        if "license" in key:
            return "Licensing"
        return "Advanced"


__all__ = [
    "CATALOG_FILENAME", "ENUM_LABELS_FILENAME", "PROGRAM_MENUS_FILENAME",
    "MENU_AREA_ORDER", "Catalog", "Program",
    "load_catalog", "load_catalog_text",
]
EMBEDDED_CATALOG_JSON = base64.b64decode("eyIxMDBDYXJkU2xvdCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY2FyZFNsb3RURUkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMC4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiNCIsIm5hbWUiOiJjYXJkU2xvdEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDAuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMyIsIm5hbWUiOiJjYXJkU2xvdENhcmRUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDAuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYXJkU2xvdE5ld0RLVVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhcmRTbG90UENNaGlnaHdheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAwLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAwIiwibmFtZSI6IkNhcmRTbG90IiwibnVtYmVyIjoiMTAwIn0sIjEwMTA2RGF5TmlnaHRNb2RlUHJpdmF0ZURheSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoicHJpdmF0ZURheVBlclRlbmFudFRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlQZXJUZW5hbnRGcmlkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTA2LjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVBlclRlbmFudE1vbmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5UGVyVGVuYW50U3VuZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNi4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlQZXJUZW5hbnRUdWVzZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNi4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlQZXJUZW5hbnRTYXR1cmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5UGVyVGVuYW50VGh1cnNkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTA2LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVBlclRlbmFudFdlZG5lc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNiIsIm5hbWUiOiJEYXlOaWdodE1vZGVQcml2YXRlRGF5IiwibnVtYmVyIjoiMTAxMDYifSwiMTAxMTJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVDYWxlbmRhclBlclRlbmFudERheU1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEyLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoicHJpdmF0ZUNhbGVuZGFyUGVyVGVuYW50VGVuYW50TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiI4IiwibmFtZSI6InByaXZhdGVDYWxlbmRhclBlclRlbmFudERheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTIuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMiIsIm5hbWUiOiJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiLCJudW1iZXIiOiIxMDExMiJ9LCIxMDExM0RheU5pZ2h0TW9kZVNjaGVkdWxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50Tm9uV29ya2luZ0RheURheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEzLjEuMS41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVBlclRlbmFudE5vbldvcmtpbmdEYXlEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMy4xLjEuNiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVQZXJUZW5hbnRQcml2YXRlSG9saWRheURheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEzLjEuMS44Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVBlclRlbmFudFByaXZhdGVIb2xpZGF5RGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjkiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50Tm9uV29ya2luZ0RheU5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMy4xLjEuNyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50UHJpdmF0ZUhvbGlkYXlOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjEwIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoidHlwZVBlclRlbmFudFRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVQZXJUZW5hbnRXb3JraW5nRGF5RGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUGVyVGVuYW50V29ya2luZ0RheURheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEzLjEuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVBlclRlbmFudFdvcmtpbmdEYXlOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMTMuMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDExMyIsIm5hbWUiOiJEYXlOaWdodE1vZGVTY2hlZHVsZSIsIm51bWJlciI6IjEwMTEzIn0sIjEwMkZsZXhpYmxlTnVtYmVyaW5nUGxhbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImZsYXhpYmxlTnVtYmVybGluZ09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAyLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZmxheGlibGVOdW1iZXJsaW5nUGxhbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAyLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMyIsIm5hbWUiOiJmbGF4aWJsZU51bWJlcmxpbmdGZWF0dXJlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDIuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDIiLCJuYW1lIjoiRmxleGlibGVOdW1iZXJpbmdQbGFuIiwibnVtYmVyIjoiMTAyIn0sIjEwMzE5SW50ZXJjZXB0UG9zaXRpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6ImludGVyY2VwdFBlclRlbmFudFRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzMTkuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpbnRlcmNlcHRQZXJUZW5hbnREYXkxRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaW50ZXJjZXB0UGVyVGVuYW50RGF5MkRlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMxOS4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImludGVyY2VwdFBlclRlbmFudE5pZ2h0RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbnRlcmNlcHRQZXJUZW5hbnREYXkxRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMxOS4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImludGVyY2VwdFBlclRlbmFudERheTJEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaW50ZXJjZXB0UGVyVGVuYW50TmlnaHREZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzMTkiLCJuYW1lIjoiSW50ZXJjZXB0UG9zaXRpb24iLCJudW1iZXIiOiIxMDMxOSJ9LCIxMDNDbGFzc09mU2VydmljZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1ZlcmlmeUFjY291bnRDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRG5kT3ZlcnJpZGVJbnZva2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RuZE92ZXJyaWRlUGVybWl0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRGF5TmlnaHRNb2RlQ2hhbmdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0F1dG9EaXNjUGFnaW5nQ2FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEaXJlY3RlZEROUmV0cmlldmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSG9va2luZ1NpZ25hbE9uT2ZmIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RhdGFPcmlnaW5hdGluZ09jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NFeGVjdXRpdmVPdmVycmlkZU9yaWdpbmF0b3IiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSGFuZHNGcmVlQW5zd2VyQmFjayIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NDYWxsRm9yd2FyZE92ZXJyaWRlV2l0aERTU0tleSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NMY2REbmlzQW5pUHJpb3JpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNDQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSGVhcmluZ0JHTSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0NhbGxGb3J3YXJkT3ZlcnJpZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEaXJlY3RlZEdyb3VwUGlja3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0V4dGVybmFsQkdNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1RydW5rR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEbmRTZXRMb2NhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1JlbW90ZVJldHJpZXZlUGlja3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0FueUV4dGVybmFsQ2FsbFBpY2t1cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NPcmlnaW5hdGVyQWNjb3VudENvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zR3JvdXBQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zTENSRmVhdHVyZUF2YWlsYWJpbGl0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RuZFNldFJlbW90ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zQ2FsbFRyYW5zZmVyV2l0aENhbXBvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0RpcmVjdGVkVGVybWluYWxQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NBYnIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJjb3NDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc09mZmhvb2tDYW1wb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRXhlY3V0aXZlT3ZlcnJpZGVPdmVycmlkZGVuUGFydHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zTG9uZ0ZsYXNoT25PZmYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSm9pbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NUaHJvdWdoRGlhbGluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NTaG9ydEZsYXNoT25PZmYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRGlzY1RhbGtpbmdPZk91dGdvaW5nQ2FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40MSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NFbWVyZ2VuY3lQYWdpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zSW5kaXZpZHVhbFRydW5rIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc1ByaXZhY3lPdmVycmlkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NEaXJlY3RlZERuUGlja3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zRGlzYVNlY3VyaXR5Q29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNvc0NvUmV0cmlldmVQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zVGFuZGVtQ29ubmVjdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb3NVQ0RBZ2VudExvZ2luTG9jYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29zVUNEQWdlbnRMb2dpblJlbW90ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40NyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMyIsIm5hbWUiOiJDbGFzc09mU2VydmljZSIsIm51bWJlciI6IjEwMyJ9LCIxMDRTeXN0ZW1UaW1lciI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzAiLCJuYW1lIjoic3lzdGVtVGltZXJUYWxraW5nT3V0cHV0VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjAiLCJuYW1lIjoic3lzdGVtVGltZXJEaWFsSW5wdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNDAiLCJuYW1lIjoic3lzdGVtVGltZXJQYWdpbmdBdXRvRGlzY1RpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjUuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckFjYk92ZXJhbGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckRlbGF5ZWQxUmluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckRlbGF5ZWQyUmluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1UaW1lckRpYWxTZW5kVGltZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMjAuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lck5ldHdvcmtEU1NSZWZyZXNoVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4yMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiNS4uMTgwIiwibmFtZSI6InN5c3RlbVRpbWVyQWNiIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMTAuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lckVtZXJnZW5jeUNhbGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjAiLCJuYW1lIjoic3lzdGVtVGltZXJBdXRvRGlzY1RpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYwMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckxvc3RDYWxsVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNC4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzAiLCJuYW1lIjoic3lzdGVtVGltZXJVbmxvY2tpbmdUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEwLi42MDAiLCJuYW1lIjoic3lzdGVtVGltZXJQYXJrIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTgwIiwibmFtZSI6InN5c3RlbVRpbWVyU21kciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE4MCIsIm5hbWUiOiJzeXN0ZW1UaW1lclVzZXJJbnB1dFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiNjAuLjE4MDAiLCJuYW1lIjoic3lzdGVtVGltZXJPdXRnb2luZ0NhbGxUYWxrRGlzY1RpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMwMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckFuc3dlcldhaXRUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckRpYWxlZDkxMUp1ZGdtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjUuLjE1IiwibmFtZSI6InN5c3RlbVRpbWVyQ2FtcG9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtVGltZXJQcmVzZXRQYXVzZVRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMjAiLCJuYW1lIjoic3lzdGVtVGltZXJPdXRnb2luZ051bWJlckRpc3BsYXlUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjI0Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoic3lzdGVtVGltZXJTeXN0ZW1DYWxsRm9yd2FyZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM2MDAiLCJuYW1lIjoic3lzdGVtVGltZXJVc2VySW5wdXREdXJhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYwMCIsIm5hbWUiOiJzeXN0ZW1UaW1lckxvc3RDYWxsRmluYWxUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMDAiLCJuYW1lIjoic3lzdGVtVGltZXJDYWxsZXJJZERpc3BsYXlUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjI2Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDQiLCJuYW1lIjoiU3lzdGVtVGltZXIiLCJudW1iZXIiOiIxMDQifSwiMTA1U3lzdGVtRGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUU5MTFTZXJ2aWNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFQcmVmaXgxSW5DYWxsSGlzdG9yeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUROSVNvckNhbGxlcklERGlzcGxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVRST3ZlcnJpZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUp1bXBpbmdMZWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFNYW55TWVtYmVyQ29uZmVyZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVBsYXlNZWxvZHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFEaXNwbGF5Q2hlY2tTdW1FcnJvciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoic3lzdGVtRGF0YVNlY29uZGFyeUNsb2NrU291cmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFEcE1ha2VSYXRpbyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN5c3RlbURhdGFTZXJ2aWNlQ29kZUNyZWRpdENhcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhTXVzaWNPbkhvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUludGVybmFsUGFkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6InN5c3RlbURhdGFDb3NPdmVycmlkZUNvZGVEaWdpdHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoic3lzdGVtRGF0YUV4dGVybmFsUGFnaW5nWm9uZU51bSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhRGVmYXVsdENhbGxpbmdOdW1iZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQ0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN5c3RlbURhdGFMb3N0Q2FsbERlc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4xNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoic3lzdGVtRGF0YURvbWVzdGljQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjI3Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhU2VsZWN0TWVsb2R5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzeXN0ZW1EYXRhTWluRGlhbERpZ2l0c0NyZWRpdENhcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQXBwZW5kZWRCY2hJbnRvQ3N0YURldklkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhU3BpZE9wZXJhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUNhbGxlZEluZGljYXRpb25PZkRzc0JsZiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQ1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVJpbmdpbmdDYWRlbmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQ2hhbmdlQUxhd011TGF3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQ29udmVydEhvb2tpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFBcHBlbmRlZFNlbmRpbmdDb21wbGV0ZUlFIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoic3lzdGVtRGF0YU5ldHdvcmtpbmdUcmFuc2l0Q291bnRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjIwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhUmVjSW5jb21wbGV0ZU91dGdvaW5nRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoic3lzdGVtRGF0YUU5MTFTZW5kaW5nRGlnaXRzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFSaW5naW5nVHJhbnNmZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YVByaXZhY3lPdmVycmlkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhVHJhbnNmZXJQcml2YWN5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoic3lzdGVtRGF0YU5pZ2h0UmVsYXlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUNhc2NhZGluZ1N5c3RlbUNGIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJzeXN0ZW1EYXRhSW50ZXJuYXRpb25hbENvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtRGF0YUV4ZWN1dGl2ZU92ZXJyaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFDTElERm9yVHJhbnNmZXJDYWxsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQW5hbG9nRElEIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhVGFuZGVtVGFsa0NvbnRpbnVlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhQXV0b1N0YXRpb25SZWxlYXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJzeXN0ZW1EYXRhUHJpbWFyeUNsb2NrU291cmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFBbmFsb2dUcnVua0h1bnRpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoic3lzdGVtRGF0YU5pZ2h0QmVsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhTnVtYmVyaW5nUGxhbklkT25DUE4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFDYWxsZXJOdW1iZXJEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1EYXRhVHlwZU9mTnVtYmVyT25DYWxsaW5nUGFydHlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS40NyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbURhdGFOdW1iZXJpbmdQbGFuSWRPbkNhbGxpbmdQYXJ0eU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQ4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjQiLCJuYW1lIjoic3lzdGVtRGF0YUxDREtleXN0cmlwUmVmcmVzaEludGVydmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi44IiwibmFtZSI6InN5c3RlbURhdGFDYWxsSGlzdG9yeVJlY2FsbFByZWZpeCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjUxIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNCIsIm5hbWUiOiJzeXN0ZW1EYXRhU25tcElwQWRkcmVzc1dpbGRjYXJkQml0TGVuZ3RoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InN5c3RlbURhdGFDYXJyaWVyQmFzZWRWTVdJQ29Qb3NpdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjUzIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUiLCJuYW1lIjoiU3lzdGVtRGF0YSIsIm51bWJlciI6IjEwNSJ9LCIxMDZEYXlOaWdodE1vZGVQcml2YXRlRGF5Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5RnJpZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDYuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlNb25kYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVN1bmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2LjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5VHVlc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwcml2YXRlRGF5U2F0dXJkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicHJpdmF0ZURheVRodXJzZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDYuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVEYXlXZWRuZXNkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2IiwibmFtZSI6IkRheU5pZ2h0TW9kZVByaXZhdGVEYXkiLCJudW1iZXIiOiIxMDYifSwiMTA3UGFkVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uMyIsIm5hbWUiOiJwYWRSZWNlaXZlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA3LjEuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwYWRWYWx1ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA3LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi4zIiwibmFtZSI6InBhZFNlbmRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA3LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDciLCJuYW1lIjoiUGFkVGFibGUiLCJudW1iZXIiOiIxMDcifSwiMTA4UGFkR3JvdXAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InBhZEdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJwYWRHcm91cERldmljZVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA4IiwibmFtZSI6IlBhZEdyb3VwIiwibnVtYmVyIjoiMTA4In0sIjEwOUV4dGVybmFsTXVzaWNPbkhvbGQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxNdXNpY09uSG9sZDEyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS4xOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsTXVzaWNPbkhvbGQxNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxNdXNpY09uSG9sZDE1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkOEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZXh0ZXJuYWxNdXNpY09uSG9sZDlFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjEwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTBFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjEyIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTFFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE0Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTJFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE2Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTNFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjE4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTRFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjIwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJleHRlcm5hbE11c2ljT25Ib2xkMTVFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjIyIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkiLCJuYW1lIjoiRXh0ZXJuYWxNdXNpY09uSG9sZCIsIm51bWJlciI6IjEwOSJ9LCIxMTBQYXNzV29yZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoicGFzc3dvcmRMZXZlbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMC4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEwIiwibmFtZSI6IlBhc3NXb3JkIiwibnVtYmVyIjoiMTEwIn0sIjExMURSTCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZHJsQ3JlZGl0Q2FyZENhbGxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMS4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJkcmxEcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMS4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTExIiwibmFtZSI6IkRSTCIsIm51bWJlciI6IjExMSJ9LCIxMTJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InByaXZhdGVDYWxlbmRhckRheU1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMi4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiOCIsIm5hbWUiOiJwcml2YXRlQ2FsZW5kYXJEYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMi4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMiIsIm5hbWUiOiJEYXlOaWdodE1vZGVQcml2YXRlQ2FsZW5kYXIiLCJudW1iZXIiOiIxMTIifSwiMTEzRGF5TmlnaHRNb2RlU2NoZWR1bGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVOb25Xb3JraW5nRGF5RGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEzLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlTm9uV29ya2luZ0RheURheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMy41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVByaXZhdGVIb2xpZGF5RGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEzLjciLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlUHJpdmF0ZUhvbGlkYXlEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTMuOCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVOb25Xb3JraW5nRGF5TmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMy42Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVByaXZhdGVIb2xpZGF5TmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMy45Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoidHlwZVdvcmtpbmdEYXlEYXkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6InR5cGVXb3JraW5nRGF5RGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTEzLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJ0eXBlV29ya2luZ0RheU5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMyIsIm5hbWUiOiJEYXlOaWdodE1vZGVTY2hlZHVsZSIsIm51bWJlciI6IjExMyJ9LCIxMTRQYWRDb25mZXJlbmNlVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBhZENvbmZWYWx1ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoicGFkQ29uZlRydW5rcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJwYWRDb25mVGVsZXBob25lcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE0LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTQiLCJuYW1lIjoiUGFkQ29uZmVyZW5jZVRhYmxlIiwibnVtYmVyIjoiMTE0In0sIjExNUFkdmlzb3J5TWVzc2FnZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjAuLjkiLCJuYW1lIjoiYWR2aXNvcnlNZXNzYWdlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTUuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJhZHZpc29yeU1lc3NhZ2VDaGFyYWN0ZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExNS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYWR2aXNvcnlNZXNzYWdlQWRkRGlnaXRzVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE1LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE1IiwibmFtZSI6IkFkdmlzb3J5TWVzc2FnZSIsIm51bWJlciI6IjExNSJ9LCIxMTZEYXRhSW5pdGlhbGl6ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMTAwLi45OTkiLCJuYW1lIjoiZGF0YUluaXRDb21tYW5kTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExNi4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTYiLCJuYW1lIjoiRGF0YUluaXRpYWxpemUiLCJudW1iZXIiOiIxMTYifSwiMTE3UHVibGljTnVtYmVyaW5nUGxhbkFuYWx5emVkRGlnaXRzIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJwdWJsaWNOdW1iZXJpbmdQbGFuQW5hbHl6ZWREaWdpdHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExNy4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi43IiwibmFtZSI6InB1YmxpY051bWJlcmluZ1BsYW5BbmFseXplZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE3LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTciLCJuYW1lIjoiUHVibGljTnVtYmVyaW5nUGxhbkFuYWx5emVkRGlnaXRzIiwibnVtYmVyIjoiMTE3In0sIjExOExvY2tQYXNzd29yZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImxvY2tQYXNzd29yZE1hc3RlcklkQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE4LjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExOCIsIm5hbWUiOiJMb2NrUGFzc3dvcmQiLCJudW1iZXIiOiIxMTgifSwiMTE5SW5pdGlhbGl6ZUxvY2tQYXNzd29yZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF0YUluaXRpYWxpemVMb2NrUGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExOS4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE5IiwibmFtZSI6IkluaXRpYWxpemVMb2NrUGFzc3dvcmQiLCJudW1iZXIiOiIxMTkifSwiMTIwVGVuYW50RGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InRlbmFudERhdGFEYXkxT3BlQ2FsbERlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJ0ZW5hbnREYXRhRGF5Mk9wZUNhbGxEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIwLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJ0ZW5hbnREYXRhVGVuYW50TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJ0ZW5hbnREYXRhTmlnaHRPcGVDYWxsRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMC4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVuYW50RGF0YURheTFPcGVDYWxsRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZW5hbnREYXRhRGF5Mk9wZUNhbGxEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoidGVuYW50RGF0YU5pZ2h0UmVsYXlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMC4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVuYW50RGF0YU5pZ2h0T3BlQ2FsbERlc3RpbmF0aW9uVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIwLjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJ0ZW5hbnREYXRhTmlnaHRCZWxsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMCIsIm5hbWUiOiJUZW5hbnREYXRhIiwibnVtYmVyIjoiMTIwIn0sIjEyMUF1dG9tYXRpY0RheWxpZ2h0U2F2aW5nQ2hhbmdlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMiIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ1dlZWtNb2RlRW5kTW9udGgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ0VuZFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4xMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImRheWxpZ2h0U2F2aW5nRGF0ZU1vZGVTdGFydERhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS45Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdXZWVrTW9kZVN0YXJ0TW9udGgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ1NoaWZ0VGltZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjEzIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdTdGFydFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4xMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRheWxpZ2h0U2F2aW5nV2Vla01vZGVFbmREYXlPZldlZWsiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdXZWVrTW9kZUVuZE51bU9mV2VlayIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkYXlsaWdodFNhdmluZ1dlZWtNb2RlU3RhcnREYXlPZldlZWsiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF5bGlnaHRTYXZpbmdXZWVrTW9kZVN0YXJ0TnVtT2ZXZWVrIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRheWxpZ2h0U2F2aW5nQXZhaWxhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjEuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRheWxpZ2h0U2F2aW5nTW9kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJkYXlsaWdodFNhdmluZ0RhdGVNb2RlRW5kRGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjEwIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxIiwibmFtZSI6IkF1dG9tYXRpY0RheWxpZ2h0U2F2aW5nQ2hhbmdlIiwibnVtYmVyIjoiMTIxIn0sIjE1MFN5c3RlbUlQRGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBUb3NGaWVsZFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBUZXJtaW5hbEF1dGhlbnRpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwVG9zUHJlY2VkZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcFN0YXRpb25JREF1dG9Bc3NpZ25tZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwVG9zVGhyb3VnaHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42MyIsIm5hbWUiOiJzeXN0ZW1JcERzY3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcFRvc1JlbGlhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwR2FpbkNvbnRyb2xNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzeXN0ZW1JcElQQ1RYSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBJRUVFODAyMXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwVG9zRGVsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBEaWZmc2VydiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcENFRENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwRWNob0NhbmNlbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBJRUVFODAyMXBEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1JcElwUXNpZ0JNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi41IiwibmFtZSI6InN5c3RlbUlwRmF4TWF4SG9wIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwRWNob0NhbmNlbEZvck1JUFUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwU0lQVHJ1bmtEaWZmc2VydiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua1Rvc0ZpZWxkVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua1Rvc1ByZWNlZGVuY2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwU0lQVHJ1bmtUb3NEZWxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua1Rvc1Rocm91Z2hwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUlwU0lQVHJ1bmtUb3NSZWxpYWJpbGl0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjMiLCJuYW1lIjoic3lzdGVtSXBTSVBUcnVua0RzY3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yOSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwIiwibmFtZSI6IlN5c3RlbUlQRGF0YSIsIm51bWJlciI6IjE1MCJ9LCIxNTFCSVBVQ29uZml1cmF0aW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJpcHVEZWZhdWx0R1dBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEuMS4xLjQiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiaXB1SXBBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEuMS4xLjIiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoiYmlwdVZlcnNpb25OdW1iZXJEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmlwdVN1Yk5ldEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MS4xLjEuMyIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjQiLCJuYW1lIjoiYmlwdUNhcmRTbG90RXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MS4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjE2Mzg0Li42NTUwNCIsIm5hbWUiOiJiaXB1TWVkaWFDaGFubmVsQmFzZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUxLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTEiLCJuYW1lIjoiQklQVUNvbmZpdXJhdGlvbiIsIm51bWJlciI6IjE1MSJ9LCIxNTJWb2ljZVBhY2tldENvbmZpZ3VyYXRpb25UYWJsZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJ2b2ljZVRibE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2b2ljZVRibFBhY2tldFRyYW5zbWlzc2lvbkludGVydmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlclR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1MCIsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlckxlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUyLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJ2b2ljZVRibFBhY2tldExvc3NUaHJlc2hvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm9pY2VUYmxQYWNrZXRUcmFuc21pc3Npb25JbnRlcnZhbEZvck1JUFUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlclR5cGVGb3JNSVBVIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIwMCIsIm5hbWUiOiJ2b2ljZVRibEppdHRlckJ1ZmZlckxlbmd0aEZvck1JUFUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJ2b2ljZVRibFBhY2tldExvc3NUaHJlc2hvbGRGb3JNSVBVIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIuMS4xLjE0Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIiLCJuYW1lIjoiVm9pY2VQYWNrZXRDb25maWd1cmF0aW9uVGFibGUiLCJudW1iZXIiOiIxNTIifSwiMTUzVm9pY2VQcm9jZXNzb3JDb250cm9sVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMyIsIm5hbWUiOiJ2cFZnY0lucHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJ2cEFkYXB0YXRpb25EdXJhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTMiLCJuYW1lIjoidnBWZ2NPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1My4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEzIiwibmFtZSI6InZwQ2djRGVjb2RlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMyIsIm5hbWUiOiJ2cENnY0VuY29kZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1My4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidnBBZGFwdGF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJ2cERldmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6InZwTmxwVGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZwQ29tZm9ydE5vaXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2cE5scCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidnBCeXBhc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1My4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MyIsIm5hbWUiOiJWb2ljZVByb2Nlc3NvckNvbnRyb2xUYWJsZSIsIm51bWJlciI6IjE1MyJ9LCIxNjFMSVBVQ29uZml1cmF0aW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVEZWZhdWx0R1dBZGRyZXNzMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS40Iiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdURlZmF1bHRHV0FkZHJlc3MyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjciLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1SXBBZGRyZXNzMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4yIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdUlwQWRkcmVzczIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuNSIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6OCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJsaXB1VmVyc2lvbk51bWJlckRpc3BsYXkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImxpcHVWZXJzaW9uTnVtYmVyRGlzcGxheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiI0IiwibmFtZSI6ImxpcHVDYXJkU2xvdEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaXB1SWRsZUlQUG9ydE51bWJlckRpc3BsYXkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJsaXB1SWRsZUlQUG9ydE51bWJlckRpc3BsYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVTdWJOZXRBZGRyZXNzMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4zIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdVN1Yk5ldEFkZHJlc3MyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjYiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXAxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXBEYXRhMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1SUVFRTgwMjFxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40MDk0IiwibmFtZSI6ImxpcHVJRUVFODAyMXFEYXRhMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXAyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVJRUVFODAyMXBEYXRhMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1SUVFRTgwMjFxMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40MDk0IiwibmFtZSI6ImxpcHVJRUVFODAyMXFEYXRhMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjE2Mzg0Li42NTUwNCIsIm5hbWUiOiJsaXB1TWVkaWFDaGFubmVsQmFzZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxNjM4NC4uNjU1MDQiLCJuYW1lIjoibGlwdU1lZGlhQ2hhbm5lbEJhc2UyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdURIQ1AxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdUROU1NlcnZlclByaW1hcnkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjIzIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVETlNTZXJ2ZXJTZWNvbmRhcnkxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjI0Iiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoibGlwdUhvc3ROYW1lMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4yNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaXB1UHJpbWFyeUROU1N1ZmZpeDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1REhDUDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1RE5TU2VydmVyUHJpbWFyeTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjgiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdUROU1NlcnZlclNlY29uZGFyeTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjkiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaXB1SG9zdE5hbWUyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjMwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImxpcHVQcmltYXJ5RE5TU3VmZml4MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4zMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxIiwibmFtZSI6IkxJUFVDb25maXVyYXRpb24iLCJudW1iZXIiOiIxNjEifSwiMTYzTElQVVZvaWNlUHJvY2Vzc29yQ29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGlwdVZwQnlwYXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNyIsIm5hbWUiOiJsaXB1VnBJcHRNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNiIsIm5hbWUiOiJsaXB1VnBSZWxhdGl2ZVRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdVZwRG91YmxlVGFsa0hhbmd0aW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTMiLCJuYW1lIjoibGlwdVZwVmdjSW5wdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVWcEFic29sdXRlVGhyZXNob2xkMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdVZwQWJzb2x1dGVUaHJlc2hvbGQyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MCIsIm5hbWUiOiJsaXB1VnBBZGFwdGF0aW9uRHVyYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEzIiwibmFtZSI6ImxpcHVWcFZnY091dHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTMiLCJuYW1lIjoibGlwdVZwQ2djRGVjb2RlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMyIsIm5hbWUiOiJsaXB1VnBDZ2NFbmNvZGVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVWcEFkYXB0YXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4zMjAiLCJuYW1lIjoibGlwdVZwRGV2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVWcEJldGFNYW50aXNzYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdVZwQmV0YUV4cG9uZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVWcE5scFRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaXB1VnBDb21mb3J0Tm9pc2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxpcHVWcE5scCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzIiwibmFtZSI6IkxJUFVWb2ljZVByb2Nlc3NvckNvbnRyb2wiLCJudW1iZXIiOiIxNjMifSwiMTY0RnVsbElwUXNpZ0RUTUZEZXRlY3Rpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RXaWRlYmFuZFRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RBYnNvbHV0ZVRocmVzaG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RTbnJMaW1pdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RIb2xkT2ZmTGltaXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NC43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42IiwibmFtZSI6ImxpcHVEdG1mRGV0ZWN0Rm9yd2FyZFR3aXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjQuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNiIsIm5hbWUiOiJsaXB1RHRtZkRldGVjdFJldmVyc2VUd2lzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0LjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYiLCJuYW1lIjoibGlwdUR0bWZEZXRlY3RGbGF0bmVzc0xpbWl0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjQuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNiIsIm5hbWUiOiJsaXB1RHRtZkRldGVjdEFkZGl0aW9uYWxUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjQuOCIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY0IiwibmFtZSI6IkZ1bGxJcFFzaWdEVE1GRGV0ZWN0aW9uIiwibnVtYmVyIjoiMTY0In0sIjE2NUZheE92ZXJJcFN5c3RlbURhdGFBc3NpZ25tZW50Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zNCIsIm5hbWUiOiJmYXhPdmVySXBTeXN0ZW1DbmdEZXRlY3RUaHJlc2hvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMDAiLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ25nQmFuZFJhdGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTciLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ2VkRGV0ZWN0VGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ2VkTWFyZ2luVGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiZmF4T3ZlcklwU3lzdGVtQ2VkRmxhdG5lc3NUaHJlc2hvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJmYXhPdmVySXBTeXN0ZW1DZWRSZWxlYXNlVGhyZXNob2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjUuNiIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY1IiwibmFtZSI6IkZheE92ZXJJcFN5c3RlbURhdGFBc3NpZ25tZW50IiwibnVtYmVyIjoiMTY1In0sIjE2NkZheE92ZXJJcFBhcmFtZXRlclRhYmxlQXNzaWdubWVudCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJmYXhPdmVySXBUYmxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZmF4T3ZlcklwVGJsU2xvd0RhdGFSZWR1bmRhbmN5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJmYXhPdmVySXBUYmxGYXN0RGF0YVJlZHVuZGFuY3kiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMiLCJuYW1lIjoiZmF4T3ZlcklwVGJsU2xvd0RhdGFGZWNOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMyIsIm5hbWUiOiJmYXhPdmVySXBUYmxGYXN0RGF0YUZlY051bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY2LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJmYXhPdmVySXBUYmxEYXRhZ3JhbVNpemUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImZheE92ZXJJcFRibE1heFJhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NiIsIm5hbWUiOiJGYXhPdmVySXBQYXJhbWV0ZXJUYWJsZUFzc2lnbm1lbnQiLCJudW1iZXIiOiIxNjYifSwiMjAwU3RhdGlvbkFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMCIsIm5hbWUiOiJzdGF0aW9uU3RhdGlvblNwZWVkRGlhbE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS40NCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25NV1dpdGhEaWFsaW5nIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjUwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvbkRybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvbkZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoic3RhdGlvbkNvcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvblFwbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uQ0VTSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uRGlhbGluZ0RpZ2l0UmVzdHJpY3Rpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkhvbGRJbmRpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQ4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uT3JpZ2luYXRpbmdPY2EiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJzdGF0aW9uRW1lcmdlbmN5R3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJzdGF0aW9uUmVtb3RlUGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40OCIsIm5hbWUiOiJzdGF0aW9uSW5kZXhDYWxsRm93YXJkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblRyYXZlbENvZGVDaGFuZ2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkN3dFJvYiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6InN0YXRpb25UZW5hbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InN0YXRpb25EcmxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQXV0b0NhbXBvbmFzRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJzdGF0aW9uRnJsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoic3RhdGlvbkNvc0RheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InN0YXRpb25RcGxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjE2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkJlYXJDYXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblNMVFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblBlcnNvbmFsQWRtaW5TZWN1cml0eUxldmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InN0YXRpb25EcmxOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkV4dGVuc2lvblBvcnRUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvbkZybE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzdGF0aW9uQ29zTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25SZWdTeXN0ZW1TcGVlZERpYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvblFwbE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblNlbmRlcml6ZWRNb2RlVG9uZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4yMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjI0Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkNhbGxGb3J3YXJkRGlhbFRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblJlbGVhc2VTdXBlcnZpc2lvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6InN0YXRpb25FcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQ2FsbFBpY2t1cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJzdGF0aW9uQ2VudGVyUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6InN0YXRpb25OZXR3b3JrQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblJlY2FsbEFmdGVyQ0hvbGRBbmRPTkgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6InN0YXRpb25Wb2ljZU1haWxJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4yOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25UR0FDT3ZlclJpZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbk5hbWVEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjM2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uU3RhdGlvbk5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMTgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uRG9vclBob25lRE5EIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25TdHV0dGVyZWREaWFsVG9uZVNlbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic3RhdGlvblN0YXRpb25MY3JHcm91cE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uUGVyc29uYWxBZG1pblBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU2Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoic3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uT3JnSW52b2tlT2NhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25TZXJ2aWNlVG9uZVBlcm1pc3Npb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN0YXRpb25EZWZhdWx0Q2FsbGluZ051bWJlcklkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU1Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblBETkNvZGVEaWdpdHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvblNMVEZTS01vZGVtU2lnbmFsVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41OCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uU0xUT2ZmSG9va0NPUHJlZmVyZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41OSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NDAiLCJuYW1lIjoic3RhdGlvblNMVENPUHJlZmVyZW5jZVRydW5rT3JPbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNjAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQ2FsbGluZ05hbWVUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjYxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25TeXN0ZW1TcGVlZERpYWxTdXBwbGVtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjYyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25BbmFsb2dTdGF0aW9uRGlzY29ubmVjdFNpZ25hbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS42MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uQ2FsbFdhaXRpbmdTd2FwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjY0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwIiwibmFtZSI6IlN0YXRpb25Bc3NpZ24iLCJudW1iZXIiOiIyMDAifSwiMjAxU3RhdGlvbkRlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiZGVsZXRlU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAxIiwibmFtZSI6IlN0YXRpb25EZWxldGUiLCJudW1iZXIiOiIyMDEifSwiMjAySVNETlN0YXRpb25Bc3NpZ25tZW50Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjI5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25DRVNJRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4yOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25EaWFsaW5nRGlnaXRSZXN0cmljdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40NiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uT3JpZ2luYXRpbmdPY2EiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNDIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkxjckdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkNoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVm9pY2VDYWxsTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25TeXN0ZW1DYWxsRm9yd2FyZERpYWxUb25lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQ1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25TcGVlY2giLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25JbnRlcmRpZ2l0MVRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25JbnRlcmRpZ2l0MlRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVGVuYW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQ4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRHJsRGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkRybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQXV0b0NhbXBvbmFzRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40OSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRnJsRGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25GcmxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQ29zRGF5MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQ29zRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvblFwbERheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uUXBsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4xNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkNvbm5lY3Rpb25Gb3JtYXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRHJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRnJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25Db3NOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvblJlZ1N5c3RlbVNwZWVkRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uUXBsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMTgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQmNoU2VsZWN0ZWRPcmlnaW5hdGluZ01ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4yNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25Qcm90b2NvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb243a0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbjMxa0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbk5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMzQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVEdBQ092ZXJSaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25TdHV0dGVyZWREaWFsVG9uZVNlbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNDciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uVW5yZXN0NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25VbnJlc3Q1NmticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbk9yZ0ludm9rZU9jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uU2VydmljZVRvbmVQZXJtaXNzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25JZGxlQmNoU2VsZWN0aW9uTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uRGVmYXVsdENhbGxpbmdOdW1iZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS41MSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25QRE5Db2RlRGlnaXRzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjUwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMCIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uU3RhdGlvblNwZWVkRGlhbE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40NCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25BZGRpdGlvbmFsRG4yIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjM1Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkFkZGl0aW9uYWxEbjMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMzYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQWRkaXRpb25hbERuNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4zNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25BZGRpdGlvbmFsRG41Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjM4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvbkFkZGl0aW9uYWxEbjYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMzkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpc2RuQmFzaWNTdGF0aW9uQWRkaXRpb25hbERuNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40MCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5CYXNpY1N0YXRpb25BZGRpdGlvbmFsRG44Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQxIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljU3RhdGlvblVucmVzdDJ4NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyIiwibmFtZSI6IklTRE5TdGF0aW9uQXNzaWdubWVudCIsIm51bWJlciI6IjIwMiJ9LCIyMDNETkNoYW5nZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiY2hhbmdlTmV3RE4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMy4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImNoYW5nZUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDMuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMyIsIm5hbWUiOiJETkNoYW5nZSIsIm51bWJlciI6IjIwMyJ9LCIyMDRES1REYXRhIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YURUTUYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVNwZWFrZXJDd3RSb2IiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUFkbWluaXN0cmF0b3JUZWxlcGhvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUJsaW5kVHJhbnNmZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVR5cGVPZlJpbmdpbmdQcmVmZXJlbmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFFeGNsdXNpdmVIb2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdE1pY3JvcGhvbmVJbml0aWFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFQcm9ncmFtbWluZ01vZGVTZWN1cml0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhVGV4dE1zZ0Rpc3BsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUhhbmRzRnJlZVNwbGFzaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhQ3JpdGVyaW9uT2ZCdXN5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFCUENJQkFUSSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhVHJ1bmtUZXN0VmVyaWZ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFSb2JSZXB0aXRpb25UaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YU9jYVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhU3RvcFNlbmRpbmdMQ0RJbmZvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFMQ0REaXNwbGF5TGFuZ3VhZ2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVJpbmdpbmdQcmVmZXJlbmNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdEF1dG9MaW5lSG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTWFpbEJveFNlbGVjdE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI0IiwibmFtZSI6ImRrdERhdGFLZXlOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUtleVBhdGVybiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVRvbmVGaXJzdFZvaWNlRmlyc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3RNaWNyb3Bob25lVXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFUeXBlT2ZJZGxlUHJlZmVyZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjksImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGt0RGF0YU92ZXJmbG93RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFBZGRPbk1vZHVsZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YVN0YXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUhhbmRzRnJlZU1pYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhRXh0ZXJuYWxSaW5naW5nUmVwZWF0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMCIsIm5hbWUiOiJka3REYXRhQ2FsbEhpc3RvcnlNZW1vcnlTaXplIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZGt0RGF0YURuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTm9SaW5nTm9GbGFzaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhRGlhbERpcmVjdG9yeVNwZWFrZXJTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhRGlhbERpcmVjdG9yeVNwZWFrZXJNYWtlQ2FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTGNkS2V5c3RyaXBLaW5kT2ZES1QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNDAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGt0RGF0YUxjZEtleXN0cmlwS2luZE9mQURNMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS40MSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJka3REYXRhTGNkS2V5c3RyaXBLaW5kT2ZBRE0yIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjQyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRrdERhdGFLZWVwU3RhdGlvbk5hbWVEaXNwbGF5QWZ0ZXJBbnN3ZXJDYWxsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0IiwibmFtZSI6IkRLVERhdGEiLCJudW1iZXIiOiIyMDQifSwiMjA1RmVhdHVyZUtleSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMiLCJuYW1lIjoiZmVhdHVyZUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNS4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIwIiwibmFtZSI6ImZlYXR1cmVLZXlObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJmZWF0dXJlUGFyYW1ldGVyNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA1LjEuMS44Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZmVhdHVyZURuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDUuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNSIsIm5hbWUiOiJGZWF0dXJlS2V5IiwibnVtYmVyIjoiMjA1In0sIjIwNlBoRE4iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGhETlBhcmFtZXRlclVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJwaEROUGFyYW1ldGVyRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBoRE5QYXJhbWV0ZXJUb25lRmlyc3RWb2ljZUZpcnN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjciLCJuYW1lIjoicGhETlBhcmFtZXRlckNlbnRlclBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuMTAiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJwaEROUGFyYW1ldGVyVm9pY2VNYWlsSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6InBoRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoicGhETlBhcmFtZXRlck93bmVyU2hpcERuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwaEROUGFyYW1ldGVyTmFtZURpc3BsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNi4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40OCIsIm5hbWUiOiJwaEROUGFyYW1ldGVyQ2FsbEZvcndhcmRJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA2LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDYiLCJuYW1lIjoiUGhETiIsIm51bWJlciI6IjIwNiJ9LCIyMDdTaW5nbGVUb3VjaEJ1dHRvbkRhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yODYwIiwibmFtZSI6InNpbmdsZVRvdWNoQnV0dG9uRmtObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA3LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoic2luZ2xlVG91Y2hCdXR0b25SZWdpc3RyYXRpb25EYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDcuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzaW5nbGVUb3VjaEJ1dHRvblByaW1lRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNy4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA3IiwibmFtZSI6IlNpbmdsZVRvdWNoQnV0dG9uRGF0YSIsIm51bWJlciI6IjIwNyJ9LCIyMDhTdGF0aW9uVGltZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uVGltZXJEbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA4LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi42MDAiLCJuYW1lIjoic3RhdGlvblRpbWVyTm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA4LjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi4yMCIsIm5hbWUiOiJzdGF0aW9uVGltZXJBYnJSZXRyeUNvdW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjUuLjYwIiwibmFtZSI6InN0YXRpb25UaW1lckFiclJlY2FsbFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJzdGF0aW9uVGltZXJIb2xkUmVjYWxsVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6InN0YXRpb25UaW1lckludGVyZGlnaXQxVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTgwIiwibmFtZSI6InN0YXRpb25UaW1lckludGVyZGlnaXQyVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMzAuLjE4MCIsIm5hbWUiOiJzdGF0aW9uVGltZXJBYnJJbnRlcnZhbFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6InN0YXRpb25UaW1lclZtd2lTZW5kaW5nVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyMCIsIm5hbWUiOiJzdGF0aW9uVGltZXJBbmFsb2dTdGF0aW9uRGlzY29ubmVjdFNpZ25hbFRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDguMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDgiLCJuYW1lIjoiU3RhdGlvblRpbWVyIiwibnVtYmVyIjoiMjA4In0sIjIwOVN0YXRpb25IdW50aW5nIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSHVudERpc3BsYXlETiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uSHVudENGIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSHVudFBpbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25IdW50VUNEIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTEwMCIsIm5hbWUiOiJzdGF0aW9uSHVudEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbkh1bnRVQ0RNdXNpY09uSG9sZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25IdW50QXV0b21hdGljQ2FtcG9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAiLCJuYW1lIjoic3RhdGlvbkh1bnRVQ0RSZXNwb25zZVRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzYwMCIsIm5hbWUiOiJzdGF0aW9uSHVudFVDRE92ZXJmbG93VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOS4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ4IiwibmFtZSI6InN0YXRpb25IdW50Q2FsbEZvcndhcmRJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uSHVudE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5IiwibmFtZSI6IlN0YXRpb25IdW50aW5nIiwibnVtYmVyIjoiMjA5In0sIjIxMFBpY2tVcEdycCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImNhbGxQaWNrdXBHcm91cERuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYWxsUGlja3VwR3JvdXBQaWNrdXA5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDExIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDEzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDE5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDIzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDI5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDMzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjM5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDM5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxQaWNrdXBHcm91cFBpY2t1cDQ4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjQ5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwIiwibmFtZSI6IlBpY2tVcEdycCIsIm51bWJlciI6IjIxMCJ9LCIyMTFTdGF0aW9uSHVudGluZ0dyb3VwRGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMTAwIiwibmFtZSI6ImRlbGV0ZVN0YXRpb25IdW50aW5nR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTEiLCJuYW1lIjoiU3RhdGlvbkh1bnRpbmdHcm91cERlbGV0ZSIsIm51bWJlciI6IjIxMSJ9LCIyMTNBZGRPbk1vZHVsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoiYWRkT25Ebk1vZHVsZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEzLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJhZGRPblBhcmFtZXRlcjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMy4xLjEuNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiYWRkT25QYXJhbWV0ZXIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTMuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImFkZE9uUGFyYW1ldGVyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEzLjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJhZGRPblBhcmFtZXRlcjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMy4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiYWRkT25QYXJhbWV0ZXI1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTMuMS4xLjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zIiwibmFtZSI6ImFkZE9uRmVhdHVyZUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMy4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIwIiwibmFtZSI6ImFkZE9uRmVhdHVyZUtleU5vIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTMuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMyIsIm5hbWUiOiJBZGRPbk1vZHVsIiwibnVtYmVyIjoiMjEzIn0sIjIxNERTUyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImRzc1N0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE0LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3MxRXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNC4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZHNzMkVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTQuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6ImRzczNFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE0LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3M0RXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNC4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZHNzNUVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTQuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6ImRzczZFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE0LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3M3RXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNC4xLjEuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiZHNzOEVxdWlwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTQuMS4xLjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNCIsIm5hbWUiOiJEU1MiLCJudW1iZXIiOiIyMTQifSwiMjE1RFNTa2V5Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkc3NGZWF0dXJlUGFyYW1ldGVyNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS44Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMyIsIm5hbWUiOiJkc3NGZWF0dXJlQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1LjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNjAiLCJuYW1lIjoiZHNzRmVhdHVyZUtleU5vIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTUuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJkc3NOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNS4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE1IiwibmFtZSI6IkRTU2tleSIsIm51bWJlciI6IjIxNSJ9LCIyMTZFbWVyZ2VuY3lSaW5nRG93biI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiZW1nUmluZ0Rvd25EZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE2LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZW1nUmluZ0Rvd25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE2LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJlbWdSaW5nRG93bkFwcGxpY2FiaWxpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNi4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYwIiwibmFtZSI6ImVtZ1JpbmdEb3duVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNi4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE2IiwibmFtZSI6IkVtZXJnZW5jeVJpbmdEb3duIiwibnVtYmVyIjoiMjE2In0sIjIxN0lTRE5pbmRpdmlkdWFsU3RhdGlvbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblN0YXRpb25TZW5kZXJpemVkTW9kZVRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlzZG5TdGF0aW9uRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5TdGF0aW9uQ2hhbmdlQ09TT3ZlcnJpZGVDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImlzZG5TdGF0aW9uVm9pY2VNYWlsSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuMTAiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuU3RhdGlvbkNQTklFQ29udGVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE3LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuU3RhdGlvbk5hbWVEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImlzZG5TdGF0aW9uU3RhdGlvbk5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblN0YXRpb25Eb29yUGhvbmVETkQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpc2RuU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjgiLCJuYW1lIjoiaXNkblN0YXRpb25FbWVyZ2VuY3lHcm91cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE3LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJpc2RuU3RhdGlvblJlbW90ZVBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ4IiwibmFtZSI6ImlzZG5TdGF0aW9uSW5kZXhDYWxsRm93YXJkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNyIsIm5hbWUiOiJJU0ROaW5kaXZpZHVhbFN0YXRpb24iLCJudW1iZXIiOiIyMTcifSwiMjE4U3RhdGlvbkh1bnRpbmdHcm91cE1lbWJlciI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaHVudEdycE1lbWJlckRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTguMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMDAwIiwibmFtZSI6Imh1bnRHcnBNZW1iZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE4LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJodW50R3JwTWVtYmVyTW9kSW5zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTguMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTEwMCIsIm5hbWUiOiJodW50R3JwTWVtYmVyTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTguMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxOCIsIm5hbWUiOiJTdGF0aW9uSHVudGluZ0dyb3VwTWVtYmVyIiwibnVtYmVyIjoiMjE4In0sIjIxOU5ldHdvcmtEU1NOb3RpZnlEYXRhRGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJuZXR3b3JrRFNTbm90aWZ5Tm9kZUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTkuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE5IiwibmFtZSI6Ik5ldHdvcmtEU1NOb3RpZnlEYXRhRGVsZXRlIiwibnVtYmVyIjoiMjE5In0sIjIyMERLVEtleXN0cmlwTGFiZWwiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJka3RMY2RLZXlzdHJpcExhYmVsRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIyMC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6ImRrdExjZEtleXN0cmlwTGFiZWxEZXZpY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMjAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZGt0TGNkS2V5c3RyaXBMYWJlbEZrTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIyMC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyIiwibmFtZSI6ImRrdExjZEtleXN0cmlwTGFiZWxEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMjAuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIyMCIsIm5hbWUiOiJES1RLZXlzdHJpcExhYmVsIiwibnVtYmVyIjoiMjIwIn0sIjI1MFN0YXRpb25JUERhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzdGF0aW9uSXBWZXJzaW9uTnVtYmVyRGlzcGxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xMCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25JcE5BVFRyYXZlcnNhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSXBEbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN0YXRpb25JcFVSSSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwVGVybWluYWxBdXRoZW50aWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwSXBBZGRyZXNzVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJzdGF0aW9uSXBTZWNvbmRhcnlWUENvbmZpZ1RhYmxlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJzdGF0aW9uSXBWb2ljZVBhY2tldENvbmZpZ1RhYmxlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJzdGF0aW9uSXBQYXNzd29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwU3RhdGlvbklEQXV0b21hdGljQXNzaWdubWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uSXBTdGF0aW9uSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzdGF0aW9uSXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuNCIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwU2Vjb25kYXJ5QXVkaW9Db2RlYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN0YXRpb25JcEF1ZGlvQ29kZWMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMiIsIm5hbWUiOiJzdGF0aW9uSXBNYWNBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNTAuMS4xLjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxMDI2Li42NTUzMiIsIm5hbWUiOiJzdGF0aW9uSXBNZWRpYUNoYW5uZWxCYXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNTAuMS4xLjE4Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3RhdGlvbklwRFRNRlRyYW5zbGF0aW9uTW9kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MCIsIm5hbWUiOiJTdGF0aW9uSVBEYXRhIiwibnVtYmVyIjoiMjUwIn0sIjI2MElwU3RhdGlvbkFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblJlY2FsbEFmdGVyQ0hvbGRBbmRPTkgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI4LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImlwU3RhdGlvblZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjI4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uVEdBQ092ZXJSaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbk5hbWVEaXNwbGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjM0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJpcFN0YXRpb25TdGF0aW9uTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4xOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbkRvb3JQaG9uZURORCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TdHV0dGVyZWREaWFsVG9uZVNlbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uU3RhdGlvbkxjckdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImlwU3RhdGlvblBlcnNvbmFsQWRtaW5QYXNzd29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41MiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25PcmdJbnZva2VPY2EiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uU2VydmljZVRvbmVQZXJtaXNzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpcFN0YXRpb25EZWZhdWx0Q2FsbGluZ051bWJlcklkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjUxIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uUEROQ29kZURpZ2l0cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41MCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMDAiLCJuYW1lIjoiaXBTdGF0aW9uU3RhdGlvblNwZWVkRGlhbE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40MSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbk1XV2l0aERpYWxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpcFN0YXRpb25EcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaXBTdGF0aW9uQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpcFN0YXRpb25RcGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uQ0VTSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25EaWFsaW5nRGlnaXRSZXN0cmljdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25Ib2xkSW5kaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40NCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25PcmlnaW5hdGluZ09jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6ImlwU3RhdGlvbkVtZXJnZW5jeUdyb3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjI2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoiaXBTdGF0aW9uUmVtb3RlUGFzc3dvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40OCIsIm5hbWUiOiJpcFN0YXRpb25JbmRleENhbGxGb3dhcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25UcmF2ZWxDb2RlQ2hhbmdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbkN3dFJvYiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6ImlwU3RhdGlvblRlbmFudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40NyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkRybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25BdXRvQ2FtcG9uYXNEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjQ5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkZybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlwU3RhdGlvbkNvc0RheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvblFwbERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25CZWFyQ2FwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblBlcnNvbmFsQWRtaW5TZWN1cml0eUxldmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjUzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlwU3RhdGlvbkRybE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uRnJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlwU3RhdGlvbkNvc05pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25SZWdTeXN0ZW1TcGVlZERpYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaXBTdGF0aW9uUXBsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMTgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBTdGF0aW9uTGFuSW50ZXJmYWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TZW5kZXJpemVkTW9kZVRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXBTdGF0aW9uRGlzcGxheUROIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjI0Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uQ2FsbEZvcndhcmREaWFsVG9uZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25SZWxlYXNlU3VwZXJ2aXNpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjU0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uU3BlYWtlck9jYUFjY2VwdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImlwU3RhdGlvbkVxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvbkNhbGxQaWNrdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjciLCJuYW1lIjoiaXBTdGF0aW9uQ2VudGVyUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4yOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlwU3RhdGlvbk5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25UMzhQcm90b2NvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBTdGF0aW9uVDM4VGFibGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblQzOFN1YnN0aXR1dGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25Mb2dpblBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjU4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblRyYW5zZmVyUmVnaXN0cmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjU5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2MCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImlwU3RhdGlvbkNvbm5lY3RpbmdFcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNjAiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBTdGF0aW9uc3RhdGlvbkNhbGxpbmdOYW1lVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS42MSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TcGVjaWZpZWRDYWxsZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS42MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFN0YXRpb25TeXN0ZW1TcGVlZERpYWxTdXBwbGVtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjYzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwU3RhdGlvblNpcEluYmFuZE1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAiLCJuYW1lIjoiSXBTdGF0aW9uQXNzaWduIiwibnVtYmVyIjoiMjYwIn0sIjMwMFRydW5rQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtSaW5nRG93bkNpcmN1aXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtTdXBwbHlPZlJpbmdpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua0RpYWxNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua0Fuc3dlclN1cGVydmlzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua1JlbGVhc2VTdXBlcnZpc2lvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRydW5rR3VhcmRUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJ0cnVua1RydW5rTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS4xMCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtTaWduYWxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6InRydW5rRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua1N0YXJ0TWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJ1bmtEdG1mQmFja1RvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNDQwIiwibmFtZSI6InRydW5rTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjk5OSIsIm5hbWUiOiJ0cnVua0h1bnRpbmdPcmRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6InRydW5rSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJ0cnVua09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAiLCJuYW1lIjoiVHJ1bmtBc3NpZ24iLCJudW1iZXIiOiIzMDAifSwiMzAxVHJ1bmtEZWxldGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjQ0MCIsIm5hbWUiOiJ0cnVua0RlbGV0ZU5vIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAxIiwibmFtZSI6IlRydW5rRGVsZXRlIiwibnVtYmVyIjoiMzAxIn0sIjMwMklTRE5QcmltYXJ5VHJ1bmsiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVW5yZXN0Mng2NGticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1NwZWVjaENoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtUV2FpdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVmlkZW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdE11bHRpcmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtTcGVlY2giLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rUTkzMVByb3RvY29sVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVuazdrSHpBdWRpb0NoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtTZW5kTUNJRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40MyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rMzFrSHpBdWRpb0NoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtSZXN0cmljdERpZ2l0YWxJbmZvQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1FzaWdJbnRlcmZhY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjM4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0lmSWROdW1iZXJJbXBsaWNpdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtRc2lnUHJlZmVyZW5jZUxpbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0JjaFNlbGVjdGVkT3JpZ2luYXRpbmdNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rUHJvdG9jb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rN2tIekF1ZGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjEzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmszMWtIekF1ZGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtSZXN0cmljdERpZ2l0YWxJbmZvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjI3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0VxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3Q2NGticHNDaE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVW5yZXN0NTZrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjYiLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0lmSWROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3QzODRrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDE5MjBrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDE1MzZrYnBzQ2hNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rRGNoUG9zaXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3QyeDY0a2Jwc0NoTWV0aG9kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0MSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtUQkNUQ29udHJhY3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1Nob3J0TGluZUJyZWFrU3VwcG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40MCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVW5yZXN0NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3Q1NmticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0lkbGVCY2hTZWxlY3Rpb25NZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDM4NGticHMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua1VucmVzdDE5MjBrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtVbnJlc3QxNTM2a2JwcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4yMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rVmlkZW9DaE1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuUHJpbWFyeVRydW5rUmJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjM3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5QcmltYXJ5VHJ1bmtTZW5kQ2FsbGluZ05hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQ1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkblByaW1hcnlUcnVua0VUU0lTZW5kaW5nVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMiIsIm5hbWUiOiJJU0ROUHJpbWFyeVRydW5rIiwibnVtYmVyIjoiMzAyIn0sIjMwM0lTRE5UcnVua0RlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImlzZG5EZWxldGVDaE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAzLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMyIsIm5hbWUiOiJJU0ROVHJ1bmtEZWxldGUiLCJudW1iZXIiOiIzMDMifSwiMzA0SUxHQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJpbGdDb250cmFjdEJlYW1Db3VudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0NhbGxpbmdOdW1iZXJJZGVudGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpbGdEcmxOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ0ZybE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjE2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaWxnQ29zTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdSZWdTeXN0ZW1TcGVlZERpYWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaWxnUXBsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdTZW5kZXJpemVkTW9kZVRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnQ2F1c2VWYWx1ZU9mRmFpbHVyZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdJbnRlcmNlcHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uNjAiLCJuYW1lIjoiaWxnRGVsYXkxUmluZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjYwIiwibmFtZSI6ImlsZ0RlbGF5MlJpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ1RydW5rVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImlsZ05ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdDb3NPdmVycmlkZUNvZGVDaGFuZ2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnVEdBQ092ZXJSaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjMwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ1N0YXRpb25MY3JHcm91cE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ09yZ0ludm9rZU9jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpbGdHQ08iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ0RybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6ImlsZ0ZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaWxnQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpbGdRcGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0FuYWxvZ0lTRE5UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiaWxnUG9vbExpbmVHcm91cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnQ2FsbGVkRGlhbFRvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdUcnVua1ByaXZhdGVTZXJ2aWNlVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjgiLCJuYW1lIjoiaWxnRW1lcmdlbmN5R3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiaWxnR3JwTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0F1dG9tYXRpY0NhbXBvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoiaWxnSW50ZXJkaWdpdDFUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE4MCIsIm5hbWUiOiJpbGdJbnRlcmRpZ2l0MlRpbWVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjI1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJpbGdUZW5hbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJpbGdEcmxEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaWxnRnJsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiaWxnQ29zRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiaWxnUXBsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4xOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ0JlYXJDYXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdUcnVua1NlcnZpY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQiLCJuYW1lIjoiSUxHQXNzaWduIiwibnVtYmVyIjoiMzA0In0sIjMwNUlMR0RlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRlbGV0ZUlsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA1LjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNSIsIm5hbWUiOiJJTEdEZWxldGUiLCJudW1iZXIiOiIzMDUifSwiMzA2T0xHQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnQ3JlZGl0Q2FyZENhbGxpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoib2xnRnJsTmlnaHQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJvbGdDb3NOaWdodCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im9sZ1FwbE5pZ2h0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnQ2VzaWRTZW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnVHJ1bmtUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoib2xnTmV0d29ya0NvcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4yNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ011c2ljT25Ib2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ0FjY291bnRDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1RyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im9sZ0ZybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoib2xnQ29zIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJvbGdRcGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ0FuYWxvZ0lTRE5UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoib2xnR2NvMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoib2xnUG9vbExpbmVHcm91cDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6Im9sZ1Bvb2xMaW5lR3JvdXAyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1RydW5rUHJpdmF0ZVNlcnZpY2VUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnQW5hbG9nRXhjbHVzaXZlTGluZUZsYXNoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJvbGdHcnBObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnUXNpZ1NlbmRpbmdUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjI0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im9sZ0ZybERheTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJvbGdDb3NEYXkyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoib2xnUXBsRGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ0JlYXJDYXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYiLCJuYW1lIjoiT0xHQXNzaWduIiwibnVtYmVyIjoiMzA2In0sIjMwN09MR0RlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRlbGV0ZU9sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA3LjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNyIsIm5hbWUiOiJPTEdEZWxldGUiLCJudW1iZXIiOiIzMDcifSwiMzA4VHJ1blRpbWVyIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cnVua1RpbWVyQWJhbmRvblN1cGVydmlzZVRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRydW5rVGltZXJEZXRlY3RBckNwYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA4LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAiLCJuYW1lIjoidHJ1bmtUaW1lckxvbmdGbGFzaFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTUiLCJuYW1lIjoidHJ1bmtUaW1lclNob3J0Rmxhc2hUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDguMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiNiIsIm5hbWUiOiJ0cnVua1RpbWVyUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA4LjEuMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAwMCIsIm5hbWUiOiJ0cnVua1RpbWVyRElEYW5kRE1JUmVzcG9uc2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJ0cnVua1RpbWVyUGF1c2VUaW1lQWZ0ZXJGbGFzaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA4LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDgiLCJuYW1lIjoiVHJ1blRpbWVyIiwibnVtYmVyIjoiMzA4In0sIjMwOURJRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaWREYXkxRGF0YURlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjEzIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImRpZERheTJEYXRhRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaWREYXkxQXVkaW9EZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGlkRGF5MkF1ZGlvRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaWROaWdodERhdGFEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4xNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJkaWRWb2ljZU1haWxJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4xOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGlkTXVzaWNPbkhvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGlkTmlnaHRBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZGlkR2NvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiZGlkSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTciLCJuYW1lIjoiZGlkVm1TZW5kaW5nRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4yMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpZERheTFEYXRhRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpZERheTJEYXRhRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImRpZFBvb2xMaW5lR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGlkRGF5MUF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkaWREYXkyQXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkaWROaWdodERhdGFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6ImRpZERlc3RpbmF0aW9uTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4xOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpZE5pZ2h0QXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjciLCJuYW1lIjoiZGlkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi44IiwibmFtZSI6ImRpZFRlbmFudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4yMyIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5IiwibmFtZSI6IkRJRCIsIm51bWJlciI6IjMwOSJ9LCIzMTBESVQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiNiIsIm5hbWUiOiJkaXRFcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaXREYXkxQXVkaW9EZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEwLjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiZGl0RGF5MkF1ZGlvRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGl0TXVzaWNPbkhvbGQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJkaXROaWdodEF1ZGlvRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGl0RGF5MUF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkaXREYXkyQXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpdE5pZ2h0QXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMCIsIm5hbWUiOiJESVQiLCJudW1iZXIiOiIzMTAifSwiMzExRElTQSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjAiLCJuYW1lIjoiZGlzYUlkbGVUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzExLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpc2FOZWNlc3NpdHlTZWN1cml0eUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMS4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE1IiwibmFtZSI6ImRpc2FTZWN1cml0eUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMCIsIm5hbWUiOiJkaXNhUmVzcG9uc2VUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzExLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRpc2FBY2Nlc3NUb1RpZUxpbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzExIiwibmFtZSI6IkRJU0EiLCJudW1iZXIiOiIzMTEifSwiMzEyRElETnVtYmVyRGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRpZERlbGV0ZUlsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJkaWREZWxldGVOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMi4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEyIiwibmFtZSI6IkRJRE51bWJlckRlbGV0ZSIsIm51bWJlciI6IjMxMiJ9LCIzMTNDYWxsZXJJRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY2FsbGVySWRJbW1lZGlhdGVDYWxsZXJJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoiY2FsbGVySWRDSVVFcXVpcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzLjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYWxsZXJJZE5vdGljZUNvbnRlbnRzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTMuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYWxsZXJJZFJlY2VpdmluZ01ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjQ0MCIsIm5hbWUiOiJjYWxsZXJJZFRydW5rTm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMy4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzIiwibmFtZSI6IkNhbGxlcklEIiwibnVtYmVyIjoiMzEzIn0sIjMxNVQxVHJ1bmtDYXJkRGF0YUFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidDFUcnVua1NlbmRQQUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNS4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InQxVHJ1bmtaZXJvQ29kZVN1cHByZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTUuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0MVRydW5rUmVjZWl2ZVBBRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiI0IiwibmFtZSI6InQxVHJ1bmtFcXVpcG1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNS4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InQxVHJ1bmtGcmFtZUZvcm1hdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1IiwibmFtZSI6IlQxVHJ1bmtDYXJkRGF0YUFzc2lnbiIsIm51bWJlciI6IjMxNSJ9LCIzMTZEY2hTaGFyZWRQUkkiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRjaFNoYXJlZEV4aXN0ZW5jZU9mRGNoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTYuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImRjaFNoYXJlZENoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoiZGNoU2hhcmVkRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTYuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjYiLCJuYW1lIjoiZGNoU2hhcmVkSWZJZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE2LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTYiLCJuYW1lIjoiRGNoU2hhcmVkUFJJIiwibnVtYmVyIjoiMzE2In0sIjMxN0lTRE5iYXNpY1RydW5rIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1NwZWVjaCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rU2VuZE1DSUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImlzZG5CYXNpY1RydW5rU3Vic2NyaWJlck51bWJlcjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoiaXNkbkJhc2ljVHJ1bmtTdWJzY3JpYmVyTnVtYmVyMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4yMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1NQSURJbml0aWFsaXplIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rQmNoU2VsZWN0ZWRPcmlnaW5hdGluZ01ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rUHJvdG9jb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rN2tIekF1ZGlvIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVuazMxa0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImlzZG5CYXNpY1RydW5rRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIwIiwibmFtZSI6ImlzZG5CYXNpY1RydW5rU3BpZFZhbHVlMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1NwaWRWYWx1ZTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMTgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNWb2ljZUNhbGxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljVHJ1bmtEZUFjdGl2ZU1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImlzZG5CYXNpY0NoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rU2hvcnRMaW5lQnJlYWtTdXBwb3J0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rVW5yZXN0NjRrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rVW5yZXN0NTZrYnBzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rSWRsZUJjaFNlbGVjdGlvbk1ldGhvZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1RFSSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxNiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6ImlzZG5CYXNpY1NQSURJbml0aWFsaXplVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImlzZG5CYXNpY1RydW5rSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJpc2RuQmFzaWNUcnVua09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXNkbkJhc2ljVHJ1bmtVbnJlc3QyeDY0a2JwcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpc2RuQmFzaWNUcnVua1RXYWl0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5CYXNpY1RydW5rRVRTSVNlbmRpbmdUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjI3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3IiwibmFtZSI6IklTRE5iYXNpY1RydW5rIiwibnVtYmVyIjoiMzE3In0sIjMxOE5vQ3BuRElEIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6Im5vRGlkRGVzdGluYXRpb25OYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjE5Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWROaWdodEF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6Im5vRGlkTm9EaWRPck5vdERldGVybWluIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6Im5vRGlkRGF5MURhdGFEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJub0RpZERheTJEYXRhRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMTUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJub0RpZERheTFBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJub0RpZERheTJBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoibm9EaWROaWdodERhdGFEZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJub0RpZFZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjE4Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub0RpZE11c2ljT25Ib2xkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6Im5vRGlkTmlnaHRBdWRpb0Rlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoibm9EaWRHY28iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJub0RpZElsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE3IiwibmFtZSI6Im5vRGlkVm1TZW5kaW5nRGlhbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4yMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im5vRGlkRGF5MURhdGFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWREYXkyRGF0YURlc3RpbmF0aW9uVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJub0RpZFBvb2xMaW5lR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWREYXkxQXVkaW9EZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im5vRGlkRGF5MkF1ZGlvRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9EaWROaWdodERhdGFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMTYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTgiLCJuYW1lIjoiTm9DcG5ESUQiLCJudW1iZXIiOiIzMTgifSwiMzE5SW50ZXJjZXB0UG9zaXRpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImludGVyY2VwdE5pZ2h0RGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTkuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJpbnRlcmNlcHREYXkxRGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaW50ZXJjZXB0RGF5MkRlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTkuNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImludGVyY2VwdE5pZ2h0RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbnRlcmNlcHREYXkxRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTkuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImludGVyY2VwdERheTJEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE5IiwibmFtZSI6IkludGVyY2VwdFBvc2l0aW9uIiwibnVtYmVyIjoiMzE5In0sIjMyMElTRE5CY2hQb3NpdGlvbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb240Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb243Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4xMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIxIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24zMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjYiLCJuYW1lIjoiYmNoRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24zMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24yMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjI1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24yNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjE3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMjciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24xOCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4xOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiY2hQb3NpdGlvbjI4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJjaFBvc2l0aW9uMTkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmNoUG9zaXRpb24yOSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMCIsIm5hbWUiOiJJU0ROQmNoUG9zaXRpb24iLCJudW1iZXIiOiIzMjAifSwiMzIxSVNETkNhbGxpbmdOdW1iZXJJZGVudGlmaWNhdGlvbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJjYWxsaW5nTnVtT2xnTnVtIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJjYWxsaW5nTnVtRGVmYXVsdENhbGxpbmdOdW0iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImNhbGxpbmdOdW1DYWxsaW5nTnVtYmVyUHJlZml4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNhbGxpbmdOdW1DYWxsaW5nTnVtYmVyVmVyaWZpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoiY2FsbGluZ051bURlZmF1bHRDYWxsaW5nTnVtMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIxLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTUiLCJuYW1lIjoiY2FsbGluZ051bURlZmF1bHRDYWxsaW5nTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIxLjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjEiLCJuYW1lIjoiSVNETkNhbGxpbmdOdW1iZXJJZGVudGlmaWNhdGlvbiIsIm51bWJlciI6IjMyMSJ9LCIzMjJJU0ROQ2FsbGluZ051bWJlclRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiY2FsbGluZ051bURlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiY2FsbGluZ051bU9MRyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoiY2FsbGluZ051bURlc3RUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJjYWxsaW5nTnVtRElETnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNSIsIm5hbWUiOiJjYWxsaW5nTnVtRElETmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIyLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIiLCJuYW1lIjoiSVNETkNhbGxpbmdOdW1iZXJUYWJsZSIsIm51bWJlciI6IjMyMiJ9LCIzMjNDYWxsQnlDYWxsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMiIsIm5hbWUiOiJjYmNGYWNpbGl0eUNvZGVWYWx1ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NyIsIm5hbWUiOiJjYmNNaW5ab25lMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDciLCJuYW1lIjoiY2JjTWluWm9uZTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NyIsIm5hbWUiOiJjYmNNaW5ab25lMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ3IiwibmFtZSI6ImNiY01heFpvbmUxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjMuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDciLCJuYW1lIjoiY2JjTWF4Wm9uZTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NyIsIm5hbWUiOiJjYmNNYXhab25lMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiY2JjU2VydmljZVBhcmFtZXRlcnMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoiY2JjTmV0d29ya0lkZW50aWZpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjMuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJjYmNJbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImNiY09sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImNiY0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiY2JjTGluZVNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjYmNLaW5kT2ZMaW5lU2VydmljZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIzIiwibmFtZSI6IkNhbGxCeUNhbGwiLCJudW1iZXIiOiIzMjMifSwiMzI0Q2FsbEJ5Q2FsbFRpbWVab25lIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJjYmNUaW1lWm9uZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNC4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImNiY1RpbWVab25lMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI0LjEuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjQiLCJuYW1lIjoiY2JjVGltZVpvbmUzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjQuMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImNiY1RpbWVab25lQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI0IiwibmFtZSI6IkNhbGxCeUNhbGxUaW1lWm9uZSIsIm51bWJlciI6IjMyNCJ9LCIzMjVGdWxsSXBRc2lnIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFFzaWdUcnVuazMxa0h6QXVkaW8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImlwUXNpZ1RydW5rRXF1aXBtZW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiaXBRc2lnVHJ1bmtJbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImlwUXNpZ1RydW5rT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwUXNpZ1RydW5rUmJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJpcFFzaWdUcnVua0NoYW5uZWxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJpcFFzaWdUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwUXNpZ1RydW5rU3BlZWNoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBRc2lnVHJ1bmtROTMxUHJvdG9jb2xUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI1LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBRc2lnVHJ1bmtMYW5JbnRlcmZhY2VOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI1IiwibmFtZSI6IkZ1bGxJcFFzaWciLCJudW1iZXIiOiIzMjUifSwiMzI2U0lQVHJ1bmsiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoic2lwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJzaXBUcnVua0VxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI2LjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMSIsIm5hbWUiOiJzaXBUcnVua0xhbkludGVyZmFjZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI2LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzaXBUcnVua0NoYW5uZWxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNi4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtSYnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNi4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNiIsIm5hbWUiOiJTSVBUcnVuayIsIm51bWJlciI6IjMyNiJ9LCIzMjdTSVBUcnVua1NlcnZpY2VLaW5kQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUmVnaXN0cmF0aW9uTW9kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRUcnVua0lsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFRydW5rT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ0MCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVHJ1bmtDaGFubmVsTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kRG9tYWluTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uODYiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNlcnZlckxvY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjciLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVlBUYWJsZUluZGV4UHJpbWFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFZQVGFibGVJbmRleFNlY29uZGFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiNzAwLi42NTUzNSIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUmVnaXN0ZXJQZXJpb2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVGltZXJCIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTQ0MCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUmVjb3ZlcnlUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmROZXR3b3JrVHJhbnNmZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFVzZXJBZ2VudEhlYWRlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2VydmVySGVhZGVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRQcm90b2NvbE9wdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiI5MC4uNjU1MzUiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNlc3Npb25UaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRBdWRpb0NvZGVjUHJpbWFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kQXVkaW9Db2RlY1NlY29uZGFyeSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kRHRtZiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kUnRjcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kVDM4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRTZXJ2ZXJDYWNoZXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFEaWZmc2VydiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFUb3NGaWVsZFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZE1lZGlhVG9zUHJlY2VkZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFUb3NEZWxheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kTWVkaWFUb3NUaHJvdWdocHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjI4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRNZWRpYVRvc1JlbGlhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjI5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYzIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRNZWRpYURzY3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lnbmFsaW5nRGlmZnNlcnYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNpZ25hbGluZ1Rvc0ZpZWxkVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lnbmFsaW5nVG9zUHJlY2VkZW5jZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lnbmFsaW5nVG9zRGVsYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNpZ25hbGluZ1Rvc1Rocm91Z2hwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZFNpZ25hbGluZ1Rvc1JlbGlhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjM2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYzIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRTaWduYWxpbmdEc2NwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjM3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjM4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZEVsZW1lbnRDYWxsUmVsZWFzZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxMC4uOTkiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlS2luZEVsZW1lbnRGYWlsdXJlVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi4zNjAwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRSZWNvdmVyeVJlZ2lzdGVyQ3ljbGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zNjAwIiwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRPcHRpb25zSW50ZXJ2YWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lwTWVzc2FnZU9wdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS40MiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kU2lwTWVzc2FnZVRvSGVhZGVyT3B0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjQzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRSZWdpc3Rlck1lc3NhZ2VGcm9tSGVhZGVyT3B0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjQ0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNpcFRydW5rU2VydmljZUtpbmRSZWdpc3Rlck1lc3NhZ2VUb0hlYWRlck9wdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS40NSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NDYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VLaW5kQXNzZXJ0SWRlbnRpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjciLCJuYW1lIjoiU0lQVHJ1bmtTZXJ2aWNlS2luZEFzc2lnbiIsIm51bWJlciI6IjMyNyJ9LCIzMjhTSVBUcnVua1NlcnZpY2VBc3NpZ24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyOC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjE2IiwibmFtZSI6InNpcFRydW5rU2VydmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI4LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyOC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI4LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoic2lwVHJ1bmtTZXJ2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua1NlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI4LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjgiLCJuYW1lIjoiU0lQVHJ1bmtTZXJ2aWNlQXNzaWduIiwibnVtYmVyIjoiMzI4In0sIjMyOVNJUFVSSUFzc2lnbiI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBVcmlUcnVua1NlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTYwIiwibmFtZSI6InNpcFVyaUluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjkuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJzaXBVcmkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyOS4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUwIiwibmFtZSI6InNpcFVyaVVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjkuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJzaXBVcmlQYXNzV29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoic2lwVXJpUmVnaXN0ZXJDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzaXBVcmlBdHRyaWJ1dGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5LjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI5IiwibmFtZSI6IlNJUFVSSUFzc2lnbiIsIm51bWJlciI6IjMyOSJ9LCI0MDBFbWVyZ2VuY3lDYWxsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNCIsIm5hbWUiOiJlbWVyZ2VuY3lDYWxsQ2FsbGVkTnVtYmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZW1lcmdlbmN5Q2FsbENhbGxlZE51bWJlclNldFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4zIiwibmFtZSI6ImVtZXJnZW5jeUNhbGxEYXlOaWdodE1vZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImVtZXJnZW5jeUNhbGxDYWxsZWROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNDAwIiwibmFtZSI6IkVtZXJnZW5jeUNhbGwiLCJudW1iZXIiOiI0MDAifSwiNDA0QXR0ZW5kYW50R3JvdXAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6ImF0dGVuZGFudEdyb3VwTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40MDQuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImF0dGVuZGFudENhbGxEaXN0cmlidXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJhdHRlbmRhbnRBbHRlcm5hdGl2ZURlc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTgwIiwibmFtZSI6ImF0dGVuZGFudE92ZXJmbG93VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6ImF0dGVuZGFudE92ZXJmbG93RGVzdGluYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6ImF0dGVuZGFudFZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40MDQuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNCIsIm5hbWUiOiJBdHRlbmRhbnRHcm91cCIsIm51bWJlciI6IjQwNCJ9LCI1MDBTeXN0ZW1DYWxsRm9yd2FyZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjQ4IiwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkRmlyc3REZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoic3lzdGVtQ2FsbEZvcndhcmRTZWNvbmREZXN0aW5hdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtQ2FsbEZvcndhcmRDYWxsVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUNhbGxGb3J3YXJkRGF5TmlnaHRNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDAuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDAiLCJuYW1lIjoiU3lzdGVtQ2FsbEZvcndhcmQiLCJudW1iZXIiOiI1MDAifSwiNTAxU3lzdGVtU3BlZWREaWFsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoic3lzdGVtU3BlZWREaWFsTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDEuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMyIsIm5hbWUiOiJzeXN0ZW1TcGVlZERpYWxzSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMS4xLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJzeXN0ZW1TcGVlZERpYWxVc2VyTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAxLjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDEiLCJuYW1lIjoiU3lzdGVtU3BlZWREaWFsIiwibnVtYmVyIjoiNTAxIn0sIjUwMlRlcm1QYWdpbmdHcnAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmc1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmc4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMTAiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzEwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjExIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4xMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzEzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE0Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcxNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4xNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMTUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMTYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzE2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE3Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBBbGxQYWdpbmdMaXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE4Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBBbGxFbWFyZ2VuY3lQYWdpbmdMaXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcxNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4yMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMTgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzE5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcyMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4yMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGVybWluYWxQYWdpbmdHcm91cFBhZ2luZzIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRlcm1pbmFsUGFnaW5nR3JvdXBQYWdpbmcyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS4yNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ZXJtaW5hbFBhZ2luZ0dyb3VwUGFnaW5nMjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIiLCJuYW1lIjoiVGVybVBhZ2luZ0dycCIsIm51bWJlciI6IjUwMiJ9LCI1MDNEZXZpY2VQYWdpbmdHcnAiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6InpvbmVSZWxheU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmczIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmc2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nOSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzExIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjEyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcxMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcxNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cEFsbFBhZ2luZ0xpc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cEFsbEVtYXJnZW5jeVBhZ2luZ0xpc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMTkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJleHRlcm5hbEdlbmVyaWNSZWxheU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcxNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMTgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzE5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjIzIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcyMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjI2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXh0ZXJuYWxQYWdpbmdHcm91cFBhZ2luZzIyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjI2Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImV4dGVybmFsUGFnaW5nR3JvdXBQYWdpbmcyMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleHRlcm5hbFBhZ2luZ0dyb3VwUGFnaW5nMjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMiLCJuYW1lIjoiRGV2aWNlUGFnaW5nR3JwIiwibnVtYmVyIjoiNTAzIn0sIjUwNFN5c3RlbUNhbGxGb3J3YXJkVHlwZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic3lzdGVtQ0ZUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDQuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNDgiLCJuYW1lIjoic3lzdGVtQ0ZUeXBlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA0IiwibmFtZSI6IlN5c3RlbUNhbGxGb3J3YXJkVHlwZSIsIm51bWJlciI6IjUwNCJ9LCI1MDZWZXJpZmllZEFjY291bnRDb2RlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJ2ZXJpZmllZEFjY291bnRDb2RlRHJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDYuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE2IiwibmFtZSI6InZlcmlmaWVkQWNjb3VudENvZGVGcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNi4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidmVyaWZpZWRBY2NvdW50Q29kZUNvZGVGbGFnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDYuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjE1IiwibmFtZSI6InZlcmlmaWVkQWNjb3VudENvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNi4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoidmVyaWZpZWRBY2NvdW50Q29kZU5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNi4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA2IiwibmFtZSI6IlZlcmlmaWVkQWNjb3VudENvZGUiLCJudW1iZXIiOiI1MDYifSwiNTA3RG9vclBob25lIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZG9vclBob25lTmlnaHREZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuMTEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkb29yUGhvbmVEYXkxRGVzdGluYXRpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImRvb3JQaG9uZURheTJEZXN0aW5hdGlvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA3LjEuMS4xMCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImRvb3JQaG9uZU5pZ2h0RGVzdGluYXRpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuMTIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJkb29yUGhvbmVOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjYiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjgiLCJuYW1lIjoiZG9vclBob25lVGVuYW50Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjMuLjMwIiwibmFtZSI6ImRvb3JQaG9uZUNhbGxUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRvb3JQaG9uZURheTFEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImRvb3JQaG9uZURheTJEZXN0aW5hdGlvblR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuOSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImRvb3JQaG9uZUVxdWlwbWVudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA3LjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjI0IiwibmFtZSI6ImRvb3JQaG9uZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA3LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDciLCJuYW1lIjoiRG9vclBob25lIiwibnVtYmVyIjoiNTA3In0sIjUwOERvb3JMb2NrQ29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJkb29yTG9ja1Bvc2l0aW9uT2ZCSU9VIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDguMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI2IiwibmFtZSI6ImRvb3JMb2NrUG9zaXRpb25PZnJERENCIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDguMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkb29yTG9ja0Nvbm5lY3Rpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDguMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZG9vckxvY2tOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwOC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA4IiwibmFtZSI6IkRvb3JMb2NrQ29udHJvbCIsIm51bWJlciI6IjUwOCJ9LCI1MDlUUk92ZXJyaWRlYnlTcGVlZERpYWwiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InRvbGxSZXN0cmljdGlvbk92ZXJyaWRlRHJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDkuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoidG9sbFJlc3RyaWN0aW9uT3ZlcnJpZGVGcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwOS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4zMiIsIm5hbWUiOiJ0b2xsUmVzdHJpY3Rpb25PdmVycmlkZUNvcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA5LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6InRvbGxSZXN0cmljdGlvbk92ZXJyaWRlUXBsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDkuNCIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTA5IiwibmFtZSI6IlRST3ZlcnJpZGVieVNwZWVkRGlhbCIsIm51bWJlciI6IjUwOSJ9LCI1MTBDT1NPdmVycmlkZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoiY29zT3ZlcmlkZU5ldHdvcmtDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiY29zT3ZlcmlkZURybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEwLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJjb3NPdmVyaWRlRnJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTAuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMyIiwibmFtZSI6ImNvc092ZXJpZGVDb3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiY29zT3ZlcmlkZVFwbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEwLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJjb3NPdmVyaWRlQ29zQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEwLjEuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoiY29zT3ZlcmlkZUNvc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTAuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMCIsIm5hbWUiOiJDT1NPdmVycmlkZSIsIm51bWJlciI6IjUxMCJ9LCI1MTJTTURSZm9yU1lTVEVNIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzbWRyQW5pRmllbGRJbmRpY2F0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEyLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzbWRyVk1DYWxsSWRGaWVsZEluZGljYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTIuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNtZHJDYWxsZXJJZEZpZWxkSW5kaWNhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckNhcnJpYWdlUmV0dXJuQWRkaXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckFiYW5kb25lZENhbGwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckJSZWNvcmRPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic21kckF1dGhvcml6YXRpb25Db2RlT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTIuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMiIsIm5hbWUiOiJTTURSZm9yU1lTVEVNIiwibnVtYmVyIjoiNTEyIn0sIjUxM1NNRFJmb3JJTEciOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiaWxnU21kcklsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdTbWRyQlJlY29yZE91dHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEzLjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnU21kckluY29taW5nQ2FsbFJlY29yZE91dHB1dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEzLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaWxnU21kckRpc3BsYXlTZWxlY3Rpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMy4xLjEuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlsZ1NtZHJEbmlzRmllbGRJbmRpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpbGdTbWRyUW9zUmVjb3JkT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMuMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMiLCJuYW1lIjoiU01EUmZvcklMRyIsIm51bWJlciI6IjUxMyJ9LCI1MTRTTURSZm9yT0xHIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6Im9sZ1NtZHJPbGciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoib2xnU21kckJSZWNvcmRPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1NtZHJPdXRnb2luZ0NhbGxSZWNvcmRPdXRwdXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im9sZ1NtZHJEaXNwbGF5U2VsZWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJvbGdTbWRyUW9zUmVjb3JkT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTQuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTQiLCJuYW1lIjoiU01EUmZvck9MRyIsIm51bWJlciI6IjUxNCJ9LCI1MTVSZWxheVNlcnZpY2UiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjExIiwibmFtZSI6ImJpb3VQb3J0VHlwZUdlbmVyaWNSZWxheTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTEiLCJuYW1lIjoiYmlvdVBvcnRUeXBlR2VuZXJpY1JlbGF5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE1LjEuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMSIsIm5hbWUiOiJiaW91UG9ydFR5cGVHZW5lcmljUmVsYXkzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTUuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo1LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjExIiwibmFtZSI6ImJpb3VQb3J0VHlwZUdlbmVyaWNSZWxheTQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNS4xLjEuNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoiYmlvdUJJT1VDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTUuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNSIsIm5hbWUiOiJSZWxheVNlcnZpY2UiLCJudW1iZXIiOiI1MTUifSwiNTE2U3RhdGlvblNwZWVkRGlhbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6InN0YXRpb25TcGVlZERpYWxOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNi4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIyIiwibmFtZSI6InN0YXRpb25TcGVlZERpYWxzSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNi4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJzdGF0aW9uU3BlZWRETiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE2LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoic3RhdGlvblNwZWVkRGlhbFVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTYuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNiIsIm5hbWUiOiJTdGF0aW9uU3BlZWREaWFsIiwibnVtYmVyIjoiNTE2In0sIjUxN011bHRpcGxlQ2FsbGluZ0dyb3VwIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBWb2ljZU1haWxJRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS42Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBEZWxheTFUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xODAiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBEZWxheTJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJtdWx0aXBsZUNhbGxpbmdHcm91cFBpbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTcuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ4IiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ0dyb3VwU3lzdGVtQ0ZJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOTYiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE3LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTciLCJuYW1lIjoiTXVsdGlwbGVDYWxsaW5nR3JvdXAiLCJudW1iZXIiOiI1MTcifSwiNTE4TXVsdGlwbGVDYWxsaW5nTWVtYmVycyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjMyIiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ01lbWJlcnNEZXN0aW5hdGlvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE4LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtdWx0aXBsZUNhbGxpbmdNZW1iZXJzRGVzdENhbGxUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTguMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjUiLCJuYW1lIjoibXVsdGlwbGVDYWxsaW5nTWVtYmVyc0Rlc3RMaXN0SW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxOC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjk2IiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ01lbWJlcnNJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE4LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtdWx0aXBsZUNhbGxpbmdNZW1iZXJzRGVzdGluYXRpb25UeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTgiLCJuYW1lIjoiTXVsdGlwbGVDYWxsaW5nTWVtYmVycyIsIm51bWJlciI6IjUxOCJ9LCI1MTlNdWx0aXBsZUNhbGxpbmdEZWxldGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjk2IiwibmFtZSI6Im11bHRpcGxlQ2FsbGluZ0luZGV4RGVsZXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTkuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE5IiwibmFtZSI6Ik11bHRpcGxlQ2FsbGluZ0RlbGV0ZSIsIm51bWJlciI6IjUxOSJ9LCI1MjBMQ1JQYXJhbWV0ZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JQYXJhbURlZmF1bHRSb3V0aW5nUGxhbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIwLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxjclBhcmFtQ2FtcG9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjAuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zIiwibmFtZSI6ImxjclBhcmFtSG9tZUFyZWFDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjAuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIwIiwibmFtZSI6IkxDUlBhcmFtZXRlciIsIm51bWJlciI6IjUyMCJ9LCI1MjFMQ1JSb3V0aW5nUGxhbkFuYWx5c2lzVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyOCIsIm5hbWUiOiJsY3JBbmFseXNpc1BsYW5OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi4xOSIsIm5hbWUiOiJsY3JBbmFseXNpc0RpZ2l0cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIxLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjEiLCJuYW1lIjoiTENSUm91dGluZ1BsYW5BbmFseXNpc1RhYmxlIiwibnVtYmVyIjoiNTIxIn0sIjUyMkxDUkV4Um91dGluZ1BsYW5BbmFseXNpc1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyRXhjZXB0aW9uYWxSb3V0ZVBsYW5OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMi4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi4xOSIsIm5hbWUiOiJsY3JFeGNlcHRpb25hbERpZ2l0cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIyLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjIiLCJuYW1lIjoiTENSRXhSb3V0aW5nUGxhbkFuYWx5c2lzVGFibGUiLCJudW1iZXIiOiI1MjIifSwiNTIzTENSUm91dGVQbGFuU2NoZWR1bGVUYWJsZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjE2IiwibmFtZSI6ImxjclNjaGR1bGVTdGF0aW9uTGNyR3JvdXBOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMy4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTI4IiwibmFtZSI6ImxjclNjaGR1bGVSb3V0ZUNob2ljZVRhYmxlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjMuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JTY2hkdWxlVGFibGVUeXBlT2ZEYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMy4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoibGNyU2NoZHVsZVJvdXRlUGxhbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTIzLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoibGNyU2NoZHVsZVRpbWVab25lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjMuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjMiLCJuYW1lIjoiTENSUm91dGVQbGFuU2NoZWR1bGVUYWJsZSIsIm51bWJlciI6IjUyMyJ9LCI1MjRMQ1JSb3V0ZUNob2ljZVRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5MiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5MyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5NCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5NSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VUYWJsZVJvdXRlRGVmaW5pdGlvblByaW9yaXR5NiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI0LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGNyUm91dGVDaG9pY2VSb3V0ZURlZmluaXRpb25Qcmlvcml0eTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JSb3V0ZUNob2ljZVRhYmxlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjQuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNCIsIm5hbWUiOiJMQ1JSb3V0ZUNob2ljZVRhYmxlIiwibnVtYmVyIjoiNTI0In0sIjUyNUxDUlJvdXRlRGVmaW5pdGlvblRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoibGNyUm91dGVEZWZpbml0aW9uT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjUuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEyOCIsIm5hbWUiOiJsY3JSb3V0ZURlZmluaXRpb25EaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI1LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImxjclJvdXRlRGVmaW5pdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI1LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjUiLCJuYW1lIjoiTENSUm91dGVEZWZpbml0aW9uVGFibGUiLCJudW1iZXIiOiI1MjUifSwiNTI2TENSRGlnaXRNb2RpZmljYXRpb25UYWJsZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JEaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjMiLCJuYW1lIjoibGNyRGlnaXRNb2RpZmljYXRpb25BZGRpdGlvbkF0VGFpbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI2LjEuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjMiLCJuYW1lIjoibGNyRGlnaXRNb2RpZmljYXRpb25BZGRpdGlvbkluRnJvbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNi4xLjEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjAiLCJuYW1lIjoibGNyRGlnaXRNb2RpZmljYXRpb25EaWdpdFRvQmVEZWxldGVkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjYuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyNiIsIm5hbWUiOiJMQ1JEaWdpdE1vZGlmaWNhdGlvblRhYmxlIiwibnVtYmVyIjoiNTI2In0sIjUyN0xDUlB1YmxpY0hvbGlkYXlDYWxlbmRhclRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjgiLCJuYW1lIjoicHVibGljSG9saWRheUNhbGVuZGFyRGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjcuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwdWJsaWNIb2xpZGF5Q2FsZW5kYXJGbGFnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjcuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjciLCJuYW1lIjoiTENSUHVibGljSG9saWRheUNhbGVuZGFyVGFibGUiLCJudW1iZXIiOiI1MjcifSwiNTI4TENSUHVibGljRGF5T2ZXZWVrTWFwcGluZ1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlTYXR1cmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlUaHVyc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlXZWRuZXNkYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyOC4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGNyUHVibGljRGF5RnJpZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxjclB1YmxpY0RheU1vbmRheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsY3JQdWJsaWNEYXlTdW5kYXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyOC43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGNyUHVibGljRGF5VHVlc2RheSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI4LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjgiLCJuYW1lIjoiTENSUHVibGljRGF5T2ZXZWVrTWFwcGluZ1RhYmxlIiwibnVtYmVyIjoiNTI4In0sIjUyOUxDUlJvdXRlUGxhblNjaGVkdWxlVGFibGVUaW1lWm9uZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6ImxjclRpbWVab25lVHlwZU9mRGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjkuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoibGNyVGltZVpvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyOS4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiI0IiwibmFtZSI6ImxjclRpbWVab25lVGltZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI5LjEuMS40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJsY3JUaW1lWm9uZVJvdXRlUGxhbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI5LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjkiLCJuYW1lIjoiTENSUm91dGVQbGFuU2NoZWR1bGVUYWJsZVRpbWVab25lIiwibnVtYmVyIjoiNTI5In0sIjUzMFRvbGxSZXN0cmljdGlvbkxDUlNjcmVlbmluZ1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjciLCJuYW1lIjoidHJMQ1J0YWJsZUNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJMQ1J0YWJsZURtQWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ckxDUnRhYmxlU2V0Tm9TZXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyTENSdGFibGVUckFjdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJMQ1J0YWJsZUxjckFjdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJ0ckxDUnRhYmxlU2tpcExlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzAiLCJuYW1lIjoiVG9sbFJlc3RyaWN0aW9uTENSU2NyZWVuaW5nVGFibGUiLCJudW1iZXIiOiI1MzAifSwiNTMxVG9sbFJlc3RyaWN0aW9uTENSU2NyZWVuaW5nRm9yT0xHVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJ0ckxDUk9sZ0NvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMS4xLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoidHJMQ1JPbGdQYXVzZUluc2VydGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMxLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0ckxDUk9sZ1RyQWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6InRyTENST2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjgiLCJuYW1lIjoidHJMQ1JPbGdTa2lwTGVuZ3RoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyTENST2xnQ29kZVNldE5vU2V0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEiLCJuYW1lIjoiVG9sbFJlc3RyaWN0aW9uTENSU2NyZWVuaW5nRm9yT0xHVGFibGUiLCJudW1iZXIiOiI1MzEifSwiNTMyVG9sbFJlc3RyaWN0aW9uVGFibGVBbGxvd0RlbnkiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRvbGxSZXN0cmljdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMyLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjE2IiwibmFtZSI6InRvbGxSZXN0cmljdGlvbkRybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMyLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzIiLCJuYW1lIjoiVG9sbFJlc3RyaWN0aW9uVGFibGVBbGxvd0RlbnkiLCJudW1iZXIiOiI1MzIifSwiNTMzVG9sbFJlc3RyaWN0aW9uVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJ0clRhYmxlRHJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJ0clRhYmxlQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMzLjEuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0clRhYmxlQ29kZUZsYWciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMy4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMyIsIm5hbWUiOiJUb2xsUmVzdHJpY3Rpb25UYWJsZSIsIm51bWJlciI6IjUzMyJ9LCI1MzRFeGNlcHRpb25hbFRvbGxSZXN0cmljdGlvblRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJleGNlcHRpb25hbFRyQ29kZUZsYWciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJleGNlcHRpb25hbERybCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjEzIiwibmFtZSI6ImV4Y2VwdGlvbmFsVHJDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzQuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNCIsIm5hbWUiOiJFeGNlcHRpb25hbFRvbGxSZXN0cmljdGlvblRhYmxlIiwibnVtYmVyIjoiNTM0In0sIjUzNUxDUlBETkF1dGhDb2RlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIiLCJuYW1lIjoibGNyQWNjZXNzQ29kZUEwMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMiIsIm5hbWUiOiJsY3JBY2Nlc3NDb2RlQTAyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzUuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyIiwibmFtZSI6ImxjckFjY2Vzc0NvZGVBMDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIiLCJuYW1lIjoibGNyQWNjZXNzQ29kZUEwNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMiIsIm5hbWUiOiJsY3JBY2Nlc3NDb2RlQTA1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzUuNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyIiwibmFtZSI6ImxjckFjY2Vzc0NvZGVBMDYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNS43Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIiLCJuYW1lIjoibGNyQWNjZXNzQ29kZUEwNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMiIsIm5hbWUiOiJsY3JBY2Nlc3NDb2RlQTA4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzUuOSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibGNyQWNjZXNzQ29kZVBETiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTM1LjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNSIsIm5hbWUiOiJMQ1JQRE5BdXRoQ29kZSIsIm51bWJlciI6IjUzNSJ9LCI1NDBBQ0RQaWxvdEROQXNzaWduIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiYWNkUGlsb3RBZnRlclNoaWZ0Rm9yd2FyZERlc3RpbmF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xNiIsIm5hbWUiOiJhY2RQaWxvdFZvaWNlTWFpbElkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAuMS4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImFjZFBpbG90QWZ0ZXJTaGlmdEZvcndhcmRUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiYWNkUGlsb3REbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTQwLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDAiLCJuYW1lIjoiQUNEUGlsb3RETkFzc2lnbiIsIm51bWJlciI6IjU0MCJ9LCI1NDFBQ0RQaWxvdERORGVsZXRlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkZWxldGVBY2RQaWxvdERuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NDEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTQxIiwibmFtZSI6IkFDRFBpbG90RE5EZWxldGUiLCJudW1iZXIiOiI1NDEifSwiNTUwRW1lcmdlbmN5Q2FsbEdyb3VwIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE51bSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZW1lcmdlbmN5R3JvdXBPbGcxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTAuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE9sZzIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImVtZXJnZW5jeUdyb3VwT2xnMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwLjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZW1lcmdlbmN5R3JvdXBPbGc0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTAuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE9sZzUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjIwIiwibmFtZSI6ImVtZXJnZW5jeUdyb3VwT2xnNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwLjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoiZW1lcmdlbmN5R3JvdXBPbGc3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTAuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIyMCIsIm5hbWUiOiJlbWVyZ2VuY3lHcm91cE9sZzgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUwIiwibmFtZSI6IkVtZXJnZW5jeUNhbGxHcm91cCIsIm51bWJlciI6IjU1MCJ9LCI1NTFFbWVyZ2VuY3lOZXR3b3JrQWNjZXNzQ29kZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjUiLCJuYW1lIjoiZW1lck5ldHdvcmtBY2Nlc3NDb2RlQWNjZXNzQ29kZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU1MS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJlbWVyTmV0d29ya0FjY2Vzc0NvZGVBY2Nlc3NDb2RlMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUxLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6ImVtZXJOZXR3b3JrQWNjZXNzQ29kZUFjY2Vzc0NvZGUzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NTEuMyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTUxIiwibmFtZSI6IkVtZXJnZW5jeU5ldHdvcmtBY2Nlc3NDb2RlIiwibnVtYmVyIjoiNTUxIn0sIjU3MEFjY291bnRDb2RlRGlnaXRMZW5ndGgiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjQuLjE1IiwibmFtZSI6ImFjY291bnRDb2RlTGVuZ3RoSW5wdXREaWdpdExlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTcwLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjQuLjE1IiwibmFtZSI6ImFjY291bnRDb2RlTGVuZ3RoVmVyaWZpZWREaWdpdExlbmd0aCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTcwLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImFjY291bnRDb2RlTGVuZ3RoQ0ZFeHRlcm5hbFdpdGhGb3JjZWRBY2MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MC4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTcwIiwibmFtZSI6IkFjY291bnRDb2RlRGlnaXRMZW5ndGgiLCJudW1iZXIiOiI1NzAifSwiNTcxRXhOdW1iZXJPZkZvcmNlZEFjY291bnRDb2RlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJlY2VwdGlvbk51bWJlcjQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3MS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzEiLCJuYW1lIjoiRXhOdW1iZXJPZkZvcmNlZEFjY291bnRDb2RlIiwibnVtYmVyIjoiNTcxIn0sIjU3M0Rvb3JQaG9uZURlbGV0ZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMjQiLCJuYW1lIjoiZG9vclBob25lRGVsZXRlRG9vclBob25lTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzMuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTczIiwibmFtZSI6IkRvb3JQaG9uZURlbGV0ZSIsIm51bWJlciI6IjU3MyJ9LCI1NzZEb29yUGhvbmVSaW5nSW5OaWdodE1vZGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI0IiwibmFtZSI6ImRvb3JQaG9uZVJpbmdQYWdpbmdHcnBOdW0iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3Ni4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiZG9vclBob25lUmluZ1RlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc2LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzYiLCJuYW1lIjoiRG9vclBob25lUmluZ0luTmlnaHRNb2RlIiwibnVtYmVyIjoiNTc2In0sIjU3N0NhbGxIaXN0b3J5U3RvclRlcm1pbmFsIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoiY2FsbEhpc3RvcnlDaXJjdWl0VHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc3LjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJjYWxsSGlzdG9yeVRlcm1pbmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzcuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3NyIsIm5hbWUiOiJDYWxsSGlzdG9yeVN0b3JUZXJtaW5hbCIsIm51bWJlciI6IjU3NyJ9LCI1NzlWb2ljZU1haWxEYXRhRm9yU3lzdGVtIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2bVN5c3RlbUFwcGxpY2F0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6InZtU3lzdGVtTGVuZ3RoT2ZWbUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtT3V0cHV0Q2xhc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1EaWFsU2VuZFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidm1TeXN0ZW1DZkJ1c3lSZWNvcmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjciLCJuYW1lIjoidm1TeXN0ZW1UcmFuc2ZlclZtRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4xNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMi4uMjAiLCJuYW1lIjoidm1TeXN0ZW1DYWxsZXJOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNyIsIm5hbWUiOiJ2bVN5c3RlbUNlbnRyYWxpemVkVm1DYWxsQmFja0RuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTAiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtTWVzc2FnZURlc2tObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIyLi4yMCIsIm5hbWUiOiJ2bVN5c3RlbUNsYXNzQW5pRG5pc0NhbGxlck51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjE5Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2bVN5c3RlbUNmQWxsQ2FsbFJlY29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjExIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2bVN5c3RlbURpcmVjdHJ5UmVjb3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InZtU3lzdGVtQ2ZOb0Fuc3dlclJlY29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjEzIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2bVN5c3RlbVJldHJpZXZpbmdNZXNzYWdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTUiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtQ2FuY2VsT2ZNdyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2bVN5c3RlbUF1dG9DYW5jZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1MY2RDb250cm9sT2ZWb2ljZU1haWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1WTWNhbGxpZEJ5REMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4xOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoidm1TeXN0ZW1CbGFua051bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtVk1Db21wYXRpYmlsaXR5Rm9yREtUNTAwMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1TeXN0ZW1WbVNtZGlUaW1lU3RhbXBQYWNrZXQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4yMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtU3lzdGVtVm1TbWRpVFJlY29yZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5IiwibmFtZSI6IlZvaWNlTWFpbERhdGFGb3JTeXN0ZW0iLCJudW1iZXIiOiI1NzkifSwiNTgwVm9pY2VNYWlsRGF0YSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1EYXRhQlRvbmVTZW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2bURhdGFBRFRvbmVTZW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoidm1EYXRhRE4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidm1EYXRhVk1Ub1ZNQmxvY2tpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtRGF0YUNvbnRyb2xNZXRob2QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZtRGF0YUVuZFRvRW5kU2lnbmFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAiLCJuYW1lIjoiVm9pY2VNYWlsRGF0YSIsIm51bWJlciI6IjU4MCJ9LCI2NTBCZWhpbmRDb25uZWN0aW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImJlaGluZE9sZ051bSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiZWhpbmRCZWhpbmRDb25uZWN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTAuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiZWhpbmRBY2NvdW50Q2VudHJleEZlYXR1cmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MCIsIm5hbWUiOiJCZWhpbmRDb25uZWN0aW9uIiwibnVtYmVyIjoiNjUwIn0sIjY1MVByaXZhdGVSb3V0ZVBsYW5BbmFseXNpc1RhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoicHJpdmF0ZUFuYWx5c2lzTm9kZUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTEuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVBbmFseXNpc1JvdXRlQ2hvaWNlVGFibGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUxIiwibmFtZSI6IlByaXZhdGVSb3V0ZVBsYW5BbmFseXNpc1RhYmxlIiwibnVtYmVyIjoiNjUxIn0sIjY1M1ByaXZhdGVSb3V0ZUNob2ljZVRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlQ2hvaWNlVGJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVSb3V0ZUNob2ljZVRibERlZkluZGV4MSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUzLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJwcml2YXRlUm91dGVDaG9pY2VUYmxEZWZJbmRleDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1My4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlQ2hvaWNlVGJsRGVmSW5kZXgzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTMuMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVSb3V0ZUNob2ljZVRibERlZkluZGV4NCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjUzLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJwcml2YXRlUm91dGVDaG9pY2VUYmxEZWZJbmRleDUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1My4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlQ2hvaWNlVGJsRGVmSW5kZXg2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTMuMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MyIsIm5hbWUiOiJQcml2YXRlUm91dGVDaG9pY2VUYWJsZSIsIm51bWJlciI6IjY1MyJ9LCI2NTRQcml2YXRlUm91dGVEZWZpbml0aW9uVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY0IiwibmFtZSI6InByaXZhdGVSb3V0ZURlZmluaXRpb25EaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU0LjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNjQiLCJuYW1lIjoicHJpdmF0ZVJvdXRlRGVmaW5pdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMjAiLCJuYW1lIjoicHJpdmF0ZVJvdXRlRGVmaW5pdGlvbk9sZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU0LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTQiLCJuYW1lIjoiUHJpdmF0ZVJvdXRlRGVmaW5pdGlvblRhYmxlIiwibnVtYmVyIjoiNjU0In0sIjY1NVByaXZhdGVEaWdpdE1vZGlmaWNhdGlvblRhYmxlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjMiLCJuYW1lIjoicHJpdmF0ZURpZ2l0TW9kaWZpY2F0aW9uQWRkaXRpb25JbkZyb250Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTUuMS4xLjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwIiwibmFtZSI6InByaXZhdGVEaWdpdE1vZGlmaWNhdGlvbkRpZ2l0VG9CZURlbGV0ZWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1NS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjY0IiwibmFtZSI6InByaXZhdGVEaWdpdE1vZGlmaWNhdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU1LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTUiLCJuYW1lIjoiUHJpdmF0ZURpZ2l0TW9kaWZpY2F0aW9uVGFibGUiLCJudW1iZXIiOiI2NTUifSwiNjU2Tm9kZUlkIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJub2RlSURQcmltYXJ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlEUHJpbWFyeU92ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjYiLCJuYW1lIjoibm9kZUlEMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU2LjMiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6Im5vZGVJRDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1Ni41Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJub2RlSUQ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuNyIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlEMk92ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlEM092ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoibm9kZUlENE92ZXJsYXBDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTYuOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU2IiwibmFtZSI6Ik5vZGVJZCIsIm51bWJlciI6IjY1NiJ9LCI2NTduZXR3b3JrQ09TbWFwcGluZyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibmV0d29ya0Nvc1RHQUNPdmVyUmlkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU3LjEuMS42Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibmV0d29ya0Nvc09yZ0ludm9rZU9jYSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU3LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjMyIiwibmFtZSI6Im5ldHdvcmtDb3NNYXBwaW5nSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1Ny4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMzIiLCJuYW1lIjoibmV0d29ya0Nvc0xvY2FsQ29zSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1Ny4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibmV0d29ya0Nvc0Nvc092ZXJyaWRlQ2hhbmdlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTcuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJuZXR3b3JrQ29zUmVnU3lzdGVtU3BlZWREaWFsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTcuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTciLCJuYW1lIjoibmV0d29ya0NPU21hcHBpbmciLCJudW1iZXIiOiI2NTcifSwiNjU4bmV0d29ya0RSTG1hcHBpbmciOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21EcmwzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21Ecmw2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsNyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS44Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsOSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4xMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMTAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMTEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDExIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21EcmwxMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4xMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMTMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMTQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRHJsQ29udmVydGVkRHJsRnJvbURybDE0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTguMS4xLjE1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0RybENvbnZlcnRlZERybEZyb21EcmwxNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4LjEuMS4xNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtEcmxDb252ZXJ0ZWREcmxGcm9tRHJsMTYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMTciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yIiwibmFtZSI6Im5ldHdvcmtEcmxUYWJsZVR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU4IiwibmFtZSI6Im5ldHdvcmtEUkxtYXBwaW5nIiwibnVtYmVyIjoiNjU4In0sIjY1OW5ldHdvcmtGUkxtYXBwaW5nIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21GcmwyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS40Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21Gcmw1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS43Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21Gcmw4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDEwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21GcmwxMSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS4xMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsMTIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMTMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDEzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjE0Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya0ZybENvbnZlcnRlZEZybEZyb21GcmwxNCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU5LjEuMS4xNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtGcmxDb252ZXJ0ZWRGcmxGcm9tRnJsMTUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OS4xLjEuMTYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrRnJsQ29udmVydGVkRnJsRnJvbUZybDE2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjE3Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMiIsIm5hbWUiOiJuZXR3b3JrRnJsVGFibGVUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTkuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1OSIsIm5hbWUiOiJuZXR3b3JrRlJMbWFwcGluZyIsIm51bWJlciI6IjY1OSJ9LCI2NjBuZXR3b3JrUVBMbWFwcGluZyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGw0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDYiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo4LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGw3Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsOCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS45Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGw5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjExLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxMCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsMTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDEyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjEzIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxMyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjE2IiwibmFtZSI6Im5ldHdvcmtRcGxDb252ZXJ0ZWRRcGxGcm9tUXBsMTQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY2MC4xLjEuMTUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJuZXR3b3JrUXBsQ29udmVydGVkUXBsRnJvbVFwbDE1Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAuMS4xLjE2Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE3LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTYiLCJuYW1lIjoibmV0d29ya1FwbENvbnZlcnRlZFFwbEZyb21RcGwxNiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoibmV0d29ya1FwbFRhYmxlVHlwZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYwLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjAiLCJuYW1lIjoibmV0d29ya1FQTG1hcHBpbmciLCJudW1iZXIiOiI2NjAifSwiNjYxTmV0d29ya0RuVGFibGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42IiwibmFtZSI6Im5ldHdvcmtEblRhYmxlTm9kZUlkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjEuMS4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJuZXR3b3JrRG5UYWJsZU5ldHdvcmtEbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjYxLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NjEiLCJuYW1lIjoiTmV0d29ya0RuVGFibGUiLCJudW1iZXIiOiI2NjEifSwiNjcwUmVtb3RlTm9kZURhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJyZW1vdGVOb2RlSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjU1MzUiLCJuYW1lIjoicmVtb3RlTm9kZVBvcnRObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcwLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InJlbW90ZU5vZGVJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MC4xLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzAiLCJuYW1lIjoiUmVtb3RlTm9kZURhdGEiLCJudW1iZXIiOiI2NzAifSwiNjcxSXBBZGRyZXNzQ29udmVydEZvclByaXZhdGVOV092ZXJJUCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcEFkZHJlc3NDb252ZXJ0VGFibGVJcEFkZHJlc3NSb3V0ZTEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MS4xLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwQWRkcmVzc0NvbnZlcnRUYWJsZUlwQWRkcmVzc1JvdXRlMiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcxLjEuMS4zIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBBZGRyZXNzQ29udmVydFRhYmxlSXBBZGRyZXNzUm91dGUzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzEuMS4xLjQiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcEFkZHJlc3NDb252ZXJ0VGFibGVJcEFkZHJlc3NSb3V0ZTQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3MS4xLjEuNSIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwQWRkcmVzc0NvbnZlcnRUYWJsZUlwQWRkcmVzc1JvdXRlNSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcxLjEuMS42Iiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBBZGRyZXNzQ29udmVydFRhYmxlSXBBZGRyZXNzUm91dGU2Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzEuMS4xLjciLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi42IiwibmFtZSI6ImlwQWRkcmVzc0NvbnZlcnRUYWJsZU5vZGVJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcxLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzEiLCJuYW1lIjoiSXBBZGRyZXNzQ29udmVydEZvclByaXZhdGVOV092ZXJJUCIsIm51bWJlciI6IjY3MSJ9LCI2NzJOb2RlSWREZXRhaWxJbmZvcm1hdGlvbkZvclByaXZhdGVOV092ZXJJUCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb0lwUHJvdG9jb2xUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvRFRNRlRyYW5zbGF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjYiLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb05vZGVJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb1ZvaWNlUGFja2V0Q29uZmlnVGFibGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvQ2hhbm5lbE5lZ290aWF0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvQXVkaW9Db2RlYyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS43Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb1RDUENvbm5lY3Rpb25SZWxlYXNlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjksImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41IiwibmFtZSI6Im5vZGVJZERldGFpbEluZm9FOTExUHJpb3JpdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3Mi4xLjEuOSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb0Zhc3RDb25uZWN0aW9uUHJvY2VkdXJlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibm9kZUlkRGV0YWlsSW5mb1QzOFByb3RvY29sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjEwIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJub2RlSWREZXRhaWxJbmZvVDM4VGFibGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im5vZGVJZERldGFpbEluZm9UMzhTdWJzdGl0dXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3Mi4xLjEuMTIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIiLCJuYW1lIjoiTm9kZUlkRGV0YWlsSW5mb3JtYXRpb25Gb3JQcml2YXRlTldPdmVySVAiLCJudW1iZXIiOiI2NzIifSwiNjczTm9kZUlkQ2hlY2tBbmREZWxldGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImNoZWNrRGVsZXRlTm9kZUlkU3RhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3My4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJjaGVja0RlbGV0ZU5vZGVJZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjczLjEuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzMiLCJuYW1lIjoiTm9kZUlkQ2hlY2tBbmREZWxldGUiLCJudW1iZXIiOiI2NzMifSwiNjc0UmVtb3RlTm9kZUlwdUlwQWRkcmVzcyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi42IiwibmFtZSI6InJlbW90ZU5vZGVJcHVOb2RlSWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3NC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyZW1vdGVOb2RlSXB1SXBBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzQuMS4xLjIiLCJzeW50YXgiOiJJcEFkZHJlc3MifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjc0IiwibmFtZSI6IlJlbW90ZU5vZGVJcHVJcEFkZHJlc3MiLCJudW1iZXIiOiI2NzQifSwiODAxTEFOIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjEyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAiLCJuYW1lIjoibGFuV3JpdGVSZXRyeUNvdW50ZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMTIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3MxIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3MyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3MzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjgiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJsYW5JcEFkZHJlc3M0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNCIsIm5hbWUiOiJsYW5Qb3J0TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxhbkNvbm5lY3Rpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImxhbkVtcGxveW1lbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTAsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NTUzNSIsIm5hbWUiOiJsYW5DbGllbnRQb3J0Tm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjY1NTM1IiwibmFtZSI6ImxhblBvcnRObyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAxLjEuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsYW5TeW5jaHJvbml6YXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMS4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMCIsIm5hbWUiOiJsYW5SZWFkUmV0cnlDb3VudGVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjExIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGFuQ2FsbGVyTmFtZVNldCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAxLjEuMS4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMSIsIm5hbWUiOiJMQU4iLCJudW1iZXIiOiI4MDEifSwiODAzSU9Mb2dpY2FsRGV2aWNlIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNCIsIm5hbWUiOiJpb1BvcnROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwMy4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIzIiwibmFtZSI6ImlvTG9naWNhbERldmljZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAzLjEuMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaW9QaHlzaWNhbERldmljZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAzLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAzIiwibmFtZSI6IklPTG9naWNhbERldmljZSIsIm51bWJlciI6IjgwMyJ9LCI4MDRSUzIzMkMiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InJzMjMyY1Bhcml0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicnMyMzJjQmF1ZFJhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwNC4xLjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi40IiwibmFtZSI6InJzMjMyY1BoeXNpY2FsUG9ydE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyczIzMmNEYXRhTGVuZ3RoIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyczIzMmNGbG93Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo2LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InJzMjMyY01heFdhaXRUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDQiLCJuYW1lIjoiUlMyMzJDIiwibnVtYmVyIjoiODA0In0sIjkxOUFsYXJtQ29udHJvbEZvclN5c3RlbSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InN5c3RlbUxhYmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi4xMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicmVzZXRDdXJyZW50QWxhcm1TdW1tYXJ5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi45Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYWxhcm1TdW1tYXJ5VHJhcEF2YWlsYWJpbGl0eSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjYuMTEuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42IiwibmFtZSI6IkFsYXJtQ29udHJvbEZvclN5c3RlbSIsIm51bWJlciI6IjkxOSJ9LCI5MjBBbGFybUNvbnRyb2xGb3JTbG90Ijp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjQiLCJuYW1lIjoiYWxhcm1QZXJjZXB0aW9uRXF1aXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjguMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYWxhcm1QZXJjZXB0aW9uQXZhaWxhYmlsaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi44LjEuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjgiLCJuYW1lIjoiQWxhcm1Db250cm9sRm9yU2xvdCIsIm51bWJlciI6IjkyMCJ9LCI5MjFUcmFmZmljTWVhc3VyZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZURpZElsZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlRGlkQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjMuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi43IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlRGlkRGlkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4zLjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vRGlkSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi40LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlTm9EaWRPck5vdERldGVybWluZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuNC4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vRGlkQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjQuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVJbGdBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMS4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6InRyYWZmaWNNZWFzdXJlSWxnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVPbGdBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMi4xLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6InRyYWZmaWNNZWFzdXJlT2xnIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4yLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTFBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vbldvcmtpbmdEYXlab25lMkFjdGl2YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlTm9uV29ya2luZ0RheVpvbmUzQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE5Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVNZW1vcnlDYXJkT3V0cHV0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVIb2xpZGF5Wm9uZTFTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMlN0YXJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yNiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlSG9saWRheVpvbmUzU3RhcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjI5Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVXb3JraW5nRGF5Wm9uZTFFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjYiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVdvcmtpbmdEYXlab25lMkVuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuOSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlV29ya2luZ0RheVpvbmUzRW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4xMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUNvbmZlcmVuY2VBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMzMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMUFjdGl2YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlSG9saWRheVpvbmUyQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjI1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVIb2xpZGF5Wm9uZTNBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjgiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVdvcmtpbmdEYXlab25lMVN0YXJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVXb3JraW5nRGF5Wm9uZTJTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuOCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlV29ya2luZ0RheVpvbmUzU3RhcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjExIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTFFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE1Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTJFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE4Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTNFbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjIxIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVEdG1mQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjMyIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVRlbmFudE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY01lYXN1cmVXb3JraW5nRGF5Wm9uZTFBY3RpdmF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlV29ya2luZ0RheVpvbmUyQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjciLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZVdvcmtpbmdEYXlab25lM0FjdGl2YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40IiwibmFtZSI6InRyYWZmaWNNZWFzdXJlTm9uV29ya2luZ0RheVpvbmUxU3RhcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjE0Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQiLCJuYW1lIjoidHJhZmZpY01lYXN1cmVOb25Xb3JraW5nRGF5Wm9uZTJTdGFydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTciLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZU5vbldvcmtpbmdEYXlab25lM1N0YXJ0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yMCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlSW50ZW5zaXR5VW5pdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMzEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMUVuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lMkVuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMjciLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUhvbGlkYXlab25lM0VuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMzAiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTEwMCIsIm5hbWUiOiJ0cmFmZmljTWVhc3VyZUh1bnRpbmdHcm91cCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuNS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNNZWFzdXJlSHVudGluZ0dyb3VwQWN0aXZhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjUuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjIuMyIsIm5hbWUiOiJUcmFmZmljTWVhc3VyZSIsIm51bWJlciI6IjkyMSJ9LCI5MjJUcmFmZmljUmVwb3J0Q29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoidHJhZmZpY1JlcG9ydExhc3REYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjIiLCJuYW1lIjoidHJhZmZpY1JlcG9ydExhc3RUaW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMy41Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidHJhZmZpY1JlcG9ydEZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMy4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjYiLCJuYW1lIjoidHJhZmZpY1JlcG9ydEZpcnN0RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIyIiwibmFtZSI6InRyYWZmaWNSZXBvcnRGaXJzdFRpbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRyYWZmaWNSZXBvcnRTdGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjMuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4zIiwibmFtZSI6IlRyYWZmaWNSZXBvcnRDb250cm9sIiwibnVtYmVyIjoiOTIyIn0sIkNhU25tcFJlZyI6eyJmaWVsZHMiOltdLCJncm91cF9vaWQiOm51bGwsIm5hbWUiOiJDYVNubXBSZWciLCJudW1iZXIiOm51bGx9LCJNSVBVVlBDb25maWciOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZQQ29uZmlnRGF0YUZvclN5c3RlbSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJtaXB1VlBDb25maWdWZXJzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZwQ29uZmlnRGF0YUZvckVhY2hEZXZpY2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjkuMi4xLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xOSIsIm5hbWUiOiJtaXB1RGVzdERldmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4yLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNSIsIm5hbWUiOiJtaXB1U3JjRGV2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjIuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZQQ29uZmlnRGF0YUZvclN5c3RlbSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiNCIsIm5hbWUiOiJtaXB1VlBDb25maWdWZXJzaW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWlwdVZwQ29uZmlnRGF0YUZvckVhY2hEZXZpY2UiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjkuMi4xLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xOSIsIm5hbWUiOiJtaXB1RGVzdERldmljZU51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOS4yLjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uNSIsIm5hbWUiOiJtaXB1U3JjRGV2aWNlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy45LjIuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjkuMSIsIm5hbWUiOiJNSVBVVlBDb25maWciLCJudW1iZXIiOm51bGx9LCJQZXJzb25hbEFkbWluIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOjYsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQnVzeU5vQW5zd2VyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjYiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEwLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkV4dENhbGxDRkJ1c3lOb0Fuc3dlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xMCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZBbGxTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5FeHRDYWxsQ0ZBbGxTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZCdXN5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjgsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGQnVzeVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS44Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkRuZFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGTm9BbnN3ZXJEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjE3Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjE5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiOC4uNjAiLCJuYW1lIjoicGVyc29uYWxBZG1pbkFueUNhbGxDRk5vQW5zd2VyVGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiI4Li42MCIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGTm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGTm9BbnN3ZXJEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjEzIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoicGVyc29uYWxBZG1pbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZOb0Fuc3dlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS41Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo5LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkV4dENhbGxDRk5vQW5zd2VyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIzLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6InBlcnNvbmFsQWRtaW5DYWxsSGlzdG9yeVJlY29yZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxOCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGQnVzeU5vQW5zd2VyRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xOCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQWxsRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluRXh0Q2FsbENGQWxsRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjguLjYwIiwibmFtZSI6InBlcnNvbmFsQWRtaW5BbnlDYWxsQ0ZCdXN5Tm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyMiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjguLjYwIiwibmFtZSI6InBlcnNvbmFsQWRtaW5FeHRDYWxsQ0ZCdXN5Tm9BbnN3ZXJUaW1lciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxNCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQnVzeU5vQW5zd2VyRGVzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4xNCIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxMiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQW55Q2FsbENGQnVzeURlc3QiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMTIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MTYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoicGVyc29uYWxBZG1pbkV4dENhbGxDRkJ1c3lEZXN0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjE2Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoicGVyc29uYWxBZG1pbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjUsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5TGF0ZXN0Q2FsbGVyTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yNSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMCIsIm5hbWUiOiJwZXJzb25hbEFkbWluQ2FsbEhpc3RvcnlMYXRlc3RDYWxsZXJOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjYsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5TGF0ZXN0VGVybWluYXRlRGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yNiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyNywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InBlcnNvbmFsQWRtaW5DYWxsSGlzdG9yeUxhdGVzdFRlcm1pbmF0ZVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJwZXJzb25hbEFkbWluRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyOSwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJwZXJzb25hbEFkbWluQ2FsbEhpc3RvcnlQcmV2aW91c0NhbGxlck5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMjkiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MjgsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjAiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5UHJldmlvdXNDYWxsZXJOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMjgiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MzAsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTYiLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5UHJldmlvdXNUZXJtaW5hdGVEYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjMwIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMxLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoicGVyc29uYWxBZG1pbkNhbGxIaXN0b3J5UHJldmlvdXNUZXJtaW5hdGVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuMzEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQiLCJuYW1lIjoiUGVyc29uYWxBZG1pbiIsIm51bWJlciI6bnVsbH0sImFsYXJtIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImFsYXJtU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InJlc3RhcnRSZWFzb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NiIsIm5hbWUiOiJyZWFzb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjIuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InJlYXNvbk5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjIuMi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjU2IiwibmFtZSI6InJlYXNvbkluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi4yLjIuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiYWxhcm1UaW1lU3RhbXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi42LjIuMi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNiIsIm5hbWUiOiJhbGFybSIsIm51bWJlciI6bnVsbH0sImJhY2t1cERhdGEiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiYmFja3VwU3RhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjcuMiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTA0ODU3NiIsIm5hbWUiOiJjdXJyZW50RGF0YSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNy4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJiYWNrdXBGdW5jdGlvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNy4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMDQ4NTc2IiwibmFtZSI6ImFsbERhdGEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjcuNCIsInN5bnRheCI6IklOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNyIsIm5hbWUiOiJiYWNrdXBEYXRhIiwibnVtYmVyIjpudWxsfSwiY29tbXVuaXR5TmFtZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMiIsIm5hbWUiOiJjbW5NYW5hZ2VFbXB0eVN0YXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNubXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjMiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoic25tcEFkbWluTGV2ZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzbm1wUHJpdmlsZWdlcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMS4yLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJzbm1wQ29tbXVuaXR5SUQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoic25tcENvbW11bml0eU5hbWUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xIiwibmFtZSI6ImNvbW11bml0eU5hbWUiLCJudW1iZXIiOm51bGx9LCJjb21wb25lbnQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtYWluQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6Im1haW5DcHVDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNpcFRydW5rQ3BuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4yMS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2lwVHJ1bmtDcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua0NwblNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4yMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFRydW5rQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwVHJ1bmtDcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpcFN0YXRpb25DcG5EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTguMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE4LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiYmFja3VwTWVtb3J5Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImJhY2t1cE1lbW9yeVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMiIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJnZW5lcmFsTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImdlbmVyYWxNZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOSIsIm5hbWUiOiJkMUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQxQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkMUMySXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMUMySXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkMUMySXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMklwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMlBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMyUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUzU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1NFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU0Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkNEMxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIyMCIsIm5hbWUiOiJkNEMySXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkNEMySXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yMjAiLCJuYW1lIjoiZDVDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDVDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ1QzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDVDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ1QzJJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNUMySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImQ1QzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMklwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDVDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ1QzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNUMyUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDVDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDVDMlBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuNC42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1NkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU2U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzFJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImQ2QzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQ2QzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNkMxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ2QzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMjIwIiwibmFtZSI6ImQ2QzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDZDMklwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguNC44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQ2QzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNkMySXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDZDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ2QzJQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ2QzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJsYW5Db250cm9sbGVyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImxhbkNvbnRyb2xsZXJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJjdGlTZXJ2ZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4zLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImN0aVNlcnZlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4zLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY3RpU2VydmVyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4zLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJjb29saW5nRmFuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIwLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImNvb2xpbmdGYW5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIwLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21hcnRNZWRpYVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWFydE1lZGlhQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InByb2dyYW1NZW1vcnlTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicHJvZ3JhbU1lbW9yeUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzZXJpYWxTdWJDcHVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTAuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU3ViQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoic21kaVZtc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjMuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21kaVZtc1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC4zLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21kaVZtc0NvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTAuMy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNlcmlhbFNtZHJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtb2RlbVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtb2RlbUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwY21TdWJDcHVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwY21TdWJDcHVDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEiLCJuYW1lIjoiY29tcG9uZW50IiwibnVtYmVyIjpudWxsfSwiY29tcG9uZW50X0NfRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNpcFRydW5rQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoic2lwVHJ1bmtDcG5TZXJ2aWNlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBUcnVua0NwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImlwVHJ1bmtDcG5DaEdyb3VwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImlwU3RhdGlvbkNwbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEuMSIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwU3RhdGlvbkNwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOSIsIm5hbWUiOiJkMUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQxQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDFDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDNDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDNDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDNDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDRDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDRDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMSIsIm5hbWUiOiJjb21wb25lbnRfQ19EIiwibnVtYmVyIjpudWxsfSwiY29tcG9uZW50X0QiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtYWluQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6Im1haW5DcHVDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNpcFRydW5rQ3BuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2lwVHJ1bmtDcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua0NwblNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFRydW5rQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwVHJ1bmtDcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpcFN0YXRpb25DcG5EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJpcFN0YXRpb25DcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiYmFja3VwTWVtb3J5Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImJhY2t1cE1lbW9yeVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMS4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMiIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE1LjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJuZXR3b3JrQ2xvY2tTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTUuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJnZW5lcmFsTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImdlbmVyYWxNZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEwLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOSIsIm5hbWUiOiJkMUMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQxQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkMUMySXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMUMySXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkMUMySXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMklwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMlBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMyUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUzU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQ2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQzQzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQzQzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1NFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU0Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNENhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkNEMxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDRDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibGFuQ29udHJvbGxlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJsYW5Db250cm9sbGVyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiY3RpU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJjdGlTZXJ2ZXJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImN0aVNlcnZlckNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY29vbGluZ0ZhblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJjb29saW5nRmFuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNtYXJ0TWVkaWFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21hcnRNZWRpYUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwcm9ncmFtTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicHJvZ3JhbU1lbW9yeUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNlcmlhbFN1YkNwdVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNlcmlhbFN1YkNwdUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoic21kaVZtc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWRpVm1zU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InNtZGlWbXNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kckNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTIuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicGNtU3ViQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjcuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoicGNtU3ViQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xIiwibmFtZSI6ImNvbXBvbmVudF9EIiwibnVtYmVyIjpudWxsfSwiY29tcG9uZW50X1BfRCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJiYWNrdXBNZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjExLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiYmFja3VwTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjExLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImNvb2xpbmdGYW5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE4LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY29vbGluZ0ZhblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiY3RpU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTQuMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY3RpU2VydmVyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4zLjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi44IiwibmFtZSI6ImN0aVNlcnZlckluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE0LjMuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiY3RpU2VydmVyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE0LjMuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkMUMxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQxQzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi45IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoiZDFDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDFDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDFDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQxQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDFDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjkiLCJuYW1lIjoiZDFDMUlmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQxU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUMySWZDYXJkR3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQxQzJJZkNhcmRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDFDMklmQ2FyZE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjQuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMUNhYmluZXQyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjMuNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDJDMUlwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxSXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDJDMUlwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMVBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzFQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjMuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMxUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQyQzJJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQyQzJJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQyQzJJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkMkMySXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMyUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMlBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS40LjQuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQzJJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDJDMklmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkMkMySWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQyQ2FiaW5ldDJTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC40LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMUlwVHJ1bmtHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy44LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJkM0MxSXBUcnVua0NoR3JwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy44LjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFJcFRydW5rU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy44LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJkM0MxSXBTdGF0aW9uRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjcuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlwU3RhdGlvblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNy4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxUG9ydEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMVBvcnRHcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMy42LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzFQb3J0R3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjYuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJcFRydW5rR3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiZDNDMklwVHJ1bmtDaEdycCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySXBUcnVua1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuOC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiZDNDMklwU3RhdGlvbkRuIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC43LjEuMiIsInN5bnRheCI6IkRpc3BsYXlTdHJpbmcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQzQzJJcFN0YXRpb25TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjcuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMlBvcnRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJQb3J0R3JvdXBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MyUG9ydEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMUlmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MxSWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzFJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDMklmQ2FyZEdyb3VwQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkM0MySWZDYXJkR3JvdXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQzQzJJZkNhcmROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNS40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDNDYWJpbmV0MlN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSXBUcnVua0dyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjguMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6ImQ0QzFJcFRydW5rQ2hHcnAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjguMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlwVHJ1bmtTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImQ0QzFJcFN0YXRpb25Hcm91cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy43LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5Ijp0cnVlLCJsZW4iOiIwLi41IiwibmFtZSI6ImQ0QzFJcFN0YXRpb25EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNy4xLjIiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkNEMxSXBTdGF0aW9uU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy43LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFQb3J0R3JvdXBDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy42LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxUG9ydEdyb3VwSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjYuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMVBvcnRHcm91cFN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjMuNi4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0QzFJZkNhcmRHcm91cENvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZDRDMUlmQ2FyZEdyb3VwU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJkNEMxSWZDYXJkTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy41Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDFDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjYuMy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImQ0Q2FiaW5ldDFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4zLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUxQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4zLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTFTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMy4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1MkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHUyU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTNDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjUuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJkaHd5U3ViQ3B1M1N0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS41LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImRod3lTdWJDcHU0Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS42LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiZGh3eVN1YkNwdTRTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNi4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJnZW5lcmFsTWVtb3J5Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xMC4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImdlbmVyYWxNZW1vcnlTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTAuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6dHJ1ZSwibGVuIjoiMC4uNSIsIm5hbWUiOiJpcFN0YXRpb25DcG5EbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjEiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBTdGF0aW9uQ3BuQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOnRydWUsImxlbiI6IjAuLjUiLCJuYW1lIjoiaXBTdGF0aW9uQ3BuRG4iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTYuMS4xIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBTdGF0aW9uQ3BuU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE2LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImlwVHJ1bmtDcG5Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE3LjEuMyIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMjgiLCJuYW1lIjoiaXBUcnVua0NwbkNoR3JvdXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTcuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoiaXBUcnVua0NwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTI4IiwibmFtZSI6InNpcFRydW5rQ3BuU2VydmljZUluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE5LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzaXBUcnVua0NwbkNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTkuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyOCIsIm5hbWUiOiJzaXBUcnVua0NwblNlcnZpY2VJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzaXBUcnVua0NwblN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xOS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6ImxhbkNvbnRyb2xsZXJDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE0LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibGFuQ29udHJvbGxlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJtYWluQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6Im1haW5DcHVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1Db250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEyLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibW9kZW1TdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTIuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoibmV0d29ya0Nsb2NrQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS4xNS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoibmV0d29ya0Nsb2NrU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjE1LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InBjbVN1YkNwdUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuNy4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InBjbVN1YkNwdVN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS43LjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzg0IiwibmFtZSI6InByb2dyYW1NZW1vcnlDb250cm9sIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJwcm9ncmFtTWVtb3J5U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjkuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kckNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC40LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU21kclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjQuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU3ViQ3B1Q29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic2VyaWFsU3ViQ3B1U3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zODQiLCJuYW1lIjoic21hcnRNZWRpYUNvbnRyb2wiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuMTMuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWFydE1lZGlhU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjEzLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uOCIsIm5hbWUiOiJzbWRpVm1zSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi40LjEuOC4zLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWRpVm1zQ29udHJvbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjQuMS44LjMuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjgiLCJuYW1lIjoic21kaVZtc0luZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjM4NCIsIm5hbWUiOiJzbWRpVm1zU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjguMy4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNC4xLjExIiwibmFtZSI6ImNvbXBvbmVudF9QX0QiLCJudW1iZXIiOm51bGx9LCJjb25maWRlbnRpYWxDb250cm9sIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiY2hhbGxlbmdlU3RyaW5nIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOC4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjgiLCJuYW1lIjoiY29uZmlkZW50aWFsQ29udHJvbCIsIm51bWJlciI6bnVsbH0sImNvbmZsaWN0Q29udHJvbCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJjb25mbGljdFNlY3VyaXR5SW5mbyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEuMS4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJjb25mbGljdFR5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY29uZmxpY3RTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4yIiwibmFtZSI6ImNvbmZsaWN0R3JvdXBOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMSIsIm5hbWUiOiJjb25mbGljdENvbnRyb2wiLCJudW1iZXIiOm51bGx9LCJkb3NDb21tYW5kIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJkb3NPcGVyYXRpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjQuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoianVkZ2VPZkNvbXBsZXRpb25Eb3NDb21tYW5kIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy40LjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy40IiwibmFtZSI6ImRvc0NvbW1hbmQiLCJudW1iZXIiOm51bGx9LCJlcnJvckFsYXJtTG9nIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NCIsIm5hbWUiOiJleHBhbmRMb2dNYW5hZ2VtZW50SW5mbyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjQiLCJuYW1lIjoibG9nTWFuYWdlbWVudEluZm8iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NiwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJrZXlPcmdDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuNiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEwLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQwOTYiLCJuYW1lIjoic2VhcmNoTmV4dCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjEwIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOjksImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDA5NiIsIm5hbWUiOiJzZWFyY2hGaXJzdCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjkiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjUsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi45OTk5OTk5OTkiLCJuYW1lIjoia2V5RXJyb3JDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoxLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjEyIiwibmFtZSI6ImtleVN0YXJ0RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjEiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjcsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMDAwIiwibmFtZSI6InNlYXJjaE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjk5IiwibmFtZSI6ImtleUVuZFJhbmtDb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uOTkiLCJuYW1lIjoia2V5U3RhcnRSYW5rQ29kZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMS4xLjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6OCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoic2VhcmNoUmVzdWx0TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4xLjEuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjEyIiwibmFtZSI6ImtleUVuZERhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjEuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMSIsIm5hbWUiOiJlcnJvckFsYXJtTG9nIiwibnVtYmVyIjpudWxsfSwiZXJyb3JTdGF0dXMiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDI5NDk2NzI5NSIsIm5hbWUiOiJlcnJvckNvZGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4yLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4yIiwibmFtZSI6ImVycm9yU3RhdHVzIiwibnVtYmVyIjpudWxsfSwiZXZlbnRUcmFjZSI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiY2hhbmdlU2lkZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjIuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoianVkZ2VPZkNvbXBsZXRpb25DaGFuZ2VTaWRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjEuMi4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibWVzc2FnZVRyYWNlQ2F0ZWdvcnkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtZXNzYWdlVHJhY2VTdGFydFN0b3AiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMS4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoibWVzc2FnZVRyYWNlU2l6ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJqdWRnZU9mQ29tcGxldGlvbk1lc3NhZ2VUcmFjZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjEuNCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlzZG5UcnVua0FsbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjMuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOm51bGwsIm5hbWUiOiJldmVudFRyYWNlUG9ydFRyYWNlS2luZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4yLjEuMS40Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZXZlbnRUcmFjZVBvcnRUcmFjZUxldmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjIuMS4xLjUiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiZXZlbnRUcmFjZVBvcnRTbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjIuMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJldmVudFRyYWNlUG9ydFBvcnROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMi4xLjEuMyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyIiwibmFtZSI6ImV2ZW50VHJhY2VQb3J0Q2FiaW5ldE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4yLjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjEuMiIsIm5hbWUiOiJldmVudFRyYWNlIiwibnVtYmVyIjpudWxsfSwiZmlsZURhdGUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6ImVyckFsbU5tbEZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6ImVyckFsbUV4cEZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6ImRrdEFkbUZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjciLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwIiwibmFtZSI6InNucEFkbUZpbGVEYXRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMDAiLCJuYW1lIjoiZXJyQWxtTm1sRmlsZURhdGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC4yLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbU5tbEZpbGVOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjIuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbU5tbENyZWF0ZURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuMi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiZXJyQWxtTm1sTW9kaWZ5RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC4yLjEuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMDAiLCJuYW1lIjoiZXJyQWxtRXhwRmlsZURhdGVJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC40LjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbUV4cEZpbGVOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjQuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImVyckFsbUV4cENyZWF0ZURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuNC4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoiZXJyQWxtRXhwTW9kaWZ5RGF0ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC40LjEuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJka3RBZG1GaWxlTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC44LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJka3RBZG1DcmVhdGVEYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjguMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImRrdEFkbU1vZGlmeURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuOC4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAwIiwibmFtZSI6ImRrdEFkbUZpbGVEYXRlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuOC4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJzbnBBZG1GaWxlTmFtZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuNC42LjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJzbnBBZG1DcmVhdGVEYXRlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS40LjYuMS4zIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InNucEFkbU1vZGlmeURhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuNi4xLjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAwIiwibmFtZSI6InNucEFkbUZpbGVEYXRlSW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQuNi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjQiLCJuYW1lIjoiZmlsZURhdGUiLCJudW1iZXIiOm51bGx9LCJmbGFzaE1lbW9yeVRlc3QiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDI5NDk2NzI5NSIsIm5hbWUiOiJhY3RUZXN0RGF0YVJlYWQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEwLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InNieVRlc3REYXRhV3JpdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEwLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMCIsIm5hbWUiOiJmbGFzaE1lbW9yeVRlc3QiLCJudW1iZXIiOm51bGx9LCJpcHVGaWxlVHJhbnNmZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTk5IiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjo0LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNvbW1hbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyU2xvdE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyIiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNhYmluZXROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNvbW1hbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjMiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MiwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyU2xvdE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEyIiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlckNhYmluZXROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjo1LCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTk5IiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlclN0YXR1cyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOjIsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjEwIiwibmFtZSI6ImlwdUZpbGVUcmFuc2ZlclNsb3ROdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMS4xLjIiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMiIsIm5hbWUiOiJpcHVGaWxlVHJhbnNmZXJDYWJpbmV0TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjEuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJpcHVGaWxlVHJhbnNmZXJTZXJ2ZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjozLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyQ29tbWFuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoyLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJpcHVGaWxlVHJhbnNmZXJTbG90TnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjEuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyQ2FiaW5ldE51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjIxMiIsIm5hbWUiOiJpcHVGaWxlU2VydmVyVXJsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS40Iiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaXB1RmlsZVNlcnZlclBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS4zIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoiaXB1RmlsZVNlcnZlclVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS4yIiwic3ludGF4IjoiRGlzcGxheVN0cmluZyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjoiMS4uMTAiLCJuYW1lIjoiaXB1RmlsZVNlcnZlckluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44LjIuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjEyIiwibmFtZSI6ImlwdUZpbGVTZXJ2ZXJVcmwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMi4xLjQiLCJzeW50YXgiOiJEaXNwbGF5U3RyaW5nIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi4xMCIsIm5hbWUiOiJpcHVGaWxlU2VydmVySW5kZXgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjguMi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgiLCJuYW1lIjoiaXB1RmlsZVRyYW5zZmVyIiwibnVtYmVyIjpudWxsfSwibGljZW5zZUNvbnRyb2wiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTE1MiIsIm5hbWUiOiJsaWNlbnNlVXNlZFBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC42LjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwMCIsIm5hbWUiOiJsaWNlbnNlVXNlZElwUG9ydCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjYuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMiIsIm5hbWUiOiJsaWNlbnNlVXNlZEJWTVVDaGFubmVsIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuNi4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjE1OTIiLCJuYW1lIjoibGljZW5zZVVzZWRRU0lHQ2hhbm5lbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjYuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi40NDAiLCJuYW1lIjoibGljZW5zZVVzZWRTSVBUcnVua0NoYW5uZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC42LjUiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTUyIiwibmFtZSI6ImxpY2Vuc2VVc2VkRFA1MDIyU0RNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuNi42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaWNlbnNlQ29tbWFuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjUuMSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMTAwMCIsIm5hbWUiOiJ2YWxpZE51bWJlckNhbGxBZ2VudCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoidmFsaWROdW1iZXJMVk1VQ2hhbm5lbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDQwIiwibmFtZSI6InZhbGlkTnVtYmVyUVNJR0NoYW5uZWwiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjI1Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjQ0MCIsIm5hbWUiOiJ2YWxpZE51bWJlclNJUFRydW5rQ2hhbm5lbCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMjYiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOTUyIiwibmFtZSI6InZhbGlkTnVtYmVyRFA1MDIyU0RNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4yNyIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2YWxpZEJhc2ljTmV0d29ya2luZyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMTQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMDAiLCJuYW1lIjoidmFsaWROdW1iZXJTb2Z0cGhvbmUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIxIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkVHJhbnNmZXJEaXJlY3RWTSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNCIsIm5hbWUiOiJ2YWxpZE51bWJlclNlcmlhbFBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjEwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkU01ESXBsdXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkUHJpdmF0ZU5ldHdvcmtpbmciLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjE1Iiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoidmFsaWRIYXJkd2FyZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMTkiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNDgiLCJuYW1lIjoidmFsaWROdW1iZXJEUkVDIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xMSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi45IiwibmFtZSI6InZhbGlkTnVtYmVyQ1NUQSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2YWxpZENvbmZpZ1R5cGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjExNTIiLCJuYW1lIjoidmFsaWROdW1iZXJQb3J0Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ2YWxpZEFDRCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzIiLCJuYW1lIjoidmFsaWRBQlIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIwIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjEwMDAiLCJuYW1lIjoidmFsaWROdW1iZXJJcFBvcnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkTUlTIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidmFsaWRBY2MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjkiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkU01ESSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidmFsaWRDZW50cmFsaXplZFZNIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMzAwIiwibmFtZSI6InZhbGlkTnVtYmVyQUNEQWdlbnQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjEyIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIxIiwibmFtZSI6InZhbGlkVXBkYXRlVmVyc2lvbiIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNiIsIm5hbWUiOiJ2YWxpZFBDQVRUIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InZhbGlkQ2VudHJhbGl6ZWRTTURSIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGljZW5zZVRyYXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4xLjUiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsaWNlbnNlU3RhdHVzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMS4zIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoibGljZW5zZUZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMS4yIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjQiLCJuYW1lIjoibGljZW5zZURlbGF5VGltZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4xLjQiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTYiLCJuYW1lIjoibGljZW5zZVN0cmluZ0ZpZWxkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMS42Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjEwIiwibmFtZSI6ImxpY2Vuc2VPcmRlck51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjEuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4xMjgiLCJuYW1lIjoibGljZW5zZUNvZGVEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMi4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjYiLCJuYW1lIjoibGljZW5zZUNvbnRyb2wiLCJudW1iZXIiOm51bGx9LCJtYWNBZGRyZXNzIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoibWFjQWRkcmVzc0RhdGEiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjkuMSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjkiLCJuYW1lIjoibWFjQWRkcmVzcyIsIm51bWJlciI6bnVsbH0sIm1lbW9yeUFjY2VzcyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJtZW1vcnlEYXRhIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41LjQiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4yNTYiLCJuYW1lIjoibWVtb3J5U2l6ZSIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IkdhdWdlMzIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJtZW1vcnlBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41LjIiLCJzeW50YXgiOiJHYXVnZTMyIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6Im1lbW9yeUZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41LjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy41IiwibmFtZSI6Im1lbW9yeUFjY2VzcyIsIm51bWJlciI6bnVsbH0sIm1pZGRsZXdhcmUiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6NCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiaXBSb3V0aW5nTmV4dEhvc3RBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjIuMS4xLjQiLCJzeW50YXgiOiJJcEFkZHJlc3MifSx7ImFjY2VzcyI6InIiLCJjb2wiOjEsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBSb3V0aW5nTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjIuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6NSwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjIiLCJuYW1lIjoiaXBSb3V0aW5nSUZOdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMi4xLjEuNSIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjoyLCJlbmMiOiJJcEFkZHJlc3MiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJpcFJvdXRpbmdJUEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMi4xLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImlwUm91dGluZ1N1Yk5ldE1hc2siLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMi4xLjEuMyIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjIsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImZ0cFVzZXJOYW1lIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjMuMS4xLjIiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjMsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImZ0cFBhc3N3b3JkIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjMuMS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOjQsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6ImZ0cEhvbWVEaXJlY3RvcnkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMy4xLjEuNCIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJyIiwiY29sIjoxLCJlbmMiOiJJTlRFR0VSIiwia2V5Ijp0cnVlLCJsZW4iOiIxLi40IiwibmFtZSI6ImZ0cEluZGV4Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjMuMS4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGNwSXBJcEFkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMS4xIiwic3ludGF4IjoiSXBBZGRyZXNzIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSXBBZGRyZXNzIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidGNwSXBTdWJOZXRNYXNrIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yLjEuMiIsInN5bnRheCI6IklwQWRkcmVzcyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklwQWRkcmVzcyIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InRjcElwRGVmYXVsdEdhdGV3YXkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMS4zIiwic3ludGF4IjoiSXBBZGRyZXNzIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIuMiIsIm5hbWUiOiJtaWRkbGV3YXJlIiwibnVtYmVyIjpudWxsfSwicmVhZFZlcnNpb24iOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJhY3RpdmVTaWRlVmVyc2lvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMi4xIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InN0YW5kYnlTaWRlVmVyc2lvbk51bWJlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMi4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uOCIsIm5hbWUiOiJzeXN0ZW1EZXRhaWxUeXBlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4yLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4yIiwibmFtZSI6InJlYWRWZXJzaW9uIiwibnVtYmVyIjpudWxsfSwicmVnaW9uIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImN1cnJlbnRSZWdpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEyLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJyZWdpb25OdW1iZXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEyLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMiIsIm5hbWUiOiJyZWdpb24iLCJudW1iZXIiOm51bGx9LCJzZXJ2ZXJOdW1iZXIiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6MiwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJhY3RpdmVTaWRlQ2FsbGVkTnVtRGF0YVRvU2VydmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMy4xLjEuMiIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6MywiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xNiIsIm5hbWUiOiJzdGFuZGJ5U2lkZUNhbGxlZE51bURhdGFUb1NlcnZlciIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTMuMS4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6MSwiZW5jIjoiSU5URUdFUiIsImtleSI6dHJ1ZSwibGVuIjpudWxsLCJuYW1lIjoiY2FsbGVkTnVtVG9TZXJ2ZXJJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTMuMS4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMyIsIm5hbWUiOiJzZXJ2ZXJOdW1iZXIiLCJudW1iZXIiOm51bGx9LCJzZXRDYWxlbmRhciI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoiZGF5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjMxIiwibmFtZSI6ImRhdGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS4zIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJsZWFwIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEuOCIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjk5IiwibmFtZSI6InllYXIiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yMyIsIm5hbWUiOiJob3VyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEuNCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMS4uMTIiLCJuYW1lIjoibW9udGgiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS4yIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41OSIsIm5hbWUiOiJzZWNvbmQiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS42Iiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi41OSIsIm5hbWUiOiJtaW51dGUiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjMuMS41Iiwic3ludGF4IjoiSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4zLjEiLCJuYW1lIjoic2V0Q2FsZW5kYXIiLCJudW1iZXIiOm51bGx9LCJzeXN0ZW1BZG1pbkxvZyI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJqdWRnZU9mQ29tcGxldGlvblN5c3RlbUFkbWluTG9nIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4zLjIiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJzeXN0ZW1BZG1pbkxvZ1N0YXJ0U3RvcCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMy4xIiwic3ludGF4IjoiRW51bWVyYXRlZElOVEVHRVIifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMyIsIm5hbWUiOiJzeXN0ZW1BZG1pbkxvZyIsIm51bWJlciI6bnVsbH0sInN5c3RlbVJlc3RhcnQiOnsiZmllbGRzIjpbeyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6ImJvb3RNb2RlIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xLjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9XSwiZ3JvdXBfb2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xIiwibmFtZSI6InN5c3RlbVJlc3RhcnQiLCJudW1iZXIiOm51bGx9LCJ0cmFwU2VuZCI6eyJmaWVsZHMiOlt7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJ0cmFwU2VuZElQT3JnQ29tbXVuaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJ0cmFwU2VuZElQTmV3Q29tbXVuaXR5Iiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS42Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIxLi4xMSIsIm5hbWUiOiJ0cmFwU2VuZElQTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS4xIiwic3ludGF4IjoiSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ0cmFwU2VuZElQU2V0Q29tbWFuZCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkuMyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoidHJhcFNlbmRJUE9yZ0FkZHJlc3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi45LjUiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InRyYXBTZW5kSVBOZXdBZGRyZXNzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS43Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOnRydWUsImxlbiI6IjEuLjExIiwibmFtZSI6InRyYXBTZW5kSVBJbmRleCIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkuMi4xLjEiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJPQ1RFVFNUUklORyIsImtleSI6ZmFsc2UsImxlbiI6IjAuLjI1NSIsIm5hbWUiOiJ0cmFwU2VuZElQQWRkcmVzcyIsIm9pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkuMi4xLjMiLCJzeW50YXgiOiJPQ1RFVFNUUklORyJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4yNTUiLCJuYW1lIjoidHJhcFNlbmRDb21tdW5pdHkiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi45LjIuMS4yIiwic3ludGF4IjoiT0NURVRTVFJJTkcifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6Ik9DVEVUU1RSSU5HIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uMjU1IiwibmFtZSI6InRyYXBTZW5kSVBUaW1lU3RhbXAiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi45LjIuMS40Iiwic3ludGF4IjoiT0NURVRTVFJJTkcifV0sImdyb3VwX29pZCI6IjEuMy42LjEuNC4xLjE4Ni4xLjIyLjkiLCJuYW1lIjoidHJhcFNlbmQiLCJudW1iZXIiOm51bGx9LCJ1cGRhdGVwcm9ncmFtIjp7ImZpZWxkcyI6W3siYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ1cEZ1bmN0aW9uIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy42LjEiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoiciIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJjaGVja0ZpbmlzaFdyaXRlRmxhc2giLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuMTAiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6IjEuLjI1NiIsIm5hbWUiOiJ1cFRvdGFsRmlsZXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuOCIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InIiLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi42NTUzNiIsIm5hbWUiOiJ1cFRvdGFsQmxvY2tzIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy42LjMiLCJzeW50YXgiOiJJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjoiMC4uNjU1MzYiLCJuYW1lIjoidXBDb3BpZWRCbG9ja3MiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuMiIsInN5bnRheCI6IklOVEVHRVIifSx7ImFjY2VzcyI6InJ3IiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidXBBY3RpdmVTaWRlTnVtYmVyIiwib2lkIjoiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy42LjQiLCJzeW50YXgiOiJFbnVtZXJhdGVkSU5URUdFUiJ9LHsiYWNjZXNzIjoicnciLCJjb2wiOm51bGwsImVuYyI6IklOVEVHRVIiLCJrZXkiOmZhbHNlLCJsZW4iOm51bGwsIm5hbWUiOiJ1cEFjdGl2ZVNpZGVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuNSIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJyIiwiY29sIjpudWxsLCJlbmMiOiJJTlRFR0VSIiwia2V5IjpmYWxzZSwibGVuIjpudWxsLCJuYW1lIjoidXBTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuNyIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiT0NURVRTVFJJTkciLCJrZXkiOmZhbHNlLCJsZW4iOiIwLi4zMSIsIm5hbWUiOiJ1cFZlcnNpb24iLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuOSIsInN5bnRheCI6Ik9DVEVUU1RSSU5HIn0seyJhY2Nlc3MiOiJydyIsImNvbCI6bnVsbCwiZW5jIjoiSU5URUdFUiIsImtleSI6ZmFsc2UsImxlbiI6bnVsbCwibmFtZSI6InVwU3RhbmRieVNpZGVTdGF0dXMiLCJvaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuNiIsInN5bnRheCI6IkVudW1lcmF0ZWRJTlRFR0VSIn1dLCJncm91cF9vaWQiOiIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYiLCJuYW1lIjoidXBkYXRlcHJvZ3JhbSIsIm51bWJlciI6bnVsbH19").decode("utf-8")  # bundled eManager catalog
EMBEDDED_ENUM_LABELS_JSON = base64.b64decode("eyIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4yIjp7IjEiOiJsb2NrIiwiMiI6InVubG9jayJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xLjEuMS4zIjp7IjAiOiJub25lIiwiMSI6ImJvb3QiLCIyIjoiZGt0IiwiMyI6InVwZG93biIsIjQiOiJzbm1wIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjEuMiI6eyIxIjoiaXNzdWUiLCIyIjoiYWN0aXZhdGUiLCIzIjoiY2FuY2VsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjEuMyI6eyIxIjoibm90eWV0IiwiMiI6Imlzc3VlU3RhbmRieSIsIjMiOiJpc3N1ZUZpbmlzaGVkIiwiNCI6ImNhbmNlbElzc3VlIiwiNSI6ImFjdGl2YXRlU3RhbmRieSIsIjYiOiJhY3RpdmF0ZUZpbmlzaGVkIiwiNyI6ImNhbmNlbEFjdGl2YXRlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMTMiOnsiMSI6InZhbGlkIiwiMiI6ImludmFsaWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xNCI6eyIxIjoidmFsaWQiLCIyIjoiaW52YWxpZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjE1Ijp7IjEiOiJ2YWxpZCIsIjIiOiJpbnZhbGlkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuMTYiOnsiMSI6InZhbGlkIiwiMiI6ImludmFsaWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy4xNyI6eyIxIjoidmFsaWQiLCIyIjoiaW52YWxpZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjIiOnsiMSI6InNtYWxsQ29uZmlnIiwiMiI6Im1pZGRsZUNvbmZpZyIsIjMiOiJsYXJnZUNvbmZpZyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjMiOnsiMSI6InZhbGlkIiwiMiI6ImludmFsaWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy40Ijp7IjEiOiJ2YWxpZCIsIjIiOiJpbnZhbGlkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjMuNSI6eyIxIjoidmFsaWQiLCIyIjoiaW52YWxpZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMC4zLjciOnsiMSI6InZhbGlkIiwiMiI6ImludmFsaWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTAuMy45Ijp7IjEiOiJ2YWxpZCIsIjIiOiJpbnZhbGlkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjEwLjUuMSI6eyIwIjoibm9wTGljZW5zZSIsIjEiOiJpbml0TGljZW5zZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjEiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTAiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTYiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMTkiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4yOCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMS4zMSI6eyIxIjoiZXJsYW5nIiwiMiI6ImNDUyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjMyIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjMzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4xLjQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjExLjEuNyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4xLjEuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4yLjEuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi4zLjEuMyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMTEuMi40LjEuMiI6eyIxIjoibm9ESUQiLCIyIjoibm90RGV0ZXJtaW5lZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjQuMS4zIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4yLjUuMS4yIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4zLjEiOnsiMSI6InN0YXJ0IiwiMiI6ImNhbmNlbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4xMS4zLjYiOnsiMSI6ImFsbE9rIiwiMiI6InBhcnRpYWxPayIsIjMiOiJuZyIsIjQiOiJjYW5jZWwiLCI1IjoicmVwb3J0aW5nIiwiNiI6Im5vRGF0YSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEuMi4xLjQiOnsiMSI6InJlYWQiLCIyIjoid3JpdGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xLjIuMS41Ijp7IjIiOiJzdXBlclVzZXIiLCIzIjoib3JkaW5hcnlVc2VyIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAwLjEuMS4zIjp7IjEiOiJub25lIiwiMiI6ImhpZ2h3YXk4IiwiMyI6ImhpZ2h3YXkxNiIsIjQiOiJoaWdod2F5MjQiLCI1IjoiaGlnaHdheTMwIiwiNiI6ImhpZ2h3YXkzMiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMC4xLjEuNCI6eyIxIjoibm9uZSIsIjIiOiJiY2gxeDhQT1JUIiwiMyI6ImJjaDJ4OFBPUlQiLCI0IjoiYmNoMXgxNlBPUlQiLCI1IjoiYmNoMngxNlBPUlQiLCI2IjoiYmNoMXgzMlBPUlQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDAuMS4xLjUiOnsiMSI6Im5vbmUiLCIyIjoidEVJRml4ZWQiLCIzIjoic2luZ2xlVEVJIiwiNCI6InR3b1RFSXMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNi4xLjEuMiI6eyIxIjoid29ya2luZ0RheSIsIjIiOiJub24td29ya2luZ0RheSIsIjMiOiJwcml2YXRlSG9saWRheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTA2LjEuMS4zIjp7IjEiOiJ3b3JraW5nRGF5IiwiMiI6Im5vbi13b3JraW5nRGF5IiwiMyI6InByaXZhdGVIb2xpZGF5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjQiOnsiMSI6IndvcmtpbmdEYXkiLCIyIjoibm9uLXdvcmtpbmdEYXkiLCIzIjoicHJpdmF0ZUhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNi4xLjEuNSI6eyIxIjoid29ya2luZ0RheSIsIjIiOiJub24td29ya2luZ0RheSIsIjMiOiJwcml2YXRlSG9saWRheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTA2LjEuMS42Ijp7IjEiOiJ3b3JraW5nRGF5IiwiMiI6Im5vbi13b3JraW5nRGF5IiwiMyI6InByaXZhdGVIb2xpZGF5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAxMDYuMS4xLjciOnsiMSI6IndvcmtpbmdEYXkiLCIyIjoibm9uLXdvcmtpbmdEYXkiLCIzIjoicHJpdmF0ZUhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDEwNi4xLjEuOCI6eyIxIjoid29ya2luZ0RheSIsIjIiOiJub24td29ya2luZ0RheSIsIjMiOiJwcml2YXRlSG9saWRheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMTEyLjEuMS4zIjp7IjEiOiJub24tc2V0IiwiMiI6IndvcmtpbmdEYXkiLCIzIjoibm9uLXdvcmtpbmdEYXkiLCI0IjoicHJpdmF0ZUhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjEwIjp7IjEiOiJwb3NzaWJsZSIsIjIiOiJpbXBvc3NpYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4xMSI6eyIxIjoicG9zc2libGUiLCIyIjoiaW1wb3NzaWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTIiOnsiMSI6InBvc3NpYmxlIiwiMiI6ImltcG9zc2libGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjEzIjp7IjEiOiJwZXJtaXR0ZWQiLCIyIjoibm90UGVybWl0dGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4xNCI6eyIxIjoicGVybWl0dGVkIiwiMiI6Im5vdFBlcm1pdHRlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTUiOnsiMSI6InBlcm1pdHRlZCIsIjIiOiJub3RQZXJtaXR0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE2Ijp7IjEiOiJwZXJtaXR0ZWQiLCIyIjoibm90UGVybWl0dGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4xNyI6eyIxIjoicGVybWl0dGVkIiwiMiI6Im5vdFBlcm1pdHRlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMTgiOnsiMSI6InBlcm1pdHRlZCIsIjIiOiJub3RQZXJtaXR0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjE5Ijp7IjEiOiJwZXJtaXR0ZWQiLCIyIjoibm90UGVybWl0dGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjAiOnsiMSI6InBlcm1pdHRlZCIsIjIiOiJub3RQZXJtaXR0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjIxIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjIiOnsiMSI6InllcyIsIjIiOiJubyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yNSI6eyIxIjoicG9zc2libGUiLCIyIjoiaW1wb3NzaWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjYiOnsiMSI6ImFsbG93ZWQiLCIyIjoibm90QWxsb3dlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjciOnsiMSI6ImFsbG93ZWQiLCIyIjoibm90QWxsb3dlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuMjgiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4yOSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zMCI6eyIxIjoiYWxsb3dlZCIsIjIiOiJub3RBbGxvd2VkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zMSI6eyIxIjoiYWxsb3dlZCIsIjIiOiJub3RBbGxvd2VkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zMiI6eyIxIjoiYWxsb3dlZCIsIjIiOiJub3RBbGxvd2VkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zMyI6eyIxIjoibmVlZCIsIjIiOiJuby1uZWVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zNCI6eyIxIjoibmVlZCIsIjIiOiJuby1uZWVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zNSI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zNiI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zNyI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS4zOSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjQiOnsiMSI6ImFsbG93ZWQiLCIyIjoibm90QWxsb3dlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNDEiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40MiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjQzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNDQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS40NSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjQ2Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNDciOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS41Ijp7IjEiOiJhbGxvd2VkIiwiMiI6Im5vdEFsbG93ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMuMS4xLjYiOnsiMSI6ImFsbG93ZWQiLCIyIjoibm90QWxsb3dlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMy4xLjEuNyI6eyIxIjoiYWxsb3dlZCIsIjIiOiJub3RBbGxvd2VkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS44Ijp7IjEiOiJwZXJtaXR0ZWQiLCIyIjoibm90UGVybWl0dGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzLjEuMS45Ijp7IjEiOiJwZXJtaXR0ZWQiLCIyIjoibm90UGVybWl0dGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTAzMTkuMS4xLjIiOnsiMSI6Im5vbmUiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDMxOS4xLjEuNCI6eyIxIjoibm9uZSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6Im5pZ2h0QmVsbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwMzE5LjEuMS42Ijp7IjEiOiJub25lIiwiMiI6ImRpYWxpbmdEaWdpdHMiLCIzIjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjE4Ijp7IjEiOiJ0aW1lODBtc2VjIiwiMiI6InRpbWUxNjBtc2VjIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA0LjIwIjp7IjEiOiJ0aW1lMjAwbXNlYyIsIjIiOiJ0aW1lODAwbXNlYyIsIjMiOiJ0aW1lMTYwMG1zZWMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMTAiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjExIjp7IjEiOiJvcGVyYWJsZSIsIjIiOiJub3RPcGVyYWJsZUFzTklUIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE2Ijp7IjEiOiJhbGxvd2VkIiwiMiI6Im5vdEFsbG93ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMTciOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjE5Ijp7IjEiOiJkTklTIiwiMiI6ImNhbGxJRCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yIjp7IjEiOiJxdWlldFRvbmUiLCIxMCI6ImV4dGVybmFsOSIsIjExIjoiZXh0ZXJuYWwxMCIsIjEyIjoiZXh0ZXJuYWwxMSIsIjEzIjoiZXh0ZXJuYWwxMiIsIjE0IjoiZXh0ZXJuYWwxMyIsIjE1IjoiZXh0ZXJuYWwxNCIsIjE2IjoiZXh0ZXJuYWwxNSIsIjE3IjoiaW50ZXJuYWwiLCIyIjoiZXh0ZXJuYWwxIiwiMyI6ImV4dGVybmFsMiIsIjQiOiJleHRlcm5hbDMiLCI1IjoiZXh0ZXJuYWw0IiwiNiI6ImV4dGVybmFsNSIsIjciOiJleHRlcm5hbDYiLCI4IjoiZXh0ZXJuYWw3IiwiOSI6ImV4dGVybmFsOCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yMyI6eyIxIjoiYWRkIiwiMiI6Im5vdEFkZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yNSI6eyIxIjoiZFBNYWtlUmF0aW8zMyIsIjIiOiJkUE1ha2VSYXRpbzQwIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjI2Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4yOSI6eyIxIjoidW5rbm93biIsIjIiOiJpU0ROVGVsZXBob255TnVtYmVyaW5nUGxhbiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zIjp7IjEiOiJyQlQiLCIyIjoibU9IIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjMwIjp7IjEiOiJob29raW5nIiwiMiI6Im9uSG9va09mZkhvb2sifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzEiOnsiMSI6InRlcm1pbmFsIiwiMiI6ImN5Y2xpYyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS4zMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjM0Ijp7IjEiOiJub3JtYWwiLCIyIjoibUZDLVIyM0RpZ2l0cyIsIjMiOiJtRkMtUjI0RGlnaXRzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjM1Ijp7IjEiOiJhTGF3IiwiMiI6Im11TGF3In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjM2Ijp7IjEiOiJzdGFydCIsIjIiOiJzdG9wIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjM3Ijp7IjEiOiJtZWxvZHkxIiwiMiI6Im1lbG9keTIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuMzgiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjM5Ijp7IjEiOiJyaW5naW5nVHlwZTEiLCIyIjoicmluZ2luZ1R5cGUyIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQwIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS40MSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNS40NCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDUiOnsiMSI6InJpbmdpbmciLCIyIjoiaWRsZSIsIjMiOiJpZGxlRG5kT24ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDYiOnsiMSI6ImFsbCIsIjIiOiJub25lIiwiMyI6ImZvcndhcmRlZEFuZFRyYW5zZmVycmVkIiwiNCI6ImZvcndhcmRlZEFuZFJlY2FsbGVkIiwiNSI6InRyYW5zZmVycmVkQW5kUmVjYWxsZWQiLCI2IjoiZm9yd2FyZGVkIiwiNyI6InRyYW5zZmVycmVkIiwiOCI6InJlY2FsbGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA1LjQ3Ijp7IjEiOiJzeXN0ZW1EZWZhdWx0IiwiMiI6InVua25vd24iLCIzIjoiaW50ZXJuYXRpb25hbE51bWJlciIsIjQiOiJuYXRpb25hbE51bWJlciIsIjUiOiJuZXR3b3JrTnVtYmVyIiwiNiI6InN1YnNjcmliZXJOdW1iZXIiLCI3IjoiYWJicmV2aWF0ZWROdW1iZXIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNDgiOnsiMSI6InN5c3RlbURlZmF1bHQiLCIyIjoidW5rbm93biIsIjMiOiJpU0ROVGVsZXBob255TnVtYmVyaW5nUGxhbiIsIjQiOiJkYXRhTnVtYmVyaW5nUGxhbiIsIjUiOiJ0ZWxleE51bWJlcmluZ1BsYW4iLCI2IjoibmF0aW9uYWxTdGFuZGFyZE51bWJlcmluZ1BsYW4iLCI3IjoicHJpdmF0ZU51bWJlcmluZ1BsYW4ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuOCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDUuOSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDYuMSI6eyIxIjoid29ya2luZ0RheSIsIjIiOiJub24td29ya2luZ0RheSIsIjMiOiJwcml2YXRlSG9saWRheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi4yIjp7IjEiOiJ3b3JraW5nRGF5IiwiMiI6Im5vbi13b3JraW5nRGF5IiwiMyI6InByaXZhdGVIb2xpZGF5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2LjMiOnsiMSI6IndvcmtpbmdEYXkiLCIyIjoibm9uLXdvcmtpbmdEYXkiLCIzIjoicHJpdmF0ZUhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDYuNCI6eyIxIjoid29ya2luZ0RheSIsIjIiOiJub24td29ya2luZ0RheSIsIjMiOiJwcml2YXRlSG9saWRheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNi41Ijp7IjEiOiJ3b3JraW5nRGF5IiwiMiI6Im5vbi13b3JraW5nRGF5IiwiMyI6InByaXZhdGVIb2xpZGF5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA2LjYiOnsiMSI6IndvcmtpbmdEYXkiLCIyIjoibm9uLXdvcmtpbmdEYXkiLCIzIjoicHJpdmF0ZUhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDYuNyI6eyIxIjoid29ya2luZ0RheSIsIjIiOiJub24td29ya2luZ0RheSIsIjMiOiJwcml2YXRlSG9saWRheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwNy4xLjEuMyI6eyIxIjoibWludXM2REIiLCIyIjoibWludXMzREIiLCIzIjoiemVyb0RCIiwiNCI6InBsdXMzREIiLCI1IjoicGx1czZEQiIsIjYiOiJwbHVzOURCIiwiNyI6InBsdXMxMkRCIiwiOCI6InBsdXMxNURCIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjEiOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTEiOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTMiOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTUiOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTciOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMTkiOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuMiI6eyIxIjoiY29ubmVjdGVkIiwiMiI6Im5vdENvbm5lY3RlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS4yMSI6eyIxIjoiY29ubmVjdGVkIiwiMiI6Im5vdENvbm5lY3RlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS4yMyI6eyIxIjoiY29ubmVjdGVkIiwiMiI6Im5vdENvbm5lY3RlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS4zIjp7IjEiOiJjb25uZWN0ZWQiLCIyIjoibm90Q29ubmVjdGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjQiOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuNSI6eyIxIjoiY29ubmVjdGVkIiwiMiI6Im5vdENvbm5lY3RlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEwOS42Ijp7IjEiOiJjb25uZWN0ZWQiLCIyIjoibm90Q29ubmVjdGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTA5LjciOnsiMSI6ImNvbm5lY3RlZCIsIjIiOiJub3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMDkuOSI6eyIxIjoiY29ubmVjdGVkIiwiMiI6Im5vdENvbm5lY3RlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExMS4xLjEuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTIuMS4xLjIiOnsiMSI6Im5vbi1zZXQiLCIyIjoid29ya2luZ0RheSIsIjMiOiJub24td29ya2luZ0RheSIsIjQiOiJwcml2YXRlSG9saWRheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjExNC4xLjEuMyI6eyIxIjoibWludXM2REIiLCIyIjoibWludXMzREIiLCIzIjoiemVyb0RCIiwiNCI6InBsdXMzREIiLCI1IjoicGx1czZEQiIsIjYiOiJwbHVzOURCIiwiNyI6InBsdXMxMkRCIiwiOCI6InBsdXMxNURCIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTE1LjEuMS4zIjp7IjEiOiJub3RBcHBsaWNhYmxlIiwiMiI6ImRpcmVjdG9yeU51bWJlciIsIjMiOiJ0aW1lIiwiNCI6ImRhdGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMTkuMSI6eyIxIjoibm9uZSIsIjIiOiJpbml0aWFsaXplTG9ja1Bhc3N3b3JkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIwLjEuMS4yIjp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjAuMS4xLjQiOnsiMSI6Im5vRGF0YSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6Im5pZ2h0QmVsbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMC4xLjEuNiI6eyIxIjoibm9EYXRhIiwiMiI6ImRpYWxpbmdEaWdpdHMiLCIzIjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIwMC4xLjEuNCI6eyIxIjoiZEtUIiwiMiI6InNMVCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMDAuMS4xLjUiOnsiMSI6ImV4dGVuc2lvbiIsIjIiOiJ2b2ljZU1haWwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjA0LjEuMS42Ijp7IjEiOiJub24iLCIyIjoib25lVW5pdCIsIjMiOiJ0d29Vbml0cyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4xIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS4yIjp7IjEiOiJkYXlPZldlZWsiLCIyIjoiZGF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjEyMS40Ijp7IjEiOiJmaXJzdCIsIjIiOiJzZWNvbmQiLCIzIjoidGhpcmQiLCI0IjoiZm91cnRoIiwiNSI6Imxhc3QifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjEuNSI6eyIxIjoic3VuZGF5IiwiMiI6Im1vbmRheSIsIjMiOiJ0dWVzZGF5IiwiNCI6IndlZG5lc2RheSIsIjUiOiJ0aHVyc2RheSIsIjYiOiJmcmlkYXkiLCI3Ijoic2F0dXJkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjEuNyI6eyIxIjoiZmlyc3QiLCIyIjoic2Vjb25kIiwiMyI6InRoaXJkIiwiNCI6ImZvdXJ0aCIsIjUiOiJsYXN0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxLjgiOnsiMSI6InN1bmRheSIsIjIiOiJtb25kYXkiLCIzIjoidHVlc2RheSIsIjQiOiJ3ZWRuZXNkYXkiLCI1IjoidGh1cnNkYXkiLCI2IjoiZnJpZGF5IiwiNyI6InNhdHVyZGF5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTIxNy4xLjEuNCI6eyIxIjoiZFQiLCIyIjoiZVQiLCIzIjoicVQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMjYwLjEuMS4zIjp7IjEiOiJpUFQiLCIyIjoic0lQIiwiMyI6ImlQLUFUVCIsIjQiOiJpUC1WTSIsIjUiOiJpUC1WQSIsIjYiOiJ2TS1TSVAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xMzA5LjEuMS40Ijp7IjEiOiJxdWlldFRvbmUiLCIxMCI6ImV4dGVybmFsOSIsIjExIjoiZXh0ZXJuYWwxMCIsIjEyIjoiZXh0ZXJuYWwxMSIsIjEzIjoiZXh0ZXJuYWwxMiIsIjE0IjoiZXh0ZXJuYWwxMyIsIjE1IjoiZXh0ZXJuYWwxNCIsIjE2IjoiZXh0ZXJuYWwxNSIsIjIiOiJleHRlcm5hbDEiLCIzIjoiZXh0ZXJuYWwyIiwiNCI6ImV4dGVybmFsMyIsIjUiOiJleHRlcm5hbDQiLCI2IjoiZXh0ZXJuYWw1IiwiNyI6ImV4dGVybmFsNiIsIjgiOiJleHRlcm5hbDciLCI5IjoiZXh0ZXJuYWw4In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTMyMi4xLjEuMyI6eyIxIjoicEROIiwiMiI6ImdDTyIsIjMiOiJwb29sTGluZUdyb3VwIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjEiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjEwIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xMSI6eyIxIjoiYmVzdEVmZm9ydCIsIjIiOiJ2b2ljZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xMyI6eyIxIjoiZWNob0NhbmNlbDE2bXMiLCIyIjoiZWNob0NhbmNlbDMybXMiLCIzIjoiZWNob0NhbmNlbDY0bXMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMTQiOnsiMSI6ImhpZ2giLCIyIjoibWlkZGxlIiwiMyI6ImxvdyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4xNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMjAiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjIyIjp7IjEiOiJlY2hvQ2FuY2VsMTZtcyIsIjIiOiJlY2hvQ2FuY2VsMzJtcyIsIjMiOiJlY2hvQ2FuY2VsNjRtcyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yMyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMjQiOnsiMSI6InRvcyIsIjIiOiJkc2NwIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjI1Ijp7IjEiOiJyb3V0aW5lIiwiMiI6InByaW9yaXR5IiwiMyI6ImltbWVkaWF0ZSIsIjQiOiJmbGFzaCIsIjUiOiJmbGFzaE92ZXJyaWRlIiwiNiI6ImNyaXRpY0VzcCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yNiI6eyIxIjoibm9ybWFsIiwiMiI6ImxvdyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1MC4yNyI6eyIxIjoibm9ybWFsIiwiMiI6ImhpZ2gifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuMjgiOnsiMSI6Im5vcm1hbCIsIjIiOiJoaWdoIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjQiOnsiMSI6InRvcyIsIjIiOiJkc2NwIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjUiOnsiMSI6InJvdXRpbmUiLCIyIjoicHJpb3JpdHkiLCIzIjoiaW1tZWRpYXRlIiwiNCI6ImZsYXNoIiwiNSI6ImZsYXNoT3ZlcnJpZGUiLCI2IjoiY3JpdGljRXNwIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUwLjYiOnsiMSI6Im5vcm1hbCIsIjIiOiJsb3cifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuNyI6eyIxIjoibm9ybWFsIiwiMiI6ImhpZ2gifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTAuOCI6eyIxIjoibm9ybWFsIiwiMiI6ImhpZ2gifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTIuMS4xLjEwIjp7IjEiOiJmaXhlZCIsIjIiOiJhZGFwdGl2ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuMiI6eyIxIjoiaW50ZXJ2YWwxMG1zIiwiMiI6ImludGVydmFsMjBtcyIsIjMiOiJpbnRlcnZhbDMwbXMiLCI0IjoiaW50ZXJ2YWw0MG1zIiwiNSI6ImludGVydmFsODBtcyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuMyI6eyIxIjoiZml4ZWQiLCIyIjoic2VxdWVudGlhbCIsIjMiOiJhZGFwdGl2ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1Mi4xLjEuOSI6eyIxIjoiaW50ZXJ2YWwxMG1zIiwiMiI6ImludGVydmFsMjBtcyIsIjMiOiJpbnRlcnZhbDMwbXMiLCI0IjoiaW50ZXJ2YWw0MG1zIiwiNSI6ImludGVydmFsODBtcyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE1My4xLjEuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjQiOnsiMSI6ImFsd2F5cyIsIjIiOiJsaW1pdGVkIiwiMyI6ImluaGliaXQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNTMuMS4xLjYiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTUzLjEuMS43Ijp7IjEiOiJieXBhc3MiLCIyIjoibm90QnlwYXNzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjEzIjp7IjEiOiJiZXN0RWZmb3J0IiwiMiI6InZvaWNlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4xNCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjE2Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMTciOnsiMSI6ImJlc3RFZmZvcnQiLCIyIjoidm9pY2UifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjEuMS4xLjE4Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2MS4xLjEuMjIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYxLjEuMS4yNyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjMuMS4xLjIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS40Ijp7IjEiOiJhbHdheXMiLCIyIjoibGltaXRlZCIsIjMiOiJpbmhpYml0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTYzLjEuMS42Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2My4xLjEuNyI6eyIxIjoiYnlwYXNzIiwiMiI6Im5vdEJ5cGFzcyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2Ni4xLjEuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjYuMS4xLjMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMTY2LjEuMS42Ijp7IjEiOiJwYWNrZXQzMG1zIiwiMiI6InBhY2tldDQwbXMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4xNjYuMS4xLjciOnsiMSI6ImF1dG8iLCIyIjoicmF0ZTI0MDBicHMiLCIzIjoicmF0ZTQ4MDBicHMiLCI0IjoicmF0ZTcyMDBicHMiLCI1IjoicmF0ZTk2MDBicHMiLCI2IjoicmF0ZTEyMDAwYnBzIiwiNyI6InJhdGUxNDQwMGJwcyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjE2NzIuMS4xLjMiOnsiMSI6ImlQUVNJRyIsIjIiOiJoMzIzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4yMCI6eyIxIjoiZFQiLCIyIjoiZVQiLCIzIjoicVQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjIyIjp7IjEiOiJwZXJtaXRlZCIsIjIiOiJvbmx5UGVybWl0ZWRJbkFHcm91cCIsIjMiOiJub3RQZXJtaXRlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMjMiOnsiMSI6ImF1ZGlvIiwiMiI6InNwZWVjaCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMyI6eyIxIjoiZEtUIiwiMiI6InNMVCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzIiOnsiMSI6ImFsbG93ZWQiLCIyIjoibm90QWxsb3dlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuMzMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zNCI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zNSI6eyIxIjoieWVzIiwiMiI6Im5vIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zNiI6eyIxIjoieWVzIiwiMiI6Im5vIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS4zNyI6eyIxIjoib3ZlcnJpZGUiLCIyIjoibm90T3ZlcnJpZGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjM5Ijp7IjEiOiJhbGxvd2VkIiwiMiI6Im5vdEFsbG93ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQiOnsiMSI6ImV4dGVuc2lvbiIsIjIiOiJ2b2ljZU1haWwiLCIzIjoiYW5ub3VuY2UifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQxIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS40MyI6eyIxIjoicmVjZWl2ZWQiLCIyIjoibm90UmVjZWl2ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQ1Ijp7IjEiOiJkVE1GIiwiMiI6ImRQIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS40NiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjQ3Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNDgiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS40OSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjUwIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNTIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41MyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU0Ijp7IjEiOiJ0aHJlZURpZ2l0cyIsIjIiOiJmb3VyRGlnaXRzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41NyI6eyIxIjoibm9ybWFsIiwiMiI6InN1cGVyMSIsIjMiOiJzdXBlcjIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjU4Ijp7IjEiOiJub25lIiwiMiI6Im9ubHlUeXBlMSIsIjMiOiJ0eXBlMUFuZFR5cGUyIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS41OSI6eyIxIjoibm9uZSIsIjIiOiJ0cnVua0FjY2VzcyIsIjMiOiJvTEdBY2Nlc3MiLCI0IjoibENSQWNjZXNzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS42MSI6eyIxIjoibm9uZSIsIjIiOiJsQ0QiLCIzIjoic1BFQ0lBTCIsIjQiOiJkRUZBVUxUIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAwLjEuMS42MiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDAuMS4xLjYzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMC4xLjEuNjQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4xOSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjIwIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjEiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4yMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjIzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4yNSI6eyIxIjoiZVhQTElDSVQiLCIyIjoicFJFRkVSUkVEIiwiMyI6ImFOWSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuMjYiOnsiMSI6ImZPUldBUkRDWUNMSUMiLCIyIjoiYkFDS1dBUkRDWUNMSUMiLCIzIjoiZk9SV0FSRFRFUk1JTkFMIiwiNCI6ImJBQ0tXQVJEVEVSTUlOQUwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMwIjp7IjEiOiJvbmUiLCIyIjoidHdvIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4zMSI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS4zMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjMzIjp7IjEiOiJhbGxvd2VkIiwiMiI6Im5vdEFsbG93ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQiOnsiMSI6ImJlbGxjb3JlTmF0aW9uYWxJU0ROIiwiMiI6ImVUU0kiLCIzIjoidFRDIiwiNCI6ImJlbGxjb3JlTmF0aW9uYWxJU0ROTm9ydGhlcm5UZWxlY29tIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40MiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNDUiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS40NiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjQ3Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwMi4xLjEuNDkiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjAyLjEuMS41Ijp7IjEiOiJwb2ludFRvUG9pbnQiLCIyIjoicG9pbnRUb011bHRpUG9pbnQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDIuMS4xLjUwIjp7IjEiOiJ0aHJlZURpZ2l0cyIsIjIiOiJmb3VyRGlnaXRzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xMCI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4xMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjEyIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMTQiOnsiMSI6ImlkbGVQcmVmZXJlbmNlIiwiMiI6InJpbmdpbmdQcmVmZXJlbmNlIiwiMyI6InByaW1lUHJlZmVyZW5jZSIsIjQiOiJub1ByZWZlcmVuY2UiLCI1IjoicHJpbWVBbmRJZGxlUHJlZmVyZW5jZSIsIjYiOiJwcmltZUFuZFJpbmdpbmdQcmVmZXJlbmNlIiwiNyI6InJpbmdpbmdBbmRJZGxlUHJlZmVyZW5jZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMTUiOnsiMSI6ImNPS2V5T25seSIsIjIiOiJkTktleU9ubHkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjE2Ijp7IjEiOiJsb25nZXN0IiwiMiI6ImNhbGxUeXBlQW5kTG9uZ2VzdCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMTciOnsiMSI6ImRpc3BsYXkiLCIyIjoibm90RGlzcGxheSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMiI6eyIxIjoiZXh0ZW5zaW9uIiwiMiI6ImF0dGVuZGFudCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjAiOnsiMSI6InVzZSIsIjIiOiJub3RVc2UifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjIxIjp7IjEiOiJlbmdsaXNoIiwiMiI6ImJyaXRpc2hFbmdsaXNoIiwiMyI6ImZyZW5jaCIsIjQiOiJzcGFuaXNoIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4yMiI6eyIxIjoibm90aGluZyIsIjIiOiJiUENJIiwiMyI6ImJBVEkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjIzIjp7IjEiOiJsZWF2ZSIsIjIiOiJzZXBhcmF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjQiOnsiMSI6ImF1dG9JbnB1dCIsIjIiOiJtYW51YWxJbnB1dCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjUiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjYiOnsiMSI6InVzZSIsIjIiOiJub1VzZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjciOnsiMSI6InllcyIsIjIiOiJubyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMjgiOnsiMSI6InR3b0N5Y2xlcyIsIjIiOiJjb250aW51b3VzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zIjp7IjEiOiJwYXR0ZXJuMSIsIjIiOiJwYXR0ZXJuMiIsIjMiOiJwYXR0ZXJuMyIsIjQiOiJub25lIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zMCI6eyIxIjoieWVzIiwiMiI6Im5vIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjMyIjp7IjEiOiJ0ZXJtaW5hbE1vZGUiLCIyIjoibGluZU1vZGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjMzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMzQiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMzUiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zNiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjM3Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuMzgiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS4zOSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDQuMS4xLjQwIjp7IjEiOiJub25lIiwiMiI6ImtleXN0cmlwMTBLZXkiLCIzIjoia2V5c3RyaXAyMEtleSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNDEiOnsiMSI6Im5vbmUiLCIyIjoia2V5c3RyaXAxMEtleSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNDIiOnsiMSI6Im5vbmUiLCIyIjoia2V5c3RyaXAxMEtleSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNDMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA0LjEuMS41Ijp7IjEiOiJub24iLCIyIjoib25lVW5pdCIsIjMiOiJ0d29Vbml0cyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNiI6eyIxIjoidG9uZSIsIjIiOiJ2b2ljZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwNC4xLjEuNyI6eyIxIjoiaGFuZHNldCIsIjIiOiJzcGVha2VyIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA2LjEuMS4xMiI6eyIxIjoieWVzIiwiMiI6Im5vIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA2LjEuMS4zIjp7IjEiOiJ0b25lIiwiMiI6InZvaWNlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS4xMCI6eyIxIjoicXVpZXRUb25lIiwiMTAiOiJleHRlcm5hbDkiLCIxMSI6ImV4dGVybmFsMTAiLCIxMiI6ImV4dGVybmFsMTEiLCIxMyI6ImV4dGVybmFsMTIiLCIxNCI6ImV4dGVybmFsMTMiLCIxNSI6ImV4dGVybmFsMTQiLCIxNiI6ImV4dGVybmFsMTUiLCIxNyI6ImludGVybmFsIiwiMiI6ImV4dGVybmFsMSIsIjMiOiJleHRlcm5hbDIiLCI0IjoiZXh0ZXJuYWwzIiwiNSI6ImV4dGVybmFsNCIsIjYiOiJleHRlcm5hbDUiLCI3IjoiZXh0ZXJuYWw2IiwiOCI6ImV4dGVybmFsNyIsIjkiOiJleHRlcm5hbDgifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjIiOnsiMSI6InNlcmlhbCIsIjIiOiJjaXJjdWxhciIsIjMiOiJkaXN0cmlidXRlIiwiNCI6ImlwVm9pY2VNYWlsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjA5LjEuMS43Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIwOS4xLjEuOCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMDkuMS4xLjkiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xMCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xMSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xMiI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xMyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xNCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xNSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xNiI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xNyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xOCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4xOSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS4yIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIwIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIxIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIyIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjIzIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI0Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI1Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI2Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI3Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI4Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjI5Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjMiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzAiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzEiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzIiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzMiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzQiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzUiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzYiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzciOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzgiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuMzkiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40MCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40MSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40MiI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40MyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40NCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40NSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40NiI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40NyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40OCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS40OSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS41Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjYiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxMC4xLjEuNyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjEwLjEuMS44Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTAuMS4xLjkiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxNi4xLjEuMiI6eyIxIjoiYXBwbHkiLCIyIjoibm90QXBwbHkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjEzIjp7IjEiOiJ5ZXMiLCIyIjoibm8ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjE0Ijp7IjEiOiJkTiIsIjIiOiJjUE4iLCIzIjoiZE5BbmRDUE4ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjMiOnsiMSI6ImRUIiwiMiI6ImVUIiwiMyI6InFUIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjE3LjEuMS42Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yMTcuMS4xLjgiOnsiMSI6ImFsbG93ZWQiLCIyIjoibm90QWxsb3dlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIxOC4xLjEuNCI6eyIxIjoibW9kaWZ5IiwiMiI6Imluc2VydCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjIyMC4xLjEuMiI6eyIxIjoiZEtUIiwiMiI6ImFETTEiLCIzIjoiYURNMiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI1MC4xLjEuMTQiOnsiMSI6IkluYmFuZCIsIjIiOiJSRkMyODMzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNSI6eyIxIjoiZzcxMSIsIjIiOiJnNzI5QSIsIjMiOiJub25lIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS4xNyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNTAuMS4xLjMiOnsiMSI6ImZpeCIsIjIiOiJhbnkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNTAuMS4xLjUiOnsiMSI6InBlcm1pdHRlZCIsIjIiOiJub3RQZXJtaXR0ZWQiLCIzIjoiZG9udENhcmUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNTAuMS4xLjYiOnsiMSI6ImFwcGx5IiwiMiI6Im5vdEFwcGx5IiwiMyI6ImRvbnRDYXJlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjUwLjEuMS45Ijp7IjEiOiJnNzExIiwiMiI6Imc3MjlBIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4yIjp7IjEiOiJpUFQiLCIyIjoic0lQIiwiMyI6ImlQLUFUVCIsIjQiOiJpUC1WTSIsIjUiOiJpUC1WQSIsIjYiOiJ2TS1TSVAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjIwIjp7IjEiOiJkVCIsIjIiOiJlVCIsIjMiOiJxVCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMjIiOnsiMSI6InBlcm1pdGVkIiwiMiI6Im9ubHlQZXJtaXRlZEluQUdyb3VwIiwiMyI6Im5vdFBlcm1pdGVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4yMyI6eyIxIjoiYXVkaW8iLCIyIjoic3BlZWNoIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zMCI6eyIxIjoiYWxsb3dlZCIsIjIiOiJub3RBbGxvd2VkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMyIjp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjMzIjp7IjEiOiJ5ZXMiLCIyIjoibm8ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjM0Ijp7IjEiOiJ5ZXMiLCIyIjoibm8ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjM1Ijp7IjEiOiJvdmVycmlkZSIsIjIiOiJub3RPdmVycmlkZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzYiOnsiMSI6ImFsbG93ZWQiLCIyIjoibm90QWxsb3dlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuMzgiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS4zOSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjQwIjp7IjEiOiJyZWNlaXZlZCIsIjIiOiJub3RSZWNlaXZlZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40MyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjQ0Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDUiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS40NiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjQ4Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNDkiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41MCI6eyIxIjoidGhyZWVEaWdpdHMiLCIyIjoiZm91ckRpZ2l0cyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNTMiOnsiMSI6Im5vcm1hbCIsIjIiOiJzdXBlcjEiLCIzIjoic3VwZXIyIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41NCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjU1Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNTciOnsiMSI6InJUUCIsIjIiOiJkaXNjb25uZWN0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS41OCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjU5Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNjEiOnsiMSI6Im5vbmUiLCIyIjoibENEIiwiMyI6InNQRUNJQUwiLCI0IjoiZEVGQVVMVCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjI2MC4xLjEuNjIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMjYwLjEuMS42MyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4yNjAuMS4xLjY0Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTEiOnsiMSI6InN1cHBsaWRlIiwiMiI6Im5vdFN1cHBsaWRlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS4xMiI6eyIxIjoicGFkZGVkIiwiMiI6ImRUTUZUb25lIiwiMyI6Im5vVG9uZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuMTQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS4xNSI6eyIxIjoidGltZTE1MDBtcyIsIjIiOiJ0aW1lNDUwbXMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDAuMS4xLjUiOnsiMSI6ImRQMTAiLCIyIjoiZFAyMCIsIjMiOiJkVE1GIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS42Ijp7IjEiOiJkSUQiLCIyIjoibE9PUCIsIjMiOiJnUk9VTkQiLCI0IjoidElFIiwiNSI6ImxQIiwiNiI6InNSIiwiNyI6ImFDVSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMC4xLjEuNyI6eyIxIjoiaW1taWRpYXRlU3RhcnQiLCIyIjoidGltaW5nU3RhcnQiLCIzIjoid2lua1N0YXJ0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS44Ijp7IjEiOiJuZWNlc3NhcnkiLCIyIjoidW4tbmVjZXNzYXJ5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAwLjEuMS45Ijp7IjEiOiJuZWNlc3NhcnkiLCIyIjoidW4tbmVjZXNzYXJ5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4xMCI6eyIxIjoiY2hhbm5lbE51bWJlckIiLCIyIjoic2xvdE1hcEIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjExIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTIiOnsiMSI6ImNoYW5uZWxOdW1iZXJCIiwiMiI6InNsb3RNYXBCIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4xMyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjE0Ijp7IjEiOiJjaGFubmVsTnVtYmVyQiIsIjIiOiJzbG90TWFwQiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTUiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4xNiI6eyIxIjoiY2hhbm5lbE51bWJlckIiLCIyIjoic2xvdE1hcEIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjE3Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMTgiOnsiMSI6ImNoYW5uZWxOdW1iZXJCIiwiMiI6InNsb3RNYXBCIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4xOSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjIwIjp7IjEiOiJjaGFubmVsTnVtYmVyQiIsIjIiOiJzbG90TWFwQiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjEiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4yMiI6eyIxIjoiY2hhbm5lbE51bWJlckIiLCIyIjoiY2hhbm5lbE51bWJlckgiLCIzIjoic2xvdE1hcEIiLCI0Ijoic2xvdE1hcEgifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjIzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjQiOnsiMSI6ImNoYW5uZWxOdW1iZXJCIiwiMiI6ImNoYW5uZWxOdW1iZXJIIiwiMyI6InNsb3RNYXBCIiwiNCI6InNsb3RNYXBIIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4yNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjI2Ijp7IjEiOiJjaGFubmVsTnVtYmVyQiIsIjIiOiJjaGFubmVsTnVtYmVySCIsIjMiOiJzbG90TWFwQiIsIjQiOiJzbG90TWFwSCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMjciOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4yOCI6eyIxIjoiY2hhbm5lbE51bWJlckIiLCIyIjoic2xvdE1hcEIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjI5Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMyI6eyIxIjoiYmVsbGNvcmVOYXRpb25hbElTRE4iLCIyIjoiZVRTSSIsIjMiOiJ0VEMiLCI0IjoiYmVsbGNvcmVOYXRpb25hbElTRE5Ob3J0aGVyblRlbGVjb20iLCI1IjoicVNJRyIsIjYiOiJpUCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzAiOnsiMSI6ImNoYW5uZWxOdW1iZXJCIiwiMiI6InNsb3RNYXBCIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjMyIjp7IjEiOiJlWFBMSUNJVCIsIjIiOiJwUkVGRVJSRUQiLCIzIjoiYU5ZIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zMyI6eyIxIjoiZk9SV0FSRENZQ0xJQyIsIjIiOiJiQUNLV0FSRENZQ0xJQyIsIjMiOiJmT1JXQVJEVEVSTUlOQUwiLCI0IjoiYkFDS1dBUkRURVJNSU5BTCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuMzYiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS4zNyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjM4Ijp7IjEiOiJtYXN0ZXIiLCIyIjoic2xhdmUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjM5Ijp7IjEiOiJzaWRlQSIsIjIiOiJzaWRlQiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDAiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40MSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjQyIjp7IjEiOiJub3JtYWwiLCIyIjoibG9uZyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNDMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzAyLjEuMS40NCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjQ1Ijp7IjEiOiJvdmVybGFwIiwiMiI6ImVuQmxvYyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwMi4xLjEuNiI6eyIxIjoiaW1wbGljaXQiLCIyIjoiZXhwbGljaXQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDIuMS4xLjkiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yIjp7IjEiOiJhbmFsb2ciLCIyIjoiaVNETiIsIjMiOiJzSVAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjIxIjp7IjEiOiJhdWRpbyIsIjIiOiJzcGVlY2gifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjI2Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjI3Ijp7IjEiOiJ1c2VyUHJvdmlkZWROdW1iZXIiLCIyIjoibmV0d29ya1Byb3ZpZGVkTnVtYmVyIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yOCI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4yOSI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zIjp7IjEiOiJjTyIsIjIiOiJ0SUUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjMwIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zNCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDQuMS4xLjM1Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuMzYiOnsiMSI6ImRUIiwiMiI6ImVUIiwiMyI6InFUIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA0LjEuMS4zOSI6eyIxIjoidXNlckJ1c3kiLCIyIjoiY29uZ2VzdGlvbiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuNCI6eyIxIjoiZElEIiwiMiI6ImRJVCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNC4xLjEuNSI6eyIxIjoibm9uLVFTSUciLCIyIjoicVNJRyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTgiOnsiMSI6ImF1ZGlvIiwiMiI6InNwZWVjaCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMTkiOnsiMSI6InF1aWV0VG9uZSIsIjEwIjoiZXh0ZXJuYWw5IiwiMTEiOiJleHRlcm5hbDEwIiwiMTIiOiJleHRlcm5hbDExIiwiMTMiOiJleHRlcm5hbDEyIiwiMTQiOiJleHRlcm5hbDEzIiwiMTUiOiJleHRlcm5hbDE0IiwiMTYiOiJleHRlcm5hbDE1IiwiMTciOiJpbnRlcm5hbCIsIjIiOiJleHRlcm5hbDEiLCIzIjoiZXh0ZXJuYWwyIiwiNCI6ImV4dGVybmFsMyIsIjUiOiJleHRlcm5hbDQiLCI2IjoiZXh0ZXJuYWw1IiwiNyI6ImV4dGVybmFsNiIsIjgiOiJleHRlcm5hbDciLCI5IjoiZXh0ZXJuYWw4In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4yIjp7IjEiOiJhbmFsb2ciLCIyIjoiaVNETiIsIjMiOiJzSVAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIwIjp7IjEiOiJuZWVkIiwiMiI6Im5vLW5lZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIxIjp7IjEiOiJuZWVkIiwiMiI6Im5vLW5lZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjIyIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuMjMiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4yNCI6eyIxIjoiY3V0VGhyb3VnaCIsIjIiOiJzZW5kZXJpemVkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA2LjEuMS4yNiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDYuMS4xLjMiOnsiMSI6ImNPIiwiMiI6InRJRSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwNi4xLjEuNCI6eyIxIjoibm9uLVFTSUciLCIyIjoicVNJRyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOC4xLjEuMiI6eyIxIjoiZGlzYWJsZSIsIjIiOiJkZXRlY3Q5NW1zIiwiMyI6ImRldGVjdDQ1MG1zIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA4LjEuMS43Ijp7IjEiOiJ0aW1lOHNlYyIsIjIiOiJ0aW1lNnNlYyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTAiOnsiMSI6Im5vRGF0YSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6ImRJU0EiLCI0IjoiYnVpbHQtaW5Nb2RlbSIsIjUiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjEyIjp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJkSVNBIiwiNCI6ImJ1aWx0LWluTW9kZW0iLCI1IjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS4xNCI6eyIxIjoibm9EYXRhIiwiMiI6ImRpYWxpbmdEaWdpdHMiLCIzIjoiZElTQSIsIjQiOiJidWlsdC1pbk1vZGVtIiwiNSI6Im5pZ2h0QmVsbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMwOS4xLjEuMTYiOnsiMSI6Im5vRGF0YSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6ImRJU0EiLCI0IjoiYnVpbHQtaW5Nb2RlbSIsIjUiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMDkuMS4xLjMiOnsiMSI6InF1aWV0VG9uZSIsIjEwIjoiZXh0ZXJuYWw5IiwiMTEiOiJleHRlcm5hbDEwIiwiMTIiOiJleHRlcm5hbDExIiwiMTMiOiJleHRlcm5hbDEyIiwiMTQiOiJleHRlcm5hbDEzIiwiMTUiOiJleHRlcm5hbDE0IiwiMTYiOiJleHRlcm5hbDE1IiwiMTciOiJpbnRlcm5hbCIsIjIiOiJleHRlcm5hbDEiLCIzIjoiZXh0ZXJuYWwyIiwiNCI6ImV4dGVybmFsMyIsIjUiOiJleHRlcm5hbDQiLCI2IjoiZXh0ZXJuYWw1IiwiNyI6ImV4dGVybmFsNiIsIjgiOiJleHRlcm5hbDciLCI5IjoiZXh0ZXJuYWw4In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS42Ijp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJkSVNBIiwiNCI6ImJ1aWx0LWluTW9kZW0iLCI1IjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzA5LjEuMS44Ijp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJkSVNBIiwiNCI6ImJ1aWx0LWluTW9kZW0iLCI1IjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEwLjEuMS4yIjp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJkSVNBIiwiNCI6ImJ1aWx0LWluTW9kZW0iLCI1IjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEwLjEuMS40Ijp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJkSVNBIiwiNCI6ImJ1aWx0LWluTW9kZW0iLCI1IjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEwLjEuMS42Ijp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJkSVNBIiwiNCI6ImJ1aWx0LWluTW9kZW0iLCI1IjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEwLjEuMS44Ijp7IjEiOiJxdWlldFRvbmUiLCIxMCI6ImV4dGVybmFsOSIsIjExIjoiZXh0ZXJuYWwxMCIsIjEyIjoiZXh0ZXJuYWwxMSIsIjEzIjoiZXh0ZXJuYWwxMiIsIjE0IjoiZXh0ZXJuYWwxMyIsIjE1IjoiZXh0ZXJuYWwxNCIsIjE2IjoiZXh0ZXJuYWwxNSIsIjE3IjoiaW50ZXJuYWwiLCIyIjoiZXh0ZXJuYWwxIiwiMyI6ImV4dGVybmFsMiIsIjQiOiJleHRlcm5hbDMiLCI1IjoiZXh0ZXJuYWw0IiwiNiI6ImV4dGVybmFsNSIsIjciOiJleHRlcm5hbDYiLCI4IjoiZXh0ZXJuYWw3IiwiOSI6ImV4dGVybmFsOCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMS4xIjp7IjEiOiJuZWNlc3NhcnkiLCIyIjoidW5uZWNlc3NhcnkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTEuNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTMuMS4xLjIiOnsiMSI6Im5vdGhpbmciLCIyIjoiYU5JLU1DSSIsIjMiOiJhTkktU3ByaW50IiwiNCI6ImNMQVNTIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzEzLjEuMS4zIjp7IjEiOiJhTklBbmRETklTIiwiMiI6ImFOSSIsIjMiOiJkTklTIiwiNCI6ImRJRCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxMy4xLjEuNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTUuMS4xLjIiOnsiMSI6Im5vbmUiLCIyIjoicFpDIiwiMyI6ImI4WlMiLCI0IjoiekNTIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1LjEuMS4zIjp7IjEiOiJub25lIiwiMiI6InNGTW9kZSIsIjMiOiJlU0ZNb2RlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE1LjEuMS41Ijp7IjEiOiJub25lIiwiMiI6InBsdXM2REIiLCIzIjoicGx1czNEQiIsIjQiOiJ6ZXJvREIiLCI1IjoibWludXMzREIiLCI2IjoibWludXM2REIiLCI3IjoibWludXM5REIiLCI4IjoibWludXMxMkRCIiwiOSI6Im1pbnVzMTVEQiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNS4xLjEuNiI6eyIxIjoibm9uZSIsIjIiOiJwbHVzNkRCIiwiMyI6InBsdXMzREIiLCI0IjoiemVyb0RCIiwiNSI6Im1pbnVzM0RCIiwiNiI6Im1pbnVzNkRCIiwiNyI6Im1pbnVzOURCIiwiOCI6Im1pbnVzMTJEQiIsIjkiOiJtaW51czE1REIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTYuMS4xLjQiOnsiMSI6ImV4aXN0IiwiMiI6Im5vdEV4aXN0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xMCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjExIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMTIiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4xMyI6eyIxIjoiZVhQTElDSVQiLCIyIjoicFJFRkVSUkVEIiwiMyI6ImFOWSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMTQiOnsiMSI6ImZPUldBUkRDWUNMSUMiLCIyIjoiYkFDS1dBUkRDWUNMSUMiLCIzIjoiZk9SV0FSRFRFUk1JTkFMIiwiNCI6ImJBQ0tXQVJEVEVSTUlOQUwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjE1Ijp7IjEiOiJ1c2VyRW50cnlPZlNQSURBdXRvU1BJRE9OIiwiMiI6InVzZXJFbnRyeU9mU1BJREF1dG9TUElET0ZGIiwiMyI6ImF1dG9TUElEIiwiNCI6Im5vbmUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjE5Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjAiOnsiMSI6Im9uZSIsIjIiOiJ0d28ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjIzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjQiOnsiMSI6InRFSUZpeGVkIiwiMiI6InNpbmdsZVRFSSIsIjMiOiJ0d29URUkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjI1Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuMjYiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS4yNyI6eyIxIjoib3ZlcmxhcCIsIjIiOiJlbkJsb2MifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjMiOnsiMSI6ImJlbGxjb3JlTmF0aW9uYWxJU0ROIiwiMiI6ImVUU0kiLCIzIjoidFRDIiwiNCI6ImJlbGxjb3JlTmF0aW9uYWxJU0ROTm9ydGhlcm5UZWxlY29tIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE3LjEuMS43Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxNy4xLjEuOCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTcuMS4xLjkiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xMCI6eyIxIjoibm9EYXRhIiwiMiI6ImRpYWxpbmdEaWdpdHMiLCIzIjoiZElTQSIsIjQiOiJidWlsdC1pbk1vZGVtIiwiNSI6Im5pZ2h0QmVsbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMTIiOnsiMSI6Im5vRGF0YSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6ImRJU0EiLCI0IjoiYnVpbHQtaW5Nb2RlbSIsIjUiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjE0Ijp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJkSVNBIiwiNCI6ImJ1aWx0LWluTW9kZW0iLCI1IjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE4LjEuMS4xNiI6eyIxIjoibm9EYXRhIiwiMiI6ImRpYWxpbmdEaWdpdHMiLCIzIjoiZElTQSIsIjQiOiJidWlsdC1pbk1vZGVtIiwiNSI6Im5pZ2h0QmVsbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMiI6eyIxIjoibm9ESUQiLCIyIjoibm90RGV0ZXJtaW5lZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOC4xLjEuMyI6eyIxIjoicXVpZXRUb25lIiwiMTAiOiJleHRlcm5hbDkiLCIxMSI6ImV4dGVybmFsMTAiLCIxMiI6ImV4dGVybmFsMTEiLCIxMyI6ImV4dGVybmFsMTIiLCIxNCI6ImV4dGVybmFsMTMiLCIxNSI6ImV4dGVybmFsMTQiLCIxNiI6ImV4dGVybmFsMTUiLCIxNyI6ImludGVybmFsIiwiMiI6ImV4dGVybmFsMSIsIjMiOiJleHRlcm5hbDIiLCI0IjoiZXh0ZXJuYWwzIiwiNSI6ImV4dGVybmFsNCIsIjYiOiJleHRlcm5hbDUiLCI3IjoiZXh0ZXJuYWw2IiwiOCI6ImV4dGVybmFsNyIsIjkiOiJleHRlcm5hbDgifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjYiOnsiMSI6Im5vRGF0YSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6ImRJU0EiLCI0IjoiYnVpbHQtaW5Nb2RlbSIsIjUiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTguMS4xLjgiOnsiMSI6Im5vRGF0YSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6ImRJU0EiLCI0IjoiYnVpbHQtaW5Nb2RlbSIsIjUiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMTkuMSI6eyIxIjoibm9uZSIsIjIiOiJkaWFsaW5nRGlnaXRzIiwiMyI6Im5pZ2h0QmVsbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMxOS4zIjp7IjEiOiJub25lIiwiMiI6ImRpYWxpbmdEaWdpdHMiLCIzIjoibmlnaHRCZWxsIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzE5LjUiOnsiMSI6Im5vbmUiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjEwIjp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjExIjp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjEyIjp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjEzIjp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE0Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE1Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE2Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE3Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE4Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjE5Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjIiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjAiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjEiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjIiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjMiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjQiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjUiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjYiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjciOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjgiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMjkiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuMyI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMCI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMSI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS4zMiI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS40Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjUiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuNiI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIwLjEuMS43Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjAuMS4xLjgiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMC4xLjEuOSI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzIxLjEuMS40Ijp7IjEiOiJvTiIsIjIiOiJvRkYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjIuMS4xLjIiOnsiMSI6InBETiIsIjIiOiJnQ08iLCIzIjoicG9vbExpbmVHcm91cCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyMy4xLjEuMyI6eyIxIjoibm9EYXRhIiwiMiI6InBPVFMiLCIzIjoiZlgiLCI0IjoidElFU0VOREVSSVpFRCIsIjUiOiJ0SUVDVVRUSFJPVUdIIiwiNiI6ImlOVFJBTEFUQU9VVFdBVFMiLCI3Ijoib1VUV0FUU1VTSU5HQkFORFMiLCI4IjoiaU5URVJMQVRBT1VUV0FUUyIsIjkiOiJpTldBVFMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjEwIjp7IjEiOiJub3JtYWwiLCIyIjoibG9uZyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNS4xLjEuNyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjUuMS4xLjgiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI1LjEuMS45Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNi4xLjEuNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjEzIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMTQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xNSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjE2Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMTgiOnsiMSI6Imc3MTF1IiwiMiI6Imc3MTFhIiwiMyI6Imc3MjlhIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4xOSI6eyIxIjoiZzcxMXUiLCIyIjoiZzcxMWEiLCIzIjoiZzcyOWEifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjIiOnsiMSI6ImNsaWVudCIsIjIiOiJzZXJ2ZXIiLCIzIjoibm9uZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjAiOnsiMSI6ImluYmFuZCIsIjIiOiJyZmMyODMzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjIyIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4yNSI6eyIxIjoidG9zIiwiMiI6ImRzY3AifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjI2Ijp7IjEiOiJyb3V0aW5lIiwiMiI6InByaW9yaXR5IiwiMyI6ImltbWVkaWF0ZSIsIjQiOiJmbGFzaCIsIjUiOiJmbGFzaE92ZXJyaWRlIiwiNiI6ImNyaXRpY0VzcCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjciOnsiMSI6Im5vcm1hbCIsIjIiOiJsb3cifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjI4Ijp7IjEiOiJub3JtYWwiLCIyIjoiaGlnaCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMjkiOnsiMSI6Im5vcm1hbCIsIjIiOiJoaWdoIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjMyIjp7IjEiOiJ0b3MiLCIyIjoiZHNjcCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzMiOnsiMSI6InJvdXRpbmUiLCIyIjoicHJpb3JpdHkiLCIzIjoiaW1tZWRpYXRlIiwiNCI6ImZsYXNoIiwiNSI6ImZsYXNoT3ZlcnJpZGUiLCI2IjoiY3JpdGljRXNwIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zNCI6eyIxIjoibm9ybWFsIiwiMiI6ImxvdyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuMzUiOnsiMSI6Im5vcm1hbCIsIjIiOiJoaWdoIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS4zNiI6eyIxIjoibm9ybWFsIiwiMiI6ImhpZ2gifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjM4Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDIiOnsiMSI6ImZxZG4iLCIyIjoiaXB1SXBBZGRyZXNzIiwiMyI6InNpcFNlcnZlcklwQWRkcmVzcyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyNy4xLjEuNDMiOnsiMSI6ImZxZG4iLCIyIjoic2lwU2VydmVySXBBZGRyZXNzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS40NCI6eyIxIjoiZnFkbiIsIjIiOiJpcHVJcEFkZHJlc3MiLCIzIjoic2lwU2VydmVySXBBZGRyZXNzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuMzI3LjEuMS40NSI6eyIxIjoiZnFkbiIsIjIiOiJzaXBTZXJ2ZXJJcEFkZHJlc3MifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy4zMjcuMS4xLjQ2Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjMyOS4xLjEuNyI6eyIxIjoibWFpbiIsIjIiOiJzdWIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjEwIjp7IjEiOiJkZWFjdGl2YXRlIiwiMiI6ImFjdGl2YXRlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yIjp7IjEiOiJkZWFjdGl2YXRlIiwiMiI6ImFjdGl2YXRlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNC40LjEuMS4yNyI6eyIwIjoiYW5zd2VyIiwiMSI6ImFiYW5kb24ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjMiOnsiMSI6ImRlYWN0aXZhdGUiLCIyIjoiYWN0aXZhdGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy40LjQuMS4xLjMxIjp7IjAiOiJhbnN3ZXIiLCIxIjoiYWJhbmRvbiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuNCI6eyIxIjoiZGVhY3RpdmF0ZSIsIjIiOiJhY3RpdmF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuNSI6eyIxIjoiZGVhY3RpdmF0ZSIsIjIiOiJhY3RpdmF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuNiI6eyIxIjoiZGVhY3RpdmF0ZSIsIjIiOiJhY3RpdmF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuNyI6eyIxIjoiZGVhY3RpdmF0ZSIsIjIiOiJhY3RpdmF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuOCI6eyIxIjoiZGVhY3RpdmF0ZSIsIjIiOiJhY3RpdmF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQuNC4xLjEuOSI6eyIxIjoiZGVhY3RpdmF0ZSIsIjIiOiJhY3RpdmF0ZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwMC4xLjEuNCI6eyIxIjoibW9kaWZ5IiwiMiI6Imluc2VydCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjQwNC4xLjEuMiI6eyIxIjoibW9zdElkbGVGaXJzdCIsIjIiOiJuZXh0QXZhaWxhYmxlRmlyc3QiLCIzIjoiYnJvYWRjYXN0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS4yIjp7IjEiOiJjT0xvb3BHcmQiLCIyIjoiZElEIiwiMyI6InRJRSIsIjQiOiJyaW5nVHJhbnNmZXIiLCI1IjoiaW50ZXJuYWwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDAuMS4xLjMiOnsiMSI6ImRheSIsIjIiOiJkYXkyIiwiMyI6Im5pZ2h0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAwLjEuMS40Ijp7IjEiOiJidXN5IiwiMiI6Im5vQW5zd2VyIiwiMyI6ImJ1c3lOb0Fuc3dlciIsIjQiOiJkTkQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjEwIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjExIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjEyIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjEzIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE0Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE1Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE2Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE3Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE4Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjE5Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjIiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjAiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjEiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjIiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjMiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjQiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjUiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjYiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMjciOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuMyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS40Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjUiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuNiI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAyLjEuMS43Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDIuMS4xLjgiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMi4xLjEuOSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMiI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xMyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xNCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xNSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xNiI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xNyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xOCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4xOSI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS4yIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjIxIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjIyIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjIzIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjI0Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjI1Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjI2Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjI3Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjI4Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjMiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuNCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS41Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjYiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwMy4xLjEuNyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTAzLjEuMS44Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDMuMS4xLjkiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNC4xLjEuMiI6eyIxIjoibm9EYXRhIiwiMiI6ImJ1c3kiLCIzIjoibm9BbnN3ZXIiLCI0IjoiYnVzeU5vQW5zd2VyIiwiNSI6ImRORCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNi4xLjEuMiI6eyIxIjoic2V0IiwiMiI6Im5vLXNldCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUwNy4xLjEuMTEiOnsiMSI6Im5vbmUiLCIyIjoiZE4iLCIzIjoicGFnaW5nR3JvdXAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjciOnsiMSI6Im5vbmUiLCIyIjoiZE4iLCIzIjoicGFnaW5nR3JvdXAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDcuMS4xLjkiOnsiMSI6Im5vbmUiLCIyIjoiZE4iLCIzIjoicGFnaW5nR3JvdXAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MDguMS4xLjIiOnsiMSI6Im5vbmUiLCIyIjoiYklPVSIsIjMiOiJkRENCIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEyLjEiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi4yIjp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTIuMyI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEyLjQiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMi41Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTIuNiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTIuNyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMuMS4xLjMiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMy4xLjEuNCI6eyIxIjoib24iLCIyIjoib2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTEzLjEuMS41Ijp7IjEiOiJvbiIsIjIiOiJvZmYifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTMuMS4xLjYiOnsiMSI6InNvdXJjZSIsIjIiOiJkZXN0aW5hdGlvbiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxMy4xLjEuNyI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTQuMS4xLjMiOnsiMSI6Im9uIiwiMiI6Im9mZiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuNCI6eyIxIjoic291cmNlIiwiMiI6ImRlc3RpbmF0aW9uIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE0LjEuMS41Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUxNC4xLjEuNiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MTguMS4xLjMiOnsiMSI6Im5vRGF0YSIsIjIiOiJkaWFsaW5nRGlnaXRzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTE4LjEuMS41Ijp7IjEiOiJpbW1lZGlhdGUiLCIyIjoiZGVsYXkxIiwiMyI6ImRlbGF5MiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMC4zIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUyMy4xLjEuMiI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjMuMS4xLjMiOnsiMSI6InRpbWVab25lMSIsIjIiOiJ0aW1lWm9uZTIiLCIzIjoidGltZVpvbmUzIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI3LjEuMS4yIjp7IjEiOiJzZXQiLCIyIjoibm9TZXQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguMSI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguMiI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguMyI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguNCI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguNSI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguNiI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjguNyI6eyIxIjoid2Vla2RheSIsIjIiOiJ3ZWVrZW5kIiwiMyI6ImhvbGlkYXkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MjkuMS4xLjIiOnsiMSI6IndlZWtkYXkiLCIyIjoid2Vla2VuZCIsIjMiOiJob2xpZGF5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTI5LjEuMS4zIjp7IjEiOiJ0aW1lWm9uZTEiLCIyIjoidGltZVpvbmUyIiwiMyI6InRpbWVab25lMyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzMC4xLjEuMiI6eyIxIjoic2V0IiwiMiI6Im5vU2V0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS4zIjp7IjEiOiJieXBhc3MiLCIyIjoic2tpcEFuZEFwcGx5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMwLjEuMS40Ijp7IjEiOiJhcHBseSIsIjIiOiJza2lwQW5kQXBwbHkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzAuMS4xLjUiOnsiMSI6ImFwcGx5IiwiMiI6InJldGFpbiIsIjMiOiJkaXNjYXJkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTMxLjEuMS4zIjp7IjEiOiJzZXQiLCIyIjoibm9TZXQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzEuMS4xLjQiOnsiMSI6ImJ5cGFzcyIsIjIiOiJza2lwQW5kQXBwbHkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzIuMS4xLjIiOnsiMSI6ImFsbG93IiwiMiI6ImRlbnkifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41MzMuMS4xLjMiOnsiMSI6InNldCIsIjIiOiJub1NldCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjUzNC4xLjEuMyI6eyIxIjoic2V0IiwiMiI6Im5vU2V0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTQwLjEuMS4yIjp7IjEiOiJub0RhdGEiLCIyIjoiZGlhbGluZ0RpZ2l0cyIsIjMiOiJuaWdodEJlbGwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzAuMyI6eyIxIjoiYWxsb3dlZCIsIjIiOiJub3RBbGxvd2VkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjEiOnsiMSI6Im9ubHlCZWZvcmVBbnN3ZXIiLCIyIjoiYmVmb3JlQW5kQWZ0ZXJBbnN3ZXJpbmcifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMTgiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIiOnsiMSI6ImF1dG9BbmRBY2Nlc3NDb2RlQ2FuY2VsIiwiMiI6ImFjY2Vzc0NvZGVDYW5jZWwifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMjAiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjIxIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS4yMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41NzkuMyI6eyIxIjoib3V0cHV0IiwiMiI6Im5vdE91dHB1dCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS40Ijp7IjEiOiJvdXRwdXQiLCIyIjoibm90T3V0cHV0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjciOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU3OS44Ijp7IjEiOiJ0aW1lODBtc2VjIiwiMiI6InRpbWUxNjBtc2VjIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTc5LjkiOnsiMSI6InVzZSIsIjIiOiJub3RVc2UifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjIiOnsiMSI6ImRUTUYiLCIyIjoic01ESSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuMyI6eyIxIjoic2VuZCIsIjIiOiJub3RTZW5kIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNTgwLjEuMS40Ijp7IjEiOiJzZW5kT25seUJUb25lIiwiMiI6Im5vdFNlbmQiLCIzIjoiYlRvbmVBbmRFeHRlbnNpb25OdW1iZXIifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy41ODAuMS4xLjUiOnsiMSI6InNlbmQiLCIyIjoibm90U2VuZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjU4MC4xLjEuOCI6eyIxIjoiYmxvY2tpbmciLCIyIjoibm9uQmxvY2tpbmcifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTAuMS4xLjIiOnsiMSI6Im9OIiwiMiI6Im9GRiJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1MC4xLjEuMyI6eyIxIjoib04iLCIyIjoib0ZGIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU3LjEuMS4zIjp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY1Ny4xLjEuNCI6eyIxIjoiYWxsb3dlZCIsIjIiOiJub3RBbGxvd2VkIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjU3LjEuMS41Ijp7IjEiOiJhbGxvd2VkIiwiMiI6Im5vdEFsbG93ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NTcuMS4xLjYiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS4xMCI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjEyIjp7IjEiOiJyVFAiLCIyIjoiZGlzY29ubmVjdCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3Mi4xLjEuMiI6eyIxIjoiaVBRU0lHIiwiMiI6ImgzMjMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjQiOnsiMSI6ImVuYWJsZSIsIjIiOiJkaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS41Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3Mi4xLjEuNiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy42NzIuMS4xLjciOnsiMSI6Imc3MTEiLCIyIjoiZzcyOUEiLCIzIjoiZzcxMU1VIiwiNCI6Imc3MTFBIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuNjcyLjEuMS44Ijp7IjEiOiJlbmFibGUiLCIyIjoiZGlzYWJsZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjY3My4xLjEuMiI6eyIxIjoibm90RXhpc3QiLCIyIjoiZXhpc3QiLCIzIjoiZGVsZXRlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuOC4xLjEuMyI6eyIxIjoiaXB1RmlsZVRyYW5zZmVyQXV0b1N0YXJ0IiwiMiI6ImlwdUZpbGVUcmFuc2ZlckF1dG9TdG9wIiwiMyI6ImlwdUZpbGVUcmFuc2ZlckltbWVkaWF0ZVNlbmQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjEzIjp7IjEiOiJ5ZXMiLCIyIjoibm8ifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjIiOnsiMSI6InRDUCIsIjIiOiJ1RFAifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjMiOnsiMSI6InNlcnZlciIsIjIiOiJjbGllbnQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDEuMS4xLjQiOnsiMSI6InN5bmNocm9uaXphdGlvbiIsIjIiOiJhc3luY2hyb25pemF0aW9uIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODAzLjEuMS4yIjp7IjEiOiJub24iLCIyIjoibEFOIiwiMyI6InJTMjMyQyJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwNC4xLjEuMiI6eyIxIjoic3BlZWQzMDAiLCIyIjoic3BlZWQxMjAwIiwiMyI6InNwZWVkMjQwMCIsIjQiOiJzcGVlZDQ4MDAiLCI1Ijoic3BlZWQ5NjAwIiwiNiI6InNwZWVkMTkyMDAiLCI3Ijoic3BlZWQzODQwMCIsIjgiOiJzcGVlZDU3NjAwIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjMuODA0LjEuMS4zIjp7IjEiOiJub24iLCIyIjoiZXZlbiIsIjMiOiJvZGQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuMy44MDQuMS4xLjQiOnsiMSI6Imxlbmd0aDdCaXQiLCIyIjoibGVuZ3RoOEJpdCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi4zLjgwNC4xLjEuNSI6eyIxIjoibm9uIiwiMiI6InNvZnQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjEuMS4xIjp7IjEiOiJzdGFydCIsIjIiOiJzdG9wIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4xLjEuMyI6eyIxIjoiY2FsbFByb2Nlc3NpbmciLCIyIjoibWFpbnRlbmFuY2UiLCIzIjoiYm90aCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMS4xLjQiOnsiMSI6Im5vcm1hbEVuZCIsIjIiOiJub3RFbmQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjEuMi4xIjp7IjAiOiJub25lIiwiMSI6Im1lc3NhZ2VUcmFjZSIsIjIiOiJpc2RuVHJhY2UiLCIzIjoiYm90aCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi41LjIuMS4yLjIiOnsiMSI6Im5vcm1hbEVuZCIsIjIiOiJub3RFbmQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4yLjEuMy4xIjp7IjEiOiJ0cmFjZU9uIiwiMiI6InRyYWNlT2ZmIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4yLjEuMS40Ijp7IjEiOiJsbGNpIiwiMiI6ImNjbDMiLCIzIjoibDJsMyIsIjQiOiJzdGF0ZSIsIjUiOiJlcnJvcnMiLCI2IjoibDJsaW5rIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjUuMi4yLjEuMS41Ijp7IjEiOiJubyIsIjIiOiJicmllZiIsIjMiOiJleHRlbnNpdmUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4zLjEiOnsiMSI6InN0YXJ0IiwiMiI6InN0b3AifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNS4zLjIiOnsiMSI6Im5vcm1hbEVuZCIsIjIiOiJub3RFbmQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi4xIjp7IjAiOiJub25lIiwiMSI6ImFsYXJtIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjYuMTEuMSI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi44LjEuMiI6eyIxIjoiZW5hYmxlIiwiMiI6ImRpc2FibGUifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNi45Ijp7IjEiOiJpZGxlIiwiMiI6Imludm9rZSJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEuMSI6eyIxIjoicmVzdGFydFdpdGhDbGVhckRhdGEiLCIyIjoicmVzdGFydCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEwLjIiOnsiMSI6IndyaXRlVGVzdCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjEyLjEiOnsiMSI6InVzYSIsIjEwIjoiaW5kb25lc2lhIiwiMTEiOiJzcmlMYW5rYSIsIjEyIjoidmlldG5hbSIsIjEzIjoiY2hpbmEiLCIxNCI6ImJyaXRhaW4iLCIxNSI6ImF1c3RyYWxpYSIsIjIiOiJjYW5hZGEiLCIzIjoibWV4aWNvIiwiNCI6InRhaXdhbiIsIjUiOiJob25nS29uZyIsIjYiOiJ0aGFpbGFuZCIsIjciOiJqYXBhbiIsIjgiOiJzaW5nYXBvcmUiLCI5IjoibWFsYXlzaWEifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xMi4yIjp7IjEiOiJ1c2EiLCIxMCI6ImluZG9uZXNpYSIsIjExIjoic3JpTGFua2EiLCIxMiI6InZpZXRuYW0iLCIxMyI6ImNoaW5hIiwiMTQiOiJicml0YWluIiwiMTUiOiJhdXN0cmFsaWEiLCIyIjoiY2FuYWRhIiwiMyI6Im1leGljbyIsIjQiOiJ0YWl3YW4iLCI1IjoiaG9uZ0tvbmciLCI2IjoidGhhaWxhbmQiLCI3IjoiamFwYW4iLCI4Ijoic2luZ2Fwb3JlIiwiOSI6Im1hbGF5c2lhIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTMuMS4xLjEiOnsiMSI6InVzYSIsIjEwIjoiaW5kb25lc2lhIiwiMTEiOiJzcmlMYW5rYSIsIjEyIjoiaW5kaWEiLCIxMyI6ImNoaW5hIiwiMTQiOiJicml0YWluIiwiMTUiOiJkdW1teTE1IiwiMTYiOiJkdW1teTE2IiwiMTciOiJkdW1teTE3IiwiMTgiOiJkdW1teTE4IiwiMTkiOiJkdW1teTE5IiwiMiI6ImNhbmFkYSIsIjIwIjoiZHVtbXkyMCIsIjIxIjoiZHVtbXkyMSIsIjIyIjoiZHVtbXkyMiIsIjIzIjoiZHVtbXkyMyIsIjI0IjoiZHVtbXkyNCIsIjI1IjoiZHVtbXkyNSIsIjI2IjoiZHVtbXkyNiIsIjI3IjoiZHVtbXkyNyIsIjI4IjoiZHVtbXkyOCIsIjI5IjoiZHVtbXkyOSIsIjMiOiJtZXhpY28iLCIzMCI6ImR1bW15MzAiLCIzMSI6ImR1bW15MzEiLCIzMiI6ImR1bW15MzIiLCI0IjoidGFpd2FuIiwiNSI6ImhvbmdLb25nIiwiNiI6InRpZSIsIjciOiJqYXBhbiIsIjgiOiJzaW5nYXBvcmUiLCI5IjoibWFsYXlzaWEifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xNC4xIjp7IjEiOiJjb2xsZWN0IiwiMiI6ImFib3J0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTQuMyI6eyIxIjoiaWRsZSIsIjIiOiJjb2xsZWN0aW5nIiwiMyI6Im5vcm1hbEVuZCIsIjQiOiJhYm5vcm1hbEVuZCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjE1LjEuMS4zIjp7IjEiOiJ1cGRJcERrdUdldEZpbGUiLCIyIjoidXBkSXBEa3VVcGRhdGUiLCIzIjoidXBkSXBEa3VSZXNldCIsIjQiOiJ1cGRJcERrdUFib3J0IiwiNSI6InVwZElwRGt1Q2FjaGVJcERrdCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjE1LjEuMS40Ijp7IjEiOiJ1cGRJcERrdUlkbGUiLCIxMCI6InVwZElwRGt1RmluaXNoZWRDYWNoaW5nIiwiMiI6InVwZElwRGt1R2V0dGluZyIsIjMiOiJ1cGRJcERrdUZpbmlzaGVkR2V0dGluZyIsIjQiOiJ1cGRJcERrdVVwZGF0aW5nIiwiNSI6InVwZElwRGt1RmluaXNoZWRVcGRhdGluZyIsIjYiOiJ1cGRJcERrdVJlc2V0dGluZyIsIjciOiJ1cGRJcERrdUFib3J0aW5nIiwiOCI6InVwZElwRGt1RXJyb3IiLCI5IjoidXBkSXBEa3VDYWNoaW5nIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTYuMS4xLjIiOnsiMSI6InVwZElwRGt0R2V0RmlsZSIsIjIiOiJ1cGRJcERrdFVwZGF0ZSIsIjMiOiJ1cGRJcERrdFJlc2V0IiwiNCI6InVwZElwRGt0QWJvcnQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xNi4xLjEuMyI6eyIxIjoidXBkSXBEa3RJZGxlIiwiMiI6InVwZElwRGt0R2V0dGluZyIsIjMiOiJ1cGRJcERrdEZpbmlzaGVkR2V0dGluZyIsIjQiOiJ1cGRJcERrdFVwZGF0aW5nIiwiNSI6InVwZElwRGt0RmluaXNoZWRVcGRhdGluZyIsIjYiOiJ1cGRJcERrdFJlc2V0dGluZyIsIjciOiJ1cGRJcERrdEFib3J0aW5nIiwiOCI6InVwZElwRGt0RXJyb3IifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xOC4xLjEuMiI6eyIxIjoiaXB0VmxhblNldCIsIjIiOiJpcHRWbGFuUmVzZXQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xOC4xLjEuMyI6eyIxIjoiaXB0VmxhbkF2YWlsYWJsZSIsIjIiOiJpcHRWbGFuTm90QXZhaWxhYmxlIiwiMyI6ImlwdFZsYW5Ob3RDb25uZWN0ZWQifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy4xOC4xLjEuNCI6eyIxIjoiaXB0VmxhbklkbGUiLCIyIjoiaXB0VmxhblByb2dyZXNzIiwiMyI6ImlwdFZsYW5FcnJvciJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjE4LjEuMS42Ijp7IjEiOiJpcHRWbGFuRW5hYmxlIiwiMiI6ImlwdFZsYW5EaXNhYmxlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMTguMS4xLjgiOnsiMSI6ImlwdFZsYW5BY2Nlc3MiLCIyIjoiaXB0VmxhblRydW5rIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMy4xLjciOnsiMCI6InN1bmRheSIsIjEiOiJtb25kYXkiLCIyIjoidHVlc2RheSIsIjMiOiJ3ZWRuZXNkYXkiLCI0IjoidGh1cnNkYXkiLCI1IjoiZnJpZGF5IiwiNiI6InNhdHVyZGF5In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuMy4xLjgiOnsiMCI6ImxlYXAiLCIxIjoibGVhcE5leHQxIiwiMiI6ImxlYXBOZXh0MiIsIjMiOiJsZWFwTmV4dDMifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy40LjEiOnsiMCI6Im5vbmUiLCIxIjoibm9ybWFsRm9ybWF0IiwiMiI6ImZvcmNlZEZvcm1hdCIsIjMiOiJ1bm1vdW50IiwiNCI6InRyYW5zZmVyIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNC4yIjp7IjEiOiJub3JtYWxFbmQiLCIyIjoiYWJub3JtYWxFbmQiLCIzIjoibm90RW5kIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNS4xIjp7IjEiOiJyZWFkIiwiMiI6IndyaXRlIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNi4xIjp7IjEiOiJjaGVja0ludm9rZSIsIjIiOiJjaGVja0ZpbmlzaCIsIjMiOiJ3cml0ZUZsYXNoIiwiNCI6InR1cm5BbmRSZXNldCIsIjUiOiJsb2NhbFVwZGF0ZSIsIjYiOiJsb2NhbFVwZGF0ZUNhbmNlbCIsIjciOiJ0dXJuQW5kSW5pdGlhbFJlc2V0In0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNi40Ijp7IjEiOiJzaWRlMCIsIjIiOiJzaWRlMSIsIjMiOiJlcnJvciJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjYuNSI6eyIxIjoibm9ybWFsIiwiMiI6InRyaWFsIiwiMyI6ImZhdWx0IiwiNCI6ImRvbnRDYXJlIiwiNSI6ImVycm9yIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNi42Ijp7IjEiOiJub3JtYWwiLCIyIjoidHJpYWwiLCIzIjoiZmF1bHQiLCI0IjoiZG9udENhcmUiLCI1IjoiZXJyb3IifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuNy42LjciOnsiMSI6ImlkbGUiLCIyIjoicnVubmluZyIsIjMiOiJzdWNjZXNzIiwiNCI6ImVycm9yIn0sIjEuMy42LjEuNC4xLjE4Ni4xLjIyLjcuNy4xIjp7IjEiOiJpbXBvcnQiLCIyIjoiZXhwb3J0IiwiMyI6ImNhbmNlbCJ9LCIxLjMuNi4xLjQuMS4xODYuMS4yMi43LjcuMiI6eyIxIjoibm9ybWFsRW5kQWxsIiwiMiI6Im5vcm1hbEVuZFBhcnQiLCIzIjoiYWJub3JtYWxFbmQiLCI0IjoiY2FuY2VsIiwiNSI6ImltcG9ydGluZyIsIjYiOiJleHBvcnRpbmcifSwiMS4zLjYuMS40LjEuMTg2LjEuMjIuOS4zIjp7IjEiOiJhZGQiLCIyIjoiZGVsIiwiMyI6InNldCJ9fQ==").decode("utf-8")  # bundled enum value labels
EMBEDDED_PROGRAM_MENUS_JSON = base64.b64decode("eyJieV9udW1iZXIiOnsiMTAwIjp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjEwMCBDYXJkIFNsb3QiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBDYXJkIEFzc2lnbm1lbnQgKDEwMCkifSwiMTAyIjp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjEwMiBGbGV4aWJsZSBOdW1iZXJpbmcgUGxhbiIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIEZsZXhpYmxlIEFjY2VzcyBDb2RlICgxMDIpIn0sIjEwMyI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMDMgQ2xhc3MgT2YgU2VydmljZSIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIENsYXNzIG9mIFNlcnZpY2UgKDEwMykifSwiMTA0Ijp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjEwNCBTeXN0ZW0gVGltZXIiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBTeXN0ZW0gVGltZXIgKDEwNCkifSwiMTA1Ijp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjEwNSBTeXN0ZW0gRGF0YSIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIFN5c3RlbSBEYXRhICgxMDUpIn0sIjEwNiI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMDYgRGF5TmlnaHQgTW9kZSBQcml2YXRlIERheSBvZiBXZWVrIE1hcHBpbmciLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBEYXkgTmlnaHQgU2VydmljZSAoMTA2LDExMiwxMTMpIn0sIjEwNyI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMDcgUGFkIFRhYmxlIiwibWVudV9wYXRoIjoiU3lzdGVtIC0gUEFEIFRhYmxlICgxMDcsMTA4LDExNCkifSwiMTA4Ijp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjEwOCBQYWQgR3JvdXAiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBQQUQgVGFibGUgKDEwNywxMDgsMTE0KSJ9LCIxMDkiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiMTA5IEV4dGVybmFsIE11c2ljIE9uIEhvbGQgU291cmNlIiwibWVudV9wYXRoIjoiU3lzdGVtIC0gTXVzaWMgT24gSG9sZCAoMTA5KSJ9LCIxMTAiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiMTEwIFBhc3N3b3JkIiwibWVudV9wYXRoIjoiU3lzdGVtIC0gUGFzc3dvcmQgKDExMCkifSwiMTExIjp7ImFyZWEiOiJMQ1IvRFIiLCJsYWJlbCI6IjExMSBEZXN0aW5hdGlvbiBSZXN0cmljdGlvbiBMZXZlbCIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIERlc3RpbmF0aW9uIFJlc3RyaWN0aW9uICg1MzIsNTMzLDUzNCwxMTEpIn0sIjExMiI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMTIgRGF5TmlnaHQgTW9kZSBQcml2YXRlIENhbGVuZGFyIiwibWVudV9wYXRoIjoiU3lzdGVtIC0gRGF5IE5pZ2h0IFNlcnZpY2UgKDEwNiwxMTIsMTEzKSJ9LCIxMTMiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiMTEzIERheU5pZ2h0IE1vZGUgU2NoZWR1bGUiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBEYXkgTmlnaHQgU2VydmljZSAoMTA2LDExMiwxMTMpIn0sIjExNCI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMTQgUGFkIENvbmZlcmVuY2UgVGFibGUiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBQQUQgVGFibGUgKDEwNywxMDgsMTE0KSJ9LCIxMTUiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiMTE1IEFkdmlzb3J5IE1lc3NhZ2UiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBBZHZpc29yeSBNZXNzYWdlICgxMTUpIn0sIjExNiI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMTYgRGF0YUluaXRpYWxpemUiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBEYXRhIEluaXRpYWxpemUgKDExNikifSwiMTE3Ijp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjExNyBQdWJsaWMgTnVtYmVyaW5nIFBsYW4gQW5hbHl6ZWQgRGlnaXRzIiwibWVudV9wYXRoIjoiU3lzdGVtIC0gUHVibGljIE51bWJlcmluZyBQbGFuICgxMTcpIn0sIjExOCI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMTggTG9jayBQYXNzd29yZCIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIExvY2sgUGFzc3dvcmQgKDExOCkifSwiMTE5Ijp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjExOSBJbml0aWFsaXplIExvY2sgUGFzc3dvcmQiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBJbml0aWFsaXplIExvY2sgUGFzc3dvcmQgKDExOSkifSwiMTIwIjp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjEyMCBUZW5hbnQgRGF0YSIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIFRlbmFudCBEYXRhICgxMjApIn0sIjEyMSI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiIxMjEgQXV0b21hdGljIERheWxpZ2h0IFNhdmluZyBDaGFuZ2UiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBBdXRvbWF0aWMgRGF5bGlnaHQgU2F2aW5nIENoYW5nZSAoMTIxKSJ9LCIxNTAiOnsiYXJlYSI6IklQLVRlbGVwaG9ueSIsImxhYmVsIjoiMTUwIFN5c3RlbSBJUCBEYXRhIEFzc2lnbm1lbnQiLCJtZW51X3BhdGgiOiJJUC1UZWxlcGhvbnkgLSBTeXN0ZW0gSVAgRGF0YSAoMTUwKSJ9LCIxNTEiOnsiYXJlYSI6IklQLVRlbGVwaG9ueSIsImxhYmVsIjoiMTUxIEJJUFUgQ29uZmlndXJhdGlvbiIsIm1lbnVfcGF0aCI6IklQLVRlbGVwaG9ueSAtIEJJUFUgQ29uZmlndXJhdGlvbiAoMTUxKSJ9LCIxNTIiOnsiYXJlYSI6IklQLVRlbGVwaG9ueSIsImxhYmVsIjoiMTUyIFZvaWNlIFBhY2tldCBDb25maWd1cmF0aW9uIiwibWVudV9wYXRoIjoiSVAtVGVsZXBob255IC0gVm9pY2UgUGFja2V0IENvbmZpZ3VyYXRpb24gKDE1MikifSwiMTUzIjp7ImFyZWEiOiJJUC1UZWxlcGhvbnkiLCJsYWJlbCI6IjE1MyBWb2ljZSBQcm9jZXNzb3IgQ29udHJvbCIsIm1lbnVfcGF0aCI6IklQLVRlbGVwaG9ueSAtIEJJUFUgRFNQIENvbnRyb2wgKDE1MykifSwiMTYxIjp7ImFyZWEiOiJJUC1UZWxlcGhvbnkiLCJsYWJlbCI6IjE2MSBMSVBVIENvbmZpZ3VyYXRpb24iLCJtZW51X3BhdGgiOiJJUC1UZWxlcGhvbnkgLSBJUFUvSVBIIENvbmZpZ3VyYXRpb24gKDE2MSkifSwiMTYzIjp7ImFyZWEiOiJJUC1UZWxlcGhvbnkiLCJsYWJlbCI6IjE2MyBMSVBVIHZvaWNlIFByb2Nlc3NvciBDb250cm9sIiwibWVudV9wYXRoIjoiSVAtVGVsZXBob255IC0gTElQVS9HSVBIIERTUCBDb250cm9sICgxNjMpIn0sIjE2NCI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjE2NCBGdWxsIElQIFFzaWcgRFRNRiBEZXRlY3Rpb24iLCJtZW51X3BhdGgiOiJUcnVuayAtIEZ1bGwgSVAgUXNpZyBEVE1GIERldGVjdGlvbiAoMTY0KSJ9LCIxNjUiOnsiYXJlYSI6IklQLVRlbGVwaG9ueSIsImxhYmVsIjoiMTY1IEZheCBPdmVyIElQIFN5c3RlbSBEYXRhIEFzc2lnbm1lbnQiLCJtZW51X3BhdGgiOiJJUC1UZWxlcGhvbnkgLSBGYXggT3ZlciBJUCBTeXN0ZW0gRGF0YSBBc3NpZ25tZW50ICgxNjUpIn0sIjE2NiI6eyJhcmVhIjoiSVAtVGVsZXBob255IiwibGFiZWwiOiIxNjYgRmF4IE92ZXIgSVAgUGFyYW1ldGVyIFRhYmxlIEFzc2lnbm1lbnQiLCJtZW51X3BhdGgiOiJJUC1UZWxlcGhvbnkgLSBGYXggUGFyYW1ldGVyICgxNjYpIn0sIjIwMCI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjAwIFN0YXRpb24gQXNzaWdubWVudCIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBBc3NpZ25tZW50IC0gQmFzaWMgKDIwMCwyMDEqLDIwMyosMjYwKikifSwiMjAxIjp7ImFyZWEiOiJTdGF0aW9uIiwibGFiZWwiOiIyMDEgU3RhdGlvbiBEZWxldGUiLCJtZW51X3BhdGgiOiJTdGF0aW9uIC0gQXNzaWdubWVudCAtIEJhc2ljICgyMDAsMjAxKiwyMDMqLDI2MCopIn0sIjIwMiI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjAyIElTRE4gU3RhdGlvbiBBc3NpZ25tZW50IiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIEJhc2ljIElTRE4gKDIwMikifSwiMjAzIjp7ImFyZWEiOiJTdGF0aW9uIiwibGFiZWwiOiIyMDMgRE4gQ2hhbmdlIiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIEFzc2lnbm1lbnQgLSBCYXNpYyAoMjAwLDIwMSosMjAzKiwyNjAqKSJ9LCIyMDQiOnsiYXJlYSI6IlN0YXRpb24iLCJsYWJlbCI6IjIwNCBES1QgRGF0YSIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBBc3NpZ25tZW50IC0gREtUICgyMDQpIn0sIjIwNSI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjA1IFN0YXRpb24gRmVhdHVyZSBLZXkiLCJtZW51X3BhdGgiOiJTdGF0aW9uIC0gQXNzaWdubWVudCAtIEtleSAoMjA1LDIxMywyMTUpIn0sIjIwNiI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjA2IFBoRE4gcGFyYW1ldGVyIiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIFBoYW50b20gRE4gKDIwNikifSwiMjA4Ijp7ImFyZWEiOiJTdGF0aW9uIiwibGFiZWwiOiIyMDggU3RhdGlvbiBUaW1lciIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBBc3NpZ25tZW50IC0gVGltZXIgKDIwOCkifSwiMjA5Ijp7ImFyZWEiOiJTdGF0aW9uIiwibGFiZWwiOiIyMDkgU3RhdGlvbiBIdW50aW5nIEdyb3VwIiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIEh1bnQgR3JvdXAgLSBHcm91cCAoMjA5LCAyMTgpIn0sIjIxMCI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjEwIENhbGwgUGlja1VwIEdyb3VwIiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIFBpY2t1cCBHcm91cCAoMjEwKSJ9LCIyMTMiOnsiYXJlYSI6IlN0YXRpb24iLCJsYWJlbCI6IjIxMyBBZGQgT24gTW9kdWxlIEtleSIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBBc3NpZ25tZW50IC0gS2V5KDIwNSwyMTMsMjE1KSJ9LCIyMTQiOnsiYXJlYSI6IlN0YXRpb24iLCJsYWJlbCI6IjIxNCBEU1MgQ29uc29sZSIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBBc3NpZ25tZW50IC0gRFNTICgyMTQpIn0sIjIxNSI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjE1IERTUyBrZXkiLCJtZW51X3BhdGgiOiJTdGF0aW9uIC0gQXNzaWdubWVudCAtIEtleSAoMjA1LDIxMywyMTUpIn0sIjIxNiI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjE2IEVtZXJnZW5jeSBSaW5nIERvd24iLCJtZW51X3BhdGgiOiJTdGF0aW9uIC0gQXNzaWdubWVudCAtIFJpbmcgRG93biAoMjE2KSJ9LCIyMTciOnsiYXJlYSI6IlN0YXRpb24iLCJsYWJlbCI6IjIxNyBJU0ROIEluZGl2aWR1YWwgU3RhdGlvbiBEYXRhIiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIElTRE4gU3RhdGlvbiBEYXRhICgyMTcpIn0sIjIxOCI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiMjE4IFN0YXRpb24gSHVudGluZyBHcm91cCBNZW1iZXIiLCJtZW51X3BhdGgiOiJTdGF0aW9uIC0gSHVudCBHcm91cCAtIE1lbWJlciAoMjA5LCAyMTgpIn0sIjIxOSI6eyJhcmVhIjoiTmV0d29ya2luZyIsImxhYmVsIjoiMjE5IE5ldHdvcmsgRFNTIEtleSBOb3RpZnkgRGF0YSBEZWxldGUiLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gTmV0d29yayBEU1MgTm90aWZ5IERhdGEgRGVsZXRlICgyMTkpIn0sIjI1MCI6eyJhcmVhIjoiSVAtVGVsZXBob255IiwibGFiZWwiOiIyNTAgU3RhdGlvbiBJUCBEYXRhIEFzc2lnbm1lbnQiLCJtZW51X3BhdGgiOiJJUC1UZWxlcGhvbnkgLSBTdGF0aW9uIElQIERhdGEgKDI1MCkifSwiMjYwIjp7ImFyZWEiOiJJUC1UZWxlcGhvbnkiLCJsYWJlbCI6IjI2MCBTdGF0aW9uIElQIEFzc2lnbm1lbnQiLCJtZW51X3BhdGgiOiJJUC1UZWxlcGhvbnkgLSBTdGF0aW9uIEFzc2lnbm1lbnQgLSBCYXNpYyAoMjAwLDIwMSosMjAzKiwyNjAqKSJ9LCIzMDAiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMDAgVHJ1bmsgQXNzaWduIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBUcnVuayBBc3NpZ25tZW50IC0gQmFzaWMgKDMwMCwzMDEqKSJ9LCIzMDEiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMDEgVHJ1bmsgRGVsZXRlIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBUcnVuayBBc3NpZ25tZW50IC0gQmFzaWMgKDMwMCwzMDEqKSJ9LCIzMDIiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMDIgSVNETiBQcmltYXJ5IFRydW5rIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBJU0ROIFBSSSAoMzAyLDMwMyopIn0sIjMwMyI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMwMyBJU0ROIFRydW5rIERlbGV0ZSIsIm1lbnVfcGF0aCI6IlRydW5rIC0gSVNETiBQUkkgKDMwMiwzMDMqKSJ9LCIzMDQiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMDQgSW5jb21pbmcgTGluZSBHcm91cCIsIm1lbnVfcGF0aCI6IlRydW5rIC0gSUxHICgzMDQsMzA1KSJ9LCIzMDUiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMDUgSUxHIERlbGV0ZSIsIm1lbnVfcGF0aCI6IlRydW5rIC0gSUxHICgzMDQsMzA1KSJ9LCIzMDYiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMDYgT3V0Z29pbmcgTGluZSBHcm91cCIsIm1lbnVfcGF0aCI6IlRydW5rIC0gT0xHICgzMDYsMzA3KikifSwiMzA3Ijp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzA3IE9MRyBEZWxldGUiLCJtZW51X3BhdGgiOiJUcnVuayAtIE9MRyAoMzA2LDMwNyopIn0sIjMwOCI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMwOCBUcnVuayBUaW1lciIsIm1lbnVfcGF0aCI6IlRydW5rIC0gVHJ1bmsgQXNzaWdubWVudCAtIFRpbWVyICgzMDgpIn0sIjMwOSI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMwOSBEaXJlY3QgSW53YXJkIERpYWxpbmciLCJtZW51X3BhdGgiOiJUcnVuayAtIERJRCAoMzA5LDMxMiopIn0sIjMxMCI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMxMCBEaXJlY3QgSW53YXJkIFRlcm1pbmF0aW9uIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBUcnVuayBBc3NpZ25tZW50IC0gRElUICgzMTApIn0sIjMxMSI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMxMSBESVNBIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBTZXJ2aWNlICgzMTEsMzE5KSJ9LCIzMTIiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMTIgRElEIE51bWJlciBEZWxldGUiLCJtZW51X3BhdGgiOiJUcnVuayAtIERJRCAoMzA5LDMxMiopIn0sIjMxMyI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMxMyBDYWxsZXIgSUQiLCJtZW51X3BhdGgiOiJUcnVuayAtIFRydW5rIEFzc2lnbm1lbnQgLSBDYWxsZXIgSUQgKDMxMykifSwiMzE1Ijp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzE1IFQxIFRydW5rIENhcmQgRGF0YSIsIm1lbnVfcGF0aCI6IlRydW5rIC0gVDEgKDMxNSkifSwiMzE2Ijp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzE2IERDSCBTaGFyZWQgSVNETiBQcmltYXJ5IFRydW5rIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBEIENoYW5uZWwgKDMxNikifSwiMzE3Ijp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzE3IElTRE4gQmFzaWMgVHJ1bmsiLCJtZW51X3BhdGgiOiJUcnVuayAtIElTRE4gQlJJICgzMTcpIn0sIjMxOCI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMxOCBObyBDcG4gb3IgT3V0IE9mIFNlYXJjaCBESUQiLCJtZW51X3BhdGgiOiJUcnVuayAtIERJRCBJbnRlcmNlcHQgKDMxOCkifSwiMzE5Ijp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzE5IEludGVyY2VwdCBQb3NpdGlvbiIsIm1lbnVfcGF0aCI6IlRydW5rIC0gU2VydmljZSAoMzExLDMxOSkifSwiMzIwIjp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzIwIEIgQ2hhbm5lbCBQb3NpdGlvbiBJU0ROIFByaW1hcnkgVHJ1bmsiLCJtZW51X3BhdGgiOiJUcnVuayAtIEIgQ2hhbm5lbCAoMzIwKSJ9LCIzMjEiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMjEgSVNETiBDYWxsaW5nIE51bWJlciBJZGVudGlmaWNhdGlvbiIsIm1lbnVfcGF0aCI6IlRydW5rIC0gQ2FsbGluZyBOdW1iZXIgKDMyMSwzMjIpIn0sIjMyMiI6eyJhcmVhIjoiVHJ1bmsiLCJsYWJlbCI6IjMyMiBJU0ROIENhbGxpbmcgTnVtYmVyIFRhYmxlIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBDYWxsaW5nIE51bWJlciAoMzIxLDMyMikifSwiMzIzIjp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzIzIENhbGwgQnkgQ2FsbCBTZXJ2aWNlIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBJU0ROIENhbGwgQnkgQ2FsbCAoMzIzLDMyNCkifSwiMzI0Ijp7ImFyZWEiOiJUcnVuayIsImxhYmVsIjoiMzI0IENhbGwgQnkgQ2FsbCBUaW1lIFpvbmUiLCJtZW51X3BhdGgiOiJUcnVuayAtIElTRE4gQ2FsbCBCeSBDYWxsICgzMjMsMzI0KSJ9LCIzMjUiOnsiYXJlYSI6IlRydW5rIiwibGFiZWwiOiIzMjUgRnVsbCBJUCBRc2lnIiwibWVudV9wYXRoIjoiVHJ1bmsgLSBGdWxsIElQIFFzaWcgKDMyNSkifSwiMzI2Ijp7ImFyZWEiOiJJUC1UZWxlcGhvbnkiLCJsYWJlbCI6IjMyNiBTSVAgVHJ1bmsiLCJtZW51X3BhdGgiOiJJUC1UZWxlcGhvbnkgLSBTSVAgVHJ1bmtpbmcgLSBDaGFubmVsIEdyb3VwIFNldHRpbmcgKDMyNiwzMjcsMzI4LDMyOSkifSwiMzI3Ijp7ImFyZWEiOiJJUC1UZWxlcGhvbnkiLCJsYWJlbCI6IjMyNyBTSVAgVHJ1bmsgU2VydmljZSBLaW5kIEFzc2lnbiIsIm1lbnVfcGF0aCI6IklQLVRlbGVwaG9ueSAtIFNJUCBUcnVua2luZyAtIENoYW5uZWwgR3JvdXAgU2V0dGluZyAoMzI2LDMyNywzMjgsMzI5KSJ9LCIzMjgiOnsiYXJlYSI6IklQLVRlbGVwaG9ueSIsImxhYmVsIjoiMzI4IFNJUCBUcnVuayBTZXJ2aWNlIEFzc2lnbiIsIm1lbnVfcGF0aCI6IklQLVRlbGVwaG9ueSAtIFNJUCBUcnVua2luZyAtIFNlcnZpY2UgRGVmaW5pdGlvbiAoMzI2LDMyNywzMjgsMzI5KSJ9LCIzMjkiOnsiYXJlYSI6IklQLVRlbGVwaG9ueSIsImxhYmVsIjoiMzI5IFNJUCBVUkkgQXNzaWduIiwibWVudV9wYXRoIjoiSVAtVGVsZXBob255IC0gU0lQIFRydW5raW5nIC0gVVJJKDMyNiwzMjcsMzI4LDMyOSkifSwiNDAwIjp7ImFyZWEiOiJBdHRlbmRhbnQiLCJsYWJlbCI6IjQwMCBFbWVyZ2VuY3kgQ2FsbCBEZXN0aW5hdGlvbiIsIm1lbnVfcGF0aCI6IkF0dGVuZGFudCAtIEVtZXJnZW5jeSBDYWxsICg0MDApIn0sIjQwNCI6eyJhcmVhIjoiQXR0ZW5kYW50IiwibGFiZWwiOiI0MDQgQXR0ZW5kYW50IEdyb3VwIiwibWVudV9wYXRoIjoiQXR0ZW5kYW50IC0gR3JvdXAgQXNzaWdubWVudCAoNDA0KSJ9LCI1MDAiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiNTAwIFN5c3RlbSBDYWxsIEZvcndhcmQiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBTeXN0ZW0gQ2FsbCBGb3J3YXJkICg1MDAsNTA0KSJ9LCI1MDEiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiNTAxIFN5c3RlbSBTcGVlZCBEaWFsIiwibWVudV9wYXRoIjoiU3lzdGVtIC0gU3lzdGVtIFNwZWVkIERpYWwgKDUwMSkifSwiNTAyIjp7ImFyZWEiOiJTdGF0aW9uIiwibGFiZWwiOiI1MDIgVGVybWluYWwgUGFnaW5nIEdyb3VwIiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIFBhZ2luZyBHcm91cCAoNTAyKSJ9LCI1MDMiOnsiYXJlYSI6IkV4dGVybmFsIERldmljZXMiLCJsYWJlbCI6IjUwMyBQYWdpbmcgRGV2aWNlIFBhZ2luZyBHcm91cCIsIm1lbnVfcGF0aCI6IkV4dGVybmFsIERldmljZXMgLSBQYWdpbmcgRGV2aWNlcyAoNTAzKSJ9LCI1MDQiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiNTA0IFN5c3RlbSBDYWxsIEZvcndhcmQgVHlwZSIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIFN5c3RlbSBDYWxsIEZvcndhcmQgKDUwMCw1MDQpIn0sIjUwNiI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MDYgVmVyaWZpZWQgQWNjb3VudCBDb2RlIiwibWVudV9wYXRoIjoiTENSL0RSIC0gU2V0IEFjY291bnQgQ29kZXMgKDUwNiw1NzAsNTcxKSJ9LCI1MDciOnsiYXJlYSI6IkV4dGVybmFsIERldmljZXMiLCJsYWJlbCI6IjUwNyBEb29yIFBob25lIiwibWVudV9wYXRoIjoiRXh0ZXJuYWwgRGV2aWNlcyAtIERvb3IgUGhvbmVzICg1MDcsNTA4LDU3MyosNTc2KSJ9LCI1MDgiOnsiYXJlYSI6IkV4dGVybmFsIERldmljZXMiLCJsYWJlbCI6IjUwOCBEb29yIExvY2sgQ29udHJvbCIsIm1lbnVfcGF0aCI6IkV4dGVybmFsIERldmljZXMgLSBEb29yIFBob25lcyAoNTA3LDUwOCw1NzMqLDU3NikifSwiNTA5Ijp7ImFyZWEiOiJMQ1IvRFIiLCJsYWJlbCI6IjUwOSBUb2xsIFJlc3RyaWN0aW9uIE92ZXJyaWRlIGJ5IFNwZWVkIERpYWwiLCJtZW51X3BhdGgiOiJMQ1IvRFIgLSBEUiBPdmVycmlkZSBieSBTeXN0ZW0gU3BlZWQgRGlhbCAoNTA5KSJ9LCI1MTAiOnsiYXJlYSI6IkxDUi9EUiIsImxhYmVsIjoiNTEwIENsYXNzIE9mIFNlcnZpY2UgT3ZlcnJpZGUiLCJtZW51X3BhdGgiOiJMQ1IvRFIgLSBDT1MgT3ZlcnJpZGUgKDUxMCkifSwiNTEyIjp7ImFyZWEiOiJNaXNjZWxsYW5lb3VzIiwibGFiZWwiOiI1MTIgU01EUiBmb3IgU1lTVEVNIiwibWVudV9wYXRoIjoiTWlzY2VsbGFuZW91cyAtIFNNRFIgKDUxMiw1MTMsNTE0KSJ9LCI1MTMiOnsiYXJlYSI6Ik1pc2NlbGxhbmVvdXMiLCJsYWJlbCI6IjUxMyBTTURSIGZvciBJTEciLCJtZW51X3BhdGgiOiJNaXNjZWxsYW5lb3VzIC0gU01EUiAoNTEyLDUxMyw1MTQpIn0sIjUxNCI6eyJhcmVhIjoiTWlzY2VsbGFuZW91cyIsImxhYmVsIjoiNTE0IFNNRFIgZm9yIE9MRyIsIm1lbnVfcGF0aCI6Ik1pc2NlbGxhbmVvdXMgLSBTTURSICg1MTIsNTEzLDUxNCkifSwiNTE1Ijp7ImFyZWEiOiJFeHRlcm5hbCBEZXZpY2VzIiwibGFiZWwiOiI1MTUgUmVsYXkgU2VydmljZSBEaXNwbGF5IiwibWVudV9wYXRoIjoiRXh0ZXJuYWwgRGV2aWNlcyAtIEJJT1UgUmVsYXkgVHlwZSAoNTE1KSJ9LCI1MTYiOnsiYXJlYSI6IlN0YXRpb24iLCJsYWJlbCI6IjUxNiBTdGF0aW9uIFNwZWVkIERpYWwiLCJtZW51X3BhdGgiOiJTdGF0aW9uIC0gU3BlZWQgRGlhbCAoNTE2KSJ9LCI1MTciOnsiYXJlYSI6IlN0YXRpb24iLCJsYWJlbCI6IjUxNyBNdWx0aXBsZSBDYWxsIEdyb3VwIiwibWVudV9wYXRoIjoiU3RhdGlvbiAtIE11bHRpcGxlIENhbGwgR3JvdXAgLSBHcm91cCAoNTE3LDUxOSopIn0sIjUxOCI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiNTE4IE11bHRpcGxlIENhbGwgTWVtYmVycyIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBNdWx0aXBsZSBDYWxsIEdyb3VwIC0gTWVtYmVycyAoNTE4KSJ9LCI1MTkiOnsiYXJlYSI6IlN0YXRpb24iLCJsYWJlbCI6IjUxOSBNdWx0aXBsZSBDYWxsIEdyb3VwIERlbGV0ZSIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBNdWx0aXBsZSBDYWxsIEdyb3VwIC0gR3JvdXAgKDUxNyw1MTkqKSJ9LCI1MjAiOnsiYXJlYSI6IkxDUi9EUiIsImxhYmVsIjoiNTIwIExDUiBQYXJhbWV0ZXJzIiwibWVudV9wYXRoIjoiTENSL0RSIC0gQXNzaWdubWVudCAoNTIwLDUyMSw1MjIpIn0sIjUyMSI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MjEgTENSIFJvdXRpbmcgUGxhbiBBbmFseXNpc1RhYmxlIiwibWVudV9wYXRoIjoiTENSL0RSIC0gQXNzaWdubWVudCAoNTIwLDUyMSw1MjIpIn0sIjUyMiI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MjIgTENSIEV4Y2VwdGlvbmFsIFJvdXRpbmcgUGxhbiBBbmFseXNpc1RhYmxlIiwibWVudV9wYXRoIjoiTENSL0RSIC0gQXNzaWdubWVudCAoNTIwLDUyMSw1MjIpIn0sIjUyMyI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MjMgTENSIFJvdXRlIFBsYW4gU2NoZWR1bGVUYWJsZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIFJvdXRlIFNjaGVkdWxlICg1MjMsNTI4KSJ9LCI1MjQiOnsiYXJlYSI6IkxDUi9EUiIsImxhYmVsIjoiNTI0IExDUiBSb3V0ZSBDaG9pY2VUYWJsZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIFJvdXRlIERlZmluZSAoNTI0LDUyNSw1MjYpIn0sIjUyNSI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MjUgTENSIFJvdXRlIERlZmluaXRpb25UYWJsZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIFJvdXRlIERlZmluZSAoNTI0LDUyNSw1MjYpIn0sIjUyNiI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MjYgTENSIERpZ2l0IE1vZGlmaWNhdGlvblRhYmxlIiwibWVudV9wYXRoIjoiTENSL0RSIC0gUm91dGUgRGVmaW5lICg1MjQsNTI1LDUyNikifSwiNTI3Ijp7ImFyZWEiOiJMQ1IvRFIiLCJsYWJlbCI6IjUyNyBMQ1IgUHVibGljIEhvbGlkYXkgQ2FsZW5kYXIgVGFibGUiLCJtZW51X3BhdGgiOiJMQ1IvRFIgLSBQdWJsaWMgSG9saWRheXMgYW5kIExDUiBUaW1lIFpvbmVzICg1MjcsNTI5KSJ9LCI1MjgiOnsiYXJlYSI6IkxDUi9EUiIsImxhYmVsIjoiNTI4IExDUiBQdWJsaWMgRGF5IE9mIFdlZWsgTWFwcGluZyBUYWJsZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIFJvdXRlIFNjaGVkdWxlICg1MjMsNTI4KSJ9LCI1MjkiOnsiYXJlYSI6IkxDUi9EUiIsImxhYmVsIjoiNTI5IExDUiBSb3V0ZSBQbGFuIFNjaGVkdWxlIFRhYmxlIFRpbWUgWm9uZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIFB1YmxpYyBIb2xpZGF5cyBhbmQgTENSIFRpbWUgWm9uZXMgKDUyNyw1MjkpIn0sIjUzMCI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MzAgVG9sbCBSZXN0cmljdGlvbiBMQ1IgU2NyZWVuaW5nIFRhYmxlIiwibWVudV9wYXRoIjoiTENSL0RSIC0gTENSL0RSIFNjcmVlbmluZyAoNTMwLDUzMSkifSwiNTMxIjp7ImFyZWEiOiJMQ1IvRFIiLCJsYWJlbCI6IjUzMSBUb2xsIFJlc3RyaWN0aW9uIExDUiBTY3JlZW5pbmcgRm9yIE9MRyBUYWJsZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIExDUi9EUiBTY3JlZW5pbmcgKDUzMCw1MzEpIn0sIjUzMiI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MzIgVG9sbCBSZXN0cmljdGlvblRhYmxlIEFsbG93IERlbnkiLCJtZW51X3BhdGgiOiJMQ1IvRFIgLSBEZXN0aW5hdGlvbiBSZXN0cmljdGlvbiAoNTMyLDUzMyw1MzQsMTExKSJ9LCI1MzMiOnsiYXJlYSI6IkxDUi9EUiIsImxhYmVsIjoiNTMzIFRvbGwgUmVzdHJpY3Rpb25UYWJsZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIERlc3RpbmF0aW9uIFJlc3RyaWN0aW9uICg1MzIsNTMzLDUzNCwxMTEpIn0sIjUzNCI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MzQgRXhjZXB0aW9uYWwgVG9sbCBSZXN0cmljdGlvbiBUYWJsZSIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIERlc3RpbmF0aW9uIFJlc3RyaWN0aW9uICg1MzIsNTMzLDUzNCwxMTEpIn0sIjUzNSI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1MzUgTENSIFBETiBhbmQgQXV0aG9yaXphdGlvbiBDb2RlIiwibWVudV9wYXRoIjoiTENSL0RSIC0gTENSIFBETiBhbmQgQXV0aG9yaXphdGlvbiBDb2RlICg1MzUpIn0sIjU0MCI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiNTQwIEFDRCBQaWxvdCBETiIsIm1lbnVfcGF0aCI6IlN0YXRpb24gLSBQaWxvdCBETiAoNTQwLDU0MSopIn0sIjU0MSI6eyJhcmVhIjoiU3RhdGlvbiIsImxhYmVsIjoiNTQxIERlbGV0ZSBBQ0QgUGlsb3QgRE4iLCJtZW51X3BhdGgiOiJTdGF0aW9uIC0gUGlsb3QgRE4gKDU0MCw1NDEqKSJ9LCI1NTAiOnsiYXJlYSI6Ik1pc2NlbGxhbmVvdXMiLCJsYWJlbCI6IjU1MCBFbmhhbmNlZCA5MTEgRW1lcmdlbmN5IENhbGwgR3JvdXAiLCJtZW51X3BhdGgiOiJNaXNjZWxsYW5lb3VzIC0gRW5oYW5jZWQgOTExICg1NTApIn0sIjU1MSI6eyJhcmVhIjoiTmV0d29ya2luZyIsImxhYmVsIjoiNTUxIC0gRW1lcmdlbmN5IE5ldHdvcmsgQWNjZXNzIENvZGUiLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gRW1lcmdlbmN5IE5ldHdvcmsgQWNjZXNzIENvZGUgQXNzaWdtZW50ICg1NTEpIn0sIjU3MCI6eyJhcmVhIjoiTENSL0RSIiwibGFiZWwiOiI1NzAgQWNjb3VudCBDb2RlIERpZ2l0IExlbmd0aCIsIm1lbnVfcGF0aCI6IkxDUi9EUiAtIEFjY291bnQgQ29kZXMgLSBEaWdpdCBMZW5ndGggKDUwNiw1NzAsNTcxKSJ9LCI1NzEiOnsiYXJlYSI6IkxDUi9EUiIsImxhYmVsIjoiNTcxIEV4Y2VwdGlvbiBOdW1iZXIgT2YgRm9yY2VkIEFjY291bnQgQ29kZXMiLCJtZW51X3BhdGgiOiJMQ1IvRFIgLSBBY2NvdW50IENvZGVzIC0gRXhjZXB0aW9uIE51bWJlciAoNTA2LDU3MCw1NzEpIn0sIjU3MyI6eyJhcmVhIjoiRXh0ZXJuYWwgRGV2aWNlcyIsImxhYmVsIjoiNTczIERvb3IgUGhvbmUgRGVsZXRlIiwibWVudV9wYXRoIjoiRXh0ZXJuYWwgRGV2aWNlcyAtIERvb3IgUGhvbmVzICg1MDcsNTA4LDU3MyosNTc2KSJ9LCI1NzYiOnsiYXJlYSI6IkV4dGVybmFsIERldmljZXMiLCJsYWJlbCI6IjU3NiBEb29yIFBob25lIFJpbmcgb24gRXh0ZXJuYWwgUGFnaW5nIEluIE5pZ2h0IE1vZGUiLCJtZW51X3BhdGgiOiJFeHRlcm5hbCBEZXZpY2VzIC0gRG9vciBQaG9uZXMgKDUwNyw1MDgsNTczKiw1NzYpIn0sIjU3NyI6eyJhcmVhIjoiTWlzY2VsbGFuZW91cyIsImxhYmVsIjoiNTc3IENhbGwgSGlzdG9yeSBTdG9yZSBUZXJtaW5hbCIsIm1lbnVfcGF0aCI6Ik1pc2NlbGxhbmVvdXMgLSBDYWxsIEhpc3RvcnkgU3RvcmUgVGVybWluYWwgKDU3NykifSwiNTc5Ijp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjU3OSBWb2ljZSBNYWlsIERhdGEgRm9yIFN5c3RlbSIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIFZvaWNlIE1haWwgRGF0YSAoNTc5KSJ9LCI1ODAiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiNTgwIFZvaWNlIE1haWwgRGF0YSIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIFZvaWNlIE1haWwgUG9ydCBEYXRhICg1ODApIn0sIjY1MCI6eyJhcmVhIjoiTWlzY2VsbGFuZW91cyIsImxhYmVsIjoiNjUwIEJlaGluZCBDZW50cmV4IEFzc2lnbm1lbnQiLCJtZW51X3BhdGgiOiJNaXNjZWxsYW5lb3VzIC0gQmVoaW5kIENlbnRyZXggKDY1MCkifSwiNjUxIjp7ImFyZWEiOiJOZXR3b3JraW5nIiwibGFiZWwiOiI2NTEgUHJpdmF0ZSBSb3V0ZSBQbGFuIEFuYWx5c2lzVGFibGUiLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gUm91dGUgUGxhbiBBbmFseXNpcyAoNjUxKSJ9LCI2NTMiOnsiYXJlYSI6Ik5ldHdvcmtpbmciLCJsYWJlbCI6IjY1MyBQcml2YXRlIFJvdXRlIENob2ljZVRhYmxlIiwibWVudV9wYXRoIjoiTmV0d29ya2luZyAtIFJvdXRlIENob2ljZSBEZWZpbml0aW9uICg2NTMsNjU0LDY1NSkifSwiNjU0Ijp7ImFyZWEiOiJOZXR3b3JraW5nIiwibGFiZWwiOiI2NTQgUHJpdmF0ZSBSb3V0ZSBEZWZpbml0aW9uVGFibGUiLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gUm91dGUgQ2hvaWNlIERlZmluaXRpb24gKDY1Myw2NTQsNjU1KSJ9LCI2NTUiOnsiYXJlYSI6Ik5ldHdvcmtpbmciLCJsYWJlbCI6IjY1NSBQcml2YXRlIERpZ2l0IE1vZGlmaWNhdGlvblRhYmxlIiwibWVudV9wYXRoIjoiTmV0d29ya2luZyAtIFJvdXRlIENob2ljZSBEZWZpbml0aW9uICg2NTMsNjU0LDY1NSkifSwiNjU2Ijp7ImFyZWEiOiJOZXR3b3JraW5nIiwibGFiZWwiOiI2NTYgTm9kZSBJRCIsIm1lbnVfcGF0aCI6Ik5ldHdvcmtpbmcgLSBOb2RlIElEICg2NTYpIn0sIjY1NyI6eyJhcmVhIjoiTmV0d29ya2luZyIsImxhYmVsIjoiNjU3IG5ldHdvcmsgQ09TIE1hcHBpbmciLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gTWFwcGluZyAoNjU3LDY1OCw2NTksNjYwKSJ9LCI2NTgiOnsiYXJlYSI6Ik5ldHdvcmtpbmciLCJsYWJlbCI6IjY1OCBuZXR3b3JrIERSTCBNYXBwaW5nIiwibWVudV9wYXRoIjoiTmV0d29ya2luZyAtIE1hcHBpbmcgKDY1Nyw2NTgsNjU5LDY2MCkifSwiNjU5Ijp7ImFyZWEiOiJOZXR3b3JraW5nIiwibGFiZWwiOiI2NTkgbmV0d29yayBGUkwgTWFwcGluZyIsIm1lbnVfcGF0aCI6Ik5ldHdvcmtpbmcgLSBNYXBwaW5nICg2NTcsNjU4LDY1OSw2NjApIn0sIjY2MCI6eyJhcmVhIjoiTmV0d29ya2luZyIsImxhYmVsIjoiNjYwIG5ldHdvcmsgUVBMIE1hcHBpbmciLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gTWFwcGluZyAoNjU3LDY1OCw2NTksNjYwKSJ9LCI2NjEiOnsiYXJlYSI6Ik5ldHdvcmtpbmciLCJsYWJlbCI6IjY2MSBuZXR3b3JrIERuIFRhYmxlIiwibWVudV9wYXRoIjoiTmV0d29ya2luZyAtIE5ldHdvcmsgRE4gVGFibGUgKDY2MSkifSwiNjcwIjp7ImFyZWEiOiJOZXR3b3JraW5nIiwibGFiZWwiOiI2NzAgUmVtb3RlIE5vZGUgRGF0YSBBc3NpZ25tZW50IiwibWVudV9wYXRoIjoiTmV0d29ya2luZyAtIFJlbW90ZSBOb2RlIERhdGEgKDY3MCkifSwiNjcxIjp7ImFyZWEiOiJOZXR3b3JraW5nIiwibGFiZWwiOiI2NzEgSVAgQWRkcmVzcyBDb252ZXJ0IGZvciBQTk92ZXJJUCIsIm1lbnVfcGF0aCI6Ik5ldHdvcmtpbmcgLSBOZXR3b3JrIE92ZXIgSVAgLSBJUCBSb3V0ZSAoNjcxLDY3Miw2NzMqKSJ9LCI2NzIiOnsiYXJlYSI6Ik5ldHdvcmtpbmciLCJsYWJlbCI6IjY3MiBOb2RlIElkIERldGFpbCBJbmZvIGZvciBQTk92ZXJJUCIsIm1lbnVfcGF0aCI6Ik5ldHdvcmtpbmcgLSBOZXR3b3JrIE92ZXIgSVAgLSBEZXRhaWwgSW5mbyAoNjcxLDY3Miw2NzMqKSJ9LCI2NzMiOnsiYXJlYSI6Ik5ldHdvcmtpbmciLCJsYWJlbCI6IjY3MyBOb2RlIElkIENoZWNrIGFuZCBEZWxldGUiLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gTmV0d29yayBPdmVyIElQIC0gRGV0YWlsIEluZm8gKDY3MSw2NzIsNjczKikifSwiNjc0Ijp7ImFyZWEiOiJOZXR3b3JraW5nIiwibGFiZWwiOiI2NzQgUmVtb3RlIE5vZGUgSVBVIElQIEFkZHJlc3MiLCJtZW51X3BhdGgiOiJOZXR3b3JraW5nIC0gUmVtb3RlIElQVSBBZGRyZXNzICg2NzQpIn0sIjgwMSI6eyJhcmVhIjoiU3lzdGVtIiwibGFiZWwiOiI4MDEgTEFOIERhdGEiLCJtZW51X3BhdGgiOiJTeXN0ZW0gLSBJL08gRGV2aWNlICg4MDEsODAzLDgwNCkifSwiODAzIjp7ImFyZWEiOiJTeXN0ZW0iLCJsYWJlbCI6IjgwMyBJTyBMb2dpY2FsIERldmljZSIsIm1lbnVfcGF0aCI6IlN5c3RlbSAtIEkvTyBEZXZpY2UgKDgwMSw4MDMsODA0KSJ9LCI4MDQiOnsiYXJlYSI6IlN5c3RlbSIsImxhYmVsIjoiODA0IFJTMjMyQyBEYXRhIiwibWVudV9wYXRoIjoiU3lzdGVtIC0gSS9PIERldmljZSAoODAxLDgwMyw4MDQpIn0sIjkwMCI6eyJhcmVhIjoiVXRpbGl0aWVzIiwibGFiZWwiOiI5MDAgQ1RYL0NJWCBSZXN0YXJ0IiwibWVudV9wYXRoIjoiVXRpbGl0aWVzIC0gT3BlcmF0aW9ucyAtIENJWC9DVFggUmVzdGFydCAoOTAwLDkwMSw5MTUpIn0sIjkwMSI6eyJhcmVhIjoiVXRpbGl0aWVzIiwibGFiZWwiOiI5MDEgQ1RYL0NJWCBWZXJzaW9uIGFuZCBQcm9jZXNzb3IgSGFyZHdhcmUiLCJtZW51X3BhdGgiOiJVdGlsaXRpZXMgLSBPcGVyYXRpb25zIC0gQ0lYL0NUWCBSZXN0YXJ0ICg5MDAsOTAxLDkxNSkifSwiOTAzIjp7ImFyZWEiOiJVdGlsaXRpZXMiLCJsYWJlbCI6IjkwMyBFdmVudCBUcmFjZSBDb250cm9sIiwibWVudV9wYXRoIjoiVXRpbGl0aWVzIC0gTWFpbnRlbmFuY2UgLSBFdmVudCBUcmFjZSBDb250cm9sICg5MDMsOTA0LDkwNSw5MDYpIn0sIjkwNCI6eyJhcmVhIjoiVXRpbGl0aWVzIiwibGFiZWwiOiI5MDQgSVNETiBUcmFjZSBMb2NhdGlvbiIsIm1lbnVfcGF0aCI6IlV0aWxpdGllcyAtIE1haW50ZW5hbmNlIC0gSVNETiBUcmFjZSBMb2NhdGlvbiAoOTAzLDkwNCw5MDUsOTA2KSJ9LCI5MDUiOnsiYXJlYSI6IlV0aWxpdGllcyIsImxhYmVsIjoiOTA1IEFsbCBJU0ROIExpbmVzIFRyYWNlIExldmVsIFNlbGVjdGlvbiIsIm1lbnVfcGF0aCI6IlV0aWxpdGllcyAtIE1haW50ZW5hbmNlIC0gQWxsIElTRE4gTGluZXMgVHJhY2UgTGV2ZWwgU2VsZWN0aW9uICg5MDMsOTA0LDkwNSw5MDYpIn0sIjkwNiI6eyJhcmVhIjoiVXRpbGl0aWVzIiwibGFiZWwiOiI5MDYgQ2hhbmdlIFRyYWNlIFNlbGVjdGlvbiIsIm1lbnVfcGF0aCI6IlV0aWxpdGllcyAtIE1haW50ZW5hbmNlIC0gQ2hhbmdlIFRyYWNlIFNlbGVjdGlvbiAoOTAzLDkwNCw5MDUsOTA2KSJ9LCI5MDgiOnsiYXJlYSI6IlV0aWxpdGllcyIsImxhYmVsIjoiOTA4IEZvcm1hdC9Vbm1vdW50IFNNL1NEIE1lZGlhIENhcmQiLCJtZW51X3BhdGgiOiJVdGlsaXRpZXMgLSBPcGVyYXRpb25zIC0gU00vU0QgQ2FyZCAoOTA4KSJ9LCI5MDkiOnsiYXJlYSI6IlV0aWxpdGllcyIsImxhYmVsIjoiOTA5IE1BQyBBZGRyZXNzIiwibWVudV9wYXRoIjoiVXRpbGl0aWVzIC0gT3BlcmF0aW9ucyAtIE1BQyBBZGRyZXNzICg5MDkpIn0sIjkxMCI6eyJhcmVhIjoiVXRpbGl0aWVzIiwibGFiZWwiOiI5MTAgRGF0YSBCYWNrdXAiLCJtZW51X3BhdGgiOiJVdGlsaXRpZXMgLSBPcGVyYXRpb25zIC0gRGF0YSBCYWNrdXAgKDkxMCkifSwiOTE1Ijp7ImFyZWEiOiJVdGlsaXRpZXMiLCJsYWJlbCI6IjkxNSBSZWdpb25hbCBTZWxlY3Rpb24iLCJtZW51X3BhdGgiOiJVdGlsaXRpZXMgLSBPcGVyYXRpb25zIC0gQ0lYL0NUWCBSZXN0YXJ0ICg5MDAsOTAxLDkxNSkifSwiOTE2Ijp7ImFyZWEiOiJVdGlsaXRpZXMiLCJsYWJlbCI6IjkxNiBJUCBDb25maWd1cmF0aW9uIiwibWVudV9wYXRoIjoiVXRpbGl0aWVzIC0gT3BlcmF0aW9ucyAtIElQIENvbmZpZ3VyYXRpb24gKDkxNikifSwiOTE5Ijp7ImFyZWEiOiJVdGlsaXRpZXMiLCJsYWJlbCI6IjkxOSBBbGFybSBDb250cm9sIGZvciBTeXN0ZW0iLCJtZW51X3BhdGgiOiJVdGlsaXRpZXMgLSBPcGVyYXRpb25zIC0gU3lzdGVtIEFsYXJtICg5MTkpIn0sIjkyMCI6eyJhcmVhIjoiVXRpbGl0aWVzIiwibGFiZWwiOiI5MjAgQWxhcm0gQ29udHJvbCBmb3IgU2xvdCIsIm1lbnVfcGF0aCI6IlV0aWxpdGllcyAtIE9wZXJhdGlvbnMgLSBBbGFybSBTbG90ICg5MjApIn0sIjkyMSI6eyJhcmVhIjoiVXRpbGl0aWVzIiwibGFiZWwiOiI5MjEgVHJhZmZpYyBNZWFzdXJlIiwibWVudV9wYXRoIjoiVXRpbGl0aWVzIC0gT3BlcmF0aW9ucyAtIFRyYWZmaWMgTWVhc3VyZSAoOTIxKSJ9LCI5MjIiOnsiYXJlYSI6IlV0aWxpdGllcyIsImxhYmVsIjoiOTIyIFRyYWZmaWMgUmVwb3J0IEdlbmVyYXRvciIsIm1lbnVfcGF0aCI6IlV0aWxpdGllcyAtIE9wZXJhdGlvbnMgLSBUcmFmZmljIFJlcG9ydCBDb250cm9sICg5MjIpIn19fQ==").decode("utf-8")  # bundled eManager menu-area map

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

# ===== enrich.py ===================================================
"""Catalog-driven enrichment: turn a raw SNMP walk into named, menu-grouped
program views — the stable JSON contract the web UI / React frontend consume.

The reverse-engineering already named every field (186 programs, 2366 fields,
787 enumerated with value labels) and recorded how eManager groups each program
into a menu area. This module is the thin, **pure** layer that wires that model
onto the bytes a CIX returns, so nothing renders as a bare OID for any cataloged
field.

The contract (``build_program_views`` / ``program_views_from_backup`` both emit
exactly this shape; keep it stable)::

    {
      "programs": [ <program_view>, ... ],   # every cataloged program that
                                             #   returned data, menu-ordered
      "menu_areas": [                        # the same programs grouped by the
        {"area": "Trunk",                    #   eManager menu area
         "programs": ["300TrunkAssign", ...],
         "row_count": N, "cell_count": N}, ...
      ],
      "feature_views": [                     # curated high-value groupings
        {"key": "trunks", "title": "Incoming lines, CO trunks & DID",
         "programs": ["300TrunkAssign", ...], "present": true}, ...
      ],
      "uncataloged": [ {"oid": "...", "raw_value": ...}, ... ],  # genuinely
                                             #   outside the catalog (should be
                                             #   rare); the only bare OIDs left
      "stats": {"programs": N, "rows": N, "cells": N,
                "named_cells": N, "raw_oid_cells": 0, "uncataloged": N}
    }

    <program_view> = {
      "catalog_key":   "300TrunkAssign",     # the only stable program id
      "program_number":"300",                # may be null (31 programs)
      "program_name":  "TrunkAssign",
      "menu_area":     "Trunk",
      "menu_path":     "Trunk - Trunk Assignment - Basic (300,301*)",
      "label":         "300 Trunk Assign",   # friendly eManager label
      "group_oid":     "1.3.6.1.4.1.186.1.22.3.300",
      "row_count":     N,
      "rows": [ <row>, ... ]
    }

    <row>  = {"index": "1", "key": "1", "cells": [ <cell>, ... ]}
    <cell> = {"col": 1, "field_name": "trunkNo",
              "oid": "1.3.6.1.4.1.186.1.22.3.300.1.1.1.1",
              "raw_value": 7, "display_value": "7",
              "syntax": "INTEGER", "access": "rw",
              "is_enum": false, "is_secret": false}

``raw_value`` is the value as read (int / str / the ``<MISSING>`` sentinel);
``display_value`` is the human string — the enum label for an enumerated field,
else the formatted scalar. The required five keys per cell are
``col, field_name, oid, raw_value, display_value``; the rest are additive.
"""


import re


# OIDs the catalog does not model but the reader already surfaces in their own
# dedicated views: the system-identity scalars (.7 → System / Overview), the
# equipment table (.1.1.1 → Equipment) and the live DN directory (.3.1200 →
# Stations). They are deliberately kept OUT of ``uncataloged`` so the Programs
# tab is not flooded with hundreds of directory rows shown elsewhere.
_LEGACY_PREFIXES = (
    f"{ENTERPRISE_ROOT}.7",
    f"{ENTERPRISE_ROOT}.1.1.1",
    f"{ENTERPRISE_ROOT}.3.1200",
)


def _handled_elsewhere(oid: str) -> bool:
    return any(oid == p or oid.startswith(p + ".") for p in _LEGACY_PREFIXES)

# Field names whose value is a live secret the frontend may want to mask. The
# value is still returned (this tool deliberately surfaces credentials); the
# flag is advisory. ``passw`` catches ftpPassWord / password / passwd.
_SECRET_RE = re.compile(r"(passw|pwd|secret)", re.IGNORECASE)


# --------------------------------------------------------------------------
# curated feature groupings (eManager program numbers; filtered to the catalog)
# --------------------------------------------------------------------------
FEATURE_GROUPS = [
    {"key": "trunks", "title": "Incoming lines, CO trunks & DID",
     "numbers": ["300", "301", "302", "303", "304", "305", "306", "307",
                 "308", "309", "312", "316", "317", "318", "320", "164",
                 "326", "327", "328", "329"]},
    {"key": "groups", "title": "Hunt, pilot & call groups",
     "numbers": ["209", "218", "540", "541", "210", "517", "519", "502",
                 "503", "404"]},
    {"key": "phantom", "title": "Phantom DNs",
     "numbers": ["206"]},
    {"key": "voicemail", "title": "Voicemail & VMID ports",
     "numbers": ["579", "580"]},
    {"key": "stations", "title": "Stations, keys & COS",
     "numbers": ["200", "204", "205", "207", "214", "220", "103"]},
    {"key": "licensing", "title": "Licensing & entitlements",
     "keys": ["licenseControl"]},
]


def _resolve_group(catalog: Catalog, group: dict) -> list[str]:
    """Catalog keys for a feature group, in a stable order, catalog-filtered."""
    out: list[str] = []
    seen: set[str] = set()
    for num in group.get("numbers", []):
        p = catalog.program(num)
        if p and p.key not in seen:
            seen.add(p.key)
            out.append(p.key)
    for key in group.get("keys", []):
        p = catalog.program(key)
        if p and p.key not in seen:
            seen.add(p.key)
            out.append(p.key)
    return out


# --------------------------------------------------------------------------
# scan scope → the programs a walk should cover (used by scan.CIXReader)
# --------------------------------------------------------------------------
def program_idents_for_scope(catalog: Catalog, scope: str):
    """Program idents a named scope should read, or ``None`` for core/all/unknown.

    Scopes: a feature-group key (``trunks``/``groups``/``phantom``/
    ``voicemail``/``stations``/``licensing``), ``features`` (every feature
    group at once), or a menu-area name (``trunk``, ``ip-telephony`` …). Unknown
    strings return ``None`` so the caller falls back to its core/all logic.
    """
    s = (scope or "").strip().lower()
    if s in ("", "core", "all"):
        return None
    groups = {g["key"]: g for g in FEATURE_GROUPS}
    if s in groups:
        return _resolve_group(catalog, groups[s]) or None
    if s in ("features", "standard"):
        out: list[str] = []
        seen: set[str] = set()
        for g in FEATURE_GROUPS:
            for k in _resolve_group(catalog, g):
                if k not in seen:
                    seen.add(k)
                    out.append(k)
        return out or None
    area = [p.key for p in catalog.programs.values()
            if catalog.menu_area(p.key).lower() == s]
    return area or None


def scope_roots(catalog: Catalog, scope: str):
    """GETNEXT roots for a named scope (field OIDs of its programs), or ``None``.

    Imported lazily by :class:`toshiba_cix.scan.CIXReader`. Reuses the backup
    planner so the walk makes as few passes as possible.
    """
    idents = program_idents_for_scope(catalog, scope)
    if not idents:
        return None
    return walk_roots(catalog, idents)


# --------------------------------------------------------------------------
# cell / value rendering
# --------------------------------------------------------------------------
def _is_enum(fld: dict) -> bool:
    return fld.get("syntax") == "EnumeratedINTEGER"


def _display_value(catalog: Catalog, fld: dict, raw_value, is_enum: bool) -> str:
    if raw_value is None or raw_value == MISSING:
        return ""
    if is_enum and isinstance(raw_value, int) and not isinstance(raw_value, bool):
        label = catalog.enum_label(fld, raw_value)
        if label:
            return label
    return str(raw_value)


def _make_cell(catalog: Catalog, fld: dict, oid: str, raw_value) -> dict:
    is_enum = _is_enum(fld)
    name = fld.get("name") or ""
    return {
        "col": fld.get("col"),
        "field_name": name,
        "oid": oid,
        "raw_value": raw_value,
        "display_value": _display_value(catalog, fld, raw_value, is_enum),
        "syntax": fld.get("syntax"),
        "access": fld.get("access"),
        "is_enum": is_enum,
        "is_secret": bool(_SECRET_RE.search(name)),
    }


def _row_sort_key(index: str):
    try:
        arcs = [int(a) for a in index.split(".")] if index else []
    except ValueError:
        return (1, len(index), index)
    return (0, len(arcs), arcs)


def _human_key(index: str) -> str:
    if not index:
        return "_"
    try:
        arcs = tuple(int(a) for a in index.split("."))
    except ValueError:
        return index
    return parse_row_index(arcs).key


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------
def _assemble(catalog: Catalog, by_prog: dict, uncataloged: list[dict]) -> dict:
    """Shared tail: build program views + menu / feature groupings + stats."""
    programs: list[dict] = []
    cell_total = 0
    row_total = 0
    for prog_key, rows_by_index in by_prog.items():
        prog = catalog.programs[prog_key]
        info = catalog.menu_info(prog_key)
        rows = []
        for index in sorted(rows_by_index, key=_row_sort_key):
            cells = sorted(rows_by_index[index].values(),
                           key=lambda c: (c["col"] is None, c["col"] or 0,
                                          c["field_name"]))
            cell_total += len(cells)
            rows.append({"index": index, "key": _human_key(index),
                         "cells": cells})
        row_total += len(rows)
        programs.append({
            "catalog_key": prog_key,
            "program_number": prog.number,
            "program_name": prog.name,
            "menu_area": info["area"],
            "menu_path": info["menu_path"],
            "label": info["label"],
            "group_oid": prog.group_oid,
            "row_count": len(rows),
            "rows": rows,
        })

    def _area_rank(area: str) -> int:
        return MENU_AREA_ORDER.index(area) if area in MENU_AREA_ORDER \
            else len(MENU_AREA_ORDER)

    def _num_key(pv: dict):
        n = pv["program_number"]
        try:
            return (0, int(n))
        except (TypeError, ValueError):
            return (1, pv["catalog_key"])

    programs.sort(key=lambda pv: (_area_rank(pv["menu_area"]), _num_key(pv)))

    # menu areas (in canonical order, only areas that returned data)
    areas: dict[str, dict] = {}
    for pv in programs:
        a = areas.setdefault(pv["menu_area"],
                             {"area": pv["menu_area"], "programs": [],
                              "row_count": 0, "cell_count": 0})
        a["programs"].append(pv["catalog_key"])
        a["row_count"] += pv["row_count"]
        a["cell_count"] += sum(len(r["cells"]) for r in pv["rows"])
    menu_areas = sorted(areas.values(), key=lambda a: _area_rank(a["area"]))

    # feature views (only programs that actually returned data)
    present_keys = {pv["catalog_key"] for pv in programs}
    feature_views = []
    for g in FEATURE_GROUPS:
        keys = [k for k in _resolve_group(catalog, g) if k in present_keys]
        feature_views.append({"key": g["key"], "title": g["title"],
                              "programs": keys, "present": bool(keys)})

    return {
        "programs": programs,
        "menu_areas": menu_areas,
        "feature_views": feature_views,
        "uncataloged": uncataloged,
        "stats": {
            "programs": len(programs),
            "rows": row_total,
            "cells": cell_total,
            "named_cells": cell_total,   # every cell here carries a field name
            "raw_oid_cells": 0,          # by construction: named or uncataloged
            "uncataloged": len(uncataloged),
        },
    }


def build_program_views(pairs, catalog: Catalog) -> dict:
    """Named, menu-grouped program views from raw ``(oid, Value)`` pairs. Pure.

    Every OID is attributed to its catalog field by longest-prefix match; the
    field's name, column, syntax, access and enum label are attached. OIDs with
    no catalog field survive verbatim in ``uncataloged`` — the only bare OIDs
    the frontend ever sees.
    """
    by_prog: dict[str, dict[str, dict]] = {}
    uncataloged: list[dict] = []
    for oid, val in pairs:
        attr = catalog.attribute_oid(oid)
        if attr is None:
            if not _handled_elsewhere(oid):
                dv = decode_value(val)
                uncataloged.append({"oid": oid, "value": dv, "raw_value": dv})
            continue
        prog_key, fld, tail = attr
        raw_value = catalog.decode_field_value(fld, val)
        index = tail or "0"
        rows = by_prog.setdefault(prog_key, {})
        row = rows.setdefault(index, {})
        # Key the cell by field OID so two columns never collapse onto one.
        row[fld.get("oid", fld.get("name"))] = _make_cell(
            catalog, fld, oid, raw_value)
    return _assemble(catalog, by_prog, uncataloged)


def program_views_from_backup(backup_doc: dict, catalog: Catalog) -> dict:
    """The same contract, rebuilt from a saved ``toshiba-cix-backup`` doc. Pure.

    A backup stores ``program → rows → {field_name: value}`` (no per-cell OID),
    so each cell's OID is reconstructed as ``field.oid + "." + row index`` and
    the field's catalog metadata re-attached. Lets the frontend render an opened
    backup file with exactly the shape a live read produces.
    """
    by_prog: dict[str, dict[str, dict]] = {}
    uncataloged = list(backup_doc.get("unmatched", []))
    for prog_key, bucket in (backup_doc.get("programs") or {}).items():
        prog = catalog.program(prog_key)
        if prog is None:
            continue
        for row in bucket.get("rows", []):
            index = row.get("index") or "0"
            cells: dict[str, dict] = {}
            for fieldkey, value in (row.get("fields") or {}).items():
                fld = prog.field(fieldkey.split("#", 1)[0])
                if fld is None:
                    continue
                base = fld.get("oid", "")
                oid = base if index in ("", "0") else f"{base}.{index}"
                cells[base] = _make_cell(catalog, fld, oid, value)
            if cells:
                by_prog.setdefault(prog.key, {})[index] = cells
    return _assemble(catalog, by_prog, uncataloged)


def empty_program_views() -> dict:
    """The contract's shape with nothing in it (catalog unavailable)."""
    return {"programs": [], "menu_areas": [], "feature_views": [],
            "uncataloged": [],
            "stats": {"programs": 0, "rows": 0, "cells": 0, "named_cells": 0,
                      "raw_oid_cells": 0, "uncataloged": 0}}


__all__ = [
    "FEATURE_GROUPS", "program_idents_for_scope", "scope_roots",
    "build_program_views", "program_views_from_backup", "empty_program_views",
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

# ===== update.py ===================================================
"""Cross-platform self-updater for the Toshiba CIX Manager (pure stdlib).

The shipped binaries (the Linux ``*-x86_64.AppImage`` and the Windows
``Toshiba CIX Manager.exe``) can check GitHub Releases for a newer version and
replace themselves in place. A plain source / pip checkout is *not* replaced —
it reports "update via git/pip" instead.

Design rules (all enforced below):

* **Check is always safe** — a GET against the GitHub Releases API, every
  network/parse error swallowed into ``{"ok": False, "error": ...}``; it never
  raises and never touches the disk.
* **Apply only on explicit confirm** — :func:`apply_update` raises unless
  ``confirm=True``. It downloads to a sibling temp file, sanity-checks the HTTP
  status and size, and only then atomically swaps it over the running binary, so
  a failed or truncated download always leaves the working binary intact.
* **No new dependencies** — ``urllib`` only.

Public surface::

    from toshiba_cix import update
    info = update.check_for_update()         # {current, latest, newer, asset_url, ...}
    plan = update.plan_update(info)          # what an apply *would* replace
    res  = update.apply_update(info, confirm=True)
    update.relaunch(res["relaunch_argv"])    # os.execv into the new binary

Everything is module-level and I/O-injectable (``apply_update`` takes a
``_downloader``; :func:`check_for_update` goes through :func:`_http_get`) so the
whole thing is unit-testable with no network.
"""


import json
import os
import platform
import re
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.request


GITHUB_REPO = "smartpbx/toshiba-cix-manager"
LATEST_RELEASE_URL = (
    f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
)
RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases"
USER_AGENT = f"toshiba-cix-manager/{__version__}"

# A shipped binary bundles its own CPython, so it is tens of MB. Anything much
# smaller than this is an HTML error page or a truncated download, not a build.
_MIN_ASSET_BYTES = 500_000
# Hard ceiling so a hostile / runaway response can't fill the disk.
_MAX_ASSET_BYTES = 500_000_000

# Per-platform release-asset suffix. CI publishes exactly these names
# (``Toshiba_CIX_Manager-x86_64.AppImage`` and ``Toshiba CIX Manager.exe``).
_ASSET_SUFFIX = {"linux": "x86_64.AppImage", "windows": ".exe"}


class UpdateError(Exception):
    """Raised only for programming misuse (e.g. apply without confirm).

    Operational failures (network down, no asset, not replaceable) are returned
    as ``{"ok": False, ...}`` dicts, never raised — a failed update must not
    crash the caller.
    """


# --------------------------------------------------------------------------- #
# semver
# --------------------------------------------------------------------------- #
def _parse_version(value: str) -> tuple[int, int, int]:
    """Parse ``"v1.2.3"`` / ``"1.2"`` / ``"1.2.3-rc1"`` to a ``(maj, min, pat)``
    tuple. Pre-release / build metadata is ignored; missing parts are ``0``."""
    text = (value or "").strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    core = re.split(r"[-+]", text, maxsplit=1)[0]
    nums: list[int] = []
    for part in core.split("."):
        m = re.match(r"\d+", part)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])  # type: ignore[return-value]


def compare_versions(a: str, b: str) -> int:
    """Return -1 / 0 / 1 for ``a`` <, ==, > ``b`` (semver, v-prefix tolerant)."""
    pa, pb = _parse_version(a), _parse_version(b)
    return (pa > pb) - (pa < pb)


def is_newer(latest: str, current: str) -> bool:
    """True when ``latest`` is strictly newer than ``current``."""
    return compare_versions(latest, current) > 0


# --------------------------------------------------------------------------- #
# packaging / platform detection
# --------------------------------------------------------------------------- #
def detect_packaging() -> dict:
    """Describe how this process is packaged and whether it can self-replace.

    Returns a dict with:
        kind         : ``"appimage"`` | ``"windows_exe"`` | ``"source"``
        path         : the on-disk file an apply would replace (``None`` for source)
        replaceable  : whether an in-place self-replace is possible
        platform     : ``"linux"`` | ``"windows"`` | other
        asset_suffix : the matching release-asset filename suffix (or ``None``)
    """
    system = platform.system()
    appimage = os.environ.get("APPIMAGE")
    # Linux AppImage: the runtime sets $APPIMAGE to the running .AppImage path.
    if system == "Linux" and appimage:
        return {
            "kind": "appimage", "path": appimage, "replaceable": True,
            "platform": "linux", "asset_suffix": _ASSET_SUFFIX["linux"],
        }
    # Windows frozen exe (PyInstaller): sys.frozen is set, sys.executable is the exe.
    if getattr(sys, "frozen", False) and (system == "Windows" or os.name == "nt"):
        return {
            "kind": "windows_exe", "path": sys.executable, "replaceable": True,
            "platform": "windows", "asset_suffix": _ASSET_SUFFIX["windows"],
        }
    # Everything else (git clone, pip install, a non-AppImage frozen Linux build):
    # report "update via git/pip" and never self-replace.
    return {
        "kind": "source", "path": None, "replaceable": False,
        "platform": system.lower(), "asset_suffix": None,
    }


def select_asset(assets, packaging: dict):
    """Pick the release asset matching ``packaging`` from a GitHub ``assets`` list.

    Returns the asset dict (``{name, browser_download_url, size, ...}``) or
    ``None`` when nothing matches this platform.
    """
    suffix = packaging.get("asset_suffix")
    if not suffix or not assets:
        return None
    for asset in assets:
        if isinstance(asset, dict) and str(asset.get("name", "")).endswith(suffix):
            return asset
    return None


# --------------------------------------------------------------------------- #
# network
# --------------------------------------------------------------------------- #
def _http_get(url: str, *, accept: str | None = None, timeout: float = 15.0):
    """Minimal GET returning ``(status, body_bytes)``. Raises on transport error."""
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        return status, resp.read()


def check_for_update(*, current: str | None = None, timeout: float = 15.0) -> dict:
    """Query GitHub Releases for the latest version. **Never raises.**

    Returns::

        {ok, current, latest, latest_tag, newer, asset_url, asset_name,
         asset_size, packaging, replaceable, html_url, error}

    On any network/parse error ``ok`` is ``False`` and ``error`` carries the
    reason; nothing is downloaded or written.
    """
    current = current or __version__
    packaging = detect_packaging()
    result = {
        "ok": False, "current": current, "latest": None, "latest_tag": None,
        "newer": False, "asset_url": None, "asset_name": None, "asset_size": None,
        "packaging": packaging["kind"], "replaceable": packaging["replaceable"],
        "html_url": RELEASES_PAGE, "error": None,
    }
    try:
        status, raw = _http_get(
            LATEST_RELEASE_URL, accept="application/vnd.github+json",
            timeout=timeout)
        if status != 200:
            result["error"] = f"GitHub returned HTTP {status}"
            return result
        data = json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            ValueError, TimeoutError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    tag = str(data.get("tag_name") or data.get("name") or "").strip()
    norm = tag[1:] if tag[:1] in ("v", "V") else tag
    result["latest_tag"] = tag or None
    result["latest"] = norm or None
    result["html_url"] = data.get("html_url") or RELEASES_PAGE
    result["newer"] = bool(norm) and is_newer(norm, current)
    asset = select_asset(data.get("assets") or [], packaging)
    if asset:
        result["asset_url"] = asset.get("browser_download_url")
        result["asset_name"] = asset.get("name")
        result["asset_size"] = asset.get("size")
    result["ok"] = True
    return result


# --------------------------------------------------------------------------- #
# plan / apply
# --------------------------------------------------------------------------- #
def plan_update(check: dict | None = None, *, current: str | None = None) -> dict:
    """Describe what an :func:`apply_update` *would* do, touching nothing.

    Pass a ``check`` from :func:`check_for_update` to avoid a second network
    call. ``can_apply`` is ``True`` only when a newer version exists, this build
    is replaceable, and a matching asset is published.
    """
    check = check if check is not None else check_for_update(current=current)
    packaging = detect_packaging()
    plan = {
        "current": check.get("current"), "latest": check.get("latest"),
        "newer": check.get("newer"), "packaging": packaging["kind"],
        "replaceable": packaging["replaceable"], "target_path": packaging["path"],
        "asset_url": check.get("asset_url"), "asset_name": check.get("asset_name"),
        "can_apply": False, "reason": None, "html_url": check.get("html_url"),
    }
    if not check.get("ok"):
        plan["reason"] = check.get("error") or "update check failed"
    elif not check.get("newer"):
        plan["reason"] = "already up to date"
    elif not packaging["replaceable"]:
        plan["reason"] = (
            "running from source — update with 'git pull' or "
            "'pip install -U' (in-place self-replace is only for the "
            "AppImage / .exe builds)")
    elif not check.get("asset_url"):
        plan["reason"] = "no matching release asset for this platform"
    else:
        plan["can_apply"] = True
        plan["reason"] = (
            f"will replace {packaging['path']} with {check.get('asset_name')}")
    return plan


def _download(url: str, dest: str, *, timeout: float = 120.0,
              min_bytes: int = _MIN_ASSET_BYTES,
              max_bytes: int = _MAX_ASSET_BYTES) -> int:
    """Stream ``url`` to ``dest``. Returns bytes written.

    Raises :class:`UpdateError` on a non-200 status, an over-size body, or a
    body smaller than ``min_bytes`` (an error page / truncated download).
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/octet-stream"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    written = 0
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        if status != 200:
            raise UpdateError(f"download returned HTTP {status}")
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise UpdateError("download exceeded the maximum size")
                fh.write(chunk)
    if written < min_bytes:
        raise UpdateError(
            f"downloaded file is implausibly small ({written} bytes)")
    return written


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _install_unix(tmp: str, target: str, size: int) -> dict:
    """Make ``tmp`` executable, stage it as ``<target>.new``, then atomically
    swap it over the (open, running) AppImage path."""
    os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    staged = target + ".new"
    os.replace(tmp, staged)      # same directory -> atomic rename
    os.replace(staged, target)   # Linux lets us replace a file that is still open
    return {
        "ok": True, "action": "replaced", "path": target, "size": size,
        "needs_restart": True, "relaunch_argv": [target] + sys.argv[1:],
        "message": (f"Updated {os.path.basename(target)}. "
                    "Relaunch to run the new version."),
    }


def _install_windows(tmp: str, target: str, size: int) -> dict:
    """Stage the download as ``<target>.new``. A running ``.exe`` can't be
    overwritten on Windows, so it is installed on next start by
    :func:`finalize_pending_update`."""
    staged = target + ".new"
    os.replace(tmp, staged)
    return {
        "ok": True, "action": "staged", "path": target, "staged_path": staged,
        "size": size, "needs_restart": True,
        "message": ("Update staged. It installs automatically the next time you "
                    "start the app (Windows can't replace a running .exe)."),
    }


def apply_update(check: dict | None = None, *, confirm: bool = False,
                 current: str | None = None, timeout: float = 120.0,
                 _downloader=None) -> dict:
    """Download the latest release and install it over the running binary.

    **Requires ``confirm=True``** — otherwise raises :class:`UpdateError`.

    The download goes to a sibling temp file; only after a clean, size-checked
    download is it swapped in (atomically on Linux, staged on Windows). Any
    failure leaves the running binary untouched and is returned as
    ``{"ok": False, ...}``.

    ``_downloader`` is injectable for tests: ``fn(url, dest, timeout=...) -> int``.
    """
    if not confirm:
        raise UpdateError("apply_update requires confirm=True (never replace a "
                          "binary without explicit confirmation)")
    check = check if check is not None else check_for_update(current=current)
    plan = plan_update(check)
    if not plan["can_apply"]:
        return {"ok": False, "action": "none", "packaging": plan["packaging"],
                "message": plan["reason"], "html_url": plan.get("html_url")}

    packaging = detect_packaging()
    target = packaging["path"]
    url = check["asset_url"]
    download = _downloader or _download
    target_dir = os.path.dirname(os.path.abspath(target))

    try:
        fd, tmp = tempfile.mkstemp(prefix=".cix-update-", dir=target_dir)
        os.close(fd)
    except OSError as exc:
        return {"ok": False, "action": "none",
                "message": f"cannot write next to {target}: {exc}"}

    try:
        size = download(url, tmp, timeout=timeout)
    except Exception as exc:  # noqa: BLE001  — any failure must be non-fatal
        _safe_unlink(tmp)
        return {"ok": False, "action": "download_failed", "message": str(exc)}

    try:
        if packaging["kind"] == "appimage":
            return _install_unix(tmp, target, size)
        if packaging["kind"] == "windows_exe":
            return _install_windows(tmp, target, size)
        _safe_unlink(tmp)
        return {"ok": False, "action": "none",
                "message": "no installer for this packaging"}
    except Exception as exc:  # noqa: BLE001
        _safe_unlink(tmp)
        return {"ok": False, "action": "install_failed", "message": str(exc)}


def finalize_pending_update() -> dict:
    """Install a staged Windows update at startup (rename-on-next-start).

    No-op on every other platform and when nothing is staged. Fully defensive —
    it must never stop the app from launching. When it swaps a new exe in it
    returns ``relaunch_argv`` so the launcher can ``execv`` into it.
    """
    try:
        packaging = detect_packaging()
        if packaging["kind"] != "windows_exe":
            return {"ok": False, "action": "none"}
        exe = packaging["path"]
        staged = exe + ".new"
        if not os.path.exists(staged):
            return {"ok": False, "action": "none"}
        backup = exe + ".old"
        _safe_unlink(backup)
        # Windows permits renaming a running .exe (but not overwriting it):
        # move the current one aside, then drop the staged one into its place.
        os.replace(exe, backup)
        os.replace(staged, exe)
        return {"ok": True, "action": "finalized", "path": exe,
                "relaunch_argv": [exe] + sys.argv[1:]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "action": "error", "message": str(exc)}


def relaunch(argv=None):  # pragma: no cover  — replaces the process image
    """Replace the current process with a fresh launch of the (updated) binary.

    ``os.execv`` does not return on success.
    """
    argv = argv or [sys.executable] + sys.argv[1:]
    os.execv(argv[0], argv)

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
import threading
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
        if path == "/api/update":
            self._handle_update_check()
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
        elif path == "/api/update":
            self._handle_update_apply(params)
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
                         "report": render_backup_text(doc, catalog=cat),
                         "program_views": program_views_from_backup(doc, cat)})

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
                         "programs": sorted(doc.get("programs", {}).keys()),
                         "program_views": program_views_from_backup(doc, cat)})

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

    # -- self-update ------------------------------------------------------
    def _handle_update_check(self):
        """GET /api/update — a *safe* check against GitHub Releases. Never
        downloads or replaces anything."""
        try:
            self._send_json(check_for_update())
        except Exception as exc:  # noqa: BLE001  — check must never 500
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def _handle_update_apply(self, params):
        """POST /api/update — download + install the latest release. Requires an
        explicit ``{"confirm": true}``; a plain POST only reports the plan."""
        if not bool(params.get("confirm")):
            self._send_json(
                {"ok": False, "error": "apply requires an explicit confirm",
                 "plan": plan_update()}, status=400)
            return
        try:
            result = apply_update(confirm=True)
        except Exception as exc:  # noqa: BLE001
            log.exception("update apply failed")
            self._send_json({"ok": False,
                             "error": f"{type(exc).__name__}: {exc}"})
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


def _background_update_check() -> None:
    """Non-blocking, best-effort 'is there a newer release?' notice.

    Runs in a daemon thread at launch. It ONLY prints a one-line notice — it
    never downloads or replaces anything (that is always an explicit user
    action via the web UI / CLI). Every error is swallowed.
    """
    try:
        info = check_for_update()
    except Exception:  # noqa: BLE001
        return
    if info.get("ok") and info.get("newer"):
        print(f"  Update available: v{info.get('latest')} "
              f"(you have {info.get('current')}) — {info.get('html_url')}")
        if info.get("replaceable"):
            print("  Use 'Check for updates' in the web UI to install it.")


def serve(host: str = "127.0.0.1", port: int = 8765, *,
          open_browser: bool = True) -> None:
    # If a Windows update was staged on a previous run, swap it in first.
    pending = finalize_pending_update()
    if pending.get("ok") and pending.get("relaunch_argv"):
        relaunch(pending["relaunch_argv"])   # does not return on success

    port = _pick_port(host, port)
    httpd = ThreadingHTTPServer((host, port), CIXHandler)
    url = f"http://{host}:{port}"
    print(f"Toshiba CIX Manager {__version__}")
    print(f"  Open: {url}")
    print("  Read-only SNMP. Writes are stubbed (not enabled). Ctrl-C to stop.")
    # Fire the update check in the background so the UI/console comes up at once.
    threading.Thread(target=_background_update_check, daemon=True).start()
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
EMBEDDED_WEBUI_HTML = base64.b64decode("PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KPHRpdGxlPlRvc2hpYmEgQ0lYIE1hbmFnZXI8L3RpdGxlPgo8c3R5bGU+CiAgOnJvb3R7CiAgICAtLWJnOiMwZjE3MjA7IC0tcGFuZWw6IzE3MjEyZTsgLS1wYW5lbDI6IzFlMmEzYTsgLS1saW5lOiMyYjNhNGU7CiAgICAtLWZnOiNlN2VlZjY7IC0tbXV0ZWQ6IzlmYjBjMzsgLS1hY2NlbnQ6IzRhYTNmZjsgLS1hY2NlbnQyOiMyYjc4ZDQ7CiAgICAtLW9rOiMzNmMwOGE7IC0td2FybjojZmZiNjQ4OyAtLWJhZDojZmY2YjZiOyAtLWNoaXA6IzI0MzQ0YTsKICB9CiAgQG1lZGlhIChwcmVmZXJzLWNvbG9yLXNjaGVtZTogbGlnaHQpewogICAgOnJvb3R7CiAgICAgIC0tYmc6I2YzZjZmYTsgLS1wYW5lbDojZmZmZmZmOyAtLXBhbmVsMjojZWVmM2Y5OyAtLWxpbmU6I2Q1ZGZlYTsKICAgICAgLS1mZzojMTMyMDJlOyAtLW11dGVkOiM1YjZiN2Q7IC0tYWNjZW50OiMxNzY5Yzk7IC0tYWNjZW50MjojMGY0ZjllOwogICAgICAtLW9rOiMxMTdhNTU7IC0td2FybjojOWE2NDAwOyAtLWJhZDojYzAzOTJiOyAtLWNoaXA6I2U1ZWRmNjsKICAgIH0KICB9CiAgKntib3gtc2l6aW5nOmJvcmRlci1ib3h9CiAgYm9keXttYXJnaW46MDtmb250OjE0cHgvMS40NSBzeXN0ZW0tdWksLWFwcGxlLXN5c3RlbSxTZWdvZSBVSSxSb2JvdG8sSGVsdmV0aWNhLEFyaWFsLHNhbnMtc2VyaWY7CiAgICAgICBiYWNrZ3JvdW5kOnZhcigtLWJnKTtjb2xvcjp2YXIoLS1mZyl9CiAgYXtjb2xvcjp2YXIoLS1hY2NlbnQpfQogIGhlYWRlcntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxNHB4O3BhZGRpbmc6MTBweCAxNnB4O2JhY2tncm91bmQ6dmFyKC0tcGFuZWwpOwogICAgICAgICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKTtwb3NpdGlvbjpzdGlja3k7dG9wOjA7ei1pbmRleDoxMDtmbGV4LXdyYXA6d3JhcH0KICBoZWFkZXIgaDF7Zm9udC1zaXplOjE2cHg7bWFyZ2luOjA7Zm9udC13ZWlnaHQ6NjUwO2xldHRlci1zcGFjaW5nOi4ycHh9CiAgLnJvLWJhZGdle2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjojMGIyMDMzO2JhY2tncm91bmQ6dmFyKC0td2Fybik7CiAgICAgICAgICAgIHBhZGRpbmc6M3B4IDhweDtib3JkZXItcmFkaXVzOjIwcHh9CiAgLnN0YXR1c3ttYXJnaW4tbGVmdDphdXRvO2NvbG9yOnZhcigtLW11dGVkKTtmb250LXNpemU6MTJweDt0ZXh0LWFsaWduOnJpZ2h0fQogIC5zdGF0dXMgYntjb2xvcjp2YXIoLS1mZyl9CiAgLnVwZGJveHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHh9CiAgLnVwZG1zZ3tmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS1tdXRlZCl9CiAgLnVwZG1zZyBie2NvbG9yOnZhcigtLXdhcm4pfQogIG1haW57cGFkZGluZzoxNnB4O21heC13aWR0aDoxMTgwcHg7bWFyZ2luOjAgYXV0b30KICAuY2FyZHtiYWNrZ3JvdW5kOnZhcigtLXBhbmVsKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTJweDsKICAgICAgICBwYWRkaW5nOjE2cHg7bWFyZ2luLWJvdHRvbToxNnB4fQogIC5jYXJkIGgye2ZvbnQtc2l6ZToxNHB4O21hcmdpbjowIDAgMTJweDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6LjVweDtjb2xvcjp2YXIoLS1tdXRlZCl9CiAgbGFiZWx7ZGlzcGxheTpibG9jaztmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS1tdXRlZCk7bWFyZ2luOjAgMCA0cHh9CiAgaW5wdXQsc2VsZWN0e3dpZHRoOjEwMCU7cGFkZGluZzo4cHggMTBweDtiYWNrZ3JvdW5kOnZhcigtLXBhbmVsMik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsKICAgICAgICAgYm9yZGVyLXJhZGl1czo4cHg7Y29sb3I6dmFyKC0tZmcpO2ZvbnQ6aW5oZXJpdH0KICBpbnB1dDpmb2N1cyxzZWxlY3Q6Zm9jdXN7b3V0bGluZToycHggc29saWQgdmFyKC0tYWNjZW50KTtvdXRsaW5lLW9mZnNldDotMXB4fQogIC5ncmlke2Rpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZml0LG1pbm1heCgxNTBweCwxZnIpKTtnYXA6MTJweH0KICAucm93e2Rpc3BsYXk6ZmxleDtnYXA6MTBweDtmbGV4LXdyYXA6d3JhcDthbGlnbi1pdGVtczpmbGV4LWVuZH0KICAuYnRue2FwcGVhcmFuY2U6bm9uZTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWFjY2VudDIpO2JhY2tncm91bmQ6dmFyKC0tYWNjZW50KTtjb2xvcjojZmZmOwogICAgICAgZm9udDppbmhlcml0O2ZvbnQtd2VpZ2h0OjYwMDtwYWRkaW5nOjhweCAxNHB4O2JvcmRlci1yYWRpdXM6OHB4O2N1cnNvcjpwb2ludGVyfQogIC5idG46aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1hY2NlbnQyKX0KICAuYnRuLmdob3N0e2JhY2tncm91bmQ6dHJhbnNwYXJlbnQ7Y29sb3I6dmFyKC0tYWNjZW50KTtib3JkZXItY29sb3I6dmFyKC0tbGluZSl9CiAgLmJ0bi5naG9zdDpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXBhbmVsMil9CiAgLmJ0bjpkaXNhYmxlZHtvcGFjaXR5Oi41O2N1cnNvcjpub3QtYWxsb3dlZH0KICAuYnRuLnNtYWxse3BhZGRpbmc6NXB4IDEwcHg7Zm9udC1zaXplOjEycHh9CiAgLm1zZ3twYWRkaW5nOjEwcHggMTJweDtib3JkZXItcmFkaXVzOjhweDttYXJnaW4tdG9wOjEycHg7Zm9udC1zaXplOjEzcHg7ZGlzcGxheTpub25lfQogIC5tc2cuc2hvd3tkaXNwbGF5OmJsb2NrfQogIC5tc2cub2t7YmFja2dyb3VuZDpyZ2JhKDU0LDE5MiwxMzgsLjE0KTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLW9rKTtjb2xvcjp2YXIoLS1vayl9CiAgLm1zZy5lcnJ7YmFja2dyb3VuZDpyZ2JhKDI1NSwxMDcsMTA3LC4xNCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1iYWQpO2NvbG9yOnZhcigtLWJhZCl9CiAgLm1zZy5pbmZve2JhY2tncm91bmQ6cmdiYSg3NCwxNjMsMjU1LC4xMik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1hY2NlbnQpO2NvbG9yOnZhcigtLWZnKX0KICAudGFic3tkaXNwbGF5OmZsZXg7Z2FwOjRweDtmbGV4LXdyYXA6d3JhcDttYXJnaW4tYm90dG9tOjE0cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbGluZSl9CiAgLnRhYntwYWRkaW5nOjhweCAxNHB4O2N1cnNvcjpwb2ludGVyO2NvbG9yOnZhcigtLW11dGVkKTtib3JkZXItYm90dG9tOjJweCBzb2xpZCB0cmFuc3BhcmVudDsKICAgICAgIGZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MTNweH0KICAudGFiLmFjdGl2ZXtjb2xvcjp2YXIoLS1mZyk7Ym9yZGVyLWJvdHRvbS1jb2xvcjp2YXIoLS1hY2NlbnQpfQogIC50YWIgLmNvdW50e2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dGVkKTtmb250LXdlaWdodDo1MDB9CiAgLnZpZXd7ZGlzcGxheTpub25lfQogIC52aWV3LmFjdGl2ZXtkaXNwbGF5OmJsb2NrfQogIHRhYmxle3dpZHRoOjEwMCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO2ZvbnQtc2l6ZToxM3B4fQogIHRoLHRke3RleHQtYWxpZ246bGVmdDtwYWRkaW5nOjdweCAxMHB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWxpbmUpO3ZlcnRpY2FsLWFsaWduOnRvcH0KICB0aHtjb2xvcjp2YXIoLS1tdXRlZCk7Zm9udC1zaXplOjExcHg7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOi40cHg7CiAgICAgcG9zaXRpb246c3RpY2t5O3RvcDo1NHB4O3otaW5kZXg6MztiYWNrZ3JvdW5kOnZhcigtLXBhbmVsKTtjdXJzb3I6cG9pbnRlcjt1c2VyLXNlbGVjdDpub25lOwogICAgIGJveC1zaGFkb3c6aW5zZXQgMCAtMXB4IDAgdmFyKC0tbGluZSl9CiAgdGJvZHkgdHI6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1wYW5lbDIpfQogIHRyLmNsaWNrYWJsZXtjdXJzb3I6cG9pbnRlcn0KICAubW9ub3tmb250LWZhbWlseTp1aS1tb25vc3BhY2UsU0ZNb25vLVJlZ3VsYXIsTWVubG8sQ29uc29sYXMsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMnB4fQogIC5jaGlwe2Rpc3BsYXk6aW5saW5lLWJsb2NrO2JhY2tncm91bmQ6dmFyKC0tY2hpcCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjIwcHg7CiAgICAgICAgcGFkZGluZzoycHggOXB4O2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dGVkKTttYXJnaW46MCA0cHggNHB4IDB9CiAgLmZpbmRpbmd7cGFkZGluZzoxMHB4IDEycHg7Ym9yZGVyLXJhZGl1czo4cHg7bWFyZ2luLWJvdHRvbTo4cHg7Zm9udC1zaXplOjEzcHh9CiAgLmZpbmRpbmcuaGlnaHtiYWNrZ3JvdW5kOnJnYmEoMjU1LDEwNywxMDcsLjEyKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJhZCl9CiAgLmZpbmRpbmcubWVkaXVte2JhY2tncm91bmQ6cmdiYSgyNTUsMTgyLDcyLC4xMik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13YXJuKX0KICAuc2V2e2ZvbnQtd2VpZ2h0OjcwMDttYXJnaW4tcmlnaHQ6NnB4fQogIC50b29sYmFye2Rpc3BsYXk6ZmxleDtnYXA6MTBweDthbGlnbi1pdGVtczpjZW50ZXI7bWFyZ2luLWJvdHRvbToxMnB4O2ZsZXgtd3JhcDp3cmFwfQogIC50b29sYmFyIGlucHV0W3R5cGU9c2VhcmNoXXttYXgtd2lkdGg6MzIwcHh9CiAgLm11dGVke2NvbG9yOnZhcigtLW11dGVkKX0KICAua3Z7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoyMDBweCAxZnI7Z2FwOjRweCAxNHB4O2ZvbnQtc2l6ZToxM3B4fQogIC5rdiBkaXYua3tjb2xvcjp2YXIoLS1tdXRlZCl9CiAgLyogZHJhd2VyICovCiAgLm92ZXJsYXl7cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtiYWNrZ3JvdW5kOnJnYmEoMCwwLDAsLjQ1KTtkaXNwbGF5Om5vbmU7ei1pbmRleDo0MH0KICAub3ZlcmxheS5zaG93e2Rpc3BsYXk6YmxvY2t9CiAgLmRyYXdlcntwb3NpdGlvbjpmaXhlZDt0b3A6MDtyaWdodDowO2hlaWdodDoxMDAlO3dpZHRoOm1pbig1NjBweCwxMDAlKTtiYWNrZ3JvdW5kOnZhcigtLXBhbmVsKTsKICAgICAgICAgIGJvcmRlci1sZWZ0OjFweCBzb2xpZCB2YXIoLS1saW5lKTt0cmFuc2Zvcm06dHJhbnNsYXRlWCgxMDAlKTt0cmFuc2l0aW9uOnRyYW5zZm9ybSAuMnM7CiAgICAgICAgICB6LWluZGV4OjUwO292ZXJmbG93LXk6YXV0bztwYWRkaW5nOjE4cHh9CiAgLmRyYXdlci5zaG93e3RyYW5zZm9ybTp0cmFuc2xhdGVYKDApfQogIC5kcmF3ZXIgaDN7bWFyZ2luOjAgMCA0cHh9CiAgLmRyYXdlciAuY2xvc2V7cG9zaXRpb246YWJzb2x1dGU7dG9wOjE0cHg7cmlnaHQ6MTZweDtjdXJzb3I6cG9pbnRlcjtjb2xvcjp2YXIoLS1tdXRlZCk7CiAgICAgICAgICAgICAgICAgZm9udC1zaXplOjIycHg7bGluZS1oZWlnaHQ6MTtiYWNrZ3JvdW5kOm5vbmU7Ym9yZGVyOm5vbmV9CiAgLmZpZWxkLWVkaXR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxMjBweCAxZnI7Z2FwOjhweDthbGlnbi1pdGVtczpjZW50ZXI7bWFyZ2luLWJvdHRvbTo4cHh9CiAgLmZpZWxkLWVkaXQgbGFiZWx7bWFyZ2luOjB9CiAgZGV0YWlsc3tib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6OHB4O21hcmdpbi1ib3R0b206OHB4O3BhZGRpbmc6NnB4IDEwcHh9CiAgc3VtbWFyeXtjdXJzb3I6cG9pbnRlcjtmb250LXdlaWdodDo2MDA7Y29sb3I6dmFyKC0tbXV0ZWQpfQogIC5oaWRle2Rpc3BsYXk6bm9uZSFpbXBvcnRhbnR9CiAgLmNlbnRlcnt0ZXh0LWFsaWduOmNlbnRlcjtwYWRkaW5nOjQwcHggMDtjb2xvcjp2YXIoLS1tdXRlZCl9CiAgLnNwaW5uZXJ7ZGlzcGxheTppbmxpbmUtYmxvY2s7d2lkdGg6MThweDtoZWlnaHQ6MThweDtib3JkZXI6M3B4IHNvbGlkIHZhcigtLWxpbmUpOwogICAgICAgICAgIGJvcmRlci10b3AtY29sb3I6dmFyKC0tYWNjZW50KTtib3JkZXItcmFkaXVzOjUwJTthbmltYXRpb246c3BpbiAuOHMgbGluZWFyIGluZmluaXRlOwogICAgICAgICAgIHZlcnRpY2FsLWFsaWduOi00cHg7bWFyZ2luLXJpZ2h0OjhweH0KICBAa2V5ZnJhbWVzIHNwaW57dG97dHJhbnNmb3JtOnJvdGF0ZSgzNjBkZWcpfX0KICAuZXhwLWJ0bnN7ZGlzcGxheTpmbGV4O2dhcDoxMHB4O2ZsZXgtd3JhcDp3cmFwfQogIGZvb3Rlcntjb2xvcjp2YXIoLS1tdXRlZCk7Zm9udC1zaXplOjExcHg7dGV4dC1hbGlnbjpjZW50ZXI7cGFkZGluZzoxNnB4fQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5Pgo8aGVhZGVyPgogIDxoMT5Ub3NoaWJhIENJWCBNYW5hZ2VyPC9oMT4KICA8c3BhbiBjbGFzcz0icm8tYmFkZ2UiIGlkPSJtb2RlQmFkZ2UiIHRpdGxlPSJSZWFkcyBhcmUgcGxhaW4gU05NUCBHRVRzLiBXcml0ZXMgcmVxdWlyZSBhbiBleHBsaWNpdCBDb25maXJtICZhbXA7IHdyaXRlIGFuZCBhcmUgcmVhZC1iYWNrIHZlcmlmaWVkLiI+UkVBRC1PTkxZPC9zcGFuPgogIDxkaXYgY2xhc3M9InN0YXR1cyIgaWQ9InN0YXR1cyI+Tm90IGNvbm5lY3RlZDwvZGl2PgogIDxkaXYgY2xhc3M9InVwZGJveCIgaWQ9InVwZGF0ZUJveCI+CiAgICA8c3BhbiBpZD0idXBkTXNnIiBjbGFzcz0idXBkbXNnIj48L3NwYW4+CiAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3Qgc21hbGwiIGlkPSJidG5VcGRDaGVjayIgdGl0bGU9IkNoZWNrIEdpdEh1YiBmb3IgYSBuZXdlciByZWxlYXNlIj5DaGVjayBmb3IgdXBkYXRlczwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0iYnRuIHNtYWxsIGhpZGUiIGlkPSJidG5VcGRBcHBseSI+VXBkYXRlPC9idXR0b24+CiAgPC9kaXY+CjwvaGVhZGVyPgoKPG1haW4+CiAgPCEtLSBDT05ORUNUIC0tPgogIDxzZWN0aW9uIGlkPSJjb25uZWN0IiBjbGFzcz0iY2FyZCI+CiAgICA8aDI+Q29ubmVjdCB0byBhIFN0cmF0YSBDSVg8L2gyPgogICAgPHAgY2xhc3M9Im11dGVkIiBzdHlsZT0ibWFyZ2luLXRvcDotNnB4Ij4KICAgICAgUGx1ZyBzdHJhaWdodCBpbnRvIHRoZSBQQlggdm9pY2UtTEFOIHBvcnQgKGRpcmVjdCksIG9yIHJlYWNoIGl0IG92ZXIgYW4gUlNNL1plcm9UaWVyCiAgICAgIChyZW1vdGUpICZtZGFzaDsgZWl0aGVyIHdheSBpdCBpcyBqdXN0IFNOTVAgdG8gYW4gSVAuIE5vIGludGVybmV0IHJlcXVpcmVkLgogICAgPC9wPgogICAgPGRpdiBjbGFzcz0iZ3JpZCI+CiAgICAgIDxkaXY+PGxhYmVsPkNJWCBJUCBhZGRyZXNzPC9sYWJlbD48aW5wdXQgaWQ9ImlwIiBwbGFjZWhvbGRlcj0iMTkyLjE2OC4yNTQuMjUzIiBhdXRvY29tcGxldGU9Im9mZiI+PC9kaXY+CiAgICAgIDxkaXY+PGxhYmVsPlNOTVAgY29tbXVuaXR5PC9sYWJlbD48aW5wdXQgaWQ9ImNvbW11bml0eSIgdmFsdWU9ImNvbW11bml0eU5hbWUiIGF1dG9jb21wbGV0ZT0ib2ZmIj48L2Rpdj4KICAgICAgPGRpdj48bGFiZWw+UG9ydDwvbGFiZWw+PGlucHV0IGlkPSJwb3J0IiB2YWx1ZT0iMTYxIj48L2Rpdj4KICAgICAgPGRpdj48bGFiZWw+U2NvcGU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9InNjb3BlIj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImNvcmUiPmNvcmUgJm1kYXNoOyBmYXN0IChzdGF0aW9ucywgc3lzdGVtLCBuZXR3b3JrKTwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0idHJ1bmtzIj50cnVua3MgJm1kYXNoOyBpbmNvbWluZyBsaW5lcywgQ08gdHJ1bmtzICZhbXA7IERJRDwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZ3JvdXBzIj5ncm91cHMgJm1kYXNoOyBodW50LCBwaWxvdCAmYW1wOyBjYWxsIGdyb3Vwczwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0idm9pY2VtYWlsIj52b2ljZW1haWwgJm1kYXNoOyBWTSBkYXRhICZhbXA7IFZNSUQgcG9ydHM8L29wdGlvbj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImxpY2Vuc2luZyI+bGljZW5zaW5nICZtZGFzaDsgZW50aXRsZW1lbnRzPC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJmZWF0dXJlcyI+ZmVhdHVyZXMgJm1kYXNoOyBhbGwgZmVhdHVyZSBhcmVhczwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iYWxsIj5hbGwgJm1kYXNoOyBmdWxsIGJhY2t1cCAoc2xvdywgd2hvbGUgTUlCKTwvb3B0aW9uPgogICAgICAgIDwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0icm93IiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4Ij4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0iYnRuUmVhZCI+UmVhZCBzeXN0ZW08L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IiBpZD0iYnRuVGVzdCI+VGVzdCBjb25uZWN0aW9uPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9ImJ0bkRpc2NvdmVyIj5BdXRvLWRpc2NvdmVyPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9ImJ0bk9wZW4iPk9wZW4gYmFja3VwIGZpbGUmaGVsbGlwOzwvYnV0dG9uPgogICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImZpbGVJbnB1dCIgYWNjZXB0PSIuanNvbixhcHBsaWNhdGlvbi9qc29uIiBjbGFzcz0iaGlkZSI+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1zZyIgaWQ9ImNvbm5lY3RNc2ciPjwvZGl2PgogICAgPGRpdiBpZD0iZGlzY292ZXJCb3giIGNsYXNzPSJoaWRlIiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4Ij4KICAgICAgPGgyPkRpc2NvdmVyZWQgY2FuZGlkYXRlczwvaDI+CiAgICAgIDx0YWJsZT48dGhlYWQ+PHRyPjx0aD5JUDwvdGg+PHRoPk1BQzwvdGg+PHRoPkZvdW5kIHZpYTwvdGg+PHRoPlZlcmlmaWVkPC90aD48dGg+PC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJkaXNjb3ZlclJvd3MiPjwvdGJvZHk+PC90YWJsZT4KICAgIDwvZGl2PgogIDwvc2VjdGlvbj4KCiAgPCEtLSBDQVRBTE9HIEJBQ0tVUCAvIFZJRVcgLyBESUZGIC8gUkVTVE9SRSAtLT4KICA8c2VjdGlvbiBpZD0iY2F0YWxvZyIgY2xhc3M9ImNhcmQiPgogICAgPGgyPkNhdGFsb2cgYmFja3VwICZtaWRkb3Q7IHZpZXcgJm1pZGRvdDsgZGlmZiAmbWlkZG90OyByZXN0b3JlPC9oMj4KICAgIDxwIGNsYXNzPSJtdXRlZCIgc3R5bGU9Im1hcmdpbi10b3A6LTZweCI+CiAgICAgIEEgY29tcGxldGUsIGNhdGFsb2ctZHJpdmVuIGJhY2t1cCBvZiBldmVyeSBwcm9ncmFtIHRoZSBlTWFuYWdlciBtb2RlbCBrbm93cwogICAgICAoPHNwYW4gaWQ9ImNhdEluZm8iPmxvYWRpbmcgY2F0YWxvZyZoZWxsaXA7PC9zcGFuPikuIFVzZXMgdGhlIElQIC8gY29tbXVuaXR5IC8gcG9ydCBhYm92ZS4KICAgICAgUmVzdG9yZSBpcyBnYXRlZCBhbmQgcmVhZC1iYWNrIHZlcmlmaWVkICZtZGFzaDsgcmVhZC1vbmx5IGZpZWxkcyBhcmUgbmV2ZXIgd3JpdHRlbi4KICAgIDwvcD4KICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImJ0bkNhdEJhY2t1cCI+RnVsbCBjYXRhbG9nIGJhY2t1cCAobGl2ZSByZWFkKTwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJidG5PcGVuQSI+T3BlbiBiYWNrdXAgJnJhcnI7IEEmaGVsbGlwOzwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJidG5PcGVuQiI+T3BlbiBiYWNrdXAgJnJhcnI7IEImaGVsbGlwOzwvYnV0dG9uPgogICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImNhdEZpbGVBIiBhY2NlcHQ9Ii5qc29uLGFwcGxpY2F0aW9uL2pzb24iIGNsYXNzPSJoaWRlIj4KICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJjYXRGaWxlQiIgYWNjZXB0PSIuanNvbixhcHBsaWNhdGlvbi9qc29uIiBjbGFzcz0iaGlkZSI+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InJvdyIgc3R5bGU9Im1hcmdpbi10b3A6MTBweDthbGlnbi1pdGVtczpjZW50ZXIiPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCIgaWQ9InNsb3RBIj5BOiAoZW1wdHkpPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCIgaWQ9InNsb3RCIj5COiAoZW1wdHkpPC9zcGFuPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3Qgc21hbGwiIGlkPSJidG5DYXRWaWV3IiBkaXNhYmxlZD5WaWV3IEE8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IHNtYWxsIiBpZD0iYnRuQ2F0RGlmZiIgZGlzYWJsZWQ+RGlmZiBBICZyYXJyOyBCPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCBzbWFsbCIgaWQ9ImJ0bkNhdERvd25sb2FkIiBkaXNhYmxlZD5Eb3dubG9hZCBBICguanNvbik8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IHNtYWxsIiBpZD0iYnRuQ2F0UmVzdG9yZVByZXYiIGRpc2FibGVkPlByZXZpZXcgcmVzdG9yZSBvZiBBPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBzbWFsbCIgaWQ9ImJ0bkNhdFJlc3RvcmVHbyIgZGlzYWJsZWQ+Q29uZmlybSAmYW1wOyByZXN0b3JlIEE8L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ibXNnIiBpZD0iY2F0TXNnIj48L2Rpdj4KICAgIDxwcmUgaWQ9ImNhdE91dCIgY2xhc3M9Im1vbm8iIHN0eWxlPSJ3aGl0ZS1zcGFjZTpwcmUtd3JhcDttYXgtaGVpZ2h0OjQ2MHB4O292ZXJmbG93OmF1dG87YmFja2dyb3VuZDp2YXIoLS1wYW5lbDIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czo4cHg7cGFkZGluZzoxMnB4O21hcmdpbi10b3A6MTJweDtkaXNwbGF5Om5vbmUiPjwvcHJlPgogIDwvc2VjdGlvbj4KCiAgPCEtLSBSRVNVTFRTIC0tPgogIDxzZWN0aW9uIGlkPSJyZXN1bHRzIiBjbGFzcz0iaGlkZSI+CiAgICA8ZGl2IGNsYXNzPSJ0YWJzIiBpZD0idGFicyI+CiAgICAgIDxkaXYgY2xhc3M9InRhYiBhY3RpdmUiIGRhdGEtdmlldz0ib3ZlcnZpZXciPk92ZXJ2aWV3PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJzdGF0aW9ucyI+U3RhdGlvbnMgPHNwYW4gY2xhc3M9ImNvdW50IiBpZD0iY1N0YXRpb25zIj48L3NwYW4+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJlcXVpcG1lbnQiPkVxdWlwbWVudCA8c3BhbiBjbGFzcz0iY291bnQiIGlkPSJjRXF1aXAiPjwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0idGFiIiBkYXRhLXZpZXc9InN5c3RlbSI+U3lzdGVtPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJuZXR3b3JrIj5OZXR3b3JrIC8gRlRQPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYiIgZGF0YS12aWV3PSJyYXciPlByb2dyYW1zIDxzcGFuIGNsYXNzPSJjb3VudCIgaWQ9ImNSYXciPjwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0idGFiIiBkYXRhLXZpZXc9ImV4cG9ydCI+RXhwb3J0PC9kaXY+CiAgICA8L2Rpdj4KCiAgICA8ZGl2IGNsYXNzPSJ2aWV3IGFjdGl2ZSIgaWQ9InZpZXctb3ZlcnZpZXciPjwvZGl2PgogICAgPGRpdiBjbGFzcz0idmlldyIgaWQ9InZpZXctc3RhdGlvbnMiPgogICAgICA8ZGl2IGNsYXNzPSJ0b29sYmFyIj4KICAgICAgICA8aW5wdXQgdHlwZT0ic2VhcmNoIiBpZD0ic3RhdGlvblNlYXJjaCIgcGxhY2Vob2xkZXI9IlNlYXJjaCBETiwgZXh0ZW5zaW9uLCBwb3J0LCB0eXBlLCBuYW1lJmhlbGxpcDsiPgogICAgICAgIDxzcGFuIGNsYXNzPSJtdXRlZCIgaWQ9InN0YXRpb25Db3VudCI+PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCIgc3R5bGU9InBhZGRpbmc6MDtvdmVyZmxvdzphdXRvIj4KICAgICAgICA8dGFibGUgaWQ9InN0YXRpb25UYWJsZSI+CiAgICAgICAgICA8dGhlYWQ+PHRyPgogICAgICAgICAgICA8dGggZGF0YS1zb3J0PSJkbiI+RE48L3RoPjx0aCBkYXRhLXNvcnQ9ImV4dGVuc2lvbiI+RXh0ZW5zaW9uPC90aD4KICAgICAgICAgICAgPHRoIGRhdGEtc29ydD0iZXF1aXBtZW50X3BvcnQiPlBvcnQ8L3RoPjx0aCBkYXRhLXNvcnQ9InR5cGUiPlR5cGU8L3RoPgogICAgICAgICAgICA8dGggZGF0YS1zb3J0PSJuYW1lIj5OYW1lPC90aD48dGggZGF0YS1zb3J0PSJrZXljb3VudCI+S2V5czwvdGg+CiAgICAgICAgICA8L3RyPjwvdGhlYWQ+CiAgICAgICAgICA8dGJvZHkgaWQ9InN0YXRpb25Sb3dzIj48L3Rib2R5PgogICAgICAgIDwvdGFibGU+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ2aWV3IiBpZD0idmlldy1lcXVpcG1lbnQiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0idmlldyIgaWQ9InZpZXctc3lzdGVtIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InZpZXciIGlkPSJ2aWV3LW5ldHdvcmsiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0idmlldyIgaWQ9InZpZXctcmF3Ij48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InZpZXciIGlkPSJ2aWV3LWV4cG9ydCI+PC9kaXY+CiAgPC9zZWN0aW9uPgo8L21haW4+Cgo8ZGl2IGNsYXNzPSJvdmVybGF5IiBpZD0ib3ZlcmxheSI+PC9kaXY+Cjxhc2lkZSBjbGFzcz0iZHJhd2VyIiBpZD0iZHJhd2VyIj48L2FzaWRlPgoKPGZvb3Rlcj5Ub3NoaWJhIENJWCBNYW5hZ2VyICZtZGFzaDsgbG9jYWwgdG9vbCBvdmVyIFNOTVAuIFdyaXRlcyByZXF1aXJlIGFuIGV4cGxpY2l0IENvbmZpcm0gJmFtcDsgd3JpdGUgYW5kIGFyZSByZWFkLWJhY2sgdmVyaWZpZWQuPC9mb290ZXI+Cgo8c2NyaXB0PgoidXNlIHN0cmljdCI7CmNvbnN0ICQgPSAocywgcj1kb2N1bWVudCk9PnIucXVlcnlTZWxlY3RvcihzKTsKY29uc3QgJCQgPSAocywgcj1kb2N1bWVudCk9PkFycmF5LmZyb20oci5xdWVyeVNlbGVjdG9yQWxsKHMpKTsKY29uc3QgZXNjID0gcyA9PiBTdHJpbmcocz09bnVsbD8iIjpzKS5yZXBsYWNlKC9bJjw+Il0vZyxjPT4oeycmJzonJmFtcDsnLCc8JzonJmx0OycsJz4nOicmZ3Q7JywnIic6JyZxdW90Oyd9W2NdKSk7CmNvbnN0IE1JU1NJTkcgPSAiPE1JU1NJTkc+IjsKbGV0IERPQyA9IG51bGw7ICAgICAgICAgICAgLy8gdGhlIGN1cnJlbnQgcmVhZCBkb2N1bWVudApsZXQgUkVQT1JUID0gIiI7ICAgICAgICAgICAvLyBzZXJ2ZXItcmVuZGVyZWQgdGV4dCByZXBvcnQKbGV0IFNUQVRJT05fU09SVCA9IHtrZXk6ImRuIiwgZGlyOjF9OwoKZnVuY3Rpb24gc2V0U3RhdHVzKGh0bWwpeyAkKCIjc3RhdHVzIikuaW5uZXJIVE1MID0gaHRtbDsgfQpmdW5jdGlvbiBzaG93TXNnKGVsLCBraW5kLCBodG1sKXsgZWwuY2xhc3NOYW1lID0gIm1zZyBzaG93ICIra2luZDsgZWwuaW5uZXJIVE1MID0gaHRtbDsgfQpmdW5jdGlvbiBoaWRlTXNnKGVsKXsgZWwuY2xhc3NOYW1lID0gIm1zZyI7IH0KCmZ1bmN0aW9uIGZtdFBvcnQocCl7CiAgaWYodHlwZW9mIHA9PT0ic3RyaW5nIiAmJiAvXlxkezZ9JC8udGVzdChwKSkgcmV0dXJuIHAuc2xpY2UoMCwyKSsiLSIrcC5zbGljZSgyLDQpKyItIitwLnNsaWNlKDQsNik7CiAgcmV0dXJuIHA9PW51bGx8fHA9PT1NSVNTSU5HID8gIiIgOiBwOwp9CmZ1bmN0aW9uIHZhbCh2KXsgcmV0dXJuICh2PT1udWxsfHx2PT09TUlTU0lORykgPyAiIiA6IHY7IH0KCmFzeW5jIGZ1bmN0aW9uIGFwaShwYXRoLCBib2R5KXsKICBjb25zdCBvcHQgPSBib2R5ID8ge21ldGhvZDoiUE9TVCIsIGhlYWRlcnM6eyJDb250ZW50LVR5cGUiOiJhcHBsaWNhdGlvbi9qc29uIn0sIGJvZHk6SlNPTi5zdHJpbmdpZnkoYm9keSl9IDoge307CiAgY29uc3QgciA9IGF3YWl0IGZldGNoKHBhdGgsIG9wdCk7CiAgY29uc3QgY3QgPSByLmhlYWRlcnMuZ2V0KCJjb250ZW50LXR5cGUiKXx8IiI7CiAgaWYoY3QuaW5jbHVkZXMoImFwcGxpY2F0aW9uL2pzb24iKSkgcmV0dXJuIHIuanNvbigpOwogIHJldHVybiByOwp9CgpmdW5jdGlvbiByZWFkRm9ybSgpewogIHJldHVybiB7CiAgICBpcDogJCgiI2lwIikudmFsdWUudHJpbSgpLAogICAgY29tbXVuaXR5OiAkKCIjY29tbXVuaXR5IikudmFsdWUudHJpbSgpIHx8ICJjb21tdW5pdHlOYW1lIiwKICAgIHBvcnQ6IHBhcnNlSW50KCQoIiNwb3J0IikudmFsdWUsMTApIHx8IDE2MSwKICAgIHNjb3BlOiAkKCIjc2NvcGUiKS52YWx1ZSwKICB9Owp9CgovKiAtLS0tLS0tLS0tIFRlc3QgY29ubmVjdGlvbiAtLS0tLS0tLS0tICovCiQoIiNidG5UZXN0Iikub25jbGljayA9IGFzeW5jICgpPT57CiAgY29uc3QgZiA9IHJlYWRGb3JtKCk7CiAgaWYoIWYuaXApeyBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImVyciIsIkVudGVyIHRoZSBDSVggSVAgYWRkcmVzcyBmaXJzdC4iKTsgcmV0dXJuOyB9CiAgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJpbmZvIiwnPHNwYW4gY2xhc3M9InNwaW5uZXIiPjwvc3Bhbj5UZXN0aW5nIFNOTVAgdG8gJytlc2MoZi5pcCkrJyZoZWxsaXA7Jyk7CiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL2Nvbm5lY3QiLCBmKTsKICAgIGlmKHJlcy5vaykgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJvayIsIkNvbm5lY3RlZC4gU29mdHdhcmUgaWQ6IDxiPiIrZXNjKHJlcy5zb2Z0d2FyZV9pZCkrIjwvYj4iKwogICAgICAgIChyZXMuY2hhc3Npc19tYWM/KCIgJm5ic3A7IE1BQzogPHNwYW4gY2xhc3M9J21vbm8nPiIrZXNjKHJlcy5jaGFzc2lzX21hYykrIjwvc3Bhbj4iKToiIikpOwogICAgZWxzZSBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImVyciIsIk5vIENJWCBhbnN3ZXJlZDogIitlc2MocmVzLmVycm9yfHwidW5rbm93biBlcnJvciIpKTsKICB9Y2F0Y2goZSl7IHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiZXJyIiwiUmVxdWVzdCBmYWlsZWQ6ICIrZXNjKGUubWVzc2FnZSkpOyB9Cn07CgovKiAtLS0tLS0tLS0tIFJlYWQgLS0tLS0tLS0tLSAqLwokKCIjYnRuUmVhZCIpLm9uY2xpY2sgPSBhc3luYyAoKT0+ewogIGNvbnN0IGYgPSByZWFkRm9ybSgpOwogIGlmKCFmLmlwKXsgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJlcnIiLCJFbnRlciB0aGUgQ0lYIElQIGFkZHJlc3MgZmlyc3QuIik7IHJldHVybjsgfQogIGNvbnN0IHNsb3cgPSBmLnNjb3BlPT09ImFsbCIgPyAiIChmdWxsIE1JQiAmbWRhc2g7IHRoaXMgY2FuIHRha2UgYSBmZXcgbWludXRlcykiIDogIiI7CiAgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJpbmZvIiwnPHNwYW4gY2xhc3M9InNwaW5uZXIiPjwvc3Bhbj5SZWFkaW5nICcrZXNjKGYuaXApK3Nsb3crJyZoZWxsaXA7Jyk7CiAgJCgiI2J0blJlYWQiKS5kaXNhYmxlZCA9IHRydWU7CiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL3JlYWQiLCBmKTsKICAgIGlmKCFyZXMub2speyBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImVyciIsIlJlYWQgZmFpbGVkOiAiK2VzYyhyZXMuZXJyb3J8fCJ1bmtub3duIikpOyByZXR1cm47IH0KICAgIERPQyA9IHJlcy5kb2M7IFJFUE9SVCA9IHJlcy5yZXBvcnQgfHwgIiI7CiAgICBoaWRlTXNnKCQoIiNjb25uZWN0TXNnIikpOwogICAgcmVuZGVyQWxsKCk7CiAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjb25uZWN0TXNnIiksImVyciIsIlJlcXVlc3QgZmFpbGVkOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQogIGZpbmFsbHl7ICQoIiNidG5SZWFkIikuZGlzYWJsZWQgPSBmYWxzZTsgfQp9OwoKLyogLS0tLS0tLS0tLSBEaXNjb3ZlciAtLS0tLS0tLS0tICovCiQoIiNidG5EaXNjb3ZlciIpLm9uY2xpY2sgPSBhc3luYyAoKT0+ewogIHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiaW5mbyIsJzxzcGFuIGNsYXNzPSJzcGlubmVyIj48L3NwYW4+U2Nhbm5pbmcgdGhlIGxvY2FsIG5ldHdvcmsgKEFSUCArIHBpbmcgc3dlZXApJmhlbGxpcDsnKTsKICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBhcGkoIi9hcGkvZGlzY292ZXIiKTsKICAgIGNvbnN0IGNhbmRzID0gKHJlcy5jYW5kaWRhdGVzfHxbXSk7CiAgICBjb25zdCBib3ggPSAkKCIjZGlzY292ZXJCb3giKSwgcm93cyA9ICQoIiNkaXNjb3ZlclJvd3MiKTsKICAgIHJvd3MuaW5uZXJIVE1MID0gIiI7CiAgICBpZighY2FuZHMubGVuZ3RoKXsgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCJpbmZvIiwiTm8gY2FuZGlkYXRlcyBmb3VuZC4gRW50ZXIgdGhlIElQIG1hbnVhbGx5LCBvciB0cnkgdGhlIC4yNTMgY29udmVudGlvbi4iKTsgYm94LmNsYXNzTGlzdC5hZGQoImhpZGUiKTsgcmV0dXJuOyB9CiAgICBjYW5kcy5mb3JFYWNoKGM9PnsKICAgICAgY29uc3QgdHIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJ0ciIpOwogICAgICB0ci5pbm5lckhUTUwgPSAiPHRkIGNsYXNzPSdtb25vJz4iK2VzYyhjLmlwKSsiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKGMubWFjfHwiIikrIjwvdGQ+IisKICAgICAgICAiPHRkPiIrZXNjKGMudmlhfHwiIikrIjwvdGQ+IisKICAgICAgICAiPHRkPiIrKGMudmVyaWZpZWQ/KCI8c3BhbiBzdHlsZT0nY29sb3I6dmFyKC0tb2spJz4mIzEwMDAzOyAiK2VzYyhjLnNvZnR3YXJlX2lkfHwiQ0lYIikrIjwvc3Bhbj4iKToiPHNwYW4gY2xhc3M9J211dGVkJz51bnZlcmlmaWVkPC9zcGFuPiIpKyI8L3RkPiIrCiAgICAgICAgIjx0ZD48YnV0dG9uIGNsYXNzPSdidG4gc21hbGwnPlVzZTwvYnV0dG9uPjwvdGQ+IjsKICAgICAgdHIucXVlcnlTZWxlY3RvcigiYnV0dG9uIikub25jbGljayA9ICgpPT57ICQoIiNpcCIpLnZhbHVlID0gYy5pcDsgaGlkZU1zZygkKCIjY29ubmVjdE1zZyIpKTsgfTsKICAgICAgcm93cy5hcHBlbmRDaGlsZCh0cik7CiAgICB9KTsKICAgIGJveC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRlIik7CiAgICBjb25zdCBudmVyaWZpZWQgPSBjYW5kcy5maWx0ZXIoYz0+Yy52ZXJpZmllZCkubGVuZ3RoOwogICAgc2hvd01zZygkKCIjY29ubmVjdE1zZyIpLCBudmVyaWZpZWQ/Im9rIjoiaW5mbyIsCiAgICAgICJGb3VuZCAiK2NhbmRzLmxlbmd0aCsiIGNhbmRpZGF0ZShzKSIrKG52ZXJpZmllZD8oIiwgIitudmVyaWZpZWQrIiB2ZXJpZmllZCBhcyBhIENJWCIpOiIiKSsiLiBQaWNrIG9uZSBiZWxvdy4iKTsKICB9Y2F0Y2goZSl7IHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiZXJyIiwiRGlzY292ZXIgZmFpbGVkOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQp9OwoKLyogLS0tLS0tLS0tLSBPcGVuIGJhY2t1cCBmaWxlIChvZmZsaW5lIHZpZXdlcikgLS0tLS0tLS0tLSAqLwokKCIjYnRuT3BlbiIpLm9uY2xpY2sgPSAoKT0+ICQoIiNmaWxlSW5wdXQiKS5jbGljaygpOwokKCIjZmlsZUlucHV0Iikub25jaGFuZ2UgPSAoZXYpPT57CiAgY29uc3QgZmlsZSA9IGV2LnRhcmdldC5maWxlc1swXTsgaWYoIWZpbGUpIHJldHVybjsKICBjb25zdCBmciA9IG5ldyBGaWxlUmVhZGVyKCk7CiAgZnIub25sb2FkID0gKCk9PnsKICAgIHRyeXsKICAgICAgY29uc3QgZG9jID0gSlNPTi5wYXJzZShmci5yZXN1bHQpOwogICAgICBpZighZG9jLnN0YXRpb25zICYmICFkb2Muc3lzdGVtKXsgdGhyb3cgbmV3IEVycm9yKCJub3QgYSBDSVggYmFja3VwIEpTT04iKTsgfQogICAgICBET0MgPSBkb2M7IFJFUE9SVCA9ICIiOwogICAgICBoaWRlTXNnKCQoIiNjb25uZWN0TXNnIikpOwogICAgICByZW5kZXJBbGwodHJ1ZSk7CiAgICB9Y2F0Y2goZSl7IHNob3dNc2coJCgiI2Nvbm5lY3RNc2ciKSwiZXJyIiwiQ291bGQgbm90IGxvYWQgYmFja3VwOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQogIH07CiAgZnIucmVhZEFzVGV4dChmaWxlKTsKICBldi50YXJnZXQudmFsdWUgPSAiIjsKfTsKCi8qIC0tLS0tLS0tLS0gVGFicyAtLS0tLS0tLS0tICovCiQkKCIudGFiIikuZm9yRWFjaCh0PT4gdC5vbmNsaWNrID0gKCk9PnsKICAkJCgiLnRhYiIpLmZvckVhY2goeD0+eC5jbGFzc0xpc3QucmVtb3ZlKCJhY3RpdmUiKSk7CiAgJCQoIi52aWV3IikuZm9yRWFjaCh4PT54LmNsYXNzTGlzdC5yZW1vdmUoImFjdGl2ZSIpKTsKICB0LmNsYXNzTGlzdC5hZGQoImFjdGl2ZSIpOwogICQoIiN2aWV3LSIrdC5kYXRhc2V0LnZpZXcpLmNsYXNzTGlzdC5hZGQoImFjdGl2ZSIpOwp9KTsKCi8qIC0tLS0tLS0tLS0gUmVuZGVyIC0tLS0tLS0tLS0gKi8KZnVuY3Rpb24gcmVuZGVyQWxsKGZyb21GaWxlKXsKICAkKCIjY29ubmVjdCIpLmNsYXNzTGlzdC5hZGQoImhpZGUiKTsKICAkKCIjcmVzdWx0cyIpLmNsYXNzTGlzdC5yZW1vdmUoImhpZGUiKTsKICBjb25zdCBkID0gRE9DLmRldmljZXx8e30sIHMgPSBET0Muc3lzdGVtfHx7fTsKICBzZXRTdGF0dXMoIjxiPiIrZXNjKGQuaXB8fCJiYWNrdXAiKSsiPC9iPiAmbWlkZG90OyAiK2VzYyh2YWwocy5zb2Z0d2FyZV9pZCl8fCI/IikrCiAgICAgICAgICAgICIgJm1pZGRvdDsgIitlc2ModmFsKHMuY2hhc3Npc19tYWMpfHwiIikgKwogICAgICAgICAgICAoZnJvbUZpbGU/IiAmbWlkZG90OyA8c3BhbiBjbGFzcz0nbXV0ZWQnPmZyb20gZmlsZTwvc3Bhbj4iOiIiKSk7CiAgJCgiI2NTdGF0aW9ucyIpLnRleHRDb250ZW50ID0gKERPQy5zdGF0aW9uc3x8W10pLmxlbmd0aDsKICAkKCIjY0VxdWlwIikudGV4dENvbnRlbnQgPSAoRE9DLmVxdWlwbWVudHx8W10pLmxlbmd0aDsKICBjb25zdCBwdiA9IERPQy5wcm9ncmFtX3ZpZXdzOwogICQoIiNjUmF3IikudGV4dENvbnRlbnQgPSAocHYgJiYgcHYucHJvZ3JhbXMpID8gcHYucHJvZ3JhbXMubGVuZ3RoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IE9iamVjdC5rZXlzKERPQy5yYXdfcHJvZ3JhbXN8fHt9KS5sZW5ndGg7CiAgcmVuZGVyT3ZlcnZpZXcoKTsgcmVuZGVyU3RhdGlvbnMoKTsgcmVuZGVyRXF1aXBtZW50KCk7IHJlbmRlclN5c3RlbSgpOwogIHJlbmRlck5ldHdvcmsoKTsgcmVuZGVyUHJvZ3JhbXMoKTsgcmVuZGVyRXhwb3J0KGZyb21GaWxlKTsKICB3aW5kb3cuc2Nyb2xsVG8oMCwwKTsKfQoKZnVuY3Rpb24gcmVuZGVyT3ZlcnZpZXcoKXsKICBjb25zdCBkID0gRE9DLmRldmljZXx8e30sIHMgPSBET0Muc3lzdGVtfHx7fTsKICBjb25zdCBmaW5kaW5ncyA9IERPQy5zZWN1cml0eV9maW5kaW5nc3x8W107CiAgbGV0IGh0bWwgPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPkRldmljZTwvaDI+PGRpdiBjbGFzcz0na3YnPiIrCiAgICBrdigiSVAgLyBwb3J0IiwgKHZhbChkLmlwKXx8IuKAlCIpKyI6IisoZC5wb3J0fHwxNjEpKSsKICAgIGt2KCJDb21tdW5pdHkiLCB2YWwoZC5jb21tdW5pdHkpKSsKICAgIGt2KCJTb2Z0d2FyZSBpZCIsIHZhbChzLnNvZnR3YXJlX2lkKSkrCiAgICBrdigiQ2hhc3NpcyBNQUMiLCB2YWwocy5jaGFzc2lzX21hYykpKwogICAga3YoIlJlYWQgYXQiLCB2YWwoZC5yZWFkX2F0KSkrCiAgICBrdigiU2NvcGUiLCB2YWwoZC5zY29wZSkpKwogICAga3YoIk9JRHMgcmVhZCIsIHZhbChkLm9pZHNfcmVhZCkpKwogICAgKGQud2Fsa19lcnJvcj9rdigiV2FsayBlcnJvciIsICI8c3BhbiBzdHlsZT0nY29sb3I6dmFyKC0td2FybiknPiIrZXNjKGQud2Fsa19lcnJvcikrIjwvc3Bhbj4iKToiIikrCiAgICAiPC9kaXY+PC9kaXY+IjsKICBpZihmaW5kaW5ncy5sZW5ndGgpewogICAgaHRtbCArPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPlNlY3VyaXR5IGZpbmRpbmdzPC9oMj4iOwogICAgZmluZGluZ3MuZm9yRWFjaChmPT4gaHRtbCArPSAiPGRpdiBjbGFzcz0nZmluZGluZyAiK2VzYyhmLnNldmVyaXR5KSsiJz48c3BhbiBjbGFzcz0nc2V2Jz4iKwogICAgICBlc2MoKGYuc2V2ZXJpdHl8fCIiKS50b1VwcGVyQ2FzZSgpKSsiPC9zcGFuPiIrZXNjKGYuZGV0YWlsKSsiPC9kaXY+Iik7CiAgICBodG1sICs9ICI8L2Rpdj4iOwogIH0KICBjb25zdCBzdCA9IERPQy5zdGF0c3x8e307CiAgaHRtbCArPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPlRvdGFsczwvaDI+PGRpdiBjbGFzcz0na3YnPiIrCiAgICBPYmplY3Qua2V5cyhzdCkuc29ydCgpLm1hcChrPT5rdihrLCBzdFtrXSkpLmpvaW4oIiIpKyI8L2Rpdj48L2Rpdj4iOwogICQoIiN2aWV3LW92ZXJ2aWV3IikuaW5uZXJIVE1MID0gaHRtbDsKfQpmdW5jdGlvbiBrdihrLHYpeyByZXR1cm4gIjxkaXYgY2xhc3M9J2snPiIrZXNjKGspKyI8L2Rpdj48ZGl2PiIrICh2PT1udWxsPyIiOigiIit2KS5zdGFydHNXaXRoKCI8Iik/djplc2ModikpICsiPC9kaXY+IjsgfQoKZnVuY3Rpb24gc3RhdGlvbktleWNvdW50KHN0KXsgcmV0dXJuIChzdC5rZXlzfHxbXSkubGVuZ3RoOyB9CmZ1bmN0aW9uIHJlbmRlclN0YXRpb25zKCl7CiAgY29uc3QgcSA9ICQoIiNzdGF0aW9uU2VhcmNoIikudmFsdWUudG9Mb3dlckNhc2UoKTsKICBsZXQgcm93cyA9IChET0Muc3RhdGlvbnN8fFtdKS5zbGljZSgpOwogIGlmKHEpewogICAgcm93cyA9IHJvd3MuZmlsdGVyKHN0PT5bc3QuZG4sc3QuZXh0ZW5zaW9uLHN0LmVxdWlwbWVudF9wb3J0LHN0LnR5cGUsc3QubmFtZV0KICAgICAgLnNvbWUodj0+IFN0cmluZyh2YWwodikpLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMocSkpKTsKICB9CiAgY29uc3QgayA9IFNUQVRJT05fU09SVC5rZXksIGRpciA9IFNUQVRJT05fU09SVC5kaXI7CiAgcm93cy5zb3J0KChhLGIpPT57CiAgICBsZXQgdmEgPSBrPT09ImtleWNvdW50Ij9zdGF0aW9uS2V5Y291bnQoYSk6dmFsKGFba10pLCB2YiA9IGs9PT0ia2V5Y291bnQiP3N0YXRpb25LZXljb3VudChiKTp2YWwoYltrXSk7CiAgICBpZihrPT09ImRuInx8az09PSJleHRlbnNpb24iKXsgY29uc3QgbmE9cGFyc2VJbnQodmEsMTApLCBuYj1wYXJzZUludCh2YiwxMCk7CiAgICAgIGlmKCFpc05hTihuYSkmJiFpc05hTihuYikpIHJldHVybiAobmEtbmIpKmRpcjsgfQogICAgcmV0dXJuIFN0cmluZyh2YSkubG9jYWxlQ29tcGFyZShTdHJpbmcodmIpKSpkaXI7CiAgfSk7CiAgJCgiI3N0YXRpb25Db3VudCIpLnRleHRDb250ZW50ID0gcm93cy5sZW5ndGgrIiBvZiAiKyhET0Muc3RhdGlvbnN8fFtdKS5sZW5ndGgrIiBzaG93biI7CiAgY29uc3QgdGIgPSAkKCIjc3RhdGlvblJvd3MiKTsgdGIuaW5uZXJIVE1MID0gIiI7CiAgcm93cy5mb3JFYWNoKHN0PT57CiAgICBjb25zdCB0ciA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInRyIik7IHRyLmNsYXNzTmFtZT0iY2xpY2thYmxlIjsKICAgIHRyLmlubmVySFRNTCA9ICI8dGQgY2xhc3M9J21vbm8nPiIrZXNjKHZhbChzdC5kbikpKyI8L3RkPiIrCiAgICAgICI8dGQgY2xhc3M9J21vbm8nPiIrZXNjKHZhbChzdC5leHRlbnNpb24pKSsiPC90ZD4iKwogICAgICAiPHRkIGNsYXNzPSdtb25vJz4iK2VzYyhmbXRQb3J0KHN0LmVxdWlwbWVudF9wb3J0KSkrIjwvdGQ+IisKICAgICAgIjx0ZD4iK2VzYyh2YWwoc3QudHlwZSkpKyI8L3RkPiIrCiAgICAgICI8dGQ+Iitlc2ModmFsKHN0Lm5hbWUpKSsiPC90ZD4iKwogICAgICAiPHRkPiIrc3RhdGlvbktleWNvdW50KHN0KSsiPC90ZD4iOwogICAgdHIub25jbGljayA9ICgpPT4gb3BlblN0YXRpb24oc3QpOwogICAgdGIuYXBwZW5kQ2hpbGQodHIpOwogIH0pOwp9CiQoIiNzdGF0aW9uU2VhcmNoIikub25pbnB1dCA9IHJlbmRlclN0YXRpb25zOwokJCgiI3N0YXRpb25UYWJsZSB0aCIpLmZvckVhY2godGg9PiB0aC5vbmNsaWNrID0gKCk9PnsKICBjb25zdCBrZXkgPSB0aC5kYXRhc2V0LnNvcnQ7CiAgaWYoU1RBVElPTl9TT1JULmtleT09PWtleSkgU1RBVElPTl9TT1JULmRpcio9LTE7IGVsc2UgU1RBVElPTl9TT1JUPXtrZXksIGRpcjoxfTsKICByZW5kZXJTdGF0aW9ucygpOwp9KTsKCmZ1bmN0aW9uIHJlbmRlckVxdWlwbWVudCgpewogIGNvbnN0IGVxID0gRE9DLmVxdWlwbWVudHx8W107CiAgbGV0IGh0bWwgPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPkVxdWlwbWVudCAvIGNhYmluZXQgcm93cyAoIitlcS5sZW5ndGgrIik8L2gyPiI7CiAgaWYoIWVxLmxlbmd0aCl7IGh0bWwgKz0gIjxwIGNsYXNzPSdtdXRlZCc+Tm9uZSByZXR1cm5lZC48L3A+PC9kaXY+IjsgJCgiI3ZpZXctZXF1aXBtZW50IikuaW5uZXJIVE1MPWh0bWw7IHJldHVybjsgfQogIGNvbnN0IGNvbHMgPSBuZXcgU2V0KCk7IGVxLmZvckVhY2gocj0+T2JqZWN0LmtleXMocikuZm9yRWFjaChrPT57IGlmKGshPT0iaW5kZXgiKSBjb2xzLmFkZChrKTsgfSkpOwogIGNvbnN0IGNvbExpc3QgPSBBcnJheS5mcm9tKGNvbHMpOwogIGh0bWwgKz0gIjxkaXYgc3R5bGU9J292ZXJmbG93OmF1dG8nPjx0YWJsZT48dGhlYWQ+PHRyPjx0aD5JbmRleDwvdGg+IisKICAgIGNvbExpc3QubWFwKGM9PiI8dGg+Iitlc2MoYykrIjwvdGg+Iikuam9pbigiIikrIjwvdHI+PC90aGVhZD48dGJvZHk+IjsKICBlcS5mb3JFYWNoKHI9PnsKICAgIGh0bWwgKz0gIjx0cj48dGQgY2xhc3M9J21vbm8nPiIrZXNjKEpTT04uc3RyaW5naWZ5KHIuaW5kZXgpKSsiPC90ZD4iKwogICAgICBjb2xMaXN0Lm1hcChjPT4iPHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwocltjXSkpKyI8L3RkPiIpLmpvaW4oIiIpKyI8L3RyPiI7CiAgfSk7CiAgaHRtbCArPSAiPC90Ym9keT48L3RhYmxlPjwvZGl2PjwvZGl2PiI7CiAgJCgiI3ZpZXctZXF1aXBtZW50IikuaW5uZXJIVE1MID0gaHRtbDsKfQoKZnVuY3Rpb24gcmVuZGVyU3lzdGVtKCl7CiAgY29uc3QgcyA9IERPQy5zeXN0ZW18fHt9OwogIGNvbnN0IG51bWJlcmluZyA9IHMubnVtYmVyaW5nX2NvbmZpZ3x8e30sIHN0YXR1cyA9IHMuc3RhdHVzfHx7fTsKICBsZXQgaHRtbCA9ICI8ZGl2IGNsYXNzPSdjYXJkJz48aDI+U3lzdGVtIG51bWJlcmluZyAvIGZlYXR1cmUgY29uZmlnIChQcm9ncmFtIDU3OSk8L2gyPiI7CiAgY29uc3QgbmsgPSBPYmplY3Qua2V5cyhudW1iZXJpbmcpLnNvcnQoKTsKICBodG1sICs9IG5rLmxlbmd0aCA/ICI8ZGl2IGNsYXNzPSdrdic+Iituay5tYXAoaz0+a3YoaywgdmFsKG51bWJlcmluZ1trXSkpKS5qb2luKCIiKSsiPC9kaXY+IgogICAgICAgICAgICAgICAgICAgIDogIjxwIGNsYXNzPSdtdXRlZCc+Tm9uZSByZXR1cm5lZC48L3A+IjsKICBodG1sICs9ICI8L2Rpdj4iOwogIGNvbnN0IHNrID0gT2JqZWN0LmtleXMoc3RhdHVzKS5zb3J0KCk7CiAgaWYoc2subGVuZ3RoKXsKICAgIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5TeXN0ZW0gc3RhdHVzIHNjYWxhcnMgKC43LiopPC9oMj48ZGl2IGNsYXNzPSdrdic+IisKICAgICAgc2subWFwKGs9Pmt2KGssIHZhbChzdGF0dXNba10pKSkuam9pbigiIikrIjwvZGl2PjwvZGl2PiI7CiAgfQogICQoIiN2aWV3LXN5c3RlbSIpLmlubmVySFRNTCA9IGh0bWw7Cn0KCmZ1bmN0aW9uIHJlbmRlck5ldHdvcmsoKXsKICBjb25zdCBuZXQgPSBET0MubmV0d29ya19hY2Nlc3N8fFtdOwogIGxldCBodG1sID0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5OZXR3b3JrIC8gRlRQIGFjY2VzcyAoLjIuMy4xLjEpPC9oMj4iOwogIGlmKCFuZXQubGVuZ3RoKXsgaHRtbCArPSAiPHAgY2xhc3M9J211dGVkJz5Ob25lIHJldHVybmVkLjwvcD48L2Rpdj4iOyAkKCIjdmlldy1uZXR3b3JrIikuaW5uZXJIVE1MPWh0bWw7IHJldHVybjsgfQogIGh0bWwgKz0gIjx0YWJsZT48dGhlYWQ+PHRyPjx0aD5Sb3c8L3RoPjx0aD5Vc2VybmFtZTwvdGg+PHRoPlBhc3N3b3JkPC90aD48dGg+UGF0aDwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT4iOwogIG5ldC5mb3JFYWNoKHI9PiBodG1sICs9ICI8dHI+PHRkPiIrZXNjKHZhbChyLmluZGV4KSkrIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwoci51c2VybmFtZSkpKwogICAgIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwoci5wYXNzd29yZCkpKyI8L3RkPjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2ModmFsKHIucGF0aCkpKyI8L3RkPjwvdHI+Iik7CiAgaHRtbCArPSAiPC90Ym9keT48L3RhYmxlPjxwIGNsYXNzPSdtdXRlZCcgc3R5bGU9J21hcmdpbi1ib3R0b206MCc+VGhlc2UgYXJlIGxpdmUgY3JlZGVudGlhbHMgcmVhZCBmcm9tIHRoZSBQQlguPC9wPjwvZGl2PiI7CiAgJCgiI3ZpZXctbmV0d29yayIpLmlubmVySFRNTCA9IGh0bWw7Cn0KCi8qIFByb2dyYW1zIHRhYjogY2F0YWxvZy1uYW1lZCwgbWVudS1ncm91cGVkIChmcm9tIERPQy5wcm9ncmFtX3ZpZXdzKS4KICAgRmFsbHMgYmFjayB0byB0aGUgbGVnYWN5IHJhdyBwYXNzdGhyb3VnaCBmb3IgYmFja3VwcyBtYWRlIGJlZm9yZSBuYW1pbmcuICovCmZ1bmN0aW9uIHJlbmRlclByb2dyYW1zKCl7CiAgY29uc3QgcHYgPSBET0MucHJvZ3JhbV92aWV3czsKICBpZighcHYgfHwgIShwdi5wcm9ncmFtc3x8W10pLmxlbmd0aCkgcmV0dXJuIHJlbmRlclJhd0xlZ2FjeSgpOwogIGNvbnN0IHByb2dCeUtleSA9IHt9OyBwdi5wcm9ncmFtcy5mb3JFYWNoKHA9PiBwcm9nQnlLZXlbcC5jYXRhbG9nX2tleV09cCk7CiAgY29uc3QgcyA9IHB2LnN0YXRzfHx7fTsKICBsZXQgaHRtbCA9ICI8ZGl2IGNsYXNzPSdjYXJkJz48aDI+UHJvZ3JhbXMgYnkgZU1hbmFnZXIgbWVudSBhcmVhPC9oMj4iOwogIGh0bWwgKz0gIjxwIGNsYXNzPSdtdXRlZCc+RXZlcnkgY2F0YWxvZ2VkIGZpZWxkIGlzIG5hbWVkIGZyb20gdGhlIHJldmVyc2UtZW5naW5lZXJlZCBtb2RlbCAmbWRhc2g7ICIrCiAgICAocy5wcm9ncmFtc3x8MCkrIiBwcm9ncmFtcywgIisocy5yb3dzfHwwKSsiIHJvd3MsICIrKHMubmFtZWRfY2VsbHN8fDApKyIgbmFtZWQgZmllbGRzIisKICAgIChzLnVuY2F0YWxvZ2VkPygiLCAiK3MudW5jYXRhbG9nZWQrIiB1bmNhdGFsb2dlZCBPSUQocykiKToiIikrIi48L3A+IjsKICBjb25zdCBmZWF0cyA9IChwdi5mZWF0dXJlX3ZpZXdzfHxbXSkuZmlsdGVyKGY9PmYucHJlc2VudCk7CiAgaWYoZmVhdHMubGVuZ3RoKSBodG1sICs9ICI8cD4iK2ZlYXRzLm1hcChmPT4iPHNwYW4gY2xhc3M9J2NoaXAnPiIrZXNjKGYudGl0bGUpKyI8L3NwYW4+Iikuam9pbigiIikrIjwvcD4iOwogIChwdi5tZW51X2FyZWFzfHxbXSkuZm9yRWFjaChhcmVhPT57CiAgICBodG1sICs9ICI8aDMgc3R5bGU9J21hcmdpbjoxNnB4IDAgNnB4O2NvbG9yOnZhcigtLWZnKSc+Iitlc2MoYXJlYS5hcmVhKSsKICAgICAgIiA8c3BhbiBjbGFzcz0nbXV0ZWQnIHN0eWxlPSdmb250LXdlaWdodDo0MDA7Zm9udC1zaXplOjEycHgnPigiK2FyZWEucHJvZ3JhbXMubGVuZ3RoKwogICAgICAiIHByb2dyYW1zLCAiK2FyZWEucm93X2NvdW50KyIgcm93cyk8L3NwYW4+PC9oMz4iOwogICAgYXJlYS5wcm9ncmFtcy5mb3JFYWNoKGtleT0+ewogICAgICBjb25zdCBwID0gcHJvZ0J5S2V5W2tleV07IGlmKCFwKSByZXR1cm47CiAgICAgIGh0bWwgKz0gIjxkZXRhaWxzPjxzdW1tYXJ5PiIrZXNjKHAubGFiZWx8fHAucHJvZ3JhbV9uYW1lfHxwLmNhdGFsb2dfa2V5KSsKICAgICAgICAiIDxzcGFuIGNsYXNzPSdtdXRlZCcgc3R5bGU9J2ZvbnQtd2VpZ2h0OjQwMCc+Jm1kYXNoOyAiK2VzYyhwLm1lbnVfcGF0aHx8cC5jYXRhbG9nX2tleSkrCiAgICAgICAgIiAoIitwLnJvd19jb3VudCsiIHJvdyhzKSk8L3NwYW4+PC9zdW1tYXJ5PiI7CiAgICAgIGh0bWwgKz0gIjxkaXYgc3R5bGU9J292ZXJmbG93OmF1dG8nPjx0YWJsZT48dGhlYWQ+PHRyPjx0aD5Sb3c8L3RoPjx0aD5GaWVsZDwvdGg+IisKICAgICAgICAiPHRoPlZhbHVlPC90aD48dGg+T0lEPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PiI7CiAgICAgIChwLnJvd3N8fFtdKS5mb3JFYWNoKHI9PnsKICAgICAgICAoci5jZWxsc3x8W10pLmZvckVhY2goYz0+ewogICAgICAgICAgbGV0IGRpc3A7CiAgICAgICAgICBpZihjLmlzX2VudW0gJiYgYy5kaXNwbGF5X3ZhbHVlICYmIFN0cmluZyhjLmRpc3BsYXlfdmFsdWUpIT09U3RyaW5nKGMucmF3X3ZhbHVlKSkKICAgICAgICAgICAgZGlzcCA9IGVzYyhjLmRpc3BsYXlfdmFsdWUpKyIgPHNwYW4gY2xhc3M9J211dGVkJz4oIitlc2MoYy5yYXdfdmFsdWUpKyIpPC9zcGFuPiI7CiAgICAgICAgICBlbHNlIGRpc3AgPSBlc2MoYy5kaXNwbGF5X3ZhbHVlIT09IiImJmMuZGlzcGxheV92YWx1ZSE9bnVsbCA/IGMuZGlzcGxheV92YWx1ZSA6IHZhbChjLnJhd192YWx1ZSkpOwogICAgICAgICAgaHRtbCArPSAiPHRyPjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2Moci5rZXl8fHIuaW5kZXgpKyI8L3RkPiIrCiAgICAgICAgICAgICI8dGQ+Iitlc2MoYy5maWVsZF9uYW1lKSsoYy5pc19zZWNyZXQ/IiA8c3BhbiBjbGFzcz0nY2hpcCc+c2VjcmV0PC9zcGFuPiI6IiIpKyI8L3RkPiIrCiAgICAgICAgICAgICI8dGQgY2xhc3M9J21vbm8nPiIrZGlzcCsiPC90ZD48dGQgY2xhc3M9J21vbm8gbXV0ZWQnPiIrZXNjKGMub2lkKSsiPC90ZD48L3RyPiI7CiAgICAgICAgfSk7CiAgICAgIH0pOwogICAgICBodG1sICs9ICI8L3Rib2R5PjwvdGFibGU+PC9kaXY+PC9kZXRhaWxzPiI7CiAgICB9KTsKICB9KTsKICBjb25zdCB1biA9IHB2LnVuY2F0YWxvZ2VkfHxbXTsKICBpZih1bi5sZW5ndGgpewogICAgaHRtbCArPSAiPGgzIHN0eWxlPSdtYXJnaW46MTZweCAwIDZweDtjb2xvcjp2YXIoLS1mZyknPlVuY2F0YWxvZ2VkIE9JRHMgIisKICAgICAgIjxzcGFuIGNsYXNzPSdtdXRlZCcgc3R5bGU9J2ZvbnQtd2VpZ2h0OjQwMDtmb250LXNpemU6MTJweCc+KCIrdW4ubGVuZ3RoKyIpPC9zcGFuPjwvaDM+IjsKICAgIGh0bWwgKz0gIjxwIGNsYXNzPSdtdXRlZCc+R2VudWluZWx5IG91dHNpZGUgdGhlIGNhdGFsb2cgJm1kYXNoOyB0aGUgb25seSB2YWx1ZXMgc3RpbGwgc2hvd24gYXMgYSBiYXJlIE9JRC48L3A+IjsKICAgIGh0bWwgKz0gIjx0YWJsZT48dGhlYWQ+PHRyPjx0aD5PSUQ8L3RoPjx0aD5WYWx1ZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT4iOwogICAgdW4uZm9yRWFjaChlPT4gaHRtbCArPSAiPHRyPjx0ZCBjbGFzcz0nbW9ubyBtdXRlZCc+Iitlc2MoZS5vaWQpKyI8L3RkPjx0ZCBjbGFzcz0nbW9ubyc+IisKICAgICAgZXNjKHZhbChlLnJhd192YWx1ZSE9bnVsbD9lLnJhd192YWx1ZTplLnZhbHVlKSkrIjwvdGQ+PC90cj4iKTsKICAgIGh0bWwgKz0gIjwvdGJvZHk+PC90YWJsZT4iOwogIH0KICBodG1sICs9ICI8L2Rpdj4iOwogICQoIiN2aWV3LXJhdyIpLmlubmVySFRNTCA9IGh0bWw7Cn0KCmZ1bmN0aW9uIHJlbmRlclJhd0xlZ2FjeSgpewogIGNvbnN0IHJhdyA9IERPQy5yYXdfcHJvZ3JhbXN8fHt9OwogIGNvbnN0IGtleXMgPSBPYmplY3Qua2V5cyhyYXcpLnNvcnQoKGEsYik9PihwYXJzZUludChhLDEwKXx8MCktKHBhcnNlSW50KGIsMTApfHwwKSk7CiAgbGV0IGh0bWwgPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPlVuZG9jdW1lbnRlZCBwcm9ncmFtcyAocmF3IHBhc3N0aHJvdWdoKTwvaDI+IjsKICBpZigha2V5cy5sZW5ndGgpeyBodG1sICs9ICI8cCBjbGFzcz0nbXV0ZWQnPk5vbmUuPC9wPjwvZGl2PiI7ICQoIiN2aWV3LXJhdyIpLmlubmVySFRNTD1odG1sOyByZXR1cm47IH0KICBodG1sICs9ICI8cCBjbGFzcz0nbXV0ZWQnPlByb2dyYW1zIHdob3NlIGNvbHVtbiBsZWdlbmQgdGhlIGNhcHR1cmUgZGlkIG5vdCBwcm92ZS4gRXZlcnkgY2VsbCBrZWVwcyBpdHMgcmF3IE9JRCBzbyBhIGxhdGVyIGRlY29kZSBjYW4gYmUgYWRkZWQuPC9wPiI7CiAga2V5cy5mb3JFYWNoKHA9PnsKICAgIGNvbnN0IGIgPSByYXdbcF0sIHJvd0tleXMgPSBPYmplY3Qua2V5cyhiLnJvd3N8fHt9KTsKICAgIGh0bWwgKz0gIjxkZXRhaWxzPjxzdW1tYXJ5PlByb2dyYW0gIitlc2MocCkrIiAmbWRhc2g7ICIrZXNjKHZhbChiLm5hbWUpKSsiICgiK3Jvd0tleXMubGVuZ3RoKyIgcm93KHMpKTwvc3VtbWFyeT4iOwogICAgaHRtbCArPSAiPHRhYmxlPjx0aGVhZD48dHI+PHRoPlJvdzwvdGg+PHRoPkNvbHVtbjwvdGg+PHRoPlZhbHVlPC90aD48dGg+T0lEPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PiI7CiAgICByb3dLZXlzLmZvckVhY2gocms9PnsKICAgICAgY29uc3Qgcm93ID0gYi5yb3dzW3JrXTsKICAgICAgT2JqZWN0LmtleXMocm93KS5mb3JFYWNoKGNvbD0+ewogICAgICAgIGh0bWwgKz0gIjx0cj48dGQgY2xhc3M9J21vbm8nPiIrZXNjKHJrKSsiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKGNvbCkrIjwvdGQ+IisKICAgICAgICAgICI8dGQgY2xhc3M9J21vbm8nPiIrZXNjKHZhbChyb3dbY29sXS52YWx1ZSkpKyI8L3RkPjx0ZCBjbGFzcz0nbW9ubyBtdXRlZCc+Iitlc2Mocm93W2NvbF0ub2lkKSsiPC90ZD48L3RyPiI7CiAgICAgIH0pOwogICAgfSk7CiAgICBodG1sICs9ICI8L3Rib2R5PjwvdGFibGU+PC9kZXRhaWxzPiI7CiAgfSk7CiAgaHRtbCArPSAiPC9kaXY+IjsKICAkKCIjdmlldy1yYXciKS5pbm5lckhUTUwgPSBodG1sOwp9CgpmdW5jdGlvbiByZW5kZXJFeHBvcnQoZnJvbUZpbGUpewogIGxldCBodG1sID0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5CYWNrdXAgZXhwb3J0PC9oMj4iKwogICAgIjxwIGNsYXNzPSdtdXRlZCc+U2F2ZSBhIGZ1bGwgYmFja3VwIG9mIHRoaXMgcmVhZC4gWW91IGNob29zZSB3aGVyZSB0aGUgZmlsZXMgbGFuZCB2aWEgeW91ciBicm93c2VyJ3Mgc2F2ZSBkaWFsb2cuPC9wPiIrCiAgICAiPGRpdiBjbGFzcz0nZXhwLWJ0bnMnPiIrCiAgICAiPGJ1dHRvbiBjbGFzcz0nYnRuJyBpZD0nZXhwWmlwJz5Eb3dubG9hZCBmdWxsIGJhY2t1cCAoLnppcCk8L2J1dHRvbj4iKwogICAgIjxidXR0b24gY2xhc3M9J2J0biBnaG9zdCcgaWQ9J2V4cEpzb24nPkpTT04gb25seTwvYnV0dG9uPiIrCiAgICAiPGJ1dHRvbiBjbGFzcz0nYnRuIGdob3N0JyBpZD0nZXhwUmVwb3J0JyIrKFJFUE9SVD8iIjoiIGRpc2FibGVkIHRpdGxlPSdPcGVuIGEgbGl2ZSByZWFkIHRvIGdldCB0aGUgdGV4dCByZXBvcnQnIikrIj5SZXBvcnQgKC50eHQpPC9idXR0b24+IisKICAgICI8YnV0dG9uIGNsYXNzPSdidG4gZ2hvc3QnIGlkPSdleHBSYXcnIisoKERPQy5yYXdfb2lkX3dhbGspPyIiOiIgZGlzYWJsZWQgdGl0bGU9J1JhdyBPSUQgd2FsayBwcmVzZW50IG9ubHkgb24gYSBsaXZlIHJlYWQnIikrIj5SYXcgT0lEIHdhbGsgKC50eHQpPC9idXR0b24+IisKICAgICI8L2Rpdj48L2Rpdj4iOwogICQoIiN2aWV3LWV4cG9ydCIpLmlubmVySFRNTCA9IGh0bWw7CiAgJCgiI2V4cEpzb24iKS5vbmNsaWNrID0gKCk9PiBkb3dubG9hZChiYXNlTmFtZSgpKyIuanNvbiIsIEpTT04uc3RyaW5naWZ5KERPQyxudWxsLDIpLCAiYXBwbGljYXRpb24vanNvbiIpOwogICQoIiNleHBSZXBvcnQiKS5vbmNsaWNrID0gKCk9PiBSRVBPUlQgJiYgZG93bmxvYWQoYmFzZU5hbWUoKSsiLnR4dCIsIFJFUE9SVCwgInRleHQvcGxhaW4iKTsKICAkKCIjZXhwUmF3Iikub25jbGljayA9ICgpPT57CiAgICBpZighRE9DLnJhd19vaWRfd2FsaykgcmV0dXJuOwogICAgY29uc3QgdHh0ID0gRE9DLnJhd19vaWRfd2Fsay5tYXAoZT0+IGUub2lkKyIgPSAiK2UudmFsdWUpLmpvaW4oIlxuIikrIlxuIjsKICAgIGRvd25sb2FkKGJhc2VOYW1lKCkrIi1vaWR3YWxrLnR4dCIsIHR4dCwgInRleHQvcGxhaW4iKTsKICB9OwogICQoIiNleHBaaXAiKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICAgIGNvbnN0IGJ0biA9ICQoIiNleHBaaXAiKTsgYnRuLmRpc2FibGVkPXRydWU7IGNvbnN0IG9sZD1idG4udGV4dENvbnRlbnQ7IGJ0bi50ZXh0Q29udGVudD0iQnVpbGRpbmfigKYiOwogICAgdHJ5ewogICAgICBjb25zdCByID0gYXdhaXQgZmV0Y2goIi9hcGkvYmFja3VwIiwge21ldGhvZDoiUE9TVCIsIGhlYWRlcnM6eyJDb250ZW50LVR5cGUiOiJhcHBsaWNhdGlvbi9qc29uIn0sCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoe2RvYzpET0N9KX0pOwogICAgICBpZighci5vayl7IGNvbnN0IGogPSBhd2FpdCByLmpzb24oKS5jYXRjaCgoKT0+KHt9KSk7IHRocm93IG5ldyBFcnJvcihqLmVycm9yfHwoIkhUVFAgIityLnN0YXR1cykpOyB9CiAgICAgIGNvbnN0IGJsb2IgPSBhd2FpdCByLmJsb2IoKTsKICAgICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgY29uc3QgYSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImEiKTsgYS5ocmVmPXVybDsgYS5kb3dubG9hZD1iYXNlTmFtZSgpKyItYmFja3VwLnppcCI7CiAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7IGEuY2xpY2soKTsgYS5yZW1vdmUoKTsgVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpOwogICAgfWNhdGNoKGUpeyBhbGVydCgiQmFja3VwIGZhaWxlZDogIitlLm1lc3NhZ2UpOyB9CiAgICBmaW5hbGx5eyBidG4uZGlzYWJsZWQ9ZmFsc2U7IGJ0bi50ZXh0Q29udGVudD1vbGQ7IH0KICB9Owp9CmZ1bmN0aW9uIGJhc2VOYW1lKCl7CiAgY29uc3QgaXAgPSAoRE9DLmRldmljZSYmRE9DLmRldmljZS5pcCl8fCJjaXgiOwogIGNvbnN0IHdoZW4gPSAoKERPQy5kZXZpY2UmJkRPQy5kZXZpY2UucmVhZF9hdCl8fCIiKS5yZXBsYWNlKC9bOlRdL2csIi0iKS5zbGljZSgwLDE5KTsKICByZXR1cm4gInRvc2hpYmEtY2l4LSIrU3RyaW5nKGlwKS5yZXBsYWNlKC9bXlx3Ll0vZywiXyIpKyh3aGVuPyItIit3aGVuOiIiKTsKfQpmdW5jdGlvbiBkb3dubG9hZChuYW1lLCB0ZXh0LCB0eXBlKXsKICBjb25zdCBibG9iID0gbmV3IEJsb2IoW3RleHRdLCB7dHlwZX0pOyBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogIGNvbnN0IGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7IGEuaHJlZj11cmw7IGEuZG93bmxvYWQ9bmFtZTsKICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOyBhLmNsaWNrKCk7IGEucmVtb3ZlKCk7IFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKfQoKLyogLS0tLS0tLS0tLSBTdGF0aW9uIGRyYXdlciArIGVkaXQgLS0tLS0tLS0tLSAqLwpmdW5jdGlvbiBjbG9zZURyYXdlcigpeyAkKCIjZHJhd2VyIikuY2xhc3NMaXN0LnJlbW92ZSgic2hvdyIpOyAkKCIjb3ZlcmxheSIpLmNsYXNzTGlzdC5yZW1vdmUoInNob3ciKTsgfQokKCIjb3ZlcmxheSIpLm9uY2xpY2sgPSBjbG9zZURyYXdlcjsKCmZ1bmN0aW9uIG9wZW5TdGF0aW9uKHN0KXsKICBjb25zdCBkciA9ICQoIiNkcmF3ZXIiKTsKICBjb25zdCBlZGl0YWJsZSA9IHtleHRlbnNpb246IkV4dGVuc2lvbiIsIHR5cGU6IlR5cGUiLCBuYW1lOiJTdGF0aW9uIG5hbWUifTsKICBsZXQgaHRtbCA9ICI8YnV0dG9uIGNsYXNzPSdjbG9zZScgdGl0bGU9J0Nsb3NlJz4mdGltZXM7PC9idXR0b24+IjsKICBodG1sICs9ICI8aDM+RE4gIitlc2ModmFsKHN0LmRuKSkrIjwvaDM+PHAgY2xhc3M9J211dGVkJz5Qb3J0ICIrZXNjKGZtdFBvcnQoc3QuZXF1aXBtZW50X3BvcnQpKSsiPC9wPiI7CgogIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5FZGl0IHN0YXRpb248L2gyPiI7CiAgT2JqZWN0LmtleXMoZWRpdGFibGUpLmZvckVhY2goZj0+ewogICAgaHRtbCArPSAiPGRpdiBjbGFzcz0nZmllbGQtZWRpdCc+PGxhYmVsPiIrZXNjKGVkaXRhYmxlW2ZdKSsiPC9sYWJlbD4iKwogICAgICAiPGlucHV0IGRhdGEtZmllbGQ9JyIrZisiJyB2YWx1ZT0nIitlc2ModmFsKHN0W2ZdKSkrIic+PC9kaXY+IjsKICB9KTsKICBodG1sICs9ICI8ZGl2IGNsYXNzPSdmaWVsZC1lZGl0Jz48bGFiZWw+UG9ydDwvbGFiZWw+PGlucHV0IHZhbHVlPSciK2VzYyhmbXRQb3J0KHN0LmVxdWlwbWVudF9wb3J0KSkrCiAgICAgICAgICAiJyBkaXNhYmxlZCB0aXRsZT0ncGh5c2ljYWwgYXNzaWdubWVudCDigJQgcmVhZC1vbmx5Jz48L2Rpdj4iOwogIGh0bWwgKz0gIjxkaXYgY2xhc3M9J3Jvdycgc3R5bGU9J21hcmdpbi10b3A6NHB4Jz4iKwogICAgICAgICAgIjxidXR0b24gY2xhc3M9J2J0biBnaG9zdCcgaWQ9J3ByZXZpZXdTdGF0aW9uJz5QcmV2aWV3IGNoYW5nZXM8L2J1dHRvbj4iKwogICAgICAgICAgIjxidXR0b24gY2xhc3M9J2J0bicgaWQ9J3dyaXRlU3RhdGlvbic+Q29uZmlybSAmYW1wOyB3cml0ZTwvYnV0dG9uPjwvZGl2PiI7CiAgaHRtbCArPSAiPHAgY2xhc3M9J211dGVkJyBzdHlsZT0nbWFyZ2luOjhweCAwIDAnPlByZXZpZXcgc2hvd3MgdGhlIGV4YWN0IFNFVHMgd2l0aG91dCBzZW5kaW5nLiAiKwogICAgICAgICAgIkNvbmZpcm0gJmFtcDsgd3JpdGUgc2VuZHMgdGhlbSBvdmVyIFNOTVAgYW5kIHJlYWRzIHRoZSB2YWx1ZXMgYmFjayB0byB2ZXJpZnkuPC9wPiI7CiAgaHRtbCArPSAiPGRpdiBjbGFzcz0nbXNnJyBpZD0nc2F2ZU1zZyc+PC9kaXY+PC9kaXY+IjsKCiAgaWYoKHN0LmtleXN8fFtdKS5sZW5ndGgpewogICAgaHRtbCArPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPktleXMgLyBidXR0b25zICgiK3N0LmtleXMubGVuZ3RoKyIpPC9oMj48ZGl2IHN0eWxlPSdvdmVyZmxvdzphdXRvJz48dGFibGU+PHRoZWFkPjx0cj48dGg+S2V5PC90aD4iOwogICAgY29uc3Qga2NvbHMgPSBuZXcgU2V0KCk7IHN0LmtleXMuZm9yRWFjaChrPT5PYmplY3Qua2V5cyhrKS5mb3JFYWNoKGM9PnsgaWYoYyE9PSJrZXkiKSBrY29scy5hZGQoYyk7IH0pKTsKICAgIGNvbnN0IGtjID0gQXJyYXkuZnJvbShrY29scyk7CiAgICBodG1sICs9IGtjLm1hcChjPT4iPHRoPiIrZXNjKGMpKyI8L3RoPiIpLmpvaW4oIiIpKyI8L3RyPjwvdGhlYWQ+PHRib2R5PiI7CiAgICBzdC5rZXlzLmZvckVhY2goaz0+eyBodG1sICs9ICI8dHI+PHRkPiIrZXNjKGsua2V5KSsiPC90ZD4iK2tjLm1hcChjPT4iPHRkIGNsYXNzPSdtb25vJz4iK2VzYyh2YWwoa1tjXSkpKyI8L3RkPiIpLmpvaW4oIiIpKyI8L3RyPiI7IH0pOwogICAgaHRtbCArPSAiPC90Ym9keT48L3RhYmxlPjwvZGl2PjwvZGl2PiI7CiAgfQoKICBjb25zdCBwcm9ncyA9IHN0LnByb2dyYW1zfHx7fTsKICBjb25zdCBwayA9IE9iamVjdC5rZXlzKHByb2dzKTsKICBpZihway5sZW5ndGgpewogICAgaHRtbCArPSAiPGRpdiBjbGFzcz0nY2FyZCc+PGgyPlBlci1zdGF0aW9uIHByb2dyYW0gZGV0YWlsPC9oMj4iOwogICAgcGsuc29ydCgpLmZvckVhY2gocD0+ewogICAgICBjb25zdCByb3dzID0gcHJvZ3NbcF0ucm93c3x8e307CiAgICAgIGh0bWwgKz0gIjxkZXRhaWxzPjxzdW1tYXJ5PlByb2dyYW0gIitlc2MocCkrIiAmbWRhc2g7ICIrZXNjKHZhbChwcm9nc1twXS5uYW1lKSkrIjwvc3VtbWFyeT4iOwogICAgICBodG1sICs9ICI8dGFibGU+PHRoZWFkPjx0cj48dGg+Um93PC90aD48dGg+Q29sPC90aD48dGg+VmFsdWU8L3RoPjx0aD5PSUQ8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+IjsKICAgICAgT2JqZWN0LmtleXMocm93cykuZm9yRWFjaChyaz0+eyBjb25zdCByb3c9cm93c1tya107CiAgICAgICAgT2JqZWN0LmtleXMocm93KS5mb3JFYWNoKGM9PnsgaHRtbCArPSAiPHRyPjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2MocmspKyI8L3RkPjx0ZCBjbGFzcz0nbW9ubyc+Iitlc2MoYykrCiAgICAgICAgICAiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKHZhbChyb3dbY10udmFsdWUpKSsiPC90ZD48dGQgY2xhc3M9J21vbm8gbXV0ZWQnPiIrZXNjKHJvd1tjXS5vaWQpKyI8L3RkPjwvdHI+IjsgfSk7IH0pOwogICAgICBodG1sICs9ICI8L3Rib2R5PjwvdGFibGU+PC9kZXRhaWxzPiI7CiAgICB9KTsKICAgIGh0bWwgKz0gIjwvZGl2PiI7CiAgfQoKICBjb25zdCBzbyA9IHN0LnNvdXJjZV9vaWRzfHx7fTsKICBpZihPYmplY3Qua2V5cyhzbykubGVuZ3RoKXsKICAgIGh0bWwgKz0gIjxkaXYgY2xhc3M9J2NhcmQnPjxoMj5Tb3VyY2UgT0lEczwvaDI+PGRpdiBjbGFzcz0na3YnPiIrCiAgICAgIE9iamVjdC5rZXlzKHNvKS5tYXAoaz0+a3YoaywgIjxzcGFuIGNsYXNzPSdtb25vIG11dGVkJz4iK2VzYyhzb1trXSkrIjwvc3Bhbj4iKSkuam9pbigiIikrIjwvZGl2PjwvZGl2PiI7CiAgfQoKICBkci5pbm5lckhUTUwgPSBodG1sOwogIGRyLnF1ZXJ5U2VsZWN0b3IoIi5jbG9zZSIpLm9uY2xpY2sgPSBjbG9zZURyYXdlcjsKICBkci5jbGFzc0xpc3QuYWRkKCJzaG93Iik7ICQoIiNvdmVybGF5IikuY2xhc3NMaXN0LmFkZCgic2hvdyIpOwogICQoIiNwcmV2aWV3U3RhdGlvbiIpLm9uY2xpY2sgPSAoKT0+IGRvU2F2ZShzdCwgZHIsIGZhbHNlKTsKICAkKCIjd3JpdGVTdGF0aW9uIikub25jbGljayA9ICgpPT4gZG9TYXZlKHN0LCBkciwgdHJ1ZSk7Cn0KCmZ1bmN0aW9uIGNvbGxlY3RDaGFuZ2VzKHN0LCBkcil7CiAgY29uc3QgY2hhbmdlcyA9IHt9OwogICQkKCJpbnB1dFtkYXRhLWZpZWxkXSIsIGRyKS5mb3JFYWNoKGlucD0+ewogICAgY29uc3QgZiA9IGlucC5kYXRhc2V0LmZpZWxkLCBudiA9IGlucC52YWx1ZTsKICAgIGlmKFN0cmluZyh2YWwoc3RbZl0pKSAhPT0gbnYpIGNoYW5nZXNbZl0gPSBudjsKICB9KTsKICByZXR1cm4gY2hhbmdlczsKfQoKZnVuY3Rpb24gb3BzVGFibGUob3BzKXsKICByZXR1cm4gIjx0YWJsZSBzdHlsZT0nbWFyZ2luLXRvcDo2cHgnPjx0aGVhZD48dHI+PHRoPkZpZWxkPC90aD48dGg+T2xkPC90aD48dGg+TmV3PC90aD48dGg+VGFyZ2V0IE9JRDwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT4iKwogICAgb3BzLm1hcChvPT4iPHRyPjx0ZD4iK2VzYyhvLmZpZWxkKSsiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKHZhbChvLm9sZF92YWx1ZSkpKwogICAgICAiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKG8ubmV3X3ZhbHVlKSsiPC90ZD48dGQgY2xhc3M9J21vbm8gbXV0ZWQnPiIrZXNjKG8udGFyZ2V0X29pZHx8KG8ubm90ZXx8IuKAlCIpKSsiPC90ZD48L3RyPiIpLmpvaW4oIiIpKwogICAgIjwvdGJvZHk+PC90YWJsZT4iOwp9Cgphc3luYyBmdW5jdGlvbiBkb1NhdmUoc3QsIGRyLCBjb25maXJtKXsKICBjb25zdCBjaGFuZ2VzID0gY29sbGVjdENoYW5nZXMoc3QsIGRyKTsKICBjb25zdCBtc2cgPSAkKCIjc2F2ZU1zZyIsIGRyKTsKICBpZighT2JqZWN0LmtleXMoY2hhbmdlcykubGVuZ3RoKXsgc2hvd01zZyhtc2csImluZm8iLCJObyBmaWVsZHMgY2hhbmdlZC4iKTsgcmV0dXJuOyB9CgogIGlmKGNvbmZpcm0pewogICAgY29uc3Qgc3VtbWFyeSA9IE9iamVjdC5rZXlzKGNoYW5nZXMpLm1hcChmPT5mKyIg4oaSIFwiIitjaGFuZ2VzW2ZdKyJcIiIpLmpvaW4oIlxuIik7CiAgICBpZighd2luZG93LmNvbmZpcm0oIldyaXRlIHRoZXNlIGNoYW5nZXMgdG8gRE4gIit2YWwoc3QuZG4pKyIgb3ZlciBTTk1QP1xuXG4iK3N1bW1hcnkrCiAgICAgICAgIlxuXG5UaGUgdmFsdWVzIHdpbGwgYmUgcmVhZCBiYWNrIHRvIHZlcmlmeS4iKSkgcmV0dXJuOwogIH0KICBjb25zdCBib2R5ID0ge2lwOihET0MuZGV2aWNlfHx7fSkuaXAgfHwgJCgiI2lwIikudmFsdWUudHJpbSgpLAogICAgICAgICAgICAgICAgY29tbXVuaXR5OiAkKCIjY29tbXVuaXR5IikudmFsdWUudHJpbSgpIHx8ICJjb21tdW5pdHlOYW1lIiwKICAgICAgICAgICAgICAgIHBvcnQ6IHBhcnNlSW50KCQoIiNwb3J0IikudmFsdWUsMTApfHwxNjEsCiAgICAgICAgICAgICAgICBzdGF0aW9uOiBzdCwgY2hhbmdlcywgY29uZmlybX07CiAgc2hvd01zZyhtc2csImluZm8iLCc8c3BhbiBjbGFzcz0ic3Bpbm5lciI+PC9zcGFuPicrKGNvbmZpcm0/IldyaXRpbmcgYW5kIHZlcmlmeWluZ+KApiI6IkJ1aWxkaW5nIHByZXZpZXfigKYiKSk7CiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL3NhdmUiLCBib2R5KTsKICAgIGlmKCFjb25maXJtKXsKICAgICAgbGV0IGh0bWwgPSBlc2MocmVzLm1lc3NhZ2V8fCJQcmV2aWV3Iik7CiAgICAgIGlmKHJlcy5wbGFubmVkX29wcyAmJiByZXMucGxhbm5lZF9vcHMubGVuZ3RoKQogICAgICAgIGh0bWwgKz0gIjxkaXYgc3R5bGU9J21hcmdpbi10b3A6OHB4Jz5QbGFubmVkIFNFVCBvcGVyYXRpb25zICg8Yj5ub3Qgc2VudDwvYj4pOiIrb3BzVGFibGUocmVzLnBsYW5uZWRfb3BzKSsiPC9kaXY+IjsKICAgICAgc2hvd01zZyhtc2csImluZm8iLGh0bWwpOwogICAgICByZXR1cm47CiAgICB9CiAgICAvLyB3cml0ZSBwYXRoCiAgICBpZighcmVzLm9rICYmIHJlcy5lcnJvcil7CiAgICAgIGxldCBodG1sID0gIldyaXRlIGZhaWxlZDogIitlc2MocmVzLmVycm9yKTsKICAgICAgaWYocmVzLnBsYW5uZWRfb3BzKSBodG1sICs9ICI8ZGl2IHN0eWxlPSdtYXJnaW4tdG9wOjhweCc+IitvcHNUYWJsZShyZXMucGxhbm5lZF9vcHMpKyI8L2Rpdj4iOwogICAgICBzaG93TXNnKG1zZywiZXJyIixodG1sKTsKICAgICAgcmV0dXJuOwogICAgfQogICAgbGV0IGh0bWwgPSBlc2MocmVzLm1lc3NhZ2V8fCIiKTsKICAgIGNvbnN0IHIgPSByZXMucmVzdWx0fHx7fTsKICAgIGlmKHIucmVzdWx0cyAmJiByLnJlc3VsdHMubGVuZ3RoKXsKICAgICAgaHRtbCArPSAiPGRpdiBzdHlsZT0nbWFyZ2luLXRvcDo4cHgnPlJlYWQtYmFjayB2ZXJpZmljYXRpb246PHRhYmxlIHN0eWxlPSdtYXJnaW4tdG9wOjZweCc+IisKICAgICAgICAiPHRoZWFkPjx0cj48dGg+RmllbGQ8L3RoPjx0aD5SZXF1ZXN0ZWQ8L3RoPjx0aD5SZWFkIGJhY2s8L3RoPjx0aD5NYXRjaDwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT4iKwogICAgICAgIHIucmVzdWx0cy5tYXAoeD0+Ijx0cj48dGQ+Iitlc2MoeC5maWVsZCkrIjwvdGQ+PHRkIGNsYXNzPSdtb25vJz4iK2VzYyh4LnJlcXVlc3RlZCkrCiAgICAgICAgICAiPC90ZD48dGQgY2xhc3M9J21vbm8nPiIrZXNjKHZhbCh4LnJlYWRfYmFjaykpKyI8L3RkPjx0ZD4iKwogICAgICAgICAgKHgubWF0Y2g/IjxzcGFuIHN0eWxlPSdjb2xvcjp2YXIoLS1vayknPiYjMTAwMDM7PC9zcGFuPiI6IjxzcGFuIHN0eWxlPSdjb2xvcjp2YXIoLS1iYWQpJz4mIzEwMDA3Ozwvc3Bhbj4iKSsKICAgICAgICAgICI8L3RkPjwvdHI+Iikuam9pbigiIikrIjwvdGJvZHk+PC90YWJsZT48L2Rpdj4iOwogICAgfQogICAgc2hvd01zZyhtc2csIHJlcy5vaz8ib2siOiJlcnIiLCBodG1sKTsKICAgIC8vIHJlZmxlY3QgdGhlIHZlcmlmaWVkIHZhbHVlcyBpbiB0aGUgaW4tbWVtb3J5IGRvYyArIHRhYmxlCiAgICBpZihyZXMub2spewogICAgICBPYmplY3Qua2V5cyhjaGFuZ2VzKS5mb3JFYWNoKGY9Pnsgc3RbZl0gPSBjaGFuZ2VzW2ZdOyB9KTsKICAgICAgcmVuZGVyU3RhdGlvbnMoKTsKICAgIH0KICB9Y2F0Y2goZSl7IHNob3dNc2cobXNnLCJlcnIiLCJTYXZlIHJlcXVlc3QgZmFpbGVkOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQp9CgovKiAtLS0tLS0tLS0tIENhdGFsb2cgYmFja3VwIC8gdmlldyAvIGRpZmYgLyByZXN0b3JlIC0tLS0tLS0tLS0gKi8KY29uc3QgQksgPSB7QTpudWxsLCBCOm51bGx9OwpmdW5jdGlvbiBjYXRTaG93KHRleHQpeyBjb25zdCBlbD0kKCIjY2F0T3V0Iik7IGVsLnRleHRDb250ZW50PXRleHQ7IGVsLnN0eWxlLmRpc3BsYXk9ImJsb2NrIjsgZWwuc2Nyb2xsVG9wPTA7IH0KZnVuY3Rpb24gYmFja3VwTGFiZWwoYil7IGNvbnN0IG09Yi5tZXRhfHx7fTsKICByZXR1cm4gKG0uc2l0ZXx8bS5zb3VyY2VfaXB8fCJiYWNrdXAiKSsiIMK3ICIrKG0ucm93c19jb3VudHx8MCkrIiByb3dzIMK3ICIrU3RyaW5nKG0ucmVhZF9hdHx8IiIpLnNsaWNlKDAsMTkpOyB9CmZ1bmN0aW9uIGNhdEJhc2VOYW1lKGIpeyBjb25zdCBtPWIubWV0YXx8e307CiAgY29uc3Qgd2hvID0gU3RyaW5nKG0uc2l0ZXx8bS5zb3VyY2VfaXB8fCJjaXgiKS5yZXBsYWNlKC9bXlx3Li1dL2csIl8iKTsKICBjb25zdCB3aGVuID0gU3RyaW5nKG0ucmVhZF9hdHx8IiIpLnJlcGxhY2UoL1s6VF0vZywiLSIpLnNsaWNlKDAsMTkpOwogIHJldHVybiAidG9zaGliYS1jaXgtIit3aG8rKHdoZW4/Ii0iK3doZW46IiIpKyItY2F0YWxvZyI7IH0KZnVuY3Rpb24gcmVmcmVzaFNsb3RzKCl7CiAgJCgiI3Nsb3RBIikudGV4dENvbnRlbnQgPSAiQTogIisoQksuQT9iYWNrdXBMYWJlbChCSy5BKToiKGVtcHR5KSIpOwogICQoIiNzbG90QiIpLnRleHRDb250ZW50ID0gIkI6ICIrKEJLLkI/YmFja3VwTGFiZWwoQksuQik6IihlbXB0eSkiKTsKICAkKCIjYnRuQ2F0VmlldyIpLmRpc2FibGVkID0gIUJLLkE7CiAgJCgiI2J0bkNhdERvd25sb2FkIikuZGlzYWJsZWQgPSAhQksuQTsKICAkKCIjYnRuQ2F0UmVzdG9yZVByZXYiKS5kaXNhYmxlZCA9ICFCSy5BOwogICQoIiNidG5DYXRSZXN0b3JlR28iKS5kaXNhYmxlZCA9ICFCSy5BOwogICQoIiNidG5DYXREaWZmIikuZGlzYWJsZWQgPSAhKEJLLkEgJiYgQksuQik7Cn0KZnVuY3Rpb24gbG9hZEJhY2t1cEludG8oc2xvdCwgZmlsZSl7CiAgY29uc3QgZnIgPSBuZXcgRmlsZVJlYWRlcigpOwogIGZyLm9ubG9hZCA9ICgpPT57CiAgICB0cnl7CiAgICAgIGNvbnN0IGRvYyA9IEpTT04ucGFyc2UoZnIucmVzdWx0KTsKICAgICAgaWYoZG9jLmZvcm1hdCAhPT0gInRvc2hpYmEtY2l4LWJhY2t1cCIpIHRocm93IG5ldyBFcnJvcigibm90IGEgY2F0YWxvZyBiYWNrdXAgKGZvcm1hdCAhPSB0b3NoaWJhLWNpeC1iYWNrdXApIik7CiAgICAgIEJLW3Nsb3RdID0gZG9jOyByZWZyZXNoU2xvdHMoKTsKICAgICAgc2hvd01zZygkKCIjY2F0TXNnIiksIm9rIiwiTG9hZGVkIHNsb3QgIitzbG90KyI6ICIrZXNjKGJhY2t1cExhYmVsKGRvYykpKTsKICAgIH1jYXRjaChlKXsgc2hvd01zZygkKCIjY2F0TXNnIiksImVyciIsIkNvdWxkIG5vdCBsb2FkIGJhY2t1cDogIitlc2MoZS5tZXNzYWdlKSk7IH0KICB9OwogIGZyLnJlYWRBc1RleHQoZmlsZSk7Cn0KJCgiI2J0bk9wZW5BIikub25jbGljayA9ICgpPT4gJCgiI2NhdEZpbGVBIikuY2xpY2soKTsKJCgiI2J0bk9wZW5CIikub25jbGljayA9ICgpPT4gJCgiI2NhdEZpbGVCIikuY2xpY2soKTsKJCgiI2NhdEZpbGVBIikub25jaGFuZ2UgPSAoZXYpPT57IGNvbnN0IGY9ZXYudGFyZ2V0LmZpbGVzWzBdOyBpZihmKSBsb2FkQmFja3VwSW50bygiQSIsZik7IGV2LnRhcmdldC52YWx1ZT0iIjsgfTsKJCgiI2NhdEZpbGVCIikub25jaGFuZ2UgPSAoZXYpPT57IGNvbnN0IGY9ZXYudGFyZ2V0LmZpbGVzWzBdOyBpZihmKSBsb2FkQmFja3VwSW50bygiQiIsZik7IGV2LnRhcmdldC52YWx1ZT0iIjsgfTsKCiQoIiNidG5DYXRCYWNrdXAiKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICBjb25zdCBmID0gcmVhZEZvcm0oKTsKICBpZighZi5pcCl7IHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLCJFbnRlciB0aGUgQ0lYIElQIGFkZHJlc3MgYWJvdmUgZmlyc3QuIik7IHJldHVybjsgfQogIGNvbnN0IGJ0bj0kKCIjYnRuQ2F0QmFja3VwIik7IGJ0bi5kaXNhYmxlZD10cnVlOyBjb25zdCBvbGQ9YnRuLnRleHRDb250ZW50OyBidG4udGV4dENvbnRlbnQ9IlJlYWRpbmfigKYiOwogIHNob3dNc2coJCgiI2NhdE1zZyIpLCJpbmZvIiwnPHNwYW4gY2xhc3M9InNwaW5uZXIiPjwvc3Bhbj5GdWxsIGNhdGFsb2cgcmVhZCBvZiAnK2VzYyhmLmlwKSsnIChldmVyeSBwcm9ncmFtIOKAlCB0aGlzIGNhbiB0YWtlIGEgd2hpbGUpJmhlbGxpcDsnKTsKICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBhcGkoIi9hcGkvY2F0YWxvZy1iYWNrdXAiLCB7aXA6Zi5pcCwgY29tbXVuaXR5OmYuY29tbXVuaXR5LCBwb3J0OmYucG9ydH0pOwogICAgaWYoIXJlcy5vayl7IHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLCJCYWNrdXAgZmFpbGVkOiAiK2VzYyhyZXMuZXJyb3J8fCJ1bmtub3duIikpOyByZXR1cm47IH0KICAgIEJLLkEgPSByZXMuYmFja3VwOyByZWZyZXNoU2xvdHMoKTsKICAgIHNob3dNc2coJCgiI2NhdE1zZyIpLCJvayIsIkJhY2t1cCByZWFkIGludG8gc2xvdCBBOiAiK2VzYyhiYWNrdXBMYWJlbChyZXMuYmFja3VwKSkrIi4gRG93bmxvYWQgaXQgdG8ga2VlcCBpdC4iKTsKICAgIGNhdFNob3cocmVzLnJlcG9ydHx8IiIpOwogIH1jYXRjaChlKXsgc2hvd01zZygkKCIjY2F0TXNnIiksImVyciIsIlJlcXVlc3QgZmFpbGVkOiAiK2VzYyhlLm1lc3NhZ2UpKTsgfQogIGZpbmFsbHl7IGJ0bi5kaXNhYmxlZD1mYWxzZTsgYnRuLnRleHRDb250ZW50PW9sZDsgfQp9OwokKCIjYnRuQ2F0VmlldyIpLm9uY2xpY2sgPSBhc3luYyAoKT0+ewogIGlmKCFCSy5BKSByZXR1cm47CiAgdHJ5eyBjb25zdCByZXMgPSBhd2FpdCBhcGkoIi9hcGkvdmlldyIsIHtiYWNrdXA6QksuQX0pOwogICAgaWYocmVzLm9rKSBjYXRTaG93KHJlcy5yZXBvcnQpOyBlbHNlIHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLGVzYyhyZXMuZXJyb3J8fCJ2aWV3IGZhaWxlZCIpKTsKICB9Y2F0Y2goZSl7IHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLCJSZXF1ZXN0IGZhaWxlZDogIitlc2MoZS5tZXNzYWdlKSk7IH0KfTsKJCgiI2J0bkNhdERpZmYiKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICBpZighQksuQSB8fCAhQksuQikgcmV0dXJuOwogIHRyeXsgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL2RpZmYiLCB7YTpCSy5BLCBiOkJLLkJ9KTsKICAgIGlmKHJlcy5vaykgY2F0U2hvdyhyZXMucmVwb3J0KTsgZWxzZSBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIixlc2MocmVzLmVycm9yfHwiZGlmZiBmYWlsZWQiKSk7CiAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIiwiUmVxdWVzdCBmYWlsZWQ6ICIrZXNjKGUubWVzc2FnZSkpOyB9Cn07CiQoIiNidG5DYXREb3dubG9hZCIpLm9uY2xpY2sgPSAoKT0+IEJLLkEgJiYgZG93bmxvYWQoY2F0QmFzZU5hbWUoQksuQSkrIi5qc29uIiwgSlNPTi5zdHJpbmdpZnkoQksuQSxudWxsLDIpLCAiYXBwbGljYXRpb24vanNvbiIpOwoKZnVuY3Rpb24gcmVuZGVyUmVzdG9yZShyZXMpewogIGNvbnN0IHMgPSByZXMuc3VtbWFyeXx8e307CiAgbGV0IGh0bWwgPSBlc2MocmVzLm1lc3NhZ2V8fCIiKSsiPGJyPjxicj4iKwogICAgIjxiPlBsYW46PC9iPiAiKyhzLnNlbmRhYmxlfHwwKSsiIHNlbmRhYmxlLCAiKyhzLnNraXBwZWR8fDApKyIgc2tpcHBlZCAoIisocy5yZWFkX29ubHl8fDApKwogICAgIiByZWFkLW9ubHkpLCAiKyhzLnVucHJvdmVuX3dpcmVfdHlwZXx8MCkrIiB1bnByb3ZlbiB3aXJlLXR5cGUuIjsKICBpZihyZXMubW9kZT09PSJ3cml0ZSIgJiYgcmVzLnJlc3VsdHMpewogICAgY29uc3QgYmFkID0gcmVzLnJlc3VsdHMuZmlsdGVyKHI9PiFyLm1hdGNoKS5sZW5ndGg7CiAgICBodG1sICs9ICI8YnI+V3JvdGUgIisocmVzLndyb3RlfHwwKSsiLCB2ZXJpZmllZCAiKyhyZXMucmVzdWx0cy5sZW5ndGgtYmFkKSsiLyIrcmVzLnJlc3VsdHMubGVuZ3RoKyIuIjsKICB9CiAgc2hvd01zZygkKCIjY2F0TXNnIiksIHJlcy5vaz8ib2siOihyZXMubW9kZT09PSJ3cml0ZSI/ImVyciI6ImluZm8iKSwgaHRtbCk7CiAgY29uc3QgbGluZXMgPSBbcmVzLm1lc3NhZ2UsICIiXTsKICAocmVzLnBsYW5uZWRfb3BzfHxbXSkuZm9yRWFjaChvPT57CiAgICBsaW5lcy5wdXNoKChvLnNlbmRhYmxlPyJTRVQgIjoic2tpcCAiKSsoby50YXJnZXRfb2lkfHwiKG5vIG9pZCkiKSsiID0gIitKU09OLnN0cmluZ2lmeShvLm5ld192YWx1ZSkrCiAgICAgICIgIFsiK28uYmVyX3R5cGUrIl0gIitvLmZpZWxkX25hbWUrKG8ubm90ZT8oIiAg4oCUICIrby5ub3RlKToiIikpOwogIH0pOwogIGlmKHJlcy5yZXN1bHRzICYmIHJlcy5yZXN1bHRzLmxlbmd0aCl7CiAgICBsaW5lcy5wdXNoKCIiKTsgbGluZXMucHVzaCgiUmVhZC1iYWNrIHZlcmlmaWNhdGlvbjoiKTsKICAgIHJlcy5yZXN1bHRzLmZvckVhY2gocj0+IGxpbmVzLnB1c2goIiAgWyIrKHIubWF0Y2g/Im9rIjoiTUlTTUFUQ0giKSsiXSAiK3IuZmllbGQrIiA9ICIrSlNPTi5zdHJpbmdpZnkoci5yZWFkX2JhY2spKyIgKHdhbnRlZCAiK0pTT04uc3RyaW5naWZ5KHIucmVxdWVzdGVkKSsiKSIpKTsKICB9CiAgY2F0U2hvdyhsaW5lcy5qb2luKCJcbiIpKTsKfQokKCIjYnRuQ2F0UmVzdG9yZVByZXYiKS5vbmNsaWNrID0gYXN5bmMgKCk9PnsKICBpZighQksuQSkgcmV0dXJuOwogIHRyeXsgY29uc3QgcmVzID0gYXdhaXQgYXBpKCIvYXBpL3Jlc3RvcmUiLCB7YmFja3VwOkJLLkEsIGNvbmZpcm06ZmFsc2V9KTsKICAgIHJlbmRlclJlc3RvcmUocmVzKTsKICB9Y2F0Y2goZSl7IHNob3dNc2coJCgiI2NhdE1zZyIpLCJlcnIiLCJSZXF1ZXN0IGZhaWxlZDogIitlc2MoZS5tZXNzYWdlKSk7IH0KfTsKJCgiI2J0bkNhdFJlc3RvcmVHbyIpLm9uY2xpY2sgPSBhc3luYyAoKT0+ewogIGlmKCFCSy5BKSByZXR1cm47CiAgY29uc3QgZiA9IHJlYWRGb3JtKCk7CiAgaWYoIWYuaXApeyBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIiwiRW50ZXIgdGhlIHRhcmdldCBDSVggSVAgYWRkcmVzcyBhYm92ZSBmaXJzdC4iKTsgcmV0dXJuOyB9CiAgaWYoIXdpbmRvdy5jb25maXJtKCJSZXN0b3JlIGJhY2t1cCBBIHRvICIrZi5pcCsiIG92ZXIgU05NUD9cblxuVGhpcyB3cml0ZXMgZXZlcnkgd3JpdGFibGUgZmllbGQgYmFjayB0byB0aGUgbGl2ZSBDSVggKGFwcGxpZWQgdG8gUkFNOyAiKwogICAgInBlcnNpc3RlbmNlIGFjcm9zcyByZWJvb3QgaXMgdW5wcm92ZW4pIGFuZCByZWFkcyBlYWNoIG9uZSBiYWNrIHRvIHZlcmlmeS4gUmVhZC1vbmx5IGZpZWxkcyBhcmUgbm90IHRvdWNoZWQuIikpIHJldHVybjsKICBjb25zdCBidG49JCgiI2J0bkNhdFJlc3RvcmVHbyIpOyBidG4uZGlzYWJsZWQ9dHJ1ZTsgY29uc3Qgb2xkPWJ0bi50ZXh0Q29udGVudDsgYnRuLnRleHRDb250ZW50PSJSZXN0b3JpbmfigKYiOwogIHNob3dNc2coJCgiI2NhdE1zZyIpLCJpbmZvIiwnPHNwYW4gY2xhc3M9InNwaW5uZXIiPjwvc3Bhbj5SZXN0b3JpbmcgdG8gJytlc2MoZi5pcCkrJyBhbmQgdmVyaWZ5aW5nJmhlbGxpcDsnKTsKICB0cnl7IGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgiL2FwaS9yZXN0b3JlIiwge2lwOmYuaXAsIGNvbW11bml0eTpmLmNvbW11bml0eSwgcG9ydDpmLnBvcnQsIGJhY2t1cDpCSy5BLCBjb25maXJtOnRydWV9KTsKICAgIGlmKCFyZXMub2sgJiYgcmVzLmVycm9yKXsgc2hvd01zZygkKCIjY2F0TXNnIiksImVyciIsIlJlc3RvcmUgZmFpbGVkOiAiK2VzYyhyZXMuZXJyb3IpKTsgcmV0dXJuOyB9CiAgICByZW5kZXJSZXN0b3JlKHJlcyk7CiAgfWNhdGNoKGUpeyBzaG93TXNnKCQoIiNjYXRNc2ciKSwiZXJyIiwiUmVxdWVzdCBmYWlsZWQ6ICIrZXNjKGUubWVzc2FnZSkpOyB9CiAgZmluYWxseXsgYnRuLmRpc2FibGVkPWZhbHNlOyBidG4udGV4dENvbnRlbnQ9b2xkOyByZWZyZXNoU2xvdHMoKTsgfQp9OwoKLyogYm9vdCAqLwooYXN5bmMgKCk9PnsgdHJ5eyBjb25zdCBjID0gYXdhaXQgYXBpKCIvYXBpL2NhdGFsb2ciKTsKICBpZihjJiZjLm9rKSAkKCIjY2F0SW5mbyIpLnRleHRDb250ZW50ID0gYy5wcm9ncmFtcysiIHByb2dyYW1zLCAiK2MuZmllbGRzKyIgZmllbGRzLCAiK2Mud3JpdGFibGUrIiB3cml0YWJsZSDCtyBjYXRhbG9nICIrYy5jYXRhbG9nX3ZlcnNpb247Cn1jYXRjaChlKXt9IH0pKCk7Cihhc3luYyAoKT0+eyB0cnl7IGNvbnN0IGggPSBhd2FpdCBhcGkoIi9hcGkvaGVhbHRoIik7CiAgaWYoaCYmaC52ZXJzaW9uKSBkb2N1bWVudC50aXRsZSA9ICJUb3NoaWJhIENJWCBNYW5hZ2VyICIraC52ZXJzaW9uOwogIGNvbnN0IGIgPSAkKCIjbW9kZUJhZGdlIik7CiAgaWYoaCAmJiBoLndyaXRlc19lbmFibGVkKXsgYi50ZXh0Q29udGVudCA9ICJXUklURVM6IENPTkZJUk0tR0FURUQiOyB9CiAgZWxzZSB7IGIudGV4dENvbnRlbnQgPSAiUkVBRC1PTkxZIjsgfQp9Y2F0Y2goZSl7fSB9KSgpOwoKLyogLS0tLS0tLS0tLSBTZWxmLXVwZGF0ZSAtLS0tLS0tLS0tICovCmxldCBVUEQgPSBudWxsOyAgIC8vIGxhc3QgL2FwaS91cGRhdGUgY2hlY2sgcmVzdWx0CmZ1bmN0aW9uIHJlbmRlclVwZGF0ZShpbmZvKXsKICBVUEQgPSBpbmZvOwogIGNvbnN0IG1zZyA9ICQoIiN1cGRNc2ciKSwgYXBwbHkgPSAkKCIjYnRuVXBkQXBwbHkiKTsKICBhcHBseS5jbGFzc0xpc3QuYWRkKCJoaWRlIik7CiAgaWYoIWluZm8gfHwgIWluZm8ub2speyBtc2cudGV4dENvbnRlbnQgPSBpbmZvICYmIGluZm8uZXJyb3IgPyAidXBkYXRlIGNoZWNrIGZhaWxlZCIgOiAiIjsgcmV0dXJuOyB9CiAgaWYoaW5mby5uZXdlcil7CiAgICBtc2cuaW5uZXJIVE1MID0gJzxiPnYnK2VzYyhpbmZvLmxhdGVzdCkrJyBhdmFpbGFibGU8L2I+ICh5b3UgaGF2ZSAnK2VzYyhpbmZvLmN1cnJlbnQpKycpJzsKICAgIGlmKGluZm8ucmVwbGFjZWFibGUgJiYgaW5mby5hc3NldF91cmwpeyBhcHBseS5jbGFzc0xpc3QucmVtb3ZlKCJoaWRlIik7IH0KICAgIGVsc2UgeyBtc2cuaW5uZXJIVE1MICs9ICcgJm1kYXNoOyA8YSBocmVmPSInK2VzYyhpbmZvLmh0bWxfdXJsKSsnIiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciI+Z2V0IGl0PC9hPic7IH0KICB9IGVsc2UgewogICAgbXNnLnRleHRDb250ZW50ID0gIlVwIHRvIGRhdGUgKHYiK2VzYyhpbmZvLmN1cnJlbnQpKyIpIjsKICB9Cn0KJCgiI2J0blVwZENoZWNrIikub25jbGljayA9IGFzeW5jICgpPT57CiAgY29uc3QgYnRuPSQoIiNidG5VcGRDaGVjayIpOyBidG4uZGlzYWJsZWQ9dHJ1ZTsgY29uc3Qgb2xkPWJ0bi50ZXh0Q29udGVudDsgYnRuLnRleHRDb250ZW50PSJDaGVja2luZ+KApiI7CiAgdHJ5eyByZW5kZXJVcGRhdGUoYXdhaXQgYXBpKCIvYXBpL3VwZGF0ZSIpKTsgfQogIGNhdGNoKGUpeyAkKCIjdXBkTXNnIikudGV4dENvbnRlbnQgPSAidXBkYXRlIGNoZWNrIGZhaWxlZCI7IH0KICBmaW5hbGx5eyBidG4uZGlzYWJsZWQ9ZmFsc2U7IGJ0bi50ZXh0Q29udGVudD1vbGQ7IH0KfTsKJCgiI2J0blVwZEFwcGx5Iikub25jbGljayA9IGFzeW5jICgpPT57CiAgaWYoIVVQRCB8fCAhVVBELm5ld2VyKSByZXR1cm47CiAgaWYoIWNvbmZpcm0oIkRvd25sb2FkIHYiK1VQRC5sYXRlc3QrIiBhbmQgcmVwbGFjZSB0aGlzIGFwcGxpY2F0aW9uPyBJdCB3aWxsIHJlc3RhcnQgYWZ0ZXJ3YXJkcy4iKSkgcmV0dXJuOwogIGNvbnN0IGJ0bj0kKCIjYnRuVXBkQXBwbHkiKTsgYnRuLmRpc2FibGVkPXRydWU7IGNvbnN0IG9sZD1idG4udGV4dENvbnRlbnQ7IGJ0bi50ZXh0Q29udGVudD0iVXBkYXRpbmfigKYiOwogICQoIiN1cGRNc2ciKS5pbm5lckhUTUwgPSAnPHNwYW4gY2xhc3M9InNwaW5uZXIiPjwvc3Bhbj5Eb3dubG9hZGluZyB2Jytlc2MoVVBELmxhdGVzdCkrJyZoZWxsaXA7JzsKICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBhcGkoIi9hcGkvdXBkYXRlIiwge2NvbmZpcm06dHJ1ZX0pOwogICAgaWYocmVzICYmIHJlcy5vayl7ICQoIiN1cGRNc2ciKS5pbm5lckhUTUwgPSAnPGI+Jytlc2MocmVzLm1lc3NhZ2V8fCJVcGRhdGVkLiIpKyc8L2I+JzsgYnRuLmNsYXNzTGlzdC5hZGQoImhpZGUiKTsgfQogICAgZWxzZSB7ICQoIiN1cGRNc2ciKS50ZXh0Q29udGVudCA9ICJVcGRhdGUgZmFpbGVkOiAiK2VzYygocmVzJiYocmVzLm1lc3NhZ2V8fHJlcy5lcnJvcikpfHwidW5rbm93biBlcnJvciIpOyB9CiAgfWNhdGNoKGUpeyAkKCIjdXBkTXNnIikudGV4dENvbnRlbnQgPSAiVXBkYXRlIGZhaWxlZDogIitlc2MoZS5tZXNzYWdlKTsgfQogIGZpbmFsbHl7IGJ0bi5kaXNhYmxlZD1mYWxzZTsgYnRuLnRleHRDb250ZW50PW9sZDsgfQp9OwovKiBub24tYmxvY2tpbmcgY2hlY2sgb24gbGF1bmNoIOKAlCBzdXJmYWNlcyBhbiBhdmFpbGFibGUgdXBkYXRlLCBuZXZlciBpbnN0YWxscyAqLwooYXN5bmMgKCk9PnsgdHJ5eyByZW5kZXJVcGRhdGUoYXdhaXQgYXBpKCIvYXBpL3VwZGF0ZSIpKTsgfWNhdGNoKGUpe30gfSkoKTsKPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo=").decode("utf-8")  # bundled UI

if __name__ == "__main__":
    _argv = sys.argv[1:]
    if _argv and _argv[0] == "read":
        raise SystemExit(reader_cli_main(_argv[1:]))
    if _argv and _argv[0] in ("serve", "web"):
        _argv = _argv[1:]
    raise SystemExit(main(_argv))  # webapp.main — serves the UI
