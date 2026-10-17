#!/usr/bin/env python3
"""Toshiba Strata CIX SNMP reader — standalone (generated).

Generated from the toshiba_cix package by build_standalone.py.
Pure stdlib; runs unchanged on a bare Python 3 (Pi / laptop).
Edit the package, not this file.
"""
from __future__ import annotations
import argparse, json, logging, socket, sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
__version__ = "2.2.1"

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
import time
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
                  max_total: int = 500000, deadline: float | None = None,
                  status: dict | None = None):
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

        ``max_total`` caps how many OIDs this walk collects and ``deadline``
        (a :func:`time.monotonic` instant) caps how long it runs; either one
        stops the walk early and returns whatever was collected so far. They
        bound a huge or non-terminating subtree so one bad branch cannot stall
        the walk forever. When ``status`` is a dict it is filled with
        ``{"stopped": "end"|"cap"|"deadline", "oids": N, "rounds": N}`` so a
        per-program caller can tell a clean finish from a truncation.

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
        rounds = 0
        cap = max(1, width)
        stopped = "end"
        while True:
            if total >= max_total:
                stopped = "cap"
                break
            if deadline is not None and time.monotonic() >= deadline:
                stopped = "deadline"
                break
            active = [c for c in cursors if not c["done"]]
            if not active:
                stopped = "end"
                break
            batch = active[:cap]
            rounds += 1
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
        if status is not None:
            status["stopped"] = stopped
            status["oids"] = total
            status["rounds"] = rounds
        return results

    def walk(self, root: str, *, max_oids: int = 20000,
             deadline: float | None = None):
        """Yield (oid, Value) for every instance lexically under ``root``.

        Single-varbind GETNEXT loop — the simple, complete, order-preserving
        walk. Stops at end-of-MIB, on the first OID that leaves ``root``, after
        ``max_oids`` (a guard against a misbehaving agent that loops), or once
        the optional ``deadline`` (a :func:`time.monotonic` instant) passes.
        """
        root = root.strip(".")
        prefix = root + "."
        current = root
        seen = 0
        while seen < max_oids:
            if deadline is not None and time.monotonic() >= deadline:
                return
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
import time
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
                 catalog=None, max_seconds: float | None = None):
        self.client = client
        self.log = logger or logging.getLogger(__name__)
        # Optional wall-clock budget for the whole walk: a guard so a huge or
        # non-terminating subtree (``--scope all`` against a big CIX) cannot run
        # forever. ``None`` = unbounded (the default; behaviour unchanged).
        self.max_seconds = max_seconds
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
    def _deadline(self) -> float | None:
        """A :func:`time.monotonic` instant to stop the walk, or ``None``."""
        return (time.monotonic() + self.max_seconds) if self.max_seconds else None

    def _collect(self) -> tuple[list[tuple[str, Value]], str | None]:
        deadline = self._deadline()
        preset = self._preset_roots()
        if preset is not None:
            return self._collect_roots(preset, deadline)
        if self.strategy == "serial":
            return self._collect_serial(deadline)
        try:
            return self._collect_bulk(deadline)
        except SnmpError as exc:
            # The batched path needs several round trips to enumerate before
            # it reads anything; if the device is flaky, fall back to the
            # dead-simple serial walk rather than returning nothing.
            self.log.warning("bulk collect failed (%s); falling back to serial",
                             exc)
            return self._collect_serial(deadline)

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

    def _collect_roots(self, roots: list[str], deadline: float | None = None
                       ) -> tuple[list[tuple[str, Value]], str | None]:
        """Walk an explicit list of subtree roots (catalog-driven scopes).

        Bulk when possible (many cursors), with a serial fallback so a flaky
        device degrades to a partial read rather than nothing."""
        if self.strategy != "serial":
            try:
                pairs = self.client.bulk_walk(roots, width=self.width,
                                              max_total=self.max_oids,
                                              deadline=deadline)
                return self._dedup(pairs), None
            except SnmpError as exc:
                self.log.warning("bulk scope walk failed (%s); serial fallback",
                                 exc)
        out: list[tuple[str, Value]] = []
        error: str | None = None
        for root in roots:
            try:
                out.extend(self.client.walk(root, max_oids=self.max_oids,
                                            deadline=deadline))
            except SnmpError as exc:
                self.log.warning("root %s interrupted: %s", root, exc)
                error = str(exc)
        return self._dedup(out), error

    def _collect_serial(self, deadline: float | None = None
                        ) -> tuple[list[tuple[str, Value]], str | None]:
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
                out.extend(self.client.walk(root, max_oids=self.max_oids,
                                            deadline=deadline))
            except SnmpError as exc:
                self.log.warning("branch %s interrupted: %s", root, exc)
                error = str(exc)
        return self._dedup(out), error

    def _collect_bulk(self, deadline: float | None = None
                      ) -> tuple[list[tuple[str, Value]], str | None]:
        """Enumerate program/column roots, then walk them all in parallel.

        Splitting each big table by column gives the batched walk many
        independent cursors. Enumeration itself is cheap (one round trip per
        discovered node)."""
        roots = self._discover_roots()
        pairs = self.client.bulk_walk(roots, width=self.width,
                                      max_total=self.max_oids,
                                      deadline=deadline)
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

if __name__ == "__main__":
    raise SystemExit(main())
