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

from __future__ import annotations

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
