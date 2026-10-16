"""Toshiba Stratagy LVMU serial admin protocol — framing + read-only link.

Lifted from the byte-verified ``stratagy_lvmu.py`` reverse-engineering
prototype (``toshiba-voicemail/STRATAGY_LVMU_SERIAL_PROTOCOL.md``): the frame
layer, opcode table and encoders are reproduced here **unchanged in behaviour**
(the same checksum rule, the same byte-exact login/ACK frames the prototype's
tests assert). On top of them this module adds:

* :class:`VMLink` — a single-threaded, **read-only** session driver over a
  :class:`~toshiba_cix.vm_serial.Transport`: banner wait → login → session
  preamble → file/record/directory reads, with a frame trace ring. It issues
  **no** write/commit opcodes; the write path is P3 and gated elsewhere.
* :class:`FakeLVMU` — an in-process protocol twin (the serial side's analogue
  of the SNMP fake agent). It replays a *card image* frame-for-frame: the AT
  softmodem banner, idle polls, the ``VALID`` login result, file reads
  (``INSTALL.CFG`` / ``<pbx>.PBX``), the box directory and 741-byte mailbox
  records — so every read screen and its tests run offline with no hardware and
  no customer capture committed to the repo.

Status markers (DESIGN_PLAN §1.2 rule 7 — "say what is unproven"): the frame
layer, login, file read, directory and the mailbox box-number/extension/
security-code decode are **confirmed** by capture. Record *flag*-field offsets
and the write header are **inferred/unknown** and live in ``vm_records.py`` with
their own labels; nothing in this module relies on them.
"""

from __future__ import annotations

import collections
import re
import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

from .vm_serial import Transport

# --------------------------------------------------------------------------
# Framing primitives (byte-identical rule to the RE prototype)
# --------------------------------------------------------------------------
SOH = 0x01

T_POLL = 0x02            # C/H idle poll / keepalive  : 01 02 00 fd
T_LOGIN = 0x03           # H   login (payload = pw + NUL)
T_LOGIN_RESULT = 0x04    # C   login result ('VALID')
T_DATA_CARD = 0x08       # C   reply to a 0x0c request (echoes opcode + seq)
T_BLOCK_START = 0x09     # C   start-of-stream preview
T_CHUNK_SHORT = 0x0a     # C/H short / final content chunk
T_ACK_RDY = 0x0b         # H   "ready for data" ACK during streaming
T_REQ_HOST = 0x0c        # H   request / write (opcode, rlen, 00, seq, [val])
T_CARD_SMALL = 0x0d      # C   small control frame (role unconfirmed)
T_ACK_HOST = 0x10        # H   continue/ACK token (01 10 00 ef)
T_ACK_CARD = 0x11        # C   continue/ACK token (01 11 00 ee)
T_CHUNK_14 = 0x14        # C/H content chunk (first full chunk of a block)
T_CHUNK_15 = 0x15        # C/H content chunk
T_CHUNK_16 = 0x16        # C   content chunk
T_CHUNK_17 = 0x17        # C   content chunk

CONTENT_TYPES = {T_BLOCK_START, T_CHUNK_SHORT, T_CHUNK_14, T_CHUNK_15,
                 T_CHUNK_16, T_CHUNK_17}
ACK_TYPES = {T_ACK_HOST, T_ACK_CARD, T_POLL, T_ACK_RDY}

# Request opcodes (confirmed unless noted; see STRATAGY_LVMU_SERIAL_PROTOCOL.md).
OP_SESSION_LOGREC = 0x10   # session record (log name, pw, admin box 997)
OP_GET_TS_12 = 0x12        # 4-byte unix-time handle               INFERRED
OP_GET_TS_13 = 0x13        # 4-byte unix-time handle               INFERRED
OP_GET_VERSION = 0x14      # firmware/version banner string
OP_READ_REC_A = 0x20       # read mailbox record part A
OP_READ_REC_B = 0x21       # read mailbox record part B
OP_SEEK = 0x22             # seek/rewind enumeration (00 00)       INFERRED
OP_SEL_MBOX = 0x42         # select mailbox properties record (MboxPps.cpp)
OP_SEL_UAGENT = 0x43       # select user-agent record (UserAgent.cpp)
OP_RECSEL_4E = 0x4e        # fast-directory record selector        INFERRED
OP_READ_SLOT = 0x60        # read indexed greeting/msg slot 0..9
OP_DIR_GLOB = 0x64         # open directory glob                   INFERRED
OP_OPEN_FILE = 0x92        # open named file; reply = LE32 length
OP_READ_BLOCK = 0x93       # read next block of open file

CLASS_MBOX = b".\\MboxPps.cpp"
CLASS_UAGENT = b".\\UserAgent.cpp"

BLOCK_HEADER = b"\x93\x04\x04"  # 4-byte prefix on a block's first content chunk


def checksum(frame_wo_cksum: bytes) -> int:
    """Trailing checksum byte: the whole frame sums to 0 mod 256."""
    return (-sum(frame_wo_cksum)) & 0xFF


def build_frame(ftype: int, payload: bytes = b"") -> bytes:
    if len(payload) > 0xFF:
        raise ValueError("payload too long for 1-byte length field")
    body = bytes([SOH, ftype & 0xFF, len(payload)]) + payload
    return body + bytes([checksum(body)])


def frame_ok(frame: bytes) -> bool:
    return len(frame) >= 4 and frame[0] == SOH and (sum(frame) & 0xFF) == 0


@dataclass
class Frame:
    ftype: int
    length: int
    payload: bytes
    raw: bytes
    cksum_ok: bool

    @property
    def opcode(self) -> Optional[int]:
        if self.ftype in (T_REQ_HOST, T_DATA_CARD) and len(self.payload) >= 1:
            return self.payload[0]
        return None

    @property
    def seq(self) -> Optional[int]:
        if self.ftype in (T_REQ_HOST, T_DATA_CARD) and len(self.payload) >= 4:
            return self.payload[3]
        return None

    @property
    def value(self) -> bytes:
        if self.ftype in (T_REQ_HOST, T_DATA_CARD) and len(self.payload) >= 4:
            return self.payload[4:]
        return b""


@dataclass
class Raw:
    data: bytes  # unframed bytes (AT modem strings, stray noise)


def iter_frames(stream: bytes) -> Iterator[object]:
    """Walk a one-directional byte stream, yielding Frame and Raw objects."""
    i, n = 0, len(stream)
    while i < n:
        if stream[i] == SOH and i + 3 <= n:
            ln = stream[i + 2]
            total = 3 + ln + 1
            if i + total <= n:
                raw = stream[i:i + total]
                if frame_ok(raw):
                    yield Frame(raw[1], ln, raw[3:3 + ln], raw, True)
                    i += total
                    continue
        j = stream.find(SOH, i + 1)
        if j == -1:
            j = n
        yield Raw(stream[i:j])
        i = j


_LOGLINE = re.compile(
    rb'^\[\s*([0-9.]+)s\]\s+(APP->CARD|CARD->APP)\s+(\d+)B\s+([0-9a-fA-F ]+?)\s+\|')


def streams_from_log(log_path: str) -> Tuple[bytes, bytes]:
    """Reconstruct ``(host->card, card->host)`` byte streams from a tap .log."""
    app = bytearray()
    card = bytearray()
    with open(log_path, "rb") as f:
        for line in f:
            m = _LOGLINE.match(line)
            if not m:
                continue
            chunk = bytes(int(h, 16) for h in m.group(4).split())
            (app if m.group(2) == b"APP->CARD" else card).extend(chunk)
    return bytes(app), bytes(card)


def reassemble_content(card_stream: bytes) -> bytes:
    """Concatenate the ASCII content carried in card->host content frames."""
    out = bytearray()
    for item in iter_frames(card_stream):
        if isinstance(item, Frame) and item.ftype in CONTENT_TYPES:
            data = item.payload
            if len(data) >= 4 and data[0:3] == BLOCK_HEADER:
                data = data[4:]
            out += data
    return out


# --------------------------------------------------------------------------
# Encoders (the confirmed, byte-exact read-path shapes)
# --------------------------------------------------------------------------
def build_login(password: str = "Stratagy") -> bytes:
    """Host login frame: 01 03 <len> <password> 00 <ck>."""
    return build_frame(T_LOGIN, password.encode("ascii") + b"\x00")


def build_ack_host() -> bytes:
    return build_frame(T_ACK_HOST)            # 01 10 00 ef


def build_get(opcode: int, seq: int, value: bytes = b"") -> bytes:
    """Host request frame (type 0x0c): payload = <op> <rlen> 00 <seq8> [val]."""
    rlen = 4 + len(value)
    payload = bytes([opcode & 0xFF, rlen & 0xFF, 0, seq & 0xFF]) + value
    return build_frame(T_REQ_HOST, payload)


def build_open_file(seq: int, path: str) -> bytes:
    return build_get(OP_OPEN_FILE, seq, path.encode("ascii") + b"\x00")


def build_read_block(seq: int) -> bytes:
    return build_get(OP_READ_BLOCK, seq)


def box_le32(box) -> bytes:
    return struct.pack("<I", int(box))


def encode_block(data: bytes, seq: int = 0) -> bytes:
    """Encode ``data`` as a card content block: a first chunk carrying the
    4-byte ``93 04 04 <seq>`` header, then 250-byte chunks, then a 0x0a tail.

    The inverse of :func:`reassemble_content` — the shape the LVMU streams a
    file/record back in. Used by :class:`FakeLVMU` and the capture-parse test."""
    out = bytearray()
    chunk = 250
    first = True
    i, n = 0, len(data)
    if n == 0:
        return bytes(build_frame(T_CHUNK_SHORT, b""))
    while i < n:
        piece = data[i:i + (chunk - 4 if first else chunk)]
        i += len(piece)
        last = i >= n
        if first:
            payload = BLOCK_HEADER + bytes([seq & 0xFF]) + piece
            ftype = T_CHUNK_SHORT if last else T_CHUNK_14
            first = False
        else:
            payload = piece
            ftype = T_CHUNK_SHORT if last else T_CHUNK_15
        out += build_frame(ftype, payload)
    return bytes(out)


# --------------------------------------------------------------------------
# Read-only link driver
# --------------------------------------------------------------------------
class VMLinkError(RuntimeError):
    pass


class VMLink:
    """A read-only Stratagy session over a byte transport.

    Owns one port; half-duplex. Every read method issues confirmed opcodes only
    and ACK-paces streamed content. No frame this class emits mutates the card.
    """

    def __init__(self, transport: Transport, password: str = "Stratagy",
                 trace_limit: int = 4000):
        self._t = transport
        self._password = password
        self._seq = 0
        self._rbuf = bytearray()
        self.trace: "collections.deque" = collections.deque(maxlen=trace_limit)
        self.firmware: str = ""
        self.admin_box: str = ""
        self.log_name: str = ""
        self.connected = False

    # -- low level --------------------------------------------------------
    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFF
        return self._seq

    def _write(self, frame: bytes) -> None:
        self.trace.append(("TX", frame.hex()))
        self._t.write(frame)

    def _read_frame(self, timeout: float = 2.0):
        """Return the next Frame/Raw from the transport, or None on timeout."""
        while True:
            parsed, consumed = _first_unit(self._rbuf)
            if parsed is not None:
                del self._rbuf[:consumed]
                if isinstance(parsed, Frame):
                    self.trace.append(("RX", parsed.raw.hex()))
                return parsed
            chunk = self._t.read(512, timeout=timeout)
            if not chunk:
                # flush any trailing raw bytes as a Raw unit
                if self._rbuf:
                    data = bytes(self._rbuf)
                    self._rbuf.clear()
                    return Raw(data)
                return None
            self._rbuf += chunk

    def _request(self, opcode: int, value: bytes = b"", timeout: float = 3.0) -> Frame:
        """Send a 0x0c request and return the card's 0x08 reply frame."""
        seq = self._next_seq()
        self._write(build_get(opcode, seq, value))
        deadline_reads = 40
        for _ in range(deadline_reads):
            fr = self._read_frame(timeout)
            if fr is None:
                break
            if isinstance(fr, Frame) and fr.ftype == T_DATA_CARD:
                return fr
            if isinstance(fr, Frame) and fr.ftype == T_ACK_CARD:
                continue
        raise VMLinkError(f"no reply to opcode 0x{opcode:02x}")

    def _read_stream(self, expected_len: int, timeout: float = 3.0) -> bytes:
        """Collect streamed content frames until ``expected_len`` bytes arrive."""
        out = bytearray()
        guard = 0
        while len(out) < expected_len and guard < 10000:
            guard += 1
            fr = self._read_frame(timeout)
            if fr is None:
                break
            if isinstance(fr, Frame) and fr.ftype in CONTENT_TYPES:
                data = fr.payload
                if len(data) >= 4 and data[0:3] == BLOCK_HEADER:
                    data = data[4:]
                out += data
                self._write(build_ack_host())   # per-chunk continue token
            # ACK/poll frames are absorbed
        return bytes(out[:expected_len]) if expected_len else bytes(out)

    # -- session ----------------------------------------------------------
    def wait_banner(self, timeout: float = 12.0) -> bool:
        """Read until the softmodem AT banner or an idle poll proves the card
        is alive at this baud. Returns True on success."""
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            fr = self._read_frame(timeout=1.0)
            if fr is None:
                continue
            if isinstance(fr, Raw) and (b"ATZ" in fr.data or b"AT&F" in fr.data):
                return True
            if isinstance(fr, Frame) and fr.ftype == T_POLL:
                return True
        return False

    def login(self, timeout: float = 5.0) -> None:
        self._write(build_login(self._password))
        for _ in range(40):
            fr = self._read_frame(timeout)
            if fr is None:
                break
            if isinstance(fr, Frame) and fr.ftype == T_LOGIN_RESULT:
                if fr.payload.startswith(b"VALID"):
                    self.connected = True
                    return
                raise VMLinkError(
                    "Remote password doesn't match a password of the Stratagy.")
        raise VMLinkError(
            "Handshake Failed. Wrong baud rate or other serial link parameter "
            "is incorrect.")

    def connect(self) -> None:
        if not self.wait_banner():
            raise VMLinkError(
                "Handshake Failed. Wrong baud rate or other serial link "
                "parameter is incorrect.")
        self.login()
        self.session_preamble()

    def session_preamble(self) -> dict:
        """Pull the firmware banner, admin box and log name (confirmed opcodes).

        Each is best-effort: a card that does not answer one leaves it blank
        rather than failing the whole connect."""
        try:
            rec = self._request(OP_SESSION_LOGREC)
            text = _ascii(rec.value)
            self.log_name = _first_token(text, r"[A-Za-z0-9_.]+\.LOG") or ""
            m = re.search(r"\b(99\d)\b", text)
            if m:
                self.admin_box = m.group(1)
        except VMLinkError:
            pass
        try:
            ver = self._request(OP_GET_VERSION)
            self.firmware = _ascii(ver.value).strip() or self.firmware
        except VMLinkError:
            pass
        return {"firmware": self.firmware, "admin_box": self.admin_box,
                "log_name": self.log_name}

    # -- reads ------------------------------------------------------------
    def read_file(self, path: str, timeout: float = 5.0) -> bytes:
        """``0x92 open -> LE32 length``, then ``0x93 read-block`` streamed."""
        reply = self._request(OP_OPEN_FILE, path.encode("ascii") + b"\x00",
                              timeout=timeout)
        length = struct.unpack_from("<I", reply.value, 0)[0] if len(reply.value) >= 4 else 0
        self._write(build_read_block(self._next_seq()))
        return self._read_stream(length, timeout=timeout)

    def read_directory(self, timeout: float = 5.0) -> Dict[str, str]:
        """Fast-dir (0x4e): the box->name directory as ``NNNH\\0name\\0``."""
        reply = self._request(OP_RECSEL_4E, b"\x00\x00", timeout=timeout)
        length = struct.unpack_from("<I", reply.value, 0)[0] if len(reply.value) >= 4 else 0
        blob = self._read_stream(length, timeout=timeout)
        from . import vm_records
        return vm_records.parse_directory(blob)

    def read_record(self, box, timeout: float = 5.0) -> Tuple[bytes, bytes]:
        """Return ``(properties_segment, ua_segment)`` for a box (0x42 / 0x43)."""
        props = self._read_selected(OP_SEL_MBOX, box, CLASS_MBOX, timeout)
        ua = self._read_selected(OP_SEL_UAGENT, box, CLASS_UAGENT, timeout)
        return props, ua

    def _read_selected(self, opcode, box, class_tag, timeout) -> bytes:
        value = box_le32(box) + b"\x00\x00" + class_tag + b"\x00"
        reply = self._request(opcode, value, timeout=timeout)
        # The reply value leads with a LE32 segment length when streamed.
        length = (struct.unpack_from("<I", reply.value, 0)[0]
                  if len(reply.value) >= 4 else 0)
        if length and length < 4096:
            return self._read_stream(length, timeout=timeout)
        # Short records come back inline in the reply value itself.
        return reply.value

    def close(self) -> None:
        self.connected = False
        try:
            self._t.close()
        except Exception:  # noqa: BLE001
            pass

    def trace_text(self) -> str:
        """The frame trace in the exe's own ``Packet to/received`` idiom."""
        lines = []
        for direction, hexs in self.trace:
            tag = "Packet to send" if direction == "TX" else "Packet received"
            lines.append(f"{tag} 0x{hexs}")
        return "\n".join(lines)


def _first_unit(buf: bytes):
    """Parse the first complete Frame/Raw from ``buf``; return (unit, consumed).

    Returns ``(None, 0)`` when more bytes are needed to decide."""
    if not buf:
        return None, 0
    if buf[0] == SOH:
        if len(buf) < 4:
            return None, 0
        ln = buf[2]
        total = 3 + ln + 1
        if len(buf) < total:
            return None, 0
        raw = bytes(buf[:total])
        if frame_ok(raw):
            return Frame(raw[1], ln, raw[3:3 + ln], raw, True), total
        # not a valid frame: emit one raw byte and resync
        return Raw(bytes(buf[:1])), 1
    # accumulate raw bytes up to the next SOH we can see
    j = buf.find(SOH, 1)
    if j == -1:
        return None, 0  # wait for more; the raw run may continue
    return Raw(bytes(buf[:j])), j


def _ascii(b: bytes) -> str:
    return b.decode("latin-1", "replace")


def _first_token(text: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, text)
    return m.group(0) if m else None


# --------------------------------------------------------------------------
# FakeLVMU — the offline protocol twin
# --------------------------------------------------------------------------
@dataclass
class CardImage:
    """A card's observable state for the fake. Pure data; no customer bytes."""
    firmware: str = "STRATAGY 1:A20d 2:NONE Jun 04 2012"
    admin_box: str = "997"
    log_name: str = "Stratagy.LOG"
    files: Dict[str, bytes] = None          # path -> bytes (INSTALL.CFG, *.PBX)
    directory: Dict[str, str] = None        # box -> name
    records: Dict[str, Tuple[bytes, bytes]] = None  # box -> (props, ua)

    def __post_init__(self):
        self.files = self.files or {}
        self.directory = self.directory or {}
        self.records = self.records or {}


class FakeLVMU(Transport):
    """An in-process Stratagy card: a :class:`Transport` that answers the host.

    It emits the AT banner up front, replies ``VALID`` to the login, serves the
    session scalars, streams files/records/directory as content frames, and
    absorbs ACK tokens — enough for every read-only screen to run offline.
    """

    name = "fake-lvmu"

    def __init__(self, image: Optional[CardImage] = None,
                 password: str = "Stratagy"):
        self.image = image or demo_card_image()
        self._password = password
        self._out = bytearray()
        self._in = bytearray()
        self._open_file: Optional[bytes] = None
        self._selected_box: Optional[str] = None
        # The softmodem banner + an idle poll, exactly as a waiting card emits.
        self._out += b"ATZ\rAT&F&C1&D2L0Q0V0X0E0&K0\r"
        self._out += build_frame(T_POLL)

    # -- Transport interface ---------------------------------------------
    def read(self, n: int, timeout: float = 2.0) -> bytes:
        chunk = bytes(self._out[:n])
        del self._out[:n]
        return chunk

    def write(self, b: bytes) -> int:
        self._in += b
        self._drain_host_frames()
        return len(b)

    def close(self) -> None:
        self._out.clear()
        self._in.clear()

    # -- card behaviour ---------------------------------------------------
    def _drain_host_frames(self) -> None:
        while True:
            unit, consumed = _first_unit(self._in)
            if unit is None or consumed == 0:
                break
            del self._in[:consumed]
            if isinstance(unit, Frame):
                self._handle(unit)

    def _emit(self, frame: bytes) -> None:
        self._out += frame

    def _reply(self, opcode: int, seq: int, value: bytes = b"") -> None:
        payload = bytes([opcode & 0xFF, (4 + len(value)) & 0xFF, 0, seq & 0xFF]) + value
        self._emit(build_frame(T_DATA_CARD, payload))

    def _stream(self, data: bytes, seq: int) -> None:
        """Emit ``data`` as a block: first chunk carries the 4-byte header."""
        self._emit(encode_block(data, seq))

    def _handle(self, fr: Frame) -> None:
        if fr.ftype == T_LOGIN:
            pw = fr.payload.rstrip(b"\x00").decode("latin-1", "replace")
            if pw == self._password:
                self._emit(build_frame(T_LOGIN_RESULT, b"VALID"))
            else:
                self._emit(build_frame(T_LOGIN_RESULT, b"INVALID"))
            return
        if fr.ftype in ACK_TYPES:
            return
        if fr.ftype != T_REQ_HOST:
            return
        op = fr.opcode
        seq = fr.seq or 0
        if op == OP_SESSION_LOGREC:
            val = (self.image.log_name.encode("latin-1") + b"\x00"
                   + self.image.admin_box.encode("latin-1") + b"\x00")
            self._reply(op, seq, val)
        elif op == OP_GET_VERSION:
            self._reply(op, seq, self.image.firmware.encode("latin-1"))
        elif op in (OP_GET_TS_12, OP_GET_TS_13):
            self._reply(op, seq, struct.pack("<I", 1339200000))
        elif op == OP_OPEN_FILE:
            path = fr.value.rstrip(b"\x00").decode("latin-1", "replace")
            data = self.image.files.get(path) or self.image.files.get(
                path.rsplit("\\", 1)[-1], b"")
            self._open_file = data
            self._reply(op, seq, struct.pack("<I", len(data)))
        elif op == OP_READ_BLOCK:
            self._stream(self._open_file or b"", seq)
            self._open_file = None
        elif op == OP_RECSEL_4E:
            blob = directory_blob(self.image.directory)
            self._reply(op, seq, struct.pack("<I", len(blob)))
            self._stream(blob, seq)
        elif op in (OP_SEL_MBOX, OP_SEL_UAGENT):
            box = str(struct.unpack_from("<I", fr.value, 0)[0]) if len(fr.value) >= 4 else None
            rec = self.image.records.get(box or "")
            seg = b""
            if rec is not None:
                seg = rec[0] if op == OP_SEL_MBOX else rec[1]
            if len(seg) >= 250:
                self._reply(op, seq, struct.pack("<I", len(seg)))
                self._stream(seg, seq)
            else:
                self._reply(op, seq, seg)
        else:
            # Unknown/inferred opcode: a harmless empty reply (never a write).
            self._reply(op, seq, b"")


def directory_blob(directory: Dict[str, str]) -> bytes:
    """Serialise a ``box->name`` map as the on-wire ``NNNH\\0name\\0`` run."""
    out = bytearray()
    for box in sorted(directory, key=lambda b: (len(b), b)):
        name = directory[box]
        out += box.encode("ascii") + b"H\x00" + name.encode("latin-1") + b"\x00"
        out += b"\x01\x00\x00\x00"  # a flag/pointer word, as the real blob has
    return bytes(out)


def demo_card_image() -> CardImage:
    """A small, PII-free card image for offline demos and tests.

    Structural strings (box numbers ``200H..``, ``set`` parameters, integration
    pattern templates) mirror a real CIX100S capture and are **model-generic,
    not customer data**; the mailbox *names* and *security codes* are synthetic.
    """
    from . import vm_records
    install_cfg = (
        "#- Stratagy Configuration\r\n"
        "set pbx_type 'CIX100S'\r\n"
        "set password 'Stratagy'\r\n"
        "set hot_box 994\r\n"
        "set error_box 999\r\n"
        "set box_snd 998\r\n"
        "set box_idx 411\r\n"
        "set defaults_box 997\r\n"
        "set security_max_length 16\r\n"
        "set security_min_length 1\r\n"
        "set baud1 9600\r\n"
        "set serial_port1 2\r\n"
        "set shutdown '2 130'\r\n"
        "set lognam 'Stratagy.LOG'\r\n"
        "set fixed_len0 3\r\n"
        "#- SMDI/Serial Integration Definitions\r\n"
        "integration 30 'Axxxxxxrrrr0000000000'\r\n"
        "integration 30 'Bxxxxxxbbbb0000000000'\r\n"
        "integration 30 'Nxxxxxxrrrr0000000000'\r\n"
        "integration 30 'Dxxxxxxxxxxcccccceeee'\r\n"
        "integration 30 'Siiiiiiiiii'\r\n"
        "#- End of Options\r\n"
    ).encode("latin-1")
    pbx = (
        "pbx_name 'Strata CIX'\r\n"
        "dl_connect H # Dial code to connect the caller to the extension\r\n"
        "dl_dtwait F- # Dial code to put a caller on transfer hold\r\n"
        "dl_ndtret F- # Dial code to use when there is no transfer dialtone\r\n"
        "dl_rnaret F- # Dial code to use when there is no answer\r\n"
        "dl_prefix  # What to dial BEFORE dialing the User ID extension\r\n"
        "dl_suffix  # What to dial AFTER dialing the User ID extension\r\n"
    ).encode("latin-1")
    names = {
        "200": "Reception", "201": "BreakRoom", "202": "Warehouse",
        "203": "Shipping", "204": "FrontDesk", "205": "Service",
        "221": "StationA", "222": "StationB", "223": "StationC",
        "241": "ScratchBox", "997": "Defaults", "999": "SystemAdmin",
    }
    records = {}
    for box, name in names.items():
        records[box] = (
            vm_records.build_props_segment(box, ext=f"{box}H", name=name,
                                           comment="EXTENSION"),
            vm_records.build_ua_segment(security_code=f"{box}00"),
        )
    return CardImage(files={"INSTALL.CFG": install_cfg, "CIX100S.PBX": pbx},
                     directory=names, records=records)


__all__ = [
    "SOH", "Frame", "Raw", "iter_frames", "streams_from_log",
    "reassemble_content", "checksum", "build_frame", "frame_ok",
    "build_login", "build_ack_host", "build_get", "build_open_file",
    "build_read_block", "box_le32", "encode_block", "VMLink", "VMLinkError",
    "FakeLVMU", "CardImage", "demo_card_image", "directory_blob",
    "OP_SESSION_LOGREC", "OP_GET_VERSION", "OP_OPEN_FILE", "OP_READ_BLOCK",
    "OP_RECSEL_4E", "OP_SEL_MBOX", "OP_SEL_UAGENT",
    "T_LOGIN", "T_LOGIN_RESULT", "T_POLL", "T_ACK_HOST", "T_ACK_CARD",
    "T_REQ_HOST", "T_DATA_CARD", "CONTENT_TYPES",
]
