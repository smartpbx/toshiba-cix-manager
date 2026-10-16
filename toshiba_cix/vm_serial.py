"""Serial transports for the Stratagy LVMU voicemail leg — pure stdlib.

The voicemail card speaks a binary record protocol over RS-232 (``vm_link.py``
frames it). This module is only the *byte pipe* underneath that: one tiny
interface — ``read(n, timeout) -> bytes`` / ``write(b) -> int`` / ``close()`` —
with three backends, so no third-party ``pyserial`` is pulled in (project rule:
stdlib only, the app ships as a single AppImage/.exe).

| backend            | how                                              | when |
|--------------------|--------------------------------------------------|------|
| :class:`PosixSerial` | ``os.open`` + ``termios`` cfmakeraw B9600 CS8  | Linux/macOS USB-serial dongle |
| :class:`TcpSerial`   | ``socket`` to ``host:port`` (raw)              | REMOTE: a serial bridge on the RSM Pi |
| ``FakeLVMU`` (vm_link) | an in-process protocol twin                   | offline tests + the capture-replay demo |

STATUS / "say what is unproven" (DESIGN_PLAN §1.2 rule 7): the POSIX and TCP
backends are written to the confirmed link parameters (9600 8N1, no flow
control — ``STRATAGY_LVMU_SERIAL_PROTOCOL.md`` §0, confirmed by capture) but
**have not been exercised against live hardware from this codebase**. They are
marked accordingly and are never reached by the offline test suite, which runs
entirely through the ``FakeLVMU`` twin. Nothing here writes to a card.
"""

from __future__ import annotations

import glob
import os
import sys
from typing import List, Optional

# Confirmed link parameters (STRATAGY_LVMU_SERIAL_PROTOCOL.md §0).
BAUD_DEFAULT = 9600


class SerialError(RuntimeError):
    """A transport-level failure (open/read/write)."""


class Transport:
    """The byte-pipe interface ``vm_link.VMLink`` drives.

    Implementations must be half-duplex-safe: ``read`` returns whatever bytes
    have arrived (up to ``n``) within ``timeout`` seconds, possibly fewer, and
    never blocks past the timeout. ``write`` sends all of ``b``.
    """

    name = "transport"

    def read(self, n: int, timeout: float = 2.0) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def write(self, b: bytes) -> int:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class PosixSerial(Transport):
    """``termios``-based serial on Linux/macOS. **Not hardware-verified here.**"""

    def __init__(self, port: str, baud: int = BAUD_DEFAULT):
        self.name = port
        self.baud = baud
        try:
            import termios  # noqa: F401 - probe availability early
        except ImportError as exc:  # pragma: no cover - Windows
            raise SerialError("termios unavailable on this platform") from exc
        try:
            self._fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as exc:
            raise SerialError(f"cannot open {port}: {exc}") from exc
        self._configure()

    def _configure(self) -> None:  # pragma: no cover - needs a tty
        import termios

        baud_const = getattr(termios, f"B{self.baud}", termios.B9600)
        attrs = termios.tcgetattr(self._fd)
        # cfmakeraw-equivalent: no canonical processing, 8N1, no flow control.
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
        iflag = 0
        oflag = 0
        lflag = 0
        cflag = (cflag & ~termios.CSIZE & ~termios.PARENB & ~termios.CSTOPB
                 & ~getattr(termios, "CRTSCTS", 0))
        cflag |= termios.CS8 | termios.CLOCAL | termios.CREAD
        cc[termios.VMIN] = 0
        cc[termios.VTIME] = 0
        termios.tcsetattr(
            self._fd, termios.TCSANOW,
            [iflag, oflag, cflag, lflag, baud_const, baud_const, cc])

    def read(self, n: int, timeout: float = 2.0) -> bytes:  # pragma: no cover
        import select

        out = bytearray()
        deadline = _monotonic() + timeout
        while len(out) < n:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                break
            r, _, _ = select.select([self._fd], [], [], remaining)
            if not r:
                break
            try:
                chunk = os.read(self._fd, n - len(out))
            except BlockingIOError:
                continue
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def write(self, b: bytes) -> int:  # pragma: no cover
        return os.write(self._fd, b)

    def close(self) -> None:  # pragma: no cover
        try:
            os.close(self._fd)
        except OSError:
            pass


class TcpSerial(Transport):
    """Raw-TCP transport for a serial bridge on the RSM Pi (REMOTE leg).

    The framing is self-synchronising (SOH + checksum) and half-duplex with
    explicit tokens, so a plain raw socket (``ser2net``/``socat`` on the Pi) is
    enough — no RFC2217 control channel. **Not hardware-verified here.**
    """

    def __init__(self, host: str, port: int, connect_timeout: float = 5.0):
        import socket

        self.name = f"{host}:{port}"
        try:
            self._sock = socket.create_connection((host, port), connect_timeout)
        except OSError as exc:
            raise SerialError(f"cannot reach {host}:{port}: {exc}") from exc
        self._sock.setblocking(False)

    def read(self, n: int, timeout: float = 2.0) -> bytes:  # pragma: no cover
        import select

        out = bytearray()
        deadline = _monotonic() + timeout
        while len(out) < n:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                break
            r, _, _ = select.select([self._sock], [], [], remaining)
            if not r:
                break
            try:
                chunk = self._sock.recv(n - len(out))
            except (BlockingIOError, InterruptedError):
                continue
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def write(self, b: bytes) -> int:  # pragma: no cover
        self._sock.sendall(b)
        return len(b)

    def close(self) -> None:  # pragma: no cover
        try:
            self._sock.close()
        except OSError:
            pass


def _monotonic() -> float:
    import time
    return time.monotonic()


def discover_ports() -> List[str]:
    """Best-effort list of candidate serial ports, same idea as the old
    "Connect Using: COM1" dropdown. Pure stdlib; never raises."""
    ports: List[str] = []
    if sys.platform.startswith("win"):  # pragma: no cover - Windows only
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"HARDWARE\DEVICEMAP\SERIALCOMM")
            i = 0
            while True:
                try:
                    _name, value, _type = winreg.EnumValue(key, i)
                    ports.append(value)
                    i += 1
                except OSError:
                    break
        except OSError:
            pass
        return ports
    # POSIX: by-id first (stable names), then the usual device nodes.
    for pattern in ("/dev/serial/by-id/*", "/dev/ttyUSB*", "/dev/ttyACM*",
                    "/dev/tty.usbserial*", "/dev/tty.usbmodem*", "/dev/cu.*"):
        ports.extend(sorted(glob.glob(pattern)))
    # de-dupe, preserve order
    seen = set()
    uniq = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def open_transport(spec: dict) -> Transport:
    """Open a transport from a connect spec.

    ``{"transport": "serial", "port": "/dev/ttyUSB0", "baud": 9600}``
    ``{"transport": "tcp", "host": "10.0.0.5", "port": 2001}``
    The ``"fake"`` transport is handled by the server (it needs a card image),
    not here, so an unknown/fake spec raises.
    """
    kind = (spec or {}).get("transport") or "serial"
    if kind == "serial":
        return PosixSerial(spec["port"], int(spec.get("baud") or BAUD_DEFAULT))
    if kind == "tcp":
        return TcpSerial(spec["host"], int(spec["port"]))
    raise SerialError(f"unknown transport {kind!r}")


__all__ = ["Transport", "PosixSerial", "TcpSerial", "SerialError",
           "discover_ports", "open_transport", "BAUD_DEFAULT"]
