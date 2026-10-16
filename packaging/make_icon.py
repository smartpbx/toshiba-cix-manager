#!/usr/bin/env python3
"""Generate raster icons from scratch — pure stdlib, no Pillow.

Produces ``packaging/icon.png`` (256x256 RGBA) for the Linux/AppImage build and
``packaging/icon.ico`` (a multi-size, classic 32-bit BMP ICO Windows + PyInstaller
accept) for the Windows build. The design mirrors ``icon.svg``: a dark rounded
tile with a three-row "station directory" motif in accent blue.

The generated files are git-ignored (they are build artifacts); the committed
icon of record is ``icon.svg``. Run from anywhere::

    python3 packaging/make_icon.py
"""

from __future__ import annotations

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# palette (R, G, B)
BG_TOP = (30, 58, 95)
BG_BOT = (18, 35, 58)
ACCENT = (74, 163, 255)
TRANSPARENT = (0, 0, 0, 0)


def _lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def _rounded(x, y, w, h, rx, px, py):
    """Is pixel (px,py) inside the rounded rect [x,x+w)x[y,y+h) with radius rx?"""
    if px < x or px >= x + w or py < y or py >= y + h:
        return False
    cx = min(max(px, x + rx), x + w - 1 - rx)
    cy = min(max(py, y + rx), y + h - 1 - rx)
    dx, dy = px - cx, py - cy
    return dx * dx + dy * dy <= rx * rx


def _draw(size: int):
    """Return an RGBA pixel buffer (list of (r,g,b,a)) of length size*size."""
    s = size / 256.0
    pad = max(2, int(round(8 * s)))
    radius = max(4, int(round(44 * s)))
    buf = [TRANSPARENT] * (size * size)

    rows = [(92, 74), (128, 74), (164, 74)]   # (row_cy, dot_cx) in 256 space
    dot_r = 13 * s
    bar_x, bar_w, bar_h, bar_rx = 98 * s, 92 * s, 18 * s, 9 * s

    for py in range(size):
        for px in range(size):
            if not _rounded(pad, pad, size - 2 * pad, size - 2 * pad,
                            radius, px, py):
                continue
            # vertical gradient background
            t = py / max(1, size - 1)
            r, g, b = _lerp(BG_TOP, BG_BOT, t)
            # motif in 256-space coords
            X, Y = px / s, py / s
            on_accent = False
            for cy, cx in rows:
                # dot
                if (X - cx) ** 2 + (Y - cy) ** 2 <= 13 ** 2:
                    on_accent = True
                    break
                # bar (rounded)
                if _rounded(98, cy - 9, 92, 18, 9, X, Y):
                    on_accent = True
                    break
            if on_accent:
                r, g, b = ACCENT
            buf[py * size + px] = (r, g, b, 255)
    return buf


# --------------------------------------------------------------------------
# PNG writer (RGBA, 8-bit)
# --------------------------------------------------------------------------
def _png_chunk(typ: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + typ + data
            + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))


def write_png(path: str, size: int, buf) -> None:
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter: none
        for x in range(size):
            raw.extend(buf[y * size + x])
    png = (b"\x89PNG\r\n\x1a\n"
           + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
           + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
           + _png_chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(png)


# --------------------------------------------------------------------------
# ICO writer (classic 32-bit BGRA BMP images + AND mask)
# --------------------------------------------------------------------------
def _bmp_image(size: int, buf) -> bytes:
    # BITMAPINFOHEADER: height is doubled (XOR image + AND mask), bottom-up.
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0,
                         0, 0, 0, 0)
    xor = bytearray()
    for y in range(size - 1, -1, -1):            # bottom-up
        for x in range(size):
            r, g, b, a = buf[y * size + x]
            xor += bytes((b, g, r, a))           # BGRA
    # AND mask: 1 bpp, rows padded to 32-bit; 0 = opaque (alpha governs anyway)
    row_bytes = ((size + 31) // 32) * 4
    and_mask = bytes(row_bytes * size)
    return header + bytes(xor) + and_mask


def write_ico(path: str, sizes) -> None:
    images = [(sz, _bmp_image(sz, _draw(sz))) for sz in sizes]
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = b""
    blob = b""
    for sz, img in images:
        w = 0 if sz >= 256 else sz
        entries += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(img), offset)
        blob += img
        offset += len(img)
    with open(path, "wb") as fh:
        fh.write(header + entries + blob)


def main() -> None:
    png_buf = _draw(256)
    png_path = os.path.join(HERE, "icon.png")
    ico_path = os.path.join(HERE, "icon.ico")
    write_png(png_path, 256, png_buf)
    write_ico(ico_path, [256, 64, 48, 32, 16])
    print(f"wrote {png_path}")
    print(f"wrote {ico_path}")


if __name__ == "__main__":
    main()
