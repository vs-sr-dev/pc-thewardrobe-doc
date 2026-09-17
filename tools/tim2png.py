#!/usr/bin/env python3
"""tim2png.py -- render a PlayStation TIM to a PNG, to see whether the reading
of the format is right.

This exists for one reason: arithmetic closure is necessary and not sufficient.
`pakdec.py` proves that all 1,112 `.PAK` files decompress to a byte count that
a TIM header accounts for exactly, with residue zero. That would still be true
if the pixels came out scrambled. Looking at one is the check the arithmetic
cannot do.

The colour encoding is the PlayStation's 16-bit ABGR1555, taken from the same
public definition as the rest of `timtmd.py`:

    bit 15      STP, the semi-transparency / mask flag
    bits 14..10 blue,  5 bits
    bits  9.. 5 green, 5 bits
    bits  4.. 0 red,   5 bits

so red sits in the low bits, not blue, and a naive RGB555 reading comes out
with the reds and blues swapped -- which is itself a useful thing to be able
to see. Five-bit channels are widened to eight by replicating the top three
bits (v << 3 | v >> 2), not by shifting alone, so white stays white.

An 8-bit indexed image packs **two pixels per halfword**, low byte first, and
looks up each byte in the CLUT; a 4-bit image packs four, low nibble first.

The PNG is written here rather than by a library so that nothing outside the
standard library is needed: one IHDR, one IDAT of zlib-compressed scanlines
each prefixed with filter byte 0, one IEND.

Nothing this writes belongs in the repository -- decoded assets stay in the
ignored work directory. That is a rule of the branch, not a property of PNG.

    python tools/tim2png.py IN.TIM OUT.png
    python tools/tim2png.py IN.PAK OUT.png --pak
    python tools/tim2png.py IN.TIM OUT.png --clut 2
"""

import argparse
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def c15(v, opaque=False):
    """One ABGR1555 halfword to (r, g, b, a).

    On the PlayStation the halfword 0x0000 -- black with STP clear -- is the
    transparent colour when a texture is composited. A background image is not
    composited, it is the bottom layer, and there 0x0000 is simply black. The
    difference is visible: rendered with the transparency rule, a room comes
    out speckled with holes wherever the artist used pure black. `opaque`
    turns the rule off, and which one is right depends on what the image is
    for, not on the bytes.
    """
    r = v & 31
    g = (v >> 5) & 31
    b = (v >> 10) & 31
    stp = (v >> 15) & 1
    a = 255 if opaque else (0 if (v & 0x7FFF) == 0 and not stp else 255)
    up = lambda x: (x << 3) | (x >> 2)
    return up(r), up(g), up(b), a


def parse_tim(data):
    if data[0:4] != bytes((0x10, 0, 0, 0)):
        raise SystemExit("not a TIM: first four bytes are %s" % data[:4].hex())
    flags = struct.unpack_from("<I", data, 4)[0]
    pmode = flags & 7
    pos = 8
    cluts = []
    if flags & 8:
        bnum, dx, dy, w, h = struct.unpack_from("<IHHHH", data, pos)
        body = pos + 12
        for j in range(h):
            cluts.append([struct.unpack_from("<H", data, body + (j * w + i) * 2)[0]
                          for i in range(w)])
        pos += 12 + w * h * 2
    bnum, dx, dy, w, h = struct.unpack_from("<IHHHH", data, pos)
    body = pos + 12
    return pmode, cluts, w, h, data[body:body + w * h * 2], (dx, dy)


def to_rgba(pmode, cluts, w, h, pix, clut_index=0, opaque=False):
    pal = cluts[clut_index] if cluts else None
    if pmode == 2:
        width = w
        rows = []
        for y in range(h):
            row = bytearray()
            for x in range(width):
                v = pix[(y * w + x) * 2] | (pix[(y * w + x) * 2 + 1] << 8)
                row += bytes(c15(v, opaque))
            rows.append(row)
        return width, h, rows
    if pmode == 1:
        width = w * 2
        rows = []
        for y in range(h):
            row = bytearray()
            base = y * w * 2
            for x in range(width):
                row += bytes(c15(pal[pix[base + x]], opaque))
            rows.append(row)
        return width, h, rows
    if pmode == 0:
        width = w * 4
        rows = []
        for y in range(h):
            row = bytearray()
            base = y * w * 2
            for x in range(width):
                byte = pix[base + (x >> 1)]
                idx = (byte & 15) if (x & 1) == 0 else (byte >> 4)
                row += bytes(c15(pal[idx], opaque))
            rows.append(row)
        return width, h, rows
    raise SystemExit("pixel mode %d not rendered" % pmode)


def write_png(path, width, height, rows):
    raw = b"".join(b"\x00" + bytes(r) for r in rows)
    def chunk(tag, payload):
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dest")
    ap.add_argument("--pak", action="store_true",
                    help="the input is a compressed .PAK, decompress it first")
    ap.add_argument("--clut", type=int, default=0)
    ap.add_argument("--opaque", action="store_true",
                    help="ignore the 0x0000-is-transparent rule; correct for a "
                         "background, wrong for a sprite")
    ap.add_argument("--block", type=int, default=0,
                    help="for files holding several TIMs, which one")
    a = ap.parse_args()

    data = open(a.src, "rb").read()
    if a.pak:
        from pakdec import depack
        data, st = depack(data)
        print("decompressed %d -> %d bytes (%s)"
              % (os.path.getsize(a.src), len(data), st))
    if a.block:
        from timtmd import tim_at
        pos = 0
        for _ in range(a.block):
            n, info = tim_at(data, pos)
            if not n:
                raise SystemExit("no block %d" % a.block)
            pos += n
        data = data[pos:]
    pmode, cluts, w, h, pix, fb = parse_tim(data)
    width, height, rows = to_rgba(pmode, cluts, w, h, pix, a.clut, a.opaque)
    write_png(a.dest, width, height, rows)
    print("%s -> %s   %dx%d  pixel mode %d  %d palette(s) of %d  frame buffer %s"
          % (os.path.basename(a.src), a.dest, width, height, pmode,
             len(cluts), len(cluts[0]) if cluts else 0, fb))


if __name__ == "__main__":
    main()
