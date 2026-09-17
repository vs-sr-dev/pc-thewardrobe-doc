#!/usr/bin/env python3
"""celdecode.py -- decode a 3DO cel to a PNG, and finish with a person looking.

Two encodings, and the tool refuses to guess which one it is looking at: the
CCB's PACKED flag decides.

UNCODED / UNPACKED, derived on this disc and proved by arithmetic that closes
to the byte:

    rowbytes = (woffset + 2) * 4        woffset is pre1 bits 24..31 for
                                        bpp < 8, bits 16..25 for bpp >= 8
    PDAT payload = rowbytes * height    -- on 13 unpacked cels of 14

PACKED, the run-length form. Every row is independently coded and starts on a
32-bit boundary:

    offset field    u8  when bpp < 8, u16 when bpp >= 8
                    = (words in this row's data) - 2
    then, bit-packed and MSB first:
       2 bits type, 6 bits (count - 1)
         0  end of row, the rest is transparent
         1  literal: count pixels follow, each bpp bits
         2  transparent: count pixels
         3  repeat: one pixel follows, drawn count times

COLOUR. A PLUT entry is a 16-bit word, and the first disc of this collection
proved the layout is 5-5-5 with the top bit unused, by counting the top bit
over 76,800 pixels of a 320x240 image. That result is INHERITED here and said
to be inherited. For 6-bit coded cels only the low five bits index the PLUT;
the sixth bit selects one of the two halves of the CCB's PIXC word, which is
the pixel processor's business and not the palette's.

The PNG writer is thirty lines of zlib and struct; there is no image library
in this pipeline.

usage:
    celdecode.py FILE OUT.png [--index N]     decode the Nth cel of a file
    celdecode.py FILE OUTDIR --all            every cel in the file
    celdecode.py FILE OUTDIR --all --scan     find cels by signature instead
    celdecode.py --validate                   negative controls; must fail
"""
import argparse
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ccbread import Bad, chunks, parse_ccb           # noqa: E402


def png(path, w, h, rgb):
    """rgb is a bytes of w*h*3."""
    raw = b"".join(b"\0" + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)))
        f.write(chunk(b"IDAT", zlib.compress(raw, 9)))
        f.write(chunk(b"IEND", b""))


def rgb555(v):
    return (((v >> 10) & 31) * 255 // 31,
            ((v >> 5) & 31) * 255 // 31,
            (v & 31) * 255 // 31)


class Bits(object):
    """MSB-first bit reader over a bytes."""

    def __init__(self, d, bitpos=0):
        self.d = d
        self.p = bitpos

    def read(self, n):
        v = 0
        for _ in range(n):
            byte = self.p >> 3
            if byte >= len(self.d):
                raise Bad("bit reader ran off the end at bit %d" % self.p)
            v = (v << 1) | ((self.d[byte] >> (7 - (self.p & 7))) & 1)
            self.p += 1
        return v

    def align32(self):
        self.p = (self.p + 31) // 32 * 32


def read_plut(d, off, clen):
    """PLUT chunk payload: a u32 then the entries, one u16 each."""
    n = (clen - 12) // 2
    return list(struct.unpack(">%dH" % n, d[off + 12:off + 12 + n * 2]))


def decode_unpacked(pdat, c):
    w, h, bpp, rowb = c["width"], c["height"], c["bpp"], c["rowbytes"]
    if len(pdat) < rowb * h:
        raise Bad("unpacked cel wants %d bytes, PDAT holds %d" % (rowb * h, len(pdat)))
    out = []
    for y in range(h):
        b = Bits(pdat, y * rowb * 8)
        out.append([b.read(bpp) for _ in range(w)])
    return out


def decode_packed(pdat, c):
    w, h, bpp = c["width"], c["height"], c["bpp"]
    wide = bpp >= 8
    rows = []
    bitpos = 0
    truncated = 0
    for y in range(h):
        rowstart = bitpos
        b = Bits(pdat, bitpos)
        row = []
        try:
            words = b.read(16 if wide else 8) + 2
            while len(row) < w:
                t = b.read(2)
                n = b.read(6) + 1
                if t == 0:
                    break
                elif t == 1:
                    for _ in range(n):
                        row.append(b.read(bpp))
                elif t == 2:
                    row.extend([None] * n)
                else:
                    v = b.read(bpp)
                    row.extend([v] * n)
        except Bad:
            # the last row of a cel can run to the last bit of the PDAT and
            # a packet header can then be cut off. The row is kept as far as
            # it decoded and COUNTED, never silently completed.
            truncated += 1
            words = (len(pdat) * 8 - rowstart + 31) // 32
        row = (row + [None] * w)[:w]
        rows.append(row)
        bitpos = rowstart + words * 32
        if bitpos > len(pdat) * 8 and y < h - 1:
            raise Bad("packed row %d of %d runs to bit %d, PDAT holds %d"
                      % (y, h, bitpos, len(pdat) * 8))
    if truncated:
        sys.stderr.write("  note: %d of %d rows were cut short at the end "
                         "of the PDAT and are drawn as far as they decoded\n"
                         % (truncated, h))
    return rows


def cels(d, tail=None):
    """Yield (ccb, plut, pdat) for every CCB..PDAT group in a chunked file."""
    ch, pad = chunks(d, zero_tail=True)
    if tail is not None:
        tail.append(pad)
    cur = plut = None
    for off, cid, clen in ch:
        if cid == b"CCB ":
            cur = parse_ccb(d, off)
            plut = None
        elif cid == b"PLUT":
            plut = read_plut(d, off, clen)
        elif cid == b"PDAT" and cur is not None:
            yield cur, plut, d[off + 8:off + clen]
            cur = None


def cels_by_scan(d):
    """Find cels by SIGNATURE rather than by chaining, and say so.

    A file that does not chain end to end is not a chunked file, and calling
    what follows a chunk walk would be a lie. This finds every place where the
    eight bytes `CCB ` + 0x00000050 occur, parses the CCB there, and then walks
    forward chunk by chunk ONLY as far as that cel's own PLUT and PDAT -- it
    never claims to have accounted for the bytes in between. The count of
    unaccounted bytes is returned with the cels.
    """
    out = []
    covered = 0
    i = d.find(b"CCB ")
    while i >= 0:
        if i + 80 <= len(d) and d[i + 4:i + 8] == b"\0\0\0\x50":
            try:
                c = parse_ccb(d, i)
            except Bad:
                i = d.find(b"CCB ", i + 1)
                continue
            off = i + 80
            plut = pdat = None
            # at most four chunks forward: PLUT, XTRA, PDAT in some order
            for _ in range(4):
                if off + 8 > len(d):
                    break
                cid = d[off:off + 4]
                clen = struct.unpack(">I", d[off + 4:off + 8])[0]
                if clen < 8 or off + clen > len(d) or not all(
                        32 <= ch < 127 for ch in cid):
                    break
                if cid == b"PLUT":
                    plut = read_plut(d, off, clen)
                elif cid == b"PDAT":
                    pdat = d[off + 8:off + clen]
                    off += clen
                    break
                off += clen
            if pdat is not None:
                out.append((c, plut, pdat))
                covered += off - i
        i = d.find(b"CCB ", i + 1)
    return out, len(d) - covered


def render(c, plut, pdat, bg=(255, 0, 255)):
    rows = decode_packed(pdat, c) if c["packed"] else decode_unpacked(pdat, c)
    w, h = c["width"], c["height"]
    out = bytearray()
    for y in range(h):
        for x in range(w):
            v = rows[y][x] if x < len(rows[y]) else None
            if v is None:
                out += bytes(bg)
            elif plut:
                # 6-bit coded cels: the low five bits index the PLUT, the
                # sixth selects a half of PIXC and is not a palette bit
                idx = (v & 0x1F) if c["bpp"] == 6 else v
                out += bytes(rgb555(plut[idx % len(plut)]))
            else:
                out += bytes(rgb555(v))
    return w, h, bytes(out)


def validate():
    ok = True
    b = Bits(b"\x80\x00")
    assert b.read(1) == 1 and b.read(7) == 0
    print("ok  : bit reader is MSB-first")
    try:
        Bits(b"\x00").read(9)
        print("FAIL: bit reader read past the end")
        ok = False
    except Bad as e:
        print("ok  : bit reader past the end rejected -- %s" % e)
    fake = {"width": 8, "height": 8, "bpp": 4, "rowbytes": 4, "packed": False}
    try:
        decode_unpacked(b"\0" * 8, fake)
        print("FAIL: a short PDAT was accepted")
        ok = False
    except Bad as e:
        print("ok  : short PDAT rejected -- %s" % e)
    assert rgb555(0x7FFF) == (255, 255, 255)
    assert rgb555(0x0000) == (0, 0, 0)
    assert rgb555(0x7C00) == (255, 0, 0)
    print("ok  : 5-5-5 white, black and red decode correctly")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--scan", action="store_true",
                    help="find cels by signature instead of by chaining")
    ap.add_argument("--validate", action="store_true")
    a = ap.parse_args()

    if a.validate:
        raise SystemExit(validate())

    d = open(a.file, "rb").read()
    tail = []
    if a.scan:
        got, unaccounted = cels_by_scan(d)
        print("%s: SIGNATURE SCAN, not a chunk walk. %d cels found, "
              "%d of %d bytes (%.2f %%) not accounted for"
              % (a.file, len(got), unaccounted, len(d),
                 100.0 * unaccounted / len(d)))
    else:
        got = list(cels(d, tail))
    if tail and tail[0]:
        print("%s: chain closes at %d, then %d zero bytes of padding"
              % (a.file, len(d) - tail[0], tail[0]))
    if a.all:
        os.makedirs(a.out, exist_ok=True)
        n = 0
        for i, (c, plut, pdat) in enumerate(got):
            try:
                w, h, rgb = render(c, plut, pdat)
            except Bad as e:
                print("  cel %3d  %4dx%-4d %2dbpp  FAILED: %s"
                      % (i, c["width"], c["height"], c["bpp"], e))
                continue
            p = os.path.join(a.out, "%03d_%dx%d_%dbpp.png" % (i, w, h, c["bpp"]))
            png(p, w, h, rgb)
            print("  cel %3d  %4dx%-4d %2dbpp  packed=%-5s -> %s"
                  % (i, w, h, c["bpp"], c["packed"], os.path.basename(p)))
            n += 1
        print("%d of %d cels decoded" % (n, len(got)))
    else:
        c, plut, pdat = got[a.index]
        w, h, rgb = render(c, plut, pdat)
        png(a.out, w, h, rgb)
        print("%s  cel %d  %dx%d  %d bpp  packed=%s  plut=%s entries -> %s"
              % (a.file, a.index, w, h, c["bpp"], c["packed"],
                 len(plut) if plut else 0, a.out))


if __name__ == "__main__":
    main()
