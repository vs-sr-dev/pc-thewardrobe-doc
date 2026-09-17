#!/usr/bin/env python3
"""dattex.py -- read the type-32 chunks of a Final Fantasy XI .DAT as images.

`datchain.py` derives the chunk chain and shows it closes exactly on the
last byte of 48,757 of 52,626 files.  A chain that closes is arithmetic.
This tool is the external fact: it takes the chain at its word, reads the
header the chain points at, and decodes the payload as a picture.  If the
header is being read correctly the picture is a picture.  If it is not,
the picture is noise, and noise is visible from across the room.

WHAT A TYPE-32 CHUNK LOOKS LIKE, DERIVED FROM THE BYTES

    +0    4      chunk tag, ASCII, NUL padded
    +4    4      u32: type = v & 0x7F, len = ((v >> 7) & 0x1FFFF F) * 16
    +8    8      zero in every chunk seen
    +16   1      0xA1 in every type-32 chunk seen
    +17   8      class, ASCII space padded -- always "model" so far
    +25   8      texture name, ASCII space padded
    +33   40     a Win32 BITMAPINFOHEADER: biSize=40, biWidth, biHeight,
                 biPlanes=1, biBitCount, ...

                 biHeight is POSITIVE, which in a Windows bitmap means
                 bottom-up.  These textures are top-down, as Direct3D
                 wants them: obeying the sign renders the glyph sheet
                 `moji` upside down, and not obeying it renders it the
                 right way up.  The header is a Windows structure being
                 used to carry Direct3D data, and only some of its
                 conventions came along.
    +73   4      format: '3TXD' / '1TXD' -- which is 'DXT3' / 'DXT1' with
                 the four bytes in the other order -- or a small integer
                 1 or 2, meaning an 8-bit palette

    and then the two branches part company, which is a measured fact and
    not a tidy one:

    format 1 or 2      +80  1024  palette, ALPHA FIRST then three colour
                                  bytes; entry 0 is transparent
                       +1104      one byte of palette index per pixel
                                  chunk length == 1104 + w*h, EXACTLY,
                                  on 61 of 61 chunks measured

    '3TXD'/'1TXD'      +77  u32   payload length in bytes.  Matches w*h
                                  (DXT3) or w*h/2 (DXT1) on 342 of 342
                       +81  u32   pitch.  Equals w*4 on 316 of 316 DXT3
                                  and on 0 of 26 DXT1
                       +85        the blocks, and the chunk is then rounded
                                  up to a multiple of 16, which leaves
                                  exactly 11 bytes of slack on 342 of 342

THE DATA OFFSET WAS DERIVED, AND THE FIRST DERIVATION WAS WRONG

The offset was first taken as `chunk length - payload length`, which gives
96 for every DXT chunk and produces a picture that is unmistakably noise.
The alignment was then found by a statistic rather than by eye: a real DXT
block has `colour0 > colour1` far more often than not, so the fraction of
blocks satisfying that was computed for every candidate offset from 76 to
115.  Offset 85 scores **100.0 %** on 2,000 blocks and every neighbour
scores between 0 % and 96 %.  The eleven bytes that the first derivation
mistook for header are the chunk's own padding at the END.

biBitCount is not to be trusted: `moji` declares 4 bits and is a 1024x2048
DXT3, which is 8 bits per pixel.  The format word wins.

Nothing is executed, nothing is contacted, nothing is written to the
object.  PNGs go where the caller says, which is never the repository.

usage:
  dattex.py list  DATFILE
  dattex.py dump  DATFILE --out DIR [--limit N] [--name NAME] [--min-side N]
"""

import argparse
import os
import struct
import sys
import zlib
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import datchain  # noqa: E402

TEX_TYPE = 32
PALETTE_OFF = 80
PALETTE_BYTES = 1024
DXT_DATA_OFF = 85
SIZE_UNIT = 16

FMT_DXT3 = b"3TXD"
FMT_DXT1 = b"1TXD"


def parse_tex(data, off, length):
    """Return a dict describing the texture, or None with a reason.

    Every field the tool relies on is checked against a second, independent
    statement of the same quantity, and a chunk whose two statements
    disagree is refused rather than guessed at.
    """
    mark = data[off + 16]
    cls = data[off + 17:off + 25].decode("latin1").rstrip("\x00 ")
    name = data[off + 25:off + 33].decode("latin1").rstrip("\x00 ")
    bi = struct.unpack_from("<IiiHHIIiiII", data, off + 33)
    bisize, w, h, planes, bits = bi[0], bi[1], bi[2], bi[3], bi[4]
    if bisize != 40:
        return None, "biSize is %d, not 40" % bisize
    if w <= 0 or h == 0:
        return None, "dimensions %dx%d" % (w, h)
    fmt = data[off + 73:off + 77]
    ah = abs(h)
    if fmt in (FMT_DXT3, FMT_DXT1):
        kind = "DXT3" if fmt == FMT_DXT3 else "DXT1"
        need = w * ah if kind == "DXT3" else w * ah // 2
        declared = struct.unpack_from("<I", data, off + 77)[0]
        pitch = struct.unpack_from("<I", data, off + 81)[0]
        if declared != need:
            return None, ("length field %d, geometry says %d"
                          % (declared, need))
        data_off = DXT_DATA_OFF
        slack = length - data_off - need
        if not 0 <= slack < SIZE_UNIT:
            return None, "slack after +%d is %d" % (data_off, slack)
        pal_off = None
    else:
        (n,) = struct.unpack_from("<I", fmt, 0)
        if n not in (1, 2):
            return None, "format word is %r" % fmt
        kind = "P8"
        need = w * ah
        pal_off = PALETTE_OFF
        data_off = PALETTE_OFF + PALETTE_BYTES
        if length != data_off + need:
            return None, ("palette layout needs %d bytes, chunk is %d"
                          % (data_off + need, length))
        pitch = None
        declared = None
        slack = 0
    if off + length > len(data):
        return None, "chunk runs past the end of the file"
    return {
        "mark": mark, "cls": cls, "name": name, "w": w, "h": h,
        "planes": planes, "bits": bits, "kind": kind, "need": need,
        "data_off": data_off, "pal_off": pal_off, "pitch": pitch,
        "declared": declared, "slack": slack, "flip": False,
        "palkind": None if pal_off is None else n,
    }, None


def _dxt_colors(c0, c1, three):
    def unpack(c):
        r = (c >> 11) & 0x1F
        g = (c >> 5) & 0x3F
        b = c & 0x1F
        return (r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)
    a = unpack(c0)
    b = unpack(c1)
    if three:
        c2 = tuple((a[i] + b[i]) // 2 for i in range(3))
        c3 = (0, 0, 0)
        return [a, b, c2, c3], True
    c2 = tuple((2 * a[i] + b[i]) // 3 for i in range(3))
    c3 = tuple((a[i] + 2 * b[i]) // 3 for i in range(3))
    return [a, b, c2, c3], False


def decode_dxt(buf, w, h, dxt3, opaque=False):
    """Return a bytearray of RGBA, w*h*4."""
    out = bytearray(w * h * 4)
    bw, bh = (w + 3) // 4, (h + 3) // 4
    stride = 8 if not dxt3 else 16
    pos = 0
    for by in range(bh):
        for bx in range(bw):
            alpha = None
            if dxt3:
                alpha = buf[pos:pos + 8]
                pos += 8
            c0, c1, idx = struct.unpack_from("<HHI", buf, pos)
            pos += 8
            cols, punch = _dxt_colors(c0, c1, (not dxt3) and c0 <= c1)
            for py in range(4):
                for px in range(4):
                    x, y = bx * 4 + px, by * 4 + py
                    if x >= w or y >= h:
                        continue
                    ci = (idx >> (2 * (py * 4 + px))) & 3
                    r, g, b = cols[ci]
                    if opaque:
                        a = 255
                    elif dxt3:
                        nib = alpha[(py * 4 + px) >> 1]
                        a = (nib & 0x0F) if (px & 1) == 0 else (nib >> 4)
                        a = (a << 4) | a
                    else:
                        a = 0 if (punch and ci == 3) else 255
                    o = (y * w + x) * 4
                    out[o] = r
                    out[o + 1] = g
                    out[o + 2] = b
                    out[o + 3] = a
    return out


def decode_paletted(pal, buf, w, h, order, alpha_scale):
    out = bytearray(w * h * 4)
    entries = []
    for i in range(256):
        q = pal[i * 4:i * 4 + 4]
        if order == "argb":
            a, r, g, b = q
        elif order == "abgr":
            a, b, g, r = q
        elif order == "rgba":
            r, g, b, a = q
        else:
            b, g, r, a = q
        a = min(255, int(a * alpha_scale))
        entries.append((r, g, b, a))
    for y in range(h):
        for x in range(w):
            i = buf[y * w + x]
            r, g, b, a = entries[i]
            o = (y * w + x) * 4
            out[o] = r
            out[o + 1] = g
            out[o + 2] = b
            out[o + 3] = a
    return out


def write_png(path, rgba, w, h, flip):
    raw = bytearray()
    rows = range(h - 1, -1, -1) if flip else range(h)
    for y in rows:
        raw.append(0)
        raw += rgba[y * w * 4:(y + 1) * w * 4]

    def chunk(tag, payload):
        return (struct.pack(">I", len(payload)) + tag + payload +
                struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def collect(path):
    data = open(path, "rb").read()
    chunks, verdict, _off = datchain.walk(data)
    out = []
    for o, tag, t, s, _fl in chunks:
        if t != TEX_TYPE:
            continue
        info, why = parse_tex(data, o, s)
        out.append((o, tag, s, info, why))
    return data, verdict, out


def cmd_list(args):
    data, verdict, texs = collect(args.datfile)
    print("%s" % args.datfile)
    print("  chain verdict: %s" % verdict)
    print("  type-32 chunks: %d" % len(texs))
    kinds = Counter()
    refused = Counter()
    for o, tag, s, info, why in texs:
        if info is None:
            refused[why.split(" ")[0]] += 1
            continue
        kinds[info["kind"]] += 1
    print("  by format: %s" % dict(kinds))
    if refused:
        print("  refused  : %s" % dict(refused))
    print()
    print("  %-9s %-9s %-9s %5s %5s %-5s %8s %6s"
          % ("offset", "tag", "name", "w", "h", "fmt", "payload", "at"))
    n = 0
    for o, tag, s, info, why in texs:
        if info is None:
            continue
        print("  %-9d %-9s %-9s %5d %5d %-5s %8d %6d"
              % (o, "".join(chr(c) for c in tag if 32 <= c < 127),
                 info["name"], info["w"], info["h"], info["kind"],
                 info["need"], info["data_off"]))
        n += 1
        if args.limit and n >= args.limit:
            print("  ... (%d more)" % (len(texs) - n))
            break
    return 0


def cmd_dump(args):
    os.makedirs(args.out, exist_ok=True)
    data, verdict, texs = collect(args.datfile)
    written = 0
    refused = 0
    for o, tag, s, info, why in texs:
        if info is None:
            refused += 1
            continue
        if args.name and args.name.lower() not in info["name"].lower():
            continue
        w, h = info["w"], abs(info["h"])
        if w < args.min_side or h < args.min_side:
            continue
        start = o + (args.force_offset if args.force_offset >= 0
                     else info["data_off"])
        kind = info["kind"]
        if kind in ("DXT3", "DXT1"):
            rgba = decode_dxt(data[start:start + info["need"]], w, h,
                              kind == "DXT3", args.opaque)
        else:
            pal = data[o + PALETTE_OFF:o + PALETTE_OFF + PALETTE_BYTES]
            body = data[start:start + info["need"]]
            rgba = decode_paletted(pal, body, w, h, args.palette_order,
                                   args.alpha_scale)
            if args.opaque:
                for i in range(3, len(rgba), 4):
                    rgba[i] = 255
        safe = "".join(c if c.isalnum() or c in "._-" else "_"
                       for c in info["name"]) or "unnamed"
        out = os.path.join(args.out, "%s_%08d_%s_%dx%d.png"
                           % (os.path.basename(args.datfile), o, safe, w, h))
        write_png(out, rgba, w, h, info["flip"])
        written += 1
        print("  wrote %s  (%s %dx%d, payload %d at +%d)"
              % (os.path.basename(out), kind, w, h, info["need"],
                 info["data_off"]))
        if args.limit and written >= args.limit:
            break
    print()
    print("written %d, refused %d, chain verdict %s"
          % (written, refused, verdict))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list")
    p.add_argument("datfile")
    p.add_argument("--limit", type=int, default=40)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("dump")
    p.add_argument("datfile")
    p.add_argument("--out", required=True)
    p.add_argument("--limit", type=int, default=8)
    p.add_argument("--name")
    p.add_argument("--min-side", type=int, default=32)
    p.add_argument("--alpha-scale", type=float, default=2.0)
    p.add_argument("--force-offset", type=int, default=-1)
    p.add_argument("--opaque", action="store_true",
                   help="ignore alpha; a visual check should not be "
                        "defeated by a texture that is legitimately "
                        "transparent")
    p.add_argument("--palette-order", default="argb",
                   choices=["argb", "abgr", "rgba", "bgra"])
    p.set_defaults(func=cmd_dump)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
