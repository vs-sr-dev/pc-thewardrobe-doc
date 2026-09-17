#!/usr/bin/env python3
"""qpic.py -- the pictures: 128 PCX, 65 masks, 63 ramps.

Three populations, three different amounts of borrowing.

`.PCX` is a public format. ZSoft published it, everyone implemented it, and the
128 files here are read with that public definition -- stated, not assumed. The
header is 128 bytes: `0A`, version, encoding, bits-per-plane, then xmin/ymin/
xmax/ymax as 16-bit little-endian, and the geometry is (xmax-xmin+1) by
(ymax-ymin+1). A 256-colour palette follows the image data, introduced by `0C`.

`.MSK` and `.LUM` are nobody's public format and are derived here from the
bytes. Both are fixed-size populations, and a fixed size is an equation:

    8,000 bytes = 160 x 50, one byte per cell.
        Row-to-row difference is minimised at stride 160 over every divisor of
        8,000, and rendering at that stride produces a coherent picture of a
        room while every other stride produces noise. The cell is 4 x 4 pixels
        and the grid covers 640 x 200: a 320-wide room uses 80 of the 160
        columns and 40 of the 65 masks do exactly that, while the 150-pixel
        play area above the panel needs 38 rows and 52 of the 65 use exactly
        38. Cell values are 0..7 plus 255.
    24 bytes = 8 RGB triples of signed offsets, applied to a palette to darken
        or lighten it. Values run either side of zero: `fc fc fc` is -4.

    python tools/qpic.py pcx  _game/scummvm/scummvm.exe _game/queen.1
    python tools/qpic.py mask _game/scummvm/scummvm.exe _game/queen.1
    python tools/qpic.py lum  _game/scummvm/scummvm.exe _game/queen.1
    python tools/qpic.py png  _game/scummvm/scummvm.exe _game/queen.1 --out _work/png --limit 6
"""

import argparse
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qres  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MASK_W, MASK_H = 160, 50


def pcx_header(b):
    (magic, ver, enc, bpp, xmin, ymin, xmax, ymax, hdpi, vdpi) = \
        struct.unpack_from("<BBBBHHHHHH", b, 0)
    nplanes = b[65]
    bpl = struct.unpack_from("<H", b, 66)[0]
    return dict(magic=magic, ver=ver, enc=enc, bpp=bpp,
                w=xmax - xmin + 1, h=ymax - ymin + 1,
                nplanes=nplanes, bpl=bpl, hdpi=hdpi, vdpi=vdpi)


def pcx_decode(b, w, h, bpl, nplanes):
    """Run-length decode. The public definition: 0xC0 in the top two bits marks
    a count of 1..63 in the low six, and the next byte is the value."""
    out = bytearray()
    p = 128
    need = bpl * nplanes * h
    while len(out) < need and p < len(b):
        c = b[p]
        p += 1
        if (c & 0xC0) == 0xC0:
            n = c & 0x3F
            if p >= len(b):
                break
            out.extend(bytes([b[p]]) * n)
            p += 1
        else:
            out.append(c)
    return bytes(out), p


def cmd_pcx(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    rows = [r for r in recs
            if r[0].upper().endswith(".PCX") or r[0].upper() == "X6.BAK"]
    geo = Counter()
    pal = 0
    good = 0
    bad = []
    tot = 0
    for name, bundle, off, size in rows:
        b = data[off:off + size]
        h = pcx_header(b)
        geo[(h["w"], h["h"], h["bpp"], h["nplanes"])] += 1
        px, endp = pcx_decode(b, h["w"], h["h"], h["bpl"], h["nplanes"])
        want = h["bpl"] * h["nplanes"] * h["h"]
        if len(px) == want:
            good += 1
        else:
            bad.append((name, len(px), want))
        if size >= 769 and b[size - 769] == 0x0C:
            pal += 1
        tot += size
    print("resources           %d (128 .PCX plus X6.BAK, which is a PCX "
          "wearing a backup's name)" % len(rows))
    print("bytes               %d" % tot)
    print("all start with 0A   %s" % all(data[r[2]] == 0x0A for r in rows))
    print("decoded to the      %d of %d" % (good, len(rows)))
    print("declared size")
    for nm, gotn, want in bad[:10]:
        print("   %-14s decoded %d, header wants %d" % (nm, gotn, want))
    print("256-colour palette  %d of %d carry a trailing 0C + 768 bytes"
          % (pal, len(rows)))
    print()
    print("%-18s %6s   %s" % ("geometry", "files", "bits/plane x planes"))
    for (w, h, bpp, np_), k in geo.most_common():
        print("%-18s %6d   %d x %d" % ("%d x %d" % (w, h), k, bpp, np_))
    return 0


def cmd_mask(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    rows = [r for r in recs if r[0].upper().endswith(".MSK")]
    sizes = Counter(r[3] for r in rows)
    print("resources           %d" % len(rows))
    print("sizes               %s" % dict(sizes))
    print("grid                %d x %d, one byte per cell = %d bytes"
          % (MASK_W, MASK_H, MASK_W * MASK_H))
    vals = Counter()
    widths = Counter()
    heights = Counter()
    blank = 0
    for name, bundle, off, size in rows:
        b = data[off:off + size]
        vals.update(b)
        if not any(b):
            blank += 1
            continue
        w = 0
        for x in range(MASK_W):
            if any(b[y * MASK_W + x] for y in range(MASK_H)):
                w = x + 1
        h = 0
        for y in range(MASK_H):
            if any(b[y * MASK_W:(y + 1) * MASK_W]):
                h = y + 1
        widths[w] += 1
        heights[h] += 1
    print("cell values         %s" % dict(sorted(vals.items())))
    print("all-zero masks      %d" % blank)
    print()
    print("used columns        %s" % dict(sorted(widths.items())))
    print("used rows           %s" % dict(sorted(heights.items())))
    print()
    print("one cell is 4 x 4 pixels, so the grid covers 640 x 200: a 320-wide")
    print("room uses 80 columns and the 150-pixel play area uses 38 rows.")
    wide = sum(v for k, v in widths.items() if k > 80)
    print("masks using more than 80 columns (scrolling rooms): %d" % wide)
    return 0


def cmd_lum(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    rows = [r for r in recs if r[0].upper().endswith(".LUM")]
    print("resources           %d" % len(rows))
    print("sizes               %s" % dict(Counter(r[3] for r in rows)))
    print("24 bytes = 8 RGB triples of signed offsets")
    grey = 0
    zero_at = Counter()
    for name, bundle, off, size in rows:
        b = data[off:off + size]
        t = [tuple(b[i * 3:i * 3 + 3]) for i in range(8)]
        if all(x[0] == x[1] == x[2] for x in t):
            grey += 1
        for i, x in enumerate(t):
            if x == (0, 0, 0):
                zero_at[i] += 1
    print("all eight triples grey (r=g=b): %d of %d" % (grey, len(rows)))
    print("which step is (0,0,0):          %s" % dict(sorted(zero_at.items())))
    print()
    print("%-10s %s" % ("name", "the eight steps, as signed offsets"))
    for name, bundle, off, size in rows[:a.top]:
        b = data[off:off + size]
        t = [b[i * 3] - 256 if b[i * 3] > 127 else b[i * 3] for i in range(8)]
        print("%-10s %s" % (name, t))
    return 0


def cmd_png(a):
    from PIL import Image
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    os.makedirs(a.out, exist_ok=True)
    k = 0
    for name, bundle, off, size in recs:
        if not name.upper().endswith(".PCX"):
            continue
        if k >= a.limit:
            break
        b = data[off:off + size]
        h = pcx_header(b)
        px, _ = pcx_decode(b, h["w"], h["h"], h["bpl"], h["nplanes"])
        im = Image.frombytes("P", (h["bpl"], h["h"]),
                             px[:h["bpl"] * h["h"]]).crop((0, 0, h["w"], h["h"]))
        if size >= 769 and b[size - 769] == 0x0C:
            im.putpalette(b[size - 768:])
        im.save(os.path.join(a.out, name + ".png"))
        k += 1
    print("wrote %d PNG to %s" % (k, a.out))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("pcx", cmd_pcx), ("mask", cmd_mask), ("lum", cmd_lum),
                     ("png", cmd_png)):
        p = sub.add_parser(name)
        p.add_argument("exe")
        p.add_argument("bundle")
        p.add_argument("--top", type=int, default=8)
        if name == "png":
            p.add_argument("--out", required=True)
            p.add_argument("--limit", type=int, default=6)
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
