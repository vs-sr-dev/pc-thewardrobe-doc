#!/usr/bin/env python3
"""cga.py -- render a region of bytes as a CGA 320x200 four-colour image.

POP-CORN is CGA only -- `popcorn.doc` says so -- and CGA mode 4 is two bits
per pixel, four pixels to the byte, 80 bytes to a scan line, 320 x 200. On the
card the lines are interleaved in two banks 0x2000 apart; in a program's own
data they may be stored either way, so `--interleave` is an option and not an
assumption, and both are worth looking at before deciding what a region is.

`popcorn.doc` also says **F8 selects a colour palette**, so the object uses at
least two of CGA's palettes. All four are here; `--palette` picks one. The
colours are the standard IBM CGA RGBI values and none of them is measured from
the object.

    python cga.py FILE --offset N [--width 320] [--rows 200] [--out X.png]
    python cga.py FILE --sheet OUT.png --step 16000     a contact sheet
    python cga.py FILE --scan                            report candidate spans

`--scan` is the honest first move: it reports, per 16,000-byte window, what
fraction of bytes are 0x00, 0xAA, 0x55 and 0xFF -- the four constant-colour
bytes of a 2bpp image -- because a region made mostly of those is a picture
with flat areas and a region made of anything else is not.

Standard library plus Pillow for the PNG. It reads; it writes only where told.
"""

import argparse
import os
import sys

from PIL import Image

# IBM CGA mode 4/5 palettes, as RGB. Index 0 is the background, which is
# programmable; black is used here and stated rather than assumed.
PALETTES = {
    0: [(0, 0, 0), (0, 170, 0), (170, 0, 0), (170, 85, 0)],          # 0 low
    1: [(0, 0, 0), (0, 170, 170), (170, 0, 170), (170, 170, 170)],   # 1 low
    2: [(0, 0, 0), (85, 255, 85), (255, 85, 85), (255, 255, 85)],    # 0 high
    3: [(0, 0, 0), (85, 255, 255), (255, 85, 255), (255, 255, 255)],  # 1 high
}

FLAT = (0x00, 0xAA, 0x55, 0xFF)


def render(data, off, width, rows, palette, interleave):
    bpr = width // 4
    img = Image.new("RGB", (width, rows))
    px = img.load()
    pal = PALETTES[palette]
    for y in range(rows):
        if interleave:
            bank, line = y & 1, y >> 1
            src = off + bank * 0x2000 + line * bpr
        else:
            src = off + y * bpr
        row = data[src:src + bpr]
        for i, b in enumerate(row):
            x = i * 4
            for k in range(4):
                v = (b >> (6 - 2 * k)) & 3
                if x + k < width:
                    px[x + k, y] = pal[v]
    return img


def scan(data, window):
    print("%10s %10s %8s %8s %8s %8s %8s"
          % ("from", "to", "00", "AA", "55", "FF", "flat%"))
    best = []
    for i in range(0, len(data), window):
        s = data[i:i + window]
        if not s:
            break
        n = float(len(s))
        c = [s.count(b) / n for b in FLAT]
        flat = sum(c)
        print("%10d %10d %8.3f %8.3f %8.3f %8.3f %8.1f"
              % (i, i + len(s), c[0], c[1], c[2], c[3], flat * 100))
        best.append((flat, i))
    best.sort(reverse=True)
    print()
    print("the five flattest windows: %s"
          % ", ".join("%d (%.1f%%)" % (o, f * 100) for f, o in best[:5]))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--width", type=int, default=320)
    ap.add_argument("--rows", type=int, default=200)
    ap.add_argument("--palette", type=int, default=1, choices=(0, 1, 2, 3))
    ap.add_argument("--interleave", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--sheet")
    ap.add_argument("--step", type=int, default=16000)
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--scale", type=int, default=1)
    args = ap.parse_args(argv)

    with open(args.path, "rb") as f:
        data = f.read()

    if args.scan:
        scan(data, args.step)
        return 0

    if args.sheet:
        tiles = []
        off = args.offset
        while off + args.step <= len(data):
            tiles.append((off, render(data, off, args.width, args.rows,
                                      args.palette, args.interleave)))
            off += args.step
        if not tiles:
            raise SystemExit("cga.py: nothing to draw")
        cols = 4
        rowsn = (len(tiles) + cols - 1) // cols
        sheet = Image.new("RGB", (cols * args.width, rowsn * args.rows),
                          (24, 24, 24))
        for i, (o, im) in enumerate(tiles):
            sheet.paste(im, ((i % cols) * args.width,
                             (i // cols) * args.rows))
        sheet.save(args.sheet)
        print("cga.py: %d tiles of %d bytes from %d, written to %s"
              % (len(tiles), args.step, args.offset, args.sheet))
        for i, (o, _) in enumerate(tiles):
            print("   tile %2d at offset %d" % (i, o))
        return 0

    img = render(data, args.offset, args.width, args.rows, args.palette,
                 args.interleave)
    if args.scale > 1:
        img = img.resize((args.width * args.scale, args.rows * args.scale),
                         Image.NEAREST)
    out = args.out or (os.path.splitext(args.path)[0]
                       + "-%d.png" % args.offset)
    img.save(out)
    print("cga.py: %s offset %d, %dx%d, palette %d, interleave %s -> %s"
          % (os.path.basename(args.path), args.offset, args.width, args.rows,
             args.palette, args.interleave, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
