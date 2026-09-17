#!/usr/bin/env python3
"""tilepeek.py -- render a raw region as 4bpp tiles under several candidate
bit layouts, so the layout is chosen by looking rather than by assertion.

The question this answers is narrow and it matters: CPS graphics ROMs sit on
the board in an interleave that an emulator has to undo with a per-game table.
If the shipped region is already in a plain linear tile order, that table was
applied before shipping. If it is not, the program must carry one.

Nothing here claims to know the right layout. It renders each candidate and
the reader decides; a wrong layout produces visible noise, a right one
produces sprites.

Usage:
    tilepeek.py FILE --offset N --tiles N --out OUT.png [--layout NAME]
"""
import argparse
import sys

import numpy as np
from PIL import Image

# a 16-colour palette that makes 4bpp index data legible without claiming to
# be the game's palette: index 0 black, then a spread.
PAL = np.array([
    (0, 0, 0), (40, 40, 90), (70, 40, 40), (40, 80, 40),
    (120, 90, 50), (90, 60, 120), (60, 120, 120), (150, 150, 150),
    (200, 120, 80), (120, 200, 120), (120, 120, 220), (220, 200, 120),
    (220, 120, 180), (160, 220, 220), (220, 220, 220), (255, 255, 255),
], dtype=np.uint8)


def tiles_planar_cps(blob, ntiles):
    """CPS-style 8x8 4bpp: 32 bytes per tile, four bitplanes, one bit of each
    plane per pixel, planes held in alternating bytes."""
    out = np.zeros((ntiles, 8, 8), dtype=np.uint8)
    for t in range(ntiles):
        b = blob[t * 32:(t + 1) * 32]
        if len(b) < 32:
            break
        for y in range(8):
            p0, p1, p2, p3 = b[y * 4], b[y * 4 + 1], b[y * 4 + 2], b[y * 4 + 3]
            for x in range(8):
                s = 7 - x
                out[t, y, x] = (((p0 >> s) & 1) | (((p1 >> s) & 1) << 1) |
                                (((p2 >> s) & 1) << 2) | (((p3 >> s) & 1) << 3))
    return out


def tiles_planar_split(blob, ntiles):
    """Same 32 bytes per tile, but the four planes are 8-byte blocks."""
    out = np.zeros((ntiles, 8, 8), dtype=np.uint8)
    for t in range(ntiles):
        b = blob[t * 32:(t + 1) * 32]
        if len(b) < 32:
            break
        for y in range(8):
            p0, p1, p2, p3 = b[y], b[8 + y], b[16 + y], b[24 + y]
            for x in range(8):
                s = 7 - x
                out[t, y, x] = (((p0 >> s) & 1) | (((p1 >> s) & 1) << 1) |
                                (((p2 >> s) & 1) << 2) | (((p3 >> s) & 1) << 3))
    return out


def tiles_packed(blob, ntiles):
    """8x8 4bpp packed: two pixels per byte, 32 bytes per tile."""
    out = np.zeros((ntiles, 8, 8), dtype=np.uint8)
    for t in range(ntiles):
        b = blob[t * 32:(t + 1) * 32]
        if len(b) < 32:
            break
        for i in range(32):
            y, x = divmod(i * 2, 8)
            out[t, y, x] = b[i] >> 4
            out[t, y, x + 1] = b[i] & 0xF
    return out


LAYOUTS = {
    "cps-planar": tiles_planar_cps,
    "split-planar": tiles_planar_split,
    "packed": tiles_packed,
}


def sheet(tiles, cols=64):
    n = len(tiles)
    rows = (n + cols - 1) // cols
    img = np.zeros((rows * 8, cols * 8), dtype=np.uint8)
    for i in range(n):
        r, c = divmod(i, cols)
        img[r * 8:(r + 1) * 8, c * 8:(c + 1) * 8] = tiles[i]
    return Image.fromarray(PAL[img], "RGB")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--offset", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--tiles", type=int, default=4096)
    ap.add_argument("--cols", type=int, default=64)
    ap.add_argument("--layout", default="all")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    with open(a.file, "rb") as fh:
        fh.seek(a.offset)
        blob = fh.read(a.tiles * 32 + 64)
    names = list(LAYOUTS) if a.layout == "all" else [a.layout]
    imgs = [sheet(LAYOUTS[n](blob, a.tiles), a.cols) for n in names]
    w, h = imgs[0].size
    out = Image.new("RGB", (w, h * len(imgs) + 4 * (len(imgs) - 1)), (255, 0, 0))
    for i, im in enumerate(imgs):
        out.paste(im, (0, i * (h + 4)))
    out.save(a.out)
    print("wrote %s  layouts top-to-bottom: %s" % (a.out, ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
