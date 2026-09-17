#!/usr/bin/env python3
"""palscoreraw.py -- palscore.py's method on a raw 8-bit index raster.

THE METHOD IS BORROWED AND THE CITATION IS THE POINT, TWICE OVER

`tools/palscore.py` scores a candidate palette by the mean absolute RGB
difference between horizontally adjacent pixels, alongside a shuffled-palette
control and an identity-greyscale control, and it says NO SEPARATION when the
winner beats the tightest control by less than 1.5x. That tool took the method
from `vis-sherlockholmes-doc/docs/05-imv-picture.md`, where a 768-byte run of
6-bit values had several readings that all produced legible pictures and only
the controls settled it.

**This file changes exactly one thing: the input.** `palscore.py` is hard-wired
to a `GIFM` container -- 320 x 200, header 791 bytes, palette at offset 23.
The raster this session needs to score is a `cellras.py` record of arbitrary
geometry with its palette in a separate file. The scoring function, the two
controls, the 1.5x threshold and the flatness statistic are copied unchanged so
that a number produced here is comparable with a number produced there.

    python tools/palscoreraw.py CELLFILE --pal PALFILE
    python tools/palscoreraw.py CELLFILE --pal PALFILE --flat
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cellras  # noqa: E402


def to_rgb(pal, order="RGB", planar=False):
    six = max(pal) <= 63
    scale = (lambda v: v * 255 // 63) if six else (lambda v: v)
    idx = "RGB".index
    out = []
    for i in range(256):
        t = ((pal[i], pal[256 + i], pal[512 + i]) if planar
             else (pal[i * 3], pal[i * 3 + 1], pal[i * 3 + 2]))
        out.append(tuple(scale(t[idx(c)]) for c in order))
    return out


def score(rgb, pix, w, h, step=2):
    """palscore.py's score(), with W and H passed in instead of global."""
    tot = n = 0
    for y in range(0, h, step):
        base = y * w
        for x in range(0, w - 1, 2):
            a = rgb[pix[base + x]]
            b = rgb[pix[base + x + 1]]
            tot += abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
            n += 3
    if n == 0:
        raise SystemExit("palscoreraw: raster %dx%d is too small to score"
                         % (w, h))
    return tot / n


def flatness(pix, w, h):
    uni = tot = 0
    for y in range(0, h - 1, 2):
        for x in range(0, w - 1, 2):
            a = pix[y * w + x]
            if (pix[y * w + x + 1] == a and pix[(y + 1) * w + x] == a
                    and pix[(y + 1) * w + x + 1] == a):
                uni += 1
            tot += 1
    return uni / tot if tot else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cell")
    ap.add_argument("--pal", required=True)
    ap.add_argument("--flat", action="store_true")
    a = ap.parse_args()

    w, h, rows = cellras.parse(open(a.cell, "rb").read(),
                               os.path.basename(a.cell))
    pix = cellras.to_indices(w, h, rows)
    pal = open(a.pal, "rb").read()
    if len(pal) != 768:
        raise SystemExit("palscoreraw: %s is %d bytes, expected 768"
                         % (a.pal, len(pal)))

    print("raster       : %s   %d x %d" % (os.path.basename(a.cell), w, h))
    print("palette      : %s   max component %d" % (os.path.basename(a.pal),
                                                    max(pal)))
    print("distinct idx : %d of 256" % len(set(pix)))
    if a.flat:
        print("2x2 uniform  : %.2f %%   (Sherlock: drawn art 15.6-82.1 %%, "
              "continuous tone 2.2 %%)" % (100 * flatness(pix, w, h)))
    print()

    cands = [("%s %s" % (os.path.basename(a.pal), order), to_rgb(pal, order))
             for order in ("RGB", "RBG", "GRB", "GBR", "BRG", "BGR")]
    cands.append(("%s planar" % os.path.basename(a.pal),
                  to_rgb(pal, "RGB", True)))

    rnd = random.Random(20921023)          # palscore.py's seed, unchanged
    base = to_rgb(pal, "RGB")
    shuffled = base[:]
    rnd.shuffle(shuffled)
    controls = [("CONTROL shuffled palette", shuffled),
                ("CONTROL identity greyscale", [(i, i, i) for i in range(256)])]

    rows_ = sorted((score(rgb, pix, w, h), n) for n, rgb in cands)
    crows = sorted((score(rgb, pix, w, h), n) for n, rgb in controls)
    ctrl = crows[0][0]

    print("%-32s %9s %9s" % ("reading", "mean dRGB", "vs ctrl"))
    for s, n in rows_:
        print("%-32s %9.2f %8.2fx" % (n, s, ctrl / s if s else 0))
    print()
    for s, n in crows:
        print("%-32s %9.2f" % (n, s))
    print()

    best, bname = rows_[0]
    factor = ctrl / best if best else 0
    if factor < 1.5:
        print("NO CANDIDATE SEPARATES FROM THE CONTROL (%.2fx)." % factor)
        return 1
    print("BEST: %s, %.2fx better than the tightest control." % (bname, factor))
    return 0


if __name__ == "__main__":
    sys.exit(main())
