#!/usr/bin/env python3
"""flatness.py -- tell art drawn in a palette from a continuous-tone source.

The question this exists to answer: is a decoded 8-bit frame a photograph (or
a scan of a painting) that has been dithered down to 256 colours, or is it
art that was drawn directly in the palette?

Looking at it does not settle it, and this repository has the receipt: a
frame of a judge in a barrister's wig was written up as "a person, filmed,
digitised and dithered down to 256 colours" and it is a drawing.

The statistic is the fraction of 2 x 2 pixel blocks whose four pixels carry
the same index. Art drawn in a palette has flat regions; a continuous-tone
source dithered to 8 bits has almost none, because the dither is what carries
the tone.

AND THE CONTROL IS ON THE DISC. `KGRAPHIC.MC` is a bank of 475 hand-painted
interface images -- the London map, the score screen -- so the range that
hand-painted art occupies can be measured rather than assumed, and a frame
can be scored against it. `--control` prints that range first.

A near-black frame is NOT diagnostic in either direction: dark dither is not
flat and dark flat is not painted. `--min-luma` filters those out and the
tool says how many it dropped, because a statistic computed over frames that
cannot carry it is worse than no statistic.
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def flat(pix, w, h):
    """(2x2-uniform fraction, horizontally-flat fraction, distinct indices)"""
    uni = sum(1 for y in range(h - 1) for x in range(w - 1)
              if pix[y * w + x] == pix[y * w + x + 1]
              == pix[(y + 1) * w + x] == pix[(y + 1) * w + x + 1])
    hf = sum(1 for y in range(h) for x in range(w - 1)
             if pix[y * w + x] == pix[y * w + x + 1])
    return (100.0 * uni / ((h - 1) * (w - 1)),
            100.0 * hf / (h * (w - 1)),
            len(set(pix)))


def luma(pix, pal):
    return sum((pal[x][0] + pal[x][1] + pal[x][2]) // 3 for x in pix) / len(pix)


def kgraphic_controls(path):
    """Every full-screen record of a KGRAPHIC bank: known hand-painted art."""
    from icomdat import Icom
    out = []
    for i, r in enumerate(Icom(path).records()):
        if not r:
            continue
        w, h = struct.unpack_from("<HH", r, 0)
        n = struct.unpack_from("<I", r, 4)[0]
        if 8 + w * h + 3 * n != len(r) or (w, h) != (320, 200):
            continue
        out.append(("%s rec %d" % (os.path.basename(path), i),
                    flat(r[8:8 + w * h], w, h), None))
    return out


def imv_first_frames(paths, minluma):
    from imv import Imv
    rows = []
    dropped = 0
    for p in paths:
        v = Imv(p)
        i = v.info()
        w, h = i["width"], i["height"]
        pal, _n, _r = v.palette()
        kb = [b for b in v.blocks if b[3] == 0x20]
        if not kb:
            continue
        body = v.b[kb[0][0] + 16:kb[0][0] + kb[0][1]]
        pix = (body[len(body) - w * h:] if (len(body) - w * h) == 1480
               else body[1480:1480 + w * h])
        if len(pix) < w * h:
            continue
        L = luma(pix, pal)
        if L < minluma:
            dropped += 1
            continue
        rows.append((os.path.relpath(p), flat(pix, w, h), L))
    return rows, dropped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--control", metavar="KGRAPHIC",
                    help="a KGRAPHIC bank to take the painted-art range from")
    ap.add_argument("--min-luma", type=float, default=25.0,
                    help="drop frames darker than this; they are not "
                         "diagnostic (default 25)")
    a = ap.parse_args()

    lo = hi = None
    if a.control:
        rows = kgraphic_controls(a.control)
        print("=== CONTROL: hand-painted full-screen art ===")
        print("%-24s %10s %10s %8s" % ("record", "2x2 uni", "flat-H", "colours"))
        for name, (u, hf, d), _ in rows:
            print("%-24s %9.2f%% %9.2f%% %8d" % (name, u, hf, d))
        vals = [r[1][0] for r in rows]
        lo, hi = min(vals), max(vals)
        print("painted-art range: %.2f %% .. %.2f %%  over %d records"
              % (lo, hi, len(rows)))
        print()

    if not a.files:
        return
    rows, dropped = imv_first_frames(a.files, a.min_luma)
    print("=== .IMV first key frames, luminance >= %.0f ===" % a.min_luma)
    print("%-34s %10s %10s %8s %8s %s"
          % ("file", "2x2 uni", "flat-H", "colours", "luma", "verdict"))
    for name, (u, hf, d), L in sorted(rows, key=lambda r: r[1][0]):
        if lo is None:
            v = ""
        elif u < lo / 2:
            v = "continuous-tone"
        elif u > hi:
            v = "drawn (flatter than any control)"
        else:
            v = "inside the painted range"
        print("%-34s %9.2f%% %9.2f%% %8d %8.1f  %s" % (name, u, hf, d, L, v))
    print()
    print("scored %d frames; dropped %d as too dark to be diagnostic"
          % (len(rows), dropped))


if __name__ == "__main__":
    main()
