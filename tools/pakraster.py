#!/usr/bin/env python3
"""pakraster.py -- does the declared width of a decoded .PAK match its raster?

`pakdec.py` proves that all 1,112 `.PAK` files decompress to exactly the number
of bytes their TIM header accounts for. That is a statement about lengths. It
says nothing about whether the pixels are laid out in rows of the declared
width, and on this disc they sometimes are not: a background whose header says
320 halfwords per row can be stored 316 to the row, with the remaining four
columns held back and written after the last row. Rendered at the declared
width such a file comes out sheared -- every row four pixels further right than
the one above -- which is visible immediately and invisible to any arithmetic.

The test is a measurement rather than a guess. For each pair of adjacent rows
the tool finds the horizontal shift, between -8 and +8, that minimises the mean
absolute difference of the green channel, and takes the mode over the image. A
raster stored at its declared width gives a modal shift of 0; one stored four
narrower gives +4.

    python tools/pakraster.py DIR
    python tools/pakraster.py DIR --list
"""

import argparse
import collections
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pakdec import depack                     # noqa: E402
from pakdec import tim_shape                  # noqa: E402


def modal_shift(hw, w, h, span=8):
    a = hw[:w * h].reshape(h, w).astype(np.int32)
    g = ((a >> 5) & 31).astype(np.int16)
    lo, hi = 10, max(11, w - 10)
    shifts = collections.Counter()
    for y in range(h - 1):
        best = None
        bs = 0
        r0 = g[y][lo:hi]
        for s in range(-span, span + 1):
            v = np.abs(r0 - np.roll(g[y + 1], s)[lo:hi]).mean()
            if best is None or v < best:
                best, bs = v, s
        shifts[bs] += 1
    mode, n = shifts.most_common(1)[0]
    return mode, n, h - 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--ext", default=".pak")
    a = ap.parse_args()

    files = []
    for dp, dn, fn in os.walk(a.root):
        for f in sorted(fn):
            if f.lower().endswith(a.ext):
                files.append(os.path.join(dp, f))

    modes = collections.Counter()
    weak = 0
    bad = []
    bydir = collections.defaultdict(collections.Counter)
    for p in files:
        out, _ = depack(open(p, "rb").read())
        sh = tim_shape(out)
        if not sh or sh["pmode"] != 2:
            continue                      # indexed sprites are checked elsewhere
        hw = np.frombuffer(out[20:20 + sh["w"] * sh["h"] * 2], dtype="<u2")
        m, n, tot = modal_shift(hw, sh["w"], sh["h"])
        modes[m] += 1
        rel = os.path.relpath(os.path.dirname(p), a.root).replace(os.sep, "/")
        bydir[rel][m] += 1
        if n < tot * 0.5:
            weak += 1
        if m != 0:
            bad.append((os.path.relpath(p, a.root), sh["w"], m, n, tot))

    total = sum(modes.values())
    print("direct-colour backgrounds examined : %d" % total)
    print("modal row-to-row horizontal shift  :")
    for m, n in sorted(modes.items(), key=lambda kv: -kv[1]):
        print("   %+d pixels   %5d files  (%.2f %%)   %s"
              % (m, n, 100.0 * n / total,
                 "declared width is the raster width" if m == 0
                 else "raster is %d narrower than declared" % m))
    print("images where the mode holds on fewer than half the row pairs : %d"
          % weak)
    print()
    print("by directory:")
    for d, c in sorted(bydir.items()):
        print("   %-24s %s" % (d, ", ".join("%+d x%d" % kv
                                            for kv in sorted(c.items()))))
    if a.list and bad:
        print()
        print("the files whose raster is not the declared width:")
        for rel, w, m, n, tot in bad:
            print("   %-40s declared %d, shift %+d on %d of %d row pairs"
                  % (rel, w, m, n, tot))


if __name__ == "__main__":
    main()
