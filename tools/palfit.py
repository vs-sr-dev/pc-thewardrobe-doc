#!/usr/bin/env python3
"""palfit.py -- score candidate readings of a palette against a decoded frame.

The problem this exists to solve: a palette block gives 768 bytes and there
is more than one way to read them (interleaved RGB, planar RGB, a one-byte
phase shift, a channel swap).  Looking at the pictures and picking the
prettiest is not a measurement.

The test used here is objective and cheap.  A dithered 8-bit image of a
photographic source has strong local colour coherence: horizontally and
vertically adjacent pixels come from nearly the same original colour even
when their palette *indices* differ wildly.  So the correct reading of the
palette is the one that minimises the mean absolute RGB difference between
adjacent pixels.  A wrong reading scatters neighbouring indices to unrelated
colours and scores much worse.

A shuffled-palette control is scored alongside, so the number has a scale:
if the best candidate does not beat the shuffled control by a wide margin,
none of the candidates is right and the tool says so instead of ranking
noise.
"""

import argparse
import random
import sys


def score(pix, w, h, pal, step=1):
    tot = 0
    n = 0
    for y in range(0, h, step):
        row = pix[y * w:(y + 1) * w]
        for x in range(w - 1):
            a = pal[row[x]]
            b = pal[row[x + 1]]
            tot += abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
            n += 1
    return tot / n


def candidates(pay):
    """Every reading of a palette payload this repository has seen used."""
    out = {}
    n = len(pay)
    for phase in (0, 1, 2):
        p = pay[phase:]
        k = min(256, len(p) // 3)
        rgb = [(p[3 * i], p[3 * i + 1], p[3 * i + 2]) for i in range(k)]
        rgb += [(0, 0, 0)] * (256 - k)
        out["interleaved RGB, phase %d" % phase] = rgb
        out["interleaved BGR, phase %d" % phase] = [(c[2], c[1], c[0])
                                                    for c in rgb]
        out["interleaved GRB, phase %d" % phase] = [(c[1], c[0], c[2])
                                                    for c in rgb]
    if n >= 768:
        out["planar RGB"] = [(pay[i], pay[256 + i], pay[512 + i])
                             for i in range(256)]
        out["planar BGR"] = [(pay[512 + i], pay[256 + i], pay[i])
                             for i in range(256)]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("imv")
    ap.add_argument("--step", type=int, default=4)
    a = ap.parse_args()
    sys.path.insert(0, "tools")
    from imv import Imv

    v = Imv(a.imv)
    i = v.info()
    w, h = i["width"], i["height"]
    pb = [bl for bl in v.blocks if bl[3] == 0x40]
    kb = [bl for bl in v.blocks if bl[3] == 0x20]
    if not pb or not kb:
        sys.exit("need one palette block and one key frame in %s" % a.imv)
    o, size = pb[0][0], pb[0][1]
    pay = v.b[o + 16:o + size]
    ko, ksz = kb[0][0], kb[0][1]
    body = v.b[ko + 16:ko + ksz]
    alen = len(body) - w * h
    pix = body[alen:alen + w * h]

    cands = candidates(pay)
    rows = []
    for name, pal in cands.items():
        rows.append((score(pix, w, h, pal, a.step), name))
    # controls: a shuffled version of the best-scoring palette, and grey
    best = min(rows)[1]
    sh = list(cands[best])
    random.Random(1).shuffle(sh)
    rows.append((score(pix, w, h, sh, a.step), "CONTROL shuffled palette"))
    rows.append((score(pix, w, h, [(i, i, i) for i in range(256)], a.step),
                 "CONTROL identity greyscale"))
    rows.sort()
    print("%-34s %s" % ("reading", "mean |dRGB| between adjacent pixels"))
    for s, name in rows:
        print("%-34s %8.2f" % (name, s))
    ctrl = [s for s, n in rows if n.startswith("CONTROL shuffled")][0]
    top, topname = rows[0]
    print()
    print("best: %s at %.2f, shuffled control at %.2f, ratio %.2f"
          % (topname, top, ctrl, ctrl / top))
    if ctrl / top < 1.5:
        print("NO CANDIDATE SEPARATES FROM THE CONTROL -- the palette is not "
              "one of these readings.")


if __name__ == "__main__":
    main()
