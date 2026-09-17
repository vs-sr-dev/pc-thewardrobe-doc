#!/usr/bin/env python3
"""palscore.py -- decide which reading of a palette is the right one, by
scoring candidates against controls instead of by looking at hexdumps.

THE METHOD IS NOT ORIGINAL AND THE CITATION IS THE POINT

This is `vis-sherlockholmes-doc/docs/05-imv-picture.md`'s method, applied to a
different disc of the same platform. That chapter had a 768-byte run of 6-bit
values, three possible phases and several possible channel orders, and every
one of them produced a legible picture. It settled the question like this:

  * neighbouring pixels of a photograph are usually near each other in colour,
    whatever their palette indices are, so **the correct reading minimises the
    mean absolute RGB difference between horizontally adjacent pixels**;
  * and -- this is the half that matters -- **a shuffled-palette control and an
    identity-greyscale control are scored alongside**, so the winning number
    has a scale. That chapter's best candidate beat its shuffled control by a
    factor of 1.31, the tool printed NO CANDIDATE SEPARATES FROM THE CONTROL,
    and the real palette turned out to be at an offset nobody had proposed.

Running the same score without the controls, which is what this session did
first, produces a ranking that looks decisive and means nothing. That mistake
is recorded in `docs/12-corrections.md`.

WHAT IS DIFFERENT HERE, AND IT WEAKENS THE SCORE

The pictures on this disc are **dithered**. Dithering deliberately alternates
neighbouring pixels between two palette entries, so the adjacency score is
raised for the correct palette as well as the wrong ones and the separation
between candidate and control is smaller than it was on `.IMV`. The dither is
why the 320 x 200 renders look speckled and why a 2 x 2 box average of the same
pixels looks like a photograph. `--flat` reports the fraction of 2 x 2 blocks
that are uniform, which is Sherlock's drawn-versus-continuous-tone statistic,
and it is reported here so that the dither claim is a measurement.

A separation factor is printed for every candidate. **Read the factor, not the
rank.** Anything under about 1.5 is this tool saying it does not know.

    python tools/palscore.py IMAGE.MLD
    python tools/palscore.py IMAGE.MLD --extern PALETTE.COL
    python tools/palscore.py IMAGE.MLD --windows
    python tools/palscore.py IMAGE.MLD --flat
"""
import argparse
import itertools
import os
import random
import struct
import sys

PIXOFF = 791
W, H = 320, 200


def load(path):
    d = open(path, "rb").read()
    if d[0:4] != b"GIFM":
        raise SystemExit("palscore: %s is not a GIFM image" % path)
    if len(d) != PIXOFF + W * H:
        raise SystemExit("palscore: %s is %d bytes, expected %d"
                         % (path, len(d), PIXOFF + W * H))
    return d[:PIXOFF], d[PIXOFF:]


def to_rgb(pal, order="RGB", planar=False, six=None):
    """Turn 768 bytes into 256 RGB triples under one reading."""
    if six is None:
        six = max(pal) <= 63
    scale = (lambda v: v * 255 // 63) if six else (lambda v: v)
    out = []
    idx = "RGB".index
    for i in range(256):
        if planar:
            t = (pal[i], pal[256 + i], pal[512 + i])
        else:
            t = (pal[i * 3], pal[i * 3 + 1], pal[i * 3 + 2])
        out.append(tuple(scale(t[idx(c)]) for c in order))
    return out


def score(rgb, pix, step=2):
    """Mean |dRGB| between horizontally adjacent pixels. Lower is better."""
    tot = 0
    n = 0
    for y in range(0, H, step):
        base = y * W
        for x in range(0, W - 1, 2):
            a = rgb[pix[base + x]]
            b = rgb[pix[base + x + 1]]
            tot += abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
            n += 3
    return tot / n


def flatness(pix):
    """Fraction of 2x2 blocks that are a single index. Sherlock's statistic:
    art drawn in a palette has flat regions, a dithered photograph has none."""
    uni = 0
    tot = 0
    for y in range(0, H - 1, 2):
        for x in range(0, W - 1, 2):
            a = pix[y * W + x]
            if (pix[y * W + x + 1] == a and pix[(y + 1) * W + x] == a
                    and pix[(y + 1) * W + x + 1] == a):
                uni += 1
            tot += 1
    return uni / tot


def candidates(head, pix, extern=None, windows=False):
    out = []
    embedded = head[23:23 + 768]
    for order in ("RGB", "RBG", "GRB", "GBR", "BRG", "BGR"):
        out.append(("embedded@23 %s" % order,
                    to_rgb(embedded, order)))
    out.append(("embedded@23 planar RGB", to_rgb(embedded, "RGB", True)))
    for phase in (1, 2):
        if 23 + phase + 768 <= len(head) + W * H:
            blob = (head + pix)[23 + phase:23 + phase + 768]
            out.append(("embedded@%d RGB" % (23 + phase), to_rgb(blob, "RGB")))
    if extern:
        e = open(extern, "rb").read()
        if len(e) != 768:
            raise SystemExit("palscore: %s is %d bytes, expected 768"
                             % (extern, len(e)))
        for order in ("RGB", "BGR"):
            out.append(("%s %s" % (os.path.basename(extern), order),
                        to_rgb(e, order)))
        out.append(("%s planar" % os.path.basename(extern),
                    to_rgb(e, "RGB", True)))
    if windows:
        blob = head + pix
        for off in range(0, 24):
            out.append(("window@%d RGB" % off,
                        to_rgb(blob[off:off + 768], "RGB")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--extern", help="a separate 768-byte palette member")
    ap.add_argument("--windows", action="store_true")
    ap.add_argument("--flat", action="store_true")
    a = ap.parse_args()

    head, pix = load(a.image)
    print("image        : %s" % os.path.basename(a.image))
    print("distinct idx : %d of 256" % len(set(pix)))
    if a.flat:
        f = flatness(pix)
        print("2x2 uniform  : %.2f %%   (Sherlock: drawn art 15.6-82.1 %%, "
              "continuous tone 2.2 %%)" % (100 * f))
    print()

    cands = candidates(head, pix, a.extern, a.windows)

    # The controls, which are the whole reason this tool exists.
    rnd = random.Random(20921023)
    base = to_rgb(head[23:23 + 768], "RGB")
    shuffled = base[:]
    rnd.shuffle(shuffled)
    grey = [(i, i, i) for i in range(256)]
    controls = [("CONTROL shuffled palette", shuffled),
                ("CONTROL identity greyscale", grey)]

    rows = [(score(rgb, pix), name) for name, rgb in cands]
    crows = [(score(rgb, pix), name) for name, rgb in controls]
    ctrl = min(s for s, _ in crows)
    rows.sort()

    print("%-32s %9s %9s" % ("reading", "mean dRGB", "vs ctrl"))
    for s, name in rows[:12]:
        print("%-32s %9.2f %8.2fx" % (name, s, ctrl / s if s else 0))
    print()
    for s, name in sorted(crows):
        print("%-32s %9.2f" % (name, s))
    print()

    best, bname = rows[0]
    factor = ctrl / best if best else 0
    if factor < 1.5:
        print("NO CANDIDATE SEPARATES FROM THE CONTROL.")
        print("Best reading %r beats the tightest control by %.2fx, which is"
              % (bname, factor))
        print("not a result. The palette is probably not one of these"
              " readings.")
        return 1
    print("BEST: %s, %.2fx better than the tightest control." % (bname, factor))
    return 0


if __name__ == "__main__":
    sys.exit(main())
