#!/usr/bin/env python3
"""tiles.py -- reassemble a set of 80x60 DIB tiles into the picture they were
cut from, by edge matching, and say how well the winning arrangement scores
against a shuffled control.

Every `GROUPnn/BACKGRND/` on this disc holds thirty 80x60 DIBs named
`SQUARE1..SQUARE30`. Thirty tiles of 4,800 pixels is 144,000 pixels, and
144,000 is exactly the pixel count of `GAMESCRN/TICKERWN.DIB`, which is
480 x 300 -- so the board is six tiles across and five down, and that is
arithmetic rather than a guess.

The file order is *not* the board order. This solves for the board order by
greedy edge matching on the palette-indexed rows and columns, then prints the
mean seam cost of the solution next to the mean seam cost of a random
arrangement of the same tiles. **A solution that does not separate from the
shuffled control has not solved anything**, and the tool says so out loud --
the lesson `palfit.py` was written for one session earlier on this platform.

Seam cost is the mean absolute difference of the RGB triples along the
touching edge, so it is a number in 0..255 and it does not depend on how many
tiles are placed.

    python tools/tiles.py DIR --cols 6 --rows 5 --png OUT.png
    python tools/tiles.py DIR --control 200
"""
import argparse
import os
import random
import sys


def load(path):
    from PIL import Image
    im = Image.open(path).convert("RGB")
    return im


def edge(im, side):
    w, h = im.size
    px = im.load()
    if side == "R":
        return [px[w - 1, y] for y in range(h)]
    if side == "L":
        return [px[0, y] for y in range(h)]
    if side == "B":
        return [px[x, h - 1] for x in range(w)]
    return [px[x, 0] for x in range(w)]


def cost(a, b):
    n = len(a)
    return sum(abs(a[i][c] - b[i][c]) for i in range(n) for c in range(3)) / (3.0 * n)


def seam_cost(order, ims, cols, rows):
    tot = 0.0
    n = 0
    for r in range(rows):
        for c in range(cols):
            i = order[r * cols + c]
            if c + 1 < cols:
                j = order[r * cols + c + 1]
                tot += cost(edge(ims[i], "R"), edge(ims[j], "L"))
                n += 1
            if r + 1 < rows:
                j = order[(r + 1) * cols + c]
                tot += cost(edge(ims[i], "B"), edge(ims[j], "T"))
                n += 1
    return tot / n


def solve(ims, cols, rows):
    """Greedy: start from every tile, extend the first row by best right
    match, then each subsequent row by best top match, and keep the layout
    with the lowest seam cost."""
    n = len(ims)
    R = [edge(im, "R") for im in ims]
    L = [edge(im, "L") for im in ims]
    B = [edge(im, "B") for im in ims]
    T = [edge(im, "T") for im in ims]
    best = None
    for start in range(n):
        used = {start}
        grid = [start]
        ok = True
        for c in range(1, cols):
            cands = [(cost(R[grid[-1]], L[j]), j) for j in range(n) if j not in used]
            if not cands:
                ok = False
                break
            _, j = min(cands)
            grid.append(j)
            used.add(j)
        if not ok:
            continue
        for r in range(1, rows):
            for c in range(cols):
                above = grid[(r - 1) * cols + c]
                cands = [(cost(B[above], T[j]), j) for j in range(n) if j not in used]
                if not cands:
                    ok = False
                    break
                _, j = min(cands)
                grid.append(j)
                used.add(j)
            if not ok:
                break
        if not ok or len(grid) != n:
            continue
        sc = seam_cost(grid, ims, cols, rows)
        if best is None or sc < best[0]:
            best = (sc, grid)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--cols", type=int, default=6)
    ap.add_argument("--rows", type=int, default=5)
    ap.add_argument("--png")
    ap.add_argument("--scale", type=int, default=2)
    ap.add_argument("--control", type=int, default=200)
    ap.add_argument("--order", default="colmajor",
                    choices=("colmajor", "rowmajor", "solve"))
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    names = sorted((f for f in os.listdir(a.dir) if f.upper().endswith(".DIB")),
                   key=lambda s: (len(s), s))
    if not names:
        print("%s: no .DIB found -- a refusal, not a zero" % a.dir)
        return 1
    print("opened %d tiles from %s" % (len(names), a.dir))
    if len(names) != a.cols * a.rows:
        print("%d tiles but %d x %d = %d cells -- refusing"
              % (len(names), a.cols, a.rows, a.cols * a.rows))
        return 1
    ims = [load(os.path.join(a.dir, nm)) for nm in names]
    w, h = ims[0].size
    print("tile %dx%d, board %dx%d px" % (w, h, w * a.cols, h * a.rows))

    # the two orders a generator would write, tested rather than assumed
    colmajor = [0] * len(ims)
    for i in range(len(ims)):
        c, r = divmod(i, a.rows)
        colmajor[r * a.cols + c] = i
    rowmajor = list(range(len(ims)))
    named = {"colmajor": colmajor, "rowmajor": rowmajor}

    if a.order == "solve":
        got = solve(ims, a.cols, a.rows)
        if not got:
            print("no complete arrangement found")
            return 1
        sc, grid = got
    else:
        grid = named[a.order]
        sc = seam_cost(grid, ims, a.cols, a.rows)

    for nm, o in named.items():
        print("seam cost, %-9s        : %.3f" % (nm, seam_cost(o, ims, a.cols, a.rows)))

    rnd = random.Random(20250904)
    ctl = []
    for _ in range(a.control):
        o = list(range(len(ims)))
        rnd.shuffle(o)
        ctl.append(seam_cost(o, ims, a.cols, a.rows))
    ctl_mean = sum(ctl) / len(ctl)
    ctl_min = min(ctl)

    print()
    print("solution seam cost          : %.3f" % sc)
    print("shuffled control, %3d draws : mean %.3f, best %.3f"
          % (a.control, ctl_mean, ctl_min))
    print("separation                  : %.2fx better than the mean shuffle,"
          " %.2fx better than the best of %d"
          % (ctl_mean / sc, ctl_min / sc, a.control))
    if ctl_min / sc < 1.5:
        print("NO SEPARATION FROM THE CONTROL -- this arrangement is not"
              " evidence of anything.")
    print()
    print("board order, by file name:")
    for r in range(a.rows):
        print("   " + " ".join("%-12s" % names[grid[r * a.cols + c]]
                               for c in range(a.cols)))

    if a.png:
        from PIL import Image
        out = Image.new("RGB", (w * a.cols, h * a.rows))
        for i, t in enumerate(grid):
            out.paste(ims[t], ((i % a.cols) * w, (i // a.cols) * h))
        if a.scale != 1:
            out = out.resize((w * a.cols * a.scale, h * a.rows * a.scale),
                             Image.NEAREST)
        out.save(a.png)
        print()
        print("wrote %s" % a.png)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
