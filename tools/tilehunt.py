"""tilehunt.py -- how a scene that is one member at 720 becomes several
members at 1080.

The two graphics archives share no key and no byte, and the aggregate pixel
area ratio is 2.2890 against the 2.2500 of a clean 1.5x.  The residue is
framing: above a tile limit the 1080 version of a scene is CUT, and the pieces
are separate members.  This tool finds the pieces by content.

    limit  <root>          where the tile limit is, measured
    pair   <root> K720 K1080  one pair, corner for corner, with the control
    hunt   <root> [--n N]  for the N largest 720 members, upscale 1.5x and
                           locate every 1080 member that is a rectangle of it
    cover  <root>          how much of the 1.5x upscale of each large 720
                           member is covered by 1080 members

Nothing is extracted; members are decoded in memory.

    python tools/tilehunt.py hunt "<root>" --n 12
"""
import os
import sys
import io
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table, extent, signature      # noqa: E402

import numpy as np                                   # noqa: E402
from PIL import Image                                # noqa: E402

A_NAME = "graphics_720.vt7a"
B_NAME = "graphics_1080.vt7a"


def load_all(root, arch):
    p = os.path.join(root, arch)
    n, ver, m2, count, recs = read_table(p)
    out = {}
    with open(p, "rb") as fh:
        for r in sorted(recs, key=lambda x: x[1]):
            fh.seek(r[1])
            if signature(fh.read(16)) != "WebP":
                continue
            fh.seek(r[1])
            blob = fh.read(extent(r))
            try:
                im = Image.open(io.BytesIO(blob))
                im.load()
            except Exception:                        # noqa: BLE001
                continue
            out[r[0]] = (im, extent(r))
    return out


def limit(root):
    print("Where the tile limit is.")
    print()
    for arch in (A_NAME, B_NAME):
        d = load_all(root, arch)
        ws = collections.Counter(im.size[0] for im, _ in d.values())
        hs = collections.Counter(im.size[1] for im, _ in d.values())
        print("== %s : %d WebP members" % (arch, len(d)))
        print("   largest width  %5d   largest height %5d" % (max(ws), max(hs)))
        print("   the ten widest distinct widths, with how many members:")
        for w in sorted(ws, reverse=True)[:10]:
            print("      %5d  x%d" % (w, ws[w]))
        print("   the ten tallest distinct heights:")
        for h in sorted(hs, reverse=True)[:10]:
            print("      %5d  x%d" % (h, hs[h]))
        over = [(im.size, e) for im, e in d.values()
                if im.size[0] > 2047 or im.size[1] > 2047]
        print("   members exceeding 2047 in either dimension : %d" % len(over))
        for s, e in sorted(over, key=lambda x: -x[1])[:6]:
            print("      %4dx%-4d  %d bytes" % (s[0], s[1], e))
        print()


def rect_mad(big, small_arr, x, y):
    h, w = small_arr.shape[:2]
    win = big[y:y + h, x:x + w]
    if win.shape != small_arr.shape:
        return 1e9
    return float(np.abs(win - small_arr).mean())


def hunt(root, n_big):
    print("For each of the largest 720 members, upscale it 1.5x and ask which")
    print("1080 members are rectangles cut out of it.")
    print()
    A = load_all(root, A_NAME)
    B = load_all(root, B_NAME)
    print("720 WebP %d, 1080 WebP %d" % (len(A), len(B)))
    print()
    # index the 1080 members by their greyscale array, once
    Bg = {}
    for k, (im, e) in B.items():
        Bg[k] = (np.asarray(im.convert("L"), dtype=np.float32), im.size, e)

    big = sorted(A.items(), key=lambda kv: -kv[1][0].size[0] * kv[1][0].size[1])
    tiled = 0
    single = 0
    for k, (im, e) in big[:n_big]:
        w, h = im.size
        uw, uh = round(w * 1.5), round(h * 1.5)
        up = np.asarray(im.convert("L").resize((uw, uh), Image.BICUBIC),
                        dtype=np.float32)
        print("720 key %-11d %4dx%-4d %9d B   ->   upscaled %4dx%-4d"
              % (k, w, h, e, uw, uh))
        hits = []
        for bk, (arr, size, be) in Bg.items():
            bw, bh = size
            if bw > uw or bh > uh:
                continue
            # a piece of a big scene is itself big; skip the sprite noise
            if bw * bh < 0.05 * uw * uh:
                continue
            # only the four corners and the four edge midpoints are tried:
            # a cut of a scene starts on a tile boundary, not anywhere
            xs = sorted(set([0, uw - bw, max(0, (uw - bw) // 2)]))
            ys = sorted(set([0, uh - bh, max(0, (uh - bh) // 2)]))
            best = 1e9
            bestpos = None
            for x in xs:
                for y in ys:
                    d = rect_mad(up, arr, x, y)
                    if d < best:
                        best, bestpos = d, (x, y)
            if best < 12.0:
                hits.append((best, bk, size, bestpos, be))
        hits.sort()
        if len(hits) > 1:
            tiled += 1
        elif len(hits) == 1:
            single += 1
        area = 0
        for d, bk, size, pos, be in hits[:6]:
            area += size[0] * size[1]
            print("      1080 key %-11d %4dx%-4d at (%4d,%4d)  MAD %6.3f  %9d B"
                  % (bk, size[0], size[1], pos[0], pos[1], d, be))
        if hits:
            print("      pieces %d, covering %d of %d upscaled pixels  (%.2f %%)"
                  % (len(hits), area, uw * uh, 100.0 * area / (uw * uh)))
        else:
            print("      no 1080 member is a rectangle of this scene")
        print()
    print("of the %d largest 720 members: %d are cut into more than one 1080"
          % (n_big, tiled))
    print("member, %d survive as a single 1080 member." % single)
    return 0


def pair(root, k720, k1080):
    """One 720 member against one 1080 member, corner for corner.

    The 720 picture is upscaled 1.5x and its TOP-LEFT rectangle compared with
    the 1080 member; the RIGHT-hand rectangle of the same size is the control
    and must score far worse.  Then the archive is searched for members of
    exactly the complementary shape -- the columns and rows the 1080 version
    is missing."""
    A = load_all(root, A_NAME)
    B = load_all(root, B_NAME)
    a, _ea = A[k720]
    b, _eb = B[k1080]
    aw, ah = a.size
    bw, bh = b.size
    uw, uh = round(aw * 1.5), round(ah * 1.5)
    print("720  key %-11d %dx%d" % (k720, aw, ah))
    print("1080 key %-11d %dx%d" % (k1080, bw, bh))
    print("the 720 picture at 1.5x would be %d x %d" % (uw, uh))
    print("height matches 1.5x exactly : %s" % (bh == uh))
    print("width  matches 1.5x exactly : %s" % (bw == uw))
    missing_w, missing_h = uw - bw, uh - bh
    print("columns unaccounted for     : %d" % missing_w)
    print("rows unaccounted for        : %d" % missing_h)
    up = a.convert("RGB").resize((uw, uh), Image.BICUBIC)
    ua = np.asarray(up, dtype=np.float32)
    bb = np.asarray(b.convert("RGB"), dtype=np.float32)
    ch, cw = min(bh, uh), min(bw, uw)
    d1 = float(np.abs(ua[0:ch, 0:cw] - bb[0:ch, 0:cw]).mean())
    print("MAD, 720 upscaled TOP-LEFT vs the 1080 member : %.3f" % d1)
    if uw > bw:
        d2 = float(np.abs(ua[0:ch, uw - cw:uw] - bb[0:ch, 0:cw]).mean())
        print("MAD against the RIGHT-hand crop (control)     : %.3f" % d2)
        if d2 <= d1:
            print("*** the control did not lose; this pairing proves nothing ***")
    found = []
    for k, (im, e) in B.items():
        w, h = im.size
        if missing_w > 0 and abs(h - bh) <= 2 and abs(w - missing_w) <= 2:
            found.append((k, w, h, "the missing columns"))
        if missing_h > 0 and abs(w - bw) <= 2 and abs(h - missing_h) <= 2:
            found.append((k, w, h, "the missing rows"))
    print("1080 members of exactly the complementary shape : %d" % len(found))
    for k, w, h, why in found:
        print("   key %-12d %4dx%-4d   %s" % (k, w, h, why))
    return 0


def main():
    cmd, root = sys.argv[1], sys.argv[2]
    if cmd == "limit":
        return limit(root)
    if cmd == "pair":
        return pair(root, int(sys.argv[3]), int(sys.argv[4]))
    if cmd == "hunt":
        n = 12
        if "--n" in sys.argv:
            n = int(sys.argv[sys.argv.index("--n") + 1])
        return hunt(root, n)
    print(__doc__)


if __name__ == "__main__":
    main()
