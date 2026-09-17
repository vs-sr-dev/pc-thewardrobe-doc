"""pixels.py -- the pixel geometry of the two graphics archives.

The question this answers is the one the file names cannot: when the same scene
exists at two sizes, is the bigger one the same picture with more pixels, or a
differently framed picture?

    dims  <root>   every WebP member's pixel dimensions, both archives
    area  <root>   total pixel area, and the ratio between the archives
    tiles <root>   members that hit the width/height clamp, which is where the
                   framing changes

Nothing is extracted; members are decoded in memory to read their header only.
"""
import os
import sys
import io
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table, extent, signature      # noqa: E402

from PIL import Image                                # noqa: E402

PAIR = ["graphics_720.vt7a", "graphics_1080.vt7a", "graphics_common.vt7a"]


def scan(root, arch):
    p = os.path.join(root, arch)
    n, ver, m2, count, recs = read_table(p)
    out = []
    with open(p, "rb") as fh:
        for r in sorted(recs, key=lambda x: x[1]):
            fh.seek(r[1])
            if signature(fh.read(16)) != "WebP":
                continue
            fh.seek(r[1])
            blob = fh.read(extent(r))
            try:
                im = Image.open(io.BytesIO(blob))
                w, h = im.size
            except Exception:                        # noqa: BLE001
                continue
            out.append((r[0], extent(r), w, h))
    return out


def dims(root):
    for arch in PAIR:
        d = scan(root, arch)
        ws = collections.Counter(x[2] for x in d)
        hs = collections.Counter(x[3] for x in d)
        print("== %s : %d WebP members" % (arch, len(d)))
        print("   widest  %d   tallest %d" % (max(ws), max(hs)))
        print("   members at the widest value  : %d" % ws[max(ws)])
        print("   members at the tallest value : %d" % hs[max(hs)])
        print("   ten commonest sizes:")
        sz = collections.Counter((x[2], x[3]) for x in d)
        for (w, h), c in sz.most_common(10):
            print("      %5d x %-5d %5d" % (w, h, c))
        print()


def area(root):
    print("Total pixel area.  If the 1080 archive is the 720 archive at 1.5x,")
    print("its area is 2.25x -- and if it is not, the difference is framing.")
    print()
    tot = {}
    for arch in ("graphics_720.vt7a", "graphics_1080.vt7a"):
        d = scan(root, arch)
        px = sum(x[2] * x[3] for x in d)
        by = sum(x[1] for x in d)
        tot[arch] = (len(d), px, by)
        print("%-22s %5d members  %16d pixels  %14d bytes  %8.4f B/px"
              % (arch, len(d), px, by, by / float(px)))
    a = tot["graphics_720.vt7a"]
    b = tot["graphics_1080.vt7a"]
    print()
    print("   member count ratio : %.4f  (1080 / 720)" % (b[0] / float(a[0])))
    print("   pixel area ratio   : %.4f  (2.2500 would be a clean 1.5x)"
          % (b[1] / float(a[1])))
    print("   byte ratio         : %.4f" % (b[2] / float(a[2])))
    print()
    print("   the shortfall against 2.25 is %.4f %% of the pixels a clean 1.5x"
          % (100.0 * (2.25 - b[1] / float(a[1])) / 2.25))
    print("   would have required.")


def tiles(root):
    print("The clamp.  A WebP member in these archives never exceeds a fixed")
    print("width and height; when a scene at 1080 would exceed it, the scene is")
    print("cut, and the cut is why a 1080 member can show LESS of a scene than")
    print("its 720 counterpart.")
    print()
    for arch in ("graphics_720.vt7a", "graphics_1080.vt7a"):
        d = scan(root, arch)
        mw = max(x[2] for x in d)
        mh = max(x[3] for x in d)
        atw = [x for x in d if x[2] == mw]
        ath = [x for x in d if x[3] == mh]
        both = [x for x in d if x[2] == mw and x[3] == mh]
        print("%-22s widest %d, tallest %d" % (arch, mw, mh))
        print("   members at the maximum width        : %4d of %d  (%.4f %%)"
              % (len(atw), len(d), 100.0 * len(atw) / len(d)))
        print("   members at the maximum height       : %4d of %d  (%.4f %%)"
              % (len(ath), len(d), 100.0 * len(ath) / len(d)))
        print("   members at BOTH maxima (square tile): %4d"
              % len(both))
        big = [x for x in d if x[2] * x[3] > 1000000]
        print("   members over one megapixel          : %4d, %d bytes"
              % (len(big), sum(x[1] for x in big)))
        print()


def main():
    cmd, root = sys.argv[1], sys.argv[2]
    if cmd == "dims":
        return dims(root)
    if cmd == "area":
        return area(root)
    if cmd == "tiles":
        return tiles(root)
    print(__doc__)


if __name__ == "__main__":
    main()
