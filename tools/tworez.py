"""tworez.py -- decide whether graphics_720.vt7a and graphics_1080.vt7a hold
the same pictures at two sizes.

The two archives share not one key and not one byte, so the question cannot be
answered from the table.  It is answered from the pixels: every WebP member of
each archive is decoded in memory, reduced to an NxN greyscale fingerprint with
the aspect ratio normalised away, and matched all-against-all against the other
archive.  Nothing is written to disk and nothing is extracted.

    match <root> [--grid N] [--thresh T]

A pair is called the same picture when the mean absolute difference of their
fingerprints is below the threshold.  Two controls run alongside:

    * the same measurement with the partners shuffled, which must NOT match;
    * the same measurement of each archive against ITSELF, which tells us how
      many pictures in one archive are near-copies of each other and therefore
      how much of the match rate is the fingerprint being too coarse.

    python tools/tworez.py match "<root>"
"""
import os
import sys
import io
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table, extent, signature      # noqa: E402

import numpy as np                                   # noqa: E402
from PIL import Image                                # noqa: E402

A = "graphics_720.vt7a"
B = "graphics_1080.vt7a"


def fingerprints(root, arch, grid):
    p = os.path.join(root, arch)
    n, ver, m2, count, recs = read_table(p)
    keys, sizes, exts, fps = [], [], [], []
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
            keys.append(r[0])
            sizes.append(im.size)
            exts.append(extent(r))
            small = im.convert("L").resize((grid, grid), Image.BILINEAR)
            fps.append(np.asarray(small, dtype=np.float32).ravel())
    return keys, sizes, exts, np.stack(fps)


def nearest(fa, fb):
    """For each row of fa, the index and MAD of the closest row of fb."""
    idx = np.empty(len(fa), dtype=np.int64)
    dist = np.empty(len(fa), dtype=np.float32)
    step = 64
    for i in range(0, len(fa), step):
        blk = fa[i:i + step]
        d = np.abs(blk[:, None, :] - fb[None, :, :]).mean(axis=2)
        idx[i:i + step] = d.argmin(axis=1)
        dist[i:i + step] = d.min(axis=1)
    return idx, dist


def match(root, grid, thresh):
    print("Deciding the two graphics archives on pixels, not on names.")
    print("%dx%d greyscale fingerprint, aspect normalised away, all-against-all."
          % (grid, grid))
    print("A pair is the same picture when mean absolute difference < %.1f"
          % thresh)
    print()
    ka, sa, ea, fa = fingerprints(root, A, grid)
    kb, sb, eb, fb = fingerprints(root, B, grid)
    print("WebP members decoded : %-22s %d" % (A, len(ka)))
    print("                       %-22s %d" % (B, len(kb)))
    print()

    idx, dist = nearest(fa, fb)
    good = dist < thresh
    print("== 720 -> 1080 ==")
    print("   720 members with a 1080 partner under threshold : %d of %d  (%.4f %%)"
          % (good.sum(), len(ka), 100.0 * good.sum() / len(ka)))
    print("   distinct 1080 members claimed                   : %d of %d"
          % (len(set(idx[good].tolist())), len(kb)))
    ds = np.sort(dist)
    print("   MAD distribution:")
    for q in (0, 10, 25, 50, 75, 90, 95, 99, 100):
        print("      p%-3d %8.4f" % (q, ds[min(len(ds) - 1, q * len(ds) // 100)]))
    print()

    ridx, rdist = nearest(fb, fa)
    rgood = rdist < thresh
    print("== 1080 -> 720 ==")
    print("   1080 members with a 720 partner under threshold  : %d of %d  (%.4f %%)"
          % (rgood.sum(), len(kb), 100.0 * rgood.sum() / len(kb)))
    print("   1080 members with NO partner                     : %d"
          % (len(kb) - rgood.sum()))
    print()

    # the scale factor of the matched pairs
    print("== the scale factor of the matched pairs ==")
    ratios = collections.Counter()
    for i in np.nonzero(good)[0]:
        wa, ha = sa[i]
        wb, hb = sb[idx[i]]
        ratios["%.3f" % (wb / float(wa))] += 1
    for k, v in ratios.most_common(10):
        print("   width ratio %-8s %6d pairs" % (k, v))
    print()
    print("   sample of matched pairs, largest first:")
    order = sorted(np.nonzero(good)[0], key=lambda i: -ea[i])[:8]
    for i in order:
        j = idx[i]
        print("      720 key %-11d %4dx%-4d %9d B   ->   1080 key %-11d %4dx%-4d %9d B   MAD %6.3f"
              % (ka[i], sa[i][0], sa[i][1], ea[i],
                 kb[j], sb[j][0], sb[j][1], eb[j], dist[i]))
    print()

    print("== CONTROL 1: the partners shuffled one position along ==")
    shuf = (idx + 1) % len(kb)
    cd = np.abs(fa - fb[shuf]).mean(axis=1)
    print("   shuffled pairs 'matching' : %d of %d  (%.4f %%)"
          % ((cd < thresh).sum(), len(cd), 100.0 * (cd < thresh).sum() / len(cd)))
    print("   shuffled median MAD       : %.4f" % float(np.median(cd)))
    if (cd < thresh).mean() > 0.10:
        print("   *** the control matched too often; the threshold is too loose ***")
    print()

    print("== CONTROL 2: each archive against itself, excluding the identity ==")
    for label, f in ((A, fa), (B, fb)):
        n = len(f)
        best = np.full(n, np.inf, dtype=np.float32)
        step = 64
        for i in range(0, n, step):
            blk = f[i:i + step]
            d = np.abs(blk[:, None, :] - f[None, :, :]).mean(axis=2)
            for k in range(blk.shape[0]):
                d[k, i + k] = np.inf
            best[i:i + step] = d.min(axis=1)
        print("   %-22s members that are near-copies of another member of the"
              " SAME archive: %d of %d  (%.4f %%)"
              % (label, (best < thresh).sum(), n,
                 100.0 * (best < thresh).sum() / n))
    print()

    b720 = sum(ea)
    b1080 = sum(eb)
    gb = sum(ea[i] for i in np.nonzero(good)[0])
    print("== bytes ==")
    print("   WebP bytes in %-22s %14d" % (A, b720))
    print("   WebP bytes in %-22s %14d" % (B, b1080))
    print("   720 WebP bytes that are a smaller copy of a 1080 WebP: %d  (%.4f %% of the 720 WebP)"
          % (gb, 100.0 * gb / b720))
    return 0


def main():
    root = sys.argv[2]
    grid, thresh = 16, 8.0
    if "--grid" in sys.argv:
        grid = int(sys.argv[sys.argv.index("--grid") + 1])
    if "--thresh" in sys.argv:
        thresh = float(sys.argv[sys.argv.index("--thresh") + 1])
    return match(root, grid, thresh)


if __name__ == "__main__":
    sys.exit(main())
