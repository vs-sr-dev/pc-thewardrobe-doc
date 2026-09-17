#!/usr/bin/env python3
"""entropy.py -- how much of an image is opaque, and which files make it so.

Two numbers get confused whenever entropy is quoted about a disc. The entropy
**of the file as a whole** is one distribution over 640 million bytes and tends
to a middling value whatever the disc holds. The entropy **of a block** is what
tells you where the compressed material is, and the useful summary is not the
mean of the block entropies but the *fraction of blocks above a threshold*,
because that is a count of how much of the object is closed to inspection.

This computes both, over an image or a tree, plus the byte histogram, and then
attributes the high-entropy blocks to the files that occupy them -- which the
image-level number alone cannot do.

    python tools/entropy.py IMAGE
    python tools/entropy.py IMAGE --block 65536 --threshold 7.5
    python tools/entropy.py DIR --tree
    python tools/entropy.py DIR --tree --by-ext
"""

import argparse
import collections
import math
import os

import numpy as np


def block_entropies(path, block):
    ents = []
    hist = np.zeros(256, dtype=np.int64)
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(block)
            if not buf:
                break
            a = np.frombuffer(buf, dtype=np.uint8)
            c = np.bincount(a, minlength=256)
            hist += c
            p = c[c > 0] / len(a)
            ents.append(float(-(p * np.log2(p)).sum()))
    return np.array(ents), hist


def whole(hist):
    n = hist.sum()
    p = hist[hist > 0] / n
    return float(-(p * np.log2(p)).sum()), n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--block", type=int, default=65536)
    ap.add_argument("--threshold", type=float, default=7.5)
    ap.add_argument("--tree", action="store_true")
    ap.add_argument("--by-ext", action="store_true")
    a = ap.parse_args()

    if not a.tree and os.path.isdir(a.path):
        # Without this, the single-file path below opens a directory and the
        # user gets a bare PermissionError from the OS, which reads like a
        # broken tool rather than like a wrong argument. The tool is not
        # broken; it wants --tree.
        ap.error("%s is a directory. This tool measures one file unless you "
                 "pass --tree, which walks every file under a root and reports "
                 "per extension. Re-run with --tree." % a.path)

    if not a.tree:
        ents, hist = block_entropies(a.path, a.block)
        h, n = whole(hist)
        print("file                 : %s" % os.path.basename(a.path))
        print("bytes                : %d" % n)
        print("entropy of the whole : %.4f bits" % h)
        print("blocks of %d      : %d" % (a.block, len(ents)))
        print("  mean               : %.4f" % ents.mean())
        print("  minimum            : %.4f" % ents.min())
        print("  maximum            : %.4f" % ents.max())
        print("  median             : %.4f" % float(np.median(ents)))
        over = int((ents > a.threshold).sum())
        print("  above %.1f           : %d  (%.2f %%)"
              % (a.threshold, over, 100.0 * over / len(ents)))
        for t in (6.0, 7.0, 7.5, 7.9, 7.99):
            k = int((ents > t).sum())
            print("    above %-5.2f       : %6d  (%6.2f %%)"
                  % (t, k, 100.0 * k / len(ents)))
        print()
        print("byte histogram, top 8:")
        order = np.argsort(-hist)
        for i in order[:8]:
            print("   0x%02X  %12d   %.2f %%" % (i, hist[i], 100.0 * hist[i] / n))
        print("   distinct byte values present : %d" % int((hist > 0).sum()))
        return

    rows = []
    byext = collections.defaultdict(lambda: [0, 0, 0, 0.0])
    for dp, dn, fn in os.walk(a.path):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            sz = os.path.getsize(p)
            if sz == 0:
                # A zero-length file has no entropy and used to be dropped
                # here, silently, which made this tool's `files` line
                # disagree with `hashall.py`'s. Two sessions diagnosed that
                # and neither could prove it; pc-karmaflow-doc has exactly 17
                # zero-length files and the discrepancy was exactly 17.
                # It is now counted, with a zero row, and the population
                # matches.
                rows.append((os.path.relpath(p, a.path), 0, 0.0, 0, 0))
                e = byext[os.path.splitext(f)[1].upper() or "(none)"]
                e[0] += 1
                continue
            ents, hist = block_entropies(p, a.block)
            h, n = whole(hist)
            over = int((ents > a.threshold).sum())
            rows.append((os.path.relpath(p, a.path), sz, h, len(ents), over))
            e = byext[os.path.splitext(f)[1].upper() or "(none)"]
            e[0] += 1
            e[1] += sz
            e[2] += over
            e[3] += h * sz
    tot = sum(r[1] for r in rows)
    print("files                : %d" % len(rows))
    print("bytes                : %d" % tot)
    print("blocks above %.1f     : %d of %d"
          % (a.threshold, sum(r[4] for r in rows), sum(r[3] for r in rows)))
    print()
    print("%-8s %6s %14s %9s %8s %9s"
          % ("ext", "files", "bytes", "pct", "blk>thr", "mean H"))
    for e, v in sorted(byext.items(), key=lambda kv: -kv[1][1]):
        print("%-8s %6d %14d %8.4f %% %8d %9.4f"
              % (e, v[0], v[1], 100.0 * v[1] / tot, v[2],
                 v[3] / v[1] if v[1] else 0))
    if a.by_ext:
        return
    print()
    print("the twelve files with the most blocks above the threshold:")
    for r in sorted(rows, key=lambda r: -r[4])[:12]:
        print("   %-46s %11d  %5d/%-5d  H %.4f" % (r[0], r[1], r[4], r[3], r[2]))


if __name__ == "__main__":
    main()
