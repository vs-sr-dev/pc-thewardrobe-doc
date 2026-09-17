#!/usr/bin/env python3
"""sdkdiff.py -- two versions of the same operating system, fourteen months apart.

Portfolio OS is pressed onto every 3DO disc by the SDK's disc builder, and no
game references it: the console boots from it. That makes `/System/` a dated
sample of the SDK rather than of the studio, and two discs from different
studios give a version diff that neither disc could give alone.

No other platform in this collection has ever had two copies of the same
operating system to compare.

The tool takes two extracted file trees and reports, per category:

    identical      byte for byte, same path, same SHA-1
    changed        same path, different bytes -- with the size delta
    only in A      present on the older disc, gone from the newer
    only in B      new

Categories are the directory under /System/, so that "what changed" can be
answered as "the DSP instruments did, the folios did, the kernel did".

usage: sdkdiff.py TREE_A TREE_B [--sub System]
"""
import argparse
import hashlib
import os


def collect(tree, sub):
    """path (case-folded, relative to the subtree) -> (realpath, size, sha1)."""
    out = {}
    base = None
    for name in os.listdir(tree):
        if name.lower() == sub.lower():
            base = os.path.join(tree, name)
    if base is None:
        raise SystemExit("sdkdiff: no %s under %s" % (sub, tree))
    for dp, dn, fn in os.walk(base):
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, base).replace(os.sep, "/")
            d = open(p, "rb").read()
            out[rel.lower()] = (rel, len(d), hashlib.sha1(d).hexdigest())
    return out


def category(rel):
    parts = rel.split("/")
    return parts[0] if len(parts) > 1 else "(top level)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--sub", default="System")
    ap.add_argument("--names", action="store_true",
                    help="list every file, not only the summary")
    ar = ap.parse_args()

    A = collect(ar.a, ar.sub)
    B = collect(ar.b, ar.sub)

    same, changed, onlya, onlyb = [], [], [], []
    for k in sorted(set(A) | set(B)):
        if k in A and k in B:
            (ra, sa, ha), (rb, sb, hb) = A[k], B[k]
            (same if ha == hb else changed).append((ra, rb, sa, sb))
        elif k in A:
            onlya.append(A[k])
        else:
            onlyb.append(B[k])

    print("A = %s   %d files, %d bytes"
          % (ar.a, len(A), sum(v[1] for v in A.values())))
    print("B = %s   %d files, %d bytes"
          % (ar.b, len(B), sum(v[1] for v in B.values())))
    print()
    print("identical (byte for byte) : %d" % len(same))
    print("present on both, changed  : %d" % len(changed))
    print("only on A (removed)       : %d" % len(onlya))
    print("only on B (added)         : %d" % len(onlyb))
    print()

    cats = {}
    for ra, rb, sa, sb in same:
        cats.setdefault(category(ra), [0, 0, 0, 0, 0])[0] += 1
    for ra, rb, sa, sb in changed:
        c = cats.setdefault(category(ra), [0, 0, 0, 0, 0])
        c[1] += 1
        c[4] += sb - sa
    for r, s, h in onlya:
        cats.setdefault(category(r), [0, 0, 0, 0, 0])[2] += 1
    for r, s, h in onlyb:
        cats.setdefault(category(r), [0, 0, 0, 0, 0])[3] += 1

    print("%-22s %6s %8s %8s %7s %12s"
          % ("category", "same", "changed", "removed", "added", "byte delta"))
    for k in sorted(cats):
        c = cats[k]
        print("%-22s %6d %8d %8d %7d %+12d" % (k, c[0], c[1], c[2], c[3], c[4]))
    tot = [sum(c[i] for c in cats.values()) for i in range(5)]
    print("%-22s %6d %8d %8d %7d %+12d"
          % ("TOTAL", tot[0], tot[1], tot[2], tot[3], tot[4]))
    print()
    print("bytes on A %d, on B %d, growth %+d = %+.4f %%"
          % (sum(v[1] for v in A.values()), sum(v[1] for v in B.values()),
             sum(v[1] for v in B.values()) - sum(v[1] for v in A.values()),
             100.0 * (sum(v[1] for v in B.values())
                      - sum(v[1] for v in A.values()))
             / sum(v[1] for v in A.values())))

    print()
    print("THE TEN LARGEST SIZE CHANGES")
    for ra, rb, sa, sb in sorted(changed, key=lambda x: -abs(x[3] - x[2]))[:10]:
        print("  %-30s %8d -> %8d  %+d" % (ra, sa, sb, sb - sa))

    print()
    print("IDENTICAL, BYTE FOR BYTE -- the same file pressed by two studios")
    for ra, rb, sa, sb in same:
        print("  %-30s %8d" % (ra, sa))

    if ar.names:
        print()
        print("ONLY ON B")
        for r, s, h in onlyb:
            print("  %-30s %8d" % (r, s))
        print()
        print("ONLY ON A")
        for r, s, h in onlya:
            print("  %-30s %8d" % (r, s))
        print()
        print("CHANGED")
        for ra, rb, sa, sb in changed:
            print("  %-30s %8d -> %8d  %+d" % (ra, sa, sb, sb - sa))


if __name__ == "__main__":
    main()
