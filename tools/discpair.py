#!/usr/bin/env python3
"""discpair.py -- how much of disc A is disc B, directory by directory.

`discdiff.py` answers "is any file on this disc also on that one" and prints a
flat hit list. That was the right shape while the answer was a handful of
third-party runtimes. It is the wrong shape for a product shipped as two CDs,
where the answer is more than half of each disc and the interesting question is
*where* the duplication sits.

This tool partitions the union of two trees into exactly four disjoint classes
and proves the partition closes:

    identical      same content hash, present on both
    same-name      same path, different content
    only-A         path present on A and not on B
    only-B         path present on B and not on A

Paths are compared after an optional rename map, because a two-disc game names
its scenario directory after the scenario: `PL0` on one disc is the structural
counterpart of `PL1` on the other, and comparing them as different names would
report a hundred percent divergence between two directories that are 8 % the
same. The map is given on the command line and printed in the output, so the
reader can see which comparison was made.

    python tools/discpair.py A B
    python tools/discpair.py A B --map PL0=PL,PL1=PL --map-dir EMD0=EMD,EMD1=EMD
    python tools/discpair.py A B --map PL0=PL,PL1=PL --list same-name
    python tools/discpair.py A B --top-dir      # roll up to the first path element

Two things it refuses to do. It never reports an identical-file count without
also reporting the number of files it hashed on each side, because "1,696
shared" means nothing without "of 2,194 and 2,224". And it asserts the closure
`identical + same-name + only-A == files(A)` and the mirror for B, and dies if
either fails -- a comparator whose classes do not partition its input is a
comparator that has silently dropped something.

No constant in this file belongs to any particular disc.
"""

import argparse
import hashlib
import os
import sys
from collections import defaultdict


def index(root, rename):
    """path -> (sha1, size), with the first path element optionally renamed."""
    out = {}
    root = root.rstrip("/").rstrip(chr(92))
    for dp, dns, fns in os.walk(root):
        dns.sort()
        for name in sorted(fns):
            p = os.path.join(dp, name)
            rel = os.path.relpath(p, root).replace(chr(92), "/")
            parts = rel.split("/")
            parts = [rename.get(x, x) for x in parts]
            rel = "/".join(parts)
            h = hashlib.sha1()
            n = 0
            with open(p, "rb") as fh:
                while True:
                    b = fh.read(1 << 22)
                    if not b:
                        break
                    n += len(b)
                    h.update(b)
            out[rel] = (h.hexdigest(), n)
    return out


def group(path, top_dir):
    parts = path.split("/")
    if len(parts) == 1:
        return "(root)"
    return parts[0] if top_dir else "/".join(parts[:-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--map", default="",
                    help="comma-separated OLD=NEW path-element renames")
    ap.add_argument("--top-dir", action="store_true",
                    help="roll up to the first path element instead of the "
                         "full parent directory")
    ap.add_argument("--list", choices=["identical", "same-name",
                                       "only-a", "only-b"])
    ap.add_argument("--tsv")
    args = ap.parse_args()

    rename = {}
    for pair in args.map.split(","):
        if pair.strip():
            old, new = pair.split("=", 1)
            rename[old] = new

    A = index(args.a, rename)
    B = index(args.b, rename)

    ident, samename, onlya, onlyb = [], [], [], []
    for p, (h, n) in sorted(A.items()):
        if p not in B:
            onlya.append((p, n))
        elif B[p][0] == h:
            ident.append((p, n))
        else:
            samename.append((p, n, B[p][1]))
    for p, (h, n) in sorted(B.items()):
        if p not in A:
            onlyb.append((p, n))

    # The partition must close. A comparator that loses a file is worthless.
    assert len(ident) + len(samename) + len(onlya) == len(A), (
        "A does not partition: %d + %d + %d != %d" % (
            len(ident), len(samename), len(onlya), len(A)))
    assert len(ident) + len(samename) + len(onlyb) == len(B), (
        "B does not partition: %d + %d + %d != %d" % (
            len(ident), len(samename), len(onlyb), len(B)))

    ba = sum(n for _, n in A.values() if True) if False else sum(
        v[1] for v in A.values())
    bb = sum(v[1] for v in B.values())
    bi = sum(n for _, n in ident)

    print("A: %s" % args.a)
    print("B: %s" % args.b)
    if rename:
        print("path-element renames applied: %s" % ", ".join(
            "%s->%s" % kv for kv in sorted(rename.items())))
    print()
    print("files hashed        A %7d   B %7d" % (len(A), len(B)))
    print("bytes               A %12d   B %12d" % (ba, bb))
    print()
    print("identical by hash   %7d files  %12d bytes"
          "   = %.4f %% of A, %.4f %% of B" % (
              len(ident), bi, 100.0 * bi / ba, 100.0 * bi / bb))
    print("same name, differs  %7d files  A %d bytes, B %d bytes" % (
        len(samename), sum(x[1] for x in samename),
        sum(x[2] for x in samename)))
    print("only on A           %7d files  %12d bytes" % (
        len(onlya), sum(n for _, n in onlya)))
    print("only on B           %7d files  %12d bytes" % (
        len(onlyb), sum(n for _, n in onlyb)))
    print()
    print("union of distinct content: %d bytes" % (ba + bb - bi))
    print()

    rows = defaultdict(lambda: [0, 0, 0, 0, 0, 0, 0, 0])
    for p, n in ident:
        r = rows[group(p, args.top_dir)]
        r[0] += 1
        r[1] += n
    for p, n, m in samename:
        r = rows[group(p, args.top_dir)]
        r[2] += 1
        r[3] += n
    for p, n in onlya:
        r = rows[group(p, args.top_dir)]
        r[4] += 1
        r[5] += n
    for p, n in onlyb:
        r = rows[group(p, args.top_dir)]
        r[6] += 1
        r[7] += n

    print("%-28s %6s %13s %6s %6s %13s %6s %13s" % (
        "directory", "same", "bytes", "diff", "onlyA", "bytes", "onlyB",
        "bytes"))
    for k in sorted(rows):
        r = rows[k]
        print("%-28s %6d %13d %6d %6d %13d %6d %13d" % (
            k, r[0], r[1], r[2], r[4], r[5], r[6], r[7]))

    if args.list:
        print()
        print("--- %s ---" % args.list)
        src = {"identical": [(p, n) for p, n in ident],
               "same-name": [(p, n) for p, n, _ in samename],
               "only-a": onlya, "only-b": onlyb}[args.list]
        for p, n in src:
            print("%12d  %s" % (n, p))

    if args.tsv:
        with open(args.tsv, "w", encoding="utf-8") as fh:
            fh.write("class\tsize_a\tsize_b\tpath\n")
            for p, n in ident:
                fh.write("identical\t%d\t%d\t%s\n" % (n, n, p))
            for p, n, m in samename:
                fh.write("same-name\t%d\t%d\t%s\n" % (n, m, p))
            for p, n in onlya:
                fh.write("only-a\t%d\t\t%s\n" % (n, p))
            for p, n in onlyb:
                fh.write("only-b\t\t%d\t%s\n" % (n, p))
        print()
        print("wrote %s" % args.tsv)


if __name__ == "__main__":
    main()
