#!/usr/bin/env python3
"""bytecross.py -- compare two files byte for byte and report the shared
prefix, the shared suffix and every differing position.

Section 12 of the VIS platform notes has said, since before the first VIS
pipeline ran, that **the unit of sharing on this platform is smaller than a
file**, and three hash sweeps across three pressings have now returned zero
crossings out of 186, 1,314 and 1,013 distinct hashes. The 84-byte
`CONTROL.TAT` identity block is identical on six discs and no file-level list
will ever see it, because the file around it differs by a byte.

None of the 418 tools in this box does this comparison. This one does, and it
is deliberately dumb: it holds both files in memory, walks them, and prints
offsets.

    python tools/bytecross.py A B
    python tools/bytecross.py A B --limit 84        first 84 bytes only
    python tools/bytecross.py A B --max-diff 40     stop listing after 40

Exit status is 0 when the files are identical over the compared range and 1
when they are not, so a shell can tell the two apart without reading prose.
"""
import argparse
import os
import sys


def load(p):
    with open(p, "rb") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--limit", type=int, default=None,
                    help="compare only the first N bytes of each")
    ap.add_argument("--max-diff", type=int, default=25)
    args = ap.parse_args()

    A, B = load(args.a), load(args.b)
    print("A : %-58s %d bytes" % (args.a, len(A)))
    print("B : %-58s %d bytes" % (args.b, len(B)))
    if args.limit is not None:
        A, B = A[:args.limit], B[:args.limit]
        print("comparing the first %d bytes of each" % args.limit)

    n = min(len(A), len(B))
    pre = 0
    while pre < n and A[pre] == B[pre]:
        pre += 1
    suf = 0
    while suf < n - pre and A[len(A) - 1 - suf] == B[len(B) - 1 - suf]:
        suf += 1

    diffs = [i for i in range(n) if A[i] != B[i]]
    print("common prefix          : %d bytes" % pre)
    print("common suffix          : %d bytes" % suf)
    print("lengths equal          : %s" % (len(A) == len(B)))
    print("differing positions in the overlapping %d bytes : %d"
          % (n, len(diffs)))
    if len(A) != len(B):
        print("bytes only in the longer file                  : %d"
              % abs(len(A) - len(B)))
    for i in diffs[:args.max_diff]:
        ca = chr(A[i]) if 32 <= A[i] < 127 else "."
        cb = chr(B[i]) if 32 <= B[i] < 127 else "."
        print("  offset %6d (0x%04X)   A %02X %r   B %02X %r"
              % (i, i, A[i], ca, B[i], cb))
    if len(diffs) > args.max_diff:
        print("  ... %d more" % (len(diffs) - args.max_diff))

    same = (len(A) == len(B)) and not diffs
    print("VERDICT: %s" % ("IDENTICAL" if same else "DIFFERENT"))
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
