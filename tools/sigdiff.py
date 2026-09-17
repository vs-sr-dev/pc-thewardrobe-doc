#!/usr/bin/env python3
"""sigdiff.py -- /signatures, the fixed-size region both 3DO discs carry.

Disc one has `/SIGNATURES`, disc two has `/signatures`, and they are the same
size to the byte: 335,872 = 164 blocks of 2,048. That is not a coincidence and
the question is what part of the two files is common.

The comparison that matters is against the noise floor. Two independent random
byte streams agree on 1/256 of their bytes = 0.3906 %. Anything far above that
is structure; and WHERE the agreement is matters more than how much, so the
runs of consecutive equal bytes are counted, not only the total.

usage: sigdiff.py FILE_A FILE_B
"""
import collections
import math
import sys


def entropy(d):
    c = collections.Counter(d)
    n = float(len(d))
    return -sum(v / n * math.log(v / n, 2) for v in c.values())


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        raise SystemExit(2)
    A = open(sys.argv[1], "rb").read()
    B = open(sys.argv[2], "rb").read()

    print("A  %-50s %d bytes" % (sys.argv[1], len(A)))
    print("B  %-50s %d bytes" % (sys.argv[2], len(B)))
    if len(A) != len(B):
        print("different sizes; comparing the first %d bytes" % min(len(A), len(B)))
    n = min(len(A), len(B))
    print("   %d bytes = %.4f blocks of 2048" % (n, n / 2048.0))
    print()

    same = sum(1 for i in range(n) if A[i] == B[i])
    print("bytes equal           : %d = %.4f %%" % (same, 100.0 * same / n))
    print("chance floor, 1 in 256: %.4f %%" % (100.0 / 256))
    print("times the noise floor : %.2f" % ((100.0 * same / n) / (100.0 / 256)))
    print()

    runs = []
    cur = 0
    start = 0
    for i in range(n):
        if A[i] == B[i]:
            if cur == 0:
                start = i
            cur += 1
        elif cur:
            runs.append((cur, start))
            cur = 0
    if cur:
        runs.append((cur, start))
    runs.sort(reverse=True)
    big = [r for r in runs if r[0] >= 8]
    print("runs of equal bytes   : %d" % len(runs))
    print("  longest             : %d bytes at offset %d" % runs[0])
    print("  runs of 8 or more   : %d, covering %d bytes = %.2f %% of the matches"
          % (len(big), sum(r[0] for r in big),
             100.0 * sum(r[0] for r in big) / same))
    print("  the ten longest     :")
    for ln, off in runs[:10]:
        print("      %6d bytes at offset %6d   (block %d)" % (ln, off, off // 2048))
    print()

    lz_a = len(A) - len(A.lstrip(b"\x00"))
    lz_b = len(B) - len(B.lstrip(b"\x00"))
    print("leading zero bytes    : A %d, B %d" % (lz_a, lz_b))
    print("entropy               : A %.4f, B %.4f bits per byte"
          % (entropy(A), entropy(B)))
    print("printable runs of 4+  : A %d, B %d"
          % (sum(1 for _ in __import__("re").finditer(rb"[ -~]{4,}", A)),
             sum(1 for _ in __import__("re").finditer(rb"[ -~]{4,}", B))))
    print()

    # per-block agreement: is the agreement spread or concentrated?
    print("PER-BLOCK AGREEMENT (2,048 bytes each), the blocks above 5 %%:")
    hits = 0
    for b in range(n // 2048):
        s = sum(1 for i in range(b * 2048, (b + 1) * 2048) if A[i] == B[i])
        if s > 2048 * 0.05:
            hits += 1
            if hits <= 20:
                print("   block %3d : %5d of 2048 = %6.2f %%"
                      % (b, s, 100.0 * s / 2048))
    print("   %d blocks of %d agree on more than 5 %% of their bytes"
          % (hits, n // 2048))


if __name__ == "__main__":
    main()
