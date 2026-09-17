#!/usr/bin/env python3
"""runexpect.py -- how many printable runs should a file of this entropy have
by chance, and how many does it have?

A compressed file yields printable runs. That is not evidence of surviving
text: 37 % of all byte values are printable ASCII, so runs of six appear by
accident about once every seven hundred bytes. The question is never "are
there runs" but "are there MORE runs than chance predicts", and that is one
line of arithmetic nobody in this collection had written down.

The model is the honest one for compressed data: bytes independent and
identically distributed with the file's OWN observed probability of being
printable, not with a uniform 95/256. A maximal run of length >= L begins at
position i when byte i-1 is not printable (or i is 0) and bytes i .. i+L-1 all
are, so

    E[runs of length >= L]  =  p**L * (1 + (N - L) * (1 - p))

`--uniform` also prints the 95/256 model, which is what somebody would use if
they did not look at the file.

The verdict is the RATIO. A ratio near 1 means the runs are chance and the file
holds no recoverable text; a ratio well above 1 means text survives and is
worth reading. This tool does not choose a threshold for you -- it prints the
ratio at every length asked for, because a single length can be a coincidence
and three agreeing cannot.

    python tools/runexpect.py _work/members/_INST32I.EX_
    python tools/runexpect.py _work/members/_INST32I.EX_ --lengths 4,5,6,8,10
    python tools/runexpect.py selftest
"""
import argparse
import collections
import math
import os
import random
import sys

LO, HI = 0x20, 0x7F


def observed_runs(data, lengths):
    """Count maximal printable runs, bucketed by the thresholds asked for.
    One pass, so the counts at different lengths are of the same runs."""
    out = dict((L, 0) for L in lengths)
    run = 0
    for x in data:
        if LO <= x < HI:
            run += 1
        else:
            for L in lengths:
                if run >= L:
                    out[L] += 1
            run = 0
    for L in lengths:
        if run >= L:
            out[L] += 1
    return out


def expected(n, p, L):
    if n < L:
        return 0.0
    return p ** L * (1.0 + (n - L) * (1.0 - p))


def entropy(counts, n):
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


def report(path, data, lengths, uniform):
    n = len(data)
    if n == 0:
        raise SystemExit("runexpect: %s is empty" % path)
    counts = collections.Counter(data)
    printable = sum(counts[x] for x in range(LO, HI))
    p = printable / n
    obs = observed_runs(data, lengths)
    print("file                       : %s" % path)
    print("bytes                      : %d" % n)
    print("distinct byte values       : %d of 256" % len(counts))
    print("Shannon entropy            : %.4f bits/byte" % entropy(counts, n))
    print("printable bytes 0x20..0x7E : %d" % printable)
    print("p(printable), from THIS file: %.6f   (a uniform model says %.6f)"
          % (p, 95.0 / 256.0))
    print()
    print("  %-4s %10s %14s %10s%s"
          % ("L", "observed", "expected", "obs/exp",
             "     uniform  obs/exp" if uniform else ""))
    for L in lengths:
        e = expected(n, p, L)
        row = "  %-4d %10d %14.1f %10.3f" % (L, obs[L], e,
                                             obs[L] / e if e else float("nan"))
        if uniform:
            eu = expected(n, 95.0 / 256.0, L)
            row += " %11.1f %8.3f" % (eu, obs[L] / eu if eu else 0.0)
        print(row)
    return obs, p


def cmd_selftest(args):
    checks = []
    rnd = random.Random(20260909)

    # Incompressible-looking data: the ratio must sit near 1.
    noise = bytes(rnd.randrange(256) for _ in range(200000))
    obs = observed_runs(noise, [6])
    e = expected(len(noise), sum(1 for b in noise if LO <= b < HI) / len(noise),
                 6)
    ratio = obs[6] / e
    checks.append(("uniform noise gives a ratio between 0.8 and 1.25",
                   0.8 < ratio < 1.25, "ratio %.3f on %d runs"
                   % (ratio, obs[6])))

    # Text buried in binary: the ratio must be enormous. The specimen has to
    # keep p LOW and the runs LONG, or the test passes for the wrong reason --
    # a specimen of pure text has p = 1, is one single run, and proves
    # nothing.
    text = (b"\x00" * 30 + b"HELLOWORLD") * 1000
    obs = observed_runs(text, [6])
    p = sum(1 for b in text if LO <= b < HI) / len(text)
    e = expected(len(text), p, 6)
    checks.append(("text buried in binary gives a ratio far above 1",
                   e > 0 and obs[6] / e > 50,
                   "p=%.4f expected=%.2f observed=%d ratio %.1f"
                   % (p, e, obs[6], obs[6] / e if e else 0)))

    # The run counter must be exact on a hand-made case.
    spec = b"abcdef\x00gh\x00ijklmnopq\x00"
    obs = observed_runs(spec, [2, 6, 9])
    ok = obs[2] == 3 and obs[6] == 2 and obs[9] == 1
    checks.append(("the run counter is exact on a hand-made specimen", ok,
                   str(obs)))

    # A run that ends at the end of the buffer must still be counted.
    obs = observed_runs(b"\x00abcdefgh", [6])
    checks.append(("a run touching the end of the file is counted",
                   obs[6] == 1, str(obs)))

    # A file with no printable byte at all must give zero, not a crash.
    obs = observed_runs(bytes(64), [6])
    checks.append(("a file with no printable byte gives zero runs",
                   obs[6] == 0, str(obs)))

    # The expectation must fall as L grows and must be zero for L > n.
    e5, e9 = expected(1000, 0.37, 5), expected(1000, 0.37, 9)
    checks.append(("the expectation falls as the length grows",
                   e9 < e5, "%.4f then %.6f" % (e5, e9)))
    checks.append(("a length longer than the file expects nothing",
                   expected(4, 0.37, 6) == 0.0, ""))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL",
                                   note))
        if not ok:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="a file, or the word selftest")
    ap.add_argument("--lengths", default="4,5,6,8,12")
    ap.add_argument("--uniform", action="store_true")
    args = ap.parse_args()
    if args.path == "selftest":
        return cmd_selftest(args)
    if not os.path.exists(args.path):
        raise SystemExit("runexpect: no such file: %s" % args.path)
    lengths = [int(x) for x in args.lengths.split(",")]
    report(args.path, open(args.path, "rb").read(), lengths, True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
