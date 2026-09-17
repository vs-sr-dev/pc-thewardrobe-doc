#!/usr/bin/env python3
"""pairdiff.py -- diff two files or two regions and REPORT THE DIFFERENCE.

Written because of the standing lesson: a hash proves equality and does not
measure difference. Two sha1s that disagree tell you nothing about how far
apart the files are; this tells you, in bytes, in runs, and by listing the
individual changes when there are few enough to list.

Usage:
    pairdiff.py A B [--list N] [--runs]
"""
import argparse
import sys


def diff(a, b, list_n=32, show_runs=False):
    n = min(len(a), len(b))
    diffs = [i for i in range(n) if a[i] != b[i]]
    print("sizes %d and %d, compared over %d bytes" % (len(a), len(b), n))
    print("differing bytes: %d (%.6f%%)" % (len(diffs), 100.0 * len(diffs) / n if n else 0))
    if not diffs:
        print("IDENTICAL over the compared length")
        return diffs
    print("first difference at 0x%X, last at 0x%X" % (diffs[0], diffs[-1]))
    # contiguous runs
    runs = []
    start = prev = diffs[0]
    for i in diffs[1:]:
        if i == prev + 1:
            prev = i
            continue
        runs.append((start, prev))
        start = prev = i
    runs.append((start, prev))
    print("in %d contiguous run(s)" % len(runs))
    if show_runs and len(runs) <= 64:
        for s, e in runs:
            print("   run 0x%08X..0x%08X  (%d bytes)" % (s, e, e - s + 1))
    if len(diffs) <= list_n:
        for i in diffs:
            print("   0x%08X  %02X -> %02X" % (i, a[i], b[i]))
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", type=int, default=32)
    ap.add_argument("--runs", action="store_true")
    ap.add_argument("a")
    ap.add_argument("b")
    args = ap.parse_args()
    with open(args.a, "rb") as fh:
        a = fh.read()
    with open(args.b, "rb") as fh:
        b = fh.read()
    diff(a, b, args.list, args.runs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
