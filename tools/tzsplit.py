#!/usr/bin/env python3
"""tzsplit.py -- read the build machines' time zones out of two clocks.

A PE carries a COFF TimeDateStamp, which the standard defines as seconds since
the Unix epoch **in UTC**. An ISO 9660 directory record carries a recording
date, which the mastering program copied from the file's timestamp on the
volume it read -- and on FAT that timestamp is **local wall-clock time on the
machine that wrote the file**, with no zone attached.

Subtract one from the other and what is left is the UTC offset of the machine
that produced the binary, plus however long elapsed between the linker starting
and the file being closed. The elapsed time is seconds; the offset is hours. So
the difference, rounded to the nearest quarter-hour, is a time zone, and files
built in different places fall into different buckets.

This is not a general property of discs. It works here because the recording
dates on this volume are the original file mtimes rather than the burn time,
which is itself a measurement -- see the seconds-parity test in `recdates.py`.

    python tools/tzsplit.py CLOCKS.TSV
    python tools/tzsplit.py CLOCKS.TSV --bucket +7:00

Input is the TSV written by `threeclocks.py --tsv`, whose columns are
path, size, clockA (the directory record), kind, clockB (the internal clock).
"""

import argparse
import collections
import csv
import datetime


def parse(s):
    s = (s or "").strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def qh(delta):
    """Round a timedelta to the nearest quarter hour and render it."""
    secs = delta.total_seconds()
    q = round(secs / 900.0)
    total = q * 15
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return "%s%d:%02d" % (sign, total // 60, total % 60)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tsv")
    ap.add_argument("--bucket")
    ap.add_argument("--max-slack", type=int, default=600,
                    help="seconds of link-to-write slack allowed before a row "
                         "is called unexplained by a zone alone")
    a = ap.parse_args()

    rows = []
    with open(a.tsv, encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            A = parse(r["clockA"])
            B = parse(r["clockB"])
            if A and B:
                rows.append((r["path"], int(r["size"]), A, B, B - A))

    print("binaries with both clocks : %d" % len(rows))
    print()

    buckets = collections.Counter(qh(d) for _, _, _, _, d in rows)
    print("-- rounded to the quarter hour: B (COFF, UTC) minus A (record) ------")
    print("  %-8s %6s   %s" % ("offset", "files", "what the offset would mean"))
    for k, n in sorted(buckets.items(), key=lambda kv: -kv[1]):
        print("  %-8s %6d" % (k, n))
    print()

    for k, _ in sorted(buckets.items(), key=lambda kv: -kv[1]):
        sel = [r for r in rows if qh(r[4]) == k]
        secs = [r[4].total_seconds() for r in sel]
        exact = sum(1 for s in secs
                    if abs(s - round(s / 900.0) * 900) <= a.max_slack)
        dirs = collections.Counter(r[0].rsplit("/", 1)[0] if "/" in r[0]
                                   else "(root)" for r in sel)
        print("-- bucket %s : %d files, %d within %d s of the exact offset"
              % (k, len(sel), exact, a.max_slack))
        for d, n in dirs.most_common(8):
            print("     %-45s %4d" % (d, n))
        lo = min(secs)
        hi = max(secs)
        print("     residual spread: %.0f s .. %.0f s" % (lo, hi))
        print()

    if a.bucket:
        sel = [r for r in rows if qh(r[4]) == a.bucket]
        print("-- every file in bucket %s --" % a.bucket)
        for p, sz, A, B, d in sorted(sel, key=lambda r: r[0]):
            print("  %-50s %9d  A %s  B %s  %+.0f s"
                  % (p, sz, A, B, d.total_seconds()))


if __name__ == "__main__":
    main()
