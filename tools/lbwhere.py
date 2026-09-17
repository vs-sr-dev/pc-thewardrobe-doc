#!/usr/bin/env python3
"""lbwhere.py -- say which archive member a byte offset falls in, and show it.

`buildpaths.py` reports 607 absolute paths beginning `R:` and tells you which
`.dat` they are in. That is not enough to decide whether they are one string or
six hundred: a `.dat` is a container, and the question is which **member** each
hit lands in, how many distinct members are involved, and what the bytes on
either side look like. This maps offsets back onto the member table `lbarc.py`
produced and prints the neighbourhood, so the decision is made by reading rather
than by counting.

    python tools/lbwhere.py _work/members.tsv "<root>" --search "R:\\data" --archive ED6_DT0A
    python tools/lbwhere.py _work/members.tsv "<root>" --offset 1234567 --archive ED6_DT0A
"""
import argparse
import bisect
import collections
import csv
import os
import re
import sys


def load(tsv):
    per = collections.defaultdict(list)
    with open(tsv, encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            per[r["archive"]].append((int(r["offset"]), int(r["packed"]), r["name"],
                                      r["iso"], int(r["slot"])))
    for k in per:
        per[k].sort()
    assert per, "no members read from %s" % tsv
    return per


def locate(members, off):
    starts = [m[0] for m in members]
    i = bisect.bisect_right(starts, off) - 1
    if i < 0:
        return None
    o, ln, name, iso, slot = members[i]
    if off < o + ln:
        return members[i], off - o
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tsv")
    ap.add_argument("root")
    ap.add_argument("--archive", required=True)
    ap.add_argument("--search", default=None, help="literal byte string to find")
    ap.add_argument("--offset", type=int, default=None)
    ap.add_argument("--context", type=int, default=24)
    ap.add_argument("--max", type=int, default=40, help="how many hits to print in full")
    a = ap.parse_args()

    per = load(a.tsv)
    assert a.archive in per, "%s is not an archive in %s" % (a.archive, a.tsv)
    members = per[a.archive]
    path = os.path.join(a.root, a.archive + ".dat")
    blob = open(path, "rb").read()
    print("archive           : %s, %d bytes, %d members" % (a.archive, len(blob), len(members)))

    hits = []
    if a.offset is not None:
        hits = [a.offset]
    else:
        assert a.search, "give --search or --offset"
        pat = a.search.encode("latin-1")
        i = blob.find(pat)
        while i >= 0:
            hits.append(i)
            i = blob.find(pat, i + 1)
        print("pattern           : %r" % pat)
    print("hits              : %d" % len(hits))

    inside = collections.Counter()
    outside = 0
    for off in hits:
        got = locate(members, off)
        if got is None:
            outside += 1
        else:
            (mo, ml, name, iso, slot), rel = got
            inside[(name, slot, ml, iso)] += 1
    print("hits inside a member : %d, in %d distinct members"
          % (sum(inside.values()), len(inside)))
    print("hits in no member (container padding or header) : %d" % outside)
    print()
    print("  %-13s %6s %10s %-20s %6s" % ("member", "slot", "bytes", "timestamp", "hits"))
    for (name, slot, ml, iso), c in inside.most_common(20):
        print("  %-13s %6d %10d %-20s %6d" % (name, slot, ml, iso, c))
    print()

    print("the first %d hits in context:" % min(a.max, len(hits)))
    for off in hits[:a.max]:
        got = locate(members, off)
        nm = got[0][2] if got else "(no member)"
        rel = got[1] if got else -1
        lo = max(0, off - a.context)
        hi = min(len(blob), off + a.context + len(a.search or ""))
        chunk = blob[lo:hi]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print("  offset %10d  member %-13s +%-8d" % (off, nm, rel))
        print("     %s" % chunk.hex(" "))
        print("     %s" % txt)


if __name__ == "__main__":
    main()
