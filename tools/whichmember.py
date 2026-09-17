#!/usr/bin/env python3
"""whichmember.py -- map a byte offset in an EmPackFi archive to the member
that contains it, and read a string hit in its context.

Yesterday's session learned that a scan which fires a lot is a scan to be read
by hand, and that reading it by hand is only possible once every offset can be
named. This does the naming: it takes the member table written by
`empack.py --tsv`, builds an interval index, and for each occurrence of a search
string prints the member, the offset inside it, and the bytes on either side.

Nothing is extracted: the tool reads at most `--context` bytes around each hit.

    python tools/whichmember.py --archive ARCHIVE --tsv MEMBERS.tsv --find Xbox
    python tools/whichmember.py --archive ARCHIVE --tsv MEMBERS.tsv \\
        --find RenderWare --encoding utf-16
    python tools/whichmember.py --archive ARCHIVE --tsv MEMBERS.tsv \\
        --find Wii --summary
"""
import argparse
import bisect
import collections
import csv
import os
import sys

CHUNK = 1 << 24


def build_index(tsv):
    rows = list(csv.DictReader(open(tsv, encoding="utf-8"), delimiter="\t"))
    ivs = sorted((int(r["offset"]), int(r["offset"]) + int(r["size"]),
                  r["name"], r["signature"]) for r in rows)
    return ivs, [x[0] for x in ivs]


def locate(ivs, starts, pos):
    i = bisect.bisect_right(starts, pos) - 1
    if i < 0:
        return None
    lo, hi, name, sig = ivs[i]
    if pos < hi:
        return (lo, hi, name, sig)
    return None


def scan(path, needle):
    """Yield every absolute offset of `needle`, streaming, with overlap."""
    n = len(needle)
    fh = open(path, "rb")
    base = 0
    tail = b""
    while True:
        buf = fh.read(CHUNK)
        if not buf:
            break
        hay = tail + buf
        start = 0
        while True:
            k = hay.find(needle, start)
            if k < 0:
                break
            yield base - len(tail) + k
            start = k + 1
        base += len(buf)
        tail = hay[-(n - 1):] if n > 1 else b""
    fh.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", required=True)
    ap.add_argument("--tsv", required=True)
    ap.add_argument("--find", required=True)
    ap.add_argument("--encoding", default="ascii",
                    choices=("ascii", "utf-16", "utf-16be"))
    ap.add_argument("--context", type=int, default=28)
    ap.add_argument("--summary", action="store_true",
                    help="count by member and by signature, print no context")
    ap.add_argument("--limit", type=int, default=200)
    a = ap.parse_args()

    if a.encoding == "ascii":
        needle = a.find.encode("latin-1")
    elif a.encoding == "utf-16":
        needle = a.find.encode("utf-16-le")
    else:
        needle = a.find.encode("utf-16-be")

    ivs, starts = build_index(a.tsv)
    fh = open(a.archive, "rb")
    hits = list(scan(a.archive, needle))

    print("archive   : %s" % os.path.basename(a.archive))
    print("needle    : %r  (%s, %d bytes)" % (a.find, a.encoding, len(needle)))
    print("hits      : %d" % len(hits))

    bymem = collections.Counter()
    bysig = collections.Counter()
    inheader = 0
    for pos in hits:
        loc = locate(ivs, starts, pos)
        if loc is None:
            inheader += 1
            bymem["(archive header or inter-member gap)"] += 1
            bysig["(header/gap)"] += 1
        else:
            bymem[loc[2]] += 1
            bysig[loc[3]] += 1
    print("in the header or a gap : %d" % inheader)
    print("distinct members       : %d"
          % len([k for k in bymem if not k.startswith("(")]))
    print()
    print("by member signature:")
    for k, v in bysig.most_common():
        print("   %-26s %6d" % (k, v))
    print()
    print("top members:")
    for k, v in bymem.most_common(15):
        print("   %6d  %s" % (v, k))

    if a.summary:
        return 0

    print()
    print("-- each hit in context --")
    for i, pos in enumerate(hits[:a.limit]):
        loc = locate(ivs, starts, pos)
        fh.seek(max(0, pos - a.context))
        ctx = fh.read(a.context * 2 + len(needle))
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in ctx)
        if loc:
            print("   %10d  +%-10d %-46s %s"
                  % (pos, pos - loc[0], loc[2].split("\\")[-1][:46], txt))
        else:
            print("   %10d  (header/gap)%-45s %s" % (pos, "", txt))
    if len(hits) > a.limit:
        print("   ... %d more not printed" % (len(hits) - a.limit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
