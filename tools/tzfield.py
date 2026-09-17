#!/usr/bin/env python3
"""tzfield.py -- what is actually in byte 24 of an ISO 9660 directory record?

ECMA-119 9.1.5 says byte 24 of the seven-byte recording date is a signed count
of 15-minute intervals from Greenwich, legal range -48..+52. `iso9660.py`
prints it as `GMT+hh:mm` and marks it `NO` in a `valid?` column when it falls
outside that range, which is correct and is not an explanation.

On *Race the Clock* the file records hold a hundred distinct values, up to
`GMT+24:45`, while every directory record holds zero. That is a clean split
between records the mastering tool synthesised and records it copied, and it
is worth more than a histogram.

So this tests candidate explanations instead of describing the distribution.
It walks the directory tree from the primary descriptor, collects every
record, and prints:

  * how many of the values are printable ASCII, and how many are legal;
  * a table of candidate identities -- is the byte the record length, the
    identifier length, a byte of the identifier, the low byte of the extent,
    a date field, an arithmetic combination of them -- each with a count out
    of the population, so a candidate that explains 15 of 3,625 is visibly
    not an explanation;
  * the **range and cardinality**, because a field taking exactly 100 values
    covering 0..99 with nothing above is a hundredths-of-a-second counter and
    not a timezone, and that is the one test that settles it;
  * the parity of the seconds field, which says whether the dates came from a
    two-second-resolution source filesystem.

    python tools/tzfield.py IMAGE.iso
"""
import argparse
import collections
import struct
import sys


def records(d, extent, length, path="/"):
    out = []
    data = d[extent * 2048:extent * 2048 + length]
    p = 0
    while p < len(data):
        n = data[p]
        if n == 0:
            p = (p // 2048 + 1) * 2048
            continue
        rec = data[p:p + n]
        idlen = rec[32]
        ident = rec[33:33 + idlen]
        if idlen > 1 or ident not in (b"\x00", b"\x01"):
            out.append({
                "path": path, "id": ident, "rec": rec,
                "extent": struct.unpack_from("<I", rec, 2)[0],
                "len": struct.unpack_from("<I", rec, 10)[0],
                "flags": rec[25], "off": extent * 2048 + p,
            })
        p += n
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    d = open(a.image, "rb").read()
    if d[16 * 2048 + 1:16 * 2048 + 6] != b"CD001":
        print("%s: no CD001 at sector 16 -- refusing" % a.image)
        return 1
    rootrec = d[16 * 2048 + 156:16 * 2048 + 190]
    ext = struct.unpack_from("<I", rootrec, 2)[0]
    ln = struct.unpack_from("<I", rootrec, 10)[0]

    allrecs = records(d, ext, ln)
    stack = [r for r in allrecs if r["flags"] & 2]
    while stack:
        r = stack.pop()
        kids = records(d, r["extent"], r["len"],
                       r["path"] + r["id"].decode("latin-1") + "/")
        allrecs += kids
        stack += [k for k in kids if k["flags"] & 2]

    files = [r for r in allrecs if not (r["flags"] & 2)]
    dirs = [r for r in allrecs if r["flags"] & 2]
    if not files:
        print("no file records walked -- refusing rather than reporting zero")
        return 1

    tz = [r["rec"][24] for r in files]
    dtz = [r["rec"][24] for r in dirs]
    print("image                  : %s" % a.image)
    print("file records           : %d" % len(files))
    print("subdirectory records   : %d" % len(dirs))
    print()
    print("byte 24 on directory records : %d distinct %s"
          % (len(set(dtz)), sorted(set(dtz))))
    print("byte 24 on file records      : %d distinct" % len(set(tz)))
    print("  printable ASCII 0x20..0x7E : %d of %d"
          % (sum(1 for t in tz if 0x20 <= t <= 0x7E), len(tz)))
    print("  legal ECMA-119 -48..+52    : %d of %d"
          % (sum(1 for t in tz
                 if -48 <= (t - 256 if t > 127 else t) <= 52), len(tz)))
    print("  min %d  max %d" % (min(tz), max(tz)))
    print("  the set is exactly 0..99   : %s" % (set(tz) == set(range(100))))
    print("     -- a field taking every value in 0..99 and none above is a")
    print("        hundredths-of-a-second counter, not a 15-minute offset")
    print()
    cands = {
        "record length": lambda r: r["rec"][0],
        "identifier length": lambda r: r["rec"][32],
        "first byte of identifier": lambda r: r["id"][0],
        "last byte of identifier": lambda r: r["id"][-1],
        "low byte of the extent": lambda r: r["extent"] & 0xFF,
        "low byte of the data length": lambda r: r["len"] & 0xFF,
        "the seconds field": lambda r: r["rec"][23],
        "the minutes field": lambda r: r["rec"][22],
        "the hours field": lambda r: r["rec"][21],
        "the file-flags byte": lambda r: r["rec"][25],
        "(hour*4 + minute//15) & 0xFF":
            lambda r: (r["rec"][21] * 4 + r["rec"][22] // 15) & 0xFF,
        "sum of the six date bytes & 0xFF":
            lambda r: sum(r["rec"][18:24]) & 0xFF,
    }
    print("candidate identities, each as a count out of %d:" % len(files))
    for name, f in cands.items():
        print("   byte 24 == %-34s %5d" % (name, sum(
            1 for r in files if r["rec"][24] == f(r))))
    print()
    ev = sum(1 for r in files if r["rec"][23] % 2 == 0)
    evd = sum(1 for r in dirs if r["rec"][23] % 2 == 0)
    print("seconds field even, file records      : %d of %d" % (ev, len(files)))
    print("seconds field even, directory records : %d of %d" % (evd, len(dirs)))
    print("   -- all-even file seconds is the two-second resolution of a FAT")
    print("      source volume; odd directory seconds mean the tool wrote")
    print("      those itself from its own clock")
    print()
    c = collections.Counter(tz)
    print("the ten commonest values:")
    for v, n in c.most_common(10):
        print("   %3d (0x%02X, '%s')  x%-5d  printed by iso9660.py as GMT%+03d:%02d"
              % (v, v, chr(v) if 0x20 <= v <= 0x7E else ".", n,
                 v // 4, (v % 4) * 15))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
