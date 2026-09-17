#!/usr/bin/env python3
"""Printable-run extraction, and the two searches this document keeps repeating:
who is named, and whose machine the paths belong to.

`strings` is not on this machine, and the two questions here are not general
ones, so the tool is specific:

    runs   <file> [minlen]      printable runs, one per line, with the offset
    find   <file> <needle>...   case-insensitive, with a byte offset each
    paths  <file>               absolute paths, BOTH kinds

`paths` looks for two shapes and reports them separately, because a previous
session lost four findings by looking only for the first:

    drive-letter paths      C:\\ff8\\Data\\ita\\FIELD\\mapdata.fi
    rooted POSIX paths      /1a/proj/master/jppc/field/mapdata/wm/wm00/wm00.id

Both exist in this object, in the same layer, and one of them names a machine
in a different country from the other.
"""
import re
import sys

DRIVE = re.compile(rb"[A-Za-z]:[\\/][A-Za-z0-9_.$~\\/ -]{2,160}")
ROOTED = re.compile(rb"/[a-z0-9_.-]+(?:/[A-Za-z0-9_.$~-]+){2,}")
RUN = re.compile(rb"[\x20-\x7e]{4,}")


def cmd_runs(path, minlen=6):
    minlen = int(minlen)
    b = open(path, "rb").read()
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, b):
        sys.stdout.buffer.write(b"%d\t" % m.start() + m.group() + b"\n")


def cmd_find(path, *needles):
    b = open(path, "rb").read()
    low = b.lower()
    for n in needles:
        nb = n.lower().encode("latin-1")
        hits = []
        i = low.find(nb)
        while i != -1:
            hits.append(i)
            i = low.find(nb, i + 1)
        wide = n.lower().encode("utf-16-le")
        w = []
        i = low.find(wide)
        while i != -1:
            w.append(i)
            i = low.find(wide, i + 1)
        print("%-24s %d ascii, %d utf-16   %s"
              % (n, len(hits), len(w), hits[:8]))


def cmd_paths(path):
    b = open(path, "rb").read()
    d = [m.group().decode("latin-1") for m in DRIVE.finditer(b)]
    r = [m.group().decode("latin-1") for m in ROOTED.finditer(b)]
    print("%s: %d drive-letter paths, %d rooted paths" % (path, len(d), len(r)))
    for s in sorted(set(d))[:40]:
        print("  D %s" % s)
    for s in sorted(set(r))[:40]:
        print("  R %s" % s)


if __name__ == "__main__":
    c = sys.argv[1]
    if c == "runs":
        cmd_runs(*sys.argv[2:])
    elif c == "find":
        cmd_find(sys.argv[2], *sys.argv[3:])
    elif c == "paths":
        cmd_paths(sys.argv[2])
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)
