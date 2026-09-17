#!/usr/bin/env python3
"""romcensus.py -- identify every region of every IBIS ROM container by what
the bytes are, not by what the sizes suggest.

Each region gets four positive tests, and the verdict names which ones fired:

  68000   the word-byte-swapped image has a legal reset vector (SP in the
          board's 0xFF0000 RAM window, even PC inside the region)
  Z80     the first bytes decode as a Z80 reset sequence (DI / IM 1 / ...)
  TEXT    printable ASCII runs appear after the word swap but not before,
          or vice versa -- which says which byte order the region is in
  FILL    fraction of the region that is 0x00 or 0xFF run-filler, reported
          as "allocated but not used"

Nothing here concludes from size. A region 0x18000 long is not a Z80 program
because 0x18000 is what a CPS1 sound board held; it is a Z80 program because
its first three bytes decode as DI ; IM 1 ; JP.

Usage:
    romcensus.py --regions DIR       (a directory of NAME.rN files)
    romcensus.py --blocks  FILE      (block profile of one region)
"""
import argparse
import collections
import glob
import math
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from m68k import swap16, vector_test          # noqa: E402
from z80head import decode as z80_decode      # noqa: E402

PRINTABLE = re.compile(rb"[\x20-\x7e]{8,}")


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def filler_fraction(b):
    return (b.count(0) + b.count(0xFF)) / len(b) if b else 0.0


def last_used(b):
    i = len(b) - 1
    while i >= 0 and b[i] in (0, 0xFF):
        i -= 1
    return i + 1


def z80_run(b, n=6):
    i = 0
    out = []
    for _ in range(n):
        ln, txt = z80_decode(b, i, len(b))
        if ln is None:
            break
        out.append(txt)
        i += ln
    return out


def text_runs(b, limit=None):
    blob = b if limit is None else b[:limit]
    return len(PRINTABLE.findall(blob))


def classify(blob):
    """Return (label, evidence-string)."""
    ev = []
    swapped = swap16(blob)
    ok68, f68 = vector_test(swapped)
    if f68.get("ok_sp") and f68.get("ok_pc"):
        ev.append("68000 vectors SP=0x%08X PC=0x%08X" % (f68["sp"], f68["pc"]))
    z = z80_run(blob)
    if len(z) >= 3 and z[0] == "DI":
        ev.append("Z80 entry: " + " ; ".join(z[:4]))
    t_plain = text_runs(blob)
    t_swap = text_runs(swapped)
    if t_swap > t_plain * 2 and t_swap > 4:
        ev.append("ASCII only after word swap (%d runs vs %d)" % (t_swap, t_plain))
    elif t_plain > 4:
        ev.append("ASCII in file order (%d runs)" % t_plain)

    if f68.get("ok_sp") and f68.get("ok_pc"):
        label = "68000 program"
    elif len(z) >= 3 and z[0] == "DI":
        label = "Z80 program"
    else:
        label = "-"
    return label, ev, f68, z


def census(paths):
    print("%-10s %-3s %10s %8s %8s %7s  %s"
          % ("set", "r", "size", "entropy", "filler%", "used", "verdict"))
    rows = []
    for p in sorted(paths):
        base = os.path.basename(p)
        stem, ext = base.rsplit(".", 1)
        with open(p, "rb") as fh:
            blob = fh.read()
        label, ev, f68, z = classify(blob)
        lu = last_used(blob)
        rows.append((stem, ext, len(blob), entropy(blob), filler_fraction(blob), lu, label, ev))
        print("%-10s %-3s %10d %8.4f %7.2f%% %8d  %s"
              % (stem, ext, len(blob), entropy(blob),
                 100 * filler_fraction(blob), lu, label))
        for e in ev:
            print("%-24s %s" % ("", e))
    return rows


def blocks(path, bs=0x8000):
    with open(path, "rb") as fh:
        b = fh.read()
    print("%s  %d bytes, blocks of 0x%X" % (path, len(b), bs))
    for i in range(0, len(b), bs):
        blk = b[i:i + bs]
        label, ev, _, z = classify(blk)
        print("  0x%08X ent=%6.3f filler=%6.2f%% head=%s %s"
              % (i, entropy(blk), 100 * filler_fraction(blk), blk[:8].hex(),
                 ("<- " + label) if label != "-" else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regions")
    ap.add_argument("--blocks")
    ap.add_argument("--bs", type=lambda s: int(s, 0), default=0x8000)
    a = ap.parse_args()
    if a.regions:
        census(glob.glob(os.path.join(a.regions, "*.r*")))
    if a.blocks:
        blocks(a.blocks, a.bs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
