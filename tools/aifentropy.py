#!/usr/bin/env python3
"""aifentropy.py -- is the body of an AIF image compressed data or ARM code?

Two structural tests disagree on the third 3DO disc. Twenty images carry a `BL`
at offset 0 and a 392/456/464-byte routine appended past their relocation data;
only nine of those twenty declare more than they store. A third test settles it
without believing either: **compressed bytes and ARM code do not have the same
entropy**, and 32-bit ARM code has a further signature nothing else has --- one
byte in four is a condition/opcode nibble drawn from a small set, so the
distribution over the fourth byte of each word is extremely peaked.

Per image this prints, over the body (offset 0x40 to the branch target at
offset 0, or to end of file when offset 0 is a NOP):

    H       Shannon entropy in bits per byte
    top4    the share of words whose top byte is 0xE (the ARM 'always'
            condition, which dominates compiler output)

Compiled ARM: H around 5, top4 well above 0.5.
Compressed:   H above 7.5, top4 near 1/16 = 0.0625.

usage: aifentropy.py TREE
"""
import math
import os
import struct
import sys

SWI11 = 0xEF000011


def bl_target(word, at):
    if (word >> 24) != 0xEB:
        return None
    disp = word & 0x00FFFFFF
    if disp & 0x800000:
        disp -= 0x1000000
    return at + 8 + 4 * disp


def entropy(b):
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = float(len(b))
    return -sum((c / n) * math.log(c / n, 2) for c in counts if c)


def always_share(b):
    n = len(b) // 4
    if n == 0:
        return 0.0
    hits = sum(1 for i in range(n) if (b[4 * i] >> 4) == 0xE)
    return float(hits) / n


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: aifentropy.py TREE" + "\n")
        raise SystemExit(2)
    tree = sys.argv[1]
    rows = []
    for root, dirs, files in os.walk(tree):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            with open(p, "rb") as fh:
                b = fh.read()
            if len(b) < 0x38:
                continue
            if struct.unpack(">I", b[0x10:0x14])[0] != SWI11:
                continue
            w0, w1 = struct.unpack(">2I", b[0:8])
            ro, rw, dbg, zi = struct.unpack(">4I", b[0x14:0x24])
            t0 = bl_target(w0, 0)
            end = t0 if t0 is not None else len(b)
            body = b[0x40:end]
            rows.append((p[len(tree):].replace(os.sep, "/"), t0 is not None,
                         len(b), ro + rw + dbg, entropy(body), always_share(body),
                         len(body)))
    rows.sort(key=lambda r: (not r[1], r[0]))
    print("%-46s %4s %8s %8s %7s %7s"
          % ("path", "BL0", "size", "declared", "H", "cond=E"))
    for p, hasbl, size, decl, h, a, n in rows:
        flag = ""
        if hasbl:
            flag = "  <- declares less than it stores" if decl < size else ""
        print("%-46s %4s %8d %8d %7.4f %7.4f%s"
              % (p, "BL" if hasbl else "NOP", size, decl, h, a, flag))
    print()
    bl = [r for r in rows if r[1]]
    nop = [r for r in rows if not r[1]]
    for label, rs in (("BL at offset 0", bl), ("NOP at offset 0", nop)):
        if not rs:
            continue
        print("%-18s %2d images   H %.4f..%.4f   cond=E %.4f..%.4f"
              % (label, len(rs), min(r[4] for r in rs), max(r[4] for r in rs),
                 min(r[5] for r in rs), max(r[5] for r in rs)))


if __name__ == "__main__":
    main()
