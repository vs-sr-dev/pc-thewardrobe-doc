#!/usr/bin/env python3
"""wmblock.py -- derive and check the block structure of `.BOT` and `.MAP`,
the world-map files in `/DATA/WM/`.

There were three `.BOT` on this object -- 18,653,184 bytes -- with no reader
anywhere in this collection and no prior art, and three `.MAP` beside them.
What follows was derived from the bytes and nothing else.

WHAT WAS OBSERVED, IN THE ORDER IT WAS OBSERVED

  1. all six files are exact multiples of 2,048. That was established from the
     published sizes alone, before the object was opened.
  2. `WM0.BOT` and `WM0.MAP` begin with the SAME 141,368 bytes, although one
     is 15,638,528 and the other 3,250,176. So they are the same kind of thing
     at two sizes, not two formats.
  3. the first sixteen uint32 of every file are 64, 1156, 2248 ... 16444 --
     sixteen values, stride 1092, first value 64 = 16 x 4. A table of sixteen
     32-bit offsets whose first entry points just past itself.
  4. that eight-byte opening recurs, in both files, at offsets 47104, 94208,
     141312, 188416 ... every **47,104** bytes.

THE UNIT, AND IT CLOSES ON ALL SIX

    47,104 = 23 x 2,048 -- twenty-three CD sectors, exactly

    file        bytes        / 47,104
    WM0.BOT    15,638,528       332
    WM2.BOT     2,260,992        48
    WM3.BOT       753,664        16
    WM0.MAP     3,250,176        69
    WM2.MAP       565,248        12
    WM3.MAP       188,416         4

  Residue 0 on six of six. **A block is 47,104 bytes, and a block holds
  sixteen members addressed by a table of sixteen little-endian uint32 at its
  head.** The offsets are relative to the block, the first is always 64, and
  the last member runs to the end of the block or short of it.

WHAT IS NOT CLAIMED

  * what a member IS. Sixteen members to a block, most of them 1,092 bytes in
    block 0 of `WM0`, is a shape and not a meaning. No member is decoded here.
  * why `WM2` and `WM3` have exactly four times as many blocks in `.BOT` as in
    `.MAP` while `WM0` has 4.8115942 times as many. That ratio is printed and
    not explained.
  * what `BOT` stands for. It is not expanded anywhere on this object and this
    tool does not guess.

    python tools/wmblock.py DIR
    python tools/wmblock.py FILE --blocks 4
"""
import argparse
import os
import struct
import sys

BLOCK = 47104          # 23 * 2048
NMEMBER = 16


def check(path, show):
    with open(path, "rb") as fh:
        data = fh.read()
    n, rem = divmod(len(data), BLOCK)
    tables_ok = 0
    monotone = 0
    fits = 0
    first64 = 0
    for b in range(n):
        base = b * BLOCK
        offs = list(struct.unpack("<16I", data[base:base + 64]))
        if offs[0] == 64:
            first64 += 1
        if all(offs[i] <= offs[i + 1] for i in range(NMEMBER - 1)):
            monotone += 1
        if offs[-1] <= BLOCK:
            fits += 1
        if offs[0] == 64 and offs[-1] <= BLOCK and \
           all(offs[i] <= offs[i + 1] for i in range(NMEMBER - 1)):
            tables_ok += 1
    print("%-10s %11d  blocks %5d  residue %5d  tables ok %5d of %5d"
          % (os.path.basename(path), len(data), n, rem, tables_ok, n))
    if show:
        for b in range(min(show, n)):
            base = b * BLOCK
            offs = list(struct.unpack("<16I", data[base:base + 64]))
            sizes = [offs[i + 1] - offs[i] for i in range(NMEMBER - 1)]
            print("   block %-4d offsets %s ..." % (b, offs[:6]))
            print("              member sizes %s" % sizes[:8])
    return 1 if rem or tables_ok != n else 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--blocks", type=int, default=0)
    a = ap.parse_args(argv[1:])
    if os.path.isdir(a.path):
        files = []
        for r, dirs, names in os.walk(a.path):
            dirs.sort()
            for nm in sorted(names):
                if nm.upper().endswith((".BOT", ".MAP")):
                    files.append(os.path.join(r, nm))
        if not files:
            print("FATAL: no .BOT or .MAP under %r -- nothing to check" % a.path)
            return 3
        bad = sum(check(p, a.blocks) for p in files)
        print("%d files, %d failed" % (len(files), bad))
        return 1 if bad else 0
    return check(a.path, a.blocks or 3)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
