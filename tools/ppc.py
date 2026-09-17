#!/usr/bin/env python3
"""ppc.py -- read a POP-CORN `.PPC` level-set file, to residue zero.

    LACRAL          6 bytes, ASCII, the studio's own name used as a magic
    49 x 176        forty-nine level blocks, no count field, no directory

and each 176-byte block is

    +0    1   bricks      count of destructible cells: non-zero cells that
                          are neither type 3 nor type 9
    +1    1   n9          how many type-9 cells the grid holds, 0..6
    +2    6   slots       the grid indices of those cells, zero-padded
    +8  168   grid        12 columns x 14 rows of one-byte cell types

HOW THE GEOMETRY WAS SETTLED, BECAUSE IT WAS GUESSED WRONG FIRST

The pre-briefing read the block as a 16-byte header and a 16 x 10 grid, on the
strength of one block whose lead byte matched its non-zero cell count, and
recorded that two other blocks refused. It refused because the grid is not 16
wide.

**It is 12 wide and 14 tall, and the header is 8 bytes, and 8 + 12 x 14 = 176.**
The evidence is that at width 12 the rows come out as three four-cell bricks,
and blocks that looked like noise at width 16 come out left-right symmetric --
block 3 of `poptab.ppc` reads `02 01 01 01 01 01 01 01 01 01 01 02` on row 1
and `02 01 02 02 02 02 02 02 02 02 01 02` on row 2, which is a border. At
width 16 those same bytes straddle two rows and say nothing.

THE LEAD BYTE, WHICH THE PRE-BRIEFING COULD NOT MAKE AGREE

It is not the count of non-zero cells. It is the count of non-zero cells that
are neither **type 3** nor **type 9**, and on that rule it agrees on **98 of
98 blocks across both files**. Types 3 and 9 are therefore the two kinds of
cell that are not a brick the player has to clear -- which is exactly the rule
`popgen.exe` must be enforcing when it refuses to save with *"Erreur de
Conception du Tableau"*, since a layout whose brick count is zero can never be
finished.

`--census` prints the per-block table, `--render N` draws one block, and
`--validate` is the refusal path. **Run `--validate` on something that must
fail before believing any census.**

    python ppc.py FILE...              validate and summarise
    python ppc.py FILE --census
    python ppc.py FILE --render 2
    python ppc.py FILE --validate      exit 1 if the file does not parse

Standard library only. It reads; it never writes.
"""

import argparse
import collections
import os
import sys

MAGIC = b"LACRAL"
BLOCK = 176
HDR = 8
COLS = 12
ROWS = 14
GRID = COLS * ROWS
SLOTS = 6
NONBRICK = (3, 9)


class NotPPC(Exception):
    pass


def parse(data):
    if len(data) < len(MAGIC):
        raise NotPPC("shorter than the magic")
    if data[:len(MAGIC)] != MAGIC:
        raise NotPPC("magic is %r, not %r" % (data[:6], MAGIC))
    body = len(data) - len(MAGIC)
    if body % BLOCK:
        raise NotPPC("%d bytes after the magic is not a multiple of %d"
                     % (body, BLOCK))
    n = body // BLOCK
    blocks = []
    for k in range(n):
        off = len(MAGIC) + k * BLOCK
        b = data[off:off + BLOCK]
        grid = b[HDR:]
        if len(grid) != GRID:
            raise NotPPC("block %d grid is %d bytes, not %d"
                         % (k, len(grid), GRID))
        counts = collections.Counter(grid)
        nz = sum(v for c, v in counts.items() if c)
        bricks = nz - sum(counts[t] for t in NONBRICK)
        nines = [i for i, c in enumerate(grid) if c == 9]
        blocks.append({
            "index": k, "offset": off, "raw": b, "grid": grid,
            "hdr_bricks": b[0], "hdr_n9": b[1],
            "hdr_slots": list(b[2:HDR]),
            "nonzero": nz, "bricks": bricks, "nines": nines,
            "types": counts,
        })
    return blocks


def check(blocks):
    """Return a dict of how many blocks satisfy each field rule."""
    r = collections.Counter()
    notes = []
    for b in blocks:
        r["blocks"] += 1
        if b["hdr_bricks"] == b["bricks"]:
            r["bricks agree"] += 1
        else:
            notes.append("block %d: header says %d bricks, grid has %d"
                         % (b["index"], b["hdr_bricks"], b["bricks"]))
        if b["hdr_n9"] == len(b["nines"]):
            r["n9 agrees"] += 1
        else:
            notes.append("block %d: header says %d type-9, grid has %d"
                         % (b["index"], b["hdr_n9"], len(b["nines"])))
        used = b["hdr_slots"][:b["hdr_n9"]]
        if used == b["nines"][:b["hdr_n9"]]:
            r["slots agree (used)"] += 1
        else:
            notes.append("block %d: slots %s against %s"
                         % (b["index"], used, b["nines"]))
        if all(x == 0 for x in b["hdr_slots"][b["hdr_n9"]:]):
            r["unused slots are zero"] += 1
        else:
            notes.append("block %d: unused slots carry %s -- a dirty buffer"
                         % (b["index"], b["hdr_slots"][b["hdr_n9"]:]))
    return r, notes


def render(b):
    g = b["grid"]
    out = []
    out.append("     " + "".join("%3d" % c for c in range(COLS)))
    for r in range(ROWS):
        row = g[r * COLS:(r + 1) * COLS]
        out.append("  %2d " % r
                   + "".join("  ." if c == 0 else "%3d" % c for c in row))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--render", type=int, metavar="N")
    ap.add_argument("--validate", action="store_true",
                    help="exit 1 unless every input parses")
    args = ap.parse_args(argv)

    failed = 0
    allblocks = []
    for p in args.paths:
        with open(p, "rb") as f:
            data = f.read()
        try:
            blocks = parse(data)
        except NotPPC as e:
            print("%-22s REFUSED: %s" % (os.path.basename(p), e))
            failed += 1
            continue
        r, notes = check(blocks)
        used = len(MAGIC) + len(blocks) * BLOCK
        print("%-22s %d bytes, magic %s, %d blocks x %d, residue %+d"
              % (os.path.basename(p), len(data), MAGIC.decode(), len(blocks),
                 BLOCK, len(data) - used))
        for k in ("bricks agree", "n9 agrees", "slots agree (used)",
                  "unused slots are zero"):
            print("    %-24s %d of %d" % (k, r[k], r["blocks"]))
        for line in notes:
            print("    NOTE: %s" % line)
        allblocks.append((p, blocks))
        if args.census:
            print("    %-5s %7s %7s %5s %5s  %s"
                  % ("blk", "bricks", "nonzero", "n9", "types", "histogram"))
            for b in blocks:
                t = dict(sorted((k, v) for k, v in b["types"].items() if k))
                print("    %-5d %7d %7d %5d %5d  %s"
                      % (b["index"], b["hdr_bricks"], b["nonzero"],
                         b["hdr_n9"], len(t), t))
        if args.render is not None:
            b = blocks[args.render]
            print("    block %d: %d bricks, %d type-9 at %s"
                  % (b["index"], b["hdr_bricks"], b["hdr_n9"], b["nines"]))
            print(render(b))

    if len(allblocks) == 2:
        a = {bytes(b["raw"]) for b in allblocks[0][1]}
        c = {bytes(b["raw"]) for b in allblocks[1][1]}
        print()
        print("distinct blocks in %s : %d of %d"
              % (os.path.basename(allblocks[0][0]), len(a),
                 len(allblocks[0][1])))
        print("distinct blocks in %s : %d of %d"
              % (os.path.basename(allblocks[1][0]), len(c),
                 len(allblocks[1][1])))
        print("blocks the two files share      : %d" % len(a & c))

    if args.validate:
        print("\nppc.py: %d of %d inputs parsed"
              % (len(args.paths) - failed, len(args.paths)))
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
