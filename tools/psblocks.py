#!/usr/bin/env python3
"""psblocks.py -- how many bytes of a tree are in PlayStation-native formats.

`timtmd.py` reads files that *are* a TIM or a TMD. This one answers the
different question the port raises: how much of a Windows CD is made of
structures no Windows API of 1997 could read, wherever they happen to sit.

It scans every byte of every file for the two ids -- 0x00000010 for TIM,
0x00000041 for TMD -- and then, crucially, **validates each candidate with the
format's own arithmetic** before counting it:

  * a TIM is accepted when its CLUT block length equals 12 + W*H*2, its pixel
    block length equals 12 + W*H*2, and both fit inside the file;
  * a TMD is accepted when its object count is sane, its object table fits,
    and no vertex or normal array reaches past the end of the file.

Without that validation the scan is a magic-number grep and 0x00000010 is far
too common a dword to grep for: on this tree the raw id count is several times
the validated count, and the gap is the point.

Overlapping and nested acceptances are resolved by walking forward: once a
block is accepted, the scan resumes after it.

    python tools/psblocks.py DIR
    python tools/psblocks.py DIR --ext .emd .emw
    python tools/psblocks.py DIR --per-file
"""

import argparse
import collections
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from timtmd import tim_at, tmd_at            # noqa: E402

TIM_ID = b"\x10\x00\x00\x00"
TMD_ID = b"\x41\x00\x00\x00"


def scan(data, min_tim=64, min_tmd=64):
    """Yield (offset, kind, length, info) for validated blocks, in file order."""
    n = len(data)
    pos = 0
    while pos < n - 8:
        i = data.find(TIM_ID, pos)
        j = data.find(TMD_ID, pos)
        cands = [x for x in (i, j) if x != -1]
        if not cands:
            return
        at = min(cands)
        if at % 4:
            pos = at + 1
            continue
        ln = info = None
        if data[at:at + 4] == TIM_ID:
            ln, info = tim_at(data, at)
            if ln and (ln < min_tim or info.get("w", 0) == 0
                       or info.get("h", 0) == 0):
                ln = None
        else:
            ln, info = tmd_at(data, at)
            if ln and (ln < min_tmd or info.get("verts", 0) == 0):
                ln = None
        if ln:
            yield at, info["kind"], ln, info
            pos = at + ln
        else:
            pos = at + 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--ext", nargs="*")
    ap.add_argument("--per-file", action="store_true")
    ap.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    ap.add_argument("--min-block", type=int, default=64,
                    help="reject accepted blocks shorter than this; a 12-byte "
                         "TMD or a 1x1 TIM is arithmetic noise, not an asset")
    a = ap.parse_args()

    files = []
    for dp, dn, fn in os.walk(a.root):
        for f in sorted(fn):
            if a.ext and not f.lower().endswith(tuple(e.lower() for e in a.ext)):
                continue
            files.append(os.path.join(dp, f))

    byext = collections.defaultdict(lambda: [0, 0, 0, 0, 0])
    # [files, file bytes, blocks, block bytes, files with >=1 block]
    raw_ids = 0
    val_blocks = 0
    tot_block_bytes = 0
    kinds = collections.Counter()
    skipped = 0
    rows = []

    for p in files:
        sz = os.path.getsize(p)
        e = os.path.splitext(p)[1].upper() or "(none)"
        rec = byext[e]
        rec[0] += 1
        rec[1] += sz
        if sz > a.max_bytes:
            skipped += 1
            continue
        data = open(p, "rb").read()
        raw_ids += data.count(TIM_ID) + data.count(TMD_ID)
        nb = 0
        bb = 0
        shape = []
        for off, kind, ln, info in scan(data, a.min_block, a.min_block):
            nb += 1
            bb += ln
            kinds[kind] += 1
            shape.append(kind)
        rec[2] += nb
        rec[3] += bb
        if nb:
            rec[4] += 1
        val_blocks += nb
        tot_block_bytes += bb
        if a.per_file and nb:
            rows.append((os.path.relpath(p, a.root), sz, nb, bb,
                         "+".join(shape[:8]) + ("+..." if len(shape) > 8 else "")))

    tot_files = sum(v[0] for v in byext.values())
    tot_bytes = sum(v[1] for v in byext.values())
    print("files scanned                : %d" % (tot_files - skipped))
    print("files skipped (over --max-bytes %d) : %d" % (a.max_bytes, skipped))
    print("file bytes                   : %d" % tot_bytes)
    print()
    print("raw id occurrences (the grep): %d" % raw_ids)
    print("validated blocks             : %d   (%s)"
          % (val_blocks, ", ".join("%s x%d" % kv for kv in kinds.most_common())))
    print("bytes inside validated blocks: %d  (%.4f %% of file bytes)"
          % (tot_block_bytes, 100.0 * tot_block_bytes / tot_bytes))
    print("  -> the grep would have counted %.1fx as many candidates"
          % (raw_ids / val_blocks if val_blocks else 0))
    print()
    print("%-8s %6s %14s %7s %14s %7s %8s"
          % ("ext", "files", "file bytes", "blocks", "block bytes", "hit", "cover"))
    for e, v in sorted(byext.items(), key=lambda kv: -kv[1][3]):
        if not v[2]:
            continue
        print("%-8s %6d %14d %7d %14d %7d %7.2f %%"
              % (e, v[0], v[1], v[2], v[3], v[4],
                 100.0 * v[3] / v[1] if v[1] else 0))
    print()
    print("extensions with no validated block:")
    none = [e for e, v in byext.items() if not v[2]]
    print("   %s" % ", ".join(sorted(none)))
    if a.per_file:
        print()
        for r in rows[:60]:
            print("   %-46s %9d  %3d blocks %9d  %s" % r)


if __name__ == "__main__":
    main()
