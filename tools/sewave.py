#!/usr/bin/env python3
"""sewave.py -- the two audio containers of Final Fantasy XI, and what is inside.

Two of this object's extensions name themselves in their own first bytes,
which is rarer than it sounds and is the difference between a measurement
and an expansion of an acronym:

    .spw   12,041 files   1,879,848,755 bytes   ->  `SeWave`
    .bgw      262 files   1,767,126,043 bytes   ->  `BGMStream` on 261,
                                                    and `RIFF` on one

THE HEADER, DERIVED FROM THE BYTES

    SeWave              BGMStream
    +0   8  "SeWave"    +0   16  "BGMStream"
    +8   u32 file size  +16  u32  file size
    +12  u32 zero       +20  u32  a small number equal to the number in
    +16  u32 a small         the file's own name (music025 -> 25)
             number      +24  u32  block count
    +20  u32 block      +28  u32  a second count
             count      +32  8    eight bytes that look like nothing else
    +24  u32 0xFFFFFFFF      in the file
    +28  8   eight      +40  u32  48 -- where the audio starts
             bytes      +44  u32
    +36  u32 48 -- where the audio starts

THE ARITHMETIC THAT HAS TO CLOSE

For `SeWave` the claim is: `file size == 48 + 9 * blockcount`, exactly,
with no slack.  Nine bytes is one control byte and eight bytes of
sixteen four-bit samples, which is the shape of every 4-bit ADPCM that has
ever been written for a console; the control byte of a silent block is
0x0C and a silent `SeWave` is `0C` followed by eight zeros, over and over,
which is what the first hundred bytes of the small effects actually are.

For `BGMStream` the same check is run and the residue is reported rather
than explained away.

None of this needs the file body: the check reads 48 bytes per file, so
the census of 12,303 files costs 590 kilobytes of reading and not 3.6
gigabytes.  That is worth saying out loud, because the reason the branch
keeps meeting tools that "scan everything" is that nobody asks what the
check actually needs.

Nothing is executed, nothing is contacted, nothing is written to the
object.

usage:
  sewave.py census ROOT [--out FILE]
  sewave.py head FILE [FILE ...]
"""

import argparse
import os
import struct
import sys
from collections import Counter

SPW_MAGIC = b"SeWave\0\0"
BGW_MAGIC = b"BGMStream\0"
BLOCK = 9
DATA_OFF = 48


def read_head(path, n=64):
    with open(path, "rb") as fh:
        return fh.read(n)


def parse_spw(h, size):
    (fsize, zero, idx, blocks) = struct.unpack_from("<IIII", h, 8)
    (sentinel,) = struct.unpack_from("<I", h, 24)
    key = h[28:36]
    (start,) = struct.unpack_from("<I", h, 36)
    return {
        "declared_size": fsize, "zero": zero, "index": idx,
        "blocks": blocks, "sentinel": sentinel, "key": key, "start": start,
        "size_ok": fsize == size,
        "closes": size == DATA_OFF + BLOCK * blocks,
        "residue": size - DATA_OFF - BLOCK * blocks,
    }


def parse_bgw(h, size):
    (fsize, idx, blocks, second) = struct.unpack_from("<IIII", h, 16)
    key = h[32:40]
    (start, word) = struct.unpack_from("<II", h, 40)
    return {
        "declared_size": fsize, "index": idx, "blocks": blocks,
        "second": second, "key": key, "start": start, "word": word,
        "size_ok": fsize == size,
        "closes": size == DATA_OFF + BLOCK * blocks,
        "residue": size - DATA_OFF - BLOCK * blocks,
        "per_block": (size - DATA_OFF) / blocks if blocks else 0,
    }


def cmd_head(args):
    for p in args.file:
        size = os.path.getsize(p)
        h = read_head(p)
        print("%s  %d bytes" % (p, size))
        if h.startswith(SPW_MAGIC[:6]):
            d = parse_spw(h, size)
        elif h.startswith(BGW_MAGIC[:9]):
            d = parse_bgw(h, size)
        else:
            print("  magic %r -- neither SeWave nor BGMStream" % h[:12])
            continue
        for k in sorted(d):
            print("    %-14s %s" % (k, d[k]))
    return 0


def cmd_census(args):
    out = sys.stdout
    if args.out:
        out = open(args.out, "w", encoding="utf-8")

    def w(s=""):
        out.write(s + "\n")

    stats = {"spw": Counter(), "bgw": Counter()}
    counts = Counter()
    bytes_ = Counter()
    magics = Counter()
    residues = {"spw": Counter(), "bgw": Counter()}
    per_block = Counter()
    read_bytes = 0
    odd = []
    blocks_total = Counter()
    for dirpath, _d, files in os.walk(args.root):
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in (".spw", ".bgw"):
                continue
            p = os.path.join(dirpath, fn)
            size = os.path.getsize(p)
            h = read_head(p)
            read_bytes += len(h)
            counts[ext] += 1
            bytes_[ext] += size
            magic = h[:9].rstrip(b"\0")
            magics[(ext, magic)] += 1
            if h.startswith(SPW_MAGIC[:6]):
                d = parse_spw(h, size)
                k = "spw"
            elif h.startswith(BGW_MAGIC[:9]):
                d = parse_bgw(h, size)
                k = "bgw"
                per_block[round(d["per_block"], 4)] += 1
            else:
                if len(odd) < 10:
                    odd.append((os.path.relpath(p, args.root), size, h[:16]))
                continue
            stats[k]["size field matches" if d["size_ok"]
                     else "size field WRONG"] += 1
            stats[k]["chain closes" if d["closes"]
                     else "chain does not close"] += 1
            stats[k]["start field is 48" if d["start"] == DATA_OFF
                     else "start field is not 48"] += 1
            residues[k][d["residue"]] += 1
            blocks_total[k] += d["blocks"]

    w("root        : %s" % args.root)
    w("bytes read  : %d  (48-byte headers only, not the bodies)" % read_bytes)
    w()
    for ext in sorted(counts):
        w("%-6s %7d files  %14d bytes" % (ext, counts[ext], bytes_[ext]))
    w()
    w("first bytes, by extension:")
    for (ext, magic), c in sorted(magics.items(), key=lambda kv: -kv[1]):
        w("  %-6s %-12s %7d" % (ext, magic.decode("latin1"), c))
    w()
    for k in ("spw", "bgw"):
        if not stats[k]:
            continue
        w("%s:" % k.upper())
        for label, c in sorted(stats[k].items()):
            w("    %-26s %7d" % (label, c))
        w("    total 9-byte blocks declared : %d" % blocks_total[k])
        w("    residue (size - 48 - 9*blocks):")
        for r, c in residues[k].most_common(6):
            w("        %10d  on %7d files" % (r, c))
        w()
    if per_block:
        w("BGMStream, bytes of body per declared block:")
        for v, c in per_block.most_common(8):
            w("    %10s  on %5d files" % (v, c))
        w()
    if odd:
        w("files whose first bytes are neither magic:")
        for rel, size, head in odd:
            w("  %-50s %12d  %r" % (rel, size, head))
    if args.out:
        out.close()
        print("wrote %s" % args.out)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("census")
    p.add_argument("root")
    p.add_argument("--out")
    p.set_defaults(func=cmd_census)
    p = sub.add_parser("head")
    p.add_argument("file", nargs="+")
    p.set_defaults(func=cmd_head)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
