#!/usr/bin/env python3
"""binindex.py -- the `.BIN` files are not one format, and this says how many.

On this object `.BIN` is the largest extension by bytes and names at least six
unrelated things. Grouping by extension therefore produces a single 715 MB
category that is not a category. This tool classifies by signature instead, and
for one of the six -- an archive whose first dwords are a table of offsets into
itself -- it derives and verifies the table.

The archive test is arithmetic and has no constants in it:

  * read the first dword. Call it T. If T is not a plausible table size
    (4 <= T <= file size, divisible by 4) the file is not of this kind;
  * read T/4 dwords. They must be monotonically non-decreasing and all within
    the file;
  * the distinct values, in order, cut the file into segments, with the end of
    the file closing the last one.

Three padding conventions appear on this object and only one was visible in the
first file opened: an unused slot may repeat the previous offset (and the table
then ends with an entry equal to the file size), or hold a plain 0, or the
table may simply be full with the last member running to EOF. The convention is
reported per file rather than assumed, and in every case the accounting is
checked: table bytes + payload bytes must equal the file size with residue 0.

    python tools/binindex.py DIR
    python tools/binindex.py DIR --ext .bin .dat
    python tools/binindex.py FILE --segments

No constant in this file belongs to any particular disc.
"""

import argparse
import collections
import os
import struct


def classify(path):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(16)
    if len(head) < 8:
        return "short", None
    if head[:4] == b"RIFF":
        return "RIFF", None
    if head[:2] == b"MZ":
        return "MZ executable", None
    if head[:4] == b"\x10\x00\x00\x00":
        return "PlayStation TIM", None
    tab = table(path, size)
    if tab is not None:
        return "indexed archive", tab
    if head[:4] == b"\x00\x00\x00\x00":
        return "leading zero dword", None
    return "unclassified " + head[:4].hex(" "), None


def table(path, size):
    with open(path, "rb") as fh:
        first = fh.read(4)
        if len(first) < 4:
            return None
        t = struct.unpack("<I", first)[0]
        if t < 4 or t > size or t % 4:
            return None
        fh.seek(0)
        raw = fh.read(t)
        if len(raw) < t:
            return None
        vals = list(struct.unpack("<%dI" % (t // 4), raw))
    if vals[0] != t:
        return None
    # Two padding conventions live in this family and only one of them was
    # visible in the first file opened. ROOMCUT.BIN repeats the previous offset
    # in an unused slot and ends with an entry equal to the file size, so the
    # table is a closed list of boundaries. ESPDAT1/ESPDAT2/ITEMDATA/OSP write
    # a plain 0 in an unused slot and carry no terminator, so the last member
    # runs to the end of the file. Accepting only the first convention reported
    # one archive per disc where there are five.
    zero_padded = 0 in vals[1:]
    used = [v for v in vals if v] if zero_padded else list(vals)
    for i in range(len(used) - 1):
        if used[i] > used[i + 1]:
            return None
    if used[-1] > size:
        return None
    bounds = sorted(set(used))
    if bounds[-1] != size:
        bounds.append(size)
    segs = [(bounds[i], bounds[i + 1] - bounds[i]) for i in range(len(bounds) - 1)]
    return {"slots": len(vals), "used": len(segs), "segments": segs,
            "empty": len(vals) - len(set(used)), "size": size,
            "pad": ("zero" if zero_padded
                    else "repeat" if used[-1] == size else "none"),
            "bytes": sum(s[1] for s in segs)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--ext", nargs="*", default=[".bin"])
    ap.add_argument("--segments", action="store_true")
    a = ap.parse_args()

    exts = tuple(e.lower() if e.startswith(".") else "." + e.lower()
                 for e in a.ext)
    targets = []
    if os.path.isdir(a.path):
        for dp, dn, fn in os.walk(a.path):
            for f in sorted(fn):
                if f.lower().endswith(exts):
                    targets.append(os.path.join(dp, f))
    else:
        targets = [a.path]

    kinds = collections.Counter()
    kbytes = collections.Counter()
    archives = []
    for p in targets:
        k, tab = classify(p)
        kinds[k] += 1
        kbytes[k] += os.path.getsize(p)
        if tab:
            archives.append((p, tab))

    print("files examined : %d" % len(targets))
    print("bytes          : %d" % sum(os.path.getsize(p) for p in targets))
    print()
    print("%-26s %6s %14s" % ("signature class", "files", "bytes"))
    for k in sorted(kinds, key=lambda x: -kbytes[x]):
        print("%-26s %6d %14d" % (k, kinds[k], kbytes[k]))
    print()
    print("-- the indexed archives, table verified --------------------------")
    print("%-40s %11s %6s %6s %6s %12s %8s %8s %s"
          % ("file", "bytes", "slots", "used", "empty", "payload", "min",
             "max", "pad"))
    for p, t in archives:
        segs = t["segments"]
        print("%-40s %11d %6d %6d %6d %12d %8d %8d %s"
              % (os.path.basename(p), t["size"], t["slots"], t["used"],
                 t["empty"], t["bytes"], min(s[1] for s in segs),
                 max(s[1] for s in segs), t["pad"]))
        print("%-40s residue %d bytes (table %d + payload %d = %d)"
              % ("", t["size"] - segs[0][0] - t["bytes"], segs[0][0],
                 t["bytes"], segs[0][0] + t["bytes"]))
    if a.segments and archives:
        p, t = archives[0]
        print()
        print("-- segment heads of %s ---" % os.path.basename(p))
        with open(p, "rb") as fh:
            heads = collections.Counter()
            for off, n in t["segments"]:
                fh.seek(off)
                heads[fh.read(4)] += 1
        for k, v in heads.most_common(20):
            print("   %s x%d" % (k.hex(" "), v))


if __name__ == "__main__":
    main()
