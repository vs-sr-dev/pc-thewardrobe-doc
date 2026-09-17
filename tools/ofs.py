#!/usr/bin/env python3
"""ofs.py -- the `.OFS` index: a fixed slot array of absolute node offsets.

Four members, two in `torrey_p.crs` and two in `practice.crx`, and two of them
are members the VIS build dropped. They are a sparse index into the archive
that contains them:

    slot i:  u24 LE  absolute byte offset of an `MDmd` node header
             0xFFFFFF means the slot is empty

    PATCH.OFS   3,072 bytes = 1024 slots,  slot = row*32 + column
    OBJECT.OFS    300 bytes =  100 slots,  slot = the number in OBJnn.BLK

THE CLOSURE IS TOTAL AND IT IS CHECKED AGAINST THE ARCHIVE, NOT AGAINST ITSELF

  * **198 of 198 non-empty slots across the four members land exactly on an
    `MDmd` node header** in the archive that holds them. An offset table read at
    the wrong stride does not land on 198 headers;
  * every `PATCH.OFS` pointee is a `.PAT` member and every `OBJECT.OFS` pointee
    is an `OBJnn.BLK` member -- 135, 18, 34 and 11 of them, which are exactly
    those archives' `.PAT` and `OBJ` counts;
  * the slot index is the member's own name: `slot == row*32 + column` on
    **135 of 135** and 18 of 18 for `PATCH.OFS`, and `slot == nn` on 34 of 34
    and 11 of 11 for `OBJECT.OFS`.

AND IT SETTLES THE GRID ORIENTATION A SECOND TIME

`pat.py` fixes the `PATCHcr` grid orientation with a seam statistic: reading
the first name character as the row gives a mean edge discontinuity of 747
against 7,815 for the transposed reading and 12,694 for an unrelated-tile
control. **This index agrees, by a completely different route**: the stride is
32 and the first character multiplies it. Two independent measurements, one
statistical and one structural.

    python tools/ofs.py ARCHIVE OFSMEMBER...
"""
import argparse
import os
import re
import sys

COLS = "0123456789ABCDEFG"
EMPTY = 0xFFFFFF


class OfsError(Exception):
    pass


def node_names(archive):
    """Every `MDmd` node offset in the archive, with the member name at +42."""
    data = open(archive, "rb").read()
    out = {}
    off = 0
    while True:
        i = data.find(b"MDmd", off)
        if i < 0:
            break
        out[i] = data[i + 42:i + 55].split(b"\0")[0].split(b"\x0e")[0] \
                     .strip().decode("latin1")
        off = i + 4
    if not out:
        raise OfsError("%s: no MDmd node headers -- not an archive"
                       % os.path.basename(archive))
    return out


def parse(data, name="<data>"):
    if len(data) % 3:
        raise OfsError("%s: %d bytes is not a whole number of u24 slots"
                       % (name, len(data)))
    return [int.from_bytes(data[i * 3:i * 3 + 3], "little")
            for i in range(len(data) // 3)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("archive")
    ap.add_argument("members", nargs="+")
    ap.add_argument("--expect-hits", type=int)
    a = ap.parse_args()

    try:
        nodes = node_names(a.archive)
    except OfsError as e:
        raise SystemExit("ofs: %s" % e)
    print("archive        : %s   %d MDmd nodes"
          % (os.path.basename(a.archive), len(nodes)))

    total_used = total_hit = 0
    for p in a.members:
        name = os.path.basename(p)
        try:
            slots = parse(open(p, "rb").read(), name)
        except OfsError as e:
            print("REFUSED  %s" % e)
            continue
        used = [(i, v) for i, v in enumerate(slots) if v != EMPTY]
        hit = [(i, v) for i, v in used if v in nodes]
        total_used += len(used)
        total_hit += len(hit)
        exts = {}
        named = 0
        for i, v in hit:
            n = nodes[v]
            exts[n.rsplit(".", 1)[-1]] = exts.get(n.rsplit(".", 1)[-1], 0) + 1
            m = re.match(r"PATCH([0-9A-G])([0-9])\.PAT$", n)
            if m and i == COLS.index(m.group(1)) * 32 + int(m.group(2)):
                named += 1
            m = re.match(r"OBJ(\d\d)\.BLK$", n)
            if m and i == int(m.group(1)):
                named += 1
        print("  %-14s %5d slots  %4d used  %4d land on a node  "
              "%4d indexed by their own name  %s"
              % (name, len(slots), len(used), len(hit), named, exts))
        if len(hit) != len(used):
            print("     *** %d slots do not point at a node header ***"
                  % (len(used) - len(hit)))
    print()
    print("ofs: %d of %d non-empty slots land on an MDmd node header"
          % (total_hit, total_used))
    if a.expect_hits is not None and total_hit != a.expect_hits:
        raise SystemExit("ofs: expected %d hits, got %d"
                         % (a.expect_hits, total_hit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
