#!/usr/bin/env python3
"""pat.py -- the `.PAT` terrain patch: a 32 x 32 mesh and a list of somethings.

153 of the 304 members of this object are `.PAT`, the largest single category,
and no session before this one parsed one. The record closes exactly:

    +0      4096 bytes   1024 vertices, each   u8 x   u8 y   u16 LE z
    +4096   u16 LE  n
    +4098   n x 7 bytes  records this reader DOES NOT NAME

THE THREE THINGS THAT MAKE IT A FORMAT AND NOT A READING

  * `n` is the count encoded twice: `4098 + 7*n == len(record)` on
    **153 of 153** members, and the tail length is congruent to 2 mod 7 on all
    of them;
  * the 1024 vertices are 32 rows of 32, and **x is non-decreasing across every
    row, on 153 of 153**. A byte pair read at the wrong stride is not monotone;
  * the degenerate case is present and behaves: four members of `practice.crx`
    are byte-identical at 4098 bytes -- the minimum -- with `n == 0`, and their
    vertices sit exactly on the 8-unit lattice `x = 8*col, y = 8*row`. A flat
    patch is flat.

WHAT IS NOT NAMED, DELIBERATELY

  The **7-byte trailing records**, 2,186 of them across the object. They read
  as `u16, u16, u16, u8` with the second field descending in exact steps within
  a group, which is the shape of something placed along a line. Trees, hazards,
  pin positions and sprinkler heads are all consistent with that and the bytes
  do not choose between them. They are described in the leftovers chapter and
  they are not given field names here.

  The **units of z** are not named either. The range over all 153 members is
  225..35,222, which is a fixed-point something and not feet.

    python tools/pat.py FILE...
    python tools/pat.py FILE... --map OUT.png --grid 17x9    (a course mosaic)
"""
import argparse
import os
import re
import struct
import sys

VERTS = 1024
MESH = VERTS * 4
COLS = "0123456789ABCDEFG"


class PatError(Exception):
    pass


def parse(data, name="<data>"):
    if len(data) < MESH + 2:
        raise PatError("%s: %d bytes cannot hold a 1024-vertex mesh and a "
                       "count" % (name, len(data)))
    verts = []
    for i in range(VERTS):
        x, y, z = data[i * 4], data[i * 4 + 1], struct.unpack_from(
            "<H", data, i * 4 + 2)[0]
        verts.append((x, y, z))
    for r in range(32):
        prev = -1
        for c in range(32):
            x = verts[r * 32 + c][0]
            if x < prev:
                raise PatError("%s: row %d column %d: x went %d -> %d, not "
                               "monotone" % (name, r, c, prev, x))
            prev = x
    n = struct.unpack_from("<H", data, MESH)[0]
    if MESH + 2 + 7 * n != len(data):
        raise PatError("%s: count %d needs %d bytes, record is %d"
                       % (name, n, MESH + 2 + 7 * n, len(data)))
    return verts, n, data[MESH + 2:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--map", metavar="OUT.png")
    ap.add_argument("--grid", default="17x9")
    ap.add_argument("--expect-ok", type=int)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    gw, gh = (int(v) for v in a.grid.lower().split("x"))
    ok = bad = 0
    tiles = {}
    zlo, zhi, nrec = 1 << 30, 0, 0
    for p in a.files:
        name = os.path.basename(p)
        try:
            verts, n, tail = parse(open(p, "rb").read(), name)
        except PatError as e:
            bad += 1
            print("REFUSED  %s" % e)
            continue
        ok += 1
        nrec += n
        zs = [v[2] for v in verts]
        zlo, zhi = min(zlo, min(zs)), max(zhi, max(zs))
        if not a.quiet:
            print("OK       %-16s %6d B  z %5d..%-5d  %3d trailing records"
                  % (name, os.path.getsize(p), min(zs), max(zs), n))
        m = re.search(r"PATCH([0-9A-G])([0-9])\.PAT$", name.upper())
        if m:
            # ORIENTATION IS MEASURED, NOT ASSUMED. Reading the first name
            # character as the column gives a mean seam discontinuity of 7,815
            # across vertical patch edges; reading it as the ROW gives 747,
            # against an unrelated-tile control of 12,694. Ten times better
            # than the control and six times better than the other reading, so
            # the first character is the row and the second is the column.
            tiles[(int(m.group(2)), COLS.index(m.group(1)))] = zs

    print()
    print("pat: %d accepted, %d refused, %d files; z %d..%d over the set; "
          "%d trailing records" % (ok, bad, ok + bad, zlo, zhi, nrec))

    if a.map:
        if not tiles:
            raise SystemExit("pat: --map found no PATCHcr names to place")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import cellras
        W, H = gw * 32, gh * 32
        span = max(1, zhi - zlo)
        buf = bytearray([0]) * (W * H)
        for (cx, cy), zs in tiles.items():
            if cx >= gw or cy >= gh:
                raise SystemExit("pat: tile (%d,%d) is outside %dx%d"
                                 % (cx, cy, gw, gh))
            for r in range(32):
                row = cy * 32 + r
                for c in range(32):
                    v = 1 + (zs[r * 32 + c] - zlo) * 254 // span
                    buf[row * W + cx * 32 + c] = v
        pal = bytearray()
        for i in range(256):
            pal += bytes((i, i, i))
        cellras.write_png(a.map, W, H, bytes(buf), bytes(pal))
        print("map: %s  %d x %d  from %d of %d grid cells, z %d..%d -> 1..255"
              % (a.map, W, H, len(tiles), gw * gh, zlo, zhi))

    if a.expect_ok is not None and ok != a.expect_ok:
        raise SystemExit("pat: expected %d accepted, got %d" % (a.expect_ok, ok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
