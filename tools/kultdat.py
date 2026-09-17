#!/usr/bin/env python3
"""kultdat.py -- read the level `.dat` texture archives of *Kult: Heretic
Kingdoms*, which are 1,518,490,468 bytes and 65.7703 % of the object.

WHAT A LEVEL `.dat` IS
----------------------
It has **no file header**. The pre-briefing read four `u32` at offset 0 --
`arena.dat` opening `128, 128, 10, 256` -- and treated them as one; they are
the header of the archive's *first member*, and the file's directory is the
`.idx` of the same stem (`tools/kultidx.py`), which gives every member a name
and a byte offset.

A member is

    +0   u32  width
    +4   u32  height
    +8   u32  format code   10 on 140,330 members, 2 on 4,140
    +12  u32  row stride in bytes
    +16       height x stride bytes of pixels

with **bpp 2 for format code 10 and 4 for format code 2**.

THE STRIDE, AND TWO WRONG RULES BEFORE THE RIGHT ONE
-----------------------------------------------------
The first acceptance test required `stride == width * bpp`. It closed 55
archives of 81 and left 106,132 bytes of residue, all of it in members whose
header read like `(w=1, h=256, fmt=10, stride=8)`: one pixel wide, eight bytes
a row. The second test required `stride == bpp * max(4, next_power_of_two(w))`,
which explains those and closed 78 -- and broke `(w=448, h=64, fmt=10,
stride=896)`, which is 448 x 2 exactly and would round to 1,024.

Both rules were guesses about the writer. The rule that closes all 81 asks
only what a decoder needs:

    fmt in {10, 2}   and   w > 0   and   h > 0
    stride >= w * bpp        (a row holds at least its pixels)
    stride % bpp == 0        (a row is a whole number of pixels)
    the payload fits in the file

Under it, **146,843 of 146,922 textures have stride exactly `w * bpp` and 79
carry one, two or three pixels of padding** -- and those 79 are the narrow
ones, widths 1, 2, 5, 6, 29 and 31. The padding is a fact about six textures'
worth of the archive and not a law, and it is reported rather than assumed.

THE STUB RECORD, WHICH IS FOUR BYTES
------------------------------------
Some index records do not own a texture. They occupy **four bytes** in the
`.dat` and their names are paths like `data/predmety/skin1.tga` -- the shared
item textures, which live in the `3d`/`textures` half of the object rather than
inside a level. 584 records over 78 archives are of that kind. They are
recognised by the acceptance test above failing, never by a hard-coded list,
and the four bytes are counted so the archive still closes at residue 0.

    python tools/kultdat.py selftest
    python tools/kultdat.py validate "<root>/data/levels/arena.dat"
    python tools/kultdat.py census   "<root>"
    python tools/kultdat.py members  "<root>/data/levels/arena.dat" --head 20
"""
import argparse
import collections
import os
import struct
import sys

BPP = {10: 2, 2: 4}
STUB = 4


class DatError(Exception):
    pass


def read_index(idx_path):
    from kultidx import parse
    blob = open(idx_path, "rb").read()
    count, width, recs = parse(blob, idx_path, strict=False)
    return recs


def member_header(blob, off):
    """Return (w, h, fmt, stride, payload) if this offset holds a texture
    header that agrees with itself, else None."""
    if off + 16 > len(blob):
        return None
    w, h, fmt, stride = struct.unpack_from("<4I", blob, off)
    if fmt not in BPP or w == 0 or h == 0:
        return None
    bpp = BPP[fmt]
    if stride < w * bpp or stride % bpp:
        return None
    if off + 16 + h * stride > len(blob):
        return None
    return w, h, fmt, stride, h * stride


def walk(dat_path, idx_path):
    """Return (members, stubs, accounted, size, anomalies)."""
    blob = open(dat_path, "rb").read()
    recs = read_index(idx_path)
    members = []
    stubs = 0
    accounted = 0
    anomalies = []
    for i, (name, off) in enumerate(recs):
        nxt = recs[i + 1][1] if i + 1 < len(recs) else len(blob)
        hdr = member_header(blob, off)
        if hdr is None:
            stubs += 1
            accounted += STUB
            if nxt - off != STUB:
                anomalies.append((i, name, off, nxt - off, "stub, gap %d not %d"
                                  % (nxt - off, STUB)))
            continue
        w, h, fmt, stride, payload = hdr
        size = 16 + payload
        accounted += size
        members.append((name, off, w, h, fmt, size, stride))
        if nxt - off != size:
            anomalies.append((i, name, off, nxt - off,
                              "declares %d, gap is %d" % (size, nxt - off)))
    return members, stubs, accounted, len(blob), anomalies


def cmd_validate(a):
    idx = os.path.splitext(a.path)[0] + ".idx"
    if not os.path.exists(idx):
        raise DatError("%s: no .idx of the same stem, and this format has no "
                       "directory of its own" % a.path)
    members, stubs, accounted, size, anomalies = walk(a.path, idx)
    print("archive     : %s" % a.path)
    print("index       : %s" % os.path.basename(idx))
    print("bytes       : %d" % size)
    print("records     : %d = %d textures + %d stubs"
          % (len(members) + stubs, len(members), stubs))
    print("accounted   : %d  (16-byte headers, payloads, and %d x 4 stub bytes)"
          % (accounted, stubs))
    print("residue     : %d  %s" % (size - accounted,
                                    "-- CLOSES" if size == accounted
                                    else "-- DOES NOT CLOSE"))
    print("anomalies   : %d" % len(anomalies))
    dims = collections.Counter((w, h) for _, _, w, h, _, _, _ in members)
    fmts = collections.Counter(f for _, _, _, _, f, _, _ in members)
    print("format codes: %s"
          % ", ".join("%d on %d members (%d bytes per pixel)" % (f, n, BPP[f])
                      for f, n in fmts.most_common()))
    print("dimensions  : %s"
          % ", ".join("%dx%d on %d" % (w, h, n) for (w, h), n in dims.most_common(6)))
    for row in anomalies[:10]:
        print("   anomaly rec %d %r at +%d: %s" % (row[0], row[1][:40], row[2], row[4]))


def cmd_members(a):
    idx = os.path.splitext(a.path)[0] + ".idx"
    members, stubs, accounted, size, anomalies = walk(a.path, idx)
    for name, off, w, h, fmt, msize, stride in members[:a.head]:
        print("%10d %5dx%-5d fmt %2d  %8d  %s" % (off, w, h, fmt, msize, name))


def cmd_census(a):
    rows = []
    tot_size = tot_acc = tot_mem = tot_stub = 0
    dims = collections.Counter()
    fmts = collections.Counter()
    pad = collections.Counter()
    closing = 0
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames.sort()
        for fn in sorted(filenames):
            if not fn.lower().endswith(".idx"):
                continue
            idx = os.path.join(dirpath, fn)
            dat = os.path.splitext(idx)[0] + ".dat"
            if not os.path.exists(dat):
                rows.append((os.path.relpath(idx, a.root), None, 0, 0, 0, 0, 0))
                continue
            members, stubs, accounted, size, anomalies = walk(dat, idx)
            rel = os.path.relpath(dat, a.root)
            rows.append((rel, size, len(members), stubs, accounted,
                         size - accounted, len(anomalies)))
            tot_size += size
            tot_acc += accounted
            tot_mem += len(members)
            tot_stub += stubs
            if size == accounted and not anomalies:
                closing += 1
            for _, _, w, h, f, _, stride in members:
                dims[(w, h)] += 1
                fmts[f] += 1
                pad[stride // BPP[f] - w] += 1

    print("%-40s %12s %8s %6s %12s %9s %5s"
          % ("archive", "bytes", "textures", "stubs", "accounted", "residue", "anom"))
    for rel, size, mem, stub, acc, res, anom in rows:
        if size is None:
            print("%-40s %12s" % (rel, "(no .dat)"))
            continue
        print("%-40s %12d %8d %6d %12d %9d %5d"
              % (rel, size, mem, stub, acc, res, anom))
    print()
    print("archives          : %d" % sum(1 for r in rows if r[1] is not None))
    print("closing at residue 0 with no anomaly : %d" % closing)
    print("bytes             : %d" % tot_size)
    print("accounted         : %d" % tot_acc)
    print("RESIDUE           : %d" % (tot_size - tot_acc))
    print("textures          : %d" % tot_mem)
    print("stub records      : %d" % tot_stub)
    print("format codes      : %s"
          % ", ".join("%d on %d (%d bpp)" % (f, n, BPP[f]) for f, n in fmts.most_common()))
    print("stride padding    : %s"
          % ", ".join("%d pixels on %d textures" % (p, n)
                      for p, n in sorted(pad.items())))
    print()
    print("the twelve commonest texture dimensions:")
    for (w, h), n in dims.most_common(12):
        print("   %4d x %-4d  %8d" % (w, h, n))
    return 1 if tot_size != tot_acc else 0


def cmd_selftest(a):
    """Built archives. The positive one must yield exactly the members named."""
    def tex(w, h, fmt, fill):
        stride = w * BPP[fmt]
        return struct.pack("<4I", w, h, fmt, stride) + bytes([fill]) * (h * stride)

    ok = True
    blob = tex(2, 2, 10, 0xAB) + b"\x00\x00\x00\x00" + tex(1, 1, 2, 0xCD)
    print("POSITIVE -- a built archive of texture, stub, texture:")
    offs = [0, 16 + 8, 16 + 8 + 4]
    got = []
    for off in offs:
        h = member_header(blob, off)
        got.append(None if h is None else (h[0], h[1], h[2], 16 + h[4]))
    want = [(2, 2, 10, 24), None, (1, 1, 2, 20)]
    good = got == want
    print("   %-5s %r" % ("ok" if good else "FAIL", got))
    if not good:
        print("         wanted %r" % (want,))
    ok = ok and good

    print()
    print("NEGATIVE -- these offsets must not be read as textures:")
    cases = [
        ("all zeros", bytes(64), 0),
        ("a stride shorter than one row of pixels",
         struct.pack("<4I", 64, 64, 10, 64) + bytes(8192), 0),
        ("a stride that is not a whole number of pixels",
         struct.pack("<4I", 64, 64, 2, 999) + bytes(1 << 20), 0),
        ("an unknown format code",
         struct.pack("<4I", 64, 64, 7, 128) + bytes(8192), 0),
        ("zero width", struct.pack("<4I", 0, 64, 10, 0) + bytes(64), 0),
        ("a payload past the end of the file",
         struct.pack("<4I", 64, 64, 10, 128) + bytes(16), 0),
        ("past the end of the file", bytes(8), 4),
        ("a TGA header", bytes([0, 0, 2, 0]) + bytes(60), 0),
    ]
    for name, blob2, off in cases:
        h = member_header(blob2, off)
        if h is None:
            print("   ok    %-42s refused" % name)
        else:
            print("   FAIL  %-42s ACCEPTED as %r" % (name, h[:4]))
            ok = False
    print()
    print("1 positive, %d negative, %s"
          % (len(cases), "all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("validate"); p.add_argument("path"); p.set_defaults(fn=cmd_validate)
    p = sub.add_parser("members"); p.add_argument("path")
    p.add_argument("--head", type=int, default=20); p.set_defaults(fn=cmd_members)
    p = sub.add_parser("census"); p.add_argument("root"); p.set_defaults(fn=cmd_census)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    try:
        rc = a.fn(a)
    except DatError as exc:
        sys.exit("DatError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
