#!/usr/bin/env python3
"""crossmembers.py -- do two games of the same studio share any bytes?

For twelve sessions this collection has published the rule *no byte of game
data ever crosses between two objects*, and `crossall.py` has verified it by
hashing whole files. Whole files were all it could hash: every object so far was
either alone in its series or stored its data in a container nobody had opened.

This is the first session where two members of the same series are both
installed and both containers are readable, so the rule can be tested at the
level that matters. This tool hashes the MEMBERS, not the files: every member of
one or more `EmPackFi` archives (Broken Sword 4, read by `empack.py`) against
every member of Broken Sword 3's `data.pak` (read by the framing `pak.py`
derived last session), and intersects the digests.

A crossing here would mean an asset survived from one game to the next. An
empty intersection is the stronger result and is reported as such, with the
number of members and bytes on each side, because an absence without a
denominator is not a measurement.

Nothing is extracted; members are hashed by streaming and never written.

    python tools/crossmembers.py --empack "<install dir>/bs4.pak" --tsv MEMBERS.tsv \\
                                 --pak "<other install>/data.pak"
    python tools/crossmembers.py --empack A.pak --tsv A.tsv \\
                                 --empack B.pak --tsv B.tsv --pak data.pak
"""
import argparse
import collections
import csv
import hashlib
import os
import struct
import sys

BUF = 1 << 20


def digest(fh, offset, size):
    h = hashlib.sha1()
    fh.seek(offset)
    left = size
    while left:
        b = fh.read(min(BUF, left))
        if not b:
            break
        h.update(b)
        left -= len(b)
    return h.hexdigest()


def read_pak(path):
    """Broken Sword 3's data.pak: u32 count, count x (0, key, offset, size)."""
    fh = open(path, "rb")
    n = os.path.getsize(path)
    count = struct.unpack("<I", fh.read(4))[0]
    if 4 + count * 16 > n:
        raise SystemExit("%s: %d members do not fit" % (path, count))
    raw = fh.read(count * 16)
    out = []
    for i in range(count):
        z, key, off, size = struct.unpack_from("<IIII", raw, i * 16)
        if z != 0 or off + size > n:
            raise SystemExit("%s: record %d does not close" % (path, i))
        out.append((("key:0x%08X" % key), size, off))
    return fh, out


def read_empack(path, tsv):
    fh = open(path, "rb")
    rows = list(csv.DictReader(open(tsv, encoding="utf-8"), delimiter="\t"))
    return fh, [(r["name"], int(r["size"]), int(r["offset"])) for r in rows]


def read_vt7a(path, tsv=None):
    """Broken Sword 5's VT7A: 'VT7A', u32 version, u32 magic2, u32 count, then
    count x (u32 key, u32 offset, u32 size_raw, u32 size_stored).  The extent on
    disk is size_stored, or size_raw when size_stored is zero."""
    fh = open(path, "rb")
    n = os.path.getsize(path)
    head = fh.read(16)
    if head[:4] != b"VT7A":
        raise SystemExit("%s: not a VT7A archive" % path)
    ver, m2, count = struct.unpack_from("<III", head, 4)
    raw = fh.read(16 * count)
    out = []
    for i in range(count):
        key, off, sraw, sst = struct.unpack_from("<IIII", raw, i * 16)
        ext = sst if sst else sraw
        if off + ext > n:
            raise SystemExit("%s: record %d does not close" % (path, i))
        out.append((("key:%d" % key), ext, off))
    return fh, out


def read_aufs(path, tsv=None):
    """Broken Sword 5's AUFS: 'AUFS', u32 count, then count x (u32 id,
    u32 offset, u32 size)."""
    fh = open(path, "rb")
    n = os.path.getsize(path)
    head = fh.read(8)
    if head[:4] != b"AUFS":
        raise SystemExit("%s: not an AUFS archive" % path)
    count = struct.unpack_from("<I", head, 4)[0]
    raw = fh.read(12 * count)
    out = []
    for i in range(count):
        ident, off, size = struct.unpack_from("<III", raw, i * 12)
        if off + size > n:
            raise SystemExit("%s: record %d does not close" % (path, i))
        out.append((("id:%d" % ident), size, off))
    return fh, out


READERS = {"pak": read_pak, "empack": read_empack,
           "vt7a": read_vt7a, "aufs": read_aufs}


def load_side(kind, path, tsv, min_size):
    fh, mem = READERS[kind](path, tsv) if kind == "empack" \
        else READERS[kind](path)
    base = os.path.basename(path)
    out = {}
    nbytes = 0
    for nm, size, off in mem:
        if size < min_size:
            continue
        out.setdefault(digest(fh, off, size), []).append((base, nm, size))
        nbytes += size
    return out, nbytes, len(mem)


def nway(sides, min_size):
    """sides: list of (label, [(kind, path, tsv), ...])"""
    loaded = []
    for label, parts in sides:
        digests = {}
        nbytes = 0
        nmem = 0
        for kind, path, tsv in parts:
            d, b, m = load_side(kind, path, tsv, min_size)
            for k, v in d.items():
                digests.setdefault(k, []).extend(v)
            nbytes += b
            nmem += m
            print("   read %-22s %-7s %7d members" % (os.path.basename(path),
                                                      kind, m))
        loaded.append((label, digests, nbytes, nmem))
        print("side %-18s %7d members, %6d distinct sha1, %14d bytes"
              % (label, nmem, len(digests), nbytes))
        print()
    print("=" * 72)
    print("pairwise intersections of the member digests")
    print()
    print("%-20s %s" % ("", " ".join("%18s" % l[:18] for l, _d, _b, _n in loaded)))
    for la, da, _b, _n in loaded:
        row = []
        for lb, db, _b2, _n2 in loaded:
            row.append("%18d" % (len(set(da) & set(db)) if la != lb else len(da)))
        print("%-20s %s" % (la, " ".join(row)))
    print()
    crossing = 0
    for i in range(len(loaded)):
        for j in range(i + 1, len(loaded)):
            la, da = loaded[i][0], loaded[i][1]
            lb, db = loaded[j][0], loaded[j][1]
            common = set(da) & set(db)
            print("%-20s vs %-20s : %d members share bytes"
                  % (la, lb, len(common)))
            crossing += len(common)
            for h in sorted(common)[:20]:
                for base, nm, size in da[h][:1]:
                    print("      %-18s %10d  %s" % (base, size, nm))
                for base, nm, size in db[h][:1]:
                    print("      %-18s %10d  %s" % (base, size, nm))
                print("      sha1 %s" % h)
    if len(loaded) >= 3:
        allthree = set(loaded[0][1])
        for _l, d, _b, _n in loaded[1:]:
            allthree &= set(d)
        print()
        print("members present in ALL %d sides : %d" % (len(loaded), len(allthree)))
    print()
    if crossing == 0:
        tot_m = sum(x[3] for x in loaded)
        tot_b = sum(x[2] for x in loaded)
        print("NOTHING CROSSES ANYWHERE.  %d members and %d bytes on %d sides,"
              % (tot_m, tot_b, len(loaded)))
        print("and not one digest appears twice.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", action="append", default=[],
                    help="LABEL=KIND:PATH[,KIND:PATH...] where KIND is one of "
                         "pak, vt7a, aufs, or empack:PATH@TSV.  Repeat for as "
                         "many objects as there are; every pair is reported.")
    ap.add_argument("--empack", action="append", default=[])
    ap.add_argument("--tsv", action="append", default=[])
    ap.add_argument("--pak", action="append", default=[])
    ap.add_argument("--min-size", type=int, default=1,
                    help="ignore members smaller than this (a zero-length or "
                         "one-byte member would cross trivially)")
    a = ap.parse_args()
    if a.side:
        sides = []
        for spec in a.side:
            label, rest = spec.split("=", 1)
            parts = []
            for chunk in rest.split(","):
                # split once only: a Windows path carries its own colon, and
                # splitting on every colon turns "pak:F:/GOG/..." into "F".
                kind, path = chunk.split(":", 1)
                tsv = None
                if "@" in path:
                    path, tsv = path.split("@", 1)
                if kind not in READERS:
                    raise SystemExit("unknown side kind %r" % kind)
                parts.append((kind, path, tsv))
            sides.append((label, parts))
        return nway(sides, a.min_size)
    if len(a.empack) != len(a.tsv):
        raise SystemExit("--empack and --tsv must come in pairs")

    left = {}
    leftbytes = 0
    for path, tsv in zip(a.empack, a.tsv):
        fh, mem = read_empack(path, tsv)
        base = os.path.basename(path)
        for nm, size, off in mem:
            if size < a.min_size:
                continue
            left.setdefault(digest(fh, off, size), []).append((base, nm, size))
            leftbytes += size
        print("read %-16s %6d members" % (base, len(mem)))

    right = {}
    rightbytes = 0
    for path in a.pak:
        fh, mem = read_pak(path)
        base = os.path.basename(path)
        for nm, size, off in mem:
            if size < a.min_size:
                continue
            right.setdefault(digest(fh, off, size), []).append((base, nm, size))
            rightbytes += size
        print("read %-16s %6d members" % (base, len(mem)))

    print()
    print("side A : %d distinct sha1 over %d members, %d bytes"
          % (len(left), sum(len(v) for v in left.values()), leftbytes))
    print("side B : %d distinct sha1 over %d members, %d bytes"
          % (len(right), sum(len(v) for v in right.values()), rightbytes))
    common = set(left) & set(right)
    print("members whose bytes are identical across the two objects : %d"
          % len(common))
    if not common:
        print()
        print("NOTHING CROSSES. The two archives share no member, byte for byte,")
        print("over %d + %d members and %d + %d bytes."
              % (sum(len(v) for v in left.values()),
                 sum(len(v) for v in right.values()), leftbytes, rightbytes))
    else:
        tot = 0
        for h in sorted(common):
            for base, nm, size in left[h]:
                print("   A  %-14s %9d  %s" % (base, size, nm))
            for base, nm, size in right[h]:
                print("   B  %-14s %9d  %s" % (base, size, nm))
                tot += size
            print("   sha1 %s" % h)
        print("crossing bytes (counted on side B): %d" % tot)

    print()
    print("-- duplication WITHIN each side --")
    dupA = sum(len(v) - 1 for v in left.values() if len(v) > 1)
    dupB = sum(len(v) - 1 for v in right.values() if len(v) > 1)
    print("side A: %d members are byte-identical to an earlier member" % dupA)
    print("side B: %d members are byte-identical to an earlier member" % dupB)
    if dupA:
        big = sorted((v for v in left.values() if len(v) > 1),
                     key=lambda v: v[0][2] * (len(v) - 1), reverse=True)[:5]
        for v in big:
            print("   A x%d  %d bytes each  %s" % (len(v), v[0][2], v[0][1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
