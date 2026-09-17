#!/usr/bin/env python3
"""tfcref.py -- do the packages point into the texture caches, and do the
offsets they declare land where `tfc.py` says an entry begins?

THE TEST
--------
`tools/tfc.py --walk` walks the three `.tfc` from byte 0 to the last byte as a
chain of `FCompressedChunkHeader` and gets residue 0 on all three, 38,820
entries. That is a reading of the caches alone, and on its own it proves only
that the chain hypothesis is self-consistent.

This program tests it against a second, independent witness. Every
`Texture2D`-shaped export in the packages carries, after its property list, an
array of mips, and every mip carries four integers:

    u32 BulkDataFlags       0x01 = the payload is in a separate file
                            0x10 = the payload is LZO-compressed
    i32 ElementCount        the mip's uncompressed size in bytes
    i32 BulkDataSizeOnDisk  what the payload occupies in that file
    i32 BulkDataOffsetInFile

and a `TextureFileCacheName` property naming which of the three caches it
means. **If the chain reading is right, every one of those offsets is the
start offset of an entry the walk found, and the sizes agree too.** If it is
wrong, they will not be, and this program will say so.

That is a closure across two files that were parsed by two different readers
with no shared assumption but the sixteen-byte chunk header.

    python tools/tfcref.py --selftest
    python tools/tfcref.py --run
    python tools/tfcref.py --run --limit 20
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kfpkg as upkg                                       # noqa: E402
import tfc                                        # noqa: E402

BULKDATA_STORE_IN_SEPARATE_FILE = 0x01
BULKDATA_LZO = 0x10


class BadExport(Exception):
    pass


def read_properties(d, o, names):
    """UE3 FPropertyTag list, terminated by the name `None`."""
    out = []
    guard = 0
    while True:
        guard += 1
        if guard > 4096:
            raise BadExport("property list did not terminate")
        nm, _, o2 = _fname(d, o, names)
        if nm == "None":
            return out, o2
        ty, _, o3 = _fname(d, o2, names)
        size, index = struct.unpack_from("<2i", d, o3)
        o4 = o3 + 8
        extra = None
        if ty == "StructProperty":
            extra, _, o4 = _fname(d, o4, names)
        elif ty == "ByteProperty":
            extra, _, o4 = _fname(d, o4, names)
        elif ty == "BoolProperty":
            extra = d[o4]
            o4 += 1
        if size < 0 or o4 + size > len(d):
            raise BadExport("property %s declares %d bytes" % (nm, size))
        value = None
        if ty == "NameProperty":
            value = _fname(d, o4, names)[0]
        elif ty == "IntProperty":
            (value,) = struct.unpack_from("<i", d, o4)
        out.append((nm, ty, size, index, extra, value))
        o = o4 + size


def _fname(d, o, names):
    a, b = struct.unpack_from("<2i", d, o)
    base = names[a] if 0 <= a < len(names) else "<name %d>" % a
    return (base if b == 0 else "%s_%d" % (base, b - 1)), b, o + 8


def read_bulk(d, o):
    """FUntypedBulkData's four integers, plus any inline payload."""
    flags, count, disk, off = struct.unpack_from("<4i", d, o)
    o += 16
    if not (flags & BULKDATA_STORE_IN_SEPARATE_FILE) and disk > 0:
        o += disk
    return (flags, count, disk, off), o


def textures_in(pkg, names, imps, exps, d):
    """Yield (export, cachename, [mips]) for every Texture2D-shaped export."""
    for x in exps:
        cls = upkg.resolve(x["class"], exps, imps) or ""
        if "Texture2D" not in cls:
            continue
        try:
            o = x["offset"] + 4          # the leading NetIndex
            props, o = read_properties(d, o, names)
            cache = None
            for (nm, ty, _s, _i, _e, v) in props:
                if nm == "TextureFileCacheName":
                    cache = v
            _sourceart, o = read_bulk(d, o)
            (nmips,) = struct.unpack_from("<i", d, o)
            o += 4
            if not 0 <= nmips <= 64:
                raise BadExport("mip count %d" % nmips)
            mips = []
            for _ in range(nmips):
                b, o = read_bulk(d, o)
                sx, sy = struct.unpack_from("<2i", d, o)
                o += 8
                mips.append((b, sx, sy))
            o += 16                      # TextureFileCacheGuid
            tail = (x["offset"] + x["size"]) - o
        except (BadExport, struct.error, IndexError) as e:
            yield x, cls, None, None, str(e)
            continue
        yield x, cls, cache, mips, tail


def cmd_run(args):
    # 1. the caches, walked
    starts = {}
    entry = {}
    for c in tfc.CACHES:
        base = os.path.splitext(os.path.basename(c))[0]
        p = os.path.join(args.root, c)
        data = open(p, "rb").read()
        s = {}
        for e in tfc.entries(data):
            s[e["offset"]] = (e["usize"], e["end"] - e["offset"])
        starts[base] = set(s)
        entry[base] = s
        del data
    print("cache entry starts, from tfc.py's walk:")
    for k in sorted(starts):
        print("   %-14s %8d entries" % (k, len(starts[k])))
    print()

    # 2. the packages, read
    hits = misses = 0
    size_ok = size_bad = 0
    inline = 0
    named = collections.Counter()
    unnamed_cache = 0
    tails = collections.Counter()
    failures = 0
    npkg = 0
    ntex = 0
    miss_examples = []
    by_cache = collections.Counter()
    claimed = collections.defaultdict(set)
    lzo_flag = collections.Counter()
    for p in sorted(upkg.tagged(args.root)):
        try:
            pkg = upkg.Package(p)
            names = pkg.names()
            imps = pkg.imports(names)
            exps = pkg.exports(names)
        except Exception:
            continue
        if not any("Texture2D" in (upkg.resolve(x["class"], exps, imps) or "")
                   for x in exps):
            continue
        pkg._logical = None
        try:
            d = pkg.logical()
        except Exception as e:
            print("   %-52s could not decompress: %s" % (upkg.rel(p), e))
            continue
        npkg += 1
        for x, cls, cache, mips, tail in textures_in(pkg, names, imps, exps, d):
            ntex += 1
            if mips is None:
                failures += 1
                continue
            tails[tail] += 1
            named[cls] += 1
            for (b, sx, sy) in mips:
                flags, count, disk, off = b
                if not (flags & BULKDATA_STORE_IN_SEPARATE_FILE):
                    inline += 1
                    continue
                lzo_flag[flags] += 1
                if cache is None:
                    unnamed_cache += 1
                    continue
                by_cache[cache] += 1
                s = entry.get(cache)
                if s is None:
                    misses += 1
                    continue
                if off in s:
                    hits += 1
                    claimed[cache].add(off)
                    if s[off][1] == disk:
                        size_ok += 1
                    else:
                        size_bad += 1
                else:
                    misses += 1
                    if len(miss_examples) < 8:
                        miss_examples.append((upkg.rel(p), x["name"], cache,
                                              off, disk, count))
        pkg._logical = None
        if args.limit and npkg >= args.limit:
            break

    print("packages holding a Texture2D-shaped export, read : %d" % npkg)
    print("Texture2D-shaped exports read                    : %d" % ntex)
    print("exports this reader could not parse              : %d" % failures)
    print()
    print("classes seen : %s" % dict(named))
    print("bulk-data flag words on separate-file mips : %s"
          % {("0x%02X" % k): v for k, v in lzo_flag.items()})
    print("mips stored inline in the package          : %d" % inline)
    print("mips claiming a separate file              : %d"
          % (hits + misses + unnamed_cache))
    print("   with no TextureFileCacheName property   : %d" % unnamed_cache)
    print("   by cache : %s" % dict(by_cache))
    print()
    print("THE CLOSURE")
    print("  declared offsets that land exactly on an entry the walk found:")
    print("     %d of %d = %.4f %%"
          % (hits, hits + misses, 100.0 * hits / max(hits + misses, 1)))
    print("  of those, the declared on-disk size equals the entry's length:")
    print("     %d of %d, disagreeing %d" % (size_ok, hits, size_bad))
    print()
    print("THE OTHER DIRECTION: cache entries nobody claims")
    for k in sorted(entry):
        allof = set(entry[k])
        cl = claimed.get(k, set())
        orphan = allof - cl
        ob = sum(entry[k][o][1] for o in orphan)
        print("  %-14s entries %6d  claimed %6d  ORPHAN %6d  orphan bytes %d"
              % (k, len(allof), len(cl), len(orphan), ob))
        print("     claims made %6d, so the mean entry is claimed %.4f times"
              % (by_cache[k], by_cache[k] / float(max(len(cl), 1))))
    if miss_examples:
        print()
        print("  the first misses:")
        for m in miss_examples:
            print("     %s  %s  %s off %d disk %d count %d" % m)
    print()
    print("the residue between where this reader stops in an export and where")
    print("the export table says it ends (unnamed trailing fields):")
    for k, v in sorted(tails.items()):
        print("   %+6d bytes  x%d" % (k, v))
    return 0


def selftest():
    names = ["None", "SizeX", "IntProperty", "TextureFileCacheName",
             "NameProperty", "Textures", "BoolProperty", "SRGB"]

    def nm(s, n=0):
        return struct.pack("<2i", names.index(s), n)

    good = bytearray()
    good += nm("SizeX") + nm("IntProperty") + struct.pack("<2i", 4, 0)
    good += struct.pack("<i", 1024)
    good += nm("SRGB") + nm("BoolProperty") + struct.pack("<2i", 0, 0) + b"\x01"
    good += (nm("TextureFileCacheName") + nm("NameProperty")
             + struct.pack("<2i", 8, 0) + nm("Textures"))
    good += nm("None")

    cases = []
    props, end = read_properties(bytes(good), 0, names)
    cases.append(("a three-property list", len(props) == 3
                  and props[2][5] == "Textures" and end == len(good)))

    # Truncating the list is NOT the test: a run of zero bytes reads as name
    # index 0, which is `None`, and terminates cleanly. The test that bites is
    # a list of valid records that never terminates.
    one = nm("SizeX") + nm("IntProperty") + struct.pack("<3i", 4, 0, 7)
    unterminated = one * 5000
    try:
        read_properties(unterminated, 0, names)
        cases.append(("a property list that never says None", False))
    except (BadExport, struct.error, IndexError):
        cases.append(("a property list that never says None", True))

    huge = bytearray(good)
    struct.pack_into("<i", huge, 16, 1 << 30)
    try:
        read_properties(bytes(huge), 0, names)
        cases.append(("a property declaring a gigabyte", False))
    except BadExport:
        cases.append(("a property declaring a gigabyte", True))

    b = struct.pack("<4i", 0x11, 8192, 7364, 100749196)
    got, o = read_bulk(b, 0)
    cases.append(("a separate-file mip consumes 16 bytes and no payload",
                  o == 16 and got[0] == 0x11))

    inline = struct.pack("<4i", 0, 2048, 2048, 40) + bytes(2048)
    got, o = read_bulk(inline, 0)
    cases.append(("an inline mip consumes its payload too", o == 16 + 2048))

    ok = sum(1 for _n, v in cases if v)
    print("tfcref selftest: %d specimens built in memory" % len(cases))
    for n, v in cases:
        print("  %-58s %s" % (n, "PASS" if v else "FAIL"))
    print()
    print("%d of %d specimens behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=upkg.ROOT)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--run", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.run:
        return cmd_run(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
