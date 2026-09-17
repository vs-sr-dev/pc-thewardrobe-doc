#!/usr/bin/env python3
"""tfc.py -- what a `.tfc` is, derived from its own bytes.

THE STARTING POINT
------------------
Three files, 1,178,381,951 bytes, 25.5360 % of the object. They begin with the
Unreal package tag `0x9E2A83C1` and they are not packages: read as one, the
folder-name length field comes out 8,192 or 16,384 bytes long, and
`tools/kfpkg.py --validate` refuses all three on that arithmetic.

WHAT THEY ARE INSTEAD, AND HOW IT WAS FOUND
-------------------------------------------
The same tag is the first field of `FCompressedChunkHeader`, the sixteen-byte
prologue that sits in front of every compressed chunk *inside* a package:

    u32 tag = 0x9E2A83C1
    u32 block size          131072 everywhere in this object
    u32 total compressed
    u32 total uncompressed
    then ceil(total uncompressed / block size) pairs of
        u32 compressed, u32 uncompressed
    then the compressed blocks, back to back

Reading a `.tfc` as **a chain of those, one after another with no padding**
walks all three files from byte 0 to the last byte with residue 0. There is no
directory, no index and no trailer: the file is a heap of independently
addressable LZO streams, and whatever names them lives somewhere else.

That "somewhere else" is the packages, and this program tests that separately
by asking whether the three cache names appear in the packages' name tables.

    python tools/tfc.py --selftest
    python tools/tfc.py --walk
    python tools/tfc.py --decompress --sample 8
    python tools/tfc.py --whonames
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzo1x import decompress, LzoError            # noqa: E402
import kfpkg as upkg                                       # noqa: E402

ROOT = "karmaflow-steam"
TAG = 0x9E2A83C1
CACHES = ["KFGame/CookedPC/CharTextures.tfc",
          "KFGame/CookedPC/Lighting.tfc",
          "KFGame/CookedPC/Textures.tfc"]


class NotAChunkChain(Exception):
    pass


def entries(data, limit=None):
    """Walk a chain of FCompressedChunkHeader. Yields dicts; raises on the
    first byte that is not one."""
    o = 0
    n = len(data)
    i = 0
    while o < n:
        if o + 16 > n:
            raise NotAChunkChain("entry %d at %d: only %d bytes left, a header "
                                 "needs 16" % (i, o, n - o))
        tag, block, ctot, utot = struct.unpack_from("<4I", data, o)
        if tag != TAG:
            raise NotAChunkChain("entry %d at %d: tag is 0x%08X, not 0x%08X"
                                 % (i, o, tag, TAG))
        if block == 0 or block > (1 << 24):
            raise NotAChunkChain("entry %d at %d: block size %d"
                                 % (i, o, block))
        if utot == 0 or utot > (1 << 30) or ctot == 0 or ctot > (1 << 30):
            raise NotAChunkChain("entry %d at %d: sizes %d/%d"
                                 % (i, o, ctot, utot))
        nb = (utot + block - 1) // block
        if o + 16 + 8 * nb > n:
            raise NotAChunkChain("entry %d at %d: %d block records run past "
                                 "the end" % (i, o, nb))
        blocks = []
        p = o + 16
        for _ in range(nb):
            blocks.append(struct.unpack_from("<2I", data, p))
            p += 8
        if sum(b[0] for b in blocks) != ctot:
            raise NotAChunkChain("entry %d at %d: block compressed sizes sum "
                                 "to %d, header says %d"
                                 % (i, o, sum(b[0] for b in blocks), ctot))
        if sum(b[1] for b in blocks) != utot:
            raise NotAChunkChain("entry %d at %d: block uncompressed sizes sum "
                                 "to %d, header says %d"
                                 % (i, o, sum(b[1] for b in blocks), utot))
        end = p + ctot
        if end > n:
            raise NotAChunkChain("entry %d at %d: payload runs to %d past the "
                                 "end %d" % (i, o, end, n))
        yield {"index": i, "offset": o, "block": block, "csize": ctot,
               "usize": utot, "blocks": blocks, "data_at": p, "end": end}
        o = end
        i += 1
        if limit and i >= limit:
            return


def cmd_walk(args):
    grand_c = grand_u = grand_n = 0
    hist = collections.Counter()
    print("%-28s %13s %8s %13s %13s %7s %8s"
          % ("cache", "bytes", "entries", "compressed", "uncompressed",
             "ratio", "residue"))
    for c in CACHES:
        p = os.path.join(args.root, c)
        data = open(p, "rb").read()
        n = 0
        tc = tu = 0
        last = 0
        try:
            for e in entries(data):
                n += 1
                tc += e["csize"]
                tu += e["usize"]
                hist[e["usize"]] += 1
                last = e["end"]
        except NotAChunkChain as ex:
            print("%-28s REFUSED %s" % (os.path.basename(c), ex))
            continue
        print("%-28s %13d %8d %13d %13d %7.4f %8d"
              % (os.path.basename(c), len(data), n, tc, tu,
                 tu / float(tc), len(data) - last))
        grand_c += tc
        grand_u += tu
        grand_n += n
    print()
    print("three caches      : %d entries" % grand_n)
    print("bytes on disk     : %d" % sum(os.path.getsize(os.path.join(args.root, c))
                                         for c in CACHES))
    print("payload compressed: %d" % grand_c)
    print("declared uncompressed : %d" % grand_u)
    print("ratio             : %.4f" % (grand_u / float(grand_c)))
    print()
    print("the entry uncompressed sizes, which are mip sizes:")
    for k, v in sorted(hist.items()):
        print("   %10d  x%-7d %s" % (k, v, _mipnote(k)))
    print()
    print("distinct sizes    : %d" % len(hist))
    print("all of them a power of two : %s"
          % all((k & (k - 1)) == 0 for k in hist))
    return 0


def _mipnote(n):
    """A DXT1 mip of side s is s*s/2 bytes; DXT5 and 8-bit are s*s."""
    out = []
    half = n * 2
    s = int(round(half ** 0.5))
    if s * s == half:
        out.append("DXT1 %dx%d" % (s, s))
    s = int(round(n ** 0.5))
    if s * s == n:
        out.append("DXT5/8bpp %dx%d" % (s, s))
    return "  ".join(out)


def cmd_decompress(args):
    ok = bad = 0
    tot_in = tot_out = 0
    for c in CACHES:
        p = os.path.join(args.root, c)
        data = open(p, "rb").read()
        taken = 0
        for e in entries(data):
            if taken >= args.sample:
                break
            taken += 1
            o = e["data_at"]
            got = 0
            try:
                for (cs, us) in e["blocks"]:
                    out = decompress(data[o:o + cs], expected=us)
                    got += len(out)
                    o += cs
                if got != e["usize"]:
                    raise LzoError("entry produced %d, declared %d"
                                   % (got, e["usize"]))
                ok += 1
                tot_in += e["csize"]
                tot_out += got
            except LzoError as ex:
                bad += 1
                print("   %s entry %d REFUSED: %s"
                      % (os.path.basename(c), e["index"], ex))
    print("entries decompressed with the package codec (LZO) : %d" % ok)
    print("entries refused                                   : %d" % bad)
    print("bytes in %d -> bytes out %d, ratio %.4f"
          % (tot_in, tot_out, tot_out / float(max(tot_in, 1))))
    print()
    print("The caches use the same codec and the same chunk header as the")
    print("packages, which is the argument that they are one mechanism and")
    print("not two.")
    return 0


def cmd_whonames(args):
    """Do the packages name the caches? The cache base names are FNames if
    they do, so this looks in the name tables and nowhere else."""
    want = {"CharTextures", "Lighting", "Textures", "TextureFileCacheName"}
    found = collections.Counter()
    where = collections.defaultdict(list)
    npkg = 0
    for p in upkg.tagged(args.root):
        try:
            pkg = upkg.Package(p)
            names = pkg.names()
        except Exception:
            continue
        npkg += 1
        s = set(names)
        for w in want:
            if w in s:
                found[w] += 1
                where[w].append(upkg.rel(p))
    print("packages whose name table was read : %d" % npkg)
    for w in sorted(want):
        print("  %-22s appears in %3d of %d name tables"
              % (w, found[w], npkg))
    print()
    for w in sorted(want):
        if where[w]:
            print("  %s, first eight:" % w)
            for r in where[w][:8]:
                print("     %s" % r)
    return 0


# ---------------------------------------------------------------- selftest

def _chain(entry_sizes):
    out = bytearray()
    for u in entry_sizes:
        block = 131072
        nb = (u + block - 1) // block
        blocks = []
        rem = u
        for _ in range(nb):
            take = min(block, rem)
            rem -= take
            blocks.append((take // 2, take))
        ctot = sum(b[0] for b in blocks)
        out += struct.pack("<4I", TAG, block, ctot, u)
        for b in blocks:
            out += struct.pack("<2I", b[0], b[1])
        out += bytes(ctot)
    return bytes(out)


def selftest():
    cases = []
    cases.append(("a three-entry chain", _chain([8192, 32768, 131072]), 3, True))
    cases.append(("one entry spanning four blocks", _chain([131072 * 4]), 1,
                  True))
    good = _chain([8192])
    cases.append(("a chain with one trailing byte", good + b"\x00", None,
                  False))
    cases.append(("the tag replaced",
                  struct.pack("<4I", 0x12345678, 131072, 10, 8192), None,
                  False))
    bad = bytearray(_chain([8192]))
    struct.pack_into("<I", bad, 8, 9999)     # total compressed disagrees
    cases.append(("block sizes that do not sum to the header", bytes(bad),
                  None, False))
    bad = bytearray(_chain([8192]))
    struct.pack_into("<I", bad, 12, 12345)   # uncompressed disagrees
    cases.append(("uncompressed total that does not sum", bytes(bad), None,
                  False))
    cases.append(("a truncated payload", _chain([131072])[:-100], None, False))
    cases.append(("the package summary of Core.u, which is not a chain",
                  struct.pack("<I", TAG) + struct.pack("<HH", 868, 0)
                  + struct.pack("<i", 132112) + struct.pack("<i", 5)
                  + b"None\0" + bytes(64), None, False))

    ok = 0
    accepted = refused = 0
    print("tfc selftest: %d specimens built in memory" % len(cases))
    for name, blob, want, should_pass in cases:
        try:
            got = list(entries(blob))
            passed = should_pass and (want is None or len(got) == want)
            note = "accepted, %d entries" % len(got)
            accepted += 1
        except NotAChunkChain as e:
            passed = not should_pass
            note = "refused: %s" % str(e)[:64]
            refused += 1
        print("  %-52s %-5s %s" % (name, "PASS" if passed else "FAIL", note))
        ok += 1 if passed else 0
    print()
    print("accepted %d, refused %d, of %d" % (accepted, refused, len(cases)))
    print("%d of %d specimens behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--sample", type=int, default=8)
    for c in ("selftest", "walk", "decompress", "whonames"):
        ap.add_argument("--" + c, action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.walk:
        return cmd_walk(a)
    if a.decompress:
        return cmd_decompress(a)
    if a.whonames:
        return cmd_whonames(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
