#!/usr/bin/env python3
"""emdhead.py -- the header shared by `.EMD`, `.PLD` and `.PLW`, tested.

Yesterday's object put its characters in PlayStation TMD blocks and
`psblocks.py` validated 828 of them. On this object the same tool validates
**ten**, and the characters are still there -- so either the models moved or
the tool went blind. This settles which, by deriving the container's header
from the population instead of from one file.

The claim under test is a single equation:

    dword at offset 0  ==  file size  -  4 * (dword at offset 4)

If it holds on every file of a family, the two dwords are a length and a count
and the four bytes per count are a table -- and the header is derived. If it
holds on some and not others, it is a coincidence and is reported as one.

The second claim under test is negative and matters more: that the geometry
inside is **not** TMD. A PlayStation TMD begins with the dword 0x00000041, a
flags word, and an object count, followed by that many 28-byte object records
whose pointers stay inside the file. The tool finds every occurrence of the id
bytes and checks the rest of the header at each, so "the magic is present" and
"a TMD is present" are separated -- they are not the same claim, and on this
object they give different answers.

    python tools/emdhead.py DIR
    python tools/emdhead.py DIR --ext .emd .pld .plw --sections

No constant in this file belongs to any particular disc.
"""

import argparse
import collections
import os
import struct


def tmd_at(b, off):
    """Does a plausible TMD header start here? ECMA nothing -- this is Sony's
    TMD as published in the PlayStation developer documentation: id, flags,
    nobj, then nobj object records of 28 bytes."""
    if off + 12 > len(b):
        return False
    idw, flags, nobj = struct.unpack_from("<III", b, off)
    if idw != 0x41 or flags > 1 or nobj == 0 or nobj > 4096:
        return False
    if off + 12 + 28 * nobj > len(b):
        return False
    for k in range(nobj):
        o = off + 12 + 28 * k
        vtop, nvert, ntop, nnorm, ptop, npoly, scale = struct.unpack_from(
            "<IIIIIIi", b, o)
        if nvert == 0 or nvert > 65535 or npoly > 65535:
            return False
        base = off + 12 if flags == 0 else 0
        if base + vtop + 8 * nvert > len(b):
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--ext", nargs="*", default=[".emd", ".pld", ".plw"])
    ap.add_argument("--sections", action="store_true")
    a = ap.parse_args()

    exts = tuple(e.lower() for e in a.ext)
    fam = collections.defaultdict(list)
    for dp, dn, fn in os.walk(a.path):
        for f in sorted(fn):
            e = os.path.splitext(f)[1].lower()
            if e in exts:
                fam[e].append(os.path.join(dp, f))

    for e in sorted(fam):
        ps = fam[e]
        holds = 0
        counts = collections.Counter()
        tabok = 0
        magic = 0
        realtmd = 0
        total = 0
        for p in ps:
            b = open(p, "rb").read()
            total += len(b)
            if len(b) < 8:
                continue
            d0, d1 = struct.unpack_from("<II", b, 0)
            counts[d1] += 1
            if d1 and d0 == len(b) - 4 * d1:
                holds += 1
            # And the table is not at offset 8; it is at offset dword0, which
            # is the same thing as the last 4*dword1 bytes. dword0 therefore
            # names two things at once -- the length of the content and the
            # place the section table begins -- and the sections it points at
            # start at 8, immediately after the header.
            if d1 and d0 + 4 * d1 <= len(b):
                vals = struct.unpack_from("<%dI" % d1, b, d0)
                if (all(8 <= v <= d0 for v in vals)
                        and all(vals[i] <= vals[i + 1] for i in range(d1 - 1))
                        and vals[0] == 8):
                    tabok += 1
            pos = b.find(b"\x41\x00\x00\x00")
            if pos >= 0:
                magic += 1
            found = False
            while pos >= 0:
                if tmd_at(b, pos):
                    found = True
                    break
                pos = b.find(b"\x41\x00\x00\x00", pos + 1)
            if found:
                realtmd += 1
        print("=" * 70)
        print("%s : %d files, %d bytes" % (e, len(ps), total))
        print("   dword0 == size - 4*dword1        : %d of %d" % (holds, len(ps)))
        print("   dword1 values                    : %s"
              % ", ".join("%d x%d" % kv for kv in sorted(counts.items())))
        print("   section table at dword0, ascending, inside [8,dword0],")
        print("   and beginning at 8               : %d of %d" % (tabok, len(ps)))
        print("   files containing the bytes 41 00 00 00 : %d" % magic)
        print("   files where a TMD header VALIDATES     : %d" % realtmd)
        if a.sections and ps:
            b = open(ps[0], "rb").read()
            d0, d1 = struct.unpack_from("<II", b, 0)
            print("   %s: size %d, dword0 %d, dword1 %d"
                  % (os.path.basename(ps[0]), len(b), d0, d1))
            vals = struct.unpack_from("<%dI" % d1, b, d0)
            print("   section table at %d: %s"
                  % (d0, ", ".join(str(v) for v in vals)))


if __name__ == "__main__":
    main()
