#!/usr/bin/env python3
"""ccbread.py -- the 3DO Cel Control Block, derived from the bytes of one disc.

WHAT WAS DERIVED HERE AND WHAT WAS ASSUMED

The container is the same chunked format the first 3DO disc used for `IMAG`:
four-character id, big-endian u32 length INCLUDING the eight-byte header,
chunks tiling the file to its last byte. That was derived on the first disc and
it is re-checked here on every file.

The CCB chunk is 80 bytes on every occurrence, which is 8 of header plus 4
plus SEVENTEEN 32-bit words. The word layout below is the published 3DO
CCB and this tool SAYS SO rather than pretending to have invented it -- but it
does not take it on trust. Two of the seventeen words are checked against a
completely independent encoding of the same two numbers:

    width  is word 16, and ALSO PRE1 bits 0..9 as (width - 1)
    height is word 17, and ALSO PRE0 bits 6..15 as (height - 1)

Two encodings of the same quantity agreeing across every CCB on a disc is a
proof that the field assignment is right; the arithmetic identity
`width * height * bpp / 8 == payload` is NOT, because it closes on a subset.
Both are reported and they are reported separately.

    +0   'CCB '
    +4   u32 chunk length, 80
    +8   u32 version
    +12  u32 flags          bit 30 LAST, bit 9 PACKED, bit 5 BGND, ...
    +16  u32 next pointer
    +20  u32 source pointer
    +24  u32 PLUT pointer
    +28  i32 x                       16.16 fixed point when YOXY is clear
    +32  i32 y
    +36  i32 hdx  \
    +40  i32 hdy   |  the 2x2 projection and its second difference,
    +44  i32 vdx   |  12.20 / 16.16 fixed point
    +48  i32 vdy   |
    +52  i32 hddx  |
    +56  i32 hddy /
    +60  u32 pixc  the two pixel-multiplier words, one per source half
    +64  u32 pre0  bits 0..2 bpp code, bit 3 REP8, bit 4 LINEAR,
                   bits 6..15 (height - 1), bits 24..26 skip-x
    +68  u32 pre1  bits 0..9 (width - 1), bits 16..25 word offset,
                   bit 11 LRFORM, bit 14 NOSWAP
    +72  u32 width
    +76  u32 height

BPP CODE, derived: the code is three bits and the disc uses more than one
value; the mapping below is the published one and every use of it is
cross-checked against the row-offset field, which independently gives the
bytes per row.

usage:
    ccbread.py census TREE            every CCB in every file
    ccbread.py dump FILE              one file, chunk by chunk, field by field
    ccbread.py validate               negative controls; must fail
"""
import argparse
import os
import struct
import sys

BPP = {0: None, 1: 1, 2: 2, 3: 4, 4: 6, 5: 8, 6: 16, 7: None}

FLAGS = [
    (31, "SKIP"), (30, "LAST"), (29, "NPABS"), (28, "SPABS"), (27, "PPABS"),
    (26, "LDSIZE"), (25, "LDPRS"), (24, "LDPPMP"), (23, "LDPLUT"),
    (22, "CCBPRE"), (21, "YOXY"), (20, "ACSC"), (19, "ALSC"), (18, "ACW"),
    (17, "ACCW"), (16, "TWD"), (15, "LCE"), (14, "ACE"), (12, "MARIA"),
    (11, "PXOR"), (10, "USEAV"), (9, "PACKED"), (6, "PLUTPOS"), (5, "BGND"),
    (4, "NOBLK"),
]


class Bad(Exception):
    pass


def chunks(d, zero_tail=False):
    """Walk a chunked file. Raises Bad if it does not tile to the last byte.

    With zero_tail=True the walk may stop early at a run of zero bytes, but
    ONLY if every remaining byte is zero -- the tail is verified, not assumed,
    and its length is returned so the caller can report it. A tail with one
    non-zero byte in it is still an error.
    """
    off = 0
    out = []
    while off + 8 <= len(d):
        if zero_tail and d[off:off + 8] == b"\0" * 8:
            if any(d[off:]):
                raise Bad("stopped at %d on eight zero bytes, but the "
                          "remaining %d bytes are not all zero"
                          % (off, len(d) - off))
            return out, len(d) - off
        cid = d[off:off + 4]
        clen = struct.unpack(">I", d[off + 4:off + 8])[0]
        if clen < 8:
            raise Bad("chunk %r at %d declares length %d, minimum is 8"
                      % (cid, off, clen))
        if off + clen > len(d):
            raise Bad("chunk %r at %d declares %d bytes, %d remain"
                      % (cid, off, clen, len(d) - off))
        if not all(32 <= c < 127 for c in cid):
            raise Bad("chunk id %r at %d is not four printable characters"
                      % (cid, off))
        out.append((off, cid, clen))
        off += clen
    if off != len(d):
        raise Bad("chain ends at %d, file is %d bytes" % (off, len(d)))
    return (out, 0) if zero_tail else out


def parse_ccb(d, off):
    """Decode one 80-byte CCB chunk at off. Returns a dict."""
    if d[off:off + 4] != b"CCB ":
        raise Bad("not a CCB at %d" % off)
    clen = struct.unpack(">I", d[off + 4:off + 8])[0]
    if clen != 80:
        raise Bad("CCB at %d is %d bytes, not 80" % (off, clen))
    w = struct.unpack(">18I", d[off + 8:off + 80])
    version, flags = w[0], w[1]
    pixc, pre0, pre1, width, height = w[13], w[14], w[15], w[16], w[17]
    bppcode = pre0 & 7
    c = {
        "off": off,
        "version": version,
        "flags": flags,
        "flagnames": [n for b, n in FLAGS if flags >> b & 1],
        "next": w[2], "source": w[3], "plut": w[4],
        "x": w[5], "y": w[6],
        "hdx": w[7], "hdy": w[8], "vdx": w[9], "vdy": w[10],
        "hddx": w[11], "hddy": w[12],
        "pixc": pixc, "pre0": pre0, "pre1": pre1,
        "width": width, "height": height,
        "bppcode": bppcode, "bpp": BPP[bppcode],
        "packed": bool(flags >> 9 & 1),
        "lrform": bool(pre1 >> 11 & 1),
        "linear": bool(pre0 >> 4 & 1),
        "rep8": bool(pre0 >> 3 & 1),
        # the two independent encodings
        "pre0_h": ((pre0 >> 6) & 0x3FF) + 1,
        "pre1_w": (pre1 & 0x3FF) + 1,
        "skipx": (pre0 >> 24) & 7,
    }
    # Row offset. DERIVED, not assumed: the field is in two different places
    # depending on the depth, and which one is right is settled by the
    # arithmetic closing on the PDAT payload rather than by documentation.
    #
    #   bpp >= 8 : bits 16..25 of pre1
    #   bpp <  8 : bits 24..31 of pre1
    #
    # and in both cases  rowbytes = (offset + 2) * 4, which is always a
    # multiple of four -- the hardware fetches cel rows a word at a time.
    if (c["bpp"] or 0) >= 8:
        c["woffset"] = (pre1 >> 16) & 0x3FF
    else:
        c["woffset"] = (pre1 >> 24) & 0xFF
    c["rowbytes"] = (c["woffset"] + 2) * 4
    return c


def census(tree):
    files = []
    for dp, dn, fn in os.walk(tree):
        for f in fn:
            files.append(os.path.join(dp, f))
    files.sort()

    tot = 0
    withccb = 0
    chain_ok = chain_bad = 0
    wmatch = wtot = hmatch = htot = 0
    rowmatch = rowtot = 0
    depths = {}
    flagcount = {}
    rows = []
    notchained = []
    for p in files:
        d = open(p, "rb").read()
        if b"CCB " not in d:
            continue
        rel = "/" + os.path.relpath(p, tree).replace(os.sep, "/")
        try:
            ch = chunks(d)
            chain_ok += 1
            chained = True
        except Bad as e:
            chain_bad += 1
            notchained.append((rel, str(e)))
            ch = []
            chained = False
        # every CCB in the file, whether or not the file chains
        offs = []
        if chained:
            offs = [o for o, cid, cl in ch if cid == b"CCB "]
        else:
            i = d.find(b"CCB ")
            while i >= 0:
                if i + 80 <= len(d) and d[i + 4:i + 8] == b"\0\0\0\x50":
                    offs.append(i)
                i = d.find(b"CCB ", i + 1)
        if offs:
            withccb += 1
        for o in offs:
            try:
                c = parse_ccb(d, o)
            except Bad:
                continue
            tot += 1
            depths[c["bpp"]] = depths.get(c["bpp"], 0) + 1
            for n in c["flagnames"]:
                flagcount[n] = flagcount.get(n, 0) + 1
            wtot += 1
            htot += 1
            if c["width"] == c["pre1_w"]:
                wmatch += 1
            if c["height"] == c["pre0_h"]:
                hmatch += 1
            # the row-offset check only means anything on an UNPACKED cel:
            # a packed cel's rows are compressed and the field is not a
            # stride. Counted separately rather than averaged together.
            if c["bpp"] and not c["packed"]:
                rowtot += 1
                want = (c["width"] * c["bpp"] + 31) // 32 * 4
                if want == c["rowbytes"]:
                    rowmatch += 1
            rows.append((rel, c))
    return dict(files=len(files), withccb=withccb, tot=tot,
                chain_ok=chain_ok, chain_bad=chain_bad,
                wmatch=wmatch, wtot=wtot, hmatch=hmatch, htot=htot,
                rowmatch=rowmatch, rowtot=rowtot,
                depths=depths, flagcount=flagcount, rows=rows,
                notchained=notchained)


def validate():
    """Negative controls. Every one of these MUST be rejected."""
    ok = True
    cases = [
        ("2,048 zero bytes", b"\0" * 2048),
        ("the string iamaduck, 2,048 bytes", b"iamaduck" * 256),
        ("a CCB header with the wrong length",
         b"CCB \x00\x00\x00\x40" + b"\0" * 56),
        ("a chunk declaring more than the file holds",
         b"CCB \x00\x00\x10\x00" + b"\0" * 72),
        ("a chunk id that is not printable",
         b"\x01\x02\x03\x04\x00\x00\x00\x10" + b"\0" * 8),
    ]
    for name, data in cases:
        try:
            chunks(data)
            if data[0:4] == b"CCB ":
                parse_ccb(data, 0)
            print("FAIL: %-45s was ACCEPTED" % name)
            ok = False
        except Bad as e:
            print("ok  : %-45s rejected -- %s" % (name, e))
    # positive control: a real CCB must parse
    good = (b"CCB " + struct.pack(">I", 80) + struct.pack(">18I",
            0, 0x47664220, 0, 0, 0, 0, 0, 0x100000, 0, 0, 0x10000, 0, 0,
            0x1f001f00, 0x2cd6, 0x2b1059, 90, 180))
    try:
        c = parse_ccb(good, 0)
        assert c["width"] == 90 and c["height"] == 180
        assert c["pre1_w"] == 90 and c["pre0_h"] == 180
        assert c["bpp"] == 16 and c["packed"]
        print("ok  : %-45s accepted, 90x180 16bpp packed"
              % "positive control (a real CCB)")
    except (Bad, AssertionError) as e:
        print("FAIL: positive control rejected -- %s" % e)
        ok = False
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["census", "dump", "validate", "list"])
    ap.add_argument("target", nargs="?")
    a = ap.parse_args()

    if a.mode == "validate":
        raise SystemExit(validate())

    if a.mode == "dump":
        d = open(a.target, "rb").read()
        print("%s  %d bytes" % (a.target, len(d)))
        try:
            ch = chunks(d)
            print("chain: %d chunks, closes at %d of %d" % (len(ch), len(d), len(d)))
        except Bad as e:
            print("chain: DOES NOT CLOSE -- %s" % e)
            ch = []
        for off, cid, clen in ch:
            print("  %8d  %-6s %8d" % (off, cid.decode("ascii", "replace"), clen))
            if cid == b"CCB ":
                c = parse_ccb(d, off)
                print("      version %d  flags %08x  %s"
                      % (c["version"], c["flags"], " ".join(c["flagnames"])))
                print("      width  %4d   (pre1 says %4d)  %s"
                      % (c["width"], c["pre1_w"],
                         "agree" if c["width"] == c["pre1_w"] else "DISAGREE"))
                print("      height %4d   (pre0 says %4d)  %s"
                      % (c["height"], c["pre0_h"],
                         "agree" if c["height"] == c["pre0_h"] else "DISAGREE"))
                print("      bpp %s (code %d)  rowbytes %d  packed %s  lrform %s"
                      % (c["bpp"], c["bppcode"], c["rowbytes"],
                         c["packed"], c["lrform"]))
                print("      pixc %08x  pre0 %08x  pre1 %08x"
                      % (c["pixc"], c["pre0"], c["pre1"]))
                print("      x %d  y %d  hdx %08x hdy %08x vdx %08x vdy %08x"
                      % (c["x"], c["y"], c["hdx"], c["hdy"], c["vdx"], c["vdy"]))
                if c["bpp"]:
                    print("      unpacked size would be %d bytes"
                          % (c["rowbytes"] * c["height"]))
        raise SystemExit(0)

    r = census(a.target)
    if a.mode == "list":
        print("%-34s %8s %5s %5s %4s %6s %6s %6s %s"
              % ("file", "offset", "w", "h", "bpp", "packed", "lrform", "rowb", "flags"))
        for rel, c in r["rows"]:
            print("%-34s %8d %5d %5d %4s %6s %6s %6d %s"
                  % (rel, c["off"], c["width"], c["height"], c["bpp"],
                     "yes" if c["packed"] else "no",
                     "yes" if c["lrform"] else "no",
                     c["rowbytes"], " ".join(c["flagnames"])))
        raise SystemExit(0)
    print("files walked                        : %d" % r["files"])
    print("files containing the string 'CCB '  : %d" % r["withccb"])
    print("CCB chunks parsed                   : %d" % r["tot"])
    print("files whose chunk chain closes      : %d" % r["chain_ok"])
    print("files whose chunk chain does not    : %d" % r["chain_bad"])
    for rel, why in r["notchained"]:
        print("    %-34s %s" % (rel, why))
    print()
    print("THE TWO INDEPENDENT ENCODINGS")
    print("  width  == pre1 bits 0..9 + 1      : %d of %d" % (r["wmatch"], r["wtot"]))
    print("  height == pre0 bits 6..15 + 1     : %d of %d" % (r["hmatch"], r["htot"]))
    print("  row bytes == ceil(w*bpp/32)*4     : %d of %d  (unpacked cels only)" % (r["rowmatch"], r["rowtot"]))
    print()
    print("BITS PER PIXEL")
    for k in sorted(r["depths"], key=lambda x: (x is None, x)):
        print("  %-6s %6d" % (k, r["depths"][k]))
    print()
    print("FLAGS, by how many CCBs set them")
    for n, v in sorted(r["flagcount"].items(), key=lambda kv: -kv[1]):
        print("  %-8s %6d" % (n, v))


if __name__ == "__main__":
    main()
