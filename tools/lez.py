#!/usr/bin/env python3
"""lez.py -- the decompressor for Moto Racer's `LEZ1` members.

Derived here from the 755 `.LEZ` members inside the 28 `.BKF` archives. It is
**not** the bit-stream unpacker `pc-cruiseforacorpse-doc/docs/04` derived from
the same company's 1991 title, and this file says so: that one is a single
stream read backwards with an XOR checksum in its trailer, and this one is
three parallel streams read forwards with no checksum at all. What the two
share is one habit -- the flag bits are consumed **thirty-two at a time** --
and one company.

The container:

    +0    4 bytes    'LEZ1'
    +4    u32        the unpacked size
    +8    u32        offset at which the FLAG stream ends and the TOKEN
                     stream begins
    +12   u32        offset at which the TOKEN stream ends and the LITERAL
                     stream begins
    +16   u16        height of the image
    +18   u16        width of the image
    +20   ...        the three streams, in that order, to the end of the member

The codec is LZSS over a **1,024-byte sliding window**:

  * FLAGS -- read as `u32` little-endian, bits consumed from bit 31 down to
    bit 0. The region is padded to a multiple of four bytes and the spare bits
    at the end are never reached. **This is the one thing that has to be right
    or nothing comes out**: byte-at-a-time MSB-first decodes 77 of the 755 and
    then wanders, which is exactly the sort of near-miss that looks like a
    working decoder. Consuming four bytes at a time is the one habit this
    codec shares with the 1991 one.
  * a 1 bit takes one byte from the LITERAL stream;
  * a 0 bit takes one `u16` little-endian from the TOKEN stream, whose low ten
    bits are the **distance back** to the match, 1..1,023, and whose top six
    bits are the match length minus three, so lengths run 3..66. The copy is
    byte at a time, so a distance shorter than the length is a run;
  * **the output is preceded by an implied run of zero bytes**: a distance
    that reaches back past the start of the output reads zeroes rather than
    failing. That is forced by the first match of most members, which fills
    the TGA header's x- and y-origin fields out of nothing.

A ring buffer of the same width decodes all 755 members to exactly the right
length with all three streams exhausted, and produces images that are visibly
almost right and wrong in every flat area. It is recorded here because it was
believed for an hour: **every arithmetic check this format offers passes under
the wrong model**, and the thing that failed it was looking at the picture.

The unpacked member is a **Truevision TGA**, and that is why the packed member
ends in the eighteen bytes `TRUEVISION-XFILE.` -- the tail of the image is the
tail of the literal stream, copied out unchanged.

    lez.py validate <memberdir>            every member, pass/fail
    lez.py census   <memberdir>            the images, by shape
    lez.py extract  <memberdir> <outdir>   write every member as a .tga
    lez.py selftest                        specimens built in memory
"""
import argparse
import collections
import os
import struct
import sys

WINDOW = 1024
MAXMATCH = 66
MINMATCH = 3
SIG = b"TRUEVISION-XFILE.\x00"


class LezError(Exception):
    pass


def unpack(d, name="<memory>"):
    """Return (image_bytes, stats). Raises LezError on anything unexpected."""
    if len(d) < 20:
        raise LezError("%s: %d bytes, shorter than the 20-byte header"
                       % (name, len(d)))
    if d[:4] != b"LEZ1":
        raise LezError("%s: magic is %r, not b'LEZ1'" % (name, d[:4]))
    size, fend, tend = struct.unpack_from("<3I", d, 4)
    height, width = struct.unpack_from("<2H", d, 16)
    if not 20 <= fend <= tend <= len(d):
        raise LezError("%s: stream offsets %d, %d out of order or outside a "
                       "%d-byte member" % (name, fend, tend, len(d)))
    if (fend - 20) % 4:
        raise LezError("%s: flag stream is %d bytes, not a multiple of four"
                       % (name, fend - 20))
    if (tend - fend) % 2:
        raise LezError("%s: token stream is %d bytes, not a multiple of two"
                       % (name, tend - fend))
    flags, toks, lits = d[20:fend], d[fend:tend], d[tend:]
    nbit, ntok, nlit = len(flags) * 8, len(toks) // 2, len(lits)
    out = bytearray()
    bi = ti = li = 0
    matched = 0
    presumed = 0
    while len(out) < size:
        if bi >= nbit:
            raise LezError("%s: flag stream exhausted with %d of %d bytes out"
                           % (name, len(out), size))
        word = struct.unpack_from("<I", flags, (bi >> 5) * 4)[0]
        bit = (word >> (31 - (bi & 31))) & 1
        bi += 1
        if bit:
            if li >= nlit:
                raise LezError("%s: literal stream exhausted with %d of %d "
                               "bytes out" % (name, len(out), size))
            out.append(lits[li])
            li += 1
        else:
            if ti >= ntok:
                raise LezError("%s: token stream exhausted with %d of %d "
                               "bytes out" % (name, len(out), size))
            v = struct.unpack_from("<H", toks, ti * 2)[0]
            ti += 1
            n = (v >> 10) + MINMATCH
            dist = v & (WINDOW - 1)
            if dist == 0:
                raise LezError("%s: token %d has distance zero" % (name, ti))
            matched += n
            p = len(out) - dist
            for _ in range(n):
                if p < 0:
                    out.append(0)
                    presumed += 1
                else:
                    out.append(out[p])
                p += 1
    if len(out) != size:
        raise LezError("%s: overshot the declared size by %d bytes"
                       % (name, len(out) - size))
    if ti != ntok:
        raise LezError("%s: %d of %d tokens left unread" % (name, ntok - ti,
                                                            ntok))
    if li != nlit:
        raise LezError("%s: %d of %d literals left unread" % (name, nlit - li,
                                                              nlit))
    if nbit - bi >= 32:
        raise LezError("%s: %d flag bits left over, more than one padding word"
                       % (name, nbit - bi))
    return bytes(out), {
        "size": size, "packed": len(d), "height": height, "width": width,
        "bits": bi, "bitpad": nbit - bi, "tokens": ntok, "literals": nlit,
        "matched": matched, "presumed": presumed,
    }


def tga_header(img):
    (idlen, cmaptype, imgtype, cmapfirst, cmaplen, cmapdepth,
     x, y, w, h, bpp, desc) = struct.unpack_from("<BBBHHBHHHHBB", img, 0)
    return dict(idlen=idlen, cmaptype=cmaptype, imgtype=imgtype,
                cmapfirst=cmapfirst, cmaplen=cmaplen, cmapdepth=cmapdepth,
                x=x, y=y, w=w, h=h, bpp=bpp, desc=desc)


def tga_closure(img, t):
    """18-byte header + colour map + image + whatever else + 26-byte footer.
    Returns the number of bytes not accounted for by header, map and pixels,
    minus the footer -- that is, the size of the developer/extension area."""
    cmapbytes = t["cmaplen"] * (t["cmapdepth"] // 8) if t["cmaptype"] else 0
    pixels = t["w"] * t["h"] * (t["bpp"] // 8)
    return len(img) - (18 + t["idlen"] + cmapbytes + pixels + 26)


def members(root, ext=".lez"):
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if fn.lower().endswith(ext):
                found.append(os.path.join(dirpath, fn))
    if not found:
        raise LezError("no %s member under %s -- refusing an empty population"
                       % (ext.upper(), root))
    return sorted(found)


def cmd_validate(args):
    paths = members(args.root)
    ok = 0
    sized = sig = hw = 0
    devsizes = collections.Counter()
    bad = []
    packed = out = 0
    padhist = collections.Counter()
    for p in paths:
        d = open(p, "rb").read()
        rel = os.path.relpath(p, args.root)
        try:
            img, st = unpack(d, rel)
        except LezError as e:
            bad.append(str(e))
            continue
        ok += 1
        packed += len(d)
        out += len(img)
        padhist[st["bitpad"]] += 1
        if img[-18:] == SIG:
            sig += 1
        t = tga_header(img)
        if (t["w"], t["h"]) == (st["width"], st["height"]):
            hw += 1
        if t["bpp"] in (8, 16, 24, 32) and t["imgtype"] in (1, 2, 3):
            sized += 1
            devsizes[tga_closure(img, t)] += 1
    print("members                          : %d" % len(paths))
    print("unpacked, all three streams exact: %d" % ok)
    for e in bad[:10]:
        print("   REFUSED %s" % e)
    print("packed bytes                     : %d" % packed)
    print("unpacked bytes                   : %d" % out)
    print("ratio                            : %.4fx" % (out / packed))
    print("header (h,w) == TGA (h,w)        : %d of %d" % (hw, ok))
    print("ends with TRUEVISION-XFILE.\\0     : %d of %d" % (sig, ok))
    print("TGA header sane (imgtype, bpp)   : %d of %d" % (sized, ok))
    print("leftover flag bits, histogram    : %s"
          % dict(sorted(padhist.items())))
    print("bytes after header+map+pixels+footer (the developer area):")
    for n, c in devsizes.most_common(8):
        print("   %8d bytes  x %d" % (n, c))
    return 0 if ok == len(paths) else 1


def cmd_census(args):
    paths = members(args.root)
    shape = collections.Counter()
    depth = collections.Counter()
    dims = collections.Counter()
    tot = 0
    for p in paths:
        d = open(p, "rb").read()
        img, st = unpack(d, os.path.relpath(p, args.root))
        t = tga_header(img)
        shape[(t["imgtype"], t["bpp"], t["cmaptype"], t["cmaplen"])] += 1
        depth[t["bpp"]] += 1
        dims[(t["w"], t["h"])] += 1
        tot += 1
    print("members : %d" % tot)
    print()
    print("%-9s %-5s %-9s %-9s %6s" % ("imgtype", "bpp", "cmaptype", "cmaplen",
                                       "count"))
    for (it, bpp, ct, cl), n in shape.most_common():
        print("%-9d %-5d %-9d %-9d %6d" % (it, bpp, ct, cl, n))
    print()
    print("the twelve most common image sizes:")
    for (w, h), n in dims.most_common(12):
        print("   %4d x %-4d  x %d" % (w, h, n))
    print()
    print("distinct sizes : %d" % len(dims))
    return 0


def cmd_extract(args):
    paths = members(args.root)
    n = 0
    for p in paths:
        d = open(p, "rb").read()
        img, _st = unpack(d, os.path.relpath(p, args.root))
        rel = os.path.relpath(p, args.root)
        dst = os.path.join(args.outdir, os.path.splitext(rel)[0] + ".tga")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as fh:
            fh.write(img)
        n += 1
    print("images written : %d" % n)
    return 0


def pack_trivial(payload, height=1, width=1):
    """Build a LEZ1 member whose payload is entirely literal. Used by the
    selftest, and it is the only encoder in this repository."""
    nbit = len(payload)
    words = (nbit + 31) // 32
    flags = bytearray(words * 4)
    for i in range(nbit):
        w = i >> 5
        b = 31 - (i & 31)
        v = struct.unpack_from("<I", flags, w * 4)[0] | (1 << b)
        struct.pack_into("<I", flags, w * 4, v)
    fend = 20 + len(flags)
    tend = fend
    return (b"LEZ1" + struct.pack("<3I", len(payload), fend, tend)
            + struct.pack("<2H", height, width) + bytes(flags) + payload)


def cmd_selftest(_args):
    body = bytes(range(256)) * 4
    good = pack_trivial(body, 16, 64)
    cases = [("a member that is all literals", good, body)]

    # one match: 3 zeroes out of the untouched ring, then a literal
    # bit 31 = 0 (a match), bit 30 = 1 (a literal), the rest never reached
    flags = struct.pack("<I", (0 << 31) | (1 << 30))
    m = b"LEZ1" + struct.pack("<3I", 4, 24, 26) + struct.pack("<2H", 1, 4) \
        + flags + struct.pack("<H", 5) + b"Z"
    cases.append(("one match of three presumed zeroes, then one literal", m,
                  b"\x00\x00\x00Z"))

    bad = [
        ("a member shorter than its header", b"LEZ1\x00\x00"),
        ("the wrong magic", b"LEZ2" + good[4:]),
        ("stream offsets out of order",
         good[:8] + struct.pack("<2I", 999999, 4) + good[16:]),
        ("a flag stream that is not a multiple of four",
         b"LEZ1" + struct.pack("<3I", 4, 22, 24) + struct.pack("<2H", 1, 4)
         + b"\xff\xff" + struct.pack("<H", 0) + b"AAAA"),
        ("a declared size larger than the streams can fill",
         b"LEZ1" + struct.pack("<3I", 4096, 24, 24) + struct.pack("<2H", 1, 4)
         + struct.pack("<I", 0xFFFFFFFF) + b"AAAA"),
        ("literals left over at the end",
         b"LEZ1" + struct.pack("<3I", 2, 24, 24) + struct.pack("<2H", 1, 2)
         + struct.pack("<I", 0xFFFFFFFF) + b"AAAA"),
    ]

    acc = ref = 0
    for label, blob, want in cases:
        try:
            got, _st = unpack(blob)
        except LezError as e:
            print("%-52s REFUSED (%s)   <-- UNEXPECTED" % (label, e))
            return 1
        if got != want:
            print("%-52s ACCEPTED but wrong: %r   <-- UNEXPECTED"
                  % (label, got))
            return 1
        print("%-52s ACCEPTED and correct" % label)
        acc += 1
    for label, blob in bad:
        try:
            unpack(blob)
        except LezError as e:
            print("%-52s REFUSED (%s)" % (label, e))
            ref += 1
        else:
            print("%-52s ACCEPTED   <-- UNEXPECTED" % label)
            return 1
    print()
    print("specimens %d : accepted and byte-exact %d, refused %d"
          % (len(cases) + len(bad), acc, ref))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("root")
    v.set_defaults(func=cmd_validate)
    c = sub.add_parser("census")
    c.add_argument("root")
    c.set_defaults(func=cmd_census)
    e = sub.add_parser("extract")
    e.add_argument("root")
    e.add_argument("outdir")
    e.set_defaults(func=cmd_extract)
    s = sub.add_parser("selftest")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args()
    try:
        return args.func(args)
    except LezError as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
