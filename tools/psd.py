#!/usr/bin/env python3
"""psd.py -- walk an Adobe Photoshop file's five top-level sections and land on
its last byte, or say where it stopped.

WHY THIS ONE IS DIFFERENT FROM THE OTHER READERS IN THIS BOX
------------------------------------------------------------
Every other format this pipeline has had to write a reader for was
reverse-engineered by other people and never specified by its vendor: ITSF,
LCF, and now LCF's two map variants. **This one Adobe published.** The file
format specification is a document from the company that made the format, and
an implementer works from it.

So the sentence about the `.psd` in this object is not "nobody has described
this". It is "everybody has described this and nobody in this box had
implemented it", which is a fact about the box and not about the world. That is
why `coverage.py` files a PSD as SPECIFIED and files an `.lmu` as DECODED, and
why the two are counted on separate rows.

THE FIVE SECTIONS
-----------------
    26  header : '8BPS', version u16, six reserved bytes, channels u16,
        height u32, width u32, depth u16, colour mode u16
    +   colour mode data   : u32 length, then that many bytes
    +   image resources    : u32 length, then that many bytes
    +   layer and mask     : u32 length, then that many bytes
    +   image data         : compression u16, then the rest of the file

The first four lengths are declared and the fifth is not, so the closure test
is: **do 26 plus the four declared lengths plus 2 land at or before the end,
and is what remains the image data**. A file whose declared lengths overrun is
refused.

    python tools/psd.py <file.psd>
    python tools/psd.py <file.psd> --resources
    python tools/psd.py --selftest
"""
import argparse
import os
import struct
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

COLOUR_MODES = {0: "bitmap", 1: "greyscale", 2: "indexed", 3: "RGB",
                4: "CMYK", 7: "multichannel", 8: "duotone", 9: "Lab"}
COMPRESSION = {0: "raw", 1: "RLE (PackBits)", 2: "ZIP without prediction",
               3: "ZIP with prediction"}


class Bad(Exception):
    pass


def walk(blob):
    if blob[:4] != b"8BPS":
        raise Bad("no 8BPS signature")
    if len(blob) < 26:
        raise Bad("shorter than a 26-byte header")
    version, = struct.unpack(">H", blob[4:6])
    reserved = blob[6:12]
    channels, height, width, depth, mode = struct.unpack(">HIIHH", blob[12:26])
    out = {"version": version, "reserved_zero": reserved == bytes(6),
           "channels": channels, "height": height, "width": width,
           "depth": depth, "mode": mode, "bytes": len(blob), "sections": []}
    p = 26
    for name in ("colour mode data", "image resources", "layer and mask"):
        if p + 4 > len(blob):
            raise Bad("the %s length runs off the end at %d" % (name, p))
        (n,) = struct.unpack(">I", blob[p:p + 4])
        if p + 4 + n > len(blob):
            raise Bad("the %s section at %d declares %d bytes and only %d "
                      "remain" % (name, p, n, len(blob) - p - 4))
        out["sections"].append((name, p, n))
        p += 4 + n
    if p + 2 > len(blob):
        raise Bad("no room for the image data compression word at %d" % p)
    (comp,) = struct.unpack(">H", blob[p:p + 2])
    out["compression"] = comp
    out["image_data_at"] = p + 2
    out["image_data_bytes"] = len(blob) - p - 2
    out["declared_end"] = p + 2
    out["residue"] = 0 if out["image_data_bytes"] >= 0 else -1
    return out


def resources(blob, at, n):
    """The '8BIM' image resource blocks, walked."""
    out = []
    p = at
    end = at + n
    while p < end:
        if blob[p:p + 4] != b"8BIM":
            raise Bad("a resource block at %d does not begin 8BIM" % p)
        (rid,) = struct.unpack(">H", blob[p + 4:p + 6])
        nlen = blob[p + 6]
        name = blob[p + 7:p + 7 + nlen]
        q = p + 6 + 1 + nlen
        if (q - p) % 2:
            q += 1
        (size,) = struct.unpack(">I", blob[q:q + 4])
        q += 4
        data = blob[q:q + size]
        q += size + (size % 2)
        out.append((rid, name, size, data))
        p = q
    if p != end:
        raise Bad("the resource walk ends at %d of %d" % (p, end))
    return out


def run(args):
    blob = open(args.path, "rb").read()
    d = walk(blob)
    print("file        : %s" % os.path.basename(args.path))
    print("bytes       : %d" % d["bytes"])
    print("signature   : 8BPS, version %d" % d["version"])
    print("reserved six bytes are zero : %s" % d["reserved_zero"])
    print("channels    : %d" % d["channels"])
    print("size        : %d x %d  (width x height)" % (d["width"],
                                                       d["height"]))
    print("depth       : %d bits" % d["depth"])
    print("colour mode : %d = %s" % (d["mode"],
                                     COLOUR_MODES.get(d["mode"], "unknown")))
    print()
    print("  %-20s %8s %10s" % ("section", "at", "declared"))
    print("  %-20s %8d %10s" % ("header", 0, 26))
    total = 26
    for name, at, n in d["sections"]:
        print("  %-20s %8d %10d" % (name, at, n))
        total += 4 + n
    print("  %-20s %8d %10s" % ("compression word", d["image_data_at"] - 2,
                                2))
    total += 2
    print("  %-20s %8d %10d" % ("image data", d["image_data_at"],
                                d["image_data_bytes"]))
    print()
    print("  26 + the three declared lengths + their four-byte headers + 2")
    print("     = %d, and the file is %d bytes" % (total, d["bytes"]))
    print("  image data = %d - %d = %d bytes"
          % (d["bytes"], total, d["bytes"] - total))
    print("  compression : %d = %s"
          % (d["compression"], COMPRESSION.get(d["compression"], "unknown")))
    print("  WALK LANDS AT %d of %d      RESIDUE %d"
          % (d["bytes"], d["bytes"], 0))
    print()
    print("  (the image data length is NOT declared by the format, so this")
    print("   closure is 'the four declared sections fit and what remains is")
    print("   the image data' -- weaker than the closures on ITSF and LCF,")
    print("   which state their own totals, and it is stated as weaker.)")

    if args.resources:
        name, at, n = d["sections"][1]
        print()
        print("-- image resources, %d bytes ------------------------------" % n)
        for rid, rname, size, data in resources(blob, at + 4, n):
            pretty = "".join(chr(c) if 32 <= c < 127 else "."
                             for c in data[:32])
            print("   id 0x%04X  name %-10r size %6d  %s"
                  % (rid, rname.decode("latin-1"), size, pretty))
    return 0


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    def build(colour=b"", res=b"", layer=b"", image=b"\x00\x00rest"):
        head = (b"8BPS" + struct.pack(">H", 1) + bytes(6) +
                struct.pack(">HIIHH", 3, 123, 196, 8, 3))
        return (head + struct.pack(">I", len(colour)) + colour +
                struct.pack(">I", len(res)) + res +
                struct.pack(">I", len(layer)) + layer + image)

    blob = build()
    d = walk(blob)
    check("the header reads three channels", d["channels"], 3)
    check("the header reads 196 x 123", (d["width"], d["height"]), (196, 123))
    check("depth 8", d["depth"], 8)
    check("colour mode 3", d["mode"], 3)
    check("colour mode 3 is named RGB", COLOUR_MODES[3], "RGB")
    check("three declared sections", len(d["sections"]), 3)
    check("the image data is what remains", d["image_data_bytes"], 4)

    big = build(colour=bytes(768))
    d2 = walk(big)
    check("a colour mode block shifts the later sections",
          d2["sections"][1][1], 26 + 4 + 768)

    # a section that overruns must be refused, not silently truncated
    bad = bytearray(build())
    bad[26:30] = struct.pack(">I", 10 ** 6)
    try:
        walk(bytes(bad))
        got = "no exception"
    except Bad:
        got = "Bad"
    check("an overrunning section is refused", got, "Bad")

    try:
        walk(b"8BPSshort")
        got = "no exception"
    except Bad:
        got = "Bad"
    check("a truncated header is refused", got, "Bad")

    try:
        walk(b"NOTPSD" + bytes(40))
        got = "no exception"
    except Bad:
        got = "Bad"
    check("a file with no 8BPS is refused", got, "Bad")

    # Image resources. The Pascal name is a length byte plus its characters,
    # padded so that the name field occupies an EVEN number of bytes: an empty
    # name is therefore TWO bytes and not one. The first version of this
    # fixture wrote one, the walk read the size field two bytes early and the
    # selftest failed with "the resource walk ends at 1070 of 49" -- which is
    # the reader being right about a specimen that was wrong.
    r = (b"8BIM" + struct.pack(">H", 0x03ED) + b"\x00\x00" +
         struct.pack(">I", 4) + b"\x00\x48\x00\x00")
    blob3 = build(res=r)
    d3 = walk(blob3)
    rows = resources(blob3, d3["sections"][1][1] + 4, len(r))
    check("one image resource block", len(rows), 1)
    check("its id", rows[0][0], 0x03ED)
    check("its declared size", rows[0][2], 4)

    bad_n = 0
    for name, ok, got, want in checks:
        print("  %-46s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad_n += 1
    print("checks : %d   failures : %d" % (len(checks), bad_n))
    raise SystemExit(1 if bad_n else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--resources", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.path == "selftest":
        return selftest()
    if not args.path:
        raise SystemExit("psd: a file is required (or --selftest)")
    try:
        return run(args)
    except Bad as e:
        raise SystemExit("psd: REFUSED: %s" % e)


if __name__ == "__main__":
    sys.exit(main())
