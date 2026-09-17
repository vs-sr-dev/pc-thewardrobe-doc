#!/usr/bin/env python3
"""icn.py -- read the .ICN files on this object: an 8-byte header and a
one-bit-per-pixel bitmap, and nothing else.

    python tools/icn.py FILE...              # header, arithmetic, ASCII render
    python tools/icn.py FILE --pbm OUT.pbm   # write a portable bitmap
    python tools/icn.py FILE --invert        # 0 is ink instead of 1
    python tools/icn.py FILE --lsb           # least-significant bit leftmost
    python tools/icn.py --refuse FILE...     # assert every input is NOT a .ICN

`.ICN` is not `.ICO`. A Windows icon begins `00 00 01 00`; these begin
`01 00 01 00`. The name is the only thing the two formats share and the name is
not a format.

THE VALIDATOR RUNS BEFORE THE CENSUS, AND IT IS THE POINT OF THIS FILE.
`validate()` refuses on any of five grounds and the tool exits 1 rather than
printing a table over a population of zero. Four tools in four sessions have now
printed a clean, correctly formatted summary over nothing at all -- avicheck.py,
pakraster.py, protscan.py and one more -- so this reader is written the other
way round: it must be shown refusing a specimen before any figure it produces is
quoted. Use --refuse for that, on a file you know is not a .ICN.

The header, derived from the two specimens and confirmed by the arithmetic:

    0..1   word   01 00      unknown, 1 on both specimens
    2..3   word   01 00      unknown, 1 on both specimens; plane count?
    4..5   word   width  in pixels, little-endian (0x2C = 44)
    6..7   word   height in pixels, little-endian (0x20 = 32)

    stride = ceil(width / 8)
    8 + stride * height == filesize        <- residue 0 or refuse

Neither the bit order nor the polarity is stated by the file. Both are decided
by rendering all four combinations and looking, which is what --lsb and
--invert are for, and the losing readings are published beside the winner.
"""
import argparse
import os
import struct
import sys


class NotAnIcn(Exception):
    """Refusal. Carries the reason, which is the part worth printing."""


def validate(data, path):
    """Refuse loudly, on five separate grounds, before anything is counted."""
    if len(data) < 8:
        raise NotAnIcn("%s: %d bytes, shorter than the 8-byte header"
                       % (path, len(data)))
    a, b, w, h = struct.unpack("<4H", data[:8])
    if data[:4] == b"\x00\x00\x01\x00":
        raise NotAnIcn("%s: begins 00 00 01 00, which is a Windows .ICO and "
                       "not this format" % path)
    if a != 1 or b != 1:
        raise NotAnIcn("%s: words 0 and 1 are %d and %d, not 1 and 1 as on "
                       "both known specimens" % (path, a, b))
    if not (1 <= w <= 4096) or not (1 <= h <= 4096):
        raise NotAnIcn("%s: %dx%d is not a plausible bitmap" % (path, w, h))
    stride = (w + 7) // 8
    want = 8 + stride * h
    if want != len(data):
        raise NotAnIcn("%s: header says %dx%d, stride %d, so 8 + %d*%d = %d "
                       "bytes; the file is %d, residue %d"
                       % (path, w, h, stride, stride, h, want, len(data),
                          len(data) - want))
    return w, h, stride


def rows(data, w, h, stride, lsb=False, invert=False):
    out = []
    for y in range(h):
        base = 8 + y * stride
        line = []
        for x in range(w):
            byte = data[base + (x >> 3)]
            bit = (byte >> (x & 7)) & 1 if lsb else (byte >> (7 - (x & 7))) & 1
            line.append(bit ^ (1 if invert else 0))
        out.append(line)
    return out


def render(px, ink="#", paper="."):
    return "\n".join("".join(ink if b else paper for b in r) for r in px)


def pbm(px, w, h, path):
    with open(path, "wb") as fh:
        fh.write(b"P1\n%d %d\n" % (w, h))
        for r in px:
            fh.write((" ".join(str(b) for b in r) + "\n").encode("ascii"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--pbm")
    ap.add_argument("--lsb", action="store_true")
    ap.add_argument("--invert", action="store_true")
    ap.add_argument("--refuse", action="store_true",
                    help="assert that every input is NOT a .ICN; exit 1 if one is")
    args = ap.parse_args()

    if args.pbm and len(args.files) != 1:
        sys.exit("--pbm takes exactly one input")

    accepted, refused = 0, 0
    for path in args.files:
        with open(path, "rb") as fh:
            data = fh.read()
        try:
            w, h, stride = validate(data, path)
        except NotAnIcn as why:
            refused += 1
            print("REFUSED: %s" % why)
            continue
        accepted += 1
        if args.refuse:
            print("ACCEPTED (and --refuse said it would not be): %s" % path)
            continue
        px = rows(data, w, h, stride, args.lsb, args.invert)
        ones = sum(sum(r) for r in px)
        print("%s" % path)
        print("  header       : %s" % " ".join("%02x" % c for c in data[:8]))
        print("  geometry     : %d x %d, stride %d, 8 + %d*%d = %d = filesize"
              % (w, h, stride, stride, h, 8 + stride * h))
        print("  padding bits : %d per row, %d total"
              % (stride * 8 - w, (stride * 8 - w) * h))
        print("  bit order    : %s   polarity: %s"
              % ("LSB first" if args.lsb else "MSB first",
                 "0 is ink" if args.invert else "1 is ink"))
        print("  ink pixels   : %d of %d = %.4f %%"
              % (ones, w * h, ones * 100.0 / (w * h)))
        print(render(px))
        if args.pbm:
            pbm(px, w, h, args.pbm)
            print("  wrote %s" % args.pbm)

    if not (accepted + refused):
        sys.exit("no inputs -- refusing to report over an empty population")
    if args.refuse and accepted:
        sys.exit("--refuse: %d of %d inputs were accepted" % (accepted, len(args.files)))
    if not args.refuse and not accepted:
        sys.exit(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
