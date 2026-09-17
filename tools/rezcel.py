#!/usr/bin/env python3
"""rezcel.py -- are the BRGR members that open 0x477EC620 headless cels?

Nineteen members across the eight `BRGR` archives on the third 3DO disc open
with the same four bytes and the same 48-byte header, constant on 19 of 19:

    477ec620 00000000 00000030 00000000 00000000 00000000
    00100000 00000000 00000000 00010000 00000000 00000000

The third word is 0x30 = 48, which is the header's own length, and the bytes
that follow it are

    1f00 1f00   4000 31d6   009e 113f   0003 ff31 ...

Those first three words are, in order, `PIXC`, `PRE0` and `PRE1` --- the last
three fields of a 3DO Cel Control Block before its width and height. Read that
way they say, by the platform notes' own arithmetic,

    height = PRE0 bits 6..15 + 1 = 200
    width  = PRE1 bits 0..9  + 1 = 320

and `/3do.logo.cel` on the same disc, which does carry a real 80-byte `CCB `,
has `PIXC` `1f001f00`, the same `PRE1` low half, and its own width and height
words agreeing with its `PRE0`/`PRE1` --- so the encoding is checked against a
cel that states the answer twice.

So these members are cels with the control block's first sixteen fields thrown
away and only the three the decoder needs kept. This tool rebuilds a synthetic
`CCB ` from those three words and hands it to the same decoder that reads a
real one, which is the whole point: if the reading is wrong the picture is
wrong, and a person looks.

usage:
    rezcel.py MEMBER.bin OUT.png
    rezcel.py DIR --all OUTDIR
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import celdecode  # noqa: E402

MAGIC = 0x477EC620
HDR = 48


class Bad(Exception):
    pass


def parse(d):
    if len(d) < HDR + 12:
        raise Bad("%d bytes is too short" % len(d))
    if struct.unpack(">I", d[0:4])[0] != MAGIC:
        raise Bad("does not open 0x477EC620: %s" % d[0:4].hex())
    hlen = struct.unpack(">I", d[8:12])[0]
    if hlen != HDR:
        raise Bad("word at +8 is %d, expected the header length %d" % (hlen, HDR))
    pixc, pre0, pre1 = struct.unpack(">3I", d[HDR:HDR + 12])
    height = ((pre0 >> 6) & 0x3FF) + 1
    width = (pre1 & 0x3FF) + 1
    bpp_code = pre0 & 7
    return dict(pixc=pixc, pre0=pre0, pre1=pre1, width=width, height=height,
                bpp_code=bpp_code, pdat=d[HDR + 12:])


def synth_ccb(a, flags):
    """An 80-byte CCB carrying the three words the member kept."""
    w = [0] * 20
    w[0] = 0x43434220          # 'CCB '
    w[1] = 80
    w[2] = 0
    w[3] = flags
    w[15] = a["pixc"]
    w[16] = a["pre0"]
    w[17] = a["pre1"]
    w[18] = a["width"]
    w[19] = a["height"]
    out = b"CCB " + struct.pack(">I", 80) + struct.pack(">18I", *w[2:])
    return out[:80]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("out")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--flags", default="0x47664620",
                    help="CCB flags to assume; the default is the ones "
                         "/3do.logo.cel carries")
    a = ap.parse_args()
    flags = int(a.flags, 0)
    paths = []
    if a.all:
        for dp, dn, fn in os.walk(a.path):
            for f in sorted(fn):
                p = os.path.join(dp, f)
                with open(p, "rb") as fh:
                    if fh.read(4) == b"G~\xc6 ":
                        paths.append(p)
        os.makedirs(a.out, exist_ok=True)
    else:
        paths = [a.path]
    ok = 0
    for p in paths:
        d = open(p, "rb").read()
        try:
            info = parse(d)
        except Bad as e:
            print("%-46s rejected: %s" % (p, e))
            continue
        ccb = synth_ccb(info, flags)
        blob = (ccb + b"PDAT" + struct.pack(">I", len(info["pdat"]) + 8)
                + info["pdat"])
        got = list(celdecode.cels(blob))
        if not got:
            print("%-46s no CCB..PDAT group came back" % p)
            continue
        c, plut, pdat = got[0]
        try:
            w, h, rgb = celdecode.render(c, plut, pdat)
        except Exception as e:
            print("%-46s %dx%d bpp-code %d -- decode failed: %s"
                  % (p, info["width"], info["height"], info["bpp_code"], e))
            continue
        outp = (a.out if not a.all
                else os.path.join(a.out, os.path.basename(os.path.dirname(p))
                                  + "-" + os.path.basename(p)[:-4] + ".png"))
        celdecode.png(outp, w, h, rgb)
        ok += 1
        print("%-46s %dx%d  bpp code %d  packed %s  lrform %s  pdat %d -> %s"
              % (p, info["width"], info["height"], info["bpp_code"],
                 bool(flags & 0x200), bool((info["pre1"] >> 11) & 1),
                 len(info["pdat"]), outp))
    print()
    print("%d of %d members decoded" % (ok, len(paths)))


if __name__ == "__main__":
    main()
