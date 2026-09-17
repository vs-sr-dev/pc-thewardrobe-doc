#!/usr/bin/env python3
"""appscrn.py -- the 3DO banner screen, derived from one file.

The platform notes have carried an open question for two discs: *a banner
screen --- the image the console shows for the disc --- as a fixed asset worth
hashing on every disc. Not found on the first disc, and this stays open.* The
third disc has a root file called `BannerScreen`, 153,688 bytes, whose first
eight bytes are `01 'APPSCRN'`.

WHAT THE BYTES SAY

    +0    u8      1
    +1    char[7] 'APPSCRN'
    +8    u32     153600   = 320 x 240 x 2
    +12   u16     240      height
    +14   u16     320      width
    +16   u32     0x10000000
    +20   u32     0
    +24   ...     the pixels begin here

and 24 + 153,600 = 153,624, which is **64 bytes short of the file**. Sixty-four
bytes is 512 bits, and 512 bits appended after a declared end is the same shape
the second disc found after `/rom_tags` and after `CPORT49.ROM`. The tool
measures the tail's entropy rather than asserting what it is.

The pixel order is not assumed. The 3DO framebuffer supports a linear order and
an interleaved one ("LRform"), and the platform notes' hardest-won line is that
which one a file uses is a decision, not a property of the machine. Both are
rendered and a person looks.

usage:
    appscrn.py FILE --png OUT.png [--order linear|lr] [--offset 24]
    appscrn.py validate
"""
import argparse
import math
import struct
import sys


class Bad(Exception):
    pass


def parse(d):
    if len(d) < 24:
        raise Bad("%d bytes is too short for a 24-byte APPSCRN header" % len(d))
    if d[0] != 1 or d[1:8] != b"APPSCRN":
        raise Bad("does not open 01 'APPSCRN': %r" % d[0:8])
    payload = struct.unpack(">I", d[8:12])[0]
    h, w = struct.unpack(">2H", d[12:16])
    if w == 0 or h == 0:
        raise Bad("zero dimension %dx%d" % (w, h))
    if payload != w * h * 2:
        raise Bad("payload word %d != %d x %d x 2 = %d" % (payload, w, h, w * h * 2))
    return dict(width=w, height=h, payload=payload,
                w4=struct.unpack(">I", d[16:20])[0],
                w5=struct.unpack(">I", d[20:24])[0])


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = float(len(b))
    return -sum((k / n) * math.log(k / n, 2) for k in c if k)


def validate():
    ok = True
    cases = [
        ("2,048 zero bytes", b"\0" * 2048),
        ("the string iamaduck", b"iamaduck" * 256),
        ("a CCB cel", b"CCB \x00\x00\x00\x50" + b"\0" * 200),
        ("APPSCRN whose payload word disagrees",
         b"\x01APPSCRN" + struct.pack(">I", 100) + struct.pack(">2H", 240, 320)
         + b"\0" * 8),
        ("a 16-byte file", b"\x01APPSCRN" + b"\0" * 8),
    ]
    for name, data in cases:
        try:
            parse(data)
            print("FAIL: %-40s was ACCEPTED" % name)
            ok = False
        except Bad as e:
            print("ok  : %-40s rejected -- %s" % (name, e))
    good = (b"\x01APPSCRN" + struct.pack(">I", 8 * 4 * 2)
            + struct.pack(">2H", 4, 8) + b"\0" * 8)
    try:
        a = parse(good)
        assert (a["width"], a["height"]) == (8, 4)
        print("ok  : %-40s accepted, %dx%d" % ("positive control", 8, 4))
    except (Bad, AssertionError) as e:
        print("FAIL: positive control rejected -- %s" % e)
        ok = False
    return 0 if ok else 1


def decode(px, w, h, order):
    """16-bit 5-5-5, MSB first. `lr` is the framebuffer's interleaved order."""
    out = bytearray(w * h * 3)
    for i in range(w * h):
        v = (px[2 * i] << 8) | px[2 * i + 1]
        r = (v >> 10) & 0x1F
        g = (v >> 5) & 0x1F
        b = v & 0x1F
        if order == "linear":
            dst = i
        else:
            # LRform, measured rather than assumed: a 32-bit word of the buffer
            # holds one pixel of display row 2n and one of display row 2n+1 at
            # the same column. Of five candidate orders rendered side by side,
            # this is the one whose vertical roughness collapses -- 1,620,860
            # against 4,278,149 for linear and 1,942,121 for the same pairing
            # with the halves swapped, on a horizontal roughness of 1,437,671.
            # A natural image has a vertical-to-horizontal ratio near 1; this
            # order gives 1.13 and linear gives 2.48. A person then looked.
            blk, j = divmod(i, 2 * w)
            x, which = divmod(j, 2)
            dst = (2 * blk + which) * w + x
        j = dst * 3
        out[j] = (r << 3) | (r >> 2)
        out[j + 1] = (g << 3) | (g >> 2)
        out[j + 2] = (b << 3) | (b >> 2)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--png")
    ap.add_argument("--order", default="linear", choices=("linear", "lr", "both"))
    ap.add_argument("--offset", type=int, default=24)
    a = ap.parse_args()
    if a.file == "validate":
        raise SystemExit(validate())
    d = open(a.file, "rb").read()
    info = parse(d)
    w, h = info["width"], info["height"]
    print("%s: %d bytes" % (a.file, len(d)))
    print("  header says %d x %d, payload %d bytes" % (w, h, info["payload"]))
    print("  word at +16 0x%08x, word at +20 0x%08x" % (info["w4"], info["w5"]))
    print("  %d header + %d payload = %d, file is %d, tail = %d bytes"
          % (a.offset, info["payload"], a.offset + info["payload"], len(d),
             len(d) - a.offset - info["payload"]))
    px = d[a.offset:a.offset + info["payload"]]
    tail = d[a.offset + info["payload"]:]
    if tail:
        print("  the tail: %d bytes, entropy %.4f bits/byte, %d distinct values"
              % (len(tail), entropy(tail), len(set(tail))))
        print("  first 16: %s" % " ".join("%02x" % x for x in tail[:16]))
    top = sum(1 for i in range(w * h)
              if (px[2 * i] & 0x80))
    print("  the top bit of the 16-bit word is set on %d of %d pixels"
          % (top, w * h))
    if a.png:
        from PIL import Image
        orders = ("linear", "lr") if a.order == "both" else (a.order,)
        ims = [Image.frombytes("RGB", (w, h), decode(px, w, h, o))
               for o in orders]
        if len(ims) == 1:
            ims[0].save(a.png)
        else:
            sheet = Image.new("RGB", (w * len(ims), h))
            for i, im in enumerate(ims):
                sheet.paste(im, (i * w, 0))
            sheet.save(a.png)
        print("  wrote %s  (%s)" % (a.png, ", ".join(orders)))


if __name__ == "__main__":
    main()
