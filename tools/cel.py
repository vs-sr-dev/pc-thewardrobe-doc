#!/usr/bin/env python3
"""cel.py -- the `.CEL` record: an uncompressed sprite that carries its own
palette and its own screen position.

Distinct from the span raster in `cellras.py`, which is what `.BLK` and the
`.GPH` cells of `title.lnx` are. A `.CEL` is simpler and larger:

    +0    u16 LE   0x9119, on 9 of 9 members
    +2    u16 LE   width
    +4    u16 LE   height
    +6    u16 LE   x on screen      65..303, inside a 320-column screen
    +8    u16 LE   y on screen      88..184, inside a 200-row screen
    +10   u16 LE   bits per pixel   8 on 9 of 9
    +12   u16 LE   payload length
    +14   18 bytes zero on 9 of 9
    +32   768      a 6-bit VGA palette, max component 62 or 63
    +800  w*h      8-bit palette indices, no compression and no transparency

TWO QUANTITIES ARE ENCODED TWICE AND BOTH ARE CHECKED: the length field
against `width * height`, and both against `len(record) - 800`. A record that
fails either is refused, and there is no repair path.

The x/y fields are why this format exists separately: a `.CEL` knows where it
goes. `MESSAGE.CEL` is 134 x 30 at (179, 151) -- lower right of a 320 x 200
screen, which is where a message box belongs.

    python tools/cel.py FILE...
    python tools/cel.py FILE... --png DIR
"""
import argparse
import os
import struct
import sys

MAGIC = 0x9119
PALOFF, PIXOFF = 32, 800


class CelError(Exception):
    pass


def parse(data, name="<data>"):
    if len(data) < PIXOFF:
        raise CelError("%s: %d bytes is shorter than the %d-byte head"
                       % (name, len(data), PIXOFF))
    magic, w, h, x, y, bpp, ln = struct.unpack_from("<7H", data, 0)
    if magic != MAGIC:
        raise CelError("%s: magic is %#06x, not %#06x" % (name, magic, MAGIC))
    if bpp != 8:
        raise CelError("%s: %d bits per pixel, this reader knows 8"
                       % (name, bpp))
    if ln != w * h:
        raise CelError("%s: length field %d against width*height %d"
                       % (name, ln, w * h))
    if len(data) - PIXOFF != ln:
        raise CelError("%s: %d payload bytes on disc against a declared %d"
                       % (name, len(data) - PIXOFF, ln))
    pal = data[PALOFF:PIXOFF]
    if max(pal) > 63:
        raise CelError("%s: palette max component %d, not 6-bit"
                       % (name, max(pal)))
    return w, h, x, y, pal, data[PIXOFF:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--png", metavar="DIR")
    ap.add_argument("--expect-ok", type=int)
    a = ap.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import cellras

    if a.png:
        os.makedirs(a.png, exist_ok=True)
    ok = bad = 0
    for p in a.files:
        name = os.path.basename(p)
        try:
            w, h, x, y, pal, pix = parse(open(p, "rb").read(), name)
        except CelError as e:
            bad += 1
            print("REFUSED  %s" % e)
            continue
        ok += 1
        print("OK       %-18s %4d x %-4d at (%3d,%3d)  %5d px  %3d indices used"
              % (name, w, h, x, y, len(pix), len(set(pix))))
        if a.png:
            rgb = bytes(bytearray(v * 255 // 63 for v in pal))
            cellras.write_png(os.path.join(a.png, name + ".png"),
                              w, h, pix, rgb)
    print()
    print("cel: %d accepted, %d refused, %d files" % (ok, bad, ok + bad))
    if a.expect_ok is not None and ok != a.expect_ok:
        raise SystemExit("cel: expected %d accepted, got %d" % (a.expect_ok, ok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
