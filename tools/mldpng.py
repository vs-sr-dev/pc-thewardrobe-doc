#!/usr/bin/env python3
"""mldpng.py -- render the `GIFM` full-screen images found inside the `MDmd`
archives of the VIS pressing of *Links: The Challenge of Golf*.

`GIFM` IS A GIF, AND THAT IS THE FINDING

An earlier version of this tool said, in a comment that survived four rewrites,
that "GIFM is not GIF; it shares three letters and nothing else". That was
wrong, and it was wrong in the way this pipeline warns about most often: an
abbreviation was expanded, disbelieved, and the disbelief was then written down
as though it were a measurement.

Laid against the GIF specification the header matches field for field:

    offset  size  GIF 87a/89a field            value here
    ------  ----  ---------------------------  ---------------------------
       0      6   signature + version          'GIFM' + 0x17 0x03
                                               (GIF has 'GIF' + '87a'/'89a')
       6      2   logical screen width, u16    320
       8      2   logical screen height, u16   200
      10      1   packed                       0xD7 = global colour table
                                               present, colour resolution
                                               6 bits, not sorted, table
                                               size 2^(7+1) = 256
      11      1   background colour index      0
      12      1   pixel aspect ratio           0
      13    768   global colour table          256 x RGB
     781      1   image separator              0x2C, which is ','
     782      2   image left, u16              0
     784      2   image top, u16               0
     786      2   image width, u16             320
     788      2   image height, u16            200
     790      1   packed                       0x00 = no local table,
                                               not interlaced
     791  w * h   image data                   RAW 8-bit indices

    13 + 768 = 781, + 10 = 791, + 320 * 200 = 64,791, which is the declared
    `raw` length of every `.MLD` member on the disc, on 8 of 8.

**The one place it departs from GIF is the last field, and that departure is
the whole design.** A real GIF stores image data as LZW codes in sub-blocks.
Here the image data is raw palette indices -- because the `MDmd` node holding
the image is *itself* LZW-compressed, by the same LSB-first variable-width LZW
with a clear code at 256 that GIF uses. **The compression was hoisted one level
up, out of the picture and into the archive**, so that a picture and a `.WAV`
get the same treatment and the picture is never compressed twice. See
`mdmd.py`, whose codec was identified separately and by known plaintext.

THE COLOUR TABLE IS AT 13, NOT AT 23, AND THAT COST AN AFTERNOON

Reading the first bytes as "4-byte magic, then a 1-byte header length 0x17 =
23" instead of "6-byte GIF signature and version" puts the colour table ten
bytes late. Every image still renders, with correct geometry and legible text,
in wrong colours -- which is exactly the trap that
`vis-sherlockholmes-doc/docs/05-imv-picture.md` documents for the same
platform. Scored against controls by `tools/palscore.py`, the offset-23 reading
came out at 38.10 mean adjacent |dRGB| against a **shuffled-palette control at
37.12**: worse than random. Offset 13 scores 23.51, 1.58x better than the
tightest control, and the owner of the machine confirmed the render against
known artwork.

The colour table holds 6-bit VGA values already shifted into 8 bits: the
maximum byte over all eight images is 252 = 63 << 2. They are written out
unchanged. `--vga6` rescales a genuine 6-bit table -- the disc's `.COL`
members, which max at 63 -- and fails loudly if handed anything larger.

PNG is written with `zlib` from the standard library; there is no image
dependency in this pipeline.

    python tools/mldpng.py IN.MLD OUT.png
    python tools/mldpng.py --probe IN.MLD ...
    python tools/mldpng.py --dir INDIR OUTDIR
"""
import argparse
import os
import struct
import sys
import zlib

MAGIC = b"GIFM"
GCT_AT = 13
GCT_LEN = 768
IMGDESC_AT = 781
PIX_AT = 791
SEPARATOR = 0x2C


class BadImage(Exception):
    pass


def parse(data, why=""):
    if len(data) < PIX_AT:
        raise BadImage("%s: %d bytes, too short for a screen descriptor, a "
                       "768-byte colour table and an image descriptor"
                       % (why, len(data)))
    if data[0:4] != MAGIC:
        raise BadImage("%s: no GIFM magic (found %r)" % (why, bytes(data[0:4])))
    w, h = struct.unpack_from("<HH", data, 6)
    packed = data[10]
    if not packed & 0x80:
        raise BadImage("%s: packed byte 0x%02x says no global colour table"
                       % (why, packed))
    entries = 1 << ((packed & 0x07) + 1)
    if entries != 256:
        raise BadImage("%s: colour table declares %d entries, this reader "
                       "handles 256" % (why, entries))
    if data[IMGDESC_AT] != SEPARATOR:
        raise BadImage("%s: no 0x2C image separator at %d (found 0x%02x)"
                       % (why, IMGDESC_AT, data[IMGDESC_AT]))
    iw, ih = struct.unpack_from("<HH", data, IMGDESC_AT + 5)
    if (iw, ih) != (w, h):
        raise BadImage("%s: screen is %d x %d but the image descriptor says "
                       "%d x %d" % (why, w, h, iw, ih))
    flags = data[IMGDESC_AT + 9]
    if flags & 0x80:
        raise BadImage("%s: image declares a local colour table, unhandled"
                       % why)
    if flags & 0x40:
        raise BadImage("%s: image is interlaced, unhandled" % why)
    want = PIX_AT + w * h
    if len(data) != want:
        raise BadImage("%s: %d x %d needs %d bytes, file has %d"
                       % (why, w, h, want, len(data)))
    return w, h, data[GCT_AT:GCT_AT + GCT_LEN], data[PIX_AT:]


def png(w, h, pal, pix, vga6=False):
    if vga6:
        if max(pal) > 63:
            raise BadImage("--vga6 given but the table holds %d, which is not "
                           "a 6-bit value" % max(pal))
        rgb = bytes(v * 255 // 63 for v in pal)
    else:
        rgb = bytes(pal)

    def chunk(tag, payload):
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += pix[y * w:(y + 1) * w]
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
            + chunk(b"PLTE", rgb)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def probe(paths):
    ok = bad = 0
    for p in paths:
        try:
            w, h, pal, pix = parse(open(p, "rb").read(), os.path.basename(p))
        except BadImage as e:
            print("%-28s REFUSED  %s" % (os.path.basename(p), e))
            bad += 1
            continue
        print("%-28s %4d x %-4d  table max %3d  %3d of 256 indices used"
              % (os.path.basename(p), w, h, max(pal), len(set(pix))))
        ok += 1
    print()
    print("%d parsed, %d refused" % (ok, bad))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("args", nargs="+")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--dir", action="store_true")
    ap.add_argument("--vga6", action="store_true",
                    help="rescale a genuine 6-bit table; fails if a byte > 63")
    a = ap.parse_args()

    if a.probe:
        return probe(a.args)
    if a.dir:
        if len(a.args) != 2:
            raise SystemExit("--dir takes INDIR OUTDIR")
        indir, outdir = a.args
        os.makedirs(outdir, exist_ok=True)
        n = 0
        for fn in sorted(os.listdir(indir)):
            src = os.path.join(indir, fn)
            if not os.path.isfile(src):
                continue
            try:
                w, h, pal, pix = parse(open(src, "rb").read(), fn)
            except BadImage:
                continue
            open(os.path.join(outdir, os.path.splitext(fn)[0] + ".png"),
                 "wb").write(png(w, h, pal, pix, a.vga6))
            n += 1
        print("wrote %d PNGs to %s" % (n, outdir))
        if n == 0:
            raise SystemExit("mldpng: no GIFM images found in %s" % indir)
        return 0
    if len(a.args) != 2:
        raise SystemExit("usage: mldpng.py IN.MLD OUT.png")
    w, h, pal, pix = parse(open(a.args[0], "rb").read(),
                           os.path.basename(a.args[0]))
    open(a.args[1], "wb").write(png(w, h, pal, pix, a.vga6))
    print("%s: %d x %d -> %s" % (os.path.basename(a.args[0]), w, h, a.args[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
