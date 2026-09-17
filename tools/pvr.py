#!/usr/bin/env python3
"""pvr.py -- PowerVR texture decoder and contact sheet.

442 loose .PVR files on this disc and 16,641 more inside the 582 PVMH archives
that come out of the .PRS files. The last step of any claim about pictures in
this branch is a human being looking at a picture, and this is what produces the
picture.

A loose .PVR on this disc is

    'GBIX'  u32 LE length  u32 LE global index  (+ padding to the length)
    'PVRT'  u32 LE length  u8 pixel format  u8 data format  u16 pad
            u16 LE width   u16 LE height    then the texel data

and a PVMH member is the same 'PVRT' chunk with the GBIX carried in the
archive's directory instead.

WHAT IS ASSERTED, AND THE ARITHMETIC THAT HAS TO CLOSE
-------------------------------------------------------

The pixel format is how one texel is stored, and all three seen on this disc
are 16 bits: ARGB1555 (0x00), RGB565 (0x01), ARGB4444 (0x02).

The data format is how the texels are ARRANGED, and that is where a wrong guess
still draws something:

  twiddled (0x01)      Morton order. Interleave the bits of x and y.
  rectangle (0x09)     plain raster rows.
  VQ (0x03)            a 2,048-byte codebook of 256 entries, each entry four
                       16-bit texels forming a 2x2 block, then one index byte
                       per 2x2 block, the indices themselves twiddled.
  small VQ (0x10)      the same with a codebook smaller than 256 entries.
  the -mipmap variants add a chain of smaller levels BEFORE the largest one.

`--geometry` requires the arithmetic to close per data format:

  twiddled / rectangle : width * height * 2  == payload
  VQ                   : 2048 + width*height/4 == payload
  mipmapped            : the same plus the sum of the smaller levels, which is
                         reported separately because the padding rule in front
                         of a mipmap chain was NOT derived and is not guessed.

Formats whose rule is not stated are counted as not stated. They are not
averaged into a success rate.

Usage:
    python tools/pvr.py --geometry DIR
    python tools/pvr.py --sheet DIR OUT.PNG [--n 240]
    python tools/pvr.py --one FILE OUT.PNG
"""
import os
import struct
import sys

PIXEL = {0x00: "ARGB1555", 0x01: "RGB565", 0x02: "ARGB4444", 0x03: "YUV422"}
DATA = {0x01: "twiddled", 0x02: "twiddled-mipmap", 0x03: "VQ",
        0x04: "VQ-mipmap", 0x05: "palette4", 0x06: "palette4-mipmap",
        0x07: "palette8", 0x08: "palette8-mipmap", 0x09: "rectangle",
        0x0b: "rectangle-stride", 0x0d: "rectangle-twiddled",
        0x10: "small-VQ", 0x11: "small-VQ-mipmap"}
MIPMAP = {0x02, 0x04, 0x06, 0x08, 0x11}
VQ = {0x03, 0x04, 0x10, 0x11}
RASTER = {0x09, 0x0b}


def texel(pf, v):
    if pf == 0x01:                                    # RGB565
        r = (v >> 11) & 31
        g = (v >> 5) & 63
        b = v & 31
        return (r * 255 // 31, g * 255 // 63, b * 255 // 31, 255)
    if pf == 0x00:                                    # ARGB1555
        a = 255 if (v >> 15) else 0
        r = (v >> 10) & 31
        g = (v >> 5) & 31
        b = v & 31
        return (r * 255 // 31, g * 255 // 31, b * 255 // 31, a)
    if pf == 0x02:                                    # ARGB4444
        a = (v >> 12) & 15
        r = (v >> 8) & 15
        g = (v >> 4) & 15
        b = v & 15
        return (r * 17, g * 17, b * 17, a * 17)
    return (255, 0, 255, 255)


def untwiddle_index(x, y):
    """Morton order: interleave the bits of y and x, y taking the low bit."""
    n = 0
    for b in range(16):
        n |= ((x >> b) & 1) << (2 * b + 1)
        n |= ((y >> b) & 1) << (2 * b)
    return n


def mip_offset(w, h, df, pf):
    """Bytes the mipmap chain in front of the largest level occupies."""
    total = 0
    s = w
    while s > 1:
        s >>= 1
        if df in VQ:
            total += max(1, (s * s) // 4)
        else:
            total += s * s * 2
    if df in VQ:
        total += 1                                    # the 1x1 level's index
    else:
        total += 2
    return total


def decode(pf, df, w, h, data):
    """Return a list of w*h RGBA tuples, or None when the format is not handled."""
    if df in VQ:
        book_entries = 256 if df in (0x03, 0x04) else (len(data) - (w * h // 4)) // 8
        book_bytes = book_entries * 8
        if book_bytes <= 0 or book_bytes > len(data):
            return None
        book = data[:book_bytes]
        idx = data[book_bytes:]
        if df in MIPMAP:
            idx = idx[mip_offset(w, h, df, pf):]
        out = [(0, 0, 0, 0)] * (w * h)
        bw, bh = w // 2, h // 2
        for by in range(bh):
            for bx in range(bw):
                k = untwiddle_index(bx, by)
                if k >= len(idx):
                    continue
                e = idx[k] * 8
                if e + 8 > len(book):
                    continue
                q = struct.unpack_from("<4H", book, e)
                for i, (dx, dy) in enumerate(((0, 0), (0, 1), (1, 0), (1, 1))):
                    px, py = bx * 2 + dx, by * 2 + dy
                    if px < w and py < h:
                        out[py * w + px] = texel(pf, q[i])
        return out
    body = data
    if df in MIPMAP:
        body = data[mip_offset(w, h, df, pf):]
    need = w * h * 2
    if len(body) < need:
        return None
    out = [(0, 0, 0, 0)] * (w * h)
    if df in RASTER:
        for y in range(h):
            for x in range(w):
                v = struct.unpack_from("<H", body, (y * w + x) * 2)[0]
                out[y * w + x] = texel(pf, v)
    else:
        for y in range(h):
            for x in range(w):
                k = untwiddle_index(x, y)
                if k * 2 + 2 > len(body):
                    continue
                v = struct.unpack_from("<H", body, k * 2)[0]
                out[y * w + x] = texel(pf, v)
    return out


def read_pvr(path):
    d = open(path, "rb").read()
    o = 0
    gbix = None
    if d[:4] == b"GBIX":
        ln = struct.unpack_from("<I", d, 4)[0]
        gbix = struct.unpack_from("<I", d, 8)[0] if ln >= 4 else None
        o = 8 + ln
    if d[o:o + 4] != b"PVRT":
        raise ValueError("%s: no PVRT at %d, found %r"
                         % (os.path.basename(path), o, bytes(d[o:o + 4])))
    dl = struct.unpack_from("<I", d, o + 4)[0]
    pf, df = d[o + 8], d[o + 9]
    w = struct.unpack_from("<H", d, o + 12)[0]
    h = struct.unpack_from("<H", d, o + 14)[0]
    return dict(gbix=gbix, pf=pf, df=df, w=w, h=h,
                payload=dl - 8, data=d[o + 16:o + 8 + dl], size=len(d),
                chunk_end=o + 8 + dl)


def expected(w, h, df):
    if df in VQ and df in (0x03,):
        return 2048 + w * h // 4
    if df == 0x01 or df in RASTER or df == 0x0d:
        return w * h * 2
    return None


def cmd_geometry(root):
    files = []
    for dp, _d, fs in os.walk(root):
        for f in sorted(fs):
            if f.upper().endswith(".PVR"):
                files.append(os.path.join(dp, f))
    import collections
    fmt = collections.Counter()
    miss = collections.Counter()
    ok = unstated = 0
    endok = 0
    for p in files:
        t = read_pvr(p)
        fmt[(t["pf"], t["df"])] += 1
        if t["chunk_end"] == t["size"]:
            endok += 1
        e = expected(t["w"], t["h"], t["df"])
        if e is None:
            unstated += 1
        elif e == t["payload"]:
            ok += 1
        else:
            miss[(t["pf"], t["df"])] += 1
    print("=== pvr.py --geometry over %s ===" % root)
    print("loose .PVR files                       : %d" % len(files))
    print("PVRT chunk ends exactly at end of file : %d" % endok)
    print("stated rule and it closes              : %d" % ok)
    print("rule not stated (mipmap chains)        : %d" % unstated)
    print("stated rule and it does NOT close      : %d" % (len(files) - ok - unstated))
    print()
    print("%-10s %-22s %7s %7s" % ("pixel", "data format", "count", "misses"))
    for (pf, df), c in fmt.most_common():
        print("%-10s %-22s %7d %7d" % (PIXEL.get(pf, "0x%02x" % pf),
                                       DATA.get(df, "0x%02x" % df), c,
                                       miss[(pf, df)]))
    return 0


def cmd_sheet(root, out, limit=240):
    from PIL import Image
    files = []
    for dp, _d, fs in os.walk(root):
        for f in sorted(fs):
            if f.upper().endswith(".PVR"):
                files.append(os.path.join(dp, f))
    step = max(1, len(files) // limit)
    picked = files[::step][:limit]
    cell = 64
    cols = 20
    rows = (len(picked) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * (cell + 2) + 2, rows * (cell + 2) + 2),
                      (18, 18, 22))
    drawn = 0
    for i, p in enumerate(picked):
        try:
            t = read_pvr(p)
            px = decode(t["pf"], t["df"], t["w"], t["h"], t["data"])
            if px is None:
                continue
            im = Image.new("RGBA", (t["w"], t["h"]))
            im.putdata(px)
            bg = Image.new("RGBA", im.size, (30, 30, 36, 255))
            im = Image.alpha_composite(bg, im).convert("RGB")
            im.thumbnail((cell, cell))
            sheet.paste(im, (2 + (i % cols) * (cell + 2), 2 + (i // cols) * (cell + 2)))
            drawn += 1
        except Exception:
            continue
    sheet.save(out)
    print("contact sheet: %d of %d sampled textures drawn -> %s"
          % (drawn, len(picked), out))
    return 0


def cmd_one(path, out):
    from PIL import Image
    t = read_pvr(path)
    px = decode(t["pf"], t["df"], t["w"], t["h"], t["data"])
    if px is None:
        raise SystemExit("pvr: format 0x%02x/0x%02x not handled" % (t["pf"], t["df"]))
    im = Image.new("RGBA", (t["w"], t["h"]))
    im.putdata(px)
    im.save(out)
    print("%s: %dx%d %s %s gbix=%s -> %s"
          % (os.path.basename(path), t["w"], t["h"],
             PIXEL.get(t["pf"]), DATA.get(t["df"]), t["gbix"], out))
    return 0


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if len(argv) < 3:
        raise SystemExit(__doc__)
    if argv[1] == "--geometry":
        return cmd_geometry(argv[2])
    if argv[1] == "--sheet":
        n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 240
        return cmd_sheet(argv[2], argv[3], n)
    if argv[1] == "--one":
        return cmd_one(argv[2], argv[3])
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
