#!/usr/bin/env python3
"""aniread.py -- the .ANI of Simulman V: a container, a palette and a sprite RLE.

58.3509 % of the object is 38 files with this extension and no magic number.
Nothing about the format was known when this tool was started. What follows is
derived from the bytes and every step of it is checked at run time.

THE CONTAINER

    u16  version       1 or 2. 37 files are version 2, LOGO.ANI is version 1.
    u16  n             number of elements.
    u32  length        version 2 only: bytes after the header.
    u16  length        version 1: the same field, half as wide.
                       -> the header is 10 bytes for version 2 and 6 for
                          version 1, which is the whole of the briefing's
                          "size minus ten on three files in four and size
                          minus six on the fourth".
    u32  offset[n]     relative to the start of this table.

Three identities hold on 38 files of 38, and the tool asserts all three:

    length == filesize - header          the declared length closes the file
    offset[0] == 4 * n                   the first element begins right after
                                         the offset table
    offset[] strictly increasing         the elements are in file order

ELEMENT 0 IS A PALETTE

    u8   0x00          type
    u8   last          index of the last entry; 0xFF on 37 of 38
    u16  0x0000        first index
    u8   0x80
    u8   rgb[3*(last+1)]   six-bit VGA DAC components, 0..63

`SMAN5/STA/ARCADE.PAL` is 773 bytes and is *exactly one of these elements*,
standing alone in a file: `00 ff 00 00 80` and 768 bytes of RGB. It is not a
palette file that happens to resemble the .ANI palettes; it is the same object
written to disk on its own.

ELEMENTS 1..n-1 ARE PICTURES

    u16  width
    u16  height
    u8   mode          1 on 155 of 156 pictures, 2 on the one inside LOGO.ANI
                       and on all 163 pictures inside the six .ELE
    ...  stream

Mode 1 is a skip/copy run encoder with an explicit row terminator:

    read a byte.
      0xFF          -> end of row: y += 1, x = 0
      anything else -> that many pixels are left untouched (transparent);
                       then read one more byte, that many literal pixels
                       follow and are copied.

A row that ends before `width` leaves the rest of the row untouched, which is
why a fully transparent row encodes as `fe 00 ff` -- skip 254, copy 0, end --
and not as a run of 320.

The stream ends two bytes before the element does, and those two bytes are
`ff ff`. That is the end marker, and it holds on 155 mode-1 pictures of 155:
every one consumes its stream to the last byte but two, and produces exactly
`height` rows. Nothing was tuned to make this come out; the count went from
0 of 155 to 155 of 155 when the two bytes were recognised for what they are.

Mode 2 is the same encoder with four bits per pixel -- see decode_mode2.

    python tools/aniread.py <objectroot>                 census
    python tools/aniread.py <objectroot> --png <outdir>  decode to PNG

Decoded pictures are written outside the repository and are not committed.
"""
import os
import struct
import sys
import zlib
from collections import Counter

TRANSPARENT = 0


def elements(d):
    ver, n = struct.unpack("<2H", d[:4])
    assert ver in (1, 2), "unknown .ANI version %d" % ver
    hdr = 6 if ver == 1 else 10
    declared = (struct.unpack("<H", d[4:6])[0] if ver == 1
                else struct.unpack("<I", d[4:8])[0])
    offs = list(struct.unpack("<%dI" % n, d[hdr:hdr + 4 * n]))
    out = []
    for k, o in enumerate(offs):
        a = hdr + o
        b = hdr + offs[k + 1] if k + 1 < n else len(d)
        out.append(d[a:b])
    return ver, hdr, declared, offs, out


def read_palette(e):
    assert e[0] == 0x00, "element 0 is not type 0"
    last = e[1]
    first = struct.unpack("<H", e[2:4])[0]
    flag = e[4]
    rgb = e[5:5 + 3 * (last + 1 - first)]
    return last, first, flag, rgb


def decode_mode1(e):
    """Returns (width, height, pixels, bytes_consumed, rows_ended)."""
    w, h = struct.unpack("<2H", e[:4])
    s = e[5:]
    buf = bytearray([TRANSPARENT]) * (w * h)
    x = y = i = 0
    rows = 0
    while i < len(s) and y < h:
        b = s[i]
        i += 1
        if b == 0xFF:
            y += 1
            x = 0
            rows += 1
            continue
        x += b
        if i >= len(s):
            break
        cnt = s[i]
        i += 1
        if cnt:
            chunk = s[i:i + cnt]
            i += cnt
            base = y * w + x
            for k, px in enumerate(chunk):
                if x + k < w and y < h:
                    buf[base + k] = px
            x += cnt
    return w, h, buf, i + 5, rows


def decode_mode2(e, base=0):
    """Mode 2: the same skip/copy row encoder, four bits per pixel.

    The count is a count of *pixels*; the literal data that follows occupies
    ceil(count / 2) bytes.

    WHICH NIBBLE COMES FIRST is not a matter of taste and was not settled by
    looking at the picture. A run with an odd pixel count leaves half of its
    last byte unused, and the unused half is whichever one the packer never
    reached. Over all 5,712 odd-length runs in the six .ELE and in LOGO.ANI,
    the **high** nibble of that last byte is zero 5,712 times and the low
    nibble takes thirteen different values. The low nibble is written first.
    Read the other way round the sprite still looks like a man walking, which
    is exactly why a count was taken instead of a vote -- and the count was
    then confirmed by a person who had the game running.

    `base` is added to every index; see eleread.py, where it is measured.

    Derived from `SMAN5/IMG/K.ELE` element 0, whose stream reads
    `ff ff 04 07 <4 bytes> ff 02 0b <6 bytes> ff 01 0d <7 bytes> ff`:
    two empty rows, then skip 4 copy 7 (four bytes), skip 2 copy 11 (six),
    skip 1 copy 13 (seven). 7 -> 4, 11 -> 6, 13 -> 7 is ceil(n/2) three times
    running, and the row terminator lands where it must each time.
    """
    w, h = struct.unpack("<2H", e[:4])
    s = e[5:]
    buf = bytearray([base + TRANSPARENT]) * (w * h)
    x = y = i = 0
    rows = 0
    while i < len(s) and y < h:
        b = s[i]
        i += 1
        if b == 0xFF:
            y += 1
            x = 0
            rows += 1
            continue
        x += b
        if i >= len(s):
            break
        cnt = s[i]
        i += 1
        nbytes = (cnt + 1) // 2
        chunk = s[i:i + nbytes]
        i += nbytes
        for k in range(cnt):
            px = (chunk[k // 2] & 0x0F) if k % 2 == 0 else (chunk[k // 2] >> 4)
            if x + k < w and y < h:
                buf[y * w + x + k] = base + px
        x += cnt
    return w, h, buf, i + 5, rows


def decode(e, base=0):
    return decode_mode1(e) if e[4] == 1 else decode_mode2(e, base)


def png(path, w, h, idx, rgb6):
    """Write an 8-bit palettised PNG. rgb6 is six-bit VGA; scale to eight."""
    pal = bytearray()
    for i in range(256):
        if 3 * i + 2 < len(rgb6):
            r, g, b = rgb6[3 * i], rgb6[3 * i + 1], rgb6[3 * i + 2]
        else:
            r = g = b = 0
        pal += bytes(((r * 255) // 63, (g * 255) // 63, (b * 255) // 63))
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += idx[y * w:(y + 1) * w]

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    out = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
    out += chunk(b"PLTE", bytes(pal))
    out += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    out += chunk(b"IEND", b"")
    open(path, "wb").write(out)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    outdir = None
    if "--png" in sys.argv:
        outdir = sys.argv[sys.argv.index("--png") + 1]
        os.makedirs(outdir, exist_ok=True)
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

    names = []
    for dp, _dd, ff in os.walk(root):
        for n in sorted(ff):
            if n.upper().endswith(".ANI"):
                names.append(os.path.relpath(os.path.join(dp, n), root)
                             .replace(os.sep, "/"))
    names.sort()
    assert names, "no .ANI under %r" % root

    print("=== the container, checked on every file ===")
    print("  %-24s %7s %3s %3s %6s %6s %6s" %
          ("file", "size", "ver", "n", "close", "off0", "mono"))
    tot_pics = 0
    tot_bytes = 0
    modes = Counter()
    dims = Counter()
    pals = Counter()
    clean = 0
    failures = []
    for f in names:
        d = open(os.path.join(root, f), "rb").read()
        tot_bytes += len(d)
        ver, hdr, declared, offs, els = elements(d)
        c1 = declared == len(d) - hdr
        c2 = offs[0] == 4 * len(offs)
        c3 = all(offs[i] < offs[i + 1] for i in range(len(offs) - 1))
        assert c1 and c2 and c3, "container identity failed on %s" % f
        print("  %-24s %7d %3d %3d %6s %6s %6s" %
              (f, len(d), ver, len(els), c1, c2, c3))
        last, first, flag, rgb = read_palette(els[0])
        pals[(last, first, flag, len(rgb))] += 1
        for k, e in enumerate(els[1:], 1):
            w, h = struct.unpack("<2H", e[:4])
            m = e[4]
            modes[m] += 1
            dims[(w, h)] += 1
            tot_pics += 1
            if m in (1, 2):
                _w, _h, buf, used, rows = decode(e)
                # the stream ends two bytes before the element does, and the
                # two are the end marker. This was not assumed: the first run
                # of this tool reported "used = len - 2" on 155 pictures of
                # 155 and on none of them anything else.
                exact = used == len(e) - 2 and e[-2:] == b"\xff\xff"
                if exact and rows == h:
                    clean += 1
                else:
                    failures.append((f, k, w, h, len(e), used, rows))
    print("  38 of 38 satisfy all three container identities.")
    print("")

    print("=== element 0, the palette, over all 38 ===")
    for (last, first, flag, ln), c in pals.most_common():
        print("  last=0x%02X first=%d flag=0x%02X rgb bytes=%d  x%d"
              % (last, first, flag, ln, c))
    p = os.path.join(root, "SMAN5", "STA", "ARCADE.PAL")
    if os.path.exists(p):
        a = open(p, "rb").read()
        print("  ARCADE.PAL is %d bytes, header %s, max component %d"
              % (len(a), " ".join("%02x" % c for c in a[:5]), max(a[5:])))
        print("  -- the same five-byte element header, standing alone in a file")
    print("")

    print("=== the pictures ===")
    print("  pictures: %d   modes: %s" % (tot_pics, dict(modes)))
    print("  distinct sizes: %d" % len(dims))
    for (w, h), c in dims.most_common():
        print("    %4d x %-4d  x%d" % (w, h, c))
    print("")
    print("=== decoded exactly (stream consumed to the ff ff, all rows produced) ===")
    print("  %d of %d pictures" % (clean, modes[1] + modes[2]))
    for f, k, w, h, ln, used, rows in failures:
        print("    SHORT %s element %d  %dx%d  len=%d used=%d rows=%d"
              % (f, k, w, h, ln, used, rows))
    print("")

    if outdir:
        wrote = 0
        for f in names:
            d = open(os.path.join(root, f), "rb").read()
            _ver, _hdr, _decl, _offs, els = elements(d)
            _last, _first, _flag, rgb = read_palette(els[0])
            stem = f.replace("/", "_").rsplit(".", 1)[0]
            for k, e in enumerate(els[1:], 1):
                w, h, buf, _u, _r = decode(e)
                png(os.path.join(outdir, "%s_%02d.png" % (stem, k)), w, h, buf, rgb)
                wrote += 1
        print("=== wrote %d PNG to %s ===" % (wrote, outdir))


if __name__ == "__main__":
    main()
