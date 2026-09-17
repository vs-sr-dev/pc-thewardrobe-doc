#!/usr/bin/env python3
"""Read the `CHAR` character sets of a SCUMM container and ask what alphabet
they cover.

The layout was derived from the four chunks themselves, not from a reference:

    +0   u32 LE   a size that equals (payload length - 15) in all four
    +4   u16      0x0363, identical in all four
    +6   15 bytes a small colour map, values 0x01..0x0F
    +21  u8       bits per pixel: 1, 2, 2, 4 in the four sets
    +22  u8       line height: 8, 12, 15, 10
    +23  u16 LE   number of character slots: 226, 226, 226, 256
    +25  u32 LE   x nslots: offset of each glyph, or 0 for "no glyph",
                  counted from +21

The check that fixes it: for every one of the four sets, the first non-zero
offset is exactly `4 + nslots*4`, i.e. the first glyph begins immediately
after the offset table -- and every offset is inside the chunk. Nothing else
about the header makes that come out right.

Each glyph is `[width:1][height:1][xoff:s8][yoff:s8]` then `width*height`
pixels packed at `bpp` bits each, most significant bit first.

The question this tool exists to answer: a game translated into Italian needs
`a e i o u` with grave accents and `e` with an acute. In CP437 those live at
0x85, 0x8A, 0x8D, 0x95, 0x97 and 0x82. `slots` prints which slots carry a
glyph, so the answer is a table and not an opinion.

Usage:
  python tools/scummfont.py info  <SAMNMAX.001> [--key 0x69]
  python tools/scummfont.py slots <SAMNMAX.001> [--font N]
  python tools/scummfont.py pgm   <SAMNMAX.001> <font> <first> <count> <out.pgm>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0] if "/" in __file__ else ".")


def load(path, key=0x69):
    d = open(path, "rb").read()
    return bytes(b ^ key for b in d) if key else d


def find_chars(c):
    out = []

    def walk(lo, hi):
        p = lo
        while p < hi:
            t = c[p:p + 4]
            l = int.from_bytes(c[p + 4:p + 8], "big")
            if t == b"CHAR":
                out.append((p, l))
            elif t in (b"LECF", b"LFLF", b"ROOM", b"OBCD", b"OBIM", b"RMIM",
                       b"PALS", b"WRAP"):
                walk(p + 8, p + l)
            p += l
    walk(0, len(c))
    return out


def header(c, p, l):
    b = c[p + 8:p + l]
    size = int.from_bytes(b[0:4], "little")
    magic = int.from_bytes(b[4:6], "little")
    cmap = list(b[6:21])
    bpp = b[21]
    hgt = b[22]
    n = int.from_bytes(b[23:25], "little")
    offs = [int.from_bytes(b[25 + 4 * i:29 + 4 * i], "little") for i in range(n)]
    return b, size, magic, cmap, bpp, hgt, n, offs


def glyph(b, offs_i, bpp):
    base = 21 + offs_i
    w, h = b[base], b[base + 1]
    xo = b[base + 2] - 256 if b[base + 2] > 127 else b[base + 2]
    yo = b[base + 3] - 256 if b[base + 3] > 127 else b[base + 3]
    px = []
    bitpos = (base + 4) * 8
    for y in range(h):
        row = []
        for x in range(w):
            v = 0
            for k in range(bpp):
                byte = b[(bitpos) >> 3]
                v = (v << 1) | ((byte >> (7 - (bitpos & 7))) & 1)
                bitpos += 1
            row.append(v)
        px.append(row)
    return w, h, xo, yo, px, (bitpos + 7) // 8


def cmd_info(path, key):
    c = load(path, key)
    cs = find_chars(c)
    print("CHAR chunks %d\n" % len(cs))
    for i, (p, l) in enumerate(cs):
        b, size, magic, cmap, bpp, hgt, n, offs = header(c, p, l)
        used = sum(1 for o in offs if o)
        first = next((o for o in offs if o), 0)
        print("font %d at %d, chunk %d bytes, payload %d" % (i, p, l, len(b)))
        print("  size field      %d   (payload - 15 = %d)" % (size, len(b) - 15))
        print("  magic           0x%04X" % magic)
        print("  colour map      %s" % cmap)
        print("  bits per pixel  %d" % bpp)
        print("  line height     %d" % hgt)
        print("  slots           %d" % n)
        print("  slots with glyph%d" % used)
        print("  first glyph at  %d, table ends at %d  -> %s"
              % (first, 4 + 4 * n, "EXACT" if first == 4 + 4 * n else "MISMATCH"))
        print("  max offset      %d, payload %d -> %s"
              % (max(offs), len(b), "inside" if 21 + max(offs) < len(b) else "OUTSIDE"))
        hs = [glyph(b, o, bpp)[1] for o in offs if o]
        ws = [glyph(b, o, bpp)[0] for o in offs if o]
        print("  glyph widths    %d..%d, heights %d..%d"
              % (min(ws), max(ws), min(hs), max(hs)))
        print()


ITALIAN = {0x82: "e acute", 0x85: "a grave", 0x8A: "e grave", 0x8D: "i grave",
           0x95: "o grave", 0x97: "u grave"}


def cmd_slots(path, key, only):
    c = load(path, key)
    cs = find_chars(c)
    for i, (p, l) in enumerate(cs):
        if only is not None and i != only:
            continue
        b, size, magic, cmap, bpp, hgt, n, offs = header(c, p, l)
        have = [k for k in range(n) if offs[k]]
        print("font %d: %d slots, %d with a glyph" % (i, n, len(have)))
        print("  lowest %d (0x%02X)  highest %d (0x%02X)"
              % (have[0], have[0], have[-1], have[-1]))
        runs = []
        s = have[0]
        prev = have[0]
        for k in have[1:]:
            if k != prev + 1:
                runs.append((s, prev))
                s = k
            prev = k
        runs.append((s, prev))
        print("  runs: %s" % ", ".join("0x%02X-0x%02X" % r for r in runs))
        print("  Italian accented vowels, CP437 positions:")
        for k, name in sorted(ITALIAN.items()):
            g = ""
            if k < n and offs[k]:
                w, h, xo, yo, px, e = glyph(b, offs[k], bpp)
                g = "glyph %dx%d" % (w, h)
            print("    0x%02X %-8s %s" % (k, name, g or "NO GLYPH"))
        upper = {0xC0: "A grave", 0xC8: "E grave", 0xC9: "E acute",
                 0xCC: "I grave", 0xD2: "O grave", 0xD9: "U grave"}
        print("  the same letters in Latin-1 positions (which CP437 uses for"
              " box-drawing):")
        for k, name in sorted(upper.items()):
            print("    0x%02X %-8s %s"
                  % (k, name, "has a glyph" if k < n and offs[k] else "no glyph"))
        print()


def cmd_pgm(path, fi, first, count, out, key):
    c = load(path, key)
    cs = find_chars(c)
    p, l = cs[fi]
    b, size, magic, cmap, bpp, hgt, n, offs = header(c, p, l)
    gs = []
    for k in range(first, min(first + count, n)):
        if offs[k]:
            gs.append(glyph(b, offs[k], bpp))
    if not gs:
        sys.exit("no glyphs in that range")
    H = max(g[1] for g in gs) + 2
    W = sum(g[0] + 1 for g in gs)
    img = [[0] * W for _ in range(H)]
    x0 = 0
    mx = max(1, (1 << bpp) - 1)
    for w, h, xo, yo, px, e in gs:
        for y in range(h):
            for x in range(w):
                img[y + 1][x0 + x] = px[y][x] * 255 // mx
        x0 += w + 1
    with open(out, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (W, H))
        for row in img:
            f.write(bytes(row))
    print("wrote %s  %dx%d  %d glyphs" % (out, W, H, len(gs)))


def main(argv):
    key = 0x69
    only = None
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--key":
            key = int(argv[i + 1], 0); i += 2
        elif argv[i] == "--font":
            only = int(argv[i + 1]); i += 2
        else:
            rest.append(argv[i]); i += 1
    if rest[0] == "info":
        cmd_info(rest[1], key)
    elif rest[0] == "slots":
        cmd_slots(rest[1], key, only)
    elif rest[0] == "pgm":
        cmd_pgm(rest[1], int(rest[2], 0), int(rest[3], 0),
                int(rest[4], 0), rest[5], key)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
