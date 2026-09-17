#!/usr/bin/env python3
"""carfont.py -- read DDFNT2.CAR, the 7 x 8 proportional font of BUMPY
(Loriciel, 1992), by its big-endian offset table and its glyph records.

THE FILE, AS THE BYTES SAY IT
-----------------------------
    +0   u8   first character (20h)
    +1   u8   last character (FFh)
    +2   u8   cell width (7)
    +3   u8   cell height (8) -- the program's line spacing is this + 2
              (0AB9h:1347h..134Ch reads byte 3 of the font, adds 2)
    +4   u8   1     +5  u8  0     (not read by the setup routine)
    +6   (last - first + 1) x u16 BE: the ABSOLUTE offset of each glyph;
         the first one is 6 + 2 x 224 = 454 = 1C6h, where the table ends
    glyph:
         u8 advance   the pen moves this many pixels (2 for an empty glyph)
         u8 rows      rows drawn, from `top`
         u8 top       first cell row of the glyph (8 for an empty glyph)
         (8 - top) bytes of rows, MSB = leftmost pixel of the cell
         one padding byte if the record would otherwise be odd in length
         -- an assembler's EVEN, and the padding byte is whatever was in
         memory (F6h after `!`, 40h after `"`); the last glyph, at the
         end of the file, has no room for one and is three bytes

Nothing here is executed; the setup routine reads byte 3 and the table's
shape says the rest. `census` closes: 224 records tile 454..1981 with no
gap, every offset rises, every glyph's rows fit in the cell.

    python tools/carfont.py census FILE
    python tools/carfont.py sheet  FILE OUT.png [--scale N]
    python tools/carfont.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfflic     # noqa: E402
import dirguard   # noqa: E402
import nameguard  # noqa: E402


class Refused(Exception):
    pass


def font(d):
    if len(d) < 8:
        raise Refused("%d bytes: no head" % len(d))
    first, last, cw, ch = d[0], d[1], d[2], d[3]
    if last < first or ch == 0 or ch > 16 or cw == 0 or cw > 16:
        raise Refused("head %s is not a font" % d[:6].hex(" "))
    n = last - first + 1
    if 6 + 2 * n > len(d):
        raise Refused("table of %d offsets does not fit" % n)
    offs = struct.unpack_from(">%dH" % n, d, 6)
    if offs[0] != 6 + 2 * n:
        raise Refused("first glyph at %d, table ends at %d" % (offs[0], 6 + 2 * n))
    glyphs = []
    padded = 0
    for i in range(n):
        o = offs[i]
        end = offs[i + 1] if i + 1 < n else len(d)
        if end <= o or o + 3 > len(d):
            raise Refused("glyph %d at %d..%d is out of order or empty" % (first + i, o, end))
        adv, rows, top = d[o], d[o + 1], d[o + 2]
        if top > ch or rows > ch - top:
            raise Refused("glyph %d: %d rows from row %d do not fit a cell of %d"
                          % (first + i, rows, top, ch))
        body = ch - top
        want = 3 + body
        pad = want % 2
        if end - o not in (want, want + pad):
            raise Refused("glyph %d: %d bytes, expected %d or %d" % (first + i, end - o, want, want + pad))
        padded += (end - o) - want
        glyphs.append(dict(char=first + i, adv=adv, rows=rows, top=top,
                           bits=d[o + 3:o + 3 + rows], off=o, length=end - o))
    return dict(first=first, last=last, cw=cw, ch=ch, glyphs=glyphs, padded=padded)


def cmd_census(path):
    d = open(path, "rb").read()
    try:
        f = font(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    g = f["glyphs"]
    empty = [x for x in g if x["rows"] == 0]
    drawn = [x for x in g if x["rows"]]
    print("%s  %d bytes  chars %02Xh..%02Xh (%d)  cell %d x %d  line spacing %d" % (
        os.path.basename(path), len(d), f["first"], f["last"], len(g), f["cw"], f["ch"], f["ch"] + 2))
    print("  drawn glyphs %d, empty %d; padding bytes %d; records tile %d..%d, residue %d" % (
        len(drawn), len(empty), f["padded"], g[0]["off"], len(d),
        len(d) - g[-1]["off"] - g[-1]["length"]))
    print("  drawn: %s" % "".join(chr(x["char"]) if 32 <= x["char"] < 127 else "\\x%02X" % x["char"]
                                 for x in drawn))
    print("  advances: %s" % sorted(set(x["adv"] for x in g)))
    return 0


def cmd_sheet(path, out, scale):
    d = open(path, "rb").read()
    try:
        f = font(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    cw, ch = 9, f["ch"] + 2
    cols = 32
    rows = (len(f["glyphs"]) + cols - 1) // cols
    W, H = cols * cw, rows * ch
    img = bytearray(W * H)
    for i, g in enumerate(f["glyphs"]):
        cx, cy = (i % cols) * cw + 1, (i // cols) * ch + 1
        for r, byte in enumerate(g["bits"]):
            y = cy + g["top"] + r
            for bit in range(8):
                if byte & (0x80 >> bit):
                    img[y * W + cx + bit] = 15
    if scale > 1:
        big = bytearray()
        for y in range(H):
            line = b"".join(bytes([v]) * scale for v in img[y * W:(y + 1) * W])
            big += line * scale
        img, W, H = big, W * scale, H * scale
    pal = [(0, 0, 0)] * 15 + [(255, 255, 255)]
    bfflic.write_png(out, img, pal, W, H)
    print("%s: %d glyphs -> %s" % (os.path.basename(path), len(f["glyphs"]), out))
    return 0


def _font(glyphs, first=0x20):
    """glyphs: list of (adv, top, rows bytes) -> a file as the writer made it."""
    n = len(glyphs)
    recs = []
    pos = 6 + 2 * n
    offs = []
    for adv, top, bits in glyphs:
        rec = bytes([adv, len(bits), top]) + bits + bytes(max(0, 8 - top - len(bits)))
        if len(rec) % 2:
            rec += b"\xEE"
        offs.append(pos)
        recs.append(rec)
        pos += len(rec)
    return bytes([first, first + n - 1, 7, 8, 1, 0]) + struct.pack(">%dH" % n, *offs) + b"".join(recs)


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-60s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    spec = _font([(2, 8, b""), (4, 0, b"\x60" * 7), (6, 3, b"\x7C"), (4, 5, b"\x60\x60\xC0")])
    f = font(spec)
    check("four glyphs, first at 6 + 8 = 14", len(f["glyphs"]) == 4 and f["glyphs"][0]["off"] == 14)
    g = f["glyphs"]
    check("an empty glyph is adv 2, top 8, 0 rows, 4 bytes (padded)",
          g[0]["adv"] == 2 and g[0]["top"] == 8 and g[0]["rows"] == 0 and g[0]["length"] == 4)
    check("a full glyph is 3 + 8 + 1 = 12 bytes", g[1]["length"] == 12 and g[1]["bits"] == b"\x60" * 7)
    check("a dash at row 3 is 3 + 5 = 8 bytes, no padding", g[2]["length"] == 8)
    check("a comma at row 5 is 3 + 3 = 6 bytes", g[3]["length"] == 6 and g[3]["bits"] == b"\x60\x60\xC0")
    check("padding counted: 2 bytes over four glyphs", f["padded"] == 2)
    for label, blob, needle in (
            ("a first offset that is not the table's end",
             spec[:6] + struct.pack(">H", 15) + spec[8:], "table ends"),
            ("a glyph whose rows do not fit the cell",
             _font([(4, 6, b"\x60" * 3)]), "do not fit"),
            ("a record of the wrong length",
             _font([(4, 0, b"\x60" * 7)])[:-2], "expected"),
            ("a head that is not a font", b"\xFF\x20\x00\x00\x00\x00" + bytes(10), "not a font")):
        try:
            font(blob)
            check("refuses " + label, False, "accepted")
        except Refused as e:
            check("refuses " + label, needle in str(e), str(e))
    print("\ncarfont.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("census", "sheet", "selftest"))
    ap.add_argument("args", nargs="*")
    ap.add_argument("--scale", type=int, default=4)
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    dirguard.want_file(a.args[0], "carfont.py")
    if a.cmd == "census":
        return cmd_census(a.args[0])
    if len(a.args) != 2:
        ap.error("sheet FILE OUT.png")
    return cmd_sheet(a.args[0], a.args[1], a.scale)


if __name__ == "__main__":
    sys.exit(main())
