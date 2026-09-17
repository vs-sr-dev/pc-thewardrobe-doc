#!/usr/bin/env python3
"""eleread.py -- the six .ELE and the five .MAT: the same pictures, twice.

The .ELE container is the .ANI container with the first two fields removed:

    u16  n             number of elements
    u32  offset[n]     relative to byte 2, so offset[0] == 4n

That single identity is what the pre-briefing saw as `u16[1] == 4 * u16[0]` on
six files of six. It is not a size field next to a count: **it is the low half
of the first 32-bit offset**, and the offset is 4n because the first element
begins immediately after the offset table. The arithmetic that "closed" was
the arithmetic of a table the reader had not found yet, and reading it from
byte 6 as the briefing tried is reading it four bytes late.

There is no palette element. The pictures are all mode 2 -- four bits per
pixel. `SIMULMAN.EXE` names `Arcade.pal` in a Pascal string, and
`SMAN5/STA/ARCADE.PAL` is one .ANI palette element standing alone in a file, so
that is the palette; but the sixteen indices are NOT the palette's first
sixteen.

WHICH SIXTEEN. Split the 256 entries into sixteen aligned blocks of sixteen
and ask which block holds a pure white (63,63,63): one block does, the last, at
240..255. It is also the only block holding a three-step flesh ramp and the
only one holding a three-step blue ramp. The sprite's commonest index, by a
factor of three over the next, is 9, and 240+9 is black.

So a four-bit picture's index i is the screen's colour 240+i: the top sixteen
slots are reserved for the character so that his colours do not change when the
room does. With base 0 the same sprites decode to a dark red smudge; with base
240 they decode to a man in a blue-black suit with white shoes and pink hands,
which is what the running game shows.

The .MAT are five files of exactly 64,000 bytes in which no byte exceeds 15 --
sixteen-colour pictures at one byte per pixel, half of every byte carrying
nothing. They are 320 x 200 and they are NOT stored one scanline after another.
The byte offset that best predicts a byte is 16, not 320: they are stored as
tiles sixteen pixels wide and ten tall, twenty across and twenty bands down, in
reading order. Rendered linearly they are stripes; rendered as tiles they are
rooms with the words CLOAK ROOM and PRIVATE legible in them.

    python tools/eleread.py <objectroot> [--png <outdir>]
"""
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aniread import decode, png            # noqa: E402


EMPTY = 0xFFFFFFFF     # a slot with no picture in it
MW, MH = 320, 200      # a .MAT screen
TW, TH = 16, 10        # and the tile it is stored in


def vdiff(d, stride):
    """Mean |p(i) - p(i+stride)|. The layout's true period minimises this."""
    n = len(d) - stride
    step = max(1, n // 20000)
    s = c = 0
    for i in range(0, n, step):
        s += abs(d[i] - d[i + stride])
        c += 1
    return s / float(c)


def drawn_indices(e):
    """The four-bit indices a mode-2 element actually paints.

    Skipped pixels are excluded: a skip is the absence of a colour, not a
    colour, and counting the untouched buffer as index 0 is how the base got
    picked wrong the first time.
    """
    w, h = struct.unpack("<2H", e[:4])
    s = e[5:]
    out = []
    x = y = i = 0
    while i < len(s) and y < h:
        b = s[i]
        i += 1
        if b == 0xFF:
            y += 1
            x = 0
            continue
        x += b
        if i >= len(s):
            break
        cnt = s[i]
        i += 1
        nb = (cnt + 1) // 2
        chunk = s[i:i + nb]
        i += nb
        for k in range(cnt):
            out.append((chunk[k // 2] & 0x0F) if k % 2 == 0
                       else (chunk[k // 2] >> 4))
        x += cnt
    return out


def untile(d):
    """A .MAT is tiles of TW x TH in reading order, not scanlines."""
    buf = bytearray(MW * MH)
    i = 0
    for band in range(MH // TH):
        for col in range(MW // TW):
            for y in range(TH):
                row = (band * TH + y) * MW + col * TW
                buf[row:row + TW] = d[i:i + TW]
                i += TW
    assert i == MW * MH, "untiling consumed %d of %d bytes" % (i, MW * MH)
    return buf


def ele_elements(d):
    """Elements in file order. A slot holding 0xFFFFFFFF is an empty slot.

    `SMAN5/IMG/SIMULMAN.ELE` declares 89 slots and holds 88 pictures: slot 15
    is 0xFFFFFFFF and every other offset is strictly increasing. Whoever
    removed that frame filled its slot with -1 rather than renumber the
    eighty-eight that follow it, which is the same decision `SMAN5/MAP/ROOM.IRM`
    exists to make possible: keep the index stable, move nothing.

    An element therefore ends at the next *non-empty* offset, not at the next
    one, and a reader that does not know this hands element 14 a length of
    38,382 bytes and falls off the end of the file.
    """
    n = struct.unpack("<H", d[:2])[0]
    offs = list(struct.unpack("<%dI" % n, d[2:2 + 4 * n]))
    out = []
    for k, o in enumerate(offs):
        if o == EMPTY:
            out.append(None)
            continue
        nxt = len(d)
        for later in offs[k + 1:]:
            if later != EMPTY:
                nxt = 2 + later
                break
        out.append(d[2 + o:nxt])
    return n, offs, out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    outdir = None
    if "--png" in sys.argv:
        outdir = sys.argv[sys.argv.index("--png") + 1]
        os.makedirs(outdir, exist_ok=True)
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

    palpath = os.path.join(root, "SMAN5", "STA", "ARCADE.PAL")
    pal = open(palpath, "rb").read()
    assert pal[:5] == b"\x00\xff\x00\x00\x80", "ARCADE.PAL is not a palette element"
    rgb = pal[5:]

    print("=== which sixteen colours a four-bit picture uses ===")
    whites, flesh, blues = [], [], []
    for blk in range(16):
        ent = [(rgb[3 * (blk * 16 + i)], rgb[3 * (blk * 16 + i) + 1],
                rgb[3 * (blk * 16 + i) + 2]) for i in range(16)]
        if any(r >= 60 and g >= 60 and b >= 60 for r, g, b in ent):
            whites.append(blk)
        if sum(1 for r, g, b in ent if r > g > 0 and r > b > 0 and r - b > 10) >= 3:
            flesh.append(blk)
        if sum(1 for r, g, b in ent if b > 15 and r == 0 and g == 0) >= 3:
            blues.append(blk)
    print("  blocks of sixteen holding a pure white   : %s" % whites)
    print("  blocks holding a three-step flesh ramp   : %s" % flesh)
    print("  blocks holding a three-step blue ramp    : %s" % blues)
    common = sorted(set(whites) & set(flesh) & set(blues))
    print("  blocks satisfying all three              : %s" % common)
    assert len(common) >= 1, "no palette block can hold these sprites"

    # Two blocks survive, 12 and 15, and they are the same sixteen colours
    # rotated by one: block 12 puts its magenta at index 0, block 15 puts it at
    # index 15. Magenta next to a flesh ramp and a blue ramp is a blitter's key
    # colour, and a key colour is the one index a sprite never draws. So count
    # the indices the sprites actually draw -- skipped pixels excluded, because
    # a skipped pixel is not a colour -- and keep the block whose magenta lands
    # on the index with a count of zero.
    drawn = Counter()
    for dp, _dd, ff in os.walk(root):
        for fn in sorted(ff):
            if not fn.upper().endswith(".ELE"):
                continue
            d = open(os.path.join(dp, fn), "rb").read()
            for e in ele_elements(d)[2]:
                if e is None or len(e) < 6:
                    continue
                drawn.update(drawn_indices(e))
    tot = sum(drawn.values())
    never = [i for i in range(16) if drawn[i] == 0]
    print("  pixels actually drawn by the 162 sprites  : %d" % tot)
    print("  four-bit indices never drawn once         : %s" % never)
    keyed = []
    for blk in common:
        mag = [i for i in range(16)
               if rgb[3 * (blk * 16 + i)] > 40 and rgb[3 * (blk * 16 + i) + 1] < 8
               and rgb[3 * (blk * 16 + i) + 2] > 40]
        print("  block %2d has its magenta at index %-2s and that index is drawn %d times"
              % (blk, mag[0] if mag else "-", drawn[mag[0]] if mag else -1))
        if mag and drawn[mag[0]] == 0:
            keyed.append(blk)
    assert len(keyed) == 1, \
        "the base is not uniquely determined: %s" % keyed
    BASE = keyed[0] * 16
    print("  -> base %d, the top sixteen slots:" % BASE)
    for i in range(BASE, BASE + 16):
        print("     %3d  %2d %2d %2d" % (i, rgb[3 * i], rgb[3 * i + 1], rgb[3 * i + 2]))
    print("")

    names = []
    for dp, _dd, ff in os.walk(root):
        for n in sorted(ff):
            if n.upper().endswith(".ELE"):
                names.append(os.path.relpath(os.path.join(dp, n), root)
                             .replace(os.sep, "/"))
    names.sort()
    assert names, "no .ELE under %r" % root

    print("=== the .ELE container ===")
    print("  %-24s %7s %4s %7s %7s %7s %6s" %
          ("file", "size", "n", "off0=4n", "mono", "closes", "empty"))
    tot_empty = 0
    tot_el = 0
    clean = 0
    bad = []
    dims = Counter()
    modes = Counter()
    for f in names:
        d = open(os.path.join(root, f), "rb").read()
        n, offs, els = ele_elements(d)
        real = [o for o in offs if o != EMPTY]
        c1 = offs[0] == 4 * n
        c2 = all(real[i] < real[i + 1] for i in range(len(real) - 1))
        c3 = 2 + real[-1] < len(d)
        empty = n - len(real)
        print("  %-24s %7d %4d %7s %7s %7s %6d" % (f, len(d), n, c1, c2, c3, empty))
        assert c1 and c2 and c3, "%s: the offset table does not fit the file" % f
        tot_empty += empty
        for k, e in enumerate(els):
            if e is None:
                continue
            if len(e) < 6:
                bad.append((f, k, "element shorter than a header"))
                continue
            w, h = struct.unpack("<2H", e[:4])
            modes[e[4]] += 1
            dims[(w, h)] += 1
            tot_el += 1
            _w, _h, buf, used, rows = decode(e, BASE)
            if used == len(e) - 2 and e[-2:] == b"\xff\xff" and rows == h:
                clean += 1
            else:
                bad.append((f, k, "%dx%d len=%d used=%d rows=%d"
                            % (w, h, len(e), used, rows)))
    print("")
    print("  slots: %d   of which empty (0xFFFFFFFF): %d   pictures: %d"
          % (tot_el + tot_empty, tot_empty, tot_el))
    print("  modes: %s" % dict(modes))
    print("  decoded exactly (stream to the ff ff, all rows): %d of %d"
          % (clean, tot_el))
    for f, k, why in bad:
        print("    NOT CLEAN %s element %d: %s" % (f, k, why))
    print("  distinct sizes: %d, commonest:" % len(dims))
    for (w, h), c in dims.most_common(8):
        print("    %3d x %-3d x%d" % (w, h, c))
    print("")

    print("=== the five .MAT, and the half of each that carries nothing ===")
    stadir = os.path.join(root, "SMAN5", "STA")
    mats = sorted(n for n in os.listdir(stadir) if n.upper().endswith(".MAT"))
    tot = 0
    for m in mats:
        d = open(os.path.join(stadir, m), "rb").read()
        c = Counter(d)
        over = sum(v for k, v in c.items() if k > 15)
        tot += len(d)
        print("  %-14s %6d bytes = %d x %d  distinct values %2d  max %2d  bytes > 15: %d"
              % (m, len(d), MW, MH, len(c), max(d), over))
        assert len(d) == MW * MH, "%s is not 320x200" % m
        assert over == 0, "%s uses a colour above 15" % m
    print("  total %d bytes; the high nibble of every one of them is zero," % tot)
    print("  so %d bytes -- %.4f %% of a 2,056,643-byte object -- are"
          % (tot // 2, 100.0 * (tot // 2) / 2056643))
    print("  four bits of nothing each, in an object whose own sprite format")
    print("  packs two pixels per byte. See the leftovers chapter.")
    print("")

    print("=== how a .MAT is laid out: measured, not assumed ===")
    d = open(os.path.join(stadir, mats[0]), "rb").read()
    scores = sorted((vdiff(d, w), w) for w in range(8, 1025))
    print("  the six byte distances that best predict a byte, in %s:" % mats[0])
    for s, w in scores[:6]:
        print("     distance %4d   mean |difference| %.3f" % (w, s))
    print("     distance  320   mean |difference| %.3f   <- a scanline, if it were one"
          % vdiff(d, 320))
    assert scores[0][1] == TW, \
        "the .MAT stride is no longer %d; the tiling below is not derived" % TW
    print("  The best distance is %d, not 320. Reassembled as %d x %d tiles laid"
          % (TW, TW, TH))
    print("  out in reading order, %d across and %d down, the five files are rooms."
          % (MW // TW, MH // TH))
    print("")

    if outdir:
        wrote = 0
        for f in names:
            d = open(os.path.join(root, f), "rb").read()
            _n, _offs, els = ele_elements(d)
            stem = f.replace("/", "_").rsplit(".", 1)[0]
            for k, e in enumerate(els):
                if e is None or len(e) < 6:
                    continue
                w, h, buf, _u, _r = decode(e, BASE)
                png(os.path.join(outdir, "%s_%03d.png" % (stem, k)), w, h, buf, rgb)
                wrote += 1
        for m in mats:
            d = open(os.path.join(stadir, m), "rb").read()
            png(os.path.join(outdir, "STA_%s.png" % m.rsplit(".", 1)[0]),
                MW, MH, untile(d), rgb)
            wrote += 1
        print("=== wrote %d PNG to %s ===" % (wrote, outdir))


if __name__ == "__main__":
    main()
