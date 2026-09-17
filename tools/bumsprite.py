#!/usr/bin/env python3
"""bumsprite.py -- read the sprite banks of BUMPY (Loriciel, 1992):
BUMSPJEU.BIN (511 sprites, 89,116 bytes) and FLECHE.BIN (1 sprite, the
arrow cursor), by the big-endian table and record head the program reads.

THE FILE, AS THE PROGRAM READS IT (0CECh:0C34h, the EGA/VGA bank setup)
----------------------------------------------------------------------------
    +0      512 x u32 BE    offsets of the records' PIXEL DATA, relative to
                            the end of this table (the code adds 800h); the
                            list ends at the first zero
    +2048   records, each:  12 bytes of u16 BE head, then the pixels
                +0  h0   0 (one record of 511 says 12)
                +2  h1   3 on every record (the top two bits of its low
                         byte must be clear, or the record is skipped)
                +4  h2   x of the hot-spot (0 or the centre)
                +6  h3   y of the hot-spot
                +8  h4   words per row over all four planes: 4 = 16 px,
                         8 = 32 px, 12 = 48 px wide
                +10 h5   rows
            pixels: h5 rows of h4 words; within a row, each 16-pixel
            column in turn, and for each column its plane 0, 1, 2, 3 word
            (so a 16-wide row is p0 p1 p2 p3 and a 32-wide row is
            p0 p1 p2 p3 p0' p1' p2' p3'), MSB = leftmost pixel; colour 0
            is the transparent one (the bank has no mask plane). The
            column-then-plane order was decided by a render: the other
            order (all of plane 0, then plane 1...) paints the 16-wide
            sprites identically and the 32-wide ones as noise.

The head is BELOW the pointer: the setup code converts every table entry
to a far pointer and then reads `[di-2]`..`[di-12]`, swapping each word.
The record's data length is not written anywhere; it is h4 * 2 * h5 on
510 of 511 records, and the census says which one is not.

    python tools/bumsprite.py census FILE...
    python tools/bumsprite.py sheet  FILE OUT.png [--pal SCREEN.VEC] [--scale N]
    python tools/bumsprite.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfflic     # noqa: E402
import dirguard   # noqa: E402
import nameguard  # noqa: E402

TABLE = 0x800
HEADLEN = 12
# the EGA's sixteen, for a sheet drawn without a screen's palette
EGA = [(0, 0, 0), (0, 0, 170), (0, 170, 0), (0, 170, 170), (170, 0, 0),
       (170, 0, 170), (170, 85, 0), (170, 170, 170), (85, 85, 85), (85, 85, 255),
       (85, 255, 85), (85, 255, 255), (255, 85, 85), (255, 85, 255),
       (255, 255, 85), (255, 255, 255)]


class Refused(Exception):
    pass


def records(d):
    """Every record, in table order, with its head and its pixel data."""
    if len(d) < TABLE + HEADLEN:
        raise Refused("%d bytes: shorter than the 2,048-byte table and one head" % len(d))
    offs = []
    for i in range(512):
        v = struct.unpack_from(">I", d, 4 * i)[0]
        if v == 0:
            break
        if v < HEADLEN or TABLE + v > len(d):
            raise Refused("entry %d = %d points outside the file" % (i, v))
        if offs and v <= offs[-1]:
            raise Refused("entry %d = %d is not after entry %d = %d" % (i, v, i - 1, offs[-1]))
        offs.append(v)
    if not offs:
        raise Refused("an empty table")
    out = []
    for k, o in enumerate(offs):
        p = TABLE + o
        h = struct.unpack_from(">6H", d, p - HEADLEN)
        end = (TABLE + offs[k + 1] - HEADLEN) if k + 1 < len(offs) else len(d)
        want = h[4] * 2 * h[5]
        if h[4] % 4 or h[4] == 0 or h[5] == 0:
            raise Refused("record %d: h4=%d h5=%d is not four planes of rows" % (k, h[4], h[5]))
        if p + want > len(d):
            raise Refused("record %d: %d bytes of pixels run past the end" % (k, want))
        out.append(dict(index=k, off=p, head=h, w=h[4] * 4, h=h[5],
                        pixels=d[p:p + want], slack=end - p - want))
    return out


def decode(rec):
    """4-bit indices, row-major, w x h."""
    w, h, wpp = rec["w"], rec["h"], rec["head"][4] // 4
    img = bytearray(w * h)
    px = rec["pixels"]
    for y in range(h):
        row = y * rec["head"][4] * 2
        for p in range(4):
            for wi in range(wpp):
                word = struct.unpack_from(">H", px, row + (wi * 4 + p) * 2)[0]
                for bit in range(16):
                    if word & (0x8000 >> bit):
                        img[y * w + wi * 16 + bit] |= 1 << p
    return img


def cmd_census(paths):
    for path in paths:
        d = open(path, "rb").read()
        try:
            recs = records(d)
        except Refused as e:
            print("REFUSED  %s: %s" % (os.path.basename(path), e))
            continue
        sizes = {}
        odd = [r for r in recs if r["slack"]]
        for r in recs:
            sizes[(r["w"], r["h"])] = sizes.get((r["w"], r["h"]), 0) + 1
        h1 = sorted(set(r["head"][1] for r in recs))
        h0 = sorted(set(r["head"][0] for r in recs))
        print("%s  %d bytes  %d records  table %d bytes" % (
            os.path.basename(path), len(d), len(recs), TABLE))
        print("  h0 values %s  h1 values %s  hot-spots %s" % (
            h0, h1, sorted(set((r["head"][2], r["head"][3]) for r in recs))))
        print("  sizes (w x h: count): %s" % ", ".join(
            "%dx%d: %d" % (k[0], k[1], v) for k, v in sorted(sizes.items(), key=lambda t: -t[1])))
        print("  records whose pixels do not fill up to the next head: %d of %d%s" % (
            len(odd), len(recs), "" if not odd else "  " + ", ".join(
                "#%d (%d slack)" % (r["index"], r["slack"]) for r in odd)))
        total = TABLE + sum(HEADLEN + len(r["pixels"]) + r["slack"] for r in recs)
        print("  table + heads + pixels + slack = %d  against %d  residue %d" % (
            total, len(d), len(d) - total))
    return 0


def palette_from_screen(path):
    import vecscreen
    return vecscreen.screen(open(path, "rb").read())["pal"]


def cmd_sheet(path, out, pal, scale):
    d = open(path, "rb").read()
    try:
        recs = records(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    cell_w = max(r["w"] for r in recs) + 2
    cell_h = max(r["h"] for r in recs) + 2
    cols = 24
    rows = (len(recs) + cols - 1) // cols
    W, H = cols * cell_w, rows * cell_h
    img = bytearray(W * H)
    for r in recs:
        cx, cy = (r["index"] % cols) * cell_w + 1, (r["index"] // cols) * cell_h + 1
        im = decode(r)
        for y in range(r["h"]):
            img[(cy + y) * W + cx:(cy + y) * W + cx + r["w"]] = im[y * r["w"]:(y + 1) * r["w"]]
    if scale > 1:
        big = bytearray(W * scale * H * scale)
        for y in range(H * scale):
            src = img[(y // scale) * W:(y // scale + 1) * W]
            big[y * W * scale:(y + 1) * W * scale] = b"".join(bytes([v]) * scale for v in src)
        img, W, H = big, W * scale, H * scale
    bfflic.write_png(out, img, pal, W, H)
    print("%s: %d sprites on a %d x %d sheet -> %s" % (os.path.basename(path), len(recs), W, H, out))
    return 0


def _bank(specs):
    """specs: list of (w, h, fill colour) -> a bank as the game reads it."""
    recs = b""
    offs = []
    pos = 0
    for w, h, c in specs:
        wpp = w // 16
        rows = b""
        for y in range(h):
            for wi in range(wpp):
                # column wi of a multi-column sprite carries colour c + wi
                cc = c + wi
                for p in range(4):
                    rows += struct.pack(">H", 0xFFFF if (cc >> p) & 1 else 0)
        head = struct.pack(">6H", 0, 3, w // 2, h // 2, wpp * 4, h)
        offs.append(pos + HEADLEN)
        recs += head + rows
        pos += len(head) + len(rows)
    table = b"".join(struct.pack(">I", o) for o in offs) + bytes(TABLE - 4 * len(offs))
    return table + recs


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-60s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    b = _bank([(16, 15, 5), (32, 6, 15), (48, 3, 1)])
    recs = records(b)
    check("three records by the table, first at 2,060", len(recs) == 3 and recs[0]["off"] == 2060)
    check("16x15, 32x6, 48x3 from h4 and h5",
          [(r["w"], r["h"]) for r in recs] == [(16, 15), (32, 6), (48, 3)])
    check("no slack between records", all(r["slack"] == 0 for r in recs))
    check("a 16x15 sprite of colour 5 decodes to 240 fives",
          decode(recs[0]) == bytes([5]) * 240)
    im = decode(recs[1])
    check("a 32x6 sprite: left column colour 15, right column colour 0 (15+1 & 15) "
          "-- column-then-plane order",
          all(im[y * 32 + x] == (15 if x < 16 else 0) for y in range(6) for x in range(32)))
    im = decode(recs[2])
    check("a 48x3 sprite: columns 1, 2, 3",
          all(im[y * 48 + x] == 1 + x // 16 for y in range(3) for x in range(48)))
    check("hot-spot read as h2, h3", recs[0]["head"][2:4] == (8, 7))
    # a slack byte after the last record's pixels is counted
    recs2 = records(b + b"\0" * 7)
    check("trailing bytes after the last record are slack, not refused", recs2[-1]["slack"] == 7)
    for label, blob, needle in (
            ("a table entry pointing past the end",
             struct.pack(">I", 5000) + bytes(TABLE - 4) + bytes(20), "outside"),
            ("a table that goes backwards",
             struct.pack(">II", 12, 12) + bytes(TABLE - 8) + bytes(12) + bytes(240), "not after"),
            ("a record with h4 not a multiple of 4",
             struct.pack(">I", 12) + bytes(TABLE - 4) + struct.pack(">6H", 0, 3, 0, 0, 5, 4) + bytes(40),
             "four planes"),
            ("a record whose pixels run past the end",
             struct.pack(">I", 12) + bytes(TABLE - 4) + struct.pack(">6H", 0, 3, 0, 0, 4, 40) + bytes(40),
             "past the end"),
            ("a file shorter than the table", bytes(100), "shorter")):
        try:
            records(blob)
            check("refuses " + label, False, "accepted")
        except Refused as e:
            check("refuses " + label, needle in str(e), str(e))
    print("\nbumsprite.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("census", "sheet", "selftest"))
    ap.add_argument("args", nargs="*")
    ap.add_argument("--pal", default=None, help="a .VEC screen whose palette to use")
    ap.add_argument("--scale", type=int, default=2)
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    if a.cmd == "census":
        for p in a.args:
            dirguard.want_file(p, "bumsprite.py")
        return cmd_census(a.args)
    if len(a.args) != 2:
        ap.error("sheet FILE OUT.png")
    dirguard.want_file(a.args[0], "bumsprite.py")
    pal = EGA
    if a.pal:
        dirguard.want_file(a.pal, "bumsprite.py")
        pal = palette_from_screen(a.pal)
    return cmd_sheet(a.args[0], a.args[1], pal, a.scale)


if __name__ == "__main__":
    sys.exit(main())
