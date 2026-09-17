#!/usr/bin/env python3
"""bumlevel.py -- read the nine levels of BUMPY (Loriciel, 1992): D1..D9
.BUM / .DEC / .PAV, once bumpack.py has unpacked them (or as they are, for
the two .BUM the release left in the clear).

WHAT THE PROGRAM SAYS THE THREE FILES ARE (cs:32B0 and cs:0A90, read)
-------------------------------------------------------------------------
    Dn.BUM   u16 head, then one record of 194 bytes per PLATFORM (the
             program's word: `[7310h]` is the platform number and the
             record is at BUM + 2 + n * 0C2h). 2,912 = 2 + 15 x 194 and
             2,330 = 2 + 12 x 194: a level is 15 or 12 platforms.
             Of a record the program copies to its working copy (cs:32FE)
             three tables of 48 bytes (+0, +48, +96) and six bytes at
             +144..+149; the last 44 bytes are not copied there.
             48 = 8 columns x 6 rows over a 320 x 192 play area (cells of
             40 x 32): in level 1, platform 0, table A is five identical
             rows `. 1 . 1 1 . 1 .` over a row of eight 1s -- a floor.
             What a value in A, B or C means to the engine is NOT derived
             here; the tables are printed as grids and counted.
    Dn.DEC   u16 head, then one record of 812 bytes per platform (at
             DEC + 2 + n * 32Ch): 12,182 = 2 + 15 x 812, 9,746 = 2 + 12 x
             812. A record is a u16 and 270 triplets; the first byte of
             many triplets steps by 20 (07h 1Bh 2Fh 43h 57h 6Bh 7Fh), the
             stride of a 20-column cell grid. Its grammar is not derived.
    Dn.PAV   6 bytes, then 320 x 192 pixels in four planes of 7,680 bytes
             (40 bytes x 192 rows each): the play background, which the
             program blits whole (source PAV + 6, 20 x 24 cells of 16 x 8,
             at 0,0 -- cs:0AA0..0ACA). The six bytes are F0 FF 00 5F 18 00
             on levels 1-5 and F0 FE 00 BF 18 AA on 6-9; the program does
             not read them. The PAV carries no palette; `render` takes one
             from a .VEC screen (the level's MONDE by default).

    python tools/bumlevel.py census  DIR         D1..D9 in DIR (unpacked)
    python tools/bumlevel.py grids   DIR/Dn.BUM  the 8 x 6 tables, per platform
    python tools/bumlevel.py render  DIR/Dn.PAV OUT.png --pal SCREEN.VEC
    python tools/bumlevel.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfflic     # noqa: E402
import dirguard   # noqa: E402
import nameguard  # noqa: E402

BUM_REC, DEC_REC = 194, 812
PAV_HEAD, PAV_PLANE, PAV_W, PAV_H = 6, 7680, 320, 192
COLS, ROWS = 8, 6


class Refused(Exception):
    pass


def bum(d):
    if len(d) < 2 or (len(d) - 2) % BUM_REC:
        raise Refused("%d bytes is not 2 + n x %d" % (len(d), BUM_REC))
    n = (len(d) - 2) // BUM_REC
    recs = []
    for k in range(n):
        r = d[2 + k * BUM_REC:2 + (k + 1) * BUM_REC]
        recs.append(dict(a=r[0:48], b=r[48:96], c=r[96:144], p=r[144:150], tail=r[150:194]))
    return dict(head=d[:2], platforms=recs)


def dec(d):
    if len(d) < 2 or (len(d) - 2) % DEC_REC:
        raise Refused("%d bytes is not 2 + n x %d" % (len(d), DEC_REC))
    n = (len(d) - 2) // DEC_REC
    recs = []
    for k in range(n):
        r = d[2 + k * DEC_REC:2 + (k + 1) * DEC_REC]
        trips = [tuple(r[2 + 3 * i:5 + 3 * i]) for i in range(270)]
        recs.append(dict(head=r[:2], triplets=trips))
    return dict(head=d[:2], platforms=recs)


def pav(d):
    if len(d) != PAV_HEAD + 4 * PAV_PLANE:
        raise Refused("%d bytes is not 6 + 4 x %d" % (len(d), PAV_PLANE))
    img = bytearray(PAV_W * PAV_H)
    for p in range(4):
        plane = d[PAV_HEAD + p * PAV_PLANE:PAV_HEAD + (p + 1) * PAV_PLANE]
        bit = 1 << p
        for y in range(PAV_H):
            for xb in range(40):
                b = plane[y * 40 + xb]
                if not b:
                    continue
                for k in range(8):
                    if b & (0x80 >> k):
                        img[y * PAV_W + xb * 8 + k] |= bit
    return dict(head=d[:6], img=img)


def cmd_census(directory):
    print("%-5s %-6s %-4s %-6s %-4s %-6s  %s" % ("level", "BUM", "plat", "DEC", "plat", "PAV", "note"))
    total = 0
    rc = 0
    for n in range(1, 10):
        row = ["D%d" % n]
        note = []
        try:
            b = bum(open(os.path.join(directory, "D%d.BUM" % n), "rb").read())
            e = dec(open(os.path.join(directory, "D%d.DEC" % n), "rb").read())
            v = pav(open(os.path.join(directory, "D%d.PAV" % n), "rb").read())
        except (Refused, OSError) as err:
            print("D%d  REFUSED %s" % (n, err))
            rc = 1
            continue
        nb, ne = len(b["platforms"]), len(e["platforms"])
        if nb != ne:
            note.append("BUM %d platforms but DEC %d" % (nb, ne))
        total += nb
        used = sorted(set(x for r in b["platforms"] for x in r["a"]))
        print("%-5s %02X%02X   %-4d %02X%02X   %-4d %s  A values %s%s" % (
            row[0], b["head"][0], b["head"][1], nb, e["head"][0], e["head"][1], ne,
            v["head"].hex(), "0..%d" % used[-1], "  " + "; ".join(note) if note else ""))
    print("platforms in nine levels: %d" % total)
    return rc


def cmd_grids(path):
    d = open(path, "rb").read()
    try:
        b = bum(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    print("%s  head %s  %d platforms" % (os.path.basename(path), b["head"].hex(" "), len(b["platforms"])))
    for k, r in enumerate(b["platforms"]):
        print("\nplatform %d   P = %s   tail non-zero %d of 44" % (
            k, " ".join("%02X" % x for x in r["p"]), sum(1 for x in r["tail"] if x)))
        for name in "abc":
            g = r[name]
            print("  %s: " % name.upper() + "  |  ".join(
                " ".join(("%2X" % g[y * COLS + x]) if g[y * COLS + x] else " ." for x in range(COLS))
                for y in range(0, 1)) )
            for y in range(1, ROWS):
                print("     " + " ".join(("%2X" % g[y * COLS + x]) if g[y * COLS + x] else " ." for x in range(COLS)))
    return 0


def cmd_render(path, out, palpath):
    import vecscreen
    d = open(path, "rb").read()
    try:
        v = pav(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    pal = vecscreen.screen(open(palpath, "rb").read())["pal"]
    bfflic.write_png(out, v["img"], pal, PAV_W, PAV_H)
    print("%s -> %s  (palette of %s; %d colours used)" % (
        os.path.basename(path), out, os.path.basename(palpath), len(set(v["img"]))))
    return 0


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-60s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    rec = bytes([1] * 48) + bytes([2] * 48) + bytes([3] * 48) + bytes(range(6)) + bytes(44)
    b = bum(b"\x10\x0E" + rec * 15)
    check("2 + 15 x 194 = 2,912 reads as 15 platforms", len(b["platforms"]) == 15)
    check("tables A, B, C and P are cut where the program cuts them",
          b["platforms"][0]["a"] == bytes([1] * 48) and b["platforms"][0]["c"][0] == 3
          and b["platforms"][0]["p"] == bytes(range(6)))
    b2 = bum(b"\x10\x0F" + rec * 12)
    check("2 + 12 x 194 = 2,330 reads as 12 platforms", len(b2["platforms"]) == 12)
    e = dec(b"\x00\x0E" + (b"\x00\x00" + bytes(i % 256 for i in range(810))) * 15)
    check("2 + 15 x 812 = 12,182 reads as 15 platforms of 270 triplets",
          len(e["platforms"]) == 15 and len(e["platforms"][0]["triplets"]) == 270)
    planes = [bytearray(PAV_PLANE) for _ in range(4)]
    planes[0][0] = 0x80
    planes[3][0] = 0x80
    planes[1][40 * 191 + 39] = 0x01
    v = pav(b"\xF0\xFF\x00\x5F\x18\x00" + b"".join(bytes(p) for p in planes))
    check("PAV pixel (0,0) from planes 0 and 3 is 9, (319,191) from plane 1 is 2",
          v["img"][0] == 9 and v["img"][191 * PAV_W + 319] == 2)
    for label, fn, blob, needle in (
            ("a BUM of the wrong length", bum, bytes(2913), "not 2 + n"),
            ("a DEC of the wrong length", dec, bytes(813), "not 2 + n"),
            ("a PAV of the wrong length", pav, bytes(30725), "not 6 + 4")):
        try:
            fn(blob)
            check("refuses " + label, False, "accepted")
        except Refused as err:
            check("refuses " + label, needle in str(err), str(err))
    print("\nbumlevel.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("census", "grids", "render", "selftest"))
    ap.add_argument("args", nargs="*")
    ap.add_argument("--pal", default=None)
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    if a.cmd == "census":
        dirguard.want_tree(a.args[0], "bumlevel.py")
        return cmd_census(a.args[0])
    dirguard.want_file(a.args[0], "bumlevel.py")
    if a.cmd == "grids":
        return cmd_grids(a.args[0])
    if len(a.args) != 2 or not a.pal:
        ap.error("render Dn.PAV OUT.png --pal SCREEN.VEC")
    dirguard.want_file(a.pal, "bumlevel.py")
    return cmd_render(a.args[0], a.args[1], a.pal)


if __name__ == "__main__":
    sys.exit(main())
