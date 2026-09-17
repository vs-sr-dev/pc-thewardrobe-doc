#!/usr/bin/env python3
"""vecscreen.py -- render the 32,099-byte screens of BUMPY (Loriciel, 1992):
the fourteen .VEC files (thirteen behind the 12-byte head that bumpack.py
unpacks, and SCORE.VEC in the clear).

THE SCREEN, AS THE PROGRAM READS IT
-----------------------------------
    +0    35 bytes   zero in all fourteen files
    +35   16 bytes   EGA palette registers -- zero in all fourteen; the
                     program fills them itself (a fixed 16-entry map at
                     DS:071Eh for the EGA, another at DS:063Ah for the
                     presentation screen; identity 0-7,16-23 is what the
                     VGA path's DAC loading implies)
    +51   48 bytes   16 x (r, g, b), 6 bits each: the VGA DAC. The library
                     routine at 0AB9h:0677h loads triplets 0-7 into DAC
                     0-7 and 8-15 into DAC 16-23 (the EGA-compatible slots)
    +99   32,000     four planes of 8,000 bytes, plane 0 first: 200 rows of
                     40 bytes, 8 pixels per byte, MSB = leftmost pixel --
                     the layout of BIOS mode 0Dh (320 x 200 x 16), which the
                     library sets (0AB9h:020Eh, `mov ax,0Dh; int 10h`) and
                     into which it copies with map-mask writes on port 3C4h

The program blits a screen with a descriptor whose source is `buffer + 99`
and whose size is 20 x 25 cells of 16 x 8 pixels (cs:304F..30A9), so the
pixels begin at +99 and cover the whole 320 x 200. Which of the two planar
orders (four sequential planes, or the four planes interleaved per row)
the file uses was decided by the first render: sequential planes paint the
title; interleaved planes paint noise. The owner confirmed the title screen
and the presentation screen on 2026-09-12.

    python tools/vecscreen.py census FILE...            heads and palettes
    python tools/vecscreen.py render FILE... --out DIR  one PNG per screen
    python tools/vecscreen.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfflic     # noqa: E402
import bumpack    # noqa: E402
import dirguard   # noqa: E402
import nameguard  # noqa: E402

SCREEN = 32099
HEAD = 99
PLANE = 8000
W, H = 320, 200
IDENTITY = bytes(list(range(8)) + list(range(16, 24)))


class Refused(Exception):
    pass


def unpacked(d):
    """The 32,099 bytes: unpacked through bumpack if headed, else as read."""
    if bumpack.looks_like_head(d):
        out, log = bumpack.stages(d)
        how = " > ".join(bumpack.METHODS[h["method"]] for h in log)
    else:
        out, how = d, "no head (in the clear)"
    if len(out) != SCREEN:
        raise Refused("%d bytes, not a %d-byte screen" % (len(out), SCREEN))
    return out, how


def palette(head):
    """16 RGB triplets (8-bit) through the registers, which are the file's
    if any is non-zero and the identity map 0-7,16-23 otherwise."""
    regs = head[35:51]
    if not any(regs):
        regs = IDENTITY
    dac = [tuple(v * 255 // 63 for v in head[51 + 3 * i:54 + 3 * i]) for i in range(16)]
    if any(v > 63 for v in head[51:99]):
        raise Refused("a DAC byte exceeds 63: not a 6-bit palette")
    pal = []
    for r in regs:
        if r < 8:
            pal.append(dac[r])
        elif 16 <= r < 24:
            pal.append(dac[8 + r - 16])
        else:
            raise Refused("palette register %d points outside DAC 0-7/16-23" % r)
    return pal


def pixels(body):
    """Four sequential planes -> one 4-bit index per pixel, row-major."""
    img = bytearray(W * H)
    for p in range(4):
        plane = body[p * PLANE:(p + 1) * PLANE]
        bit = 1 << p
        for y in range(H):
            row = plane[y * 40:(y + 1) * 40]
            base = y * W
            for xb in range(40):
                b = row[xb]
                if not b:
                    continue
                for k in range(8):
                    if b & (0x80 >> k):
                        img[base + xb * 8 + k] |= bit
    return img


def screen(d):
    out, how = unpacked(d)
    head, body = out[:HEAD], out[HEAD:]
    return dict(how=how, head=head, pal=palette(head), img=pixels(body),
                zero35=not any(head[:35]), regs0=not any(head[35:51]))


def cmd_census(paths):
    print("%-14s %7s  %-22s %-6s %-6s  %s" % ("file", "packed", "stages", "35=0",
                                            "regs=0", "colours used / DAC"))
    for p in paths:
        d = open(p, "rb").read()
        try:
            s = screen(d)
        except (Refused, bumpack.Refused) as e:
            print("%-14s %7d  REFUSED %s" % (os.path.basename(p), len(d), e))
            continue
        used = sorted(set(s["img"]))
        print("%-14s %7d  %-22s %-6s %-6s  %d used: %s" % (
            os.path.basename(p), len(d), s["how"], s["zero35"], s["regs0"],
            len(used), " ".join("%d" % u for u in used)))
        print("%-14s %7s  DAC %s" % ("", "", " ".join(
            "%02X%02X%02X" % c for c in s["pal"])))
    return 0


def cmd_render(paths, outdir):
    os.makedirs(outdir, exist_ok=True)
    rc = 0
    for p in paths:
        d = open(p, "rb").read()
        try:
            s = screen(d)
        except (Refused, bumpack.Refused) as e:
            print("REFUSED  %s: %s" % (os.path.basename(p), e))
            rc = 1
            continue
        name = os.path.splitext(os.path.basename(p))[0] + ".png"
        bfflic.write_png(os.path.join(outdir, name), s["img"], s["pal"], W, H)
        print("%-14s -> %s  (%s)" % (os.path.basename(p), name, s["how"]))
    return rc


def _specimen():
    """A screen: head of 51 zeros + a 16-entry 6-bit palette, then four
    planes with pixel (x, y) = (x // 20 + y // 50 * 4) & 15 -- every colour."""
    pal = b"".join(bytes([(i * 4) & 63, (63 - i * 4) & 63, i & 63]) for i in range(16))
    head = bytes(51) + pal
    planes = [bytearray(PLANE) for _ in range(4)]
    for y in range(H):
        for x in range(W):
            c = (x // 20 + (y // 50) * 4) & 15
            for p in range(4):
                if c & (1 << p):
                    planes[p][y * 40 + x // 8] |= 0x80 >> (x % 8)
    return head + b"".join(bytes(pl) for pl in planes)


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-60s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    spec = _specimen()
    check("specimen is 32,099 bytes", len(spec) == SCREEN)
    s = screen(spec)
    check("a screen in the clear is read without bumpack", s["how"].startswith("no head"))
    check("pixel (0,0) is colour 0 and (319,199) is (15 + 12) & 15 = 11",
          s["img"][0] == 0 and s["img"][199 * W + 319] == 11)
    check("pixel (25, 60) is 1 + 4 = 5", s["img"][60 * W + 25] == 5)
    check("all 16 colours are used", len(set(s["img"])) == 16)
    check("zero registers fall back to the identity map 0-7,16-23",
          s["regs0"] and s["pal"][15] == (60 * 255 // 63, 3 * 255 // 63, 15 * 255 // 63))
    # through bumpack: RLE the specimen with escape 0xFF (no 0xFF in it? make sure)
    body = spec.replace(b"\xFF", b"\xFE")
    stream = b"\xFF"
    i = 0
    while i < len(body):
        j = i
        while j < len(body) and body[j] == body[i] and j - i < 255:
            j += 1
        n = j - i
        if n >= 4:
            stream += bytes([0xFF, body[i], n])
        else:
            stream += body[i:j]
        i = j
    packed = bumpack._head(len(body), 0, 4) + stream
    s2 = screen(packed)
    check("the same screen behind an RLE head unpacks to the same pixels",
          s2["how"] == "rle" and s2["img"] == pixels(body[HEAD:]))
    # registers that point somewhere
    h2 = bytearray(spec)
    h2[35:51] = bytes(list(range(16, 24)) + list(range(8)))
    s3 = screen(bytes(h2))
    check("non-zero registers are honoured (reg 0 -> DAC 16 -> triplet 8)",
          s3["pal"][0] == s["pal"][8])
    h2[35] = 9
    try:
        screen(bytes(h2))
        check("refuses a register outside DAC 0-7/16-23", False)
    except Refused as e:
        check("refuses a register outside DAC 0-7/16-23", "outside" in str(e))
    try:
        screen(spec[:-1])
        check("refuses 32,098 bytes", False)
    except Refused as e:
        check("refuses 32,098 bytes", "not a" in str(e))
    h3 = bytearray(spec)
    h3[52] = 64
    try:
        screen(bytes(h3))
        check("refuses a DAC byte of 64", False)
    except Refused as e:
        check("refuses a DAC byte of 64", "6-bit" in str(e))
    print("\nvecscreen.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("census", "render", "selftest"))
    ap.add_argument("args", nargs="*")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    for p in a.args:
        dirguard.want_file(p, "vecscreen.py")
    if a.cmd == "census":
        return cmd_census(a.args)
    if not a.out:
        ap.error("render FILE... --out DIR")
    return cmd_render(a.args, a.out)


if __name__ == "__main__":
    sys.exit(main())
