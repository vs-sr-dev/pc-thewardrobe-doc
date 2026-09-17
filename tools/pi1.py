#!/usr/bin/env python3
"""pi1.py - reader for the `.PI1` members of the Delphine volumes.

`.PI1` is Atari ST Degas Elite's extension. **These are not Degas Elite files.**
A Degas `.PI1` is a fixed 32,034 bytes; nothing here is that size. The extension
is a fossil, in the same way `.FR` is a fossil of the French original: the name
survived a port that replaced the contents.

The format derives from the bytes and closes exactly, in two variants
distinguished by a `u16 BE` mode word at offset 0:

    mode 8   2 + 768 + 64,000 = 64,770
             768-byte palette, 256 entries of R,G,B, each an 8-bit value of the
             form (n << 2) | 3 - a 6-bit VGA DAC value widened to a byte
             64,000 bytes of chunky 8-bit pixels, 320 x 200

    mode 5   2 + 64 + 40,000 = 40,066
             64-byte palette, 32 entries of u16 BE 0x0RGB - 4 bits per gun,
             the Amiga/STE encoding, not VGA's
             40,000 bytes of 5 bitplanes, 320 x 200, bit-planar

    "PAL\\0"  4 + 768 = 772
             a palette with no image attached

So one game ships one extension over two colour depths, two palette encodings
and two pixel layouts, and the planar one is the machine this game came from.

Three plane layouts are offered because the file cannot say which it is. The
argument that settles it is a person looking at the picture: `word` (Atari ST's
own interleave, one 16-bit word per plane per group) and `line` (planes one
after another inside each scan line) both produce banded rubbish; `image` -
five contiguous 8,000-byte planes for the whole screen - produces rooms. So the
planar variant here keeps the ST's *colour* encoding and not the ST's *pixel*
encoding, which is a thing the arithmetic could not have told anyone.

Usage:
    pi1.py validate <dir>                    sizes and modes, closes or not
    pi1.py render   <dir> <outdir> [--interleave image|word|line]
    pi1.py selftest <dir>                    negative controls that must fail
"""
import sys
import os
import struct
import argparse
import glob

WIDTH = 320
HEIGHT = 200

MODE8 = 64770
MODE5 = 40066
PALONLY = 772


class Pi1Error(Exception):
    pass


def parse(data, interleave="image"):
    """Return (width, height, palette as 256 RGB triples, index bytes)."""
    if len(data) >= 4 and data[:4] == b"PAL\x00":
        if len(data) != PALONLY:
            raise Pi1Error("a PAL block is %d bytes, this is %d"
                           % (PALONLY, len(data)))
        pal = vga_palette(data[4:772])
        return 0, 0, pal, b""
    if len(data) < 2:
        raise Pi1Error("%d bytes, too short for a mode word" % len(data))
    mode = struct.unpack(">H", data[:2])[0]
    if mode == 8:
        if len(data) != MODE8:
            raise Pi1Error("mode 8 must be %d bytes, this is %d"
                           % (MODE8, len(data)))
        pal = vga_palette(data[2:770])
        return WIDTH, HEIGHT, pal, data[770:]
    if mode == 5:
        if len(data) != MODE5:
            raise Pi1Error("mode 5 must be %d bytes, this is %d"
                           % (MODE5, len(data)))
        pal = st_palette(data[2:66])
        return WIDTH, HEIGHT, pal, planar_to_chunky(data[66:], 5, interleave)
    raise Pi1Error("mode word %d is neither 5 nor 8" % mode)


def vga_palette(raw):
    if len(raw) != 768:
        raise Pi1Error("a 256-colour palette is 768 bytes, this is %d"
                       % len(raw))
    return [tuple(raw[i * 3:i * 3 + 3]) for i in range(256)]


def st_palette(raw):
    if len(raw) != 64:
        raise Pi1Error("a 32-colour palette is 64 bytes, this is %d" % len(raw))
    pal = []
    for i in range(32):
        v = struct.unpack(">H", raw[i * 2:i * 2 + 2])[0]
        r = (v >> 8) & 0xF
        g = (v >> 4) & 0xF
        b = v & 0xF
        pal.append((r * 17, g * 17, b * 17))
    return pal + [(0, 0, 0)] * 224


def planar_to_chunky(raw, planes, interleave):
    need = WIDTH * HEIGHT * planes // 8
    if len(raw) != need:
        raise Pi1Error("%d bitplanes of %dx%d need %d bytes, this is %d"
                       % (planes, WIDTH, HEIGHT, need, len(raw)))
    out = bytearray(WIDTH * HEIGHT)
    line_bytes = WIDTH * planes // 8
    plane_line = WIDTH // 8
    plane_size = WIDTH * HEIGHT // 8
    for y in range(HEIGHT):
        row = y * WIDTH
        for xb in range(plane_line):
            if interleave == "image":
                # each bitplane is one contiguous block for the whole screen
                bits = [raw[p * plane_size + y * plane_line + xb]
                        for p in range(planes)]
            elif interleave == "word":
                # Atari ST: groups of `planes` 16-bit words, one word per plane
                grp = (xb // 2) * planes * 2 + (xb & 1)
                bits = [raw[y * line_bytes + grp + p * 2]
                        for p in range(planes)]
            else:
                # planes one after another inside each scan line
                bits = [raw[y * line_bytes + p * plane_line + xb]
                        for p in range(planes)]
            for b in range(8):
                px = 0
                for p in range(planes):
                    px |= ((bits[p] >> (7 - b)) & 1) << p
                out[row + xb * 8 + b] = px
    return bytes(out)


def cmd_validate(args):
    files = sorted(glob.glob(os.path.join(args.paths[0], "**", "*.PI1"),
                             recursive=True))
    kinds = {}
    bad = []
    for f in files:
        data = open(f, "rb").read()
        try:
            w, h, pal, px = parse(data)
        except Pi1Error as e:
            bad.append((f, len(data), str(e)))
            continue
        mode = ("PAL" if data[:4] == b"PAL\x00"
                else struct.unpack(">H", data[:2])[0])
        k = (len(data), mode)
        kinds[k] = kinds.get(k, 0) + 1
    print("%-10s %-6s %8s   %s" % ("bytes", "mode", "files", "arithmetic"))
    arith = {MODE8: "2 + 768 + 64,000", MODE5: "2 + 64 + 40,000",
             PALONLY: "4 + 768"}
    for (n, mode), c in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print("%-10d %-6s %8d   %s" % (n, mode, c, arith.get(n, "?")))
    print()
    print("parsed %d of %d" % (len(files) - len(bad), len(files)))
    for f, n, e in bad:
        print("FAIL %s (%d): %s" % (f, n, e))
    return 1 if bad else 0


def cmd_render(args):
    from PIL import Image
    in_dir, out_dir = args.paths[0], args.paths[1]
    os.makedirs(out_dir, exist_ok=True)
    files = sorted(glob.glob(os.path.join(in_dir, "**", "*.PI1"),
                             recursive=True))
    n = 0
    seen = set()
    for f in files:
        data = open(f, "rb").read()
        base = os.path.basename(f)[:-4]
        if data in seen:
            continue
        seen.add(data)
        try:
            w, h, pal, px = parse(data, args.interleave)
        except Pi1Error as e:
            print("skip %s: %s" % (base, e))
            continue
        if w == 0:
            im = Image.new("RGB", (256, 16))
            for i, c in enumerate(pal):
                for x in range(16):
                    for y in range(16):
                        im.putpixel(((i % 16) * 16 + x, 0), c)
            im = Image.new("RGB", (16 * 16, 16 * 16))
            for i, c in enumerate(pal):
                for x in range(16):
                    for y in range(16):
                        im.putpixel(((i % 16) * 16 + x, (i // 16) * 16 + y), c)
        else:
            im = Image.frombytes("P", (w, h), px)
            flat = []
            for c in pal:
                flat.extend(c)
            im.putpalette(flat)
            im = im.convert("RGB")
        im.save(os.path.join(out_dir, base + ".png"))
        n += 1
    print("rendered %d distinct images into %s" % (n, out_dir))
    return 0


def cmd_selftest(args):
    fired = total = 0

    def expect_fail(label, blob):
        nonlocal fired, total
        total += 1
        try:
            parse(blob)
            print("%-40s ACCEPTED <<< BUG" % label)
        except Pi1Error as e:
            fired += 1
            print("%-40s REFUSED (%s)" % (label, e))

    good = None
    for f in sorted(glob.glob(os.path.join(args.paths[0], "**", "*.PI1"),
                              recursive=True)):
        d = open(f, "rb").read()
        if len(d) == MODE8:
            good = d
            break
    if good is None:
        print("selftest found no mode 8 image", file=sys.stderr)
        return 1
    expect_fail("mode 8 image one byte short", good[:-1])
    expect_fail("mode 8 image one byte long", good + b"\x00")
    expect_fail("mode word changed to 4", b"\x00\x04" + good[2:])
    expect_fail("a mode 5 body under a mode 8 word",
                b"\x00\x08" + bytes(MODE5 - 2))
    expect_fail("a .SET member fed to the reader", b"SET" + bytes(5000))
    expect_fail("a truncated PAL block", b"PAL\x00" + bytes(100))
    print()
    print("negative controls that fired: %d of %d" % (fired, total))
    return 0 if fired == total else 1


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("validate", "render", "selftest"))
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--interleave", choices=("image", "word", "line"),
                    default="image")
    args = ap.parse_args()
    return {"validate": cmd_validate, "render": cmd_render,
            "selftest": cmd_selftest}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
