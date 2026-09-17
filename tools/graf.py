#!/usr/bin/env python3
"""graf.py -- read the game's own picture files of Polanie: the 6-byte-head
raw 8-bit image (FONT.DAT, SETUP1.DAT, SETUP2.DAT, and the thirty slots of
GRAF.DAT), and render them with the 8-bit palettes of PAL.DAT / SETUP.PAL.

THE FORMAT, AS THE BYTES SAY IT (nothing in the engine was needed to read it)
------------------------------------------------------------------------------
    +0   u16   L        6 + (w+1) * (h+1) -- the image's own length
    +2   u16   w        319: the ROW STRIDE of the pixels that follow
    +4   u16   h        100 or 99: the rows are h+1
    +6   w*(h+1)        8-bit indices, row-major, top row first, stride w
    ...  h+1 bytes      slack: the buffer was allocated (w+1)*(h+1) and the
                        rows written at w; what is left is stale memory

THE STRIDE IS 319, NOT 320, AND THE FIRST RENDER SAID SO. The first draft of
this tool read `w+1` as the width and rendered at 320: the owner saw every
picture "shifted diagonally", and a row-to-row difference over strides
318..321 (`_work/`, 34 images) picks 319 on 32 of 34 (the other two tie 318
with 319; none picks 320). At 319 the idol in the menu background stands
straight and the sprite sheets align. The head's `w` is therefore the stride
and `L` counts one column and one row more than are used; the tool measures
the slack instead of pretending it is picture.

`FONT.DAT` and `SETUP1.DAT` are ONE 319 x 101 image and close exactly on
their length (32,326 bytes); `SETUP2.DAT` one 319 x 100 (32,006). `GRAF.DAT`
(990,000 bytes) is THIRTY SLOTS of 33,000 bytes, each holding one such image
at its start and stale bytes after it: slots 0..14 are 319 x 101, slots
15..29 are 319 x 100, and slot k and slot k+15 are the top and bottom halves
of one 319 x 201 screen -- fifteen screens, some of them pictures (the menu
background), most of them sprite sheets. The palettes are `PAL.DAT`, 14 x 768
bytes, and `SETUP.PAL`, 1 x 768, all of them 8-bit RGB (in palette 0, 471 of
the 768 bytes exceed 63; a 6-bit VGA palette has none), so the `v<<2|v>>4`
scale of `res.py` is NOT applied here. Which palette goes with which screen
is not written in the files; `render` takes the index on the command line
and the reader decides by looking.

    python tools/graf.py census  FILE...                 heads and closure
    python tools/graf.py render  FILE OUTDIR --pal P [--index N]
                                                         PNGs, one per image
                                                         (GRAF.DAT: per screen)
    python tools/graf.py sheet   GRAF.DAT PAL.DAT OUT.png  every screen under
                                                         every palette, scaled
    python tools/graf.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfflic     # noqa: E402  write_png
import dirguard   # noqa: E402
import nameguard  # noqa: E402

SLOT = 33000
HEAD = 6


class Refused(Exception):
    pass


def head(d, off):
    """The 6-byte head at `off`, checked against its own arithmetic."""
    if off + HEAD > len(d):
        raise Refused("no room for a head at %d" % off)
    L, w, h1 = struct.unpack_from("<3H", d, off)
    h = h1 + 1
    if L != HEAD + (w + 1) * h:
        raise Refused("head at %d says L=%d, but 6 + (%d+1) x (%d+1) = %d"
                      % (off, L, w, h1, HEAD + (w + 1) * h))
    if off + L > len(d):
        raise Refused("image at %d of %d bytes runs past the end (%d)"
                      % (off, L, len(d)))
    body = d[off + HEAD:off + L]
    return dict(off=off, L=L, w=w, h=h, pixels=body[:w * h], slack=body[w * h:])


def looks_like_head(b, size):
    """For coverage.py: a 6-byte head whose L closes on the file, or a file
    that is a whole number of 33,000-byte slots whose first slot opens with
    such a head. Widths of 8..1024 and rows of 1..1024 only, so a run of
    small integers does not pass."""
    if size is None or len(b) < HEAD:
        return False
    L, w, h1 = struct.unpack_from("<3H", b, 0)
    if not (8 <= w <= 1024 and 0 <= h1 < 1024):
        return False
    if L != HEAD + (w + 1) * (h1 + 1):
        return False
    if size == L:
        return True
    return size % SLOT == 0 and L <= SLOT and size >= SLOT


def images(d):
    """Every image in the file. A file that is exactly one image is one;
    a file that is a whole number of 33,000-byte slots is one per slot
    (with the padding checked to be zero); anything else is refused."""
    first = head(d, 0)
    if first["L"] == len(d):
        return [first], "one image, closes on the file length"
    if len(d) % SLOT:
        raise Refused("%d bytes is neither one image (%d) nor a whole number "
                      "of %d-byte slots" % (len(d), first["L"], SLOT))
    out = []
    padbytes = stale = 0
    for k in range(len(d) // SLOT):
        im = head(d, k * SLOT)
        if im["L"] > SLOT:
            raise Refused("slot %d holds %d bytes, more than a slot" % (k, im["L"]))
        pad = d[k * SLOT + im["L"]:(k + 1) * SLOT]
        # The tail of a slot is NOT zero in GRAF.DAT: it carries stale bytes
        # (pixel-like, repeated between slots 15 and 29), the leftovers of
        # whatever buffer the writer had. It is measured, not refused.
        padbytes += len(pad)
        stale += sum(1 for b in pad if b)
        out.append(im)
    return out, "%d slots of %d bytes, %d tail bytes of which %d non-zero" % (
        len(out), SLOT, padbytes, stale)


def palettes(d):
    if len(d) % 768:
        raise Refused("%d bytes is not a whole number of 768-byte palettes"
                      % len(d))
    pals = []
    for k in range(len(d) // 768):
        p = d[k * 768:(k + 1) * 768]
        pals.append([tuple(p[i:i + 3]) for i in range(0, 768, 3)])
    return pals


def screens(ims):
    """GRAF.DAT's pairing: slot k on top of slot k+15."""
    n = len(ims) // 2
    out = []
    for k in range(n):
        top, bot = ims[k], ims[k + n]
        if top["w"] != bot["w"]:
            raise Refused("slots %d and %d differ in width" % (k, k + n))
        out.append(dict(w=top["w"], h=top["h"] + bot["h"],
                        pixels=top["pixels"] + bot["pixels"],
                        slots=(k, k + n)))
    return out


def cmd_census(paths):
    for p in paths:
        d = open(p, "rb").read()
        try:
            ims, note = images(d)
        except Refused as e:
            print("%-12s REFUSED: %s" % (os.path.basename(p), e))
            continue
        sizes = {}
        for im in ims:
            key = "%dx%d" % (im["w"], im["h"])
            sizes[key] = sizes.get(key, 0) + 1
        used = sorted(set(b for im in ims for b in set(im["pixels"])))
        slack = sum(len(im["slack"]) for im in ims)
        slack_nz = sum(1 for im in ims for b in im["slack"] if b)
        print("%-12s %8d bytes  %2d image(s)  %s  sizes %s  indices used %d "
              "(min %d max %d)  slack %d bytes, %d non-zero"
              % (os.path.basename(p), len(d), len(ims), note,
                 " ".join("%s:%d" % kv for kv in sorted(sizes.items())),
                 len(used), used[0], used[-1], slack, slack_nz))
    return 0


def cmd_render(path, outdir, palpath, index):
    d = open(path, "rb").read()
    ims, note = images(d)
    pals = palettes(open(palpath, "rb").read())
    if not (0 <= index < len(pals)):
        raise SystemExit("graf.py: palette %d of %d" % (index, len(pals)))
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(path))[0].lower()
    if len(ims) == 1:
        im = ims[0]
        out = os.path.join(outdir, "%s_pal%02d.png" % (base, index))
        bfflic.write_png(out, im["pixels"], pals[index], im["w"], im["h"])
        print("%s: %dx%d with palette %d -> %s" % (
            os.path.basename(path), im["w"], im["h"], index, out))
        return 0
    for k, sc in enumerate(screens(ims)):
        out = os.path.join(outdir, "%s_screen%02d_pal%02d.png" % (base, k, index))
        bfflic.write_png(out, sc["pixels"], pals[index], sc["w"], sc["h"])
        print("screen %2d (slots %d+%d) %dx%d palette %d -> %s"
              % (k, sc["slots"][0], sc["slots"][1], sc["w"], sc["h"], index, out))
    return 0


def cmd_sheet(path, palpath, out, scale=4, index=None):
    """Every screen under every palette, each cell 1/scale: the picture
    that decides the pairing. With `index`, the fifteen screens under that
    one palette, five per row."""
    d = open(path, "rb").read()
    ims, note = images(d)
    scs = screens(ims)
    pals = palettes(open(palpath, "rb").read())
    cw, ch = scs[0]["w"] // scale, scs[0]["h"] // scale
    if index is None:
        cols = [(sc, pal) for sc in scs for pal in pals]
        ncol = len(pals)
    else:
        cols = [(sc, pals[index]) for sc in scs]
        ncol = 5
    nrow = (len(cols) + ncol - 1) // ncol
    W, H = cw * ncol, ch * nrow
    rows = []
    for r in range(nrow):
        cells = cols[r * ncol:(r + 1) * ncol]
        for yy in range(ch):
            row = []
            for sc, pal in cells:
                for xx in range(cw):
                    row.append(pal[sc["pixels"][(yy * scale) * sc["w"] + xx * scale]])
            row += [(0, 0, 0)] * (W - len(row))
            rows.append(row)
    import zlib
    raw = b"".join(b"\0" + bytes(c for px in row for c in px) for row in rows)

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
    open(out, "wb").write(png)
    print("%d screens x %s, cells %dx%d -> %s (%dx%d)"
          % (len(scs), "%d palettes" % len(pals) if index is None
             else "palette %d" % index, cw, ch, out, W, H))
    return 0


def fit_score(pixels, w, pal, step=3):
    """Mean RGB distance between horizontal neighbours: low when the palette
    makes the picture smooth, high when it makes noise. Not a proof -- a
    ranking, for the eye to confirm."""
    tot = 0
    n = 0
    for i in range(0, len(pixels) - 1, step):
        if (i + 1) % w == 0:
            continue
        a, b = pal[pixels[i]], pal[pixels[i + 1]]
        tot += abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
        n += 1
    return tot / n if n else 0.0


def cmd_fit(path, palpath):
    d = open(path, "rb").read()
    ims, note = images(d)
    scs = screens(ims) if len(ims) > 1 else [dict(w=ims[0]["w"],
                                                  pixels=ims[0]["pixels"],
                                                  slots=(0,))]
    pals = palettes(open(palpath, "rb").read())
    print("%-8s %s   best" % ("screen", " ".join("%5d" % k for k in range(len(pals)))))
    for si, sc in enumerate(scs):
        scores = [fit_score(sc["pixels"], sc["w"], pal) for pal in pals]
        best = min(range(len(pals)), key=lambda k: scores[k])
        ranked = sorted(range(len(pals)), key=lambda k: scores[k])
        print("%-8d %s   %d (then %s)"
              % (si, " ".join("%5.1f" % s for s in scores), best,
                 " ".join(str(k) for k in ranked[1:4])))
    return 0


def _image(w, h, fill, slack=0xEE):
    """A specimen as the writer made them: head (L, w, h-1), h rows at
    stride w, then h bytes of slack."""
    return (struct.pack("<3H", HEAD + (w + 1) * h, w, h - 1)
            + bytes([fill]) * (w * h) + bytes([slack]) * h)


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-56s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    one = _image(319, 101, 7)
    check("specimen is 32,326 bytes like FONT.DAT", len(one) == 32326)
    ims, note = images(one)
    check("one 319x101 image closes on its length, 101 slack bytes",
          len(ims) == 1 and ims[0]["w"] == 319 and ims[0]["h"] == 101
          and len(ims[0]["pixels"]) == 319 * 101 and len(ims[0]["slack"]) == 101
          and set(ims[0]["pixels"]) == {7} and note.startswith("one image"))
    slots = b"".join((_image(319, 101, k) + bytes(SLOT - 32326)) for k in range(2)) \
        + b"".join((_image(319, 100, 10 + k) + bytes(SLOT - 32006)) for k in range(2))
    ims, note = images(slots)
    check("four slots read as four images", len(ims) == 4 and "4 slots" in note)
    ims, note = images(slots[:SLOT - 1] + b"\1" + slots[SLOT:])
    check("a stale tail byte is counted, not refused", "1 non-zero" in note)
    scs = screens(ims)
    check("two screens of 319x201 from slots k and k+2",
          len(scs) == 2 and scs[0]["h"] == 201 and scs[0]["slots"] == (0, 2)
          and scs[1]["pixels"][0] == 1 and scs[1]["pixels"][-1] == 11
          and len(scs[1]["pixels"]) == 319 * 201)
    for label, bad, needle in (
            ("a head whose L is off by one",
             struct.pack("<3H", 7 + 6, 1, 1) + bytes(6), "(1+1) x (1+1)"),
            ("an image running past the end", one[:-1], "one image" if False
             else "runs past"),
            ("a file that is neither one image nor slots", one + b"\0" * 5,
             "neither")):
        try:
            images(bad)
            check("refuses " + label, False, "accepted")
        except Refused as e:
            check("refuses " + label, needle in str(e), str(e))
    pals = palettes(bytes(range(256)) * 3 + bytes(768))
    check("two palettes from 1,536 bytes, taken at 8 bits unscaled",
          len(pals) == 2 and pals[0][255] == (253, 254, 255) and pals[0][1] == (3, 4, 5))
    try:
        palettes(bytes(700))
        check("refuses a palette file of 700 bytes", False)
    except Refused:
        check("refuses a palette file of 700 bytes", True)
    print("\ngraf.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--pal")
    ap.add_argument("--index", type=int, default=None,
                    help="palette index (render: default 0; sheet: one "
                         "palette instead of all)")
    ap.add_argument("--scale", type=int, default=4)
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    dirguard.want_file(a.args[0], "graf.py")
    try:
        if a.cmd == "census":
            for p in a.args:
                dirguard.want_file(p, "graf.py")
            return cmd_census(a.args)
        if a.cmd == "render":
            if not a.pal or len(a.args) != 2:
                ap.error("render FILE OUTDIR --pal PALFILE [--index N]")
            dirguard.want_file(a.pal, "graf.py")
            return cmd_render(a.args[0], a.args[1], a.pal,
                              0 if a.index is None else a.index)
        if a.cmd == "fit":
            if len(a.args) != 2:
                ap.error("fit FILE PALFILE")
            dirguard.want_file(a.args[1], "graf.py")
            return cmd_fit(a.args[0], a.args[1])
        if a.cmd == "sheet":
            if len(a.args) != 3:
                ap.error("sheet GRAF.DAT PAL.DAT OUT.png")
            dirguard.want_file(a.args[1], "graf.py")
            return cmd_sheet(a.args[0], a.args[1], a.args[2], a.scale,
                             a.index)
    except Refused as e:
        print("graf.py: REFUSED: %s" % e)
        return 1
    ap.error("unknown command %r" % a.cmd)


if __name__ == "__main__":
    sys.exit(main())
