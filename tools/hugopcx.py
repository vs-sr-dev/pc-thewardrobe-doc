#!/usr/bin/env python3
"""hugopcx.py -- read the `.ART` and `.PIX` files of *Hugo's House of Horrors*.

They are **ZSoft PCX**, version 5, run-length encoded, one bit per pixel over
four planes -- a 16-colour EGA image in the format ZSoft published in 1985 --
and a `.PIX` file is **several PCX images concatenated with no index and no
count**, one per animation frame. Nothing in this object says how many; the
only way to know is to decode a frame and see where it ended.

That is the whole format, and this reader exists to prove it rather than to
assert it:

    validate   decode every frame of every file and report the residue.
               A file whose frames do not tile it exactly is a failure and is
               named. This is the check that must be run before any census.
    census     per-file frame counts, geometry and compression ratios.
    render     write PNGs, to a directory named on the command line and never
               to the directory the artefact is in.
    planes     read a .B / .O / .OB file as one 320x200 one-bit plane.

**Refusal is the point.** `validate` on anything that is not one of these
files must fail loudly, and `--selftest` runs it against a specimen built to
fail before any real file is quoted.

The PCX definition used here is public (ZSoft Technical Reference Manual) and
is used openly; what is *not* public is that these files hold more than one
image, that a `.PIX` frame's `Xmin`/`Ymin` are where the artist cut it from a
320x200 screen, and that `.B`/`.O`/`.OB` are one plane of that same geometry.
Those come from the bytes.

    python tools/hugopcx.py validate <dir>
    python tools/hugopcx.py census   <dir>
    python tools/hugopcx.py render   <dir> --out _work/render [--only GARDEN]
    python tools/hugopcx.py planes   <dir>
    python tools/hugopcx.py --selftest
"""
import argparse
import os
import struct
import sys

SIG = b"\x0a\x05\x01\x01"          # manufacturer 10, version 5, RLE, 1 bpp
HDR = 128
PLANE_BYTES = 8000                 # 320 * 200 / 8, one 1-bit plane
SCREEN_W, SCREEN_H = 320, 200


class Bad(Exception):
    """A file that is not what this reader reads. Raised, never swallowed."""


def parse_header(buf, off):
    if off + HDR > len(buf):
        raise Bad("offset %d: only %d bytes left, a header is %d"
                  % (off, len(buf) - off, HDR))
    h = buf[off:off + HDR]
    if h[:4] != SIG:
        raise Bad("offset %d: signature is %s, not %s"
                  % (off, h[:4].hex(" "), SIG.hex(" ")))
    xmin, ymin, xmax, ymax, hdpi, vdpi = struct.unpack("<6H", h[4:16])
    nplanes = h[65]
    bpl = struct.unpack("<H", h[66:68])[0]
    if xmax < xmin or ymax < ymin:
        raise Bad("offset %d: empty box (%d,%d)-(%d,%d)"
                  % (off, xmin, ymin, xmax, ymax))
    if nplanes == 0 or bpl == 0:
        raise Bad("offset %d: NPlanes %d BytesPerLine %d" % (off, nplanes, bpl))
    return {
        "off": off, "xmin": xmin, "ymin": ymin, "xmax": xmax, "ymax": ymax,
        "hdpi": hdpi, "vdpi": vdpi, "nplanes": nplanes, "bpl": bpl,
        "w": xmax - xmin + 1, "h": ymax - ymin + 1,
        "palette": h[16:64], "paletteinfo": struct.unpack("<H", h[68:70])[0],
        "hscreen": struct.unpack("<H", h[70:72])[0],
        "vscreen": struct.unpack("<H", h[72:74])[0],
    }


def unrle(buf, off, need):
    """PCX run-length decode of exactly `need` bytes. Over-run is fatal."""
    out = bytearray()
    i = off
    while len(out) < need:
        if i >= len(buf):
            raise Bad("run-length data ran out at %d with %d of %d bytes"
                      % (i, len(out), need))
        c = buf[i]
        i += 1
        if c & 0xC0 == 0xC0:
            n = c & 0x3F
            if i >= len(buf):
                raise Bad("run count %d at %d has no data byte" % (n, i - 1))
            out += bytes([buf[i]]) * n
            i += 1
        else:
            out.append(c)
    if len(out) != need:
        raise Bad("a run overshot: %d bytes decoded, %d wanted"
                  % (len(out), need))
    return bytes(out), i


def read_frames(buf, name="<buffer>"):
    """Every PCX image in `buf`, in order. The file must tile exactly."""
    if not buf:
        raise Bad("%s: empty, and an empty file is not zero frames -- it is "
                  "not a PCX" % name)
    frames = []
    off = 0
    while off < len(buf):
        h = parse_header(buf, off)
        need = h["nplanes"] * h["bpl"] * h["h"]
        raw, nxt = unrle(buf, off + HDR, need)
        h["raw"] = raw
        h["uncompressed"] = need
        h["stored"] = nxt - off
        frames.append(h)
        off = nxt
    if off != len(buf):
        raise Bad("%s: frames end at %d, file is %d" % (name, off, len(buf)))
    return frames


def to_indices(f):
    """Planar 1-bit-by-4 to one byte of colour index per pixel."""
    w, h, npl, bpl = f["w"], f["h"], f["nplanes"], f["bpl"]
    raw = f["raw"]
    px = bytearray(w * h)
    for y in range(h):
        base = y * npl * bpl
        for p in range(npl):
            row = base + p * bpl
            bit = 1 << p
            for x in range(w):
                if raw[row + (x >> 3)] & (0x80 >> (x & 7)):
                    px[y * w + x] |= bit
    return px


def palette_rgb(f):
    p = f["palette"]
    return [(p[i * 3], p[i * 3 + 1], p[i * 3 + 2]) for i in range(16)]


def art_and_pix(d):
    return sorted(f for f in os.listdir(d)
                  if f.upper().endswith((".ART", ".PIX")))


def planes_of(d):
    return sorted(f for f in os.listdir(d)
                  if os.path.splitext(f)[1].upper() in (".B", ".O", ".OB"))


def cmd_validate(args):
    files = art_and_pix(args.dir)
    if not files:
        print("hugopcx: no .ART or .PIX in %s -- nothing to validate"
              % args.dir, file=sys.stderr)
        return 2
    ok = bad = 0
    frames = 0
    stored = uncompressed = 0
    for name in files:
        path = os.path.join(args.dir, name)
        buf = open(path, "rb").read()
        try:
            fr = read_frames(buf, name)
        except Bad as e:
            print("  FAIL %-14s %s" % (name, e))
            bad += 1
            continue
        ok += 1
        frames += len(fr)
        stored += len(buf)
        uncompressed += sum(f["uncompressed"] for f in fr)
        print("  ok   %-14s %7d bytes  %2d frame(s)  residue 0"
              % (name, len(buf), len(fr)))
    print()
    print("files      : %d of %d tile exactly, %d failed" % (ok, len(files), bad))
    print("frames     : %d" % frames)
    print("stored     : %d bytes" % stored)
    print("decoded    : %d bytes" % uncompressed)
    if stored:
        print("ratio      : %.4f (decoded / stored)" % (uncompressed / stored))
    return 1 if bad else 0


def cmd_census(args):
    files = art_and_pix(args.dir)
    if not files:
        print("hugopcx: no .ART or .PIX in %s" % args.dir, file=sys.stderr)
        return 2
    print("%-14s %7s %3s %5s %5s %-11s %8s %8s"
          % ("file", "bytes", "fr", "w", "h", "first origin",
             "decoded", "ratio"))
    for name in files:
        buf = open(os.path.join(args.dir, name), "rb").read()
        fr = read_frames(buf, name)
        dec = sum(f["uncompressed"] for f in fr)
        w = {f["w"] for f in fr}
        h = {f["h"] for f in fr}
        print("%-14s %7d %3d %5s %5s (%3d,%3d)   %8d %8.4f"
              % (name, len(buf), len(fr),
                 str(sorted(w)[0]) if len(w) == 1 else "var",
                 str(sorted(h)[0]) if len(h) == 1 else "var",
                 fr[0]["xmin"], fr[0]["ymin"], dec, dec / len(buf)))
    return 0


def cmd_render(args):
    from PIL import Image
    out = args.out
    if os.path.abspath(out).startswith(os.path.abspath(args.dir) + os.sep) \
            or os.path.abspath(out) == os.path.abspath(args.dir):
        raise SystemExit("hugopcx: refusing to write inside the artefact "
                         "directory %s" % args.dir)
    os.makedirs(out, exist_ok=True)
    n = 0
    for name in art_and_pix(args.dir):
        if args.only and args.only.upper() not in name.upper():
            continue
        buf = open(os.path.join(args.dir, name), "rb").read()
        fr = read_frames(buf, name)
        for i, f in enumerate(fr):
            img = Image.frombytes("P", (f["w"], f["h"]),
                                  bytes(to_indices(f)))
            pal = []
            for r, g, b in palette_rgb(f):
                pal += [r, g, b]
            img.putpalette(pal + [0] * (768 - len(pal)))
            stem = os.path.splitext(name)[0] + os.path.splitext(name)[1][1:]
            suffix = "" if len(fr) == 1 else "-%02d" % i
            p = os.path.join(out, "%s%s.png" % (stem, suffix))
            img.resize((f["w"] * args.scale, f["h"] * args.scale),
                       Image.NEAREST).save(p)
            n += 1
    print("wrote %d PNG(s) to %s" % (n, out))
    return 0


def cmd_planes(args):
    files = planes_of(args.dir)
    if not files:
        print("hugopcx: no .B/.O/.OB in %s" % args.dir, file=sys.stderr)
        return 2
    print("%-14s %7s %6s %8s %8s %6s"
          % ("file", "bytes", "ok", "set bits", "nonzero", "values"))
    bad = 0
    for name in files:
        buf = open(os.path.join(args.dir, name), "rb").read()
        good = len(buf) == PLANE_BYTES
        bad += 0 if good else 1
        print("%-14s %7d %6s %8d %8d %6d"
              % (name, len(buf), "yes" if good else "NO",
                 sum(bin(b).count("1") for b in buf),
                 sum(1 for b in buf if b), len(set(buf))))
    print()
    print("planes     : %d, of which %d are not exactly %d bytes"
          % (len(files), bad, PLANE_BYTES))
    print("geometry   : %d x %d / 8 = %d, residue %d"
          % (SCREEN_W, SCREEN_H, SCREEN_W * SCREEN_H // 8,
             SCREEN_W * SCREEN_H % 8))
    return 1 if bad else 0


def selftest():
    """Three specimens that must fail, run before any real file is quoted."""
    fails = 0
    for label, buf in (
            ("empty", b""),
            ("wrong signature", b"MZ" + b"\x00" * 200),
            ("truncated payload", SIG + struct.pack("<4H", 0, 0, 7, 0)
             + b"\x00" * 53 + b"\x01" + struct.pack("<H", 1)
             + b"\x00" * 60 + b"\xc1"),
    ):
        try:
            read_frames(buf, label)
        except Bad as e:
            print("  refused %-18s %s" % (label, e))
            continue
        print("  ACCEPTED %-17s -- the reader is lying" % label)
        fails += 1
    good = bytearray(SIG + b"\x00" * 124)
    good[4:12] = struct.pack("<4H", 0, 0, 7, 0)   # 8 x 1
    good[65] = 1
    good[66:68] = struct.pack("<H", 1)
    good += b"\xc1\x55"                            # one run of 1
    try:
        fr = read_frames(bytes(good), "control")
        print("  accepted %-17s 1 frame, %d x %d, residue 0"
              % ("positive control", fr[0]["w"], fr[0]["h"]))
    except Bad as e:
        print("  REFUSED the positive control: %s" % e)
        fails += 1
    print()
    print("selftest: %d failure(s)" % fails)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    for name in ("validate", "census", "planes"):
        s = sub.add_parser(name)
        s.add_argument("dir")
    s = sub.add_parser("render")
    s.add_argument("dir")
    s.add_argument("--out", required=True)
    s.add_argument("--only")
    s.add_argument("--scale", type=int, default=1)
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.cmd:
        ap.print_help()
        return 2
    return {"validate": cmd_validate, "census": cmd_census,
            "render": cmd_render, "planes": cmd_planes}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
