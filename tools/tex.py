#!/usr/bin/env python3
"""tex.py -- read Square's `.TEX` bitmap, the commonest leaf inside a `.LGP`,
and write it out as PNG.

`lgp.py` opens the container; this opens what is inside it, and it exists so
that the container reader can be checked against something a person can look
at. A closure residue of 0 says the offsets are right; a picture says the
offsets are right AND point at what the archive says they point at.

THE LAYOUT, DERIVED FROM THE BYTES

The commonest sizes on this object are 5,356, 17,644 and 66,796 bytes, and
64 x 64 = 4,096, 128 x 128 = 16,384, 256 x 256 = 65,536. **The difference is
1,260 on all three**, which is what first fixed the header and the palette
together -- and it is also what made the first draft of this reader wrong,
because 1,260 = 236 + 1,024 is a coincidence of the commonest case and not the
rule. Five members of MENU_US.LGP alone come up 832 or 960 bytes short of it,
and the palette length has to be read rather than assumed:

      0  236   header, 59 uint32 little-endian. The fields used here:
                 [ 0] version, 1 on every TEX on this object
                 [12] palette count
                 [13] colours per palette
                 [15] width
                 [16] height
                 [20] bits per pixel, 8 on every TEX here
                 [50] bytes per colour, 4
    236  P     the palette, P = [12] x [13] x [50] bytes, B G R A
  236+P  w*h   one byte of palette index per pixel, top row first

    236 + [12]*[13]*[50] + w*h == file length, residue 0.

  P is 1,024 on most members -- one palette of 256 colours for the character
  portraits, sixteen of sixteen for the battle windows and the fonts, and both
  are 256 entries. It is not always: three palettes of sixteen is 192 bytes and
  one of sixteen is 64. `--palette N` picks which palette to use where there
  is more than one.

  The fourth byte of a colour takes three values across the palettes read here
  -- **255, 254 and 0** -- so it is an opacity or a flag and not padding. This
  tool writes RGB and prints the set of values it saw rather than guessing
  which.

    python tools/tex.py FILE.tex OUT.png
    python tools/tex.py ARCHIVE.LGP OUTDIR --member NAME
    python tools/tex.py ARCHIVE.LGP OUTDIR --all
    python tools/tex.py FILE.tex --info
"""
import argparse
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lgp  # noqa: E402

HDR = 236


class NotTex(Exception):
    pass


def parse(data, label="<bytes>"):
    if len(data) < HDR:
        raise NotTex("%s: %d bytes is shorter than the header"
                     % (label, len(data)))
    f = struct.unpack("<59I", data[:HDR])
    w, h, bpp = f[15], f[16], f[20]
    npal, ncol, bpc = f[12], f[13], f[50]
    if f[0] != 1 or bpp != 8 or bpc != 4:
        raise NotTex("%s: version %d, %d bpp, %d bytes per colour -- this "
                     "reader only knows version 1, 8 bpp, 4" % (label, f[0],
                                                                bpp, bpc))
    pal = npal * ncol * bpc
    if not 0 < pal <= 1 << 16:
        raise NotTex("%s: palette %d x %d x %d = %d bytes is not a palette"
                     % (label, npal, ncol, bpc, pal))
    if HDR + pal + w * h != len(data):
        raise NotTex("%s: %d + %d + %d x %d = %d against %d bytes"
                     % (label, HDR, pal, w, h, HDR + pal + w * h, len(data)))
    return {"w": w, "h": h, "npal": npal, "ncol": ncol, "palbytes": pal,
            "pal": data[HDR:HDR + pal], "px": data[HDR + pal:], "f": f}


def png(path, w, h, rgb):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += rgb[y * w * 3:(y + 1) * w * 3]

    def chunk(tag, body):
        return (struct.pack(">I", len(body)) + tag + body
                + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n"
                 + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                 + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
                 + chunk(b"IEND", b""))


def render(t, which):
    w, h = t["w"], t["h"]
    base = which * t["ncol"] * 4 if t["npal"] > 1 else 0
    if base >= t["palbytes"]:
        base = 0
    out = bytearray(w * h * 3)
    pal = t["pal"]
    for i, v in enumerate(t["px"]):
        p = base + v * 4
        if p + 3 > len(pal):
            p = 0
        out[i * 3] = pal[p + 2]
        out[i * 3 + 1] = pal[p + 1]
        out[i * 3 + 2] = pal[p]
    return out


def info(t, label):
    print("%-22s %4d x %-4d  palettes %2d x %3d = %5d bytes  4th-byte values %s"
          % (label, t["w"], t["h"], t["npal"], t["ncol"], t["palbytes"],
             sorted({t["pal"][k] for k in range(3, t["palbytes"], 4)})))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--member")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--palette", type=int, default=0)
    ap.add_argument("--info", action="store_true")
    a = ap.parse_args(argv[1:])

    if a.src.upper().endswith(".LGP"):
        data = open(a.src, "rb").read()
        _c, ents, _l, _cf, _t, _acc = lgp.parse(data, a.src)
        pick = [e for e in ents
                if a.all or (a.member and e["name"] == a.member)]
        if not pick:
            print("FATAL: no member selected in %s" % a.src)
            return 3
        os.makedirs(a.out, exist_ok=True)
        n = ok = 0
        for e in pick:
            blob = data[e["data"]:e["data"] + e["length"]]
            n += 1
            try:
                t = parse(blob, e["name"])
            except NotTex as exc:
                if not a.all:
                    print("REFUSED: %s" % exc)
                continue
            ok += 1
            if a.info:
                info(t, e["name"])
            else:
                dest = os.path.join(a.out, e["name"].replace(".", "_") + ".png")
                png(dest, t["w"], t["h"], render(t, a.palette))
                print("%-22s %4dx%-4d -> %s" % (e["name"], t["w"], t["h"], dest))
        print("%d of %d members parsed as TEX" % (ok, n))
        return 0
    blob = open(a.src, "rb").read()
    t = parse(blob, os.path.basename(a.src))
    if a.info or not a.out:
        info(t, os.path.basename(a.src))
        return 0
    png(a.out, t["w"], t["h"], render(t, a.palette))
    print("%s %dx%d -> %s" % (a.src, t["w"], t["h"], a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
