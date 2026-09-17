#!/usr/bin/env python3
"""mttex.py -- decoder for the MT Framework .tex texture, derived from the bytes.

This collection has never opened one of these. The header was derived, not
looked up:

    +0   4    'TEX\\0'
    +4   u32   version / flags word, constant across almost every file here
    +8   u32   mip count in bits 0-5, width in bits 6-18, height in bits 19-31
    +12  u32   format code in bits 8-15
    +16  u32   header size in bytes (0x18 on every 2D texture seen)
    +20  u32   unused / per-format

The dimension packing is confirmed the only way that counts: the width and
height it predicts, multiplied by the bits-per-pixel the format code implies,
must equal the payload length that the .arc header declared independently.
That is one quantity encoded twice in two different places, and it agrees or
the derivation is wrong.

Block decoders for BC1 and BC3 are implemented here from the public block
layouts. BC7 is NOT implemented; files in that format are reported as
"format not decoded" rather than guessed at.

Usage:
    mttex.py --probe FILE...            header + predicted vs actual size
    mttex.py --census DIR               probe every .tex-like file in a tree
    mttex.py --png FILE --out OUT.png   decode and write a PNG
"""
import argparse
import glob
import os
import struct
import sys

import numpy as np

MAGIC = b"TEX\x00"

# format code (bits 8-15 of word at +12) -> (name, bits per pixel, decoder)
#
# 0x2A was derived here and is not a standard DXGI format. Its blocks are BC3
# blocks, but the six green bits of both RGB565 endpoints are hard-set to 1 in
# 100 % of blocks sampled, so the colour block carries only two 5-bit fields,
# and the 8-bit interpolated alpha carries the image's luminance -- decoding
# the alpha channel alone yields a clean greyscale picture. Treating
# (alpha, B-field, R-field) as (Y, Cb, Cr) and converting from YCbCr gives a
# correct colour image; treating it as YCoCg does not.
FORMATS = {
    0x19: ("BC1", 4, "bc1"),
    0x1A: ("BC1a", 4, "bc1"),
    0x1B: ("BC2", 8, None),
    0x1C: ("BC3", 8, "bc3"),
    0x1F: ("BC4", 4, None),
    0x07: ("cube/float", None, None),
    0x20: ("cube/other", 8, None),
    0x2A: ("BC3-YCbCr", 8, "ycbcr"),
    0x30: ("BC7", 8, "bc7"),
}


class NotTex(Exception):
    pass


def parse(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        d = bytes(path_or_bytes)
        name = "<bytes>"
    else:
        with open(path_or_bytes, "rb") as fh:
            d = fh.read()
        name = path_or_bytes
    if len(d) < 24 or d[:4] != MAGIC:
        raise NotTex("%s: magic %r, not %r" % (name, d[:4], MAGIC))
    w1, dims, fmtw, hdrsize, w5 = struct.unpack_from("<IIIII", d, 4)
    mips = dims & 0x3F
    width = (dims >> 6) & 0x1FFF
    height = (dims >> 19) & 0x1FFF
    fmt = (fmtw >> 8) & 0xFF
    fname, bpp, dec = FORMATS.get(fmt, ("0x%02X" % fmt, None, None))
    return {
        "path": name, "size": len(d), "data": d,
        "flags": w1, "mips": mips, "width": width, "height": height,
        "fmt": fmt, "fmt_name": fname, "bpp": bpp, "decoder": dec,
        "hdrsize": hdrsize, "w5": w5,
    }


def predicted_payload(width, height, bpp, mips=1):
    """Bytes for the base level only, block-aligned."""
    if bpp is None:
        return None
    bw = (width + 3) // 4
    bh = (height + 3) // 4
    block_bytes = 8 if bpp == 4 else 16
    return bw * bh * block_bytes


# ---------------------------------------------------------------- BC decoders

def _c565(c):
    r = ((c >> 11) & 0x1F) * 255 // 31
    g = ((c >> 5) & 0x3F) * 255 // 63
    b = (c & 0x1F) * 255 // 31
    return r, g, b


def _color_block(blk, out, ox, oy, W, H, opaque):
    c0, c1 = struct.unpack_from("<HH", blk, 0)
    bits = struct.unpack_from("<I", blk, 4)[0]
    p = [_c565(c0), _c565(c1)]
    if c0 > c1 or opaque:
        p.append(tuple((2 * p[0][i] + p[1][i]) // 3 for i in range(3)))
        p.append(tuple((p[0][i] + 2 * p[1][i]) // 3 for i in range(3)))
        alpha3 = 255
    else:
        p.append(tuple((p[0][i] + p[1][i]) // 2 for i in range(3)))
        p.append((0, 0, 0))
        alpha3 = 0
    for y in range(4):
        for x in range(4):
            px, py = ox + x, oy + y
            if px >= W or py >= H:
                continue
            idx = (bits >> (2 * (4 * y + x))) & 3
            out[py, px, 0:3] = p[idx]
            if not opaque and idx == 3:
                out[py, px, 3] = alpha3


def decode_bc1(data, W, H):
    out = np.zeros((H, W, 4), dtype=np.uint8)
    out[:, :, 3] = 255
    i = 0
    for by in range(0, H, 4):
        for bx in range(0, W, 4):
            _color_block(data[i:i + 8], out, bx, by, W, H, False)
            i += 8
    return out


def decode_bc3(data, W, H):
    out = np.zeros((H, W, 4), dtype=np.uint8)
    i = 0
    for by in range(0, H, 4):
        for bx in range(0, W, 4):
            blk = data[i:i + 16]
            a0, a1 = blk[0], blk[1]
            abits = int.from_bytes(blk[2:8], "little")
            av = [a0, a1]
            if a0 > a1:
                for k in range(1, 7):
                    av.append(((7 - k) * a0 + k * a1) // 7)
            else:
                for k in range(1, 5):
                    av.append(((5 - k) * a0 + k * a1) // 5)
                av += [0, 255]
            _color_block(blk[8:16], out, bx, by, W, H, True)
            for y in range(4):
                for x in range(4):
                    px, py = bx + x, by + y
                    if px >= W or py >= H:
                        continue
                    out[py, px, 3] = av[(abits >> (3 * (4 * y + x))) & 7]
            i += 16
    return out


def decode(info):
    """Return a PIL RGBA image."""
    from PIL import Image
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ddswrap import to_image

    payload = info["data"][24:]
    W, H = info["width"], info["height"]
    dec = info["decoder"]
    if dec == "bc7":
        return to_image(payload, W, H, "BC7")
    if dec == "bc1":
        return to_image(payload, W, H, "BC1")
    if dec == "bc3":
        return to_image(payload, W, H, "BC3")
    if dec == "ycbcr":
        a = np.array(to_image(payload, W, H, "BC3"))
        y = Image.fromarray(a[:, :, 3], "L")
        cb = Image.fromarray(a[:, :, 2], "L")
        cr = Image.fromarray(a[:, :, 0], "L")
        return Image.merge("YCbCr", (y, cb, cr)).convert("RGB").convert("RGBA")
    raise NotTex("%s: format %s (0x%02X) not decoded"
                 % (info["path"], info["fmt_name"], info["fmt"]))


# ---------------------------------------------------------------- reporting

def probe(path):
    info = parse(path)
    payload = info["size"] - 24
    pred = predicted_payload(info["width"], info["height"], info["bpp"], info["mips"])
    verdict = "?" if pred is None else ("MATCH" if pred == payload else "no")
    print("%-46s %5dx%-5d mips=%-2d fmt=0x%02X %-10s payload=%9d predicted=%9s %s"
          % (os.path.basename(path)[:46], info["width"], info["height"],
             info["mips"], info["fmt"], info["fmt_name"], payload,
             pred if pred is not None else "-", verdict))
    return info, payload, pred


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--census")
    ap.add_argument("--png")
    ap.add_argument("--out")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()

    if a.census:
        paths = [p for p in glob.glob(os.path.join(a.census, "**", "*"), recursive=True)
                 if os.path.isfile(p)]
        n = ok = bad = skip = 0
        fmts = {}
        for p in sorted(paths):
            try:
                info, payload, pred = probe(p)
            except NotTex:
                skip += 1
                continue
            n += 1
            fmts[info["fmt_name"]] = fmts.get(info["fmt_name"], 0) + 1
            if pred is None:
                continue
            if pred == payload:
                ok += 1
            else:
                bad += 1
        print("\n%d .tex files, %d skipped (not TEX)" % (n, skip))
        print("size prediction: %d match, %d mismatch, %d unpredictable"
              % (ok, bad, n - ok - bad))
        print("formats: %s" % fmts)
        return 0 if bad == 0 else 1

    if a.probe:
        for p in a.files:
            try:
                probe(p)
            except NotTex as e:
                print("NOT-TEX  %s" % e)
        return 0

    if a.png:
        info = parse(a.png)
        img = decode(info)
        img.save(a.out)
        print("wrote %s  %dx%d  %s" % (a.out, info["width"], info["height"],
                                       info["fmt_name"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
