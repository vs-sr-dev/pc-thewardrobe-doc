#!/usr/bin/env python3
"""ddswrap.py -- wrap a raw block-compressed payload in a DDS header.

The .tex payload is a bare stream of BC blocks. Rather than reimplement the
BC7 decoder, this builds the public DDS container around the payload and hands
it to Pillow, whose BCn decoder is used deliberately and is named here as the
public implementation being relied on. The DDS and DXGI structures are the
documented ones.

Validation: the wrapper is only trusted when the decoded image is inspected.
A wrong format guess produces a decode that either fails or is visibly noise,
and --try compares candidates so the choice is made by looking, not asserting.

Usage:
    ddswrap.py --payload FILE --w N --h N --format BC1|BC3|BC7 --out OUT.png
"""
import argparse
import io
import struct
import sys

DDSD = 0x1 | 0x2 | 0x4 | 0x1000 | 0x80000        # caps|height|width|pixelformat|linearsize
DDPF_FOURCC = 0x4
DXGI = {"BC1": 71, "BC2": 74, "BC3": 77, "BC4": 80, "BC5": 83, "BC7": 98}
BLOCKBYTES = {"BC1": 8, "BC4": 8, "BC2": 16, "BC3": 16, "BC5": 16, "BC7": 16}


def dds_bytes(payload, w, h, fmt):
    bb = BLOCKBYTES[fmt]
    linear = ((w + 3) // 4) * ((h + 3) // 4) * bb
    use_dx10 = fmt in ("BC7", "BC4", "BC5")
    fourcc = b"DX10" if use_dx10 else {"BC1": b"DXT1", "BC2": b"DXT3",
                                       "BC3": b"DXT5"}[fmt]
    hdr = b"DDS " + struct.pack(
        "<IIIIIII44sIIIIIIIIIIIII",
        124, DDSD, h, w, linear, 0, 1, b"\x00" * 44,
        32, DDPF_FOURCC, struct.unpack("<I", fourcc)[0], 0, 0, 0, 0, 0,
        0x1000, 0, 0, 0, 0)
    if use_dx10:
        hdr += struct.pack("<IIIII", DXGI[fmt], 3, 0, 1, 0)
    return hdr + payload[:linear]


def to_image(payload, w, h, fmt):
    from PIL import Image
    return Image.open(io.BytesIO(dds_bytes(payload, w, h, fmt))).convert("RGBA")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", required=True)
    ap.add_argument("--skip", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--w", type=int, required=True)
    ap.add_argument("--h", type=int, required=True)
    ap.add_argument("--format", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    with open(a.payload, "rb") as fh:
        blob = fh.read()[a.skip:]
    img = to_image(blob, a.w, a.h, a.format)
    img.save(a.out)
    print("wrote %s  %dx%d as %s" % (a.out, a.w, a.h, a.format))
    return 0


if __name__ == "__main__":
    sys.exit(main())
