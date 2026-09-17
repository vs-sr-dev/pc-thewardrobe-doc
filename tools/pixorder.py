#!/usr/bin/env python3
"""pixorder.py -- try every plausible framebuffer order and let a person choose.

The platform notes' hardest-won line is that the 3DO framebuffer supports more
than one pixel order, that a descriptor can lie about which, and that the only
check that settles it is rendering and looking. This renders a 16-bit 5-5-5
payload under several candidate orders into one sheet.

    linear     row-major, the obvious one
    lr-half    within a row, even words are the left half and odd the right
    lr-pair    a 32-bit word holds one pixel of row 2n and one of row 2n+1
    lr-pair-s  the same, with the halves swapped
    fields     the first half of the buffer is the even rows, the second the odd

usage: pixorder.py FILE --offset N --size WxH --png OUT.png
"""
import argparse
import struct


def orders(w, h):
    half = w // 2
    def linear(i):
        return i
    def lr_half(i):
        row, col = divmod(i, w)
        return row * w + (col // 2) + (half if col & 1 else 0)
    def lr_pair(i):
        blk, j = divmod(i, 2 * w)
        x, which = divmod(j, 2)
        return (2 * blk + which) * w + x
    def lr_pair_s(i):
        blk, j = divmod(i, 2 * w)
        x, which = divmod(j, 2)
        return (2 * blk + (1 - which)) * w + x
    def fields(i):
        n = w * h
        if i < n // 2:
            row, col = divmod(i, w)
            return (2 * row) * w + col
        j = i - n // 2
        row, col = divmod(j, w)
        return (2 * row + 1) * w + col
    return [("linear", linear), ("lr-half", lr_half), ("lr-pair", lr_pair),
            ("lr-pair-s", lr_pair_s), ("fields", fields)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--size", default="320x240")
    ap.add_argument("--png", required=True)
    ap.add_argument("--cols", type=int, default=3)
    a = ap.parse_args()
    w, h = (int(x) for x in a.size.split("x"))
    d = open(a.file, "rb").read()[a.offset:a.offset + w * h * 2]
    from PIL import Image
    ims = []
    for name, f in orders(w, h):
        out = bytearray(w * h * 3)
        for i in range(w * h):
            v = (d[2 * i] << 8) | d[2 * i + 1]
            r = (v >> 10) & 0x1F
            g = (v >> 5) & 0x1F
            b = v & 0x1F
            j = f(i) * 3
            if 0 <= j <= len(out) - 3:
                out[j] = (r << 3) | (r >> 2)
                out[j + 1] = (g << 3) | (g >> 2)
                out[j + 2] = (b << 3) | (b >> 2)
        ims.append((name, Image.frombytes("RGB", (w, h), bytes(out))))
    cols = a.cols
    rows = (len(ims) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * w, rows * h), (0, 0, 0))
    for k, (name, im) in enumerate(ims):
        sheet.paste(im, ((k % cols) * w, (k // cols) * h))
    sheet.save(a.png)
    print("wrote %s  order of panels: %s"
          % (a.png, ", ".join(n for n, _ in ims)))


if __name__ == "__main__":
    main()
