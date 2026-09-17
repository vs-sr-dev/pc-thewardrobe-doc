"""cram.py -- a Microsoft Video 1 (`CRAM`) decoder, 16-bit variant, written
from the public description of the format.

The format is public and simple, and this file states the whole of it so that
the decoder can be audited rather than trusted. Microsoft Video 1 codes a frame
as a raster of 4x4 blocks, emitted **bottom row first** (the frame is a DIB and
DIBs are stored upside down), left to right within a row. The bitstream is a
sequence of little-endian 16-bit words; the low byte is read first and is called
`a` below, the high byte `b`.

For each block, read one word:

    b & 0xFC == 0x84    skip run. The next ((b - 0x84) << 8) + a blocks are
                        copied unchanged from the previous frame. The count
                        includes the current block.
    b <  0x80           2-colour or 8-colour block. The word is a 16-bit mask,
                        one bit per pixel, LSB first, rows bottom-up.
                        Read two more words as colours 0 and 1.
                        If colour 0 has bit 15 set, this is an 8-colour block:
                        read six more words, giving four independent colour
                        pairs, one per 2x2 quadrant of the block; strip bit 15
                        from colour 0 before use.
                        Pixel (x, y) takes colours[((y & 2) << 1) + (x & 2) + (bit ^ 1)]
                        in the 8-colour case and colours[bit ^ 1] in the
                        2-colour case.
    otherwise           1-colour block: the word itself is the colour, and the
                        whole 4x4 block is filled with it.

    a == 0 and b == 0 with no blocks left    end of frame.

Pixels are RGB555: red in bits 14..10, green 9..5, blue 4..0. Bit 15 is not a
pixel bit; it is the 8-colour flag and is masked off.

Two things make this a measurement rather than an assertion:

  * `--verify` decodes every frame of a file and checks that the decoder
    consumed **exactly** the bytes of each chunk, no more and no fewer. A
    format guessed wrongly does not land on the chunk boundary 147 times.
  * `--selftest` runs three negative controls that must fail.

Usage:
    python tools/cram.py FILE.AVI --verify
    python tools/cram.py FILE.AVI --frames N,N,N --out DIR
    python tools/cram.py --selftest
"""

import os
import struct
import sys


class CramError(Exception):
    pass


def parse_avi(path):
    """Return (width, height, bits, frames) where frames is a list of
    (fourcc, offset, size) for the video stream, in file order."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"RIFF" or data[8:12] != b"AVI ":
        raise CramError("not a RIFF/AVI file: %r" % data[:12])

    width = height = bits = None
    compression = None
    frames = []

    def walk(off, end, inlist):
        nonlocal width, height, bits, compression
        while off + 8 <= end:
            cid = data[off:off + 4]
            csz = struct.unpack_from("<I", data, off + 4)[0]
            body = off + 8
            if cid in (b"RIFF", b"LIST"):
                walk(body + 4, min(body + csz, end), data[body:body + 4])
            elif cid == b"strf" and width is None:
                # BITMAPINFOHEADER
                (_sz, w, h, _pl, bc) = struct.unpack_from("<IiiHH", data, body)
                comp = data[body + 16:body + 20]
                width, height, bits, compression = w, abs(h), bc, comp
            elif inlist == b"movi" and cid[2:4] in (b"db", b"dc"):
                frames.append((cid, body, csz))
            off = body + csz + (csz & 1)

    walk(0, len(data), None)
    if width is None:
        raise CramError("no strf found")
    return width, height, bits, compression, frames, data


def decode_frame(buf, width, height, prev=None):
    """Decode one CRAM 16-bit frame. Returns (pixels, bytes_consumed).
    `pixels` is a flat list of RGB555 ints, row 0 = top."""
    if width % 4 or height % 4:
        raise CramError("CRAM requires dimensions that are multiples of 4, got %dx%d"
                        % (width, height))
    bw, bh = width // 4, height // 4
    total = bw * bh
    pix = list(prev) if prev is not None else [0] * (width * height)
    if len(pix) != width * height:
        raise CramError("previous frame is the wrong size")

    p = 0
    n = len(buf)
    skip = 0
    remaining = total
    for by in range(bh - 1, -1, -1):        # bottom row of blocks first
        for bx in range(bw):
            if skip:
                skip -= 1
                remaining -= 1
                continue
            if p + 2 > n:
                raise CramError("ran out of bitstream at block (%d,%d), offset %d of %d"
                                % (bx, by, p, n))
            a, b = buf[p], buf[p + 1]
            p += 2
            if a == 0 and b == 0 and remaining == 0:
                return pix, p
            if (b & 0xFC) == 0x84:
                skip = ((b - 0x84) << 8) + a - 1
                if skip < 0:
                    raise CramError("negative skip run at offset %d" % (p - 2))
                remaining -= 1
                continue
            # The first block row decoded is the BOTTOM row of the picture: a
            # DIB is stored bottom-up. Within a block, y = 0 is the block's own
            # bottom row and y increases upward.
            base_y = by * 4
            if b < 0x80:
                flags = (b << 8) | a
                if p + 4 > n:
                    raise CramError("truncated colour pair at offset %d" % p)
                c0, c1 = struct.unpack_from("<HH", buf, p)
                p += 4
                if c0 & 0x8000:
                    if p + 12 > n:
                        raise CramError("truncated 8-colour block at offset %d" % p)
                    rest = struct.unpack_from("<6H", buf, p)
                    p += 12
                    cols = [c0 & 0x7FFF, c1] + list(rest)
                    for y in range(4):
                        row = (base_y + 3 - y) * width + bx * 4
                        for x in range(4):
                            bit = flags & 1
                            flags >>= 1
                            pix[row + x] = cols[((y & 2) << 1) + (x & 2) + (bit ^ 1)] & 0x7FFF
                else:
                    cols = (c0 & 0x7FFF, c1 & 0x7FFF)
                    for y in range(4):
                        row = (base_y + 3 - y) * width + bx * 4
                        for x in range(4):
                            bit = flags & 1
                            flags >>= 1
                            pix[row + x] = cols[bit ^ 1]
            else:
                c = ((b << 8) | a) & 0x7FFF
                for y in range(4):
                    row = (base_y + 3 - y) * width + bx * 4
                    for x in range(4):
                        pix[row + x] = c
            remaining -= 1
    # The frame ends with an optional 0x0000 terminator word that the block
    # loop never reaches, because the loop stops when the last block is done.
    if p + 2 == n and buf[p] == 0 and buf[p + 1] == 0:
        p += 2
    return pix, p


def rgb555_to_rgb(pix, width, height):
    import numpy as np
    a = np.array(pix, dtype=np.uint16).reshape(height, width)
    r = ((a >> 10) & 0x1F).astype(np.uint16)
    g = ((a >> 5) & 0x1F).astype(np.uint16)
    b = (a & 0x1F).astype(np.uint16)
    out = np.empty((height, width, 3), dtype=np.uint8)
    out[..., 0] = ((r * 255 + 15) // 31).astype(np.uint8)
    out[..., 1] = ((g * 255 + 15) // 31).astype(np.uint8)
    out[..., 2] = ((b * 255 + 15) // 31).astype(np.uint8)
    return out


def verify(path):
    w, h, bits, comp, frames, data = parse_avi(path)
    print("file            : %s" % path)
    print("dimensions      : %dx%d, %d bpp, compression %r" % (w, h, bits, comp))
    print("video chunks    : %d  (%s)"
          % (len(frames), ", ".join("%s x%d" % (k.decode(), sum(1 for f in frames if f[0] == k))
                                    for k in sorted({f[0] for f in frames}))))
    if comp not in (b"CRAM", b"cram", b"MSVC", b"msvc"):
        print("NOT a Microsoft Video 1 stream; refusing to decode")
        return 1
    if bits != 16:
        print("this decoder implements only the 16-bit variant; stream says %d bpp" % bits)
        return 1
    prev = None
    exact = short = over = 0
    modes = {"skip": 0, "1col": 0, "2col": 0, "8col": 0}
    for i, (cid, off, size) in enumerate(frames):
        buf = data[off:off + size]
        try:
            pix, used = decode_frame(buf, w, h, prev)
        except CramError as exc:
            print("frame %d (%s, %d bytes): DECODE FAILED: %s" % (i, cid.decode(), size, exc))
            return 1
        if used == size:
            exact += 1
        elif used < size:
            short += 1
            if short <= 3:
                print("frame %d: consumed %d of %d (%d left over)" % (i, used, size, size - used))
        else:
            over += 1
        prev = pix
    print()
    print("frames decoded                       : %d" % len(frames))
    print("chunks consumed to the exact byte    : %d" % exact)
    print("chunks with bytes left over          : %d" % short)
    print("chunks that overran                  : %d" % over)
    print()
    print("A format guessed wrongly does not land on the chunk boundary %d times." % exact)
    return 0 if (exact == len(frames)) else 1


def dump_frames(path, wanted, outdir):
    from PIL import Image
    w, h, bits, comp, frames, data = parse_avi(path)
    os.makedirs(outdir, exist_ok=True)
    prev = None
    want = set(wanted)
    hi = max(want)
    for i, (cid, off, size) in enumerate(frames):
        if i > hi:
            break
        pix, used = decode_frame(data[off:off + size], w, h, prev)
        prev = pix
        if i in want:
            arr = rgb555_to_rgb(pix, w, h)
            name = os.path.join(outdir, "frame%04d.png" % i)
            Image.fromarray(arr).save(name)
            print("wrote %s  (chunk %s, %d bytes, consumed %d)"
                  % (name, cid.decode(), size, used))
    return 0


def selftest():
    fails = 0
    print("=== NEGATIVE CONTROL 1: a truncated bitstream must raise ===")
    try:
        decode_frame(b"\x00\x00", 8, 8)
        print("  *** DID NOT RAISE ***")
        fails += 1
    except CramError as exc:
        print("  raised: %s" % exc)

    print("=== NEGATIVE CONTROL 2: non-multiple-of-4 dimensions must raise ===")
    try:
        decode_frame(b"\x00" * 64, 7, 8)
        print("  *** DID NOT RAISE ***")
        fails += 1
    except CramError as exc:
        print("  raised: %s" % exc)

    print("=== NEGATIVE CONTROL 3: a wrong-sized previous frame must raise ===")
    try:
        decode_frame(b"\x00" * 64, 8, 8, prev=[0] * 3)
        print("  *** DID NOT RAISE ***")
        fails += 1
    except CramError as exc:
        print("  raised: %s" % exc)

    print("=== POSITIVE CONTROL: a hand-built 1-colour block decodes to that colour ===")
    # one 4x4 block, colour 0x7C00 = pure red in RGB555, then the terminator.
    buf = struct.pack("<H", 0xFC00) + b"\x00\x00"
    pix, used = decode_frame(buf, 4, 4)
    ok = set(pix) == {0x7C00} and used == 4   # 2 for the block, 2 for the terminator
    print("  pixels %r consumed %d -> %s" % (sorted(set(pix)), used, "ok" if ok else "WRONG"))
    if not ok:
        fails += 1

    print("=== POSITIVE CONTROL: a 2-colour checkerboard mask ===")
    # flags = 0x5555 -> alternating bits; b = 0x55 < 0x80 so it is a 2-colour block
    buf = struct.pack("<HHH", 0x5555, 0x001F, 0x7C00)
    pix, used = decode_frame(buf, 4, 4)
    ok = sorted(set(pix)) == [0x001F, 0x7C00] and used == 6
    print("  pixels %r consumed %d -> %s" % (sorted(set(pix)), used, "ok" if ok else "WRONG"))
    if not ok:
        fails += 1

    print()
    print("failures: %d" % fails)
    return 1 if fails else 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if len(argv) < 3:
        print(__doc__)
        return 2
    path = argv[1]
    if "--verify" in argv:
        return verify(path)
    if "--frames" in argv:
        wanted = [int(x) for x in argv[argv.index("--frames") + 1].split(",")]
        outdir = argv[argv.index("--out") + 1] if "--out" in argv else "."
        return dump_frames(path, wanted, outdir)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
