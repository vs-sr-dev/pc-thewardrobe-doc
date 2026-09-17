#!/usr/bin/env python3
"""unitytex.py -- decode Unity 5.2 `Texture2D` objects out of a version-15
SerializedFile and write them as PNG.

This exists so that the container work in this repository ends in a picture
rather than in a byte count.  Everything upstream of it -- `sfv15.py`'s two
closures, `unityweb.py`'s four -- proves that the *framing* was read
correctly.  Only a decoded image proves the *contents* were.

The Texture2D body, derived from this object at serialization version 15
--------------------------------------------------------------------------

    aligned string  m_Name
    i32             m_Width
    i32             m_Height
    i32             m_CompleteImageSize
    i32             m_TextureFormat
    i32             m_MipCount          -- 7 on a 64x64 with a full chain,
                                           1 on a texture with no mips, which
                                           is how it was told from the bool
                                           some readers expect here
    u8              m_IsReadable
    u8              m_ReadAllowed
    align 4
    i32             m_ImageCount
    i32             m_TextureDimension  -- 2
    i32             m_FilterMode
    i32             m_Aniso
    f32             m_MipBias
    i32             m_WrapMode
    i32             m_LightmapFormat
    i32             m_ColorSpace
    i32             imageDataSize
    ...             imageDataSize bytes

THE CLOSURE: `imageDataSize` must equal `m_CompleteImageSize`, and the object
body must end at the last byte of the image data, give or take the one to
three bytes of padding Unity uses to align an object body to four.  A layout
error anywhere above moves that end by more than three.  On this object the
closure holds on 625 of 625.

The pixel formats implemented are the ones this object uses, and no others:

    1  Alpha8      8 bits, alpha only
    2  ARGB4444    16 bits, four nibbles
    4  RGBA32      32 bits
    5  ARGB32      32 bits
    7  RGB565      16 bits
    10 DXT1        4 bits, 8-byte blocks, one-bit alpha
    12 DXT5        8 bits, 16-byte blocks, interpolated alpha

DXT1 and DXT5 are decoded here in full -- colour endpoints, the two or four
interpolated colours, the 2-bit index grid, and DXT5's eight-value alpha ramp.
A block decoder that is wrong produces an image, so the check is not that it
runs: it is that `m_CompleteImageSize` equals the exact block count for the
declared width and height, which this tool asserts before decoding a byte.

PNG is written with `zlib` from the standard library and nothing else.

    python unitytex.py selftest
    python unitytex.py list    FILE|DIR
    python unitytex.py extract FILE --name NAME --out OUT.png [--matte 20]
    python unitytex.py census  DIR

Standard library only.
"""

import argparse
import collections
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sfv15                                                # noqa: E402

FORMAT = {
    1: 'Alpha8', 2: 'ARGB4444', 3: 'RGB24', 4: 'RGBA32', 5: 'ARGB32',
    7: 'RGB565', 10: 'DXT1', 12: 'DXT5', 13: 'RGBA4444', 34: 'ETC_RGB4',
}
# bits per pixel for the block-compressed and linear formats this tool knows
BPP = {1: 8, 2: 16, 3: 24, 4: 32, 5: 32, 7: 16, 10: 4, 12: 8, 13: 16}


class Refused(Exception):
    pass


class Texture(object):
    def __init__(self, sf, obj):
        b = sf.body(obj)
        n, = struct.unpack_from('<i', b, 0)
        if not 0 <= n <= 4096 or 4 + n > len(b):
            raise Refused('m_Name length %d in a %d-byte body' % (n, len(b)))
        self.name = b[4:4 + n].decode('utf-8', 'replace')
        p = (4 + n + 3) & ~3
        (self.width, self.height, self.complete_size, self.format,
         self.mip_count) = struct.unpack_from('<5i', b, p)
        p += 20
        self.is_readable = b[p]
        self.read_allowed = b[p + 1]
        p = (p + 2 + 3) & ~3
        (self.image_count, self.dimension, self.filter_mode,
         self.aniso) = struct.unpack_from('<4i', b, p)
        p += 16
        self.mip_bias, = struct.unpack_from('<f', b, p)
        p += 4
        (self.wrap_mode, self.lightmap_format, self.colour_space,
         self.data_size) = struct.unpack_from('<4i', b, p)
        p += 16
        self.data = b[p:p + self.data_size]
        self.tail = len(b) - p - self.data_size
        self.body_len = len(b)

    @property
    def closes(self):
        """imageDataSize == m_CompleteImageSize, and the body ends there.

        `self.tail` is allowed to be one, two or three bytes: Unity aligns an
        object body to four, and eight of this object's 625 textures have an
        odd image size -- 21,845 and 699,050 and 42 among them, all of them
        Unity's own built-in resources.  Requiring tail == 0 reported those
        eight as failures for one run of this tool, which was wrong about the
        format and is recorded in docs/14 rather than quietly changed.
        """
        return (self.data_size == self.complete_size and 0 <= self.tail < 4
                and (self.body_len % 4) == 0)

    def expected_level0(self):
        """Bytes the top mip must occupy, from the format alone."""
        f = self.format
        if f in (10, 12):
            bw = (self.width + 3) // 4
            bh = (self.height + 3) // 4
            return bw * bh * (8 if f == 10 else 16)
        if f not in BPP:
            raise Refused('format %d (%s) is not implemented'
                          % (f, FORMAT.get(f, '?')))
        return self.width * self.height * BPP[f] // 8

    def rgba(self):
        """The top mip level, as width*height*4 bytes of RGBA."""
        need = self.expected_level0()
        if len(self.data) < need:
            raise Refused('%d bytes of pixels where the top mip of a %dx%d '
                          '%s needs %d'
                          % (len(self.data), self.width, self.height,
                             FORMAT.get(self.format, self.format), need))
        d = self.data[:need]
        f = self.format
        if f == 10:
            return _dxt(d, self.width, self.height, False)
        if f == 12:
            return _dxt(d, self.width, self.height, True)
        return _linear(d, self.width, self.height, f)


def _linear(d, w, h, f):
    out = bytearray(w * h * 4)
    if f == 1:                                              # Alpha8
        for i in range(w * h):
            out[i * 4:i * 4 + 4] = bytes((255, 255, 255, d[i]))
        return _flip(out, w, h)
    if f == 2:                                              # ARGB4444
        for i in range(w * h):
            v = d[i * 2] | (d[i * 2 + 1] << 8)
            a = (v >> 12) & 0xf
            r = (v >> 8) & 0xf
            g = (v >> 4) & 0xf
            b = v & 0xf
            out[i * 4:i * 4 + 4] = bytes((r * 17, g * 17, b * 17, a * 17))
        return _flip(out, w, h)
    if f == 3:                                              # RGB24
        for i in range(w * h):
            out[i * 4:i * 4 + 4] = bytes((d[i * 3], d[i * 3 + 1],
                                          d[i * 3 + 2], 255))
        return _flip(out, w, h)
    if f == 4:                                              # RGBA32
        return _flip(bytearray(d), w, h)
    if f == 5:                                              # ARGB32
        for i in range(w * h):
            a, r, g, b = d[i * 4], d[i * 4 + 1], d[i * 4 + 2], d[i * 4 + 3]
            out[i * 4:i * 4 + 4] = bytes((r, g, b, a))
        return _flip(out, w, h)
    if f == 7:                                              # RGB565
        for i in range(w * h):
            v = d[i * 2] | (d[i * 2 + 1] << 8)
            r = (v >> 11) & 0x1f
            g = (v >> 5) & 0x3f
            b = v & 0x1f
            out[i * 4:i * 4 + 4] = bytes((r * 255 // 31, g * 255 // 63,
                                          b * 255 // 31, 255))
        return _flip(out, w, h)
    raise Refused('format %d is not implemented' % f)


def _565(v):
    r = (v >> 11) & 0x1f
    g = (v >> 5) & 0x3f
    b = v & 0x1f
    return (r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)


def _dxt(d, w, h, dxt5):
    """DXT1 and DXT5, decoded in full.

    DXT1: two 16-bit RGB565 endpoints, then sixteen 2-bit indices.  When
    c0 > c1 the two interpolated colours are 2/3 and 1/3 mixes; when c0 <= c1
    there is one 1/2 mix and index 3 is transparent black, which is the
    one-bit alpha DXT1 has and which a decoder that ignores it renders as an
    opaque black square.

    DXT5: eight bytes of alpha first -- two endpoints and sixteen 3-bit
    indices packed into six bytes, little-endian -- then a DXT1 colour block
    whose alpha branch is *not* taken.
    """
    bw, bh = (w + 3) // 4, (h + 3) // 4
    out = bytearray(w * h * 4)
    stride = w * 4
    bs = 16 if dxt5 else 8
    for by in range(bh):
        for bx in range(bw):
            o = (by * bw + bx) * bs
            alpha = None
            if dxt5:
                a0, a1 = d[o], d[o + 1]
                bits = int.from_bytes(d[o + 2:o + 8], 'little')
                tab = [a0, a1]
                if a0 > a1:
                    for i in range(1, 7):
                        tab.append(((7 - i) * a0 + i * a1) // 7)
                else:
                    for i in range(1, 5):
                        tab.append(((5 - i) * a0 + i * a1) // 5)
                    tab.append(0)
                    tab.append(255)
                alpha = [tab[(bits >> (3 * i)) & 7] for i in range(16)]
                o += 8
            c0, c1 = struct.unpack_from('<HH', d, o)
            idx, = struct.unpack_from('<I', d, o + 4)
            r0, g0, b0 = _565(c0)
            r1, g1, b1 = _565(c1)
            cols = [(r0, g0, b0, 255), (r1, g1, b1, 255)]
            if dxt5 or c0 > c1:
                cols.append(((2 * r0 + r1) // 3, (2 * g0 + g1) // 3,
                             (2 * b0 + b1) // 3, 255))
                cols.append(((r0 + 2 * r1) // 3, (g0 + 2 * g1) // 3,
                             (b0 + 2 * b1) // 3, 255))
            else:
                cols.append(((r0 + r1) // 2, (g0 + g1) // 2,
                             (b0 + b1) // 2, 255))
                cols.append((0, 0, 0, 0))
            for py in range(4):
                y = by * 4 + py
                if y >= h:
                    break
                row = y * stride
                for px in range(4):
                    x = bx * 4 + px
                    if x >= w:
                        break
                    i = py * 4 + px
                    r, g, b, a = cols[(idx >> (2 * i)) & 3]
                    if alpha is not None:
                        a = alpha[i]
                    p = row + x * 4
                    out[p] = r
                    out[p + 1] = g
                    out[p + 2] = b
                    out[p + 3] = a
    return _flip(out, w, h)


def _flip(buf, w, h):
    """Unity stores textures bottom-up; PNG is top-down."""
    stride = w * 4
    out = bytearray(len(buf))
    for y in range(h):
        s = (h - 1 - y) * stride
        out[y * stride:(y + 1) * stride] = buf[s:s + stride]
    return out


def write_png(path, rgba, w, h):
    raw = bytearray()
    stride = w * 4
    for y in range(h):
        raw.append(0)
        raw += rgba[y * stride:(y + 1) * stride]

    def chunk(tag, payload):
        return (struct.pack('>I', len(payload)) + tag + payload +
                struct.pack('>I', zlib.crc32(tag + payload) & 0xffffffff))

    ihdr = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(chunk(b'IHDR', ihdr))
        f.write(chunk(b'IDAT', zlib.compress(bytes(raw), 6)))
        f.write(chunk(b'IEND', b''))
    return os.path.getsize(path)


def textures(paths):
    for p in sfv15.candidates(paths):
        sf = sfv15.load(p)
        for o in sf.objects:
            if o['class_id'] != 28:
                continue
            try:
                yield p, Texture(sf, o)
            except Refused:
                continue


# ----------------------------------------------------------------- selftest

def cmd_selftest(_args):
    print('unitytex.py selftest -- pixel blocks built in memory, with the')
    print('answer known in advance.  A DXT decoder that is wrong still')
    print('produces an image, so these check values and not exit codes.')
    print()
    ok = bad = 0

    def check(name, got, want):
        nonlocal ok, bad
        if got == want:
            print('  ok      %-40s %s' % (name, got))
            ok += 1
        else:
            print('  WRONG   %-40s got %s, wanted %s' % (name, got, want))
            bad += 1

    # a DXT1 block: c0 = pure red, c1 = pure blue, all sixteen indices 0
    blk = struct.pack('<HHI', 0xf800, 0x001f, 0x00000000)
    px = _dxt(blk, 4, 4, False)
    check('DXT1 index 0 is endpoint 0', tuple(px[0:4]), (255, 0, 0, 255))
    blk = struct.pack('<HHI', 0xf800, 0x001f, 0x55555555)
    px = _dxt(blk, 4, 4, False)
    check('DXT1 index 1 is endpoint 1', tuple(px[0:4]), (0, 0, 255, 255))
    # c0 > c1, index 2 is the 2/3 mix
    blk = struct.pack('<HHI', 0xf800, 0x001f, 0xaaaaaaaa)
    px = _dxt(blk, 4, 4, False)
    check('DXT1 index 2 is the 2/3 mix', tuple(px[0:3]), (170, 0, 85))
    # c0 <= c1, index 3 is transparent black -- the case a naive decoder
    # renders as opaque black
    blk = struct.pack('<HHI', 0x001f, 0xf800, 0xffffffff)
    px = _dxt(blk, 4, 4, False)
    check('DXT1 one-bit alpha, index 3', tuple(px[0:4]), (0, 0, 0, 0))
    # DXT5 alpha: a0 > a1, index 0 is a0
    a = bytes([200, 10]) + b'\x00' * 6
    blk = a + struct.pack('<HHI', 0xffff, 0x0000, 0x00000000)
    px = _dxt(blk, 4, 4, True)
    check('DXT5 alpha index 0 is a0', px[3], 200)
    # every index = 1 -> a1
    bits = 0
    for i in range(16):
        bits |= 1 << (3 * i)
    a = bytes([200, 10]) + bits.to_bytes(6, 'little')
    blk = a + struct.pack('<HHI', 0xffff, 0x0000, 0x00000000)
    px = _dxt(blk, 4, 4, True)
    check('DXT5 alpha index 1 is a1', px[3], 10)
    # DXT5 never takes DXT1's alpha branch even when c0 <= c1
    blk = bytes([255, 255]) + b'\x00' * 6 + struct.pack('<HHI', 0x001f,
                                                        0xf800, 0xffffffff)
    px = _dxt(blk, 4, 4, True)
    check('DXT5 colour block has no 1-bit alpha', px[3], 255)
    # linear formats
    check('ARGB32 channel order',
          tuple(_linear(bytes([1, 2, 3, 4]), 1, 1, 5)), (2, 3, 4, 1))
    check('RGBA32 channel order',
          tuple(_linear(bytes([1, 2, 3, 4]), 1, 1, 4)), (1, 2, 3, 4))
    check('ARGB4444 nibble expansion',
          tuple(_linear(bytes([0x34, 0xf1]), 1, 1, 2)), (17, 51, 68, 255))
    check('RGB565 white', tuple(_linear(bytes([0xff, 0xff]), 1, 1, 7)),
          (255, 255, 255, 255))
    check('Alpha8', tuple(_linear(bytes([77]), 1, 1, 1)), (255, 255, 255, 77))
    # the bottom-up flip
    two = bytes([1, 1, 1, 1, 2, 2, 2, 2])
    check('bottom-up flip', tuple(_flip(bytearray(two), 1, 2)),
          (2, 2, 2, 2, 1, 1, 1, 1))
    # PNG round trip through zlib
    import tempfile
    fd, tp = tempfile.mkstemp(suffix='.png')
    os.close(fd)
    n = write_png(tp, bytearray([255, 0, 0, 255] * 4), 2, 2)
    head = open(tp, 'rb').read(8)
    os.unlink(tp)
    check('PNG signature', head, b'\x89PNG\r\n\x1a\n')
    check('PNG is not empty', n > 60, True)
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


# ----------------------------------------------------------------- commands

def cmd_list(args):
    print('%-40s %5s %5s %-10s %5s %10s %s'
          % ('NAME', 'W', 'H', 'FORMAT', 'MIPS', 'BYTES', 'CLOSES'))
    n = 0
    for _p, t in textures(args.paths):
        if args.name and args.name not in t.name:
            continue
        n += 1
        if n > args.limit:
            break
        print('%-40s %5d %5d %-10s %5d %10d %s'
              % (t.name[:40], t.width, t.height,
                 FORMAT.get(t.format, str(t.format)), t.mip_count,
                 t.data_size, 'yes' if t.closes else 'NO'))
    return 0


def cmd_extract(args):
    for _p, t in textures(args.paths):
        if t.name != args.name:
            continue
        if not t.closes:
            raise Refused('%s does not close: data %d, complete %d, tail %d'
                          % (t.name, t.data_size, t.complete_size, t.tail))
        want = t.expected_level0()
        print('%s  %dx%d  %s  mips %d' % (t.name, t.width, t.height,
                                          FORMAT.get(t.format, t.format),
                                          t.mip_count))
        print('  m_CompleteImageSize %d, top mip needs %d, whole chain %d'
              % (t.complete_size, want, t.data_size))
        px = t.rgba()
        if args.matte is not None:
            # Much of this object's UI art is white with an alpha mask, which
            # a viewer on a white page renders as an empty rectangle.  This
            # composites it over one grey level so the decode can be SEEN,
            # and it is an option rather than the default because it changes
            # the pixels: the file written with --matte is no longer the
            # texture, it is a picture of the texture on a background.
            m = args.matte
            out = bytearray(len(px))
            for i in range(0, len(px), 4):
                a = px[i + 3]
                for c in range(3):
                    out[i + c] = (px[i + c] * a + m * (255 - a)) // 255
                out[i + 3] = 255
            px = out
        n = write_png(args.out, px, t.width, t.height)
        print('  %d pixels decoded -> %s, %d bytes%s'
              % (t.width * t.height, args.out, n,
                 '  (composited over grey %d)' % args.matte
                 if args.matte is not None else ''))
        return 0
    raise Refused('no Texture2D named %r' % args.name)


def cmd_census(args):
    fmt = collections.Counter()
    fby = collections.Counter()
    n = closes = 0
    px = 0
    for _p, t in textures(args.paths):
        n += 1
        fmt[t.format] += 1
        fby[t.format] += t.data_size
        px += t.width * t.height
        if t.closes:
            closes += 1
    print('Texture2D objects : %d' % n)
    print('closing on m_CompleteImageSize and the body end : %d of %d'
          % (closes, n))
    print('top-mip pixels    : %d' % px)
    print()
    print('%-10s %7s %14s' % ('FORMAT', 'COUNT', 'BYTES'))
    tot = totb = 0
    for f in sorted(fmt):
        print('%-10s %7d %14d' % (FORMAT.get(f, str(f)), fmt[f], fby[f]))
        tot += fmt[f]
        totb += fby[f]
    print('%-10s %7d %14d' % ('TOTAL', tot, totb))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'list', 'extract', 'census'))
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--name')
    ap.add_argument('--out')
    ap.add_argument('--limit', type=int, default=40)
    ap.add_argument('--matte', type=int,
                    help='composite over this grey level (0-255) so that '
                         'white-on-alpha art is visible; changes the pixels')
    args = ap.parse_args()
    if args.mode != 'selftest' and not args.paths:
        ap.error('%s needs a path' % args.mode)
    if args.mode == 'extract' and not (args.name and args.out):
        ap.error('extract needs --name and --out')
    try:
        return globals()['cmd_' + args.mode](args)
    except Refused as ex:
        sys.stderr.write('REFUSED: %s\n' % ex)
        return 2


if __name__ == '__main__':
    sys.exit(main())
