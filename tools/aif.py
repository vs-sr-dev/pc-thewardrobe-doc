#!/usr/bin/env python3
"""
aif.py - reader for AIF textures as shipped by Tales of Crestoria (Android).

AIF is tri-Ace's texture wrapper, carried over from the studio's console engine.
The Xbox 360 form is big-endian and wraps a tiled Xenos surface; the Android
form documented here keeps the same field layout inside the `imgX` sub-chunk but
writes it little-endian, with the fourccs byte-reversed (the file opens with the
bytes " FIA"), and stores a plain GLES texture instead. Every texture in the
Crestoria APK is 8 bpp with 16-byte 4x4 elements: ETC2 RGBA8 with EAC alpha, the
format GLES 3.0 guarantees. See docs/formats/aif.md.

Decodes to PNG with nothing but the standard library.
"""
import argparse, os, struct, zlib

TAG_AIF = b' FIA'    # 'AIF ' reversed
TAG_IMGX = b'Xgmi'   # 'imgX' reversed


class AifError(Exception):
    pass


class Texture:
    __slots__ = ('asset_id', 'fmt', 'flags', 'width', 'height', 'depth', 'bpp',
                 'bytes_per_elem', 'elem_w', 'elem_h', 'pitch', 'base_size',
                 'data_offset', 'raw')

    def describe(self):
        kind = 'ETC2_RGBA8' if self.bpp == 8 and self.bytes_per_elem == 16 else 'fmt0x%x' % self.fmt
        return ('%s %dx%d bpp=%d elem=%dB (%dx%d elems) pitch=%d base=%d id=%s'
                % (kind, self.width, self.height, self.bpp, self.bytes_per_elem,
                   self.elem_w, self.elem_h, self.pitch, self.base_size, self.asset_id))


def parse(data):
    if data[:4] != TAG_AIF:
        raise AifError('not an AIF (magic %r)' % data[:4])
    i = data.find(TAG_IMGX)
    if i < 0:
        raise AifError('no imgX sub-chunk')
    t = Texture()
    t.asset_id = data[i + 0x14:i + 0x18][::-1].decode('ascii', 'replace')
    t.fmt, t.flags = struct.unpack_from('<II', data, i + 0x20)
    (t.width, t.height, t.depth, t.bpp, t.bytes_per_elem,
     t.elem_w, t.elem_h, _one) = struct.unpack_from('<8H', data, i + 0x28)
    t.pitch, t.base_size = struct.unpack_from('<II', data, i + 0x38)
    t.data_offset = len(data) - t.base_size
    t.raw = data[t.data_offset:t.data_offset + t.base_size]
    return t


# ------------------------------------------------------------------ ETC2 / EAC

_ETC1_MOD = ((2, 8, -2, -8), (5, 17, -5, -17), (9, 29, -9, -29), (13, 42, -13, -42),
             (18, 60, -18, -60), (24, 80, -24, -80), (33, 106, -33, -106),
             (47, 183, -47, -183))
_ETC2_DIST = (3, 6, 11, 16, 23, 32, 41, 64)
_EAC_MOD = ((-3, -6, -9, -15, 2, 5, 8, 14), (-3, -7, -10, -13, 2, 6, 9, 13),
            (-2, -5, -8, -13, 1, 4, 7, 12), (-2, -4, -6, -13, 1, 3, 5, 12),
            (-3, -6, -8, -12, 2, 5, 7, 11), (-3, -7, -9, -11, 2, 6, 8, 10),
            (-4, -7, -8, -11, 3, 6, 7, 10), (-3, -5, -8, -11, 2, 4, 7, 10),
            (-2, -6, -8, -10, 1, 5, 7, 9), (-2, -5, -8, -10, 1, 4, 7, 9),
            (-2, -4, -8, -10, 1, 3, 7, 9), (-2, -5, -7, -10, 1, 4, 6, 9),
            (-3, -4, -7, -10, 2, 3, 6, 9), (-1, -2, -3, -10, 0, 1, 2, 9),
            (-4, -6, -8, -9, 3, 5, 7, 8), (-3, -5, -7, -9, 2, 4, 6, 8))


def _c(v):
    return 0 if v < 0 else (255 if v > 255 else v)


def _ext4(v):
    return (v << 4) | v


def _ext5(v):
    return (v << 3) | (v >> 2)


def _ext6(v):
    return (v << 2) | (v >> 4)


def _ext7(v):
    return (v << 1) | (v >> 6)


def _s3(v):
    return v - 8 if v >= 4 else v


def _etc1_paint(c1, c2, t1, t2, flip, idx_hi, idx_lo, out):
    m1, m2 = _ETC1_MOD[t1], _ETC1_MOD[t2]
    for i in range(16):
        x, y = i >> 2, i & 3
        second = (y >= 2) if flip else (x >= 2)
        base, mod = (c2, m2) if second else (c1, m1)
        d = mod[(((idx_hi >> i) & 1) << 1) | ((idx_lo >> i) & 1)]
        out[i] = (_c(base[0] + d), _c(base[1] + d), _c(base[2] + d))


def _paint4(p, idx_hi, idx_lo, out):
    for i in range(16):
        out[i] = p[(((idx_hi >> i) & 1) << 1) | ((idx_lo >> i) & 1)]


def _etc2_t(b, idx_hi, idx_lo, out):
    r0, r1, r2, r3 = b[0], b[1], b[2], b[3]
    c1 = (_ext4(((r0 & 0x18) >> 1) | (r0 & 3)), _ext4(r1 >> 4), _ext4(r1 & 15))
    c2 = (_ext4(r2 >> 4), _ext4(r2 & 15), _ext4(r3 >> 4))
    d = _ETC2_DIST[((r3 >> 1) & 6) | (r3 & 1)]
    p = (c1, tuple(_c(v + d) for v in c2), c2, tuple(_c(v - d) for v in c2))
    _paint4(p, idx_hi, idx_lo, out)


def _etc2_h(b, idx_hi, idx_lo, out):
    r0, r1, r2, r3 = b[0], b[1], b[2], b[3]
    c1 = (_ext4((r0 >> 3) & 15),
          _ext4(((r0 << 1) & 14) | ((r1 >> 4) & 1)),
          _ext4((r1 & 8) | ((r1 << 1) & 6) | ((r2 >> 7) & 1)))
    c2 = (_ext4((r2 >> 3) & 15),
          _ext4(((r2 << 1) & 14) | (r3 >> 7)),
          _ext4((r3 >> 3) & 15))
    di = (r3 & 4) | ((r3 << 1) & 2)
    if ((c1[0] << 16) | (c1[1] << 8) | c1[2]) >= ((c2[0] << 16) | (c2[1] << 8) | c2[2]):
        di |= 1
    d = _ETC2_DIST[di]
    p = (tuple(_c(v + d) for v in c1), tuple(_c(v - d) for v in c1),
         tuple(_c(v + d) for v in c2), tuple(_c(v - d) for v in c2))
    _paint4(p, idx_hi, idx_lo, out)


def _etc2_planar(b, out):
    r0, r1, r2, r3, r4, r5, r6, r7 = b
    ro = _ext6((r0 >> 1) & 0x3F)
    go = _ext7(((r0 & 1) << 6) | ((r1 >> 1) & 0x3F))
    bo = _ext6(((r1 & 1) << 5) | (r2 & 0x18) | ((r2 << 1) & 6) | ((r3 >> 7) & 1))
    rh = _ext6(((r3 >> 1) & 0x3E) | (r3 & 1))
    gh = _ext7(r4 >> 1)
    bh = _ext6(((r4 & 1) << 5) | (r5 >> 3))
    rv = _ext6(((r5 & 7) << 3) | (r6 >> 5))
    gv = _ext7(((r6 & 0x1F) << 2) | (r7 >> 6))
    bv = _ext6(r7 & 0x3F)
    for y in range(4):
        for x in range(4):
            out[x * 4 + y] = (
                _c((x * (rh - ro) + y * (rv - ro) + 4 * ro + 2) >> 2),
                _c((x * (gh - go) + y * (gv - go) + 4 * go + 2) >> 2),
                _c((x * (bh - bo) + y * (bv - bo) + 4 * bo + 2) >> 2))


def _etc2_rgb(b, out):
    """Decode one 8-byte ETC2 RGB block into out[16] as (r, g, b) tuples."""
    r0, r1, r2, r3 = b[0], b[1], b[2], b[3]
    idx_hi = (b[4] << 8) | b[5]
    idx_lo = (b[6] << 8) | b[7]
    diff, flip = r3 & 2, r3 & 1
    if not diff:
        c1 = (_ext4(r0 >> 4), _ext4(r1 >> 4), _ext4(r2 >> 4))
        c2 = (_ext4(r0 & 15), _ext4(r1 & 15), _ext4(r2 & 15))
        _etc1_paint(c1, c2, (r3 >> 5) & 7, (r3 >> 2) & 7, flip, idx_hi, idx_lo, out)
        return
    r, dr = r0 >> 3, _s3(r0 & 7)
    g, dg = r1 >> 3, _s3(r1 & 7)
    bl, db = r2 >> 3, _s3(r2 & 7)
    if not 0 <= r + dr <= 31:
        _etc2_t(b, idx_hi, idx_lo, out)
        return
    if not 0 <= g + dg <= 31:
        _etc2_h(b, idx_hi, idx_lo, out)
        return
    if not 0 <= bl + db <= 31:
        _etc2_planar(b, out)
        return
    c1 = (_ext5(r), _ext5(g), _ext5(bl))
    c2 = (_ext5(r + dr), _ext5(g + dg), _ext5(bl + db))
    _etc1_paint(c1, c2, (r3 >> 5) & 7, (r3 >> 2) & 7, flip, idx_hi, idx_lo, out)


def _eac_alpha(b, out):
    base, mult, tbl = b[0], b[1] >> 4, b[1] & 15
    bits = int.from_bytes(b[2:8], 'big')
    mod = _EAC_MOD[tbl]
    for i in range(16):
        out[i] = _c(base + mod[(bits >> (45 - 3 * i)) & 7] * mult)


def decode_etc2_rgba8(raw, width, height):
    """Return RGBA bytes for an ETC2_RGBA8_EAC surface."""
    bw, bh = (width + 3) // 4, (height + 3) // 4
    img = bytearray(width * height * 4)
    rgb = [(0, 0, 0)] * 16
    alpha = [0] * 16
    stride = width * 4
    k = 0
    for by in range(bh):
        for bx in range(bw):
            blk = raw[k:k + 16]
            k += 16
            _eac_alpha(blk, alpha)
            _etc2_rgb(blk[8:16], rgb)
            for i in range(16):
                px, py = bx * 4 + (i >> 2), by * 4 + (i & 3)
                if px >= width or py >= height:
                    continue
                o = py * stride + px * 4
                r, g, b = rgb[i]
                img[o] = r
                img[o + 1] = g
                img[o + 2] = b
                img[o + 3] = alpha[i]
    return bytes(img)


def write_png(path, width, height, rgba):
    def chunk(tag, payload):
        return (struct.pack('>I', len(payload)) + tag + payload
                + struct.pack('>I', zlib.crc32(tag + payload) & 0xFFFFFFFF))
    rows = bytearray()
    stride = width * 4
    for y in range(height):
        rows.append(0)
        rows += rgba[y * stride:(y + 1) * stride]
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)))
        f.write(chunk(b'IDAT', zlib.compress(bytes(rows), 6)))
        f.write(chunk(b'IEND', b''))


def _walk(paths):
    for path in paths:
        if os.path.isdir(path):
            for dp, _, fn in os.walk(path):
                for x in sorted(fn):
                    if x.lower().endswith('.aif'):
                        yield os.path.join(dp, x)
        else:
            yield path


def cmd_info(args):
    for f in _walk(args.paths):
        try:
            print('%-46s %s' % (os.path.relpath(f), parse(open(f, 'rb').read()).describe()))
        except AifError as e:
            print('%-46s !! %s' % (os.path.relpath(f), e))


def cmd_decode(args):
    os.makedirs(args.out, exist_ok=True)
    for f in _walk(args.paths):
        t = parse(open(f, 'rb').read())
        if not (t.bpp == 8 and t.bytes_per_elem == 16):
            print('skip %s: unsupported %s' % (f, t.describe()))
            continue
        rgba = decode_etc2_rgba8(t.raw, t.width, t.height)
        dst = os.path.join(args.out, os.path.splitext(os.path.basename(f))[0] + '.png')
        write_png(dst, t.width, t.height, rgba)
        print('%s -> %s  (%dx%d)' % (os.path.basename(f), dst, t.width, t.height))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('info', help='print texture headers')
    p.add_argument('paths', nargs='+')
    p.set_defaults(fn=cmd_info)
    p = sub.add_parser('decode', help='decode to PNG')
    p.add_argument('paths', nargs='+')
    p.add_argument('-o', '--out', required=True)
    p.set_defaults(fn=cmd_decode)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
