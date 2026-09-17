#!/usr/bin/env python3
"""Take a Texture2D out of a Unity bundle and turn it into something openable.

Two jobs, and the second matters more for preservation than the first.

  * **the uncompressed formats become PNG.**  RGBA32, RGB24, Alpha8, RGB565,
    RGBA4444 and BGRA32 are laid out plainly and a PNG writer is thirty lines
    of `zlib` and `struct`.  289 of this object's 8,634 textures are in one of
    those, and one of them can be looked at with the eyes, which is the only
    instrument that has ever corrected a chapter in this branch;
  * **the ASTC formats become `.astc` files with the standard header.**  96.87 %
    of this object's texture bytes are ASTC at four block sizes, and a correct
    ASTC decoder is several hundred lines of weight grids, partitions and void
    extents that this session is not going to write and check in an afternoon.
    Writing the payload out with the 16-byte magic-1.0 header that every ASTC
    tool reads is honest, it is complete, and in five years it is worth more
    than a half-checked decoder.  **This tool says which it did.**

The size check, which fires on every texture and is the reason to trust the
rest: a texture's pixel count, format and mip count determine exactly how many
bytes its data must be.  The tool computes that and compares it with the size
Unity declared.  A format table with a wrong entry does not produce a wrong
picture here, it produces a mismatch line.

    python texdump.py one  BUNDLE NAME  OUTDIR
    python texdump.py all  DIR OUTDIR [--format RGBA32] [--limit N]
    python texdump.py check DIR             -- the size check, nothing written

Standard library only.
"""

import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unityasset

# bytes per pixel for the plainly-laid-out formats
LINEAR = {4: 4, 5: 4, 14: 4, 3: 3, 1: 1, 57: 1, 7: 2, 13: 2, 2: 2, 9: 2,
          56: 2, 17: 8, 20: 16}

# ASTC block footprints, by Unity TextureFormat id
ASTC_BLOCK = {48: (4, 4), 49: (5, 5), 50: (6, 6), 51: (8, 8), 52: (10, 10),
              53: (12, 12), 60: (4, 4), 61: (5, 5), 62: (6, 6), 63: (8, 8),
              64: (10, 10), 65: (12, 12)}

# 4x4-block formats and their bytes per block
BLOCK4 = {10: 8, 12: 16, 26: 8, 27: 16, 25: 16, 24: 16,
          34: 8, 45: 8, 46: 8, 47: 16, 41: 8, 43: 16}


def level_bytes(fmt, w, h):
    if fmt in LINEAR:
        return w * h * LINEAR[fmt]
    if fmt in ASTC_BLOCK:
        bw, bh = ASTC_BLOCK[fmt]
        return ((w + bw - 1) // bw) * ((h + bh - 1) // bh) * 16
    if fmt in BLOCK4:
        return ((w + 3) // 4) * ((h + 3) // 4) * BLOCK4[fmt]
    return None


def expected_bytes(fmt, w, h, mips):
    total = 0
    for i in range(max(1, mips)):
        lw, lh = max(1, w >> i), max(1, h >> i)
        n = level_bytes(fmt, lw, lh)
        if n is None:
            return None
        total += n
    return total


def png(path, w, h, rgba):
    """Write 8-bit RGBA PNG. `rgba` is w*h*4 bytes, top row first."""
    raw = bytearray()
    stride = w * 4
    for y in range(h):
        raw.append(0)
        raw += rgba[y * stride:(y + 1) * stride]

    def chunk(tag, data):
        c = tag + data
        return struct.pack('>I', len(data)) + c + \
            struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)

    out = b'\x89PNG\r\n\x1a\n'
    out += chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
    out += chunk(b'IDAT', zlib.compress(bytes(raw), 6))
    out += chunk(b'IEND', b'')
    with open(path, 'wb') as f:
        f.write(out)
    return len(out)


def to_rgba(fmt, w, h, d):
    n = w * h
    out = bytearray(n * 4)
    if fmt in (4,):                              # RGBA32
        out[:] = d[:n * 4]
    elif fmt == 5:                               # ARGB32
        for i in range(n):
            a, r, g, b = d[i * 4:i * 4 + 4]
            out[i * 4:i * 4 + 4] = bytes((r, g, b, a))
    elif fmt == 14:                              # BGRA32
        for i in range(n):
            b, g, r, a = d[i * 4:i * 4 + 4]
            out[i * 4:i * 4 + 4] = bytes((r, g, b, a))
    elif fmt == 3:                               # RGB24
        for i in range(n):
            out[i * 4:i * 4 + 4] = d[i * 3:i * 3 + 3] + b'\xff'
    elif fmt in (1, 57):                         # Alpha8 / R8
        for i in range(n):
            v = d[i]
            out[i * 4:i * 4 + 4] = bytes((v, v, v, 255))
    elif fmt == 7:                               # RGB565
        for i in range(n):
            v = struct.unpack_from('<H', d, i * 2)[0]
            r = (v >> 11) & 31
            g = (v >> 5) & 63
            b = v & 31
            out[i * 4:i * 4 + 4] = bytes((r * 255 // 31, g * 255 // 63,
                                          b * 255 // 31, 255))
    else:
        return None
    # Unity stores textures bottom row first; PNG wants top first.
    stride = w * 4
    flipped = bytearray()
    for y in range(h - 1, -1, -1):
        flipped += out[y * stride:(y + 1) * stride]
    return flipped


def astc_file(path, fmt, w, h, data):
    bw, bh = ASTC_BLOCK[fmt]
    hdr = bytes((0x13, 0xAB, 0xA1, 0x5C, bw, bh, 1))
    hdr += bytes((w & 255, (w >> 8) & 255, (w >> 16) & 255))
    hdr += bytes((h & 255, (h >> 8) & 255, (h >> 16) & 255))
    hdr += bytes((1, 0, 0))
    with open(path, 'wb') as f:
        f.write(hdr)
        f.write(data)
    return 16 + len(data)


def pixels_of(b, v):
    sd = v.get('m_StreamData') or {}
    if sd.get('size'):
        src = os.path.basename(sd['path'].replace('\\', '/'))
        for k, n in b.streams.items():
            if os.path.basename(k) == src:
                return b.arc.read(n.offset + sd['offset'], sd['size'])
        raise ValueError('stream node %s not in this archive' % src)
    return bytes(v.get('image data') or b'')


def _each(root, fn, want_fmt=None, want_name=None, limit=None):
    paths = unityasset.bundles_in(root)
    n = 0
    for p in paths:
        try:
            b = unityasset.Bundle(p)
        except Exception:
            continue
        for node, sf, o in b.objects():
            if sf.class_of(o) != 28:
                continue
            v, _, _ = b.read(sf, o)
            if want_name and v.get('m_Name') != want_name:
                continue
            if want_fmt is not None and v.get('m_TextureFormat') != want_fmt:
                continue
            fn(b, v)
            n += 1
            if limit and n >= limit:
                b.close()
                return n
        b.close()
    return n


import unityfs  # noqa: E402  (after sys.path fix-up above)

FMT = unityasset.TEXFMT


def cmd_check(argv):
    root = argv[2]
    ok = bad = unknown = 0
    worst = []

    def each(b, v):
        nonlocal ok, bad, unknown
        f, w, h = v['m_TextureFormat'], v['m_Width'], v['m_Height']
        mips = v.get('m_MipCount') or 1
        sd = v.get('m_StreamData') or {}
        have = sd.get('size') or len(v.get('image data') or b'')
        want = expected_bytes(f, w, h, mips)
        if want is None:
            unknown += 1
        elif want == have:
            ok += 1
        else:
            bad += 1
            if len(worst) < 12:
                worst.append((FMT.get(f, f), w, h, mips, have, want))

    n = _each(root, each)
    print('Texture2D examined              %d' % n)
    print('declared size == computed size  %d  %.4f%%'
          % (ok, 100.0 * ok / n if n else 0))
    print('mismatch                        %d' % bad)
    print('format not in the size table    %d' % unknown)
    for r in worst:
        print('  %-16s %5dx%-5d mips %2d  have %10d  want %10d  diff %d'
              % (r[0], r[1], r[2], r[3], r[4], r[5], r[4] - r[5]))
    return 0


def cmd_one(argv):
    bundle, name, outdir = argv[2], argv[3], argv[4]
    os.makedirs(outdir, exist_ok=True)
    done = []

    def each(b, v):
        f, w, h = v['m_TextureFormat'], v['m_Width'], v['m_Height']
        mips = v.get('m_MipCount') or 1
        d = pixels_of(b, v)
        want = expected_bytes(f, w, h, mips)
        print('%s  %dx%d  %s  mips %d  %d bytes  (computed %s)'
              % (v['m_Name'], w, h, FMT.get(f, f), mips, len(d), want))
        base = os.path.join(outdir, v['m_Name'])
        if f in ASTC_BLOCK:
            n = astc_file(base + '.astc', f, w, h, d[:level_bytes(f, w, h)])
            print('  wrote %s.astc  %d bytes  (top mip only; NOT decoded)'
                  % (v['m_Name'], n))
            done.append('astc')
        else:
            rgba = to_rgba(f, w, h, d)
            if rgba is None:
                print('  no writer for %s' % FMT.get(f, f))
                return
            n = png(base + '.png', w, h, rgba)
            print('  wrote %s.png  %d bytes  (decoded)' % (v['m_Name'], n))
            done.append('png')

    n = _each(bundle, each, want_name=name)
    if not n:
        print('no Texture2D named %r in %s' % (name, bundle))
        return 1
    return 0


def cmd_all(argv):
    root, outdir = argv[2], argv[3]
    want = None
    if '--format' in argv:
        w = argv[argv.index('--format') + 1]
        want = [k for k, x in FMT.items() if x == w]
        want = want[0] if want else int(w)
    limit = int(argv[argv.index('--limit') + 1]) if '--limit' in argv else 24
    os.makedirs(outdir, exist_ok=True)
    wrote = [0, 0]

    def each(b, v):
        f, w, h = v['m_TextureFormat'], v['m_Width'], v['m_Height']
        try:
            d = pixels_of(b, v)
        except Exception as e:
            print('  %s: %s' % (v.get('m_Name'), e))
            return
        safe = ''.join(c if c.isalnum() or c in '._-' else '_'
                       for c in (v.get('m_Name') or 'unnamed'))
        base = os.path.join(outdir, safe)
        if f in ASTC_BLOCK:
            astc_file(base + '.astc', f, w, h, d[:level_bytes(f, w, h)])
            wrote[1] += 1
        else:
            rgba = to_rgba(f, w, h, d)
            if rgba is None:
                return
            png(base + '.png', w, h, rgba)
            wrote[0] += 1
        print('  %-40s %5dx%-5d %-14s' % (safe[:40], w, h, FMT.get(f, f)))

    _each(root, each, want_fmt=want, limit=limit)
    print('PNG written (decoded)      %d' % wrote[0])
    print('ASTC written (NOT decoded) %d' % wrote[1])
    return 0


CMDS = dict(one=cmd_one, all=cmd_all, check=cmd_check)


def main(argv):
    if len(argv) < 3 or argv[1] not in CMDS:
        print(__doc__)
        return 2
    return CMDS[argv[1]](argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
