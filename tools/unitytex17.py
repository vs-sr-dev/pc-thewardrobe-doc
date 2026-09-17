#!/usr/bin/env python3
"""unitytex17.py -- decode `Texture2D` objects out of a version-17 Unity
SerializedFile (Unity 5.5), whose pixels sit in a `.resS` sidecar named by
`m_StreamData`, and write them as PNG.

WHY A SECOND TEXTURE TOOL
-------------------------
`unitytex.py` was written on pc-iamsetsuna-doc for serialization version 15
(Unity 5.2), where the pixels follow the header inside the object body.  At
version 17 the body is the same to the last field and then goes on: after
`imageDataSize` (which is 0 for 743 of this object's 822 textures) comes
`m_StreamData` -- u32 offset, u32 size, aligned string path -- and the pixels
live in the sidecar the path names, beside the serialized file.  Read with the
version-15 layout the body simply ends early and every streamed texture
reports zero bytes; read with a 2019 layout (`unityfs.py`'s
`read_texture2d`, which expects `m_ForcedFallbackFormat`, three bools and
three wrap modes that 5.5 does not write) every field after the name is
wrong.  This reader was written from a hex dump of the first three bodies
(`UISprite`, `Background`, `Knob` in `sharedassets0.assets`), field by field,
and closes twice on every texture before a pixel is claimed.

The Texture2D body at serialization version 17, as measured on this object
-----------------------------------------------------------------------------

    aligned string  m_Name
    i32             m_Width
    i32             m_Height
    i32             m_CompleteImageSize   -- every mip level, summed
    i32             m_TextureFormat
    i32             m_MipCount
    u8              m_IsReadable
    u8              m_ReadAllowed
    align 4
    i32             m_ImageCount
    i32             m_TextureDimension    -- 2
    i32             m_FilterMode
    i32             m_Aniso
    f32             m_MipBias
    i32             m_WrapMode            -- ONE wrap mode; U/V/W came in 2017
    i32             m_LightmapFormat
    i32             m_ColorSpace
    i32             imageDataSize         -- 0 when the pixels are streamed
    ...             imageDataSize bytes, then align 4
    u32             m_StreamData.offset   -- into the sidecar
    u32             m_StreamData.size
    aligned string  m_StreamData.path     -- e.g. `sharedassets2.assets.resS`

THE TWO CLOSURES.  First, the body must end at the last byte of the path
plus 0..3 bytes of alignment padding: a layout error anywhere above moves that
end by more than three.  Second, `m_CompleteImageSize` must equal the block
or linear arithmetic of width x height x format over every mip level, and
when the pixels are streamed `m_StreamData.size` must equal it too.  On this
object both hold on 822 of 822 -- `census` prints the counts and a texture
that fails either is listed by name rather than decoded.  It is the second
closure that settles what format 10 is: at 4 bits per pixel (DXT1) the 39
textures of that format close; at 8 (the DXT3 that `unityfs.py`'s table names
for 10) none would.  Unity's own enum has no DXT3 at all.

The formats decoded are the seven this object uses, and the block decoders and
the PNG writer are `unitytex.py`'s, imported and not copied: Alpha8 (1),
ARGB4444 (2), RGB24 (3), RGBA32 (4), ARGB32 (5), DXT1 (10), DXT5 (12).  A
format outside the list is refused by number.

    python tools/unitytex17.py list    FILE|DIR
    python tools/unitytex17.py census  DIR
    python tools/unitytex17.py extract FILE --name NAME --out OUT.png [--mip N]
    python tools/unitytex17.py sidecars DIR      -- how the records tile each .resS
    python tools/unitytex17.py selftest

`--mip N` decodes mip level N instead of 0: a 4096 x 4096 DXT5 is a million
blocks, which the pure-Python decoder takes a minute over, and its mip 2 is
the same picture at 1024 x 1024 in four seconds.  The level decoded is
written into the PNG's name of record by the caller, not hidden.

Standard library only, plus `unityfs.py`, `unitytex.py`, `dirguard.py` and
`nameguard.py` from this folder.
"""

import argparse
import collections
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                            # noqa: E402
import nameguard                                           # noqa: E402
import unityfs                                             # noqa: E402
import unitytex                                            # noqa: E402

nameguard.guard()

FORMAT = {1: 'Alpha8', 2: 'ARGB4444', 3: 'RGB24', 4: 'RGBA32', 5: 'ARGB32',
          7: 'RGB565', 9: 'R16', 10: 'DXT1', 12: 'DXT5', 13: 'RGBA4444',
          14: 'BGRA32'}
BPP = {1: 8, 2: 16, 3: 24, 4: 32, 5: 32, 7: 16, 9: 16, 10: 4, 12: 8, 13: 16,
       14: 32}
BLOCK = {10: 8, 12: 16}          # bytes per 4 x 4 block
DECODABLE = (1, 2, 3, 4, 5, 7, 10, 12)


class Refused(Exception):
    pass


def level_bytes(fmt, w, h):
    """Bytes of one mip level, by the format's arithmetic; None if unknown.

    A 0 x 0 texture is 0 bytes: the nine `Font Texture` objects of this
    object are dynamic font atlases with no pixels at build time, and a
    reader that rounds them up to 1 x 1 fails its own arithmetic on them.
    """
    if w == 0 or h == 0:
        return 0
    if fmt in BLOCK:
        return ((w + 3) // 4) * ((h + 3) // 4) * BLOCK[fmt]
    if fmt in BPP:
        return w * h * BPP[fmt] // 8
    return None


def mip_sizes(fmt, w, h, mips):
    out = []
    if w == 0 or h == 0:
        return [0]
    for lv in range(max(1, mips)):
        lw, lh = max(1, w >> lv), max(1, h >> lv)
        n = level_bytes(fmt, lw, lh)
        if n is None:
            return None
        out.append(n)
    return out


class Texture(object):
    """One Texture2D body at version 17, with both closures evaluated."""

    def __init__(self, body, little=True, cubemap=False):
        b = body
        self.cubemap = cubemap
        e = '<' if little else '>'
        if len(b) < 4:
            raise Refused('a %d-byte body' % len(b))
        n, = struct.unpack_from(e + 'i', b, 0)
        if not 0 <= n <= 4096 or 4 + n > len(b):
            raise Refused('m_Name length %d in a %d-byte body' % (n, len(b)))
        self.name = b[4:4 + n].decode('utf-8', 'replace')
        p = (4 + n + 3) & ~3
        if p + 20 > len(b):
            raise Refused('body ends inside the size fields')
        (self.width, self.height, self.complete, self.format,
         self.mips) = struct.unpack_from(e + '5i', b, p)
        p += 20
        self.is_readable, self.read_allowed = b[p], b[p + 1]
        p = (p + 2 + 3) & ~3
        (self.image_count, self.dimension, self.filter_mode,
         self.aniso) = struct.unpack_from(e + '4i', b, p)
        p += 16
        self.mip_bias, = struct.unpack_from(e + 'f', b, p)
        p += 4
        (self.wrap_mode, self.lightmap_format, self.colour_space,
         self.data_size) = struct.unpack_from(e + '4i', b, p)
        p += 16
        if self.data_size < 0 or p + self.data_size > len(b):
            raise Refused('imageDataSize %d runs past a %d-byte body'
                          % (self.data_size, len(b)))
        self.inline = b[p:p + self.data_size]
        p = (p + self.data_size + 3) & ~3
        if p + 12 > len(b):
            raise Refused('no room for m_StreamData after the image data')
        self.stream_offset, self.stream_size, pl = struct.unpack_from(
            e + 'IIi', b, p)
        if not 0 <= pl <= 1024 or p + 12 + pl > len(b):
            raise Refused('m_StreamData.path length %d' % pl)
        self.stream_path = b[p + 12:p + 12 + pl].decode('utf-8', 'replace')
        end = p + 12 + pl
        if cubemap:
            # Cubemap (89) is a Texture2D body followed by m_SourceTextures:
            # i32 count, then count PPtr of 12 bytes (i32 fileID, i64
            # pathID). The stream holds m_ImageCount faces, each of
            # m_CompleteImageSize.
            q = (end + 3) & ~3
            if q + 4 > len(b):
                raise Refused('no room for m_SourceTextures')
            self.source_count, = struct.unpack_from(e + 'i', b, q)
            if not 0 <= self.source_count <= 64:
                raise Refused('m_SourceTextures count %d' % self.source_count)
            end = q + 4 + 12 * self.source_count
        self.padding = len(b) - end
        self.closed = 0 <= self.padding <= 3
        sizes = mip_sizes(self.format, self.width, self.height, self.mips)
        self.mip_bytes = sizes
        self.expected = sum(sizes) if sizes else None
        faces = self.image_count if cubemap else 1
        self.arith = (self.expected == self.complete
                      and (self.data_size == self.complete * faces
                           if self.data_size else
                           self.stream_size == self.complete * faces))
        self.streamed = self.data_size == 0 and self.stream_size > 0

    def where(self):
        if self.streamed:
            return '%s+%d' % (self.stream_path, self.stream_offset)
        if self.data_size:
            return 'inline'
        return 'none'


def pixels(tex, sf_path):
    """The whole image-data block: inline, or read out of the sidecar."""
    if tex.data_size:
        return bytes(tex.inline)
    if not tex.streamed:
        raise Refused('%s has no pixels: imageDataSize 0 and no stream'
                      % tex.name)
    side = os.path.join(os.path.dirname(sf_path), tex.stream_path)
    if not os.path.isfile(side):
        raise Refused('%s names %s, which is not beside %s'
                      % (tex.name, tex.stream_path,
                         os.path.basename(sf_path)))
    if tex.stream_offset + tex.stream_size > os.path.getsize(side):
        raise Refused('%s: record %d+%d runs past %s'
                      % (tex.name, tex.stream_offset, tex.stream_size,
                         tex.stream_path))
    with open(side, 'rb') as f:
        f.seek(tex.stream_offset)
        return f.read(tex.stream_size)


def decode(tex, data, mip=0):
    """RGBA rows, top-down, of one mip level."""
    if tex.format not in DECODABLE:
        raise Refused('format %d (%s) is not decoded by this tool'
                      % (tex.format, FORMAT.get(tex.format, '?')))
    if not tex.closed or not tex.arith:
        raise Refused('%s does not close (padding %d, arithmetic %s); '
                      'not decoding' % (tex.name, tex.padding, tex.arith))
    if not 0 <= mip < len(tex.mip_bytes):
        raise Refused('%s has %d mip levels, not %d'
                      % (tex.name, len(tex.mip_bytes), mip + 1))
    start = sum(tex.mip_bytes[:mip])
    w, h = max(1, tex.width >> mip), max(1, tex.height >> mip)
    d = data[start:start + tex.mip_bytes[mip]]
    if len(d) != tex.mip_bytes[mip]:
        raise Refused('%s: mip %d wants %d bytes, %d available'
                      % (tex.name, mip, tex.mip_bytes[mip], len(d)))
    if tex.format in BLOCK:
        return unitytex._dxt(d, w, h, tex.format == 12), w, h
    return unitytex._linear(d, w, h, tex.format), w, h


def textures_of(path):
    """Every Texture2D/Cubemap body of one file as `(Texture | Refused,
    obj)`; a whole file that this reader cannot take yields ONE
    `(Refused, None)` and stops. Two such refusals, both from
    pc-thewardrobe-doc: a file that is not a SerializedFile (`SaveIcon.png`
    passed the old `is_serialized` as "version 13" and `load` died with a
    `struct.error` that killed the census whole), and a SerializedFile
    whose format is not 17 -- this is the VERSION-17 layout, read from a
    hex dump of Monstrum's Unity 5.5 bodies; format 22 (Unity 6) has
    another layout and another reader, `unitytex22.py`. A wrong layout
    renders a plausible, wrong picture; refusing by name is the guard."""
    try:
        sf = unityfs.load(path)
    except unityfs.NotSerialized as e:
        yield Refused('not a SerializedFile: %s' % e), None
        return
    if sf.version != 17:
        yield Refused('%s is SerializedFile format %d (Unity %s); this reader '
                      'is the version-17 layout and refuses it -- format 22 is '
                      'unitytex22.py' % (os.path.basename(path), sf.version,
                                         sf.unity_version)), None
        return
    little = sf.endianness == 0
    for o in sf.objects:
        cid = sf.class_of(o)
        if cid not in (28, 89):
            continue
        try:
            yield Texture(sf.body(o), little, cubemap=(cid == 89)), o
        except Refused as e:
            yield e, o


def files_of(root):
    if os.path.isfile(root):
        return [root]
    return [p for p in unityfs.walk(root) if unityfs.is_serialized(p)]


# ------------------------------------------------------------------ commands

def cmd_list(args):
    if not os.path.isdir(args.path):
        dirguard.want_file(args.path, 'unitytex17')
    rows = 0
    print('%-40s %5s %5s %-8s %4s %11s %-5s %-5s  %s'
          % ('NAME', 'W', 'H', 'FORMAT', 'MIPS', 'BYTES', 'CLOSE', 'ARITH',
             'WHERE'))
    for p in files_of(args.path):
        rel = os.path.basename(p)
        for t, o in textures_of(p):
            if isinstance(t, Refused):
                print('%-40s REFUSED %s' % (rel, t))
                continue
            print('%-40s %5d %5d %-8s %4d %11d %-5s %-5s  %s'
                  % (t.name[:40], t.width, t.height,
                     FORMAT.get(t.format, str(t.format)), t.mips, t.complete,
                     'yes' if t.closed else 'NO', 'yes' if t.arith else 'NO',
                     t.where()))
            rows += 1
    print()
    print('%d Texture2D objects' % rows)
    return 0


def cmd_census(args):
    dirguard.want_tree(args.path, 'unitytex17')
    n = closed = arith = streamed = inline = 0
    fmt_n = collections.Counter()
    fmt_b = collections.Counter()
    side_n = collections.Counter()
    side_b = collections.Counter()
    size_n = collections.Counter()
    failed = []
    per_file = collections.Counter()
    total = 0
    cubes = 0
    refused_files = []
    for p in files_of(args.path):
        rel = os.path.relpath(p, args.path).replace(os.sep, '/')
        for t, o in textures_of(p):
            if isinstance(t, Refused):
                if o is None:
                    refused_files.append((rel, str(t)))
                else:
                    failed.append((rel, str(t)))
                continue
            n += 1
            cubes += t.cubemap
            per_file[rel] += 1
            closed += t.closed
            arith += bool(t.arith)
            if not (t.closed and t.arith):
                failed.append((rel, '%s: padding %d, expected %s, complete %d,'
                               ' stream %d' % (t.name, t.padding, t.expected,
                                               t.complete, t.stream_size)))
            fmt_n[t.format] += 1
            fmt_b[t.format] += t.complete
            total += t.complete
            size_n[(t.width, t.height)] += 1
            if t.streamed:
                streamed += 1
                side_n[t.stream_path] += 1
                side_b[t.stream_path] += t.stream_size
            elif t.data_size:
                inline += 1
                side_n['(inline in %s)' % rel] += 1
                side_b['(inline in %s)' % rel] += t.data_size
            else:
                side_n['(no pixels: %s)' % rel] += 1
    print('Texture2D objects        %d in %d serialized files (%d of them '
          'Cubemap, class 89, whose stream holds m_ImageCount faces)'
          % (n, len(per_file), cubes))
    print('closure (body end)       %d of %d' % (closed, n))
    print('closure (arithmetic)     %d of %d' % (arith, n))
    print('pixels streamed          %d   inline %d   none %d'
          % (streamed, inline, n - streamed - inline))
    print('bytes of pixels          %d (m_CompleteImageSize summed)' % total)
    print()
    print('%-4s %-10s %6s %14s' % ('FMT', 'NAME', 'COUNT', 'BYTES'))
    for f, c in fmt_n.most_common():
        print('%-4d %-10s %6d %14d' % (f, FORMAT.get(f, '?'), c, fmt_b[f]))
    print()
    print('%-40s %6s %14s' % ('WHERE', 'COUNT', 'BYTES'))
    for k, c in side_n.most_common():
        print('%-40s %6d %14d' % (k, c, side_b[k]))
    print()
    print('%-14s %6s' % ('SIZE', 'COUNT'))
    for (w, h), c in size_n.most_common(15):
        print('%-14s %6d' % ('%d x %d' % (w, h), c))
    print()
    print('%-32s %6s' % ('FILE', 'COUNT'))
    for k in sorted(per_file):
        print('%-32s %6d' % (k, per_file[k]))
    if failed:
        print()
        print('%d textures did not close or were refused:' % len(failed))
        for rel, why in failed:
            print('  %-28s %s' % (rel, why))
    if refused_files:
        print()
        print('%d FILES REFUSED WHOLE (not this reader\'s format):'
              % len(refused_files))
        for rel, why in refused_files:
            print('  %-28s %s' % (rel, why))
    return 0 if not (failed or refused_files) else 1


def cmd_extract(args):
    dirguard.want_file(args.path, 'unitytex17')
    for t, o in textures_of(args.path):
        if isinstance(t, Refused) and o is None:
            sys.exit('unitytex17: refused: %s' % t)
        if isinstance(t, Refused) or t.name != args.name:
            continue
        data = pixels(t, args.path)
        rgba, w, h = decode(t, data, args.mip)
        n = unitytex.write_png(args.out, rgba, w, h)
        print('%s: %d x %d %s, %d mips, %s; mip %d decoded to %d x %d; '
              '%s written, %d bytes'
              % (t.name, t.width, t.height, FORMAT.get(t.format, t.format),
                 t.mips, t.where(), args.mip, w, h, args.out, n))
        return 0
    sys.exit('unitytex17: no Texture2D named %r in %s'
             % (args.name, os.path.basename(args.path)))


def cmd_sidecars(args):
    """How the stream records tile each .resS: sorted by offset, gaps between
    them, overlaps, and the first and last byte reached."""
    dirguard.want_tree(args.path, 'unitytex17')
    recs = collections.defaultdict(list)
    for p in files_of(args.path):
        d = os.path.dirname(p)
        for t, o in textures_of(p):
            if isinstance(t, Refused) or not t.streamed:
                continue
            recs[os.path.join(d, t.stream_path)].append(
                (t.stream_offset, t.stream_size, t.name))
    print('%-28s %12s %5s %12s %10s %8s %8s %-8s'
          % ('SIDECAR', 'BYTES', 'RECS', 'REACHED', 'GAP BYTES', 'GAPS',
             'OVERLAP', 'ENDS AT'))
    for side in sorted(recs):
        rs = sorted(recs[side])
        size = os.path.getsize(side) if os.path.isfile(side) else -1
        pos = 0
        gaps = gap_bytes = overlaps = 0
        for off, sz, _n in rs:
            if off > pos:
                gaps += 1
                gap_bytes += off - pos
            elif off < pos:
                overlaps += 1
            pos = max(pos, off + sz)
        print('%-28s %12d %5d %12d %10d %8d %8d %-8s'
              % (os.path.basename(side), size, len(rs), pos, gap_bytes, gaps,
                 overlaps, 'file' if pos == size else 'short'))
    return 0


# ------------------------------------------------------------------ selftest

def _body(name, w, h, fmt, mips, inline=b'', stream=None):
    """A version-17 Texture2D body, as this tool reads it."""
    nb = name.encode('utf-8')
    b = struct.pack('<i', len(nb)) + nb
    b += bytes((-len(b)) % 4)
    sizes = mip_sizes(fmt, w, h, mips)
    total = sum(sizes) if sizes else len(inline)
    b += struct.pack('<5i', w, h, total, fmt, mips)
    b += bytes((0, 0, 0, 0))
    b += struct.pack('<4i', 1, 2, 1, 16) + struct.pack('<f', 0.0)
    b += struct.pack('<3i', 1, 6, 1)
    b += struct.pack('<i', len(inline)) + inline
    b += bytes((-len(b)) % 4)
    off, sz, path = stream if stream else (0, 0, '')
    pb = path.encode('utf-8')
    b += struct.pack('<IIi', off, sz, len(pb)) + pb
    b += bytes((-len(b)) % 4)
    return b


def cmd_selftest(_args):
    checks = []
    # 1. an inline 2 x 2 RGBA32 with one mip: parse, close, decode, PNG
    px = bytes((255, 0, 0, 255, 0, 255, 0, 255,      # bottom row in Unity
                0, 0, 255, 255, 255, 255, 255, 255))  # top row
    b = _body('two', 2, 2, 4, 1, inline=px)
    t = Texture(b)
    checks.append(('inline RGBA32 body parses and closes',
                   t.name == 'two' and t.closed and t.arith
                   and t.data_size == 16 and not t.streamed,
                   '%s %s %s' % (t.closed, t.arith, t.data_size)))
    rgba, w, h = decode(t, pixels(t, os.devnull))
    checks.append(('decode flips bottom-up to top-down',
                   bytes(rgba[:4]) == bytes((0, 0, 255, 255))
                   and bytes(rgba[8:12]) == bytes((255, 0, 0, 255)),
                   bytes(rgba[:4]).hex()))
    # 2. a streamed DXT1 4 x 4 with 3 mips, pixels in a temp sidecar
    tmp = tempfile.mkdtemp()
    try:
        # one DXT1 block: c0 = pure red 565, c1 = pure blue, all indices 0
        block = struct.pack('<HHI', 0xF800, 0x001F, 0)
        data = block + block + block      # 4x4, 2x2, 1x1: one block each
        side = os.path.join(tmp, 'sharedassets9.assets.resS')
        with open(side, 'wb') as f:
            f.write(bytes(64) + data)
        sizes = mip_sizes(10, 4, 4, 3)
        checks.append(('DXT1 4 x 4 with 3 mips is 8 + 8 + 8 bytes',
                       sizes == [8, 8, 8], str(sizes)))
        b2 = _body('red', 4, 4, 10, 3,
                   stream=(64, 24, 'sharedassets9.assets.resS'))
        t2 = Texture(b2)
        checks.append(('streamed DXT1 body closes on both counts',
                       t2.closed and t2.arith and t2.streamed
                       and t2.stream_path == 'sharedassets9.assets.resS',
                       '%s %s' % (t2.closed, t2.arith)))
        fake_sf = os.path.join(tmp, 'sharedassets9.assets')
        d2 = pixels(t2, fake_sf)
        checks.append(('the sidecar is read at the record offset',
                       d2 == data, d2.hex()))
        rgba2, w2, h2 = decode(t2, d2, 0)
        checks.append(('DXT1 index 0 everywhere is the c0 colour (red)',
                       (w2, h2) == (4, 4)
                       and all(bytes(rgba2[i:i + 4]) == bytes((255, 0, 0, 255))
                               for i in range(0, 64, 4)),
                       bytes(rgba2[:4]).hex()))
        rgba3, w3, h3 = decode(t2, d2, 2)
        checks.append(('--mip 2 of a 4 x 4 is 1 x 1',
                       (w3, h3) == (1, 1) and len(rgba3) == 4, '%dx%d' % (w3, h3)))
        # 3. refusals: a body one byte short of its path; a size that
        #    disagrees with the arithmetic; a record past the sidecar; a
        #    format this tool does not decode
        try:
            Texture(b2[:-4 - 1])
            checks.append(('a body cut inside the path is refused', False, ''))
        except Refused:
            checks.append(('a body cut inside the path is refused', True, ''))
        bad = bytearray(b2)
        struct.pack_into('<i', bad, 16, 999)          # m_CompleteImageSize
        t3 = Texture(bytes(bad))
        checks.append(('a CompleteImageSize off the arithmetic fails the '
                       'second closure and is not decoded',
                       t3.closed and not t3.arith
                       and _refuses(decode, t3, d2), ''))
        b4 = _body('far', 4, 4, 10, 3,
                   stream=(1000, 24, 'sharedassets9.assets.resS'))
        checks.append(('a record past the sidecar is refused',
                       _refuses(pixels, Texture(b4), fake_sf), ''))
        b5 = _body('half', 4, 4, 15, 1, inline=bytes(32))
        t5 = Texture(b5)
        checks.append(('an unknown format keeps its number and is refused',
                       t5.expected is None and not t5.arith
                       and _refuses(decode, t5, bytes(32)), ''))
        checks.append(('a body with 4 bytes of padding does not close',
                       not Texture(b2 + bytes(4)).closed, ''))
    finally:
        for n in os.listdir(tmp):
            os.remove(os.path.join(tmp, n))
        os.rmdir(tmp)
    checks.append(('a 0 x 0 texture (a dynamic font atlas) is 0 bytes and '
                   'closes with no pixels',
                   mip_sizes(4, 0, 0, 1) == [0]
                   and Texture(_body('Font Texture', 0, 0, 4, 1)).arith
                   and not Texture(_body('Font Texture', 0, 0, 4, 1)).streamed,
                   ''))
    cube = bytearray(_body('cube', 2, 2, 4, 1, stream=(0, 6 * 16, 'x.resS')))
    struct.pack_into('<i', cube, 32, 6)              # m_ImageCount = 6 faces
    cube += struct.pack('<i', 6) + bytes(72)         # 6 source PPtrs
    cube = bytes(cube)
    tc = Texture(cube, cubemap=True)
    checks.append(('a Cubemap body closes after 6 source PPtrs and its '
                   'stream is 6 faces of CompleteImageSize',
                   tc.closed and tc.arith and tc.source_count == 6
                   and tc.image_count == 6 and tc.complete == 16,
                   '%s %s %d %d' % (tc.closed, tc.arith, tc.source_count,
                                    tc.image_count)))
    checks.append(('the same body read as a Texture2D does NOT close',
                   not Texture(cube).closed, ''))
    checks.append(('format 10 is DXT1 at 4 bits per pixel, 12 is DXT5 at 8',
                   level_bytes(10, 1024, 1024) == 524288
                   and level_bytes(12, 1024, 1024) == 1048576, ''))
    checks.append(('a 4096 x 4096 DXT5 over 13 mips is 22,369,648 bytes -- '
                   'Brute_Diffuse_04 of this object',
                   sum(mip_sizes(12, 4096, 4096, 13)) == 22369648,
                   str(sum(mip_sizes(12, 4096, 4096, 13)))))
    # 4. the two whole-file refusals of pc-thewardrobe-doc: a PNG, and a
    #    SerializedFile at format 22, both on disk, neither a traceback
    tmp = tempfile.mkdtemp()
    try:
        png = os.path.join(tmp, 'SaveIcon.png')
        with open(png, 'wb') as f:
            f.write(b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR'
                    + struct.pack('>II', 64, 64) + b'\x08\x06\0\0\0'
                    + bytes(100))
        f22 = os.path.join(tmp, 'sharedassets0.assets')
        with open(f22, 'wb') as f:
            f.write(unityfs._fake_serialized(22))
        f17 = os.path.join(tmp, 'sharedassets1.assets')
        with open(f17, 'wb') as f:
            f.write(unityfs._fake_serialized(17))
        r = list(textures_of(png))
        checks.append(('a PNG handed to textures_of is REFUSED, not raised',
                       len(r) == 1 and isinstance(r[0][0], Refused)
                       and r[0][1] is None, ''))
        r = list(textures_of(f22))
        checks.append(('a format-22 SerializedFile is REFUSED BY NAME and '
                       'points at unitytex22.py',
                       len(r) == 1 and isinstance(r[0][0], Refused)
                       and 'format 22' in str(r[0][0])
                       and 'unitytex22' in str(r[0][0]),
                       str(r[0][0])[:60] if r else ''))
        r = list(textures_of(f17))
        checks.append(('a format-17 SerializedFile with no textures yields '
                       'nothing and no refusal', r == [], str(r)))
        checks.append(('files_of() no longer selects the PNG',
                       png not in files_of(tmp) and f22 in files_of(tmp), ''))
    finally:
        for nm in os.listdir(tmp):
            os.unlink(os.path.join(tmp, nm))
        os.rmdir(tmp)
    width = max(len(c[0]) for c in checks)
    bad = 0
    for label, ok, note in checks:
        print('  %-*s  %s  %s' % (width, label, 'ok  ' if ok else 'FAIL', note))
        bad += not ok
    print()
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def _refuses(fn, *a):
    try:
        fn(*a)
    except Refused:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd')
    p = sub.add_parser('list')
    p.add_argument('path')
    p = sub.add_parser('census')
    p.add_argument('path')
    p = sub.add_parser('extract')
    p.add_argument('path')
    p.add_argument('--name', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--mip', type=int, default=0)
    p = sub.add_parser('sidecars')
    p.add_argument('path')
    sub.add_parser('selftest')
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        return {'list': cmd_list, 'census': cmd_census,
                'extract': cmd_extract, 'sidecars': cmd_sidecars,
                'selftest': cmd_selftest}[args.cmd](args)
    except Refused as e:
        sys.exit('unitytex17: refused -- %s' % e)


if __name__ == '__main__':
    sys.exit(main())
