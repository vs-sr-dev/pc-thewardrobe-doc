#!/usr/bin/env python3
"""unitytex22.py -- `Texture2D` and `Sprite` objects out of a version-22 Unity
SerializedFile (Unity 6), read from a hex dump on pc-thewardrobe-doc, closed
twice on every texture and once on every sprite before a pixel is claimed.

WHY A THIRD TEXTURE TOOL, AND WHY IT IS NOT A GENERAL UNITY 6 READER
--------------------------------------------------------------------
`unitytex.py` reads serialization version 15 (Unity 5.2, pixels inline);
`unitytex17.py` reads version 17 (Unity 5.5, pixels in a `.resS` sidecar
named by `m_StreamData`) and REFUSES every other version by name, because
a wrong layout renders a plausible, wrong picture. This object is Unity
6000.3.6f1, format 22: `unityfs.py` reads the container (105 files,
28,593 objects, 105 of 105 closing on their own size), but the Texture2D
body has grown since 17 and the pictures of this game are not the
textures anyway -- they are 17,368 `Sprite` objects, each naming a
texture and a rectangle inside it. So this tool reads exactly two
classes, 28 and 213, and nothing else of Unity 6.

The Texture2D body at format 22 (Unity 6000.3), as measured on this object
---------------------------------------------------------------------------
Read from the hex dump of `Background` (32 x 32 RGBA32, 6 mips, streamed,
152 bytes) and `BradyBunchUltimate SDF Atlas` (1024 x 1024 Alpha8, inline,
1,048,716 bytes) in `sharedassets0.assets`, then closed on 1,161 of 1,161:

    aligned string  m_Name
    4 bytes         NEW since 17: byte 0 is 1 on exactly the 109 textures
                    whose format carries no alpha channel (RGB24 x18, DXT1
                    x91) and 0 on the 1,052 whose format does -- a flag that
                    behaves as "the alpha channel is optional"; bytes 1..3
                    are 0 on 1,161 of 1,161. Unity's names for these bytes
                    (m_ForcedFallbackFormat / m_DownscaleFallback /
                    m_IsAlphaChannelOptional in its type tree) are not
                    derived here; the tool calls the i32 `forced_fallback`.
    i32             m_Width
    i32             m_Height
    i32             m_CompleteImageSize        -- every mip level, summed
    i32             m_MipsStripped             -- NEW
    i32             m_TextureFormat
    i32             m_MipCount
    u8 u8 u8        m_IsReadable, m_IsPreProcessed, m_IgnoreMipmapLimit  -- NEW (third)
    align 4
    aligned string  m_MipmapLimitGroupName     -- NEW
    u8              m_StreamingMipmaps         -- NEW
    align 4
    i32             m_StreamingMipmapsPriority -- NEW
    i32             m_ImageCount
    i32             m_TextureDimension         -- 2
    i32 i32 f32     m_FilterMode, m_Aniso, m_MipBias
    i32 i32 i32     m_WrapU, m_WrapV, m_WrapW  -- THREE wrap modes; 17 had one
    i32             m_LightmapFormat
    i32             m_ColorSpace               -- NEW
    i32 + bytes     m_PlatformBlob, align 4    -- NEW (0 bytes here)
    i32 + bytes     image data, align 4        -- 0 when streamed
    u64             m_StreamData.offset        -- u64; 17 had u32
    u32             m_StreamData.size
    aligned string  m_StreamData.path

Two closures per texture, as on 17: the BODY ends exactly where the last
field ends (padding 0), and the ARITHMETIC `m_CompleteImageSize == the sum
of the mip levels by the format's bits per pixel` holds, with the stream
record's size (or the inline block's) equal to it.

The Sprite body at format 22, as measured on this object
--------------------------------------------------------
Read from the hex dump of `Background` in `sharedassets0.assets` (576 bytes)
and closed on every sprite of the census:

    aligned string  m_Name
    f32 x4          m_Rect (x, y, w, h)        -- in texture pixels
    f32 x2          m_Offset
    f32 x4          m_Border
    f32             m_PixelsToUnits
    f32 x2          m_Pivot
    u32             m_Extrude
    u8              m_IsPolygon, align 4
    16 bytes + i64  m_RenderDataKey (GUID, long)
    i32 + strings   m_AtlasTags
    i32 + i64       m_SpriteAtlas (PPtr)
    -- m_RD, the SpriteRenderData --
    i32 + i64       texture (PPtr: fileID, pathID) -- THE PICTURE
    i32 + i64       alphaTexture (PPtr)
    i32 + ...       m_SecondaryTextures (PPtr + string each)
    i32 + 48 each   m_SubMeshes (firstByte, indexCount, topology, baseVertex,
                                 firstVertex, vertexCount, AABB 6 f32)
    i32 + bytes     m_IndexBuffer, align 4
    u32             m_VertexData.m_VertexCount
    i32 + 4 each    m_VertexData.m_Channels (stream, offset, format, dim)
    i32 + bytes     m_VertexData.m_DataSize + data, align 4
    i32 + 64 each   m_Bindpose (Matrix4x4f)
    f32 x4          m_TextureRect              -- the rectangle IN the texture
    f32 x2          m_TextureRectOffset
    f32 x2          m_AtlasRectOffset
    u32             m_SettingsRaw              -- bit 0 packed, bits 2-5 rotation,
                                                  bit 6 mesh type (1 = tight)
    f32 x4          m_UVTransform
    f32             m_DownscaleMultiplier
    i32 + (i32 + 8 each)  m_PhysicsShape (vector of vector of Vector2)
    i32 + ...       m_Bones (0 on every sprite here)
    aligned string  m_SpriteID

One closure per sprite: the body ends where `m_SpriteID` ends. The picture
is `m_TextureRect` of the texture the PPtr names (fileID 0 = this file,
fileID n = the file's n-th external), rendered top-down from Unity's
bottom-up rows. This tool renders SOME sprites (`render`), and says so: a
census of 17,368 is a count, a render is a picture the owner can confirm.

What it does not read, said in advance: Unity 6's other 40-odd classes;
`m_PhysicsShape` beyond its count; sprites whose `m_SettingsRaw` says
rotated (counted, refused at render); formats outside RGBA32, ARGB32,
RGB24, Alpha8, RGB565, ARGB4444, DXT1, DXT5 (counted, refused at render:
BC7 and the ASTC family are named, not decoded).

    python tools/unitytex22.py census   DIR            -- every Texture2D, two closures
    python tools/unitytex22.py list     FILE|DIR
    python tools/unitytex22.py sidecars DIR            -- the .resS tiled by records
    python tools/unitytex22.py sprites  DIR [--list]   -- every Sprite, closure, texture link
    python tools/unitytex22.py extract  FILE --name N --out X.png [--mip M]
    python tools/unitytex22.py render   DIR --sprite N --out X.png   (or --pathid P --file F)
    python tools/unitytex22.py selftest

Standard library only. The decoders are `unitytex.py`'s.
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
import unitytex17                                          # noqa: E402

FORMAT = dict(unityfs.TEXFMT)
BPP = dict(unitytex17.BPP)
BLOCK = dict(unitytex17.BLOCK)
BLOCK.update({25: 16, 24: 16, 26: 8, 27: 16})     # BC7, BC6H, BC4, BC5: named, sized, not decoded
DECODABLE = unitytex17.DECODABLE
Refused = unitytex17.Refused


def level_bytes(fmt, w, h):
    """Bytes of one mip level by the format's arithmetic (unitytex17's, with
    the BC family sized); None if the format is unknown; 0 for 0 x 0."""
    if w == 0 or h == 0:
        return 0
    if fmt in BLOCK:
        return ((w + 3) // 4) * ((h + 3) // 4) * BLOCK[fmt]
    if fmt in BPP:
        return w * h * BPP[fmt] // 8
    return None


def mip_sizes(fmt, w, h, mips):
    if w == 0 or h == 0:
        return [0]
    out = []
    for lv in range(max(1, mips)):
        n = level_bytes(fmt, max(1, w >> lv), max(1, h >> lv))
        if n is None:
            return None
        out.append(n)
    return out

FILE_VERSION = 22


class R(object):
    def __init__(self, b, little=True):
        self.b = b
        self.p = 0
        self.e = '<' if little else '>'

    def u8(self):
        v = self.b[self.p]
        self.p += 1
        return v

    def i32(self):
        v = struct.unpack_from(self.e + 'i', self.b, self.p)[0]
        self.p += 4
        return v

    def u32(self):
        v = struct.unpack_from(self.e + 'I', self.b, self.p)[0]
        self.p += 4
        return v

    def i64(self):
        v = struct.unpack_from(self.e + 'q', self.b, self.p)[0]
        self.p += 8
        return v

    def u64(self):
        v = struct.unpack_from(self.e + 'Q', self.b, self.p)[0]
        self.p += 8
        return v

    def f32(self):
        v = struct.unpack_from(self.e + 'f', self.b, self.p)[0]
        self.p += 4
        return v

    def raw(self, n):
        if self.p + n > len(self.b):
            raise Refused('%d bytes wanted at %d of a %d-byte body'
                          % (n, self.p, len(self.b)))
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def align(self, n=4):
        self.p = (self.p + n - 1) & ~(n - 1)

    def astr(self):
        n = self.i32()
        if n < 0 or n > 1 << 20:
            raise Refused('string length %d at %d is not credible' % (n, self.p - 4))
        s = self.raw(n).decode('utf-8', 'replace')
        self.align()
        return s

    def pptr(self):
        return self.i32(), self.i64()


class Texture(object):
    """One Texture2D body at format 22, with both closures evaluated."""

    def __init__(self, b, little=True):
        r = R(b, little)
        self.name = r.astr()
        self.forced_fallback = r.i32()
        self.width = r.i32()
        self.height = r.i32()
        self.complete = r.i32()
        self.mips_stripped = r.i32()
        self.format = r.i32()
        self.mips = r.i32()
        self.readable = r.u8()
        self.preprocessed = r.u8()
        self.ignore_mip_limit = r.u8()
        r.align()
        self.mip_group = r.astr()
        self.streaming_mipmaps = r.u8()
        r.align()
        self.streaming_priority = r.i32()
        self.image_count = r.i32()
        self.dimension = r.i32()
        self.filter = r.i32()
        self.aniso = r.i32()
        self.mip_bias = r.f32()
        self.wrap = (r.i32(), r.i32(), r.i32())
        self.lightmap_format = r.i32()
        self.color_space = r.i32()
        n = r.i32()
        self.platform_blob = r.raw(n)
        r.align()
        self.data_size = r.i32()
        if self.data_size < 0:
            raise Refused('%s: image data size %d' % (self.name, self.data_size))
        self.inline = r.raw(self.data_size)
        r.align()
        self.stream_offset = r.u64()
        self.stream_size = r.u32()
        self.stream_path = r.astr()
        self.end = r.p
        self.padding = len(b) - r.p
        self.closed = (self.padding == 0)
        self.streamed = bool(self.stream_path)
        sizes = mip_sizes(self.format, self.width, self.height, self.mips)
        self.mip_bytes = sizes
        self.expected = sum(sizes) * max(1, self.image_count) if sizes else None
        have = self.stream_size if self.streamed else self.data_size
        self.arith = (self.expected is not None and self.expected == self.complete
                      and have == self.complete)

    def where(self):
        if self.streamed:
            return '%s+%d..%d' % (self.stream_path, self.stream_offset,
                                  self.stream_offset + self.stream_size)
        if self.data_size:
            return 'inline'
        return 'no pixels'


class Sprite(object):
    """One Sprite body at format 22, closed on its end."""

    def __init__(self, b, little=True):
        r = R(b, little)
        self.name = r.astr()
        self.rect = tuple(r.f32() for _ in range(4))
        self.offset = (r.f32(), r.f32())
        self.border = tuple(r.f32() for _ in range(4))
        self.ppu = r.f32()
        self.pivot = (r.f32(), r.f32())
        self.extrude = r.u32()
        self.is_polygon = r.u8()
        r.align()
        self.render_key = (r.raw(16).hex(), r.i64())
        n = r.i32()
        if not 0 <= n < 64:
            raise Refused('%s: %d atlas tags' % (self.name, n))
        self.atlas_tags = [r.astr() for _ in range(n)]
        self.atlas = r.pptr()
        self.texture = r.pptr()
        self.alpha_texture = r.pptr()
        n = r.i32()
        if not 0 <= n < 64:
            raise Refused('%s: %d secondary textures' % (self.name, n))
        self.secondary = []
        for _ in range(n):
            self.secondary.append((r.pptr(), r.astr()))
        n = r.i32()
        if not 0 <= n < 1024:
            raise Refused('%s: %d submeshes' % (self.name, n))
        self.submeshes = []
        for _ in range(n):
            self.submeshes.append(struct.unpack_from(r.e + 'IIiIII', b, r.p))
            r.p += 24
            r.raw(24)                      # localAABB
        n = r.i32()
        self.index_bytes = n
        r.raw(n)
        r.align()
        self.vertex_count = r.u32()
        n = r.i32()
        if not 0 <= n < 64:
            raise Refused('%s: %d vertex channels' % (self.name, n))
        self.channels = [tuple(r.raw(4)) for _ in range(n)]
        n = r.i32()
        self.vertex_bytes = n
        r.raw(n)
        r.align()
        n = r.i32()
        if not 0 <= n < 1024:
            raise Refused('%s: %d bind poses' % (self.name, n))
        self.bindpose = n
        r.raw(64 * n)
        self.texture_rect = tuple(r.f32() for _ in range(4))
        self.texture_rect_offset = (r.f32(), r.f32())
        self.atlas_rect_offset = (r.f32(), r.f32())
        self.settings_raw = r.u32()
        self.uv_transform = tuple(r.f32() for _ in range(4))
        self.downscale = r.f32()
        n = r.i32()
        if not 0 <= n < 4096:
            raise Refused('%s: %d physics shapes' % (self.name, n))
        self.physics_shapes = []
        for _ in range(n):
            m = r.i32()
            if not 0 <= m < 1 << 20:
                raise Refused('%s: a physics shape of %d points' % (self.name, m))
            r.raw(8 * m)
            self.physics_shapes.append(m)
        n = r.i32()
        if n != 0:
            raise Refused('%s: %d bones -- SpriteBone is not read here'
                          % (self.name, n))
        self.bones = n
        self.sprite_id = r.astr()
        self.end = r.p
        self.padding = len(b) - r.p
        self.closed = (self.padding == 0)

    @property
    def packed(self):
        return self.settings_raw & 1

    @property
    def rotation(self):
        return (self.settings_raw >> 2) & 0xF

    @property
    def tight(self):
        return (self.settings_raw >> 6) & 1


# ------------------------------------------------------------------ walking

def load22(path):
    """The SerializedFile, or a Refused naming the format."""
    try:
        sf = unityfs.load(path)
    except unityfs.NotSerialized as e:
        raise Refused('not a SerializedFile: %s' % e)
    if sf.version != FILE_VERSION:
        raise Refused('%s is SerializedFile format %d (Unity %s); this reader '
                      'is the version-22 layout and refuses it'
                      % (os.path.basename(path), sf.version, sf.unity_version))
    return sf


def textures_of(path):
    """`(Texture | Refused, obj)` per Texture2D; one `(Refused, None)` when
    the whole file is refused."""
    try:
        sf = load22(path)
    except Refused as e:
        yield e, None
        return
    little = sf.endianness == 0
    for o in sf.objects:
        if sf.class_of(o) != 28:
            continue
        try:
            yield Texture(sf.body(o), little), o
        except (Refused, struct.error, IndexError) as e:
            yield Refused(str(e)), o


def sprites_of(path, sf=None):
    try:
        sf = sf or load22(path)
    except Refused as e:
        yield e, None
        return
    little = sf.endianness == 0
    for o in sf.objects:
        if sf.class_of(o) != 213:
            continue
        try:
            yield Sprite(sf.body(o), little), o
        except (Refused, struct.error, IndexError) as e:
            yield Refused(str(e)), o


def files_of(root):
    if os.path.isfile(root):
        return [root]
    return [p for p in unityfs.walk(root) if unityfs.is_serialized(p)]


def pixels(tex, sf_path):
    return unitytex17.pixels(tex, sf_path)


def decode(tex, data, mip=0):
    if tex.format not in DECODABLE:
        raise Refused('%s is %s (%d), which this tool names and does not decode'
                      % (tex.name, FORMAT.get(tex.format, '?'), tex.format))
    return unitytex17.decode(tex, data, mip)


# ------------------------------------------------------------------ commands

def cmd_list(args):
    if not os.path.isdir(args.path):
        dirguard.want_file(args.path, 'unitytex22')
    rows = 0
    print('%-40s %5s %5s %-10s %4s %11s %-5s %-5s  %s'
          % ('NAME', 'W', 'H', 'FORMAT', 'MIPS', 'BYTES', 'CLOSE', 'ARITH',
             'WHERE'))
    for p in files_of(args.path):
        rel = os.path.basename(p)
        for t, o in textures_of(p):
            if isinstance(t, Refused):
                print('%-40s REFUSED %s' % (rel, t))
                continue
            print('%-40s %5d %5d %-10s %4d %11d %-5s %-5s  %s'
                  % (t.name[:40], t.width, t.height,
                     FORMAT.get(t.format, str(t.format)), t.mips, t.complete,
                     'yes' if t.closed else 'NO', 'yes' if t.arith else 'NO',
                     t.where()))
            rows += 1
    print()
    print('%d Texture2D objects' % rows)
    return 0


def cmd_census(args):
    dirguard.want_tree(args.path, 'unitytex22')
    n = closed = arith = streamed = inline = 0
    fmt_n = collections.Counter()
    fmt_b = collections.Counter()
    side_n = collections.Counter()
    side_b = collections.Counter()
    size_n = collections.Counter()
    fallback_nonzero = readable = 0
    failed, refused_files = [], []
    per_file = collections.Counter()
    total = 0
    for p in files_of(args.path):
        rel = os.path.relpath(p, args.path).replace(os.sep, '/')
        for t, o in textures_of(p):
            if isinstance(t, Refused):
                (refused_files if o is None else failed).append((rel, str(t)))
                continue
            n += 1
            per_file[rel] += 1
            closed += t.closed
            arith += bool(t.arith)
            fallback_nonzero += (t.forced_fallback != 0)
            readable += t.readable
            if not (t.closed and t.arith):
                failed.append((rel, '%s: padding %d, expected %s, complete %d,'
                               ' stream %d, inline %d'
                               % (t.name, t.padding, t.expected, t.complete,
                                  t.stream_size, t.data_size)))
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
    print('Texture2D objects        %d in %d serialized files (format %d)'
          % (n, len(per_file), FILE_VERSION))
    print('closure (body end)       %d of %d' % (closed, n))
    print('closure (arithmetic)     %d of %d' % (arith, n))
    print('pixels streamed          %d   inline %d   none %d'
          % (streamed, inline, n - streamed - inline))
    print('bytes of pixels          %d (m_CompleteImageSize summed)' % total)
    print('m_ForcedFallbackFormat   non-zero on %d of %d; m_IsReadable on %d'
          % (fallback_nonzero, n, readable))
    print()
    print('%-4s %-12s %6s %14s %s' % ('FMT', 'NAME', 'COUNT', 'BYTES', 'DECODED HERE'))
    for f, c in fmt_n.most_common():
        print('%-4d %-12s %6d %14d %s' % (f, FORMAT.get(f, '?'), c, fmt_b[f],
                                          'yes' if f in DECODABLE else 'no'))
    print()
    print('%-40s %6s %14s' % ('WHERE', 'COUNT', 'BYTES'))
    for k, c in side_n.most_common():
        print('%-40s %6d %14d' % (k, c, side_b[k]))
    print()
    print('%-14s %6s' % ('SIZE', 'COUNT'))
    for (w, h), c in size_n.most_common(15):
        print('%-14s %6d' % ('%d x %d' % (w, h), c))
    print()
    print('%-40s %6s' % ('FILE', 'COUNT'))
    for k in sorted(per_file):
        print('%-40s %6d' % (k, per_file[k]))
    if failed:
        print()
        print('%d textures did not close or were refused:' % len(failed))
        for rel, why in failed:
            print('  %-28s %s' % (rel, why))
    if refused_files:
        print()
        print('%d FILES REFUSED WHOLE:' % len(refused_files))
        for rel, why in refused_files:
            print('  %-28s %s' % (rel, why))
    return 0 if not (failed or refused_files) else 1


def cmd_sidecars(args):
    """How the stream records tile each .resS: sorted by offset, gaps,
    overlaps, first and last byte reached -- to the last byte or not."""
    dirguard.want_tree(args.path, 'unitytex22')
    recs = collections.defaultdict(list)
    for p in files_of(args.path):
        d = os.path.dirname(p)
        for t, o in textures_of(p):
            if isinstance(t, Refused) or not t.streamed:
                continue
            recs[os.path.join(d, t.stream_path)].append(
                (t.stream_offset, t.stream_size, t.name))
    print('%-32s %12s %5s %12s %10s %6s %8s %-8s'
          % ('SIDECAR', 'BYTES', 'RECS', 'REACHED', 'GAP BYTES', 'GAPS',
             'OVERLAP', 'ENDS AT'))
    tiled = 0
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
        ends = 'file' if pos == size else 'short'
        tiled += (pos == size and overlaps == 0)
        print('%-32s %12d %5d %12d %10d %6d %8d %-8s'
              % (os.path.basename(side), size, len(rs), pos, gap_bytes, gaps,
                 overlaps, ends))
    print()
    print('%d of %d sidecars reached to the last byte with no overlap'
          % (tiled, len(recs)))
    return 0 if tiled == len(recs) else 1


def _resolve(sf, pptr, path):
    """(file path, path id) a PPtr names: fileID 0 is this file, n>0 the
    n-th external, beside this file."""
    fid, pid = pptr
    if fid == 0:
        return path, pid
    if 1 <= fid <= len(sf.externals):
        ext = sf.externals[fid - 1]['path']
        return os.path.join(os.path.dirname(path), os.path.basename(ext)), pid
    return None, pid


def cmd_sprites(args):
    dirguard.want_tree(args.path, 'unitytex22')
    n = closed = 0
    same = external = none = 0
    packed = rotated = tight = polygon = 0
    failed, refused_files = [], []
    per_file = collections.Counter()
    tex_refs = collections.Counter()
    sizes = collections.Counter()
    ppu = collections.Counter()
    verts = idx = 0
    rows = []
    for p in files_of(args.path):
        rel = os.path.relpath(p, args.path).replace(os.sep, '/')
        try:
            sf = load22(p)
        except Refused as e:
            refused_files.append((rel, str(e)))
            continue
        for s, o in sprites_of(p, sf):
            if isinstance(s, Refused):
                failed.append((rel, str(s)))
                continue
            n += 1
            per_file[rel] += 1
            closed += s.closed
            if not s.closed:
                failed.append((rel, '%s: %d bytes of padding' % (s.name, s.padding)))
            fid, pid = s.texture
            if pid == 0:
                none += 1
            elif fid == 0:
                same += 1
            else:
                external += 1
            tpath, tpid = _resolve(sf, s.texture, p)
            tex_refs[(os.path.basename(tpath) if tpath else '?', tpid)] += 1
            packed += s.packed
            rotated += (s.rotation != 0)
            tight += s.tight
            polygon += s.is_polygon
            sizes[(int(round(s.rect[2])), int(round(s.rect[3])))] += 1
            ppu[s.ppu] += 1
            verts += s.vertex_count
            idx += s.index_bytes // 2
            if args.list:
                rows.append((rel, o['path_id'], s.name, s.rect, s.texture_rect,
                             os.path.basename(tpath) if tpath else '?', tpid,
                             s.settings_raw))
    if args.list:
        print('%-22s %8s %-40s %-22s %-22s %-28s %8s %4s'
              % ('FILE', 'PATHID', 'NAME', 'RECT', 'TEXRECT', 'TEXTURE FILE',
                 'TEXPATH', 'SET'))
        for rel, pid, nm, rc, tr, tf, tp, sr in rows:
            print('%-22s %8d %-40s %-22s %-22s %-28s %8d %4d'
                  % (rel[:22], pid, nm[:40],
                     '%g,%g %gx%g' % rc, '%.0f,%.0f %.0fx%.0f' % tr,
                     tf[:28], tp, sr))
        print()
    print('Sprite objects           %d in %d serialized files' % (n, len(per_file)))
    print('closure (body end)       %d of %d' % (closed, n))
    print('texture PPtr             same file %d   external file %d   none %d'
          % (same, external, none))
    print('distinct textures named  %d' % len(tex_refs))
    print('packed %d   rotated %d   tight mesh %d   polygon %d'
          % (packed, rotated, tight, polygon))
    print('vertices %d   indices %d' % (verts, idx))
    print()
    print('%-14s %6s' % ('PPU', 'COUNT'))
    for k, c in ppu.most_common(6):
        print('%-14g %6d' % (k, c))
    print()
    print('%-14s %6s' % ('RECT SIZE', 'COUNT'))
    for (w, h), c in sizes.most_common(15):
        print('%-14s %6d' % ('%d x %d' % (w, h), c))
    print()
    print('%-40s %6s' % ('FILE', 'SPRITES'))
    for k in sorted(per_file):
        print('%-40s %6d' % (k, per_file[k]))
    print()
    print('%-40s %6s' % ('TEXTURE (file, path id)', 'SPRITES'))
    for (tf, tp), c in tex_refs.most_common(12):
        print('%-40s %6d' % ('%s #%d' % (tf, tp), c))
    if failed:
        print()
        print('%d sprites did not close or were refused:' % len(failed))
        for rel, why in failed[:40]:
            print('  %-28s %s' % (rel, why))
    if refused_files:
        print()
        print('%d FILES REFUSED WHOLE:' % len(refused_files))
        for rel, why in refused_files:
            print('  %-28s %s' % (rel, why))
    return 0 if not (failed or refused_files) else 1


def cmd_extract(args):
    dirguard.want_file(args.path, 'unitytex22')
    for t, o in textures_of(args.path):
        if isinstance(t, Refused) and o is None:
            sys.exit('unitytex22: refused: %s' % t)
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
    sys.exit('unitytex22: no Texture2D named %r in %s'
             % (args.name, os.path.basename(args.path)))


def crop(rgba, tw, th, rect):
    """`rect` (x, y, w, h) in Unity's bottom-up pixel coordinates, out of
    top-down RGBA rows: the rows y+h-1 .. y from the bottom."""
    x, y, w, h = [int(round(v)) for v in rect]
    x = max(0, min(x, tw))
    y = max(0, min(y, th))
    w = max(0, min(w, tw - x))
    h = max(0, min(h, th - y))
    out = bytearray()
    for row in range(h):
        src_row = th - (y + h) + row
        s = (src_row * tw + x) * 4
        out += rgba[s:s + w * 4]
    return out, w, h


def render_sprite(sf, sf_path, s):
    tpath, tpid = _resolve(sf, s.texture, sf_path)
    if tpath is None or tpid == 0:
        raise Refused('%s names no texture (PPtr %r)' % (s.name, s.texture))
    if not os.path.isfile(tpath):
        raise Refused('%s: texture file %s is not beside %s'
                      % (s.name, os.path.basename(tpath), os.path.basename(sf_path)))
    if s.rotation:
        raise Refused('%s: m_SettingsRaw says rotation %d, which this tool '
                      'does not undo' % (s.name, s.rotation))
    tsf = load22(tpath)
    for o in tsf.objects:
        if o['path_id'] == tpid:
            break
    else:
        raise Refused('%s: no object %d in %s' % (s.name, tpid, os.path.basename(tpath)))
    if tsf.class_of(o) != 28:
        raise Refused('%s: object %d in %s is class %d, not Texture2D'
                      % (s.name, tpid, os.path.basename(tpath), tsf.class_of(o)))
    t = Texture(tsf.body(o), tsf.endianness == 0)
    if not (t.closed and t.arith):
        raise Refused('%s: texture %s does not close' % (s.name, t.name))
    rgba, w, h = decode(t, pixels(t, tpath), 0)
    out, cw, ch = crop(rgba, w, h, s.texture_rect)
    return out, cw, ch, t, tpath


def cmd_render(args):
    dirguard.want_tree(args.path, 'unitytex22')
    files = [args.file] if args.file else files_of(args.path)
    for p in files:
        try:
            sf = load22(p)
        except Refused:
            continue
        for s, o in sprites_of(p, sf):
            if isinstance(s, Refused):
                continue
            if args.pathid is not None:
                if o['path_id'] != args.pathid:
                    continue
            elif s.name != args.sprite:
                continue
            rgba, w, h, t, tpath = render_sprite(sf, p, s)
            n = unitytex.write_png(args.out, rgba, w, h)
            print('%s (path %d in %s): rect %g,%g %gx%g, texture rect '
                  '%.1f,%.1f %.1fx%.1f of %s (%d x %d %s, path %d in %s); '
                  '%d x %d rendered, %s written, %d bytes'
                  % (s.name, o['path_id'], os.path.basename(p), s.rect[0],
                     s.rect[1], s.rect[2], s.rect[3], s.texture_rect[0],
                     s.texture_rect[1], s.texture_rect[2], s.texture_rect[3],
                     t.name, t.width, t.height, FORMAT.get(t.format, t.format),
                     s.texture[1], os.path.basename(tpath), w, h, args.out, n))
            return 0
    sys.exit('unitytex22: no Sprite %s under %s'
             % (repr(args.sprite) if args.pathid is None else '#%d' % args.pathid,
                args.path))


# ------------------------------------------------------------------ selftest

def _astr(s):
    b = s.encode('utf-8')
    out = struct.pack('<i', len(b)) + b
    return out + bytes((-len(out)) & 3)


def _tex_body(name, w, h, fmt, mips, inline=b'', stream=None, fallback=0):
    """A Texture2D body at format 22, from the layout in the docstring."""
    b = _astr(name)
    complete = sum(mip_sizes(fmt, w, h, mips))
    b += struct.pack('<iiiiiii', fallback, w, h, complete, 0, fmt, mips)
    b += bytes((0, 0, 0)) + b'\0'                     # 3 bools + align
    b += _astr('')                                    # mip limit group
    b += b'\0\0\0\0'                                  # streaming mipmaps + align
    b += struct.pack('<iiiiifiiiii', 0, 1, 2, 1, 1, 0.0, 1, 1, 1, 0, 1)
    b += struct.pack('<i', 0)                         # platform blob
    b += struct.pack('<i', len(inline)) + inline
    b += bytes((-len(b)) & 3)
    if stream:
        off, size, path = stream
        b += struct.pack('<QI', off, size) + _astr(path)
    else:
        b += struct.pack('<QI', 0, 0) + _astr('')
    return b


def _sprite_body(name, rect, tex_pptr, texrect, settings=0x40):
    b = _astr(name)
    b += struct.pack('<4f', *rect)
    b += struct.pack('<2f', 0, 0)
    b += struct.pack('<4f', 0, 0, 0, 0)
    b += struct.pack('<f', 100.0)
    b += struct.pack('<2f', 0.5, 0.5)
    b += struct.pack('<I', 1)
    b += b'\0\0\0\0'
    b += bytes(16) + struct.pack('<q', 7)
    b += struct.pack('<i', 0)                         # atlas tags
    b += struct.pack('<iq', 0, 0)                     # sprite atlas
    b += struct.pack('<iq', *tex_pptr)                # texture
    b += struct.pack('<iq', 0, 0)                     # alpha texture
    b += struct.pack('<i', 0)                         # secondary
    b += struct.pack('<i', 1) + struct.pack('<IIiIII', 0, 6, 0, 0, 0, 4) + bytes(24)
    b += struct.pack('<i', 12) + struct.pack('<6H', 0, 1, 2, 2, 3, 0)
    b += struct.pack('<I', 4)
    b += struct.pack('<i', 2) + bytes((0, 0, 0, 3)) + bytes((0, 12, 0, 2))
    b += struct.pack('<i', 80) + bytes(80)
    b += struct.pack('<i', 0)                         # bindpose
    b += struct.pack('<4f', *texrect)
    b += struct.pack('<2f', 0, 0)
    b += struct.pack('<2f', -1, -1)
    b += struct.pack('<I', settings)
    b += struct.pack('<4f', 100, 8, 100, 8)
    b += struct.pack('<f', 1.0)
    b += struct.pack('<i', 1) + struct.pack('<i', 3) + bytes(24)
    b += struct.pack('<i', 0)                         # bones
    b += _astr('')                                    # sprite id
    return b


def cmd_selftest(_args):
    checks = []
    # 1. an inline 2 x 2 RGBA32, one mip: both closures
    px = bytes((255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255))
    t = Texture(_tex_body('two', 2, 2, 4, 1, inline=px))
    checks.append(('inline RGBA32 body at 22 parses and closes twice',
                   t.name == 'two' and t.closed and t.arith and t.data_size == 16
                   and not t.streamed and t.wrap == (1, 1, 1),
                   '%s %s %d' % (t.closed, t.arith, t.data_size)))
    checks.append(('a body with 4 bytes of padding does not close',
                   not Texture(_tex_body('two', 2, 2, 4, 1, inline=px) + bytes(4)).closed, ''))
    # 2. a streamed 32 x 32 RGBA32 with 6 mips: 5,460 bytes, the object's Background
    t2 = Texture(_tex_body('Background', 32, 32, 4, 6, stream=(0, 5460, 'sharedassets0.assets.resS')))
    checks.append(('32 x 32 RGBA32 over 6 mips is 5,460 bytes -- Background of this object',
                   t2.complete == 5460 and t2.arith and t2.closed and t2.streamed,
                   str(t2.complete)))
    checks.append(('the stream offset is read as u64',
                   Texture(_tex_body('x', 2, 2, 4, 1, stream=(1 << 33, 16, 'a.resS'))).stream_offset == 1 << 33, ''))
    checks.append(('a stream record smaller than m_CompleteImageSize fails the arithmetic',
                   not Texture(_tex_body('x', 32, 32, 4, 6, stream=(0, 4096, 'a.resS'))).arith, ''))
    checks.append(('a 1024 x 1024 Alpha8 with one mip is 1,048,576 bytes -- the SDF atlas',
                   sum(mip_sizes(1, 1024, 1024, 1)) == 1048576, ''))
    checks.append(('BC7 (25) is named and sized at 16 bytes per block and not decoded',
                   FORMAT[25] == 'BC7' and level_bytes(25, 8, 8) == 64 and 25 not in DECODABLE, ''))
    # 3. the sprite: closure, PPtr, rect
    sb = _sprite_body('hero', (0, 0, 8, 8), (0, 3), (2, 2, 4, 4))
    s = Sprite(sb)
    checks.append(('a sprite body at 22 parses and closes',
                   s.closed and s.name == 'hero' and s.texture == (0, 3)
                   and s.rect == (0, 0, 8, 8) and s.texture_rect == (2, 2, 4, 4)
                   and s.tight == 1 and s.rotation == 0 and s.vertex_count == 4,
                   '%s %r' % (s.closed, s.texture)))
    checks.append(('a sprite with 4 bytes of padding does not close',
                   not Sprite(sb + bytes(4)).closed, ''))
    checks.append(('rotation is bits 2-5 of m_SettingsRaw',
                   Sprite(_sprite_body('r', (0, 0, 8, 8), (0, 3), (0, 0, 8, 8), settings=0x45)).rotation == 1, ''))
    # 4. crop: a 4 x 4 top-down image, Unity rect (1, 1, 2, 2) from the bottom
    img = bytearray()
    for y in range(4):
        for x in range(4):
            img += bytes((x, y, 0, 255))              # top-down rows: y = 0 is the top
    out, cw, ch = crop(img, 4, 4, (1, 1, 2, 2))
    checks.append(('crop takes Unity\'s bottom-up rect from top-down rows',
                   (cw, ch) == (2, 2) and bytes(out[:4]) == bytes((1, 1, 0, 255))
                   and bytes(out[-4:]) == bytes((2, 2, 0, 255)),
                   bytes(out).hex()))
    # 5. on disk: a fake 22 file with one texture and one sprite, rendered
    tmp = tempfile.mkdtemp()
    try:
        body_t = _tex_body('atlas', 4, 4, 4, 1, inline=bytes(img))
        body_s = _sprite_body('hero', (0, 0, 4, 4), (0, 1), (1, 1, 2, 2))
        objs = [(1, 28, body_t), (2, 213, body_s)]
        blob = _fake_file(objs)
        fp = os.path.join(tmp, 'sharedassets0.assets')
        with open(fp, 'wb') as f:
            f.write(blob)
        sf = load22(fp)
        checks.append(('a hand-built format-22 file with a texture and a sprite loads',
                       sf.version == 22 and len(sf.objects) == 2, ''))
        got = [s for s, o in sprites_of(fp, sf)]
        checks.append(('sprites_of finds the sprite and it closes',
                       len(got) == 1 and not isinstance(got[0], Refused) and got[0].closed,
                       ''))
        rgba, w, h, t, tp = render_sprite(sf, fp, got[0])
        checks.append(('render_sprite decodes the texture and crops the rect',
                       (w, h) == (2, 2) and len(rgba) == 16, '%d %d' % (w, h)))
        png = os.path.join(tmp, 'hero.png')
        n = unitytex.write_png(png, rgba, w, h)
        with open(png, 'rb') as f:
            head = f.read(24)
        checks.append(('the PNG written is 2 x 2', n > 0 and head[16:24] == struct.pack('>II', 2, 2), ''))
        f17 = os.path.join(tmp, 'sharedassets1.assets')
        with open(f17, 'wb') as f:
            f.write(unityfs._fake_serialized(17))
        r = list(textures_of(f17))
        checks.append(('a format-17 file is REFUSED BY NAME',
                       len(r) == 1 and isinstance(r[0][0], Refused) and 'format 17' in str(r[0][0]), ''))
        pngf = os.path.join(tmp, 'SaveIcon.png')
        with open(pngf, 'wb') as f:
            f.write(b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + bytes(100))
        r = list(textures_of(pngf))
        checks.append(('a PNG is REFUSED, not raised',
                       len(r) == 1 and isinstance(r[0][0], Refused), ''))
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


def _fake_file(objs):
    """A format-22 SerializedFile holding `objs` = [(path_id, class_id, body)],
    one type per class, no type tree, little-endian."""
    classes = sorted({c for _p, c, _b in objs})
    meta = b'6000.3.6f1\0' + struct.pack('<i', 19) + b'\0'
    meta += struct.pack('<i', len(classes))
    for c in classes:
        meta += struct.pack('<i', c) + b'\0' + struct.pack('<h', -1) + bytes(16)
    meta += struct.pack('<i', len(objs))
    data = b''
    starts = []
    for pid, c, body in objs:
        starts.append(len(data))
        data += body + bytes((-len(body)) & 7)
    for (pid, c, body), st in zip(objs, starts):
        meta += bytes((-len(meta)) & 3)
        meta += struct.pack('<qqIi', pid, st, len(body), classes.index(c))
    meta += struct.pack('<i', 0)                       # script types
    meta += struct.pack('<i', 0)                       # externals
    meta += struct.pack('<i', 0)                       # ref types
    meta += b'\0'                                      # user information
    data_off = (48 + len(meta) + 15) & ~15
    total = data_off + len(data)
    head = (struct.pack('>IIII', 0, 0, 22, 0) + bytes(4) + struct.pack('>I', len(meta))
            + struct.pack('>qqq', total, data_off, 0))
    out = head + meta
    out += bytes(data_off - len(out)) + data
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('list')
    p.add_argument('path')
    p = sub.add_parser('census')
    p.add_argument('path')
    p = sub.add_parser('sidecars')
    p.add_argument('path')
    p = sub.add_parser('sprites')
    p.add_argument('path')
    p.add_argument('--list', action='store_true')
    p = sub.add_parser('extract')
    p.add_argument('path')
    p.add_argument('--name', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--mip', type=int, default=0)
    p = sub.add_parser('render')
    p.add_argument('path')
    p.add_argument('--sprite')
    p.add_argument('--pathid', type=int)
    p.add_argument('--file')
    p.add_argument('--out', required=True)
    sub.add_parser('selftest')
    args = ap.parse_args()
    nameguard.guard()
    return {'list': cmd_list, 'census': cmd_census, 'sidecars': cmd_sidecars,
            'sprites': cmd_sprites, 'extract': cmd_extract, 'render': cmd_render,
            'selftest': cmd_selftest}[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())
