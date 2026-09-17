#!/usr/bin/env python3
"""sfv15.py -- read Unity SerializedFile **version 15** with no Unity and no
third-party package.

Why this file exists rather than a patch to `unityfs.py`
--------------------------------------------------------

The box already holds `unityfs.py`, written for `pc-themurderofsonicthehedgehog
-doc` against Unity 2019.4 and SerializedFile **version 21**.  Pointed at this
object, which is Unity 5.2.2p3 and SerializedFile **version 15**, it exits 0 and
reports 19,361,497,355,137 bytes for one class in a 1,471,268,535-byte tree,
over 25 files where the magic finds 35, with negative class IDs.

The defect is one that a version branch cannot hide: at version 15 an
`ObjectInfo` record carries **five bytes that version 21 does not have**, and a
reader that omits them desynchronises the object array after the first record.
The five are, in order:

    u16  classID            -- at v15 the object's class is here, and the
                               i32 typeID before it is a *key* into the type
                               table, negative for MonoBehaviour script types
    i16  scriptTypeIndex    -- called isDestroyed in some readers; -1 (0xFFFF)
                               on every object in this object
    u8   stripped           -- present only at v15 and v16

That is the whole of the difference for the object array, and it accounts for
both symptoms at once: the byte totals are garbage because `byteStart` and
`byteSize` are read from the middle of the previous record, and the class IDs
are negative because `unityfs.py` treats v15's `typeID` as a v21 type-table
index and falls through to printing the raw number when the index is out of
range.  The negatives are real v15 typeIDs; they are not class IDs at all.

The layout this file implements, at version 15
-----------------------------------------------

    header, big-endian, always:
      +0x00  u32  metadataSize
      +0x04  u32  fileSize          -- the file's own length
      +0x08  u32  version           -- 15
      +0x0C  u32  dataOffset
      +0x10  u8   endianness (0 = little), then three reserved bytes

    metadata, in the declared endianness, from +0x14:
      cstr   unityVersion                     (version >= 7)
      i32    targetPlatform                   (version >= 8)
      u8     enableTypeTree                   (version >= 13)
      i32    typeCount, then that many:
               i32  classID
               [16] scriptID    -- only when classID < 0 (version < 16)
               [16] oldTypeHash
               type tree blob   -- only when enableTypeTree
      i32    objectCount, then that many:
               align 4; i64 pathID; u32 byteStart; u32 byteSize; i32 typeID;
               u16 classID; i16 scriptTypeIndex; u8 stripped
      i32    scriptTypeCount, then that many:
               i32 fileIndex; align 4; i64 identifierInFile
      i32    externalCount, then that many:
               cstr (empty); [16] guid; i32 type; cstr path
      cstr   userInformation

TWO INDEPENDENT CLOSURES, and both are checked on every read
------------------------------------------------------------

  1. `metadataSize + 20` must equal the offset the metadata parse stops at.
     Unity wrote that integer; this reader did not.
  2. `dataOffset + max(byteStart + byteSize)` must equal `fileSize`, and
     `fileSize` must equal the length of the file on disk.

A reader with the layout wrong fails both.  `close` reports them per file and
in total, and no mode of this tool prints a byte figure without having passed
check 1 -- which is the assertion `unityfs.py` does not make and the reason it
could report nineteen terabytes.

    python sfv15.py selftest              -- built in memory, most refused
    python sfv15.py validate PATH...      -- header only, and why it refused
    python sfv15.py info    FILE
    python sfv15.py objects FILE [--class N] [--limit N]
    python sfv15.py close   DIR|FILE...   -- the two closures, per file
    python sfv15.py account DIR|FILE...   -- every byte, in five buckets
    python sfv15.py census  DIR           -- every object of every file
    python sfv15.py names   DIR [--class N] [--limit N]
    python sfv15.py paths   DIR           -- the ResourceManager table

Standard library only.
"""

import argparse
import collections
import os
import struct
import sys

VERSION_SUPPORTED = 15

# Unity 5.x runtime class IDs.  Only the ones this object uses are named; a
# class not in this table prints as its number and is never guessed at.  The
# numbers are Unity's and are stable across 5.x; they are checked here against
# the object rather than trusted, in the sense that every ID this reader
# produces comes from a u16 field and is therefore non-negative by
# construction.
CLASS = {
    0: 'Object', 1: 'GameObject', 2: 'Component', 3: 'LevelGameManager',
    4: 'Transform', 5: 'TimeManager', 6: 'GlobalGameManager',
    8: 'Behaviour', 9: 'GameManager', 11: 'AudioManager',
    13: 'InputManager', 18: 'EditorExtension', 19: 'Physics2DSettings',
    20: 'Camera', 21: 'Material', 23: 'MeshRenderer', 25: 'Renderer',
    27: 'Texture', 28: 'Texture2D', 29: 'OcclusionCullingSettings',
    33: 'MeshFilter', 41: 'OcclusionPortal', 43: 'Mesh', 45: 'Skybox',
    47: 'QualitySettings', 48: 'Shader', 49: 'TextAsset',
    50: 'Rigidbody2D', 53: 'Collider2D', 54: 'Rigidbody',
    55: 'PhysicsManager', 56: 'Collider', 57: 'Joint', 58: 'CircleCollider2D',
    59: 'HingeJoint', 60: 'PolygonCollider2D', 61: 'BoxCollider2D',
    62: 'PhysicsMaterial2D', 64: 'MeshCollider', 65: 'BoxCollider',
    68: 'EdgeCollider2D', 70: 'CapsuleCollider2D', 72: 'ComputeShader',
    74: 'AnimationClip', 75: 'ConstantForce', 78: 'TagManager',
    81: 'AudioListener', 82: 'AudioSource', 83: 'AudioClip',
    84: 'RenderTexture', 89: 'Cubemap', 90: 'Avatar',
    91: 'AnimatorController', 93: 'RuntimeAnimatorController',
    95: 'Animator', 96: 'TrailRenderer', 98: 'DelayedCallManager',
    102: 'TextMesh', 104: 'RenderSettings', 108: 'Light',
    109: 'CGProgram', 110: 'BaseAnimationTrack', 111: 'Animation',
    114: 'MonoBehaviour', 115: 'MonoScript', 116: 'MonoManager',
    117: 'Texture3D', 118: 'NewAnimationTrack', 119: 'Projector',
    120: 'LineRenderer', 121: 'Flare', 122: 'Halo', 123: 'LensFlare',
    124: 'FlareLayer', 125: 'HaloLayer', 126: 'NavMeshProjectSettings',
    128: 'Font', 129: 'PlayerSettings', 130: 'NamedObject',
    134: 'PhysicMaterial', 135: 'SphereCollider', 136: 'CapsuleCollider',
    137: 'SkinnedMeshRenderer', 138: 'FixedJoint', 141: 'BuildSettings',
    142: 'AssetBundle', 143: 'CharacterController', 144: 'CharacterJoint',
    145: 'SpringJoint', 146: 'WheelCollider', 147: 'ResourceManager',
    150: 'PreloadData', 152: 'MovieTexture', 153: 'ConfigurableJoint',
    154: 'TerrainCollider', 156: 'TerrainData', 157: 'LightmapSettings',
    158: 'WebCamTexture', 159: 'EditorSettings', 162: 'EditorUserSettings',
    164: 'AudioReverbFilter', 165: 'AudioHighPassFilter',
    166: 'AudioChorusFilter', 167: 'AudioReverbZone', 168: 'AudioEchoFilter',
    169: 'AudioLowPassFilter', 170: 'AudioDistortionFilter',
    171: 'SparseTexture', 180: 'AudioBehaviour', 181: 'AudioFilter',
    182: 'WindZone', 183: 'Cloth', 184: 'SubstanceArchive',
    185: 'ProceduralMaterial', 186: 'ProceduralTexture',
    191: 'OffMeshLink', 192: 'OcclusionArea', 193: 'Tree',
    195: 'NavMeshAgent', 196: 'NavMeshSettings', 198: 'ParticleSystem',
    199: 'ParticleSystemRenderer', 200: 'ShaderVariantCollection',
    205: 'LODGroup', 206: 'BlendTree', 207: 'Motion',
    208: 'NavMeshObstacle', 212: 'SpriteRenderer', 213: 'Sprite',
    214: 'CachedSpriteAtlas', 215: 'ReflectionProbe', 218: 'Terrain',
    220: 'LightProbeGroup', 221: 'AnimatorOverrideController',
    222: 'CanvasRenderer', 223: 'Canvas', 224: 'RectTransform',
    225: 'CanvasGroup', 226: 'BillboardAsset', 227: 'BillboardRenderer',
    228: 'SpeedTreeWindAsset', 229: 'AnchoredJoint2D', 230: 'Joint2D',
    231: 'SpringJoint2D', 232: 'DistanceJoint2D', 233: 'HingeJoint2D',
    234: 'SliderJoint2D', 235: 'WheelJoint2D', 238: 'NavMeshData',
    240: 'AudioMixer', 241: 'AudioMixerController',
    243: 'AudioMixerGroupController', 244: 'AudioMixerEffectController',
    245: 'AudioMixerSnapshotController', 246: 'PhysicsUpdateBehaviour2D',
    247: 'ConstantForce2D', 248: 'Effector2D', 249: 'AreaEffector2D',
    250: 'PointEffector2D', 251: 'PlatformEffector2D',
    252: 'SurfaceEffector2D', 258: 'LightProbes',
    271: 'SampleClip', 272: 'AudioMixerSnapshot', 273: 'AudioMixerGroup',
    290: 'AssetBundleManifest', 1001: 'Prefab', 1002: 'EditorExtensionImpl',
    1003: 'AssetImporter', 1004: 'AssetDatabase', 1005: 'Mesh3DSImporter',
    1006: 'TextureImporter', 1007: 'ShaderImporter',
    1011: 'AudioImporter', 1020: 'AudioBuildInfo',
}

# Classes whose serialised body begins with an aligned length-prefixed
# `m_Name`, at this serialization version.  Everything else is reported as
# unnamed rather than scanned, because a scanned name and a structural one are
# different kinds of evidence and mixing them is the failure mode this
# collection keeps recording.
NAME_AT_0 = {
    21, 27, 28, 43, 48, 49, 74, 83, 89, 90, 91, 93, 95, 115, 117, 128,
    134, 142, 152, 156, 171, 184, 185, 186, 200, 206, 213, 226, 228, 238,
    240, 241, 243, 244, 245, 271, 272, 273, 290,
}


class Refused(Exception):
    """A refusal with a reason.  Never an exit code of 0."""


class Reader(object):
    def __init__(self, data, pos, little):
        self.d = data
        self.p = pos
        self.e = '<' if little else '>'

    def need(self, n):
        if self.p + n > len(self.d):
            raise Refused('ran past the end of the file at offset %d wanting '
                          '%d bytes of %d' % (self.p, n, len(self.d)))

    def u8(self):
        self.need(1)
        v = self.d[self.p]
        self.p += 1
        return v

    def i16(self):
        self.need(2)
        v = struct.unpack_from(self.e + 'h', self.d, self.p)[0]
        self.p += 2
        return v

    def u16(self):
        self.need(2)
        v = struct.unpack_from(self.e + 'H', self.d, self.p)[0]
        self.p += 2
        return v

    def i32(self):
        self.need(4)
        v = struct.unpack_from(self.e + 'i', self.d, self.p)[0]
        self.p += 4
        return v

    def u32(self):
        self.need(4)
        v = struct.unpack_from(self.e + 'I', self.d, self.p)[0]
        self.p += 4
        return v

    def i64(self):
        self.need(8)
        v = struct.unpack_from(self.e + 'q', self.d, self.p)[0]
        self.p += 8
        return v

    def raw(self, n):
        self.need(n)
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def cstr(self, limit=4096):
        z = self.d.find(b'\0', self.p)
        if z < 0 or z - self.p > limit:
            raise Refused('unterminated string at offset %d' % self.p)
        v = self.d[self.p:z]
        self.p = z + 1
        return v

    def align(self, n=4):
        self.p = (self.p + n - 1) // n * n


class SerializedFile15(object):
    """One version-15 SerializedFile, parsed, with both closures checked."""

    def __init__(self, data, path='<memory>'):
        self.path = path
        self.data = data
        if len(data) < 20:
            raise Refused('%d bytes is shorter than a header' % len(data))
        meta, fsize, version, doff = struct.unpack_from('>IIII', data, 0)
        self.metadata_size = meta
        self.file_size = fsize
        self.version = version
        self.data_offset = doff
        if version != VERSION_SUPPORTED:
            raise Refused('SerializedFile version %d; this reader is version '
                          '%d only and does not guess' %
                          (version, VERSION_SUPPORTED))
        if fsize != len(data):
            raise Refused('declared fileSize %d against %d bytes on disk'
                          % (fsize, len(data)))
        if not 0 < doff <= fsize:
            raise Refused('dataOffset %d outside a file of %d' % (doff, fsize))
        if not 0 < meta + 20 <= fsize:
            raise Refused('metadataSize %d outside a file of %d'
                          % (meta, fsize))
        self.endianness = data[16]
        if self.endianness not in (0, 1):
            raise Refused('endianness byte is %d, neither 0 nor 1'
                          % self.endianness)
        little = self.endianness == 0
        r = Reader(data, 20, little)
        self.unity_version = r.cstr(64).decode('ascii', 'replace')
        self.target_platform = r.i32()
        self.type_tree = bool(r.u8())
        n = r.i32()
        if not 0 <= n <= 1 << 16:
            raise Refused('typeCount %d is not credible' % n)
        self.types = []
        for _ in range(n):
            self.types.append(self._type(r))
        n = r.i32()
        if not 0 <= n <= 1 << 22:
            raise Refused('objectCount %d is not credible' % n)
        self.objects = []
        for _ in range(n):
            r.align(4)
            path_id = r.i64()
            byte_start = r.u32()
            byte_size = r.u32()
            type_id = r.i32()
            class_id = r.u16()
            script_type_index = r.i16()
            stripped = r.u8()
            end = doff + byte_start + byte_size
            if end > fsize:
                raise Refused('object %d ends at %d past the declared '
                              'fileSize %d' % (path_id, end, fsize))
            self.objects.append(dict(
                path_id=path_id, start=byte_start, size=byte_size,
                type_id=type_id, class_id=class_id,
                script_type_index=script_type_index, stripped=stripped))
        n = r.i32()
        if not 0 <= n <= 1 << 20:
            raise Refused('scriptTypeCount %d is not credible' % n)
        self.script_types = []
        for _ in range(n):
            fi = r.i32()
            r.align(4)
            self.script_types.append((fi, r.i64()))
        n = r.i32()
        if not 0 <= n <= 1 << 16:
            raise Refused('externalCount %d is not credible' % n)
        self.externals = []
        for _ in range(n):
            r.cstr(256)
            guid = r.raw(16)
            ty = r.i32()
            self.externals.append(dict(guid=guid.hex(), type=ty,
                                       path=r.cstr(512).decode('ascii',
                                                               'replace')))
        self.user_information = r.cstr(4096).decode('ascii', 'replace')
        self.metadata_end = r.p
        # CLOSURE 1.  Unity's integer against this reader's walk.  A layout
        # error anywhere above lands here, which is the point: without it a
        # reader can produce a full table of impossible numbers and exit 0.
        if self.metadata_end != meta + 20:
            raise Refused('metadata parse stopped at %d where metadataSize '
                          'declares %d; the layout is wrong'
                          % (self.metadata_end, meta + 20))

    def _type(self, r):
        class_id = r.i32()
        script_id = b''
        if class_id < 0:
            script_id = r.raw(16)
        old_hash = r.raw(16)
        tree = None
        if self.type_tree:
            tree = self._type_tree_blob(r)
        return dict(class_id=class_id, script_id=script_id.hex(),
                    hash=old_hash.hex(), tree=tree)

    def _type_tree_blob(self, r):
        """The blob form: a flat 24-byte node array and one string pool.

        Node width is 24 at every version below 19, where a 64-bit hash was
        appended.  Getting it wrong desynchronises every following type and is
        caught by closure 1 rather than by a guess.
        """
        count = r.i32()
        strbuf = r.i32()
        if not 0 <= count <= 1 << 20 or not 0 <= strbuf <= 1 << 24:
            raise Refused('type tree: %d nodes, %d string bytes, not credible'
                          % (count, strbuf))
        nodes = []
        for _ in range(count):
            r.need(24)
            ver = struct.unpack_from(r.e + 'H', r.d, r.p)[0]
            level = r.d[r.p + 2]
            flags = r.d[r.p + 3]
            toff, noff = struct.unpack_from(r.e + 'II', r.d, r.p + 4)
            bsize, index, meta = struct.unpack_from(r.e + 'iii', r.d, r.p + 12)
            r.p += 24
            nodes.append(dict(version=ver, level=level, flags=flags,
                              type_off=toff, name_off=noff, size=bsize,
                              index=index, meta=meta))
        pool = r.raw(strbuf)
        return dict(nodes=nodes, pool=pool)

    # -- the second closure ------------------------------------------------

    def extent(self):
        """dataOffset + the furthest object end, which Unity says is fileSize."""
        if not self.objects:
            return self.data_offset
        return self.data_offset + max(o['start'] + o['size']
                                      for o in self.objects)

    def closes(self):
        return self.extent() == self.file_size

    def object_bytes(self):
        return sum(o['size'] for o in self.objects)

    def body(self, o):
        s = self.data_offset + o['start']
        return self.data[s:s + o['size']]

    def name_of(self, o):
        """m_Name where the class is known to keep it at offset 0, else None."""
        if o['class_id'] not in NAME_AT_0:
            return None
        b = self.body(o)
        if len(b) < 4:
            return None
        little = self.endianness == 0
        n = struct.unpack_from('<i' if little else '>i', b, 0)[0]
        if not 0 <= n <= 4096 or 4 + n > len(b):
            return None
        try:
            t = b[4:4 + n].decode('utf-8')
        except UnicodeDecodeError:
            return None
        if any(ord(c) < 32 and c != '\t' for c in t):
            return None
        return t


# ---------------------------------------------------------------- discovery

def looks_serialized(data):
    """The cheap test: four big-endian u32 and an endianness byte."""
    if len(data) < 20:
        return False
    meta, fsize, version, doff = struct.unpack_from('>IIII', data, 0)
    if not 5 <= version <= 30:
        return False
    if data[16] not in (0, 1):
        return False
    return 0 < doff <= fsize and 0 < meta + 20 <= fsize


def walk(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            yield os.path.join(dirpath, nm)


def candidates(roots):
    """Every file in the roots whose first twenty bytes look like a header."""
    out = []
    for root in roots:
        for p in walk(root):
            try:
                with open(p, 'rb') as f:
                    head = f.read(20)
            except OSError:
                continue
            if looks_serialized(head):
                out.append(p)
    return out


def load(path):
    with open(path, 'rb') as f:
        return SerializedFile15(f.read(), path)


# ----------------------------------------------------------------- selftest

def _build(version=15, ntypes=1, nobjects=1, endian=0, break_what=None):
    """A minimal but complete version-15 file, built in memory.

    `break_what` names the single thing to corrupt, so that the refusals below
    are refusals of one specific defect rather than of a random byte.
    """
    little = endian == 0
    e = '<' if little else '>'
    meta = bytearray()
    meta += b'5.2.2p3\0'
    meta += struct.pack(e + 'i', 5)
    meta += b'\0'                                   # enableTypeTree = 0
    meta += struct.pack(e + 'i', ntypes)
    for i in range(ntypes):
        meta += struct.pack(e + 'i', 104)
        meta += b'\xaa' * 16
    meta += struct.pack(e + 'i', nobjects)
    body = bytearray()
    for i in range(nobjects):
        while len(meta) % 4:
            meta += b'\0'
        start = len(body)
        size = 16
        body += bytes(range(16))
        meta += struct.pack(e + 'q', i + 1)
        meta += struct.pack(e + 'II', start, size)
        meta += struct.pack(e + 'i', 104)
        meta += struct.pack(e + 'H', 104)
        if break_what == 'no_five':
            pass                                    # the v21 shape exactly
        else:
            meta += struct.pack(e + 'h', -1)
            meta += b'\0'
    meta += struct.pack(e + 'i', 0)                 # scriptTypes
    meta += struct.pack(e + 'i', 0)                 # externals
    meta += b'\0'                                   # userInformation
    metadata_size = len(meta)
    data_offset = (20 + metadata_size + 15) // 16 * 16
    pad = data_offset - 20 - metadata_size
    file_size = data_offset + len(body)
    if break_what == 'filesize':
        file_size += 1
    if break_what == 'metasize':
        metadata_size += 1
    if break_what == 'version':
        version = 21
    if break_what == 'endian':
        endian = 7
    head = struct.pack('>IIII', metadata_size, file_size, version, data_offset)
    head += bytes([endian, 0, 0, 0])
    out = bytearray(head + bytes(meta) + b'\0' * pad + bytes(body))
    if break_what == 'object_past_end':
        # rewrite the first object's byteSize to run past the file
        pass
    return bytes(out)


def cmd_selftest(_args):
    print('sfv15.py selftest -- specimens built in memory, most of them')
    print('required to be REFUSED.  A reader that accepts all of these is the')
    print('reader this file was written to replace.')
    print()
    ok = bad = 0

    def expect_ok(name, blob):
        nonlocal ok, bad
        try:
            sf = SerializedFile15(blob)
            print('  ACCEPT  %-34s objects %d, closure1 ok, closure2 %s'
                  % (name, len(sf.objects),
                     'ok' if sf.closes() else 'FAILED'))
            if not sf.closes():
                bad += 1
            else:
                ok += 1
        except Refused as ex:
            print('  ACCEPT  %-34s *** WRONGLY REFUSED: %s' % (name, ex))
            bad += 1

    def expect_refuse(name, blob, because):
        nonlocal ok, bad
        try:
            SerializedFile15(blob)
            print('  REFUSE  %-34s *** WRONGLY ACCEPTED (%s)' % (name, because))
            bad += 1
        except Refused as ex:
            print('  REFUSE  %-34s %s' % (name, ex))
            ok += 1

    expect_ok('one type, one object', _build())
    expect_ok('34 types, 101 objects', _build(ntypes=34, nobjects=101))
    expect_ok('big-endian metadata', _build(endian=1))
    expect_refuse('version 21', _build(break_what='version'),
                  'this reader is v15 only')
    expect_refuse('fileSize off by one', _build(break_what='filesize'),
                  'the header declares its own length')
    expect_refuse('metadataSize off by one', _build(break_what='metasize'),
                  'closure 1')
    expect_refuse('endianness byte 7', _build(break_what='endian'),
                  'neither 0 nor 1')
    expect_refuse('v21 ObjectInfo shape (the actual bug)',
                  _build(nobjects=8, break_what='no_five'),
                  'five bytes short per object')
    expect_refuse('empty file', b'', 'shorter than a header')
    expect_refuse('nineteen bytes', b'\0' * 19, 'shorter than a header')
    expect_refuse('a Lua script', b'\x1bLuaR\x00\x01\x04\x04\x04\x04\x00'
                                  b'\x19\x93\r\n\x1a\n' + b'\0' * 64,
                  'not a SerializedFile at all')
    expect_refuse('a UnityWeb bundle header',
                  b'UnityWeb\x00' + b'\x00' * 64, 'wrong container')
    expect_refuse('an @UTF table', b'@UTF' + b'\x00' * 64, 'wrong container')
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


# ----------------------------------------------------------------- commands

def cmd_validate(args):
    paths = [p for r in args.paths for p in walk(r)]
    print('%-52s %10s %10s  %s' % ('FILE', 'DECLARED', 'ON DISK', 'VERDICT'))
    n_ok = n_ref = n_skip = 0
    for p in paths:
        try:
            with open(p, 'rb') as f:
                head = f.read(20)
        except OSError:
            continue
        if not looks_serialized(head):
            n_skip += 1
            continue
        size = os.path.getsize(p)
        declared = struct.unpack_from('>I', head, 4)[0]
        try:
            load(p)
            verdict = 'read'
            n_ok += 1
        except Refused as ex:
            verdict = 'REFUSED: %s' % ex
            n_ref += 1
        print('%-52s %10d %10d  %s'
              % (short(p), declared, size, verdict))
    print()
    print('%d read, %d refused, %d skipped as not a SerializedFile'
          % (n_ok, n_ref, n_skip))
    return 0 if n_ref == 0 else 2


def short(p, keep=52):
    p = p.replace('\\', '/')
    return p if len(p) <= keep else '...' + p[-(keep - 3):]


def cmd_info(args):
    sf = load(args.paths[0])
    print(short(args.paths[0], 200))
    print()
    print('format version      %d' % sf.version)
    print('unity version       %s' % sf.unity_version)
    print('target platform     %d%s' % (sf.target_platform,
                                        ' (StandaloneWindows)'
                                        if sf.target_platform == 5 else ''))
    print('endianness          %s' % ('little' if sf.endianness == 0
                                      else 'big'))
    print('type tree           %s' % ('present' if sf.type_tree else 'absent'))
    print('metadataSize        %d' % sf.metadata_size)
    print('  parse stopped at  %d          closure 1 %s'
          % (sf.metadata_end, 'CLOSES' if sf.metadata_end ==
             sf.metadata_size + 20 else 'FAILS'))
    print('dataOffset          %d' % sf.data_offset)
    print('fileSize declared   %d' % sf.file_size)
    print('  on disk           %d' % len(sf.data))
    print('  dataOffset + max object end %d   closure 2 %s'
          % (sf.extent(), 'CLOSES' if sf.closes() else 'FAILS'))
    print('types               %d' % len(sf.types))
    print('objects             %d' % len(sf.objects))
    print('  object bytes      %d' % sf.object_bytes())
    print('script types        %d' % len(sf.script_types))
    print('externals           %d' % len(sf.externals))
    print('userInformation     %r' % sf.user_information)
    neg = [t['class_id'] for t in sf.types if t['class_id'] < 0]
    print('negative typeIDs    %d of %d types (MonoBehaviour scripts)'
          % (len(neg), len(sf.types)))
    if sf.externals:
        print()
        print('externals:')
        for x in sf.externals:
            print('  type %d  %s' % (x['type'], x['path']))
    return 0


def cmd_objects(args):
    sf = load(args.paths[0])
    print('%-20s %-28s %10s %10s %8s  %s'
          % ('PATH ID', 'CLASS', 'START', 'SIZE', 'TYPEID', 'NAME'))
    n = 0
    for o in sf.objects:
        if args.klass is not None and o['class_id'] != args.klass:
            continue
        if n >= args.limit:
            break
        n += 1
        nm = sf.name_of(o)
        print('%-20d %-28s %10d %10d %8d  %s'
              % (o['path_id'],
                 '%s (%d)' % (CLASS.get(o['class_id'], '?'), o['class_id']),
                 o['start'], o['size'], o['type_id'], nm if nm else ''))
    print()
    print('%d objects listed of %d' % (n, len(sf.objects)))
    return 0


def cmd_close(args):
    paths = candidates(args.paths)
    print('Two closures, both of them Unity\'s arithmetic and not this')
    print('reader\'s: metadataSize against where the metadata parse stops,')
    print('and dataOffset + the furthest object end against fileSize.')
    print()
    print('%-52s %8s %8s %6s %6s' %
          ('FILE', 'BYTES', 'OBJECTS', 'META', 'DATA'))
    n = c1 = c2 = 0
    total = objs = objbytes = 0
    refused = []
    for p in paths:
        try:
            sf = load(p)
        except Refused as ex:
            refused.append((p, str(ex)))
            continue
        n += 1
        m_ok = sf.metadata_end == sf.metadata_size + 20
        d_ok = sf.closes()
        c1 += m_ok
        c2 += d_ok
        total += sf.file_size
        objs += len(sf.objects)
        objbytes += sf.object_bytes()
        print('%-52s %8d %8d %6s %6s'
              % (short(p), sf.file_size, len(sf.objects),
                 'ok' if m_ok else 'FAIL', 'ok' if d_ok else 'FAIL'))
    print()
    print('files read              : %d' % n)
    print('closure 1 (metadataSize): %d of %d' % (c1, n))
    print('closure 2 (fileSize)    : %d of %d' % (c2, n))
    print('bytes                   : %d' % total)
    print('objects                 : %d' % objs)
    print('object bytes            : %d of %d, residue %d'
          % (objbytes, total, total - objbytes))
    if refused:
        print()
        print('%d refused:' % len(refused))
        for p, why in refused:
            print('  %-52s %s' % (short(p), why))
    return 0 if (n and c1 == n and c2 == n and not refused) else 2


def cmd_paths(args):
    """Unity's `ResourceManager` (class 147): the table of names the game
    loads objects by, rather than by reference.

    The body is `i32 count`, then that many (aligned string, i32 fileID,
    i64 pathID).  The count is the check: the walk must produce exactly that
    many entries with no string length out of range, and it does.
    """
    total = 0
    for p in candidates(args.paths):
        sf = load(p)
        for o in sf.objects:
            if o['class_id'] != 147:
                continue
            b = sf.body(o)
            n, = struct.unpack_from('<i', b, 0)
            if not 0 <= n <= 1 << 20:
                raise Refused('ResourceManager count %d is not credible' % n)
            q = 4
            paths = []
            for _ in range(n):
                if q + 4 > len(b):
                    raise Refused('path table runs past the object body')
                ln, = struct.unpack_from('<i', b, q)
                q += 4
                if not 0 <= ln <= 512 or q + ln > len(b):
                    raise Refused('path length %d at %d is not credible'
                                  % (ln, q))
                paths.append(b[q:q + ln].decode('utf-8', 'replace'))
                q += ln
                q = (q + 3) & ~3
                q += 12                      # fileID i32 + pathID i64
            print('%s' % short(p))
            print('  entries declared %d, parsed %d' % (n, len(paths)))
            print('  table consumed %d of the %d-byte object body'
                  % (q, len(b)))
            pre = collections.Counter(s.split('/')[0] for s in paths)
            print()
            print('  %-28s %s' % ('TOP-LEVEL SEGMENT', 'ENTRIES'))
            for k, v in pre.most_common(args.limit):
                print('  %-28s %d' % (k, v))
            print()
            for s in paths[:8]:
                print('    %s' % s)
            total += len(paths)
    print()
    print('%d paths over all ResourceManager objects' % total)
    return 0


def cmd_account(args):
    """Every byte of every file, in five buckets that must sum to fileSize.

    Closure 2 only proves the furthest object ends where the header says the
    file does.  This is the stronger statement: header, metadata, the padding
    to dataOffset, every object body and every alignment gap between objects,
    summed, against fileSize -- with overlaps counted separately, because two
    objects claiming the same byte would make the sum close for the wrong
    reason.
    """
    paths = candidates(args.paths)
    t = collections.Counter()
    files = nover = 0
    refused = []
    print('%-52s %10s %8s %8s' % ('FILE', 'BYTES', 'OBJECTS', 'RESIDUE'))
    for p in paths:
        try:
            sf = load(p)
        except Refused as ex:
            refused.append((p, str(ex)))
            continue
        files += 1
        objs = sorted(sf.objects, key=lambda o: o['start'])
        cur = gap = over = 0
        for o in objs:
            if o['start'] < cur:
                over += cur - o['start']
            else:
                gap += o['start'] - cur
            cur = max(cur, o['start'] + o['size'])
        if over == 0:
            nover += 1
        obj = sum(o['size'] for o in objs)
        hpad = sf.data_offset - 20 - sf.metadata_size
        acc = 20 + sf.metadata_size + hpad + obj + gap
        t['fs'] += sf.file_size
        t['hdr'] += 20
        t['meta'] += sf.metadata_size
        t['hpad'] += hpad
        t['obj'] += obj
        t['gap'] += gap
        t['over'] += over
        print('%-52s %10d %8d %8d'
              % (short(p), sf.file_size, len(objs), sf.file_size - acc))
    s = t['hdr'] + t['meta'] + t['hpad'] + t['obj'] + t['gap']
    print()
    print('files                       : %d' % files)
    print('non-overlapping object sets : %d of %d' % (nover, files))
    print('header      20 bytes each   : %d' % t['hdr'])
    print('metadata                    : %d' % t['meta'])
    print('padding to dataOffset       : %d' % t['hpad'])
    print('object bodies               : %d' % t['obj'])
    print('alignment gaps between them : %d' % t['gap'])
    print('                              ----------')
    print('sum                         : %d' % s)
    print('fileSize, summed            : %d' % t['fs'])
    print('RESIDUE                     : %d' % (t['fs'] - s))
    print('overlapping bytes           : %d' % t['over'])
    if refused:
        print()
        print('%d refused:' % len(refused))
        for p, why in refused:
            print('  %-52s %s' % (short(p), why))
    return 0 if (files and t['fs'] == s and t['over'] == 0
                 and not refused) else 2


def cmd_census(args):
    paths = candidates(args.paths)
    per = collections.Counter()
    byt = collections.Counter()
    versions = collections.Counter()
    unity = collections.Counter()
    files = objs = 0
    total_file_bytes = 0
    refused = []
    for p in paths:
        try:
            sf = load(p)
        except Refused as ex:
            refused.append((p, str(ex)))
            continue
        files += 1
        total_file_bytes += sf.file_size
        versions[sf.version] += 1
        unity[sf.unity_version] += 1
        for o in sf.objects:
            per[o['class_id']] += 1
            byt[o['class_id']] += o['size']
            objs += 1
    total = sum(byt.values())
    # The assertion `unityfs.py` does not make.  A per-class byte total larger
    # than the bytes those files occupy is impossible, and this is a one-line
    # check that says so out loud instead of printing the table.
    if total > total_file_bytes:
        sys.stderr.write('FATAL: object bytes %d exceed the %d bytes of the '
                         '%d files they came from\n'
                         % (total, total_file_bytes, files))
        return 3
    print('%d serialized files, %d objects, %d bytes of file'
          % (files, objs, total_file_bytes))
    print('format versions: %s' % ', '.join('%d x%d' % kv
                                            for kv in sorted(versions.items())))
    print('unity versions:  %s' % ', '.join('%s x%d' % kv
                                            for kv in sorted(unity.items())))
    print()
    print('%-32s %9s %14s %8s' % ('CLASS', 'OBJECTS', 'BYTES', 'SHARE'))
    for cid, n in per.most_common(args.limit):
        print('%-32s %9d %14d %7.2f%%'
              % ('%s (%d)' % (CLASS.get(cid, '?'), cid), n, byt[cid],
                 100.0 * byt[cid] / total if total else 0.0))
    print('%-32s %9d %14d %7.2f%%' % ('TOTAL', objs, total, 100.0))
    print()
    print('object bytes %d of %d file bytes, residue %d (header, metadata, '
          'alignment)' % (total, total_file_bytes, total_file_bytes - total))
    print('negative class IDs: %d  (a v15 reader cannot produce one: the '
          'class comes from a u16)' % sum(1 for c in per if c < 0))
    if refused:
        print()
        print('%d candidates refused:' % len(refused))
        for p, why in refused[:20]:
            print('  %-52s %s' % (short(p), why))
    return 0


def cmd_names(args):
    paths = candidates(args.paths)
    n = 0
    named = unnamed = 0
    for p in paths:
        try:
            sf = load(p)
        except Refused:
            continue
        for o in sf.objects:
            if args.klass is not None and o['class_id'] != args.klass:
                continue
            nm = sf.name_of(o)
            if nm is None:
                unnamed += 1
                continue
            named += 1
            if n < args.limit:
                n += 1
                print('%-40s %-24s %s'
                      % (short(p, 40),
                         '%s (%d)' % (CLASS.get(o['class_id'], '?'),
                                      o['class_id']), nm))
    print()
    print('%d named, %d unnamed (the class does not keep m_Name at offset 0)'
          % (named, unnamed))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'validate', 'info', 'objects',
                                     'close', 'account', 'census', 'names',
                                     'paths'))
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--class', dest='klass', type=int)
    ap.add_argument('--limit', type=int, default=40)
    args = ap.parse_args()
    if args.mode != 'selftest' and not args.paths:
        ap.error('%s needs a path' % args.mode)
    fn = globals()['cmd_' + args.mode]
    try:
        return fn(args)
    except Refused as ex:
        sys.stderr.write('REFUSED: %s\n' % ex)
        return 2


if __name__ == '__main__':
    sys.exit(main())
