#!/usr/bin/env python3
"""Read Unity SerializedFiles with no Unity and no third-party package.

*Tales of Luminaria* ships its content as Unity serialized files rather than as
an engine container of its own: `globalgamemanagers`, seven `levelN` scenes,
seven `sharedassetsN.assets` (one of them split across nine parts), and 447
individually serialised assets named after their GUID.  None of them is
encrypted -- which is worth saying plainly, because the native code beside them
is -- so the whole object graph is readable from the outside.

What the format is, at the version this build writes (21, Unity 2019.4.16f1):

    +0x00  u32 BE  metadataSize
    +0x04  u32 BE  fileSize          -- the file's own length, so a free
    +0x08  u32 BE  version              positive control on every read
    +0x0C  u32 BE  dataOffset
    +0x10  u8      endianness (0 = little), then three reserved bytes
           cstr    unity version, e.g. "2019.4.16f1"
           i32     target platform (13 = Android)
           u8      type tree present
           i32     type count, then that many SerializedType
           i32     object count, then that many ObjectInfo:
                     align 4; i64 pathID; u32 byteStart; u32 byteSize; i32 type
           i32     script type count, then (i32 fileIndex, align, i64 id)
           i32     external count, then (cstr, guid[16], i32, cstr path)
           i32     reference type count (version >= 20)
           cstr    user information

The `fileSize` field is the check this repository asks every container to
supply and almost none does: the header states the length of the thing it
describes, written by Unity and by nothing of ours, so a reader that has the
layout wrong is caught by the file rather than by an assumption.  `verify`
reports it, and reports every object whose byteStart+byteSize runs past the
end, which is the same check one level down.

Names are read where the class puts them.  Most NamedObject subclasses begin
with `m_Name` as an aligned length-prefixed string; MonoBehaviour puts it at
+28, after m_GameObject, m_Enabled and m_Script; GameObject puts it after the
component array and m_Layer.  Anything else is reported as unnamed rather than
guessed at, and the count of unnamed objects is printed, because a name census
that silently drops what it cannot parse is the failure mode section 7 of
tales-blockcodec-doc keeps recording.

    python unityfs.py info    FILE
    python unityfs.py objects FILE [--class N] [--limit N]
    python unityfs.py verify  PATH...        -- fileSize and object bounds
    python unityfs.py census  DIR            -- every object of every file, by class
    python unityfs.py names   DIR [--class N] [--out FILE]
    python unityfs.py text    DIR            -- every TextAsset, with its content
    python unityfs.py scripts DIR [--list]   -- MonoScript class/namespace/assembly
    python unityfs.py paths   FILE           -- the ResourceManager path table
    python unityfs.py textures DIR           -- every Texture2D, with a size check
    python unityfs.py shaders FILE           -- the ScriptMapper's shader-name table
    python unityfs.py externals DIR          -- the reference graph between files
    python unityfs.py classes                -- the class-ID table this tool knows
    python unityfs.py selftest               -- hand-built headers at 17 and 22, a PNG refused

TWO THINGS MENDED ON pc-thewardrobe-doc (Unity 6000.3.6f1, format 22)
------------------------------------------------------------------------
1. `is_serialized()` accepted `SaveIcon.png`: a PNG's IHDR chunk length
   (`00 00 00 0D` at +8) read as version 13 and the high byte of its width
   (+16) as endianness 0, so `load()` walked into it and died with a
   `struct.error` traceback, and that traceback killed `unitytex17.py
   census` and `unitymovie.py census` whole. Now `is_serialized()` closes
   on `fileSize == the file's own length` as coverage.py's probe always
   has, and `load()` raises `NotSerialized` (a ValueError) with the path
   and the reason instead of letting `struct` speak: a reader refuses, it
   does not raise.
2. `info` printed `metadata size 1292 (parsed to 1340)`, which on
   pc-monstrum-doc (format 17) read `1292 (parsed to 1312)`: the file's
   `metadataSize` counts from the END of the header and the reader's
   position counts from byte 0, so the two differ by the header -- 20
   bytes at 17, 48 at 22 -- and by nothing else. The line now says so and
   `verify` counts the closure `header + metadataSize == parse end` on
   every file, so a real over-read would be a number and not a
   parenthesis.

Standard library only.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nameguard                                        # noqa: E402

# This tool prints the names of the files it refuses, and on
# pc-rpgmakervxace-doc one of them is Japanese. Without this it dies of
# UnicodeEncodeError when PYTHONIOENCODING is unset, and `refusalclass.py`
# then files it under `exception` -- so a published figure about the OBJECT
# moved by two because of an environment variable.
nameguard.guard()

# Unity's runtime class IDs.  Only the ones that turn up in this package are
# named; anything else is printed as its number, never guessed at.
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
    84: 'RenderTexture', 86: 'CustomRenderTexture', 89: 'Cubemap',
    90: 'Avatar', 91: 'AnimatorController', 93: 'RuntimeAnimatorController',
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
    208: 'NavMeshObstacle', 210: 'SortingGroup', 212: 'SpriteRenderer',
    213: 'Sprite', 214: 'CachedSpriteAtlas', 215: 'ReflectionProbe',
    218: 'Terrain', 220: 'LightProbeGroup', 221: 'AnimatorOverrideController',
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
    252: 'SurfaceEffector2D', 253: 'BuoyancyEffector2D',
    254: 'RelativeJoint2D', 255: 'FixedJoint2D', 256: 'FrictionJoint2D',
    257: 'TargetJoint2D', 258: 'LightProbes', 259: 'LightProbeProxyVolume',
    271: 'SampleClip', 272: 'AudioMixerSnapshot', 273: 'AudioMixerGroup',
    290: 'AssetBundleManifest', 300: 'RuntimeInitializeOnLoadManager',
    310: 'UnityConnectSettings', 319: 'AvatarMask', 320: 'PlayableDirector',
    328: 'VideoPlayer', 329: 'VideoClip', 330: 'BillboardBatchRenderer',
    331: 'SpriteMask', 362: 'WorldAnchor', 363: 'OcclusionCullingData',
    1001: 'PrefabInstance', 1002: 'EditorExtensionImpl',
    1006: 'TextureImporter', 1007: 'ShaderImporter',
    1020: 'AudioImporter', 1035: 'ModelImporter',
    687078895: 'SpriteAtlas', 1480428607: 'SpriteAtlasDatabase',
    -1: 'UnknownType',
}

# Where m_Name lives, per class.  0 means "the object starts with it".
NAME_AT_28 = {114}          # MonoBehaviour: after GameObject, Enabled, Script
NAME_SPECIAL = {1}          # GameObject: after the component array and m_Layer
# Shader keeps m_Name inside m_ParsedForm, after the property table and every
# subshader, so no fixed offset reaches it and a player build carries no type
# tree to ask.  Scanning does NOT recover it: the first plausible string in a
# Shader object is the first entry of its property table, so a scan returns
# `_MainTex` and `$Globals` and looks like it worked.  Shader is therefore
# reported as unnamed here, and its real names come from the ScriptMapper --
# `unityfs.py shaders`.  See docs/09-corrections.md.
SCANNED_NAME = set()
# Everything else that carries a name is a NamedObject subclass and starts
# with it; anything that does not is reported unnamed, not guessed.
# 30 and 94 are GraphicsSettings and ScriptMapper -- identified by their
# position in Unity's fixed manager order in globalgamemanagers, not by a
# published table -- and 1403656975 is a manager this repository has not
# identified at all (docs/99-open-questions.md).  None of the three carries
# m_Name, and the last two are zero bytes long.
# 98 is DelayedCallManager, whose serialized body in this package is zero
# bytes long -- a manager with no fields, not a parse failure.
UNNAMED = {98, 30, 94, 1403656975, 937362698, 48, 4, 224, 222, 223, 225, 33, 23, 25, 212, 137, 95, 20, 108, 82, 81,
           2, 8, 18, 27, 5, 6, 9, 11, 13, 19, 29, 47, 55, 78, 104, 116, 126,
           129, 141, 147, 150, 157, 159, 196, 205, 210, 220, 258, 300, 310,
           363, 1001}


# Unity's built-in type-tree string pool.  A type-tree node names its type and
# its field by an offset; with bit 0x80000000 set the offset indexes this fixed
# table instead of the per-file pool, which is how the format avoids writing
# "m_Name" and "PPtr<Texture2D>" into every file.  The table is Unity's, not
# this repository's, and it is reproduced verbatim -- a wrong byte here shows
# up as a garbled field name and nothing worse, but a missing one shows up as
# a field that cannot be found.
COMMON_STRINGS = (
    b'AABB\0AnimationClip\0AnimationCurve\0AnimationState\0Array\0Base\0'
    b'BitField\0bitset\0bool\0char\0ColorRGBA\0Component\0data\0deque\0'
    b'double\0dynamic_array\0FastPropertyName\0first\0float\0Font\0'
    b'GameObject\0Generic Mono\0GradientNEW\0GUID\0GUIStyle\0int\0list\0'
    b'long long\0map\0Matrix4x4f\0MdFour\0MonoBehaviour\0MonoScript\0'
    b'm_ByteSize\0m_Curve\0m_EditorClassIdentifier\0m_EditorHideFlags\0'
    b'm_Enabled\0m_ExtensionPtr\0m_GameObject\0m_Index\0m_IsArray\0'
    b'm_IsStatic\0m_MetaFlag\0m_Name\0m_ObjectHideFlags\0m_PrefabInternal\0'
    b'm_PrefabParentObject\0m_Script\0m_StaticEditorFlags\0m_Type\0'
    b'm_Version\0Object\0pair\0PPtr<Component>\0PPtr<GameObject>\0'
    b'PPtr<Material>\0PPtr<MonoBehaviour>\0PPtr<MonoScript>\0PPtr<Object>\0'
    b'PPtr<Prefab>\0PPtr<Sprite>\0PPtr<TextAsset>\0PPtr<Texture>\0'
    b'PPtr<Texture2D>\0PPtr<Transform>\0Prefab\0Quaternionf\0Rectf\0'
    b'RectInt\0RectOffset\0second\0set\0short\0size\0SInt16\0SInt32\0'
    b'SInt64\0SInt8\0staticvector\0string\0TextAsset\0TextMesh\0Texture\0'
    b'Texture2D\0Transform\0TypelessData\0UInt16\0UInt32\0UInt64\0UInt8\0'
    b'unsigned int\0unsigned long long\0unsigned short\0vector\0Vector2f\0'
    b'Vector3f\0Vector4f\0m_ScriptingClassIdentifier\0Gradient\0Type*\0'
    b'int2_storage\0int3_storage\0BoundsInt\0m_CorrespondingSourceObject\0'
    b'm_PrefabInstance\0m_PrefabAsset\0FileSize\0Hash128\0')


def _tt_string(off, pool):
    if off & 0x80000000:
        buf = COMMON_STRINGS
        off &= 0x7FFFFFFF
    else:
        buf = pool
    if off >= len(buf):
        return '(offset %d)' % off
    end = buf.find(b'\0', off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode('utf-8', 'replace')


class Reader(object):
    def __init__(self, data, pos=0, little=True):
        self.d = data
        self.p = pos
        self.e = '<' if little else '>'

    def u8(self):
        v = self.d[self.p]
        self.p += 1
        return v

    def i16(self):
        v = struct.unpack_from(self.e + 'h', self.d, self.p)[0]
        self.p += 2
        return v

    def i32(self):
        v = struct.unpack_from(self.e + 'i', self.d, self.p)[0]
        self.p += 4
        return v

    def u32(self):
        v = struct.unpack_from(self.e + 'I', self.d, self.p)[0]
        self.p += 4
        return v

    def i64(self):
        v = struct.unpack_from(self.e + 'q', self.d, self.p)[0]
        self.p += 8
        return v

    def raw(self, n):
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def cstr(self):
        end = self.d.find(b'\0', self.p)
        if end < 0:
            end = len(self.d)
        v = self.d[self.p:end]
        self.p = end + 1
        return v.decode('utf-8', 'replace')

    def align(self, n=4):
        self.p = (self.p + n - 1) & ~(n - 1)


class NotSerialized(ValueError):
    """`load()` refuses a file that is not a SerializedFile with this, and
    a caller walking a tree catches it and counts the file as skipped."""


def _header_check(data, path='?'):
    """The header's own arithmetic, before a byte of metadata is parsed:
    version 5..30, endianness 0 or 1, and fileSize == len(data) -- the
    free positive control Unity writes on every file. Returns None or the
    reason the file is refused."""
    if len(data) < 20:
        return 'too short to be a SerializedFile (%d bytes)' % len(data)
    _m, fsize, version, _d = struct.unpack_from('>IIII', data, 0)
    if not 5 <= version <= 30:
        return 'version %d is not a SerializedFile version' % version
    if data[16] not in (0, 1):
        return 'endianness byte %d is neither 0 nor 1' % data[16]
    if version >= 22:
        if len(data) < 48:
            return 'version %d needs a 48-byte header, %d bytes' % (version, len(data))
        fsize = struct.unpack_from('>q', data, 24)[0]
    if fsize != len(data):
        return ('fileSize %d does not equal the file\'s %d bytes'
                % (fsize, len(data)))
    return None


class SerializedFile(object):
    def __init__(self, data, path='?'):
        self.data = data
        self.path = path
        why = _header_check(data, path)
        if why:
            raise NotSerialized('%s: %s' % (path, why))
        try:
            self._parse(data)
        except (struct.error, IndexError, UnicodeDecodeError) as ex:
            raise NotSerialized('%s: header passes but the metadata does not '
                                'parse (%s: %s)' % (path, type(ex).__name__, ex))

    def _parse(self, data):
        (self.metadata_size, self.file_size, self.version,
         self.data_offset) = struct.unpack_from('>IIII', data, 0)
        if not 5 <= self.version <= 30:
            raise ValueError('version %d is not a SerializedFile version'
                             % self.version)
        self.endianness = data[16]
        # Version 22 moved the three size fields out of the 32-bit header and
        # into 64-bit fields after it, zeroing the originals.  A reader that
        # does not know this reads metadataSize=0, fileSize=0, dataOffset=0 and
        # then walks off the end of the buffer -- which is how this object
        # announced itself: DISSIDIA's globalgamemanagers is Unity 6000.3.10f1
        # and every one of its serialized files is version 22.
        #   +20  u32 BE  metadataSize
        #   +24  i64 BE  fileSize      -- still the file's own length
        #   +32  i64 BE  dataOffset
        #   +40  i64 BE  (unknown, zero on every file measured here)
        #   +48  cstr    unity version
        self.big_header = self.version >= 22
        if self.big_header:
            self.metadata_size = struct.unpack_from('>I', data, 20)[0]
            self.file_size = struct.unpack_from('>q', data, 24)[0]
            self.data_offset = struct.unpack_from('>q', data, 32)[0]
            self.header_unknown = struct.unpack_from('>q', data, 40)[0]
            start = 48
        else:
            self.header_unknown = None
            start = 20
        r = Reader(data, start, little=(self.endianness == 0))
        self.unity_version = r.cstr()
        self.target_platform = r.i32()
        self.type_tree = bool(r.u8())
        self.types = []
        n = r.i32()
        for _ in range(n):
            self.types.append(self._type(r, False))
        self.objects = []
        n = r.i32()
        for _ in range(n):
            r.align(4)
            path_id = r.i64()
            if self.version >= 22:
                byte_start = r.i64()
            else:
                byte_start = r.u32()
            byte_size = r.u32()
            type_id = r.i32()
            self.objects.append(dict(path_id=path_id, start=byte_start,
                                     size=byte_size, type_index=type_id))
        self.script_types = []
        if self.version >= 11:
            n = r.i32()
            for _ in range(n):
                fi = r.i32()
                r.align(4)
                self.script_types.append((fi, r.i64()))
        self.externals = []
        n = r.i32()
        for _ in range(n):
            r.cstr()
            guid = r.raw(16)
            ty = r.i32()
            self.externals.append(dict(guid=guid.hex(), type=ty,
                                       path=r.cstr()))
        self.ref_types = []
        if self.version >= 20:
            try:
                n = r.i32()
                if 0 <= n < 4096:
                    for _ in range(n):
                        self.ref_types.append(self._type(r, True))
            except (struct.error, IndexError):
                pass
        try:
            self.user_information = r.cstr()
        except (struct.error, IndexError):
            self.user_information = ''
        self.metadata_end = r.p
        # `metadataSize` counts from the end of the header; `metadata_end`
        # counts from byte 0. Header 20 bytes below version 22, 48 from it.
        self.header_size = 48 if self.big_header else 20
        self.metadata_closes = (self.header_size + self.metadata_size
                                == self.metadata_end)

    def _type(self, r, is_ref):
        class_id = r.i32()
        stripped = r.u8() if self.version >= 16 else 0
        script_index = r.i16() if self.version >= 17 else -1
        script_id = b''
        if is_ref and script_index >= 0:
            script_id = r.raw(16)
        elif self.version >= 16 and class_id == 114:
            script_id = r.raw(16)
        elif self.version < 16 and class_id < 0:
            script_id = r.raw(16)
        old_hash = r.raw(16)
        tree = None
        deps = []
        if self.type_tree:
            # Luminaria's files were built with the type tree stripped, so this
            # branch never ran and the reader simply stopped after the hash.
            # DISSIDIA's bundles ship the tree -- typeTreePresent is 1 on every
            # SerializedFile inside a UnityFS archive here and 0 on every one
            # in the APK -- and a reader that skips it walks off the end of the
            # buffer, which is how this was found rather than assumed.
            tree = self._type_tree_blob(r)
            if self.version >= 21:
                if is_ref:
                    r.cstr()
                    r.cstr()
                    r.cstr()
                else:
                    n = r.i32()
                    deps = [r.i32() for _ in range(n)]
        return dict(class_id=class_id, stripped=stripped,
                    script_index=script_index, script_id=script_id.hex(),
                    hash=old_hash.hex(), tree=tree, deps=deps)

    def _type_tree_blob(self, r):
        """The blob form of the type tree: a flat node array and one string
        pool, with each node naming its type and field by offset into the pool.
        Offsets with bit 0x80000000 set index Unity's built-in string table
        instead of the pool.

        Node width is 24 bytes, and 32 from version 19 on because a 64-bit
        reference-type hash was appended.  Getting that wrong desynchronises
        every following type, so the caller's `fileSize` check is the control.
        """
        count = r.i32()
        strbuf = r.i32()
        if not 0 <= count <= 1 << 20 or not 0 <= strbuf <= 1 << 24:
            raise ValueError('type tree: %d nodes, %d string bytes, not '
                             'credible' % (count, strbuf))
        wide = self.version >= 19
        nodes = []
        for _ in range(count):
            ver = struct.unpack_from(r.e + 'H', r.d, r.p)[0]
            level = r.d[r.p + 2]
            flags = r.d[r.p + 3]
            toff, noff = struct.unpack_from(r.e + 'II', r.d, r.p + 4)
            bsize, index, meta = struct.unpack_from(r.e + 'iii', r.d, r.p + 12)
            r.p += 32 if wide else 24
            nodes.append(dict(version=ver, level=level, flags=flags,
                              type_off=toff, name_off=noff, size=bsize,
                              index=index, meta=meta))
        pool = r.raw(strbuf)
        for n in nodes:
            n['type'] = _tt_string(n['type_off'], pool)
            n['name'] = _tt_string(n['name_off'], pool)
        return nodes

    def class_of(self, obj):
        i = obj['type_index']
        if 0 <= i < len(self.types):
            return self.types[i]['class_id']
        return i

    def body(self, obj):
        s = self.data_offset + obj['start']
        return self.data[s:s + obj['size']]

    def name_of(self, obj, scan=False):
        """m_Name, where the class is known to keep it.  None when not.

        With `scan`, classes whose name offset is not fixed fall back to
        `scan_string`, and the caller is told which route produced it by
        `name_method`.
        """
        cid = self.class_of(obj)
        if scan and cid in SCANNED_NAME:
            return scan_string(self.body(obj))
        if cid in UNNAMED:
            return None
        b = self.body(obj)
        little = self.endianness == 0
        if cid in NAME_AT_28:
            return _string_at(b, 28, little)
        if cid in NAME_SPECIAL:
            if len(b) < 4:
                return None
            n = struct.unpack_from('<i' if little else '>i', b, 0)[0]
            if not 0 <= n < 4096:
                return None
            off = 4 + n * 12 + 4          # components, then m_Layer
            return _string_at(b, off, little)
        return _string_at(b, 0, little)


def _string_at(b, off, little):
    """An aligned length-prefixed string at a known offset, or None.

    A zero length is a *result*, not a failure: most MonoBehaviour components
    attached to a GameObject carry an empty m_Name, and rejecting length zero
    reported 800 of this package's 828 of them as unparsed.  Empty comes back
    as the empty string and is counted apart from a name that is really there.
    """
    if off < 0 or off + 4 > len(b):
        return None
    n = struct.unpack_from('<i' if little else '>i', b, off)[0]
    if not 0 <= n <= 1024 or off + 4 + n > len(b):
        return None
    s = b[off + 4:off + 4 + n]
    try:
        t = s.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 32 and c not in '\t' for c in t):
        return None
    return t


def scan_string(b, minlen=3, maxlen=256, limit=4096):
    """The first plausible aligned string anywhere in the first `limit` bytes.

    This is a *fallback*, and it is kept separate from `name_of` so that a
    number obtained this way is never mixed with a number obtained from a known
    field offset.  Shader is the class that needs it: at this serialization
    version its `m_ParsedForm.m_Name` sits after the whole property table and
    every subshader, at an offset no fixed rule can give, and there is no type
    tree in a player build to ask.  Reporting 95 shaders as unnamed would be a
    false negative; reporting a scanned name as a structural one would be worse.
    """
    n = min(len(b), limit)
    for off in range(0, n - 4, 4):
        ln = struct.unpack_from('<i', b, off)[0]
        if not minlen <= ln <= maxlen or off + 4 + ln > len(b):
            continue
        s = b[off + 4:off + 4 + ln]
        try:
            t = s.decode('ascii')
        except UnicodeDecodeError:
            continue
        if all(32 <= ord(c) < 127 for c in t):
            return t
    return None


def read_whole(path):
    """The file's bytes, joining a `.splitN` set back together first.

    Unity's Android build splits any serialized file over a size limit into
    `name.split0`, `name.split1`, ...  Each part is a fragment: only part zero
    carries the header, and its declared `fileSize` is the size of the *whole*
    file, so part zero on its own fails the header's own check.  That failure
    is worth keeping rather than papering over -- it is what told this reader
    the splits existed -- but the parts have to be joined before anything can
    be read out of them.  `sharedassets3.assets` in this package is nine parts.
    """
    if path.endswith('.split0'):
        stem = path[:-1]
        parts, i = [], 0
        while os.path.exists('%s%d' % (stem, i)):
            parts.append(open('%s%d' % (stem, i), 'rb').read())
            i += 1
        return b''.join(parts), i
    return open(path, 'rb').read(), 1


def load(path):
    """A SerializedFile, or `NotSerialized` (a ValueError) saying why.
    Never a `struct.error`: a reader refuses, it does not raise."""
    data, _n = read_whole(path)
    return SerializedFile(data, path)


def is_serialized(path):
    """The header's arithmetic on the first 48 bytes plus the file's length
    on disk: version, endianness AND fileSize == the file. The third test
    is what keeps a PNG (IHDR length 13 at +8) out; before it, it was in.
    A `.split0` part fails this on purpose (its fileSize is the whole)."""
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            h = f.read(48)
        if len(h) < 20:
            return False
        _m, fsize, v, _d = struct.unpack_from('>IIII', h, 0)
        if not (5 <= v <= 30 and h[16] in (0, 1)):
            return False
        if v >= 22:
            if len(h) < 48:
                return False
            fsize = struct.unpack_from('>q', h, 24)[0]
        return fsize == size
    except OSError:
        return False


def walk(root):
    """Every file, with a split set collapsed to its part zero."""
    if os.path.isfile(root):
        yield root
        return
    import re
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            m = re.search(r'\.split(\d+)$', nm)
            if m and m.group(1) != '0':
                continue
            yield os.path.join(dirpath, nm)


# ------------------------------------------------------------------ commands

def cmd_info(argv):
    sf = load(argv[2])
    print('%s' % argv[2])
    print()
    print('format version     %d' % sf.version)
    print('unity version      %s' % sf.unity_version)
    print('target platform    %d%s' % (sf.target_platform,
                                       ' (Android)' if sf.target_platform == 13
                                       else ''))
    print('endianness         %s' % ('little' if sf.endianness == 0 else 'big'))
    print('type tree          %s' % ('present' if sf.type_tree else 'absent'))
    print('metadata size      %d, after a %d-byte header = %d; parsed to %d   %s'
          % (sf.metadata_size, sf.header_size,
             sf.header_size + sf.metadata_size, sf.metadata_end,
             'agrees' if sf.metadata_closes else 'DISAGREES'))
    print('data offset        %d' % sf.data_offset)
    print('file size declared %d' % sf.file_size)
    print('file size actual   %d   %s'
          % (len(sf.data),
             'agrees' if sf.file_size == len(sf.data) else 'DISAGREES'))
    print('types              %d' % len(sf.types))
    print('objects            %d' % len(sf.objects))
    print('script types       %d' % len(sf.script_types))
    print('externals          %d' % len(sf.externals))
    print('reference types    %d' % len(sf.ref_types))
    print('user information   %r' % sf.user_information)
    if sf.externals:
        print()
        print('externals:')
        for x in sf.externals:
            print('  %-40s type %d  guid %s' % (x['path'], x['type'], x['guid']))


def cmd_objects(argv):
    sf = load(argv[2])
    want = int(argv[argv.index('--class') + 1]) if '--class' in argv else None
    limit = int(argv[argv.index('--limit') + 1]) if '--limit' in argv else 10 ** 9
    print('%-22s %-26s %12s %12s  %s'
          % ('PATH ID', 'CLASS', 'START', 'SIZE', 'NAME'))
    n = 0
    for o in sf.objects:
        cid = sf.class_of(o)
        if want is not None and cid != want:
            continue
        if n >= limit:
            break
        n += 1
        nm = sf.name_of(o)
        print('%-22d %-26s %12d %12d  %s'
              % (o['path_id'], '%s (%d)' % (CLASS.get(cid, '?'), cid),
                 o['start'], o['size'], nm if nm is not None else ''))
    print()
    print('%d objects listed of %d in the file' % (n, len(sf.objects)))


def cmd_verify(argv):
    paths = [a for a in argv[2:] if not a.startswith('--')]
    files = [p for r in paths for p in walk(r)]
    print('The header states the file\'s own length and every object\'s extent.')
    print('Both are Unity\'s numbers, not ours, so both are free positive')
    print('controls on the reader.')
    print()
    print('%-46s %8s %9s %9s %9s' %
          ('FILE', 'OBJECTS', 'SIZE OK', 'BOUNDS OK', 'BAD'))
    tot = ok_size = bad_obj = n_obj = nfile = skipped = ok_meta = 0
    for p in files:
        if not is_serialized(p):
            skipped += 1
            continue
        try:
            sf = load(p)
        except NotSerialized as ex:
            print('%-46s %8s %9s %9s  %s'
                  % (os.path.basename(p)[:46], '-', '-', '-', ex))
            continue
        nfile += 1
        good_size = sf.file_size == len(sf.data)
        ok_size += good_size
        ok_meta += sf.metadata_closes
        if not sf.metadata_closes:
            print('%-46s metadata: header %d + declared %d != parsed %d'
                  % (os.path.basename(p)[:46], sf.header_size,
                     sf.metadata_size, sf.metadata_end))
        bad = 0
        for o in sf.objects:
            end = sf.data_offset + o['start'] + o['size']
            if end > len(sf.data) or o['start'] < 0:
                bad += 1
        n_obj += len(sf.objects)
        bad_obj += bad
        tot += 1
        if not good_size or bad:
            print('%-46s %8d %9s %9s %9d'
                  % (os.path.basename(p)[:46], len(sf.objects),
                     'yes' if good_size else 'NO',
                     'no' if bad else 'yes', bad))
    print()
    print('%d serialized files read, %d skipped as not serialized' %
          (nfile, skipped))
    print('%d of %d declare a fileSize that matches the file on disk'
          % (ok_size, tot))
    print('%d of %d parse the metadata to exactly header + metadataSize'
          % (ok_meta, tot))
    print('%d of %d objects lie inside the file they are declared in'
          % (n_obj - bad_obj, n_obj))


def cmd_census(argv):
    import collections
    root = argv[2]
    per_class = collections.Counter()
    bytes_class = collections.Counter()
    nfile = nobj = 0
    versions = collections.Counter()
    unity = collections.Counter()
    skipped = []
    for p in walk(root):
        if not is_serialized(p):
            skipped.append(p)
            continue
        try:
            sf = load(p)
        except (ValueError, struct.error, IndexError):
            skipped.append(p)
            continue
        nfile += 1
        versions[sf.version] += 1
        unity[sf.unity_version] += 1
        for o in sf.objects:
            cid = sf.class_of(o)
            per_class[cid] += 1
            bytes_class[cid] += o['size']
            nobj += 1
    print('%d serialized files, %d objects' % (nfile, nobj))
    print('format versions: %s' % ', '.join('%d x%d' % (k, v)
                                            for k, v in sorted(versions.items())))
    print('unity versions:  %s' % ', '.join('%s x%d' % (k, v)
                                            for k, v in sorted(unity.items())))
    print()
    print('%-30s %10s %14s %8s' % ('CLASS', 'OBJECTS', 'BYTES', 'SHARE'))
    total = sum(bytes_class.values())
    for cid, n in per_class.most_common():
        print('%-30s %10d %14d %7.2f%%'
              % ('%s (%d)' % (CLASS.get(cid, '?'), cid), n, bytes_class[cid],
                 100.0 * bytes_class[cid] / total if total else 0))
    print('%-30s %10d %14d %7.2f%%' % ('TOTAL', nobj, total, 100.0))
    print()
    print('%d files in the tree are not serialized files:' % len(skipped))
    for p in skipped:
        print('  %-56s %12d' % (os.path.relpath(p, root).replace('\\', '/'),
                                os.path.getsize(p)))


def cmd_names(argv):
    root = argv[2]
    want = int(argv[argv.index('--class') + 1]) if '--class' in argv else None
    out = argv[argv.index('--out') + 1] if '--out' in argv else None
    rows = []
    named = unnamed = notype = empty = scanned = 0
    for p in walk(root):
        if not is_serialized(p):
            continue
        try:
            sf = load(p)
        except (ValueError, struct.error, IndexError):
            continue
        rel = os.path.relpath(p, root).replace('\\', '/')
        for o in sf.objects:
            cid = sf.class_of(o)
            if want is not None and cid != want:
                continue
            if cid in UNNAMED:
                notype += 1
                continue
            nm = sf.name_of(o, scan=True)
            if nm is None:
                unnamed += 1
                continue
            if nm == '':
                empty += 1
                continue
            if cid in SCANNED_NAME:
                scanned += 1
            named += 1
            rows.append((nm, CLASS.get(cid, str(cid)), rel))
    rows.sort()
    if out:
        with open(out, 'w', encoding='utf-8') as f:
            for nm, cl, rel in rows:
                f.write('%s\t%s\t%s\n' % (nm, cl, rel))
        print('%d names written to %s' % (len(rows), out))
    else:
        for nm, cl, rel in rows:
            print('%-64s %-24s %s' % (nm[:64], cl, rel))
    print()
    print('%d names read, of which %d were found by scanning rather than at a'
          % (named, scanned))
    print('known field offset.')
    print('%d objects belong to a class that carries no name this reader can'
          % notype)
    print('reach at a fixed offset.  Shader is in that set: its m_Name is')
    print('inside m_ParsedForm at no fixed offset, and its names come from the')
    print('ScriptMapper instead -- `unityfs.py shaders`.')
    print('%d carry m_Name and it is the empty string -- a result, not a'
          % empty)
    print('failure: most MonoBehaviour components on a GameObject have one.')
    print('%d belong to a class that should carry a name and did not parse.'
          % unnamed)
    print('The last number is the one to watch: it is the count this census')
    print('would have dropped silently if it were not printed.')


def cmd_externals(argv):
    root = argv[2]
    edges = 0
    files = 0
    import collections
    targets = collections.Counter()
    for p in walk(root):
        if not is_serialized(p):
            continue
        try:
            sf = load(p)
        except (ValueError, struct.error, IndexError):
            continue
        files += 1
        rel = os.path.relpath(p, root).replace('\\', '/')
        if sf.externals:
            print('%s' % rel)
            for x in sf.externals:
                print('    -> %-44s type %d' % (x['path'], x['type']))
                targets[x['path']] += 1
                edges += 1
    print()
    print('%d files, %d external references, %d distinct targets'
          % (files, edges, len(targets)))
    print()
    print('%-52s %8s' % ('TARGET', 'REFS'))
    for t, n in targets.most_common():
        print('%-52s %8d' % (t, n))


def cmd_classes(argv):
    print('%-14s %s' % ('CLASS ID', 'NAME'))
    for cid in sorted(CLASS):
        print('%-14d %s' % (cid, CLASS[cid]))
    print()
    print('%d class IDs known to this tool.  Anything else is printed as its'
          % len(CLASS))
    print('number rather than named, so an unrecognised class shows up as an')
    print('unrecognised class instead of disappearing.')


def cmd_text(argv):
    """Every TextAsset in a tree, with its content.

    Four of them in this package, and one is worth the command on its own.
    A TextAsset is a length-prefixed string after m_Name, so it needs no
    guessing: read m_Name, align, read the next length-prefixed block.
    """
    root = argv[2]
    n = 0
    for p in walk(root):
        if not is_serialized(p):
            continue
        try:
            sf = load(p)
        except (ValueError, struct.error, IndexError):
            continue
        rel = os.path.relpath(p, root).replace(chr(92), '/')
        for o in sf.objects:
            if sf.class_of(o) != 49:
                continue
            n += 1
            b = sf.body(o)
            nm = _string_at(b, 0, sf.endianness == 0) or ''
            off = (4 + len(nm.encode('utf-8')) + 3) & ~3
            body = b''
            if off + 4 <= len(b):
                ln = struct.unpack_from('<i', b, off)[0]
                if 0 <= ln <= len(b) - off - 4:
                    body = b[off + 4:off + 4 + ln]
            print('=' * 72)
            print('%s   in %s   %d bytes' % (nm, rel, len(body)))
            print('=' * 72)
            try:
                print(body.decode('utf-8'))
            except UnicodeDecodeError:
                print(body[:512].hex())
            print()
    print('%d TextAssets in the tree.' % n)



def cmd_scripts(argv):
    """Every MonoScript: class name, namespace, assembly.

    A MonoScript is IL2CPP's surviving record of a managed type -- the class
    itself is gone into the encrypted `libil2cpp.so`, but its name, namespace
    and assembly are here in the clear, because the serializer needs them to
    bind a MonoBehaviour to its script.  On a build whose code cannot be read
    this is the only view of the code there is, and it is a complete one: a
    type that has an instance in any scene has a MonoScript.

    Layout at version 21:  m_Name (string, aligned), m_ExecutionOrder (i32),
    m_PropertiesHash (16 bytes), m_ClassName, m_Namespace, m_AssemblyName.
    """
    import collections
    root = argv[2]
    rows = []
    ns = collections.Counter()
    asm = collections.Counter()
    bad = 0
    for p in walk(root):
        if not is_serialized(p):
            continue
        try:
            sf = load(p)
        except (ValueError, struct.error, IndexError):
            continue
        for o in sf.objects:
            if sf.class_of(o) != 115:
                continue
            b = sf.body(o)
            try:
                r = Reader(b, 0, sf.endianness == 0)
                n = r.i32()
                name = r.raw(n).decode('utf-8', 'replace')
                r.align(4)
                r.i32()                      # m_ExecutionOrder
                r.raw(16)                    # m_PropertiesHash
                n = r.i32()
                cls = r.raw(n).decode('utf-8', 'replace')
                r.align(4)
                n = r.i32()
                nsp = r.raw(n).decode('utf-8', 'replace')
                r.align(4)
                n = r.i32()
                am = r.raw(n).decode('utf-8', 'replace')
            except (struct.error, IndexError, ValueError):
                bad += 1
                continue
            rows.append((am, nsp, cls, name))
            ns[nsp] += 1
            asm[am] += 1
    rows.sort()
    if '--list' in argv:
        for am, nsp, cls, name in rows:
            print('%-34s %-46s %s' % (am, nsp or '(global namespace)', cls))
        print()
    print('%d MonoScripts read, %d that did not parse' % (len(rows), bad))
    print()
    print('%-46s %8s' % ('ASSEMBLY', 'TYPES'))
    for k, v in asm.most_common():
        print('%-46s %8d' % (k or '(none)', v))
    print()
    print('%-58s %8s' % ('NAMESPACE', 'TYPES'))
    for k, v in ns.most_common(60):
        print('%-58s %8d' % (k or '(global namespace)', v))
    if len(ns) > 60:
        print('... %d more namespaces' % (len(ns) - 60))
    print()
    print('%d distinct namespaces, %d distinct assemblies'
          % (len(ns), len(asm)))
    print()
    # Counted from the parsed fields, not from the formatted listing above.
    # Counting the listing instead gave 6,536 rows, 114 assemblies and 335
    # namespaces on this package, because a long name overflows its column
    # and a namespace can contain the word being searched for.
    dbg = sum(1 for _a, _n, c, _m in rows if c.startswith('Debug'))
    mock = sum(1 for _a, _n, c, _m in rows if 'Mock' in c or 'Sample' in c)
    col = sum(1 for _a, n, _c, _m in rows
              if n == 'Colopl' or n.startswith('Colopl.'))
    coln = len(set(n for _a, n, _c, _m in rows
                   if n == 'Colopl' or n.startswith('Colopl.')))
    print('%-52s %6d' % ('class names beginning "Debug"', dbg))
    print('%-52s %6d' % ('class names containing "Mock" or "Sample"', mock))
    print('%-52s %6d' % ('types in a Colopl.* namespace', col))
    print('%-52s %6d' % ('  spread over this many Colopl.* namespaces', coln))



def cmd_paths(argv):
    """The ResourceManager's container: every asset path the build can name.

    `globalgamemanagers` carries a ResourceManager (class 147) whose m_Container
    is a vector of (string, PPtr) pairs -- the `Resources.Load` path table.  It
    is a structural read, not a scan: a count, then that many aligned strings
    each followed by a 4-byte file index and an 8-byte path ID.  The count is
    the control -- a wrong layout runs off the end of the object long before it
    reaches the last entry, so reaching exactly the declared count with the
    object exactly consumed is the check.

    This is where the build's own naming convention is, and on a package with
    no game data it is the closest thing to a manifest of what the game would
    have loaded.
    """
    sf = load(argv[2])
    n_obj = 0
    for o in sf.objects:
        if sf.class_of(o) != 147:
            continue
        n_obj += 1
        b = sf.body(o)
        r = Reader(b, 0, sf.endianness == 0)
        count = r.i32()
        print('ResourceManager m_Container declares %d entries, in %d bytes'
              % (count, len(b)))
        print()
        rows = []
        try:
            for _ in range(count):
                ln = r.i32()
                name = r.raw(ln).decode('utf-8', 'replace')
                r.align(4)
                fid = r.i32()
                pid = r.i64()
                rows.append((name, fid, pid))
        except (struct.error, IndexError):
            pass
        for name, fid, pid in rows:
            print('%-64s file %d  path %d' % (name, fid, pid))
        print()
        print('%d of %d entries read; %d bytes of the object consumed of %d'
              % (len(rows), count, r.p, len(b)))
        if len(rows) == count:
            print('The declared count was reached exactly, which is the check.')
        else:
            print('The declared count was NOT reached -- the layout above is')
            print('wrong somewhere and the list must not be trusted.')
    if not n_obj:
        print('no ResourceManager object in this file')



# Unity's TextureFormat enum, the members a mobile build can use.
TEXFMT = {
    1: 'Alpha8', 2: 'ARGB4444', 3: 'RGB24', 4: 'RGBA32', 5: 'ARGB32',
    # 9 = R16, 10 = DXT1, 11 unused, 12 = DXT5 (Unity's TextureFormat
    # enum has no DXT3). This table had 8: R16, 9: DXT1, 10: DXT3 --
    # off by one -- and on pc-monstrum-doc the 39 textures of format 10
    # closed on the 4-bits-per-pixel arithmetic of DXT1 (unitytex17.py).
    7: 'RGB565', 9: 'R16', 10: 'DXT1', 12: 'DXT5',
    13: 'RGBA4444', 14: 'BGRA32', 15: 'RHalf', 16: 'RGHalf',
    17: 'RGBAHalf', 18: 'RFloat', 19: 'RGFloat', 20: 'RGBAFloat',
    21: 'YUY2', 22: 'RGB9e5Float', 24: 'BC6H', 25: 'BC7', 26: 'BC4',
    27: 'BC5', 28: 'DXT1Crunched', 29: 'DXT5Crunched',
    30: 'PVRTC_RGB2', 31: 'PVRTC_RGBA2', 32: 'PVRTC_RGB4',
    33: 'PVRTC_RGBA4', 34: 'ETC_RGB4', 41: 'EAC_R', 42: 'EAC_R_SIGNED',
    43: 'EAC_RG', 44: 'EAC_RG_SIGNED', 45: 'ETC2_RGB', 46: 'ETC2_RGBA1',
    47: 'ETC2_RGBA8', 48: 'ASTC_RGB_4x4', 49: 'ASTC_RGB_5x5',
    50: 'ASTC_RGB_6x6', 51: 'ASTC_RGB_8x8', 52: 'ASTC_RGB_10x10',
    53: 'ASTC_RGB_12x12', 54: 'ASTC_RGBA_4x4', 55: 'ASTC_RGBA_5x5',
    56: 'ASTC_RGBA_6x6', 57: 'ASTC_RGBA_8x8', 58: 'ASTC_RGBA_10x10',
    59: 'ASTC_RGBA_12x12', 60: 'ETC_RGB4_3DS', 61: 'ETC_RGBA8_3DS',
    62: 'RG16', 63: 'R8', 64: 'ETC_RGB4Crunched', 65: 'ETC2_RGBA8Crunched',
}

# Bits per pixel, for the formats whose size is a plain function of the
# dimensions.  This is what makes the header check possible: Unity states
# m_CompleteImageSize, and width * height * bpp / 8, rounded up to the block
# grid, has to reproduce it.  Nothing of ours writes either number.
BPP = {
    1: 8, 3: 24, 4: 32, 5: 32, 7: 16, 9: 16, 2: 16, 13: 16, 14: 32,
    62: 16, 63: 8,
    # 9 was 4 and 10 was 8 here (DXT1 at 9, DXT3 at 10): off by one
    # against Unity's enum, repaired on pc-monstrum-doc with TEXFMT.
    10: 4, 12: 8, 26: 4, 27: 8, 25: 8, 24: 8,
    34: 4, 45: 4, 46: 4, 47: 8, 41: 4, 43: 8,
    48: 8, 49: 8, 50: 8, 51: 8, 52: 8, 53: 8,
    54: 8, 55: 8, 56: 8, 57: 8, 58: 8, 59: 8,
}
# Block dimensions for the block-compressed formats.
BLOCK = {
    10: (4, 4), 12: (4, 4), 24: (4, 4), 25: (4, 4),
    26: (4, 4), 27: (4, 4),
    34: (4, 4), 41: (4, 4), 43: (4, 4), 45: (4, 4), 46: (4, 4), 47: (4, 4),
    48: (4, 4), 54: (4, 4), 49: (5, 5), 55: (5, 5), 50: (6, 6), 56: (6, 6),
    51: (8, 8), 57: (8, 8), 52: (10, 10), 58: (10, 10),
    53: (12, 12), 59: (12, 12),
}
# ASTC always spends 128 bits per block, whatever the block size.
ASTC = set(range(48, 60))


def texture_bytes(fmt, w, h, mips=1):
    """Expected byte count for one texture, all mip levels."""
    if fmt not in BPP:
        return None
    total = 0
    for level in range(max(1, mips)):
        lw = max(1, w >> level)
        lh = max(1, h >> level)
        if fmt in BLOCK:
            bw, bh = BLOCK[fmt]
            blocks = ((lw + bw - 1) // bw) * ((lh + bh - 1) // bh)
            total += blocks * (16 if fmt in ASTC else
                               (8 if BPP[fmt] * bw * bh // 8 == 8 else
                                BPP[fmt] * bw * bh // 8))
        else:
            total += lw * lh * BPP[fmt] // 8
    return total


def read_texture2d(sf, obj):
    """Texture2D fields, at the layout Unity 2019.4 writes.

    m_Name, m_ForcedFallbackFormat, m_DownscaleFallback, align, m_Width,
    m_Height, m_CompleteImageSize, m_TextureFormat, m_MipCount, three bools,
    align, m_StreamingMipmapsPriority, m_ImageCount, m_TextureDimension, the
    six GLTextureSettings words, m_LightmapFormat, m_ColorSpace, and then the
    image data length -- which is zero when the pixels live in a `.resource`
    file, in which case a StreamingInfo follows.
    """
    b = sf.body(obj)
    r = Reader(b, 0, sf.endianness == 0)
    n = r.i32()
    name = r.raw(n).decode('utf-8', 'replace')
    r.align(4)
    r.i32()                                  # m_ForcedFallbackFormat
    r.u8()                                   # m_DownscaleFallback
    r.align(4)
    width = r.i32()
    height = r.i32()
    complete = r.i32()
    fmt = r.i32()
    mips = r.i32()
    r.u8(); r.u8(); r.u8()                   # readable, ignoreLimit, streaming
    r.align(4)
    r.i32()                                  # streaming priority
    image_count = r.i32()
    dim = r.i32()
    for _ in range(6):
        r.i32()                              # filter, aniso, bias, wrapU/V/W
    r.i32()                                  # m_LightmapFormat
    colour = r.i32()
    size = r.i32()
    stream = None
    if size == 0:
        try:
            r.p += 0
            off = r.u32()
            sz = r.u32()
            ln = r.i32()
            path = r.raw(ln).decode('utf-8', 'replace')
            stream = (off, sz, path)
        except (struct.error, IndexError):
            stream = None
    return dict(name=name, width=width, height=height, complete=complete,
                format=fmt, mips=mips, image_count=image_count, dim=dim,
                colour=colour, size=size, stream=stream)


def cmd_textures(argv):
    """Every Texture2D in a tree, with the header's own consistency check.

    m_CompleteImageSize is Unity's statement of how many bytes the pixels
    occupy.  width, height, format and mip count are enough to compute that
    independently, so the two can be compared -- and a reader that has the
    field order wrong fails the comparison instead of printing a plausible
    table.  The count of agreements is printed, which is the free positive
    control this repository asks every container for.
    """
    import collections
    root = argv[2]
    rows = []
    fmts = collections.Counter()
    fmt_bytes = collections.Counter()
    agree = checked = 0
    for p in walk(root):
        if not is_serialized(p):
            continue
        try:
            sf = load(p)
        except (ValueError, struct.error, IndexError):
            continue
        rel = os.path.relpath(p, root).replace(chr(92), '/')
        # The layout below is Unity 2019.4's. On pc-monstrum-doc (Unity
        # 5.5, version 17) it read every field after m_Name from the wrong
        # offset and printed 8 textures of "format 0, 39 bytes" with rc 0.
        # A reader that has the wrong layout must say so, not tabulate.
        major = sf.unity_version.split('.')[0]
        if not (major.isdigit() and int(major) >= 2019):
            print('%s: engine %s -- this reader knows the 2019.4 Texture2D '
                  'layout; refusing (unitytex17.py reads version 17, '
                  'unitytex.py version 15)' % (rel, sf.unity_version))
            continue
        for o in sf.objects:
            if sf.class_of(o) != 28:
                continue
            try:
                t = read_texture2d(sf, o)
            except (struct.error, IndexError, ValueError, UnicodeDecodeError):
                continue
            exp = texture_bytes(t['format'], t['width'], t['height'],
                                t['mips'])
            ok = ''
            if exp is not None and t['complete']:
                checked += 1
                if exp == t['complete']:
                    agree += 1
                    ok = 'yes'
                else:
                    ok = '%d' % exp
            fmts[t['format']] += 1
            fmt_bytes[t['format']] += t['complete']
            rows.append((t, ok, rel))
    rows.sort(key=lambda r: -r[0]['complete'])
    print('%-38s %6s %6s %5s %-18s %11s %8s'
          % ('NAME', 'W', 'H', 'MIPS', 'FORMAT', 'BYTES', 'W*H*BPP'))
    for t, ok, rel in rows:
        print('%-38s %6d %6d %5d %-18s %11d %8s'
              % (t['name'][:38], t['width'], t['height'], t['mips'],
                 TEXFMT.get(t['format'], str(t['format'])), t['complete'], ok))
    print()
    print('%d Texture2D objects, %d bytes of pixels'
          % (len(rows), sum(t['complete'] for t, _o, _r in rows)))
    print('%d of %d agree with width x height x bits-per-pixel over all mips'
          % (agree, checked))
    print('(the rest are formats whose size this tool does not compute, or a')
    print('disagreement -- either way the number is printed, not hidden)')
    print()
    print('%-22s %8s %14s' % ('FORMAT', 'TEXTURES', 'BYTES'))
    for f, n in fmts.most_common():
        print('%-22s %8d %14d' % (TEXFMT.get(f, str(f)), n, fmt_bytes[f]))
    streamed = sum(1 for t, _o, _r in rows if t['stream'])
    print()
    print('%d of %d textures keep their pixels in a separate .resource file'
          % (streamed, len(rows)))



def cmd_shaders(argv):
    """The ScriptMapper's shader table: every shader the build can name.

    `globalgamemanagers` carries a ScriptMapper (class 94) whose `m_Shaders` is
    a map from PPtr<Shader> to the shader's name -- **PPtr first, string
    second**, which is the opposite order from the ResourceManager's container
    and is the kind of thing that has to be found by the declared count failing
    rather than guessed.

    This is the route to a shader's name, and it exists because the direct one
    does not: at serialization version 21 a Shader's own `m_Name` lives inside
    `m_ParsedForm`, after the whole property table and every subshader, at an
    offset no fixed rule reaches and with no type tree in a player build to
    ask.  Scanning the object for its first plausible string returns the first
    *property* name instead -- `_MainTex`, `_Color`, `$Globals` -- which looks
    like a result and is not one.  See docs/09-corrections.md.
    """
    sf = load(argv[2])
    found = False
    for o in sf.objects:
        if sf.class_of(o) != 94:
            continue
        found = True
        b = sf.body(o)
        r = Reader(b, 0, sf.endianness == 0)
        count = r.i32()
        rows = []
        try:
            for _ in range(count):
                fid = r.i32()
                pid = r.i64()
                ln = r.i32()
                nm = r.raw(ln).decode('utf-8', 'replace')
                r.align(4)
                rows.append((nm, fid, pid))
        except (struct.error, IndexError, ValueError):
            pass
        print('ScriptMapper m_Shaders declares %d entries, in %d bytes'
              % (count, len(b)))
        print()
        print('%-58s %6s %22s' % ('SHADER', 'FILE', 'PATH ID'))
        for nm, fid, pid in rows:
            print('%-58s %6d %22d' % (nm, fid, pid))
        print()
        print('%d of %d entries read; %d bytes of the object consumed of %d'
              % (len(rows), count, r.p, len(b)))
        if len(rows) == count:
            print('The declared count was reached exactly, which is the check.')
        else:
            print('The declared count was NOT reached -- do not trust the list.')
        ext = collections_Counter(fid for _n, fid, _p in rows)
        print()
        print('%-6s %8s  %s' % ('FILE', 'SHADERS', 'WHICH FILE THAT IS'))
        for fid, n in sorted(ext.items()):
            if fid == 0:
                where = 'this file'
            elif fid - 1 < len(sf.externals):
                where = sf.externals[fid - 1]['path']
            else:
                where = '(out of range)'
            print('%-6d %8d  %s' % (fid, n, where))
    if not found:
        print('no ScriptMapper object in this file')


def collections_Counter(it):
    d = {}
    for x in it:
        d[x] = d.get(x, 0) + 1
    return d


def _fake_serialized(version):
    """A SerializedFile of one type and no objects, built by hand at the
    20-byte header (17) or the 48-byte one (22), fileSize written last."""
    body = b'5.5.0f3\0' if version < 22 else b'6000.3.6f1\0'
    body += struct.pack('<i', 19)            # target platform
    body += b'\0'                            # no type tree
    body += struct.pack('<i', 1)             # one type
    body += struct.pack('<i', 28) + b'\0' + struct.pack('<h', -1) + bytes(16)
    body += struct.pack('<i', 0)             # no objects
    body += struct.pack('<i', 0)             # no script types
    body += struct.pack('<i', 0)             # no externals
    if version >= 20:
        body += struct.pack('<i', 0)         # no reference types
    body += b'\0'                            # user information
    if version < 22:
        hdr = 20
        meta = len(body)
        data_off = (hdr + meta + 15) & ~15
        total = data_off
        head = struct.pack('>IIII', meta, total, version, data_off) + bytes(4)
    else:
        hdr = 48
        meta = len(body)
        data_off = (hdr + meta + 15) & ~15
        total = data_off
        head = (struct.pack('>IIII', 0, 0, version, 0) + bytes(4)
                + struct.pack('>I', meta) + struct.pack('>qqq', total,
                                                        data_off, 0))
    out = head + body
    return out + bytes(total - len(out))


def cmd_selftest(argv):
    """Hand-built headers at 17 and 22; a PNG head refused by name."""
    import tempfile
    checks = []
    f17 = _fake_serialized(17)
    f22 = _fake_serialized(22)
    png = (b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR'
           + struct.pack('>II', 64, 64) + b'\x08\x06\0\0\0' + bytes(100))
    sf17 = SerializedFile(f17, 'fake17')
    sf22 = SerializedFile(f22, 'fake22')
    checks.append(('a hand-built version-17 file loads', sf17.version == 17))
    checks.append(('a hand-built version-22 file loads', sf22.version == 22))
    checks.append(('at 17 the header is 20 bytes and header + metadataSize '
                   '== the parse end', sf17.header_size == 20
                   and sf17.metadata_closes))
    checks.append(('at 22 the header is 48 bytes and header + metadataSize '
                   '== the parse end', sf22.header_size == 48
                   and sf22.metadata_closes))
    checks.append(('the parse end differs from metadataSize by exactly the '
                   'header, 20 and 48',
                   sf17.metadata_end - sf17.metadata_size == 20
                   and sf22.metadata_end - sf22.metadata_size == 48))
    checks.append(('a PNG head reads as version 13 at +8, which is why it '
                   'used to pass', struct.unpack_from('>I', png, 8)[0] == 13))
    why = _header_check(png, 'png')
    checks.append(('THE REPAIR: the PNG is refused by fileSize, not by '
                   'struct.error', why is not None and 'fileSize' in why))
    try:
        SerializedFile(png, 'png')
        raised = None
    except NotSerialized as ex:
        raised = ex
    except struct.error:
        raised = 'struct.error'
    checks.append(('load() raises NotSerialized (a ValueError) and not '
                   'struct.error', isinstance(raised, NotSerialized)))
    checks.append(('NotSerialized is a ValueError, so old callers still '
                   'catch it', isinstance(raised, ValueError)))
    bad = f22[:24] + struct.pack('>q', len(f22) + 1) + f22[32:]
    checks.append(('a version-22 file whose fileSize is one byte off is '
                   'refused', _header_check(bad) is not None))
    trunc = f22[:60]
    try:
        SerializedFile(trunc, 'trunc')
        r2 = None
    except NotSerialized as ex:
        r2 = ex
    checks.append(('a truncated file is refused, not raised', r2 is not None))
    # is_serialized on disk: the PNG and the two fakes
    d = tempfile.mkdtemp()
    try:
        for nm, blob in (('f17', f17), ('f22', f22), ('x.png', png)):
            with open(os.path.join(d, nm), 'wb') as fh:
                fh.write(blob)
        checks.append(('is_serialized() accepts the two fakes on disk',
                       is_serialized(os.path.join(d, 'f17'))
                       and is_serialized(os.path.join(d, 'f22'))))
        checks.append(('is_serialized() refuses the PNG on disk',
                       not is_serialized(os.path.join(d, 'x.png'))))
        try:
            load(os.path.join(d, 'x.png'))
            r3 = None
        except NotSerialized as ex:
            r3 = ex
        checks.append(('load() on the PNG refuses with the path and the '
                       'reason', r3 is not None and 'x.png' in str(r3)))
    finally:
        for nm in os.listdir(d):
            os.unlink(os.path.join(d, nm))
        os.rmdir(d)
    failed = 0
    for label, ok in checks:
        print('  %-78s %s' % (label, 'ok' if ok else 'FAIL'))
        failed += not ok
    print()
    print('%d checks, %d failures' % (len(checks), failed))
    if failed:
        raise SystemExit(1)


CMDS = dict(shaders=cmd_shaders, textures=cmd_textures, paths=cmd_paths, scripts=cmd_scripts, info=cmd_info, objects=cmd_objects, verify=cmd_verify, text=cmd_text,
            census=cmd_census, names=cmd_names, externals=cmd_externals,
            classes=cmd_classes, selftest=cmd_selftest)


def main(argv):
    if len(argv) < 2 or argv[1] not in CMDS:
        raise SystemExit(__doc__)
    try:
        CMDS[argv[1]](argv)
    except NotSerialized as ex:
        raise SystemExit('unityfs: refused: %s' % ex)


if __name__ == '__main__':
    main(sys.argv)
