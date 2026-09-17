"""a3ds.py -- a chunk reader for Autodesk 3D Studio `.3DS` files.

The format is public and trivially chunked, which is why it is worth reading
rather than asserting. Every chunk is:

    u16  chunk id, little-endian
    u32  chunk length in bytes, **including these six header bytes**
    ...  length - 6 bytes of payload, which for container chunks is more chunks

The outermost chunk of a `.3DS` file has id 0x4D4D (which is why every one of
these files begins with the bytes `4D 4D`) and its length field is the length
of the whole file. That single fact is the validation this tool leans on: if
the top chunk's length is not exactly the file size, the file is not a whole
3DS and nothing else printed about it can be trusted.

The chunks read for content:

    0x4D4D  M3DMAGIC        the file
    0x0002  M3D_VERSION     u32 version
    0x3D3D  MDATA           the mesh section
    0x4000  NAMED_OBJECT    asciiz name, then the object's chunks
    0x4100  N_TRI_OBJECT    a mesh
    0x4110  POINT_ARRAY     u16 count, then count * 3 float32
    0x4120  FACE_ARRAY      u16 count, then count * 4 u16 (a,b,c,flags)
    0x4140  TEX_VERTS       u16 count, then count * 2 float32
    0xAFFF  MAT_ENTRY       a material
    0xA000  MAT_NAME        asciiz
    0xA300  MAT_TEXNAME     asciiz -- the texture file this material asks for
    0xB000  KFDATA          keyframe data

Everything else is walked, counted and reported by id without being decoded,
so the census below is of the whole file and not of the parts this tool
happens to understand.

Usage:
    python tools/a3ds.py FILE.3DS --tree
    python tools/a3ds.py DIR --census
    python tools/a3ds.py DIR --textures
    python tools/a3ds.py --selftest
"""

import os
import struct
import sys

# 0x0100 MASTER_SCALE is NOT in this set: it is a single float32, and treating
# it as a container is what made the first run of this tool report a four-byte
# shortfall on 36 files out of 36 -- the same four bytes every time, which is
# what a fixed-size payload mistaken for children looks like.
CONTAINERS = {0x4D4D, 0x3D3D, 0x4000, 0x4100, 0xAFFF, 0xB000, 0xB002, 0xB003,
              0xB004, 0xB005, 0xB006, 0xB007, 0xA200, 0xA33A, 0xA33C,
              0xA33D, 0xA210, 0xA230, 0xA33E, 0xA320, 0xA321, 0xA322, 0xA324,
              0xA325, 0xA326, 0xA328, 0xA329, 0x4600, 0x4700, 0xAFFE}

# Chunks whose payload begins with a fixed-size block of their own before any
# child chunk starts. Descending at the first payload byte reads those fixed
# bytes as a chunk header and produces nonsense; the sizes below are from the
# public definitions and each one is confirmed by the tree closing afterwards.
#   0x4000 is handled separately: its prelude is a NUL-terminated name.
PRELUDE = {
    0x4600: 12,   # N_DIRECT_LIGHT: 3 x float32 position
    0x4700: 32,   # N_CAMERA: position, target (3+3 floats), bank, lens
}
NAMES = {
    0x4D4D: "M3DMAGIC", 0x0002: "M3D_VERSION", 0x3D3D: "MDATA",
    0x3D3E: "MESH_VERSION", 0x0100: "MASTER_SCALE", 0x2100: "AMBIENT_LIGHT",
    0x4000: "NAMED_OBJECT", 0x4100: "N_TRI_OBJECT", 0x4110: "POINT_ARRAY",
    0x4120: "FACE_ARRAY", 0x4130: "MSH_MAT_GROUP", 0x4140: "TEX_VERTS",
    0x4150: "SMOOTH_GROUP", 0x4160: "MESH_MATRIX", 0x4600: "N_DIRECT_LIGHT",
    0x4700: "N_CAMERA", 0xAFFF: "MAT_ENTRY", 0xA000: "MAT_NAME",
    0xA010: "MAT_AMBIENT", 0xA020: "MAT_DIFFUSE", 0xA030: "MAT_SPECULAR",
    0xA040: "MAT_SHININESS", 0xA050: "MAT_TRANSPARENCY", 0xA100: "MAT_SHADING",
    0xA200: "MAT_TEXMAP", 0xA300: "MAT_TEXNAME", 0xA351: "MAT_MAP_TILING",
    0xB000: "KFDATA", 0xB008: "KFSEG", 0xB009: "KFCURTIME", 0xB00A: "KFHDR",
    0xB002: "OBJECT_NODE_TAG", 0xB010: "NODE_ID/NAME", 0xB013: "PIVOT",
    0x0011: "COLOR_24", 0x0012: "LIN_COLOR_24", 0x0030: "INT_PERCENTAGE",
    0x0031: "FLOAT_PERCENTAGE",
}


class ThreeDSError(Exception):
    pass


def asciiz(data, off):
    end = data.index(b"\x00", off)
    return data[off:end].decode("latin-1"), end + 1


def walk(data, start, end, depth, out, stats):
    p = start
    while p + 6 <= end:
        cid, clen = struct.unpack_from("<HI", data, p)
        if clen < 6:
            raise ThreeDSError("chunk 0x%04X at %d claims length %d, which is"
                               " shorter than its own header" % (cid, p, clen))
        if p + clen > end:
            raise ThreeDSError("chunk 0x%04X at %d claims %d bytes but only %d"
                               " remain in its parent" % (cid, p, clen, end - p))
        stats["ids"][cid] = stats["ids"].get(cid, 0) + 1
        body = p + 6
        label = NAMES.get(cid, "?")
        extra = ""
        if cid == 0x4000:
            name, _ = asciiz(data, body)
            extra = " name=%r" % name
            stats["objects"].append(name)
        elif cid == 0xA000:
            name, _ = asciiz(data, body)
            extra = " name=%r" % name
            stats["materials"].append(name)
        elif cid == 0xA300:
            name, _ = asciiz(data, body)
            extra = " texture=%r" % name
            stats["textures"].append(name)
        elif cid == 0x4110:
            (n,) = struct.unpack_from("<H", data, body)
            extra = " vertices=%d" % n
            stats["vertices"] += n
            if 2 + n * 12 != clen - 6:
                raise ThreeDSError("POINT_ARRAY says %d vertices but the chunk"
                                   " holds %d bytes of payload" % (n, clen - 6))
        elif cid == 0x4120:
            (n,) = struct.unpack_from("<H", data, body)
            extra = " faces=%d" % n
            stats["faces"] += n
        elif cid == 0x4140:
            (n,) = struct.unpack_from("<H", data, body)
            extra = " texverts=%d" % n
        elif cid == 0x0002:
            (v,) = struct.unpack_from("<I", data, body)
            extra = " version=%d" % v
            stats["version"] = v
        if out is not None:
            out.append("%s%04X %-16s %8d%s" % ("  " * depth, cid, label, clen, extra))
        if cid in CONTAINERS:
            if cid == 0x4000:
                _n, sub = asciiz(data, body)
            else:
                sub = body + PRELUDE.get(cid, 0)
            walk(data, sub, p + clen, depth + 1, out, stats)
        p += clen
    if p != end:
        raise ThreeDSError("chunks under a container ended at %d, not at %d" % (p, end))


def read(path, want_tree=False):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 6:
        raise ThreeDSError("file is %d bytes, too short for one chunk" % len(data))
    cid, clen = struct.unpack_from("<HI", data, 0)
    if cid != 0x4D4D:
        raise ThreeDSError("top chunk is 0x%04X, not 0x4D4D" % cid)
    if clen != len(data):
        raise ThreeDSError("top chunk claims %d bytes, file is %d" % (clen, len(data)))
    stats = {"ids": {}, "objects": [], "materials": [], "textures": [],
             "vertices": 0, "faces": 0, "version": None, "bytes": len(data)}
    out = [] if want_tree else None
    walk(data, 0, len(data), 0, out, stats)
    return stats, out


def census(root):
    files = []
    if os.path.isdir(root):
        for f in sorted(os.listdir(root)):
            if f.lower().endswith(".3ds"):
                files.append(os.path.join(root, f))
    else:
        files = [root]
    if not files:
        print("FATAL: no .3DS files under %s" % root)
        return 3
    print("%-14s %8s %5s %8s %8s %6s %6s  %s"
          % ("file", "bytes", "ver", "verts", "faces", "objs", "mats", "closes?"))
    tv = tf = 0
    ok = bad = 0
    allobj = []
    for p in files:
        try:
            s, _ = read(p)
        except ThreeDSError as exc:
            print("%-14s FAILED: %s" % (os.path.basename(p), exc))
            bad += 1
            continue
        ok += 1
        tv += s["vertices"]
        tf += s["faces"]
        allobj += s["objects"]
        print("%-14s %8d %5s %8d %8d %6d %6d  %s"
              % (os.path.basename(p), s["bytes"], s["version"], s["vertices"],
                 s["faces"], len(s["objects"]), len(s["materials"]), "yes"))
    print()
    print("files that parse with the top chunk equal to the file size: %d of %d"
          % (ok, ok + bad))
    print("total vertices : %d" % tv)
    print("total faces    : %d" % tf)
    print("total objects  : %d  (%d distinct names)" % (len(allobj), len(set(allobj))))
    return 0 if bad == 0 else 1


def textures(root):
    import collections
    files = [os.path.join(root, f) for f in sorted(os.listdir(root))
             if f.lower().endswith(".3ds")] if os.path.isdir(root) else [root]
    tex = collections.Counter()
    mat = collections.Counter()
    per = {}
    for p in files:
        s, _ = read(p)
        tex.update(s["textures"])
        mat.update(s["materials"])
        per[os.path.basename(p)] = sorted(set(s["textures"]))
    print("distinct texture names asked for by the meshes: %d" % len(tex))
    for k, v in sorted(tex.items()):
        print("  %-16s x%d" % (k, v))
    print()
    print("distinct material names: %d" % len(mat))
    for k, v in sorted(mat.items()):
        print("  %-16s x%d" % (k, v))
    return 0


def selftest():
    fails = 0
    print("=== NEGATIVE CONTROL 1: a wrong top chunk id must raise ===")
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "a3ds_selftest.3ds")
    with open(tmp, "wb") as fh:
        fh.write(struct.pack("<HI", 0x1234, 6))
    try:
        read(tmp)
        print("  *** DID NOT RAISE ***")
        fails += 1
    except ThreeDSError as exc:
        print("  raised: %s" % exc)

    print("=== NEGATIVE CONTROL 2: a top chunk length that is not the file size"
          " must raise ===")
    with open(tmp, "wb") as fh:
        fh.write(struct.pack("<HI", 0x4D4D, 99) + b"\x00" * 4)
    try:
        read(tmp)
        print("  *** DID NOT RAISE ***")
        fails += 1
    except ThreeDSError as exc:
        print("  raised: %s" % exc)

    print("=== NEGATIVE CONTROL 3: a child chunk that overruns its parent must raise ===")
    body = struct.pack("<HI", 0x3D3D, 40)
    with open(tmp, "wb") as fh:
        fh.write(struct.pack("<HI", 0x4D4D, 6 + len(body)) + body)
    try:
        read(tmp)
        print("  *** DID NOT RAISE ***")
        fails += 1
    except ThreeDSError as exc:
        print("  raised: %s" % exc)

    print("=== POSITIVE CONTROL: a hand-built file with 3 vertices and 1 face ===")
    pts = struct.pack("<H", 3) + struct.pack("<9f", *([0.0] * 9))
    fcs = struct.pack("<H", 1) + struct.pack("<4H", 0, 1, 2, 7)
    tri = (struct.pack("<HI", 0x4110, 6 + len(pts)) + pts
           + struct.pack("<HI", 0x4120, 6 + len(fcs)) + fcs)
    obj = b"CUBE\x00" + struct.pack("<HI", 0x4100, 6 + len(tri)) + tri
    md = struct.pack("<HI", 0x4000, 6 + len(obj)) + obj
    mdata = struct.pack("<HI", 0x3D3D, 6 + len(md)) + md
    whole = struct.pack("<HI", 0x4D4D, 6 + len(mdata)) + mdata
    with open(tmp, "wb") as fh:
        fh.write(whole)
    s, _ = read(tmp)
    ok = (s["vertices"] == 3 and s["faces"] == 1 and s["objects"] == ["CUBE"])
    print("  vertices=%d faces=%d objects=%r -> %s"
          % (s["vertices"], s["faces"], s["objects"], "ok" if ok else "WRONG"))
    if not ok:
        fails += 1
    os.unlink(tmp)
    print()
    print("failures: %d" % fails)
    return 1 if fails else 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if len(argv) < 3:
        print(__doc__)
        return 2
    if "--census" in argv:
        return census(argv[1])
    if "--textures" in argv:
        return textures(argv[1])
    if "--tree" in argv:
        s, out = read(argv[1], want_tree=True)
        print("\n".join(out))
        print()
        print("vertices %d  faces %d  objects %r" % (s["vertices"], s["faces"], s["objects"]))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
