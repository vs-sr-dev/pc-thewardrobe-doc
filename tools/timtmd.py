#!/usr/bin/env python3
"""timtmd.py -- the PlayStation TIM and TMD formats, read on a Windows CD.

Both definitions are public and documented -- they are in Sony's PlayStation
Developer Reference (the "File Formats" volume of the Run-Time Library
reference) -- and this tool uses them as published rather than deriving them.
That is stated here because the rest of this repository derives formats from
bytes, and the difference matters when the result is scored.

**TIM**, the texture format:

     0   4   file id, 0x00000010, little-endian
     4   4   flags.  bits 0..2 = pixel mode:
                0 = 4 bits per pixel, indexed
                1 = 8 bits per pixel, indexed
                2 = 16 bits per pixel, direct (BGR555 with a mask bit)
                3 = 24 bits per pixel, direct
                4 = mixed
             bit 3 = CF, set when a CLUT block follows

   then, if CF is set, the CLUT block:
     0   4   bnum, the length of this whole block including this field
     4   2   DX, the frame-buffer x of the palette
     6   2   DY, the frame-buffer y
     8   2   W, entries per palette
    10   2   H, number of palettes
    12   .   W * H halfwords, each an ABGR1555 entry

   then the pixel block, laid out exactly like the CLUT block, whose W counts
   **halfwords, not pixels**: at 4 bpp a row is W*4 pixels wide, at 8 bpp W*2,
   at 16 bpp W, at 24 bpp W*2/3.

The closure test is arithmetic and total: 8 + clut_bnum + pixel_bnum must equal
the file size. A format read correctly leaves no bytes over.

**TMD**, the model format:

     0   4   file id, 0x00000041
     4   4   flags.  bit 0 = FIXP, set when the pointers below are absolute
                     addresses rather than offsets from the end of the table
     8   4   nobj, the number of objects
   then nobj object descriptors of 28 bytes:
     0   4   vert_top      4   4   n_vert
     8   4   normal_top   12   4   n_normal
    16   4   prim_top     20   4   n_prim
    24   4   scale, a signed power-of-two exponent

A vertex is 8 bytes (three s16 and a pad), a normal is 8 bytes (three s16 and
a pad). Primitives are variable-length and are counted, not walked.

**The base of the pointers was derived from the bytes, not taken on trust.**
Descriptions of TMD disagree about what a non-FIXP pointer is relative to;
this repository settled it by arithmetic on `HORR/USA/ITEM_M2/I00V.IVM`, whose
single object declares vert_top 13916 / 295 vertices, normal_top 16276 / 1316
normals and prim_top 28. Taking the base as the address **after** the object
table leaves the normals ending 28 bytes past the end of a 92,896-byte file.
Taking it as the address **of** the object table -- the TMD's own start plus
its 12-byte header -- puts the primitives immediately after the table, the
normals exactly where the vertices end, and the last normal on the last byte
of the file. Residue zero. One reading closes and the other does not.

    python tools/timtmd.py DIR
    python tools/timtmd.py DIR --ext .tim .ivm .etm
    python tools/timtmd.py FILE --verbose
    python tools/timtmd.py DIR --tmd
    python tools/timtmd.py DIR --tsv OUT.tsv
"""

import argparse
import collections
import os
import struct

TIM_ID = 0x00000010
TMD_ID = 0x00000041
PMODE = {0: "4bpp indexed", 1: "8bpp indexed", 2: "16bpp direct",
         3: "24bpp direct", 4: "mixed"}


def read_tim(path):
    data = open(path, "rb").read()
    d = {"path": path, "size": len(data), "ok": False, "why": ""}
    if len(data) < 8:
        d["why"] = "shorter than a header"
        return d
    fid, flags = struct.unpack_from("<II", data, 0)
    d["id"] = fid
    d["flags"] = flags
    if fid != TIM_ID:
        d["why"] = "id is 0x%08X, not 0x00000010" % fid
        return d
    pmode = flags & 7
    cf = bool(flags & 8)
    d["pmode"] = pmode
    d["clut_flag"] = cf
    pos = 8
    d["nclut"] = 0
    d["clut_entries"] = 0
    if cf:
        if pos + 12 > len(data):
            d["why"] = "CLUT block header runs past the end"
            return d
        bnum, dx, dy, w, h = struct.unpack_from("<IHHHH", data, pos)
        d["clut_bnum"] = bnum
        d["clut_w"] = w
        d["clut_h"] = h
        d["nclut"] = h
        d["clut_entries"] = w
        if bnum != 12 + w * h * 2:
            d["why"] = ("CLUT bnum %d != 12 + %d*%d*2 = %d"
                        % (bnum, w, h, 12 + w * h * 2))
            return d
        pos += bnum
    else:
        d["clut_bnum"] = 0
    if pos + 12 > len(data):
        d["why"] = "pixel block header runs past the end"
        return d
    bnum, dx, dy, w, h = struct.unpack_from("<IHHHH", data, pos)
    d["pix_bnum"] = bnum
    d["fb_x"] = dx
    d["fb_y"] = dy
    d["w_halfwords"] = w
    d["h"] = h
    if bnum != 12 + w * h * 2:
        d["why"] = "pixel bnum %d != 12 + %d*%d*2 = %d" % (bnum, w, h,
                                                           12 + w * h * 2)
        return d
    mult = {0: 4, 1: 2, 2: 1, 3: 2.0 / 3.0}.get(pmode, 1)
    d["pixels_w"] = int(w * mult)
    d["pixels_h"] = h
    pos += bnum
    d["accounted"] = pos
    d["residue"] = len(data) - pos
    d["ok"] = (d["residue"] == 0)
    if not d["ok"]:
        d["why"] = "residue %d bytes" % d["residue"]
    return d


def read_tmd(path):
    data = open(path, "rb").read()
    d = {"path": path, "size": len(data), "ok": False, "why": ""}
    if len(data) < 12:
        d["why"] = "shorter than a header"
        return d
    fid, flags, nobj = struct.unpack_from("<III", data, 0)
    d["id"] = fid
    d["flags"] = flags
    d["nobj"] = nobj
    if fid != TMD_ID:
        d["why"] = "id is 0x%08X, not 0x00000041" % fid
        return d
    d["fixp"] = bool(flags & 1)
    base = 12
    if base > len(data):
        d["why"] = "object table of %d objects runs past the end" % nobj
        return d
    objs = []
    hi = base
    verts = norms = prims = 0
    for i in range(nobj):
        o = struct.unpack_from("<6Ii", data, 12 + i * 28)
        (vt, nv, nt, nn, pt, npz, scale) = o
        objs.append(o)
        verts += nv
        norms += nn
        prims += npz
        if not d["fixp"]:
            hi = max(hi, base + vt + nv * 8, base + nt + nn * 8, base + pt)
    d["objects"] = objs
    d["vertices"] = verts
    d["normals"] = norms
    d["primitives"] = prims
    d["high_water"] = hi
    d["residue"] = len(data) - hi
    # A TMD closes when the vertex and normal arrays fit inside the file and
    # the primitive lists (variable length) fill the rest. The strong test is
    # that nothing points past the end.
    d["ok"] = hi <= len(data) and nobj > 0
    if not d["ok"]:
        d["why"] = "pointers reach %d in a %d-byte file" % (hi, len(data))
    return d


def tim_at(data, pos):
    """Parse one TIM starting at pos. Returns (length, info) or (None, why)."""
    if pos + 8 > len(data):
        return None, "no room for a header"
    fid, flags = struct.unpack_from("<II", data, pos)
    if fid != TIM_ID:
        return None, "id 0x%08X" % fid
    pmode = flags & 7
    p = pos + 8
    nclut = 0
    entries = 0
    if flags & 8:
        if p + 12 > len(data):
            return None, "CLUT header past the end"
        bnum, dx, dy, w, h = struct.unpack_from("<IHHHH", data, p)
        if bnum != 12 + w * h * 2 or bnum <= 0:
            return None, "CLUT bnum mismatch"
        nclut, entries = h, w
        p += bnum
    if p + 12 > len(data):
        return None, "pixel header past the end"
    bnum, dx, dy, w, h = struct.unpack_from("<IHHHH", data, p)
    if bnum != 12 + w * h * 2 or bnum <= 0:
        return None, "pixel bnum mismatch"
    p += bnum
    mult = {0: 4, 1: 2, 2: 1, 3: 2.0 / 3.0}.get(pmode, 1)
    return p - pos, {"kind": "TIM", "pmode": pmode, "cluts": nclut,
                     "entries": entries, "w": int(w * mult), "h": h,
                     "fb": (dx, dy)}


def tmd_at(data, pos):
    """Parse one TMD starting at pos. Returns (length, info) or (None, why)."""
    if pos + 12 > len(data):
        return None, "no room for a header"
    fid, flags, nobj = struct.unpack_from("<III", data, pos)
    if fid != TMD_ID:
        return None, "id 0x%08X" % fid
    if nobj == 0 or nobj > 4096:
        return None, "nobj %d" % nobj
    base = pos + 12
    if base + nobj * 28 > len(data):
        return None, "object table past the end"
    hi = base
    verts = norms = prims = 0
    for i in range(nobj):
        vt, nv, nt, nn, pt, npz, scale = struct.unpack_from(
            "<6Ii", data, pos + 12 + i * 28)
        verts += nv
        norms += nn
        prims += npz
        if not (flags & 1):
            hi = max(hi, base + vt + nv * 8, base + nt + nn * 8,
                     base + pt)
    if hi > len(data):
        return None, "pointers reach %d in %d bytes" % (hi, len(data))
    return hi - pos, {"kind": "TMD", "nobj": nobj, "verts": verts,
                             "norms": norms, "prims": prims,
                             "declared_end": hi}


def chain(path):
    """Walk a file as a sequence of TIM and TMD blocks until it is consumed.

    A TMD's primitive lists are variable-length and the header does not give
    their total size, so a TMD can only be the LAST block of a chain: the tool
    says so rather than guessing a length. Everything before it must close.
    """
    data = open(path, "rb").read()
    pos = 0
    blocks = []
    while pos < len(data):
        n, info = tim_at(data, pos)
        if n:
            blocks.append((pos, n, info))
            pos += n
            continue
        n, info = tmd_at(data, pos)
        if n:
            blocks.append((pos, n, info))
            pos += n
            continue
        return blocks, pos, len(data) - pos, info
    return blocks, pos, 0, ""


def cmd_chain(files, root):
    shapes = collections.Counter()
    closed = 0
    total_blocks = collections.Counter()
    resid_bytes = 0
    bad = []
    for p in files:
        blocks, pos, residue, why = chain(p)
        shape = "+".join(b[2]["kind"] for b in blocks) or "(none)"
        shapes[(os.path.splitext(p)[1].upper(), shape, residue == 0)] += 1
        for b in blocks:
            total_blocks[b[2]["kind"]] += 1
        if residue == 0 and blocks:
            closed += 1
        else:
            resid_bytes += residue
            bad.append((p, shape, residue, why))
    print("-- walked as a chain of TIM and TMD blocks --------------------------")
    print("   files fully consumed : %d / %d" % (closed, len(files)))
    print("   blocks found         : %s"
          % ", ".join("%s x%d" % kv for kv in total_blocks.most_common()))
    print("   bytes left over      : %d" % resid_bytes)
    print()
    print("   %-6s %-28s %-7s %6s" % ("ext", "shape", "closed", "files"))
    for (ext, shape, ok), n in sorted(shapes.items(), key=lambda kv: -kv[1]):
        print("   %-6s %-28s %-7s %6d" % (ext, shape, ok, n))
    if bad:
        print()
        print("   files that did not consume:")
        for p, shape, r, why in bad[:12]:
            print("     %-50s %-16s residue %8d  (%s)"
                  % (os.path.relpath(p, root), shape, r, why))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--ext", nargs="*", default=[".tim", ".ivm", ".etm"])
    ap.add_argument("--tmd", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--tsv")
    ap.add_argument("--chain", action="store_true")
    a = ap.parse_args()

    exts = tuple(e.lower() for e in ([".tmd"] if a.tmd else a.ext))
    files = []
    if os.path.isdir(a.path):
        for dp, dn, fn in os.walk(a.path):
            for f in sorted(fn):
                if f.lower().endswith(exts):
                    files.append(os.path.join(dp, f))
    else:
        files = [a.path]

    if a.chain:
        cmd_chain(files, a.path if os.path.isdir(a.path) else ".")
        return

    if a.tmd:
        ok = 0
        rows = []
        for p in files:
            d = read_tmd(p)
            rows.append(d)
            ok += 1 if d["ok"] else 0
            print("%-46s %8d  objs %3d fixp %-5s verts %6d norms %6d prims %6d "
                  "high %8d residue %6d  %s"
                  % (os.path.relpath(p, a.path if os.path.isdir(a.path) else "."),
                     d["size"], d.get("nobj", -1), d.get("fixp"),
                     d.get("vertices", 0), d.get("normals", 0),
                     d.get("primitives", 0), d.get("high_water", 0),
                     d.get("residue", 0), "ok" if d["ok"] else d["why"]))
        print()
        print("TMD files            : %d" % len(files))
        print("parsed with no pointer past the end : %d / %d" % (ok, len(files)))
        print("total objects        : %d" % sum(r.get("nobj", 0) for r in rows))
        print("total vertices       : %d" % sum(r.get("vertices", 0) for r in rows))
        print("total normals        : %d" % sum(r.get("normals", 0) for r in rows))
        print("total primitives     : %d" % sum(r.get("primitives", 0) for r in rows))
        return

    rows = [read_tim(p) for p in files]
    ok = [r for r in rows if r["ok"]]
    bad = [r for r in rows if not r["ok"]]
    byext = collections.Counter(os.path.splitext(r["path"])[1].upper()
                                for r in rows)
    print("candidate files      : %d   (%s)"
          % (len(rows), ", ".join("%s x%d" % kv for kv in byext.most_common())))
    print("id == 0x00000010     : %d" % sum(1 for r in rows
                                            if r.get("id") == TIM_ID))
    print("closed on the byte   : %d / %d   (8 + clut_bnum + pix_bnum == size)"
          % (len(ok), len(rows)))
    print("bytes in closed files: %d" % sum(r["size"] for r in ok))
    print()
    print("-- pixel mode -------------------------------------------------------")
    pm = collections.Counter((r.get("pmode"), r.get("clut_flag")) for r in rows)
    for (m, cf), n in sorted(pm.items(), key=lambda kv: -kv[1]):
        print("   flags 0x%02X  %-14s CLUT %-5s  %5d files"
              % ((m or 0) | (8 if cf else 0), PMODE.get(m, "?"), cf, n))
    print()
    print("-- palettes ---------------------------------------------------------")
    nc = collections.Counter(r.get("nclut", 0) for r in rows)
    print("   palettes per file : %s"
          % ", ".join("%d x%d" % kv for kv in sorted(nc.items())))
    print("   files with >1 palette : %d of %d"
          % (sum(v for k, v in nc.items() if k > 1), len(rows)))
    ce = collections.Counter(r.get("clut_entries", 0) for r in rows)
    print("   entries per palette   : %s"
          % ", ".join("%d x%d" % kv for kv in sorted(ce.items())))
    print()
    print("-- dimensions -------------------------------------------------------")
    dims = collections.Counter((r.get("pixels_w"), r.get("pixels_h"))
                               for r in ok)
    for (w, h), n in dims.most_common(12):
        print("   %4s x %-4s  %5d files" % (w, h, n))
    print("   distinct sizes    : %d" % len(dims))
    print()
    if bad:
        print("-- files that did not close ----------------------------------------")
        for r in bad[:20]:
            print("   %-52s %8d  %s"
                  % (os.path.relpath(r["path"], a.path), r["size"], r["why"]))
    if a.verbose:
        for r in rows:
            print(r)
    if a.tsv:
        with open(a.tsv, "w", encoding="utf-8") as fh:
            fh.write("path\tsize\tflags\tpmode\tcluts\tclut_entries\t"
                     "w\th\tfb_x\tfb_y\tresidue\n")
            for r in rows:
                fh.write("%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n"
                         % (os.path.relpath(r["path"], a.path), r["size"],
                            r.get("flags"), r.get("pmode"), r.get("nclut"),
                            r.get("clut_entries"), r.get("pixels_w"),
                            r.get("pixels_h"), r.get("fb_x"), r.get("fb_y"),
                            r.get("residue")))
        print("wrote %s" % a.tsv)


if __name__ == "__main__":
    main()
