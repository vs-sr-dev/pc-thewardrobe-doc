#!/usr/bin/env python3
"""aifstub.py -- is the tail of an AIF image a decompressor, and is it the same one?

The `BL` at offset 0 of an ARM Image Format file branches to decompression code.
If that code is real, it sits at the branch target, it runs to the end of the
file, and images built by the same toolchain share it byte for byte.

This measures the tail of every AIF image under a tree:

    the branch target at offset 0
    the number of bytes from there to end of file
    the SHA-1 of those bytes

and groups the images by that hash. A test that says "compressed" because of one
word at offset 0 is an assertion; a test that says "compressed, and here are
nine images sharing one 392-byte decompressor byte for byte" is a measurement.

The negative control is the images with a NOP at offset 0: they must have no
such tail, and the tool prints them so the absence is visible.

usage: aifstub.py TREE
"""
import hashlib
import os
import struct
import sys

SWI11 = 0xEF000011


def bl_target(word, at):
    if (word >> 24) != 0xEB:
        return None
    disp = word & 0x00FFFFFF
    if disp & 0x800000:
        disp -= 0x1000000
    return at + 8 + 4 * disp


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: aifstub.py TREE" + "\n")
        raise SystemExit(2)
    tree = sys.argv[1]
    imgs = []
    for root, dirs, files in os.walk(tree):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            with open(p, "rb") as fh:
                b = fh.read()
            if len(b) < 0x38:
                continue
            if struct.unpack(">I", b[0x10:0x14])[0] != SWI11:
                continue
            w0, w1 = struct.unpack(">2I", b[0:8])
            ro, rw, dbg, zi = struct.unpack(">4I", b[0x14:0x24])
            imgs.append(dict(path=p[len(tree):].replace(os.sep, "/"),
                             size=len(b), ro=ro, rw=rw, dbg=dbg, zi=zi,
                             t0=bl_target(w0, 0), t1=bl_target(w1, 4), buf=b))
    imgs.sort(key=lambda r: r["path"])

    print("=== the relocation branch, on every image ===")
    ok_rr = ok_rrd = 0
    for r in imgs:
        if r["t1"] == r["ro"] + r["rw"]:
            ok_rr += 1
        if r["t1"] == r["ro"] + r["rw"] + r["dbg"]:
            ok_rrd += 1
    print("BL at 0x04 target == ro + rw          : %d of %d" % (ok_rr, len(imgs)))
    print("BL at 0x04 target == ro + rw + debug  : %d of %d" % (ok_rrd, len(imgs)))
    for r in imgs:
        if r["dbg"]:
            print("   %-44s ro %d + rw %d + debug %d = %d, branch 0x%x = %d"
                  % (r["path"], r["ro"], r["rw"], r["dbg"],
                     r["ro"] + r["rw"] + r["dbg"], r["t1"], r["t1"]))
    print()

    print("=== the tail after the branch target at offset 0 ===")
    groups = {}
    withbl = [r for r in imgs if r["t0"] is not None]
    for r in withbl:
        tail = r["buf"][r["t0"]:]
        h = hashlib.sha1(tail).hexdigest()
        groups.setdefault((len(tail), h), []).append(r["path"])
        r["taillen"] = len(tail)
        r["tailsha"] = h
    print("images with a BL at offset 0 : %d" % len(withbl))
    print("distinct tails               : %d" % len(groups))
    for (n, h), paths in sorted(groups.items()):
        print("  %5d bytes  %s  %d image(s)" % (n, h[:16], len(paths)))
        for p in paths:
            print("        %s" % p)
    print()
    print("=== negative control: images with a NOP at offset 0 ===")
    nop = [r for r in imgs if r["t0"] is None]
    print("%d images. None of them can have a decompressor tail, because there is"
          % len(nop))
    print("no branch to one. Their read-only + read-write + debug against size:")
    bad = 0
    for r in nop:
        decl = r["ro"] + r["rw"] + r["dbg"]
        if decl > r["size"]:
            bad += 1
            print("   %-44s declares %d > stores %d  <- MUST NOT HAPPEN"
                  % (r["path"], decl, r["size"]))
    print("images with a NOP that declare more than they store: %d (expected 0)"
          % bad)
    print()
    print("=== ratios, computed against the compressed region and not the file ===")
    print("%-46s %8s %8s %8s %8s" % ("path", "stored", "stub", "declared", "ratio"))
    for r in sorted(withbl, key=lambda r: r["path"]):
        stored = r["t0"]
        decl = r["ro"] + r["rw"] + r["dbg"]
        print("%-46s %8d %8d %8d %8.4f"
              % (r["path"], stored, r["taillen"], decl, float(decl) / stored))


if __name__ == "__main__":
    main()
