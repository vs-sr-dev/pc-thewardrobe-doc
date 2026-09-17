#!/usr/bin/env python3
"""aifprobe.py -- what is actually at the far end of an AIF's branch at offset 0?

`aifcensus.py` calls an image COMPRESSED when offset 0 holds a `BL` rather than
a `NOP`. On the first two 3DO discs that test agreed with the size relation
every time. On the third it fires on twenty images of thirty-seven and eleven of
those twenty declare LESS than they store, which no decompressor can do.

This prints, for every AIF image under a tree, the branch target at offset 0,
the branch target at offset 4, the declared sizes and the file length, so that
the disagreement can be classified rather than asserted.

usage: aifprobe.py TREE
"""
import os
import struct
import sys

SWI11 = 0xEF000011
NOP = 0xE1A00000


def bl_target(word, at):
    if (word >> 24) != 0xEB:
        return None
    disp = word & 0x00FFFFFF
    if disp & 0x800000:
        disp -= 0x1000000
    return at + 8 + 4 * disp


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: aifprobe.py TREE" + "\n")
        raise SystemExit(2)
    tree = sys.argv[1]
    rows = []
    for root, dirs, files in os.walk(tree):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            with open(p, "rb") as fh:
                b = fh.read()
            if len(b) < 0x38:
                continue
            if struct.unpack(">I", b[0x10:0x14])[0] != SWI11:
                continue
            w0, w1, w2, w3 = struct.unpack(">4I", b[0:16])
            ro, rw, dbg, zi = struct.unpack(">4I", b[0x14:0x24])
            dbgtype, base, work, flags, dbase = struct.unpack(">5I", b[0x24:0x38])
            name = p[len(tree):].replace(os.sep, "/")
            rows.append(dict(path=name, size=len(b), ro=ro, rw=rw, dbg=dbg, zi=zi,
                             t0=bl_target(w0, 0), t1=bl_target(w1, 4),
                             t3=bl_target(w3, 12), flags=flags, base=base,
                             work=work, dbase=dbase, dbgtype=dbgtype,
                             w0=w0, tail=b[-16:]))
    rows.sort(key=lambda r: r["path"])
    hdr = ("%-46s %8s %8s %7s %6s %8s %8s %8s %8s"
           % ("path", "size", "ro", "rw", "dbg", "zi", "BL0", "BL4", "ro+rw"))
    print(hdr)
    for r in rows:
        print("%-46s %8d %8d %7d %6d %8d %8s %8s %8d%s"
              % (r["path"], r["size"], r["ro"], r["rw"], r["dbg"], r["zi"],
                 "NOP" if r["t0"] is None else "0x%x" % r["t0"],
                 "NOP" if r["t1"] is None else "0x%x" % r["t1"],
                 r["ro"] + r["rw"],
                 "" if r["t1"] == r["ro"] + r["rw"] else "   <- reloc off"))
    print()
    print("images                          : %d" % len(rows))
    bl0 = [r for r in rows if r["t0"] is not None]
    print("BL at offset 0                  : %d" % len(bl0))
    print("  of those, ro+rw > size        : %d"
          % sum(1 for r in bl0 if r["ro"] + r["rw"] > r["size"]))
    print("  of those, ro+rw < size        : %d"
          % sum(1 for r in bl0 if r["ro"] + r["rw"] < r["size"]))
    nop0 = [r for r in rows if r["t0"] is None]
    print("NOP at offset 0                 : %d" % len(nop0))
    print("  of those, ro+rw > size        : %d"
          % sum(1 for r in nop0 if r["ro"] + r["rw"] > r["size"]))
    print()
    print("branch-at-0 targets, sorted:")
    for r in sorted(bl0, key=lambda r: r["t0"]):
        rel = "beyond ro" if r["t0"] >= r["ro"] else "inside ro"
        print("   %-44s BL0 -> 0x%-6x  (%6.2f %% of file, %s)  ro+rw/size %.4f"
              % (r["path"], r["t0"], 100.0 * r["t0"] / r["size"], rel,
                 float(r["ro"] + r["rw"]) / r["size"]))


if __name__ == "__main__":
    main()
