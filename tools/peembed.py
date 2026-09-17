#!/usr/bin/env python3
"""peembed.py -- close a PE image on its own section table, walk its resource
directory, and find whole executables stored inside it as resources.

WHY THIS EXISTS
---------------
A signature count that finds `MZP` twice inside one file invites the reading
that the file is two files glued together, and the arithmetic can even seem to
support it. That reading is checkable and this tool checks it, by asking three
questions in order:

  1. **does the outer image already account for the whole file?** The section
     table declares, for every section, a raw pointer and a raw size. The
     highest `pointer + size` is where the image ends. If that equals the file's
     byte count, the file is ONE image and nothing was appended to it;
  2. **where does the inner signature fall?** If it lands inside a section, it
     is content, not a second file;
  3. **does a resource entry begin exactly there, and does its declared size
     equal the inner image's own reach?** If it does, the inner executable is
     a resource, and two independent structures -- the outer file's resource
     directory and the inner file's section table -- have agreed on a length.

Only the third answer turns "there are two MZ headers in here" into a
measurement. `--split`, deliberately, is not offered: this tool cannot cut a
file in two, because on the object it was written for the file does not divide.

    python tools/peembed.py <file.exe>
    python tools/peembed.py <file.exe> --resources
    python tools/peembed.py <file.exe> --extract-to <dir>
    python tools/peembed.py selftest
"""
import argparse
import collections
import os
import struct
import sys


class Bad(Exception):
    pass


RT = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
      6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA",
      11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON",
      16: "VERSION", 24: "MANIFEST"}


def read_pe(blob, base=0):
    """Parse one PE image starting at `base`. Returns a dict, or raises."""
    if len(blob) < base + 64:
        raise Bad("no room for a DOS header at %d" % base)
    if blob[base:base + 2] != b"MZ":
        raise Bad("no MZ signature at %d: %r" % (base, blob[base:base + 2]))
    (lfanew,) = struct.unpack_from("<I", blob, base + 0x3C)
    pe = base + lfanew
    if pe + 24 > len(blob):
        raise Bad("e_lfanew %d at %d points past the end of the file"
                  % (lfanew, base))
    if blob[pe:pe + 4] != b"PE\x00\x00":
        raise Bad("no PE signature at e_lfanew=%d (found %r)"
                  % (lfanew, blob[pe:pe + 4]))
    (machine, nsec, stamp, _, _, optsz, chars) = struct.unpack_from(
        "<HHIIIHH", blob, pe + 4)
    (optmagic,) = struct.unpack_from("<H", blob, pe + 24)
    (imgbase,) = struct.unpack_from("<I", blob, pe + 24 + 28)
    (sizeimage, sizehdr) = struct.unpack_from("<II", blob, pe + 24 + 56)
    sect = pe + 24 + optsz
    if sect + nsec * 40 > len(blob):
        raise Bad("the section table of %d sections at %d runs off the end"
                  % (nsec, sect))
    sections = []
    for i in range(nsec):
        (name, vsize, va, rsize, rptr) = struct.unpack_from("<8sIIII", blob,
                                                            sect + i * 40)
        sections.append(dict(name=name.rstrip(b"\x00").decode("ascii",
                                                              "replace"),
                             vsize=vsize, va=va, rsize=rsize, rptr=rptr))
    if not sections:
        raise Bad("the image at %d declares zero sections" % base)
    reach = max(s["rptr"] + s["rsize"] for s in sections)
    (nrva,) = struct.unpack_from("<I", blob, pe + 24 + 92)
    dirs = []
    for i in range(min(nrva, 16)):
        dirs.append(struct.unpack_from("<II", blob, pe + 24 + 96 + i * 8))
    return dict(base=base, pe=pe, lfanew=lfanew, machine=machine,
                stamp=stamp, characteristics=chars, opt_magic=optmagic,
                image_base=imgbase, size_of_image=sizeimage,
                size_of_headers=sizehdr, sections=sections, reach=reach,
                dirs=dirs, stub=bytes(blob[base:base + 4]))


def rsrc_walk(blob, img):
    """Every leaf of the resource directory as (path, file offset, size)."""
    rs = [s for s in img["sections"] if s["name"] == ".rsrc"]
    if not rs:
        return [], None
    rs = rs[0]
    RVA, RAW = rs["va"], rs["rptr"]
    lo, hi = RAW, RAW + rs["rsize"]

    def off(rva):
        o = RAW + (rva - RVA)
        if not lo <= o < hi:
            raise Bad("a resource RVA of %d lands at %d, outside .rsrc "
                      "(%d..%d)" % (rva, o, lo, hi))
        return o

    out = []
    seen = set()

    def walk(rva, path, depth):
        if depth > 4:
            raise Bad("the resource tree is deeper than four levels")
        o = off(rva)
        if o in seen:
            raise Bad("the resource tree loops back to %d" % o)
        seen.add(o)
        nname, nid = struct.unpack_from("<HH", blob, o + 12)
        for k in range(nname + nid):
            nm, offs = struct.unpack_from("<II", blob, o + 16 + k * 8)
            if nm & 0x80000000:
                po = off(RVA + (nm & 0x7FFFFFFF))
                (ln,) = struct.unpack_from("<H", blob, po)
                name = blob[po + 2:po + 2 + ln * 2].decode("utf-16-le")
            else:
                name = (RT.get(nm, str(nm)) if depth == 0 else str(nm))
            if offs & 0x80000000:
                walk(RVA + (offs & 0x7FFFFFFF), path + [name], depth + 1)
            else:
                do = off(RVA + offs)
                drva, dsz = struct.unpack_from("<II", blob, do)
                out.append((path + [name], off(drva), dsz))

    walk(RVA, [], 0)
    return out, rs


def report(path, args):
    blob = open(path, "rb").read()
    img = read_pe(blob)
    print("file                    : %s" % path)
    print("bytes                   : %d" % len(blob))
    print("DOS stub's first 4 bytes: %r" % img["stub"])
    print("e_lfanew                : %d" % img["lfanew"])
    print("machine                 : 0x%04X" % img["machine"])
    print("COFF TimeDateStamp      : %d" % img["stamp"])
    print("sections                : %d" % len(img["sections"]))
    print()
    print("-- QUESTION 1: does the outer image account for the whole file? -")
    print("   %-10s %10s %10s %10s %10s %12s"
          % ("name", "vsize", "rva", "rawsize", "rawptr", "raw end"))
    for s in img["sections"]:
        print("   %-10s %10d %10d %10d %10d %12d"
              % (s["name"], s["vsize"], s["va"], s["rsize"], s["rptr"],
                 s["rptr"] + s["rsize"]))
    print("   highest raw end      : %d" % img["reach"])
    print("   file length          : %d" % len(blob))
    print("   RESIDUE              : %d" % (img["reach"] - len(blob)))
    print()

    ents, rs = rsrc_walk(blob, img)
    print("-- the resource directory --------------------------------------")
    if rs is None:
        print("   no .rsrc section")
    else:
        print("   .rsrc at raw %d, %d bytes" % (rs["rptr"], rs["rsize"]))
        print("   leaf entries         : %d" % len(ents))
        print("   declared bytes       : %d" % sum(e[2] for e in ents))
        byt = collections.Counter(e[0][0] for e in ents)
        print("   by top-level type    : %s" % dict(byt))
    print()

    print("-- QUESTION 2 and 3: is there an executable inside it? ---------")
    inner = []
    off = 0
    while True:
        j = blob.find(b"MZ", off)
        if j < 0:
            break
        off = j + 1
        if j == 0:
            continue
        try:
            sub = read_pe(blob, j)
        except Bad:
            continue
        where = [s for s in img["sections"]
                 if s["rptr"] <= j < s["rptr"] + s["rsize"]]
        hit = [e for e in ents if e[1] == j]
        inner.append((j, sub, where, hit))
        print("   an MZ that parses as PE at file offset %d" % j)
        print("      stub %r, e_lfanew %d, %d sections, stamp %d"
              % (sub["stub"], sub["lfanew"], len(sub["sections"]),
                 sub["stamp"]))
        print("      it falls inside the outer image's %s section"
              % (where[0]["name"] if where else "(no)"))
        print("      its own section table reaches   : %d bytes" % sub["reach"])
        if hit:
            for p, o, sz in hit:
                print("      a resource entry begins exactly here:")
                print("         %s" % "/".join(p))
                print("         declared size %d against the inner image's "
                      "reach %d   RESIDUE %d" % (sz, sub["reach"],
                                                 sz - sub["reach"]))
        else:
            print("      NO resource entry begins at this offset")
        print()
    if not inner:
        print("   none")
    print("-- the verdict -------------------------------------------------")
    if img["reach"] == len(blob) and inner and all(h for _, _, _, h in inner):
        print("   The file is ONE image that accounts for every byte, and the")
        print("   inner executable(s) are RESOURCES of it. The file does not")
        print("   divide in two, and any arithmetic that appears to divide it")
        print("   is a coincidence of the remainder, not a boundary.")
    elif img["reach"] == len(blob):
        print("   The file is ONE image that accounts for every byte.")
    else:
        print("   The outer image does not account for the whole file: %d "
              "bytes are outside it." % (len(blob) - img["reach"]))

    if args.resources and ents:
        print()
        print("-- every resource leaf, by declared size -----------------------")
        for p, o, sz in sorted(ents, key=lambda e: -e[2]):
            print("   %-40s offset %-9d size %-9d first4 %r"
                  % ("/".join(p), o, sz, blob[o:o + 4]))

    if args.extract_to:
        os.makedirs(args.extract_to, exist_ok=True)
        n = 0
        for j, sub, where, hit in inner:
            if not hit:
                continue
            p, o, sz = hit[0]
            name = "_".join(x.replace("/", "_") for x in p) + ".bin"
            with open(os.path.join(args.extract_to, name), "wb") as fh:
                fh.write(blob[o:o + sz])
            n += 1
            print()
            print("   wrote %s (%d bytes)"
                  % (os.path.join(args.extract_to, name), sz))
        if not n:
            print()
            print("   nothing extracted: no inner image is a resource")
    return 0 if img["reach"] == len(blob) else 1


# ---------------------------------------------------------------- selftest

def build_pe(sections=None, extra=b"", lfanew=0x80, stub=b"MZ\x90\x00",
             sig=b"PE\x00\x00", nsec=None, optsz=224):
    if sections is None:
        sections = [("CODE", 0x1000, 512, 512)]
    head = bytearray(lfanew)
    head[0:4] = stub
    struct.pack_into("<I", head, 0x3C, lfanew)
    coff = bytearray(24 + optsz)
    coff[0:4] = sig
    struct.pack_into("<HHIIIHH", coff, 4, 0x014C,
                     nsec if nsec is not None else len(sections),
                     708992537, 0, 0, optsz, 0x818E)
    struct.pack_into("<H", coff, 24, 0x010B)
    table = bytearray()
    reach = 0
    for name, va, rsize, rptr in sections:
        table += struct.pack("<8sIIII", name.encode(), rsize, va, rsize, rptr)
        reach = max(reach, rptr + rsize)
    body = bytearray(max(0, reach - (lfanew + len(coff) + len(table))))
    return bytes(head + coff + table + body) + extra


def selftest():
    checks = []

    def ok(n, c):
        checks.append((n, bool(c)))

    def refuses(n, thunk, frag):
        try:
            thunk()
        except Bad as e:
            ok(n + " (" + frag + ")", frag in str(e))
        else:
            ok(n + " (" + frag + ")", False)

    blob = build_pe()
    img = read_pe(blob)
    ok("a constructed PE parses", img["machine"] == 0x014C)
    ok("its reach is the highest raw end", img["reach"] == 1024)
    ok("a file exactly that long closes at residue 0",
       img["reach"] - len(blob[:1024]) == 0)

    refuses("empty input", lambda: read_pe(b""), "no room for a DOS header")
    refuses("a PNG", lambda: read_pe(b"\x89PNG\r\n\x1a\n" + bytes(200)),
            "no MZ signature")
    refuses("an ITSF container", lambda: read_pe(b"ITSF" + bytes(200)),
            "no MZ signature")
    refuses("an NE binary",
            lambda: read_pe(build_pe(sig=b"NE\x00\x00")), "no PE signature")
    refuses("e_lfanew past the end",
            lambda: read_pe(build_pe()[:100]), "points past the end")
    refuses("a section table that runs off the end",
            lambda: read_pe(build_pe(nsec=4000)), "runs off the end")
    refuses("an image declaring zero sections",
            lambda: read_pe(build_pe(sections=[], nsec=0)),
            "zero sections")

    # An MZP stub is an MZ: Borland's `MZP` must still parse.
    img = read_pe(build_pe(stub=b"MZP\x00"))
    ok("an MZP stub parses as MZ, because 'MZ' is the signature",
       img["stub"] == b"MZP\x00")

    # A file with bytes appended past the image's reach.
    blob = build_pe(extra=b"appended")
    img = read_pe(blob)
    ok("eight appended bytes make the residue -8, not 0",
       img["reach"] - len(blob) == -8)

    # Two sections, and the reach is the higher end, not the last listed.
    img = read_pe(build_pe(sections=[("CODE", 0x1000, 512, 2048),
                                     ("DATA", 0x2000, 512, 512)]))
    ok("the reach is the HIGHEST raw end, not the last section's",
       img["reach"] == 2560)

    # An inner MZ that does not parse must not be reported as an image.
    blob = build_pe(sections=[("CODE", 0x1000, 1024, 512)]) + b"MZnotape"
    found = []
    o = 0
    while True:
        j = blob.find(b"MZ", o)
        if j < 0:
            break
        o = j + 1
        if j == 0:
            continue
        try:
            read_pe(blob, j)
            found.append(j)
        except Bad:
            pass
    ok("a bare 'MZ' with no PE header behind it is not counted as an image",
       found == [])

    ok("resource type 10 is named RCDATA", RT[10] == "RCDATA")
    ok("resource type 16 is named VERSION", RT[16] == "VERSION")

    width = max(len(n) for n, _ in checks)
    for n, g in checks:
        print("  %-*s %s" % (width, n, "ok" if g else "FAIL"))
    bad = [n for n, g in checks if not g]
    print("%d checks, %d failures" % (len(checks), len(bad)))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--resources", action="store_true")
    ap.add_argument("--extract-to")
    args = ap.parse_args()
    if args.path == "selftest":
        return selftest()
    return report(args.path, args)


if __name__ == "__main__":
    sys.exit(main())
