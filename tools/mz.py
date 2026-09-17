#!/usr/bin/env python3
"""mz.py -- read a real-mode DOS MZ executable header and its relocations.

This collection has opened PE32, PE32+, NE-shaped expectations and a good
many flat binaries, and it has never read an MZ header.  `SHI.EXE` on the
*Sherlock Holmes: Consulting Detective* VIS disc is one, and the platform
checklist for that machine says a title is a Win16 **NE** application -- so
reading the header and showing that `e_lfanew` is zero and that the page
arithmetic closes on the file length is the measurement that says what this
binary is, rather than what it is not.

The header, per the DOS 2.0 EXE format:

     +0  2  e_magic      'MZ' or 'ZM'
     +2  2  e_cblp       bytes used in the last 512-byte page
     +4  2  e_cp         number of 512-byte pages, last one included
     +6  2  e_crlc       relocation entries
     +8  2  e_cparhdr    header size in 16-byte paragraphs
    +10  2  e_minalloc   minimum extra paragraphs
    +12  2  e_maxalloc   maximum extra paragraphs
    +14  2  e_ss         initial SS, relative to the load segment
    +16  2  e_sp         initial SP
    +18  2  e_csum       checksum, usually 0
    +20  2  e_ip         initial IP
    +22  2  e_cs         initial CS, relative to the load segment
    +24  2  e_lfarlc     file offset of the relocation table
    +26  2  e_ovno       overlay number
    +60  4  e_lfanew     offset of a PE/NE/LE header -- ZERO means there is
                         none, and this file is a plain real-mode program

THE CHECK THAT MATTERS

`(e_cp - 1) * 512 + e_cblp` is the file length the header claims.  Comparing
it with the length on disc is a quantity encoded twice: the header says how
long the image is, and the file system says how long the file is.  When they
agree with residue 0, nothing has been appended to the executable -- no
overlay, no self-extracting payload, no packer's tail.  When they disagree,
the difference is the interesting part.
"""

import argparse
import os
import struct
import sys

FIELDS = ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc",
          "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs",
          "e_lfarlc", "e_ovno"]


def read(path):
    b = open(path, "rb").read()
    if len(b) < 64:
        raise ValueError("%s is %d bytes, too short for an MZ header"
                         % (path, len(b)))
    if b[:2] not in (b"MZ", b"ZM"):
        raise ValueError("%s does not begin with MZ or ZM (it begins %r)"
                         % (path, b[:2]))
    v = struct.unpack_from("<14H", b, 0)
    d = dict(zip(FIELDS, v))
    d["e_lfanew"] = struct.unpack_from("<I", b, 0x3C)[0]
    d["file_size"] = len(b)
    d["_bytes"] = b
    return d


def report(path, show_relocs):
    d = read(path)
    b = d.pop("_bytes")
    size = d["file_size"]
    print("=== %s ===" % os.path.relpath(path))
    print("  file size on disc          : %d" % size)
    for k in FIELDS[1:] + ["e_lfanew"]:
        print("  %-26s : %-8d 0x%X" % (k, d[k], d[k]))
    print()
    claimed = (d["e_cp"] - 1) * 512 + d["e_cblp"] if d["e_cblp"] else \
        d["e_cp"] * 512
    print("  pages x 512 + last page    : (%d - 1) * 512 + %d = %d"
          % (d["e_cp"], d["e_cblp"], claimed))
    print("  against the file length    : %d   residue %+d %s"
          % (size, size - claimed,
             "-- NOTHING IS APPENDED" if size == claimed else
             "-- THERE IS DATA BEYOND THE DECLARED IMAGE"))
    hdr = d["e_cparhdr"] * 16
    print("  header                     : %d paragraphs = %d bytes"
          % (d["e_cparhdr"], hdr))
    print("  load image                 : %d - %d = %d bytes"
          % (size, hdr, size - hdr))
    print("  entry point                : %04X:%04X  (file offset %d)"
          % (d["e_cs"], d["e_ip"], hdr + d["e_cs"] * 16 + d["e_ip"]))
    print("  initial stack              : %04X:%04X" % (d["e_ss"], d["e_sp"]))
    print("  extra paragraphs           : min %d (%d bytes), max %d%s"
          % (d["e_minalloc"], d["e_minalloc"] * 16, d["e_maxalloc"],
             "  (0xFFFF = take all available memory)"
             if d["e_maxalloc"] == 0xFFFF else ""))
    print()
    if d["e_lfanew"] == 0:
        print("  e_lfanew is 0: there is NO extended header. This is a plain")
        print("  real-mode DOS executable -- not NE, not LE, not LX, not PE.")
    else:
        tag = b[d["e_lfanew"]:d["e_lfanew"] + 2]
        print("  e_lfanew points at 0x%X, where the signature is %r"
              % (d["e_lfanew"], tag))
    for sig in (b"NE", b"LE", b"LX", b"PE\0\0"):
        n = b.count(sig)
        print("  occurrences of %-6r anywhere in the file: %d"
              % (sig.decode("latin-1"), n))
    print()
    # relocations
    off = d["e_lfarlc"]
    n = d["e_crlc"]
    print("  relocation table           : %d entries at 0x%X, %d bytes,"
          " ending 0x%X" % (n, off, n * 4, off + n * 4))
    if off + n * 4 > hdr:
        print("  !! the table runs past the end of the header")
    else:
        print("  header slack after table   : %d bytes" % (hdr - off - n * 4))
    inside = 0
    outside = []
    segs = {}
    for i in range(n):
        o, s = struct.unpack_from("<HH", b, off + 4 * i)
        segs[s] = segs.get(s, 0) + 1
        lin = s * 16 + o
        if lin < size - hdr:
            inside += 1
        else:
            outside.append((i, s, o))
    print("  entries landing inside the load image : %d / %d" % (inside, n))
    if outside:
        print("  entries landing outside               : %d, first %r"
              % (len(outside), outside[:3]))
    print("  distinct relocation segments          : %d" % len(segs))
    slack = b[off + n * 4:hdr]
    print("  header slack is all zero              : %s"
          % (not any(slack)))
    if show_relocs:
        print("  first 12 entries (segment:offset):")
        for i in range(min(12, n)):
            o, s = struct.unpack_from("<HH", b, off + 4 * i)
            print("     %04X:%04X" % (s, o))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--relocs", action="store_true")
    a = ap.parse_args()
    rc = 0
    for p in a.files:
        try:
            report(p, a.relocs)
        except ValueError as e:
            print("=== %s ===" % os.path.relpath(p))
            print("  REJECTED: %s" % e)
            rc = 1
        print()
    sys.exit(rc)


if __name__ == "__main__":
    main()
