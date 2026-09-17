#!/usr/bin/env python3
"""farcalls.py -- map the far calls of an unpacked DOS MZ program to the
segments its relocation table names, and say how many go where.

WHY
---
A program with no symbol table and no compiler banner still has a structure,
and its relocation table is where that structure is written down: every
`call far seg:off` (opcode 9Ah) whose segment word is a relocation item points
at a segment the program itself declares. Counting those calls per segment
finds the run-time library (the segment that gets most of them), the modules
that get a handful, and the entry segment; and `--to OFFSET` answers "who
calls this routine", which is how the drawing interpreter of THE DEMON'S FORGE
was placed at one call site (pc-demonsforge-doc/docs/04).

The count is of far calls whose segment word is a relocation item. Far calls
through a register or a memory pointer, near calls, and jump tables are not
seen; a `9A` byte inside data is excluded because its segment word is not
relocated -- which is the point of using the table rather than the opcode.

    python tools/farcalls.py demons-forge/FORGE.EXE
    python tools/farcalls.py demons-forge/FORGE.EXE --to 0x717B
    python tools/farcalls.py --selftest

Standard library only; it reads and prints.
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402


def analyse(blob):
    if blob[:2] not in (b"MZ", b"ZM") or len(blob) < 28:
        raise ValueError("not an MZ executable")
    f = struct.unpack("<14H", blob[:28])
    cparhdr, crlc, lfarlc = f[4], f[3], f[12]
    hdr = cparhdr * 16
    items = set()
    for i in range(crlc):
        off, seg = struct.unpack("<HH", blob[lfarlc + 4 * i:lfarlc + 4 * i + 4])
        items.add(seg * 16 + off)
    per_seg = collections.Counter()
    calls = []                       # (file offset of the 9A, target file offset, seg, off)
    for i in range(hdr, len(blob) - 4):
        if blob[i] == 0x9A and (i + 3 - hdr) in items:
            off, seg = struct.unpack("<HH", blob[i + 1:i + 5])
            per_seg[seg] += 1
            calls.append((i, hdr + seg * 16 + off, seg, off))
    return {"header": hdr, "relocs": crlc, "per_seg": per_seg, "calls": calls,
            "entry": (f[11], f[10]), "entry_file": hdr + f[11] * 16 + f[10]}


def report(path, a):
    print(os.path.basename(path))
    print("  header %d bytes, %d relocation items, entry %04X:%04X = file 0x%05X"
          % (a["header"], a["relocs"], a["entry"][0], a["entry"][1], a["entry_file"]))
    print("  far calls whose segment word is a relocation item: %d, into %d segments"
          % (len(a["calls"]), len(a["per_seg"])))
    print("  %-8s %-10s %s" % ("segment", "file", "calls"))
    for seg, n in sorted(a["per_seg"].items()):
        print("  %04X     0x%05X    %d" % (seg, a["header"] + seg * 16, n))


def selftest():
    checks = []
    # an MZ with a 32-byte header, two far calls into segment 0001 and one 9A in data
    body = bytearray(b"\x90" * 8)
    body += b"\x9a\x10\x00\x01\x00"          # call far 0001:0010  (reloc at body+11)
    body += b"\x9a\x20\x00\x01\x00"          # call far 0001:0020  (reloc at body+16)
    body += b"\x9a\x00\x00\x01\x00"          # a 9A that is NOT relocated: data
    body += b"\x00" * 16                     # segment 0001 begins at body+16
    relocs = struct.pack("<HHHH", 11, 0, 16, 0)
    # header: 28 bytes of fields, the 8-byte relocation table at 28, padded to 48 = 3 paragraphs
    hdr = struct.pack("<14H", 0x5A4D, (48 + len(body)) % 512, 1, 2, 3, 0, 0xFFFF, 0, 0, 0, 0, 0, 28, 0)
    blob = (bytes(hdr) + relocs).ljust(48, b"\0") + bytes(body)
    a = analyse(blob)
    checks.append(("two relocated far calls are counted, the unrelocated 9A is not", len(a["calls"]) == 2, str(a["calls"])))
    checks.append(("both go to segment 0001; the first lands at file 48 + 16 + 0x10",
                   len(a["calls"]) == 2 and (a["per_seg"][1], a["calls"][0][1]) == (2, 48 + 16 + 0x10), str(a["calls"])))
    try:
        analyse(b"XX" + bytes(40))
        checks.append(("a non-MZ file is refused", False, "it parsed"))
    except ValueError:
        checks.append(("a non-MZ file is refused", True, ""))
    checks.append(("dirguard.want_file is imported", hasattr(dirguard, "want_file"), ""))
    checks.append(("nameguard.guard is imported", hasattr(nameguard, "guard"), ""))
    w = max(len(c[0]) for c in checks)
    for label, ok, d in checks:
        print("  %-*s  %s%s" % (w, label, "ok" if ok else "FAIL", "" if ok else "   " + d))
    bad = sum(1 for c in checks if not c[1])
    print("%d checks, %d failures" % (len(checks), bad))
    return 1 if bad else 0


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?")
    ap.add_argument("--to", help="file offset of a routine: list the far calls that reach it")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        raise SystemExit(selftest())
    if not args.file:
        ap.error("give an MZ file, or --selftest")
    dirguard.want_file(args.file, "farcalls")
    blob = open(args.file, "rb").read()
    try:
        a = analyse(blob)
    except ValueError as exc:
        sys.exit("farcalls: %s: %s" % (os.path.basename(args.file), exc))
    report(args.file, a)
    if args.to:
        want = int(args.to, 0)
        hits = [c for c in a["calls"] if c[1] == want]
        print("  calls to file 0x%05X: %d  %s" % (want, len(hits), " ".join("0x%05X" % c[0] for c in hits)))


if __name__ == "__main__":
    main()
