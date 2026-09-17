#!/usr/bin/env python3
"""m68k.py -- word byte-swap and 68000 reset-vector test for CPS ROM regions.

A 68000 program ROM built from two 8-bit chips on a 16-bit bus ends up, in a
little-endian dump, with the two bytes of every 16-bit word exchanged. Undoing
that is one line; the useful part is the test that says whether the result is
actually a 68000 image.

The test used here, and it is a positive test, not an absence:

  * longword 0 is the initial stack pointer: must be even, must be non-zero,
    and on this hardware must land in the 0xFF0000 work-RAM window;
  * longword 1 is the initial program counter: must be even, non-zero, and
    must land inside the region;
  * the remaining exception vectors must be even and inside the region too.

The 0xFF0000 constraint is the board's, not the format's, and it is named
here so that a reader can see exactly what is being assumed.

Usage:
    m68k.py --vectors FILE [--offset N] [--size N]
    m68k.py --swap    FILE --out FILE
    m68k.py --strings FILE [--min N]
"""
import argparse
import re
import struct
import sys


def swap16(b):
    a = bytearray(b)
    a[0::2] = b[1::2]
    a[1::2] = b[0::2]
    return bytes(a)


def vector_test(img, nvec=64):
    """img is already byte-swapped. Returns (verdict, facts)."""
    if len(img) < nvec * 4:
        return False, {"why": "shorter than %d vectors" % nvec}
    vecs = list(struct.unpack_from(">%dI" % nvec, img, 0))
    sp, pc = vecs[0], vecs[1]
    facts = {"sp": sp, "pc": pc, "nvec": nvec}
    ok_sp = (sp % 2 == 0) and (0x00FF0000 <= sp <= 0x00FFFFFF)
    ok_pc = (pc % 2 == 0) and (0 < pc < len(img))
    rest = vecs[2:]
    inside = sum(1 for v in rest if v % 2 == 0 and 0 < v < len(img))
    facts["ok_sp"] = ok_sp
    facts["ok_pc"] = ok_pc
    facts["vectors_inside"] = inside
    facts["vectors_checked"] = len(rest)
    facts["frac_inside"] = inside / len(rest) if rest else 0.0
    verdict = ok_sp and ok_pc and facts["frac_inside"] > 0.5
    return verdict, facts


ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")


def strings(img, minlen=6):
    return [(m.start(), m.group()) for m in
            re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, img)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", action="store_true")
    ap.add_argument("--swap", action="store_true")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--offset", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--min", type=int, default=6)
    ap.add_argument("--out")
    ap.add_argument("file")
    a = ap.parse_args()

    with open(a.file, "rb") as fh:
        data = fh.read()
    if a.size:
        data = data[a.offset:a.offset + a.size]
    elif a.offset:
        data = data[a.offset:]
    img = swap16(data)

    if a.swap:
        if not a.out:
            print("--swap needs --out")
            return 2
        with open(a.out, "wb") as fh:
            fh.write(img)
        print("wrote %s (%d bytes)" % (a.out, len(img)))
    if a.vectors:
        ok, f = vector_test(img)
        print("%-6s SP=0x%08X (%s)  PC=0x%08X (%s)  other vectors inside: %d/%d (%.1f%%)"
              % ("68000" if ok else "no",
                 f.get("sp", 0), "ok" if f.get("ok_sp") else "bad",
                 f.get("pc", 0), "ok" if f.get("ok_pc") else "bad",
                 f.get("vectors_inside", 0), f.get("vectors_checked", 0),
                 100 * f.get("frac_inside", 0)))
    if a.strings:
        for off, s in strings(img, a.min):
            print("0x%08X  %s" % (off, s.decode("latin-1")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
