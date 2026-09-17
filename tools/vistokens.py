#!/usr/bin/env python3
"""vistokens.py -- ask a disc what it knows about the machine it is on.

The Tandy/Memorex VIS platform notes list a set of tokens that identify a
title as VIS-aware: the platform's own names, its ROM shell, the DLLs a
Modular Windows title must statically import, and the port and address
constants the homebrew work measured.  This tool counts them across every
file of a disc, case-insensitively, in ASCII and in UTF-16LE, and prints
which FILES matched rather than only how many hits there were.

That last part is the point.  A scan that fires is a scan to read by hand:
the previous session in this collection got eight hits on a project name and
all eight were inside the hexadecimal offset column its own dumper had
printed.  So this tool reports file names and offsets, never a bare count.

The byte constants are searched as little-endian 16-bit immediates preceded
by the x86 opcodes that would load them, not as bare byte pairs -- `0x388`
appears by chance roughly once per 65,536 bytes and a 445 MB disc would show
about 6,800 accidental hits.  Encoding the opcode is what makes the search a
measurement instead of a coin toss.
"""

import argparse
import os
import re
import sys

# Names the platform notes use, plus the ones a Win16 title would carry.
NAME_TOKENS = [
    "Tandy", "VIS", "Video Information System", "tlaunch", "MODULAR",
    "Modular Windows", "HC.DLL", "DISPDIB", "DispDib", "MMSYSTEM",
    "WIN.INI", "SYSTEM.INI", "WINDOWS", "KERNEL", "USER.EXE", "GDI",
    "EnterDVA", "DVA", "minwin", "Maketat", "hcGetCursorPos",
    "StretchDIBits", "WIN87EM", "waveOut", "timeGetTime",
]

# x86 immediate loads of the constants the notes list.  Each entry is
# (label, list of byte patterns, why this pattern and not the bare value).
def imm_patterns(value, label, note):
    lo = value & 0xFF
    hi = (value >> 8) & 0xFF
    pats = [
        (bytes([0xB8, lo, hi]), "mov ax,imm16"),
        (bytes([0xBA, lo, hi]), "mov dx,imm16"),
        (bytes([0xBB, lo, hi]), "mov bx,imm16"),
        (bytes([0xB9, lo, hi]), "mov cx,imm16"),
        (bytes([0x81, 0xFA, lo, hi]), "cmp dx,imm16"),
    ]
    return label, pats, note


CONSTANTS = [
    imm_patterns(0x388, "OPL3 index port 0x388",
                 "the notes' FM path; a title that writes FM music loads it"),
    imm_patterns(0x389, "OPL3 data port 0x389", "the FM data port"),
    imm_patterns(0x220, "DAC / Sound Blaster base 0x220",
                 "the VIS PCM DAC lives here and so does a Sound Blaster"),
    imm_patterns(0xA000, "VGA frame buffer segment 0xA000",
                 "a mode 13h program loads this into a segment register"),
]

# Interrupt calls, as opcodes.
INTS = [
    (b"\xcd\x10", "INT 10h  BIOS video"),
    (b"\xcd\x33", "INT 33h  DOS mouse driver"),
    (b"\xcd\x21", "INT 21h  DOS kernel"),
    (b"\xcd\x13", "INT 13h  BIOS disk"),
    (b"\xcd\x2f", "INT 2Fh  multiplex"),
]

# Specific mode-set sequences.  Mode 13h through the BIOS is the signature of
# an ordinary DOS VGA program; anything else is machine-specific.
MODESETS = [
    (b"\xb8\x13\x00\xcd\x10", "mov ax,0013h / int 10h  -- VGA mode 13h"),
    (b"\xb0\x13\xb4\x00\xcd\x10", "mov al,13h / mov ah,0 / int 10h"),
    (b"\xb8\x12\x00\xcd\x10", "mov ax,0012h / int 10h  -- VGA 640x480x4"),
    (b"\xb8\x03\x00\xcd\x10", "mov ax,0003h / int 10h  -- text 80x25"),
]


def walk(root):
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            yield os.path.join(dp, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--code", action="store_true")
    ap.add_argument("--max-show", type=int, default=6)
    a = ap.parse_args()
    if not (a.names or a.code):
        a.names = a.code = True

    files = [p for p in walk(a.root)]
    total = sum(os.path.getsize(p) for p in files)
    print("files scanned : %d" % len(files))
    print("bytes scanned : %d" % total)
    print()

    if a.names:
        print("=== NAME TOKENS (case-insensitive, ASCII and UTF-16LE) ===")
        print("%-26s %6s  %s" % ("token", "hits", "files"))
        for t in NAME_TOKENS:
            hits = 0
            where = []
            pats = [t.encode("ascii", "ignore"),
                    t.encode("utf-16-le")]
            for p in files:
                b = open(p, "rb").read()
                low = b.lower()
                n = 0
                for pat in pats:
                    if not pat:
                        continue
                    n += len(re.findall(re.escape(pat.lower()), low))
                if n:
                    hits += n
                    where.append("%s@%d" % (os.path.relpath(p, a.root), n))
            print("%-26s %6d  %s" % (t, hits, ", ".join(where[:a.max_show])
                                     + (" ..." if len(where) > a.max_show
                                        else "")))
        print()

    if a.code:
        print("=== x86 CODE PATTERNS ===")
        for label, pats, note in CONSTANTS:
            rows = []
            for pat, how in pats:
                for p in files:
                    b = open(p, "rb").read()
                    for m in re.finditer(re.escape(pat), b):
                        rows.append((os.path.relpath(p, a.root), m.start(),
                                     how))
            print("%-34s %3d hits   (%s)" % (label, len(rows), note))
            for r in rows[:a.max_show]:
                print("        %-16s +0x%06X  %s" % r)
            if len(rows) > a.max_show:
                print("        ... %d more" % (len(rows) - a.max_show))
        print()
        print("%-34s %s" % ("interrupt", "hits"))
        for pat, label in INTS:
            rows = []
            for p in files:
                b = open(p, "rb").read()
                c = len(re.findall(re.escape(pat), b))
                if c:
                    rows.append("%s@%d" % (os.path.relpath(p, a.root), c))
            print("%-34s %s" % (label, ", ".join(rows[:a.max_show]) or "0"))
        print()
        print("=== MODE-SET SEQUENCES ===")
        for pat, label in MODESETS:
            rows = []
            for p in files:
                b = open(p, "rb").read()
                for m in re.finditer(re.escape(pat), b):
                    rows.append("%s+0x%X" % (os.path.relpath(p, a.root),
                                             m.start()))
            print("%-46s %s" % (label, ", ".join(rows[:a.max_show]) or "none"))


if __name__ == "__main__":
    main()
