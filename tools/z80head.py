#!/usr/bin/env python3
"""z80head.py -- decode the first instructions of a candidate Z80 image.

Not a full disassembler. It decodes exactly the opcodes a sound-driver entry
sequence uses, and refuses to guess at anything else -- the point is to say
"this is a Z80 reset sequence" or "this is not", with the decode printed so a
reader can check it by hand.

Usage:
    z80head.py FILE [FILE...] [--offset N] [--n N] [--banner]
"""
import argparse
import re
import sys

# opcode -> (length, text). Only what a reset/entry sequence needs.
ONE = {
    0x00: "NOP", 0xF3: "DI", 0xFB: "EI", 0x76: "HALT",
    0xC9: "RET", 0xE9: "JP (HL)", 0xAF: "XOR A", 0x37: "SCF",
    0xD9: "EXX", 0x08: "EX AF,AF'",
}
ED = {0x56: "IM 1", 0x46: "IM 0", 0x5E: "IM 2", 0x47: "LD I,A", 0xB0: "LDIR"}


def decode(b, i, limit):
    """Return (length, text) or (None, None) if we refuse to guess."""
    op = b[i]
    if op in ONE:
        return 1, ONE[op]
    if op == 0xED and i + 1 < limit:
        sub = b[i + 1]
        if sub in ED:
            return 2, ED[sub]
        return 2, "ED %02X (not decoded)" % sub
    if op == 0xC3 and i + 2 < limit:
        return 3, "JP 0x%04X" % (b[i + 1] | (b[i + 2] << 8))
    if op == 0xCD and i + 2 < limit:
        return 3, "CALL 0x%04X" % (b[i + 1] | (b[i + 2] << 8))
    if op == 0x31 and i + 2 < limit:
        return 3, "LD SP,0x%04X" % (b[i + 1] | (b[i + 2] << 8))
    if op == 0x21 and i + 2 < limit:
        return 3, "LD HL,0x%04X" % (b[i + 1] | (b[i + 2] << 8))
    if op == 0x3E and i + 1 < limit:
        return 2, "LD A,0x%02X" % b[i + 1]
    if op == 0x32 and i + 2 < limit:
        return 3, "LD (0x%04X),A" % (b[i + 1] | (b[i + 2] << 8))
    if op == 0xD3 and i + 1 < limit:
        return 2, "OUT (0x%02X),A" % b[i + 1]
    return None, None


BANNER = re.compile(rb"[\x20-\x7e]{8,}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offset", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--n", type=int, default=6)
    ap.add_argument("--banner", action="store_true")
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0)
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()

    for path in a.files:
        with open(path, "rb") as fh:
            data = fh.read()
        blob = data[a.offset:a.offset + a.size] if a.size else data[a.offset:]
        print("%s (%d bytes from 0x%X)" % (path, len(blob), a.offset))
        i = 0
        decoded = 0
        for _ in range(a.n):
            ln, txt = decode(blob, i, len(blob))
            if ln is None:
                print("  +0x%04X  %02X  <refusing to decode>" % (i, blob[i]))
                break
            print("  +0x%04X  %-8s %s"
                  % (i, blob[i:i + ln].hex(), txt))
            i += ln
            decoded += 1
        print("  decoded %d instructions cleanly" % decoded)
        if a.banner:
            hits = [(m.start(), m.group()) for m in BANNER.finditer(blob[:0x400])]
            for off, s in hits[:8]:
                print("  banner +0x%04X  %r" % (off, s.decode("latin-1")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
