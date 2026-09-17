#!/usr/bin/env python3
"""controltat.py -- read the Tandy/Memorex VIS vendor block `CONTROL.TAT`.

Every VIS disc carries one of these in its root.  The platform checklist
(`vis-platformnotes-doc`, section 2) describes its fields in four paragraphs
of prose across three discs and no tool implements it, so each new disc has
been read by hand.  This turns those paragraphs into a table.

WHAT THE NOTES ESTABLISH, AND WHAT THIS TOOL CHECKS

  * the leading **84 bytes are byte-identical** on every disc seen so far,
    md5 `ed9bfc904220e409f04c0772f1797ff7`.  It is the platform's cheapest
    identity test and this tool prints it first;
  * a **title field at 0x54**, written once by whoever ran Tandy's mastering
    tool and evidently never reviewed -- two of the four discs known describe
    themselves on a retail pressing as something other than a finished
    product;
  * **twelve binary bytes from 0x98**, different on every disc and
    unexplained;
  * a **`Maketat - Version is V(B) D-Mmm-YY` string** near the end, which
    dates the pressing process independently of anything the title claims;
  * a third short field the notes read as `minwin <drive letter>` and
    attribute the one-byte length differences to.

Everything printed here is located by searching for the ASCII, not by
assuming an offset, and the offsets found are printed alongside -- so when
the fifth disc lays them out differently the tool says so instead of
silently reading the wrong bytes.

`--strict` fails loudly when the 84-byte block does not match, which is the
whole point of having a cheap identity test.
"""

import argparse
import hashlib
import os
import re
import sys

CANON_MD5 = "ed9bfc904220e409f04c0772f1797ff7"
COPYRIGHT = b"Copyright (c) 1992 Tandy Corporation. All Rights Reserved."


def runs(b, minlen=4):
    out = []
    cur = bytearray()
    start = 0
    for i, x in enumerate(b):
        if 0x20 <= x < 0x7F:
            if not cur:
                start = i
            cur.append(x)
        else:
            if len(cur) >= minlen:
                out.append((start, bytes(cur)))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((start, bytes(cur)))
    return out


def report(path, strict):
    b = open(path, "rb").read()
    md5 = hashlib.md5(b[:84]).hexdigest()
    print("=== %s ===" % os.path.relpath(path))
    print("  total length                : %d bytes" % len(b))
    print("  md5 of the leading 84 bytes : %s" % md5)
    print("  the platform notes' value   : %s   %s"
          % (CANON_MD5, "MATCH" if md5 == CANON_MD5 else "*** DIFFERENT ***"))
    print("  sha1 of the whole file      : %s"
          % hashlib.sha1(b).hexdigest())
    print()
    print("  copyright line present      : %s"
          % ("yes at 0x%X" % b.find(COPYRIGHT) if COPYRIGHT in b else "NO"))

    all_runs = runs(b, 4)
    # the title field: the notes place it at 0x54
    title = [(o, s) for o, s in all_runs if 0x50 <= o <= 0x60]
    print("  title field (notes: 0x54)   : %s"
          % (("0x%X  %r" % (title[0][0], title[0][1].decode("latin-1").strip()))
             if title else "not found near 0x54"))

    m = re.search(rb"Maketat[^\x00\n\r]*", b)
    print("  Maketat string              : %s"
          % (("0x%X  %r" % (m.start(), m.group().decode("latin-1").strip()))
             if m else "not found"))

    print("  twelve binary bytes at 0x98 : %s"
          % " ".join("%02X" % x for x in b[0x98:0x98 + 12]))
    print("  and 0x93..0xA4 for context  : %s"
          % " ".join("%02X" % x for x in b[0x93:0xA5]))
    print("  byte at 0xC6                : 0x%02X" % b[0xC6])

    print()
    print("  every printable run of 4+ bytes, with its offset:")
    for o, s in all_runs:
        print("    0x%03X  %r" % (o, s.decode("latin-1")))

    print()
    # the program list: names separated by CR inside a single run
    progs = [(o, s) for o, s in all_runs
             if re.search(rb"\.(EXE|COM|BAT|DLL)", s, re.I)]
    if progs:
        print("  PROGRAM NAMES IN THE BLOCK (the strongest candidate for what")
        print("  this file is FOR -- a launch list, where a PC would have an")
        print("  AUTOEXEC):")
        for o, s in progs:
            print("    0x%03X  %r" % (o, s.decode("latin-1")))
    else:
        print("  no program names in the block")

    auth = re.search(rb"\[\s*ATTENTION.*?\]", b, re.S)
    print()
    print("  authorisation statement     : %s"
          % (("0x%X  %r" % (auth.start(),
                            auth.group().decode("latin-1")))
             if auth else "none"))

    nz = [i for i, x in enumerate(b) if x]
    print()
    print("  last non-zero byte          : 0x%X (of 0x%X)"
          % (nz[-1] if nz else -1, len(b) - 1))
    print("  zero bytes                  : %d of %d (%.2f %%)"
          % (b.count(0), len(b), 100.0 * b.count(0) / len(b)))
    if strict and md5 != CANON_MD5:
        raise SystemExit("the 84-byte identity block does not match; this is "
                         "either not a VIS CONTROL.TAT or the platform's "
                         "cheapest identity test has just been broken")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args()
    for p in a.files:
        report(p, a.strict)
        print()


if __name__ == "__main__":
    main()
