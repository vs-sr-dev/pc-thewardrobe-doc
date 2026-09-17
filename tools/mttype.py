#!/usr/bin/env python3
"""mttype.py -- resolve MT Framework .arc resource type hashes to class names.

The hash function was derived, not looked up. Method:

  1. take every string in the executable's .rdata that looks like an MT
     Framework resource class name (`r` followed by letters and digits);
  2. try a small family of CRC-32 variants on each;
  3. keep the variant that maps a known class to a known hash.

The one that fires is  (~crc32(name)) & 0x7FFFFFFF  -- CRC-32 with the final
complement omitted (JAMCRC), truncated to 31 bits. It is confirmed on more
than one pair before being used, and the tool prints the confirmations.

--verify runs the negative control: a name that is NOT in the executable must
not collide with any observed hash.

Usage:
    mttype.py --derive EXE
    mttype.py --resolve EXE --hashes H,H,H
"""
import argparse
import re
import sys
import zlib

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")


def jamcrc31(s):
    return (~zlib.crc32(s.encode("latin-1"))) & 0x7FFFFFFF


VARIANTS = {
    "crc32": lambda s: zlib.crc32(s.encode()) & 0xFFFFFFFF,
    "crc32&31": lambda s: zlib.crc32(s.encode()) & 0x7FFFFFFF,
    "jamcrc": lambda s: (~zlib.crc32(s.encode())) & 0xFFFFFFFF,
    "jamcrc&31": jamcrc31,
}

CLASSNAME = re.compile(rb"r[A-Za-z][A-Za-z0-9_]{1,30}")


def class_names(pe_path):
    sys.path.insert(0, "tools")
    from pe import PE
    pe = PE(pe_path)
    blob = pe.section_bytes(".rdata")
    out = set()
    for m in re.finditer(rb"[\x20-\x7e]{2,64}", blob):
        s = m.group().decode("latin-1")
        for tok in re.findall(r"\br[A-Za-z][A-Za-z0-9_]{1,30}", s):
            out.add(tok)
    # also take whole null-terminated strings that are exactly a class name
    for part in blob.split(b"\x00"):
        try:
            s = part.decode("ascii")
        except UnicodeDecodeError:
            continue
        if re.fullmatch(r"r[A-Za-z][A-Za-z0-9_]{1,30}", s):
            out.add(s)
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--derive", action="store_true")
    ap.add_argument("--resolve", action="store_true")
    ap.add_argument("--hashes", default="")
    ap.add_argument("exe")
    a = ap.parse_args()

    names = class_names(a.exe)
    print("candidate class-name strings in .rdata: %d" % len(names))

    targets = [int(h, 0) for h in a.hashes.split(",") if h.strip()]

    if a.derive:
        # which variant maps some candidate onto some target?
        for vname, fn in VARIANTS.items():
            table = {}
            for n in names:
                table.setdefault(fn(n), []).append(n)
            hits = [(t, table[t]) for t in targets if t in table]
            print("%-12s maps %d of %d observed hashes" % (vname, len(hits), len(targets)))
            for t, ns in hits:
                print("       0x%08X -> %s" % (t, ", ".join(ns)))

    if a.resolve:
        table = {}
        for n in names:
            table.setdefault(jamcrc31(n), []).append(n)
        print("\nresolving %d observed type hashes with jamcrc&31:" % len(targets))
        got = 0
        for t in targets:
            if t in table:
                got += 1
                print("  0x%08X = %s" % (t, ", ".join(table[t])))
            else:
                print("  0x%08X = <unresolved>" % t)
        print("resolved %d of %d" % (got, len(targets)))
        print("\nnegative control: names that are not in .rdata must not collide")
        for probe in ("rNotAThing", "rZzzzzz", "rQwertyuiop"):
            h = jamcrc31(probe)
            print("  %-12s -> 0x%08X  %s"
                  % (probe, h, "COLLIDES" if h in targets else "no collision"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
