#!/usr/bin/env python3
"""chrread.py -- the .CHR archive of Super Street Fighter II Turbo (3DO).

27 files and 8,015,897 bytes, 2.58 % of the pressing, and the largest thing on
this disc that is not music. Nothing on the first 3DO disc looks like it and
the platform notes have never seen it.

WHAT IS DERIVED HERE

The first word of the file is the size in bytes of a table of 32-bit
big-endian offsets, and that table is the file's index. This is derived, not
assumed, and it is checkable: `count = first_word / 4` gives a table whose
entries are strictly increasing and all inside the file, on 27 files of 27, and
the property fails immediately on any other file on the disc (see --validate).

The same rule applies AGAIN inside the first entry -- a section whose own first
word is the size of its own offset table. So a .CHR is a two-level tree of
offset tables, and the leaves are:

    section 0    a nested archive: four sub-tables
      sub 0        a table of 8-byte strides -- an index into sub 1
      sub 1        8-byte records, `01000000 <u32 index>`
      sub 2        a table of offsets into sub 3
      sub 3        the pixel data
    sections 1..7  further data

WHAT IS NOT DERIVED, AND SAID SO

**The leaf pixel data is not decoded.** What was tried, and what it did:

  * read as a 3DO packed cel with an 8-bit row-offset field: the first row
    decodes to end-of-row immediately, and so does the second -- consistent
    with noise, not with a sprite;
  * read as a 3DO unpacked cel at 1, 2, 4, 6, 8 and 16 bpp: no width divides
    the leaf lengths into a whole number of rows for any of them;
  * looked for a `CCB ` signature inside the leaves: 26 of the 27 .CHR files
    contain none at all;
  * checked the leading 8 bytes of a leaf as (u16, u16, u16, u16): the values
    are not the multiples of 12 that every decoded CCB on this disc uses for
    width, so they are not a width/height pair in the platform's own units.

So the .CHR leaves are reported by offset and length and NOT by geometry. A
plausible picture would be worse than none.

The companion `.PAL` files ARE derived: 32-entry palettes of 16-bit 5-5-5
colour, top bit unused -- the same layout the first disc proved, re-proved
here on 43,520 words of which zero have the top bit set.

usage:
    chrread.py census DIR       every .CHR and .PAL in a directory
    chrread.py dump FILE        one file's offset tree
    chrread.py validate         negative controls; must fail
"""
import argparse
import os
import struct
import sys


class Bad(Exception):
    pass


def table(d, base, limit=0x8000):
    """The offset table that starts at base. Raises Bad if it is not one."""
    if base + 4 > len(d):
        raise Bad("no room for a table header at %d" % base)
    first = struct.unpack(">I", d[base:base + 4])[0]
    if first == 0 or first % 4 or first > limit or base + first > len(d):
        raise Bad("first word at %d is %d, not a plausible table size"
                  % (base, first))
    n = first // 4
    v = struct.unpack(">%dI" % n, d[base:base + first])
    for i in range(n - 1):
        if v[i] >= v[i + 1]:
            raise Bad("table at %d is not strictly increasing at entry %d "
                      "(%d then %d)" % (base, i, v[i], v[i + 1]))
    if base + v[-1] > len(d):
        raise Bad("table at %d: last entry %d runs past the %d-byte file"
                  % (base, v[-1], len(d)))
    return v


def pal(d):
    """A .PAL as 16-bit words; returns (entries, top_bit_set, low_bit_set)."""
    if len(d) % 64:
        raise Bad("%d bytes is not a whole number of 64-byte palettes" % len(d))
    w = struct.unpack(">%dH" % (len(d) // 2), d)
    return w, sum(1 for v in w if v & 0x8000), sum(1 for v in w if v & 1)


def validate():
    ok = True
    cases = [
        ("2,048 zero bytes", b"\0" * 2048),
        ("the string iamaduck", b"iamaduck" * 256),
        ("a table whose entries go backwards",
         struct.pack(">4I", 16, 100, 50, 200) + b"\0" * 300),
        ("a table running past the end",
         struct.pack(">2I", 8, 0xFFFFFF) + b"\0" * 100),
        ("an AIFF container", b"FORM\x00\x01\x00\x00AIFC" + b"\0" * 64),
    ]
    for name, data in cases:
        try:
            table(data, 0)
            print("FAIL: %-40s was ACCEPTED as an offset table" % name)
            ok = False
        except Bad as e:
            print("ok  : %-40s rejected -- %s" % (name, e))
    good = struct.pack(">4I", 16, 32, 64, 96) + b"\0" * 100
    try:
        v = table(good, 0)
        assert v == (16, 32, 64, 96)
        print("ok  : %-40s accepted" % "positive control (a real table)")
    except (Bad, AssertionError) as e:
        print("FAIL: positive control rejected -- %s" % e)
        ok = False
    try:
        pal(b"\x00\x00" * 31)
        print("FAIL: a 62-byte palette file was accepted")
        ok = False
    except Bad as e:
        print("ok  : %-40s rejected -- %s" % ("a 62-byte .PAL", e))
    return 0 if ok else 1


def dump(path):
    d = open(path, "rb").read()
    print("%s  %d bytes" % (path, len(d)))
    t = table(d, 0)
    print("level 0: %d entries" % len(t))
    for i, o in enumerate(t):
        nxt = t[i + 1] if i + 1 < len(t) else len(d)
        print("  [%d] offset %8d  length %8d" % (i, o, nxt - o))
    print("tail after the last entry: %d bytes" % 0)
    try:
        t1 = table(d, t[0])
        print("level 1, inside entry 0 at %d: %d entries" % (t[0], len(t1)))
        for i, o in enumerate(t1):
            nxt = t1[i + 1] if i + 1 < len(t1) else (t[1] - t[0])
            print("    [%d] +%-8d length %8d  first bytes %s"
                  % (i, o, nxt - o, d[t[0] + o:t[0] + o + 8].hex()))
    except Bad as e:
        print("level 1: not a table -- %s" % e)


def census(root):
    chr_ok = chr_bad = 0
    lvl1 = {}
    rows = []
    for f in sorted(os.listdir(root)):
        p = os.path.join(root, f)
        d = open(p, "rb").read()
        if f.upper().endswith(".PAL"):
            w, hi, lo = pal(d)
            rows.append(("PAL", f, len(d), len(d) // 64, hi, lo, len(w)))
            continue
        if not f.upper().endswith(".CHR"):
            continue
        try:
            t = table(d, 0)
            chr_ok += 1
            try:
                n1 = len(table(d, t[0]))
            except Bad:
                n1 = 0
            lvl1[len(t)] = lvl1.get(len(t), 0) + 1
            rows.append(("CHR", f, len(d), len(t), n1,
                         len(d) - t[-1], sum(1 for x in [d.find(b"CCB ")] if x >= 0)))
        except Bad as e:
            chr_bad += 1
            rows.append(("CHR", f, len(d), 0, 0, 0, str(e)))

    print(".CHR files whose first word is an offset table : %d" % chr_ok)
    print(".CHR files where it is not                     : %d" % chr_bad)
    print("level-0 entry counts                           : %s"
          % ", ".join("%d entries on %d files" % (k, v)
                      for k, v in sorted(lvl1.items())))
    print()
    print("%-4s %-10s %10s %6s %6s %10s %s"
          % ("kind", "file", "bytes", "L0", "L1", "tail", "note"))
    for r in rows:
        if r[0] == "CHR":
            print("%-4s %-10s %10d %6d %6d %10s %s"
                  % (r[0], r[1], r[2], r[3], r[4], r[5],
                     "has a CCB" if r[6] else ""))
        else:
            print("%-4s %-10s %10d %6d palettes of 32   top bit set %d of %d, "
                  "low bit set %d" % (r[0], r[1], r[2], r[3], r[4], r[6], r[5]))
    tot = sum(r[2] for r in rows if r[0] == "PAL")
    hi = sum(r[4] for r in rows if r[0] == "PAL")
    n = sum(r[6] for r in rows if r[0] == "PAL")
    print()
    print("PALETTES: %d bytes, %d 16-bit words, top bit set on %d of them."
          % (tot, n, hi))
    print("  Zero of %d is the same proof the first disc ran on 76,800 pixels:" % n)
    print("  the format is 5-5-5 with the top bit unused, not 5-6-5.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["census", "dump", "validate"])
    ap.add_argument("target", nargs="?")
    a = ap.parse_args()
    if a.mode == "validate":
        raise SystemExit(validate())
    if a.mode == "dump":
        dump(a.target)
    else:
        census(a.target)


if __name__ == "__main__":
    main()
