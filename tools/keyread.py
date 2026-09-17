#!/usr/bin/env python3
"""keyread.py -- the ten .KEY files are the game's dialogue, XOR-obfuscated.

The .KEY are the highest-entropy data in the object (mean 4.9112, against
4.7457 for the pictures and 2.4114 for the screens) and the only files that
looked like nothing. They are text.

HOW IT WAS FOUND. Not by guessing. A single-byte XOR, a single-byte add and a
single-byte subtract were tried at all 256 keys, then the same three after bit
reversal, nibble swap, complement and all seven rotations -- 2,304 candidate
transforms -- and each result was scored on the fraction of printable bytes.
Ninety-six candidates cleared 85 %. They were then scored again on whether
common Italian function words appeared, and exactly one reading produced
`Pronto Cactus? Sono io...`.

    the transform is XOR, and the key is byte 0 of the file itself.

Six files begin 0xCB and four begin 0xDA, and each is its own key. The header
is four bytes; the text starts at byte 4. Nothing else is needed.

THE CHARACTER SET IS NOT ASCII, QUITE. Two substitutions run through every
file and both have the same cause -- the font. `SMAN5/FNT/*.CHV` declares its
first glyph at 0x21 and its last at 0x7A, so **space (0x20) has no glyph** and
the text writes `_` for it, 2,158 times against 3 real spaces. Comma is
written `$`. Accented vowels are plain CP437 -- 0x85 0x8A 0x8D 0x95 0x97, the
DOS code page's own a e i o u grave -- 110 of them, and `SMAN5/FNT/GENE.CHV`
declares its last glyph at 0x97, which is where the Italian language stops.

That is the opposite decision from the other Simulmondo game in this
collection. *1000 Miglia* has "not one accented character in 1,588,227 bytes"
and writes `e'` for `è` throughout (its `docs/21-leftovers.md`). A year later
the same studio drew the accents into the font and shipped them as one byte
each.

    python tools/keyread.py <objectroot> [--dump <outdir>]

--dump writes the decoded dialogue outside the repository. It is not committed:
this repository publishes measurements, not the game's script.
"""
import os
import re
import struct
import sys
from collections import Counter

PRINTABLE = set(range(0x20, 0x7F))

# CP437, the DOS code page, at the five positions Italian uses.
CP437 = {0x85: "a-grave", 0x8A: "e-grave", 0x8D: "i-grave",
         0x95: "o-grave", 0x97: "u-grave"}

# The words that separated the true reading from the ninety-five near misses.
# `_` is the separator because the font has no space; see the docstring.
WORDS = [b"_DI_", b"_IL_", b"_LA_", b"_CHE_", b"_NON_", b"_UN_",
         b"PER_", b"_CON_", b"ARE_", b"_SONO_", b"_QUALCOSA"]


def decode(d):
    """XOR the body with byte 0. Returns (key, plaintext)."""
    assert len(d) > 4, "a .KEY shorter than its own header"
    k = d[0]
    return k, bytes(b ^ k for b in d[4:])


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    outdir = None
    if "--dump" in sys.argv:
        outdir = sys.argv[sys.argv.index("--dump") + 1]
        os.makedirs(outdir, exist_ok=True)
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

    names = []
    for dp, _dd, ff in os.walk(root):
        for n in sorted(ff):
            if n.upper().endswith(".KEY"):
                names.append(os.path.relpath(os.path.join(dp, n), root)
                             .replace(os.sep, "/"))
    names.sort()
    assert names, "no .KEY under %r" % root

    print("=== validate on something that must fail ===")
    print("  Printability is the WRONG test here and saying so is the point.")
    print("  0xCB and 0xCC differ in one low bit, so decoding with the key")
    print("  next door leaves the printable fraction untouched -- 96 of 2,304")
    print("  candidate transforms cleared 85 %% printable and 95 of them were")
    print("  nonsense. What separates the reading from its neighbours is")
    print("  whether Italian words come out.")
    d = open(os.path.join(root, names[0]), "rb").read()
    _k, good = decode(d)
    for off in (0, 1, 0x80):
        t = bytes(b ^ ((d[0] + off) & 0xFF) for b in d[4:])
        pr = sum(1 for c in t if c in PRINTABLE) / len(t)
        w = sum(t.upper().count(x) for x in WORDS)
        print("  key 0x%02X  printable %.4f   Italian words %2d %s"
              % ((d[0] + off) & 0xFF, pr, w, "<- the file's own byte 0" if not off else ""))
    base = sum(good.upper().count(x) for x in WORDS)
    near = sum(bytes(b ^ ((d[0] + 1) & 0xFF)
                     for b in d[4:]).upper().count(x) for x in WORDS)
    assert base > 0 and near == 0, \
        "the word test no longer separates the key from its neighbour"
    print("")

    print("=== the ten dialogue files ===")
    print("  %-24s %6s %5s %9s %9s" % ("file", "bytes", "key", "printable", "%"))
    tot = 0
    high = Counter()
    allkeys = Counter()
    for f in names:
        d = open(os.path.join(root, f), "rb").read()
        k, t = decode(d)
        allkeys[k] += 1
        pr = sum(1 for c in t if c in PRINTABLE)
        tot += len(d)
        # Only the five CP437 vowels count as accents. A first attempt
        # counted every byte above 0x7E and put 0xCB and 0xDA at the top of
        # the list, which are not letters at all: they are the record
        # separators, 0x00 XORed with the file's own key.
        high.update(c for c in t if c in CP437)
        print("  %-24s %6d  0x%02X %9d %8.2f %%"
              % (f, len(d), k, pr, 100.0 * pr / len(t)))
        line = re.sub(rb"[^\x20-\x7e]", b".", t[:78]).decode()
        print("      %s" % line)
    print("  total %d bytes, keys used: %s"
          % (tot, ", ".join("0x%02X x%d" % (k, c) for k, c in sorted(allkeys.items()))))
    print("")

    print("=== the accented letters, and where the font stops ===")
    acc = Counter()
    for f in names:
        d = open(os.path.join(root, f), "rb").read()
        _k, t = decode(d)
        acc.update(c for c in t if c in CP437)
    print("  The five bytes below are CP437, the DOS code page, at its own")
    print("  positions for the vowels Italian needs:")
    for v, c in sorted(acc.items()):
        print("    0x%02X  %-2s x%d" % (v, CP437[v], c))
    print("  total: %d accented letters in %d bytes of dialogue"
          % (sum(acc.values()), tot))
    assert sum(acc.values()) > 0, "no accented letters -- the reading is wrong"
    print("")
    print("  And the font stops exactly where the language does. The .CHV")
    print("  header is (first glyph, last glyph):")
    for dp, _dd, ff in os.walk(root):
        for n in sorted(ff):
            if n.upper().endswith(".CHV"):
                p = os.path.join(dp, n)
                c = open(p, "rb").read()
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                nglyph = c[1] - c[0] + 1
                first4 = struct.unpack("<I", c[5:9])[0]
                print("    %-24s 0x%02X..0x%02X = %3d glyphs   offset[0]=%4d = 4n:%s %s"
                      % (rel, c[0], c[1], nglyph, first4, first4 == 4 * nglyph,
                         "<- reaches %s" % CP437.get(c[1], "") if c[1] in CP437 else ""))
    print("  0x97 is CP437's u-grave. The dialogue font's last glyph is the")
    print("  last letter the Italian language asks for, and not one more.")
    print("")
    print("  *1000 Miglia*, a year earlier, has no accented character in")
    print("  1,588,227 bytes and writes e' for e-grave throughout. Same studio,")
    print("  same city, opposite decision.")
    print("")

    print("=== the two substitutions, counted ===")
    us = sp = 0
    for f in names:
        d = open(os.path.join(root, f), "rb").read()
        _k, t = decode(d)
        us += t.count(b"_")
        sp += t.count(b" ")
    print("  underscore in the plaintext : %d" % us)
    print("  space (0x20) in the plaintext: %d" % sp)
    print("  -- the font has no glyph below 0x21, so the separator had to be")
    print("     a character it could draw.")

    if outdir:
        for f in names:
            d = open(os.path.join(root, f), "rb").read()
            _k, t = decode(d)
            dst = os.path.join(outdir, os.path.basename(f).rsplit(".", 1)[0] + ".txt")
            open(dst, "wb").write(t)
        print("")
        print("=== wrote %d decoded scripts to %s ===" % (len(names), outdir))


if __name__ == "__main__":
    main()
