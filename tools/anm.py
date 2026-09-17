#!/usr/bin/env python3
"""Open the outer layer of the other engine's animation files.

The Rebel Assault demo on this disc is a second LucasArts engine with formats
that are not SCUMM: `.ANM`, `.CHK`, `.NUT`, `.SAD`, `.BMF`, `.FNT`. This tool
opens exactly one of them, and its job is as much to say *how much is still
closed* as to report what it found.

What the bytes give without any outside knowledge:

* An `.ANM` begins `ANIM` followed by a big-endian length -- the same
  `[tag][BE length]` shape as the SCUMM container two directories away, from
  the same studio in the same year, **with the opposite inclusion rule**. In
  the SCUMM container `LECF` declares 13,789,910 on a file of 13,789,910: the
  length includes the eight header bytes. Here `ANIM` declares 40,496 on a
  file of 40,504, and the first sibling of `AHDR` sits at 8 + 8 + 774 where
  `AHDR` declared 774: the length **excludes** the header. Two chunked
  formats, one building, one year, two conventions -- and the only way to know
  which you are holding is to make the walk close.
* The first child is `AHDR`, 774 payload bytes: a 16-bit version, a 16-bit
  frame count, one more 16-bit field, and then exactly **768** bytes, which is
  a 256-entry RGB palette. 6 + 768 = 774 is the whole of it, with nothing left
  over -- which is the argument that it is a palette, not a hope.
* The rest of the file is a sequence of `FRME` chunks, one per frame.

Everything below the frame chunk -- the actual video codec -- is **not opened**
and this tool says so with a byte count, because an unopened fraction that is
measured is a result and an unopened fraction that is not mentioned is a hole.

Usage:
  python tools/anm.py <file.anm ...>
  python tools/anm.py --census <dir>
"""
import collections
import os
import sys


def be(b, o, n=4):
    return int.from_bytes(b[o:o + n], "big")


def le(b, o, n=2):
    return int.from_bytes(b[o:o + n], "little")


def walk(d):
    """Top-level chunk list of an ANM: [(tag, off, size)]."""
    out = []
    p = 8
    while p < len(d):
        if p + 8 > len(d):
            out.append(("<short tail>", p, len(d) - p))
            break
        t = d[p:p + 4].decode("latin-1")
        l = be(d, p + 4) + 8          # the length EXCLUDES the header here
        if l < 8 or p + l > len(d):
            out.append(("<bad length %d>" % (l - 8), p, len(d) - p))
            break
        out.append((t, p, l))
        p += l
    return out


def report(path):
    d = open(path, "rb").read()
    tag = d[:4].decode("latin-1")
    decl = be(d, 4)
    print("%s  %d bytes" % (os.path.basename(path), len(d)))
    print("  outer tag        %r" % tag)
    print("  declared length  %d, + 8 = %d, file = %d -> %s"
          % (decl, decl + 8, len(d),
             "CORRECT" if decl + 8 == len(d) else "MISMATCH by %d"
             % (len(d) - decl - 8)))
    cs = walk(d)
    hdr = [c for c in cs if c[0] == "AHDR"]
    frames = 0
    if hdr:
        t, o, l = hdr[0]
        b = d[o + 8:o + l]
        ver, nfr, third = le(b, 0), le(b, 2), le(b, 4)
        pal = b[6:]
        trip = {pal[i:i + 3] for i in range(0, len(pal) - 2, 3)}
        print("  AHDR             %d payload bytes" % len(b))
        print("    version        %d" % ver)
        print("    frame count    %d" % nfr)
        print("    third field    %d (0x%04X)" % (third, third))
        print("    trailing bytes %d  = %d RGB triples, %d distinct, range %d..%d"
              % (len(pal), len(pal) // 3, len(trip), min(pal), max(pal)))
        frames = nfr
    kinds = collections.Counter(c[0] for c in cs)
    body = sum(c[2] for c in cs if c[0] != "AHDR")
    print("  top-level chunks %d  %s" % (len(cs), dict(kinds)))
    print("  frame chunks     %d, declared frame count %d -> %s"
          % (kinds.get("FRME", 0), frames,
             "MATCH" if kinds.get("FRME", 0) == frames else "DIFFER"))
    tiles = sum(c[2] for c in cs) + 8 == len(d) and all(
        not c[0].startswith("<") for c in cs)
    print("  walk closes      %s" % ("EXACTLY" if tiles else "NO"))
    print("  bytes below the frame chunk header, NOT OPENED: %d = %.2f %% of"
          " the file" % (body, 100.0 * body / len(d)))
    print()
    return len(d), body


def main(argv):
    if argv and argv[0] == "--census":
        tot = closed = 0
        for f in sorted(os.listdir(argv[1])):
            if f.lower().endswith(".anm"):
                a, b = report(os.path.join(argv[1], f))
                tot += a
                closed += b
        print("TOTAL %d bytes of .ANM, %d not opened = %.2f %%"
              % (tot, closed, 100.0 * closed / tot if tot else 0))
        return
    for f in argv:
        report(f)


if __name__ == "__main__":
    main(sys.argv[1:])
