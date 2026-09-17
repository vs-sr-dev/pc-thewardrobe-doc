#!/usr/bin/env python3
"""Open `SAMNMAX.RSC`, the shell's resource file, and check it closes.

`SAM.EXE` is the menu program: the highway screen that offers the game, the
demos, the sound setup and the four Red Book tracks. Its data is one 745,041
byte file, and the file is not encrypted and not chunked -- it is a directory
of nine entries followed by nine payloads.

The layout, derived by arithmetic and then tested:

    +0   u32 LE   entry count, 9
    then, per entry:
      ...      a byte 0x04 introduces the entry
      11       the name in MS-DOS FCB form, `LECLOGO2FLC`, NUL-terminated
      u16      an index
      7        seven bytes identical in every entry
      u32      a field that varies
      u32      the payload SIZE
      n        the name again in ordinary form, `LECLOGO2.FLC`, NUL-terminated

    then the nine payloads, in directory order, back to back.

The test that fixes it, and the only reason to believe any of the above: the
nine sizes are 469,992 + 14,320 + 11,382 + 11,622 + 72,353 + 70,414 + 46,736
+ 38,625 + 9,172 = **744,616**, the directory ends at byte **425**, and
425 + 744,616 = **745,041**, which is the file. Nothing was fitted to make
that happen; if the size field had been the wrong u32 the sum would have been
nonsense. The tool prints the sum and the residue and refuses to call it
closed unless the residue is zero.

What is in it is the interesting part, and it is why this file has a tool:
`README.TXT` is one of the nine payloads, 9,172 bytes, the same length as the
two loose copies. The disc therefore carries the Italian readme **three**
times -- in the root, in `SAMNMAX/`, and inside this archive -- and only two
of the three are visible to a SHA-1 census of files.

Usage:
  python tools/rsc.py <SAMNMAX.RSC> [--extract dir]
"""
import hashlib
import os
import sys


def entries(d):
    n = int.from_bytes(d[0:4], "little")
    p = 4
    out = []
    for _ in range(n):
        # find the 0x04 that precedes the FCB name
        while p < len(d) and d[p] != 0x04:
            p += 1
        p += 1
        fcb = d[p:p + 11].decode("latin-1")
        p += 12                     # 11 + NUL
        idx = int.from_bytes(d[p:p + 2], "little")
        p += 2 + 7                  # index + the seven constant bytes
        var = int.from_bytes(d[p:p + 4], "little")
        p += 4
        size = int.from_bytes(d[p:p + 4], "little")
        p += 4
        e = d.index(b"\0", p)
        name = d[p:e].decode("latin-1")
        p = e + 1
        out.append((fcb, name, idx, var, size))
    # Two bytes follow the last long name before the first payload. They are
    # not guessed away: with them the nine sizes plus the directory come to
    # 745,041 exactly and every payload begins on its own magic (0xAF11/0xAF12
    # for the four animations, `Creative Voice File` for the four samples);
    # without them every payload is short by two and none of the magics land.
    return out, n, p + 2


def main(argv):
    extract = None
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--extract":
            extract = argv[i + 1]; i += 2
        else:
            rest.append(argv[i]); i += 1
    d = open(rest[0], "rb").read()
    es, n, dirend = entries(d)
    print("%s  %d bytes, %d entries declared, directory ends at %d"
          % (os.path.basename(rest[0]), len(d), n, dirend))
    print("%-13s %-14s %6s %10s %10s %10s"
          % ("fcb name", "name", "index", "size", "start", "end"))
    pos = dirend
    total = 0
    for fcb, name, idx, var, size in es:
        print("%-13s %-14s %6d %10d %10d %10d"
              % (fcb, name, idx, size, pos, pos + size))
        pos += size
        total += size
    print()
    print("sizes sum to     %d" % total)
    print("directory        %d" % dirend)
    print("sum + directory  %d" % (total + dirend))
    print("file             %d" % len(d))
    print()
    print("%s" % ("CLOSES EXACTLY" if total + dirend == len(d)
                  else "RESIDUE %d -- the layout above is wrong"
                  % (len(d) - total - dirend)))
    print()
    pos = dirend
    for fcb, name, idx, var, size in es:
        body = d[pos:pos + size]
        h = hashlib.sha1(body).hexdigest()
        print("  %-14s %8d  sha1 %s  %r" % (name, size, h, body[:12]))
        if extract:
            os.makedirs(extract, exist_ok=True)
            open(os.path.join(extract, name), "wb").write(body)
        pos += size


if __name__ == "__main__":
    main(sys.argv[1:])
