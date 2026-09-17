"""layoutbin.py -- read the name pool at the end of InstallShield's LAYOUT.BIN,
and cross it against the disc.

What is derived here and what is not, stated plainly:

  **derived.** The last part of the file is a pool of NUL-terminated ASCII file
  names in mixed case, one after another, with no length prefixes. Extracting
  them is a matter of splitting on NUL and keeping the runs that end in a known
  extension, and the result is checkable: every name it produces either is or is
  not a file on the disc, and the cross-reference is printed in both directions.

  **not derived.** The first ~1,900 bytes are a table of ascending 16-bit
  values in groups, separated by 8-byte records whose first word is a
  page-aligned 32-bit value (0x4000, 0x2000) and whose second is a byte length
  (2676, 344). It has the shape of a PE base-relocation directory and it is not
  one: the block sizes exceed what a 4 KB page can hold, and this is a data
  file, not an image. Three readings were tried -- relocation blocks from
  offset 0, 4 and 8 -- and none closes on the file length. It is left
  underived and said so, rather than described by the shape it resembles.

Usage:
    python tools/layoutbin.py _work/files/LAYOUT.BIN --names
    python tools/layoutbin.py _work/files/LAYOUT.BIN --cross _work/files
"""

import os
import re
import sys

KNOWN = ("bmp", "wav", "3ds", "dat", "avi", "txt", "sav", "exe", "dll", "ini",
         "inf", "tag", "lid", "ins", "ico", "ttf", "bin", "cab", "e_e", "ex_")
NAME = re.compile(rb"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,30}\.(?:%s)"
                  % "|".join(KNOWN).encode("ascii"), re.IGNORECASE)


def names(path):
    with open(path, "rb") as fh:
        data = fh.read()
    out = []
    for m in NAME.finditer(data):
        s = m.group(0).decode("ascii")
        # a name in the pool is delimited by NUL on both sides
        a, b = m.start(), m.end()
        if (a == 0 or data[a - 1] == 0) and (b >= len(data) or data[b] == 0):
            out.append((a, s))
    return data, out


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    data, found = names(argv[1])
    print("file            : %s (%d bytes)" % (argv[1], len(data)))
    print("names extracted : %d" % len(found))
    print("pool starts at  : %s" % (found[0][0] if found else "n/a"))
    print("pool ends at    : %s of %d" % (found[-1][0] + len(found[-1][1]) if found else "n/a",
                                          len(data)))
    if "--names" in argv:
        for off, s in found:
            print("  %6d  %s" % (off, s))
        return 0
    if "--cross" in argv:
        root = argv[argv.index("--cross") + 1]
        disc = {f.upper() for f in os.listdir(root) if os.path.isfile(os.path.join(root, f))}
        mine = {s.upper() for _o, s in found}
        print()
        print("names in LAYOUT.BIN               : %d" % len(mine))
        print("files in the disc root            : %d" % len(disc))
        print("in both                           : %d" % len(mine & disc))
        print("in LAYOUT.BIN but not on the disc : %d" % len(mine - disc))
        for x in sorted(mine - disc):
            print("     %s" % x)
        print("on the disc but not in LAYOUT.BIN : %d" % len(disc - mine))
        for x in sorted(disc - mine):
            print("     %s" % x)
        print()
        print("case: names as spelled in LAYOUT.BIN vs the ISO primary namespace")
        mixed = sum(1 for _o, s in found if s != s.upper())
        print("  spelled in mixed case           : %d of %d" % (mixed, len(found)))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
