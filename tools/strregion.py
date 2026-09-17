"""strregion.py -- print the NUL-separated strings in a byte range of a file,
and pull out drive-lettered paths, so that a string found by a count can be
read in the company it keeps.

A string index tells you a name is present. It does not tell you that the name
sits between an Italian error message and a URL, which is the kind of thing
that decides what the name means.

Usage:
    python tools/strregion.py FILE --range 453000:454500
    python tools/strregion.py FILE --paths
    python tools/strregion.py FILE --grep MODELLI --window 200
"""

import re
import sys

DRIVE = re.compile(rb"[A-Za-z]:[\\/][A-Za-z0-9_.\\/ -]{2,80}")
PRINTABLE = re.compile(rb"[\x20-\x7E\xA0-\xFF]{4,}")


def strings_in(data, lo, hi):
    out = []
    for m in PRINTABLE.finditer(data, lo, hi):
        out.append((m.start(), m.group(0).decode("latin-1")))
    return out


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    with open(argv[1], "rb") as fh:
        data = fh.read()

    if "--paths" in argv:
        seen = {}
        for m in DRIVE.finditer(data):
            s = m.group(0).decode("latin-1")
            seen.setdefault(s, []).append(m.start())
        print("file                    : %s (%d bytes)" % (argv[1], len(data)))
        print("distinct drive-lettered : %d" % len(seen))
        print("total occurrences       : %d" % sum(len(v) for v in seen.values()))
        for s in sorted(seen):
            print("  %-52s x%-4d first at %d" % (s, len(seen[s]), seen[s][0]))
        return 0

    if "--grep" in argv:
        needle = argv[argv.index("--grep") + 1].encode("latin-1")
        win = int(argv[argv.index("--window") + 1]) if "--window" in argv else 120
        n = 0
        pos = data.find(needle)
        while pos != -1:
            n += 1
            lo, hi = max(0, pos - win), min(len(data), pos + win)
            print("--- occurrence %d at offset %d" % (n, pos))
            for off, s in strings_in(data, lo, hi):
                print("    %-8d %s" % (off, s))
            pos = data.find(needle, pos + 1)
        if n == 0:
            print("(needle %r not present -- this is a measurement, not a failure)" % needle)
        return 0

    if "--range" in argv:
        lo, hi = (int(x) for x in argv[argv.index("--range") + 1].split(":"))
        for off, s in strings_in(data, lo, min(hi, len(data))):
            print("%-8d %s" % (off, s))
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
