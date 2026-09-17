#!/usr/bin/env python3
"""buildroot.py -- how many times the studio's own source tree is inside the
shipped executable, and how many distinct paths that is.

WHY THIS IS A FILE AND NOT A COMMAND
------------------------------------
Rule 0 of this pipeline: `Write` or `Edit`, never a shell heredoc, for anything
containing a backslash. It has now been broken six times in this collection
and the symptom is always the same -- **a regular expression matching
`<letter>:\\<folder>` returns zero from inside a heredoc and the right answer
from a file**. Previous sessions got 0 against 70 and 0 against 147.

This session broke it twice. The second time produced

    NUL-terminated strings starting with the root : 0, distinct 0

on a file in which a plain substring count returns **28,360**. The measurement
is in a file now, and the file is the reason the number below can be trusted.

    python tools/buildroot.py
    python tools/buildroot.py --selftest
"""
import argparse
import collections
import os
import re
import sys

ROOT = "karmaflow-steam"
EXE = os.path.join("Binaries", "Win64", "KFGame.exe")

# A NUL-terminated ANSI path beginning with a drive letter.
PATH = re.compile(rb"[A-Za-z]:\\[^\x00\r\n]{4,240}")


def safe(s):
    """Printable only. Some 'paths' in an 83-megabyte binary are two bytes of
    texture after a drive letter, and printing them raw puts control bytes into
    notes/ where `toolscan.py` refuses them."""
    return "".join(c if 32 <= ord(c) < 127 else "\\x%02x" % ord(c) for c in s)


def census(data, root_needle):
    """Every NUL-terminated drive-letter path, and the subset under `root`."""
    all_paths = []
    for m in PATH.finditer(data):
        all_paths.append(m.group().decode("latin-1"))
    mine = [p for p in all_paths if p.lower().startswith(root_needle)]
    return all_paths, mine


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--file", default=EXE)
    ap.add_argument("--needle", default="d:\\basecamp games\\")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    p = os.path.join(a.root, a.file)
    data = open(p, "rb").read()
    print("file    : %s   %d bytes" % (a.file.replace("\\", "/"), len(data)))
    print()
    print("plain substring counts, which need no regular expression:")
    for s in (b"basecamp games", b"basecamp", b"karmaflow", b"UnrealEd",
              b"Array.h"):
        print("   %-18s %8d" % (s.decode(), data.lower().count(s.lower())))
    print()
    allp, mine = census(data, a.needle.lower())
    print("drive-letter paths, NUL-terminated : %d, distinct %d"
          % (len(allp), len(set(allp))))
    print("of those under %-18s : %d, distinct %d case-folded, %d as written"
          % (a.needle, len(mine), len(set(p.lower() for p in mine)),
             len(set(mine))))
    print()
    c = collections.Counter(p.lower() for p in mine)
    print("the twelve commonest:")
    for k, v in c.most_common(12):
        print("   x%-6d %s" % (v, safe(k)))
    print()
    tails = collections.Counter()
    for k, v in c.items():
        parts = k.rstrip("\\").split("\\")
        tails["\\".join(parts[:-1])] += v
    print("by directory, the ten commonest:")
    for k, v in tails.most_common(10):
        print("   x%-6d %s" % (v, safe(k)))
    print()
    others = collections.Counter()
    for p in allp:
        if p.lower().startswith(a.needle.lower()):
            continue
        others[p.split("\\")[0].lower() + "\\" + p.split("\\")[1].lower()] += 1
    print("drive-letter paths NOT under the studio root, by first two "
          "components:")
    for k, v in others.most_common(12):
        print("   x%-6d %s" % (v, safe(k)))
    return 0


def selftest():
    cases = []
    blob = (b"junk\x00D:\\Basecamp Games\\Projects\\a.h\x00more\x00"
            b"d:\\basecamp games\\projects\\b.h\x00"
            b"R:\\sw\\physx\\c.h\x00")
    allp, mine = census(blob, "d:\\basecamp games\\")
    cases.append(("three paths found", len(allp) == 3))
    cases.append(("two of them under the root", len(mine) == 2))
    cases.append(("case does not matter for the root test",
                  sorted(x.lower()[:4] for x in mine) == ["d:\\b", "d:\\b"]))
    cases.append(("a path with no drive letter is not matched",
                  census(b"\\\\server\\share\\x.h\x00", "d:")[0] == []))
    cases.append(("a NUL ends a path",
                  census(b"C:\\aaaa\x00bbbb\x00", "c:")[0]
                  == ["C:\\aaaa"]))
    cases.append(("a three-character path is too short to match",
                  census(b"C:\\ab\x00", "c:")[0] == []))
    ok = sum(1 for _n, v in cases if v)
    print("buildroot selftest: %d specimens built in memory" % len(cases))
    for n, v in cases:
        print("  %-52s %s" % (n, "PASS" if v else "FAIL"))
    print()
    print("%d of %d behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
