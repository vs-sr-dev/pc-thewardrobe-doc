#!/usr/bin/env python3
"""utf16sift.py -- sift.py's personal-data patterns, applied to UTF-16LE too.

`pc-heretickingdoms-doc/docs/18` left this prediction:

    P2. The next Windows-era object in this collection whose text layer is
    UTF-16 will produce a `sift.py` e-mail count that is too low by the number
    of version resources in it. The mechanism is now named and the fix is one
    `.encode('utf-16-le')` per pattern.

This object's pre-briefing said the defect **cannot fire here**, because "this
object's text is eight-bit ASCII throughout". It is not: `unins000.dat` holds
254 UTF-16LE runs of six characters or more, and among them are the machine's
host name, the account name, and the installation path -- which is the exact
class of thing `sift.py --group personal` exists to find and reported as zero.

This tool does not modify `sift.py`. It imports its pattern groups, runs each
one twice -- once as written and once with every literal byte widened to
UTF-16LE -- and prints both counts, so the size of the blind spot is a number
rather than an assertion.

    python tools/utf16sift.py <root> --group personal
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sift  # noqa: E402

# The one pattern the personal group has never had, named by five consecutive
# pre-briefings as `home dir : 0`.
EXTRA = [("drive-letter home path", rb"[A-Za-z]:\\[A-Za-z0-9_. ~-]{2,}\\",
          False)]


def widen(pat):
    """Turn a byte regex over ASCII into the same regex over UTF-16LE, by
    putting a NUL after every literal byte **and wrapping each atom in a
    non-capturing group**, so that a following quantifier still applies to the
    character and not to the NUL. Getting that wrong is silent: the first
    version of this function emitted `[A-Za-z]\\x00{2,}` and reported zero
    UTF-16 hits on a file that has 254 of them."""
    out = bytearray()
    i = 0
    while i < len(pat):
        c = pat[i:i + 1]
        if c == b"\\":
            out += b"(?:" + pat[i:i + 2] + b"\\x00)"
            i += 2
            continue
        if c == b"[":
            j = pat.index(b"]", i)
            while pat[j - 1:j] == b"\\":
                j = pat.index(b"]", j + 1)
            out += b"(?:" + pat[i:j + 1] + b"\\x00)"
            i = j + 1
            continue
        if c in b"{":
            j = pat.index(b"}", i)
            out += pat[i:j + 1]
            i = j + 1
            continue
        if c in b"+*?":
            out += c
            i += 1
            continue
        out += b"(?:" + re.escape(c) + b"\\x00)"
        i += 1
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--group", default="personal")
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()

    blobs = []
    for dp, _dn, fns in os.walk(a.root):
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            blobs.append((os.path.relpath(p, a.root), open(p, "rb").read()))
    if not blobs:
        print("REFUSED: empty population under %s" % a.root, file=sys.stderr)
        return 3

    items = sift.GROUPS[a.group] + EXTRA
    print("blobs : %d   bytes : %d" % (len(blobs),
                                       sum(len(b) for _n, b in blobs)))
    print()
    print("%-28s %8s %8s %8s %8s" % ("pattern", "8-bit", "blobs", "UTF-16",
                                     "blobs"))
    print("-" * 66)
    grand16 = 0
    for name, pat, ci in items:
        f = re.I if ci else 0
        r8 = re.compile(pat, f)
        r16 = re.compile(widen(pat), f)
        h8 = b8 = h16 = b16 = 0
        hits = []
        for n, b in blobs:
            c8 = len(r8.findall(b))
            c16 = len(r16.findall(b))
            h8 += c8
            h16 += c16
            b8 += 1 if c8 else 0
            b16 += 1 if c16 else 0
            if c16 and a.show:
                for m in r16.finditer(b):
                    hits.append((n, m.group().decode("utf-16-le", "replace")))
        grand16 += h16
        print("%-28s %8d %8d %8d %8d" % (name[:28], h8, b8, h16, b16))
        if a.show:
            for n, s in hits[:12]:
                print("      %-28s %r" % (n, s))
    print("-" * 66)
    print("hits that only a UTF-16 pass finds : %d" % grand16)
    return 0


if __name__ == "__main__":
    sys.exit(main())
