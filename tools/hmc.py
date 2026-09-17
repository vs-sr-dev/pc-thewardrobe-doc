#!/usr/bin/env python3
"""hmc.py -- 106 files with an extension nobody publishes, and a header everybody does.

`.hmc` begins with four bytes and then `78 9C`. `78 9C` is the zlib header --
RFC 1950 section 2.2: CMF `0x78` is deflate with a 32 KiB window, FLG `0x9C`
sets the check bits so that `0x789C % 31 == 0` and selects the default
compression level. It is the single commonest two-byte sequence in computing
and it is documented by the people who invented it.

So the format is: a four-byte little-endian length, then a zlib stream. This
tool asserts that reading -- it does not assume it. For every file it reports
whether the stream inflates, how many bytes come out, whether that equals the
declared length, and what the first bytes of the plaintext look like. A file
that fails any of those is printed, not skipped.

Validate on one specimen before running the population:

    python tools/hmc.py FILE --one
    python tools/hmc.py TREE --census
    python tools/hmc.py TREE --census --extract _work/hmc
"""

import argparse
import os
import sys
import zlib
from collections import Counter


def read_one(path):
    b = open(path, "rb").read()
    if len(b) < 6:
        return None, "too short", None
    declared = int.from_bytes(b[0:4], "little")
    if b[4:6] != b"\x78\x9c":
        return declared, "no zlib header at offset 4 (%s)" % b[4:6].hex(), None
    try:
        out = zlib.decompress(b[4:])
    except zlib.error as e:
        return declared, "inflate failed: %s" % e, None
    return declared, None, out


def sniff(b):
    head = b[:400].lstrip()
    low = head.lower()
    if low.startswith(b"<?xml"):
        return "XML"
    if low.startswith(b"<!doctype html") or low.startswith(b"<html"):
        return "HTML"
    if b[:2] == b"BM":
        return "BMP"
    if b[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if b[:4] == b"\xd0\xcf\x11\xe0":
        return "OLE2"
    if b[:2] == b"PK":
        return "ZIP"
    printable = sum(1 for c in b[:512] if 9 <= c <= 13 or 32 <= c < 127)
    if b[:512] and printable / len(b[:512]) > 0.90:
        return "text"
    return "binary"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--one", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--ext", default=".hmc")
    ap.add_argument("--extract")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    if a.one:
        declared, err, out = read_one(a.path)
        print("file      %s  (%d bytes on disc)"
              % (a.path, os.path.getsize(a.path)))
        print("declared  %d" % declared)
        if err:
            print("ERROR     %s" % err)
            return
        print("inflated  %d   %s" % (len(out),
                                     "MATCHES" if len(out) == declared
                                     else "DOES NOT MATCH the declared length"))
        print("looks like %s" % sniff(out))
        print("ratio     %.4f" % (os.path.getsize(a.path) / max(1, len(out))))
        print()
        print(out[:600].decode("latin-1"))
        return

    if not a.census:
        ap.print_help()
        return

    n = ok = mismatch = failed = 0
    raw = infl = 0
    kinds = Counter()
    problems = []
    if a.extract:
        os.makedirs(a.extract, exist_ok=True)
    for dp, _dn, fn in os.walk(a.path):
        for f in sorted(fn):
            if not f.lower().endswith(a.ext.lower()):
                continue
            n += 1
            p = os.path.join(dp, f)
            raw += os.path.getsize(p)
            declared, err, out = read_one(p)
            if err:
                failed += 1
                problems.append((p, err))
                continue
            ok += 1
            infl += len(out)
            if len(out) != declared:
                mismatch += 1
                problems.append((p, "declared %d, inflated %d"
                                 % (declared, len(out))))
            kinds[sniff(out)] += 1
            if a.extract:
                o = os.path.join(a.extract, f + ".out")
                open(o, "wb").write(out)

    print("files with extension %s          %d" % (a.ext, n))
    print("  four-byte length + zlib, inflated  %d" % ok)
    print("  inflate failed                     %d" % failed)
    print("  inflated length != declared length %d" % mismatch)
    print("  bytes on disc                      %d" % raw)
    print("  bytes after inflating              %d  (%.3fx)"
          % (infl, infl / max(1, raw)))
    print()
    print("  what the plaintext is:")
    for k, c in kinds.most_common():
        print("    %-10s %5d" % (k, c))
    if problems:
        print()
        print("  problems:")
        for p, e in problems[:20]:
            print("    %-70s %s" % (p[-70:], e))


if __name__ == "__main__":
    main()
