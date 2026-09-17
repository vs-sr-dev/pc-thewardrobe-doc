#!/usr/bin/env python3
"""samebytes.py -- prove two files are identical by comparing them, not by
comparing statements about them.

A crossing between two discs is a claim that two sequences of bytes are equal.
A hash is evidence for that claim and is not the claim. Two hashes agreeing
proves the two *hashes* agree, and if both were computed by the same tool from
the same list, it proves rather less than that.

This tool takes one local file and one (image, sector, length) triple, reads
the bytes out of the image itself, and compares them directly: length first,
then a streaming byte comparison that stops at the first difference and reports
its offset. It prints both hashes as a by-product, so the hash-level and
byte-level answers appear together and can disagree in public.

    python tools/samebytes.py FILE --image IMG --sector N --length L
    python tools/samebytes.py FILE --other OTHERFILE

The image may be 2,048-byte or raw 2,352-byte sectors; the sync pattern decides.
"""

import argparse
import hashlib
import os

SECTOR = 2048
RAW = 2352
SYNC = b"\x00" + b"\xff" * 10 + b"\x00"


def image_bytes(path, sector, length):
    with open(path, "rb") as fh:
        raw = fh.read(12) == SYNC
        step = RAW if raw else SECTOR
        off = 16 if raw else 0
        out = bytearray()
        lba = sector
        while len(out) < length:
            fh.seek(lba * step + off)
            out += fh.read(SECTOR)
            lba += 1
        return bytes(out[:length]), ("raw 2352" if raw else "cooked 2048")


def digest(b):
    return hashlib.sha1(b).hexdigest(), hashlib.md5(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--image")
    ap.add_argument("--sector", type=int)
    ap.add_argument("--length", type=int)
    ap.add_argument("--other")
    a = ap.parse_args()

    mine = open(a.file, "rb").read()
    if a.other:
        theirs = open(a.other, "rb").read()
        src = a.other
        kind = "file"
    else:
        if a.image is None or a.sector is None:
            ap.error("give --other, or --image with --sector and --length")
        theirs, kind = image_bytes(a.image, a.sector,
                                   a.length if a.length else len(mine))
        src = "%s @ sector %d" % (os.path.basename(a.image), a.sector)

    print("mine   : %-50s %d bytes" % (a.file, len(mine)))
    print("theirs : %-50s %d bytes  (%s)" % (src, len(theirs), kind))
    print()
    ms, mm = digest(mine)
    ts, tm = digest(theirs)
    print("  sha1   mine %s" % ms)
    print("         thrs %s   %s" % (ts, "SAME" if ms == ts else "DIFFERENT"))
    print("  md5    mine %s" % mm)
    print("         thrs %s   %s" % (tm, "SAME" if mm == tm else "DIFFERENT"))
    print()

    if len(mine) != len(theirs):
        print("  LENGTH DIFFERS: %d vs %d" % (len(mine), len(theirs)))
        raise SystemExit(1)

    first = None
    ndiff = 0
    for i, (x, y) in enumerate(zip(mine, theirs)):
        if x != y:
            ndiff += 1
            if first is None:
                first = i
    print("  byte-by-byte over %d bytes:" % len(mine))
    print("    differing bytes            %d" % ndiff)
    print("    first difference at offset %s"
          % ("none" if first is None else first))
    if first is None:
        print()
        print("  -> IDENTICAL, established by comparison and not by hash.")
        print("     first 16 bytes: %s" % mine[:16].hex(" "))
        print("     last  16 bytes: %s" % mine[-16:].hex(" "))
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
