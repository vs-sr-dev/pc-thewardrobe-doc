#!/usr/bin/env python3
"""lnx.py -- read the `.LNX` chunk container of the MS-DOS Links release.

`title.lnx` is not an `MDmd` archive and `mdmd.py` correctly refuses it. Its
own header is a plain offset table and it closes on itself:

    +0        u16 LE   count
    +2        count x u32 LE   absolute file offsets, strictly increasing
    2 + 4*count  ==  offsets[0]        <-- the quantity encoded twice

Chunk i runs from offsets[i] to offsets[i+1], and the last one to end of file.
The container carries no lengths, no names and no types: a chunk is whatever
the bytes at its offset are.

EVERY ONE OF THOSE PROPERTIES IS CHECKED AND EVERY FAILURE IS FATAL, because
the point of this reader is to be able to say that the header is a header
rather than that it can be read as one. In particular the identity
`2 + 4*count == offsets[0]` is checked and NOT used to derive count: the
declared count wins, and the identity is a test of it. That is the exact
mistake the sibling repository made on a different file -- letting an
arithmetic identity overrule a declared field -- and it is not repeated here.

    python tools/lnx.py FILE                     header, chunk table, magics
    python tools/lnx.py FILE --extract DIR       write chunk_NN.bin
    python tools/lnx.py FILE --expect-count 17   fatal if it is not 17
"""
import argparse
import hashlib
import os
import struct
import sys


class LnxError(Exception):
    pass


def parse(data, path="<data>"):
    if len(data) < 6:
        raise LnxError("%s: %d bytes is too short to hold a count and one "
                       "offset" % (path, len(data)))
    count = struct.unpack_from("<H", data, 0)[0]
    if count == 0:
        raise LnxError("%s: declared chunk count is 0" % path)
    need = 2 + 4 * count
    if need > len(data):
        raise LnxError("%s: declared count %d needs a %d-byte table, file is "
                       "%d bytes" % (path, count, need, len(data)))
    offsets = list(struct.unpack_from("<%dI" % count, data, 2))

    if offsets[0] != need:
        raise LnxError("%s: header does not close: 2 + %d*4 = %d but the first "
                       "offset is %d" % (path, count, need, offsets[0]))
    for i in range(1, count):
        if offsets[i] <= offsets[i - 1]:
            raise LnxError("%s: offsets are not strictly increasing at index "
                           "%d: %d then %d" % (path, i, offsets[i - 1],
                                               offsets[i]))
    if offsets[-1] >= len(data):
        raise LnxError("%s: last offset %d is at or past end of file (%d)"
                       % (path, offsets[-1], len(data)))

    chunks = []
    for i in range(count):
        start = offsets[i]
        end = offsets[i + 1] if i + 1 < count else len(data)
        chunks.append((i, start, end - start, data[start:end]))
    total = sum(c[2] for c in chunks)
    if total + need != len(data):
        raise LnxError("%s: chunk sizes sum to %d, header is %d, file is %d -- "
                       "residue %d" % (path, total, need, len(data),
                                       len(data) - total - need))
    return count, offsets, chunks


def describe(blob):
    """What the first bytes of a chunk are, said without interpreting them."""
    if len(blob) >= 4 and blob[:4] == b"MDmd":
        return "MDmd"
    hi = max(blob) if blob else 0
    if hi <= 63:
        return "no magic, max byte %d (<= 63)" % hi
    return "no magic, max byte %d" % hi


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--extract", metavar="DIR")
    ap.add_argument("--expect-count", type=int)
    args = ap.parse_args()

    data = open(args.path, "rb").read()
    try:
        count, offsets, chunks = parse(data, args.path)
    except LnxError as e:
        raise SystemExit("lnx: %s" % e)

    if args.expect_count is not None and count != args.expect_count:
        raise SystemExit("lnx: expected count %d, header declares %d"
                         % (args.expect_count, count))

    print("file            : %s" % os.path.basename(args.path))
    print("bytes           : %d" % len(data))
    print("declared count  : %d" % count)
    print("header size     : 2 + %d*4 = %d" % (count, 2 + 4 * count))
    print("first offset    : %d   -- identity holds, and was CHECKED not USED"
          % offsets[0])
    print("chunk bytes     : %d   (%d + %d = %d)"
          % (sum(c[2] for c in chunks), 2 + 4 * count,
             sum(c[2] for c in chunks), len(data)))
    print()
    print("  #   offset     size  sha1[:12]      opens with")
    for i, start, size, blob in chunks:
        print("  %2d  %7d  %7d  %s  %s"
              % (i, start, size, hashlib.sha1(blob).hexdigest()[:12],
                 describe(blob)))

    nmd = sum(1 for c in chunks if c[3][:4] == b"MDmd")
    print()
    print("MDmd chunks     : %d of %d" % (nmd, count))

    if args.extract:
        os.makedirs(args.extract, exist_ok=True)
        for i, start, size, blob in chunks:
            out = os.path.join(args.extract, "chunk_%02d.bin" % i)
            with open(out, "wb") as fh:
                fh.write(blob)
        print("extracted       : %d chunks to %s" % (count, args.extract))
    return 0


if __name__ == "__main__":
    sys.exit(main())
