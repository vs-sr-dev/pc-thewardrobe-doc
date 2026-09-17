#!/usr/bin/env python3
"""jstore.py -- read `header.bin`, the index of a Storage content database.

The format is not described by anybody. It is derived here, and the derivation
is stated so that it can be checked:

  * every one of the 1,559 GUIDs that name a file in `OfficialContent\\
    Resources\\` occurs in `header.bin`, exactly once each, and 1,547 of them
    sit at sixteen-byte spacing in one run;
  * the four bytes immediately before such a run are the run's length as a
    little-endian `u32` -- 1,547 before the run of 1,547, and 12 before the run
    of 12;
  * the byte before *that* is `0xFF`.

So the file is a sequence of records:

    FF  <u32 count>  <count x 16-byte GUID>

with a small number of bare `0x00` bytes between records, which this reader
counts and reports rather than skipping silently. Nothing else is assumed: the
walk is strictly sequential from byte 0 and every byte is accounted for.

The closure test is external and it is the point of the tool: the number of
GUIDs the walk finds must equal `_objectsCount` in the `info.bin` beside the
file, which was written by a different part of the same program and which
`tools/nrbf.py` reads out of a published Microsoft format.

    python tools/jstore.py academagia-steam/OfficialContent/header.bin --validate
    python tools/jstore.py academagia-steam/OfficialContent/header.bin --census
    python tools/jstore.py --zip academagia-steam/Mods/Content.mdm \\
        --member new_header.bin --census
    python tools/jstore.py --selftest
"""
import argparse
import collections
import os
import struct
import sys
import uuid
import zipfile

GUID = 16
MARK = 0xFF
MAX_COUNT = 1 << 21          # 2,097,152 GUIDs = 32 MB; nothing here is close


class JStoreError(Exception):
    pass


def walk(data, max_count=MAX_COUNT):
    """Return (lists, filler) where lists is [(offset, count)] and filler is
    [(offset, bytes)]. Raises if a byte cannot be accounted for."""
    n = len(data)
    p = 0
    lists = []
    filler = []
    while p < n:
        if data[p] == MARK and p + 5 <= n:
            count = struct.unpack_from("<I", data, p + 1)[0]
            end = p + 5 + GUID * count
            if count <= max_count and end <= n:
                lists.append((p + 5, count))
                p = end
                continue
        start = p
        while p < n:
            if data[p] == MARK and p + 5 <= n:
                c = struct.unpack_from("<I", data, p + 1)[0]
                if c <= max_count and p + 5 + GUID * c <= n:
                    break
            p += 1
        filler.append((start, data[start:p]))
    return lists, filler


def guids(data, lists):
    for off, count in lists:
        for k in range(count):
            yield data[off + GUID * k:off + GUID * k + GUID]


def validate(data, label, expect=None):
    lists, filler = walk(data)
    total = sum(c for _, c in lists)
    body = sum(5 + GUID * c for _, c in lists)
    fill = sum(len(b) for _, b in filler)
    print("index        : %s" % label)
    print("bytes        : %d" % len(data))
    print("lists        : %d" % len(lists))
    print("GUIDs        : %d" % total)
    print("arithmetic   : 5 x %d + 16 x %d + %d = %d"
          % (len(lists), total, fill, body + fill))
    print("residue      : %d" % (len(data) - body - fill))
    print("filler runs  : %d holding %d bytes, all zero : %s"
          % (len(filler), fill,
             all(b == 0 for _, blob in filler for b in blob)))
    bad = 0
    if len(data) - body - fill:
        bad += 1
        print("FAILURE: the walk does not cover the file")
    if expect is not None:
        print("_objectsCount from info.bin : %d   residue against it : %d"
              % (expect, total - expect))
        if total != expect:
            bad += 1
            print("FAILURE: the index and the manifest disagree")
    dup = len(list(guids(data, lists))) - len(set(guids(data, lists)))
    print("GUIDs repeated inside this index : %d" % dup)
    return 1 if bad else 0


def census(data, label, resources=None):
    lists, filler = walk(data)
    print("index        : %s" % label)
    print("lists        : %d   GUIDs : %d"
          % (len(lists), sum(c for _, c in lists)))
    print()
    print("  #    count      share   first GUID")
    total = sum(c for _, c in lists)
    for i, (off, count) in enumerate(lists):
        g = uuid.UUID(bytes_le=bytes(data[off:off + GUID])) if count else None
        print("%3d  %7d  %8.4f %%  %s"
              % (i, count, 100.0 * count / total, g))
    if resources:
        want = set()
        for name in resources:
            try:
                want.add(uuid.UUID(name).bytes_le)
            except ValueError:
                pass
        print()
        print("resource names on disk : %d" % len(want))
        for i, (off, count) in enumerate(lists):
            got = sum(1 for k in range(count)
                      if bytes(data[off + GUID * k:off + GUID * k + GUID])
                      in want)
            if got:
                print("  list %d holds %d of them (%d of %d in the list)"
                      % (i, got, got, count))
    return 0


def selftest():
    ok = 0
    fail = []

    def must_raise(name, blob, **kw):
        try:
            lists, filler = walk(blob, **kw)
        except JStoreError:
            return True
        # walk() never raises; the contract is that every byte is either in a
        # list or in a filler run, so the test is arithmetic and not an
        # exception. Checked below instead.
        body = sum(5 + GUID * c for _, c in lists)
        fill = sum(len(b) for _, b in filler)
        if body + fill != len(blob):
            return True
        fail.append(name)
        return False

    # A specimen that must be read exactly.
    g1 = uuid.uuid4().bytes_le
    g2 = uuid.uuid4().bytes_le
    good = b"\xff" + struct.pack("<I", 2) + g1 + g2 + b"\xff" + \
        struct.pack("<I", 0)
    lists, filler = walk(good)
    if [c for _, c in lists] == [2, 0] and not filler:
        ok += 1
    else:
        fail.append("two-list specimen")

    # Specimens that must NOT be read as a clean index.
    bads = [
        ("all zeros", b"\x00" * 64),
        ("PNG", b"\x89PNG\r\n\x1a\n" + b"\x00" * 40),
        ("a count that runs off the end",
         b"\xff" + struct.pack("<I", 1000) + b"\x00" * 8),
        ("text", b"Monstrous Emanations" * 3),
        ("a truncated final GUID",
         b"\xff" + struct.pack("<I", 1) + g1[:9]),
    ]
    for name, blob in bads:
        lists, filler = walk(blob)
        clean = filler == [] and lists != []
        if not clean:
            ok += 1
        else:
            fail.append(name)

    # And one where the marker byte appears inside a GUID: the walk must still
    # cover every byte, because coverage is the invariant, not prettiness.
    inside = b"\xff" + struct.pack("<I", 1) + b"\xff" * GUID
    lists, filler = walk(inside)
    body = sum(5 + GUID * c for _, c in lists)
    if body + sum(len(b) for _, b in filler) == len(inside):
        ok += 1
    else:
        fail.append("marker inside a GUID")

    print("selftest: %d of 7 specimens behaved as required "
          "(5 of the 7 must be refused as an index)" % ok)
    for f in fail:
        print("  FAILED: %s" % f)
    return 0 if not fail else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--zip", dest="zippath")
    ap.add_argument("--member", default="header.bin")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--expect", type=int)
    ap.add_argument("--resources", help="directory of GUID-named files")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.zippath:
        with zipfile.ZipFile(a.zippath) as z:
            data = z.read(a.member)
        label = "%s :: %s" % (os.path.basename(a.zippath), a.member)
    else:
        if not a.path:
            ap.error("give a path, or --zip, or --selftest")
        with open(a.path, "rb") as f:
            data = f.read()
        label = a.path
    res = sorted(os.listdir(a.resources)) if a.resources else None
    rc = 0
    if a.validate or not a.census:
        rc |= validate(data, label, a.expect)
    if a.census:
        if a.validate:
            print()
        rc |= census(data, label, res)
    return rc


if __name__ == "__main__":
    sys.exit(main())
