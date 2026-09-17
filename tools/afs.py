#!/usr/bin/env python3
"""afs.py -- CRI AFS archive reader. Two files on this disc, 138,684,416 bytes.

The pre-briefing read the first eight bytes as 'AFS\\0' followed by a u32 that
is 2044 little-endian, and warned that it had been read by eye on a platform
whose file endianness it had not established. It was right, and this tool says
why it has to be: 0x000007fc is 2,044 read little-endian and 4,228,448,256 read
big-endian, and only one of those is an entry count for a 73 MB archive.

    +0   4   'AFS' and a NUL
    +4   4   u32 LE   entry count
    +8   8n           entry table: u32 LE offset, u32 LE size, per entry
    ...              then the members, each at its declared offset

and that is the whole format. There is no name table in the header of either
archive on this disc: members are addressed by index.

THE ENDIANNESS FINDING
----------------------

Every member of both archives is a CRI ADX, and the ADX header is BIG-endian
while this archive's table is LITTLE-endian. Same vendor, same disc, same
machine, two byte orders. The checklist's section 5 asks about the endianness
of the SH-4 and gets answered about the CPU; the honest answer about the *files*
is that this disc is mixed, and that the split falls exactly along the age of
the two formats rather than along the machine they were shipped on.

THE CONTROLS
------------

`--validate` requires, per archive:

  * the declared entry count and the table both fit inside the archive;
  * no member starts before the end of the table;
  * no member ends past end-of-file;
  * members do not overlap;
  * the gaps between members are accounted for and reported, not ignored.

Usage:
    python tools/afs.py --validate FILE...
    python tools/afs.py --list FILE
    python tools/afs.py --extract FILE OUTDIR
"""
import os
import struct
import sys


def entries(path):
    fh = open(path, "rb")
    head = fh.read(8)
    if head[:4] != b"AFS\x00":
        fh.close()
        raise ValueError("%s: head is %r, not 'AFS' + NUL" % (path, head[:4]))
    n = struct.unpack_from("<I", head, 4)[0]
    tbl = fh.read(8 * n)
    if len(tbl) != 8 * n:
        fh.close()
        raise ValueError("%s: entry table of %d entries does not fit" % (path, n))
    out = [struct.unpack_from("<II", tbl, i * 8) for i in range(n)]
    return fh, n, out


def cmd_validate(paths):
    rc = 0
    for path in paths:
        size = os.path.getsize(path)
        fh, n, ent = entries(path)
        table_end = 8 + 8 * n
        nonempty = [e for e in ent if e[1] > 0]
        before = sum(1 for o, s in nonempty if o < table_end)
        past = sum(1 for o, s in nonempty if o + s > size)
        srt = sorted(nonempty)
        overlap = sum(1 for i in range(len(srt) - 1)
                      if srt[i][0] + srt[i][1] > srt[i + 1][0])
        gap = 0
        cur = table_end
        for o, s in srt:
            if o > cur:
                gap += o - cur
            cur = max(cur, o + s)
        tail = size - cur
        heads = {}
        for o, s in nonempty:
            fh.seek(o)
            k = fh.read(2)
            heads[k] = heads.get(k, 0) + 1
        print("=== %s ===" % os.path.basename(path))
        print("  file size                        : %d" % size)
        print("  declared entries                 : %d" % n)
        print("  non-empty entries                : %d" % len(nonempty))
        print("  entry table ends at              : %d" % table_end)
        print("  members starting before the table: %d" % before)
        print("  members ending past end of file  : %d" % past)
        print("  overlapping members              : %d" % overlap)
        print("  bytes of member data             : %d" % sum(s for _o, s in nonempty))
        print("  bytes in gaps between members    : %d" % gap)
        print("  bytes after the last member      : %d" % tail)
        print("  accounting: %d + %d + %d + %d = %d  (file %d, remainder %d)"
              % (table_end, sum(s for _o, s in nonempty), gap, tail,
                 table_end + sum(s for _o, s in nonempty) + gap + tail,
                 size, size - (table_end + sum(s for _o, s in nonempty) + gap + tail)))
        print("  first two bytes of every member  : %s"
              % ", ".join("%r x%d" % (k, v) for k, v in
                          sorted(heads.items(), key=lambda kv: -kv[1])))
        if before or past or overlap:
            rc = 1
        fh.close()
    return rc


def cmd_list(path, limit=20):
    fh, n, ent = entries(path)
    print("%s: %d entries" % (os.path.basename(path), n))
    for i, (o, s) in enumerate(ent[:limit]):
        fh.seek(o)
        head = fh.read(16)
        print("  %5d  off %10d  size %8d  head %s" % (
            i, o, s, " ".join("%02x" % b for b in head[:8])))
    fh.close()
    return 0


def cmd_extract(path, outdir):
    fh, n, ent = entries(path)
    os.makedirs(outdir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(path))[0]
    written = 0
    for i, (o, s) in enumerate(ent):
        if s == 0:
            continue
        fh.seek(o)
        open(os.path.join(outdir, "%s_%04d.ADX" % (stem, i)), "wb").write(fh.read(s))
        written += 1
    fh.close()
    print("extracted %d members of %d from %s to %s"
          % (written, n, os.path.basename(path), outdir))
    return 0


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if len(argv) < 3:
        raise SystemExit(__doc__)
    if argv[1] == "--validate":
        return cmd_validate(argv[2:])
    if argv[1] == "--list":
        return cmd_list(argv[2])
    if argv[1] == "--extract":
        return cmd_extract(argv[2], argv[3])
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
