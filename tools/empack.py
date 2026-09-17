#!/usr/bin/env python3
"""empack.py -- read an `EmPackFi` archive of the Emmersion engine.

Broken Sword: The Angel of Death ships three of them and they are 99.3801 % of
the installation. The format is not documented anywhere; what follows is derived
from the bytes and the derivation is printed so it can be argued with.

    char[8]  'EmPackFi'
    u32      zero        (0 on all three samples)
    u32      header_end  (start of the first member's data region)
    u32      count       (number of members)
    u32      four        (4 on all three samples -- a version)
    then `count` records of TWELVE bytes each, starting at offset 24:
        u32  name_delta    a pointer to this member's name, RELATIVE TO THE
                           START OF THIS RECORD -- the name of record i lives
                           at 24 + 12*i + name_delta
        u32  size          the member's length in bytes
        u32  offset        the member's position in the file, a multiple of 256
    then, at 24 + 12*count, a blob of NUL-terminated names.

The self-relative pointer is the one field the arithmetic of the pre-briefing
got wrong, and the error is instructive: record 0's `name_delta` is exactly
12*count, which is also the distance from offset 24 to the name blob, so a
reader that treats the field as blob-relative agrees with the file on record 0
and drifts by twelve bytes per record afterwards. It produces names that are
real -- they are the tails of the previous entries' paths -- and it produces
them for every record, so nothing ever fails. `rameira.evp` was the twelfth of
those, and it is not a filename.

The derivation is not believed because it closes. It is believed because of an
EXTERNAL FACT, which this tool checks and prints: in each archive exactly one
record satisfies `offset + size == filesize`, and the bytes it points at are the
bytes the file visibly ends with -- for bs4.pak thirty-eight bytes of UTF-16LE
reading `4096 Hello there`, for audio.pak two thousand three hundred and
fifty-eight bytes of XML ending `<!-- Emmersion Xml file EOF -->`. A table that
merely tiled the file would not also predict its visible tail, to the byte, in
two different files, with two different contents.

Nothing is ever extracted. The signature census reads at most 64 bytes from the
front of a member and never writes one anywhere.

    python tools/empack.py "<install dir>/bs4.pak"
    python tools/empack.py "<install dir>/audio.pak" --census
    python tools/empack.py "<install dir>/manual.pdf" --expect-fail
    python tools/empack.py ARCHIVE --names 20
    python tools/empack.py ARCHIVE --tsv notes/members-bs4.tsv
"""
import argparse
import collections
import os
import struct
import sys

MAGIC = b"EmPackFi"
REC = 12
HDR = 24


class NotAnEmPack(Exception):
    pass


def read_header(fh, size):
    fh.seek(0)
    head = fh.read(HDR)
    if len(head) < HDR:
        raise NotAnEmPack("file is shorter than a %d-byte header" % HDR)
    if head[:8] != MAGIC:
        raise NotAnEmPack("magic is %r, not %r" % (head[:8], MAGIC))
    zero, header_end, count, four = struct.unpack_from("<IIII", head, 8)
    if count == 0:
        raise NotAnEmPack("declared member count is zero")
    if HDR + REC * count > size:
        raise NotAnEmPack("record table of %d x %d does not fit in %d bytes"
                          % (count, REC, size))
    return zero, header_end, count, four


def read_records(fh, count):
    fh.seek(HDR)
    raw = fh.read(REC * count)
    if len(raw) != REC * count:
        raise NotAnEmPack("short read on the record table")
    out = []
    for i in range(count):
        out.append(struct.unpack_from("<III", raw, i * REC))
    return out


def read_names(fh, count, header_end, recs):
    """Name of record i lives at absolute HDR + REC*i + name_delta."""
    start = HDR + REC * count
    fh.seek(start)
    blob = fh.read(max(0, header_end - start))
    names = []
    for i, (noff, _sz, _off) in enumerate(recs):
        rel = HDR + REC * i + noff - start
        if rel < 0 or rel >= len(blob):
            names.append(None)
            continue
        end = blob.find(b"\x00", rel)
        if end < 0:
            end = len(blob)
        names.append(blob[rel:end].decode("latin-1"))
    return names, blob, start


SIGS = [
    (b"BIKi", "Bink video (BIKi)"),
    (b"BIKb", "Bink video (BIKb)"),
    (b"BIKf", "Bink video (BIKf)"),
    (b"BIKg", "Bink video (BIKg)"),
    (b"BIKh", "Bink video (BIKh)"),
    (b"RIFF", "RIFF"),
    (b"ID3", "MP3 with ID3 tag"),
    (b"OggS", "Ogg"),
    (b"DDS ", "DirectDraw Surface"),
    (b"BM", "Windows bitmap"),
    (b"\x89PNG", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"\x1f\x8b", "gzip"),
    (b"PK\x03\x04", "ZIP"),
    (b"EmPackFi", "EmPackFi (nested)"),
    (b"<?xml", "XML declaration"),
    (b"<!--", "XML comment"),
    (b"<", "XML/markup"),
    (b"\xff\xfe", "UTF-16LE with BOM"),
    (b"\xef\xbb\xbf", "UTF-8 with BOM"),
    (b"MZ", "PE/DOS executable"),
    (b"\x7fELF", "ELF"),
    (b"%PDF", "PDF"),
]


def mp3_sync(b):
    """A bare MPEG audio frame header: 11 sync bits, a legal version and layer."""
    if len(b) < 4 or b[0] != 0xFF or (b[1] & 0xE0) != 0xE0:
        return False
    ver = (b[1] >> 3) & 3
    lay = (b[1] >> 1) & 3
    br = (b[2] >> 4) & 15
    sr = (b[2] >> 2) & 3
    return ver != 1 and lay != 0 and br not in (0, 15) and sr != 3


def classify(head, name):
    if not head:
        return "(empty)"
    # The signature table comes FIRST. A UTF-16LE byte-order mark is ff fe,
    # and ff fe passes the eleven-bit MPEG sync test (fe & e0 == e0), so a
    # sync-first reader calls every UTF-16 text file an MP3. It called
    # twenty-eight of them that, including the credits roll.
    for sig, label in SIGS:
        if head.startswith(sig):
            return label
    if mp3_sync(head):
        return "MPEG audio frame"
    if head[:4] in (b"\x00\x00\x00\x00",):
        return "starts with four NUL"
    printable = sum(1 for c in head[:32] if 9 <= c <= 13 or 32 <= c < 127)
    if printable == min(32, len(head)):
        return "printable text"
    return "unrecognised"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--census", action="store_true",
                    help="read 64 bytes from the front of every member and "
                         "count signatures")
    ap.add_argument("--names", type=int, default=12,
                    help="how many member names to print")
    ap.add_argument("--tsv", default=None,
                    help="write name/size/offset/signature as TSV")
    ap.add_argument("--expect-fail", action="store_true",
                    help="the control: this file must NOT parse")
    a = ap.parse_args()

    size = os.path.getsize(a.path)
    fh = open(a.path, "rb")

    try:
        zero, header_end, count, four = read_header(fh, size)
    except NotAnEmPack as e:
        if a.expect_fail:
            print("control       : %s" % os.path.basename(a.path))
            print("bytes         : %d" % size)
            print("verdict       : REFUSED, as required -- %s" % e)
            return 0
        print("NOT an EmPackFi archive: %s" % e, file=sys.stderr)
        return 1

    if a.expect_fail:
        print("control FAILED: %s parsed as an EmPackFi archive"
              % os.path.basename(a.path), file=sys.stderr)
        return 1

    print("archive       : %s" % os.path.basename(a.path))
    print("bytes         : %d" % size)
    print("magic         : %r at offset 0" % MAGIC.decode())
    print("header words  : u32 %d, u32 %d (header_end), u32 %d (count), u32 %d"
          % (zero, header_end, count, four))
    print("record table  : %d records x %d bytes at offset %d .. %d"
          % (count, REC, HDR, HDR + REC * count))
    print("name blob     : %d .. %d = %d bytes"
          % (HDR + REC * count, header_end, header_end - HDR - REC * count))

    recs = read_records(fh, count)
    n0 = recs[0][0]
    print("record 0 name_delta        : %d   (count x 12 = %d)  -> %s"
          % (n0, REC * count, "MATCH" if n0 == REC * count else "DIFFER"))

    names, blob, blob_start = read_names(fh, count, header_end, recs)
    unnamed = sum(1 for x in names if x is None)

    # -- the arithmetic --------------------------------------------------
    aligned = sum(1 for (_n, _s, o) in recs if o % 256 == 0)
    past_end = [i for i, (_n, s, o) in enumerate(recs) if o + s > size]
    before_hdr = [i for i, (_n, _s, o) in enumerate(recs) if o < header_end]
    exact = [i for i, (_n, s, o) in enumerate(recs) if o + s == size]
    total = sum(s for (_n, s, _o) in recs)
    napos = [HDR + REC * i + recs[i][0] for i in range(count)]
    monotone = all(napos[i] < napos[i + 1] for i in range(count - 1))
    # the names should tile the blob with no gap and no overlap
    tiled = all(napos[i] + len(names[i]) + 1 == napos[i + 1]
                for i in range(count - 1)
                if names[i] is not None) and \
        napos[0] == HDR + REC * count and \
        napos[-1] + len(names[-1]) + 1 == header_end

    print()
    print("-- the arithmetic --")
    print("offsets that are a multiple of 256 : %d of %d" % (aligned, count))
    print("members that run past the end      : %d" % len(past_end))
    print("members that start inside the header: %d" % len(before_hdr))
    print("min offset %d  vs header_end %d  -> %s"
          % (min(o for (_n, _s, o) in recs), header_end,
             "header fits" if min(o for (_n, _s, o) in recs) >= header_end
             else "OVERLAP"))
    print("sum of declared sizes              : %d  (%.4f %% of the file)"
          % (total, 100.0 * total / size))
    print("names resolved                     : %d of %d" % (count - unnamed, count))
    print("absolute name positions increasing : %s" % monotone)
    print("names tile the blob, no gap/overlap: %s" % tiled)

    print()
    print("-- the external fact --")
    print("records with offset + size == filesize : %d" % len(exact))
    for i in exact:
        noff, s, o = recs[i]
        fh.seek(o)
        tail = fh.read(min(s, 64))
        print("   record %d  %r  size %d  offset %d" % (i, names[i], s, o))
        print("   its first %d bytes: %r" % (len(tail), tail[:48]))
        fh.seek(o + s - min(s, 48))
        print("   its last  %d bytes: %r" % (min(s, 48), fh.read(min(s, 48))))

    # -- coverage --------------------------------------------------------
    spans = sorted((o, o + s) for (_n, s, o) in recs)
    merged = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1]:
            if hi > merged[-1][1]:
                merged[-1][1] = hi
        else:
            merged.append([lo, hi])
    covered = sum(hi - lo for lo, hi in merged)
    overlap = total - covered
    gaps = []
    cur = header_end
    for lo, hi in merged:
        if lo > cur:
            gaps.append((cur, lo))
        cur = max(cur, hi)
    if cur < size:
        gaps.append((cur, size))
    gapbytes = sum(hi - lo for lo, hi in gaps)

    print()
    print("-- coverage --")
    print("bytes inside a member (union)      : %d  (%.4f %%)"
          % (covered, 100.0 * covered / size))
    print("overlap (sum - union)              : %d bytes" % overlap)
    print("header                             : %d bytes" % header_end)
    print("gaps between members               : %d spans, %d bytes (%.4f %%)"
          % (len(gaps), gapbytes, 100.0 * gapbytes / size))
    print("header + union + gaps              : %d   file is %d   delta %d"
          % (header_end + covered + gapbytes, size,
             header_end + covered + gapbytes - size))
    big = sorted(gaps, key=lambda g: g[1] - g[0], reverse=True)[:5]
    for lo, hi in big:
        print("   largest gap %d bytes at %d" % (hi - lo, lo))

    # -- names -----------------------------------------------------------
    print()
    print("-- names --")
    lens = [len(x) for x in names if x is not None]
    print("mean name length : %.1f characters  (min %d, max %d)"
          % (sum(lens) / len(lens), min(lens), max(lens)))
    print("distinct names   : %d of %d" % (len(set(names)), count))
    print("names containing a backslash : %d" % sum(1 for x in names if x and "\\" in x))
    print("names containing a forward slash : %d" % sum(1 for x in names if x and "/" in x))
    print("names with a drive letter    : %d"
          % sum(1 for x in names if x and len(x) > 1 and x[1] == ":"))
    ext = collections.Counter(os.path.splitext(x)[1].lower()
                              for x in names if x is not None)
    print("by extension, top 20:")
    for e, n in ext.most_common(20):
        b = sum(recs[i][1] for i in range(count)
                if names[i] is not None and
                os.path.splitext(names[i])[1].lower() == e)
        print("   %-14s %7d  %14d" % (e or "(none)", n, b))
    print("first %d names:" % a.names)
    for i in range(min(a.names, count)):
        print("   %6d  %12d  %10d  %s" % (i, recs[i][2], recs[i][1], names[i]))

    # -- signature census ------------------------------------------------
    if a.census or a.tsv:
        cen = collections.Counter()
        cenb = collections.Counter()
        rows = []
        order = sorted(range(count), key=lambda i: recs[i][2])
        for i in order:
            noff, s, o = recs[i]
            fh.seek(o)
            head = fh.read(min(64, s))
            k = classify(head, names[i])
            cen[k] += 1
            cenb[k] += s
            rows.append((names[i], s, o, k))
        print()
        print("-- signature census, %d members, first 64 bytes of each --" % count)
        print("   %-26s %8s %16s %8s" % ("signature", "members", "bytes", "pct"))
        for k, n in cen.most_common():
            print("   %-26s %8d %16d %7.4f %%"
                  % (k, n, cenb[k], 100.0 * cenb[k] / size))
        print("   %-26s %8d %16d %7.4f %%"
              % ("TOTAL", sum(cen.values()), sum(cenb.values()),
                 100.0 * sum(cenb.values()) / size))
        if a.tsv:
            with open(a.tsv, "w", encoding="utf-8") as out:
                out.write("name\tsize\toffset\tsignature\n")
                for nm, s, o, k in sorted(rows, key=lambda r: r[2]):
                    out.write("%s\t%d\t%d\t%s\n" % (nm, s, o, k))
            print("wrote %s" % a.tsv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
