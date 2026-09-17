#!/usr/bin/env python3
"""emdf.py -- read the `EMDF` member format inside an EmPackFi archive.

`.epc` is the Emmersion engine's compiled asset container and it is the largest
single thing in Broken Sword: The Angel of Death -- 1,987 members of `bs4.pak`,
1,557,790,042 bytes, 58.39 % of the whole installation. This tool reads its
header. It never extracts a member and never decodes a mesh or a texture; what
it decodes is the header, the string table, and one field that nothing else in
this collection has ever had: **a timestamp written by the tool that built the
member**, in ASCII, in the clear.

Derived from the bytes:

    u32[1 or 2]  zero padding      -- FOUR bytes on 20 members, EIGHT on 1,967
    char[4]      'EMDF'
    u32          a counter         -- grows with the member's size
    u32          zero
    u32          312               -- the header length, on 1,987 of 1,987
    ...
    +200         "HH MM SS DD MM YYYY\\0", ASCII, relative to 'EMDF'
    ...
    +304         the string table begins: NUL-terminated names, and the space
                 between them is padded with the repeating ASCII word `ALIGN`

The timestamp is not zero-padded consistently. 362 of 1,987 members write at
least one field as a single digit -- `08 59 5 23 05 2006` -- which is what a
`%d` in a format string does when the author meant `%02d`. That is why a naive
fixed-width read finds 1,605 stamps and a flexible one finds 1,987.

    python tools/emdf.py --archive "<install dir>/bs4.pak" \\
                         --tsv _work/members-bs4.tsv
    python tools/emdf.py --archive ARCHIVE --tsv MEMBERS.tsv --strings 40
    python tools/emdf.py --selftest "<install dir>/bs4.pak" \\
                         --tsv _work/members-bs4.tsv
"""
import argparse
import collections
import csv
import datetime
import os
import re
import struct
import sys

MAGIC = b"EMDF"
STAMP = re.compile(rb"^(\d{1,2}) (\d{1,2}) (\d{1,2}) (\d{1,2}) (\d{1,2}) (\d{4})\x00")


def find_magic(head):
    """EMDF sits after four or eight zero bytes. Return its offset or -1."""
    for off in (8, 4):
        if head[off:off + 4] == MAGIC and head[:off] == b"\x00" * off:
            return off
    return -1


def parse(head):
    """head is at least 512 bytes of a member. Returns a dict or None."""
    m = find_magic(head)
    if m < 0:
        return None
    counter, zero, hdrlen = struct.unpack_from("<III", head, m + 4)
    out = {"magic_at": m, "counter": counter, "zero2": zero, "hdrlen": hdrlen,
           "word24": head[m + 24:m + 28].hex(), "stamp": None, "padded": True}
    sm = STAMP.match(head[m + 200:m + 224])
    if sm:
        g = [x.decode() for x in sm.groups()]
        out["padded"] = all(len(x) == 2 for x in g[:5])
        hh, mi, ss, dd, mo, yy = (int(x) for x in g)
        try:
            out["stamp"] = datetime.datetime(yy, mo, dd, hh, mi, ss)
        except ValueError:
            out["stamp"] = None
    return out


def strings_of(head, m):
    """The names after the 312-byte header, with the ALIGN padding removed."""
    blob = head[m + 304:]
    out = []
    for part in blob.split(b"\x00"):
        part = re.sub(rb"(?:ALIGN)+A?L?I?G?N?$", b"", part)
        part = re.sub(rb"^(?:ALIGN)+", b"", part)
        if len(part) >= 3 and all(32 <= c < 127 for c in part):
            out.append(part.decode("latin-1"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", required=True)
    ap.add_argument("--tsv", required=True,
                    help="the member table written by empack.py --tsv")
    ap.add_argument("--strings", type=int, default=0,
                    help="print this many strings from the first member")
    ap.add_argument("--selftest", action="store_true",
                    help="run the controls that must fail before the census")
    a = ap.parse_args()

    rows = list(csv.DictReader(open(a.tsv, encoding="utf-8"), delimiter="\t"))
    fh = open(a.archive, "rb")

    if a.selftest:
        print("-- controls, which must NOT parse as EMDF --")
        for probe, why in ((b"BIKi" + b"\x00" * 508, "a Bink header"),
                           (b"\x00" * 8 + b"EMDX" + b"\x00" * 500, "EMDF with one letter changed"),
                           (b"\x01" * 8 + MAGIC + b"\x00" * 500, "EMDF without its zero prefix")):
            r = parse(probe)
            print("   %-34s -> %s" % (why, "REFUSED" if r is None else "ACCEPTED (BAD)"))
            if r is not None:
                return 1
        good = parse(b"\x00" * 8 + MAGIC + struct.pack("<III", 1, 0, 312)
                     + b"\x00" * 180 + b"09 24 55 20 04 2006\x00" + b"\x00" * 300)
        print("   %-34s -> %s" % ("a hand-built valid header",
                                  "ACCEPTED, stamp %s" % good["stamp"]))
        print()

    seen = []
    notemdf = collections.Counter()
    for r in rows:
        s, o, nm = int(r["size"]), int(r["offset"]), r["name"]
        fh.seek(o)
        head = fh.read(min(s, 512))
        d = parse(head)
        if d is None:
            notemdf[os.path.splitext(nm)[1].lower()] += 1
            continue
        d["name"] = nm
        d["size"] = s
        d["offset"] = o
        seen.append(d)

    print("archive              : %s" % os.path.basename(a.archive))
    print("members in the table : %d" % len(rows))
    print("EMDF members         : %d   %d bytes  (%.4f %% of the archive)"
          % (len(seen), sum(d["size"] for d in seen),
             100.0 * sum(d["size"] for d in seen) / os.path.getsize(a.archive)))
    ext = collections.Counter(os.path.splitext(d["name"])[1].lower() for d in seen)
    print("EMDF by extension    : %s" % dict(ext.most_common(8)))
    print("non-EMDF by extension: %s" % dict(notemdf.most_common(12)))
    print("zero prefix length   : %s"
          % dict(collections.Counter(d["magic_at"] for d in seen)))
    print("header length field  : %s"
          % dict(collections.Counter(d["hdrlen"] for d in seen)))
    print("word at EMDF+24      : %s"
          % dict(collections.Counter(d["word24"] for d in seen).most_common(4)))

    st = [d for d in seen if d["stamp"]]
    print()
    print("-- the timestamp, at EMDF+200, ASCII, HH MM SS DD MM YYYY --")
    print("members carrying one  : %d of %d" % (len(st), len(seen)))
    print("zero-padded correctly : %d;  at least one field bare: %d (%.2f %%)"
          % (sum(1 for d in st if d["padded"]),
             sum(1 for d in st if not d["padded"]),
             100.0 * sum(1 for d in st if not d["padded"]) / max(1, len(st))))
    if st:
        st.sort(key=lambda d: d["stamp"])
        print("earliest              : %s   %s"
              % (st[0]["stamp"], st[0]["name"].split("\\")[-1]))
        print("latest                : %s   %s"
              % (st[-1]["stamp"], st[-1]["name"].split("\\")[-1]))
        days = collections.Counter(d["stamp"].date() for d in st)
        print("distinct days         : %d over a span of %d days"
              % (len(days), (st[-1]["stamp"].date() - st[0]["stamp"].date()).days + 1))
        mo = collections.Counter(d["stamp"].strftime("%Y-%m") for d in st)
        for k in sorted(mo):
            print("   %s  %5d  %s" % (k, mo[k], "#" * (mo[k] // 12)))
        print("   busiest days:")
        for k, v in days.most_common(5):
            print("      %s  %5d" % (k, v))
        dow = collections.Counter(d["stamp"].strftime("%a") for d in st)
        print("   by weekday: %s"
              % " ".join("%s %d" % (k, dow.get(k, 0))
                         for k in ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")))
        we = dow.get("Sat", 0) + dow.get("Sun", 0)
        print("   weekend: %d of %d = %.2f %%" % (we, len(st), 100.0 * we / len(st)))
        hrs = collections.Counter(d["stamp"].hour for d in st)
        print("   by hour:")
        for h in sorted(hrs):
            print("      %02d  %4d  %s" % (h, hrs[h], "#" * (hrs[h] // 8)))

    if a.strings and seen:
        d = seen[0]
        fh.seek(d["offset"])
        head = fh.read(min(d["size"], 4096))
        print()
        print("-- the string table of %s --" % d["name"].split("\\")[-1])
        for s in strings_of(head, d["magic_at"])[:a.strings]:
            print("   %s" % s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
