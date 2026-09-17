#!/usr/bin/env python3
"""recdates.py -- the recording dates of an ISO 9660 tree, read as evidence.

`iso9660.py --dates` prints a histogram of every directory record's date,
directories included, and that is the right thing for auditing a date parser.
It is the wrong thing for asking what the dates *mean*, because a directory's
date is written by the mastering program and a file's date is carried in from
wherever the file came from. Those are two clocks and mixing them costs the
question its denominator.

This tool separates them and then asks four things of the file dates:

  1. how many distinct timestamps, how many distinct days, over what span;
  2. **whether the seconds field is even**, on three denominators: all records,
     records whose time is not 00:00:00, and directories. ECMA-119 9.1.5 gives
     the seconds a whole byte with a range of 0..59, so an ISO 9660 volume can
     record an odd second. FAT cannot: it stores the time of day in 2-second
     units, so every mtime it holds is even. A tree whose file dates are all
     even and whose directory dates are not was assembled from a FAT volume;
     a tree where both are even proves only that the mastering program rounds.
     The 00:00:00 records must be excluded from the numerator, because zero is
     even for free and inflates the evidence;
  3. what carries the midnight timestamps, by directory and by extension;
  4. the densest days, and what is in them.

Nothing here is disc-specific: every number printed comes from the image the
tool is pointed at.

    python tools/recdates.py IMAGE
    python tools/recdates.py IMAGE --tsv OUT.tsv
    python tools/recdates.py IMAGE --day 1996-10-31
    python tools/recdates.py IMAGE --year 1995
"""

import argparse
import collections
import datetime
import os
import struct
import sys

SECTOR = 2048
RAW = 2352


class Image(object):
    """Presents either a cooked 2048 image or a raw 2352 one as flat sectors."""

    def __init__(self, path):
        self.fh = open(path, "rb")
        self.size = os.path.getsize(path)
        head = self.fh.read(16)
        self.raw = head[:12] == b"\x00" + b"\xff" * 10 + b"\x00"
        self.step = RAW if self.raw else SECTOR
        # The user area does not begin at a fixed offset in a raw image. Mode 1
        # puts it at 16, immediately after the four-byte header; Mode 2 Form 1
        # puts eight bytes of subheader in between and starts at 24. Written on
        # a Mode 1 disc and given the offset as a constant, this tool read
        # eight bytes of subheader plus 2,040 bytes of payload on the first
        # Mode 2 object it met, found no `CD001`, and stopped. Derive it.
        self.mode = head[15] if self.raw else None
        if not self.raw:
            self.off = 0
        elif self.mode == 1:
            self.off = 16
        elif self.mode == 2:
            self.off = 24
        else:
            raise SystemExit(
                "recdates: raw sector 0 declares mode %r, which is neither 1 "
                "nor 2; refusing to guess the user-area offset" % (self.mode,))
        self.sectors = self.size // self.step

    def sector(self, lba):
        self.fh.seek(lba * self.step + self.off)
        return self.fh.read(SECTOR)

    def read(self, lba, nbytes):
        out = bytearray()
        while len(out) < nbytes:
            out += self.sector(lba)
            lba += 1
        return bytes(out[:nbytes])


def rec_date(b):
    """ECMA-119 9.1.5, the seven-byte recording date. Returns (dt, tzbyte, raw)."""
    y, mo, d, h, mi, s, tz = b[0], b[1], b[2], b[3], b[4], b[5], b[6]
    if tz > 127:
        tz -= 256
    try:
        dt = datetime.datetime(1900 + y, mo, d, h, mi, s)
    except ValueError:
        dt = None
    return dt, tz, bytes(b)


def walk(img):
    """Yield every directory record below the root, as dicts."""
    for lba in range(16, min(img.sectors, 64)):
        b = img.sector(lba)
        if b[1:6] != b"CD001":
            continue
        if b[0] == 1:
            pvd = b
            break
    else:
        raise SystemExit("no primary volume descriptor")

    root = pvd[156:190]
    rext = struct.unpack_from("<I", root, 2)[0]
    rlen = struct.unpack_from("<I", root, 10)[0]

    out = []
    todo = [(rext, rlen, "/")]
    seen = set()
    while todo:
        ext, ln, path = todo.pop(0)
        if (ext, path) in seen:
            continue
        seen.add((ext, path))
        data = img.read(ext, ln)
        pos = 0
        while pos < len(data):
            rl = data[pos]
            if rl == 0:
                pos = (pos // SECTOR + 1) * SECTOR
                continue
            r = data[pos:pos + rl]
            nlen = r[32]
            name = bytes(r[33:33 + nlen])
            flags = r[25]
            e = struct.unpack_from("<I", r, 2)[0]
            sz = struct.unpack_from("<I", r, 10)[0]
            dt, tz, raw = rec_date(r[18:25])
            isdir = bool(flags & 0x02)
            if name not in (b"\x00", b"\x01"):
                nm = name.decode("latin-1")
                full = path + nm
                out.append({"path": full, "name": nm, "isdir": isdir,
                            "size": sz, "extent": e, "dt": dt, "tz": tz,
                            "raw": raw})
                if isdir:
                    todo.append((e, sz, full + "/"))
            pos += rl
    return out


def pct(a, b):
    return 100.0 * a / b if b else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--tsv")
    ap.add_argument("--day")
    ap.add_argument("--year", type=int)
    a = ap.parse_args()

    img = Image(a.image)
    recs = walk(img)
    files = [r for r in recs if not r["isdir"]]
    dirs = [r for r in recs if r["isdir"]]
    tot = sum(r["size"] for r in files)

    print("image            : %s (%s sectors of %d)"
          % (os.path.basename(a.image), img.sectors, img.step))
    print("records          : %d  (%d files, %d directories)"
          % (len(recs), len(files), len(dirs)))
    print("file bytes       : %d" % tot)
    print()

    bad = [r for r in files if r["dt"] is None]
    print("unparseable dates: %d" % len(bad))

    tzs = collections.Counter(r["tz"] for r in files)
    print("timezone offsets : %s"
          % ", ".join("%+d quarter-hours (GMT%+03d:%02d) x%d"
                      % (t, t // 4, abs(t % 4) * 15, n)
                      for t, n in tzs.most_common()))
    print()

    stamps = collections.Counter(r["dt"] for r in files if r["dt"])
    days = collections.Counter(r["dt"].date() for r in files if r["dt"])
    print("distinct timestamps (files only) : %d" % len(stamps))
    print("distinct days       (files only) : %d" % len(days))
    lo, hi = min(days), max(days)
    print("span                             : %s .. %s  (%d days inclusive)"
          % (lo, hi, (hi - lo).days + 1))
    print()

    # -- the evenness of the seconds, on three denominators -----------------
    def evencount(rs):
        e = sum(1 for r in rs if r["dt"] and r["dt"].second % 2 == 0)
        return e, len(rs)

    midnight = [r for r in files if r["dt"] and r["dt"].hour == 0
                and r["dt"].minute == 0 and r["dt"].second == 0]
    midset = set(id(r) for r in midnight)
    nonmid = [r for r in files if id(r) not in midset]

    print("-- the seconds field ------------------------------------------------")
    e, n = evencount(files)
    print("  even seconds, all file records          %d / %d  (%.4f %%)"
          % (e, n, pct(e, n)))
    print("  records at exactly 00:00:00             %d / %d  (%.4f %%)  %d bytes (%.4f %%)"
          % (len(midnight), n, pct(len(midnight), n),
             sum(r["size"] for r in midnight),
             pct(sum(r["size"] for r in midnight), tot)))
    e2, n2 = evencount(nonmid)
    print("  even seconds, excluding 00:00:00        %d / %d  (%.4f %%)   <-- the evidence"
          % (e2, n2, pct(e2, n2)))
    e3, n3 = evencount(dirs)
    print("  even seconds, directory records         %d / %d  (%.4f %%)"
          % (e3, n3, pct(e3, n3)))
    odd = [r for r in files if r["dt"] and r["dt"].second % 2]
    for r in odd[:10]:
        print("     ODD: %s  %s" % (r["dt"], r["path"]))
    print()

    print("-- resolution of the other fields -----------------------------------")
    for field in ("second", "minute", "hour", "day"):
        vals = collections.Counter(getattr(r["dt"], field)
                                   for r in nonmid if r["dt"])
        print("  distinct %-7s values (non-midnight records)  %2d   %s"
              % (field, len(vals),
                 "even only" if field == "second"
                 and all(v % 2 == 0 for v in vals) else ""))
    print()

    print("-- densest days -----------------------------------------------------")
    bytes_by_day = collections.Counter()
    for r in files:
        if r["dt"]:
            bytes_by_day[r["dt"].date()] += r["size"]
    print("  %-12s %7s %16s %9s" % ("day", "files", "bytes", "pct"))
    for d, c in days.most_common(15):
        print("  %-12s %7d %16d %8.4f %%"
              % (d, c, bytes_by_day[d], pct(bytes_by_day[d], tot)))
    tail = [d for d, c in days.items() if c < 100]
    tail10 = [d for d, c in days.items() if c < 10]
    print("  days with fewer than 100 files : %d" % len(tail))
    print("  days with fewer than  10 files : %d" % len(tail10))
    print("  top 8 days cover               : %d files (%.4f %%)"
          % (sum(c for _, c in days.most_common(8)),
             pct(sum(c for _, c in days.most_common(8)), len(files))))
    print()

    print("-- years ------------------------------------------------------------")
    yr = collections.Counter(r["dt"].year for r in files if r["dt"])
    byr = collections.Counter()
    for r in files:
        if r["dt"]:
            byr[r["dt"].year] += r["size"]
    for y in sorted(yr):
        print("  %d  %6d files  %14d bytes  (%.4f %%)"
              % (y, yr[y], byr[y], pct(byr[y], tot)))
    print()

    print("-- oldest and newest ------------------------------------------------")
    ordered = sorted((r for r in files if r["dt"]), key=lambda r: r["dt"])
    for r in ordered[:6]:
        print("  oldest  %s  %10d  %s" % (r["dt"], r["size"], r["path"]))
    for r in ordered[-6:]:
        print("  newest  %s  %10d  %s" % (r["dt"], r["size"], r["path"]))
    print()

    if a.day:
        want = datetime.date.fromisoformat(a.day)
        sel = [r for r in files if r["dt"] and r["dt"].date() == want]
        print("-- %s : %d files, %d bytes --" % (want, len(sel),
                                                 sum(r["size"] for r in sel)))
        bydir = collections.Counter()
        byext = collections.Counter()
        for r in sel:
            bydir[r["path"].rsplit("/", 1)[0] or "/"] += 1
            byext[os.path.splitext(r["name"].split(";")[0])[1].upper()] += 1
        for k, v in bydir.most_common(20):
            print("   %-40s %5d" % (k, v))
        print("   by extension: %s"
              % ", ".join("%s x%d" % (k or "(none)", v)
                          for k, v in byext.most_common()))
        print()

    if a.year:
        sel = [r for r in files if r["dt"] and r["dt"].year == a.year]
        print("-- year %d : %d files, %d bytes --"
              % (a.year, len(sel), sum(r["size"] for r in sel)))
        bydir = collections.Counter()
        for r in sel:
            bydir[r["path"].rsplit("/", 1)[0] or "/"] += 1
        for k, v in bydir.most_common(30):
            print("   %-40s %5d" % (k, v))
        for r in sorted(sel, key=lambda r: r["dt"])[:20]:
            print("   %s  %9d  %s" % (r["dt"], r["size"], r["path"]))
        print()

    if a.tsv:
        with open(a.tsv, "w", encoding="utf-8") as fh:
            fh.write("path\tsize\textent\tdate\ttz\traw\n")
            for r in sorted(files, key=lambda r: r["path"]):
                fh.write("%s\t%d\t%d\t%s\t%d\t%s\n"
                         % (r["path"], r["size"], r["extent"],
                            r["dt"].isoformat(sep=" ") if r["dt"] else "?",
                            r["tz"], r["raw"].hex()))
        print("wrote %s" % a.tsv)


if __name__ == "__main__":
    main()
