#!/usr/bin/env python3
"""dirclock.py -- did the mastering program write the directory dates, or copy
them?

`recdates.py` proves a source volume was FAT by showing that every file record
has an even seconds field while the directory records, written on the day of
the burn, do not. That test needs the directory records to disagree with the
files. On an object where *both* populations are even the test says nothing,
and reusing its conclusion there is exactly the mistake this collection keeps
making.

There is a second test and it does not need the parity of the directories at
all. It needs three facts that any ISO 9660 volume carries:

  1. the four volume-descriptor timestamps, which are written by the mastering
     program from its own clock, in ASCII, to a **hundredth of a second**;
  2. the seven-byte recording date of every directory record;
  3. the same for every file record.

If any volume-descriptor timestamp carries an **odd** seconds field, then the
mastering program's clock is not restricted to even seconds -- so all-even
directory records cannot be its work, and must have been carried in from the
source volume like the files were. And if the directory dates are *older than
the burn* they are inherited on a second, independent ground.

The tool prints all three populations side by side, states which of the two
tests fired, and refuses to conclude anything when neither does.

    python tools/dirclock.py IMAGE
    python tools/dirclock.py IMAGE --list

Raw bytes are printed beside every date, because a date parser you cannot audit
is not a measurement. No constant here belongs to any particular disc.
"""

import argparse
import collections
import datetime
import os
import struct
import sys

SECTOR = 2048


class Image(object):
    def __init__(self, path):
        self.fh = open(path, "rb")
        self.size = os.path.getsize(path)
        head = self.fh.read(16)
        self.raw = head[:12] == b"\x00" + b"\xff" * 10 + b"\x00"
        self.step = 2352 if self.raw else SECTOR
        if not self.raw:
            self.off = 0
        elif head[15] == 1:
            self.off = 16
        elif head[15] == 2:
            self.off = 24
        else:
            raise SystemExit("dirclock: sector 0 declares mode %r" % head[15])
        self.sectors = self.size // self.step

    def sector(self, lba):
        self.fh.seek(lba * self.step + self.off)
        return self.fh.read(SECTOR)

    def read(self, lba, n):
        out = bytearray()
        while len(out) < n:
            out += self.sector(lba)
            lba += 1
        return bytes(out[:n])


def rec_date(b):
    y, mo, d, h, mi, s, tz = b[0], b[1], b[2], b[3], b[4], b[5], b[6]
    if tz > 127:
        tz -= 256
    try:
        return datetime.datetime(1900 + y, mo, d, h, mi, s), tz
    except ValueError:
        return None, tz


def dec_datetime(b):
    """The 17-byte volume-descriptor timestamp: 16 ASCII digits, then a
    timezone byte in 15-minute units. ECMA-119 8.4.26.1."""
    raw = bytes(b[:16])
    tz = struct.unpack_from("b", b, 16)[0]
    if raw == b"0" * 16 or raw == bytes(16):
        return None, None, tz, raw
    try:
        dt = datetime.datetime(int(raw[0:4]), int(raw[4:6]), int(raw[6:8]),
                               int(raw[8:10]), int(raw[10:12]), int(raw[12:14]))
    except ValueError:
        return None, None, tz, raw
    return dt, int(raw[14:16]), tz, raw


def walk(img):
    for lba in range(16, min(img.sectors, 64)):
        b = img.sector(lba)
        if b[1:6] == b"CD001" and b[0] == 1:
            pvd = b
            break
    else:
        raise SystemExit("dirclock: no primary volume descriptor")

    root = pvd[156:190]
    files, dirs = [], []
    todo = [(struct.unpack_from("<I", root, 2)[0],
             struct.unpack_from("<I", root, 10)[0], "/")]
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
            rec = data[pos:pos + rl]
            nlen = rec[32]
            name = bytes(rec[33:33 + nlen])
            flags = rec[25]
            e = struct.unpack_from("<I", rec, 2)[0]
            sz = struct.unpack_from("<I", rec, 10)[0]
            raw7 = bytes(rec[18:25])
            dt, tz = rec_date(raw7)
            if name not in (b"\x00", b"\x01"):
                nm = name.decode("latin1")
                if flags & 0x02:
                    dirs.append((path + nm, dt, tz, raw7))
                    todo.append((e, sz, path + nm + "/"))
                else:
                    files.append((path + nm, sz, dt, tz, raw7))
            pos += rl
    return pvd, files, dirs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    img = Image(a.image)
    pvd, files, dirs = walk(img)

    print("image            : %s (%d sectors of %d)" % (
        os.path.basename(a.image), img.sectors, img.step))
    print("records          : %d files, %d directories" % (len(files), len(dirs)))
    print()

    print("-- the mastering program's own clock (volume descriptor) ----------")
    labels = ("creation", "modification", "expiration", "effective")
    vd_odd = []
    for i, label in enumerate(labels):
        dt, hund, tz, raw = dec_datetime(pvd[813 + 17 * i:813 + 17 * i + 17])
        if dt is None:
            print("  %-13s (unset)      tz byte %4d   raw %s" % (
                label, tz, raw.hex(" ")))
            continue
        odd = dt.second % 2
        if odd:
            vd_odd.append((label, dt))
        print("  %-13s %s.%02d   tz byte %4d %s  seconds=%02d %s" % (
            label, dt.strftime("%Y-%m-%d %H:%M:%S"), hund, tz,
            "(LEGAL)" if -48 <= tz <= 52 else "(OUT OF RANGE, ECMA-119 8.4.26.1"
            " allows -48..+52)", dt.second, "ODD" if odd else "even"))
    print()

    ftz = collections.Counter(f[3] for f in files)
    dtz = collections.Counter(d[2] for d in dirs)
    print("  timezone byte on file records      : %s" % dict(ftz))
    print("  timezone byte on directory records : %s" % dict(dtz))
    print()

    print("-- the seconds field ---------------------------------------------")
    fe = sum(1 for f in files if f[2] and f[2].second % 2 == 0)
    de = sum(1 for d in dirs if d[1] and d[1].second % 2 == 0)
    print("  even, file records      %5d / %d" % (fe, len(files)))
    print("  even, directory records %5d / %d" % (de, len(dirs)))
    print()

    print("-- test 1: does the mastering clock emit odd seconds? -------------")
    if vd_odd:
        for label, dt in vd_odd:
            print("  YES -- %s at %s carries seconds=%02d" % (
                label, dt.strftime("%Y-%m-%d %H:%M:%S"), dt.second))
        print("  => all-even directory records are NOT this program's work.")
    else:
        print("  no volume-descriptor timestamp carries an odd second;")
        print("  test 1 does not fire and proves nothing either way.")
    print()

    print("-- test 2: are the directory dates older than the burn? -----------")
    burn, _, _, _ = dec_datetime(pvd[813:830])
    older = [d for d in dirs if d[1] and burn and d[1] < burn]
    same_day = [d for d in dirs if d[1] and burn and d[1].date() == burn.date()]
    print("  volume creation      : %s" % burn)
    print("  directory records dated before it : %d of %d" % (older, len(dirs))
          if isinstance(older, int) else
          "  directory records dated before it : %d of %d" % (len(older), len(dirs)))
    print("  directory records on the burn day : %d of %d" % (
        len(same_day), len(dirs)))
    if dirs:
        ds = sorted(d[1] for d in dirs if d[1])
        print("  directory date range : %s .. %s" % (ds[0], ds[-1]))
    fs = sorted(f[2] for f in files if f[2])
    if fs:
        print("  file      date range : %s .. %s" % (fs[0], fs[-1]))

    # Per directory: is its own date older than the newest file it holds?
    newest = collections.defaultdict(lambda: None)
    for p, sz, dt, tz, raw in files:
        parent = p.rsplit("/", 1)[0] or "/"
        if dt and (newest[parent] is None or dt > newest[parent]):
            newest[parent] = dt
    older_than_children = 0
    counted = 0
    for p, dt, tz, raw in dirs:
        n = newest.get(p)
        if n and dt:
            counted += 1
            if dt < n:
                older_than_children += 1
    print("  directories older than their own newest file : %d of %d" % (
        older_than_children, counted))
    print()

    if a.list:
        print("-- every directory record ----------------------------------------")
        print("%-34s %-20s %-24s %s" % ("path", "date", "raw seven bytes",
                                        "newest file inside"))
        for p, dt, tz, raw in sorted(dirs):
            print("%-34s %-20s %-24s %s" % (
                p, dt, raw.hex(" "), newest.get(p)))


if __name__ == "__main__":
    main()
