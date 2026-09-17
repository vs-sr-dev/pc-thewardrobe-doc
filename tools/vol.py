#!/usr/bin/env python3
"""vol.py - reader for the Delphine `D1`..`D5` volume files.

The container format is derived from the bytes, not from a specification:

    u16 BE   number of directory entries
    u16 BE   size of one entry, observed 30
    N x 30   name, NUL-terminated inside the first 14 bytes
             u32 BE   absolute offset of the member in this file
             u32 BE   packed size (bytes on disk)
             u32 BE   unpacked size
             4 bytes  a constant tag, not expanded here

`validate` refuses to list anything until the directory closes on the length of
the file: first offset == end of directory, no gaps, no overlaps, nothing past
EOF, last member ending at the last byte. A container that does not close is a
container that was misread.

Usage:
    vol.py validate <dir|file> [...]      structure only, exit 1 if it fails
    vol.py list     <dir|file> [...]      one CSV row per member (needs validate)
    vol.py census   <dir>                 totals, by extension, duplicates
    vol.py selftest <dir>                 negative controls that must fail
"""
import sys
import os
import struct
import hashlib
import argparse

ENTRY = 30
NAMEFIELD = 14


class VolumeError(Exception):
    pass


class Member:
    __slots__ = ("name", "volume", "index", "offset", "packed", "unpacked",
                 "tag", "namefield")

    def __init__(self, name, volume, index, offset, packed, unpacked, tag,
                 namefield):
        self.name = name
        self.volume = volume
        self.index = index
        self.offset = offset
        self.packed = packed
        self.unpacked = unpacked
        self.tag = tag
        self.namefield = namefield

    @property
    def stored(self):
        return self.packed == self.unpacked

    @property
    def ext(self):
        return self.name.rsplit(".", 1)[1].upper() if "." in self.name else ""


class Volume:
    def __init__(self, path, data=None):
        self.path = path
        self.name = os.path.basename(path)
        self.data = data if data is not None else open(path, "rb").read()
        self.size = len(self.data)
        self.members = []
        self.problems = []
        self._parse()

    def _parse(self):
        if self.size < 4:
            raise VolumeError("%s: %d bytes, too short for a header"
                              % (self.name, self.size))
        count, esz = struct.unpack(">HH", self.data[:4])
        self.count = count
        self.entry_size = esz
        if esz != ENTRY:
            raise VolumeError("%s: entry size %d, expected %d"
                              % (self.name, esz, ENTRY))
        self.dir_end = 4 + count * esz
        if self.dir_end > self.size:
            raise VolumeError("%s: directory of %d entries needs %d bytes, "
                              "file is %d" % (self.name, count, self.dir_end,
                                              self.size))
        for i in range(count):
            base = 4 + i * esz
            rec = self.data[base:base + esz]
            namefield = rec[:NAMEFIELD]
            nul = namefield.find(b"\x00")
            if nul < 0:
                raise VolumeError("%s: entry %d has no NUL in its name field"
                                  % (self.name, i))
            name = namefield[:nul].decode("latin-1")
            off, packed, unpacked = struct.unpack(">III", rec[14:26])
            self.members.append(Member(name, self.name, i, off, packed,
                                       unpacked, rec[26:30], namefield))

    def check(self):
        """Return the list of structural problems. Empty means it closes."""
        p = []
        if not self.members:
            if self.size != self.dir_end:
                p.append("empty volume but %d bytes long, header says %d"
                         % (self.size, self.dir_end))
            return p
        ordered = sorted(self.members, key=lambda m: m.offset)
        if ordered[0].offset != self.dir_end:
            p.append("first member at %d, directory ends at %d"
                     % (ordered[0].offset, self.dir_end))
        cursor = self.dir_end
        for m in ordered:
            if m.offset < cursor:
                p.append("overlap: %s at %d, previous extent ended at %d"
                         % (m.name, m.offset, cursor))
            elif m.offset > cursor:
                p.append("gap of %d before %s at %d"
                         % (m.offset - cursor, m.name, m.offset))
            if m.offset + m.packed > self.size:
                p.append("past EOF: %s at %d + %d > %d"
                         % (m.name, m.offset, m.packed, self.size))
            if m.packed > m.unpacked:
                p.append("packed > unpacked: %s %d > %d"
                         % (m.name, m.packed, m.unpacked))
            cursor = max(cursor, m.offset + m.packed)
        if cursor != self.size:
            p.append("last member ends at %d, file is %d" % (cursor, self.size))
        self.problems = p
        return p

    def raw(self, m):
        return self.data[m.offset:m.offset + m.packed]


def volume_paths(args):
    out = []
    for a in args:
        if os.path.isdir(a):
            for n in sorted(os.listdir(a)):
                full = os.path.join(a, n)
                if not os.path.isfile(full):
                    continue
                head = open(full, "rb").read(4)
                if len(head) == 4 and head[2:4] == b"\x00\x1e":
                    out.append(full)
        else:
            out.append(a)
    return out


def load(args, require_clean=True):
    vols = []
    bad = 0
    for p in volume_paths(args):
        v = Volume(p)
        probs = v.check()
        if probs:
            bad += 1
            for s in probs:
                print("FAIL %s: %s" % (v.name, s), file=sys.stderr)
        vols.append(v)
    if bad and require_clean:
        raise VolumeError("%d volume(s) did not close; refusing to list" % bad)
    return vols


def cmd_validate(args):
    vols = load(args.paths, require_clean=False)
    print("%-8s %10s %6s %5s %9s %10s %10s %7s" %
          ("file", "bytes", "count", "esz", "dir end", "sum packed",
           "last byte", "slack"))
    tot_entries = tot_packed = tot_unpacked = tot_bytes = 0
    failed = 0
    for v in vols:
        sump = sum(m.packed for m in v.members)
        last = max((m.offset + m.packed for m in v.members), default=v.dir_end)
        print("%-8s %10d %6d %5d %9d %10d %10d %7d" %
              (v.name, v.size, v.count, v.entry_size, v.dir_end, sump, last,
               v.size - last))
        tot_entries += v.count
        tot_packed += sump
        tot_unpacked += sum(m.unpacked for m in v.members)
        tot_bytes += v.size
        if v.problems:
            failed += 1
    print()
    print("entries %d  packed %d  unpacked %d  volume bytes %d"
          % (tot_entries, tot_packed, tot_unpacked, tot_bytes))
    hdr = 4 * len(vols)
    dirs = tot_entries * ENTRY
    print("headers %d + directories %d + payload %d = %d ; files = %d ; "
          "remainder %d"
          % (hdr, dirs, tot_packed, hdr + dirs + tot_packed, tot_bytes,
             tot_bytes - (hdr + dirs + tot_packed)))
    tags = {}
    for v in vols:
        for m in v.members:
            tags[m.tag] = tags.get(m.tag, 0) + 1
    for t, n in sorted(tags.items(), key=lambda kv: -kv[1]):
        print("tag %-12r %d of %d" % (t, n, tot_entries))
    print()
    print("volumes that did not close: %d of %d" % (failed, len(vols)))
    return 1 if failed else 0


def cmd_list(args):
    vols = load(args.paths)
    print("volume,index,name,offset,packed,unpacked,stored,sha1_packed")
    for v in vols:
        for m in v.members:
            h = hashlib.sha1(v.raw(m)).hexdigest()
            print("%s,%d,%s,%d,%d,%d,%d,%s"
                  % (v.name, m.index, m.name, m.offset, m.packed, m.unpacked,
                     1 if m.stored else 0, h))
    return 0


def cmd_census(args):
    vols = load(args.paths)
    allm = [m for v in vols for m in v.members]
    byname = {}
    raws = {}
    for v in vols:
        for m in v.members:
            byname.setdefault(m.name, []).append((v, m))
            raws[(v.name, m.name)] = v.raw(m)
    stored = [m for m in allm if m.stored]
    packedm = [m for m in allm if not m.stored]
    print("entries %d  distinct names %d  duplicates %d"
          % (len(allm), len(byname), len(allm) - len(byname)))
    print("stored     %4d members %10d bytes"
          % (len(stored), sum(m.packed for m in stored)))
    print("compressed %4d members %10d bytes -> %10d unpacked (%.4fx)"
          % (len(packedm), sum(m.packed for m in packedm),
             sum(m.unpacked for m in packedm),
             sum(m.unpacked for m in packedm) /
             max(1, sum(m.packed for m in packedm))))
    print("all        %4d members %10d bytes -> %10d unpacked (%.4fx)"
          % (len(allm), sum(m.packed for m in allm),
             sum(m.unpacked for m in allm),
             sum(m.unpacked for m in allm) /
             max(1, sum(m.packed for m in allm))))
    print()
    ext = {}
    for m in allm:
        e = ext.setdefault(m.ext or "(none)", [0, 0, set()])
        e[0] += 1
        e[1] += m.unpacked
        e[2].add(m.name)
    print("%-8s %6s %9s %12s" % ("ext", "count", "distinct", "unpacked"))
    for e, (c, b, names) in sorted(ext.items(), key=lambda kv: -kv[1][1]):
        print("%-8s %6d %9d %12d" % (e, c, len(names), b))
    print()
    multi = {n: vs for n, vs in byname.items() if len(vs) > 1}
    same = diff = 0
    difflist = []
    for n, vs in sorted(multi.items()):
        blobs = {raws[(v.name, m.name)] for v, m in vs}
        if len(blobs) == 1:
            same += 1
        else:
            diff += 1
            difflist.append((n, [(v.name, m.packed, m.unpacked) for v, m in vs]))
    print("names in more than one volume: %d" % len(multi))
    print("  byte-identical everywhere : %d" % same)
    print("  differing                 : %d" % diff)
    for n, where in difflist:
        print("    %-16s %s" % (n, " ".join("%s:%d/%d" % w for w in where)))
    print()
    distinct_packed = 0
    distinct_unpacked = 0
    for n, vs in byname.items():
        v, m = vs[0]
        distinct_packed += m.packed
        distinct_unpacked += m.unpacked
    print("distinct members: packed %d unpacked %d ; duplication costs %d bytes"
          % (distinct_packed, distinct_unpacked,
             sum(m.packed for m in allm) - distinct_packed))
    dirty = sum(1 for m in allm
                if any(b for b in m.namefield[m.namefield.find(b"\x00") + 1:]))
    print("records with non-zero bytes after the name terminator: %d of %d"
          % (dirty, len(allm)))
    return 0


def cmd_selftest(args):
    """Negative controls: the validator must refuse things that are wrong."""
    paths = volume_paths(args.paths)
    if not paths:
        print("selftest needs at least one volume", file=sys.stderr)
        return 1
    src = open(paths[0], "rb").read()
    fired = 0
    total = 0

    def expect_fail(label, blob):
        nonlocal fired, total
        total += 1
        try:
            v = Volume("synthetic", blob)
            probs = v.check()
            ok = bool(probs)
            why = probs[0] if probs else "accepted it"
        except VolumeError as e:
            ok = True
            why = str(e)
        except Exception as e:
            ok = True
            why = "%s: %s" % (type(e).__name__, e)
        fired += 1 if ok else 0
        print("%-34s %s  (%s)" % (label, "REFUSED" if ok else "ACCEPTED <<< BUG",
                                  why))

    expect_fail("entry size 31 instead of 30",
                src[:2] + b"\x00\x1f" + src[4:])
    expect_fail("entry count + 1",
                struct.pack(">H", struct.unpack(">H", src[:2])[0] + 1) + src[2:])
    expect_fail("first member offset + 1",
                src[:4 + 14] + struct.pack(">I", struct.unpack(
                    ">I", src[18:22])[0] + 1) + src[22:])
    expect_fail("last byte chopped off", src[:-1])
    expect_fail("one byte appended", src + b"\x00")
    expect_fail("a name field with no NUL",
                src[:4] + b"A" * 14 + src[18:])
    print()
    print("negative controls that fired: %d of %d" % (fired, total))
    return 0 if fired == total else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "list", "census", "selftest"):
        s = sub.add_parser(name)
        s.add_argument("paths", nargs="+")
    args = ap.parse_args()
    try:
        return {"validate": cmd_validate, "list": cmd_list,
                "census": cmd_census, "selftest": cmd_selftest}[args.cmd](args)
    except VolumeError as e:
        print("vol.py: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
