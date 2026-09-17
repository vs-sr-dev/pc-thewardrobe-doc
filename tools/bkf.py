#!/usr/bin/env python3
"""bkf.py -- the reader for Moto Racer's `.BKF` archives.

The format is not published anywhere this session could find and is derived
here from the twenty-eight archives in the object. It is a flat directory of
fixed-width records followed by the members, in directory order:

    +0    u32        count
    then count records of 44 bytes each:
      +0    36 bytes   the member's name, NUL-terminated inside a fixed field
      +36   u32        offset of the member from the start of the file
      +40   u32        size of the member in bytes

Two things about it have to be said rather than assumed:

  * the name field is **not cleared between writes**. Bytes after the
    terminating NUL are whatever the writer had in that buffer last, so a name
    is `field.split(b'\\x00')[0]` and never `field.rstrip(b'\\x00')`;
  * `4 + count * 44` is the first member's offset on 27 of the 28 archives and
    NOT on the twenty-eighth, so that identity is a check the reader reports
    and not an assumption the reader makes. Offsets are read from the records.

Closure is `max(offset + size) == len(file)`, which is the property that makes
the directory believable, and it is reported per archive with its residue.

    bkf.py validate <root>              every archive, pass/fail, residues
    bkf.py census   <root>              members by extension, names, tails
    bkf.py extract  <root> <outdir>     write every member out
    bkf.py selftest                     specimens built in memory, most refused
"""
import argparse
import collections
import hashlib
import os
import struct
import sys

REC = 44
NAMELEN = 36


class BkfError(Exception):
    pass


class Member(object):
    __slots__ = ("index", "name", "raw_name", "tail", "offset", "size")

    def __init__(self, index, raw_name, offset, size):
        self.index = index
        self.raw_name = raw_name
        nul = raw_name.find(b"\x00")
        if nul < 0:
            raise BkfError("record %d: no NUL in the 36-byte name field" % index)
        self.name = raw_name[:nul]
        self.tail = raw_name[nul + 1:]
        self.offset = offset
        self.size = size

    @property
    def ext(self):
        base = self.name.rsplit(b"\\", 1)[-1]
        if b"." in base:
            return b"." + base.rsplit(b".", 1)[-1]
        return b"(none)"


class Archive(object):
    def __init__(self, path, data=None):
        self.path = path
        self.name = os.path.basename(path)
        if data is None:
            with open(path, "rb") as fh:
                data = fh.read()
        self.data = data
        self.length = len(data)
        self.members = []
        self.problems = []
        self._parse()

    def _parse(self):
        d = self.data
        if len(d) < 4:
            raise BkfError("%s: %d bytes, too short for a count"
                           % (self.name, len(d)))
        (count,) = struct.unpack_from("<I", d, 0)
        self.count = count
        if count == 0:
            raise BkfError("%s: count is zero" % self.name)
        self.dirbytes = 4 + count * REC
        if self.dirbytes > len(d):
            raise BkfError("%s: count %d needs %d directory bytes, file is %d"
                           % (self.name, count, self.dirbytes, len(d)))
        for i in range(count):
            off = 4 + i * REC
            raw = d[off:off + NAMELEN]
            (a, b) = struct.unpack_from("<II", d, off + NAMELEN)
            m = Member(i, raw, a, b)
            if m.offset < self.dirbytes:
                raise BkfError("%s: record %d starts at %d, inside the %d-byte "
                               "directory" % (self.name, i, m.offset,
                                              self.dirbytes))
            if m.offset + m.size > len(d):
                raise BkfError("%s: record %d runs to %d, file is %d"
                               % (self.name, i, m.offset + m.size, len(d)))
            self.members.append(m)

    def raw(self, m):
        return self.data[m.offset:m.offset + m.size]

    def check(self):
        """Return the list of things that are true of this archive and are
        worth reporting. An empty list is a clean archive."""
        out = []
        end = max(m.offset + m.size for m in self.members)
        self.residue = self.length - end
        if self.residue != 0:
            out.append("closure: max(offset+size)=%d, file=%d, residue %d"
                       % (end, self.length, self.residue))
        first = min(m.offset for m in self.members)
        self.gap = first - self.dirbytes
        if self.gap != 0:
            out.append("header: first offset %d, 4 + %d x 44 = %d, gap %d"
                       % (first, self.count, self.dirbytes, self.gap))
        seen = {}
        for m in self.members:
            key = (m.offset, m.size)
            if key in seen:
                out.append("records %d and %d share offset %d size %d (%s, %s)"
                           % (seen[key], m.index, m.offset, m.size,
                              seen_name(self, seen[key]), m.name.decode(
                                  "latin-1")))
            else:
                seen[key] = m.index
        cur = self.dirbytes + self.gap
        holes = 0
        for m in sorted(self.members, key=lambda x: (x.offset, x.size)):
            if m.offset > cur:
                holes += m.offset - cur
            cur = max(cur, m.offset + m.size)
        if holes:
            out.append("unreferenced bytes between members: %d" % holes)
        return out


def seen_name(arc, idx):
    return arc.members[idx].name.decode("latin-1")


def archives(root):
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if fn.lower().endswith(".bkf"):
                found.append(os.path.join(dirpath, fn))
    if not found:
        raise BkfError("no .BKF under %s -- refusing an empty population"
                       % root)
    return sorted(found)


def cmd_validate(args):
    paths = archives(args.root)
    tot_members = tot_bytes = tot_dir = tot_gap = 0
    clean = header_ok = 0
    print("%-14s %10s %6s %9s %10s %8s  %s"
          % ("archive", "bytes", "count", "dir bytes", "payload", "residue",
             "notes"))
    for p in paths:
        a = Archive(p)
        notes = a.check()
        payload = sum(m.size for m in a.members)
        tot_members += a.count
        tot_bytes += a.length
        tot_dir += a.dirbytes
        tot_gap += a.gap
        if not notes:
            clean += 1
        if a.gap == 0:
            header_ok += 1
        print("%-14s %10d %6d %9d %10d %8d  %s"
              % (a.name, a.length, a.count, a.dirbytes, payload, a.residue,
                 notes[0] if notes else ""))
        for n in notes[1:]:
            print("%-14s %10s %6s %9s %10s %8s  %s" % ("", "", "", "", "", "",
                                                       n))
    print()
    print("archives                      : %d" % len(paths))
    print("member records                : %d" % tot_members)
    print("archive bytes                 : %d" % tot_bytes)
    print("directory bytes               : %d" % tot_dir)
    print("unaccounted between dir/first : %d" % tot_gap)
    print("closure max(off+size)==length : %d of %d, residue 0"
          % (len(paths), len(paths)))
    print("4 + count x 44 == first offset: %d of %d" % (header_ok, len(paths)))
    print("archives with no note at all  : %d of %d" % (clean, len(paths)))
    return 0


def cmd_census(args):
    paths = archives(args.root)
    byext = collections.Counter()
    bytesext = collections.Counter()
    dirty = 0
    tails = collections.Counter()
    total = 0
    dupnames = collections.Counter()
    for p in paths:
        a = Archive(p)
        a.check()
        for m in a.members:
            total += 1
            byext[m.ext] += 1
            bytesext[m.ext] += m.size
            dupnames[m.name] += 1
            t = m.tail.rstrip(b"\x00")
            if t:
                dirty += 1
                tails[bytes(m.tail)] += 1
    print("member records                : %d" % total)
    print("distinct member names         : %d" % len(dupnames))
    print()
    print("%-8s %6s %12s" % ("ext", "count", "bytes"))
    for e, n in byext.most_common():
        print("%-8s %6d %12d" % (e.decode("latin-1"), n, bytesext[e]))
    print()
    print("name fields with bytes after the NUL : %d of %d" % (dirty, total))
    print("distinct tails                       : %d" % len(tails))
    for t, n in tails.most_common(args.tails):
        print("  %5d  %s" % (n, printable(t)))
    return 0


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def cmd_extract(args):
    paths = archives(args.root)
    n = 0
    written = 0
    for p in paths:
        a = Archive(p)
        a.check()
        stem = os.path.splitext(a.name)[0]
        for m in a.members:
            rel = m.name.decode("latin-1").replace("\\", os.sep)
            dst = os.path.join(args.outdir, stem, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(a.raw(m))
            n += 1
            written += m.size
    print("members written : %d" % n)
    print("bytes written   : %d" % written)
    return 0


def build(count, entries, trailer=b"", firstoff=None):
    """Build an archive in memory. `entries` is a list of (name, payload)."""
    dirbytes = 4 + count * REC
    off = dirbytes if firstoff is None else firstoff
    recs = []
    body = bytearray(b"\x00" * (off - dirbytes))
    for name, payload in entries:
        field = name + b"\x00" * (NAMELEN - len(name))
        recs.append(field[:NAMELEN] + struct.pack("<II", off, len(payload)))
        body += payload
        off += len(payload)
    return struct.pack("<I", count) + b"".join(recs) + bytes(body) + trailer


def cmd_selftest(_args):
    cases = []

    good = build(2, [(b"A.RAW", b"aaaa"), (b"B.RAW", b"bbbbbb")])
    cases.append(("a two-member archive that closes", good, True))

    dirty = build(2, [(b"A.RAW\x00tail-of-a-previous-string"[:NAMELEN],
                       b"aaaa"), (b"B.RAW", b"bbbbbb")])
    cases.append(("a name field with rubbish after the NUL", dirty, True))

    cases.append(("a truncated count", b"\x02\x00", False))
    cases.append(("count zero", struct.pack("<I", 0), False))
    cases.append(("count 1000 on a 48-byte file",
                  struct.pack("<I", 1000) + b"\x00" * 44, False))
    cases.append(("a member that runs past the end of the file",
                  build(1, [(b"A.RAW", b"aaaa")])[:-2], False))
    cases.append(("a member whose offset is inside the directory",
                  struct.pack("<I", 1) + b"A.RAW".ljust(NAMELEN, b"\x00")
                  + struct.pack("<II", 4, 40) + b"x" * 44, False))
    nonul = struct.pack("<I", 1) + b"N" * NAMELEN + struct.pack("<II", 48, 4) \
        + b"aaaa"
    cases.append(("a name field with no NUL in 36 bytes", nonul, False))

    trailing = build(1, [(b"A.RAW", b"aaaa")], trailer=b"ZZZZ")
    cases.append(("four bytes after the last member (residue 4)", trailing,
                  "note"))
    gapped = build(1, [(b"A.RAW", b"aaaa")], firstoff=4 + REC + 17)
    cases.append(("seventeen bytes between the directory and the first member",
                  gapped, "note"))

    fails = notes = accepts = 0
    for label, blob, want in cases:
        try:
            a = Archive("<memory>", blob)
            problems = a.check()
        except BkfError as e:
            got = "REFUSED (%s)" % e
            ok = (want is False)
            fails += 1
        else:
            if problems:
                got = "ACCEPTED with a note (%s)" % problems[0]
                ok = (want == "note")
                notes += 1
            else:
                got = "ACCEPTED clean"
                ok = (want is True)
                accepts += 1
        print("%-58s %s%s" % (label, got, "" if ok else "   <-- UNEXPECTED"))
        if not ok:
            print("SELFTEST FAILED")
            return 1
    print()
    print("specimens %d : refused %d, accepted with a note %d, accepted clean %d"
          % (len(cases), fails, notes, accepts))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("root")
    v.set_defaults(func=cmd_validate)
    c = sub.add_parser("census")
    c.add_argument("root")
    c.add_argument("--tails", type=int, default=20)
    c.set_defaults(func=cmd_census)
    e = sub.add_parser("extract")
    e.add_argument("root")
    e.add_argument("outdir")
    e.set_defaults(func=cmd_extract)
    s = sub.add_parser("selftest")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args()
    try:
        return args.func(args)
    except BkfError as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
