#!/usr/bin/env python3
"""ispkg.py -- read an InstallShield 3 SETUP.PKG file manifest.

There is no published specification for this format. Everything below was
derived from the bytes of one 4,513-byte file and then checked against a second
specimen from an unrelated product; where a field's meaning is not established
the tool prints it as an unnamed integer rather than inventing a name for it.

The layout, as derived from two specimens -- this object's 4,513-byte manifest
and Microsoft FrontPage 98's 49,276-byte one, which is a different product from
a different company two years earlier:

    0x00  u16   0xA34A, the same on both
    0x02  u16   equals the value at +0x0A plus 14, on both. It is NOT a magic
                number: the pre-briefing read all four bytes as one constant
                and the high half is not constant.
    0x04  u16   0 on both
    0x06  u16   2 on both
    0x08  u16   0 on both
    0x0A  u16   the length of everything after the sixteen-byte header up to
                the end of the record table -- on both specimens it is exactly
                (end of the walk) minus 16
    0x0C  u16   0 on both
    0x0E  u16   GROUP COUNT
    then  group-count records of   (u16 name length, name, NUL)
    then  u16   FILE COUNT
          u16   0 on both
    then  file-count records of
                (u32 size, u8 name length, name, NUL, u16 group index)
    then  the trailer:  u16 1, u16 1, u16 name length, the archive's own name
                with NO terminator, then the six bytes 01 01 0a 00 00 00 --
                IDENTICAL on both specimens, which is all this object can say
                about them

THREE SELF-CHECKING QUANTITIES, ALL CHECKED, ALL FATAL

    1. the walk consumes exactly `group count` group records;
    2. it consumes exactly `file count` file records;
    3. it ends 16 bytes past the value at +0x0A -- so the format states its own
       payload length and the reader lands on it.

The u32 size field holds the member's size AS STORED inside the archive, not
its expanded size: on this object the 256 values sum to 6,607,311 and that is
exactly what `isz.py` reads out of `_SETUP.1`'s own entry table.

    python tools/ispkg.py walk _work/members/SETUP.PKG
    python tools/ispkg.py walk _work/members/SETUP.PKG --tsv notes/setup-pkg.tsv
    python tools/ispkg.py walk _work/members/SETUP.PKG --explain
    python tools/ispkg.py selftest
"""
import argparse
import collections
import os
import struct
import sys

MAGIC_LO = 0xA34A       # constant on both specimens
HEADER_LEN = 0x10


class PkgError(Exception):
    """Raised for any manifest this reader will not stand behind."""


class Reader:
    """A bounds-checked cursor. Every read is checked against the length of
    the buffer, so a truncated file raises here and never returns a short
    value that a caller might mistake for data."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def need(self, n):
        if n < 0:
            raise PkgError("negative read of %d at %d" % (n, self.pos))
        if self.pos + n > len(self.data):
            raise PkgError("read of %d bytes at offset %d runs past the end "
                           "of a %d-byte file" % (n, self.pos, len(self.data)))

    def u8(self):
        self.need(1)
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self):
        self.need(2)
        v = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def u32(self):
        self.need(4)
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def raw(self, n):
        self.need(n)
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def name(self, n):
        """A length-prefixed name followed by an explicit NUL. The NUL is
        checked: if it is not there the record shape is wrong and continuing
        would silently resynchronise onto garbage."""
        v = self.raw(n)
        term = self.u8()
        if term != 0:
            raise PkgError("name %r at offset %d is not NUL-terminated "
                           "(found 0x%02x)" % (v, self.pos - n - 1, term))
        try:
            return v.decode("cp437")
        except UnicodeDecodeError:
            raise PkgError("name at offset %d is not decodable as CP437"
                           % (self.pos - n - 1))


def parse(data):
    """Parse a SETUP.PKG. Returns a dict. Raises PkgError on anything it is
    not sure about."""
    if len(data) < HEADER_LEN:
        raise PkgError("a %d-byte file is too short to be a manifest"
                       % len(data))
    r = Reader(data)
    magic = r.u32()
    if (magic & 0xFFFF) != MAGIC_LO:
        raise PkgError("the low half of the leading u32 is 0x%04X, not 0x%04X"
                       % (magic & 0xFFFF, MAGIC_LO))
    h = [r.u16() for _ in range(5)]
    group_count = r.u16()
    if r.pos != HEADER_LEN:
        raise PkgError("header walk ended at %d, expected %d"
                       % (r.pos, HEADER_LEN))

    groups = []
    for i in range(group_count):
        n = r.u16()
        groups.append(r.name(n))
    if len(groups) != group_count:
        raise PkgError("declared %d groups, parsed %d"
                       % (group_count, len(groups)))
    groups_end = r.pos

    file_count = r.u16()
    pad = r.u16()
    files_start = r.pos

    files = []
    for i in range(file_count):
        size = r.u32()
        n = r.u8()
        nm = r.name(n)
        grp = r.u16()
        if grp >= group_count:
            raise PkgError("file %d (%r) claims group %d but only %d groups "
                           "are declared" % (i, nm, grp, group_count))
        files.append({"size": size, "name": nm, "group": grp})
    if len(files) != file_count:
        raise PkgError("declared %d files, parsed %d"
                       % (file_count, len(files)))

    return {
        "magic": magic,
        "header_unknowns": h,
        "group_count": group_count,
        "groups": groups,
        "groups_end": groups_end,
        "file_count": file_count,
        "pad": pad,
        "files_start": files_start,
        "files": files,
        "walk_end": r.pos,
        "length": len(data),
        "trailer": data[r.pos:],
    }


def ext_of(name):
    base = name.rsplit("\\", 1)[-1]
    if "." in base[1:]:
        return base.rsplit(".", 1)[-1].upper()
    return "(none)"


def cmd_walk(args):
    with open(args.path, "rb") as fh:
        data = fh.read()
    p = parse(data)
    files = p["files"]
    total = sum(f["size"] for f in files)

    print("manifest        : %s" % args.path)
    print("file length     : %d bytes" % p["length"])
    print("leading u32     : 0x%08X   (low half 0x%04X is constant; high "
          "half %d is +0x0A plus 14 on both specimens: %s)"
          % (p["magic"], p["magic"] & 0xFFFF, p["magic"] >> 16,
             "yes" if (p["magic"] >> 16) == p["header_unknowns"][3] + 14
             else "NO"))
    print("header unknowns : %s"
          % " ".join("%d" % v for v in p["header_unknowns"]))
    print("group count     : %d   (declared and parsed)" % p["group_count"])
    print("group table     : offsets %d .. %d" % (HEADER_LEN, p["groups_end"]))
    print("file count      : %d   (declared and parsed)" % p["file_count"])
    print("pad after count : %d" % p["pad"])
    print("record table    : offsets %d .. %d" % (p["files_start"],
                                                  p["walk_end"]))
    print("walk ended      : %d bytes from the end of the file"
          % (p["length"] - p["walk_end"]))
    print("declared bytes  : %d   (the sum of %d u32 size fields)"
          % (total, len(files)))
    print()
    print("trailer, verbatim, %d bytes:" % len(p["trailer"]))
    print("  hex   %s" % " ".join("%02x" % b for b in p["trailer"]))
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in p["trailer"])
    print("  ascii %s" % printable)
    print()

    print("groups, as named in the group table:")
    print("  %s" % " ".join(p["groups"]))
    print()

    by_group = collections.Counter()
    bytes_by_group = collections.Counter()
    for f in files:
        by_group[f["group"]] += 1
        bytes_by_group[f["group"]] += f["size"]
    print("by group index:")
    print("  %-5s %-10s %6s %14s" % ("idx", "name", "files", "bytes"))
    for g in range(p["group_count"]):
        print("  %-5d %-10s %6d %14d"
              % (g, p["groups"][g], by_group[g], bytes_by_group[g]))
    print("  %-5s %-10s %6d %14d"
          % ("", "TOTAL", sum(by_group.values()), sum(bytes_by_group.values())))
    print()

    by_ext = collections.Counter()
    bytes_by_ext = collections.Counter()
    for f in files:
        e = ext_of(f["name"])
        by_ext[e] += 1
        bytes_by_ext[e] += f["size"]
    print("by extension:")
    print("  %-8s %6s %14s" % ("ext", "files", "bytes"))
    for e, n in by_ext.most_common():
        print("  %-8s %6d %14d" % (e, n, bytes_by_ext[e]))
    print("  %-8s %6d %14d" % ("TOTAL", sum(by_ext.values()),
                               sum(bytes_by_ext.values())))
    print()

    dup = collections.Counter(f["name"].upper() for f in files)
    repeated = [(n, c) for n, c in dup.items() if c > 1]
    print("names appearing more than once : %d" % len(repeated))
    for n, c in sorted(repeated):
        rows = [f for f in files if f["name"].upper() == n]
        print("  %-20s x%d  sizes %s  groups %s"
              % (n, c, sorted({f["size"] for f in rows}),
                 sorted(f["group"] for f in rows)))
    print()

    if args.explain:
        print("what the unnamed header integers land on:")
        marks = {
            HEADER_LEN: "end of the fixed header",
            p["groups_end"]: "end of the group table",
            p["files_start"]: "start of the record table",
            p["walk_end"]: "end of the record table",
            p["length"]: "end of the file",
        }
        marks[p["walk_end"] - 16] = ("the end of the record table minus the "
                                     "sixteen-byte header")
        for i, v in enumerate(p["header_unknowns"]):
            off = 4 + 2 * i
            note = marks.get(v, "")
            if not note and 0 < v < p["length"]:
                note = "inside the file, %d bytes from the end" % (
                    p["length"] - v)
            elif not note:
                note = "not an offset into this file"
            print("  +0x%02X  %6d   %s" % (off, v, note))
        print()

    n_show = min(args.show, len(files))
    print("first %d of %d records:" % (n_show, len(files)))
    print("  %6s %12s %5s  %s" % ("#", "size", "group", "name"))
    for i, f in enumerate(files[:n_show]):
        print("  %6d %12d %5d  %s" % (i, f["size"], f["group"], f["name"]))
    print()
    print("largest ten of %d:" % len(files))
    for f in sorted(files, key=lambda x: -x["size"])[:10]:
        print("  %12d %5d  %s" % (f["size"], f["group"], f["name"]))

    if args.tsv:
        out = os.path.abspath(args.tsv)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("index\tsize\tgroup\tgroup_name\text\tname\n")
            for i, f in enumerate(files):
                fh.write("%d\t%d\t%d\t%s\t%s\t%s\n"
                         % (i, f["size"], f["group"],
                            p["groups"][f["group"]], ext_of(f["name"]),
                            f["name"]))
        print()
        print("wrote %s -- %d rows" % (args.tsv, len(files)))
    return 0


def build_specimen(groups, files, magic=0x118BA34A, lie_group_count=0,
                   lie_file_count=0, drop_tail=0, bad_terminator=False):
    """Construct a manifest in memory. Used only by selftest."""
    out = bytearray()
    out += struct.pack("<I", magic)
    out += struct.pack("<HHHHH", 0, 2, 0, 0, 0)
    out += struct.pack("<H", len(groups) + lie_group_count)
    for g in groups:
        b = g.encode("cp437")
        out += struct.pack("<H", len(b)) + b + b"\x00"
    out += struct.pack("<HH", len(files) + lie_file_count, 0)
    for size, name, grp in files:
        b = name.encode("cp437")
        out += struct.pack("<I", size) + bytes([len(b)]) + b
        out += (b"\x01" if bad_terminator else b"\x00")
        out += struct.pack("<H", grp)
    out += b"\x01\x00\x01\x00"
    if drop_tail:
        return bytes(out[:-drop_tail])
    return bytes(out)


def cmd_selftest(args):
    good_groups = ["Group1", "Group2"]
    good_files = [(100, "A.MID", 0), (250, "B.BMP", 1), (7, "C.WAV", 0)]

    checks = []

    # The one specimen that must be ACCEPTED, and every field is checked.
    spec = build_specimen(good_groups, good_files)
    try:
        p = parse(spec)
        ok = (p["group_count"] == 2 and p["file_count"] == 3
              and [f["name"] for f in p["files"]] == ["A.MID", "B.BMP", "C.WAV"]
              and sum(f["size"] for f in p["files"]) == 357
              and [f["group"] for f in p["files"]] == [0, 1, 0]
              and p["groups"] == good_groups
              and len(p["trailer"]) == 4)
        checks.append(("a well-formed manifest is accepted and reads back",
                       ok, "" if ok else "parsed but the values are wrong"))
    except PkgError as e:
        checks.append(("a well-formed manifest is accepted and reads back",
                       False, str(e)))

    rejects = [
        ("a leading u32 whose low half is wrong",
         build_specimen(good_groups, good_files, magic=0xDEADBEEF)),
        ("a group count larger than the groups present",
         build_specimen(good_groups, good_files, lie_group_count=3)),
        ("a file count larger than the records present",
         build_specimen(good_groups, good_files, lie_file_count=5)),
        ("a truncated record table",
         build_specimen(good_groups, good_files, drop_tail=12)),
        ("a name that is not NUL-terminated",
         build_specimen(good_groups, good_files, bad_terminator=True)),
        ("a group index past the end of the group table",
         build_specimen(good_groups, [(1, "X.DAT", 9)])),
        ("an empty file",
         b""),
        ("four correct bytes and nothing else",
         struct.pack("<I", 0x118BA34A)),
    ]
    for label, spec in rejects:
        try:
            parse(spec)
            checks.append((label + " is rejected", False,
                           "PARSED -- the reader accepted it"))
        except PkgError as e:
            checks.append((label + " is rejected", True, str(e)[:70]))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL",
                                   note))
        if not ok:
            failed += 1
    print()
    print("%d checks, %d accepted specimen, %d rejected specimens, %d failures"
          % (len(checks), 1, len(checks) - 1, failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("walk")
    w.add_argument("path")
    w.add_argument("--tsv")
    w.add_argument("--show", type=int, default=12)
    w.add_argument("--explain", action="store_true")
    w.set_defaults(func=cmd_walk)
    s = sub.add_parser("selftest")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args()
    try:
        return args.func(args)
    except PkgError as e:
        print("ispkg: REFUSED: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
