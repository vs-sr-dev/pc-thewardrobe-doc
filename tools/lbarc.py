#!/usr/bin/env python3
"""lbarc.py -- read Nihon Falcom's `LB DIR` / `LB DAT` archive pairs.

Sixty-five per cent of this object is twenty-six pairs of files. The `.dat`
holds the bytes; the `.dir` holds one 36-byte record per slot. Neither is the
index of the other in the usual sense: **both** carry the offsets, and the
number that counts is the one the two agree on. This tool reads both and makes
them agree, or says where they do not.

The format is not documented by Falcom. It is derived from the bytes here, and
the derivation is printed rather than assumed:

    .dir   00  char[8]  "LB DIR" 1a 00
           08  u32      slot count N
           0c  u32      zero on every sample
           10  N records of 36 bytes:
                 00  char[12]  name, 8.3, space-padded, no separator
                 0c  u32       unknown, zero on every sample
                 10  u32       size, uncompressed
                 14  u32       block, a power of two >= size
                 18  u32       packed, stored size
                 1c  u32       timestamp, Unix seconds
                 20  u32       offset into the .dat

    .dat   00  char[8]  "LB DAT" 1a 00
           08  u32      slot count N, the same N
           0c  u32      zero on every sample
           10  (N+1) u32 offsets; the last is the file size, so
               header = 16 + 4*(N+1) and member data begins there

Nothing is ever extracted. Member bytes are read only when `--signatures` is
given, and then only the first 16 of each.

    python tools/lbarc.py --validate "<root>/ED6_DT00"
    python tools/lbarc.py --census "<root>"
    python tools/lbarc.py --census "<root>" --members _work/members.tsv
    python tools/lbarc.py --census "<root>" --signatures --tsv _work/sigs.tsv
"""
import argparse
import collections
import datetime
import glob
import os
import struct
import sys

DIRMAGIC = b"LB DIR" + bytes([0x1A, 0x00])
DATMAGIC = b"LB DAT" + bytes([0x1A, 0x00])
REC = 36
FILLER = b"/_______.___"   # the sentinel name an unused slot carries
UTC = datetime.timezone.utc


def when(ts):
    if not ts:
        return "-"
    return datetime.datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S")


class Archive(object):
    def __init__(self, stem):
        self.stem = stem
        self.name = os.path.basename(stem)
        self.dirpath = stem + ".dir"
        self.datpath = stem + ".dat"
        with open(self.dirpath, "rb") as fh:
            self.dirblob = fh.read()
        assert self.dirblob[:8] == DIRMAGIC, (
            "%s does not begin with LB DIR; refusing to decode it as one"
            % self.dirpath)
        self.dirsize = len(self.dirblob)
        self.count, self.dirpad = struct.unpack_from("<II", self.dirblob, 8)
        assert self.count > 0, "%s declares zero slots" % self.dirpath
        expect = 16 + self.count * REC
        assert expect == self.dirsize, (
            "%s: 16 + %d x 36 = %d but the file is %d"
            % (self.dirpath, self.count, expect, self.dirsize))

        self.datsize = os.path.getsize(self.datpath)
        with open(self.datpath, "rb") as fh:
            head = fh.read(16 + 4 * (self.count + 1))
        assert head[:8] == DATMAGIC, (
            "%s does not begin with LB DAT" % self.datpath)
        dcount, self.datpad = struct.unpack_from("<II", head, 8)
        assert dcount == self.count, (
            "%s declares %d slots, %s declares %d"
            % (self.datpath, dcount, self.dirpath, self.count))
        self.table = list(struct.unpack_from("<%dI" % (self.count + 1), head, 16))
        self.datheader = 16 + 4 * (self.count + 1)

        self.records = []
        for i in range(self.count):
            o = 16 + i * REC
            raw = self.dirblob[o:o + 12]
            a, size, block, packed, ts, off = struct.unpack_from("<6I", self.dirblob, o + 12)
            name = raw.decode("latin-1").rstrip("\x00")
            self.records.append(dict(i=i, raw=raw, name=name.strip(), a=a, size=size,
                                     block=block, packed=packed, ts=ts, off=off))

    # --- populations -----------------------------------------------------
    # A slot is one of three things, and the three are not the same thing:
    #   used        a name and a non-zero size: a member that is in the .dat
    #   ghost       a real name and zero size: a member that was removed
    #   filler      the sentinel name FILLER, every other field zero
    @property
    def used(self):
        return [r for r in self.records if r["size"]]

    @property
    def ghosts(self):
        return [r for r in self.records
                if not r["size"] and r["raw"] != FILLER and r["raw"].strip(b"\x00 ")]

    @property
    def filler(self):
        return [r for r in self.records if r["raw"] == FILLER]

    @property
    def other(self):
        return [r for r in self.records
                if not r["size"] and r["raw"] != FILLER and not r["raw"].strip(b"\x00 ")]

    @property
    def terminator(self):
        """Index of the .dat table entry that equals the file size, or None."""
        for i, v in enumerate(self.table):
            if v == self.datsize:
                return i
        return None

    def reach(self):
        return max((r["off"] + r["packed"]) for r in self.records) if self.records else 0

    def agree(self):
        """How many .dir offsets equal the .dat table entry for the same slot.

        The comparison stops at the terminator: past it the .dat table is zero
        and the .dir is filler, and agreeing about nothing is not agreement.
        """
        end = self.terminator if self.terminator is not None else self.count
        same = diff = 0
        for r in self.records[:end]:
            if self.table[r["i"]] == r["off"]:
                same += 1
            else:
                diff += 1
        return same, diff, end


def archives(root):
    out = []
    for d in sorted(glob.glob(os.path.join(root, "*.dir"))):
        stem = d[:-4]
        if os.path.exists(stem + ".dat"):
            out.append(stem)
    return out


def validate(stem):
    a = Archive(stem)
    print("== %s ==" % a.name)
    print("  .dir              %d bytes, magic %r" % (a.dirsize, DIRMAGIC))
    print("  slot count        %d  (16 + %d x 36 = %d)" % (a.count, a.count, a.dirsize))
    print("  word at 0x0c      %d in the .dir, %d in the .dat" % (a.dirpad, a.datpad))
    print("  .dat              %d bytes, magic %r" % (a.datsize, DATMAGIC))
    print("  .dat header       16 + 4 x (%d + 1) = %d" % (a.count, a.datheader))
    print("  offset table      %d entries, first %d, last %d"
          % (len(a.table), a.table[0], a.table[-1]))
    print("  first member offset vs header : %d vs %d  %s"
          % (a.table[0], a.datheader, "EQUAL" if a.table[0] == a.datheader else "DIFFERENT"))
    print("  terminator        table[%s] = %d = the file size"
          % (a.terminator, a.datsize))
    print("  entries after it  %d, of which zero: %d"
          % (len(a.table) - a.terminator - 1,
             sum(1 for v in a.table[a.terminator + 1:] if v == 0)))
    same, diff, end = a.agree()
    print("  .dir offset == .dat table     : %d of %d agree, %d differ (up to the terminator)"
          % (same, end, diff))
    print("  used   (name and size)        %d" % len(a.used))
    print("  ghosts (name, size zero)      %d" % len(a.ghosts))
    print("  filler (%s)         %d" % (FILLER.decode(), len(a.filler)))
    print("  neither of the three          %d" % len(a.other))
    print("  used + ghosts                 %d, terminator index %s"
          % (len(a.used) + len(a.ghosts), a.terminator))
    print("  reach             %d, file %d, residue %d"
          % (a.reach(), a.datsize, a.datsize - a.reach()))
    print()
    print("  first six records:")
    print("    %-13s %-9s %10s %9s %10s %-20s %10s"
          % ("name", "a", "size", "block", "packed", "timestamp (UTC)", "offset"))
    for r in a.records[:6]:
        print("    %-13s %-9d %10d %9d %10d %-20s %10d"
              % (r["name"], r["a"], r["size"], r["block"], r["packed"], when(r["ts"]), r["off"]))
    return a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="an archive stem for --validate, a directory for --census")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--members", default=None, metavar="TSV",
                    help="write one row per named member")
    ap.add_argument("--signatures", action="store_true",
                    help="read the first 16 bytes of every member")
    ap.add_argument("--tsv", default=None, help="write signatures here")
    a = ap.parse_args()

    if a.validate:
        validate(a.target)
        return

    if not a.census:
        sys.exit("give --validate <stem> or --census <dir>")

    stems = archives(a.target)
    print("archives found    : %d" % len(stems))
    print()
    print("%-12s %6s %6s %6s %6s %6s %14s %14s %8s %5s"
          % ("archive", "slots", "used", "ghost", "filler", "term", "dat bytes",
             "member bytes", "residue", "agree"))
    tot = collections.Counter()
    objs = []
    for s in stems:
        ar = Archive(s)
        objs.append(ar)
        same, diff, end = ar.agree()
        mb = sum(r["packed"] for r in ar.used)
        res = ar.datsize - ar.reach()
        print("%-12s %6d %6d %6d %6d %6s %14d %14d %8d %5s"
              % (ar.name, ar.count, len(ar.used), len(ar.ghosts), len(ar.filler),
                 ar.terminator, ar.datsize, mb, res,
                 "all" if diff == 0 else "%d BAD" % diff))
        tot["slots"] += ar.count
        tot["used"] += len(ar.used)
        tot["ghost"] += len(ar.ghosts)
        tot["filler"] += len(ar.filler)
        tot["other"] += len(ar.other)
        tot["dat"] += ar.datsize
        tot["mem"] += mb
        tot["res"] += res
        tot["hdr"] += ar.datheader
        tot["bad"] += diff
        tot["term"] += ar.terminator if ar.terminator is not None else 0
    print("%-12s %6d %6d %6d %6d %6d %14d %14d %8d %5d"
          % ("TOTAL", tot["slots"], tot["used"], tot["ghost"], tot["filler"],
             tot["term"], tot["dat"], tot["mem"], tot["res"], tot["bad"]))
    print()
    print("used + ghosts = %d, and the terminators sum to %d  %s"
          % (tot["used"] + tot["ghost"], tot["term"],
             "EQUAL" if tot["used"] + tot["ghost"] == tot["term"] else "DIFFERENT"))
    print("used + ghosts + filler = %d, slots = %d, unaccounted %d"
          % (tot["used"] + tot["ghost"] + tot["filler"], tot["slots"],
             tot["slots"] - tot["used"] - tot["ghost"] - tot["filler"]))
    print()
    print("declared size == stored size on : %d of %d members"
          % (sum(1 for o in objs for r in o.used if r["size"] == r["packed"]), tot["used"]))
    print("sum of the 26 .dat headers      : %d" % tot["hdr"])
    print("member bytes + headers          : %d   (.dat total %d, difference %d)"
          % (tot["mem"] + tot["hdr"], tot["dat"], tot["dat"] - tot["mem"] - tot["hdr"]))
    print("the word at record offset 0x0c, distinct values : %s"
          % dict(collections.Counter(r["a"] for o in objs for r in o.records).most_common(6)))
    blocks = collections.Counter(r["block"] for o in objs for r in o.used)
    print("the word at record offset 0x14, distinct values : %d" % len(blocks))
    print("   %s" % ", ".join("%d x%d" % (k, v) for k, v in sorted(blocks.items())))
    bad = sum(1 for o in objs for r in o.used if r["block"] < r["size"])
    print("   members where that word < size : %d" % bad)
    dirty = sum(1 for o in objs for r in o.filler
                if any([r["a"], r["size"], r["block"], r["packed"], r["ts"], r["off"]]))
    print("filler records carrying non-zero data  : %d of %d" % (dirty, tot["filler"]))
    print("zero .dat table entries after the terminators : %d of %d"
          % (sum(1 for o in objs for v in o.table[o.terminator + 1:] if v == 0),
             sum(len(o.table) - o.terminator - 1 for o in objs)))
    ghosts = [(o.name, r) for o in objs for r in o.ghosts]
    print("named records with zero size (ghosts)  : %d" % len(ghosts))
    for nm, r in ghosts[:12]:
        print("   %-12s slot %5d  %-13s block %7d off %10d ts %s"
              % (nm, r["i"], r["name"], r["block"], r["off"], when(r["ts"])))

    if a.members:
        with open(a.members, "w", encoding="utf-8", newline="") as fh:
            fh.write("archive\tslot\tname\tsize\tblock\tpacked\tts\tiso\toffset\n")
            for o in objs:
                for r in o.used:
                    fh.write("%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%d\n"
                             % (o.name, r["i"], r["name"], r["size"], r["block"],
                                r["packed"], r["ts"], when(r["ts"]), r["off"]))
        print()
        print("wrote %s" % a.members)

    if a.signatures:
        rows = []
        for o in objs:
            with open(o.datpath, "rb") as fh:
                for r in o.used:
                    fh.seek(r["off"])
                    rows.append((o.name, r, fh.read(16)))
        print()
        print("signatures read : %d members, %d bytes" % (len(rows), 16 * len(rows)))
        byext = collections.defaultdict(collections.Counter)
        for nm, r, sig in rows:
            ext = r["name"].split(".")[-1] if "." in r["name"] else ""
            byext[ext][sig[:4]] += 1
        for ext in sorted(byext, key=lambda e: -sum(byext[e].values())):
            c = byext[ext]
            print("  .%-4s %6d members, %3d distinct 4-byte openings; top: %s"
                  % (ext, sum(c.values()), len(c),
                     "  ".join("%s x%d" % (k.hex(), v) for k, v in c.most_common(3))))
        if a.tsv:
            with open(a.tsv, "w", encoding="utf-8", newline="") as fh:
                fh.write("archive\tname\tsize\tsig16\n")
                for nm, r, sig in rows:
                    fh.write("%s\t%s\t%d\t%s\n" % (nm, r["name"], r["size"], sig.hex()))
            print("wrote %s" % a.tsv)


if __name__ == "__main__":
    main()
