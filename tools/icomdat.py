#!/usr/bin/env python3
"""icomdat.py -- the one container format ICOM Simulations used for every
data file on the *Sherlock Holmes: Consulting Detective* VIS disc.

DERIVED SHAPE

    +0        u32   E, the offset at which the records end
    +4        ...   the records, back to back
    E         u32   N, the number of records
    E + 4     u32[] N+1 absolute file offsets: table[0] is 4, table[N] is E.
                    Record i is the bytes from table[i] to table[i+1].
                    Repeated entries are empty records and the format uses
                    them freely.

THE CHECK THAT MAKES IT A DERIVATION, AND IT IS DOUBLE

Two quantities, each written down twice in two different places:

  * **E** is the u32 in the header AND the last entry of the table;
  * **N** is the u32 at E AND the length of the table divided by four,
    minus one.

This repository's standing rule is that an arithmetic which closes is not a
structure demonstrated, and that a quantity encoded twice, in two places,
agreeing on N of N, is.  Both of these hold on every data file of this disc,
and the one file that fails them -- `DEMO.DAT` -- fails them loudly, which is
the negative control arriving for free.

WHAT USES IT

Everything except the two executables, the two Windows `.DIB`, Tandy's
`CONTROL.TAT`, `DEMO.DAT` and the 157 `.IMV` streams -- so the game's text,
its newspaper, its character directory, its object tables, its scene lists,
its shared 2.2 MB graphics bank and its 8.5 MB of sampled sound are one
format with one reader.
"""

import argparse
import os
import struct
import sys

PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


class Icom:
    def __init__(self, path):
        self.path = path
        self.b = open(path, "rb").read()
        L = len(self.b)
        if L < 8:
            raise ValueError("%s is %d bytes, too short" % (path, L))
        self.end = struct.unpack_from("<I", self.b, 0)[0]
        self.tbl = self.end + 4
        if not (8 <= self.tbl <= L):
            raise ValueError("%s: the header's end-of-records offset %d puts "
                             "the table at %d, outside a %d-byte file"
                             % (path, self.end, self.tbl, L))
        if (L - self.tbl) % 4:
            raise ValueError("%s: %d bytes of table is not a whole number of "
                             "u32 entries" % (path, L - self.tbl))
        self.count = struct.unpack_from("<I", self.b, self.end)[0]
        entries = (L - self.tbl) // 4
        if entries != self.count + 1:
            raise ValueError("%s: the count at %d says %d records but the "
                             "table holds %d entries, which is %d records"
                             % (path, self.end, self.count, entries,
                                entries - 1))
        self.table = [struct.unpack_from("<I", self.b, self.tbl + 4 * i)[0]
                      for i in range(entries)]
        if not all(self.table[i] <= self.table[i + 1]
                   for i in range(entries - 1)):
            raise ValueError("%s: the record table is not non-decreasing"
                             % path)
        if self.table[0] != 4:
            raise ValueError("%s: the first record starts at %d, not 4"
                             % (path, self.table[0]))
        if self.table[-1] != self.end:
            raise ValueError("%s: the table's last entry (%d) does not equal "
                             "the header's offset (%d) -- the two statements "
                             "of where the records end disagree"
                             % (path, self.table[-1], self.end))

    def record(self, i):
        return self.b[self.table[i]:self.table[i + 1]]

    def records(self):
        return [self.record(i) for i in range(self.count)]


def cmd_validate(paths, quiet):
    ok = bad = 0
    for p in paths:
        try:
            c = Icom(p)
            ok += 1
            if not quiet:
                recs = c.records()
                nonempty = sum(1 for r in recs if r)
                pr = sum(1 for r in recs for x in r if x in PRINTABLE)
                tot = sum(len(r) for r in recs) or 1
                print("%-30s %9d  entries %5d  records %5d (%5d non-empty)"
                      "  printable %6.2f %%"
                      % (os.path.relpath(p), len(c.b), c.count, len(recs),
                         nonempty, 100.0 * pr / tot))
        except ValueError as e:
            bad += 1
            print("%-30s REJECTED: %s" % (os.path.relpath(p), e))
    print()
    print("validated %d of %d; the table's last entry equalled the header's "
          "offset on %d of %d" % (ok, ok + bad, ok, ok + bad))
    return bad


def cmd_records(paths, limit, width, raw):
    for p in paths:
        c = Icom(p)
        recs = c.records()
        print("=== %s  %d records ===" % (os.path.relpath(p), len(recs)))
        for i, r in enumerate(recs[:limit] if limit else recs):
            if raw:
                print("  %4d  %5d  %s" % (i, len(r), r[:width].hex(" ")))
            else:
                t = r.decode("latin-1").replace("\r", " ").replace("\n", " ")
                print("  %4d  %5d  %s" % (i, len(r), t[:width]))
        if limit and len(recs) > limit:
            print("  ... %d more" % (len(recs) - limit))
        print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--records", action="store_true")
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--width", type=int, default=160)
    a = ap.parse_args()
    rc = 0
    if a.validate:
        rc = 1 if cmd_validate(a.files, a.quiet) else 0
    if a.records:
        cmd_records(a.files, a.limit, a.width, a.raw)
    sys.exit(rc)


if __name__ == "__main__":
    main()
