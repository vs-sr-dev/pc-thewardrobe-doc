#!/usr/bin/env python3
"""mctext.py -- reader for the .MC / .MM / .TIN case files of
*Sherlock Holmes: Consulting Detective, Vol. I* (Tandy/Memorex VIS, 1992).

Three case directories (`MC`, `MM`, `TIN`) each hold the same nine stems.
This tool does three things and refuses to guess at a fourth:

  --census    printable fraction, byte histogram summary, longest printable
              run, and line/record structure, for every file given.

  --paths     validate the path-list shape shared by SCENES.* and
              GAMESCEN.DAT: a leading u32, then plain-text relative paths.
              The u32 is checked against the file length TWO ways and the
              tool says which one closes, rather than asserting a reading.

  --records   split a record-per-entity text file (HOLMES.*, DIRECTRY.*,
              BAKER.*) into records on its own separator and print them, or
              with --keys print only each record's leading key so two cases
              can be compared by record rather than by hash.

Nothing here is a published format. Every structural claim is validated on
the sample and the residue is printed; where a reading does not close, the
tool says so instead of rounding.
"""

import argparse
import os
import sys

PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def printable_runs(b, minlen):
    runs = []
    cur = bytearray()
    for x in b:
        if 0x20 <= x < 0x7F:
            cur.append(x)
        else:
            if len(cur) >= minlen:
                runs.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= minlen:
        runs.append(bytes(cur))
    return runs


def cmd_census(paths, minrun):
    print("%-28s %9s %8s %8s %7s %7s %7s" % (
        "file", "bytes", "print%", "zero%", "runs", "longest", "lines"))
    for p in paths:
        b = open(p, "rb").read()
        if not b:
            print("%-28s %9d  EMPTY" % (os.path.basename(p), 0))
            continue
        npr = sum(1 for x in b if x in PRINTABLE)
        nz = b.count(0)
        runs = printable_runs(b, minrun)
        longest = max((len(r) for r in runs), default=0)
        print("%-28s %9d %7.2f%% %7.2f%% %7d %7d %7d" % (
            os.path.relpath(p), len(b), 100.0 * npr / len(b),
            100.0 * nz / len(b), len(runs), longest, b.count(b"\r\n")))


def cmd_paths(paths):
    """SCENES.* and GAMESCEN.DAT: u32 then a plain-text path list.

    Two readings of the u32 are tested against the file length and the tool
    reports which closes with residue 0.  Asserting one without the other is
    how an arithmetic that closes gets mistaken for a structure.
    """
    import struct
    for p in paths:
        b = open(p, "rb").read()
        n = struct.unpack_from("<I", b, 0)[0]
        print("=== %s  (%d bytes)" % (os.path.relpath(p), len(b)))
        print("    u32 at +0            : %d (0x%X)" % (n, n))
        print("    reading A, byte count: %d + 4 = %d   residue %+d"
              % (n, n + 4, len(b) - (n + 4)))
        # reading B: the u32 counts entries, each entry a fixed-width record
        rest = len(b) - 4
        print("    reading B, entry count: %d entries in %d bytes = %.4f b/entry"
              % (n, rest, rest / n if n else 0))
        body = b[4:]
        # entries look NUL- or newline-separated; try both and report
        for sep, name in ((b"\x00", "NUL"), (b"\r\n", "CRLF"), (b"\n", "LF")):
            parts = [x for x in body.split(sep) if x.strip()]
            if len(parts) > 1:
                print("    split on %-4s: %d parts, first %r last %r"
                      % (name, len(parts), parts[0][:40], parts[-1][:40]))
        print()


def cmd_records(paths, sep, keys, limit):
    sepb = sep.encode().decode("unicode_escape").encode("latin-1")
    for p in paths:
        b = open(p, "rb").read()
        recs = [r for r in b.split(sepb) if r.strip()]
        print("=== %s  (%d bytes, %d records on %r)"
              % (os.path.relpath(p), len(b), len(recs), sepb))
        for i, r in enumerate(recs[:limit] if limit else recs):
            t = r.decode("latin-1")
            if keys:
                t = t.split(" - ")[0].split("-")[0].strip()[:60]
                print("  %4d  %s" % (i, t))
            else:
                print("  %4d  %s" % (i, t[:300]))
        if limit and len(recs) > limit:
            print("  ... %d more" % (len(recs) - limit))
        print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--paths", action="store_true")
    ap.add_argument("--records", action="store_true")
    ap.add_argument("--sep", default=r"\r\n")
    ap.add_argument("--keys", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--minrun", type=int, default=6)
    a = ap.parse_args()
    if not (a.census or a.paths or a.records):
        sys.exit("pick one of --census, --paths, --records")
    if a.census:
        cmd_census(a.files, a.minrun)
    if a.paths:
        cmd_paths(a.files)
    if a.records:
        cmd_records(a.files, a.sep, a.keys, a.limit)


if __name__ == "__main__":
    main()
