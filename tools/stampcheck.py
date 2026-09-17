#!/usr/bin/env python3
"""stampcheck.py -- decide whether a PE's COFF `TimeDateStamp` is a clock
reading or a field somebody wrote something else into.

WHY A THIRD TEST WAS NEEDED
---------------------------
`pecensus.py` tests one thing: *is the file's mtime earlier than its link
time*. On three consecutive objects it has answered `impossible mtimes : 0 of
N` while the link times were fiction, because a 1992 stamp on a 2026 file
passes that test comfortably.

`pc-rpgmaker2000-doc/docs/08` proposed a second test -- *do two files of
different sizes share a stamp to the second* -- which catches a linker constant
shared across a build. On this object it catches four files. **It misses two
more**, whose stamps are `0x00200000` and `0x00010000`: exactly 2 MiB and 64
KiB, on files that are neither. A constant shared by one file is invisible to a
collision test.

So there are three tests here, each reported separately, because they catch
different lies and a single verdict would hide which:

  T1 IMPOSSIBLE   the file's mtime precedes its link time
  T2 COLLIDING    two files of DIFFERENT sizes carry the same stamp to the
                  second
  T3 ROUND        the stamp, read as an integer, is a round binary quantity --
                  a power of two, or a multiple of 64 KiB -- which a second
                  count since 1970 has a vanishing chance of being

T3 is deliberately narrow. A timestamp is a number and some real timestamps are
round; the defence is that the round values that matter here are *small*
(before 1980, i.e. under 315,532,800) and simultaneously powers of two. Both
conditions together are what the tool reports as ROUND, and the two parts are
printed so a reader can disagree with either.

    python tools/stampcheck.py <root>
    python tools/stampcheck.py <root> --expect-false 5
    python tools/stampcheck.py --selftest
"""
import argparse
import datetime
import hashlib
import os
import struct
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

# 1980-01-01 UTC. A PE cannot have been linked before the format existed, and
# nothing in this collection legitimately carries a stamp before it.
PRE_MODERN = 315532800


def is_power_of_two(n):
    return n > 0 and (n & (n - 1)) == 0


def round_binary(n):
    """(verdict, why) for T3."""
    if n == 0:
        return True, "zero"
    if n < PRE_MODERN and is_power_of_two(n):
        return True, "a power of two (2^%d) and before 1980" % n.bit_length()
    if n < PRE_MODERN and n % 65536 == 0:
        return True, "a multiple of 64 KiB (%d x 65536) and before 1980" \
            % (n // 65536)
    return False, ""


def coff_stamp(blob):
    """(TimeDateStamp, linker major.minor) or None if it is not a PE."""
    if blob[:2] != b"MZ":
        return None
    if len(blob) < 0x40:
        return None
    (lfanew,) = struct.unpack("<I", blob[0x3C:0x40])
    if lfanew + 24 > len(blob) or blob[lfanew:lfanew + 4] != b"PE\0\0":
        return None
    (stamp,) = struct.unpack("<I", blob[lfanew + 8:lfanew + 12])
    opt = lfanew + 24
    linker = None
    if opt + 2 <= len(blob):
        linker = "%d.%02d" % (blob[opt + 2], blob[opt + 3])
    return stamp, linker


def utc(n):
    try:
        return datetime.datetime.fromtimestamp(
            n, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "(not a representable time)"


def scan(root):
    rows = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            path = os.path.join(dp, f)
            try:
                blob = open(path, "rb").read()
            except OSError:
                continue
            got = coff_stamp(blob)
            if not got:
                continue
            stamp, linker = got
            rows.append({
                "path": os.path.relpath(path, root).replace(os.sep, "/"),
                "bytes": len(blob), "stamp": stamp, "linker": linker,
                "mtime": os.path.getmtime(path),
                "sha1": hashlib.sha1(blob).hexdigest(),
            })
    return rows


def analyse(rows):
    by_stamp = {}
    for r in rows:
        by_stamp.setdefault(r["stamp"], []).append(r)
    for r in rows:
        peers = by_stamp[r["stamp"]]
        sizes = {p["bytes"] for p in peers}
        r["t1"] = r["mtime"] < r["stamp"]
        r["t2"] = len(sizes) > 1
        r["t3"], r["t3why"] = round_binary(r["stamp"])
        r["false"] = r["t1"] or r["t2"] or r["t3"]
    return rows


def run(args):
    rows = analyse(scan(args.root))
    if not rows:
        raise SystemExit("stampcheck: no PE files under %s -- refusing to "
                         "report a clean sheet over nothing" % args.root)
    print("binaries with a COFF TimeDateStamp : %d" % len(rows))
    print()
    print("  %-46s %10s %10s %-20s %s"
          % ("file", "bytes", "stamp", "as a time (UTC)", "T1 T2 T3"))
    for r in sorted(rows, key=lambda r: -r["bytes"]):
        p = r["path"]
        # A path column that eats the front of a name is worse than one that
        # wraps: pecensus.py truncates from the LEFT and prints
        # "mple/ArcheiaPictureTutorial/...". This truncates from the middle
        # and says so with an ellipsis.
        if len(p) > 46:
            p = p[:21] + "..." + p[-22:]
        print("  %-46s %10d %10d %-20s %s  %s  %s"
              % (p, r["bytes"], r["stamp"], utc(r["stamp"]),
                 "Y" if r["t1"] else ".", "Y" if r["t2"] else ".",
                 "Y" if r["t3"] else "."))
    print()
    t1 = sum(1 for r in rows if r["t1"])
    t2 = sum(1 for r in rows if r["t2"])
    t3 = sum(1 for r in rows if r["t3"])
    bad = sum(1 for r in rows if r["false"])
    print("  T1 IMPOSSIBLE (mtime precedes link time)      : %d of %d"
          % (t1, len(rows)))
    print("  T2 COLLIDING  (a stamp shared across sizes)   : %d of %d"
          % (t2, len(rows)))
    print("  T3 ROUND      (a round binary quantity)       : %d of %d"
          % (t3, len(rows)))
    print("  FALSE by at least one test                    : %d of %d"
          % (bad, len(rows)))
    # Two denominators, because this object ships two binaries twice and a
    # count of FILES is not a count of BINARIES. Saying "five of nine" while
    # the table shows seven rows is not a small slip: it is one denominator
    # borrowed for another's numerator.
    if any("sha1" in r for r in rows):
        seen = {}
        for r in rows:
            seen.setdefault(r["sha1"], r)
        distinct = list(seen.values())
        dbad = sum(1 for r in distinct if r["false"])
        print("  the same, counted by DISTINCT BINARY not by file : %d of %d"
              % (dbad, len(distinct)))
    print()
    for r in rows:
        if r["t3"]:
            print("  ROUND : %-40s stamp 0x%08X = %d, %s"
                  % (r["path"], r["stamp"], r["stamp"], r["t3why"]))
    print()
    print("-- and what the tests do NOT say ------------------------------")
    print("  A stamp that passes all three is not thereby true. These tests")
    print("  catch three ways of being obviously false and no way of being")
    print("  quietly false, and a linker that writes a plausible wrong date")
    print("  defeats all of them.")
    if args.expect_false is not None and bad != args.expect_false:
        raise SystemExit("FATAL: --expect-false %d, got %d"
                         % (args.expect_false, bad))
    return 0


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    check("0x00200000 is round", round_binary(0x00200000)[0], True)
    check("0x00010000 is round", round_binary(0x00010000)[0], True)
    check("0x00200000 is named as a power of two",
          "power of two" in round_binary(0x00200000)[1], True)
    check("zero is round", round_binary(0)[0], True)
    # a real 2000 timestamp
    check("2000-03-01 02:30:53 is not round",
          round_binary(951877853)[0], False)
    check("2009-12-05 22:50:52 is not round",
          round_binary(1260053452)[0], False)
    check("the 1992 Borland constant is NOT caught by T3",
          round_binary(709000937)[0], False)
    # a modern power of two must not be flagged: 2^30 is 2004 and is after 1980
    check("a power of two after 1980 is not flagged by T3",
          round_binary(1 << 30)[0], False)
    check("a power of two before 1980 is flagged",
          round_binary(1 << 24)[0], True)
    check("is_power_of_two rejects 3", is_power_of_two(3), False)
    check("is_power_of_two accepts 65536", is_power_of_two(65536), True)

    # T2: four files sharing one stamp across different sizes
    rows = [
        {"path": "a", "bytes": 100, "stamp": 709000937, "mtime": 2e9},
        {"path": "b", "bytes": 200, "stamp": 709000937, "mtime": 2e9},
        {"path": "c", "bytes": 300, "stamp": 0x00200000, "mtime": 2e9},
        {"path": "d", "bytes": 400, "stamp": 951877853, "mtime": 2e9},
        {"path": "e", "bytes": 400, "stamp": 1260053452, "mtime": 1e9},
    ]
    analyse(rows)
    check("T2 catches the two sharing a stamp across sizes",
          sum(1 for r in rows if r["t2"]), 2)
    check("T3 catches the round one alone",
          [r["path"] for r in rows if r["t3"]], ["c"])
    check("T1 catches the one whose mtime precedes its stamp",
          [r["path"] for r in rows if r["t1"]], ["e"])
    check("three of the five are false by some test",
          sum(1 for r in rows if r["false"]), 4)

    # two files of the SAME size sharing a stamp are not T2 -- they may be one
    # file shipped twice, which this object does three times
    same = [{"path": "x", "bytes": 124928, "stamp": 65536, "mtime": 2e9},
            {"path": "y", "bytes": 124928, "stamp": 65536, "mtime": 2e9}]
    analyse(same)
    check("identical sizes do not trigger T2",
          sum(1 for r in same if r["t2"]), 0)
    check("but T3 still catches them",
          sum(1 for r in same if r["t3"]), 2)

    check("a non-PE yields no stamp", coff_stamp(b"not a pe"), None)
    check("an MZ with no PE header yields no stamp",
          coff_stamp(b"MZ" + bytes(0x3E) + b"\x00\x01\x00\x00"), None)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-52s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?")
    ap.add_argument("--expect-false", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.root == "selftest":
        return selftest()
    if not args.root:
        raise SystemExit("stampcheck: a root is required (or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
