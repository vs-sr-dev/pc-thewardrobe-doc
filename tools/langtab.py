#!/usr/bin/env python3
"""langtab.py -- the five LANG tables of Theme Park, which are the game's words.

`LANG0-0.DAT` through `LANG4-0.DAT` are five languages of one string table.
The format is derived here and is three fields deep:

    +0        u16       group count, 26 on all five files
    +2        u16 x 26  the number of strings in each group
    +54       ...       the strings, NUL-terminated, back to back, in group
                        order

The check that fixes it: the counts sum to the number of NUL-terminated
strings, on 5 of 5 files, with no residue and no leftover group. Nothing was
fitted -- if the first `u16` had been anything but a group count the sum would
not have landed.

What it is worth is not the format, it is that **group 5 is the 29 ride
descriptions in ride-index order**, which is the naming layer this object was
said not to have. `RIDEANI.NNN` is indexed by that same number: the executable
builds `data/rideani.` + `%s%03d`, and a save file carries the same 29 names at
a 200-byte stride. Three witnesses, one order.

    python tools/langtab.py <file> --groups        the 26 group sizes
    python tools/langtab.py <file> --group N       one group, numbered
    python tools/langtab.py <file> --find TEXT
    python tools/langtab.py --census <dir>         all five, side by side
    python tools/langtab.py --selftest
"""
import argparse
import os
import struct
import sys


class Refused(Exception):
    pass


def parse(d):
    if len(d) < 4:
        raise Refused("shorter than a group count")
    n = struct.unpack_from("<H", d, 0)[0]
    if not 0 < n < 1024:
        raise Refused("group count %d is implausible" % n)
    if 2 + 2 * n > len(d):
        raise Refused("the %d group counts do not fit in %d bytes" % (n, len(d)))
    counts = list(struct.unpack_from("<%dH" % n, d, 2))
    body = d[2 + 2 * n:]
    parts = body.split(b"\0")
    # a trailing NUL leaves one empty element that is not a string
    if parts and parts[-1] == b"":
        parts = parts[:-1]
    if sum(counts) > len(parts):
        raise Refused("counts sum to %d but only %d strings are present"
                      % (sum(counts), len(parts)))
    groups = []
    i = 0
    for c in counts:
        groups.append([s.decode("latin-1") for s in parts[i:i + c]])
        i += c
    return {"n": n, "counts": counts, "groups": groups,
            "strings": len(parts), "residue": len(parts) - sum(counts)}


def cmd_groups(path):
    t = parse(open(path, "rb").read())
    print("%s  %d groups, %d strings, residue %d"
          % (os.path.basename(path), t["n"], t["strings"], t["residue"]))
    for i, g in enumerate(t["groups"]):
        first = g[0][:52] if g else ""
        print("  %2d  %5d  %s" % (i, len(g), first))
    return 0


def cmd_group(path, n):
    t = parse(open(path, "rb").read())
    for i, s in enumerate(t["groups"][n]):
        print("%4d  %s" % (i, s))
    return 0


def cmd_find(path, text):
    t = parse(open(path, "rb").read())
    up = text.upper()
    for gi, g in enumerate(t["groups"]):
        for i, s in enumerate(g):
            if up in s.upper():
                print("group %2d index %4d : %s" % (gi, i, s))
    return 0


def cmd_census(root):
    print("%-14s %8s %7s %8s %8s  %s"
          % ("file", "bytes", "groups", "strings", "residue", "group 0 [1]"))
    for n in sorted(os.listdir(root)):
        if not n.upper().startswith("LANG"):
            continue
        p = os.path.join(root, n)
        d = open(p, "rb").read()
        try:
            t = parse(d)
        except Refused as e:
            print("%-14s REFUSED %s" % (n, e))
            continue
        print("%-14s %8d %7d %8d %8d  %s"
              % (n, len(d), t["n"], t["strings"], t["residue"],
                 t["groups"][0][1] if len(t["groups"][0]) > 1 else ""))
    return 0


def cmd_selftest():
    def build(counts, strings, n=None):
        n = len(counts) if n is None else n
        head = struct.pack("<H", n) + struct.pack("<%dH" % len(counts), *counts)
        return head + b"\0".join(s.encode() for s in strings) + b"\0"
    cases = [
        ("two groups that close", build([2, 1], ["A", "B", "C"]), True),
        ("a group count of zero", build([], [], 0), False),
        ("counts that ask for more strings than exist",
         build([9], ["A"]), False),
        ("empty file", b"", False),
        ("a group count of 40000", struct.pack("<H", 40000), False),
        ("one group of one", build([1], ["ONLY"]), True),
    ]
    fails = 0
    for name, data, ok in cases:
        try:
            parse(data)
            got, why = True, ""
        except Refused as e:
            got, why = False, str(e)
        mark = "ok " if got == ok else "FAIL"
        if got != ok:
            fails += 1
        print("%s  %-46s expected %-7s got %-7s %s"
              % (mark, name, "accept" if ok else "refuse",
                 "accept" if got else "refuse", why))
    t = parse(cases[0][1])
    good = t["groups"] == [["A", "B"], ["C"]] and t["residue"] == 0
    print("%s  %-46s %s" % ("ok " if good else "FAIL",
                            "the accepted table splits into the right groups",
                            "[[A,B],[C]] residue 0" if good else repr(t)))
    if not good:
        fails += 1
    print()
    print("%d specimens, %d must be accepted, %d failures"
          % (len(cases) + 1, sum(1 for c in cases if c[2]) + 1, fails))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--groups", action="store_true")
    ap.add_argument("--group", type=int)
    ap.add_argument("--find")
    ap.add_argument("--census")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    if a.selftest:
        return cmd_selftest()
    if a.census:
        return cmd_census(a.census)
    if not a.path:
        print(__doc__)
        return 2
    if a.group is not None:
        return cmd_group(a.path, a.group)
    if a.find:
        return cmd_find(a.path, a.find)
    return cmd_groups(a.path)


if __name__ == "__main__":
    sys.exit(main())
