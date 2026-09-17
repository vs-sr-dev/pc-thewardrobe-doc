#!/usr/bin/env python3
"""rooms.py - the shape of the game, read out of the names and the symbols.

This engine keeps no central table of what a room is made of. The binding
between a location and its background, its geometry, its script, its dialogue
and its sprites is the **8.3 filename convention** and nothing else, so the
structure of the game is recoverable from the volume directories alone, without
decompressing anything.

Three views:

    families  <objdir>        the S<n> file families, one row per room number
    resident  <objdir>        names by how many of the five floppies carry them
    symbols   <membersdir>    the `super.` global namespace, over distinct .OVL
    selftest                  controls that must behave

`families` and `resident` read the directories of `D1`..`D5` and touch no
member. `symbols` needs the members unpacked first:

    python tools/unpack.py extract cruise-for-a-corpse _work/members
    python tools/rooms.py symbols _work/members

The counts printed by `symbols` are over **distinct member names**, one instance
each, because 88 `.OVL` entries carry only 82 distinct names and counting the
entries would weight whatever happens to be duplicated across floppies.
"""
import sys
import os
import re
import glob
import argparse
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vol import Volume, volume_paths  # noqa: E402

# S<digits> then an optional suffix, then an extension: S27A.PI1, S33SP01.SET
ROOM = re.compile(r"^S(\d{1,3})([A-Z0-9_]*)\.([A-Z0-9]{1,3})$")
SUPER = re.compile(rb"super\.[A-Za-z_]+")

CORE = ("PI1", "CTP", "OVL", "FR", "SET")


def directories(objdir):
    """name -> set of volumes carrying it, read from the directories only."""
    where = collections.defaultdict(set)
    for p in volume_paths([objdir]):
        v = Volume(p)
        probs = v.check()
        if probs:
            raise SystemExit("%s did not close: %s" % (v.name, probs[0]))
        for m in v.members:
            where[m.name].add(v.name)
    return where


def cmd_families(args):
    where = directories(args.path)
    fam = collections.defaultdict(lambda: collections.defaultdict(list))
    for n in where:
        m = ROOM.match(n)
        if m:
            fam[int(m.group(1))][m.group(3)].append(n)
    print("%-6s %4s %4s %4s %4s %4s   %s"
          % ("S<n>", "PI1", "CTP", "OVL", "FR", "SET", "volumes"))
    complete = scenes = 0
    ctp = 0
    for k in sorted(fam):
        d = fam[k]
        counts = [len(d.get(e, [])) for e in CORE]
        vols = sorted({v for e in d for n in d[e] for v in where[n]})
        print("  S%-4d %4d %4d %4d %4d %4d   %s"
              % (k, counts[0], counts[1], counts[2], counts[3], counts[4],
                 ",".join(vols)))
        ctp += counts[1]
        if counts[0] and counts[1] and counts[2] and counts[3]:
            complete += 1
        elif counts[2] and counts[3] and not counts[0] and not counts[1]:
            scenes += 1
    print()
    print("room-numbered families            : %d" % len(fam))
    print("  with background, geometry,")
    print("  script and dialogue             : %d" % complete)
    print("  script and dialogue ONLY        : %d" % scenes)
    print("  neither                         : %d"
          % (len(fam) - complete - scenes))
    print(".CTP members inside those families: %d" % ctp)
    total_ctp = sum(1 for n in where if n.endswith(".CTP"))
    print(".CTP members in the whole object  : %d  (accounted for: %s)"
          % (total_ctp, "yes" if ctp == total_ctp else "NO"))
    return 0


def cmd_resident(args):
    where = directories(args.path)
    by = collections.Counter(len(v) for v in where.values())
    print("names by how many volumes carry them:")
    for k in sorted(by, reverse=True):
        print("   on %d volume(s): %4d names" % (k, by[k]))
    print()
    nvol = len({v for vs in where.values() for v in vs})
    for level in (nvol, nvol - 1):
        names = sorted(n for n in where if len(where[n]) == level)
        print("on %d of %d volumes - %d names:" % (level, nvol, len(names)))
        for n in names:
            print("   %s" % n)
        print()
    return 0


def cmd_symbols(args):
    seen = {}
    for f in sorted(glob.glob(os.path.join(args.path, "**", "*.OVL"),
                              recursive=True)):
        seen.setdefault(os.path.basename(f), f)
    sup = collections.Counter()
    users = 0
    for n, f in sorted(seen.items()):
        data = open(f, "rb").read()
        hits = SUPER.findall(data)
        if hits:
            users += 1
        for h in hits:
            sup[h.decode()] += 1
    print("distinct .OVL members read      : %d" % len(seen))
    print("of which reference `super.`     : %d" % users)
    print("distinct `super.` symbols       : %d" % len(sup))
    print("total references                : %d" % sum(sup.values()))
    print()
    print("%-24s %s" % ("symbol", "references"))
    for k, v in sup.most_common():
        print("  %-22s %d" % (k, v))
    return 0


def cmd_selftest(args):
    fired = total = 0

    def check(label, got, want):
        nonlocal fired, total
        total += 1
        ok = got == want
        fired += ok
        print("%-46s %-18s %s"
              % (label, repr(got), "ok" if ok else "<<< FAIL, wanted %r" % (want,)))

    # the family pattern must accept what it is for and refuse what it is not
    check("S27A.PI1 is a room file", bool(ROOM.match("S27A.PI1")), True)
    check("S133.FR is a room file", bool(ROOM.match("S133.FR")), True)
    check("S33SP01.SET is a room file", bool(ROOM.match("S33SP01.SET")), True)
    check("SHIP.PI1 is NOT room-numbered", bool(ROOM.match("SHIP.PI1")), False)
    check("SUZAN.FR is NOT room-numbered", bool(ROOM.match("SUZAN.FR")), False)
    check("SPACE_FL.H32 is NOT room-numbered",
          bool(ROOM.match("SPACE_FL.H32")), False)
    check("the number is read, not the suffix",
          ROOM.match("S27A.PI1").group(1), "27")
    # the symbol pattern
    check("finds a dotted symbol",
          SUPER.findall(b"\x00super.raoul\x00"), [b"super.raoul"])
    check("does not match bare `super`", SUPER.findall(b"super\x00"), [])
    check("does not run past the symbol",
          SUPER.findall(b"super.salle1"), [b"super.salle"])
    print()
    print("controls that behaved: %d of %d" % (fired, total))
    return 0 if fired == total else 1


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("families", "resident", "symbols",
                                    "selftest"))
    ap.add_argument("path", nargs="?")
    args = ap.parse_args()
    if args.cmd == "selftest":
        return cmd_selftest(args)
    if not args.path:
        ap.error("%s needs a directory" % args.cmd)
    return {"families": cmd_families, "resident": cmd_resident,
            "symbols": cmd_symbols}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
