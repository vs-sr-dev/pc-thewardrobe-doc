#!/usr/bin/env python3
"""crossnames.py -- compare two objects' sha1 lists by CONTENT and then by
NAME, and split both sides of the comparison.

`crossall.py` answers "how many of my hashes appear anywhere in the
collection". That is the question about the collection. This answers the two
questions about the objects:

  * **what does not cross** -- because a chapter about what is new in a product
    must not use the whole tree as its denominator when half the tree is
    somebody else's chapter;
  * **what crosses under a different name** -- because two file names over one
    set of bytes is a publisher's decision, and the decision is legible.

THE RENAME CLASSES ARE RULES, NOT A HAND-SORTED LIST
-----------------------------------------------------
Every renamed pair is put in exactly one class by a rule that can be read:

    same          the two base names are equal
    spaced        inserting one space before a trailing run of digits in the
                  OLD name yields the NEW name  (`Boss1` -> `Boss 1`)
    prefixed      the new name is the old name with a leading `SE`, after the
                  spacing rule has been allowed to apply
    retranslated  everything else

The counts are printed per class and their sum is checked against the renamed
total, because 50 + 3 + 38 = 91 is exactly the kind of arithmetic this pipeline
gets wrong when it is done by eye.

    python tools/crossnames.py notes/sha1-all.txt ../pc-rpgmaker2000-doc/notes/sha1-all.txt
    python tools/crossnames.py A B --expect-crossing 368 --expect-renamed 91
    python tools/crossnames.py --selftest
"""
import argparse
import collections
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

ROW = re.compile(r"^([0-9a-f]{40})\s+(\d+)\s+(.*)$")
TRAILING_DIGITS = re.compile(r"^(.*?)(\d+)$")


def read_list(path):
    """{sha1: [(bytes, path)]} from a hashall-style listing."""
    out = collections.defaultdict(list)
    n = 0
    for line in open(path, encoding="utf-8", errors="replace"):
        m = ROW.match(line.rstrip("\n"))
        if not m:
            continue
        out[m.group(1)].append((int(m.group(2)), m.group(3)))
        n += 1
    if not out:
        raise SystemExit("crossnames: no hash rows parsed from %s -- refusing "
                         "to report an empty comparison" % path)
    return out, n


def stem(path):
    return os.path.splitext(os.path.basename(path))[0]


def ext(path):
    return os.path.splitext(path)[1].lower() or "(none)"


def classify(old, new):
    if old == new:
        return "same"
    m = TRAILING_DIGITS.match(old)
    spaced = "%s %s" % (m.group(1), m.group(2)) if m else None
    if spaced == new:
        return "spaced"
    for base in (old, spaced):
        if base and "SE" + base == new:
            return "prefixed"
    return "retranslated"


def run(args):
    mine, nmine = read_list(args.mine)
    theirs, ntheirs = read_list(args.theirs)
    crossing = sorted(set(mine) & set(theirs))
    only_mine = sorted(set(mine) - set(theirs))

    print("mine   : %s   %d rows, %d distinct sha1" % (args.mine, nmine,
                                                       len(mine)))
    print("theirs : %s   %d rows, %d distinct sha1" % (args.theirs, ntheirs,
                                                       len(theirs)))
    print()
    print("crossing     : %d of %d" % (len(crossing), len(mine)))
    print("NOT crossing : %d of %d" % (len(only_mine), len(mine)))
    print("the two sum to my distinct hashes : %s"
          % (len(crossing) + len(only_mine) == len(mine)))
    print()

    for label, keys in (("CROSSING", crossing), ("NOT CROSSING", only_mine)):
        rows = collections.Counter()
        byte_rows = collections.Counter()
        for k in keys:
            size, path = mine[k][0]
            rows[ext(path)] += 1
            byte_rows[ext(path)] += size
        print("-- %s, by extension (one row per distinct hash) ----" % label)
        tot = totb = 0
        for e, c in rows.most_common():
            print("   %-8s %5d files %12d bytes" % (e, c, byte_rows[e]))
            tot += c
            totb += byte_rows[e]
        print("   %-8s %5d        %12d" % ("TOTAL", tot, totb))
        print()

    print("-- the crossing hashes, by name -------------------------------")
    classes = collections.Counter()
    examples = collections.defaultdict(list)
    for k in crossing:
        mine_name = stem(mine[k][0][1])
        their_name = stem(theirs[k][0][1])
        c = classify(their_name, mine_name)
        classes[c] += 1
        examples[c].append((their_name, mine_name))
    same = classes["same"]
    renamed = sum(v for c, v in classes.items() if c != "same")
    print("   same base name in both objects : %d" % same)
    print("   renamed                        : %d" % renamed)
    for c in ("spaced", "prefixed", "retranslated"):
        print("      %-14s %4d" % (c, classes[c]))
    total_classes = classes["spaced"] + classes["prefixed"] + \
        classes["retranslated"]
    print("   the three classes sum to the renamed total : %s  (%d + %d + %d "
          "= %d)" % (total_classes == renamed, classes["spaced"],
                     classes["prefixed"], classes["retranslated"],
                     total_classes))
    print("   same + renamed = crossing : %s"
          % (same + renamed == len(crossing)))
    print()
    for c in ("spaced", "prefixed", "retranslated"):
        if not examples[c]:
            continue
        print("   -- %s" % c)
        show = sorted(examples[c])
        if c != "retranslated" and not args.all:
            show = show[:6]
        for a, b in show:
            print("      %-24s -> %s" % (a, b))
        if len(examples[c]) > len(show):
            print("      ... %d more" % (len(examples[c]) - len(show)))
        print()

    bad = []
    if args.expect_crossing is not None and len(crossing) != args.expect_crossing:
        bad.append("--expect-crossing %d : got %d" % (args.expect_crossing,
                                                      len(crossing)))
    if args.expect_renamed is not None and renamed != args.expect_renamed:
        bad.append("--expect-renamed %d : got %d" % (args.expect_renamed,
                                                     renamed))
    if bad:
        for b in bad:
            print("FATAL: %s" % b)
        raise SystemExit(1)
    return 0


def selftest():
    import shutil
    import tempfile
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    check("an identical name is 'same'", classify("Boss1", "Boss1"), "same")
    check("a space before a trailing number is 'spaced'",
          classify("Boss1", "Boss 1"), "spaced")
    check("a multi-digit trailing number spaces too",
          classify("Track12", "Track 12"), "spaced")
    check("an SE prefix is 'prefixed'", classify("Sea", "SESea"), "prefixed")
    check("an SE prefix over a spacing is 'prefixed'",
          classify("Rain1", "SERain 1"), "prefixed")
    check("a different word is 'retranslated'",
          classify("Devil", "Demon Lord"), "retranslated")
    check("a number that is not trailing does not space",
          classify("2003Sorrow", "2003 Sorrow"), "retranslated")
    check("SERain from Rain1 is retranslated, not prefixed",
          classify("Rain1", "SERain"), "retranslated")

    tmp = tempfile.mkdtemp(prefix="crossnames-")
    try:
        a = os.path.join(tmp, "a.txt")
        b = os.path.join(tmp, "b.txt")
        open(a, "w").write(
            "%s %12d  RTP/Music/Boss 1.mid\n" % ("a" * 40, 100) +
            "%s %12d  RTP/Music/SESea.wav\n" % ("b" * 40, 200) +
            "%s %12d  rpg2003.exe\n" % ("c" * 40, 300))
        open(b, "w").write(
            "%s %12d  RTP/Music/Boss1.mid\n" % ("a" * 40, 100) +
            "%s %12d  RTP/Music/Sea.wav\n" % ("b" * 40, 200) +
            "%s %12d  rpg2000.exe\n" % ("d" * 40, 400))
        mine, n = read_list(a)
        theirs, n2 = read_list(b)
        check("three rows parsed", n, 3)
        check("three distinct hashes", len(mine), 3)
        check("two cross", len(set(mine) & set(theirs)), 2)
        check("one does not", len(set(mine) - set(theirs)), 1)
        cross = sorted(set(mine) & set(theirs))
        cl = [classify(stem(theirs[k][0][1]), stem(mine[k][0][1]))
              for k in cross]
        check("the two crossings classify", sorted(cl),
              ["prefixed", "spaced"])

        empty = os.path.join(tmp, "empty.txt")
        open(empty, "w").write("no hashes here\n")
        try:
            read_list(empty)
            got = "no exception"
        except SystemExit:
            got = "SystemExit"
        check("a listing with no hash rows is fatal", got, "SystemExit")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

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
    ap.add_argument("mine", nargs="?")
    ap.add_argument("theirs", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--expect-crossing", type=int)
    ap.add_argument("--expect-renamed", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.mine == "selftest":
        return selftest()
    if not args.mine or not args.theirs:
        raise SystemExit("crossnames: two hash listings are required "
                         "(or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
