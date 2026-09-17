#!/usr/bin/env python3
"""depotsplit.py -- does a shop's depot boundary fall on a directory boundary?

`steamacf.py` closes a manifest's `SizeOnDisk` against a counted tree, and
`pc-rpgmaker2000-doc/docs/03` said what that is worth: **a single-depot closure
says nothing about any individual file.** An object with two depots can say
more, and only if somebody checks: if each depot's declared size equals the
counted weight of a named subtree, then the shop's partition and the
filesystem's partition are the same partition, and each depot's total is a
statement about a smaller population than the whole tree.

This tool makes that a command rather than a subtraction. Every group is
counted by walking the tree; the groups must be disjoint and must cover every
file; and each group's counted bytes are compared with a declared depot size.
**Assigning a subtree to a depot by taking the tree's total and subtracting the
other depot is not a measurement and this tool cannot be made to do it.**

    python tools/depotsplit.py --root rpgmakerxp-steam \\
        --group 235903=rtp --group 235902=.,System,Bonus \\
        --declare 235903=21322110 --declare 235902=5593273
    python tools/depotsplit.py --selftest
"""
import argparse
import os
import sys


def walk(root):
    rows = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            rows.append((rel, os.path.getsize(p)))
    if not rows:
        sys.exit("depotsplit: no files under %r -- refusing to report a clean "
                 "table over an empty population" % root)
    return rows


def top(rel):
    return rel.split("/", 1)[0] if "/" in rel else "."


def assign(rows, groups):
    """groups: {label: [top-level names]}. Returns {label: (files, bytes)} and
    the list of files no group claimed."""
    where = {}
    for label, names in groups.items():
        for n in names:
            if n in where:
                sys.exit("depotsplit: %r is claimed by both %s and %s"
                         % (n, where[n], label))
            where[n] = label
    counts = {label: [0, 0] for label in groups}
    orphan = []
    for rel, size in rows:
        label = where.get(top(rel))
        if label is None:
            orphan.append(rel)
            continue
        counts[label][0] += 1
        counts[label][1] += size
    return counts, orphan


# --------------------------------------------------------------- by PATH
#
# Added on pc-rpgmakervxace-doc, where the tool could not express the object at
# all. That object has six depots, and:
#
#   * `dlc\Bonus` sits in a directory called `dlc\` and belongs to the BASE
#     depot, while its three siblings are each a depot of their own -- so one
#     top-level name spans two depots;
#   * depot 220708 is the language packs, and exactly ONE FILE of it is
#     installed -- so a depot is a single file inside a directory whose other
#     files belong elsewhere.
#
# A grouping by top-level component cannot say either thing. `--path` takes a
# path PREFIX (a directory, or one file), longest match wins, and `--rest`
# names the group that takes whatever is left. That is enough to close six
# depots that do not follow directory boundaries -- and the closure is still
# done by WALKING, never by subtracting one declared figure from another.

def assign_paths(rows, prefixes, rest_label=None):
    """prefixes: [(label, path-prefix)]. Longest prefix wins, so a file group
    can sit inside a directory group. Returns {label: [files, bytes]} and the
    orphans."""
    ordered = sorted(prefixes, key=lambda lp: -len(lp[1]))
    labels = {lp[0] for lp in prefixes}
    if rest_label:
        labels.add(rest_label)
    counts = {label: [0, 0] for label in labels}
    orphan = []
    for rel, size in rows:
        hit = None
        for label, pref in ordered:
            if rel == pref or rel.startswith(pref.rstrip("/") + "/"):
                hit = label
                break
        if hit is None:
            if rest_label:
                hit = rest_label
            else:
                orphan.append(rel)
                continue
        counts[hit][0] += 1
        counts[hit][1] += size
    return counts, orphan


def by_path(args):
    prefixes = []
    for spec in args.path:
        if "=" not in spec:
            sys.exit("depotsplit: --path wants LABEL=some/path, got %r" % spec)
        label, p = spec.split("=", 1)
        prefixes.append((label, p.strip().replace(os.sep, "/").strip("/")))
    declared = {}
    for d in args.declare:
        if "=" not in d:
            sys.exit("depotsplit: --declare wants LABEL=BYTES, got %r" % d)
        label, n = d.split("=", 1)
        declared[label] = int(n)

    rows = walk(args.root)
    total_files = len(rows)
    total_bytes = sum(s for _r, s in rows)
    counts, orphan = assign_paths(rows, prefixes, args.rest)

    by_label = {}
    for label, pref in prefixes:
        by_label.setdefault(label, []).append(pref)
    if args.rest:
        by_label.setdefault(args.rest, ["<everything else>"])

    print("root      : %s" % args.root)
    print("the tree  : %d files, %d bytes" % (total_files, total_bytes))
    print("grouped by PATH PREFIX, longest match first")
    print()
    print("  %-10s %7s %12s %12s %9s  %s"
          % ("label", "files", "counted", "declared", "residue", "paths"))
    bad = 0
    for label in sorted(counts):
        f, b = counts[label]
        dec = declared.get(label)
        res = "-" if dec is None else "%d" % (b - dec)
        if dec is not None and b != dec:
            bad += 1
        print("  %-10s %7d %12d %12s %9s  %s"
              % (label, f, b, "-" if dec is None else dec, res,
                 ", ".join(by_label.get(label, []))))
    sf = sum(c[0] for c in counts.values())
    sb = sum(c[1] for c in counts.values())
    print("  %-10s %7d %12d" % ("SUM", sf, sb))
    print()
    print("  every file claimed by exactly one group : %s"
          % (not orphan and sf == total_files))
    print("  files no group claimed                  : %d" % len(orphan))
    for rel in orphan[:12]:
        print("     %s" % rel)
    print("  the groups cover the tree, residue      : %d"
          % (total_bytes - sb))
    print()
    if declared:
        print("  groups whose counted bytes differ from the declared "
              "figure : %d" % bad)
    print()
    print("  Every figure above was produced by WALKING. No group's total is")
    print("  the tree's total minus another group's, and this tool cannot be")
    print("  made to produce one that way.")
    return 1 if (bad or orphan) else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root")
    ap.add_argument("--group", action="append", default=[],
                    metavar="LABEL=a,b,c")
    ap.add_argument("--path", action="append", default=[],
                    metavar="LABEL=some/path",
                    help="a path PREFIX rather than a top-level component. "
                         "Longest match wins, so a single file can be its own "
                         "group inside a directory that is another group. "
                         "Repeatable, and may be given more than once for the "
                         "same label.")
    ap.add_argument("--rest", metavar="LABEL",
                    help="the group that takes every file no --path claimed. "
                         "Without it an unclaimed file is an orphan and the "
                         "tool fails.")
    ap.add_argument("--declare", action="append", default=[],
                    metavar="LABEL=BYTES")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.root:
        sys.exit("depotsplit: --root is required")
    if args.group and args.path:
        sys.exit("depotsplit: --group and --path are two ways of saying the "
                 "same thing and mixing them would make the partition "
                 "ambiguous. Use one.")
    if args.path:
        return by_path(args)
    if os.path.isfile(args.root):
        sys.exit("depotsplit: --root wants a directory, not a file: %s"
                 % args.root)
    groups = {}
    for g in args.group:
        if "=" not in g:
            sys.exit("depotsplit: --group wants LABEL=a,b,c, got %r" % g)
        label, names = g.split("=", 1)
        groups[label] = [n.strip() for n in names.split(",") if n.strip()]
    declared = {}
    for d in args.declare:
        if "=" not in d:
            sys.exit("depotsplit: --declare wants LABEL=BYTES, got %r" % d)
        label, n = d.split("=", 1)
        declared[label] = int(n)

    rows = walk(args.root)
    total_files = len(rows)
    total_bytes = sum(s for _r, s in rows)
    counts, orphan = assign(rows, groups)

    print("root      : %s" % args.root)
    print("the tree  : %d files, %d bytes" % (total_files, total_bytes))
    print()
    print("  %-10s %-28s %7s %12s %12s %9s"
          % ("label", "top-level names", "files", "counted", "declared",
             "residue"))
    bad = 0
    for label in sorted(groups):
        f, b = counts[label]
        dec = declared.get(label)
        res = "" if dec is None else "%d" % (b - dec)
        if dec is not None and b != dec:
            bad += 1
        print("  %-10s %-28s %7d %12d %12s %9s"
              % (label, ",".join(groups[label]), f, b,
                 "-" if dec is None else dec, res))
    sf = sum(c[0] for c in counts.values())
    sb = sum(c[1] for c in counts.values())
    print("  %-10s %-28s %7d %12d" % ("SUM", "", sf, sb))
    print()
    print("  files no group claimed : %d" % len(orphan))
    for r in orphan[:10]:
        print("     %s" % r)
    print("  the groups cover the tree : %s   residue %d files, %d bytes"
          % (sf == total_files and sb == total_bytes,
             sf - total_files, sb - total_bytes))
    if declared:
        print("  every declared size equals its counted subtree : %s"
              % (bad == 0))
    if bad or orphan or sf != total_files or sb != total_bytes:
        print("  THE SPLIT DOES NOT CLOSE", file=sys.stderr)
        return 1
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    rows = [("a/x", 10), ("a/y", 20), ("b/z", 5), ("top.txt", 1)]
    counts, orphan = assign(rows, {"one": ["a"], "two": ["b", "."]})
    ok("a top-level directory groups its files",
       counts["one"] == [2, 30], str(counts["one"]))
    ok("a root file is grouped under '.'",
       counts["two"] == [2, 6], str(counts["two"]))
    ok("nothing is orphaned when the groups cover the tree", not orphan)
    counts, orphan = assign(rows, {"one": ["a"]})
    ok("an unclaimed subtree is reported and not folded in",
       len(orphan) == 2, str(orphan))
    ok("a file at the root has top-level '.'", top("top.txt") == ".")
    ok("a nested file takes its first component", top("a/b/c") == "a")
    ok("the two depots of this object sum to the tree",
       21322110 + 5593273 == 26915383,
       str(21322110 + 5593273))

    # ---- --path, added on pc-rpgmakervxace-doc. Eight checks, of which three
    # assert the two things --group could NOT express: one top-level name
    # spanning two groups, and a single FILE being a group inside a directory
    # that is another group.
    prows = [("dlc/Bonus/a.png", 10), ("dlc/Bonus/b.png", 20),
             ("dlc/Pack/c.png", 5), ("rtp/d.ogg", 7),
             ("RPGVXAceITA.dll", 100), ("RPGVXAceENU.dll", 200),
             ("Projects/cd32.zip", 3)]
    c, orp = assign_paths(prows, [("PACK", "dlc/Pack"), ("RTP", "rtp")],
                          "BASE")
    ok("PATH: one top-level name can span two groups -- dlc/Pack is its own "
       "and dlc/Bonus falls to the rest",
       c["PACK"] == [1, 5] and c["BASE"][0] == 5, str(c))
    ok("PATH: --rest takes everything unclaimed and nothing is orphaned",
       not orp and sum(x[0] for x in c.values()) == len(prows), str(orp))
    c, orp = assign_paths(prows, [("LANG", "RPGVXAceITA.dll")], "BASE")
    ok("PATH: a single FILE is a group of one, and its sibling is not in it",
       c["LANG"] == [1, 100], str(c["LANG"]))
    c, orp = assign_paths(prows, [("OUTER", "dlc"),
                                  ("INNER", "dlc/Bonus/a.png")], "BASE")
    ok("PATH: the LONGEST prefix wins, so a file inside a claimed directory "
       "can belong to a different group",
       c["INNER"] == [1, 10] and c["OUTER"] == [2, 25], str(c))
    c, orp = assign_paths(prows, [("RTP", "rtp/")], "BASE")
    ok("PATH: a trailing slash on a prefix does not change what it claims",
       c["RTP"] == [1, 7], str(c["RTP"]))
    c, orp = assign_paths(prows, [("X", "rt")], "BASE")
    ok("PATH: a prefix must end on a path separator -- 'rt' does NOT claim "
       "'rtp/d.ogg'",
       c["X"] == [0, 0], str(c["X"]))
    c, orp = assign_paths(prows, [("RTP", "rtp")], None)
    ok("PATH: without --rest an unclaimed file is an ORPHAN and is not "
       "silently folded in",
       len(orp) == 6, str(len(orp)))
    ok("PATH: the walked groups of this object sum to SizeOnDisk plus the "
       "owner's two files",
       62332617 + 202842120 + 2945024 + 57491682 + 15516018 + 1386605
       + 208338 == 342722404,
       str(62332617 + 202842120 + 2945024 + 57491682 + 15516018 + 1386605
           + 208338))
    ok("and their file counts do too", 882 + 31 == 913)

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
