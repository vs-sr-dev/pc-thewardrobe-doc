#!/usr/bin/env python3
"""qinv.py -- the installation, split into the layers that made it.

This object is one directory of 45 files written by three groups of people
twenty-two years apart, plus the machine that installed it this morning. Every
figure in this repository has to name its layer, so the split has to be a tool
and not a paragraph.

The assignment is by name, and the rules are printed with the result so that a
reader can disagree with a specific line instead of with the total. `Manual.pdf`
is the one genuinely arguable case and it is flagged rather than buried.

    python tools/qinv.py _game
    python tools/qinv.py _game --mtimes
    python tools/qinv.py _game --check 237605368
"""

import argparse
import datetime
import os
import sys
from collections import Counter, defaultdict

SEP = chr(92)

# (layer, predicate description, matcher)
RULES = [
    ("game", "queen.1 and queen.ini -- the 1995 data and the path the "
             "installer wrote for it",
     lambda p: p in ("queen.1", "queen.ini")),
    ("scummvm", "everything under scummvm/ -- the 2017 interpreter",
     lambda p: p.startswith("scummvm/")),
    ("inno", "unins000.* -- the Inno Setup uninstaller",
     lambda p: os.path.basename(p).lower().startswith("unins000.")),
    ("gog", "the rest -- the 2018 shop wrapper, including Manual.pdf",
     lambda p: True),
]


def walk(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace(SEP, "/").replace(os.sep, "/")
            st = os.stat(p)
            out.append((rel, st.st_size, st.st_mtime))
    return out


def layer_of(rel):
    for name, _doc, pred in RULES:
        if pred(rel):
            return name
    return "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--mtimes", action="store_true")
    ap.add_argument("--check", type=int, default=None)
    a = ap.parse_args()

    rows = walk(a.root)
    total = sum(r[1] for r in rows)

    print("root                %s" % a.root)
    print("files               %d" % len(rows))
    print("bytes               %d" % total)
    ndirs = len({os.path.dirname(r[0]) for r in rows})
    print("directories         %d (counting the root)" % ndirs)
    print()

    print("the rules, in order; the first that matches wins")
    for name, doc, _ in RULES:
        print("  %-8s %s" % (name, doc))
    print()

    byl = defaultdict(list)
    for rel, size, mt in rows:
        byl[layer_of(rel)].append((rel, size, mt))

    print("%-10s %5s %14s %10s" % ("layer", "files", "bytes", "share"))
    acc = 0
    for name, _doc, _ in RULES:
        g = byl.get(name, [])
        b = sum(x[1] for x in g)
        acc += b
        print("%-10s %5d %14d %9.4f %%" % (name, len(g), b, 100.0 * b / total))
    print("%-10s %5d %14d %9.4f %%" % ("sum", len(rows), acc,
                                       100.0 * acc / total))
    if acc != total:
        print("MISMATCH: layers do not close", file=sys.stderr)
        return 2
    if a.check is not None:
        print("check               %d expected, %d measured, %s"
              % (a.check, total, "equal" if a.check == total else "DIFFERENT"))
        if a.check != total:
            return 2

    if a.mtimes:
        print()
        c = Counter(datetime.datetime.fromtimestamp(r[2]).strftime(
            "%Y-%m-%d %H:%M:%S") for r in rows)
        print("distinct mtimes     %d" % len(c))
        for k in sorted(c):
            names = [r[0] for r in rows
                     if datetime.datetime.fromtimestamp(r[2]).strftime(
                         "%Y-%m-%d %H:%M:%S") == k]
            shown = ", ".join(names) if len(names) <= 4 else (
                "%d files" % len(names))
            print("  %s  %4d  %s" % (k, c[k], shown))
        span = max(r[2] for r in rows) - min(r[2] for r in rows)
        newest = [r for r in rows
                  if r[2] >= max(x[2] for x in rows) - 86400]
        nspan = max(r[2] for r in newest) - min(r[2] for r in newest)
        print("  full span         %.0f s" % span)
        print("  install-day span  %.0f s over %d files"
              % (nspan, len(newest)))

    print()
    print("%-10s %5s %14s" % ("extension", "files", "bytes"))
    ce = Counter()
    be = Counter()
    for rel, size, _ in rows:
        e = os.path.splitext(rel)[1].lower() or "(none)"
        ce[e] += 1
        be[e] += size
    for e, n in sorted(ce.items(), key=lambda kv: -be[kv[0]]):
        print("%-10s %5d %14d %9.4f %%" % (e, n, be[e], 100.0 * be[e] / total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
