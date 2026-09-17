#!/usr/bin/env python3
"""fourmanifests.py -- the four PlayOnline manifests, as four sets.

This object carries FOUR manifests, not one: `file.txt` and `patch.txt`
exist in the `FINAL FANTASY XI` branch and again in the `PlayOnlineViewer`
branch.  Each line is

    <22 characters>:<size in bytes>:<relative path>

and the file ends with a line `::`.  The 22-character field is MD5 in a
permuted base64 alphabet -- see `polhash.py`, which breaks it and
reproduces 61,301 of 61,301 fields exactly.

THE COMPARISON IS CASE-INSENSITIVE, AND THAT IS A CHOICE

The manifests declare `ImeUiDll.dll`; the disk carries `imeuidll.dll`.
Windows resolves those to the same file and a case-sensitive comparison
reports a declared-and-absent file where there is none.  This tool runs
BOTH comparisons and prints both, so that the number is never quoted
without the rule that produced it.

THE FOUR SETS

For each branch: what both manifests declare, what only one declares,
what the disk holds and neither declares, and -- the interesting one --
where the two manifests of the same branch disagree with each other.

Nothing is executed, nothing is contacted, nothing is written to the
object.

usage:
  fourmanifests.py ROOT [--out FILE]
       ROOT is the directory holding SquareEnix\\
"""

import argparse
import os
import sys
from collections import Counter

BRANCHES = [
    ("FINAL FANTASY XI", os.path.join("SquareEnix", "FINAL FANTASY XI")),
    ("PlayOnlineViewer", os.path.join("SquareEnix", "PlayOnlineViewer")),
]
FIELD = 22


def read_manifest(path):
    entries = []
    terminators = 0
    malformed = 0
    raw = open(path, "rb").read()
    crlf = raw.count(b"\r\n")
    lf = raw.count(b"\n")
    assert lf > 0, "%s has no LF: a CRLF-only reader would return one entry" % path
    eol = "CRLF" if crlf == lf else ("LF" if crlf == 0 else "mixed")
    for line in raw.split(b"\n"):
        line = line.rstrip(b"\r")
        if not line:
            continue
        if line == b"::":
            terminators += 1
            continue
        try:
            parts = line.decode("ascii").split(":", 2)
        except UnicodeDecodeError:
            malformed += 1
            continue
        if len(parts) != 3 or not parts[1].isdigit():
            malformed += 1
            continue
        entries.append((parts[0], int(parts[1]), parts[2]))
    return entries, terminators, malformed, eol


def walk_branch(base):
    """{relpath_as_declared_style: size} for every file under base."""
    out = {}
    for dirpath, _d, files in os.walk(base):
        for fn in files:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, base).replace(os.sep, "/")
            try:
                out[rel] = os.path.getsize(p)
            except OSError:
                pass
    return out


def compare(entries, disk, fold):
    """Return (present, absent, mismatch, absent_list, mismatch_list)."""
    key = (lambda s: s.lower()) if fold else (lambda s: s)
    dk = {}
    for rel, sz in disk.items():
        dk.setdefault(key(rel), (rel, sz))
    present = absent = mismatch = 0
    absent_list = []
    mismatch_list = []
    for _f, sz, rel in entries:
        hit = dk.get(key(rel))
        if hit is None:
            absent += 1
            if len(absent_list) < 40:
                absent_list.append(rel)
            continue
        if hit[1] != sz:
            mismatch += 1
            if len(mismatch_list) < 40:
                mismatch_list.append((rel, sz, hit[1]))
            continue
        present += 1
    return present, absent, mismatch, absent_list, mismatch_list


def cmd(args):
    out = sys.stdout
    if args.out:
        out = open(args.out, "w", encoding="utf-8")

    def w(s=""):
        out.write(s + "\n")

    grand = Counter()
    for label, rel in BRANCHES:
        base = os.path.join(args.root, rel)
        disk = walk_branch(base)
        w("=" * 74)
        w("BRANCH %s" % label)
        w("=" * 74)
        w("  on disk: %d files, %d bytes"
          % (len(disk), sum(disk.values())))
        mans = {}
        for name in ("file.txt", "patch.txt"):
            p = os.path.join(base, name)
            e, t, m, eol = read_manifest(p)
            mans[name] = e
            w("  %-10s %7d entries, '::' x%d, malformed %d, line ending %s, "
              "%d declared bytes"
              % (name, len(e), t, m, eol, sum(x[1] for x in e)))
            grand[name + ":" + label] = len(e)
        a = {x[2].lower(): (x[0], x[1]) for x in mans["file.txt"]}
        b = {x[2].lower(): (x[0], x[1]) for x in mans["patch.txt"]}
        both = set(a) & set(b)
        same = sum(1 for k in both if a[k] == b[k])
        w()
        w("  file.txt is a subset of patch.txt : %s"
          % ("YES" if set(a) <= set(b) else "NO"))
        w("  named by both                     : %d" % len(both))
        w("    identical in hash and size      : %d" % same)
        w("    disagreeing                     : %d" % (len(both) - same))
        for k in sorted(both):
            if a[k] != b[k]:
                w("      %s" % k)
                w("        file.txt  %s %d" % (a[k][0], a[k][1]))
                w("        patch.txt %s %d" % (b[k][0], b[k][1]))
        only_a = sorted(set(a) - set(b))
        only_b = sorted(set(b) - set(a))
        w("  only in file.txt                  : %d" % len(only_a))
        for k in only_a[:12]:
            w("      %s" % k)
        w("  only in patch.txt                 : %d" % len(only_b))
        for k in only_b[:12]:
            w("      %s" % k)
        w()
        for name in ("file.txt", "patch.txt"):
            e = mans[name]
            for fold in (True, False):
                p_, ab, mm, abl, mml = compare(e, disk, fold)
                w("  %-10s %-18s present %6d  absent %3d  size mismatch %3d"
                  % (name, "case-insensitive" if fold else "case-SENSITIVE",
                     p_, ab, mm))
                if fold:
                    for x in abl[:8]:
                        w("        absent: %s" % x)
                    for rel2, dec, act in mml[:8]:
                        w("        mismatch: %s declared %d, on disk %d"
                          % (rel2, dec, act))
                elif ab or mm:
                    w("        (the extra absences are names that differ only "
                      "in case)")
        w()
        for name in ("file.txt", "patch.txt"):
            declared = set(x[2].lower() for x in mans[name])
            und = {k: v for k, v in disk.items() if k.lower() not in declared}
            w("  present and NOT declared by %-10s : %6d files, %12d bytes"
              % (name, len(und), sum(und.values())))
            by_ext = Counter()
            by_top = Counter()
            for k, v in und.items():
                by_ext[os.path.splitext(k)[1].lower() or "(none)"] += v
                by_top[k.split("/")[0] if "/" in k else "(root)"] += v
            w("     by extension: %s"
              % ", ".join("%s %d" % (e2, n)
                          for e2, n in by_ext.most_common(8)))
            w("     by directory: %s"
              % ", ".join("%s %d" % (e2, n)
                          for e2, n in by_top.most_common(8)))
        w()
    if args.out:
        out.close()
        print("wrote %s" % args.out)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--out")
    args = ap.parse_args()
    return cmd(args)


if __name__ == "__main__":
    sys.exit(main())
