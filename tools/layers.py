#!/usr/bin/env python3
"""layers.py -- what this disc is made of, grouped by directory before extension.

The rule this branch keeps re-learning is that a name is a claim and a directory
is a fact. `Micodb/` is not a database, `.001` is not a split archive, and `.sld`
is not a proprietary format; grouping by extension first would have produced
three wrong sentences. So this tool groups by first-level directory, then by
second-level directory inside it, and only then by extension.

It reads the extracted Joliet tree (real names), and it takes the sha1 list
`hashall.py` already produced so that duplicate payload is counted once and
reported separately rather than silently inflating a stratum.

    python tools/layers.py TREE --hashes notes/hashall.txt
    python tools/layers.py TREE --hashes notes/hashall.txt --dupes
    python tools/layers.py TREE --hashes notes/hashall.txt --products
"""

import argparse
import os
import sys
from collections import Counter, defaultdict


def walk(root):
    out = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            out.append((rel, os.path.getsize(p)))
    return out


def top(rel):
    return rel.split("/")[0] if "/" in rel else "(root)"


def second(rel):
    parts = rel.split("/")
    return "/".join(parts[:2]) if len(parts) > 2 else (
        parts[0] + "/" if len(parts) == 2 else "(root)")


def ext(rel):
    base = rel.rsplit("/", 1)[-1]
    return ("." + base.rsplit(".", 1)[-1].lower()) if "." in base else "(none)"


def table(title, counts, sizes, total_bytes, limit=None):
    print("-- %s %s" % (title, "-" * max(0, 66 - len(title))))
    rows = sorted(sizes.items(), key=lambda kv: -kv[1])
    if limit:
        rows = rows[:limit]
    print("  %-42s %6s %14s %10s" % ("", "files", "bytes", "share"))
    for k, b in rows:
        print("  %-42s %6d %14d %9.4f %%"
              % (k[:42], counts[k], b, 100.0 * b / total_bytes))
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tree")
    ap.add_argument("--hashes")
    ap.add_argument("--dupes", action="store_true")
    ap.add_argument("--products", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    files = walk(a.tree)
    total = sum(s for _p, s in files)
    print("files %d   bytes %d" % (len(files), total))
    print()

    tc, tb = Counter(), Counter()
    ec, eb = Counter(), Counter()
    sc, sb = Counter(), Counter()
    for rel, size in files:
        tc[top(rel)] += 1
        tb[top(rel)] += size
        ec[ext(rel)] += 1
        eb[ext(rel)] += size
        sc[second(rel)] += 1
        sb[second(rel)] += size

    table("first-level directory", tc, tb, total)
    table("second-level directory (top 24)", sc, sb, total, 24)
    table("extension (top 20)", ec, eb, total, 20)

    print("-- the largest files ------------------------------------------------")
    for rel, size in sorted(files, key=lambda kv: -kv[1])[:12]:
        print("  %-64s %12d %8.4f %%" % (rel[-64:], size, 100.0 * size / total))
    print()

    if a.hashes:
        by_hash = defaultdict(list)
        for line in open(a.hashes, encoding="utf-8", errors="replace"):
            parts = line.rstrip("\n").split(None, 2)
            if len(parts) == 3 and len(parts[0]) == 40:
                by_hash[parts[0]].append((parts[2], int(parts[1])))
        groups = [(h, v) for h, v in by_hash.items() if len(v) > 1]
        wasted = sum(v[0][1] * (len(v) - 1) for _h, v in groups)
        print("-- duplicate payload ------------------------------------------------")
        print("  distinct sha1                %d" % len(by_hash))
        print("  groups with more than one    %d" % len(groups))
        print("  extra copies                 %d"
              % sum(len(v) - 1 for _h, v in groups))
        print("  bytes in the extra copies    %d  (%.4f %%)"
              % (wasted, 100.0 * wasted / total))
        print()
        if a.dupes:
            for h, v in sorted(groups, key=lambda kv: -kv[1][0][1] * (len(kv[1]) - 1)):
                print("  %s  %d bytes x%d" % (h[:12], v[0][1], len(v)))
                for p, _s in sorted(v):
                    print("      %s" % p)
            print()

    if a.products:
        print("-- product directories, per declared category ------------------------")
        cats = defaultdict(list)
        for rel, size in files:
            parts = rel.split("/")
            if len(parts) >= 2:
                cats[parts[0]].append((parts[1], size))
            else:
                cats["(root)"].append((parts[0], size))
        for cat in sorted(cats):
            sub = Counter()
            subn = Counter()
            for name, size in cats[cat]:
                sub[name] += size
                subn[name] += 1
            print("  %s  --  %d entries" % (cat, len(sub)))
            for name, b in sorted(sub.items(), key=lambda kv: -kv[1]):
                print("      %-40s %5d %12d" % (name[:40], subn[name], b))
            print()


if __name__ == "__main__":
    main()
