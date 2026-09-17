#!/usr/bin/env python3
"""crossdisc.py -- does any file on this disc exist on any other disc measured
in this collection?

`discdiff.py` answers this for two extracted trees. It needs both trees on disk,
and fourteen extracted trees is a hundred gigabytes that nobody kept. What every
repository in the collection *did* keep is its sha1 list, in `notes/`, in one of
two shapes:

    <sha1>  <size>  <path>            (hashall.py, sha1-all.txt)
    <path> ... <sha1>                 (iso9660.py --sha1)

so this tool reads those instead. It is strictly weaker than `discdiff.py` --
it can only see discs whose repository wrote a hash list, and it says how many
that is -- and strictly cheaper, which is why it can cover the whole collection
instead of one pair.

Zero is a real answer here and has been three times in this branch. It is only
worth printing next to the number of files and the number of discs it was
looked for in, so that is what the summary prints.

    python tools/crossdisc.py notes/hashall.txt --against ../*/notes/sha1-all.txt
    python tools/crossdisc.py notes/hashall.txt --against LIST [LIST ...] --names
"""

import argparse
import os
import re
import sys
from collections import defaultdict

SHA1 = re.compile(r"\b([0-9a-f]{40})\b")


def load(path):
    """Return {sha1: [names]} from either hash-list shape."""
    out = defaultdict(list)
    for line in open(path, encoding="utf-8", errors="replace"):
        m = SHA1.search(line)
        if not m:
            continue
        h = m.group(1)
        rest = (line[:m.start()] + line[m.end():]).strip()
        rest = re.sub(r"^\s*\d+\s+", "", rest)
        out[h].append(rest.strip() or "?")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mine")
    ap.add_argument("--against", nargs="+", required=True)
    ap.add_argument("--names", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    mine = load(a.mine)
    print("this disc          : %d distinct sha1 over %d listed files"
          % (len(mine), sum(len(v) for v in mine.values())))
    print()
    print("%-46s %7s %7s %s" % ("hash list", "hashes", "shared", "repository"))
    total_shared = 0
    discs = 0
    hits = []
    for p in sorted(a.against):
        if not os.path.exists(p) or os.path.abspath(p) == os.path.abspath(a.mine):
            continue
        other = load(p)
        if not other:
            continue
        discs += 1
        common = set(mine) & set(other)
        total_shared += len(common)
        repo = p.replace("\\", "/").split("/")
        repo = repo[-3] if len(repo) >= 3 else p
        print("%-46s %7d %7d %s"
              % (os.path.basename(p), len(other), len(common), repo))
        for h in sorted(common):
            hits.append((repo, h, mine[h], other[h]))
    print()
    print("discs compared     : %d" % discs)
    print("crossings found    : %d" % total_shared)
    if hits:
        print()
        for repo, h, a_names, b_names in hits:
            print("  %s  %s" % (h, repo))
            print("      here  : %s" % "; ".join(a_names[:4]))
            print("      there : %s" % "; ".join(b_names[:4]))


if __name__ == "__main__":
    main()
