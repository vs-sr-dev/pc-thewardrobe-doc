"""extractcheck.py -- verify an extracted tree against an iso9660.py --sha1 listing.

Why this exists: `_work/files/` was extracted by a previous session and every
measurement in this repository is taken from it rather than from the image, so
the equivalence of the two has to be a measurement and not an assumption. This
tool re-reads both sides and compares (size, sha1) per path, in both directions,
and exits non-zero if anything at all disagrees.

Usage:
    python tools/extractcheck.py notes/sha1-iso.txt _work/files
    python tools/extractcheck.py notes/sha1-iso.txt _work/files --selftest

`--selftest` is the positive control: it flips one byte of one file's expected
hash in memory and asserts that the comparison reports it. A checker that
cannot report a mismatch is not a checker.
"""

import hashlib
import os
import re
import sys

LINE = re.compile(
    r"^(/\S+);1\s+(\d+)\s+(\d+)\s+(\S+\s+\S+)\s+(\S+)\s+([0-9a-f]{40})\s*$"
)


def read_listing(path):
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE.match(line)
            if m:
                out[m.group(1).upper()] = (int(m.group(2)), m.group(6))
    return out


def read_tree(root):
    out = {}
    sep = os.sep
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            key = "/" + rel.replace(sep, "/").replace("\\", "/")
            h = hashlib.sha1()
            with open(full, "rb") as fh:
                while True:
                    b = fh.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
            out[key.upper()] = (os.path.getsize(full), h.hexdigest())
    return out


def compare(listing, tree):
    same = []
    mismatch = []
    only_listing = []
    only_tree = []
    for k, v in sorted(listing.items()):
        if k not in tree:
            only_listing.append(k)
        elif tree[k] == v:
            same.append(k)
        else:
            mismatch.append((k, v, tree[k]))
    for k in sorted(tree):
        if k not in listing:
            only_tree.append(k)
    return same, mismatch, only_listing, only_tree


def report(listing, tree, label=""):
    same, mismatch, only_l, only_t = compare(listing, tree)
    if label:
        print("=== %s ===" % label)
    print("listing entries        : %d" % len(listing))
    print("tree files             : %d" % len(tree))
    print("identical (size+sha1)  : %d" % len(same))
    print("mismatched             : %d" % len(mismatch))
    print("in listing, not in tree: %d" % len(only_l))
    print("in tree, not in listing: %d" % len(only_t))
    for k, exp, got in mismatch:
        print("  MISMATCH %s expected %s got %s" % (k, exp, got))
    for k in only_l:
        print("  MISSING  %s" % k)
    for k in only_t:
        print("  EXTRA    %s" % k)
    return len(mismatch) + len(only_l) + len(only_t)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    listing = read_listing(argv[1])
    if not listing:
        print("FATAL: parsed zero entries from %s -- a tool that finds nothing"
              " is not a tool that says zero" % argv[1])
        return 3
    tree = read_tree(argv[2])
    if not tree:
        print("FATAL: found zero files under %s" % argv[2])
        return 3
    bad = report(listing, tree, "extracted tree vs image listing")
    if "--selftest" in argv:
        print()
        victim = sorted(listing)[0]
        size, h = listing[victim]
        poisoned = dict(listing)
        poisoned[victim] = (size, "0" * 40)
        n = report(poisoned, tree, "POSITIVE CONTROL: one hash deliberately wrong")
        if n != 1:
            print("POSITIVE CONTROL FAILED: expected exactly 1 disagreement, got %d" % n)
            return 4
        print("positive control fired as expected on %s" % victim)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
