#!/usr/bin/env python3
"""markers.py -- count four-character markers per file, with the chance
expectation printed beside every count.

The trap this exists to avoid: on a 629,649,408-byte object a *three*-byte
string is expected 37.5391 times by chance and a *four*-byte string 0.1466
times. `CEL` occurring 82 times is not a finding; `PDAT` occurring 1,818 times
is. Every count printed here carries E[random] for a file of that size, so a
number can never be read without its noise floor.

    python tools/markers.py TREE
    python tools/markers.py TREE --marks PDAT PLUT IMAG CCB
    python tools/markers.py TREE --top 20
"""
import argparse
import collections
import os

DEFAULT = ["PDAT", "PLUT", "IMAG", "CCB ", "FORM", "ANIM", "SDX2", "M.K.",
           "COMM", "SSND", "AIFF", "AIFC"]


def walk(root):
    for r, _dirs, names in os.walk(root):
        for n in sorted(names):
            p = os.path.join(r, n)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            yield "/" + rel, p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--marks", nargs="*", default=DEFAULT)
    ap.add_argument("--top", type=int, default=15)
    a = ap.parse_args()

    marks = [m.encode("latin-1") for m in a.marks]
    mx = max(len(m) for m in marks)
    total = collections.Counter()
    per = collections.defaultdict(collections.Counter)
    sizes = {}
    nbytes = 0

    for rel, p in walk(a.root):
        sizes[rel] = os.path.getsize(p)
        nbytes += sizes[rel]
        with open(p, "rb") as fh:
            carry = b""
            while True:
                blob = fh.read(1 << 22)
                if not blob:
                    break
                buf = carry + blob
                for m in marks:
                    c = buf.count(m)
                    if c:
                        total[m] += c
                        per[rel][m] += c
                carry = buf[-(mx - 1):] if mx > 1 else b""

    print("tree: %s" % a.root)
    print("files: %d   bytes: %d" % (len(sizes), nbytes))
    print()
    print("%-8s %10s %12s" % ("marker", "count", "E[random]"))
    for m, s in zip(marks, a.marks):
        exp = float(nbytes - len(m) + 1) / (256.0 ** len(m))
        print("%-8s %10d %12.4f" % (s, total[m], exp))

    for m, s in zip(marks, a.marks):
        if not total[m]:
            continue
        rows = sorted(per.items(), key=lambda kv: -kv[1][m])[:a.top]
        rows = [r for r in rows if r[1][m]]
        print("\n%s -- %d occurrences, top %d files:" % (s, total[m], len(rows)))
        for rel, c in rows:
            print("  %7d  %12d  %s" % (c[m], sizes[rel], rel))


if __name__ == "__main__":
    main()
