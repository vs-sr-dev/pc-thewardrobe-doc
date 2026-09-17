#!/usr/bin/env python3
"""leaves.py -- census the object's smallest addressable things, not its files.

The file-level duplication of this object is 32.9663 %, and that figure is
measured at the only level anybody had looked at. 42.6696 % of the object's
file bytes are `.LGP` archives, and a copy that lives inside one of them is
invisible to a file-level sweep. `pc-finalfantasy8-doc/docs/14` made exactly
this argument on the next game in the series and went from a file-level number
to **60.1834 % on 91,584 leaves**; this is the same argument on this object,
with its own tool, because that repository's `leafcensus.py` was written for a
different game's containers and copying it would be inheriting a hypothesis.

A LEAF, HERE, IS DEFINED AND THE DEFINITION IS PRINTED

    level 0   a file inside an ISO 9660 volume that is not a container
    level 1   a member of a `.LGP` archive

There is no level 2 on this object: `lgp.py --census` finds no `.LGP` inside
any `.LGP`. Three InstallShield cabinets (`_SYS1.CAB`, `_USER1.CAB`,
`DATA1.CAB`, 489,174 bytes together) are counted as level-0 leaves and are NOT
opened; that is 0.0229 % of the object's file bytes and the tool says so rather
than quietly treating a container as a leaf.

MEMBERS ARE STORED, NOT COMPRESSED. `lgp.py` shows member headers plus payload
plus directory plus lookup plus conflict table plus trailer equal to the
archive length with residue 0 on 49 of 49, and the payload share is 99.4850 %.
So "stored bytes" and "addressed bytes" are the same number here, which is a
real difference from the neighbour's object, where leaves were counted
decompressed and the leaf total exceeded the media total. **Say which one a
figure is**, always; here they coincide and that is itself worth one line.

    python tools/leaves.py ROOT [--out FILE] [--by-container]

ROOT is a directory of extracted volumes. The output is one tab-separated line
per leaf: sha1, size, path. Exit 3 on an empty population.
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lgp  # noqa: E402

CABS = (".CAB",)


def leaves(root):
    """Yield (sha1, size, path, level) for every leaf under root."""
    for r, dirs, names in os.walk(root):
        dirs.sort()
        for nm in sorted(names):
            p = os.path.join(r, nm)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            with open(p, "rb") as fh:
                data = fh.read()
            if nm.upper().endswith(".LGP"):
                creator, entries, lookup, conflicts, trailer_ok, acc = \
                    lgp.parse(data, p)
                if acc["residue"] != 0:
                    raise SystemExit(
                        "FATAL: %s does not close (residue %d); a leaf census "
                        "over an archive that does not close is a guess"
                        % (rel, acc["residue"]))
                for e in entries:
                    blob = data[e["data"]:e["data"] + e["length"]]
                    yield (hashlib.sha1(blob).hexdigest(), e["length"],
                           rel + "#" + e["name"], 1)
            else:
                yield (hashlib.sha1(data).hexdigest(), len(data), rel, 0)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out")
    ap.add_argument("--by-container", action="store_true")
    a = ap.parse_args(argv[1:])

    rows = list(leaves(a.root))
    if not rows:
        print("FATAL: no leaves under %r -- this census has nothing to do"
              % a.root)
        return 3

    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
            for h, n, p, lv in rows:
                fh.write("%s\t%d\t%d\t%s\n" % (h, n, lv, p))

    stored = sum(n for _h, n, _p, _lv in rows)
    first = {}
    for h, n, _p, _lv in rows:
        first.setdefault(h, n)
    distinct_bytes = sum(first.values())
    lv0 = [r for r in rows if r[3] == 0]
    lv1 = [r for r in rows if r[3] == 1]

    print("root                : %s" % a.root)
    print("leaves              : %d" % len(rows))
    print("  level 0, files    : %d   %d bytes"
          % (len(lv0), sum(r[1] for r in lv0)))
    print("  level 1, members  : %d   %d bytes"
          % (len(lv1), sum(r[1] for r in lv1)))
    print("stored bytes        : %d" % stored)
    print("distinct sha1       : %d" % len(first))
    print("distinct bytes      : %d" % distinct_bytes)
    print("redundancy          : %d bytes = %.4f %%"
          % (stored - distinct_bytes,
             100.0 * (stored - distinct_bytes) / stored))
    dupes = sum(1 for h, n, _p, _lv in rows) - len(first)
    print("leaves that are a copy of another leaf : %d of %d = %.4f %%"
          % (dupes, len(rows), 100.0 * dupes / len(rows)))
    cabs = [r for r in rows if r[2].upper().endswith(CABS)]
    print("containers counted as leaves and not opened : %d, %d bytes"
          % (len(cabs), sum(r[1] for r in cabs)))

    if a.by_container:
        print()
        print("%-46s %7s %8s %14s %10s" %
              ("container", "leaves", "distinct", "stored", "redundant"))
        agg = {}
        for h, n, p, lv in rows:
            key = p.split("#")[0] if lv else "(loose files)"
            agg.setdefault(key, []).append((h, n))
        for key in sorted(agg):
            items = agg[key]
            f = {}
            for h, n in items:
                f.setdefault(h, n)
            st = sum(n for _h, n in items)
            db = sum(f.values())
            print("%-46s %7d %8d %14d %9.2f %%" %
                  (key if len(key) <= 46 else "..." + key[-43:],
                   len(items), len(f), st,
                   100.0 * (st - db) / st if st else 0.0))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
