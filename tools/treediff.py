#!/usr/bin/env python3
"""treediff.py -- what changed in a live installation since a treecensus TSV.

An installation on a hard disk is not a disc: it can be written to while you
are looking at it, by the storefront client that installed it. This compares a
`treecensus.py --tsv` snapshot against a fresh walk and prints, in both
directions, what appeared, what vanished, what changed size and what changed
only its mtime.

The point of separating those last two is that a file whose bytes changed and a
file whose clock was touched are different events, and a tool that lumps them
reports a rewrite where there was a `utime`.

    python tools/treediff.py notes/tree.tsv "<install dir>"
    python tools/treediff.py notes/tree.tsv "<install dir>" --sha1 notes/sha1-all.txt

With --sha1 the files whose size is unchanged are re-hashed, so that a
same-size rewrite -- the only kind a size comparison cannot see -- is caught.
Nothing is written to the installation.
"""
import argparse
import hashlib
import os
import sys


def read_tsv(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        head = fh.readline().rstrip("\n").split("\t")
        if head[:3] != ["path", "size", "mtime"]:
            sys.exit("%s: header is %r, not the treecensus TSV header" % (path, head))
        for line in fh:
            p, s, m = line.rstrip("\n").split("\t")[:3]
            out[p.replace("\\", "/")] = (int(s), m)
    if not out:
        sys.exit("%s: no rows -- refusing to report 'no change' on an empty baseline"
                 % path)
    return out


def read_sha1(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split(None, 2)
            if len(parts) == 3 and len(parts[0]) == 40:
                out[parts[2].replace("\\", "/")] = parts[0]
    return out


def walk(root):
    out = {}
    import datetime
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for f in sorted(fn):
            full = os.path.join(dp, f)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            st = os.stat(full)
            m = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            out[rel] = (st.st_size, m, full)
    return out


def sha1(path):
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline")
    ap.add_argument("root")
    ap.add_argument("--sha1", default=None, metavar="FILE")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()

    old = read_tsv(a.baseline)
    new = walk(a.root)
    oldset, newset = set(old), set(new)

    added = sorted(newset - oldset)
    gone = sorted(oldset - newset)
    resized = sorted(k for k in oldset & newset if old[k][0] != new[k][0])
    touched = sorted(k for k in oldset & newset
                     if old[k][0] == new[k][0] and old[k][1] != new[k][1])

    print("baseline          : %s   %d files, %d bytes"
          % (a.baseline, len(old), sum(v[0] for v in old.values())))
    print("now               : %d files, %d bytes"
          % (len(new), sum(v[0] for v in new.values())))
    print("bytes, difference : %+d"
          % (sum(v[0] for v in new.values()) - sum(v[0] for v in old.values())))
    print()
    print("appeared          : %d" % len(added))
    for k in (added if a.full else added[:40]):
        print("    + %-56s %12d  %s" % (k, new[k][0], new[k][1]))
    print("vanished          : %d" % len(gone))
    for k in (gone if a.full else gone[:40]):
        print("    - %-56s %12d  %s" % (k, old[k][0], old[k][1]))
    print("changed size      : %d" % len(resized))
    for k in (resized if a.full else resized[:40]):
        print("    ~ %-56s %12d -> %-12d  %s -> %s"
              % (k, old[k][0], new[k][0], old[k][1], new[k][1]))
    print("same size, new mtime : %d" % len(touched))
    for k in (touched if a.full else touched[:40]):
        print("    t %-56s %12d  %s -> %s" % (k, new[k][0], old[k][1], new[k][1]))
    print()

    if a.sha1:
        oldh = read_sha1(a.sha1)
        if not oldh:
            sys.exit("%s: no sha1 rows -- refusing to report 'identical' on an "
                     "empty baseline" % a.sha1)
        same_size = [k for k in oldset & newset if old[k][0] == new[k][0]]
        checked = rewritten = missing = 0
        for k in sorted(same_size):
            if k not in oldh:
                missing += 1
                continue
            checked += 1
            if sha1(new[k][2]) != oldh[k]:
                rewritten += 1
                print("    ! REWRITTEN IN PLACE %s  (%d bytes, same size)"
                      % (k, new[k][0]))
        print("same-size files re-hashed : %d of %d  (%d not in the sha1 baseline)"
              % (checked, len(same_size), missing))
        print("rewritten in place        : %d" % rewritten)
        if checked == 0:
            sys.exit("nothing was re-hashed: the comparison did not run")


if __name__ == "__main__":
    main()
