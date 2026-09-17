#!/usr/bin/env python3
"""setuplist.py -- the installer read as a descriptor of a disc that does not
exist yet.

An ISO 9660 primary descriptor describes the object it is inside. An installer
describes something else: the state of somebody's hard disc after they say yes.
It is a fourth descriptor, and it can be compared with the other three.

The tool pulls every one-directory-deep 8.3 reference out of a binary and sets
that list against a real tree three ways:

    on the disc and named by the installer      -> gets copied
    on the disc and NOT named by the installer  -> played from the CD, or dead
    named by the installer and NOT on the disc  -> the interesting one

The third set is the one worth having. A name the installer will look for and
the disc does not carry is either a file cut before release, a file from
another edition, or a bug that would have stopped an install.

Two things about the matching, both learned the hard way on this binary:

  * the names inside it are **mixed case** -- `objspr` then a backslash then
    `OSP00094.pak`, `Stage1` then `ROOM10A0.RDT` -- while the disc's own 8.3
    namespace is upper case throughout. A case-sensitive upper-case pattern
    finds a fraction of them and reports a smaller list than exists;
  * the installer's directory names are not the disc's. It writes `Stage1`
    where the disc has `STAGE1` and `objspr` where the disc has `OBJSPR`, and
    on some builds it writes only the stage number. The comparison therefore
    keys on the **file name alone**, folded to upper case, and reports the
    directory it saw beside it.

    python tools/setuplist.py SETUP.EXE --tree DIR
    python tools/setuplist.py SETUP.EXE --tree DIR --under HORR/USA
    python tools/setuplist.py SETUP.EXE --dump OUT.txt
"""

import argparse
import collections
import os
import re

SEP = bytes((0x5C,))            # the DOS separator, written this way on purpose
NAME = rb"[A-Za-z0-9_\-]"
PAT = re.compile(NAME + b"{1,8}" + re.escape(SEP) + NAME + b"{1,8}" +
                 rb"\." + NAME + b"{1,3}")


def split(tok):
    d, rest = tok.split(SEP.decode("ascii"), 1)
    return d, rest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--tree")
    ap.add_argument("--under", default="")
    ap.add_argument("--dump")
    a = ap.parse_args()

    data = open(a.binary, "rb").read()
    hits = []
    for m in PAT.finditer(data):
        d, f = split(m.group(0).decode("ascii"))
        hits.append((m.start(), d, f))

    distinct = sorted(set((d.upper(), f.upper()) for _, d, f in hits))
    print("binary                    : %s (%d bytes)"
          % (os.path.basename(a.binary), len(data)))
    print("one-deep 8.3 references   : %d" % len(hits))
    print("distinct dir + name       : %d" % len(distinct))
    print("distinct names            : %d" % len(set(f for d, f in distinct)))
    bydir = collections.Counter(d for d, f in distinct)
    print("distinct directories      : %d" % len(bydir))
    for d, n in bydir.most_common(24):
        print("   %-12s %5d" % (d, n))
    byext = collections.Counter(f.rsplit(".", 1)[1] for d, f in distinct)
    print("by extension              : %s"
          % ", ".join("%s x%d" % kv for kv in byext.most_common(24)))
    if hits:
        print("first reference at offset : %d" % hits[0][0])
        print("last  reference at offset : %d" % hits[-1][0])
        print("span                      : %d bytes (%.2f %% of the file)"
              % (hits[-1][0] - hits[0][0],
                 100.0 * (hits[-1][0] - hits[0][0]) / len(data)))

    if a.dump:
        with open(a.dump, "w", encoding="utf-8") as fh:
            for d, f in distinct:
                fh.write("%s/%s\n" % (d, f))
        print("wrote %s" % a.dump)

    if not a.tree:
        return

    ondisc = {}
    for dp, dn, fn in os.walk(a.tree):
        rel = os.path.relpath(dp, a.tree).replace(os.sep, "/")
        if a.under and not (rel == a.under or rel.startswith(a.under + "/")):
            continue
        for f in fn:
            ondisc.setdefault(f.upper(), []).append(
                (rel + "/" + f) if rel != "." else f)

    inst = set(f for d, f in distinct)
    disc = set(ondisc)
    both = inst & disc
    only_inst = inst - disc
    only_disc = disc - inst

    def sz(k):
        return os.path.getsize(os.path.join(a.tree, ondisc[k][0]))

    print()
    print("=" * 68)
    print("tree                      : %s%s"
          % (a.tree, (" under " + a.under) if a.under else ""))
    print("distinct file names on it : %d" % len(disc))
    print("named by the installer    : %d" % len(inst))
    print()
    print("on the disc AND named     : %d   %d bytes"
          % (len(both), sum(sz(k) for k in both)))
    print("on the disc, NOT named    : %d   %d bytes"
          % (len(only_disc), sum(sz(k) for k in only_disc)))
    print("named, NOT on the disc    : %d   <-- the interesting set"
          % len(only_inst))
    print()
    if only_disc:
        byext = collections.Counter(k.rsplit(".", 1)[-1] for k in only_disc)
        print("-- on the disc and never named by the installer ------------------")
        print("   by extension: %s"
              % ", ".join("%s x%d" % kv for kv in byext.most_common(24)))
        rows = sorted(only_disc, key=lambda k: -sz(k))
        for k in rows[:25]:
            print("     %-46s %10d" % (ondisc[k][0], sz(k)))
        if len(rows) > 25:
            print("     ... %d more" % (len(rows) - 25))
    print()
    if only_inst:
        where = {}
        for _, d, f in hits:
            where.setdefault(f.upper(), d)
        print("-- named by the installer and not on the disc --------------------")
        for f in sorted(only_inst):
            print("     %s / %s" % (where.get(f, "?"), f))


if __name__ == "__main__":
    main()
