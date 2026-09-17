#!/usr/bin/env python3
"""romtables.py -- read the nine VTABLE/FTABLE pairs of Final Fantasy XI.

Every `ROM*` directory of this object carries its own pair of index files
-- `VTABLE.DAT`/`FTABLE.DAT` in `ROM`, `VTABLE2.DAT`/`FTABLE2.DAT` in
`ROM2`, and so on to `ROM9` -- and all eighteen are exactly 109,701 and
219,402 bytes, a ratio of exactly 2.

THE READING, AND WHY THE ARITHMETIC IS NOT THE PROOF

Read `VTABLE` as one byte per file id naming the volume that holds it
(0 = nobody) and `FTABLE` as one u16 per id splitting as

    directory = value >> 7          file = value & 0x7F

and the tables produce a directory-and-file address for every id they
claim.  That the sizes are in a ratio of 2, and that `>> 7` never
overflows, is arithmetic: it would close on random bytes of the right
length.  The external fact is that **every address the tables produce
names a file that is actually on the disk**, and the tool reports that
as a fraction with both numbers, never as a yes.

The tool also runs the check the other way, which is the one that finds
something: how many files ARE on the disk that no id points at.

WHAT IT IS FOR

The object was described to me as built in layers, each expansion laid
over the one before.  The pairwise intersection of the nine claimed-id
sets is the test of that description, and it is printed in full rather
than summarised, because a matrix that is zero off the diagonal is a
partition and not a stack.  Where the overlap actually lives -- identical
files under two different ids in two different layers -- is measured
separately, from sha1 sums computed elsewhere.

Nothing is executed, nothing is contacted, nothing is written to the
object.

usage:
  romtables.py read   ROOT [--sha1 FILE] [--out FILE]
"""

import argparse
import os
import struct
import sys
from collections import Counter, defaultdict

LAYERS = ["", "2", "3", "4", "5", "6", "7", "8", "9"]
DIR_SHIFT = 7
FILE_MASK = 0x7F


def layer_name(suffix):
    return "ROM" + suffix


def read_pair(root, suffix):
    # The base layer's pair does NOT live in `ROM\`: `VTABLE.DAT` and
    # `FTABLE.DAT` sit in the root of the game branch, beside `ROM\`, while
    # every other layer keeps its pair inside its own directory.  A reader
    # that looks in `ROM\` finds nothing, reports eight layers instead of
    # nine, and looks like it worked.
    d = root if suffix == "" else os.path.join(root, layer_name(suffix))
    v = os.path.join(d, "VTABLE%s.DAT" % suffix)
    f = os.path.join(d, "FTABLE%s.DAT" % suffix)
    if not (os.path.exists(v) and os.path.exists(f)):
        return None
    vb = open(v, "rb").read()
    fb = open(f, "rb").read()
    return vb, fb


def scan_disk(root, suffix):
    """Return {(dir, file): size} for every <n>/<m>.DAT under the layer."""
    base = os.path.join(root, layer_name(suffix))
    out = {}
    if not os.path.isdir(base):
        return out
    for sub in os.listdir(base):
        p = os.path.join(base, sub)
        if not os.path.isdir(p) or not sub.isdigit():
            continue
        for fn in os.listdir(p):
            stem, ext = os.path.splitext(fn)
            if ext.lower() != ".dat" or not stem.isdigit():
                continue
            out[(int(sub), int(stem))] = os.path.getsize(
                os.path.join(p, fn))
    return out


def runs(sorted_ids):
    """Collapse a sorted list of ints into (start, end_inclusive) runs."""
    out = []
    for i in sorted_ids:
        if out and i == out[-1][1] + 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def cmd_read(args):
    out = sys.stdout
    if args.out:
        out = open(args.out, "w", encoding="utf-8")

    def w(s=""):
        out.write(s + "\n")

    claimed = {}
    addrs = {}
    disk = {}
    w("root : %s" % args.root)
    w()
    w("%-6s %10s %10s %8s %8s %8s %8s %8s"
      % ("layer", "vtable B", "ftable B", "ids", "distinct",
         "max dir", "on disk", "exist"))
    total_ids = None
    for suf in LAYERS:
        pair = read_pair(args.root, suf)
        if pair is None:
            continue
        vb, fb = pair
        assert len(fb) == 2 * len(vb), (
            "FTABLE%s is %d bytes and VTABLE%s is %d: the pair is not in "
            "the 2:1 ratio the reading assumes" % (suf, len(fb), suf, len(vb)))
        n = len(vb)
        if total_ids is None:
            total_ids = n
        else:
            assert total_ids == n, "layers disagree on the size of the id space"
        vals = struct.unpack("<%dH" % n, fb)
        ids = [i for i in range(n) if vb[i] != 0]
        a = {}
        for i in ids:
            v = vals[i]
            a[i] = (v >> DIR_SHIFT, v & FILE_MASK)
        claimed[suf] = set(ids)
        addrs[suf] = a
        disk[suf] = scan_disk(args.root, suf)
        distinct = set(a.values())
        exist = sum(1 for t in distinct if t in disk[suf])
        w("%-6s %10d %10d %8d %8d %8d %8d %8s"
          % (layer_name(suf), len(vb), len(fb), len(ids), len(distinct),
             max((t[0] for t in distinct), default=0), len(disk[suf]),
             "%d/%d" % (exist, len(distinct))))

    w()
    w("what byte values stand in each VTABLE, which is the question the")
    w("pre-briefing answers with a bracketed number and never shows:")
    for suf in LAYERS:
        pair = read_pair(args.root, suf)
        if pair is None:
            continue
        vb, _fb = pair
        c = Counter(vb)
        nz = {k: v for k, v in c.items() if k != 0}
        w("  %-6s zero %7d   non-zero values %s"
          % (layer_name(suf), c[0], sorted(nz.items())))

    w()
    everyone = set()
    for s in claimed.values():
        everyone |= s
    w("id space                          : %d" % total_ids)
    w("ids claimed by at least one layer : %d" % len(everyone))
    w("ids claimed by no layer           : %d" % (total_ids - len(everyone)))
    counts = Counter()
    for i in everyone:
        counts[sum(1 for s in claimed.values() if i in s)] += 1
    for k in sorted(counts):
        w("  claimed by %d layer(s) : %d" % (k, counts[k]))

    w()
    w("pairwise intersection of the claimed-id sets:")
    keys = [s for s in LAYERS if s in claimed]
    w("        " + "".join("%8s" % layer_name(s) for s in keys))
    for a1 in keys:
        row = "".join("%8d" % len(claimed[a1] & claimed[b1]) for b1 in keys)
        w("%-8s%s" % (layer_name(a1), row))

    w()
    unclaimed = sorted(set(range(total_ids)) - everyone)
    rs = runs(unclaimed)
    rs_sorted = sorted(rs, key=lambda r: r[0] - r[1])
    w("the %d unclaimed ids form %d contiguous runs." % (len(unclaimed), len(rs)))
    w("the ten longest:")
    for a1, b1 in rs_sorted[:10]:
        w("  %6d .. %-6d  %6d ids" % (a1, b1, b1 - a1 + 1))
    top = max(everyone) if everyone else 0
    w("highest claimed id : %d of %d" % (top, total_ids - 1))
    tail = [r for r in rs if r[1] == total_ids - 1]
    if tail:
        w("the id space ends in a run of %d unclaimed ids (%d..%d)"
          % (tail[0][1] - tail[0][0] + 1, tail[0][0], tail[0][1]))

    w()
    w("FILES ON DISK THAT NO ID POINTS AT")
    w("%-6s %8s %8s %10s %16s" % ("layer", "on disk", "reached",
                                  "unreached", "unreached bytes"))
    tot_un = tot_b = 0
    unreached_paths = []
    for suf in keys:
        d = disk[suf]
        reached = set(addrs[suf].values()) & set(d)
        un = set(d) - reached
        b = sum(d[t] for t in un)
        tot_un += len(un)
        tot_b += b
        for t in sorted(un):
            unreached_paths.append((layer_name(suf), t[0], t[1], d[t]))
        w("%-6s %8d %8d %10d %16d"
          % (layer_name(suf), len(d), len(reached), len(un), b))
    w("%-6s %8s %8s %10d %16d" % ("total", "", "", tot_un, tot_b))
    w()
    w("(the two table files themselves are not <n>/<m>.DAT and are not")
    w(" counted in either column)")
    w()
    w("the twenty largest unreached files:")
    for lay, dd, ff, sz in sorted(unreached_paths, key=lambda t: -t[3])[:20]:
        w("  %-6s %4d/%-4d %12d" % (lay, dd, ff, sz))

    if args.sha1:
        w()
        w("THE SAME FILE UNDER TWO IDS IN TWO LAYERS")
        w("(sha1 sums read from %s, computed elsewhere)" % args.sha1)
        by_hash = defaultdict(list)
        for line in open(args.sha1, encoding="utf-8", errors="replace"):
            parts = line.rstrip("\n").split(None, 2)
            if len(parts) != 3:
                continue
            h, sz, rel = parts
            if "/ROM" not in rel or not rel.endswith(".DAT"):
                continue
            seg = rel.split("/")
            try:
                i = max(j for j, s in enumerate(seg) if s.startswith("ROM"))
            except ValueError:
                continue
            lay = seg[i]
            if len(seg) < i + 3:
                continue
            by_hash[h].append((lay, int(sz), rel))
        cross = 0
        cross_bytes = 0
        pairs = Counter()
        biggest = []
        for h, lst in by_hash.items():
            lays = set(x[0] for x in lst)
            if len(lays) < 2:
                continue
            cross += 1
            sz = lst[0][1]
            cross_bytes += sz * (len(lst) - 1)
            for a1 in sorted(lays):
                for b1 in sorted(lays):
                    if a1 < b1:
                        pairs[(a1, b1)] += 1
            biggest.append((sz, sorted(lays), len(lst)))
        w("  distinct contents present in more than one layer : %d" % cross)
        w("  bytes they cost beyond the first copy            : %d" % cross_bytes)
        w("  layer pairs that share content:")
        for (a1, b1), c in pairs.most_common(30):
            w("    %-6s %-6s %6d" % (a1, b1, c))
        w("  the ten largest:")
        for sz, lays, n in sorted(biggest, reverse=True)[:10]:
            w("    %12d x%d  %s" % (sz, n, " ".join(lays)))

    if args.out:
        out.close()
        print("wrote %s" % args.out)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("read")
    p.add_argument("root")
    p.add_argument("--sha1")
    p.add_argument("--out")
    p.set_defaults(func=cmd_read)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
