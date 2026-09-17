#!/usr/bin/env python3
"""fivebuilds.py -- five parallel builds of one product, set against each other.

The object of this document ships the same game five times in five languages.
Nineteen diff tools were inherited into this repository and every one of them
compares two things; none of them compares five. This does.

WHY A HASH LIST OF FIVE `.exe` CANNOT ANSWER THIS

  The five installers have five distinct SHA-1 and share, as it turns out,
  most of their payload. **A hash proves equality and does not measure
  difference**, so the interesting quantity -- how much of one build is also
  in the other four -- lives one level down, in the members, and no file-level
  comparison can ever see it. This tool works on the member censuses that
  `nsis.py --census` derives, keyed on SHA-1 rather than on name, because the
  same bytes appear under different names across builds and the same name
  appears with different bytes.

WHAT IT PRINTS, AND WHY EACH NUMBER IS THERE

  * per build: members, distinct blobs, blob bytes -- the denominators;
  * the presence distribution: how many distinct blobs occur in 5 of the
    builds, in 4, in 3, in 2, in exactly 1. Those five numbers sum to the
    union and they *are* the result; a single "shared percentage" would hide
    the shape;
  * the same distribution weighted by bytes, because 12,000 small voice files
    and six 200 MB archives do not deserve one vote each;
  * per-extension totals per build, which is where a localisation shows what
    it is made of;
  * and, for any name given with `--track`, which builds carry it and whether
    the bytes are the same.

    python tools/fivebuilds.py notes/members-*.txt
    python tools/fivebuilds.py notes/members-*.txt --ext
    python tools/fivebuilds.py notes/members-*.txt --track .vox
"""
import argparse
import collections
import os
import sys

TAB = chr(9)
BSL = chr(92)


def load(path):
    name = os.path.basename(path).replace("members-", "").replace(".txt", "")
    rows = []
    body = False
    meta = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("# sha1"):
            body = True
            continue
        if not body:
            bits = line.rstrip("\n").split(TAB)
            if len(bits) >= 2 and not line.startswith("#"):
                meta[bits[0]] = bits[1]
            continue
        bits = line.rstrip("\n").split(TAB)
        if len(bits) != 4:
            continue
        rows.append((bits[0], int(bits[1]), int(bits[2]), bits[3]))
    return name, meta, rows


def ext_of(path):
    base = path.rsplit(BSL, 1)[-1]
    if "." not in base:
        return "(none)"
    return "." + base.rsplit(".", 1)[-1].lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--ext", action="store_true")
    ap.add_argument("--track")
    ap.add_argument("--out")
    args = ap.parse_args()

    builds = [load(p) for p in args.files]
    order = ["english", "spanish", "italian", "french", "german"]
    builds.sort(key=lambda b: order.index(b[0]) if b[0] in order else 99)

    lines = []

    def say(s=""):
        lines.append(s)
        print(s)

    say("build      members  distinct  distinct bytes   decompressed   ratio")
    for name, meta, rows in builds:
        blobs = {}
        for h, sz, pos, p in rows:
            blobs[h] = sz
        say("%-9s %8d %9d %15s %14s   %s"
            % (name, len(rows), len(blobs), format(sum(blobs.values()), ","),
               format(int(meta.get("decompressed", 0)), ","),
               meta.get("chain_residue", "?")))

    # presence distribution over distinct blobs
    presence = collections.defaultdict(set)
    size_of = {}
    for name, meta, rows in builds:
        for h, sz, pos, p in rows:
            presence[h].add(name)
            size_of[h] = sz
    dist = collections.Counter(len(v) for v in presence.values())
    bytes_dist = collections.Counter()
    for h, v in presence.items():
        bytes_dist[len(v)] += size_of[h]
    say()
    say("distinct blobs across the union, by how many builds carry them")
    say("  in N builds     blobs           bytes        share of union")
    total_b = sum(size_of.values())
    for n in range(len(builds), 0, -1):
        say("  %d           %8d  %16s  %8.4f %%"
            % (n, dist.get(n, 0), format(bytes_dist.get(n, 0), ","),
               100.0 * bytes_dist.get(n, 0) / total_b if total_b else 0))
    say("  union       %8d  %16s" % (len(presence), format(total_b, ",")))

    if args.ext:
        say()
        exts = set()
        per = {}
        for name, meta, rows in builds:
            blobs = {}
            for h, sz, pos, p in rows:
                blobs[(h, ext_of(p))] = sz
            agg = collections.defaultdict(lambda: [0, 0])
            for (h, e), sz in blobs.items():
                agg[e][0] += 1
                agg[e][1] += sz
            per[name] = agg
            exts |= set(agg)
        say("bytes per extension, per build (distinct blobs only)")
        say("%-9s %s" % ("ext", "".join("%18s" % b[0] for b in builds)))
        for e in sorted(exts, key=lambda x: -max(per[b[0]].get(x, [0, 0])[1]
                                                 for b in builds)):
            say("%-9s %s" % (e, "".join(
                "%18s" % format(per[b[0]].get(e, [0, 0])[1], ",")
                for b in builds)))
        say("%-9s %s" % ("files", "".join(
            "%18s" % format(sum(v[0] for v in per[b[0]].values()), ",")
            for b in builds)))

    if args.track:
        say()
        say("members whose path contains %r" % args.track)
        for name, meta, rows in builds:
            hit = [r for r in rows if args.track in r[3]]
            blobs = {r[0]: r[1] for r in hit}
            say("  %-9s %6d members, %6d distinct, %16s bytes"
                % (name, len(hit), len(blobs),
                   format(sum(blobs.values()), ",")))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as o:
            o.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
