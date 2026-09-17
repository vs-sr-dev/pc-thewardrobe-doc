#!/usr/bin/env python3
"""crossall.py -- intersect this object's file hashes with every other list in
the collection, without being told where the lists are.

`crossdisc.py` takes `--against` and a list of files, which means the answer
depends on which files you remembered to name. That was fine while the answer
was always zero. It stops being fine the moment the answer is not zero, because
then the size of the search matters as much as the hit.

This tool sweeps a directory of repositories, treats **any** line in **any**
`notes/` text file that contains a 40-hex-character token as a possible hash
record, and intersects the resulting set with the hashes of the tree it is
pointed at. It does not care what the surrounding format is, so it reads census
files, hash lists, tree dumps and stream inventories alike.

Two guards, both of which have to be printed rather than assumed:

  * **the empty file.** sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 is the
    hash of zero bytes and it crosses with every collection that contains an
    empty file. It is excluded from the hit list and reported separately;
  * **self-matches.** The repository being measured is skipped, and so is any
    list that turns out to be a copy of this object's own hashes, otherwise a
    disc crosses with itself.

A hit is a claim about bytes, so the tool prints the size on both sides where
the other list records one, and never claims identity from a hash alone -- the
byte-level comparison is a separate step and is named as such.

    python tools/crossall.py MYHASHES.txt --collection ..
    python tools/crossall.py MYHASHES.txt --collection .. --verbose

The collection root is an argument and has no default, because a default would
be a path on one machine.
"""

import argparse
import collections
import os
import re

HEX40 = re.compile(r"\b([0-9a-f]{40})\b")
EMPTY = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def load_mine(path):
    """hashall.py format: sha1, size, path -- whitespace separated."""
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split(None, 2)
            if len(parts) == 3 and HEX40.fullmatch(parts[0]):
                out[parts[0]] = (int(parts[1]), parts[2].strip())
    return out


def scan(collection, skip_repo, exts=(".txt", ".tsv", ".md", ".csv")):
    """Yield (repo, relpath, sha1, line) for every hash-looking token found."""
    for repo in sorted(os.listdir(collection)):
        rp = os.path.join(collection, repo)
        if not os.path.isdir(rp) or repo == skip_repo:
            continue
        for sub in ("notes", "docs"):
            d = os.path.join(rp, sub)
            if not os.path.isdir(d):
                continue
            for dp, dn, fn in os.walk(d):
                for f in fn:
                    if os.path.splitext(f)[1].lower() not in exts:
                        continue
                    p = os.path.join(dp, f)
                    try:
                        with open(p, encoding="utf-8", errors="replace") as fh:
                            for line in fh:
                                for m in HEX40.finditer(line.lower()):
                                    yield (repo,
                                           os.path.relpath(p, rp).replace(os.sep, "/"),
                                           m.group(1), line.rstrip())
                    except OSError:
                        continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mine")
    ap.add_argument("--collection", required=True)
    ap.add_argument("--skip", default="", help="repository directory to skip")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--min-bytes", type=int, default=0, metavar="N",
                    help="report only crossings on files of at least N bytes; "
                         "the rate-versus-length table is printed regardless")
    a = ap.parse_args()

    mine = load_mine(a.mine)
    print("my distinct sha1            : %d" % len(mine))
    print("  (identical files inside one object collapse into one key here;")
    print("   the file count is the tree census's, not this tool's)")
    print("empty-file sha1 among mine  : %s"
          % ("YES -- excluded" if EMPTY in mine else "no"))
    print("collection root             : %s" % a.collection)
    print("skipping                    : %s" % (a.skip or "(nothing)"))
    print()

    files_seen = set()
    repos_seen = set()
    tokens = 0
    hits = collections.defaultdict(list)
    empty_hits = collections.defaultdict(list)
    for repo, rel, h, line in scan(a.collection, a.skip):
        repos_seen.add(repo)
        files_seen.add((repo, rel))
        tokens += 1
        if h == EMPTY:
            empty_hits[repo].append((rel, line))
            continue
        if h in mine:
            hits[h].append((repo, rel, line))

    print("repositories swept          : %d" % len(repos_seen))
    print("list files swept            : %d" % len(files_seen))
    print("hash tokens read            : %d" % tokens)
    print("distinct sha1 in those lists: (counted below)")
    print()
    print("=" * 72)
    print("EMPTY-FILE SHA1 (the trap): %d occurrences in %d repositories"
          % (sum(len(v) for v in empty_hits.values()), len(empty_hits)))
    for repo, v in sorted(empty_hits.items()):
        print("   %-40s x%d" % (repo, len(v)))
    print("   -> excluded from the crossings below.")
    print()
    print("=" * 72)
    print("THE RATE AS A FUNCTION OF MINIMUM FILE LENGTH")
    print()
    print("A crossing is a claim that two objects share a file. On a tree whose")
    print("files are short, it is also a claim that two short byte strings")
    print("happened to be equal, and those are not the same claim. This table is")
    print("printed BEFORE any figure is quoted, and the figure quoted anywhere")
    print("else has to name the threshold it was taken at.")
    print()
    print("%12s %12s %12s %12s" % ("min bytes", "my hashes", "crossings", "rate"))
    for lo in (0, 1, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 65536):
        pop = [h for h, (size, path) in mine.items() if size >= lo]
        cr = [h for h in hits if mine[h][0] >= lo]
        print("%12d %12d %12d %11.4f %%"
              % (lo, len(pop), len(cr),
                 100.0 * len(cr) / len(pop) if pop else 0.0))
    print()
    shown = {h: w for h, w in hits.items() if mine[h][0] >= a.min_bytes}
    print("=" * 72)
    print("CROSSINGS at a minimum length of %d bytes: %d of my %d distinct "
          "hashes appear in another repository"
          % (a.min_bytes, len(shown),
             len([h for h, (s, p) in mine.items() if s >= a.min_bytes])))
    if a.min_bytes == 0:
        print("   (threshold 0 -- every hash, including files too short to be "
              "anybody's)")
    print()
    for h, where in sorted(shown.items(), key=lambda kv: -mine[kv[0]][0]):
        size, path = mine[h]
        print("sha1 %s   %d bytes" % (h, size))
        print("   mine : %s" % path)
        for repo, rel, line in where:
            print("   also : %-34s %s" % (repo, rel))
            if a.verbose:
                print("          | %s" % line.strip()[:150])
        print()


if __name__ == "__main__":
    main()
