#!/usr/bin/env python3
"""datmembers.py -- hash every chunk of every .DAT, so that members can cross.

`crossall.py` crosses this object's FILES against every hash list in the
collection and finds two.  That is a statement about files and not about
content: two objects can share a texture, a sound or a mesh without sharing
a file, and every previous session that asked the question had to build a
member list first.

This is that member list, for this object's format.  `datchain.py` derives
the chunk chain; this walks it over every `.DAT` whose chain closes and
writes one sha1 per chunk, in the same three-column shape
(`<sha1> <size> <name>`) that every other hash list in this collection
uses, so `crossall.py` can read it without being taught anything.

The name column is `<relative path>#<offset>:<tag>:<type>`, which is enough
to find the member again and is not a path on this machine.

Chunks smaller than a threshold are skipped by default: a 16-byte `end`
chunk is identical in ninety-seven thousand places and would cross with
everything, which is the same trap as the empty file and is reported
rather than silently dropped.

Nothing is executed, nothing is contacted, nothing is written to the
object, and no member is extracted -- only hashed.

usage:
  datmembers.py ROOT --out FILE [--min-size N]
"""

import argparse
import hashlib
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import datchain  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-size", type=int, default=64)
    args = ap.parse_args()

    files = closed = 0
    members = 0
    skipped = 0
    skipped_bytes = 0
    hashed_bytes = 0
    distinct = set()
    dupes = Counter()

    with open(args.out, "w", encoding="utf-8") as out:
        for dirpath, _d, fns in os.walk(args.root):
            for fn in fns:
                if not fn.lower().endswith(".dat"):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    data = open(p, "rb").read()
                except OSError:
                    continue
                files += 1
                chunks, verdict, _ = datchain.walk(data)
                if verdict != "closes":
                    continue
                closed += 1
                rel = os.path.relpath(p, args.root).replace(os.sep, "/")
                for off, tag, t, size, _fl in chunks:
                    if size < args.min_size:
                        skipped += 1
                        skipped_bytes += size
                        continue
                    body = data[off:off + size]
                    h = hashlib.sha1(body).hexdigest()
                    name = "".join(chr(c) for c in tag if 32 <= c < 127)
                    members += 1
                    hashed_bytes += size
                    if h in distinct:
                        dupes[h] += 1
                    distinct.add(h)
                    out.write("%s %12d %s#%d:%s:%d\n"
                              % (h, size, rel, off, name, t))

    print("root            : %s" % args.root)
    print("files seen      : %d" % files)
    print("chains that close: %d" % closed)
    print("members hashed  : %d" % members)
    print("bytes hashed    : %d" % hashed_bytes)
    print("members skipped as too small (< %d bytes) : %d, %d bytes"
          % (args.min_size, skipped, skipped_bytes))
    print("distinct sha1   : %d" % len(distinct))
    print("members that repeat inside this object    : %d hashes"
          % len(dupes))
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
