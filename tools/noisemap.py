#!/usr/bin/env python3
"""noisemap.py -- where a string lands, and how many chance would put there.

`strcount.py` reports that `PS2` occurs 479 times in this object, `Ogg` 491,
`Wii` 466, `PDB` 1,206 and `Kraken` 122.  Not one of those numbers means
anything on its own, because a three-byte sequence occurs in 15,150,034,054
bytes of anything about

    15,150,034,054 / 256^3 = 903.0

times by chance alone.  491 is BELOW chance.  479 for a FOUR-byte string,
against a chance expectation of 3.53, is a hundred and thirty-six times
chance and is a fact.

So every count this tool prints comes with two companions: the number
chance predicts over the same population, and the ratio.  And every hit is
mapped into the structure that contains it -- which file, and, when the
file is a `.DAT` whose chunk chain closes, which chunk of which type.  A
count without a location is a rumour.

The chance model is the crude one and is stated so it can be argued with:
bytes are treated as independent and uniform, which they are not; the
prediction is `N / 256^L` for a string of L bytes over N bytes.  For an
object that is 8.28 % above entropy 7.5 -- that is, mostly NOT random --
the model over-predicts for text and under-predicts for structure.  It is
used as an order-of-magnitude floor, never as a p-value.

Nothing is executed, nothing is contacted, nothing is written to the object.

usage:
  noisemap.py ROOT STRING [STRING ...] [--out FILE] [--ext .dat,.dll]
"""

import argparse
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import datchain  # noqa: E402

CHUNKSZ = 1 << 22


def chunk_index(data):
    """Return (offsets, chunks) for a .DAT whose chain closes, else None."""
    chunks, verdict, _ = datchain.walk(data)
    if verdict != "closes":
        return None
    return chunks


def locate(chunks, off):
    lo, hi = 0, len(chunks) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        o = chunks[mid][0]
        if o <= off:
            best = chunks[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("string", nargs="+")
    ap.add_argument("--out")
    ap.add_argument("--ext", default="",
                    help="comma-separated extensions to restrict to")
    args = ap.parse_args()

    exts = set(e.lower() for e in args.ext.split(",") if e) or None
    needles = [(s, s.encode("ascii")) for s in args.string]
    utf16 = [(s, s.encode("utf-16-le")) for s in args.string]

    hits = defaultdict(Counter)          # string -> Counter(file)
    total = Counter()
    total16 = Counter()
    in_chunk = defaultdict(Counter)      # string -> Counter((type, tag))
    files_with = defaultdict(set)
    nbytes = 0
    nfiles = 0

    for dirpath, _d, files in os.walk(args.root):
        for fn in files:
            if exts and os.path.splitext(fn)[1].lower() not in exts:
                continue
            p = os.path.join(dirpath, fn)
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            nfiles += 1
            nbytes += len(data)
            rel = os.path.relpath(p, args.root).replace(os.sep, "/")
            chunks = None
            wanted = False
            for s, b in needles:
                if b in data:
                    wanted = True
            if wanted and fn.lower().endswith(".dat"):
                chunks = chunk_index(data)
            for s, b in needles:
                start = 0
                while True:
                    i = data.find(b, start)
                    if i < 0:
                        break
                    total[s] += 1
                    hits[s][rel] += 1
                    files_with[s].add(rel)
                    if chunks:
                        c = locate(chunks, i)
                        if c:
                            tag = "".join(chr(x) for x in c[1]
                                          if 32 <= x < 127)
                            in_chunk[s][(c[2], tag)] += 1
                    else:
                        in_chunk[s][(-1, os.path.splitext(fn)[1].lower())] += 1
                    start = i + 1
            for s, b in utf16:
                total16[s] += data.count(b)

    out = sys.stdout
    if args.out:
        out = open(args.out, "w", encoding="utf-8")

    def w(s=""):
        out.write(s + "\n")

    w("root  : %s" % args.root)
    w("files : %d" % nfiles)
    w("bytes : %d" % nbytes)
    if exts:
        w("restricted to extensions: %s" % ",".join(sorted(exts)))
    w()
    w("%-26s %8s %8s %12s %8s %8s"
      % ("string", "ascii", "utf16le", "chance", "obs/chance", "files"))
    for s, b in needles:
        exp = nbytes / (256.0 ** len(b))
        ratio = (total[s] / exp) if exp else float("inf")
        w("%-26s %8d %8d %12.2f %8.2f %8d"
          % (s, total[s], total16[s], exp, ratio, len(files_with[s])))
    w()
    w("chance is N / 256^L with bytes treated as independent and uniform,")
    w("which they are not.  It is a floor, not a p-value.")
    w()
    for s, _b in needles:
        if not total[s]:
            continue
        w("-" * 70)
        w("%s -- %d occurrences in %d files" % (s, total[s], len(files_with[s])))
        w("  the ten files that carry the most:")
        for rel, c in hits[s].most_common(10):
            w("    %-58s %6d" % (rel[:58], c))
        w("  where inside, when the container is a .DAT whose chain closes")
        w("  (type -1 means the file is not a .DAT, or its chain does not close):")
        for (t, tag), c in in_chunk[s].most_common(12):
            w("    type %4d  %-10s %6d" % (t, tag, c))
    if args.out:
        out.close()
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
