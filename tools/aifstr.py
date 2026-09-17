#!/usr/bin/env python3
"""aifstr.py -- printable runs in an ARM Image Format binary, and the two-way
cross-reference against a file listing.

The 3DO platform notes ask for this in section 6 and it has paid off on every
platform in the collection: names in the binary with no file behind them are
cut content; files no binary names are generated names or dead weight.

The wrinkle on this disc is case. The executable writes
`$exdir/CNB/carbitmaps/baracuda.3DO` and the directory is `/CNB/CarBitmaps/`,
so a case-sensitive match reports a miss that is not one. This tool resolves
both ways and reports the exact and the case-folded counts separately, because
the difference between them is itself the measurement: it says the file system
or the layer above it folds case.

    python tools/aifstr.py BINARY --min 6
    python tools/aifstr.py BINARY --xref notes/sha1-all.txt
    python tools/aifstr.py BINARY --prefix '$exdir'
"""
import argparse
import re
import sys

RUN = re.compile(rb"[\x20-\x7e]{4,}")


def runs(data, minlen):
    for m in RUN.finditer(data):
        s = m.group(0)
        if len(s) >= minlen:
            yield m.start(), s.decode("latin-1")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--min", type=int, default=6)
    ap.add_argument("--prefix")
    ap.add_argument("--xref", help="a listing whose last field is a disc path")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    data = open(a.binary, "rb").read()
    found = list(runs(data, a.min))
    print("%s: %d bytes, %d printable runs of %d or more"
          % (a.binary, len(data), len(found), a.min))

    if a.prefix:
        sel = [(o, s) for o, s in found if s.startswith(a.prefix)]
        print("runs beginning %r: %d" % (a.prefix, len(sel)))
        if not a.quiet:
            for o, s in sel:
                print("  %8d  %s" % (o, s))

    if a.xref:
        paths = []
        for ln in open(a.xref, encoding="latin-1"):
            ln = ln.rstrip("\n")
            if not ln.strip():
                continue
            p = ln.split()[-1]
            if p.startswith("/"):
                paths.append(p)
        exact = set(paths)
        folded = {}
        for p in paths:
            folded.setdefault(p.lower(), []).append(p)
        print("\nlisting: %d paths" % len(paths))

        # every string that looks like a path reference
        cands = []
        for o, s in found:
            t = s.strip()
            for pre in ("$exdir", "$boot"):
                i = t.find(pre)
                if i >= 0:
                    t = t[i + len(pre):]
                    break
            t = t.strip().lstrip("%")
            if "/" in t and not t.endswith("/") and " " not in t:
                cands.append((o, s, "/" + t.lstrip("/")))
        seen = set()
        cands = [c for c in cands if not (c[2] in seen or seen.add(c[2]))]
        hit_exact = [c for c in cands if c[2] in exact]
        hit_fold = [c for c in cands
                    if c[2] not in exact and c[2].lower() in folded]
        miss = [c for c in cands
                if c[2] not in exact and c[2].lower() not in folded]
        print("distinct path-shaped strings in the binary : %d" % len(cands))
        print("  resolve exactly                          : %d" % len(hit_exact))
        print("  resolve only when case is folded         : %d" % len(hit_fold))
        print("  resolve to nothing on the disc           : %d" % len(miss))
        if not a.quiet:
            for o, s, p in miss:
                print("    MISS  %8d  %s" % (o, s))

        named = set()
        for c in cands:
            if c[2] in exact:
                named.add(c[2])
            elif c[2].lower() in folded:
                named.update(folded[c[2].lower()])
        unnamed = [p for p in paths if p not in named]
        print("  files the binary names                   : %d" % len(named))
        print("  files nothing in this binary names       : %d" % len(unnamed))


if __name__ == "__main__":
    main()
