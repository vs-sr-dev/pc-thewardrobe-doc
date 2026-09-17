#!/usr/bin/env python3
"""strcount.py -- count strings over every byte of a tree, in as many
ENCODINGS AS ARE INDEPENDENT.

This branch's most insidious error has five variants, and the newest is **a
search in a file is not a measurement of an object**. A claim like "`XSEED`
appears nowhere in this object" or "`xinput1_3.dll` is named by nothing" is a
claim about every byte, and it is worth exactly as much as the search behind it.

So this tool takes strings and a root, reads **every file in full** -- no size
cap, no sampling, no extension filter -- and reports, per string, the count in
ASCII, in UTF-16LE and in Shift-JIS, and which files carry it. A string that is
found nowhere prints `-- nowhere in the object --` rather than a blank, so a
zero is visibly a measurement rather than a tool that failed to run.

The chunked reader carries a 64-byte overlap between reads so a match that
straddles a chunk boundary is not lost.

    python tools/strcount.py "<root>" xinput1_3.dll XINPUT9_1_0.dll steam_api.dll
    python tools/strcount.py "<root>" --file strings.txt
    python tools/strcount.py "<root>" ED6_DT1A --encodings ascii

Strings that are personal identifiers should not be given to this tool: it
prints what it is given. Use `envblock.py --leakcheck` for those, which counts
without printing.
"""
import argparse
import os
import sys

ENCODINGS = [("ascii", "latin-1"), ("utf-16", "utf-16-le"), ("sjis", "cp932")]
OVERLAP = 64


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("strings", nargs="*")
    ap.add_argument("--file", default=None,
                    help="read one string per line from this file as well")
    ap.add_argument("--encodings", nargs="*", default=None,
                    help="limit to these: ascii, utf-16, sjis")
    ap.add_argument("--files", action="store_true",
                    help="list every file that carries each string, not the first six")
    a = ap.parse_args()

    wanted = list(a.strings)
    if a.file:
        with open(a.file, encoding="utf-8") as fh:
            wanted += [ln.rstrip("\n") for ln in fh if ln.strip()]
    if not wanted:
        sys.exit("give at least one string, or --file")

    encs = [e for e in ENCODINGS
            if a.encodings is None or e[0] in a.encodings]
    needles = {}
    aliased = 0          # strings whose codecs collapse to the same bytes
    alias_note = {}
    for s in wanted:
        seen = {}
        for label, codec in encs:
            try:
                nd = s.encode(codec)
            except UnicodeEncodeError:
                continue
            if nd in seen:
                # Shift-JIS is ASCII-compatible in the single-byte range, so an
                # ASCII string encodes identically under cp932 and latin-1.
                # Counting it twice does not make it two pieces of evidence.
                alias_note.setdefault(s, []).append((label, seen[nd]))
                aliased += 1
                continue
            seen[nd] = label
            needles.setdefault(s, {})[label] = nd
    counted_once = True

    paths = []
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames.sort()
        for fn in sorted(filenames):
            paths.append(os.path.join(dirpath, fn))

    live = [(label, codec) for label, codec in encs
            if any(label in needles.get(s, {}) for s in wanted)]
    counts = {s: {label: 0 for label, _ in encs} for s in wanted}
    where = {s: set() for s in wanted}
    nbytes = 0
    for p in paths:
        rel = os.path.relpath(p, a.root)
        with open(p, "rb") as fh:
            prev = b""
            while True:
                chunk = fh.read(1 << 22)
                if not chunk:
                    break
                nbytes += len(chunk)
                buf = prev + chunk
                for s, byenc in needles.items():
                    for label, nd in byenc.items():
                        n = buf.count(nd)
                        if n:
                            counts[s][label] += n
                            where[s].add(rel)
                prev = buf[-OVERLAP:]

    print("root           : %s" % ("<install dir>" if os.path.isabs(a.root) else a.root))
    print("files searched : %d" % len(paths))
    print("bytes searched : %d   (every byte of every file, no cap)" % nbytes)
    print("encodings      : %s" % ", ".join(l for l, _ in live))
    if aliased:
        dropped = sorted({b for v in alias_note.values() for b, _a in v})
        kept = sorted({a for v in alias_note.values() for _b, a in v})
        print("encodings asked for but NOT independent : %s"
              % ", ".join(dropped))
        print("   %d of the %d strings encode to the SAME bytes under %s as"
              % (len(alias_note), len(wanted), ", ".join(dropped)))
        print("   under %s, so that column would repeat this one rather than"
              % ", ".join(kept))
        print("   corroborate it.  It is not counted and not printed.")
        print("   Every row below therefore rests on %d independent"
              % len(live))
        print("   encoding(s), not %d." % len(encs))
    print()
    head = "%-24s" % "string"
    for label, _ in live:
        head += " %8s" % label
    print(head + "  files that carry it")
    for s in wanted:
        row = "%-24s" % (s if len(s) <= 24 else s[:21] + "...")
        for label, _ in live:
            row += " %8d" % counts[s][label]
        fs = sorted(where[s])
        if not fs:
            row += "  -- nowhere in the object --"
        elif a.files or len(fs) <= 6:
            row += "  " + ", ".join(fs)
        else:
            row += "  " + ", ".join(fs[:6]) + " (+%d more)" % (len(fs) - 6)
        print(row)


if __name__ == "__main__":
    main()
