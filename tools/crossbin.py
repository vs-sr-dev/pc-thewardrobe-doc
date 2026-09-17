#!/usr/bin/env python3
"""How much of two binaries is literally the same bytes.

`shared_runs()` below is **lifted verbatim** from `crossz.py` in
`pc-leathergoddessesofphobos-doc`, where it measured how much two Infocom
story files share. Nothing in it is Z-machine-specific -- it is a suffix-window
index and an extension walk -- so it is reused unchanged, and this file states
that rather than pretending to be new work.

What had to change is everything around it, and it is worth listing because
the changes are the reason `crossz.py` itself was not carried into this
repository:

  * `crossz.py`'s entry points all take a *pair of Z-machine story files plus
    their header offsets*; three of its four commands are about abbreviation
    tables, dictionaries and action tables, which do not exist here.
  * Its `rep_bytes` opened files whole. Two DOS/4GW executables are 133 KB and
    255 KB, which is fine, but the same question asked of `SAMNMAX.001` and a
    254 KB executable is 13.8 MB against 255 KB, so this version takes a
    `--limit` and reports when it has truncated, instead of quietly running
    for minutes.
  * `--decrypt` XORs one side with 0x69, because one of the interesting pairs
    here has an encrypted member.

A run is counted once however many times it occurs, and the occurrence count
is printed separately, so that a run of 256 zero bytes appearing 400 times
cannot inflate the shared total. That property is `crossz.py`'s and it is why
it was worth reusing rather than rewriting.

Usage:
  python tools/crossbin.py <A> <B> [minrun] [--decrypt-a] [--decrypt-b]
                                   [--limit N] [--top N]
"""
import collections
import os
import sys


def shared_runs(a, b, minrun):
    """Every maximal run of >= minrun bytes of `a` that occurs anywhere in
    `b`, reported once per distinct run content.

    Method, stated because it is the part that can be wrong: index every
    position of `b` by its minrun-byte window, then walk `a` extending each
    window hit as far as it goes. A run is counted once however many times it
    occurs; `occurrences` reports the multiplicity separately, so a run of 32
    zero bytes that appears 400 times cannot inflate the shared total."""
    idx = collections.defaultdict(list)
    for i in range(len(b) - minrun + 1):
        idx[b[i:i + minrun]].append(i)
    runs = {}
    i = 0
    while i <= len(a) - minrun:
        w = a[i:i + minrun]
        hits = idx.get(w)
        if not hits:
            i += 1
            continue
        best = 0
        for j in hits:
            n = minrun
            while (i + n < len(a) and j + n < len(b) and a[i + n] == b[j + n]):
                n += 1
            best = max(best, n)
        runs[a[i:i + best]] = runs.get(a[i:i + best], 0) + 1
        i += best
    return runs


def pct(x, y):
    return 100.0 * x / y if y else 0.0


def main(argv):
    minrun = 32
    limit = 0
    top = 8
    da = db = False
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--decrypt-a":
            da = True; i += 1
        elif argv[i] == "--decrypt-b":
            db = True; i += 1
        elif argv[i] == "--limit":
            limit = int(argv[i + 1]); i += 2
        elif argv[i] == "--top":
            top = int(argv[i + 1]); i += 2
        else:
            rest.append(argv[i]); i += 1
    pa, pb = rest[0], rest[1]
    if len(rest) > 2:
        minrun = int(rest[2])
    a = open(pa, "rb").read()
    b = open(pb, "rb").read()
    if da:
        a = bytes(x ^ 0x69 for x in a)
    if db:
        b = bytes(x ^ 0x69 for x in b)
    trunc = ""
    if limit and len(a) > limit:
        a = a[:limit]
        trunc = "  (A TRUNCATED to %d bytes)" % limit
    if limit and len(b) > limit:
        b = b[:limit]
        trunc += "  (B TRUNCATED to %d bytes)" % limit
    runs = shared_runs(a, b, minrun)
    tot = sum(len(r) for r in runs)
    occ = sum(runs.values())
    print("shared byte runs of >= %d bytes%s" % (minrun, trunc))
    print("  A %s  %d bytes%s" % (os.path.basename(pa), len(a),
                                  " (XOR 0x69)" if da else ""))
    print("  B %s  %d bytes%s" % (os.path.basename(pb), len(b),
                                  " (XOR 0x69)" if db else ""))
    print("  distinct runs          %d" % len(runs))
    print("  occurrences in A       %d" % occ)
    print("  bytes in distinct runs %d = %.4f %% of A, %.4f %% of B"
          % (tot, pct(tot, len(a)), pct(tot, len(b))))
    if runs:
        longest = max(runs, key=len)
        print("  longest run            %d bytes" % len(longest))
        print("  longest run head       %s" % longest[:48].hex())
        pr = bytes(c if 32 <= c < 127 else 46 for c in longest[:64])
        print("  longest run as text    %s" % pr.decode("latin-1"))
    for r in sorted(runs, key=len, reverse=True)[:top]:
        pr = bytes(c if 32 <= c < 127 else 46 for c in r[:40])
        print("     %5d B  x%-3d  %s" % (len(r), runs[r], pr.decode("latin-1")))


if __name__ == "__main__":
    main(sys.argv[1:])
