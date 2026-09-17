#!/usr/bin/env python3
"""qtext.py -- everything in this bundle that is words.

Four places hold text, and only one of them is obvious.

  `QUEEN2.JAS`   35,840 bytes of plain ASCII, one line per sentence the game
                 can display, each ending in `*` and a number.
  `.DOG`         73 AMOS banks of dialogue, with the same `*NN` convention
                 embedded in a binary tree structure.
  `.CRD` + `DATA` the credits, in a small markup where a line beginning `.i`
                 indents, `.c` centres, `.l` and `.r` align and `.p` paginates.
  `.CUT`         301 cutscene scripts, which are mostly not words.

The `*NN` suffix is counted rather than guessed at: it is stripped, tallied, and
its distribution reported, because a number that appears on almost every line of
a talkie is worth a sentence either way.

    python tools/qtext.py credits _game/scummvm/scummvm.exe _game/queen.1
    python tools/qtext.py lines   _game/scummvm/scummvm.exe _game/queen.1
    python tools/qtext.py xref    _game/scummvm/scummvm.exe _game/queen.1
"""

import argparse
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qres  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

STAR = re.compile(r"\*(\d+)")


def cmd_credits(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    for nm in ("DATA", "CREDIT1.CRD", "CREDIT2.CRD"):
        r = d[nm]
        b = data[r[2]:r[2] + r[3]]
        print("=" * 70)
        print("%s -- %d bytes" % (nm, r[3]))
        print("=" * 70)
        txt = b.decode("latin1")
        print(txt.replace("\r\n", "\n"))
    return 0


def cmd_lines(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    r = d["QUEEN2.JAS"]
    b = data[r[2]:r[2] + r[3]]
    txt = b.decode("latin1")
    lines = [x for x in txt.split("\r\n") if x]
    print("QUEEN2.JAS          %d bytes" % r[3])
    print("printable bytes     %d = %.2f %%"
          % (sum(1 for c in b if 32 <= c < 127 or c in (13, 10)),
             100.0 * sum(1 for c in b if 32 <= c < 127 or c in (13, 10)) / r[3]))
    print("lines               %d" % len(lines))
    stars = Counter()
    words = 0
    chars = 0
    for L in lines:
        for s in STAR.findall(L):
            stars[int(s)] += 1
        clean = STAR.sub("", L)
        words += len(clean.split())
        chars += len(clean)
    print("words               %d" % words)
    print("characters, codes   %d (codes stripped)" % chars)
    print("lines carrying *NN  %d" % sum(1 for L in lines if STAR.search(L)))
    print("distinct *NN values %d, most common %s"
          % (len(stars), stars.most_common(10)))
    print()
    print("first %d lines:" % a.top)
    for L in lines[:a.top]:
        print("   %s" % L)
    print()

    dogs = [r for r in recs if r[0].upper().endswith(".DOG")]
    dwords = 0
    dchars = 0
    dlines = 0
    dstars = Counter()
    body = 0
    for name, bundle, off, size in dogs:
        b = data[off:off + size]
        body += size - 20
        for m in re.finditer(rb"[\x20-\x7e]{8,}", b[20:]):
            s = m.group().decode("latin1")
            for x in STAR.findall(s):
                dstars[int(x)] += 1
            clean = STAR.sub("", s)
            dlines += 1
            dwords += len(clean.split())
            dchars += len(clean)
    print(".DOG                %d banks, %d body bytes" % (len(dogs), body))
    print("printable runs >=8  %d" % dlines)
    print("words               %d" % dwords)
    print("characters          %d = %.2f %% of the bodies"
          % (dchars, 100.0 * dchars / body))
    print("distinct *NN values %d, most common %s"
          % (len(dstars), dstars.most_common(8)))
    print()
    print("all the words in the game: %d in QUEEN2.JAS + %d in .DOG = %d"
          % (words, dwords, words + dwords))
    return 0


def cmd_xref(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    sb = [r[0][:8] for r in recs if r[0].upper().endswith(".SB")]
    cut = [os.path.splitext(r[0])[0] for r in recs
           if r[0].upper().endswith(".CUT")]
    dog = [os.path.splitext(r[0])[0] for r in recs
           if r[0].upper().endswith(".DOG")]
    cutset = set(cut)
    hit = Counter()
    for s in sb:
        for k in (5, 4, 3):
            if s[:k] in cutset:
                hit[s[:k]] += 1
                break
    print("speech resources    %d" % len(sb))
    print(".CUT scripts        %d" % len(cut))
    print(".DOG banks          %d" % len(dog))
    print()
    print("speech names whose leading characters are a .CUT name: %d (%.2f %%)"
          % (sum(hit.values()), 100.0 * sum(hit.values()) / len(sb)))
    print(".CUT names that at least one speech file points at:    %d of %d"
          % (len(hit), len(cut)))
    print()
    print("%-10s %s" % ("cutscene", "speech takes"))
    for k, v in hit.most_common(a.top):
        print("%-10s %d" % (k, v))
    print()
    rooms = Counter(s[:2] for s in sb if s[:2].isdigit())
    print("speech whose name begins with two digits: %d, over %d room numbers"
          % (sum(rooms.values()), len(rooms)))
    print("busiest rooms       %s" % rooms.most_common(8))
    speakers = Counter(s[6] for s in sb if s[:2].isdigit())
    print("speaker letter      %s" % dict(speakers.most_common()))
    takes = Counter(s[7] for s in sb if s[:2].isdigit())
    print("take digit          %s" % dict(sorted(takes.items())))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("credits", cmd_credits), ("lines", cmd_lines),
                     ("xref", cmd_xref)):
        p = sub.add_parser(name)
        p.add_argument("exe")
        p.add_argument("bundle")
        p.add_argument("--top", type=int, default=12)
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
