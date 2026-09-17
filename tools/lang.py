#!/usr/bin/env python3
"""Which files of this object contain Italian, and how many bytes is that.

The question the layer table cannot answer: *how much of this disc was made in
Italy?* The obvious answer -- two `README.TXT` files, 18,344 bytes, 0.0081 % --
is wrong, and this tool is what shows it is wrong.

The measurement, and its guard. A naive count of Italian function words in a
binary finds Italian in everything: `di`, `la`, `si`, `no` and `come` occur by
accident in 8-bit audio and in 8 MB of video, and on a first pass this tool
reported Italian in two Rebel Assault sound effects and in `O1OPEN.ANM`. So a
file counts as carrying Italian only if it contains at least one **sentence**:
a printable run of `--minrun` characters or more (default 30) holding at least
`--minmarkers` distinct Italian marker words (default 3) and more Italian
markers than English ones. A run of PCM does not do that; a dialogue box does.

Both the sentence hits and the raw per-file word counts are printed, so the
guard can be inspected rather than trusted. The word lists are the ones in
`scummtext.py`, imported rather than copied, so there is one list to disagree
with.

`SAMNMAX.001` is decrypted with XOR 0x69 before scanning; `MONSTER.SOU` is
scanned like everything else -- 200 MB of 8-bit PCM is exactly the population
the guard exists for, and the result of scanning it is a result.

Usage:
  python tools/lang.py <object_dir> <census.txt> [--minrun 30] [--minmarkers 3]
                       [--show N]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scummtext import IT, EN                                  # noqa: E402

WORD = re.compile(r"[A-Za-zÀ-ÿ']+")
RUN = re.compile(rb"[\x20-\x7e\x80-\xa5]+")


def read_census(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 5:
            out[f[4].replace(chr(92), "/")] = int(f[1])
    return out


def scan(data, minrun, minmarkers):
    words = 0
    it = en = 0
    hits = []
    for m in RUN.finditer(data):
        s = m.group().decode("cp437")
        ws = [w.lower() for w in WORD.findall(s)]
        words += len(ws)
        i = sum(1 for w in ws if w in IT)
        e = sum(1 for w in ws if w in EN)
        it += i
        en += e
        if len(s) >= minrun:
            distinct = len({w for w in ws if w in IT})
            if distinct >= minmarkers and i > e:
                hits.append(s)
    return words, it, en, hits


def main(argv):
    minrun = 30
    minmarkers = 3
    show = 2
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--minrun":
            minrun = int(argv[i + 1]); i += 2
        elif argv[i] == "--minmarkers":
            minmarkers = int(argv[i + 1]); i += 2
        elif argv[i] == "--show":
            show = int(argv[i + 1]); i += 2
        else:
            rest.append(argv[i]); i += 1
    root, census = rest[0], rest[1]
    sizes = read_census(census)
    total = sum(sizes.values())
    print("%-28s %11s %7s %7s %8s %6s"
          % ("file", "bytes", "IT", "EN", "words", "sent."))
    carriers = []
    for dp, _, ns in os.walk(root):
        for n in sorted(ns):
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, root).replace(chr(92), "/")
            d = open(p, "rb").read()
            if rel.endswith("SAMNMAX.001"):
                d = bytes(b ^ 0x69 for b in d)
            words, it, en, hits = scan(d, minrun, minmarkers)
            print("%-28s %11d %7d %7d %8d %6d"
                  % (rel, sizes.get(rel, len(d)), it, en, words, len(hits)))
            if hits:
                carriers.append((rel, sizes.get(rel, len(d)), hits))
    print()
    s = sum(z for _, z, _ in carriers)
    print("files carrying at least one Italian sentence: %d of %d"
          % (len(carriers), len(sizes)))
    print("their size: %d bytes = %.4f %% of %d" % (s, 100.0 * s / total, total))
    print()
    for rel, z, hits in carriers:
        print("  %-28s %11d  %d sentence(s)" % (rel, z, len(hits)))
        for h in hits[:show]:
            print("      %s" % h.strip()[:96])


if __name__ == "__main__":
    main(sys.argv[1:])
