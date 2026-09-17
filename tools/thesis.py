#!/usr/bin/env python3
"""thesis.py -- how much of this object is recorded sound and film.

The collection asks one question of every object: what fraction of its bytes is
a recording of something that happened in a room -- speech, music, film -- as
against everything a programmer or an artist made. This tool answers it for
Broken Sword: The Angel of Death by summing member sizes from the tables
`empack.py` wrote, and it does the sum twice: once by the member's file
extension, once by the signature actually found at its first byte, so the two
can be compared and the disagreements printed rather than averaged away.

Every figure is given against BOTH denominators the repository publishes: the
whole disk (31 files, 2,668,075,144 bytes) and the archives alone.

    python tools/thesis.py --tsv _work/members-bs4.tsv --archive-size 1979623974 \\
                           --tsv ... --total 2668075144
"""
import argparse
import collections
import csv
import os
import sys

SOUND_EXT = {".mp3", ".wav", ".ogg", ".aif", ".aiff"}
FILM_EXT = {".bik", ".avi", ".mpg", ".mpeg", ".bk2"}
SOUND_SIG = {"MPEG audio frame", "MP3 with ID3 tag", "RIFF", "Ogg"}
FILM_SIG = {"Bink video (BIKi)", "Bink video (BIKb)", "Bink video (BIKf)",
            "Bink video (BIKg)", "Bink video (BIKh)"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", action="append", required=True)
    ap.add_argument("--total", type=int, required=True,
                    help="bytes of the whole object")
    a = ap.parse_args()

    rows = []
    for t in a.tsv:
        tag = os.path.basename(t).replace("members-", "").replace(".tsv", "")
        for r in csv.DictReader(open(t, encoding="utf-8"), delimiter="\t"):
            rows.append((tag, r["name"], int(r["size"]), r["signature"]))

    arch = sum(s for _t, _n, s, _g in rows)
    print("member tables read   : %d" % len(a.tsv))
    print("members              : %d" % len(rows))
    print("bytes inside members : %d" % arch)
    print("whole object         : %d" % a.total)
    print()

    print("-- by extension --")
    ext = collections.Counter()
    extb = collections.Counter()
    for _t, n, s, _g in rows:
        e = os.path.splitext(n)[1].lower()
        ext[e] += 1
        extb[e] += s
    print("   %-12s %8s %16s %10s %10s" % ("ext", "members", "bytes",
                                           "of object", "of members"))
    for e, n in extb.most_common(20):
        print("   %-12s %8d %16d %9.4f %% %9.4f %%"
              % (e or "(none)", ext[e], extb[e],
                 100.0 * extb[e] / a.total, 100.0 * extb[e] / arch))

    print()
    print("-- by signature --")
    sig = collections.Counter()
    sigb = collections.Counter()
    for _t, _n, s, g in rows:
        sig[g] += 1
        sigb[g] += s
    for g, n in sigb.most_common(20):
        print("   %-26s %8d %16d %9.4f %%"
              % (g, sig[g], sigb[g], 100.0 * sigb[g] / a.total))

    print()
    print("-- the two sums --")
    for label, fn in (("by extension",
                       lambda t, n, s, g: (os.path.splitext(n)[1].lower() in SOUND_EXT,
                                           os.path.splitext(n)[1].lower() in FILM_EXT)),
                      ("by signature",
                       lambda t, n, s, g: (g in SOUND_SIG, g in FILM_SIG))):
        snd = sum(s for t, n, s, g in rows if fn(t, n, s, g)[0])
        flm = sum(s for t, n, s, g in rows if fn(t, n, s, g)[1])
        sn = sum(1 for t, n, s, g in rows if fn(t, n, s, g)[0])
        fn_ = sum(1 for t, n, s, g in rows if fn(t, n, s, g)[1])
        print("   %s:" % label)
        print("      sound  %6d members %14d bytes  %8.4f %% of the object"
              % (sn, snd, 100.0 * snd / a.total))
        print("      film   %6d members %14d bytes  %8.4f %% of the object"
              % (fn_, flm, 100.0 * flm / a.total))
        print("      TOGETHER              %14d bytes  %8.4f %% of the object"
              % (snd + flm, 100.0 * (snd + flm) / a.total))

    print()
    print("-- where extension and signature disagree --")
    dis = collections.Counter()
    for t, n, s, g in rows:
        e = os.path.splitext(n)[1].lower()
        se = e in SOUND_EXT or e in FILM_EXT
        sg = g in SOUND_SIG or g in FILM_SIG
        if se != sg:
            dis[(e, g)] += 1
    if not dis:
        print("   none: every member the extension calls a recording is one, and")
        print("   every member the signature calls a recording has the extension.")
    for (e, g), n in dis.most_common(14):
        print("   %-10s named, %-26s found : %d" % (e or "(none)", g, n))

    print()
    print("-- per archive --")
    for tag in sorted({t for t, _n, _s, _g in rows}):
        sel = [r for r in rows if r[0] == tag]
        b = sum(r[2] for r in sel)
        snd = sum(r[2] for r in sel if os.path.splitext(r[1])[1].lower() in SOUND_EXT)
        flm = sum(r[2] for r in sel if os.path.splitext(r[1])[1].lower() in FILM_EXT)
        print("   %-10s %6d members %14d bytes  sound %8.4f %%  film %8.4f %%"
              % (tag, len(sel), b, 100.0 * snd / b, 100.0 * flm / b))
    return 0


if __name__ == "__main__":
    sys.exit(main())
