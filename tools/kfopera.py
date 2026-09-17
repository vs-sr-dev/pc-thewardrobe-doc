#!/usr/bin/env python3
"""opera.py -- how a rock opera becomes five worlds, measured without leaving
the bytes.

THE MEASUREMENT
---------------
Two lists exist inside the object and neither was written with the other in
mind: the eighty-nine cooked map names under `KFGame\\CookedPC\\Maps\\`, and
the twelve `TIT2` frames of the soundtrack's MP3. This program compares them
as sets of tokens.

A map name like `KF-W5_Twins` is split on the separators UE3 map names use
(`-`, `_`) and on capital-letter boundaries; a track title like *The Twins* is
split on spaces and stripped of stop words. The intersection is published, and
so is the part that does not intersect --- which is most of it, and saying so
is the point. A correspondence that only prints its hits is not a measurement.

    python tools/kfopera.py --selftest
    python tools/kfopera.py --match
    python tools/kfopera.py --worlds
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kfaudio                                    # noqa: E402

ROOT = "karmaflow-steam"
MAPS = os.path.join("KFGame", "CookedPC", "Maps")
STOP = {"the", "of", "and", "a", "an"}


def tokens(name):
    """Split a UE3 map name into lower-case word tokens."""
    s = re.sub(r"^KF[-_]?", "", name)
    s = re.sub(r"^W\d+[-_]?", "", s)
    parts = re.split(r"[-_\s]+", s)
    out = []
    for p in parts:
        for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+", p):
            w = w.lower()
            if w and w not in STOP:
                out.append(w)
    return out


def title_tokens(t):
    return [w.lower() for w in re.findall(r"[A-Za-z]+", t)
            if w.lower() not in STOP]


def maps(root):
    out = []
    base = os.path.join(root, MAPS)
    for r, _d, fs in os.walk(base):
        world = os.path.relpath(r, base).replace("\\", "/")
        for f in sorted(fs):
            out.append((world if world != "." else "(loose)",
                        os.path.splitext(f)[0],
                        os.path.getsize(os.path.join(r, f))))
    return out


def tracks(root):
    out = []
    for p in kfaudio.mp3s(root):
        data = open(p, "rb").read(1 << 20)
        _v, _f, _s, _e, fr = kfaudio.id3(data)
        out.append((int(fr["TRCK"][0]), fr["TIT2"][0]))
    return sorted(out)


def cmd_match(args):
    ms = maps(args.root)
    ts = tracks(args.root)
    print("map packages : %d      soundtrack titles : %d" % (len(ms), len(ts)))
    print()
    tset = {}
    for num, t in ts:
        for w in title_tokens(t):
            tset.setdefault(w, []).append((num, t))
    print("the title vocabulary, %d distinct words:" % len(tset))
    print("   %s" % " ".join(sorted(tset)))
    print()
    hits = []
    misses = []
    for world, name, size in ms:
        got = [w for w in tokens(name) if w in tset]
        if got:
            hits.append((world, name, size, got,
                         sorted({t for w in got for t in tset[w]})))
        else:
            misses.append((world, name, size))
    print("%-9s %-34s %13s  %s" % ("world", "map", "bytes", "shared word ->"
                                   " track"))
    for world, name, size, got, tr in sorted(hits):
        print("%-9s %-34s %13d  %s -> %s"
              % (world, name, size, ",".join(got),
                 "; ".join("%d %s" % t for t in tr)))
    print()
    print("maps sharing a word with a track title : %d of %d = %.4f %%"
          % (len(hits), len(ms), 100.0 * len(hits) / len(ms)))
    print("maps sharing nothing                   : %d of %d = %.4f %%"
          % (len(misses), len(ms), 100.0 * len(misses) / len(ms)))
    print("bytes on the matching side             : %d of %d = %.4f %%"
          % (sum(h[2] for h in hits), sum(m[2] for m in ms),
             100.0 * sum(h[2] for h in hits) / sum(m[2] for m in ms)))
    print()
    covered = sorted({t[0] for h in hits for t in h[4]})
    print("tracks named by at least one map : %d of 12 -- %s"
          % (len(covered), covered))
    print("tracks named by no map           : %s"
          % [n for n, _t in ts if n not in covered])
    print()
    print("the maps that share nothing, which are most of them:")
    for world, name, size in sorted(misses)[:40]:
        print("   %-9s %-40s %d" % (world, name, size))
    if len(misses) > 40:
        print("   ... and %d more" % (len(misses) - 40))
    return 0


def cmd_worlds(args):
    ms = maps(args.root)
    by = collections.Counter()
    bb = collections.Counter()
    for world, name, size in ms:
        by[world] += 1
        bb[world] += size
    print("%-10s %6s %14s %9s" % ("world", "maps", "bytes", "share"))
    tot = sum(bb.values())
    for k in sorted(by):
        print("%-10s %6d %14d %8.4f %%" % (k, by[k], bb[k],
                                           100.0 * bb[k] / tot))
    print("%-10s %6d %14d %8.4f %%" % ("sum", sum(by.values()), tot, 100.0))
    print()
    tags = collections.Counter()
    for _w, name, _s in ms:
        for t in re.findall(r"_(T\d|PW|P\d|Climax|Lighting|Audio|Subtitles|"
                            r"Collectibles|Collectables|Cinematics|"
                            r"Staticmeshes|Decoration)", name):
            tags[t] += 1
    print("recurring name components across the 89 maps:")
    for k, v in tags.most_common():
        print("   %-14s %d" % (k, v))
    print()
    nonascii = [n for _w, n, _s in ms if not n.isascii()]
    lower = [n for _w, n, _s in ms if n.islower()]
    temp = [n for _w, n, _s in ms if "TEMP" in n.upper()]
    print("map names that are entirely lower case : %s" % lower)
    print("map names still carrying TEMP          : %s" % temp)
    print("map names with a byte above 0x7F       : %s" % nonascii)
    return 0


def selftest():
    cases = []
    cases.append(("KF-W5_Twins yields 'twins'",
                  tokens("KF-W5_Twins") == ["twins"]))
    cases.append(("KF-W3_Sky_BirdGoddessFight splits the run of capitals",
                  tokens("KF-W3_Sky_BirdGoddessFight")
                  == ["sky", "bird", "goddess", "fight"]))
    cases.append(("KF-W5_Conductor yields 'conductor'",
                  tokens("KF-W5_Conductor") == ["conductor"]))
    cases.append(("the world prefix is stripped",
                  "w5" not in tokens("KF-W5_Heart")))
    cases.append(("stop words are dropped from a title",
                  title_tokens("The Muse And The Conductor")
                  == ["muse", "conductor"]))
    cases.append(("a Dutch map name yields its own word",
                  tokens("extraleveldingen") == ["extraleveldingen"]))
    cases.append(("KF-W2_SwampPuzzleTEMP keeps TEMP",
                  "temp" in tokens("KF-W2_SwampPuzzleTEMP")))
    cases.append(("a numeric part survives",
                  tokens("KF-W2_1stShaman")[:2] == ["1", "st"]))
    ok = sum(1 for _n, v in cases if v)
    print("kfopera selftest: %d specimens" % len(cases))
    for n, v in cases:
        print("  %-52s %s" % (n, "PASS" if v else "FAIL"))
    print()
    print("%d of %d behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    for c in ("selftest", "match", "worlds"):
        ap.add_argument("--" + c, action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.match:
        return cmd_match(a)
    if a.worlds:
        return cmd_worlds(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
