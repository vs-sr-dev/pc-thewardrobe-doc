#!/usr/bin/env python3
"""kultlang.py -- the eight localisations of *Kult: Heretic Kingdoms*, counted
against each other rather than described.

The object ships `br ch de eng es fr it ru` and the shop's `.info` declares
one, `en`. The eight do not hold the same things: the file counts are within
10 % of each other and the byte counts differ by a factor of eleven, Spanish
and Italian holding 2.7 megabytes where Russian holds 30.

This tool answers that with set differences instead of totals. For every
localised directory -- `attunements`, `quests`, `hints`, `dia`, `dialogs`,
`Leveltext` -- it lists the entries each language has, and reports:

  * the per-language file and byte count, split by extension, which is where
    the eleven-to-one gap either is or is not the voice-over;
  * the entries English has and another language does not, **by name**;
  * the entries a language has and English does not.

    python tools/kultlang.py census   "<root>"
    python tools/kultlang.py diff     "<root>" quests
    python tools/kultlang.py diff     "<root>" attunements --lang it
    python tools/kultlang.py selftest
"""
import argparse
import collections
import os
import sys

LANGS = ["br", "ch", "de", "eng", "es", "fr", "it", "ru"]
# `data\dia\<lang>`, `data\quests\<lang>`, ... -- the parent is the subsystem
SUBSYSTEMS = ["attunements", "dia", "dialogs", "hints", "Leveltext", "quests"]
REFERENCE = "eng"


class LangError(Exception):
    pass


def lang_dir(root, sub, lang):
    return os.path.join(root, "data", sub, lang)


def entries(root, sub, lang):
    """The set of names one level below `data/<sub>/<lang>`, with a flag for
    whether each is a directory. Names are compared case-insensitively because
    the object's own tree relies on that -- `stand1` and `Stand1` are the same
    animation."""
    d = lang_dir(root, sub, lang)
    if not os.path.isdir(d):
        return {}
    out = {}
    for name in os.listdir(d):
        out[name.lower()] = (name, os.path.isdir(os.path.join(d, name)))
    return out


def weigh(root, sub, lang):
    """(files, bytes, per-extension bytes) under one language directory."""
    d = lang_dir(root, sub, lang)
    files = 0
    total = 0
    per = collections.Counter()
    perf = collections.Counter()
    for dirpath, dirnames, filenames in os.walk(d):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            s = os.path.getsize(p)
            files += 1
            total += s
            e = os.path.splitext(fn)[1].lower()
            per[e] += s
            perf[e] += 1
    return files, total, per, perf


def cmd_census(a):
    print("%-12s %8s %8s %8s %8s %8s %8s %8s %8s"
          % ("subsystem", *LANGS))
    for sub in SUBSYSTEMS:
        row = [len(entries(a.root, sub, l)) for l in LANGS]
        print("%-12s %8d %8d %8d %8d %8d %8d %8d %8d" % (sub, *row))
    print()
    print("%-6s %8s %12s %12s %12s %12s %8s"
          % ("lang", "files", "bytes", ".ogg bytes", ".txt bytes",
             "other bytes", ".ogg"))
    grand_f = grand_b = 0
    per_lang = {}
    for l in LANGS:
        f = b = 0
        ogg = txt = other = 0
        oggn = 0
        for sub in SUBSYSTEMS:
            ff, bb, per, perf = weigh(a.root, sub, l)
            f += ff
            b += bb
            ogg += per.get(".ogg", 0)
            txt += per.get(".txt", 0)
            oggn += perf.get(".ogg", 0)
            other += bb - per.get(".ogg", 0) - per.get(".txt", 0)
        per_lang[l] = (f, b, ogg, txt, other, oggn)
        grand_f += f
        grand_b += b
        print("%-6s %8d %12d %12d %12d %12d %8d" % (l, f, b, ogg, txt, other, oggn))
    print("%-6s %8d %12d" % ("total", grand_f, grand_b))
    print()
    big = max(per_lang, key=lambda l: per_lang[l][1])
    small = min(per_lang, key=lambda l: per_lang[l][1])
    fb, bb = per_lang[big][1], per_lang[small][1]
    print("largest is %s at %d bytes, smallest is %s at %d, ratio %.4f"
          % (big, fb, small, bb, fb / float(bb)))
    print("and with .ogg removed from both: %d against %d, ratio %.4f"
          % (per_lang[big][1] - per_lang[big][2],
             per_lang[small][1] - per_lang[small][2],
             (per_lang[big][1] - per_lang[big][2])
             / float(per_lang[small][1] - per_lang[small][2])))


def cmd_diff(a):
    sub = a.sub
    ref = entries(a.root, sub, REFERENCE)
    if not ref:
        raise LangError("no data/%s/%s in %s" % (sub, REFERENCE, a.root))
    langs = [a.lang] if a.lang else [l for l in LANGS if l != REFERENCE]
    print("subsystem : data/%s" % sub)
    print("reference : %s, %d entries" % (REFERENCE, len(ref)))
    print()
    for l in langs:
        e = entries(a.root, sub, l)
        missing = sorted(set(ref) - set(e))
        extra = sorted(set(e) - set(ref))
        print("%-4s %5d entries   missing from it %4d   not in %s %4d"
              % (l, len(e), len(missing), REFERENCE, len(extra)))
        if a.names:
            for m in missing:
                print("      -- %s" % ref[m][0])
            for x in extra:
                print("      ++ %s" % e[x][0])
    print()
    # the union view: which entries exist in how many languages
    tally = collections.Counter()
    where = collections.defaultdict(list)
    for l in LANGS:
        for k, (name, isdir) in entries(a.root, sub, l).items():
            tally[k] += 1
            where[k].append(l)
    hist = collections.Counter(tally.values())
    print("entries by how many of the eight languages hold them:")
    for k in sorted(hist, reverse=True):
        print("   in %d languages : %d entries" % (k, hist[k]))
    if a.names:
        for n in sorted(hist):
            if n == 8:
                continue
            print()
            print("the entries present in exactly %d languages:" % n)
            for k in sorted(tally):
                if tally[k] == n:
                    print("   %-44s %s" % (k, " ".join(where[k])))


def cmd_selftest(a):
    """The comparison is a set difference over directory listings, so the
    thing that can go wrong is case. This checks that."""
    ok = True
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        for lang, names in (("eng", ["Quest_One.txt", "quest_two.txt"]),
                            ("it", ["QUEST_ONE.TXT"])):
            d = os.path.join(t, "data", "quests", lang)
            os.makedirs(d)
            for n in names:
                open(os.path.join(d, n), "w").close()
        e = entries(t, "quests", "eng")
        i = entries(t, "quests", "it")
        missing = sorted(set(e) - set(i))
        good = missing == ["quest_two.txt"]
        print("   %-5s case-insensitive difference -> %r"
              % ("ok" if good else "FAIL", missing))
        ok = ok and good
        empty = entries(t, "quests", "zz")
        good2 = empty == {}
        print("   %-5s a language directory that does not exist -> %r"
              % ("ok" if good2 else "FAIL", empty))
        ok = ok and good2
    try:
        cmd_diff(argparse.Namespace(root=".", sub="nosuchthing", lang=None,
                                    names=False))
    except LangError as exc:
        print("   ok    a subsystem that does not exist is refused: %s" % exc)
    else:
        print("   FAIL  a subsystem that does not exist was accepted")
        ok = False
    print()
    print("%s" % ("all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("census"); p.add_argument("root"); p.set_defaults(fn=cmd_census)
    p = sub.add_parser("diff"); p.add_argument("root"); p.add_argument("sub")
    p.add_argument("--lang"); p.add_argument("--names", action="store_true")
    p.set_defaults(fn=cmd_diff)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    try:
        rc = a.fn(a)
    except LangError as exc:
        sys.exit("LangError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
