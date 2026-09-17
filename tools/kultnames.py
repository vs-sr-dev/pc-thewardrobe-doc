#!/usr/bin/env python3
"""kultnames.py -- census the naming layers of *Kult: Heretic Kingdoms*.

On this object the names ARE the content. Nothing is hidden and everything is
enormous: the directory tree carries the cast, the bestiary, the animation
vocabulary, the attunement list, the quest list and the world map, and the
executable carries the script language. This walks every layer and counts it,
so that "counting the naming layers" is an act of measurement performed on the
opened object rather than an estimate made before it.

    python tools/kultnames.py census   "<root>"
    python tools/kultnames.py models   "<root>"
    python tools/kultnames.py anims    "<root>"
    python tools/kultnames.py cast     "<root>"
    python tools/kultnames.py places   "<root>"
    python tools/kultnames.py selftest
"""
import argparse
import collections
import os
import sys

LANGS = ["br", "ch", "de", "eng", "es", "fr", "it", "ru"]


def model_dirs(root):
    d = os.path.join(root, "3d")
    return sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))


def animation_dirs(root):
    """Return [(model, variant, animation)] for every leaf under 3d."""
    base = os.path.join(root, "3d")
    out = []
    for m in model_dirs(root):
        md = os.path.join(base, m)
        for v in sorted(os.listdir(md)):
            vd = os.path.join(md, v)
            if not os.path.isdir(vd):
                continue
            for an in sorted(os.listdir(vd)):
                if os.path.isdir(os.path.join(vd, an)):
                    out.append((m, v, an))
    return out


def cmd_models(a):
    ms = model_dirs(a.root)
    print("model directories under 3d/ : %d" % len(ms))
    parts = collections.Counter()
    for m in ms:
        for dirpath, dirnames, filenames in os.walk(os.path.join(a.root, "3d", m)):
            for fn in filenames:
                parts[m] += 1
    print()
    print("%-22s %7s" % ("model", "files"))
    for m in ms:
        print("%-22s %7d" % (m, parts[m]))


def cmd_anims(a):
    rows = animation_dirs(a.root)
    names = collections.Counter(an for _, _, an in rows)
    folded = collections.Counter(an.lower() for _, _, an in rows)
    print("animation directories        : %d" % len(rows))
    print("distinct names, exact case   : %d" % len(names))
    print("distinct names, case-folded  : %d" % len(folded))
    print("model x variant pairs        : %d"
          % len(set((m, v) for m, v, _ in rows)))
    print()
    print("%-14s %6s   %s" % ("animation", "total", "the spellings, with counts"))
    for k, n in folded.most_common():
        spell = collections.Counter(an for _, _, an in rows if an.lower() == k)
        print("%-14s %6d   %s" % (k, n,
              "  ".join("%s %d" % (s, c) for s, c in spell.most_common())))
    print()
    per = collections.Counter(m for m, _, _ in rows)
    print("the twelve models with the most animation directories:")
    for m, n in per.most_common(12):
        print("   %-22s %4d" % (m, n))


def cmd_cast(a):
    print("%-6s %8s   %s" % ("lang", "speakers", "the ones only this language has"))
    allsp = collections.Counter()
    per = {}
    for l in LANGS:
        d = os.path.join(a.root, "data", "dia", l)
        if not os.path.isdir(d):
            continue
        sp = sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))
        per[l] = set(x.lower() for x in sp)
        for x in sp:
            allsp[x.lower()] += 1
    for l in LANGS:
        only = sorted(k for k in per[l] if allsp[k] == 1)
        print("%-6s %8d   %s" % (l, len(per[l]), ", ".join(only) or "-"))
    print()
    print("speakers present in all eight : %d"
          % sum(1 for k, v in allsp.items() if v == 8))
    print("speakers present in fewer     : %d"
          % sum(1 for k, v in allsp.items() if v < 8))
    for k, v in sorted(allsp.items()):
        if v < 8:
            print("   %-28s in %d languages" % (k, v))
    print()
    ref = sorted(per.get("eng", ()))
    print("the cast, as the English tree names it (%d):" % len(ref))
    line = []
    for n in ref:
        line.append(n)
        if len(line) == 4:
            print("   " + "  ".join("%-24s" % x for x in line))
            line = []
    if line:
        print("   " + "  ".join("%-24s" % x for x in line))


def cmd_places(a):
    d = os.path.join(a.root, "data", "Leveltext", "eng")
    places = sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))
    lev = os.path.join(a.root, "data", "levels")
    stems = sorted(set(os.path.splitext(f)[0] for f in os.listdir(lev)
                       if f.lower().endswith(".dat")))
    print("place directories in data/Leveltext/eng : %d" % len(places))
    print("level stems in data/levels              : %d" % len(stems))
    print()
    for p in places:
        inner = sorted(os.listdir(os.path.join(d, p)))
        print("   %-26s %2d files   %s" % (p, len(inner), ", ".join(inner[:4])))
    print()
    print("level stems, which are Slovak:")
    for i in range(0, len(stems), 4):
        print("   " + "  ".join("%-22s" % s for s in stems[i:i + 4]))


def cmd_census(a):
    layers = []
    ms = model_dirs(a.root)
    layers.append(("model directories", len(ms), "3d/<model>/"))
    anims = animation_dirs(a.root)
    layers.append(("animation directories", len(anims),
                   "3d/<model>/<variant>/<animation>/"))
    layers.append(("distinct animation names, exact case",
                   len(set(an for _, _, an in anims)), "as spelled"))
    layers.append(("distinct animation names, case-folded",
                   len(set(an.lower() for _, _, an in anims)), "folded"))
    d = os.path.join(a.root, "data", "dia", "eng")
    layers.append(("speaker directories", len(os.listdir(d)), "data/dia/eng/"))
    for sub in ("attunements", "quests", "hints"):
        p = os.path.join(a.root, "data", sub, "eng")
        layers.append(("%s names" % sub, len(os.listdir(p)),
                       "data/%s/eng/" % sub))
    p = os.path.join(a.root, "data", "Leveltext", "eng")
    layers.append(("place directories", len(os.listdir(p)), "data/Leveltext/eng/"))
    lev = os.path.join(a.root, "data", "levels")
    layers.append(("level stems", len(set(os.path.splitext(f)[0]
                                          for f in os.listdir(lev)
                                          if f.lower().endswith(".dat"))),
                   "data/levels/*.dat"))
    p = os.path.join(a.root, "data", "spell")
    layers.append(("spell and projectile files", len(os.listdir(p)), "data/spell/"))
    p = os.path.join(a.root, "data", "creature")
    layers.append(("creature files", len(os.listdir(p)), "data/creature/"))
    p = os.path.join(a.root, "data", "predmety")
    n = sum(len(f) for _, _, f in os.walk(p))
    layers.append(("item files", n, "data/predmety/ (Slovak: items)"))
    print("%-42s %8s  %s" % ("naming layer", "count", "where"))
    for name, n, where in layers:
        print("%-42s %8d  %s" % (name, n, where))
    print()
    print("layers counted here : %d" % len(layers))
    print("and two more that need a reader rather than a listing:")
    print("   script commands inside kult.exe        -- tools/kultexe.py")
    print("   texture member names inside the 82 .idx -- tools/kultidx.py names")


def cmd_selftest(a):
    """The census is directory listings, so what can go wrong is counting a
    file as a directory and folding case wrongly. Both are checked."""
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as t:
        for p in ("3d/heroine/1/Stand1", "3d/heroine/1/stand1x",
                  "3d/heroine/2/stand1", "3d/bear/1/Move1"):
            os.makedirs(os.path.join(t, *p.split("/")))
        open(os.path.join(t, "3d", "heroine", "notadir.3d"), "w").close()
        ms = model_dirs(t)
        good = ms == ["bear", "heroine"]
        print("   %-5s a file beside the model directories is not a model: %r"
              % ("ok" if good else "FAIL", ms))
        ok = ok and good
        rows = animation_dirs(t)
        got = sorted(an for _, _, an in rows)
        good = got == ["Move1", "Stand1", "stand1", "stand1x"]
        print("   %-5s animation leaves: %r" % ("ok" if good else "FAIL", got))
        ok = ok and good
        folded = len(set(an.lower() for _, _, an in rows))
        good = folded == 3
        print("   %-5s case-folded distinct names: %d (Stand1 and stand1 are one)"
              % ("ok" if good else "FAIL", folded))
        ok = ok and good
    print()
    print("%s" % ("all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("census", cmd_census), ("models", cmd_models),
                     ("anims", cmd_anims), ("cast", cmd_cast),
                     ("places", cmd_places)):
        p = sub.add_parser(name)
        p.add_argument("root")
        p.set_defaults(fn=fn)
    p = sub.add_parser("selftest")
    p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
