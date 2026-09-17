#!/usr/bin/env python3
"""namespaces.py -- why the ISO name and the Joliet name of the same extent
differ, classified by rule rather than counted.

`iso9660.py --compare` establishes *that* the two namespaces disagree and by how
much. On this object they disagree on every shared extent, so "how much" stops
being informative and the question becomes "under what rule". This tool answers
it by re-deriving the primary name from the Joliet name and asking whether the
derivation lands.

The rule being asserted is ISO 9660 **Level 1** as ECMA-119 defines it (7.5, 7.6
and Annex A):

  * the d-characters are A-Z, 0-9 and _ ; everything else is out of the set;
  * a file identifier is at most 8 characters, optionally a SEPARATOR1 (.) and
    at most 3 more, then SEPARATOR2 (;) and a version number;
  * a directory identifier is at most 8 characters and carries no dot and no
    version.

Nothing in the standard says what a writer must do with a name that breaks
those limits, so the *mapping* is the writer's invention and is exactly what
this tool measures. It tests, in order:

    exact        uppercase(joliet) == primary
    case         differs only in letter case
    subst        after mapping out-of-set characters to _ , equal
    truncate     after mapping and truncating stem to 8 / ext to 3 , equal
    counter      as truncate, but the primary's tail is digits that the Joliet
                 name does not have -- a disambiguator
    unexplained  none of the above

and then, separately, asks how many Joliet names would **collide** if truncated
without a disambiguator, which is the number of names that owe their uniqueness
to Joliet rather than to the directory they sit in.

    python tools/namespaces.py IMAGE
    python tools/namespaces.py IMAGE --unexplained
    python tools/namespaces.py IMAGE --collisions
    python tools/namespaces.py IMAGE --dos
"""

import argparse
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iso9660  # noqa: E402

DCHAR = re.compile(r"[^A-Z0-9_]")


def strip_version(name):
    return name.split(";")[0] if ";" in name else name


def level1(name, isdir):
    """Map one Joliet name to what ISO 9660 Level 1 would allow, mechanically:
    uppercase, out-of-set characters to _, stem to 8, extension to 3."""
    up = name.upper()
    if isdir:
        return DCHAR.sub("_", up)[:8]
    if "." in up:
        stem, _, ext = up.rpartition(".")
    else:
        stem, ext = up, ""
    stem = DCHAR.sub("_", stem)[:8]
    ext = DCHAR.sub("_", ext)[:3]
    return stem + ("." + ext if ext else "")


def pairs(image):
    fh, mm = iso9660.open_image(image)
    try:
        vds = iso9660.read_vds(mm)
        pri = iso9660.tree_of(mm, vds, False)
        jol = iso9660.tree_of(mm, vds, True)
    finally:
        mm.close()
        fh.close()
    by_ext_p = defaultdict(list)
    for e in pri:
        by_ext_p[(e["extent"], e["isdir"])].append(e)
    out = []
    for e in jol:
        key = (e["extent"], e["isdir"])
        cands = by_ext_p.get(key)
        if not cands:
            continue
        # extents are unique per namespace on this object; if they were not,
        # match on size as well before giving up.
        p = cands[0] if len(cands) == 1 else None
        if p is None:
            for c in cands:
                if c["size"] == e["size"]:
                    p = c
                    break
        if p is None:
            continue
        out.append((p, e))
    return out, len(pri), len(jol)


def classify(p, j):
    pn = strip_version(p["name"])
    jn = strip_version(j["name"])
    isdir = j["isdir"]
    if pn == jn:
        return "exact"
    if pn == jn.upper():
        return "case"
    mapped_only = DCHAR.sub("_", jn.upper())
    if isdir:
        mapped_only = mapped_only
    else:
        if "." in jn.upper():
            s, _, x = jn.upper().rpartition(".")
            mapped_only = DCHAR.sub("_", s) + "." + DCHAR.sub("_", x)
        else:
            mapped_only = DCHAR.sub("_", jn.upper())
    if pn == mapped_only:
        return "subst"
    t = level1(jn, isdir)
    if pn == t:
        return "truncate"
    # counter: same length as the truncation, agreeing on a prefix, and the
    # place where they part is a digit on the primary side.
    if len(pn) == len(t):
        i = 0
        while i < len(pn) and pn[i] == t[i]:
            i += 1
        if i < len(pn) and pn[i].isdigit():
            return "counter"
    if len(pn) <= len(t):
        if t.startswith(pn[:max(0, len(pn) - 3)]) and any(ch.isdigit() for ch in pn):
            return "counter"
    return "unexplained"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--unexplained", action="store_true")
    ap.add_argument("--collisions", action="store_true")
    ap.add_argument("--dos", action="store_true")
    a = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    prs, npri, njol = pairs(a.image)
    print("records matched by extent: %d  (primary %d, joliet %d)"
          % (len(prs), npri, njol))
    print()

    kinds = Counter()
    unexp = []
    counters = []
    for p, j in prs:
        k = classify(p, j)
        kinds[k] += 1
        if k == "unexplained":
            unexp.append((p, j))
        if k == "counter":
            counters.append((p, j))

    print("-- how the primary name is derived from the Joliet name ------------")
    order = ["exact", "case", "subst", "truncate", "counter", "unexplained"]
    for k in order:
        if kinds.get(k):
            print("  %-12s %6d   (%.4f %%)"
                  % (k, kinds[k], 100.0 * kinds[k] / len(prs)))
    print("  %-12s %6d" % ("total", sum(kinds.values())))
    mech = sum(kinds.get(k, 0) for k in ("exact", "case", "subst",
                                         "truncate", "counter"))
    print()
    print("  explained by the mechanical Level 1 rule: %d of %d = %.4f %%"
          % (mech, len(prs), 100.0 * mech / len(prs)))
    print()

    # what the two names have in common, in shape
    same_len = sum(1 for p, j in prs
                   if len(strip_version(p["name"])) == len(strip_version(j["name"])))
    print("  primary and Joliet names of equal length: %d" % same_len)
    print()

    print("-- collisions if the Joliet names were truncated blind --------------")
    per_dir = defaultdict(list)
    for p, j in prs:
        per_dir[(j["path"], j["isdir"])].append(j)
    groups = 0
    victims = 0
    worst = []
    for (path, isdir), lst in per_dir.items():
        c = defaultdict(list)
        for e in lst:
            c[level1(strip_version(e["name"]), isdir)].append(e["name"])
        for key, names in c.items():
            if len(names) > 1:
                groups += 1
                victims += len(names)
                worst.append((len(names), path, key, sorted(names)))
    print("  colliding groups            %d" % groups)
    print("  names inside them           %d" % victims)
    print("  names that owe uniqueness to Joliet or to Nero's counter: %d"
          % (victims - groups))
    worst.sort(reverse=True)
    for n, path, key, names in worst[:12]:
        print("    %-42s -> %-13s x%d" % (path[:42], key, n))
        for nm in names[:4]:
            print("        %s" % nm)
        if len(names) > 4:
            print("        ... %d more" % (len(names) - 4))
    print()
    print("  primary names actually carrying a counter: %d" % len(counters))
    for p, j in counters[:12]:
        print("    %-34s <- %s" % (strip_version(p["name"]), strip_version(j["name"])))
    print()

    if a.unexplained or unexp:
        print("-- names the rule does not explain ---------------------------------")
        print("  %d" % len(unexp))
        for p, j in unexp[:40]:
            print("    primary %-16s  joliet %-40s  level1 -> %s"
                  % (strip_version(p["name"]), strip_version(j["name"]),
                     level1(strip_version(j["name"]), j["isdir"])))
        print()

    if a.dos:
        print("-- what a DOS sees -------------------------------------------------")
        bad = []
        depth = Counter()
        for p, j in prs:
            pn = strip_version(p["name"])
            if p["isdir"]:
                ok = len(pn) <= 8 and not DCHAR.search(pn)
            else:
                if "." in pn:
                    s, _, x = pn.rpartition(".")
                else:
                    s, x = pn, ""
                ok = (len(s) <= 8 and len(x) <= 3
                      and not DCHAR.search(s) and not DCHAR.search(x))
            if not ok:
                bad.append(pn)
            depth[p["path"].count("/")] += 1
        print("  records violating Level 1 8.3: %d of %d" % (len(bad), len(prs)))
        for b in bad[:20]:
            print("    %s" % b)
        print("  directory depth of records (path separators):")
        for d in sorted(depth):
            print("    depth %-2d  %6d" % (d, depth[d]))


if __name__ == "__main__":
    main()
