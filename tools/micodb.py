#!/usr/bin/env python3
"""micodb.py -- the disc's index of every issue before this one.

`Micodb/` is 742 files and its name says "db". The briefing for this session
read it as the magazine's article archive; it is not. It is a **catalogue of
every program the magazine has published on a cover disc**, one HTML page per
program, and each page names the issue number and the month it appeared in.

    Micodb/DB/s<N>.htm   one program: name, issue, licence, type, OS
    Micodb/DB/c<N>.htm   one category listing
    Micodb/DB/l<a-z>.htm alphabetical index pages
    Micodb/DB/completi.htm   the complete-programs list
    Micodb/index.htm     a three-column frameset

Which makes it the only thing on this disc that dates the disc. The object
carries no issue number anywhere -- not in the volume identifier, not in the
sleeve, not in a page -- but the catalogue of everything *before* it ends at a
particular number and month, and the next one is this one. That inference is
arithmetic on the series and it is printed as such, with the gaps shown, so
that it can be checked rather than believed.

    python tools/micodb.py TREE
    python tools/micodb.py TREE --programs
"""

import argparse
import html
import os
import re
import sys
from collections import Counter, defaultdict

REC = re.compile(r"Pubblicato su (.+?) numero\s+(\d+)\s*/\s*(.+)")
MONTHS = ["Gennaio", "Febbraio", "Marzo", "Aprile", "Maggio", "Giugno",
          "Luglio", "Agosto", "Settembre", "Ottobre", "Novembre", "Dicembre",
          "Natale"]


def lines(path):
    t = open(path, "rb").read().decode("latin-1")
    t = re.sub(r"<[^>]+>", "\n", t)
    t = html.unescape(t)
    return [re.sub(r"\s+", " ", x).strip() for x in t.split("\n") if x.strip()]


def field(ls, label):
    for i, l in enumerate(ls):
        if l.lower().startswith(label.lower()):
            v = l.split(":", 1)[1].strip() if ":" in l else ""
            if v:
                return v
            if i + 1 < len(ls):
                return ls[i + 1]
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tree")
    ap.add_argument("--programs", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    d = os.path.join(a.tree, "Micodb", "DB")
    files = sorted(os.listdir(d))
    s = [f for f in files if re.fullmatch(r"s\d+\.htm", f)]
    c = [f for f in files if re.fullmatch(r"c\d+\.htm", f)]
    l = [f for f in files if re.fullmatch(r"l[a-z]\.htm", f)]
    other = [f for f in files if f not in set(s) | set(c) | set(l)]
    nums = sorted(int(f[1:-4]) for f in s)

    print("Micodb/DB               %d files" % len(files))
    print("  program records s*    %d   numbered %d..%d, %d numbers absent"
          % (len(s), nums[0], nums[-1], nums[-1] - nums[0] + 1 - len(nums)))
    print("  category listings c*  %d" % len(c))
    print("  alphabetical l*       %d" % len(l))
    print("  other                 %d   %s" % (len(other), ", ".join(other)))
    print()

    issues = Counter()
    lic = Counter()
    typ = Counter()
    oss = Counter()
    names = []
    noissue = 0
    for f in s:
        ls = lines(os.path.join(d, f))
        name = field(ls, "Nome")
        rec = None
        for x in ls:
            m = REC.search(x)
            if m:
                rec = (m.group(1).strip(), int(m.group(2)),
                       m.group(3).strip())
                break
        if rec is None:
            noissue += 1
        else:
            issues[(rec[1], rec[2])] += 1
        lic[field(ls, "Licenza")] += 1
        typ[field(ls, "Tipo")] += 1
        oss[field(ls, "Sistema operativo")] += 1
        names.append((name, rec))

    print("program records carrying an issue reference : %d of %d"
          % (len(s) - noissue, len(s)))
    print("distinct issues referenced                  : %d" % len(issues))
    print()
    print("%-6s %-22s %s" % ("issue", "month as printed", "programs"))
    for (n, month), k in sorted(issues.items()):
        print("%-6d %-22s %d" % (n, month, k))
    print()
    lo = min(n for n, _m in issues)
    hi = max(n for n, _m in issues)
    have = {n for n, _m in issues}
    gaps = sorted(set(range(lo, hi + 1)) - have)
    print("issue numbers run %d..%d; %d present, %d absent%s"
          % (lo, hi, len(have), len(gaps),
             (": " + ", ".join(str(g) for g in gaps)) if gaps else ""))
    latest = max(issues, key=lambda k: k[0])
    print("the newest issue this catalogue knows about : numero %d / %s"
          % (latest[0], latest[1]))
    print("therefore the next issue in the series is   : numero %d"
          % (latest[0] + 1))
    print()
    print("-- licence, as the catalogue records it ----------------------------")
    for k, v in lic.most_common(12):
        print("   %-40s %4d" % ((k or "(blank)")[:40], v))
    print()
    print("-- type ------------------------------------------------------------")
    for k, v in typ.most_common(14):
        print("   %-40s %4d" % ((k or "(blank)")[:40], v))
    print()
    if a.programs:
        for name, rec in sorted(names):
            print("   %-52s %s" % (name[:52],
                                   ("numero %d / %s" % (rec[1], rec[2]))
                                   if rec else "(no issue)"))


if __name__ == "__main__":
    main()
