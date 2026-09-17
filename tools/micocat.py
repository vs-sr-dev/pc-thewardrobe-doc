#!/usr/bin/env python3
"""micocat.py -- the catalogue the disc keeps about itself.

This object declares its own contents in three places and they do not agree:

  1. the **directories**, which are what a filesystem shows;
  2. the **HTML pages** in `CD-ROM/`, which the shell displays and which carry
     a name, a version, a licence, an operating system, a minimum machine and a
     web address for each entry;
  3. the **printed sleeve**, which is not on the disc at all and is handled by
     `manifest.py`.

Only the first two are inside the image, so only those two are this tool's
business. It parses the category pages for the per-entry record the editors
used consistently -- `Licenza:`, `Sistema operativo:`, `Requisiti minimi:`,
`Sito:` / `Sito web:` -- and for the `in questa sezione` navigation list at the
top of each page, which is the editors' own enumeration of the section.

The editors put each label in one table cell and its value in the next, so
after the tags are stripped the value lands on the line below the label. This
tool takes the value from the same line if there is one there and from the next
line otherwise, and it never invents one.

Nothing here is guessed from a filename: an entry exists because a `Licenza:`
line exists, and a section membership exists because the page's own navigation
says so.

    python tools/micocat.py TREE
    python tools/micocat.py TREE --entries
"""

import argparse
import html
import os
import re
import sys
from collections import OrderedDict, Counter

PAGES = OrderedDict([
    ("completi", ["completi.htm"]),
    ("Creativita", ["creativita.htm", "creativita2.htm", "creativita3.htm"]),
    ("indispensabili", ["indispensabili.htm", "indispensabili2.htm",
                        "indispensabili3.htm", "indispensabili4.htm"]),
    ("Internet", ["internet.htm"]),
    ("Utility", ["utility.htm", "utility2.htm"]),
    ("giochi", ["giochi.htm"]),
    ("Primipassi", ["primi.htm"]),
    ("Listini", ["Listini.htm"]),
    ("vetrina", ["vetrina.htm"]),
])

LABEL = re.compile(r"^(Licenza|Sistema operativo|Requisiti minimi|Sito web|Sito)"
                   r"\s*:", re.I)


def lines_of(path):
    raw = open(path, "rb").read()
    t = raw.decode("latin-1")
    t = re.sub(r"<script.*?</script>", " ", t, flags=re.S | re.I)
    t = re.sub(r"<style.*?</style>", " ", t, flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", "\n", t)
    t = html.unescape(t)
    return [re.sub(r"[\s ]+", " ", l).strip() for l in t.split("\n")]


def title_index(lines, licenza_i):
    """Walk back from a `Licenza:` line, past the description, to the title.

    The generated markup leaves long runs of empty lines between cells -- on
    `giochi.htm` the title sits fourteen blank lines above its own description
    -- so the budget is counted in *non-empty* lines, not in lines."""
    budget = 10
    for j in range(licenza_i - 1, -1, -1):
        cand = lines[j]
        if not cand:
            continue
        budget -= 1
        if budget < 0:
            return None
        if len(cand) > 60:
            continue
        if cand.endswith((".", "!", "?", ":", ",")):
            continue
        if LABEL.match(cand):
            continue
        return j
    return None


def first_licenza(lines):
    for i, l in enumerate(lines):
        if re.match(r"^Licenza\s*:", l, re.I):
            return i
    return None


def nav_list(lines):
    start = None
    for i, l in enumerate(lines):
        if re.search(r"questa\s+sezione", l, re.I):
            start = i + 1
            break
    if start is None:
        return []
    fl = first_licenza(lines)
    stop = len(lines)
    if fl is not None:
        ti = title_index(lines, fl)
        stop = ti if (ti is not None and ti > start) else fl
    return [l for l in lines[start:stop] if l]


def field_after(lines, i):
    """The label is in one table cell and the value in the next, so after the
    tags are stripped the value is on the same line or on the next non-empty
    one. Never invent one, and never cross into the following label."""
    same = lines[i].split(":", 1)[1].strip()
    if same:
        return same
    for j in range(i + 1, min(i + 40, len(lines))):
        if lines[j]:
            return "" if LABEL.match(lines[j]) else lines[j]
    return ""


def entries(lines):
    out = []
    for i, l in enumerate(lines):
        if not re.match(r"^Licenza\s*:", l, re.I):
            continue
        rec = {"Licenza": field_after(lines, i)}
        budget = 12
        for j in range(i + 1, len(lines)):
            if not lines[j]:
                continue
            budget -= 1
            if budget < 0:
                break
            m = LABEL.match(lines[j])
            if not m:
                continue
            key = m.group(1)
            key = "Sito web" if key.lower().startswith("sito") else key
            if key == "Licenza":
                break
            rec.setdefault(key, field_after(lines, j))
        ti = title_index(lines, i)
        if ti is not None:
            rec["name"] = lines[ti]
        out.append(rec)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tree")
    ap.add_argument("--entries", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    root = os.path.join(a.tree, "CD-ROM")
    print("%-16s %6s %6s %8s   %s"
          % ("section", "pages", "nav", "entries", "directories on the disc"))
    print("-" * 92)
    total_entries = 0
    total_nav = 0
    total_dirs = 0
    all_lic = Counter()
    all_os = Counter()
    all_sites = Counter()
    detail = OrderedDict()
    for section, pages in PAGES.items():
        navs = []
        ents = []
        seen = 0
        for p in pages:
            fp = os.path.join(root, p)
            if not os.path.exists(fp):
                continue
            seen += 1
            ln = lines_of(fp)
            n = nav_list(ln)
            if n and not navs:
                navs = n
            ents.extend(entries(ln))
        dirp = os.path.join(a.tree, section)
        ndirs = (len([d for d in os.listdir(dirp)
                      if os.path.isdir(os.path.join(dirp, d))])
                 if os.path.isdir(dirp) else 0)
        nfiles = (len([d for d in os.listdir(dirp)
                       if os.path.isfile(os.path.join(dirp, d))])
                  if os.path.isdir(dirp) else 0)
        detail[section] = (navs, ents)
        total_entries += len(ents)
        total_nav += len(navs)
        total_dirs += ndirs
        for e in ents:
            all_lic[e.get("Licenza", "?")] += 1
            all_os[e.get("Sistema operativo", "?")] += 1
            if e.get("Sito web"):
                all_sites[e["Sito web"]] += 1
        print("%-16s %6d %6d %8d   %d directories%s"
              % (section, seen, len(navs), len(ents), ndirs,
                 (" + %d loose files" % nfiles) if nfiles else ""))
    print("-" * 92)
    print("%-16s %6s %6d %8d   %d directories"
          % ("total", "", total_nav, total_entries, total_dirs))
    print()

    print("-- licence, as the editors declare it -------------------------------")
    for k, v in all_lic.most_common():
        print("   %-40s %4d" % ((k or "(blank)")[:40], v))
    print()
    print("-- operating system declared ----------------------------------------")
    for k, v in all_os.most_common(10):
        print("   %-40s %4d" % ((k or "(blank)")[:40], v))
    print()
    print("-- addresses named (%d distinct over %d entries) --------------------"
          % (len(all_sites), sum(all_sites.values())))
    for k, v in all_sites.most_common(40):
        print("   %-52s %4d" % (k[:52], v))
    print()

    if a.entries:
        for section, (navs, ents) in detail.items():
            print("== %s ==  nav %d, entries %d" % (section, len(navs), len(ents)))
            if navs:
                print("   nav: %s" % " | ".join(navs))
            for e in ents:
                print("   %-40s %-14s %-24s %s"
                      % (e.get("name", "?")[:40], e.get("Licenza", "")[:14],
                         e.get("Sistema operativo", "")[:24],
                         e.get("Sito web", "")))
            print()


if __name__ == "__main__":
    main()
