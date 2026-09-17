#!/usr/bin/env python3
"""level.py -- split GRAF\\LEVEL.DAT of Polanie into its text-map levels,
read each header with the designers' own legend (which is at the END of the
file, in Polish), and count what stands on every map.

THE FORMAT, AS THE FILE SAYS IT
-------------------------------
LEVEL.DAT is CR/LF text. It opens with a separator line of twelve cp437
box-drawing bytes; then, for each level:

    $D2 E1 T07 M0 G P8 *Helwig Wiking* lev1 "hel"      the header
    !wwwwwww...                                        66 rows, each `!`
    ...                                                then 66 map cells
    <the separator line>

and after the last level the legend, verbatim from the designers:

    ABC drzewa iglaste (conifers)  DEF drzewa lisciaste (broadleaf)
    G drzewo suche (dead tree)  g sucha ziemia (dry earth)  w woda (water)
    s skaly (rocks)  t droga (road)  a..n gadgety  o,p ognisko (campfire)
    . leczenie (healing)  + odkrycie (discovery)  = start
    * postac przy E1 (the person to find)  ^ miejsce koncowe (the goal)
    - pastwisko wrogow (enemy pasture, D0)  ? miejsce zbiorki (rally)
    D  the enemy's algorithm: D0 wioska (village), D1 bitwa dynamiczna,
       D2 bitwa statyczna (obrona), D3 brak sterowania (no control)
    E  the ending: E0 kill everything but the building numbered T (T20 =
       spare nothing); E1 find `*` and bring him to `^` (T = his type)
    M  the MILK cap ("maxymalna ilosc mleka"): M0 0, M1 250, M2 450,
       M3 650 ... M9 duzo (lots)
    buildings (3x3), ours / theirs:  H/N glowny (main)  I/O obora (cowshed)
       J/P koszary (barracks)  K/Q swiatynia (temple)  L/R koszary2
       M/S dom wodza (chief's house, 2x2)
    characters, ours / theirs:  x/T krowa (cow)  y/U topornik (axeman)
       z/W lucznik (archer)  9/X kaplanka (priestess)  0/Y kaplan (priest)
       :/Z miecznik (swordsman)  ;/# wlocznik (spearman)  </" dow (leader)
       >/% niedzwiedz (bear)  ,/& ????

`N`, `G` and `P` in the headers are not in the legend and are reported as
found, not explained. Words of letters standing inside a map (`Bili`,
`Uiat`) are letters from the alphabet placed side by side; the tool counts
them as cells because that is what the format makes them.

    python tools/level.py census   GRAF/LEVEL.DAT      the 28 headers, grids
    python tools/level.py units    GRAF/LEVEL.DAT      what stands on each map
    python tools/level.py legend   GRAF/LEVEL.DAT      the legend, cp852 -> utf-8
    python tools/level.py selftest
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

BUILDINGS = {"H": "glowny", "I": "obora", "J": "koszary", "K": "swiatynia",
             "L": "koszary2", "M": "dom wodza"}
BUILDINGS_THEIRS = dict(zip("NOPQRS", BUILDINGS.values()))
UNITS = {"x": "krowa", "y": "topornik", "z": "lucznik", "9": "kaplanka",
         "0": "kaplan", ":": "miecznik", ";": "wlocznik", "<": "dow",
         ">": "niedzwiedz", ",": "????"}
UNITS_THEIRS = dict(zip('TUWXYZ#"%&', UNITS.values()))
TERRAIN = {"w": "water", "s": "rocks", "t": "road", "g": "dry earth",
           "G": "dead tree", " ": "grass"}
for c in "ABC":
    TERRAIN[c] = "conifer"
for c in "DEF":
    TERRAIN[c] = "broadleaf"
MARKS = {".": "healing", "+": "discovery", "=": "start", "*": "person",
         "^": "goal", "-": "enemy pasture", "?": "rally"}
HEADER = re.compile(r"^\$\s*(.*)$")


class Refused(Exception):
    pass


def split(text):
    """Return (levels, legend_lines). A level is dict(header, fields, rows,
    line) with rows the map rows without their `!`."""
    lines = [l.rstrip("\r") for l in text.split("\n")]
    levels = []
    cur = None
    last_row = 0
    between = []
    for i, line in enumerate(lines):
        if HEADER.match(line):
            cur = dict(line=i + 1, header=line, rows=[], raw=[])
            levels.append(cur)
            continue
        if line.startswith("!") and cur is not None:
            cur["raw"].append(line[1:])
            last_row = i
            continue
        if line.strip():
            between.append((i + 1, line))
    if not levels:
        raise Refused("no `$` header line in the file")
    # the legend is everything after the last map row; the lines between
    # levels before that (separators of box-drawing bytes, `level 26`
    # comments) are kept as `between`
    legend = lines[last_row + 1:]
    between = [b for b in between if b[0] <= last_row]
    for lv in levels:
        lv["fields"] = parse_header(lv["header"])
        widths = [len(r) for r in lv["raw"]]
        mode = max(set(widths), key=widths.count) if widths else 0
        lv["w"] = mode
        lv["h"] = len(lv["raw"])
        lv["rows"] = [r[:mode].ljust(mode) for r in lv["raw"]]
        lv["overflow"] = [(k, r[mode:]) for k, r in enumerate(lv["raw"])
                          if len(r) > mode and r[mode:].strip()]
        lv["short"] = sum(1 for r in lv["raw"] if len(r) < mode)
    return levels, legend, between


def parse_header(line):
    body = HEADER.match(line).group(1)
    f = dict(D=None, E=None, T=None, M=None, N=None, G=False, P=None,
             hero=None, lev=None, title=None, note="")
    m = re.search(r"\*([^*]+)\*", body)
    if m:
        f["hero"] = m.group(1).strip()
        body = body.replace(m.group(0), " ")
    m = re.search(r'"([^"]*)"', body)
    if m:
        f["title"] = m.group(1)
        body = body.replace(m.group(0), " ")
    rest = []
    for tok in body.split():
        m = re.match(r"^([DETMNP])(\d+)$", tok)
        if m:
            f[m.group(1)] = int(m.group(2))
        elif tok == "G":
            f["G"] = True
        elif re.match(r"^lev(\d+)$", tok):
            f["lev"] = int(tok[3:])
        else:
            rest.append(tok)
    f["note"] = " ".join(rest)
    return f


def count_cells(rows):
    c = {}
    for r in rows:
        for ch in r:
            c[ch] = c.get(ch, 0) + 1
    return c


def cmd_census(path):
    text = open(path, "rb").read().decode("latin-1")
    levels, legend, between = split(text)
    print("%s: %d levels, %d legend lines after the last map row, %d "
          "non-empty lines between levels"
          % (os.path.basename(path), len(levels), len(legend), len(between)))
    print("%3s %5s %3s %3s %3s %3s %3s %2s %3s %8s %4s  %-16s %s"
          % ("#", "line", "D", "E", "T", "M", "N", "G", "P", "grid", "over",
             "hero", "title / note"))
    grids = {}
    over = 0
    for k, lv in enumerate(levels):
        f = lv["fields"]
        g = "%dx%d" % (lv["w"], lv["h"])
        grids[g] = grids.get(g, 0) + 1
        over += len(lv["overflow"])
        print("%3d %5d %3s %3s %3s %3s %3s %2s %3s %8s %4s  %-16s %s"
              % (f["lev"] or k + 1, lv["line"], f["D"], f["E"], f["T"], f["M"],
                 "" if f["N"] is None else f["N"], "G" if f["G"] else "",
                 "" if f["P"] is None else f["P"], g,
                 len(lv["overflow"]) or "", f["hero"] or "",
                 ('"%s"' % f["title"] if f["title"] else "") + " " + f["note"]))
    print("grids (mode width x rows): %s"
          % ", ".join("%s x%d" % kv for kv in sorted(grids.items())))
    print("rows with text beyond the grid width: %d (kept out of the counts: %s)"
          % (over, ", ".join(sorted(set(t.strip() for lv in levels
                                         for _, t in lv["overflow"])))))
    print("lines between levels: %s" % ", ".join(
        sorted(set(l.strip() for _, l in between
                   if not all(ord(c) > 127 or c == " " for c in l)))))
    levs = [lv["fields"]["lev"] for lv in levels]
    print("lev numbers: %s .. %s, %d distinct, gaps: %s"
          % (min(levs), max(levs), len(set(levs)),
             sorted(set(range(min(levs), max(levs) + 1)) - set(levs)) or "none"))
    for key in "DEM":
        vals = {}
        for lv in levels:
            v = lv["fields"][key]
            vals[v] = vals.get(v, 0) + 1
        print("%s values: %s" % (key, ", ".join("%s x%d" % kv for kv in sorted(vals.items()))))
    return 0


def cmd_units(path):
    text = open(path, "rb").read().decode("latin-1")
    levels, legend, between = split(text)
    tot = {}
    print("%3s  %-38s  %-38s  %s" % ("#", "ours (units / buildings)", "theirs", "marks"))
    for k, lv in enumerate(levels):
        c = count_cells(lv["rows"])
        for ch, n in c.items():
            tot[ch] = tot.get(ch, 0) + n
        ours = ["%s%s" % (UNITS[ch], "" if n == 1 else " x%d" % n)
                for ch, n in c.items() if ch in UNITS]
        ourb = ["%s%s" % (BUILDINGS[ch], "" if n == 1 else " x%d" % n)
                for ch, n in c.items() if ch in BUILDINGS]
        theirs = ["%s%s" % (UNITS_THEIRS[ch], "" if n == 1 else " x%d" % n)
                  for ch, n in c.items() if ch in UNITS_THEIRS]
        theirb = ["%s%s" % (BUILDINGS_THEIRS[ch], "" if n == 1 else " x%d" % n)
                  for ch, n in c.items() if ch in BUILDINGS_THEIRS]
        marks = ["%s%s" % (MARKS[ch], "" if n == 1 else " x%d" % n)
                 for ch, n in c.items() if ch in MARKS]
        print("%3d  %-38s  %-38s  %s"
              % (lv["fields"]["lev"] or k + 1,
                 ", ".join(sorted(ours)) + " / " + ", ".join(sorted(ourb)),
                 ", ".join(sorted(theirs)) + " / " + ", ".join(sorted(theirb)),
                 ", ".join(sorted(marks))))
    cells = sum(tot.values())
    print("\nall %d levels, %d cells:" % (len(levels), cells))
    for label, table in (("terrain", TERRAIN), ("our units", UNITS),
                         ("their units", UNITS_THEIRS), ("our buildings", BUILDINGS),
                         ("their buildings", BUILDINGS_THEIRS), ("marks", MARKS)):
        print("  %-16s %s" % (label, ", ".join(
            "%s(%s)=%d" % (repr(ch), table[ch], tot.get(ch, 0))
            for ch in table if tot.get(ch, 0))))
    known = set(TERRAIN) | set(UNITS) | set(UNITS_THEIRS) | set(BUILDINGS) \
        | set(BUILDINGS_THEIRS) | set(MARKS) | set("abcdefhijklmnop")
    other = {ch: n for ch, n in tot.items() if ch not in known}
    print("  %-16s %s" % ("gadgets a..p", ", ".join(
        "%s=%d" % (repr(ch), tot[ch]) for ch in "abcdefhijklmnop" if tot.get(ch))))
    print("  %-16s %s" % ("not in legend", ", ".join(
        "%s=%d" % (repr(ch), n) for ch, n in sorted(other.items()))))
    print("  cells accounted by the legend: %d of %d"
          % (cells - sum(other.values()), cells))
    return 0


def cmd_legend(path):
    text = open(path, "rb").read().decode("latin-1")
    levels, legend, between = split(text)
    raw = "\n".join(legend).encode("latin-1")
    print(raw.decode("cp852", "replace"))
    return 0


MAZOVIA = {0x86: "ą", 0x8D: "ć", 0x91: "ę", 0x92: "ł", 0xA4: "ń", 0xA2: "ó",
           0x9E: "ś", 0xA6: "ź", 0xA7: "ż", 0x8F: "Ą", 0x95: "Ć", 0x90: "Ę",
           0x9C: "Ł", 0xA5: "Ń", 0xA3: "Ó", 0x98: "Ś", 0xA0: "Ź", 0xA1: "Ż"}
# The engine's own text (the strings in SLAVS.EXE) and FONT.DAT put the
# Polish letters on ASCII punctuation instead; this is the mapping the font
# sheet shows, confirmed on seven letters by whole words in the engine
# (`Naprawd$ chcesz wyj*+?` = `Naprawdę chcesz wyjść?`).
ENGINE = {"#": "ą", "$": "ę", "%": "ó", "&": "ź", "*": "ś", "+": "ć", "`": "ł"}


def mazovia(raw):
    """bytes -> str, the nine-plus-nine Polish letters of the Mazovia code
    page decoded, any other high byte shown as \\xNN so nothing is invented."""
    out = []
    for b in raw:
        if b < 128:
            out.append(chr(b))
        elif b in MAZOVIA:
            out.append(MAZOVIA[b])
        else:
            out.append("\\x%02X" % b)
    return "".join(out)


def cmd_briefings(path):
    """LEVEL.INI: `$` sections in groups (a group restarts at level 1),
    each a run of `!` lines ending in `%`; which are English, which Polish
    (Mazovia high bytes), which empty (`~` only)."""
    raw = open(path, "rb").read()
    lines = raw.split(b"\n")
    groups = []
    cur = None
    titles = []
    for i, line in enumerate(lines):
        line = line.rstrip(b"\r")
        if line.startswith(b"$"):
            name = line[1:].strip()
            m = re.search(rb"(\d+)\s*$", name)
            num = int(m.group(1)) if m else None
            if cur is None or (num == 1 and cur["sections"]) or \
                    (num is None and cur["sections"] and cur["sections"][-1]["num"] is not None):
                cur = dict(sections=[], title=titles[-1] if titles else "")
                groups.append(cur)
            cur["sections"].append(dict(num=num, name=name, lines=[], line=i + 1))
        elif line.startswith(b"!") and cur is not None:
            cur["sections"][-1]["lines"].append(line[1:])
        elif line.strip() and not line.strip().startswith(b"-"):
            titles.append(mazovia(line.strip()))
    print("%s: %d bytes, %d `$` sections in %d groups"
          % (os.path.basename(path), len(raw), sum(len(g["sections"]) for g in groups),
             len(groups)))
    hi_total = 0
    for g in groups:
        if g["sections"] and g["sections"][0]["num"] is None:
            g["title"] = "(%s ...)" % mazovia(g["sections"][0]["name"])
    for gi, g in enumerate(groups):
        eng = pol = empty = 0
        polish = []
        for s in g["sections"]:
            text = b"".join(s["lines"])
            hi = sum(1 for b in text if b >= 128)
            hi_total += hi
            words = re.sub(rb"[^A-Za-z]+", b" ", text).split()
            if hi:
                pol += 1
                polish.append(s["num"] if s["num"] is not None else s["name"].decode("latin-1"))
            elif not [w for w in words]:
                empty += 1
            else:
                eng += 1
        print("  group %d %-40r sections %2d: %2d with Latin words, %2d with "
              "Mazovia bytes (%s), %2d empty"
              % (gi + 1, g["title"][:40], len(g["sections"]), eng, pol,
                 ", ".join(str(p) for p in polish) or "-", empty))
    print("  high bytes in the file: %d, all of them Mazovia lowercase: %s"
          % (hi_total, all(b in MAZOVIA for b in raw if b >= 128)))
    print()
    for g in groups:
        for s in g["sections"]:
            if s["num"] is None or "autorzy" in s["name"].decode("latin-1") \
                    or g["title"].startswith("teksty") and s["num"] == 3 \
                    and "poczatk" in g["title"]:
                if s["lines"]:
                    print("--- %s (line %d) ---" % (mazovia(s["name"]), s["line"]))
                    for l in s["lines"]:
                        t = mazovia(l).rstrip("%").rstrip()
                        if t.strip() not in ("", "~"):
                            print("   " + t)
    return 0


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-56s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    sample = ("\xd4 \xd5\r\n\r\n"
              '$D2 E1 T07 M0 G P8 *Helwig Wiking* lev1 "hel"\r\n'
              "!wwwt x H\r\n!  yy N  \r\n!  zz N     Uiat\r\n\xd4 \xd5\r\n"
              "         level 2\r\n"
              "$D0 E0 T20 N01  M7  lev2   wiocha na wioche....\"susza\"\r\n"
              "!TT=^\r\n\xd4 \xd5\r\n\r\nABC - drzewa\r\n")
    levels, legend, between = split(sample)
    check("two levels split, legend after the last map row",
          len(levels) == 2 and len(legend) == 4 and legend[2] == "ABC - drzewa")
    check("separator and `level 2` comment kept as between-lines",
          len(between) == 3 and between[2][1].strip() == "level 2")
    check("a row longer than the mode width is trimmed and its tail kept",
          levels[0]["w"] == 8 and levels[0]["overflow"] == [(2, "   Uiat")])
    f = levels[0]["fields"]
    check("header 1: D2 E1 T7 M0 G P8, hero, lev1, title",
          (f["D"], f["E"], f["T"], f["M"], f["G"], f["P"], f["hero"], f["lev"],
           f["title"]) == (2, 1, 7, 0, True, 8, "Helwig Wiking", 1, "hel"))
    f = levels[1]["fields"]
    check("header 2: N01 read, note kept, no hero",
          f["N"] == 1 and f["hero"] is None and f["note"] == "wiocha na wioche...."
          and f["title"] == "susza")
    check("grid of level 1 is 8x3", (levels[0]["w"], levels[0]["h"]) == (8, 3))
    c = count_cells(levels[0]["rows"])
    check("cells counted: 3 water, 1 road, 1 cow, 2 axemen, 2 archers, "
          "main + 2 enemy mains; the overflow `Uiat` not counted",
          (c["w"], c["t"], c["x"], c["y"], c["z"], c["H"], c["N"],
           c.get("U", 0)) == (3, 1, 1, 2, 2, 1, 2, 0))
    try:
        split("no headers here\r\n")
        check("refuses a file with no `$` header", False)
    except Refused:
        check("refuses a file with no `$` header", True)
    print("\nlevel.py selftest: %d failures, 0 skipped (the sample is built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd")
    ap.add_argument("path", nargs="?")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.path:
        ap.error("no input")
    dirguard.want_file(a.path, "level.py")
    try:
        if a.cmd == "census":
            return cmd_census(a.path)
        if a.cmd == "units":
            return cmd_units(a.path)
        if a.cmd == "legend":
            return cmd_legend(a.path)
        if a.cmd == "briefings":
            return cmd_briefings(a.path)
    except Refused as e:
        print("level.py: REFUSED: %s" % e)
        return 1
    ap.error("unknown command %r" % a.cmd)


if __name__ == "__main__":
    sys.exit(main())
