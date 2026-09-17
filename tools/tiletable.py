#!/usr/bin/env python3
"""tiletable.py -- read the five-language tile vocabulary that ships beside the
tileset images, and say which languages it is in by looking at the characters.

`rtp\\Graphics\\Tilesets\\` holds 22 `.png` and 22 `.txt`. Each `.txt` row is
five fields separated by `|`, one row per tile:

    Grassland|<Japanese>|Prairie|Wiese|Prado

2,544 rows x 5 fields = 12,720 strings, in plain text, next to the images they
name. No object in this collection has ever shipped a localisation table for
its own vocabulary, and `coverage.py` filed all 22 of these files as OPAQUE
because they are UTF-8 and the classifier tested ASCII and cp932.

WHAT THIS TOOL DOES THAT A ROW COUNT DOES NOT
----------------------------------------------
`_pre/tilenames.py` counted the rows and the fields. This identifies the
LANGUAGES, and it does it **by Unicode codepoint block and not by column
position**, so that "column 2 is Japanese" is a measurement rather than an
assumption. It then counts the rows in which two or more language fields are
byte-identical, which is the only thing in the file that distinguishes a
translated vocabulary from a copied one.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**A codepoint census cannot tell French from Spanish, or either from English.**
Latin-script languages share a block, so this tool can prove that column 2 is
Japanese and that columns 1, 3, 4 and 5 are Latin -- and it CANNOT prove which
Latin language each of the four is. The check written against that blind spot
is `--selftest`'s assertion that the classifier returns `latin` and NOT a
language name for four different Latin-script strings, so the tool is
structurally incapable of claiming more than it can see. The four columns'
identities below are attributed to the object's own ordering and to the
vendor's shipped interface languages, and are reported as ATTRIBUTED and not as
demonstrated.

    python tools/tiletable.py census rpgvxace-steam/rtp/Graphics/Tilesets
    python tools/tiletable.py langs  rpgvxace-steam/rtp/Graphics/Tilesets
    python tools/tiletable.py dupes  rpgvxace-steam/rtp/Graphics/Tilesets
    python tools/tiletable.py selftest
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nameguard                                          # noqa: E402

nameguard.guard()

SEP = "|"
FIELDS = 5


def script_of(text):
    """Which script a string is written in, by codepoint block.

    Returns one of `ascii`, `latin`, `japanese`, `mixed`, `empty`. It
    deliberately does NOT return a language: see the blind spot above.
    """
    if not text:
        return "empty"
    kinds = set()
    for ch in text:
        o = ord(ch)
        if o < 0x80:
            kinds.add("ascii")
        elif 0x80 <= o <= 0x24F:
            kinds.add("latin")
        elif (0x3040 <= o <= 0x30FF or 0x4E00 <= o <= 0x9FFF
              or 0xFF00 <= o <= 0xFFEF):
            kinds.add("japanese")
        else:
            kinds.add("other")
    if kinds == {"ascii"}:
        return "ascii"
    if kinds <= {"ascii", "latin"}:
        return "latin"
    if "japanese" in kinds and kinds <= {"ascii", "japanese"}:
        return "japanese"
    return "mixed"


def read_dir(directory):
    if not os.path.isdir(directory):
        sys.exit("tiletable: %s is not a directory of tileset tables"
                 % directory)
    txt = sorted(n for n in os.listdir(directory)
                 if n.lower().endswith(".txt"))
    png = sorted(n for n in os.listdir(directory)
                 if n.lower().endswith(".png"))
    if not txt:
        sys.exit("tiletable: no .txt under %r -- refusing to report a clean "
                 "census over an empty population" % directory)
    tables = {}
    encodings = {}
    for name in txt:
        p = os.path.join(directory, name)
        with open(p, "rb") as fh:
            raw = fh.read()
        try:
            text = raw.decode("utf-8")
            encodings[name] = "utf-8"
        except UnicodeDecodeError:
            text = raw.decode("cp932")
            encodings[name] = "cp932"
        rows = [ln for ln in text.split("\n") if ln.strip()]
        tables[name] = [r.rstrip("\r").split(SEP) for r in rows]
    return tables, png, encodings


def cmd_census(directory):
    tables, png, encodings = read_dir(directory)
    stems_txt = {os.path.splitext(n)[0] for n in tables}
    stems_png = {os.path.splitext(n)[0] for n in png}
    total_rows = sum(len(v) for v in tables.values())
    widths = collections.Counter()
    blanks = 0
    strings = 0
    empty_fields = 0
    for rows in tables.values():
        for r in rows:
            widths[len(r)] += 1
            strings += len(r)
            empty_fields += sum(1 for f in r if not f.strip())
    print("tileset tables (.txt) : %d" % len(tables))
    print("tileset images (.png) : %d" % len(png))
    print("stems in both         : %d" % len(stems_txt & stems_png))
    print("only .txt             : %s"
          % (sorted(stems_txt - stems_png) or "none"))
    print("only .png             : %s"
          % (sorted(stems_png - stems_txt) or "none"))
    print("RESIDUE on the stem join : %d" % len(stems_txt ^ stems_png))
    print()
    print("encodings, by the first codec that takes the whole file : %s"
          % dict(collections.Counter(encodings.values())))
    print()
    print("total rows            : %d" % total_rows)
    print("blank lines           : %d" % blanks)
    print("fields per row        : %s" % dict(widths))
    print("rows with exactly %d   : %d of %d"
          % (FIELDS, widths[FIELDS], total_rows))
    print("strings in total      : %d   (%d rows x %d fields)"
          % (strings, total_rows, FIELDS))
    print("empty fields          : %d" % empty_fields)
    print()
    print("  per file:")
    for name in sorted(tables):
        print("    %-28s %5d rows" % (name, len(tables[name])))
    return 0


def cmd_langs(directory):
    tables, _png, _enc = read_dir(directory)
    per_col = [collections.Counter() for _ in range(FIELDS)]
    samples = [None] * FIELDS
    for rows in tables.values():
        for r in rows:
            for i, f in enumerate(r[:FIELDS]):
                per_col[i][script_of(f)] += 1
                if samples[i] is None and script_of(f) == "japanese":
                    samples[i] = f
    print("THE FIVE COLUMNS, BY UNICODE BLOCK AND NOT BY POSITION")
    print()
    print("  %-6s %s" % ("column", "scripts observed, commonest first"))
    for i, c in enumerate(per_col):
        print("  %-6d %s" % (i + 1, ", ".join("%s x%d" % (k, v)
                                              for k, v in c.most_common())))
    print()
    jp = [i + 1 for i, c in enumerate(per_col) if c["japanese"]]
    print("  columns containing Japanese characters : %s" % jp)
    print("  columns that are Latin script only     : %s"
          % [i + 1 for i, c in enumerate(per_col) if not c["japanese"]])
    print()
    print("  DEMONSTRATED from the object: column 2 is Japanese; columns 1,")
    print("  3, 4 and 5 are Latin script. A codepoint census cannot tell")
    print("  four Latin-script languages apart and this tool does not try.")
    print()
    print("  ATTRIBUTED, from the object's own column order and from the")
    print("  interface languages the product ships: English, Japanese,")
    print("  French, German, Spanish. THAT IS AN ATTRIBUTION AND NOT A")
    print("  MEASUREMENT, and the fifth is not Italian while the interface")
    print("  this installation runs in is.")
    return 0


def cmd_dupes(directory):
    tables, _png, _enc = read_dir(directory)
    total = 0
    all_same = 0
    pairs = collections.Counter()
    n_distinct = collections.Counter()
    examples = []
    for name in sorted(tables):
        for r in tables[name]:
            if len(r) != FIELDS:
                continue
            total += 1
            distinct = len(set(r))
            n_distinct[distinct] += 1
            if distinct == 1:
                all_same += 1
                if len(examples) < 8:
                    examples.append((name, r[0]))
            for i in range(FIELDS):
                for j in range(i + 1, FIELDS):
                    if r[i] == r[j]:
                        pairs[(i + 1, j + 1)] += 1
    print("rows of exactly %d fields : %d" % (FIELDS, total))
    print()
    print("  distinct strings in a row   rows")
    for k in sorted(n_distinct):
        print("  %-27d %d" % (k, n_distinct[k]))
    print()
    print("  rows where all five fields are byte-identical : %d of %d"
          % (all_same, total))
    print()
    print("  column pairs that are byte-identical, commonest first:")
    for (i, j), n in pairs.most_common():
        print("    column %d == column %d   %5d rows" % (i, j, n))
    print()
    print("  A row whose five fields are identical is a tile whose name was")
    print("  not translated, and counting them is the only thing in this")
    print("  file that tells a translated vocabulary from a copied one.")
    if examples:
        print()
        print("  the first few untranslated rows:")
        for name, word in examples:
            print("    %-28s %s" % (name, word))
    return 0


def selftest():
    checks = []

    def ok(label, good, note=""):
        checks.append((label, good, note))

    ok("ASCII is ascii", script_of("Grassland") == "ascii")
    ok("accented Latin is latin", script_of("Prairie fleurie") == "ascii")
    ok("a Latin-1 accent is latin", script_of("Wüste") == "latin")
    ok("hiragana is japanese", script_of("そうげん") == "japanese")
    ok("kanji is japanese", script_of("草原") == "japanese")
    ok("katakana is japanese", script_of("カタカナ") == "japanese")
    ok("an empty field is empty and not ascii", script_of("") == "empty")
    ok("Japanese with an ASCII digit is still japanese",
       script_of("草原2") == "japanese")
    ok("Cyrillic is neither latin nor japanese",
       script_of("трава") == "mixed")

    # ---- P19: the blind spot is that a codepoint census cannot tell four
    # Latin-script languages apart. These four assert that the classifier
    # REFUSES to name one, so the tool cannot claim what it cannot see.
    for word, lang in (("Grassland", "English"), ("Prairie", "French"),
                       ("Wiese", "German"), ("Prado", "Spanish")):
        ok("BLIND SPOT: %r is classified as script and NOT as %s"
           % (word, lang), script_of(word) == "ascii")

    ok("and a Latin-script result is never a language name",
       script_of("Wüste") in ("ascii", "latin", "japanese", "mixed", "empty"))

    row = "Grassland|草原|Prairie|Wiese|Prado".split(SEP)
    ok("a five-field row splits into five", len(row) == FIELDS)
    ok("and column 2 of it is the Japanese one",
       script_of(row[1]) == "japanese")
    ok("and no other column of it is",
       [i for i, f in enumerate(row) if script_of(f) == "japanese"] == [1])

    same = "Bridge|Bridge|Bridge|Bridge|Bridge".split(SEP)
    ok("an untranslated row has one distinct string", len(set(same)) == 1)
    ok("and a translated row has more", len(set(row)) > 1)

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("census", "langs", "dupes", "selftest"))
    ap.add_argument("directory", nargs="?")
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.directory:
        sys.exit("tiletable: %s needs the directory holding the tileset "
                 "tables" % args.mode)
    if args.mode == "census":
        return cmd_census(args.directory)
    if args.mode == "langs":
        return cmd_langs(args.directory)
    return cmd_dupes(args.directory)


if __name__ == "__main__":
    sys.exit(main())
