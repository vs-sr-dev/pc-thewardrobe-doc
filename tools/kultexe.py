#!/usr/bin/env python3
"""kultexe.py -- read `kult.exe`'s string pool as the game's own vocabulary.

The main executable is 1,714,688 bytes, PE32, linker 10.00, COFF 2015-08-27.
It carries three things this object cannot be read without:

  * **the script language.** Every command the level scripts can issue is a
    literal beginning `^`. They are the design of the game in a list --
    `^attune_item`, `^enter_dreamworld`, `^assign_quest`, `^cast_spell_char`.
  * **the file vocabulary**: the extensions and path templates the engine
    opens, which is what says where a save goes and what `konzola` is.
  * **the developer's own language.** The retail build carries Slovak error
    messages and two Slovak script commands in an otherwise English set.

It also carries what is NOT there, which is the point of `--find`: `AGP!`, the
magic on 14,697 files, is not a string constant in the program that writes it.

Written with `Write` and not a heredoc because it holds backslashes -- rule 0.

    python tools/kultexe.py commands "<root>/kult.exe"
    python tools/kultexe.py vocab    "<root>/kult.exe"
    python tools/kultexe.py find     "<root>/kult.exe" AGP!
    python tools/kultexe.py years    "<root>"
    python tools/kultexe.py selftest
"""
import argparse
import collections
import os
import re
import struct
import sys

ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
COMMAND = re.compile(r"^\^[a-z0-9_]+$")

# Slovak words that appear in this build's own messages and command names.
# Each is checked against the file, never asserted.
SLOVAK = ["Nenasiel", "Uspesne", "nacital", "kuzlo", "charakter", "pozadie",
          "pohyb", "konzola", "predmet", "masky", "jaskyna", "dedina"]


def runs(blob, minlen=4):
    for m in ASCII_RUN.finditer(blob):
        s = m.group().decode("latin-1")
        if len(s) >= minlen:
            yield m.start(), s


LETTERS = re.compile(r"[a-z]{3}")


def commands(blob, filtered=True):
    """Every distinct literal that is a caret followed by name characters.

    A bare `\\^[A-Za-z0-9_]+` search over a 1.7-megabyte PE returns 165
    literals, and 46 of them are strings like `^0b0f0j0n0r0` and `^3c3k3p3`
    that fall out of the image's own data rather than out of a script pool.
    They are excluded by requiring **three consecutive lower-case letters**,
    which is a property of a word and not of a hex pattern -- and the count of
    what the filter removed is reported, because a filter whose yield is not
    published is a thumb on the scale.

    `filtered=False` returns the raw set, so the two numbers can be compared.
    """
    found = {}
    for off, s in runs(blob, 4):
        for piece in re.findall(r"\^[A-Za-z0-9_]+", s):
            low = piece.lower()
            if COMMAND.match(low) and len(low) > 3:
                if filtered and not LETTERS.search(low):
                    continue
                found.setdefault(low, off)
    return found


def cmd_commands(a):
    blob = open(a.path, "rb").read()
    raw = commands(blob, filtered=False)
    found = commands(blob)
    lo, hi = 1100000, 1250000
    inside = {k: v for k, v in found.items() if lo <= v <= hi}
    outside = {k: v for k, v in found.items() if not (lo <= v <= hi)}
    print("file                     : %s  %d bytes" % (a.path, len(blob)))
    print("caret literals, unfiltered : %d" % len(raw))
    print("rejected as not words      : %d  (no three consecutive letters)"
          % (len(raw) - len(found)))
    print("script commands            : %d" % len(found))
    print("first at offset            : %d, last at %d"
          % (min(found.values()), max(found.values())))
    print("of those, between %d and %d : %d, and outside it %d"
          % (lo, hi, len(inside), len(outside)))
    print("the ones outside that region : %s" % ", ".join(sorted(outside)))
    print()
    groups = collections.OrderedDict([
        ("attunement", ("attun",)),
        ("dreamworld", ("dream",)),
        ("quest", ("quest",)),
        ("character", ("char", "creature")),
        ("spell and combat", ("spell", "cast", "attack", "kill", "heal",
                              "element", "damage")),
        ("items, money and shops", ("item", "gold", "shop", "sell", "buy",
                                    "container", "weapon")),
        ("camera, view and world", ("view", "worldmap", "lookat", "teleport",
                                    "center", "poz", "pohyb", "background")),
        ("presentation", ("anim", "voice", "slide", "outro", "text", "fade",
                          "dialog", "sound", "music")),
        ("flow control and state", ("flag", "state", "mem", "save", "load",
                                    "rest", "enable", "disable", "goto",
                                    "run_", "wait", "set_", "part")),
    ])
    used = set()
    for label, keys in groups.items():
        rows = sorted(c for c in found
                      if c not in used and any(k in c for k in keys))
        used.update(rows)
        print("%s -- %d" % (label, len(rows)))
        for i in range(0, len(rows), 3):
            print("   " + "  ".join("%-30s" % r for r in rows[i:i + 3]))
        print()
    rest = sorted(c for c in found if c not in used)
    print("not grouped -- %d" % len(rest))
    for i in range(0, len(rest), 3):
        print("   " + "  ".join("%-30s" % r for r in rest[i:i + 3]))
    print()
    slovak = [c for c in sorted(found)
              if any(w.lower() in c for w in ("pozadie", "pohyb", "poz_"))]
    print("commands whose name is Slovak : %d" % len(slovak))
    for c in slovak:
        print("   %s" % c)


def cmd_vocab(a):
    blob = open(a.path, "rb").read()
    sep = chr(92)
    print("file : %s  %d bytes" % (a.path, len(blob)))
    print()
    print("extensions the program names:")
    exts = collections.Counter()
    for off, s in runs(blob, 4):
        for m in re.finditer(r"\.[A-Za-z0-9]{1,6}\b", s):
            exts[m.group().lower()] += 1
    for e, n in exts.most_common(24):
        print("   %-10s %4d" % (e, n))
    print()
    print("strings holding a path separator or a format specifier:")
    shown = 0
    seen = set()
    for off, s in runs(blob, 6):
        if (sep in s or "/" in s) and "%" in s or s.startswith("/data"):
            if s in seen:
                continue
            seen.add(s)
            shown += 1
            if shown <= 40:
                print("   %8d  %s" % (off, s[:100]))
    print("   ... %d distinct" % len(seen))
    print()
    print("Slovak words, each searched for rather than asserted:")
    for w in SLOVAK:
        i = blob.find(w.encode("latin-1"))
        print("   %-12s %s" % (w, "at %d" % i if i >= 0 else "ABSENT"))
    print()
    print("the Slovak messages, in full:")
    for off, s in runs(blob, 6):
        if any(w in s for w in ("Nenasiel", "Uspesne", "nacital")):
            print("   %8d  %s" % (off, s[:100]))


def cmd_find(a):
    blob = open(a.path, "rb").read()
    needle = a.text.encode("latin-1")
    hits = []
    start = 0
    while True:
        i = blob.find(needle, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    print("%s in %s : %d occurrences" % (a.text, os.path.basename(a.path), len(hits)))
    for i in hits[:20]:
        lo = max(0, i - 16)
        print("   %8d  %r" % (i, blob[lo:i + len(needle) + 16]))
    # and the same four bytes as a little-endian u32 immediate, which is how a
    # magic gets written when it is not a string constant
    if len(needle) == 4:
        val = struct.unpack("<I", needle)[0]
        imm = struct.pack("<I", val)
        n = blob.count(imm)
        print()
        print("as a little-endian u32 immediate (0x%08X) : %d occurrences"
              % (val, n))
    return 0 if hits else 1


def cmd_years(a):
    """Where 2004 is, and where it is not. Searched over the whole tree, in
    ASCII and in UTF-16LE, because this object's text layer is UTF-16."""
    # One pass over each file, two regexes, rather than twenty searches each.
    # 1990..2029 is the window: everything outside it is a coordinate.
    a8 = re.compile(rb"(?:199|200|201|202)[0-9]")
    a16 = re.compile(rb"(?:1\x009\x009\x00|2\x000\x000\x00|2\x000\x001\x00"
                     rb"|2\x000\x002\x00)[0-9]\x00")
    counts = collections.Counter()
    where = collections.defaultdict(list)
    files = 0
    hitfiles = 0
    for dirpath, dirnames, filenames in os.walk(a.root):
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            try:
                blob = open(p, "rb").read()
            except OSError:
                continue
            files += 1
            local = collections.Counter()
            for m in a8.finditer(blob):
                local[m.group().decode("ascii")] += 1
            for m in a16.finditer(blob):
                local[m.group().decode("utf-16-le")] += 1
            if not local:
                continue
            hitfiles += 1
            rel = os.path.relpath(p, a.root)
            for y, n in local.items():
                counts[y] += n
                if len(where[y]) < 14:
                    where[y].append((rel, n))
    print("files searched : %d, of which holding a year-shaped run : %d"
          % (files, hitfiles))
    print("both ASCII and UTF-16LE, window 1990..2029")
    print()
    for y in sorted(counts):
        print("   %s  %8d occurrences" % (y, counts[y]))
    print()
    for y in sorted(counts):
        print("%s -- up to fourteen files:" % y)
        for rel, n in where[y]:
            print("   %6d x  %s" % (n, rel))
        print()


def cmd_selftest(a):
    ok = True
    print("POSITIVE -- the command scanner on a built pool:")
    pool = (b"\x00^attune_item\x00^add_gold\x00garbage\x00"
            b"^UPPER_CASE\x00^ok_one\x00")
    got = sorted(commands(pool))
    want = ["^add_gold", "^attune_item", "^ok_one", "^upper_case"]
    good = got == want
    print("   %-5s %r" % ("ok" if good else "FAIL", got))
    if not good:
        print("         wanted %r" % (want,))
    ok = ok and good

    print()
    print("NEGATIVE -- these must yield nothing:")
    cases = [
        ("a caret alone", b"^\x00"),
        ("a caret and one character", b"^a\x00"),
        ("a caret followed by punctuation", b"^!!!\x00"),
        ("no caret at all", b"attune_item\x00add_gold\x00"),
        ("an empty pool", b""),
    ]
    for name, blob in cases:
        got = commands(blob)
        if not got:
            print("   ok    %-40s nothing" % name)
        else:
            print("   FAIL  %-40s %r" % (name, sorted(got)))
            ok = False
    print()
    print("1 positive, %d negative, %s"
          % (len(cases), "all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("commands", cmd_commands), ("vocab", cmd_vocab)):
        p = sub.add_parser(name); p.add_argument("path"); p.set_defaults(fn=fn)
    p = sub.add_parser("find"); p.add_argument("path"); p.add_argument("text")
    p.set_defaults(fn=cmd_find)
    p = sub.add_parser("years"); p.add_argument("root"); p.set_defaults(fn=cmd_years)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
