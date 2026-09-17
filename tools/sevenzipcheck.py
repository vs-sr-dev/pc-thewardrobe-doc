#!/usr/bin/env python3
"""sevenzipcheck.py -- set my derived NSIS listing against 7-Zip's.

A second implementation that agrees is a check. A second implementation used
*instead* of a derivation is not a derivation, so this runs last and it
compares sets rather than counts: a count can match while the contents do not.

Two normalisations, both of which have to be stated because both could hide a
disagreement:

  * 7-Zip prints the installer's own paths without the `$INSTDIR` prefix that
    the entries stream carries, so the prefix is stripped from mine;
  * 7-Zip leaves the language placeholders unresolved as `$(LSTR_nn)` while
    this reader resolves them through the language table. With `--remask` the
    resolution is undone before comparing, so the comparison tests the *paths*
    and not the language resolution; without it, the diff shows exactly how
    many names the resolution touched.

    python tools/sevenzipcheck.py notes/members-english.txt _work/7z-english.txt --remask
"""
import re
import sys

INSTDIR = "$INSTDIR" + chr(92)
PLUGDIR = "$PLUGINSDIR" + chr(92)


def read_mine(path, remask=False):
    names = []
    lang = {}
    body = False
    for line in open(path, encoding="utf-8"):
        if line.startswith("# sha1"):
            body = True
            continue
        if line.startswith("langstring" + chr(9)):
            bits = line.rstrip("\n").split(chr(9), 2)
            if len(bits) == 3 and bits[2]:
                lang[bits[2]] = "$(LSTR_%s)" % bits[1]
            continue
        if not body or line.startswith("#"):
            continue
        parts = line.rstrip("\n").split(chr(9))
        if len(parts) != 4:
            continue
        p = parts[3]
        for pref in (INSTDIR, PLUGDIR):
            if p.startswith(pref):
                p = p[len(pref):]
        if remask:
            for val in sorted(lang, key=len, reverse=True):
                # only mask strings long enough to be a path segment: the
                # language table also holds the word 'english', which is a
                # literal inside six archive names and must not be masked
                if len(val) > 7 and val in p:
                    p = p.replace(val, lang[val])
        names.append(p)
    return names


def read_7z(path):
    names = []
    started = False
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("------------------- ----- "):
            started = not started
            continue
        if not started:
            continue
        m = re.match(r"^.{53}(.*)$", line.rstrip("\n"))
        if not m:
            continue
        p = m.group(1)
        if p.startswith(PLUGDIR):
            p = p[len(PLUGDIR):]
        names.append(p)
    return names


def main():
    remask = "--remask" in sys.argv
    mine = read_mine(sys.argv[1], remask=remask)
    theirs = read_7z(sys.argv[2])
    ms, ts = set(mine), set(theirs)
    print("remask  %s" % remask)
    print("mine    %6d entries, %6d distinct names" % (len(mine), len(ms)))
    print("7-Zip   %6d entries, %6d distinct names" % (len(theirs), len(ts)))
    only_mine = sorted(ms - ts)
    only_theirs = sorted(ts - ms)
    print("in both %6d" % len(ms & ts))
    print("only in mine  %d" % len(only_mine))
    for n in only_mine[:12]:
        print("    %s" % n)
    print("only in 7-Zip %d" % len(only_theirs))
    for n in only_theirs[:12]:
        print("    %s" % n)
    return 0 if not only_mine and not only_theirs else 1


if __name__ == "__main__":
    sys.exit(main())
