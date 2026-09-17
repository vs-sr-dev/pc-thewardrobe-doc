#!/usr/bin/env python3
"""redactnotes.py -- withhold personal identifiers from the raw tool output
before it is committed, and say how many were withheld.

`buildpaths.py` prints every absolute path it finds, and twenty-five of the 646
on this disc run through a named user's home directory -- `Documents and
Settings\\<account>` and `Dokumente und Einstellungen\\<account>`. Those carry the
Windows account names of developers at two companies. This repository counts
personal identifiers and does not publish them, in `docs/` and in `notes/`
alike, so the raw output cannot be committed as it stands.

What this does **not** do is mask or truncate. A masked string is still a
publication of its shape and its length, and a file full of `<redacted>` invites
somebody to reconstruct it. The matching lines are **removed**, and a header is
written at the top of the file saying how many were removed, by which pattern,
and how to reproduce the unredacted output locally.

    python tools/redactnotes.py notes/buildpaths.tsv notes/buildpaths.txt
    python tools/redactnotes.py --check notes/*.txt notes/*.tsv

**A second mode, added for the thirty-first object, and it substitutes rather
than removes.** That object is a live installation rather than a disc image, so
every tool was pointed at a directory on the machine that read it, and several
of them print that directory at the top of their output. It is not a personal
identifier -- it names no account and no person -- but it is a path on *this*
computer and the branch rule is that such paths are not written down.

Removing those lines would take the header off a census. Substituting a token
for the root loses nothing, because the root is an argument the reader supplies
anyway. So the two cases are treated differently on purpose:

    a person's home directory   -> the line is REMOVED, and counted
    the root a tool was given   -> the root is REPLACED by a token, and counted

and the difference is that a masked personal identifier still publishes its
shape and its length, while a masked command-line argument publishes nothing at
all.

    python tools/redactnotes.py --root "<the directory you pointed the tools at>" notes/*.txt
"""

import argparse
import re
import sys

BSLASH = chr(92)

HOME = re.compile(r"(Documents and Settings|Dokumente und Einstellungen|"
                  r"Users)[\\/][^\\/\s\"']+", re.I)
HEADER = ("# %d line(s) withheld from this file by tools/redactnotes.py.\n"
          "# Reason: %s.\n"
          "# This repository counts personal identifiers and does not publish\n"
          "# them. The counts derived from them are in the paths chapter.\n"
          "# To reproduce the unredacted output, re-run the tool named in the\n"
          "# chapter against your own copy of the object.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--check", action="store_true",
                    help="report and change nothing")
    ap.add_argument("--pattern", default=None,
                    help="regex identifying the lines to withhold; defaults "
                         "to the home-directory pattern above. Each object "
                         "leaks a different shape of identifier, so this is "
                         "an argument and not a constant: on the Amazon Queen "
                         "installation the leak is the install path an "
                         "installer wrote this morning, not a build path from "
                         "1995")
    ap.add_argument("--reason", default="absolute paths running through a "
                                        "named user's home directory")
    ap.add_argument("--root", default=None,
                    help="the directory the tools were pointed at; every "
                         "spelling of it is replaced by a token rather than "
                         "removed. See the note in the docstring about why "
                         "this case is substituted and the other removed")
    ap.add_argument("--root-token", default="<install dir>")
    a = ap.parse_args()
    global HOME
    if a.pattern:
        HOME = re.compile(a.pattern, re.I)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    roots = []
    if a.root:
        r = a.root.rstrip("/").rstrip(BSLASH)
        roots = [r, r.replace("/", BSLASH), r.replace(BSLASH, "/")]
        roots = sorted(set(roots), key=len, reverse=True)

    bad = 0
    subs = 0
    for p in a.paths:
        if roots:
            try:
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                text = None
            if text is not None:
                n = sum(text.count(r) for r in roots)
                if n:
                    for r in roots:
                        text = text.replace(r, a.root_token)
                    if not a.check:
                        with open(p, "w", encoding="utf-8", newline="") as fh:
                            fh.write(text)
                    subs += n
                    print("  %-40s %d occurrence(s) of the root %s"
                          % (p, n, "would be replaced" if a.check
                             else "replaced by " + a.root_token))
        try:
            lines = open(p, encoding="utf-8", errors="replace").readlines()
        except OSError as e:
            print("  cannot read %s: %s" % (p, e))
            continue
        hits = [l for l in lines if HOME.search(l)]
        if not hits:
            print("  clean   %s" % p)
            continue
        bad += len(hits)
        print("  %-40s %d line(s) match" % (p, len(hits)))
        if a.check:
            continue
        keep = [l for l in lines if not HOME.search(l)]
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(HEADER % (len(hits), a.reason))
            fh.writelines(keep)
        print("      rewrote %s: %d lines kept, %d withheld"
              % (p, len(keep), len(hits)))
    if subs:
        print()
        print("%d occurrence(s) of the root directory %s."
              % (subs, "would be replaced" if a.check else "replaced"))
    if a.check and (bad or subs):
        print()
        print("%d line(s) would be withheld. Run without --check to do it."
              % bad)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
