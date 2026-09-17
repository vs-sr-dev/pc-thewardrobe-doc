#!/usr/bin/env python3
"""envblock.py -- find captured Windows environment blocks inside binary data.

A Windows process environment is a run of `NAME=value` strings separated by NUL
and terminated by two NULs. When an exporter writes its whole environment into
the file it is exporting -- which happens when a tool serialises a struct it
should not have -- the block travels with the asset for as long as the asset
ships. That is not a build path and no path scanner is looking for it, so it
needs its own search.

The tool reports the **shape** of what it finds: which variable names are
present, how many blocks, in which files and at which offsets. Values are
printed only for variables on an explicit allow-list of ones that name a
machine's software rather than its user; everything else is counted and its
length reported, and the value is not reproduced. `--reveal --i-am-sure` prints
values, and exists so that a human can check the classification once.

    python tools/envblock.py "<root>"
    python tools/envblock.py "<root>" --ext .dat --min-vars 4
"""
import argparse
import collections
import os
import re
import sys

# variables whose value describes the software, not the person
SAFE = {
    "COMSPEC", "OS", "PATH", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION", "PROCESSOR_IDENTIFIER", "HOMEDRIVE", "COMMONPROGRAMFILES",
    "PROGRAMFILES", "TEMP", "TMP", "SESSIONNAME",
}
# variables whose value names a person, a machine, or a network
PERSONAL = {
    "COMPUTERNAME", "USERNAME", "USERDOMAIN", "USERPROFILE", "HOMEPATH",
    "LOGONSERVER", "APPDATA", "CLIENTNAME", "HOMESHARE",
}

VAR = re.compile(rb"([A-Za-z_][A-Za-z0-9_()# ]{1,40})=([ -~]{0,400})\x00")


def blocks(blob, minvars):
    """Runs of at least `minvars` consecutive NAME=value NUL records."""
    out = []
    pos = 0
    while True:
        m = VAR.search(blob, pos)
        if not m:
            break
        start = m.start()
        run = []
        p = start
        while True:
            m2 = VAR.match(blob, p)
            if not m2:
                break
            run.append((m2.start(), m2.group(1).decode("latin-1"),
                        m2.group(2).decode("latin-1")))
            p = m2.end()
        if len(run) >= minvars:
            out.append((start, run))
            pos = p
        else:
            pos = m.end()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--ext", nargs="*", default=None,
                    help="limit to these extensions; default is every file")
    ap.add_argument("--min-vars", type=int, default=4)
    ap.add_argument("--reveal", action="store_true")
    ap.add_argument("--i-am-sure", action="store_true")
    ap.add_argument("--leakcheck", nargs="*", default=None, metavar="DIR",
                    help="after scanning, check that no file under these "
                         "directories contains any of the identifiers found. "
                         "Values are never printed.")
    a = ap.parse_args()

    files = []
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames.sort()
        for fn in sorted(filenames):
            if a.ext and os.path.splitext(fn)[1].lower() not in [e.lower() for e in a.ext]:
                continue
            files.append(os.path.join(dirpath, fn))

    nblocks = 0
    names = collections.Counter()
    perfile = collections.Counter()
    personal_hits = collections.Counter()
    identifiers = set()
    searched = 0
    for path in files:
        blob = open(path, "rb").read()
        searched += len(blob)
        for off, run in blocks(blob, a.min_vars):
            nblocks += 1
            for _o, _k, _v in run:
                if _k.upper() in PERSONAL:
                    # keep the leaf of a path and the whole value, so that a
                    # careless paraphrase is caught as well as a copy-paste
                    identifiers.add(_v)
                    leaf = _v.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
                    identifiers.add(leaf)
                    identifiers.add(leaf.split(".")[0])
            perfile[os.path.relpath(path, a.root)] += 1
            print("block at %s +%d, %d variables"
                  % (os.path.relpath(path, a.root), off, len(run)))
            for o, k, v in run:
                key = k.upper()
                names[key] += 1
                if key in SAFE or (a.reveal and a.i_am_sure):
                    print("      %-24s = %s" % (k, v))
                elif key in PERSONAL:
                    personal_hits[key] += 1
                    print("      %-24s = <%d characters, names a person or a machine: "
                          "counted, not reproduced>" % (k, len(v)))
                else:
                    print("      %-24s = <%d characters, unclassified: not reproduced>"
                          % (k, len(v)))
            print()

    print("=" * 70)
    print("files searched   : %d" % len(files))
    print("bytes searched   : %d" % searched)
    print("blocks found     : %d in %d files" % (nblocks, len(perfile)))
    for k, v in perfile.most_common():
        print("   %-24s %d" % (k, v))
    print("distinct variable names : %d" % len(names))
    print("   %s" % ", ".join("%s x%d" % (k, v) for k, v in names.most_common()))
    print("variables that name a person, a machine or a network : %d occurrences"
          % sum(personal_hits.values()))
    for k, v in personal_hits.most_common():
        print("   %-24s %d" % (k, v))
    if nblocks == 0:
        print()
        print("NOTE: zero blocks. That is a result only if the search ran; "
              "%d files and %d bytes were read." % (len(files), searched))

    if a.leakcheck is not None:
        print()
        print("=" * 70)
        toks = sorted({t for t in identifiers if len(t) >= 4})
        assert toks, ("no personal identifier was recovered, so there is "
                      "nothing to check for. Refusing to report CLEAN on an "
                      "empty search.")
        print("identifiers recovered : %d, of 4 characters or more "
              "(NOT printed)" % len(toks))
        checked = 0
        hits = []
        for d in (a.leakcheck or ["docs", "notes", "tools"]):
            for dirpath, dirnames, filenames in os.walk(d):
                dirnames[:] = [x for x in dirnames if x != "__pycache__"]
                for fn in sorted(filenames):
                    if fn.endswith(".pyc"):
                        continue
                    p = os.path.join(dirpath, fn)
                    checked += 1
                    data = open(p, "rb").read()
                    for t in toks:
                        for enc in ("latin-1", "utf-16-le"):
                            try:
                                needle = t.encode(enc)
                            except UnicodeEncodeError:
                                continue
                            if needle in data:
                                hits.append((p, len(t), enc))
        print("repository files      : %d" % checked)
        for p, n, enc in hits:
            print("   HIT  %-50s a %d-character identifier, %s" % (p, n, enc))
        print("hits                  : %d" % len(hits))
        print("VERDICT               : %s"
              % ("CLEAN" if not hits else "NOT CLEAN -- read the hits above"))
        print()
        print("A hit is not automatically a leak. A four-character identifier "
              "can collide with an unrelated constant, and this tool reports "
              "the collision rather than deciding it. Each hit must be looked "
              "at once, by a person, and the verdict written down.")


if __name__ == "__main__":
    main()
