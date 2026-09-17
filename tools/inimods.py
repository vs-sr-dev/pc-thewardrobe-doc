#!/usr/bin/env python3
"""inimods.py -- every module a Windows 3.1 `.INI` names, checked one name at a
time against a real file tree.

`setuplist.py` pulls `directory\\name.ext` references out of a binary, which is
the right shape for an installer and the wrong shape for a `SYSTEM.INI`, whose
values are mostly bare file names -- `mouse.drv`, `vgasys.fon`,
`mmsystem.dll`. Those are the interesting ones on a Modular Windows disc,
because the runtime lives in ROM: a name the disc configures and does not
carry is a name the disc expects the console to supply, and counting them is
the closest a single pressing gets to describing the ROM.

The tool prints the answer for **every** name, present or absent, so that
"none of them is here" is a list of fourteen lines rather than a zero.

    python tools/inimods.py FILE.INI --tree DIR
    python tools/inimods.py FILE.INI --tree DIR --ext .drv .dll .fon .cor .mod
"""
import argparse
import os
import re
import sys

DEFAULT_EXT = (".drv", ".dll", ".fon", ".exe", ".com", ".cor", ".mod",
               ".vxd", ".386")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ini")
    ap.add_argument("--tree", required=True)
    ap.add_argument("--ext", nargs="*", default=list(DEFAULT_EXT))
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    text = open(a.ini, "rb").read().decode("latin-1")
    exts = "|".join(re.escape(e.lstrip(".")) for e in a.ext)
    # a module reference is a run of name characters ending in one of the
    # extensions, optionally preceded by a path; the path is kept for report
    pat = re.compile(r"([A-Za-z0-9_.%s%s\-]*[A-Za-z0-9_\-]+\.(?:%s))"
                     % (re.escape(chr(92)), re.escape("/"), exts),
                     re.IGNORECASE)
    section = None
    found = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s
            continue
        for m in pat.finditer(s):
            ref = m.group(1)
            key = s.split("=", 1)[0].strip() if "=" in s else ""
            found.append((section or "", key, ref))

    seen = set()
    mods = []
    for sec, key, ref in found:
        base = ref.replace(chr(92), "/").rsplit("/", 1)[-1].upper()
        if (base, ref.upper()) in seen:
            continue
        seen.add((base, ref.upper()))
        mods.append((sec, key, ref, base))

    tree = {}
    nfiles = 0
    for r, dirs, names in os.walk(a.tree):
        for nm in names:
            nfiles += 1
            tree.setdefault(nm.upper(), []).append(
                os.path.relpath(os.path.join(r, nm), a.tree).replace(chr(92), "/"))

    print("ini            : %s" % a.ini)
    print("tree           : %s   %d files, %d distinct names"
          % (a.tree, nfiles, len(tree)))
    print("module names   : %d distinct, matched on the base name folded up"
          % len(mods))
    print()
    print("%-14s %-14s %-30s %s" % ("[section]", "key", "value", "on the tree?"))
    present = 0
    for sec, key, ref, base in mods:
        hits = tree.get(base, [])
        if hits:
            present += 1
        print("%-14s %-14s %-30s %s"
              % (sec, key, ref, hits[0] if hits else "ABSENT"))
    print()
    print("present on the disc : %d of %d" % (present, len(mods)))
    print("absent from the disc: %d of %d" % (len(mods) - present, len(mods)))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
