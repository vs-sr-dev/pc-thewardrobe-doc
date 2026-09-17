#!/usr/bin/env python3
"""buildpaths.py -- the absolute paths a build machine left inside the product.

`paths.py` counts them and classifies them; this one collects the distinct
*Telltale-rooted* strings out of the preference files the localised builds
shipped, so the chapter can print the list instead of a total. It exists
separately because the pattern contains four backslashes and a character
class, and this session lost that pattern twice to a shell heredoc before
putting it in a file. A tool in a file has a backslash count that can be
checked.

    python tools/buildpaths.py _work/out out.txt
"""
import os
import re
import sys

BSL = chr(92)
PAT = re.compile(("[A-Za-z]:[" + BSL + BSL + "/][Tt]elltale"
                  "[" + BSL + BSL + "/A-Za-z0-9_. -]{0,90}").encode("ascii"))


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "_work/out"
    out = sys.argv[2] if len(sys.argv) > 2 else None
    found = {}
    files = 0
    scanned = 0
    for dp, _dn, fn in os.walk(root):
        for n in sorted(fn):
            p = os.path.join(dp, n)
            scanned += 1
            hits = {m.group().decode("latin-1")
                    for m in PAT.finditer(open(p, "rb").read())}
            if hits:
                files += 1
            for h in hits:
                found.setdefault(h, set()).add(os.path.basename(dp))
    lines = ["files carrying a Telltale-rooted path: %d of %d scanned"
             % (files, scanned),
             "distinct paths: %d" % len(found), ""]
    for k in sorted(found):
        lines.append("%-92s %s" % (k, ",".join(sorted(found[k]))))
    text = "\n".join(lines)
    print(text)
    if out:
        open(out, "w", encoding="utf-8").write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
