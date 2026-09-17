#!/usr/bin/env python3
"""pathvendors.py -- divide `buildpaths.py`'s output by whose machine it came from.

`buildpaths.py` is run intact on every object in this collection so its total
stays comparable across ten of them. What it does not do is say *whose* machines
those paths belong to, and on a disc that is 68 % other people's installers that
is the whole question: 646 DOS-shaped paths from one vendor is a leak, and 646
from twenty vendors is an inventory.

So this reads the TSV `buildpaths.py` already wrote and groups it two ways:

  * by the **product directory** the string was found in -- which vendor shipped
    the file that leaked;
  * by the **build root**, drive letter plus first path component -- which
    directory on which machine the developer was working in.

It also counts, without printing them, the paths that run through a named user's
home directory (`Documents and Settings`, `Dokumente und Einstellungen`,
`Users`). Those carry a person's account name, and this branch counts personal
identifiers rather than publishing them.

    python tools/pathvendors.py notes/buildpaths.tsv
"""

import argparse
import re
import sys
from collections import Counter, defaultdict

ROOT = re.compile(r"^([A-Za-z]):[\\/]([^\\/]*)")
HOME = re.compile(r"(Documents and Settings|Dokumente und Einstellungen|Users)"
                  r"[\\/]", re.I)


def product(path):
    parts = path.split("/")
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tsv")
    ap.add_argument("--roots", type=int, default=30)
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    rows = [l.rstrip("\n").split("\t")
            for l in open(a.tsv, encoding="utf-8", errors="replace")][1:]
    rows = [r for r in rows if len(r) >= 5]
    dos = [r for r in rows if r[3] == "DOS"]
    mac = [r for r in rows if r[3] == "Mac"]

    print("hits            %d   (DOS %d, Mac-shaped %d)"
          % (len(rows), len(dos), len(mac)))
    print("distinct strings  DOS %d   Mac-shaped %d"
          % (len(set(r[4] for r in dos)), len(set(r[4] for r in mac))))
    print("files carrying at least one DOS path: %d"
          % len(set(r[1] for r in dos)))
    print()

    v = Counter()
    vs = defaultdict(set)
    for r in dos:
        p = product(r[1])
        v[p] += 1
        vs[p].add(r[4])
    print("-- DOS-shaped paths by product directory ---------------------------")
    for k, n in v.most_common():
        print("   %-48s %5d hits %5d distinct" % (k[:48], n, len(vs[k])))
    print()

    roots = Counter()
    rootfiles = defaultdict(set)
    for r in dos:
        m = ROOT.match(r[4])
        if m:
            key = m.group(1).upper() + ":" + chr(92) + m.group(2)
            roots[key] += 1
            rootfiles[key].add(product(r[1]))
    print("-- build roots (drive letter + first component): %d distinct --------"
          % len(roots))
    for k, n in roots.most_common(a.roots):
        print("   %-44s %5d   %s"
              % (k[:44], n, ", ".join(sorted(rootfiles[k]))[:40]))
    print()

    home = [r for r in dos if HOME.search(r[4])]
    print("paths through a named user's home directory: %d hits, %d distinct"
          % (len(home), len(set(r[4] for r in home))))
    print("   the account names are counted here and written nowhere")
    print()

    mc = Counter(r[1] for r in mac)
    print("-- Macintosh-shaped hits, by file ----------------------------------")
    for k, n in mc.most_common(12):
        print("   %-56s %3d" % (k[-56:], n))
    print()
    print("   a sample of what the Macintosh heuristic actually matched:")
    for r in mac[:10]:
        print("      %s" % r[4][:78])


if __name__ == "__main__":
    main()
