#!/usr/bin/env python3
"""buildorder.py -- recover the order the banks were packed in, out of a buffer
nobody cleared.

The 36-byte name field of a `.BKF` record is not cleared between writes
(see docs/03), so whatever the packer had in that buffer last survives behind
the terminating NUL. In six of the twenty-eight archives the surviving tail is
a fragment of the packer's own console line:

    ACCEPT.LEZ\\0 + '430557 bytes) saved in ba'

and 1,430,557 is the length of `MENUFR.BKF`, which is the archive built
immediately before `MENUGR.BKF`. The number is truncated at the front by the
length of the member's own name, so it is matched as a **suffix** of a decimal
length, and a match is only reported when exactly one archive in the object
ends that way.

    python tools/buildorder.py <root>
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bkf import Archive, archives, BkfError  # noqa: E402

TAIL = re.compile(rb"(\d+) bytes\) saved in b")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    a = ap.parse_args()
    arcs = {}
    tails = {}
    for p in archives(a.root):
        arc = Archive(p)
        arcs[arc.name] = arc.length
        keep = []
        for m in arc.members:
            t = m.tail.rstrip(b"\x00")
            if t:
                keep.append((m.index, m.name.decode("latin-1"),
                             t.decode("latin-1")))
        tails[arc.name] = keep

    print("%-14s %10s  %s" % ("archive", "bytes", "record 0's tail"))
    print("-" * 72)
    for name in sorted(arcs):
        t = ""
        for idx, _n, s in tails[name]:
            if idx == 0:
                t = s
                break
        print("%-14s %10d  %r" % (name, arcs[name], t))

    print()
    print("the 'N bytes) saved in b...' fragments, resolved:")
    edges = []
    for name in sorted(arcs):
        for idx, mname, s in tails[name]:
            m = TAIL.search(s.encode("latin-1"))
            if not m:
                continue
            digits = m.group(1).decode()
            cands = [k for k, v in arcs.items() if str(v).endswith(digits)]
            if len(cands) == 1:
                edges.append((cands[0], name))
                print("   %-14s record %-3d tail %-28r -> %s (%d bytes)"
                      % (name, idx, s, cands[0], arcs[cands[0]]))
            else:
                print("   %-14s record %-3d tail %-28r -> %d candidates %s"
                      % (name, idx, s, len(cands), sorted(cands)))
    print()
    if not edges:
        print("no resolvable fragment -- nothing to chain")
        return 1
    succ = dict(edges)
    preds = set(succ.keys())
    heads = [b for _a, b in edges if b not in preds]
    print("chains, each arrow meaning 'packed immediately before':")
    seen = set()
    starts = [a for a, _b in edges if a not in succ.values()]
    for s in sorted(set(starts)):
        chain = [s]
        cur = s
        while cur in succ and succ[cur] not in chain:
            cur = succ[cur]
            chain.append(cur)
        seen.update(chain)
        print("   " + " -> ".join(chain))
    left = [b for _a, b in edges if b not in seen]
    for x in sorted(set(left)):
        print("   (unattached) %s" % x)
    print()
    print("archives with a resolvable predecessor : %d of %d"
          % (len(edges), len(arcs)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BkfError as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        sys.exit(2)
