#!/usr/bin/env python3
"""qres.py -- the 7,671 resources of queen.1, listed, typed and counted.

`qtbl.py` finds and chooses the table. This tool uses it and does the census:
what is in the bundle, how much of it there is, what its first bytes say it is,
and whether the whole thing closes.

Nothing here trusts a file extension. The `type` column is decided by opening
the resource and looking, and where the first bytes disagree with the name that
is reported rather than reconciled -- three of this bundle's sixteen extensions
turn out to carry more than one kind of thing.

    python tools/qres.py census _game/scummvm/scummvm.exe _game/queen.1
    python tools/qres.py list _game/scummvm/scummvm.exe _game/queen.1 > notes/resources.txt
    python tools/qres.py heads _game/scummvm/scummvm.exe _game/queen.1
    python tools/qres.py extract _game/scummvm/scummvm.exe _game/queen.1 _work/res --ext .PCX
    python tools/qres.py names _game/scummvm/scummvm.exe _game/queen.1 --ext .SB
"""

import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qtbl  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# What the first bytes actually say, derived by looking rather than assumed.
# Each entry is (label, predicate on the first 16 bytes and the size).
SIGS = [
    ("PCX",   lambda h, n: h[:1] == b"\x0a" and h[1:2] in (b"\x02", b"\x03",
                                                           b"\x04", b"\x05")),
    ("AmBk",  lambda h, n: h[:4] == b"AmBk"),
    ("markup", lambda h, n: h[:1] == b"." and h[1:2].isdigit() or
               h[:3] in (b".8\r", b".c\r")),
    ("zeros", lambda h, n: h[:16] == b"\x00" * 16),
    ("SBform", lambda h, n: len(h) >= 4 and h[1] == 0 and h[3] == 0 and
               0 < h[0] < 128 and h[2] > 0),
]


def classify(head, size):
    for label, pred in SIGS:
        try:
            if pred(head, size):
                return label
        except Exception:
            pass
    return "?"


def get_table(exe, bundle, version):
    buf = qtbl.load(exe)
    data = qtbl.load(bundle)
    at, ver = qtbl.find_qtbl(buf)
    tabs, _ = qtbl.walk_qtbl(buf, at)
    best = None
    scored = []
    for rel, n, fo in tabs:
        recs = qtbl.read_records(buf, fo, n)
        b1 = [r for r in recs if r[1] == 1]
        if sum(r[3] for r in b1) != len(data):
            continue
        _per, good, tot, _oob = qtbl.content_score(recs, data)
        scored.append((good / tot if tot else 0, fo, n, recs))
    if not scored:
        raise SystemExit("no table whose bundle-1 bytes equal the bundle size")
    scored.sort(reverse=True)
    best = scored[0]
    if len(scored) > 1 and best[0] < 0.9:
        raise SystemExit("no table passes the content test convincingly")
    return buf, data, best[1], best[2], best[3], len(scored)


def rows_of(recs, data):
    out = []
    for name, bundle, off, size in recs:
        head = data[off:off + 16]
        out.append((name, bundle, off, size, head, classify(head, size)))
    return out


def cmd_census(a):
    buf, data, fo, n, recs, ncand = get_table(a.exe, a.bundle, a.version)
    rows = rows_of(recs, data)
    total = len(data)
    print("bundle              %s (%d bytes)" % (a.bundle, total))
    print("table chosen at     %d = 0x%X, %d records" % (fo, fo, n))
    print("candidates whose bundle-1 total equalled the bundle size: %d" % ncand)
    print()
    ce, be = Counter(), Counter()
    for name, _b, _o, size, _h, _t in rows:
        e = os.path.splitext(name)[1].upper() or "(none)"
        ce[e] += 1
        be[e] += size
    print("%-9s %6s %14s %10s" % ("extension", "files", "bytes", "share"))
    for e in sorted(ce, key=lambda k: -be[k]):
        print("%-9s %6d %14d %9.4f %%" % (e, ce[e], be[e], 100.0 * be[e] / total))
    print("%-9s %6d %14d %9.4f %%" % ("total", sum(ce.values()),
                                      sum(be.values()),
                                      100.0 * sum(be.values()) / total))
    print()
    print("%-9s %6s %14s   %s" % ("first-byte type", "files", "bytes",
                                  "extensions it appears under"))
    ct, bt = Counter(), Counter()
    where = defaultdict(Counter)
    for name, _b, _o, size, _h, t in rows:
        ct[t] += 1
        bt[t] += size
        where[t][os.path.splitext(name)[1].upper() or "(none)"] += 1
    for t in sorted(ct, key=lambda k: -bt[k]):
        exts = ", ".join("%s x%d" % (k, v) for k, v in where[t].most_common())
        print("%-9s %6d %14d %8.4f %%  %s"
              % (t, ct[t], bt[t], 100.0 * bt[t] / total, exts))
    print()
    d = qtbl.arith(recs, total)
    print("coverage            %d of %d = %.6f %%"
          % (d["bytes"], total, d["coverage"]))
    print("holes / overlaps    %d / %d" % (d["holes"], d["overlaps"]))
    print("duplicate names     %d" % d["dupnames"])
    print("first byte used     %d" % d["first"])
    print("last byte used      %d" % d["end"])
    sizes = Counter(r[3] for r in recs)
    print()
    print("fixed-size populations (a fixed size is an equation):")
    for size, k in sizes.most_common(8):
        if k < 5:
            continue
        exts = Counter(os.path.splitext(r[0])[1].upper()
                       for r in recs if r[3] == size)
        print("  %8d bytes x %-5d  %s" % (size, k, dict(exts)))
    return 0


def cmd_list(a):
    buf, data, fo, n, recs, _ = get_table(a.exe, a.bundle, a.version)
    rows = rows_of(recs, data)
    print("# table at 0x%X, %d records, from %s" % (fo, n, os.path.basename(a.exe)))
    print("# %-12s %3s %11s %10s  %-7s %s"
          % ("name", "bnd", "offset", "size", "type", "first 12 bytes"))
    for name, b, off, size, head, t in rows:
        print("%-14s %3d %11d %10d  %-7s %s" % (name, b, off, size, t,
                                                head[:12].hex()))
    return 0


def cmd_heads(a):
    buf, data, fo, n, recs, _ = get_table(a.exe, a.bundle, a.version)
    rows = rows_of(recs, data)
    byext = defaultdict(list)
    for r in rows:
        byext[os.path.splitext(r[0])[1].upper() or "(none)"].append(r)
    for e in sorted(byext):
        g = byext[e]
        c = Counter(r[4][:a.width].hex() for r in g)
        print("%-8s %5d files, %d distinct first-%d-byte patterns"
              % (e, len(g), len(c), a.width))
        for h, k in c.most_common(a.top):
            ex = next(r[0] for r in g if r[4][:a.width].hex() == h)
            print("   %-6d %-24s  %s" % (k, h, ex))
        print()
    return 0


def cmd_names(a):
    buf, data, fo, n, recs, _ = get_table(a.exe, a.bundle, a.version)
    sel = [r for r in recs
           if not a.ext or r[0].upper().endswith(a.ext.upper())]
    print("%s: %d resources" % (a.ext or "all", len(sel)))
    lens = Counter(len(r[0]) for r in sel)
    print("name lengths        %s" % dict(sorted(lens.items())))
    stems = [os.path.splitext(r[0])[0] for r in sel]
    L = Counter(len(s) for s in stems)
    print("stem lengths        %s" % dict(sorted(L.items())))
    if a.positions:
        width = max(len(s) for s in stems)
        print()
        print("%-4s %8s  %s" % ("pos", "distinct", "values (most common first)"))
        for i in range(width):
            c = Counter(s[i] for s in stems if len(s) > i)
            top = " ".join("%s:%d" % (k, v) for k, v in c.most_common(12))
            print("%-4d %8d  %s" % (i, len(c), top))
    if a.groups:
        g = Counter(s[:a.groups] for s in stems)
        print()
        print("distinct %d-character prefixes: %d" % (a.groups, len(g)))
        for k, v in g.most_common(a.top):
            print("   %-8s %d" % (k, v))
    return 0


def cmd_extract(a):
    buf, data, fo, n, recs, _ = get_table(a.exe, a.bundle, a.version)
    os.makedirs(a.out, exist_ok=True)
    k = 0
    for name, bundle, off, size in recs:
        if a.ext and not name.upper().endswith(a.ext.upper()):
            continue
        if a.name and name.upper() != a.name.upper():
            continue
        with open(os.path.join(a.out, name), "wb") as fh:
            fh.write(data[off:off + size])
        k += 1
    print("wrote %d resources to %s" % (k, a.out))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("census", cmd_census), ("list", cmd_list),
                     ("heads", cmd_heads), ("names", cmd_names),
                     ("extract", cmd_extract)):
        p = sub.add_parser(name)
        p.add_argument("exe")
        p.add_argument("bundle")
        p.add_argument("--version", default=None)
        if name == "heads":
            p.add_argument("--width", type=int, default=8)
            p.add_argument("--top", type=int, default=4)
        if name == "names":
            p.add_argument("--ext", default=None)
            p.add_argument("--positions", action="store_true")
            p.add_argument("--groups", type=int, default=0)
            p.add_argument("--top", type=int, default=20)
        if name == "extract":
            p.add_argument("out")
            p.add_argument("--ext", default=None)
            p.add_argument("--name", default=None)
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
