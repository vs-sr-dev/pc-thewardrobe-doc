"""locate.py -- count a string in an image AND say where every occurrence is.

The rule this tool exists to enforce: a count is not a finding until it has an
address. `IVAN` occurring three times in 142 MB is a number; `IVAN` occurring
three times inside the pixel data of a bitmap is a different sentence from
`IVAN` occurring three times in a copyright notice, and the count cannot tell
them apart.

For every occurrence the tool prints the absolute image offset, the sector, the
file whose extent contains that sector (or the structure, if it is metadata),
the offset within that file, and a context window with non-printable bytes
shown as dots. It also prints the random expectation for a needle of that
length over an image of that size, so that a count is never published naked:

    expected = (image_bytes - len(needle) + 1) / 256 ** len(needle)

and, for counts below five, the Poisson tail probability of seeing at least
that many by chance.

Usage:
    python tools/locate.py IMAGE MANIFEST.tsv --find IVAN
    python tools/locate.py IMAGE MANIFEST.tsv --find "Tecniche Nuove" --utf16
    python tools/locate.py IMAGE MANIFEST.tsv --find-hex 424d --max 20
"""

import bisect
import math
import mmap
import sys

SECTOR = 2048


def load_manifest(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        head = fh.readline()
        if not head.startswith("sha1"):
            raise SystemExit("FATAL: %s does not look like a manifest" % path)
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) < 6:
                continue
            rows.append({"sha1": p[0], "size": int(p[1]), "extent": int(p[2]),
                         "path": p[5]})
    if not rows:
        raise SystemExit("FATAL: parsed zero rows from %s" % path)
    rows.sort(key=lambda r: r["extent"])
    starts = [r["extent"] * SECTOR for r in rows]
    return rows, starts


def owner(rows, starts, off):
    i = bisect.bisect_right(starts, off) - 1
    if i < 0:
        return None, None
    r = rows[i]
    rel = off - starts[i]
    if rel < r["size"]:
        return r, rel
    if rel < ((r["size"] + SECTOR - 1) // SECTOR) * SECTOR:
        return r, -1          # inside this file's sector tail (slack)
    return None, None


def poisson_tail(k, lam):
    """P(X >= k) for X ~ Poisson(lam)."""
    if k <= 0:
        return 1.0
    p = 0.0
    for i in range(0, k):
        p += math.exp(-lam) * lam ** i / math.factorial(i)
    return max(0.0, 1.0 - p)


def show(data, off, n, width=32):
    a = max(0, off - width)
    b = min(len(data), off + n + width)
    chunk = data[a:b]
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
    return txt


def run(image, manifest, needle, maxshow, regex=None):
    rows, starts = load_manifest(manifest)
    with open(image, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        total = len(mm)
        hits = []
        if regex is not None:
            import re as _re
            pat = _re.compile(regex)
            hits = [m.start() for m in pat.finditer(mm)]
            needle = regex
            n = 0
        else:
            pos = mm.find(needle, 0)
            while pos != -1:
                hits.append(pos)
                pos = mm.find(needle, pos + 1)
            n = len(needle)

        if regex is not None:
            print("image                : %s  (%d bytes)" % (image, total))
            print("pattern              : %r" % regex)
            print("occurrences          : %d" % len(hits))
            print()
            print("%-12s %8s %-26s %10s  context" % ("offset", "sector", "owner", "in-file"))
            for h in hits[:maxshow]:
                r, rel = owner(rows, starts, h)
                who = "(metadata / unclaimed)" if r is None else r["path"]
                where = "" if r is None else ("SLACK" if rel == -1 else str(rel))
                print("%-12d %8d %-26s %10s  %s"
                      % (h, h // SECTOR, who[:26], where, show(mm, h, 16)))
            return 0

        expect = (total - n + 1) / (256.0 ** n)
        print("image                : %s  (%d bytes)" % (image, total))
        print("needle               : %r  (%d bytes)" % (needle, n))
        print("occurrences          : %d" % len(hits))
        print("random expectation   : %.6g  (image_bytes / 256^%d)" % (expect, n))
        if len(hits) < 5:
            print("Poisson P(X >= %d)    : %.6g   <- below five occurrences the"
                  " ratio to the expectation is not a signal-to-noise ratio"
                  % (len(hits), poisson_tail(len(hits), expect)))
        elif expect > 0:
            print("count / expectation  : %.2fx" % (len(hits) / expect))
        print()
        if not hits:
            print("(nothing found -- and a tool that finds nothing is not a tool"
                  " that says zero: the needle above is what was searched for)")
            return 0
        print("%-12s %8s %-26s %10s  context" % ("offset", "sector", "owner", "in-file"))
        for h in hits[:maxshow]:
            r, rel = owner(rows, starts, h)
            if r is None:
                who, where = "(metadata / unclaimed)", ""
            elif rel == -1:
                who, where = r["path"], "SLACK"
            else:
                who, where = r["path"], str(rel)
            print("%-12d %8d %-26s %10s  %s"
                  % (h, h // SECTOR, who[:26], where, show(mm, h, n)))
        if len(hits) > maxshow:
            print("... %d more not shown" % (len(hits) - maxshow))
        print()
        from collections import Counter
        c = Counter()
        for h in hits:
            r, rel = owner(rows, starts, h)
            c[r["path"] if r else "(metadata / unclaimed)"] += 1
        print("by owning file:")
        for k, v in c.most_common():
            print("  %-30s %d" % (k, v))
    return 0


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 2
    image, manifest = argv[1], argv[2]
    maxshow = int(argv[argv.index("--max") + 1]) if "--max" in argv else 40
    if "--regex" in argv:
        return run(image, manifest,
                   None, maxshow,
                   regex=argv[argv.index("--regex") + 1].encode("latin-1"))
    if "--find-hex" in argv:
        needle = bytes.fromhex(argv[argv.index("--find-hex") + 1])
    elif "--find" in argv:
        s = argv[argv.index("--find") + 1]
        needle = s.encode("utf-16-le") if "--utf16" in argv else s.encode("latin-1")
    else:
        print(__doc__)
        return 2
    return run(image, manifest, needle, maxshow)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
