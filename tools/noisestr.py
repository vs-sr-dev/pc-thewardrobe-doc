"""noisestr.py -- a scan that fires a lot is a scan to read by hand.

`strcount.py` finds `Wii` 417 times, `iOS` 341 and `Xbox` 49 inside this
object.  None of them is evidence of anything until two questions are answered:
where does each hit land, and how many would chance put there anyway?

    where <root> --tsv MEMBERS.tsv STRING [STRING...]

For every hit the tool reports whether it falls in an archive's index table, in
the slack between members, or inside a member -- and if inside a member, what
that member is.  Beside it, the count chance predicts for a string of that
length over the same number of bytes, and the observed count divided by it.

Nothing is extracted.

    python tools/noisestr.py where "<root>" --tsv _work/vt7a-members.tsv Wii iOS Xbox
"""
import os
import sys
import bisect
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table as vt_table, extent, VT7A   # noqa: E402
from aufs import read_table as aufs_table, OSA          # noqa: E402

CHUNK = 1 << 24


def layout(root, arch):
    """Return (table_end, [(start, end, label)]) sorted by start."""
    if arch.endswith(".vt7a"):
        n, ver, m2, count, recs = vt_table(os.path.join(root, arch))
        tend = 16 + 16 * count
        spans = sorted((r[1], r[1] + extent(r), r[0]) for r in recs)
    else:
        n, count, recs = aufs_table(os.path.join(root, arch))
        tend = 8 + 12 * count
        spans = sorted((o, o + s, i) for i, o, s in recs)
    return n, tend, spans


def sigmap(tsv):
    out = {}
    if not tsv or not os.path.exists(tsv):
        return out
    with open(tsv) as fh:
        fh.readline()
        for line in fh:
            f = line.rstrip("\n").split("\t")
            out[(f[0], int(f[1]))] = f[6]
    return out


def where(root, tsv, needles):
    sigs = sigmap(tsv)
    files = sorted(f for f in os.listdir(root)
                   if os.path.isfile(os.path.join(root, f)))
    total_bytes = sum(os.path.getsize(os.path.join(root, f)) for f in files)
    print("files %d, bytes %d" % (len(files), total_bytes))
    print()
    per = {n: collections.Counter() for n in needles}
    inmember = {n: collections.Counter() for n in needles}
    for f in files:
        p = os.path.join(root, f)
        n = os.path.getsize(p)
        arch = f if (f.endswith(".vt7a") or f.endswith(".osa")) else None
        tend = None
        starts = ends = ids = None
        if arch:
            _n, tend, spans = layout(root, arch)
            starts = [s[0] for s in spans]
            ends = [s[1] for s in spans]
            ids = [s[2] for s in spans]
        with open(p, "rb") as fh:
            base = 0
            tail = b""
            while True:
                buf = fh.read(CHUNK)
                if not buf:
                    break
                data = tail + buf
                dbase = base - len(tail)
                for needle in needles:
                    nb = needle.encode("latin-1")
                    i = data.find(nb)
                    while i >= 0:
                        pos = dbase + i
                        if arch is None:
                            per[needle]["plain file: " + f] += 1
                        elif pos < tend:
                            per[needle]["index table"] += 1
                        else:
                            j = bisect.bisect_right(starts, pos) - 1
                            if j >= 0 and pos < ends[j]:
                                per[needle]["inside a member"] += 1
                                key = (arch, ids[j])
                                inmember[needle][sigs.get(key, "osa/Opus")] += 1
                            else:
                                per[needle]["slack between members"] += 1
                        i = data.find(nb, i + 1)
                base += len(buf)
                tail = data[-32:]
    print("%-10s %8s %10s %12s %14s %10s"
          % ("string", "hits", "expected", "observed/exp", "where", ""))
    for needle in needles:
        tot = sum(per[needle].values())
        exp = total_bytes / float(256 ** len(needle))
        print()
        print("%-10s %8d %10.1f %12.3f" % (needle, tot, exp, tot / exp if exp else 0))
        for k, v in per[needle].most_common():
            print("      %-28s %8d   %6.2f %%" % (k, v, 100.0 * v / tot))
        if inmember[needle]:
            print("      of the ones inside a member, the member is:")
            for k, v in inmember[needle].most_common(8):
                print("         %-25s %8d" % (k, v))
    print()
    print("`expected` is what a uniformly random byte stream of the same size")
    print("would contain: bytes / 256^len.  It is an upper bound on innocence,")
    print("not a proof: real data is not uniform.  A ratio near 1 means the")
    print("count is what chance gives you and carries no information.")
    return 0


def main():
    root = sys.argv[2]
    tsv = None
    if "--tsv" in sys.argv:
        tsv = sys.argv[sys.argv.index("--tsv") + 1]
    needles = [a for a in sys.argv[3:]
               if not a.startswith("--") and a != tsv]
    return where(root, tsv, needles)


if __name__ == "__main__":
    sys.exit(main())
