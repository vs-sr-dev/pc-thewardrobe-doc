#!/usr/bin/env python3
"""mraccount.py -- every byte of the object, assigned to a named bucket.

Two levels, and they are kept apart because they have different denominators:

  * LEVEL 1 -- the 100 files on disk. Every file goes into exactly one bucket
    and the buckets sum to the object.
  * LEVEL 2 -- the 28 `.BKF` archives opened, so that their 83,128,008 bytes
    become a directory, an orphan, and 1,969 member records by family.

The archive arithmetic has one wrinkle that has to be said rather than
rounded: `MENU.BKF` names one 6,355-byte blob **twice**, so the sum of the
1,969 record sizes is 6,355 larger than the archive bytes those records
occupy. The tool reports both numbers and the difference, and the closure is
stated on the distinct bytes.

Each bucket carries a verdict, and only three are allowed:

    published   a format with a public specification, used as such
    derived     derived in this repository, from this object, with a tool
                that validates and a selftest that refuses
    not derived the bytes are read but their structure is not

    python tools/accounting.py motoracer-gog _work/members
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bkf import Archive, archives  # noqa: E402

PUBLISHED, DERIVED, OPAQUE = "published", "derived", "not derived"

FILE_BUCKETS = [
    (".wav", "RIFF/WAVE PCM, the ripped compact disc", PUBLISHED),
    (".bkf", "the container -- opened at level 2", DERIVED),
    (".trk", "TRK\\0 track data -- header derived, records not", OPAQUE),
    (".exe", "PE32 / MZP", PUBLISHED),
    (".dll", "PE32", PUBLISHED),
    (".zip", "ZIP + deflate", PUBLISHED),
    (".ico", "Windows icon", PUBLISHED),
    (".txt", "eight-bit text", PUBLISHED),
    (".msg", "Inno Setup message table", OPAQUE),
    (".bpt", "BPT -- not derived", OPAQUE),
    (".ini", "eight-bit text", PUBLISHED),
    (".info", "JSON", PUBLISHED),
    (".lnk", "Windows shell link", PUBLISHED),
    (".dem", "eight-bit text", PUBLISHED),
    (".err", "eight-bit text", PUBLISHED),
    (".dat", "see below", OPAQUE),
]

MEMBER_BUCKETS = {
    ".LEZ": ("LEZ1 -> Truevision TGA, by tools/lez.py", DERIVED),
    ".RAW": ("'mhwanh' RAW image", PUBLISHED),
    ".TMP": ("'mhwanh' RAW image", PUBLISHED),
    ".WAV": ("'rmnr' sound -- not derived", OPAQUE),
    ".MAP": ("01 80 00 00 -- not derived", OPAQUE),
    ".3DF": ("01 00 xx 00 3-D model -- not derived", OPAQUE),
    ".ROT": ("ROT\\0, 112 bytes on 106 of 106", DERIVED),
    ".BPT": ("BPT -- not derived", OPAQUE),
    ".FNT": ("font -- not derived", OPAQUE),
    ".GEN": ("bracketed markup, eight-bit text", DERIVED),
    ".SKL": ("skeleton -- not derived", OPAQUE),
    ".PIV": ("pivots -- not derived", OPAQUE),
    ".SNI": ("SNI\\0 -- not derived", OPAQUE),
    ".DEM": ("eight-bit text", PUBLISHED),
    ".ACT": ("Adobe Color Table, 768 bytes", PUBLISHED),
    ".TGA": ("Truevision TGA, stored", PUBLISHED),
}
for n in range(1, 12):
    MEMBER_BUCKETS[".%d" % n] = ("'mhwanh' RAW image", PUBLISHED)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("members")
    args = ap.parse_args()

    files = []
    for dp, _dn, fns in os.walk(args.root):
        for fn in fns:
            files.append(os.path.join(dp, fn))
    if not files:
        print("REFUSED: no files under %s" % args.root, file=sys.stderr)
        return 3
    total = sum(os.path.getsize(p) for p in files)

    by = collections.OrderedDict()
    for ext, label, verdict in FILE_BUCKETS:
        by[ext] = [label, verdict, 0, 0]
    other = ["anything with no bucket", OPAQUE, 0, 0]
    for p in files:
        ext = os.path.splitext(p)[1].lower()
        row = by.get(ext, other)
        row[2] += 1
        row[3] += os.path.getsize(p)

    print("LEVEL 1 -- the %d files on disk" % len(files))
    print("%-6s %5s %12s %9s  %-12s %s"
          % ("ext", "files", "bytes", "pct", "verdict", "what"))
    acc = 0
    for ext, (label, verdict, n, b) in by.items():
        if not n:
            continue
        acc += b
        print("%-6s %5d %12d %8.4f%%  %-12s %s"
              % (ext, n, b, 100.0 * b / total, verdict, label))
    if other[2]:
        acc += other[3]
        print("%-6s %5d %12d %8.4f%%  %-12s %s"
              % ("(other)", other[2], other[3], 100.0 * other[3] / total,
                 other[1], other[0]))
    print("%-6s %5d %12d %8.4f%%" % ("total", len(files), acc,
                                     100.0 * acc / total))
    print("residue against the object : %d" % (total - acc))

    print()
    print("LEVEL 2 -- the 28 archives opened")
    arcs = archives(args.root)
    dirbytes = gap = recsum = arcbytes = 0
    fam = collections.OrderedDict()
    seen = collections.defaultdict(set)
    for p in arcs:
        a = Archive(p)
        a.check()
        arcbytes += a.length
        dirbytes += a.dirbytes
        gap += a.gap
        for m in a.members:
            recsum += m.size
            ext = m.ext.decode("latin-1").upper()
            label, verdict = MEMBER_BUCKETS.get(ext, ("unclassified", OPAQUE))
            row = fam.setdefault(ext, [label, verdict, 0, 0, 0])
            row[2] += 1
            row[3] += m.size
            key = (a.name, m.offset, m.size)
            if key not in seen[ext]:
                seen[ext].add(key)
                row[4] += m.size
    distinct = sum(r[4] for r in fam.values())
    print("archive bytes                        : %d" % arcbytes)
    print("  directories, 4 + count x 44        : %d" % dirbytes)
    print("  the orphan inside MENU.BKF         : %d" % gap)
    print("  member payload, distinct blobs     : %d" % distinct)
    print("  sum                                : %d  (residue %d)"
          % (dirbytes + gap + distinct, arcbytes - dirbytes - gap - distinct))
    print("  sum over the 1,969 RECORDS         : %d" % recsum)
    print("  records minus distinct blobs       : %d  (MENU.BKF names one "
          "blob twice)" % (recsum - distinct))
    print()
    print("%-8s %6s %12s %9s  %-12s %s"
          % ("member", "count", "bytes", "pct", "verdict", "what"))
    for ext, (label, verdict, n, b, dist) in sorted(
            fam.items(), key=lambda kv: -kv[1][3]):
        print("%-8s %6d %12d %8.4f%%  %-12s %s"
              % (ext, n, b, 100.0 * b / total, verdict, label))
    print("%-8s %6d %12d" % ("total", sum(r[2] for r in fam.values()), recsum))

    print()
    print("COVERAGE -- the object with the archives opened")
    cov = collections.Counter()
    for ext, (label, verdict, n, b) in by.items():
        if ext == ".bkf" or not n:
            continue
        cov[verdict] += b
    for ext, (label, verdict, n, b, dist) in fam.items():
        cov[verdict] += dist
    cov[DERIVED] += dirbytes
    cov[OPAQUE] += gap
    grand = sum(cov.values())
    for k in (PUBLISHED, DERIVED, OPAQUE):
        print("   %-12s %12d  %8.4f%%" % (k, cov[k], 100.0 * cov[k] / total))
    print("   %-12s %12d  %8.4f%%  residue %d"
          % ("total", grand, 100.0 * grand / total, total - grand))
    print()
    print("   read : %d bytes, %.4f%% of %d"
          % (cov[PUBLISHED] + cov[DERIVED],
             100.0 * (cov[PUBLISHED] + cov[DERIVED]) / total, total))
    return 0 if total == acc == grand else 1


if __name__ == "__main__":
    sys.exit(main())
