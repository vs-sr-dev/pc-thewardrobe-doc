"""manifest.py -- build the one table every other measurement in this
repository is allowed to quote from.

Every chapter that prints a count of files, a sum of bytes or a percentage has
to be able to name the row set it counted. This tool emits that row set once,
as tab-separated text, from the image's primary namespace via iso9660.py's
--sha1 output, and prints the summary arithmetic with the denominators spelled
out.

Columns: sha1, size, extent, mtime_local, tz, path

Usage:
    python tools/manifest.py notes/sha1-iso.txt IMAGE_BYTES > notes/manifest.tsv
    python tools/manifest.py notes/sha1-iso.txt 141996032 --summary
"""

import collections
import re
import sys

LINE = re.compile(
    r"^(/\S+);1\s+(\d+)\s+(\d+)\s+(\S+\s+\S+)\s+(GMT[+-]\d\d:\d\d)\s+([0-9a-f]{40})\s*$"
)


def parse(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE.match(line)
            if m:
                rows.append({
                    "path": m.group(1),
                    "size": int(m.group(2)),
                    "extent": int(m.group(3)),
                    "mtime": m.group(4),
                    "tz": m.group(5),
                    "sha1": m.group(6),
                })
    return rows


def summary(rows, image_bytes):
    total = sum(r["size"] for r in rows)
    print("files                      : %d" % len(rows))
    print("bytes in files             : %d" % total)
    print("image bytes                : %d" % image_bytes)
    print("files / image              : %.4f %%" % (total * 100.0 / image_bytes))
    print("bytes outside any file     : %d  (%.4f %%)"
          % (image_bytes - total, (image_bytes - total) * 100.0 / image_bytes))
    print("distinct sha1              : %d" % len({r["sha1"] for r in rows}))
    print("zero-length files          : %d" % sum(1 for r in rows if r["size"] == 0))
    print("distinct mtimes            : %d" % len({r["mtime"] for r in rows}))
    print("distinct tz offsets        : %s"
          % sorted(collections.Counter(r["tz"] for r in rows).items()))
    print()
    dup = collections.Counter(r["sha1"] for r in rows)
    print("sha1 values used more than once:")
    for h, n in dup.most_common():
        if n > 1:
            names = sorted(r["path"] for r in rows if r["sha1"] == h)
            print("  %s x%d  %d bytes  %s" % (h, n, next(r["size"] for r in rows if r["sha1"] == h),
                                              " ".join(names)))
    print()
    ext = collections.defaultdict(lambda: [0, 0])
    for r in rows:
        e = r["path"].rsplit(".", 1)[-1].upper() if "." in r["path"].rsplit("/", 1)[-1] else "(none)"
        ext[e][0] += 1
        ext[e][1] += r["size"]
    print("by extension (count, bytes, %% of image):")
    for e, (n, b) in sorted(ext.items(), key=lambda kv: -kv[1][1]):
        print("  %-8s %4d %14d  %8.4f %%" % (e, n, b, b * 100.0 / image_bytes))
    print()
    months = collections.Counter(r["mtime"][:7] for r in rows)
    print("mtime histogram by month:")
    for m in sorted(months):
        print("  %s  %3d" % (m, months[m]))
    old = min(rows, key=lambda r: r["mtime"])
    new = max(rows, key=lambda r: r["mtime"])
    print("oldest : %s  %s" % (old["mtime"], old["path"]))
    print("newest : %s  %s" % (new["mtime"], new["path"]))


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    rows = parse(argv[1])
    if not rows:
        print("FATAL: parsed zero rows from %s" % argv[1])
        return 3
    image_bytes = int(argv[2])
    if "--summary" in argv:
        summary(rows, image_bytes)
        return 0
    print("sha1\tsize\textent\tmtime\ttz\tpath")
    for r in sorted(rows, key=lambda r: r["path"]):
        print("%s\t%d\t%d\t%s\t%s\t%s"
              % (r["sha1"], r["size"], r["extent"], r["mtime"], r["tz"], r["path"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
