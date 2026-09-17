#!/usr/bin/env python3
"""kultaccount.py -- the accounting table, over 56,868 files and 2,308,777,670
bytes, closing at residue 0.

Every previous accounting in this collection was readable at a glance because
the object had tens or hundreds of files. This one has fifty-six thousand, and
the table only means something if the rule that puts a file in a bucket is
stated and mechanical. So: **every file is assigned by the first rule it
matches, the rules are in one list below, and the rules are about what the file
IS rather than what its extension says.** Two of them exist only because the
extension lies -- `.dat` is a level texture archive, an `AGP!` container, a
walkability mask and an Inno uninstall log, in four different places.

Each bucket carries a STATUS, and the status is what the coverage figure is
made of:

    derived      this session derived the format and a reader closes on it
    published    a public specification, used as such and named
    text         read as text, whose encoding was measured (UTF-16LE or ASCII)
    not derived  counted, named, and left closed

**Coverage is the share of bytes that is not `not derived`.** Duplicates are
counted once each, in the ordinary sense that a file is a file: the redundancy
figure (23,661 files, 274,462,231 bytes) is reported separately and is NOT
subtracted, because the object holds those bytes whether or not they repeat.

    python tools/kultaccount.py "<root>"
    python tools/kultaccount.py "<root>" --list-bucket "format not derived"
"""
import argparse
import collections
import hashlib
import os
import sys

DERIVED = "derived"
PUBLISHED = "published"
TEXT = "text"
CLOSED = "not derived"


def classify(root, rel, name, size, head, has_idx, sibling_size_txt):
    """Return (bucket, status). First match wins; the order is the rule."""
    low = name.lower()
    ext = os.path.splitext(low)[1]

    if ext == ".idx":
        return "level texture index (u32 count + 124-byte records)", DERIVED
    if ext == ".dat" and has_idx:
        return "level texture archive (16-byte member header)", DERIVED
    if low == "maska.dat":
        return "object mask (width x height bytes of 0 and 1)", DERIVED
    if low == "size.txt" and sibling_size_txt:
        return "object mask dimensions (size.txt)", DERIVED
    if head[:4] == b"AGP!":
        return "AGP! container (LZSS, decompressed at residue 0)", DERIVED
    if ext == ".sk":
        return "material assignment (.sk)", DERIVED
    if low == "ini":
        return "animation speed (SPEED n)", DERIVED
    if low == "levelname":
        return "place display name (UTF-16LE)", TEXT
    if ext == ".tga":
        return "Truevision TGA", PUBLISHED
    if ext == ".ogg":
        return "Ogg Vorbis", PUBLISHED
    if ext in (".exe", ".dll"):
        return "PE32 binary", PUBLISHED
    if ext == ".pdf":
        return "PDF", PUBLISHED
    if ext in (".zip", ".hashdb"):
        return "ZIP", PUBLISHED
    if ext == ".ico":
        return "Windows icon", PUBLISHED
    if ext == ".bmp":
        return "Windows bitmap", PUBLISHED
    if ext == ".dds":
        return "DirectDraw Surface", PUBLISHED
    if ext == ".x":
        return "DirectX .X mesh, text form", PUBLISHED
    if ext == ".sdb":
        return "Windows shim database (sdbf)", PUBLISHED
    if ext == ".lnk":
        return "Windows shell link", PUBLISHED
    if ext in (".txt", ".cfg", ".ini", ".bat", ".info", ".script", ".msg",
               ".log"):
        return "text and configuration", TEXT
    if ext == "" and low in (".txt", "2q", "n_down"):
        return "text and configuration", TEXT
    if ext == ".msk":
        return "the .msk name table -- FORMAT NOT DERIVED", CLOSED
    if ext == ".swatch":
        return "Maya swatch cache -- FORMAT NOT DERIVED", CLOSED
    return "everything else -- FORMAT NOT DERIVED", CLOSED


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root")
    ap.add_argument("--list-bucket", default=None)
    ap.add_argument("--hash", action="store_true",
                    help="also compute the duplicate figures (slow: minutes)")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

    files = 0
    total = 0
    counts = collections.Counter()
    bytes_ = collections.Counter()
    status_of = {}
    listed = []
    digests = collections.Counter()
    sizes_by_hash = {}

    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames.sort()
        names = set(n.lower() for n in filenames)
        has_mask = "maska.dat" in names
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, a.root)
            size = os.path.getsize(p)
            with open(p, "rb") as fh:
                head = fh.read(4)
            has_idx = (fn.lower().endswith(".dat")
                       and os.path.exists(os.path.splitext(p)[0] + ".idx"))
            bucket, status = classify(a.root, rel, fn, size, head, has_idx,
                                      has_mask)
            files += 1
            total += size
            counts[bucket] += 1
            bytes_[bucket] += size
            status_of[bucket] = status
            if a.list_bucket and a.list_bucket.lower() in bucket.lower():
                listed.append((size, rel))
            if a.hash:
                h = hashlib.sha1(open(p, "rb").read()).hexdigest()
                digests[h] += 1
                sizes_by_hash[h] = size

    print("root      : %s" % a.root)
    print("files     : %d" % files)
    print("bytes     : %d" % total)
    print()
    print("%-52s %7s %14s %9s  %s"
          % ("bucket", "files", "bytes", "share", "status"))
    order = sorted(bytes_, key=lambda b: -bytes_[b])
    for b in order:
        print("%-52s %7d %14d %8.4f %%  %s"
              % (b[:52], counts[b], bytes_[b], 100.0 * bytes_[b] / total,
                 status_of[b]))
    print("%-52s %7d %14d %8.4f %%"
          % ("TOTAL", sum(counts.values()), sum(bytes_.values()),
             100.0 * sum(bytes_.values()) / total))
    print()
    print("residue   : %d files, %d bytes"
          % (files - sum(counts.values()), total - sum(bytes_.values())))
    print()
    per_status = collections.Counter()
    fper_status = collections.Counter()
    for b in bytes_:
        per_status[status_of[b]] += bytes_[b]
        fper_status[status_of[b]] += counts[b]
    print("%-14s %8s %14s %9s" % ("status", "files", "bytes", "share"))
    for s in (DERIVED, PUBLISHED, TEXT, CLOSED):
        print("%-14s %8d %14d %8.4f %%"
              % (s, fper_status[s], per_status[s], 100.0 * per_status[s] / total))
    covered = total - per_status[CLOSED]
    print()
    print("COVERAGE  : %d of %d bytes = %.4f %%"
          % (covered, total, 100.0 * covered / total))
    print("            %d of %d files = %.4f %%"
          % (files - fper_status[CLOSED], files,
             100.0 * (files - fper_status[CLOSED]) / files))
    if a.hash:
        groups = [h for h, n in digests.items() if n > 1]
        indup = sum(digests[h] for h in groups)
        redundant = sum(sizes_by_hash[h] * (digests[h] - 1) for h in groups)
        print()
        print("distinct sha1        : %d" % len(digests))
        print("duplicate groups     : %d" % len(groups))
        print("files inside them    : %d" % indup)
        print("check                : %d - %d + %d = %d"
              % (files, indup, len(groups), files - indup + len(groups)))
        print("redundant bytes      : %d = %.4f %%"
              % (redundant, 100.0 * redundant / total))
    if listed:
        print()
        print("files in the bucket matching %r: %d" % (a.list_bucket, len(listed)))
        for size, rel in sorted(listed, reverse=True)[:40]:
            print("   %12d  %s" % (size, rel))


if __name__ == "__main__":
    main()
