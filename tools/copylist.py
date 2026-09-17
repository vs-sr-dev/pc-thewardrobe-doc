#!/usr/bin/env python3
"""copylist.py -- one record per copy the directory records declare.

The platform notes ask every 3DO repository for three hash lists and this is
the second of them: the file-level list cannot say anything about the
redundancy, because the redundancy is in the index rather than in the data.
One record per declared copy, with the block it sits at and the SHA-1 of that
block, is what makes *do the copies agree* a question a reader can check
without the disc.

usage: copylist.py IMAGE [--raw 2352] [--off 16]
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import opera  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--raw", type=int, default=2352)
    ap.add_argument("--off", type=int, default=16)
    a = ap.parse_args()
    vol = opera.Volume(a.image, a.raw, a.off)
    img = vol.img
    rows = []

    def add(path, kind, copies, blocks):
        for i, b in enumerate(copies):
            h = hashlib.sha1(b"".join(img.block(b + k) for k in range(blocks)))
            rows.append((path, kind, i, b, blocks, h.hexdigest()))

    add("/", "dir", vol.label.root_copies, vol.label.root_blocks)

    def visit(path, block, blocks):
        for e in opera.walk_dir(img, block, blocks):
            name = e.name.decode("latin1") if isinstance(e.name, bytes) else e.name
            p = (path.rstrip("/") + "/" + name)
            if e.kind == opera.T_DIRECTORY:
                add(p, "dir", e.copies, e.block_count)
                visit(p, e.copies[0], e.block_count)
            elif len(e.copies) > 1:
                add(p, "file", e.copies, e.block_count)

    visit("/", vol.label.root_copies[0], vol.label.root_blocks)

    groups = {}
    for path, kind, i, b, n, h in rows:
        groups.setdefault(path, []).append(h)
    dis = [p for p, hs in groups.items() if len(set(hs)) > 1]

    print("# one record per copy the directory records declare")
    print("# path, kind, copy index, first block, blocks, sha1 of the copy")
    print("# %d records in %d groups; %d groups disagree with themselves"
          % (len(rows), len(groups), len(dis)))
    for r in sorted(rows):
        print("%-40s %-4s copy %d  block %6d  blocks %2d  %s" % r)
    print()
    print("# groups whose copies are not all identical:")
    for p in sorted(dis):
        print("#   %s" % p)


if __name__ == "__main__":
    main()
