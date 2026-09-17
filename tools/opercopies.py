#!/usr/bin/env python3
"""opercopies.py -- compare, byte for byte, every copy the Opera directory
records claim.

The 3DO platform notes ask for this in section 4 and it is the pass this
format makes cheap that every other optical format in this collection makes
expensive. On CD-i, discovering that two discs of eight pressed whole files
two or three times took four discs and a complete cross-hash. Here the file
system says so in a field, and checking it is one pass over 121 blocks.

Two questions, both answered by reading rather than by inference:

  * do the copies agree? A disagreement between two copies of the same
    directory would be the finding of the day;
  * how much of the disc goes to copies? That is the number the platform
    notes wanted and it is arithmetic once the field is read.

    python tools/opercopies.py IMAGE
    python tools/opercopies.py IMAGE --verbose
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
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    vol = opera.Volume(a.image, raw=a.raw, off=a.off)
    img = vol.img

    groups = []
    groups.append(("/", vol.label.root_copies, vol.label.root_blocks))
    for e in vol.dirs:
        groups.append((e.path, e.copies, e.block_count))
    ndirs = len(groups)
    for e in vol.files:
        if len(e.copies) > 1:
            groups.append((e.path, e.copies, e.block_count))

    disagree = []
    blocks = 0
    extra = 0
    for path, copies, n in groups:
        hs = []
        for c in copies:
            hs.append(hashlib.sha1(img.blocks(c, n)).hexdigest())
        blocks += n * len(copies)
        extra += n * (len(copies) - 1)
        if len(set(hs)) != 1:
            disagree.append((path, copies, hs))
        if a.verbose:
            print("%-34s %d copies at %s  %s"
                  % (path, len(copies), copies,
                     "AGREE" if len(set(hs)) == 1 else "DISAGREE"))

    print("groups compared            : %d (%d directories, %d files)"
          % (len(groups), ndirs, len(groups) - ndirs))
    print("blocks read                : %d" % blocks)
    print("blocks that are second or later copies : %d = %d bytes"
          % (extra, extra * 2048))
    print("  as a share of the track  : %.4f %%"
          % (100.0 * extra / img.sectors))
    print("  as a share of the user data : %.4f %%"
          % (100.0 * extra * 2048 / (img.sectors * 2048)))
    print("groups whose copies disagree : %d" % len(disagree))
    for path, copies, hs in disagree:
        print("\n  %s" % path)
        for c, h in zip(copies, hs):
            print("     block %7d  %s" % (c, h))
        base = img.blocks(copies[0], 1)
        for c in copies[1:]:
            other = img.blocks(c, 1)
            d = [i for i in range(len(base)) if base[i] != other[i]]
            if not d:
                continue
            print("     block %d vs %d: %d bytes differ, offsets %d..%d"
                  % (copies[0], c, len(d), d[0], d[-1]))
            for i in d[:24]:
                print("        +%-5d  %02x %-3s   %02x %-3s"
                      % (i, base[i],
                         chr(base[i]) if 32 <= base[i] < 127 else "",
                         other[i],
                         chr(other[i]) if 32 <= other[i] < 127 else ""))
            if len(d) > 24:
                print("        ... %d more" % (len(d) - 24))


if __name__ == "__main__":
    main()
