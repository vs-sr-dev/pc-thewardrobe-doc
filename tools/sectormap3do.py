#!/usr/bin/env python3
"""sectormap3do.py -- every sector of the track, attributed to exactly one owner.

The question this answers is the one the CD-i and Amiga CD checklists both put
first and this platform's checklist puts fifth: *what is in the sectors that
belong to no file?* On this disc the honest answer turned out to be "almost
nothing, once the directory walker was fixed", and the only way to say that
with a straight face is to attribute every sector and make the total close.

Each of the track's sectors is given exactly one owner, in this order of
precedence, and double ownership is reported rather than silently resolved:

    label       block 0 and its second copy, the volume label record
    dir         a directory block, any copy
    file        a block inside a file, first copy
    copy        a block inside the second or later copy of a file
    duck        unowned, and exactly 2048 bytes of repeating 'iamaduck'
    zero        unowned, and all zero
    other       unowned, and none of the above  <- the interesting bucket

`iamaduck` is what the Opera mastering tool writes into space nothing uses. It
is 8 bytes; a 2048-byte sector holds 256 of them, and the phase is aligned to
the start of the sector.

    python tools/sectormap3do.py IMAGE
    python tools/sectormap3do.py IMAGE --runs        list the unowned runs
    python tools/sectormap3do.py IMAGE --dump N      hexdump the head of run N
"""
import argparse
import collections
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__
                else __file__.rsplit("/", 1)[0])
import opera  # noqa: E402

DUCK = (b"iamaduck" * 256)
assert len(DUCK) == 2048
ZERO = b"\0" * 2048


def build(vol):
    n = vol.img.sectors
    owner = [None] * n
    clash = []

    def claim(start, count, tag, who):
        for b in range(start, start + count):
            if b >= n:
                raise SystemExit("%s claims block %d, past the %d sectors of "
                                 "the track" % (who, b, n))
            if owner[b] is not None:
                clash.append((b, owner[b], (tag, who)))
            else:
                owner[b] = (tag, who)

    for e in vol.dirs:
        for i, c in enumerate(e.copies):
            claim(c, e.block_count, "dir" if i == 0 else "dircopy", e.path)
    for i, c in enumerate(vol.label.root_copies):
        claim(c, vol.label.root_blocks, "dir" if i == 0 else "dircopy", "/")
    for e in vol.files:
        for i, c in enumerate(e.copies):
            claim(c, e.block_count, "file" if i == 0 else "copy", e.path)
    return owner, clash


def classify(vol, owner):
    n = len(owner)
    tally = collections.Counter()
    unowned = []
    for b in range(n):
        if owner[b] is not None:
            tally[owner[b][0]] += 1
            continue
        d = vol.img.block(b)
        if d == DUCK:
            tally["duck"] += 1
        elif d == ZERO:
            tally["zero"] += 1
        else:
            tally["other"] += 1
            unowned.append(b)
    return tally, unowned


def runs_of(blocks):
    out = []
    for b in blocks:
        if out and out[-1][0] + out[-1][1] == b:
            out[-1][1] += 1
        else:
            out.append([b, 1])
    return [tuple(r) for r in out]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--raw", type=int, default=2352)
    ap.add_argument("--off", type=int, default=16)
    ap.add_argument("--runs", action="store_true")
    ap.add_argument("--dump", type=int)
    a = ap.parse_args()

    vol = opera.Volume(a.image, raw=a.raw, off=a.off)
    owner, clash = build(vol)
    tally, unowned = classify(vol, owner)
    n = vol.img.sectors

    print("physical sectors in the track      : %d" % n)
    print("blocks the volume label declares   : %d" % vol.label.block_count)
    print("sectors past the declared volume   : %d"
          % (n - vol.label.block_count))
    print()
    print("files      : %d" % len(vol.files))
    print("directories: %d" % len(vol.dirs))
    print("bytes in files: %d" % sum(e.byte_count for e in vol.files))
    print()
    order = ["file", "copy", "dir", "dircopy", "duck", "zero", "other"]
    tot = 0
    for k in order:
        v = tally.get(k, 0)
        tot += v
        print("  %-8s %8d  %8.4f %%" % (k, v, 100.0 * v / n))
    print("  %-8s %8d  %8.4f %%" % ("TOTAL", tot, 100.0 * tot / n))
    if tot != n:
        raise SystemExit("accounting does not close: %d != %d" % (tot, n))
    print("\ndouble-claimed blocks: %d" % len(clash))
    for b, x, y in clash[:20]:
        print("  block %d claimed by %s and by %s" % (b, x, y))

    attributed = sum(tally.get(k, 0) for k in ("file", "copy", "dir", "dircopy"))
    print("\nattributed to the file system : %d = %.4f %%"
          % (attributed, 100.0 * attributed / n))
    print("owned by nothing              : %d = %.4f %%"
          % (n - attributed, 100.0 * (n - attributed) / n))

    rr = runs_of(unowned)
    print("\n'other' sectors: %d in %d runs" % (len(unowned), len(rr)))
    if a.runs:
        for i, (s, ln) in enumerate(sorted(rr, key=lambda r: -r[1])):
            print("  run %3d  start %7d  length %7d  = %11d bytes"
                  % (i, s, ln, ln * 2048))
    if a.dump is not None:
        rr2 = sorted(rr, key=lambda r: -r[1])
        s, ln = rr2[a.dump]
        d = vol.img.block(s)
        print("\nrun %d, sector %d, first 128 bytes:" % (a.dump, s))
        for o in range(0, 128, 16):
            row = d[o:o + 16]
            print("   %05X  %s  %s" % (o, " ".join("%02x" % c for c in row),
                                       "".join(chr(c) if 32 <= c < 127 else "."
                                               for c in row)))


if __name__ == "__main__":
    main()
