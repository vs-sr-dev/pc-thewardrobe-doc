#!/usr/bin/env python3
"""qbank.py -- the frame banks: .BBK, .ACT, .SAM, and what they are not.

The briefing filed `.ACT` under the pictures and `.SAM` under "looks like audio
too". Both guesses came from the first six bytes, and the first six bytes of a
frame bank look a lot like the first six bytes of a sound. They are not the
same thing, and the way to tell is not to squint at them but to parse the whole
file and see whether it closes on the last byte.

The structure derived here, entirely from the bytes:

    0..1        frame count, 16-bit little-endian
    then, for each frame:
        +0..1   width          16-bit LE
        +2..3   height         16-bit LE
        +4..5   x offset       16-bit LE, signed
        +6..7   y offset       16-bit LE, signed
        +8..    width x height bytes, one palette index per pixel, 0 = clear

No compression anywhere, which is why nothing in this bundle has entropy above
7.5. A bank closes when 2 + sum over frames of (8 + w*h) equals the resource
size exactly; `check` reports the residue rather than hiding it, because a
residue of zero over a hundred files is the only thing that makes this a
derivation instead of a story.

    python tools/qbank.py check _game/scummvm/scummvm.exe _game/queen.1
    python tools/qbank.py show  _game/scummvm/scummvm.exe _game/queen.1 --name AMAZON.ACT
    python tools/qbank.py png   _game/scummvm/scummvm.exe _game/queen.1 --name JOEB.BBK --out _work/png
"""

import argparse
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qres  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BANK_EXT = (".BBK", ".ACT", ".SAM")


def parse(b):
    """Return (frames, residue, error). frames = [(w, h, x, y, data_offset)]."""
    if len(b) < 2:
        return [], len(b), "too short"
    n = struct.unpack_from("<H", b, 0)[0]
    p = 2
    frames = []
    for _ in range(n):
        if p + 8 > len(b):
            return frames, len(b) - p, "ran off the end in a frame header"
        w, h, x, y = struct.unpack_from("<HHhh", b, p)
        p += 8
        if p + w * h > len(b):
            return frames, len(b) - p, "frame %dx%d does not fit" % (w, h)
        frames.append((w, h, x, y, p))
        p += w * h
    return frames, len(b) - p, None


def cmd_check(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    rows = []
    for name, bundle, off, size in recs:
        ext = os.path.splitext(name)[1].upper()
        if ext not in BANK_EXT and not a.all:
            continue
        b = data[off:off + size]
        frames, residue, err = parse(b)
        rows.append((name, ext, size, len(frames), residue, err))
    print("banks parsed        %d" % len(rows))
    print()
    print("%-8s %6s %14s %8s %10s %10s"
          % ("ext", "files", "bytes", "frames", "closed", "residue!=0"))
    by = defaultdict(list)
    for r in rows:
        by[r[1]].append(r)
    for ext in sorted(by):
        g = by[ext]
        closed = sum(1 for r in g if r[4] == 0 and r[5] is None)
        print("%-8s %6d %14d %8d %10d %10d"
              % (ext, len(g), sum(r[2] for r in g), sum(r[3] for r in g),
                 closed, len(g) - closed))
    print()
    bad = [r for r in rows if r[4] != 0 or r[5] is not None]
    print("files that do not close: %d" % len(bad))
    for name, ext, size, nf, residue, err in bad[:a.top]:
        print("  %-14s %8d bytes, %4d frames, residue %d  %s"
              % (name, size, nf, residue, err or ""))
    if bad and len(bad) > a.top:
        print("  ... and %d more" % (len(bad) - a.top))
    good = [r for r in rows if r[4] == 0 and r[5] is None]
    print()
    print("of the ones that close:")
    print("  frames             %d" % sum(r[3] for r in good))
    print("  pixels             %d" % 0)
    return 0


def cmd_show(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    r = d[a.name.upper()]
    b = data[r[2]:r[2] + r[3]]
    frames, residue, err = parse(b)
    print("%s  %d bytes" % (r[0], r[3]))
    print("declared frames     %d" % struct.unpack_from("<H", b, 0)[0])
    print("parsed frames       %d" % len(frames))
    print("residue             %d   %s" % (residue, err or "closes exactly"))
    print()
    print("%-5s %6s %6s %6s %6s %10s %10s"
          % ("#", "w", "h", "x", "y", "pixels", "at"))
    tot = 0
    for i, (w, h, x, y, at) in enumerate(frames):
        tot += w * h
        if i < a.top:
            print("%-5d %6d %6d %6d %6d %10d %10d" % (i, w, h, x, y, w * h, at))
    if len(frames) > a.top:
        print("... %d more" % (len(frames) - a.top))
    print()
    print("pixels total        %d" % tot)
    print("arithmetic          2 + %d headers x 8 + %d pixels = %d, size %d"
          % (len(frames), tot, 2 + len(frames) * 8 + tot, r[3]))
    used = Counter()
    for w, h, x, y, at in frames:
        used.update(b[at:at + w * h])
    print("palette indices     %d distinct, index 0 is %.2f %% of all pixels"
          % (len(used), 100.0 * used.get(0, 0) / max(tot, 1)))
    return 0


def cmd_png(a):
    from PIL import Image
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    r = d[a.name.upper()]
    b = data[r[2]:r[2] + r[3]]
    frames, residue, err = parse(b)
    os.makedirs(a.out, exist_ok=True)
    k = 0
    for i, (w, h, x, y, at) in enumerate(frames):
        if w == 0 or h == 0:
            continue
        im = Image.frombytes("L", (w, h), b[at:at + w * h])
        im.save(os.path.join(a.out, "%s.%03d.png" % (r[0], i)))
        k += 1
    print("wrote %d frames from %s (residue %d)" % (k, r[0], residue))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("check", cmd_check), ("show", cmd_show), ("png", cmd_png)):
        p = sub.add_parser(name)
        p.add_argument("exe")
        p.add_argument("bundle")
        p.add_argument("--top", type=int, default=20)
        if name == "check":
            p.add_argument("--all", action="store_true")
        else:
            p.add_argument("--name", required=True)
        if name == "png":
            p.add_argument("--out", required=True)
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
