#!/usr/bin/env python3
"""qmus.py -- the music, which is half a megabyte and not a recording.

Five resources: `AQBANK.MUS`, `AQB2.MUS`, `AQ.RL`, `AQ8.RL`, `AQBANK.RL`. Names
that say *bank*, and a shape that turns out to be an index followed by its data:

    0..1     entry count, 16-bit little-endian
    2..      count entries of 32-bit little-endian
    then     two bytes, then the data the entries point at

The top four bits of an entry are flags, not address: masked off with
0x0FFFFFFF every entry lands inside the resource and the sequence is monotone.
What the entries point at is the finding -- `4D 54 68 64` is `MThd`, the header
of a Standard MIDI File, and the first one in `AQBANK.RL` carries a text meta
event reading *Copyright (C) 1990 by Voyetra Technologies*.

That settles the question the thesis needed settled. The music of this game is
not recorded: it is a score plus an instrument bank, and it contributes exactly
zero bytes to the recorded-reality column while costing 0.57 % of the disc.

    python tools/qmus.py index _game/scummvm/scummvm.exe _game/queen.1
    python tools/qmus.py midi  _game/scummvm/scummvm.exe _game/queen.1
"""

import argparse
import os
import re
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qres  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

NAMES = ("AQBANK.MUS", "AQB2.MUS", "AQ.RL", "AQ8.RL", "AQBANK.RL")
MASK = 0x0FFFFFFF


def index_of(b):
    cnt = struct.unpack_from("<H", b, 0)[0]
    raw = [struct.unpack_from("<I", b, 2 + 4 * i)[0] for i in range(cnt)]
    offs = [v & MASK for v in raw]
    flags = [v >> 28 for v in raw]
    return cnt, raw, offs, flags


def cmd_index(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    tot = 0
    for nm in NAMES:
        r = d[nm]
        b = data[r[2]:r[2] + r[3]]
        cnt, raw, offs, flags = index_of(b)
        tot += r[3]
        inside = sum(1 for o in offs if 0 < o <= len(b))
        mono = all(offs[i] <= offs[i + 1] for i in range(cnt - 1))
        print("%-11s %8d bytes  entries %4d  first %6d  gap %d"
              % (nm, r[3], cnt, offs[0], offs[0] - (2 + 4 * cnt)))
        print("            inside the resource %d/%d, monotone %s, "
              "flag nibbles %s"
              % (inside, cnt, mono, dict(Counter(flags).most_common())))
        heads = Counter(bytes(b[o:o + 4]) for o in offs if o + 4 <= len(b))
        print("            entry heads %s"
              % {k.hex(): v for k, v in heads.most_common(4)})
    print()
    print("five resources, %d bytes = %.4f %% of the bundle"
          % (tot, 100.0 * tot / len(data)))
    return 0


def cmd_midi(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    grand = 0
    gbytes = 0
    for nm in NAMES:
        r = d[nm]
        b = data[r[2]:r[2] + r[3]]
        pos = [m.start() for m in re.finditer(b"MThd", b)]
        trk = len(re.findall(b"MTrk", b))
        print("%-11s MThd %3d, MTrk %3d" % (nm, len(pos), trk))
        grand += len(pos)
        gbytes += r[3]
        for p in pos[:a.top]:
            ln, fmt, ntrk, div = struct.unpack_from(">IHHH", b, p + 4)
            print("    at %-8d header %d bytes, format %d, %d tracks, "
                  "division %d" % (p, ln, fmt, ntrk, div))
    print()
    print("Standard MIDI files found: %d, inside %d bytes" % (grand, gbytes))
    txt = set()
    for nm in NAMES:
        r = d[nm]
        b = data[r[2]:r[2] + r[3]]
        for m in re.finditer(rb"\xff\x02(.)", b):
            ln = m.group(1)[0]
            s = b[m.end():m.end() + ln]
            if len(s) == ln and all(32 <= c < 127 for c in s):
                txt.add(s.decode("ascii"))
        for m in re.finditer(rb"\xff\x03(.)", b):
            ln = m.group(1)[0]
            s = b[m.end():m.end() + ln]
            if len(s) == ln and all(32 <= c < 127 for c in s):
                txt.add(s.decode("ascii"))
    print("copyright and track-name meta events, distinct: %d" % len(txt))
    for s in sorted(txt):
        print("   %s" % s)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("index", cmd_index), ("midi", cmd_midi)):
        p = sub.add_parser(name)
        p.add_argument("exe")
        p.add_argument("bundle")
        p.add_argument("--top", type=int, default=3)
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
