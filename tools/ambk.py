#!/usr/bin/env python3
"""ambk.py -- the 376 resources that begin "AmBk", and where they come from.

`AmBk` is the header of an AMOS memory bank. AMOS is a BASIC dialect for the
Commodore Amiga, and a bank is how an AMOS program stores anything that is not
program text: sprites, samples, arrays, whatever the author wanted to keep. The
header, which the AMOS documentation describes and which is checked here against
the bytes rather than taken on faith:

    0..3    "AmBk"
    4..5    bank number, 16-bit big-endian
    6..7    bank type / flags, 16-bit big-endian
    8..11   length, 32-bit big-endian, with bit 31 set
    12..19  eight characters of name, space padded

The length counts from byte 12, name included, so a bank closes when
12 + (length & 0x7FFFFFFF) equals the size of the resource. Every one of the 376
does, which is why this is a derivation and not a resemblance.

Big-endian is the finding. A 1995 MS-DOS CD, read by a table of big-endian
offsets, holding containers whose lengths are big-endian, written by a BASIC
for a 68000. The DOS release is not a port that forgot to convert: the whole
toolchain spoke Motorola and the DOS side simply read what it was given.

    python tools/ambk.py census _game/scummvm/scummvm.exe _game/queen.1
    python tools/ambk.py show   _game/scummvm/scummvm.exe _game/queen.1 --name QUEEN.JAS
    python tools/ambk.py text   _game/scummvm/scummvm.exe _game/queen.1 --ext .DOG
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

MAGIC = b"AmBk"


def parse(b):
    if b[:4] != MAGIC:
        return None
    num, typ = struct.unpack_from(">HH", b, 4)
    raw = struct.unpack_from(">I", b, 8)[0]
    length = raw & 0x7FFFFFFF
    name = b[12:20].decode("latin1")
    return dict(num=num, typ=typ, raw=raw, length=length, name=name,
                closes=(12 + length == len(b)), residue=len(b) - 12 - length)


def cmd_census(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    rows = []
    for name, bundle, off, size in recs:
        b = data[off:off + size]
        d = parse(b)
        if d:
            d["file"] = name
            d["size"] = size
            rows.append(d)
    print("resources beginning AmBk: %d of %d" % (len(rows), len(recs)))
    print("bytes               %d (%.4f %% of the bundle)"
          % (sum(r["size"] for r in rows),
             100.0 * sum(r["size"] for r in rows) / len(data)))
    print("close exactly       %d" % sum(1 for r in rows if r["closes"]))
    for r in rows:
        if not r["closes"]:
            print("   %-14s residue %d" % (r["file"], r["residue"]))
    print()
    print("bit 31 of the length set in %d of %d"
          % (sum(1 for r in rows if r["raw"] & 0x80000000), len(rows)))
    print()
    print("%-10s %s" % ("bank number", dict(Counter(r["num"] for r in rows)
                                            .most_common())))
    print("%-10s %s" % ("bank type", dict(Counter(r["typ"] for r in rows)
                                          .most_common())))
    print("%-10s %s" % ("bank name", dict(Counter(r["name"] for r in rows)
                                          .most_common())))
    print()
    print("%-8s %6s %12s %10s %10s"
          % ("ext", "files", "bytes", "min", "max"))
    by = {}
    for r in rows:
        by.setdefault(os.path.splitext(r["file"])[1].upper(), []).append(r)
    for e in sorted(by):
        g = by[e]
        print("%-8s %6d %12d %10d %10d"
              % (e, len(g), sum(x["size"] for x in g),
                 min(x["size"] for x in g), max(x["size"] for x in g)))
    print()
    print("the little-endian reading of the same length field, for comparison:")
    for r in rows[:3]:
        le = struct.unpack_from("<I", data[0:0], 0) if False else \
            int.from_bytes(bytes(reversed(struct.pack(">I", r["raw"]))), "big")
        print("   %-14s big-endian %10d (closes), little-endian %13d (does not)"
              % (r["file"], r["length"], le))
    return 0


def cmd_show(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    r = d[a.name.upper()]
    b = data[r[2]:r[2] + r[3]]
    p = parse(b)
    print("resource            %s, %d bytes" % (r[0], r[3]))
    for k in ("num", "typ", "name", "length", "closes", "residue"):
        print("%-19s %s" % (k, p[k]))
    print("length field raw    0x%08X" % p["raw"])
    print("arithmetic          12 + %d = %d, size %d" % (p["length"],
                                                         12 + p["length"], r[3]))
    print()
    body = b[20:]
    print("first 64 bytes after the name:")
    for i in range(0, min(64, len(body)), 16):
        print("  %04X %s  %s" % (i, body[i:i + 16].hex(" "),
                                 "".join(chr(c) if 32 <= c < 127 else "."
                                         for c in body[i:i + 16])))
    txt = re.findall(rb"[\x20-\x7e]{6,}", body)
    print()
    print("printable runs >= 6 %d, %d bytes = %.2f %% of the body"
          % (len(txt), sum(len(t) for t in txt),
             100.0 * sum(len(t) for t in txt) / max(len(body), 1)))
    for t in txt[:a.top]:
        print("   %s" % t.decode("latin1"))
    return 0


def cmd_text(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    rows = [r for r in recs
            if (not a.ext or r[0].upper().endswith(a.ext.upper()))]
    words = re.compile(rb"[A-Za-z][A-Za-z' ,.!?-]{5,}")
    tot = 0
    hits = 0
    body_bytes = 0
    for name, bundle, off, size in rows:
        b = data[off:off + size]
        if b[:4] != MAGIC:
            continue
        body = b[20:]
        body_bytes += len(body)
        ws = words.findall(body)
        tot += sum(len(w) for w in ws)
        hits += len(ws)
    print("resources           %d" % len(rows))
    print("body bytes          %d" % body_bytes)
    print("word-like runs      %d, %d bytes = %.4f %% of the bodies"
          % (hits, tot, 100.0 * tot / max(body_bytes, 1)))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("census", cmd_census), ("show", cmd_show),
                     ("text", cmd_text)):
        p = sub.add_parser(name)
        p.add_argument("exe")
        p.add_argument("bundle")
        p.add_argument("--top", type=int, default=12)
        if name == "show":
            p.add_argument("--name", required=True)
        if name == "text":
            p.add_argument("--ext", default=None)
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
