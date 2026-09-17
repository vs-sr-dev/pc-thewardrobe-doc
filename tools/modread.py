#!/usr/bin/env python3
"""modread.py -- validate a ProTracker module and split its bytes into
sequence and sample.

A tracker module is half a score and half a recording, and the thesis this
collection keeps ("what fraction of an object is recorded rather than
computed") cannot treat it as one or the other. So this tool counts both, from
the format rather than from a rule of thumb:

    header      20 bytes of title
    31 x 30     instrument records: 22 bytes of name, then
                length/2, finetune, volume, repeat point/2, repeat length/2
    1           number of positions in the order table
    1           restart byte
    128         order table
    4           'M.K.' for a four-channel module
    -----
    1084        so the pattern data begins at 1084

    patterns    (max(order) + 1) x 64 rows x channels x 4 bytes
    samples     the rest: sum of 2 x instrument length

The identity that must hold, and that this tool asserts:

    1084 + patterns + samples == file size

A module that satisfies it is understood; one that misses by a few bytes is a
module with something appended, and the tool says by how much rather than
rounding.

    python tools/modread.py TREE
    python tools/modread.py FILE.MOD --instruments
"""
import argparse
import os
import re
import struct

SIGS = {b"M.K.": 4, b"M!K!": 4, b"4CHN": 4, b"6CHN": 6, b"8CHN": 8,
        b"FLT4": 4, b"FLT8": 8}

# A tracker module's 31 instrument slots are where musicians sign their work,
# and a zero-length slot is a line of free text. On this disc seven of the nine
# modules carry a conversion credit in them, and five of those end with a
# telephone number. The name of a person who signed a product they worked on is
# published here; their telephone number is not. This tool redacts anything
# that is shaped like contact data, so that `notes/modules.txt` can be
# committed without a separate redaction pass.
TEL = re.compile(r"(?:\+\d{1,3}[ .-])?\(?\d{3}\)?[ .-]\d{3,4}[ .-]\d{4}")
MAIL = re.compile(r"[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\.[A-Za-z]{2,}")


def redact(name):
    s = name.decode("latin-1")
    if MAIL.search(s):
        return "[an address, withheld]"
    if TEL.search(s):
        return "[a telephone number, withheld]"
    return s


def read(path):
    d = open(path, "rb").read()
    if len(d) < 1084:
        return None
    sig = d[1080:1084]
    if sig not in SIGS:
        return None
    ch = SIGS[sig]
    title = d[0:20].split(b"\0")[0]
    ins = []
    o = 20
    for i in range(31):
        name = d[o:o + 22].split(b"\0")[0]
        ln, ft, vol, rp, rl = struct.unpack_from(">HBBHH", d, o + 22)
        ins.append({"name": name, "bytes": ln * 2, "finetune": ft,
                    "volume": vol, "repeat": rp * 2, "replen": rl * 2})
        o += 30
    npos = d[950]
    restart = d[951]
    order = list(d[952:1080])
    npat = max(order[:max(npos, 1)]) + 1 if npos else max(order) + 1
    patbytes = npat * 64 * ch * 4
    sampbytes = sum(i["bytes"] for i in ins)
    return {"path": path, "size": len(d), "sig": sig, "channels": ch,
            "title": title, "positions": npos, "restart": restart,
            "patterns": npat, "patbytes": patbytes, "sampbytes": sampbytes,
            "instruments": ins,
            "total": 1084 + patbytes + sampbytes}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--instruments", action="store_true")
    a = ap.parse_args()

    paths = []
    if os.path.isdir(a.root):
        for r, _d, ns in os.walk(a.root):
            for n in sorted(ns):
                paths.append(os.path.join(r, n))
    else:
        paths = [a.root]

    rows = []
    for p in paths:
        i = read(p)
        if i:
            rows.append(i)

    print("%-34s %8s %4s %4s %4s %9s %9s %9s %s"
          % ("file", "size", "sig", "chan", "pat", "patbytes", "samples",
             "1084+p+s", "title"))
    tot = tsamp = tpat = 0
    off = []
    for i in rows:
        rel = i["path"].replace(os.sep, "/")
        rel = rel[rel.find("/files/") + 6:] if "/files/" in rel else rel
        print("%-34s %8d %4s %4d %4d %9d %9d %9d %s"
              % (rel, i["size"], i["sig"].decode(), i["channels"],
                 i["patterns"], i["patbytes"], i["sampbytes"], i["total"],
                 i["title"].decode("latin-1")))
        tot += i["size"]
        tsamp += i["sampbytes"]
        tpat += i["patbytes"]
        if i["total"] != i["size"]:
            off.append((rel, i["size"] - i["total"]))
        if a.instruments:
            for k, ins in enumerate(i["instruments"]):
                if ins["bytes"] or ins["name"].strip():
                    print("      %2d %-24s %7d bytes vol %3d ft %d"
                          % (k + 1, redact(ins["name"]),
                             ins["bytes"], ins["volume"], ins["finetune"]))

    print("\n%d modules, %d bytes" % (len(rows), tot))
    print("  header    : %d bytes (%d x 1084)" % (1084 * len(rows), len(rows)))
    print("  patterns  : %d bytes = %.4f %%" % (tpat, 100.0 * tpat / tot))
    print("  samples   : %d bytes = %.4f %%" % (tsamp, 100.0 * tsamp / tot))
    print("  accounted : %d of %d" % (1084 * len(rows) + tpat + tsamp, tot))
    print("modules whose arithmetic does not close: %d" % len(off))
    for rel, d in off:
        print("  %s: file is %+d bytes against 1084 + patterns + samples"
              % (rel, d))


if __name__ == "__main__":
    main()
