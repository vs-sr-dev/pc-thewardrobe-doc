#!/usr/bin/env python3
"""aiffread.py -- AIFF and AIFF-C, read from the COMM chunk and not from the
extension, with the duration arithmetic printed on every line.

The 3DO platform notes ask for exactly this in section 8: sample rate,
channels, frame count and running time in minutes and seconds, "because
durations are what make an audio finding checkable by someone who does not have
the disc".

The sample rate in AIFF is an **80-bit IEEE 754 extended float**, which is the
one field people skip and get wrong. It is decoded here from its bytes:

    sign(1) exponent(15) integer-bit(1) fraction(63)
    value = (-1)^s * 2^(e-16383) * (m / 2^63)

AIFF-C adds a four-character compression id to COMM. The 3DO's is **SDX2**, a
square-difference codec at a fixed 2:1. For a compressed file the frame count
in COMM still counts *sample frames*, so the running time is unaffected by the
coding and the byte count is what changes; both are printed.

The chunk walk is validated by chaining: FORM's declared length plus 8 must
equal the file size, and the chunks inside must tile the FORM payload exactly.
A file that nearly chains is reported, not rounded off.

    python tools/aiffread.py TREE
    python tools/aiffread.py FILE.aifc --dump
"""
import argparse
import os
import struct
import sys


def extended80(b):
    """The 80-bit IEEE extended sample rate, exactly."""
    e = struct.unpack_from(">H", b, 0)[0]
    m = struct.unpack_from(">Q", b, 2)[0]
    sign = -1 if (e & 0x8000) else 1
    e &= 0x7FFF
    if e == 0 and m == 0:
        return 0.0
    return sign * m * (2.0 ** (e - 16383 - 63))


def chunks(d, o, end):
    out = []
    while o + 8 <= end:
        cid = d[o:o + 4]
        ln = struct.unpack_from(">I", d, o + 4)[0]
        out.append((cid, ln, o + 8))
        o += 8 + ln + (ln & 1)      # IFF chunks pad to even
    return out, o


def read(path):
    d = open(path, "rb").read()
    if d[:4] != b"FORM":
        return None
    formlen = struct.unpack_from(">I", d, 4)[0]
    kind = d[8:12]
    cs, end = chunks(d, 12, 8 + formlen)
    info = {"path": path, "size": len(d), "kind": kind,
            "formlen": formlen, "closes": (8 + formlen == len(d)),
            "chains": (end == 8 + formlen), "chunks": cs}
    for cid, ln, o in cs:
        if cid == b"COMM":
            ch, fr = struct.unpack_from(">HI", d, o)
            bits = struct.unpack_from(">H", d, o + 6)[0]
            rate = extended80(d[o + 8:o + 18])
            info["channels"] = ch
            info["frames"] = fr
            info["bits"] = bits
            info["rate"] = rate
            info["codec"] = d[o + 18:o + 22] if ln >= 22 else b"NONE"
        elif cid == b"SSND":
            info["ssnd"] = ln - 8
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--dump", action="store_true")
    a = ap.parse_args()

    paths = []
    if os.path.isdir(a.root):
        for r, _d, ns in os.walk(a.root):
            for n in sorted(ns):
                p = os.path.join(r, n)
                with open(p, "rb") as fh:
                    if fh.read(4) == b"FORM":
                        paths.append(p)
    else:
        paths = [a.root]

    print("%-38s %-5s %5s %4s %3s %11s %10s %9s %s"
          % ("file", "kind", "rate", "bits", "ch", "frames", "ssnd", "time",
             "codec"))
    tsec = 0.0
    tbytes = 0
    bad = []
    for p in paths:
        i = read(p)
        if i is None or "frames" not in i:
            bad.append((p, "no COMM"))
            continue
        secs = i["frames"] / i["rate"] if i["rate"] else 0.0
        tsec += secs
        tbytes += i.get("ssnd", 0)
        rel = p.replace(os.sep, "/")
        rel = rel[rel.find("/files/") + 6:] if "/files/" in rel else rel
        print("%-38s %-5s %5d %4d %3d %11d %10d %5d:%05.2f %s"
              % (rel, i["kind"].decode(), int(round(i["rate"])), i["bits"],
                 i["channels"], i["frames"], i.get("ssnd", 0),
                 int(secs // 60), secs % 60, i["codec"].decode("latin-1")))
        if not i["closes"] or not i["chains"]:
            bad.append((p, "FORM %d, file %d, chain ends %s"
                        % (i["formlen"], i["size"], i["chains"])))
        if a.dump:
            for cid, ln, o in i["chunks"]:
                print("      %r %d at %d" % (cid, ln, o))

    print("\n%d files, %d bytes of sample data, %d:%05.2f total"
          % (len(paths), tbytes, int(tsec // 60), tsec % 60))
    print("containers that do not close or chain: %d" % len(bad))
    for p, why in bad:
        print("  %s -- %s" % (p, why))


if __name__ == "__main__":
    main()
