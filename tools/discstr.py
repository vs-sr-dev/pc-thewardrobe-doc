#!/usr/bin/env python3
"""discstr.py -- count strings over the user data of a whole track.

`strcount.py` walks a tree of files, which is the right denominator for a
folder and the wrong one for a disc: on an optical object the interesting
question is usually "how many times does this occur *on the pressing*", and the
pressing has bytes that are in no file.

This reads the 2,048-byte user area of every sector in order, with a 64-byte
overlap so a match that straddles two sectors is not lost, and reports each
string's count. A string found nowhere prints `-- nowhere on the disc --`, so a
zero is visibly a measurement.

It also prints, for each string length in the query set, the number of
occurrences a uniformly random object of the same size would be expected to
contain:

    E[n] = (N - L + 1) / 256^L

On a 629,649,408-byte object that is 37.5391 for a three-byte string and
0.1466 for a four-byte one. **A three-byte marker occurring 82 times has not
been found 82 times; it has been found 44 times more than nothing.** Every
count this tool prints carries its expectation beside it for that reason.

    python tools/discstr.py IMAGE PDAT PLUT CCB CEL
    python tools/discstr.py IMAGE --file notes/strings.txt
    python tools/discstr.py IMAGE --raw 2048 --off 0 iamaduck
"""
import argparse
import os
import sys

CHUNK = 512


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("strings", nargs="*")
    ap.add_argument("--file")
    ap.add_argument("--raw", type=int, default=2352)
    ap.add_argument("--off", type=int, default=16)
    ap.add_argument("--size", type=int, default=2048)
    a = ap.parse_args()

    pats = list(a.strings)
    if a.file:
        for ln in open(a.file, encoding="utf-8"):
            ln = ln.rstrip("\n")
            if ln and not ln.startswith("#"):
                pats.append(ln)
    if not pats:
        raise SystemExit("no strings given")
    raw = [p.encode("latin-1") for p in pats]
    maxlen = max(len(p) for p in raw)

    total = os.path.getsize(a.image)
    if total % a.raw:
        raise SystemExit("%d bytes is not a whole number of %d-byte sectors"
                         % (total, a.raw))
    sectors = total // a.raw
    nbytes = sectors * a.size

    counts = [0] * len(raw)
    fh = open(a.image, "rb")
    carry = b""
    done = 0
    while True:
        blob = fh.read(a.raw * CHUNK)
        if not blob:
            break
        if a.raw == a.size and a.off == 0:
            user = blob
        else:
            user = b"".join(blob[i + a.off:i + a.off + a.size]
                            for i in range(0, len(blob), a.raw))
        buf = carry + user
        for i, p in enumerate(raw):
            counts[i] += buf.count(p)
        carry = buf[-(maxlen - 1):] if maxlen > 1 else b""
        done += len(user)
    fh.close()
    if done != nbytes:
        raise SystemExit("read %d user bytes, expected %d" % (done, nbytes))

    print("object: %s" % a.image)
    print("sectors: %d   user bytes: %d" % (sectors, nbytes))
    print()
    print("%-34s %10s %12s" % ("string", "count", "E[random]"))
    for p, s, c in zip(raw, pats, counts):
        exp = float(nbytes - len(p) + 1) / (256.0 ** len(p))
        if c == 0:
            print("%-34s %10s %12.4f  -- nowhere on the disc --"
                  % (s, "0", exp))
        else:
            print("%-34s %10d %12.4f" % (s, c, exp))


if __name__ == "__main__":
    main()
