#!/usr/bin/env python3
"""disccontacts.py -- address-shaped and telephone-shaped strings over the user
data of a whole track, counted and not printed.

`contacts.py` walks a tree of files. On a disc that is the wrong denominator:
half of this collection's surprises have come from the parts of an optical
object that belong to no file, and a forgotten address in the mastering slack
would be invisible to a per-file scan. So this reads every sector of the track
in order, with an overlap so a match cannot fall between two sectors, and
reports both denominators in the same run.

It **counts and does not print** anything that matches the person-shaped
pattern. A tool whose job is to find personal data must not be the thing that
publishes it. Matches are bucketed:

    function   info@, support@, sales@, webmaster@ and the like -- a role
    other      everything else, counted only

    python tools/disccontacts.py IMAGE
    python tools/disccontacts.py IMAGE --raw 2048 --off 0
"""
import argparse
import os
import re

ADDR = re.compile(rb"[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,64}\.[A-Za-z]{2,12}")
TEL = re.compile(rb"(?:\+\d{1,3}[ .-])?\(?\d{3}\)?[ .-]\d{3,4}[ .-]\d{4}")
FUNCTION = (b"info", b"support", b"sales", b"webmaster", b"admin", b"contact",
            b"help", b"service", b"postmaster", b"abuse", b"noreply")
CHUNK = 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--raw", type=int, default=2352)
    ap.add_argument("--off", type=int, default=16)
    ap.add_argument("--size", type=int, default=2048)
    a = ap.parse_args()

    total = os.path.getsize(a.image)
    if total % a.raw:
        raise SystemExit("%d bytes is not a whole number of %d-byte sectors"
                         % (total, a.raw))
    sectors = total // a.raw

    fh = open(a.image, "rb")
    carry = b""
    nbytes = 0
    func = []
    other = 0
    tel = 0
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
        nbytes += len(user)
        for m in ADDR.finditer(buf):
            s = m.group(0)
            local = s.split(b"@")[0].lower()
            if local in FUNCTION:
                func.append(s.decode("latin-1"))
            else:
                other += 1
        tel += len(TEL.findall(buf))
        carry = buf[-256:]
    fh.close()

    print("image                     : %s" % a.image)
    print("sectors read              : %d" % sectors)
    print("user bytes scanned        : %d" % nbytes)
    print()
    print("function addresses (a role, not a person: printed) : %d"
          % len(func))
    for s in sorted(set(func)):
        print("   %s" % s)
    print("person-shaped addresses (COUNTED, NOT PRINTED)     : %d" % other)
    print("telephone-shaped strings                           : %d" % tel)


if __name__ == "__main__":
    main()
