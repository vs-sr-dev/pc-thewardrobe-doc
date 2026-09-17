#!/usr/bin/env python3
"""maska.py -- read `data\\masky\\`, which is 7,881 files and the largest
directory in the object by file count, and whose whole format is two files.

`masky` is Slovak for *masks*. Each leaf directory holds a pair:

    size.txt    ASCII, `"<width> <height>"`, three to seven bytes
    maska.dat   width x height bytes, every one of them 0 or 1

That is the entire specification, and it closes at residue 0: the product of
the two numbers in the text file equals the length of the binary one, byte for
byte, on every pair in the object.

WHY THIS DIRECTORY MATTERS OUT OF PROPORTION TO ITS 148,581 BYTES
------------------------------------------------------------------
It is where the object's short files live. A 2 x 2 mask is four bytes; a 5 x 5
mask is twenty-five. `crossall.py` reported that four of this object's eight
crossings with the rest of the collection are files of 15, 8, 6 and 4 bytes,
and every one of them is a `maska.dat`. A four-byte file whose every byte is
0 or 1 has at most sixteen possible contents. **Colliding with somebody else's
four-byte file is not a relationship; it is arithmetic**, and this directory is
where the arithmetic comes from.

    python tools/maska.py selftest
    python tools/maska.py validate "<root>/data/masky/!!!/02"
    python tools/maska.py census   "<root>"
    python tools/maska.py show     "<root>/data/masky/!!!/02"
"""
import argparse
import collections
import os
import sys


class MaskError(Exception):
    pass


def parse_size(blob, path="<memory>"):
    try:
        text = blob.decode("ascii")
    except UnicodeDecodeError:
        raise MaskError("%s: size.txt is not ASCII" % path)
    parts = text.split()
    if len(parts) != 2:
        raise MaskError("%s: size.txt holds %d whitespace-separated fields, "
                        "not 2: %r" % (path, len(parts), text[:32]))
    try:
        w, h = int(parts[0]), int(parts[1])
    except ValueError:
        raise MaskError("%s: size.txt fields are not integers: %r" % (path, text[:32]))
    if w <= 0 or h <= 0:
        raise MaskError("%s: size.txt declares %d x %d" % (path, w, h))
    return w, h


def check(mask, w, h, path="<memory>"):
    if len(mask) != w * h:
        raise MaskError("%s: size.txt declares %d x %d = %d and maska.dat is "
                        "%d bytes" % (path, w, h, w * h, len(mask)))
    bad = [b for b in set(mask) if b not in (0, 1)]
    if bad:
        raise MaskError("%s: maska.dat holds byte values other than 0 and 1: %r"
                        % (path, sorted(bad)[:8]))
    return True


def load_pair(d):
    sp = os.path.join(d, "size.txt")
    mp = os.path.join(d, "maska.dat")
    if not os.path.exists(sp) or not os.path.exists(mp):
        raise MaskError("%s: needs both size.txt and maska.dat" % d)
    w, h = parse_size(open(sp, "rb").read(), d)
    mask = open(mp, "rb").read()
    check(mask, w, h, d)
    return w, h, mask


def cmd_validate(a):
    w, h, mask = load_pair(a.path)
    on = sum(mask)
    print("directory : %s" % a.path)
    print("size.txt  : %d x %d" % (w, h))
    print("maska.dat : %d bytes   -- %d x %d = %d, CLOSES" % (len(mask), w, h, w * h))
    print("set cells : %d of %d = %.4f %%" % (on, w * h, 100.0 * on / (w * h)))


def cmd_show(a):
    w, h, mask = load_pair(a.path)
    print("%s   %d x %d" % (a.path, w, h))
    for y in range(h):
        print("   " + "".join("#" if mask[y * w + x] else "." for x in range(w)))


def cmd_census(a):
    pairs = 0
    lone_mask = 0
    lone_size = 0
    total_bytes = 0
    total_cells = 0
    set_cells = 0
    dims = collections.Counter()
    sizes = collections.Counter()
    failures = []
    files_seen = 0
    other = collections.Counter()
    for dirpath, dirnames, filenames in os.walk(a.root):
        names = set(filenames)
        for fn in filenames:
            files_seen += 1
        has_m = "maska.dat" in names
        has_s = "size.txt" in names
        if not (has_m or has_s):
            continue
        if has_m and not has_s:
            lone_mask += 1
            continue
        if has_s and not has_m:
            lone_size += 1
            continue
        try:
            w, h, mask = load_pair(dirpath)
        except MaskError as exc:
            failures.append(str(exc))
            continue
        pairs += 1
        total_bytes += len(mask) + os.path.getsize(os.path.join(dirpath, "size.txt"))
        total_cells += w * h
        set_cells += sum(mask)
        dims[(w, h)] += 1
        sizes[len(mask)] += 1
        for fn in filenames:
            if fn not in ("maska.dat", "size.txt"):
                other[os.path.splitext(fn)[1].lower()] += 1

    print("root                 : %s" % a.root)
    print("mask pairs           : %d" % pairs)
    print("maska.dat with no size.txt : %d" % lone_mask)
    print("size.txt with no maska.dat : %d" % lone_size)
    print("files in those pairs : %d" % (pairs * 2))
    print("bytes in those pairs : %d" % total_bytes)
    print("cells                : %d, of which set %d = %.4f %%"
          % (total_cells, set_cells, 100.0 * set_cells / total_cells if total_cells else 0))
    print("closure              : every pair satisfies width x height = len(maska.dat)")
    print("failures             : %d" % len(failures))
    for f in failures[:10]:
        print("   %s" % f)
    print()
    print("the twelve commonest mask shapes:")
    for (w, h), n in dims.most_common(12):
        print("   %4d x %-4d %6d" % (w, h, n))
    print()
    print("masks of four bytes or fewer : %d"
          % sum(n for s, n in sizes.items() if s <= 4))
    print("masks of 64 bytes or fewer   : %d"
          % sum(n for s, n in sizes.items() if s <= 64))
    if other:
        print()
        print("other files sitting in a mask directory, by extension:")
        for e, n in other.most_common(8):
            print("   %-10s %5d" % (e or "(none)", n))
    return 1 if (failures or lone_mask or lone_size) else 0


def cmd_selftest(a):
    ok = True
    print("POSITIVE -- a 2 x 3 mask must parse and check:")
    w, h = parse_size(b"2 3", "built")
    mask = bytes([1, 0, 0, 1, 1, 0])
    good = (w, h) == (2, 3) and check(mask, w, h, "built")
    print("   %-5s size.txt -> (%d, %d), six bytes accepted" % ("ok" if good else "FAIL", w, h))
    ok = ok and good

    print()
    print("NEGATIVE -- these must all be refused:")
    cases = [
        ("size.txt with one field", lambda: parse_size(b"5", "n")),
        ("size.txt with three fields", lambda: parse_size(b"5 5 5", "n")),
        ("size.txt that is not a number", lambda: parse_size(b"w h", "n")),
        ("size.txt declaring zero", lambda: parse_size(b"0 5", "n")),
        ("size.txt that is not ASCII", lambda: parse_size(b"\xff\xfe5 5", "n")),
        ("a mask of the wrong length", lambda: check(bytes(24), 5, 5, "n")),
        ("a mask holding a byte that is not 0 or 1",
         lambda: check(bytes([0, 1, 2, 1]), 2, 2, "n")),
        ("a TGA header as a mask",
         lambda: check(bytes([0, 0, 2, 0]), 2, 2, "n")),
    ]
    for name, fn in cases:
        try:
            fn()
        except MaskError as exc:
            print("   ok    %-42s refused: %s" % (name, str(exc)[:44]))
        else:
            print("   FAIL  %-42s ACCEPTED" % name)
            ok = False
    print()
    print("1 positive, %d negative, %s"
          % (len(cases), "all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("validate"); p.add_argument("path"); p.set_defaults(fn=cmd_validate)
    p = sub.add_parser("show"); p.add_argument("path"); p.set_defaults(fn=cmd_show)
    p = sub.add_parser("census"); p.add_argument("root"); p.set_defaults(fn=cmd_census)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    try:
        rc = a.fn(a)
    except MaskError as exc:
        sys.exit("MaskError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
