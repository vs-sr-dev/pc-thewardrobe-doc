#!/usr/bin/env python3
"""kultidx.py -- read the 82 `.idx` files of *Kult: Heretic Kingdoms*.

The shape, derived from `data/levels/arena.idx` and then required of the other
eighty-one:

    +0    u32   count
    then  `count` records of a FIXED width w:
              +0        the member's name, NUL-padded, w - 4 bytes
              +(w - 4)  u32 offset of the member in the `.dat` of the same stem

`arena.idx` is 657,824 bytes with count 5,305 and `4 + 5305 x 124 = 657,824`,
so the width there is 124 and the name field is 120. **The width is not
assumed to be 124 anywhere in this tool.** It is computed per file as
`(size - 4) / count` and the file is refused if that division leaves a
remainder -- which is the only thing that makes the closure a measurement
rather than a restatement.

HOW THE SECOND FIELD WAS FOUND, WHICH IS THE PART WORTH KEEPING
---------------------------------------------------------------
The pre-briefing read the record as "a NUL-padded path" and the arithmetic
closed. It closed because 124 is the right width, not because the record is
only a name. The first version of this tool required every byte after the name
to be zero -- and it refused all 82 files, on record 1 of every one of them.
Four non-zero bytes at a constant position in 5,304 records of 5,305 are a
field. They start at 0, they ascend strictly, and the gaps between them are
8,208, 32,784, 2,064, 16,400, 65,552 -- every one of them `16 + 2^k`. They are
offsets into the `.dat` beside the index, and the 16 is the member header.

**A closure that closes on the wrong reading is the failure mode this pipeline
keeps writing down**, and the strict check is what caught it. The check is
still here: a record is refused if the name field has anything after its NUL
other than NUL, or if the name holds an unprintable byte.

    python tools/kultidx.py selftest
    python tools/kultidx.py validate "<root>/data/levels/arena.idx"
    python tools/kultidx.py census   "<root>"
    python tools/kultidx.py list     "<root>/data/levels/arena.idx"
    python tools/kultidx.py names    "<root>" -o names.txt
"""
import argparse
import collections
import os
import struct
import sys

MAX_COUNT = 1 << 22          # 4,194,304 -- a refusal, not a limit


class IdxError(Exception):
    pass


def parse(blob, path="<memory>", strict=True):
    """Return (count, width, [(name, offset), ...]) or raise.

    `strict=False` keeps the arithmetic checks -- which are what decides
    whether the file is an index at all -- and downgrades the per-record name
    checks to a count, so the census can report the two separately. Three of
    the object's 82 index files close on the arithmetic and hold malformed
    names, and collapsing those two facts into one verdict would lose the
    interesting half.
    """
    if len(blob) < 8:
        raise IdxError("%s: %d bytes, too short for a count and one record"
                       % (path, len(blob)))
    (count,) = struct.unpack_from("<I", blob, 0)
    if count == 0:
        raise IdxError("%s: declares zero records" % path)
    if count > MAX_COUNT:
        raise IdxError("%s: declares %d records, which is past this reader's "
                       "sanity limit of %d" % (path, count, MAX_COUNT))
    body = len(blob) - 4
    if body % count:
        raise IdxError("%s: %d bytes after the count is not divisible by %d "
                       "records -- remainder %d, so the record width is not "
                       "constant" % (path, body, count, body % count))
    width = body // count
    if width < 2 or width > 4096:
        raise IdxError("%s: computed record width %d is not credible"
                       % (path, width))
    if width < 6:
        raise IdxError("%s: record width %d leaves no room for a name and a "
                       "u32" % (path, width))
    namelen = width - 4
    out = []
    bad = []
    for i in range(count):
        rec = blob[4 + i * width: 4 + (i + 1) * width]
        field = rec[:namelen]
        (off,) = struct.unpack_from("<I", rec, namelen)
        z = field.find(b"\x00")
        if z < 0:
            bad.append((i, "no NUL terminator in the %d-byte name field" % namelen))
            name = field
        else:
            name = field[:z]
            if any(field[z:]):
                bad.append((i, "non-zero bytes after the name inside the name "
                               "field"))
        if any(b < 32 or b == 127 for b in name):
            bad.append((i, "unprintable byte in the name %r" % name[:32]))
        out.append((name.decode("latin-1"), off))
    if bad and strict:
        i, why = bad[0]
        raise IdxError("%s: %d of %d records are malformed; the first is "
                       "record %d -- %s" % (path, len(bad), count, i, why))
    parse.last_bad = len(bad)
    parse.last_first_bad = bad[0] if bad else None
    return count, width, out


parse.last_bad = 0
parse.last_first_bad = None


def cmd_validate(a):
    blob = open(a.path, "rb").read()
    count, width, recs = parse(blob, a.path)
    names = [n for n, _ in recs]
    offs = [o for _, o in recs]
    print("file        : %s" % a.path)
    print("bytes       : %d" % len(blob))
    print("count       : %d" % count)
    print("record width: %d   (computed, not assumed) = %d name + 4 offset"
          % (width, width - 4))
    print("arithmetic  : 4 + %d x %d = %d   -- file is %d  %s"
          % (count, width, 4 + count * width, len(blob),
             "CLOSES" if 4 + count * width == len(blob) else "DOES NOT CLOSE"))
    print("longest name: %d characters" % max(len(n) for n in names))
    print("distinct    : %d of %d" % (len(set(names)), count))
    print("offsets     : first %d, last %d, strictly ascending %s"
          % (offs[0], offs[-1],
             "yes" if all(offs[i] < offs[i + 1] for i in range(len(offs) - 1))
             else "NO"))
    dat = os.path.splitext(a.path)[0] + ".dat"
    if os.path.exists(dat):
        size = os.path.getsize(dat)
        print("companion   : %s  %d bytes; last offset is %s it, tail is %d bytes"
              % (os.path.basename(dat), size,
                 "inside" if offs[-1] < size else "OUTSIDE", size - offs[-1]))
    print()
    for n, o in recs[:a.head]:
        print("   %10d  %s" % (o, n))


def cmd_list(a):
    blob = open(a.path, "rb").read()
    count, width, recs = parse(blob, a.path)
    for n, o in recs:
        print("%10d\t%s" % (o, n))


def cmd_census(a):
    rows = []
    failures = []
    malformed = []
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames.sort()
        for fn in sorted(filenames):
            if not fn.lower().endswith(".idx"):
                continue
            p = os.path.join(dirpath, fn)
            blob = open(p, "rb").read()
            rel = os.path.relpath(p, a.root)
            dat = os.path.splitext(p)[0] + ".dat"
            dsize = os.path.getsize(dat) if os.path.exists(dat) else None
            try:
                count, width, recs = parse(blob, p, strict=False)
            except IdxError as exc:
                failures.append(str(exc))
                rows.append((rel, len(blob), None, None, 0, 0, dsize, ""))
                continue
            if parse.last_bad:
                malformed.append((rel, parse.last_bad, count,
                                  parse.last_first_bad))
            names = [n for n, _ in recs]
            offs = [o for _, o in recs]
            asc = all(offs[i] < offs[i + 1] for i in range(len(offs) - 1))
            if dsize is None:
                note = "no .dat"
            elif not asc:
                note = "NOT ASCENDING"
            elif offs[-1] >= dsize:
                note = "LAST OFFSET OUTSIDE"
            else:
                note = "ok, tail %d" % (dsize - offs[-1])
            rows.append((rel, len(blob), count, width, len(set(names)),
                         max(len(n) for n in names), dsize, note))
    print("%-40s %10s %7s %6s %8s %6s %12s %s"
          % ("file", "bytes", "count", "width", "distinct", "maxlen",
             ".dat bytes", "offsets"))
    ok = 0
    tb = tc = tdat = 0
    paired = 0
    widths = collections.Counter()
    for rel, size, count, width, distinct, maxlen, dsize, note in rows:
        if count is None:
            print("%-40s %10d %7s" % (rel, size, "REFUSED"))
            continue
        ok += 1
        tb += size
        tc += count
        widths[width] += 1
        if dsize is not None:
            paired += 1
            tdat += dsize
        print("%-40s %10d %7d %6d %8d %6d %12s %s"
              % (rel, size, count, width, distinct, maxlen,
                 dsize if dsize is not None else "-", note))
    print()
    print("files             : %d, of which parsed %d" % (len(rows), ok))
    print("bytes             : %d" % tb)
    print("records, summed   : %d" % tc)
    print("record widths     : %s"
          % ", ".join("%d on %d files" % (w, n) for w, n in sorted(widths.items())))
    print("with a .dat of the same stem : %d, and those .dat total %d bytes"
          % (paired, tdat))
    print("closure           : every parsed file satisfies 4 + count x width = size")
    print()
    print("THE TWO VERDICTS, KEPT APART")
    print("  arithmetic closes (4 + count x width = size) : %d of %d"
          % (ok, len(rows)))
    print("  every name field well formed                 : %d of %d"
          % (ok - len(malformed), len(rows)))
    if malformed:
        print()
        print("the files that close on the arithmetic and hold malformed names:")
        for rel, bad, count, first in malformed:
            idx, why = first
            print("   %-34s %5d of %5d records; first is record %d -- %s"
                  % (rel, bad, count, idx, why))
    if failures:
        print()
        print("refusals:")
        for f in failures:
            print("   %s" % f)
    return 1 if failures else 0


def cmd_names(a):
    """The union of every name in every .idx, which is the object's largest
    naming layer."""
    seen = collections.Counter()
    per = {}
    for dirpath, dirnames, filenames in os.walk(a.root):
        for fn in sorted(filenames):
            if not fn.lower().endswith(".idx"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                count, width, recs = parse(open(p, "rb").read(), p, strict=False)
            except IdxError:
                continue
            per[os.path.relpath(p, a.root)] = recs
            for n, _ in recs:
                seen[n] += 1
    total = sum(seen.values())
    print("index files parsed : %d" % len(per))
    print("name slots         : %d" % total)
    print("distinct names     : %d" % len(seen))
    print("mean repeats       : %.4f" % (total / float(len(seen)) if seen else 0))
    exts = collections.Counter(os.path.splitext(n)[1].lower() for n in seen)
    print()
    print("distinct names by extension:")
    for e, n in exts.most_common(12):
        print("   %-10s %6d" % (e or "(none)", n))
    print()
    print("the twelve most repeated names:")
    for n, c in seen.most_common(12):
        print("   %5d  %s" % (c, n))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            for n in sorted(seen):
                fh.write("%s\n" % n)
        print()
        print("wrote %d distinct names to %s" % (len(seen), a.out))


def cmd_selftest(a):
    """Built specimens. Most must be refused; the one that is accepted must
    produce the exact names named here."""
    def table(width, recs):
        b = struct.pack("<I", len(recs))
        for n, o in recs:
            b += n.encode("latin-1").ljust(width - 4, b"\x00") + struct.pack("<I", o)
        return b

    ok = True
    print("POSITIVE -- must parse and yield exactly these records:")
    want = [("a/one.tga", 0), ("a/two.tga", 8208), ("b/three.tga", 16416)]
    good = table(16, want)
    try:
        c, w, r = parse(good, "built")
        good_ok = (c, w, r) == (3, 16, want)
        print("   %-5s count=%d width=%d records=%r"
              % ("ok" if good_ok else "FAIL", c, w, r))
        ok = ok and good_ok
    except IdxError as exc:
        print("   FAIL  raised %s" % exc)
        ok = False

    print()
    print("NEGATIVE -- must all be refused:")
    cases = [
        ("empty", b""),
        ("a count and no body", struct.pack("<I", 5)),
        ("count zero", struct.pack("<I", 0) + bytes(64)),
        ("body not divisible by the count",
         struct.pack("<I", 3) + bytes(50)),
        ("a count larger than the sanity limit",
         struct.pack("<I", 1 << 24) + bytes(64)),
        ("data inside the name field after its NUL",
         struct.pack("<I", 1) + b"name\x00\x01\x02\x03\x04\x05\x06\x07"
         + struct.pack("<I", 0)),
        ("an unprintable byte in a name",
         struct.pack("<I", 1) + b"na\x07me\x00" + bytes(7) + struct.pack("<I", 0)),
        ("a TGA header, the other big population",
         bytes([0, 0, 2, 0]) + bytes(60)),
    ]
    for name, blob in cases:
        try:
            parse(blob, name)
        except IdxError as exc:
            print("   ok    %-38s refused: %s" % (name, str(exc)[:56]))
        else:
            print("   FAIL  %-38s ACCEPTED" % name)
            ok = False
    print()
    print("1 positive, %d negative, %s"
          % (len(cases), "all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("validate"); p.add_argument("path")
    p.add_argument("--head", type=int, default=8); p.set_defaults(fn=cmd_validate)
    p = sub.add_parser("list"); p.add_argument("path"); p.set_defaults(fn=cmd_list)
    p = sub.add_parser("census"); p.add_argument("root"); p.set_defaults(fn=cmd_census)
    p = sub.add_parser("names"); p.add_argument("root")
    p.add_argument("-o", "--out"); p.set_defaults(fn=cmd_names)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    try:
        rc = a.fn(a)
    except IdxError as exc:
        sys.exit("IdxError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
