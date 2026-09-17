#!/usr/bin/env python3
"""oggmeta.py -- read the Ogg Vorbis comment headers of the 1,872 audio files.

This is where 2004 is.

Nothing else in *Kult: Heretic Kingdoms* carries the year it was published.
`kult.exe` was linked 2015-08-27, `configure.exe` 2015-01-13, `bass.dll`
2013-02-16, the studio's own `dialog editor.exe` 2006-02-20 and the Inno
uninstaller 2018-08-20; every file on disk is stamped 2017-06-09 or later; and
the four bytes `2004` occur in the clear only inside GOG's own manifest, where
they are part of a file size.

The Ogg Vorbis comment header is a published format -- the Vorbis I
specification, section 5, `\\x03vorbis`, a vendor string and a list of
`FIELD=value` pairs -- and this tool uses that description and says so. What is
not published, and is read out of the object here, is what the studio put in
those fields: the **session dates of the voice recording and the music**, to
the day, with the software that wrote them.

    python tools/oggmeta.py census "<root>"
    python tools/oggmeta.py dates  "<root>"
    python tools/oggmeta.py show   "<root>/data/music/Battle5.ogg"
    python tools/oggmeta.py selftest
"""
import argparse
import collections
import os
import struct
import sys

HEAD = b"\x03vorbis"


class OggError(Exception):
    pass


def comments(blob, path="<memory>", window=1 << 16):
    """Return (vendor, [comment strings]). Refuses rather than guesses."""
    if blob[:4] != b"OggS":
        raise OggError("%s: does not begin OggS" % path)
    i = blob.find(HEAD, 0, window)
    if i < 0:
        raise OggError("%s: no comment header in the first %d bytes"
                       % (path, window))
    j = i + len(HEAD)
    if j + 4 > len(blob):
        raise OggError("%s: comment header truncated at the vendor length" % path)
    (vlen,) = struct.unpack_from("<I", blob, j)
    j += 4
    if vlen > 1 << 20 or j + vlen > len(blob):
        raise OggError("%s: vendor length %d is not credible" % (path, vlen))
    vendor = blob[j:j + vlen].decode("latin-1")
    j += vlen
    if j + 4 > len(blob):
        raise OggError("%s: no comment count after the vendor string" % path)
    (count,) = struct.unpack_from("<I", blob, j)
    j += 4
    if count > 4096:
        raise OggError("%s: declares %d comments, which is not credible"
                       % (path, count))
    out = []
    for k in range(count):
        if j + 4 > len(blob):
            raise OggError("%s: comment %d of %d runs past the end"
                           % (path, k, count))
        (clen,) = struct.unpack_from("<I", blob, j)
        j += 4
        if clen > 1 << 20 or j + clen > len(blob):
            raise OggError("%s: comment %d declares %d bytes" % (path, k, clen))
        out.append(blob[j:j + clen].decode("latin-1"))
        j += clen
    return vendor, out


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.lower().endswith(".ogg"):
                yield os.path.join(dirpath, fn)


def cmd_show(a):
    blob = open(a.path, "rb").read()
    vendor, cs = comments(blob, a.path)
    print("file   : %s  %d bytes" % (a.path, len(blob)))
    print("vendor : %s" % vendor)
    for c in cs:
        print("   %s" % c)


def cmd_census(a):
    vendors = collections.Counter()
    fields = collections.Counter()
    values = collections.defaultdict(collections.Counter)
    n = bad = 0
    for p in walk(a.root):
        n += 1
        try:
            vendor, cs = comments(open(p, "rb").read(), p)
        except OggError:
            bad += 1
            continue
        vendors[vendor] += 1
        for c in cs:
            if "=" in c:
                k, v = c.split("=", 1)
                fields[k.upper()] += 1
                values[k.upper()][v] += 1
            else:
                fields["(no = sign)"] += 1
                values["(no = sign)"][c] += 1
    print("ogg files            : %d" % n)
    print("refusing to parse    : %d" % bad)
    print()
    print("vendor strings (the encoder library, from the Vorbis I header):")
    for v, c in vendors.most_common():
        print("   %6d  %s" % (c, v))
    print()
    print("comment fields:")
    for f, c in fields.most_common():
        print("   %-14s %6d, %d distinct values" % (f, c, len(values[f])))
    for f in ("SOFTWARE", "ENCODER", "(no = sign)", "ARTIST", "TITLE",
              "COMMENT", "GENRE", "ALBUM"):
        if f not in values:
            continue
        print()
        print("%s:" % f)
        for v, c in values[f].most_common(12):
            print("   %6d  %r" % (c, v))
    return 1 if bad else 0


def cmd_dates(a):
    per = collections.Counter()
    bydir = collections.defaultdict(collections.Counter)
    nodate = collections.Counter()
    n = 0
    for p in walk(a.root):
        n += 1
        try:
            vendor, cs = comments(open(p, "rb").read(), p)
        except OggError:
            continue
        d = None
        for c in cs:
            if c.upper().startswith("DATE="):
                d = c.split("=", 1)[1]
        rel = os.path.relpath(p, a.root)
        parts = rel.split(os.sep)[:-1]          # the directory, not the file
        top = os.sep.join(parts[:3]) if parts else "(root)"
        if d is None:
            nodate[top] += 1
            continue
        per[d] += 1
        bydir[top][d] += 1
    print("ogg files            : %d" % n)
    print("carrying a DATE      : %d" % sum(per.values()))
    print("carrying none        : %d" % sum(nodate.values()))
    print("distinct dates       : %d" % len(per))
    if per:
        ds = sorted(per)
        print("earliest             : %s" % ds[0])
        print("latest               : %s" % ds[-1])
        years = collections.Counter(d[:4] for d in per.elements())
        print("by year              : %s"
              % ", ".join("%s x%d" % (y, c) for y, c in sorted(years.items())))
        months = collections.Counter(d[:7] for d in per.elements())
        print()
        print("by month:")
        for m, c in sorted(months.items()):
            print("   %-9s %5d  %s" % (m, c, "#" * min(60, c // 4)))
        print()
        print("every distinct date, with how many files carry it:")
        for d in ds:
            print("   %-12s %5d" % (d, per[d]))
    print()
    print("by directory:")
    for top in sorted(set(list(bydir) + list(nodate))):
        dd = bydir.get(top, collections.Counter())
        print("   %-28s %5d dated (%d distinct), %d undated"
              % (top, sum(dd.values()), len(dd), nodate.get(top, 0)))
        if dd:
            print("      %s .. %s" % (min(dd), max(dd)))


def cmd_selftest(a):
    def build(vendor, cs):
        b = b"OggS" + bytes(22) + HEAD
        b += struct.pack("<I", len(vendor)) + vendor.encode()
        b += struct.pack("<I", len(cs))
        for c in cs:
            b += struct.pack("<I", len(c)) + c.encode()
        return b

    ok = True
    print("POSITIVE -- a built comment header must read back exactly:")
    blob = build("libVorbis test", ["DATE=2004-06-23", "SOFTWARE=Sound Forge"])
    v, cs = comments(blob, "built")
    good = v == "libVorbis test" and cs == ["DATE=2004-06-23",
                                            "SOFTWARE=Sound Forge"]
    print("   %-5s vendor=%r comments=%r" % ("ok" if good else "FAIL", v, cs))
    ok = ok and good

    print()
    print("NEGATIVE -- these must all be refused:")
    cases = [
        ("empty", b""),
        ("not an Ogg", b"RIFF" + bytes(60)),
        ("an Ogg with no comment header", b"OggS" + bytes(200)),
        ("a vendor length past the end",
         b"OggS" + bytes(22) + HEAD + struct.pack("<I", 1 << 24)),
        ("a comment count that is not credible",
         b"OggS" + bytes(22) + HEAD + struct.pack("<I", 0) + struct.pack("<I", 99999)),
        ("a comment running past the end",
         b"OggS" + bytes(22) + HEAD + struct.pack("<I", 0)
         + struct.pack("<I", 1) + struct.pack("<I", 500)),
        ("a TGA header", bytes([0, 0, 2, 0]) + bytes(60)),
    ]
    for name, blob in cases:
        try:
            comments(blob, name)
        except OggError as exc:
            print("   ok    %-40s refused: %s" % (name, str(exc)[:44]))
        else:
            print("   FAIL  %-40s ACCEPTED" % name)
            ok = False
    print()
    print("1 positive, %d negative, %s"
          % (len(cases), "all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("show"); p.add_argument("path"); p.set_defaults(fn=cmd_show)
    p = sub.add_parser("census"); p.add_argument("root"); p.set_defaults(fn=cmd_census)
    p = sub.add_parser("dates"); p.add_argument("root"); p.set_defaults(fn=cmd_dates)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    try:
        rc = a.fn(a)
    except OggError as exc:
        sys.exit("OggError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
