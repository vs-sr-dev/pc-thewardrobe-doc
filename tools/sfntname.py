#!/usr/bin/env python3
"""sfntname.py -- the `name` table of a TrueType / OpenType font: family,
style, copyright, foundry, version, as the font states them.

The layout is Apple's TrueType Reference Manual and Microsoft's OpenType
specification (chapter `name`): an sfnt offset table (`00 01 00 00` /
`OTTO` / `true`, u16 numTables, then 16-byte table records of tag, checksum,
offset, length); the `name` table is a u16 format, u16 count, u16
stringOffset, then count 12-byte records (platformID, encodingID,
languageID, nameID, length, offset) over a string pool. Name IDs: 0
copyright, 1 family, 2 subfamily, 3 unique id, 4 full name, 5 version, 6
PostScript name, 7 trademark, 8 manufacturer, 9 designer, 10 description,
11 vendor URL, 12 designer URL, 13 licence. Platform 3 (Windows) strings are
UTF-16BE; platform 1 (Macintosh) strings are Mac Roman.

Written on pc-losthorizon-doc for eight fonts in `fonts\\` whose file names
say `headlight`, `jillican regular`, `steelfish`... and whose name tables say
who made them. Nothing is rasterised.

    python tools/sfntname.py FILE...
    python tools/sfntname.py --census DIR
    python tools/sfntname.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                  # noqa: E402
import nameguard                                 # noqa: E402

nameguard.guard()

NAME_IDS = {0: "copyright", 1: "family", 2: "subfamily", 3: "unique", 4: "full",
            5: "version", 6: "postscript", 7: "trademark", 8: "manufacturer",
            9: "designer", 10: "description", 11: "vendor URL", 12: "designer URL",
            13: "licence", 14: "licence URL"}


class Bad(Exception):
    pass


def tables(blob):
    if len(blob) < 12:
        raise Bad("shorter than an offset table")
    tag = blob[:4]
    if tag not in (b"\x00\x01\x00\x00", b"OTTO", b"true"):
        raise Bad("not an sfnt (%r)" % tag)
    n = struct.unpack_from(">H", blob, 4)[0]
    if 12 + 16 * n > len(blob):
        raise Bad("%d table records run past the end" % n)
    out = {}
    for i in range(n):
        t, chk, off, ln = struct.unpack_from(">4sIII", blob, 12 + 16 * i)
        if off + ln > len(blob):
            raise Bad("table %r at %d + %d runs past the end" % (t, off, ln))
        out[t] = (off, ln)
    return out


def names(blob):
    """{(platform, language, nameID): text} for every record."""
    t = tables(blob)
    if b"name" not in t:
        raise Bad("no name table")
    off, ln = t[b"name"]
    fmt, count, soff = struct.unpack_from(">HHH", blob, off)
    out = {}
    for i in range(count):
        plat, enc, lang, nid, sl, so = struct.unpack_from(">6H", blob, off + 6 + 12 * i)
        s = blob[off + soff + so:off + soff + so + sl]
        if plat == 3 or (plat == 0):
            text = s.decode("utf-16-be", "replace")
        else:
            text = s.decode("mac_roman", "replace")
        out[(plat, lang, nid)] = text
    return out


def card(blob):
    """One value per name ID, Windows English first, then anything."""
    n = names(blob)
    out = {}
    for (plat, lang, nid), text in sorted(n.items(), key=lambda kv: (kv[0][0] != 3, kv[0][1] != 0x409)):
        out.setdefault(nid, text)
    return out, len(n)


def show(path):
    dirguard.want_file(path, "sfntname")
    blob = open(path, "rb").read()
    try:
        c, n = card(blob)
        t = tables(blob)
    except Bad as e:
        print("%s: REFUSED: %s" % (nameguard.safe(path), e))
        return 1
    print("%s  %d bytes  %d tables (%s)  %d name records"
          % (nameguard.safe(os.path.basename(path)), len(blob), len(t),
             " ".join(sorted(k.decode("latin-1") for k in t)), n))
    for nid in sorted(c):
        print("   %-13s %s" % (NAME_IDS.get(nid, "id %d" % nid), c[nid].replace("\r", " ").replace("\n", " ")[:140]))
    return 0


def census(root):
    dirguard.want_tree(root, "sfntname")
    rows = []
    for dp, dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                hd = fh.read(4)
            if hd not in (b"\x00\x01\x00\x00", b"OTTO", b"true"):
                continue
            blob = open(p, "rb").read()
            try:
                c, n = card(blob)
            except Bad as e:
                rows.append((f, "REFUSED", str(e), "", ""))
                continue
            rows.append((f, c.get(1, ""), c.get(2, ""), c.get(8, c.get(9, "")), c.get(0, "")))
    print("%d sfnt fonts by magic under %s" % (len(rows), nameguard.safe(root)))
    print("  %-24s %-24s %-12s %-28s %s" % ("file", "family", "style", "manufacturer/designer", "copyright"))
    for f, fam, sty, man, cop in rows:
        print("  %-24s %-24s %-12s %-28s %s" % (nameguard.safe(f)[:24], fam[:24], sty[:12], man[:28], cop[:60]))
    return 0


def _font(records):
    """A tiny sfnt with only a name table, for the selftest."""
    pool = b""
    recs = b""
    for plat, lang, nid, text in records:
        s = text.encode("utf-16-be") if plat == 3 else text.encode("mac_roman")
        recs += struct.pack(">6H", plat, 1, lang, nid, len(s), len(pool))
        pool += s
    name = struct.pack(">HHH", 0, len(records), 6 + len(recs)) + recs + pool
    head = b"\x00\x01\x00\x00" + struct.pack(">HHHH", 1, 16, 0, 0)
    rec = struct.pack(">4sIII", b"name", 0, 12 + 16, len(name))
    return head + rec + name


def selftest():
    checks = []
    f = _font([(3, 0x409, 1, "Steelfish"), (3, 0x409, 8, "Typodermic Fonts"),
               (1, 0, 0, "Copyright (c) 2003")])
    c, n = card(f)
    checks.append(("family, manufacturer and copyright are read", c == {1: "Steelfish", 8: "Typodermic Fonts", 0: "Copyright (c) 2003"}, str(c)))
    checks.append(("three records are counted", n == 3, str(n)))
    checks.append(("a Windows string is UTF-16BE and a Macintosh one Mac Roman",
                   names(f)[(3, 0x409, 1)] == "Steelfish" and names(f)[(1, 0, 0)].startswith("Copyright"), ""))
    checks.append(("a PNG is REFUSED", _refuses(b"\x89PNG\r\n\x1a\n" + bytes(20)), ""))
    checks.append(("an sfnt whose name table runs past the end is REFUSED",
                   _refuses(f[:-5]), ""))
    width = max(len(x[0]) for x in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL", note))
        failed += 0 if ok else 1
    print()
    print("%d checks, %d failures (0 skipped: the selftest builds its own font)" % (len(checks), failed))
    return 1 if failed else 0


def _refuses(blob):
    try:
        card(blob)
    except Bad:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--census", metavar="DIR")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.census:
        return census(a.census)
    if not a.files:
        ap.error("give a font, --census DIR or --selftest")
    rc = 0
    for f in a.files:
        rc |= show(f)
    return rc


if __name__ == "__main__":
    sys.exit(main())
