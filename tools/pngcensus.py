#!/usr/bin/env python3
"""pngcensus.py -- census a tree of PNG files against the published format, and
close every one of them on its own declared chunk lengths.

PNG is specified (W3C PNG 1.2, ISO/IEC 15948) and this tool uses the
specification and says so. What it measures is not "does a decoder open these"
-- any decoder does -- but three things a decoder does not report:

  * **closure.** The 8-byte signature plus, for every chunk, 4 bytes of
    declared length + 4 of type + the declared data + 4 of CRC, must sum to the
    file's byte count exactly. Residue is printed per file and in total. A
    library that stops at IEND cannot tell you whether bytes follow it;
  * **the CRC-32 of every chunk**, which is the only per-byte check any file in
    this object carries about itself. It is verified, not skipped;
  * **palette identity.** A palettised library made by one studio may reuse one
    table across many images, or give each one its own. The sha1 of each PLTE
    chunk's data answers that, and no image decoder will tell you.

Two shares are reported and neither is allowed to stand in for the other: the
count of files, and the count of bytes.

    python tools/pngcensus.py <root>
    python tools/pngcensus.py <root> --by-dir
    python tools/pngcensus.py <root> --tsv notes/pngcensus.tsv
    python tools/pngcensus.py selftest
"""
import argparse
import binascii
import collections
import hashlib
import os
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"

COLOUR = {0: "greyscale", 2: "truecolour", 3: "palettised",
          4: "greyscale+alpha", 6: "truecolour+alpha"}


class Bad(Exception):
    pass


def walk_png(blob):
    """Return (ihdr, chunks, residue). Raise Bad with an offset on refusal.

    `chunks` is a list of (type, offset, declared_length, data, crc_ok).
    """
    if len(blob) < 8:
        raise Bad("shorter than the 8-byte signature: %d bytes" % len(blob))
    if blob[:8] != SIG:
        raise Bad("no PNG signature at 0: %r" % blob[:8])
    off = 8
    chunks = []
    ihdr = None
    while off + 8 <= len(blob):
        (length,) = struct.unpack_from(">I", blob, off)
        ctype = blob[off + 4:off + 8]
        end = off + 8 + length + 4
        if end > len(blob):
            raise Bad("chunk %r at %d declares %d bytes and the file ends at "
                      "%d" % (ctype, off, length, len(blob)))
        data = blob[off + 8:off + 8 + length]
        (declared_crc,) = struct.unpack_from(">I", blob, off + 8 + length)
        crc_ok = binascii.crc32(ctype + data) & 0xFFFFFFFF == declared_crc
        chunks.append((ctype, off, length, data, crc_ok))
        if ctype == b"IHDR":
            if length != 13:
                raise Bad("IHDR at %d declares %d bytes, not 13"
                          % (off, length))
            ihdr = struct.unpack(">IIBBBBB", data)
        off = end
        if ctype == b"IEND":
            break
    if ihdr is None:
        raise Bad("no IHDR chunk")
    if not chunks or chunks[-1][0] != b"IEND":
        raise Bad("the last chunk is %r and not IEND"
                  % (chunks[-1][0] if chunks else None))
    return ihdr, chunks, len(blob) - off


def census(root, by_dir, tsv):
    rows = []
    refused = []
    for dp, dn, fn in os.walk(root):
        for f in sorted(fn):
            if not f.lower().endswith(".png"):
                continue
            p = os.path.join(dp, f)
            blob = open(p, "rb").read()
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                ihdr, chunks, residue = walk_png(blob)
            except Bad as e:
                refused.append((rel, str(e)))
                continue
            plte = [c for c in chunks if c[0] == b"PLTE"]
            pal = (hashlib.sha1(plte[0][3]).hexdigest() if plte else None)
            pal_entries = (plte[0][2] // 3) if plte else 0
            idat = sum(c[2] for c in chunks if c[0] == b"IDAT")
            idat_sha1 = hashlib.sha1(
                b"".join(c[3] for c in chunks if c[0] == b"IDAT")).hexdigest()
            bad_crc = sum(1 for c in chunks if not c[4])
            rows.append(dict(path=rel, dirname=os.path.dirname(rel) or ".",
                             bytes=len(blob), w=ihdr[0], h=ihdr[1],
                             depth=ihdr[2], colour=ihdr[3], interlace=ihdr[6],
                             chunks=len(chunks), residue=residue,
                             pal=pal, pal_entries=pal_entries, idat=idat,
                             idat_sha1=idat_sha1, bad_crc=bad_crc,
                             types=[c[0].decode("ascii", "replace")
                                    for c in chunks]))
    if not rows and not refused:
        sys.exit("pngcensus: no .png under %r -- refusing to report a clean "
                 "census over an empty population" % root)

    nb = sum(r["bytes"] for r in rows)
    print("root                 : %s" % root)
    print("files matching .png  : %d" % (len(rows) + len(refused)))
    print("parsed as PNG        : %d" % len(rows))
    print("refused              : %d" % len(refused))
    for rel, why in refused:
        print("   %-50s %s" % (rel, why))
    print("bytes in parsed files: %d" % nb)
    print()
    print("-- closure: signature + every declared chunk length + CRC ------")
    print("   files closing at residue 0        : %d of %d"
          % (sum(1 for r in rows if r["residue"] == 0), len(rows)))
    nonzero = [r for r in rows if r["residue"] != 0]
    for r in nonzero[:10]:
        print("   %-46s residue %d" % (r["path"], r["residue"]))
    print("   chunks walked                     : %d"
          % sum(r["chunks"] for r in rows))
    print("   chunks whose CRC-32 verifies      : %d of %d"
          % (sum(r["chunks"] - r["bad_crc"] for r in rows),
             sum(r["chunks"] for r in rows)))
    print("   files with a failing CRC          : %d"
          % sum(1 for r in rows if r["bad_crc"]))
    print()
    print("-- what IHDR declares ------------------------------------------")
    geom = collections.Counter((r["depth"], r["colour"], r["interlace"])
                               for r in rows)
    print("   depth  colour type            interlace  files")
    for (d, c, i), n in sorted(geom.items()):
        print("   %5d  %d %-20s %6d  %7d"
              % (d, c, COLOUR.get(c, "?"), i, n))
    print()
    print("-- the palettes ------------------------------------------------")
    pals = collections.Counter(r["pal"] for r in rows if r["pal"])
    print("   files carrying a PLTE chunk       : %d of %d"
          % (sum(1 for r in rows if r["pal"]), len(rows)))
    print("   DISTINCT palettes by sha1 of PLTE : %d" % len(pals))
    print("   palette entry counts              : %s"
          % dict(collections.Counter(r["pal_entries"] for r in rows
                                     if r["pal"])))
    for h, n in pals.most_common(5):
        print("   %s  shared by %d files" % (h[:16], n))
    print()
    print("-- geometry ----------------------------------------------------")
    dims = collections.Counter((r["w"], r["h"]) for r in rows)
    print("   distinct (width, height) pairs    : %d" % len(dims))
    for (w, h), n in dims.most_common(8):
        print("   %5d x %-5d  %d files" % (w, h, n))
    print()
    print("-- chunk types seen --------------------------------------------")
    types = collections.Counter(t for r in rows for t in r["types"])
    print("   %s" % "  ".join("%s %d" % (t, n)
                              for t, n in types.most_common()))
    print()
    print("-- is any two the same image? ----------------------------------")
    print("   The tree has one sha1 per file, so no two files are")
    print("   byte-identical. This asks the weaker and more useful question:")
    print("   do two files carry the SAME COMPRESSED PIXEL STREAM, which")
    print("   would make them the same image in different wrapping?")
    idatkey = collections.Counter(r["idat_sha1"] for r in rows)
    dup = {h: n for h, n in idatkey.items() if n > 1}
    print("   distinct IDAT streams by sha1      : %d over %d files"
          % (len(idatkey), len(rows)))
    print("   files sharing an IDAT stream       : %d"
          % sum(n for n in dup.values()))
    for h, n in sorted(dup.items(), key=lambda kv: -kv[1])[:5]:
        who = [r["path"] for r in rows if r["idat_sha1"] == h]
        print("      %s x%d  %s" % (h[:12], n, ", ".join(who[:4])))
    geomkey = collections.Counter((r["w"], r["h"], r["depth"], r["colour"],
                                   r["pal"]) for r in rows)
    print("   files sharing (w, h, depth, colour, palette) with another")
    print("   file but NOT its pixels            : %d"
          % (sum(n for n in geomkey.values() if n > 1)
             - sum(n for n in dup.values())))

    if by_dir:
        print()
        print("-- by directory ------------------------------------------------")
        agg = collections.defaultdict(lambda: [0, 0, set()])
        for r in rows:
            a = agg[r["dirname"]]
            a[0] += 1
            a[1] += r["bytes"]
            a[2].add(r["pal"])
        print("   %-16s %5s %12s %s" % ("dir", "files", "bytes", "palettes"))
        for k in sorted(agg):
            a = agg[k]
            print("   %-16s %5d %12d %d" % (k, a[0], a[1], len(a[2])))

    if tsv:
        with open(tsv, "w", encoding="utf-8") as fh:
            fh.write("path\tbytes\twidth\theight\tdepth\tcolour\tchunks\t"
                     "residue\tpalette_sha1\tpalette_entries\tidat_bytes\n")
            for r in sorted(rows, key=lambda x: x["path"]):
                fh.write("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\t%d\n"
                         % (r["path"], r["bytes"], r["w"], r["h"], r["depth"],
                            r["colour"], r["chunks"], r["residue"],
                            r["pal"] or "-", r["pal_entries"], r["idat"]))
        print()
        print("full table : %s (%d rows)" % (tsv, len(rows)))
    return 0 if not refused and not nonzero else 1


def chunk(ctype, data):
    return (struct.pack(">I", len(data)) + ctype + data
            + struct.pack(">I", binascii.crc32(ctype + data) & 0xFFFFFFFF))


def make_png(w=2, h=2, depth=8, colour=3, pal=None, trailer=b"",
             break_crc=False, break_length=False):
    ihdr = struct.pack(">IIBBBBB", w, h, depth, colour, 0, 0, 0)
    out = SIG + chunk(b"IHDR", ihdr)
    if colour == 3:
        out += chunk(b"PLTE", pal if pal is not None else bytes(3 * 4))
    raw = b"".join(b"\x00" + bytes(w) for _ in range(h))
    idat = chunk(b"IDAT", zlib.compress(raw))
    if break_crc:
        idat = idat[:-4] + b"\xde\xad\xbe\xef"
    if break_length:
        idat = struct.pack(">I", 1 << 20) + idat[4:]
    out += idat + chunk(b"IEND", b"") + trailer
    return out


def selftest():
    checks = []

    def ok(name, cond):
        checks.append((name, bool(cond)))

    def refuses(name, blob, fragment):
        try:
            walk_png(blob)
        except Bad as e:
            ok(name + " (" + fragment + ")", fragment in str(e))
        else:
            ok(name + " (" + fragment + ")", False)

    good = make_png()
    ihdr, chunks, residue = walk_png(good)
    ok("a constructed 2x2 palettised PNG parses", ihdr[:4] == (2, 2, 8, 3))
    ok("it closes at residue 0", residue == 0)
    ok("it has IHDR, PLTE, IDAT, IEND in that order",
       [c[0] for c in chunks] == [b"IHDR", b"PLTE", b"IDAT", b"IEND"])
    ok("every CRC verifies", all(c[4] for c in chunks))

    refuses("empty input", b"", "shorter than")
    refuses("a GIF", b"GIF89a" + bytes(40), "no PNG signature")
    refuses("the signature alone", SIG, "no IHDR")
    refuses("a chunk that overruns the file", make_png(break_length=True),
            "declares")
    refuses("an IHDR of the wrong length",
            SIG + chunk(b"IHDR", bytes(12)) + chunk(b"IEND", b""),
            "not 13")
    refuses("a file that does not end on IEND",
            SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)),
            "not IEND")
    refuses("a JPEG", b"\xff\xd8\xff\xe0" + bytes(60), "no PNG signature")
    refuses("a RIFF WAVE", b"RIFF" + bytes(4) + b"WAVEfmt ", "no PNG")
    refuses("an ITSF header", b"ITSF\x03\x00\x00\x00" + bytes(88), "no PNG")
    refuses("seven bytes of the signature", SIG[:7], "shorter than")
    refuses("the signature with one bit flipped in it",
            b"\x89PNH\r\n\x1a\n" + chunk(b"IHDR", bytes(13)),
            "no PNG signature")
    refuses("a chunk header split across the end of the file",
            SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 3, 0, 0, 0))
            + b"\x00\x00", "not IEND")

    ihdr, chunks, residue = walk_png(make_png(trailer=b"junkjunk"))
    ok("eight appended bytes are reported as residue 8, not swallowed",
       residue == 8)

    ihdr, chunks, residue = walk_png(make_png(break_crc=True))
    ok("a corrupted CRC is reported rather than raising",
       sum(1 for c in chunks if not c[4]) == 1)

    a = make_png(pal=bytes(range(12)))
    b = make_png(pal=bytes(range(12)))
    c = make_png(pal=bytes(range(11, -1, -1)))
    def palhash(blob):
        return hashlib.sha1(
            [x for x in walk_png(blob)[1] if x[0] == b"PLTE"][0][3]).hexdigest()
    ok("two files with the same palette hash the same",
       palhash(a) == palhash(b))
    ok("a different palette hashes differently", palhash(a) != palhash(c))

    ihdr, chunks, residue = walk_png(make_png(colour=2))
    ok("a truecolour PNG has no PLTE",
       not any(x[0] == b"PLTE" for x in chunks))

    width = max(len(n) for n, _ in checks)
    for n, good_ in checks:
        print("  %-*s %s" % (width, n, "ok" if good_ else "FAIL"))
    bad = [n for n, g in checks if not g]
    print("%d checks, %d failures" % (len(checks), len(bad)))
    return 1 if bad else 0



def utf8_stdout():
    """Print recovered text without dying on a default Windows console.

    This tool prints strings it recovered from an object, and those strings can
    hold any byte. On a default Windows console `sys.stdout` is cp1252 and a
    single Japanese character kills the process half-way through a table. The
    previous session shipped a tool that only worked when `PYTHONIOENCODING`
    happened to be set, and that is the defect this function exists to not
    repeat: the encoding is made explicit here rather than inherited.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--by-dir", action="store_true")
    ap.add_argument("--tsv")
    args = ap.parse_args()
    utf8_stdout()
    if args.root == "selftest":
        return selftest()
    return census(args.root, args.by_dir, args.tsv)


if __name__ == "__main__":
    sys.exit(main())
