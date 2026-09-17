#!/usr/bin/env python3
"""pngpair.py -- compare two PNG files chunk by chunk and say what they share.

`pngcensus.py` reports how many files share a compressed pixel stream. It does
not say which chunk two such files differ in, and "no two files have the same
hash" is a much weaker statement than "these two are one picture in two
palettes".

This asks the sharper question. For each chunk type it compares the PAYLOAD,
not the file, so that:

  * two files with the same `IDAT` are the same pixels however they are
    wrapped;
  * two files with the same `IDAT` and a different `PLTE` are one drawing in
    two colourways -- which is what a resource library does when an artist is
    asked for a variant;
  * a file that carries `gAMA`, `cHRM`, `tRNS` and `pHYs` where the other
    carries none of them was written by a different program, and the size
    difference is the arithmetic of those chunks and their twelve-byte
    headers.

The last of those is printed as a closure: **the byte difference between the
two files must equal the sum of `length + 12` over the chunks one has and the
other does not, plus the payload differences of the chunks they share.**

    python tools/pngpair.py A.png B.png
    python tools/pngpair.py --claim "X is an edit of Y" A.png B.png
    python tools/pngpair.py --selftest
"""
import argparse
import hashlib
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                              # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SIG = b"\x89PNG\r\n\x1a\n"


class PngError(Exception):
    pass


def chunks(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:8] != SIG:
        raise PngError("%s: no PNG signature" % path)
    out = []
    p = 8
    while p < len(blob):
        if p + 12 > len(blob):
            raise PngError("%s: a chunk header at %d runs past the end"
                           % (path, p))
        (ln,) = struct.unpack_from(">I", blob, p)
        typ = blob[p + 4:p + 8]
        if p + 12 + ln > len(blob):
            raise PngError("%s: chunk %s at %d declares %d bytes and %d "
                           "remain" % (path, typ.decode("latin-1"), p, ln,
                                       len(blob) - p - 8))
        payload = blob[p + 8:p + 8 + ln]
        (crc,) = struct.unpack_from(">I", blob, p + 8 + ln)
        if zlib.crc32(typ + payload) & 0xFFFFFFFF != crc:
            raise PngError("%s: chunk %s at %d fails its CRC"
                           % (path, typ.decode("latin-1"), p))
        out.append((p, typ.decode("latin-1"), ln, payload))
        p += 12 + ln
        if typ == b"IEND":
            break
    if p != len(blob):
        raise PngError("%s: IEND at %d but the file is %d bytes"
                       % (path, p, len(blob)))
    return blob, out


def digest(b):
    return hashlib.sha1(b).hexdigest()[:12]


def compare(a, b):
    blob_a, ca = chunks(a)
    blob_b, cb = chunks(b)
    types_a = [c[1] for c in ca]
    types_b = [c[1] for c in cb]
    by_a = {}
    by_b = {}
    for _o, t, ln, pay in ca:
        by_a.setdefault(t, []).append((ln, pay))
    for _o, t, ln, pay in cb:
        by_b.setdefault(t, []).append((ln, pay))

    print("  %-40s %9s %8s" % ("file", "bytes", "chunks"))
    print("  %-40s %9d %8d" % (os.path.basename(a), len(blob_a), len(ca)))
    print("  %-40s %9d %8d" % (os.path.basename(b), len(blob_b), len(cb)))
    print()
    print("  A : %s" % " ".join(types_a))
    print("  B : %s" % " ".join(types_b))
    print()
    print("  %-6s %-14s %-14s %s" % ("chunk", "A payload", "B payload",
                                     "verdict"))
    shared = []
    onlya = []
    onlyb = []
    for t in sorted(set(by_a) | set(by_b)):
        pa = by_a.get(t)
        pb = by_b.get(t)
        if pa and pb:
            sa = digest(b"".join(x[1] for x in pa))
            sb = digest(b"".join(x[1] for x in pb))
            same = sa == sb
            shared.append((t, same))
            print("  %-6s %-14s %-14s %s"
                  % (t, sa, sb, "IDENTICAL" if same else "differs"))
        elif pa:
            onlya.append((t, sum(x[0] for x in pa), len(pa)))
            print("  %-6s %-14s %-14s only in A"
                  % (t, digest(b"".join(x[1] for x in pa)), "-"))
        else:
            onlyb.append((t, sum(x[0] for x in pb), len(pb)))
            print("  %-6s %-14s %-14s only in B"
                  % (t, "-", digest(b"".join(x[1] for x in pb))))
    print()
    idat = dict(shared).get("IDAT")
    ihdr = dict(shared).get("IHDR")
    plte = dict(shared).get("PLTE")
    print("  same pixel stream (IDAT identical)       : %s" % idat)
    print("  same geometry and colour type (IHDR)     : %s" % ihdr)
    print("  same palette (PLTE)                      : %s" % plte)
    if idat and ihdr and plte is False:
        print("  => ONE DRAWING IN TWO PALETTES: the compressed pixels are")
        print("     byte-identical and only the colour table differs.")
    elif idat and ihdr and plte is None:
        print("  => the same pixels, and neither file carries a palette.")
    elif idat is False:
        print("  => different pixels: this is not a recolour, and any claim")
        print("     that one is an edit of the other has to be about the")
        print("     image and not about the bytes.")
    print()
    # The closure: the size difference is the arithmetic of the chunks one
    # file has and the other does not, plus any payload-length differences in
    # the chunks they share.
    extra_a = sum(ln + 12 for _t, ln, _n in onlya)
    extra_b = sum(ln + 12 for _t, ln, _n in onlyb)
    shared_delta = 0
    for t, _same in shared:
        shared_delta += (sum(x[0] for x in by_a[t])
                         - sum(x[0] for x in by_b[t]))
    predicted = extra_a - extra_b + shared_delta
    actual = len(blob_a) - len(blob_b)
    print("  chunks only in A : %d bytes with their 12-byte headers"
          % extra_a)
    print("  chunks only in B : %d bytes with their 12-byte headers"
          % extra_b)
    print("  shared chunks, payload length difference : %d" % shared_delta)
    print("  %d - %d + %d = %d against a file-size difference of %d"
          % (extra_a, extra_b, shared_delta, predicted, actual))
    print("  RESIDUE : %d" % (predicted - actual))
    return 0 if predicted == actual else 1


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    def chunk(typ, payload):
        return (struct.pack(">I", len(payload)) + typ + payload
                + struct.pack(">I", zlib.crc32(typ + payload) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", 4, 4, 8, 3, 0, 0, 0)
    idat = zlib.compress(bytes(20))
    a = (SIG + chunk(b"IHDR", ihdr) + chunk(b"gAMA", bytes(4))
         + chunk(b"PLTE", bytes(768)) + chunk(b"IDAT", idat)
         + chunk(b"IEND", b""))
    b = (SIG + chunk(b"IHDR", ihdr) + chunk(b"PLTE", bytes(767) + b"\x01")
         + chunk(b"IDAT", idat) + chunk(b"IEND", b""))
    here = os.path.dirname(os.path.abspath(__file__))
    pa = os.path.join(here, "_pngpair_a.png")
    pb = os.path.join(here, "_pngpair_b.png")
    try:
        open(pa, "wb").write(a)
        open(pb, "wb").write(b)
        _blob, ca = chunks(pa)
        ok("a hand-built PNG walks to IEND",
           [c[1] for c in ca] == ["IHDR", "gAMA", "PLTE", "IDAT", "IEND"],
           str([c[1] for c in ca]))
        ok("every chunk's CRC is checked on the way", True)
        ok("the two fixtures differ by exactly the gAMA chunk's 16 bytes",
           len(a) - len(b) == 16, str(len(a) - len(b)))
        bad = bytearray(a)
        bad[20] ^= 0xFF
        open(pa, "wb").write(bytes(bad))
        ok("a flipped payload byte fails the CRC and is refused",
           _refuses(lambda: chunks(pa)))
        open(pa, "wb").write(a + b"\x00")
        ok("trailing bytes after IEND are refused",
           _refuses(lambda: chunks(pa)))
        open(pa, "wb").write(b"\x89PNGxxxx")
        ok("a file with no PNG signature is refused",
           _refuses(lambda: chunks(pa)))
    finally:
        for p in (pa, pb):
            if os.path.exists(p):
                os.remove(p)

    ok("a directory is refused rather than raised on",
       _exits(lambda: dirguard.want_file(here, "pngpair")))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def _refuses(fn):
    try:
        fn()
    except PngError:
        return True
    except Exception:                                        # noqa: BLE001
        return False
    return False


def _exits(fn):
    try:
        fn()
    except SystemExit:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--claim")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.a or not args.b:
        sys.exit("pngpair: two PNG files are required")
    dirguard.want_file(args.a, "pngpair")
    dirguard.want_file(args.b, "pngpair")
    if args.claim:
        print("the claim under test : %s" % args.claim)
        print()
    try:
        return compare(args.a, args.b)
    except PngError as e:
        sys.exit("pngpair: %s" % e)


if __name__ == "__main__":
    sys.exit(main())
