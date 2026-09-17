#!/usr/bin/env python3
"""pngchunk.py -- find a named PNG chunk across a tree, verify its CRC
independently, and dump what it holds.

`pngcensus.py` counts chunk types over a whole library and reports, on this
object, `tIME 1` and `tpNg 1` out of 1,848 chunks. A count of one is an
invitation and not an answer: **which file, at what offset, and what is in it**
are three further questions, and one of the two type codes is in no PNG
specification at all.

The CRC is recomputed here from `zlib.crc32` over `type + data`, deliberately
by a different route from `pngcensus.py`, because "the CRC verifies" is the
whole reason a four-byte type nobody has registered has to be taken seriously
rather than dismissed as damage.

`tIME` is decoded per the PNG specification: seven bytes, a big-endian u16 year
then five u8. Anything else is dumped as bytes and as text, and this tool does
not guess.

    python tools/pngchunk.py <root> --type tIME
    python tools/pngchunk.py <root> --type tpNg --dump
    python tools/pngchunk.py <root> --list-types
    python tools/pngchunk.py --selftest
"""
import argparse
import os
import struct
import sys
import zlib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

SIG = b"\x89PNG\r\n\x1a\n"

# The chunk types PNG registers, so that "not in any specification" is a
# statement this tool can make rather than one the prose has to assert.
REGISTERED = {
    "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT",
    "sRGB", "tEXt", "zTXt", "iTXt", "bKGD", "hIST", "pHYs", "sPLT", "tIME",
    "acTL", "fcTL", "fdAT", "eXIf", "cICP", "mDCv", "cLLi",
}


class Bad(Exception):
    pass


def walk(blob):
    """Yield (type, offset, length, data, crc_declared, crc_computed)."""
    if not blob.startswith(SIG):
        raise Bad("no PNG signature")
    p = len(SIG)
    while p < len(blob):
        if p + 8 > len(blob):
            raise Bad("a chunk header runs off the end at %d" % p)
        (length,) = struct.unpack(">I", blob[p:p + 4])
        ctype = blob[p + 4:p + 8]
        d0 = p + 8
        if d0 + length + 4 > len(blob):
            raise Bad("chunk %r at %d declares %d bytes and only %d remain"
                      % (ctype, p, length, len(blob) - d0))
        data = blob[d0:d0 + length]
        (declared,) = struct.unpack(">I", blob[d0 + length:d0 + length + 4])
        computed = zlib.crc32(ctype + data) & 0xFFFFFFFF
        yield (ctype.decode("latin-1"), p, length, data, declared, computed)
        p = d0 + length + 4
        if ctype == b"IEND":
            break
    if p != len(blob):
        raise Bad("the walk ends at %d of %d" % (p, len(blob)))


def files(root):
    if os.path.isfile(root):
        yield root
        return
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            if f.lower().endswith(".png"):
                yield os.path.join(dp, f)


def decode_time(data):
    if len(data) != 7:
        return "tIME is specified as seven bytes and this one is %d" % len(data)
    year, month, day, hour, minute, second = struct.unpack(">HBBBBB", data)
    return ("%04d-%02d-%02d %02d:%02d:%02d UTC"
            % (year, month, day, hour, minute, second))


def dump(data, limit=256):
    out = []
    for off in range(0, min(len(data), limit), 16):
        row = data[off:off + 16]
        h = " ".join("%02x" % c for c in row)
        t = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
        out.append("      %04x  %-47s  |%s|" % (off, h, t))
    if len(data) > limit:
        out.append("      ... %d further bytes" % (len(data) - limit))
    return "\n".join(out)


def run(args):
    seen = 0
    hits = 0
    types = {}
    bad_crc = 0
    for path in files(args.root):
        blob = open(path, "rb").read()
        seen += 1
        try:
            for ctype, off, length, data, declared, computed in walk(blob):
                types[ctype] = types.get(ctype, 0) + 1
                if declared != computed:
                    bad_crc += 1
                if args.type and ctype != args.type:
                    continue
                if not args.type:
                    continue
                hits += 1
                rel = os.path.relpath(path, args.root
                                      if os.path.isdir(args.root)
                                      else os.path.dirname(args.root))
                print("file          : %s" % rel.replace(os.sep, "/"))
                print("chunk         : %s at byte offset %d, length %d"
                      % (ctype, off, length))
                print("CRC declared  : %08x" % declared)
                print("CRC computed  : %08x   %s"
                      % (computed,
                         "VERIFIES" if declared == computed else "DOES NOT"))
                print("registered in the PNG specification : %s"
                      % ("yes" if ctype in REGISTERED else "NO"))
                if ctype == "tIME":
                    print("decoded       : %s" % decode_time(data))
                if args.dump or ctype not in REGISTERED:
                    print("payload:")
                    print(dump(data))
                    try:
                        print("as text       : %r" % data.decode("ascii"))
                    except Exception:
                        pass
                print()
        except Bad as e:
            print("REFUSED %s : %s" % (path, e))
    if args.list_types:
        print("  %-6s %6s  %s" % ("type", "count", "registered"))
        for t in sorted(types, key=lambda k: (-types[k], k)):
            print("  %-6s %6d  %s" % (t, types[t],
                                      "yes" if t in REGISTERED else "NO"))
    print("files walked : %d" % seen)
    print("chunks seen  : %d" % sum(types.values()))
    print("CRC failures : %d" % bad_crc)
    if args.type:
        print("occurrences of %s : %d" % (args.type, hits))
        if args.expect is not None and hits != args.expect:
            raise SystemExit("FATAL: --expect %d, got %d" % (args.expect, hits))
    return 0


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    def chunk(ctype, data):
        return (struct.pack(">I", len(data)) + ctype + data +
                struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 3, 0, 0, 0)
    tim = struct.pack(">HBBBBB", 2000, 5, 19, 12, 44, 9)
    blob = (SIG + chunk(b"IHDR", ihdr) + chunk(b"PLTE", b"\x00\x00\x00") +
            chunk(b"tIME", tim) + chunk(b"tpNg", b"hello") +
            chunk(b"IDAT", b"\x00") + chunk(b"IEND", b""))
    rows = list(walk(blob))
    check("six chunks walked", len(rows), 6)
    check("every CRC verifies",
          all(r[4] == r[5] for r in rows), True)
    check("tIME decodes to the specified reading",
          decode_time(tim), "2000-05-19 12:44:09 UTC")
    check("tpNg is not registered", "tpNg" in REGISTERED, False)
    check("tIME is registered", "tIME" in REGISTERED, True)
    check("the tpNg payload survives",
          [r[3] for r in rows if r[0] == "tpNg"], [b"hello"])

    # a corrupted CRC must be caught, not silently accepted
    bad = bytearray(blob)
    bad[-5] ^= 0xFF
    rows2 = list(walk(bytes(bad)))
    check("a flipped byte breaks exactly one CRC",
          sum(1 for r in rows2 if r[4] != r[5]), 1)

    # no signature
    try:
        list(walk(b"not a png at all"))
        got = "no exception"
    except Bad:
        got = "Bad"
    check("a file with no signature is refused", got, "Bad")

    # truncated
    try:
        list(walk(blob[:20]))
        got = "no exception"
    except Bad:
        got = "Bad"
    check("a truncated file is refused", got, "Bad")

    check("a tIME of the wrong length is reported, not decoded",
          decode_time(b"\x00\x00").startswith("tIME is specified"), True)

    bad_n = 0
    for name, ok, got, want in checks:
        print("  %-48s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad_n += 1
    print("checks : %d   failures : %d" % (len(checks), bad_n))
    raise SystemExit(1 if bad_n else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?")
    ap.add_argument("--type")
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--list-types", action="store_true")
    ap.add_argument("--expect", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.root == "selftest":
        return selftest()
    if not args.root:
        raise SystemExit("pngchunk: a root is required (or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
