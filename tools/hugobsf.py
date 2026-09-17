#!/usr/bin/env python3
"""hugobsf.py -- read `HUGO.BSF`, the 381 encrypted bytes *Hugo's House of
Horrors* will not start without.

**This reader was written from the bytes of this object.** It is not
`pc-nitemare3d-doc/tools/n3dbsf.py` copied or adapted; that repository's
chapter 08 is an **attributed reference** to a finding about a *different*
file -- `NITE3D.BSF`, 15,792 bytes, 1995, the same author two years later --
and a tool written for one object is a hypothesis about the next one, not a
result about it. What was taken from that chapter is two facts and one
warning:

  * the cipher is XOR against a 52-byte ASCII key which is the author's own
    copyright string, and that string is in this object's own executable;
  * the file is a header followed by chunks, and the header's XOR checksum
    **of the ciphertext** must come out 0;
  * **a whole-file XOR never works**, because the key phase restarts at every
    chunk boundary instead of running continuously.

Everything else here -- the header length, the chunk count, where the length
field sits -- was measured on `HUGO.BSF` and is different from the 1995 file's.

What is measured, and each figure has a command in `docs/08`:

    key           52 bytes at offset 112848 of HHH.EXE, taken from the
                  executable and not from the other repository
    header        44 bytes, its ciphertext XOR checksum 0x00
    chunks        one, at offset 44, 337 bytes, its length a u16 at header+42
    tiling        44 + 337 = 381, residue 0

    python tools/hugobsf.py info   <dir>
    python tools/hugobsf.py text   <dir>
    python tools/hugobsf.py header <dir>
    python tools/hugobsf.py --selftest
"""
import argparse
import os
import struct
import sys

KEY_OFFSET = 112848
KEY_LEN = 52
HEADER_LEN = 44
LEN_AT = 42                  # u16, offset of the chunk length inside the header


class Bad(Exception):
    """Not this file. Raised, never swallowed."""


def xor_checksum(data, seed=0):
    acc = seed
    for b in data:
        acc ^= b
    return acc


def decode(seg, key):
    """XOR against the key with the phase starting at 0 for THIS buffer.

    The phase is the offset within the buffer being decoded, not within the
    file. That single fact is why a whole-file XOR produces noise, and it is
    the only thing about this scheme that is not obvious.
    """
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(seg))


def read_key(exe_path):
    exe = open(exe_path, "rb").read()
    key = exe[KEY_OFFSET:KEY_OFFSET + KEY_LEN]
    if len(key) != KEY_LEN:
        raise Bad("%s is too short to hold the key at %d"
                  % (exe_path, KEY_OFFSET))
    if not all(32 <= b < 127 for b in key):
        raise Bad("the 52 bytes at %d of %s are not ASCII: %r"
                  % (KEY_OFFSET, exe_path, key))
    return key


def open_bsf(buf, key):
    if len(buf) < HEADER_LEN + 1:
        raise Bad("%d bytes: too short to be a header and a chunk" % len(buf))
    chk = xor_checksum(buf[:HEADER_LEN])
    if chk != 0:
        raise Bad("the header's ciphertext XOR checksum is 0x%02x, not 0x00 "
                  "-- this is not a Gray .BSF, or the key region is wrong"
                  % chk)
    hdr = decode(buf[:HEADER_LEN], key)
    length = struct.unpack("<H", hdr[LEN_AT:LEN_AT + 2])[0]
    if HEADER_LEN + length != len(buf):
        raise Bad("header says %d bytes of chunk; %d + %d = %d against a file "
                  "of %d -- the chunks do not tile"
                  % (length, HEADER_LEN, length, HEADER_LEN + length,
                     len(buf)))
    body = decode(buf[HEADER_LEN:HEADER_LEN + length], key)
    return hdr, body, length


def find(d, name):
    p = os.path.join(d, name)
    if not os.path.exists(p):
        raise SystemExit("hugobsf: %s is not in %s" % (name, d))
    return p


def load(args):
    key = read_key(find(args.dir, "HHH.EXE"))
    buf = open(find(args.dir, "HUGO.BSF"), "rb").read()
    return key, buf, open_bsf(buf, key)


def cmd_info(args):
    key, buf, (hdr, body, length) = load(args)
    exe = open(find(args.dir, "HHH.EXE"), "rb").read()
    print("key            : %r" % key.decode("ascii"))
    print("                 %d bytes, from HHH.EXE offset %d"
          % (len(key), KEY_OFFSET))
    print("file           : HUGO.BSF, %d bytes" % len(buf))
    print("header         : %d bytes, ciphertext XOR 0x%02x  (valid)"
          % (HEADER_LEN, xor_checksum(buf[:HEADER_LEN])))
    print("chunk length   : %d, from the u16 at header+%d" % (length, LEN_AT))
    print("tiling         : %d + %d = %d, residue %d"
          % (HEADER_LEN, length, HEADER_LEN + length,
             len(buf) - HEADER_LEN - length))
    print("plaintext      : %d printable of %d = %.2f %%"
          % (sum(1 for c in body if 32 <= c < 127 or c in (9, 10, 13)),
             len(body),
             100.0 * sum(1 for c in body
                         if 32 <= c < 127 or c in (9, 10, 13)) / len(body)))
    print()
    print("the whole-file XOR that never works, at its best of 52 phases:")
    best = max(
        (sum(1 for i, c in enumerate(buf)
             if 32 <= (c ^ key[(i + p) % KEY_LEN]) < 127), p)
        for p in range(KEY_LEN))
    print("  phase %-2d : %d printable of %d -- and the 44 header bytes are "
          "never among them" % (best[1], best[0], len(buf)))
    print()
    print("HHH.EXE byte-wise XOR : 0x%02x   (%d bytes)"
          % (xor_checksum(exe), len(exe)))
    print("  seeded with 0x7B -- the constant the 1995 tamper routine uses --")
    print("  it comes out 0x%02x. That is a 1-in-256 coincidence or it is the"
          % xor_checksum(exe, 0x7B))
    print("  mechanism; this object cannot tell which, and docs/08 says so.")
    return 0


def cmd_text(args):
    _, _, (hdr, body, length) = load(args)
    sys.stdout.write(body.decode("cp437"))
    return 0


def cmd_header(args):
    _, buf, (hdr, body, length) = load(args)
    print("ciphertext : %s" % " ".join("%02x" % c for c in buf[:HEADER_LEN]))
    print("plaintext  : %s" % " ".join("%02x" % c for c in hdr))
    print("as text    : %s"
          % "".join(chr(c) if 32 <= c < 127 else "." for c in hdr))
    print()
    print("+%-2d u16 = %d   the chunk length, and the only field this object "
          "closes" % (LEN_AT, struct.unpack("<H", hdr[LEN_AT:LEN_AT + 2])[0]))
    print("the other 42 bytes are not parsed. See docs/16 -- what would close")
    print("them is a second .BSF from another release of the same game.")
    return 0


def selftest():
    """Specimens that must fail, run before any real file is quoted."""
    key = b"K" * KEY_LEN
    fails = 0
    for label, buf in (
            ("empty", b""),
            ("too short", b"\x00" * 40),
            ("checksum not zero", b"\x01" + b"\x00" * 43 + b"x"),
            ("chunks do not tile", bytes([0x00] * 42 + [0xFF, 0xFF]) + b"x"),
    ):
        try:
            open_bsf(buf, key)
        except Bad as e:
            print("  refused %-20s %s" % (label, e))
            continue
        print("  ACCEPTED %-19s -- the reader is lying" % label)
        fails += 1
    plain = bytearray(HEADER_LEN)
    plain[LEN_AT:LEN_AT + 2] = struct.pack("<H", 3)
    good = bytearray(decode(bytes(plain), key))
    good[0] ^= xor_checksum(good)             # make the header XOR come out 0
    good += decode(b"abc", key)
    try:
        hdr, body, n = open_bsf(bytes(good), key)
        print("  accepted %-19s header 44, chunk %d, residue 0"
              % ("positive control", n))
    except Bad as e:
        print("  REFUSED the positive control: %s" % e)
        fails += 1
    print()
    print("selftest: %d failure(s)" % fails)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    for name in ("info", "text", "header"):
        s = sub.add_parser(name)
        s.add_argument("dir")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        return {"info": cmd_info, "text": cmd_text,
                "header": cmd_header}[args.cmd](args)
    except Bad as e:
        print("hugobsf: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
