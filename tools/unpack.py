#!/usr/bin/env python3
"""unpack.py - the decompressor for the members of `D1`..`D5`.

The routine is Delphine's own bit-stream unpacker, the one used across the
company's DOS/Amiga/ST titles. It is a public algorithm and this file says so;
the implementation below was written from the algorithm's description and is
validated here against the object, on every compressed member, with a checksum
the format carries itself.

Three things make it unusual and all three have to be right or nothing comes
out:

  * it reads the packed stream from the **end** toward the start, four bytes at
    a time, big-endian;
  * it writes the output from the **end** of the destination buffer toward the
    start, so back-references point *forward* in the buffer;
  * the trailer carries the unpacked length and a running XOR checksum, so the
    unpacked length is encoded twice in two unrelated places - once in the
    volume directory and once in the last four bytes of the packed block - and
    the two have to agree.

Trailer, at the end of the packed block, read backwards:

    [-4:]    u32 BE   unpacked size
    [-8:-4]  u32 BE   checksum seed
    [-12:-8] u32 BE   first bit chunk

Bit sequence -> effect (bits are consumed low-order first out of each chunk):

    0 0        literal run of (3 bits) + 1
    0 1        back-reference, length 2,            offset  8 bits
    1 00       back-reference, length 3,            offset  9 bits
    1 01       back-reference, length 4,            offset 10 bits
    1 10       back-reference, length (8 bits) + 1, offset 12 bits
    1 11       literal run of (8 bits) + 9

Usage:
    unpack.py validate <dir>            every compressed member, pass/fail
    unpack.py extract  <dir> <outdir>   write every member out
    unpack.py selftest <dir>            negative controls that must fail
"""
import sys
import os
import struct
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vol import Volume, volume_paths, VolumeError  # noqa: E402

MASK32 = 0xFFFFFFFF


class UnpackError(Exception):
    pass


class Unpacker:
    def __init__(self, src):
        if len(src) < 12:
            raise UnpackError("packed block of %d bytes has no trailer"
                              % len(src))
        self.src = src
        self.rd = len(src) - 4
        self.size = self._read32()
        self.crc = self._read32()
        self.chunk = self._read32()
        self.crc ^= self.chunk

    def _read32(self):
        if self.rd < 0 or self.rd + 4 > len(self.src):
            raise UnpackError("read past the start of the packed block")
        v = struct.unpack(">I", self.src[self.rd:self.rd + 4])[0]
        self.rd -= 4
        return v

    def _bit(self):
        bit = self.chunk & 1
        self.chunk >>= 1
        if self.chunk == 0:
            self.chunk = self._read32()
            self.crc ^= self.chunk
            bit = self.chunk & 1
            self.chunk = (self.chunk >> 1) | 0x80000000
        return bit

    def _bits(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | self._bit()
        return v

    def run(self, expected=None, strict=True):
        """Unpack. The trailer's length is the authority: it is the number the
        bit stream and the checksum agree on. `expected` is the volume
        directory's claim; with strict=True a disagreement is an error, with
        strict=False it is recorded and the trailer wins."""
        size = self.size
        self.declared = expected
        self.mismatch = (expected is not None and size != expected)
        if self.mismatch and strict:
            raise UnpackError("trailer says %d unpacked bytes, the directory "
                              "says %d" % (size, expected))
        dst = bytearray(size)
        wr = size - 1
        left = size
        while left > 0:
            if not self._bit():
                if not self._bit():
                    n = self._bits(3) + 1
                    left -= n
                    for _ in range(n):
                        if wr < 0:
                            raise UnpackError("wrote past the start of output")
                        dst[wr] = self._bits(8)
                        wr -= 1
                else:
                    off = self._bits(8)
                    left -= 2
                    for _ in range(2):
                        if wr < 0 or wr + off >= size:
                            raise UnpackError("back-reference out of range")
                        dst[wr] = dst[wr + off]
                        wr -= 1
            else:
                c = self._bits(2)
                if c == 3:
                    n = self._bits(8) + 9
                    left -= n
                    for _ in range(n):
                        if wr < 0:
                            raise UnpackError("wrote past the start of output")
                        dst[wr] = self._bits(8)
                        wr -= 1
                elif c < 2:
                    n = c + 3
                    off = self._bits(c + 9)
                    left -= n
                    for _ in range(n):
                        if wr < 0 or wr + off >= size:
                            raise UnpackError("back-reference out of range")
                        dst[wr] = dst[wr + off]
                        wr -= 1
                else:
                    n = self._bits(8) + 1
                    off = self._bits(12)
                    left -= n
                    for _ in range(n):
                        if wr < 0 or wr + off >= size:
                            raise UnpackError("back-reference out of range")
                        dst[wr] = dst[wr + off]
                        wr -= 1
        if left != 0:
            raise UnpackError("overshot the output by %d bytes" % -left)
        if wr != -1:
            raise UnpackError("write cursor ended at %d, expected -1" % wr)
        if self.crc != 0:
            raise UnpackError("checksum %08x, expected 0" % self.crc)
        return bytes(dst)


def unpack_member(raw, packed, unpacked):
    """Return the member's bytes. Stored members are returned as they are."""
    if packed == unpacked:
        return raw, "stored"
    return Unpacker(raw).run(expected=unpacked, strict=False), "unpacked"


def each_member(paths):
    for p in volume_paths(paths):
        v = Volume(p)
        probs = v.check()
        if probs:
            raise VolumeError("%s did not close: %s" % (v.name, probs[0]))
        for m in v.members:
            yield v, m, v.raw(m)


def cmd_validate(args):
    ok = bad = stored = 0
    agree = 0
    mism = []
    failures = []
    tot_in = tot_out = 0
    for v, m, raw in each_member(args.paths):
        if m.packed == m.unpacked:
            stored += 1
            continue
        try:
            u = Unpacker(raw)
            out = u.run(expected=m.unpacked, strict=False)
        except UnpackError as e:
            bad += 1
            failures.append((v.name, m.name, m.packed, m.unpacked, str(e)))
            continue
        ok += 1
        if u.mismatch:
            mism.append((v.name, m.name, m.packed, m.unpacked, len(out)))
        else:
            agree += 1
        tot_in += m.packed
        tot_out += len(out)
    n = ok + bad
    print("compressed members                       : %d" % n)
    print("  unpacked with checksum zero            : %d" % ok)
    print("  refused                                : %d" % bad)
    print("stored members (returned as they are)    : %d" % stored)
    print()
    print("the unpacked length is written twice - in the volume directory and")
    print("in the last four bytes of the packed block:")
    print("  the two agree                          : %d of %d" % (agree, n))
    print("  they disagree                          : %d of %d" % (len(mism), n))
    print("bytes %d -> %d (%.4fx)" % (tot_in, tot_out,
                                      tot_out / max(1, tot_in)))
    for f in failures:
        print("REFUSED  %s %s %d/%d: %s" % f)
    for vol, name, p, d, got in mism:
        print("DISAGREE %-3s %-14s packed %-6d directory %-6d trailer %-6d "
              "delta %+d" % (vol, name, p, d, got, got - d))
    print()
    print("result: %d of %d unpacked, %d of %d with both lengths agreeing"
          % (ok, n, agree, n))
    return 0 if bad == 0 else 1


def cmd_selftest(args):
    """The unpacker must refuse damaged input, not quietly return the right
    number of bytes."""
    victim = None
    for v, m, raw in each_member(args.paths):
        if m.packed != m.unpacked and 500 < m.packed < 20000:
            victim = (v, m, raw)
            break
    if victim is None:
        print("selftest found no suitable member", file=sys.stderr)
        return 1
    v, m, raw = victim
    good = Unpacker(raw).run(expected=m.unpacked, strict=False)
    print("control member: %s in %s, %d -> %d, sha1 %s"
          % (m.name, v.name, m.packed, len(good),
             hashlib.sha1(good).hexdigest()))
    fired = total = 0

    def expect_fail(label, blob, expected, strict=False):
        nonlocal fired, total
        total += 1
        try:
            out = Unpacker(blob).run(expected=expected, strict=strict)
            if out == good:
                print("%-40s ACCEPTED and identical <<< BUG" % label)
                return
            print("%-40s ACCEPTED but different output <<< WEAK" % label)
        except UnpackError as e:
            fired += 1
            print("%-40s REFUSED (%s)" % (label, e))
        except Exception as e:
            fired += 1
            print("%-40s REFUSED (%s: %s)" % (label, type(e).__name__, e))

    mid = len(raw) // 2
    flipped = bytearray(raw)
    flipped[mid] ^= 0x01
    expect_fail("one bit flipped in the middle", bytes(flipped), m.unpacked)

    trailer = bytearray(raw)
    trailer[-1] ^= 0x01
    expect_fail("last byte of the trailer flipped", bytes(trailer), None)

    expect_fail("directory length disagreeing by one",
                raw, Unpacker(raw).size + 1, strict=True)
    expect_fail("truncated by four bytes", raw[:-4], m.unpacked)
    expect_fail("read forwards instead of backwards",
                bytes(reversed(raw)), m.unpacked)
    stored = None
    for v2, m2, raw2 in each_member(args.paths):
        if m2.packed == m2.unpacked and m2.packed > 64:
            stored = (m2, raw2)
            break
    if stored is not None:
        expect_fail("a stored member fed to the unpacker",
                    stored[1], stored[0].unpacked, strict=True)
    print()
    print("negative controls that fired: %d of %d" % (fired, total))
    return 0 if fired == total else 1


def cmd_extract(args):
    out_root = args.paths[-1]
    src = args.paths[:-1]
    n = 0
    index = []
    refused = []
    for v, m, raw in each_member(src):
        try:
            data, how = unpack_member(raw, m.packed, m.unpacked)
        except UnpackError as e:
            refused.append((v.name, m.name, str(e)))
            continue
        if m.packed != m.unpacked and len(data) != m.unpacked:
            how = "unpacked-short"
        d = os.path.join(out_root, v.name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, m.name), "wb") as f:
            f.write(data)
        index.append((v.name, m.name, m.offset, m.packed, m.unpacked, how,
                      hashlib.sha1(raw).hexdigest(),
                      hashlib.sha1(data).hexdigest()))
        n += 1
    with open(os.path.join(out_root, "members.csv"), "w") as f:
        f.write("volume,name,offset,packed,unpacked,how,sha1_packed,"
                "sha1_unpacked\n")
        for row in index:
            f.write("%s,%s,%d,%d,%d,%s,%s,%s\n" % row)
    print("wrote %d members under %s" % (n, out_root))
    for r in refused:
        print("REFUSED %s %s: %s" % r)
    print("refused: %d" % len(refused))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "extract", "selftest"):
        s = sub.add_parser(name)
        s.add_argument("paths", nargs="+")
    args = ap.parse_args()
    try:
        return {"validate": cmd_validate, "extract": cmd_extract,
                "selftest": cmd_selftest}[args.cmd](args)
    except (VolumeError, UnpackError) as e:
        print("unpack.py: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
