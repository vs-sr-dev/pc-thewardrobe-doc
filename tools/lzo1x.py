#!/usr/bin/env python3
"""lzo1x.py -- a decompressor for the LZO1X bit-stream, in pure Python.

WHY THIS FILE EXISTS
--------------------
The 109 compressed Unreal packages in this object declare
`CompressionFlags = 2`, and in UE3 that constant is `COMPRESS_LZO`. There is
no `lzo` module in this interpreter and `zlib` cannot read the stream, so the
choice was between not opening 51 % of the object and writing the decoder.

PROVENANCE, STATED PLAINLY
--------------------------
The LZO1X **format** is public: the decompression algorithm is published in
Markus Oberhumer's LZO and miniLZO sources and has been re-implemented many
times. This file is a transcription of that published algorithm into Python.
It is NOT derived from the object, and no document in this repository may
claim that the LZO1X bit-stream was reverse-engineered here. What WAS derived
from the object is that these packages use it at all, and that is a different
sentence.

The stream is a sequence of instructions, each of which either copies literal
bytes from the input or copies a run from the output produced so far:

    first byte > 17          a literal run of (byte - 17)
    t >= 64                  M4-ish short match, 3-bit length, 8-bit offset
    32 <= t < 64             long match, 16-bit offset, extendable length
    16 <= t < 32             match with a 14-bit-plus offset; the end-of-stream
                             marker lives in this branch
    t < 16                   after a match: a two-byte match; otherwise a
                             literal run whose length is extendable by
                             counting zero bytes

The two-low-bits trailer (`t = ip[-2] & 3`) after every match is the number of
literals that follow it immediately, and it is the part every naive
re-implementation gets wrong.

FAILURE IS LOUD
---------------
Every read past the end of the input, every back-reference before the start of
the output and every stream that ends without the end-of-stream marker raises
`LzoError`. A decoder that returns short output quietly would have produced a
plausible wrong answer on 371,299 exports, which is the exact failure mode the
rules of this pipeline are written against.

    python tools/lzo1x.py --selftest
"""
import argparse
import struct
import sys


class LzoError(Exception):
    pass


def decompress(src, expected=None):
    """Decode one LZO1X stream. `expected`, when given, is checked."""
    src = memoryview(bytes(src))
    n = len(src)
    out = bytearray()
    ip = 0

    def need(k):
        if ip + k > n:
            raise LzoError("input overrun: want %d bytes at %d of %d"
                           % (k, ip, n))

    def copy_match(m_pos, count):
        if m_pos < 0:
            raise LzoError("back-reference before the start of the output: "
                           "%d (output is %d bytes)" % (m_pos, len(out)))
        # Overlapping copies are legal and are the whole point of LZ77. The
        # non-overlapping case is the common one and is a slice; only the
        # overlapping case has to go a byte at a time. Doing both by hand
        # made this decoder four times slower than it needed to be, which on
        # 4.4 gigabytes is the difference between a command and an afternoon.
        # `out.extend`, not `out +=`: the augmented form makes `out` a local
        # of this closure and the selftest caught it on the first run.
        if m_pos + count <= len(out):
            out.extend(out[m_pos:m_pos + count])
            return
        for _ in range(count):
            out.append(out[m_pos])
            m_pos += 1

    state = 0            # literals copied by the previous instruction
    first = True

    if src[0] > 17:
        t = src[0] - 17
        ip = 1
        if t < 4:
            state = t
            # fall through to match_next
            need(t)
            out += src[ip:ip + t]
            ip += t
            need(1)
            t = src[ip]
            ip += 1
            first = False
            goto_match = True
        else:
            need(t)
            out += src[ip:ip + t]
            ip += t
            state = 4
            need(1)
            t = src[ip]
            ip += 1
            if t >= 16:
                goto_match = True
            else:
                # first_literal_run's M2 case
                m_pos = len(out) - (1 + 0x0800) - (t >> 2)
                need(1)
                m_pos -= src[ip] << 2
                ip += 1
                copy_match(m_pos, 3)
                goto_match = False
                t = src[ip - 2] & 3
                state = t
                if t:
                    need(t)
                    out += src[ip:ip + t]
                    ip += t
                    need(1)
                    t = src[ip]
                    ip += 1
                    goto_match = True
            first = False
    else:
        goto_match = False
        t = 0

    while True:
        if not goto_match:
            need(1)
            t = src[ip]
            ip += 1
            if t < 16:
                if t == 0:
                    while True:
                        need(1)
                        if src[ip] != 0:
                            break
                        t += 255
                        ip += 1
                        if t > (1 << 26):
                            raise LzoError("literal run length ran away")
                    t += 15 + src[ip]
                    ip += 1
                t += 3
                need(t)
                out += src[ip:ip + t]
                ip += t
                state = 4
                need(1)
                t = src[ip]
                ip += 1
                if t < 16:
                    m_pos = len(out) - (1 + 0x0800) - (t >> 2)
                    need(1)
                    m_pos -= src[ip] << 2
                    ip += 1
                    copy_match(m_pos, 3)
                    t = src[ip - 2] & 3
                    state = t
                    if t == 0:
                        continue
                    need(t)
                    out += src[ip:ip + t]
                    ip += t
                    need(1)
                    t = src[ip]
                    ip += 1
        goto_match = False

        # ---- match ----
        while True:
            if t >= 64:
                m_pos = len(out) - 1 - ((t >> 2) & 7)
                need(1)
                m_pos -= src[ip] << 3
                ip += 1
                count = (t >> 5) - 1 + 2
            elif t >= 32:
                t &= 31
                if t == 0:
                    while True:
                        need(1)
                        if src[ip] != 0:
                            break
                        t += 255
                        ip += 1
                        if t > (1 << 26):
                            raise LzoError("match length ran away")
                    t += 31 + src[ip]
                    ip += 1
                need(2)
                m_pos = len(out) - 1 - (struct.unpack_from("<H", src, ip)[0] >> 2)
                ip += 2
                count = t + 2
            elif t >= 16:
                m_pos = len(out) - ((t & 8) << 11)
                t &= 7
                if t == 0:
                    while True:
                        need(1)
                        if src[ip] != 0:
                            break
                        t += 255
                        ip += 1
                        if t > (1 << 26):
                            raise LzoError("match length ran away")
                    t += 7 + src[ip]
                    ip += 1
                need(2)
                m_pos -= struct.unpack_from("<H", src, ip)[0] >> 2
                ip += 2
                if m_pos == len(out):
                    # end-of-stream marker
                    if expected is not None and len(out) != expected:
                        raise LzoError("stream ended at %d bytes, expected %d"
                                       % (len(out), expected))
                    if ip != n:
                        raise LzoError("stream ended with %d input bytes left"
                                       % (n - ip))
                    return bytes(out)
                m_pos -= 0x4000
                count = t + 2
            else:
                m_pos = len(out) - 1 - (t >> 2)
                need(1)
                m_pos -= src[ip] << 2
                ip += 1
                copy_match(m_pos, 2)
                t = src[ip - 2] & 3
                state = t
                if t == 0:
                    break
                need(t)
                out += src[ip:ip + t]
                ip += t
                need(1)
                t = src[ip]
                ip += 1
                continue
            copy_match(m_pos, count)
            t = src[ip - 2] & 3
            state = t
            if t == 0:
                break
            need(t)
            out += src[ip:ip + t]
            ip += t
            need(1)
            t = src[ip]
            ip += 1
        # loop back to the literal-run reader
    raise LzoError("unreachable")


# ---------------------------------------------------------------- selftest

def _literal_stream(payload):
    """Build a valid LZO1X stream that is one literal run plus the EOS mark.

    This is the one encoder shape this file needs, and writing it is how the
    decoder gets tested without a compressor: encode, decode, compare.
    """
    out = bytearray()
    t = len(payload)
    if t < 4:
        raise ValueError("this toy encoder needs at least 4 literals")
    if t <= 238:
        out.append(t + 17)
    else:
        out.append(0)
        t2 = t - 3
        if t2 < 18:
            raise ValueError("bad length for the zero-extension form")
        rem = t2 - 18
        while rem >= 255:
            out.append(0)
            rem -= 255
        out.append(rem + 1 if False else rem)
        # the zero-run form is: 0, then k zero bytes, then (rem) where
        # length = 3 + 15 + 255*k + rem
        out = bytearray([0])
        rem = t - 3 - 15
        while rem > 255:
            out.append(0)
            rem -= 255
        out.append(rem)
    out += payload
    # end of stream: 0x11, 0x00, 0x00
    out += bytes([0x11, 0x00, 0x00])
    return bytes(out)


def selftest():
    specimens = []

    # 1. round trip, short literal run
    p = bytes(range(64))
    specimens.append(("short literal run, 64 bytes", _literal_stream(p), p, True))

    # 2. round trip, long literal run through the zero-extension form
    p = bytes((i * 7 + 3) & 0xFF for i in range(1000))
    specimens.append(("long literal run, 1000 bytes", _literal_stream(p), p, True))

    # 3. a real back-reference: literals then an M2 match repeating them
    #    18 literals ('A'*18), then M3 (t=32|len) offset 1 -> RLE
    body = bytearray()
    body.append(4 + 17)          # literal run of 4
    body += b"ABCD"
    # M3: t in [32,63], t&31 = length-2 ; offset16 = (dist-1)<<2
    body.append(32 | 6)          # length 8
    body += struct.pack("<H", (4 - 1) << 2)   # distance 4
    body += bytes([0x11, 0x00, 0x00])
    specimens.append(("match, distance 4 length 8", bytes(body),
                      b"ABCD" * 3, True))

    # 4. truncated input -- must be refused
    specimens.append(("truncated stream", _literal_stream(bytes(64))[:10],
                      None, False))

    # 5. back-reference before the start of the output -- must be refused
    bad = bytearray()
    bad.append(4 + 17)
    bad += b"ABCD"
    bad.append(32 | 6)
    bad += struct.pack("<H", (900 - 1) << 2)   # distance 900, output is 4
    bad += bytes([0x11, 0x00, 0x00])
    specimens.append(("back-reference before the output", bytes(bad),
                      None, False))

    # 6. no end-of-stream marker -- must be refused
    specimens.append(("no end-of-stream marker",
                      _literal_stream(bytes(range(64)))[:-3], None, False))

    # 7. trailing garbage after the end-of-stream marker -- must be refused
    specimens.append(("trailing bytes after EOS",
                      _literal_stream(bytes(range(64))) + b"\x00\x00",
                      None, False))

    # 8. expected-length mismatch -- must be refused
    specimens.append(("declared length disagrees",
                      _literal_stream(bytes(range(64))), 65, False))

    ok = 0
    accepted = 0
    refused = 0
    print("lzo1x selftest: %d specimens built in memory" % len(specimens))
    for name, stream, want, should_pass in specimens:
        try:
            if name == "declared length disagrees":
                got = decompress(stream, expected=want)
            else:
                got = decompress(stream)
            passed = should_pass and (want is None or got == want)
            note = "accepted, %d bytes out" % len(got)
            if should_pass and want is not None and got != want:
                note = "accepted but WRONG: %r" % got[:32]
            accepted += 1
        except LzoError as e:
            passed = not should_pass
            note = "refused: %s" % e
            refused += 1
        print("  %-38s %-9s %s" % (name, "PASS" if passed else "FAIL", note))
        ok += 1 if passed else 0
    print()
    print("accepted %d, refused %d, of %d -- and the refusals are the point"
          % (accepted, refused, len(specimens)))
    print("%d of %d specimens behaved as required" % (ok, len(specimens)))
    return 0 if ok == len(specimens) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
