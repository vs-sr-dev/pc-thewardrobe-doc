#!/usr/bin/env python3
"""steve.py -- the `STEVE` sound record of the MS-DOS Links release.

WHAT IS MEASURED, AND WHAT IS NOT

Thirty-six members of `sounds.lz` and thirteen members of `title.lnx` open with
the five bytes `53 54 45 56 45`. Everything below is a measurement over all 49
of them; the naming of the format is NOT one, and this tool does not do it.

    +0   5 bytes   'STEVE'
    +5   u8        2 on 44 of 49, 3 on 5
    +6   u8        0x48 on 49 of 49
    +7   u32 LE    a length: payload bytes on 45 of 49, whole-record bytes on 4
    +11  21 bytes  varies, 8 distinct values over 49 members, and the bytes
                   read as 8086 instructions -- `83 c4 04`, `80 7e 04 0a`
    +32            the payload, to end of record

**The 32-byte header size is measured, not assumed.** For each of the 49
members, the largest offset k such that every byte from k on is <= 70 is
exactly 32. See `--header`.

WHY THE PAYLOAD IS AN AMPLITUDE STREAM AND NOT CODE

  * every payload byte over all 49 members lies in 0..69, and all 70 levels
    occur -- 130,503 bytes in the 36 `.RS` members alone;
  * the distribution is unimodal about 31.64, which is code-like in nothing;
  * and the known-answer control settles it: **`SILENCE.RS` is 499 bytes of the
    single value 34 and one byte of 0**, entropy 0.021 bits, two distinct
    values, the lowest of the 36 by a factor of 170. A member called SILENCE
    that is a constant is the degenerate case of an amplitude stream. It is not
    the degenerate case of anything else.

  34 is the midpoint of 0..69, so silence sits at mid-scale: the stream is
  UNSIGNED amplitude, and this tool converts it by scaling 0..69 onto 0..255.

WHAT THIS TOOL REFUSES TO SAY

  **The sample rate is not in the header, and this tool does not know it.**
  `--rate` defaults to 5000 Hz because a 2,000-sample `QUACK1` and a
  6,900-sample `GOTAHOLD` come out at plausible durations there, which is a
  guess dressed as arithmetic. Anything written with the default is labelled.

    python tools/steve.py FILE...                 validate, one line each
    python tools/steve.py FILE... --header        show the header-size proof
    python tools/steve.py FILE... --wav DIR [--rate N]
"""
import argparse
import collections
import math
import os
import struct
import sys

MAGIC = b"STEVE"
HEADER = 32
LEVELS = 70          # measured: payload bytes span 0..69 inclusive


class SteveError(Exception):
    pass


def parse(data, name="<data>"):
    if len(data) < HEADER:
        raise SteveError("%s: %d bytes cannot hold a %d-byte header"
                         % (name, len(data), HEADER))
    if data[:5] != MAGIC:
        raise SteveError("%s: no STEVE magic (found %r)" % (name, data[:5]))
    variant, const = data[5], data[6]
    if const != 0x48:
        raise SteveError("%s: byte +6 is %d, not 0x48 as on 49 of 49 measured "
                         "members" % (name, const))
    declared = struct.unpack_from("<I", data, 7)[0]
    payload = data[HEADER:]
    if declared == len(payload):
        closes = "payload"
    elif declared == len(data):
        closes = "record"
    else:
        raise SteveError("%s: length field %d matches neither the payload "
                         "(%d) nor the record (%d)"
                         % (name, declared, len(payload), len(data)))
    hi = max(payload) if payload else 0
    if hi >= LEVELS:
        raise SteveError("%s: payload byte %d is outside the measured 0..%d "
                         "amplitude range" % (name, hi, LEVELS - 1))
    return variant, declared, closes, payload


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def header_proof(data):
    """The largest k with every byte from k on <= 70, computed not assumed."""
    k = len(data)
    while k > 0 and data[k - 1] < LEVELS + 1:
        k -= 1
    return k


def write_wav(path, payload, rate):
    pcm = bytes(bytearray(min(255, v * 255 // (LEVELS - 1)) for v in payload))
    n = len(pcm)
    hdr = (b"RIFF" + struct.pack("<I", 36 + n) + b"WAVEfmt "
           + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate, 1, 8)
           + b"data" + struct.pack("<I", n))
    with open(path, "wb") as fh:
        fh.write(hdr + pcm)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--wav", metavar="DIR")
    ap.add_argument("--rate", type=int, default=5000)
    ap.add_argument("--header", action="store_true")
    ap.add_argument("--expect-ok", type=int)
    a = ap.parse_args()

    if a.wav:
        os.makedirs(a.wav, exist_ok=True)
    ok = bad = 0
    tot = 0
    heads = collections.Counter()
    print("%-16s %8s %3s %8s %-8s %8s %4s %5s"
          % ("member", "bytes", "v", "length", "closes", "entropy", "max", "lvls"))
    for p in a.files:
        name = os.path.basename(p)
        data = open(p, "rb").read()
        try:
            variant, declared, closes, payload = parse(data, name)
        except SteveError as e:
            bad += 1
            print("REFUSED  %s" % e)
            continue
        ok += 1
        tot += len(payload)
        heads[header_proof(data)] += 1
        print("%-16s %8d %3d %8d %-8s %8.3f %4d %5d"
              % (name, len(data), variant, declared, closes,
                 entropy(payload), max(payload) if payload else 0,
                 len(set(payload))))
        if a.wav:
            write_wav(os.path.join(a.wav, name + ".wav"), payload, a.rate)

    print()
    print("steve: %d accepted, %d refused, %d payload bytes"
          % (ok, bad, tot))
    if a.header:
        print("header size, computed as the last offset after which every "
              "byte is <= %d:" % LEVELS)
        for k, v in sorted(heads.items()):
            print("   %3d bytes on %d members" % (k, v))
    if a.wav:
        print("wav: %d files at %d Hz -- THE RATE IS A GUESS, not a field"
              % (ok, a.rate))
    if a.expect_ok is not None and ok != a.expect_ok:
        raise SystemExit("steve: expected %d accepted, got %d"
                         % (a.expect_ok, ok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
