#!/usr/bin/env python3
"""pakdec.py -- the .PAK container of Resident Evil PC, decompressed and checked.

**The format is public and this tool uses the published definition**, as the
branch's rule 4 requires it to say. The description and a reference decoder in C
are on the Archive Team file-format wiki's page for the Resident Evil `.PAK`
format; the C is itself credited there as descended from ScummVM's LZW decoder.
What is *derived here* is everything downstream: that the output is a TIM, that
it closes on the byte under `timtmd.py`'s arithmetic, and what the population
looks like.

Before the description was in hand this repository had measured the following
from the bytes alone, and the measurements agree with it, which is why they are
kept here rather than deleted:

  * every one of the 1,112 files begins `08 00 20 80` and has an entropy of
    7.6 to 7.98 bits per byte, so it is entropy-coded, not stored;
  * in a 42,638-byte specimen, **42,632 of 42,634 four-byte sequences are
    distinct** -- there is essentially no repetition at byte granularity, which
    rules out an LZ77-style scheme that emits literal bytes;
  * the tail of a file falls into a run with a period of exactly **40 bits**
    whose successive groups differ by exactly 0x0040100401, i.e. bits 0, 10, 20
    and 30. Four fields of ten bits each, each one greater than the last. That
    is a dictionary coder emitting consecutive new codes at a ten-bit width;
  * read as nine-bit big-endian codes from bit zero, the first code of every
    file is **16 = 0x10** and the next three are zero -- which is `10 00 00 00`,
    the PlayStation TIM identifier, before any decompression at all.

The published algorithm, restated:

  bits are read most-significant first, continuously across the byte stream;
  the code width starts at **9**; the dictionary starts empty with the next
  free code at **0x103**; three codes are control codes and not dictionary
  entries:

      0x100   end of stream
      0x101   increase the code width by one bit
      0x102   flush: reinitialise the dictionary, reset the width to 9, and
              start again with a fresh first code

  otherwise the usual LZW: a code below the next-free code expands through the
  (index, value) chain; a code equal to it is the KwKwK case and expands the
  previous string plus its own first byte; after each expansion a new entry
  (previous code, first byte of this expansion) is added.

Note what is *absent*: there is no clear-code-on-full behaviour and no maximum
width in the algorithm itself -- the width only ever grows when the encoder
says so with 0x101.

    python tools/pakdec.py FILE --out OUT.tim
    python tools/pakdec.py DIR --census
    python tools/pakdec.py DIR --census --dump _work/paktim
"""

import argparse
import collections
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from timtmd import tim_at                      # noqa: E402


def tim_shape(out):
    """Read a decoded PAK as a TIM under BOTH bnum conventions.

    Sony's definition makes `bnum` the length of the whole block, header
    included: 12 + W*H*2. Some of the images on this disc write it as the
    payload alone, W*H*2, twelve bytes short. Both readings are tried and the
    one that closes on the file is reported, so the split between the two
    conventions is a measurement rather than a parser bug.
    """
    if len(out) < 20 or out[0:4] != bytes((0x10, 0, 0, 0)):
        return None
    flags = int.from_bytes(out[4:8], "little")
    pmode = flags & 7
    pos = 8
    cluts = entries = 0
    conv = None
    for _ in range(2):
        if pos + 12 > len(out):
            return None
        bnum = int.from_bytes(out[pos:pos + 4], "little")
        w = int.from_bytes(out[pos + 8:pos + 10], "little")
        h = int.from_bytes(out[pos + 10:pos + 12], "little")
        want_full = 12 + w * h * 2
        if bnum == want_full:
            this = "spec"
        elif bnum == w * h * 2:
            this = "payload-only"
        else:
            return None
        conv = this if conv is None else ("mixed" if conv != this else conv)
        blocklen = want_full
        if _ == 0 and (flags & 8):
            cluts, entries = h, w
            pos += blocklen
            continue
        mult = {0: 4, 1: 2, 2: 1, 3: 2.0 / 3.0}.get(pmode, 1)
        pos += blocklen
        return {"pmode": pmode, "cluts": cluts, "entries": entries,
                "w": int(w * mult), "h": h, "end": pos,
                "residue": len(out) - pos, "bnum": conv}
    return None

END, WIDEN, FLUSH, FIRST_FREE = 0x100, 0x101, 0x102, 0x103


class Bits(object):
    """Most-significant-bit-first reader over a byte string."""

    __slots__ = ("d", "pos", "acc", "n")

    def __init__(self, data):
        self.d = data
        self.pos = 0
        self.acc = 0
        self.n = 0

    def read(self, k):
        while self.n < k:
            if self.pos >= len(self.d):
                # The encoder always terminates with 0x100; running out of
                # bytes first is a truncated file and is reported, not padded
                # over silently.
                raise EOFError("ran out of bits after %d bytes" % self.pos)
            self.acc = (self.acc << 8) | self.d[self.pos]
            self.pos += 1
            self.n += 8
        self.n -= k
        v = (self.acc >> self.n) & ((1 << k) - 1)
        self.acc &= (1 << self.n) - 1
        return v


def depack(data, limit=512 << 10):
    """Return (output bytes, stats dict). Raises on a malformed stream."""
    bits = Bits(data)
    out = bytearray()
    widens = 0
    flushes = 0
    maxwidth = 9
    entries = 0
    while True:
        index = [0] * 0x10000
        value = bytearray(0x10000)
        nxt = FIRST_FREE
        width = 9
        try:
            old = bits.read(width)
        except EOFError:
            break
        if old == END:
            break
        c = old
        out.append(c & 0xFF)
        while True:
            new = bits.read(width)
            if new == END:
                return bytes(out), {"widens": widens, "flushes": flushes,
                                    "maxwidth": maxwidth, "entries": entries,
                                    "bits_read": bits.pos}
            if new == FLUSH:
                flushes += 1
                break
            if new == WIDEN:
                width += 1
                widens += 1
                maxwidth = max(maxwidth, width)
                continue
            stack = bytearray()
            if new >= nxt:
                stack.append(c & 0xFF)
                code = old
            else:
                code = new
            while code > 255:
                if code >= nxt:
                    raise ValueError("code %d beyond the dictionary" % code)
                stack.append(value[code])
                code = index[code]
            stack.append(code & 0xFF)
            c = stack[-1]
            stack.reverse()
            out += stack
            if len(out) > limit:
                raise ValueError("output exceeded %d bytes" % limit)
            if nxt < 0x10000:
                index[nxt] = old
                value[nxt] = c
                nxt += 1
                entries += 1
            old = new
    return bytes(out), {"widens": widens, "flushes": flushes,
                        "maxwidth": maxwidth, "entries": entries,
                        "bits_read": bits.pos}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--out")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--dump", help="directory to write the decoded TIMs into")
    ap.add_argument("--ext", default=".pak")
    a = ap.parse_args()

    if os.path.isdir(a.path):
        files = []
        for dp, dn, fn in os.walk(a.path):
            for f in sorted(fn):
                if f.lower().endswith(a.ext):
                    files.append(os.path.join(dp, f))
    else:
        files = [a.path]

    if not a.census:
        data = open(files[0], "rb").read()
        out, st = depack(data)
        print("in  %s  %d bytes" % (files[0], len(data)))
        print("out %d bytes   ratio %.4f" % (len(out), len(out) / len(data)))
        print("stats %s" % st)
        sh = tim_shape(out)
        print("as a TIM: %s" % (sh if sh else "REJECTED"))
        if a.out:
            open(a.out, "wb").write(out)
            print("wrote %s" % a.out)
        return

    ok = failed = 0
    tim_ok = 0
    residues = collections.Counter()
    dims = collections.Counter()
    pmodes = collections.Counter()
    convs = collections.Counter()
    in_bytes = out_bytes = 0
    widths = collections.Counter()
    flushes = collections.Counter()
    bydir = collections.defaultdict(lambda: [0, 0, 0])
    errs = []
    for p in files:
        data = open(p, "rb").read()
        in_bytes += len(data)
        try:
            out, st = depack(data)
        except Exception as e:
            failed += 1
            errs.append((p, str(e)))
            continue
        ok += 1
        out_bytes += len(out)
        widths[st["maxwidth"]] += 1
        flushes[st["flushes"]] += 1
        sh = tim_shape(out)
        rel = os.path.relpath(os.path.dirname(p), a.path).replace(os.sep, "/")
        e = bydir[rel]
        e[0] += 1
        e[1] += len(data)
        e[2] += len(out)
        if sh:
            residues[sh["residue"]] += 1
            if sh["residue"] == 0:
                tim_ok += 1
            dims[(sh["w"], sh["h"])] += 1
            pmodes[sh["pmode"]] += 1
            convs[sh["bnum"]] += 1
        else:
            residues["not a TIM"] += 1
        if a.dump:
            d = os.path.join(a.dump, rel)
            os.makedirs(d, exist_ok=True)
            base = os.path.splitext(os.path.basename(p))[0] + ".TIM"
            open(os.path.join(d, base), "wb").write(out)

    print("files                 : %d" % len(files))
    print("decompressed          : %d" % ok)
    print("failed                : %d" % failed)
    for p, e in errs[:10]:
        print("    %-50s %s" % (os.path.relpath(p, a.path), e))
    print("compressed bytes      : %d" % in_bytes)
    print("decompressed bytes    : %d" % out_bytes)
    print("ratio                 : %.4f : 1" % (out_bytes / in_bytes if in_bytes else 0))
    print()
    print("-- the oracle: is the output a TIM? ---------------------------------")
    print("output parses as a TIM and closes with residue 0 : %d / %d"
          % (tim_ok, ok))
    print("residues              : %s"
          % ", ".join("%s x%d" % kv for kv in residues.most_common(6)))
    print()
    print("-- decoded image sizes ----------------------------------------------")
    for (w, h), n in dims.most_common(12):
        print("   %4s x %-4s  %5d files" % (w, h, n))
    print("   distinct sizes     : %d" % len(dims))
    print("   bnum convention    : %s"
          % ", ".join("%s x%d" % kv for kv in convs.most_common()))
    print("   pixel modes        : %s"
          % ", ".join("mode %s x%d" % kv for kv in pmodes.most_common()))
    print()
    print("-- the bitstream ----------------------------------------------------")
    print("   maximum code width : %s"
          % ", ".join("%d bits x%d" % kv for kv in sorted(widths.items())))
    print("   flush codes (0x102): %s"
          % ", ".join("%d x%d" % kv for kv in sorted(flushes.items())))
    print()
    print("-- by directory -----------------------------------------------------")
    for k, v in sorted(bydir.items(), key=lambda kv: -kv[1][1]):
        print("   %-24s %5d files  %12d -> %12d   %.4f : 1"
              % (k, v[0], v[1], v[2], v[2] / v[1] if v[1] else 0))


if __name__ == "__main__":
    main()
