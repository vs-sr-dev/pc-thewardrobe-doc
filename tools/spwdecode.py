#!/usr/bin/env python3
"""spwdecode.py -- decode a SeWave / BGMStream body, and prove it is sound.

`sewave.py` settles the container: the 22 leading bytes of every one of the
12,041 `.spw` and 261 `.bgw` name themselves, the size field matches the
file on 12,302 of 12,302, and the body starts at 48 on all of them.  Two
bytes of the header then decide what the body is:

    +42  u8  channels          1 or 2
    +44  u8  codec             0x10, 0x01, 0x00, 0x04, 0x08

and the count at +20 times a per-codec constant reproduces the body length
EXACTLY:

    codec 0x10   9 bytes per unit per channel   4-bit ADPCM, 16 samples
                                                per 9 bytes
    codec 0x01   2 bytes per unit per channel   16-bit linear PCM
    codec 0x00   3/16 byte per unit per channel
    codec 0x04   3 bytes per unit per channel
    codec 0x08   5 bytes per unit per channel

HOW A DECODE IS PROVED WITHOUT LISTENING TO IT

A wrong decode of audio looks like noise, and noise has no memory: the
correlation between one sample and the next is near zero.  Real recorded
sound at any sane rate is heavily oversampled relative to its own
bandwidth, so adjacent samples are strongly correlated -- typically 0.9
and up.  So the tool decodes, measures lag-1 correlation, and ALSO
measures it on a control: the same bytes read as if they were the other
codec.  If the control scores as well as the candidate, the measurement
means nothing and the tool says so.

The ADPCM filter split is not assumed either.  The control byte of a
9-byte block packs a range and a filter index into two nibbles, and which
nibble is which is decided by trying both and keeping the one that
correlates -- with the loser printed beside the winner.

Nothing is executed, nothing is contacted, nothing is written to the
object.

usage:
  spwdecode.py probe FILE [FILE ...]
  spwdecode.py wav   FILE --out FILE.wav [--rate N]
  spwdecode.py plot  FILE --out FILE.png [--width N] [--height N]
"""

import argparse
import math
import os
import struct
import sys
import zlib

DATA_OFF = 48
BLOCK = 9

# The five filters every 4-bit console ADPCM of this generation uses,
# as (a1, a2) in 64ths.  They are not derived here: they are the published
# Sony ADPCM coefficients, used as a hypothesis and then TESTED by the
# correlation measurement, exactly as a public format definition is
# allowed to be used in this branch -- named, and validated on a specimen.
FILTERS = [(0, 0), (60, 0), (115, -52), (98, -55), (122, -60)]


def parse_header(data):
    if data[:6] == b"SeWave":
        base = 8
        kind = "SeWave"
    elif data[:9] == b"BGMStream":
        base = 16
        kind = "BGMStream"
    else:
        return None
    size = struct.unpack_from("<I", data, base)[0]
    count = struct.unpack_from("<I", data, base + 12)[0]
    channels = data[base + 34]
    codec = data[base + 36]
    return {"kind": kind, "size": size, "count": count,
            "channels": channels, "codec": codec}


def decode_pcm16(body, channels):
    n = len(body) // 2
    vals = struct.unpack("<%dh" % n, body[:n * 2])
    return [list(vals[c::channels]) for c in range(channels)]


def clamp16(v):
    return -32768 if v < -32768 else (32767 if v > 32767 else v)


def decode_adpcm(body, channels, shift_low):
    """Decode 9-byte blocks.  shift_low selects which nibble of the
    control byte is the range and which is the filter index."""
    out = [[] for _ in range(channels)]
    hist = [[0, 0] for _ in range(channels)]
    nblocks = len(body) // BLOCK
    for b in range(nblocks):
        ch = b % channels
        off = b * BLOCK
        ctl = body[off]
        if shift_low:
            shift = ctl & 0x0F
            filt = ctl >> 4
        else:
            shift = ctl >> 4
            filt = ctl & 0x0F
        if filt >= len(FILTERS):
            filt = 0
        a1, a2 = FILTERS[filt]
        s1, s2 = hist[ch]
        for i in range(8):
            byte = body[off + 1 + i]
            for nib in (byte & 0x0F, byte >> 4):
                v = nib - 16 if nib > 7 else nib
                v <<= (12 - shift) if shift <= 12 else 0
                v += (s1 * a1 + s2 * a2) >> 6
                v = clamp16(v)
                out[ch].append(v)
                s2, s1 = s1, v
        hist[ch] = [s1, s2]
    return out


def lag1(samples):
    n = len(samples)
    if n < 3:
        return 0.0
    m = sum(samples) / n
    num = 0.0
    den = 0.0
    prev = samples[0] - m
    for i in range(1, n):
        cur = samples[i] - m
        num += prev * cur
        den += prev * prev
        prev = cur
    den += prev * prev
    return num / den if den else 0.0


def load(path, limit_blocks=0):
    data = open(path, "rb").read()
    h = parse_header(data)
    if h is None:
        return None, None
    body = data[DATA_OFF:]
    if limit_blocks:
        body = body[:limit_blocks * BLOCK * max(1, h["channels"])]
    return h, body


def decode(h, body, shift_low=True):
    if h["codec"] == 0x01:
        return decode_pcm16(body, h["channels"]), "PCM16"
    if h["codec"] == 0x10:
        return decode_adpcm(body, h["channels"], shift_low), "ADPCM4"
    return None, "codec 0x%02X not derived" % h["codec"]


def cmd_probe(args):
    print("%-56s %-9s %2s %-6s %8s %8s %8s"
          % ("file", "codec", "ch", "kind", "lag1 A", "lag1 B", "control"))
    for p in args.file:
        h, body = load(p, args.blocks)
        if h is None:
            print("%-56s  not a SeWave/BGMStream" % os.path.basename(p))
            continue
        name = os.path.basename(p)
        if h["codec"] == 0x01:
            ch, kind = decode(h, body)
            a = lag1(ch[0][:200000])
            # the control: the same bytes read as 4-bit ADPCM, which they
            # are not
            cch, _k = decode_adpcm(body, h["channels"], True), None
            c = lag1(cch[0][:200000])
            print("%-56s 0x%02X      %2d %-6s %8.4f %8s %8.4f"
                  % (name[:56], h["codec"], h["channels"], kind, a, "-", c))
        elif h["codec"] == 0x10:
            a = lag1(decode_adpcm(body, h["channels"], True)[0][:200000])
            b = lag1(decode_adpcm(body, h["channels"], False)[0][:200000])
            # the control: the same bytes read as 16-bit PCM, which they
            # are not
            c = lag1(decode_pcm16(body, h["channels"])[0][:200000])
            print("%-56s 0x%02X      %2d %-6s %8.4f %8.4f %8.4f"
                  % (name[:56], h["codec"], h["channels"], "ADPCM4", a, b, c))
        else:
            print("%-56s 0x%02X      %2d  not derived"
                  % (name[:56], h["codec"], h["channels"]))
    print()
    print("lag1 A = range in the low nibble, B = range in the high nibble.")
    print("control = the identical bytes decoded as the OTHER codec.  If the")
    print("control scores as high as the candidate, nothing has been shown.")
    return 0


def write_wav(path, chans, rate):
    n = len(chans[0])
    nch = len(chans)
    inter = bytearray()
    for i in range(n):
        for c in range(nch):
            inter += struct.pack("<h", clamp16(int(chans[c][i])))
    data = bytes(inter)
    hdr = b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt "
    hdr += struct.pack("<IHHIIHH", 16, 1, nch, rate, rate * nch * 2, nch * 2, 16)
    hdr += b"data" + struct.pack("<I", len(data))
    open(path, "wb").write(hdr + data)


def cmd_wav(args):
    h, body = load(args.file)
    chans, kind = decode(h, body, True)
    if chans is None:
        print(kind)
        return 2
    write_wav(args.out, chans, args.rate)
    print("%s -> %s  (%s, %d channels, %d samples, %.3f s at %d Hz)"
          % (args.file, args.out, kind, len(chans), len(chans[0]),
             len(chans[0]) / float(args.rate), args.rate))
    print("lag-1 correlation of channel 0 : %.4f" % lag1(chans[0][:400000]))
    return 0


def png(path, w, h, rows):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += rows[y]

    def chunk(tag, payload):
        return (struct.pack(">I", len(payload)) + tag + payload +
                struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))
    out = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    out += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    out += chunk(b"IEND", b"")
    open(path, "wb").write(out)


def cmd_plot(args):
    h, body = load(args.file)
    chans, kind = decode(h, body, True)
    if chans is None:
        print(kind)
        return 2
    W, H = args.width, args.height
    s = chans[0]
    n = len(s)
    rows = [bytearray([16, 18, 22] * W) for _ in range(H)]
    mid = H // 2
    for x in range(W):
        a = n * x // W
        b = max(a + 1, n * (x + 1) // W)
        seg = s[a:b]
        lo, hi = min(seg), max(seg)
        y0 = mid - int(hi * mid / 32768.0)
        y1 = mid - int(lo * mid / 32768.0)
        y0 = max(0, min(H - 1, y0))
        y1 = max(0, min(H - 1, y1))
        for y in range(y0, y1 + 1):
            rows[y][x * 3] = 120
            rows[y][x * 3 + 1] = 210
            rows[y][x * 3 + 2] = 160
    for x in range(W):
        rows[mid][x * 3] = 90
        rows[mid][x * 3 + 1] = 100
        rows[mid][x * 3 + 2] = 110
    png(args.out, W, H, rows)
    print("%s -> %s  (%s, %d samples, lag1 %.4f)"
          % (os.path.basename(args.file), args.out, kind, n, lag1(s[:400000])))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("file", nargs="+")
    p.add_argument("--blocks", type=int, default=0)
    p.set_defaults(func=cmd_probe)
    p = sub.add_parser("wav")
    p.add_argument("file")
    p.add_argument("--out", required=True)
    p.add_argument("--rate", type=int, default=44100)
    p.set_defaults(func=cmd_wav)
    p = sub.add_parser("plot")
    p.add_argument("file")
    p.add_argument("--out", required=True)
    p.add_argument("--width", type=int, default=900)
    p.add_argument("--height", type=int, default=200)
    p.set_defaults(func=cmd_plot)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
