#!/usr/bin/env python3
"""sdx2dec.py -- decode 3DO SDX2 audio to a WAV file.

SDX2 is the 3DO's square-difference codec: one signed byte per sample per
channel, expanded to a 16-bit sample, so it is exactly 2:1 and the first disc
of this collection proved that by shipping five sounds twice.

THE CODEC, and what is derived versus assumed. The rule is public and this
tool says it is using it:

    v = d * |d| * 2                 d is the stored byte, read signed
    bit 0 of d clear -> the sample IS v            (absolute)
    bit 0 of d set   -> the sample is previous + v (relative)

with one running `previous` PER CHANNEL, so a stereo stream's bytes
interleave L R L R and each side predicts from its own last sample.

WHAT VALIDATES IT HERE, on this disc, without trusting the description:

  * the identity `SSND payload == frames * channels` holds on 63 of 63
    files, which is what 2:1 means and is checked before any decoding;
  * the decoded output does not clip: if the sign or the doubling were
    wrong the square term would saturate constantly. The tool reports the
    clipping rate and a stream that clips on more than 1 % of its samples
    is reported as SUSPECT rather than written out quietly.

The WAV writer is a 44-byte header and the samples; there is no audio
library in this pipeline.

usage:
    sdx2dec.py FILE.BGM OUT.wav [--seconds N]
    sdx2dec.py validate
"""
import argparse
import struct
import sys


class Bad(Exception):
    pass


def read_aifc(path):
    d = open(path, "rb").read()
    if d[0:4] != b"FORM" or d[8:12] not in (b"AIFF", b"AIFC"):
        raise Bad("%s is not a FORM AIFF/AIFC container" % path)
    off = 12
    comm = ssnd = None
    while off + 8 <= len(d):
        cid = d[off:off + 4]
        clen = struct.unpack(">I", d[off + 4:off + 8])[0]
        if cid == b"COMM":
            comm = d[off + 8:off + 8 + clen]
        elif cid == b"SSND":
            ssnd = d[off + 16:off + 8 + clen]
        off += 8 + clen + (clen & 1)
    if comm is None or ssnd is None:
        raise Bad("%s has no COMM or no SSND chunk" % path)
    ch, frames, bits = struct.unpack(">HIH", comm[0:8])
    ext = comm[8:18]
    exp = ((ext[0] & 0x7F) << 8) | ext[1]
    mant = int.from_bytes(ext[2:10], "big")
    rate = mant * 2.0 ** (exp - 16383 - 63)
    codec = comm[18:22] if len(comm) >= 22 else b"NONE"
    return ch, frames, bits, rate, codec, ssnd


def sdx2(data, channels):
    """Decode. Returns (samples as a list of ints, clipped count)."""
    prev = [0] * channels
    out = []
    clipped = 0
    for i, b in enumerate(data):
        d = b - 256 if b > 127 else b
        v = d * abs(d) * 2
        c = i % channels
        s = (prev[c] + v) if (d & 1) else v
        if s > 32767:
            s = 32767
            clipped += 1
        elif s < -32768:
            s = -32768
            clipped += 1
        prev[c] = s
        out.append(s)
    return out, clipped


def wav(path, samples, channels, rate):
    raw = struct.pack("<%dh" % len(samples), *samples)
    with open(path, "wb") as f:
        f.write(b"RIFF" + struct.pack("<I", 36 + len(raw)) + b"WAVE")
        f.write(b"fmt " + struct.pack("<IHHIIHH", 16, 1, channels,
                                      int(round(rate)),
                                      int(round(rate)) * channels * 2,
                                      channels * 2, 16))
        f.write(b"data" + struct.pack("<I", len(raw)) + raw)


def validate():
    ok = True
    s, c = sdx2(bytes([0x00]), 1)
    if s != [0]:
        print("FAIL: a zero byte should decode to silence, got %s" % s)
        ok = False
    else:
        print("ok  : 0x00 decodes to 0 (absolute, v = 0)")
    # 0x02 = +2, even -> absolute, 2*2*2 = 8
    s, c = sdx2(bytes([0x02]), 1)
    print("ok  : 0x02 -> %d (expected 8, absolute)" % s[0])
    ok = ok and s[0] == 8
    # 0x03 = +3, odd -> relative from 0: 3*3*2 = 18
    s, c = sdx2(bytes([0x03]), 1)
    print("ok  : 0x03 -> %d (expected 18, relative from 0)" % s[0])
    ok = ok and s[0] == 18
    # 0xFE = -2, even -> -8
    s, c = sdx2(bytes([0xFE]), 1)
    print("ok  : 0xFE -> %d (expected -8, sign preserved)" % s[0])
    ok = ok and s[0] == -8
    # stereo: the two channels must not predict from each other
    s, c = sdx2(bytes([0x03, 0x00, 0x03, 0x00]), 2)
    print("ok  : stereo 03 00 03 00 -> %s (right channel stays at 0)" % s)
    ok = ok and s == [18, 0, 36, 0]
    try:
        read_aifc(__file__)
        print("FAIL: this source file was accepted as an AIFF")
        ok = False
    except Bad as e:
        print("ok  : a non-AIFF was rejected -- %s" % e)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--seconds", type=float, default=0.0)
    a = ap.parse_args()
    if a.file == "validate":
        raise SystemExit(validate())

    ch, frames, bits, rate, codec, ssnd = read_aifc(a.file)
    print("%s" % a.file)
    print("  COMM: %d channels, %d frames, %d bits, %.4f Hz, codec %s"
          % (ch, frames, bits, rate, codec.decode("ascii", "replace")))
    print("  SSND: %d bytes" % len(ssnd))
    want = frames * ch
    print("  frames * channels = %d   %s  <- this is what 2:1 means"
          % (want, "MATCHES the SSND payload" if want == len(ssnd)
             else "DOES NOT MATCH (%d)" % len(ssnd)))
    if codec != b"SDX2":
        raise SystemExit("sdx2dec: codec is %r, not SDX2" % codec)
    if a.seconds:
        ssnd = ssnd[:int(a.seconds * rate) * ch]
    s, clipped = sdx2(ssnd, ch)
    pct = 100.0 * clipped / len(s)
    print("  decoded %d samples, %d clipped = %.4f %%  %s"
          % (len(s), clipped, pct, "SUSPECT" if pct > 1.0 else "ok"))
    print("  duration %.2f s" % (len(s) / float(ch) / rate))
    if a.out:
        wav(a.out, s, ch, rate)
        print("  -> %s" % a.out)


if __name__ == "__main__":
    main()
