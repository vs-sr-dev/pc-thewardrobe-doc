#!/usr/bin/env python3
"""sndsread.py -- the SNDS half of a 3DO Data Streamer file.

The stream's subscriber table names three tags: `FILM`, `SNDS` and `CTRL`. The
`FILM` half is video (see `cvidmovie.py`); this is the other half. Its first
chunk is a header whose fields are read here as numbers and named only where a
second, independent quantity on the disc forces the name.

    +16  'SHDR'
    +40  u32   8       bits per sample
    +44  u32   22050   sample rate
    +48  u32   2       channels
    +52  char[4] 'NONE'   compression
    +60  u32   total sample bytes

Each later chunk is `SNDS` + `SSMP` + a length + raw samples, and the tool
concatenates them and writes a WAV so a person can listen to it, which is the
only check that tells a correct sample format from an arithmetically plausible
one.

It also prints the timestamps, because the timestamp is what makes this an
interleaved container rather than two files in a trench coat: the video's
timestamps and the audio's are on the same clock, and dividing one by the other
gives the frame rate without anybody declaring it.

usage:
    sndsread.py FILE [--wav OUT.wav]
"""
import argparse
import collections
import struct
import wave


def chunks(data):
    off = 0
    out = []
    while off < len(data):
        tag = data[off:off + 4]
        size = struct.unpack(">I", data[off + 4:off + 8])[0]
        if size < 8 or off + size > len(data):
            raise SystemExit("bad chain at %d" % off)
        out.append((off, tag, size))
        off += size
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--wav")
    a = ap.parse_args()
    data = open(a.file, "rb").read()
    cs = chunks(data)
    snds = [c for c in cs if c[1] == b"SNDS"]
    hdr = [c for c in snds if data[c[0] + 16:c[0] + 20] == b"SHDR"]
    smp = [c for c in snds if data[c[0] + 16:c[0] + 20] == b"SSMP"]
    print("%s" % a.file)
    print("SNDS chunks: %d   header %d   sample %d" % (len(snds), len(hdr), len(smp)))
    off = hdr[0][0]
    w = struct.unpack(">16I", data[off:off + 64])
    print()
    print("the SNDS header chunk, %d bytes:" % hdr[0][2])
    names = {10: "bits per sample", 11: "sample rate", 12: "channels",
             13: "compression, as four characters", 15: "total sample bytes"}
    for i in range(16):
        raw = data[off + 4 * i:off + 4 * i + 4]
        txt = ("'" + raw.decode("latin1") + "'"
               if all(0x20 <= c < 0x7F for c in raw) else "")
        print("   +%-4d 0x%08x %10d  %-8s %s"
              % (4 * i, w[i], w[i], txt, names.get(i, "")))
    bits, rate, chans = w[10], w[11], w[12]
    comp = data[off + 52:off + 56]
    total = w[15]

    pay = bytearray()
    for o, t, s in smp:
        n = struct.unpack(">I", data[o + 20:o + 24])[0]
        pay += data[o + 24:o + 24 + n]
    print()
    print("sample bytes concatenated : %d" % len(pay))
    print("sample bytes declared     : %d   (difference %d)"
          % (total, len(pay) - total))
    if bits and chans and rate:
        frames = total // (chans * bits // 8)
        secs = float(frames) / rate
        print("declared duration         : %d frames / %d Hz / %d ch = %.4f s "
              "= %d:%05.2f" % (frames, rate, chans, secs, int(secs // 60),
                               secs % 60))

    film = [c for c in cs if c[1] == b"FILM"
            and data[c[0] + 16:c[0] + 20] == b"FRME"]
    ts = [struct.unpack(">I", data[o + 8:o + 12])[0] for o, t, s in film]
    d = collections.Counter(ts[i + 1] - ts[i] for i in range(len(ts) - 1))
    print()
    print("video timestamps: %d frames, %d..%d" % (len(ts), ts[0], ts[-1]))
    print("   deltas: %s"
          % ", ".join("%d (x%d)" % (k, v) for k, v in d.most_common(6)))
    ats = [struct.unpack(">I", data[o + 8:o + 12])[0] for o, t, s in smp]
    ad = collections.Counter(ats[i + 1] - ats[i] for i in range(len(ats) - 1))
    print("audio timestamps: %d chunks, %d..%d" % (len(ats), ats[0], ats[-1]))
    print("   deltas: %s"
          % ", ".join("%d (x%d)" % (k, v) for k, v in ad.most_common(6)))
    if bits and chans and rate and d:
        per = d.most_common(1)[0][0]
        # one audio chunk is this many seconds
        bytes_per_chunk = struct.unpack(">I", data[smp[1][0] + 20:smp[1][0] + 24])[0]
        chunk_secs = float(bytes_per_chunk) / (rate * chans * bits // 8)
        chunk_ticks = ad.most_common(1)[0][0] if ad else 0
        print()
        print("THE CLOCK, derived and not declared:")
        print("   one audio chunk is %d bytes = %.6f s and %d ticks"
              % (bytes_per_chunk, chunk_secs, chunk_ticks))
        if chunk_secs:
            hz = chunk_ticks / chunk_secs
            print("   so the stream clock runs at %.2f ticks per second" % hz)
            print("   one video frame is %d ticks = %.4f s = %.4f frames/s"
                  % (per, per / hz, hz / per))
    if a.wav:
        f = wave.open(a.wav, "wb")
        f.setnchannels(chans)
        f.setsampwidth(1)
        f.setframerate(rate)
        # 8-bit PCM in a WAV is unsigned; the 3DO's is signed
        f.writeframes(bytes((x + 128) & 0xFF for x in pay))
        f.close()
        print()
        print("wrote %s  (%d channels, %d Hz, 8-bit, compression %r)"
              % (a.wav, chans, rate, comp))


if __name__ == "__main__":
    main()
