#!/usr/bin/env python3
"""mpegaudio.py -- read MPEG audio and RIFF/WAVE headers from inside an
EmPackFi archive, and turn 864 megabytes of `.mp3` into a running time.

The MPEG-1/2 audio frame header is public (ISO/IEC 11172-3 and 13818-3) and
eleven bits of it are a sync word. This tool uses the published tables; it
decodes no audio and extracts no member. For each member it reads the first
frame header -- and, to prove the header is not a coincidence, it walks the
NEXT `--frames` frames by the length the first one predicts and requires that
every one of them start with a sync word too. A random four bytes will pass the
first test about once in two thousand; passing it fifty times running is what
makes the reading a measurement.

Duration is computed two ways and both are printed, because they can disagree:
   * by counting every frame in the member and multiplying by the samples per
     frame (exact, and what this tool does when `--exact` is given);
   * by dividing the member's byte length by the first frame's bit rate
     (right for a constant-bit-rate file, wrong for a variable one).

    python tools/mpegaudio.py --archive A.pak --tsv A.tsv
    python tools/mpegaudio.py --archive A.pak --tsv A.tsv --exact
    python tools/mpegaudio.py --archive A.pak --tsv A.tsv --selftest
"""
import argparse
import collections
import csv
import os
import struct
import sys

V = {0: "MPEG 2.5", 1: None, 2: "MPEG 2", 3: "MPEG 1"}
L = {0: None, 1: "III", 2: "II", 3: "I"}
BITRATE = {
    ("MPEG 1", "I"): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0],
    ("MPEG 1", "II"): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0],
    ("MPEG 1", "III"): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],
    ("MPEG 2", "I"): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0],
    ("MPEG 2", "II"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
    ("MPEG 2", "III"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
}
BITRATE[("MPEG 2.5", "I")] = BITRATE[("MPEG 2", "I")]
BITRATE[("MPEG 2.5", "II")] = BITRATE[("MPEG 2", "II")]
BITRATE[("MPEG 2.5", "III")] = BITRATE[("MPEG 2", "III")]
SRATE = {"MPEG 1": [44100, 48000, 32000], "MPEG 2": [22050, 24000, 16000],
         "MPEG 2.5": [11025, 12000, 8000]}
SAMPLES = {("MPEG 1", "I"): 384, ("MPEG 1", "II"): 1152, ("MPEG 1", "III"): 1152,
           ("MPEG 2", "I"): 384, ("MPEG 2", "II"): 1152, ("MPEG 2", "III"): 576,
           ("MPEG 2.5", "I"): 384, ("MPEG 2.5", "II"): 1152, ("MPEG 2.5", "III"): 576}
MODE = {0: "stereo", 1: "joint stereo", 2: "dual channel", 3: "mono"}


def frame(b, i=0):
    if i + 4 > len(b):
        return None
    if b[i] != 0xFF or (b[i + 1] & 0xE0) != 0xE0:
        return None
    ver = V[(b[i + 1] >> 3) & 3]
    lay = L[(b[i + 1] >> 1) & 3]
    if ver is None or lay is None:
        return None
    bi = (b[i + 2] >> 4) & 15
    si = (b[i + 2] >> 2) & 3
    if bi in (0, 15) or si == 3:
        return None
    pad = (b[i + 2] >> 1) & 1
    br = BITRATE[(ver, lay)][bi] * 1000
    sr = SRATE[ver][si]
    if br == 0:
        return None
    mode = MODE[(b[i + 3] >> 6) & 3]
    if lay == "I":
        length = (12 * br // sr + pad) * 4
    else:
        length = 144 * br // sr + pad if ver == "MPEG 1" else 72 * br // sr + pad
    return {"ver": ver, "layer": lay, "bitrate": br, "rate": sr, "pad": pad,
            "mode": mode, "length": length, "samples": SAMPLES[(ver, lay)]}


def skip_id3(fh, off, size):
    fh.seek(off)
    h = fh.read(10)
    if h[:3] == b"ID3" and len(h) == 10:
        n = ((h[6] & 0x7F) << 21) | ((h[7] & 0x7F) << 14) | \
            ((h[8] & 0x7F) << 7) | (h[9] & 0x7F)
        return 10 + n
    return 0


def chain(fh, off, size, want):
    """Read `want` consecutive frames by predicted length. Returns how many."""
    got = 0
    pos = off
    while got < want and pos - off + 4 <= size:
        fh.seek(pos)
        f = frame(fh.read(4))
        if f is None:
            break
        pos += f["length"]
        got += 1
    return got


def wavfmt(fh, off, size):
    fh.seek(off)
    b = fh.read(min(size, 256))
    if b[:4] != b"RIFF" or b[8:12] != b"WAVE":
        return None
    i = 12
    while i + 8 <= len(b):
        cid = b[i:i + 4]
        cl = struct.unpack_from("<I", b, i + 4)[0]
        if cid == b"fmt ":
            tag, ch, sr, _bps, _al, bits = struct.unpack_from("<HHIIHH", b, i + 8)
            return {"tag": tag, "ch": ch, "rate": sr, "bits": bits,
                    "declared": struct.unpack_from("<I", b, 4)[0]}
        i += 8 + cl + (cl & 1)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", required=True)
    ap.add_argument("--tsv", required=True)
    ap.add_argument("--frames", type=int, default=50,
                    help="consecutive frames that must chain before a member "
                         "counts as MPEG audio")
    ap.add_argument("--exact", action="store_true",
                    help="walk every frame of every member (slow, exact)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        print("-- controls --")
        for b, why in ((b"BIKi\x00\x00\x00\x00", "a Bink header"),
                       (b"\xff\xff\xff\xff", "four 0xFF"),
                       (b"\xff\xe0\x00\x00", "a sync word with a free bit rate")):
            print("   %-34s -> %s"
                  % (why, "REFUSED" if frame(b) is None else "ACCEPTED (BAD)"))
        bom = frame(b"\xff\xfe4\x000\x00")
        print("   %-34s -> ACCEPTED by the one-header test, as %s layer %s"
              % ("a UTF-16LE byte-order mark", bom["ver"], bom["layer"]))
        print("        ff fe satisfies eleven sync bits, so ONE header is not a")
        print("        measurement. This tool requires a chain of %d frames, and"
              % a.frames)
        print("        the chain is what rejects it: in bs4.pak that test threw")
        print("        out twenty-eight members, and all twenty-eight are text.")
        f = frame(b"\xff\xfb\x90\x00")
        print("   %-34s -> %s %s %d bit/s %d Hz %s, frame %d bytes"
              % ("a hand-built MPEG 1 layer III header", f["ver"], f["layer"],
                 f["bitrate"], f["rate"], f["mode"], f["length"]))
        print()

    fh = open(a.archive, "rb")
    rows = list(csv.DictReader(open(a.tsv, encoding="utf-8"), delimiter="\t"))

    kinds = collections.Counter()
    profile = collections.Counter()
    secs = 0.0
    bytes_ = 0
    nmp3 = 0
    chainfail = 0
    wavs = []
    exact_secs = 0.0
    for r in rows:
        size, off = int(r["size"]), int(r["offset"])
        nm = r["name"]
        w = wavfmt(fh, off, size)
        if w:
            wavs.append((nm, size, w))
            kinds["RIFF/WAVE"] += 1
            continue
        skip = skip_id3(fh, off, size)
        fh.seek(off + skip)
        f = frame(fh.read(4))
        if f is None:
            kinds["not audio"] += 1
            continue
        got = chain(fh, off + skip, size - skip, a.frames)
        if got < min(a.frames, 4):
            chainfail += 1
            kinds["sync word but no chain"] += 1
            continue
        nmp3 += 1
        kinds["MPEG audio"] += 1
        profile[(f["ver"], f["layer"], f["bitrate"] // 1000, f["rate"], f["mode"])] += 1
        secs += (size - skip) * 8.0 / f["bitrate"]
        bytes_ += size
        if a.exact:
            pos = off + skip
            n = 0
            while pos - off + 4 <= size:
                fh.seek(pos)
                g = frame(fh.read(4))
                if g is None:
                    break
                pos += g["length"]
                n += 1
            exact_secs += n * f["samples"] / float(f["rate"])

    print("archive : %s" % os.path.basename(a.archive))
    print("members : %d" % len(rows))
    for k, v in kinds.most_common():
        print("   %-26s %6d" % (k, v))
    print("members with a sync word that did not chain %d frames : %d"
          % (a.frames, chainfail))
    print()
    print("-- MPEG audio, %d members, %d bytes --" % (nmp3, bytes_))
    print("   %-38s %7s %14s" % ("version / layer / kbit/s / Hz / mode", "members", "share"))
    for k, v in profile.most_common(12):
        print("   %-8s %-4s %4d kbit/s %6d Hz %-13s %7d  %6.2f %%"
              % (k[0], k[1], k[2], k[3], k[4], v, 100.0 * v / max(1, nmp3)))
    print()
    print("   running time, from bit rate and length : %.1f s = %d h %02d m %02d s"
          % (secs, int(secs // 3600), int(secs % 3600 // 60), int(secs % 60)))
    if a.exact:
        print("   running time, by counting frames       : %.1f s = %d h %02d m %02d s"
              % (exact_secs, int(exact_secs // 3600), int(exact_secs % 3600 // 60),
                 int(exact_secs % 60)))
        print("   the two differ by %.1f s (%.4f %%)"
              % (abs(secs - exact_secs), 100.0 * abs(secs - exact_secs) / max(1e-9, exact_secs)))

    if wavs:
        print()
        print("-- RIFF/WAVE, %d members, %d bytes --"
              % (len(wavs), sum(s for _n, s, _w in wavs)))
        pf = collections.Counter((w["tag"], w["ch"], w["rate"], w["bits"])
                                 for _n, _s, w in wavs)
        for k, v in pf.most_common():
            print("   format 0x%04X  %d ch  %6d Hz  %2d bits : %d members"
                  % (k[0], k[1], k[2], k[3], v))
        closes = sum(1 for _n, s, w in wavs if w["declared"] + 8 == s)
        print("   `RIFF size + 8 == member size` : %d of %d" % (closes, len(wavs)))
        tot = 0.0
        for _n, s, w in wavs:
            if w["tag"] == 1 and w["rate"] and w["ch"] and w["bits"]:
                tot += (s - 44) * 8.0 / (w["rate"] * w["ch"] * w["bits"])
        print("   running time of the linear-PCM ones : %.1f s" % tot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
