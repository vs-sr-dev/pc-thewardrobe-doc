#!/usr/bin/env python3
"""mp3loose.py -- MPEG audio headers, ID3 tags and running time for loose files.

`mpegaudio.py` in this repository reads MPEG audio out of an EmPackFi archive
and cannot be pointed at a directory. The object here keeps eighteen `.mp3` as
ordinary files, so this is the same discipline with a different front door and
one addition: it reads the ID3 tags and the Xing/Info/LAME frame, because the
question "who encoded this" is answered by a tag and not by a bit rate.

The frame header is public (ISO/IEC 11172-3). Eleven bits are a sync word, so
four random bytes pass the first test about once in two thousand. The reading
is only a measurement if it survives repetition, so every frame in the file is
walked by the length the previous one predicts and the count of frames that
failed to start with a sync word is printed beside the count that did.

Duration is computed two ways and both are printed:
  * exact, by counting frames and multiplying by samples-per-frame;
  * nominal, by dividing the payload length by the first frame's bit rate,
    which is right for constant bit rate and wrong otherwise.
When they differ the file is not CBR, and that difference is the measurement.

    python tools/mp3loose.py DIR [--tsv out.tsv]
"""
import argparse
import os
import struct
import sys

BITRATES_V1L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256,
                 320, 0]
BITRATES_V2L3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160,
                 0]
RATES = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000],
         0: [11025, 12000, 8000]}
MODES = ["stereo", "joint stereo", "dual channel", "mono"]


def parse_frame(b, off):
    if off + 4 > len(b):
        return None
    h = struct.unpack_from(">I", b, off)[0]
    if (h & 0xFFE00000) != 0xFFE00000:
        return None
    ver = (h >> 19) & 3
    layer = (h >> 17) & 3
    if ver == 1 or layer == 0:
        return None
    bri = (h >> 12) & 15
    sri = (h >> 10) & 3
    if bri in (0, 15) or sri == 3:
        return None
    pad = (h >> 9) & 1
    mode = (h >> 6) & 3
    table = BITRATES_V1L3 if ver == 3 else BITRATES_V2L3
    if layer != 1:                       # layer III only, which is what .mp3 is
        return None
    br = table[bri] * 1000
    sr = RATES[ver][sri]
    spf = 1152 if ver == 3 else 576
    length = (144 * br) // sr + pad if ver == 3 else (72 * br) // sr + pad
    return {"bitrate": br, "rate": sr, "mode": MODES[mode], "spf": spf,
            "len": length, "version": "MPEG1" if ver == 3 else "MPEG2"}


def id3_size(b):
    if b[:3] != b"ID3":
        return 0
    n = b[6] << 21 | b[7] << 14 | b[8] << 7 | b[9]
    return 10 + n


def read_id3(b):
    """ID3v2.2, v2.3 and v2.4.

    v2.2 uses THREE-character frame ids and a three-byte size, and the first
    version of this function refused anything below v2.3 and returned an empty
    dict. It then reported "ID3v2 tags: 0 of 18" on eighteen tagged files. A
    tool that finds nothing is not a tool that says zero, so the version byte
    is now branched on rather than used as a filter. See docs/17-corrections.md.
    """
    out = {}
    if b[:3] != b"ID3" or b[3] < 2:
        return out
    end = id3_size(b)
    idlen = 3 if b[3] == 2 else 4
    hdrlen = 6 if b[3] == 2 else 10
    i = 10
    while i + hdrlen <= end:
        fid = b[i:i + idlen]
        if not fid.strip(b"\0"):
            break
        if b[3] == 2:
            sz = b[i + 3] << 16 | b[i + 4] << 8 | b[i + 5]
        elif b[3] == 3:
            sz = struct.unpack_from(">I", b, i + 4)[0]
        else:
            sz = (b[i + 4] << 21 | b[i + 5] << 14 | b[i + 6] << 7 | b[i + 7])
        if sz <= 0 or i + hdrlen + sz > end:
            break
        val = b[i + hdrlen:i + hdrlen + sz]
        if val[:1] in (b"\x00", b"\x01", b"\x02", b"\x03"):
            enc, val = val[0], val[1:]
            try:
                txt = val.decode("utf-16" if enc in (1, 2) else
                                 ("utf-8" if enc == 3 else "latin-1"))
            except Exception:
                txt = val.decode("latin-1", "replace")
        else:
            txt = val.decode("latin-1", "replace")
        out[fid.decode("ascii", "replace")] = txt.strip("\0").strip()
        i += hdrlen + sz
    return out


def xing(b, first_off, fr):
    """Return (tag, frames, bytes, lame) if a Xing/Info header is present."""
    side = 32 if fr["version"] == "MPEG1" and fr["mode"] != "mono" else (
        17 if fr["version"] == "MPEG1" else
        (17 if fr["mode"] != "mono" else 9))
    at = first_off + 4 + side
    tag = b[at:at + 4]
    if tag not in (b"Xing", b"Info"):
        return None
    flags = struct.unpack_from(">I", b, at + 4)[0]
    p = at + 8
    frames = nbytes = None
    if flags & 1:
        frames = struct.unpack_from(">I", b, p)[0]
        p += 4
    if flags & 2:
        nbytes = struct.unpack_from(">I", b, p)[0]
        p += 4
    if flags & 4:
        p += 100
    if flags & 8:
        p += 4
    lame = b[p:p + 9]
    lame = lame.decode("latin-1", "replace") if lame[:4].isascii() else ""
    return (tag.decode(), frames, nbytes, lame)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--tsv")
    args = ap.parse_args()

    files = []
    if os.path.isdir(args.target):
        for root, _d, names in os.walk(args.target):
            for n in sorted(names):
                if n.lower().endswith(".mp3"):
                    files.append(os.path.join(root, n))
    else:
        files = [args.target]
    files.sort()
    if not files:
        print("no .mp3 under %s" % args.target)
        return 1

    rows = []
    tot_bytes = tot_exact = tot_nominal = 0
    kinds = {}
    print("%-34s %11s %8s %8s %6s %-12s %8s %8s" %
          ("file", "bytes", "kbit/s", "Hz", "mode", "version", "exact s",
           "nominal s"))
    print("-" * 118)
    for p in files:
        b = open(p, "rb").read()
        tags = read_id3(b)
        off = id3_size(b)
        fr = parse_frame(b, off)
        # allow a small resync, and say so if it was needed
        resync = 0
        while fr is None and off < len(b) - 4 and resync < 4096:
            off += 1
            resync += 1
            fr = parse_frame(b, off)
        if fr is None:
            print("%-34s NO MPEG FRAME" % os.path.basename(p))
            continue
        first_off = off
        nframes = 0
        bad = 0
        cur = off
        rates = set()
        while cur + 4 <= len(b):
            f2 = parse_frame(b, cur)
            if f2 is None:
                bad += 1
                break
            rates.add(f2["bitrate"])
            nframes += 1
            cur += f2["len"]
        exact = nframes * fr["spf"] / float(fr["rate"])
        payload = len(b) - first_off
        nominal = payload * 8.0 / fr["bitrate"]
        x = xing(b, first_off, fr)
        tot_bytes += len(b)
        tot_exact += exact
        tot_nominal += nominal
        key = (fr["bitrate"], fr["rate"], fr["mode"], fr["version"],
               len(rates) == 1)
        kinds[key] = kinds.get(key, 0) + 1
        rows.append((os.path.basename(p), len(b), fr, exact, nominal, tags, x,
                     nframes, bad, len(rates)))
        print("%-34s %11d %8d %8d %6s %-12s %8.2f %9.2f" %
              (os.path.basename(p)[:34], len(b), fr["bitrate"] // 1000,
               fr["rate"], "mono" if fr["mode"] == "mono" else "st",
               fr["version"], exact, nominal))
    print("-" * 118)
    print("files              : %d" % len(rows))
    print("bytes              : %d" % tot_bytes)
    print("exact duration     : %.2f s = %.2f min" % (tot_exact, tot_exact / 60))
    print("nominal duration   : %.2f s = %.2f min" % (tot_nominal,
                                                      tot_nominal / 60))
    print("distinct headers   : %d" % len(kinds))
    for k, v in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print("   %d kbit/s %d Hz %s %s  cbr=%s  x%d"
              % (k[0] // 1000, k[1], k[2], k[3], k[4], v))
    allx = [r[6] for r in rows if r[6]]
    print("Xing/Info frames   : %d of %d" % (len(allx), len(rows)))
    lames = sorted(set(x[3] for x in allx if x[3]))
    print("encoder strings    : %s" % (lames if lames else "none"))
    tagged = [r for r in rows if r[5]]
    print("ID3v2 tags         : %d of %d" % (len(tagged), len(rows)))
    keys = sorted({k for r in rows for k in r[5]})
    print("ID3 frames present : %s" % (keys if keys else "none"))
    for r in rows[:3]:
        if r[5]:
            print("   %s -> %s" % (r[0], r[5]))
    nonlinear = [r[0] for r in rows if r[8]]
    print("files whose frame walk broke early : %d %s"
          % (len(nonlinear), nonlinear[:5]))
    vbr = [r[0] for r in rows if r[9] > 1]
    print("files with more than one bit rate  : %d %s" % (len(vbr), vbr[:5]))

    if args.tsv:
        with open(args.tsv, "w", encoding="utf-8") as o:
            o.write("file\tbytes\tkbps\thz\tmode\tversion\texact_s\tnominal_s\n")
            for r in rows:
                o.write("%s\t%d\t%d\t%d\t%s\t%s\t%.3f\t%.3f\n"
                        % (r[0], r[1], r[2]["bitrate"] // 1000, r[2]["rate"],
                           r[2]["mode"], r[2]["version"], r[3], r[4]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
