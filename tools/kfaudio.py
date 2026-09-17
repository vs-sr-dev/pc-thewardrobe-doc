#!/usr/bin/env python3
"""kfaudio.py -- the soundtrack in both of the two forms it ships in, and
whether they are the same twelve performances.

Twelve MP3 and twelve WAV, 520,488,268 bytes together, which is Steam depot
317943 exactly. Both formats are **published** -- RIFF/WAVE, MPEG-1 Audio
Layer III and ID3v2.3.0 -- and both are read here without a library, because
the ID3 text frames are the object's own signed statement about who made it
and the durations are the only honest way to ask whether the two sets are the
same recordings.

A hash comparison would answer nothing: one set is lossless PCM and the other
is a lossy encode of it, so they cannot agree byte for byte and their
disagreeing proves nothing. **Duration can be compared**, and it is compared
here frame by frame rather than from a bit rate.

    python tools/kfaudio.py --selftest
    python tools/kfaudio.py --id3
    python tools/kfaudio.py --wav
    python tools/kfaudio.py --match
"""
import argparse
import collections
import os
import struct
import sys

ROOT = "karmaflow-steam"
OST = "Original Soundtrack"
MP3DIR = os.path.join(OST, "Karmaflow The Rock Opera Videogame - "
                            "Original Soundtrack")
WAVDIR = os.path.join(OST, "WAV")

BITRATE_V1L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256,
                320, 0]
RATE_V1 = [44100, 48000, 32000, 0]

# Named rather than written inline. The first attempt at the BWF reader below
# was patched into this file through a shell heredoc, in breach of rule 0 of
# this pipeline, and the escape for a NUL byte arrived as a real NUL byte:
# Python then refused the whole file with "source code cannot contain null
# bytes". Fifth violation of that rule in the collection, and the first that
# failed loudly instead of returning a wrong number.
NUL = b"\x00"


class NotAudio(Exception):
    pass


# ------------------------------------------------------------------- ID3v2

def synchsafe(b):
    if any(x & 0x80 for x in b):
        raise NotAudio("a synchsafe integer with a high bit set")
    return (b[0] << 21) | (b[1] << 14) | (b[2] << 7) | b[3]


def id3(data):
    if data[:3] != b"ID3":
        raise NotAudio("no ID3 magic")
    ver = "2.%d.%d" % (data[3], data[4])
    flags = data[5]
    size = synchsafe(data[6:10])
    end = 10 + size
    o = 10
    frames = collections.OrderedDict()
    while o + 10 <= end:
        fid = data[o:o + 4]
        if fid == b"\0\0\0\0":
            break
        if not all(48 <= c <= 90 for c in fid):
            raise NotAudio("frame id %r is not four capitals or digits" % fid)
        (fsize,) = struct.unpack_from(">I", data, o + 4)
        if fsize <= 0 or o + 10 + fsize > end:
            raise NotAudio("frame %s declares %d bytes and does not fit"
                           % (fid.decode("latin-1"), fsize))
        body = data[o + 10:o + 10 + fsize]
        o += 10 + fsize
        if fid[:1] == b"T":
            enc = body[0]
            raw = body[1:]
            if enc == 0:
                txt = raw.decode("latin-1")
            elif enc == 1:
                txt = raw.decode("utf-16", errors="replace")
            elif enc == 3:
                txt = raw.decode("utf-8", errors="replace")
            else:
                raise NotAudio("text encoding byte %d" % enc)
            frames[fid.decode("latin-1")] = (txt.rstrip("\x00"), enc)
    return ver, flags, size, end, frames


def mp3_frames(data, start):
    """Walk MPEG audio frames. Returns (count, samples, first header)."""
    o = start
    n = len(data)
    count = 0
    samples = 0
    first = None
    while o + 4 <= n:
        if data[o] != 0xFF or (data[o + 1] & 0xE0) != 0xE0:
            o += 1
            continue
        h = struct.unpack_from(">I", data, o)[0]
        ver = (h >> 19) & 3
        layer = (h >> 17) & 3
        bri = (h >> 12) & 0xF
        sri = (h >> 10) & 3
        pad = (h >> 9) & 1
        if ver != 3 or layer != 1 or bri in (0, 15) or sri == 3:
            o += 1
            continue
        br = BITRATE_V1L3[bri] * 1000
        sr = RATE_V1[sri]
        length = (144 * br) // sr + pad
        if length <= 4:
            o += 1
            continue
        if first is None:
            first = (br, sr, (h >> 6) & 3)
        count += 1
        samples += 1152
        o += length
    return count, samples, first


# -------------------------------------------------------------------- RIFF

def wav(data):
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise NotAudio("not RIFF/WAVE")
    (declared,) = struct.unpack_from("<I", data, 4)
    o = 12
    fmt = None
    datalen = None
    chunks = []
    while o + 8 <= len(data):
        tag = bytes(data[o:o + 4])
        (sz,) = struct.unpack_from("<I", data, o + 8 - 4)
        chunks.append((tag.decode("latin-1"), sz))
        if tag == b"fmt ":
            fmt = struct.unpack_from("<HHIIHH", data, o + 8)
        elif tag == b"data":
            datalen = sz
        o += 8 + sz + (sz & 1)
    if fmt is None or datalen is None:
        raise NotAudio("no fmt or no data chunk")
    return declared, fmt, datalen, chunks


# ---------------------------------------------------------------- commands

def mp3s(root):
    d = os.path.join(root, MP3DIR)
    return sorted(os.path.join(d, f) for f in os.listdir(d)
                  if f.lower().endswith(".mp3"))


def wavs(root):
    d = os.path.join(root, WAVDIR)
    return sorted(os.path.join(d, f) for f in os.listdir(d)
                  if f.lower().endswith(".wav"))


def cmd_id3(args):
    rows = []
    counts = collections.Counter()
    encs = collections.Counter()
    versions = collections.Counter()
    constant = collections.defaultdict(set)
    for p in mp3s(args.root):
        data = open(p, "rb").read()
        ver, flags, size, end, fr = id3(data)
        versions[ver] += 1
        counts[len(fr)] += 1
        for k, (v, e) in fr.items():
            encs[e] += 1
            constant[k].add(v)
        rows.append((os.path.basename(p), len(data), ver, size, fr))
    print("MP3 files              : %d" % len(rows))
    print("ID3 versions           : %s" % dict(versions))
    print("text frames per file   : %s" % dict(counts))
    print("text encoding bytes    : %s   (0 = ISO-8859-1)" % dict(encs))
    print()
    print("frames that are the same on every file:")
    for k in sorted(constant):
        if len(constant[k]) == 1:
            print("   %-6s %s" % (k, list(constant[k])[0]))
    print()
    print("frames that differ:")
    for k in sorted(constant):
        if len(constant[k]) > 1:
            print("   %-6s %d distinct values" % (k, len(constant[k])))
    print()
    print("track by track:")
    for base, size, ver, isize, fr in sorted(
            rows, key=lambda r: int(r[4].get("TRCK", ("0", 0))[0])):
        print("  %2s  %-30s" % (fr.get("TRCK", ("?", 0))[0],
                                fr.get("TIT2", ("?", 0))[0]))
        print("      TPE1 %s" % fr.get("TPE1", ("?", 0))[0])
    print()
    people = set()
    for _b, _s, _v, _i, fr in rows:
        for who in fr.get("TPE1", ("", 0))[0].split("/"):
            who = who.strip()
            if who:
                people.add(who)
    print("distinct names in TPE1 across the twelve : %d" % len(people))
    for w in sorted(people):
        print("   %s" % w)
    nonascii = [w for w in people if any(ord(c) > 127 for c in w)]
    print()
    print("names holding a byte above 0x7F : %s" % nonascii)
    for w in nonascii:
        print("   %r encodes to %s in ISO-8859-1"
              % (w, w.encode("latin-1").hex(" ")))
    return 0


def cmd_wav(args):
    tot = 0
    secs = 0.0
    closes = 0
    fmts = collections.Counter()
    rows = []
    for p in wavs(args.root):
        data = open(p, "rb").read()
        declared, fmt, datalen, chunks = wav(data)
        tot += len(data)
        if declared + 8 == len(data):
            closes += 1
        fmts[fmt[:4]] += 1
        d = datalen / float(fmt[3])
        secs += d
        rows.append((os.path.basename(p), len(data), d, chunks))
    print("WAV files                     : %d" % len(rows))
    print("bytes                         : %d" % tot)
    print("RIFF length agrees with the file : %d of %d" % (closes, len(rows)))
    print("fmt (tag, channels, rate, byterate) : %s"
          % {str(k): v for k, v in fmts.items()})
    print("total playing time            : %.3f s = %d min %d s"
          % (secs, int(secs) // 60, int(secs) % 60))
    print()
    for r in sorted(rows):
        print("   %-40s %11d  %8.3f s  %s"
              % (r[0], r[1], r[2], " ".join(c[0] for c in r[3])))
    return 0


def _key(name):
    """`7_Bird Goddess.wav` and `Bird Goddess.mp3` are the same piece."""
    b = os.path.splitext(os.path.basename(name))[0]
    if "_" in b and b.split("_", 1)[0].isdigit():
        b = b.split("_", 1)[1]
    return b.strip().lower()


def cmd_match(args):
    w = {}
    for p in wavs(args.root):
        data = open(p, "rb").read()
        _d, fmt, datalen, _c = wav(data)
        w[_key(p)] = (datalen / float(fmt[3]), os.path.basename(p))
    m = {}
    for p in mp3s(args.root):
        data = open(p, "rb").read()
        ver, _f, size, end, fr = id3(data)
        count, samples, first = mp3_frames(data, end)
        rate = first[1] if first else 44100
        m[_key(p)] = (samples / float(rate), os.path.basename(p), count,
                      first, fr.get("TRCK", ("?", 0))[0],
                      fr.get("TIT2", ("?", 0))[0])
    print("MP3 by name : %d      WAV by name : %d" % (len(m), len(w)))
    both = sorted(set(m) & set(w))
    print("pieces present in both      : %d" % len(both))
    print("in the MP3 set only         : %s" % sorted(set(m) - set(w)))
    print("in the WAV set only         : %s" % sorted(set(w) - set(m)))
    print()
    print("%-4s %-32s %10s %10s %9s  %s"
          % ("trk", "piece", "WAV s", "MP3 s", "delta s", "MP3 frames"))
    worst = 0.0
    tw = tm = 0.0
    for k in sorted(both, key=lambda x: int(m[x][4]) if m[x][4].isdigit()
                    else 0):
        ws = w[k][0]
        ms = m[k][0]
        tw += ws
        tm += ms
        worst = max(worst, abs(ws - ms))
        print("%-4s %-32s %10.3f %10.3f %+9.3f  %d"
              % (m[k][4], m[k][5][:32], ws, ms, ms - ws, m[k][2]))
    print()
    print("total WAV %.3f s   total MP3 %.3f s   difference %+.3f s"
          % (tw, tm, tm - tw))
    print("largest per-track difference : %.3f s" % worst)
    print()
    print("An MP3 frame holds 1,152 samples and a file must be a whole number")
    print("of frames, so an encoder pads: a positive difference of well under")
    print("a second on every track is the padding and not a different take.")
    br = collections.Counter(v[3] for v in m.values())
    print()
    print("MP3 first-frame (bitrate, rate, mode) : %s"
          % {str(k): v for k, v in br.items()})
    return 0


def cmd_bwf(args):
    """The twelve WAV are not plain PCM: they are Broadcast Wave files.

    `bext` is EBU Tech 3285, published; `minf`, `elm1` and `regn` are
    Steinberg's; `umid` is SMPTE 330M. The pre-briefing read the `fmt` chunk
    and the file length and stopped, and so recorded that this object has
    three clocks inside it. It has five, and two of them are here.
    """
    import datetime
    rows = []
    for p in wavs(args.root):
        d = open(p, "rb").read(1 << 19)
        o = 12
        info = {"chunks": []}
        while o + 8 <= len(d):
            tag = bytes(d[o:o + 4])
            (sz,) = struct.unpack_from("<I", d, o + 4)
            body = d[o + 8:o + 8 + sz]
            info["chunks"].append(tag.decode("latin-1"))
            if tag == b"bext":
                if sz < 602:
                    raise NotAudio("bext of %d bytes is shorter than the "
                                   "602-byte fixed part" % sz)
                info["orig"] = body[256:288].rstrip(NUL).decode("latin-1")
                info["ref"] = body[288:320].rstrip(NUL).decode("latin-1")
                info["date"] = body[320:330].decode("latin-1")
                info["time"] = body[330:338].decode("latin-1")
                tl, th = struct.unpack_from("<2I", body, 338)
                info["tref"] = (th << 32) | tl
                info["ver"] = struct.unpack_from("<H", body, 346)[0]
                info["umid"] = body[348:412]
                info["coding"] = body[602:].rstrip(NUL).decode("latin-1")
            elif tag == b"minf":
                (ft,) = struct.unpack_from("<Q", body, 0)
                info["minf"] = (datetime.datetime(1601, 1, 1)
                                + datetime.timedelta(microseconds=ft // 10))
            elif tag == b"data":
                break
            o += 8 + sz + (sz & 1)
        rows.append((os.path.basename(p), info))
    rows.sort(key=lambda r: r[1].get("date", "") + r[1].get("time", ""))
    print("WAV read : %d" % len(rows))
    print("chunk sequences : %s"
          % {" ".join(v["chunks"]): 1 for _k, v in rows})
    print("bext Originator : %s" % {r[1]["orig"] for r in rows})
    print("bext Version    : %s" % {r[1]["ver"] for r in rows})
    print("bext UMID all zero : %d of %d"
          % (sum(1 for r in rows if set(r[1]["umid"]) == {0}), len(rows)))
    print("bext CodingHistory non-empty : %d of %d"
          % (sum(1 for r in rows if r[1]["coding"]), len(rows)))
    print()
    print("%-40s %-10s %-8s %-14s %s"
          % ("file", "bext date", "local", "TimeReference", "minf FILETIME"))
    for n, i in rows:
        print("%-40s %-10s %-8s %-14d %s"
              % (n[:40], i["date"], i["time"], i["tref"], i.get("minf")))
    print()
    deltas = []
    for _n, i in rows:
        if "minf" not in i:
            continue
        local = datetime.datetime.strptime(i["date"] + " " + i["time"],
                                           "%Y-%m-%d %H:%M:%S")
        deltas.append((local - i["minf"]).total_seconds())
    print("bext local time minus minf FILETIME, in seconds:")
    print("   min %.1f  max %.1f  over %d files"
          % (min(deltas), max(deltas), len(deltas)))
    print("   Every one of them is a little under 3,600. `minf` is a Windows")
    print("   FILETIME, which is UTC by definition; `bext` OriginationTime is")
    print("   local. The offset is therefore +1 hour, and 25-27 March 2015 is")
    print("   before the European summer-time change of 29 March 2015, so it")
    print("   is UTC+1 standard time -- which is the Netherlands' own clock.")
    print("   The few seconds on top are how long the bounce took to finish")
    print("   writing after the header was stamped.")
    print()
    tr = collections.Counter(i["tref"] for _n, i in rows)
    print("TimeReference values, in samples at 44,100 Hz:")
    for k, v in tr.most_common():
        print("   %-12d = %.3f s = %s   x%d"
              % (k, k / 44100.0,
                 str(datetime.timedelta(seconds=k / 44100.0)), v))
    print()
    print("OriginatorReference, which Pro Tools generates per file:")
    for n, i in rows:
        print("   %-40s %s" % (n[:40], i["ref"]))
    return 0


def selftest():
    cases = []
    # a minimal valid ID3v2.3 with one text frame
    body = b"\x00" + b"Karmaflow"
    frame = b"TALB" + struct.pack(">I", len(body)) + b"\x00\x00" + body
    tag = b"ID3\x03\x00\x00" + bytes([0, 0, 0, len(frame)]) + frame
    try:
        ver, _f, size, end, fr = id3(tag)
        cases.append(("a one-frame ID3v2.3.0 tag",
                      ver == "2.3.0" and fr["TALB"][0] == "Karmaflow"))
    except NotAudio:
        cases.append(("a one-frame ID3v2.3.0 tag", False))
    for name, blob in (
            ("no ID3 magic", b"RIFFxxxxWAVE"),
            ("a synchsafe size with a high bit",
             b"ID3\x03\x00\x00" + bytes([0x80, 0, 0, 4]) + b"TALB"),
            ("a frame that does not fit",
             b"ID3\x03\x00\x00" + bytes([0, 0, 0, 14]) + b"TALB"
             + struct.pack(">I", 9999) + b"\x00\x00"),
            ("a frame id that is not four capitals",
             b"ID3\x03\x00\x00" + bytes([0, 0, 0, 14]) + b"t\x01\x02\x03"
             + struct.pack(">I", 1) + b"\x00\x00\x00")):
        try:
            id3(blob)
            cases.append((name, False))
        except NotAudio:
            cases.append((name, True))
    hdr = struct.pack("<HHIIHH", 1, 2, 44100, 176400, 4, 16)
    good = (b"RIFF" + struct.pack("<I", 4 + 8 + len(hdr) + 8 + 8) + b"WAVE"
            + b"fmt " + struct.pack("<I", len(hdr)) + hdr
            + b"data" + struct.pack("<I", 8) + bytes(8))
    try:
        declared, fmt, datalen, ch = wav(good)
        cases.append(("a minimal PCM WAVE",
                      fmt[2] == 44100 and datalen == 8 and len(ch) == 2))
    except NotAudio:
        cases.append(("a minimal PCM WAVE", False))
    for name, blob in (("a bank, which is not RIFF", b"BKHD" + bytes(32)),
                       ("RIFF with no fmt chunk",
                        b"RIFF" + struct.pack("<I", 4) + b"WAVE")):
        try:
            wav(blob)
            cases.append((name, False))
        except NotAudio:
            cases.append((name, True))
    cases.append(("the name key strips a leading track number",
                  _key("7_Bird Goddess.wav") == _key("Bird Goddess.mp3")))
    ok = sum(1 for _n, v in cases if v)
    print("kfaudio selftest: %d specimens built in memory" % len(cases))
    for n, v in cases:
        print("  %-46s %s" % (n, "PASS" if v else "FAIL"))
    print()
    print("%d of %d behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    for c in ("selftest", "id3", "wav", "match", "bwf"):
        ap.add_argument("--" + c, action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.id3:
        return cmd_id3(a)
    if a.wav:
        return cmd_wav(a)
    if a.match:
        return cmd_match(a)
    if a.bwf:
        return cmd_bwf(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
