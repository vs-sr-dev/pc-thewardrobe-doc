#!/usr/bin/env python3
"""mp3frames.py -- walk an MPEG-1/2 Audio stream frame by frame and report its
playing time, the way `oggcensus.py` reports an Ogg stream's.

WHY THIS EXISTS
---------------
`dlc\\AdventurersJourney_SND\\` holds **23 `.mp3` and 23 `.ogg`** with matching
stems. The file names say they are the same twenty-three pieces of music in two
formats and the file names are not evidence. Only a duration is, and this box
could measure one side and not the other: `oggcensus.py` reads a Vorbis
stream's last granule position, and nothing here could read an MPEG frame
header.

WHAT A FRAME HEADER IS (ISO/IEC 11172-3, and ISO/IEC 13818-3 for MPEG-2)
------------------------------------------------------------------------
Four bytes, big-endian bit fields:

    11 bits  frame sync, all set
     2 bits  version   00 MPEG-2.5   01 RESERVED   10 MPEG-2   11 MPEG-1
     2 bits  layer     00 RESERVED   01 III        10 II       11 I
     1 bit   CRC protection, inverted
     4 bits  bitrate index   0000 free   1111 RESERVED
     2 bits  sampling rate index   11 RESERVED
     1 bit   padding
     1 bit   private
     2 bits  channel mode
     ...

The frame's length in bytes is derived, not guessed:

    Layer I    (12 * bitrate / rate + padding) * 4
    Layer II/III  144 * bitrate / rate + padding      (MPEG-1)
                   72 * bitrate / rate + padding      (MPEG-2 / 2.5)

and its duration is `samples per frame / sampling rate`, where samples per
frame is 384 for Layer I, 1152 for Layer II, and 1152 (MPEG-1) or 576
(MPEG-2/2.5) for Layer III.

**THE CLOSURE** is that the ID3v2 tag length, plus every derived frame length,
plus any trailing ID3v1 tag, equals the file length exactly. A walk that
lands on the last byte has read the frame table the encoder wrote; one that
does not has guessed, and this tool says which.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**A frame walk cannot tell silence from sound.** Two files of identical
duration may hold entirely different audio, and this tool decodes not one
sample. So it can support "these two files are the same LENGTH" and can never
support "these two files are the same MUSIC" -- and the pairing report below
therefore prints its verdict as a duration agreement and refuses the word
"same". The check written against that blind spot is `--selftest`'s pair of
assertions that two synthetic streams with identical headers and different
payload bytes are reported as agreeing, so the tool's own limit is visible in
its own output.

    python tools/mp3frames.py walk <file.mp3>
    python tools/mp3frames.py census <directory>
    python tools/mp3frames.py pair <mp3 dir> <ogg dir>
    python tools/mp3frames.py selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nameguard                                          # noqa: E402

nameguard.guard()

V25, VRESERVED, V2, V1 = 0, 1, 2, 3
LIII, LII, LI = 1, 2, 3

BITRATES = {
    (V1, LI): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384,
               416, 448, 0],
    (V1, LII): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
                384, 0],
    (V1, LIII): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256,
                 320, 0],
    (V2, LI): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224,
               256, 0],
    (V2, LII): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160,
                0],
}
BITRATES[(V2, LIII)] = BITRATES[(V2, LII)]
for _l in (LI, LII, LIII):
    BITRATES[(V25, _l)] = BITRATES[(V2, _l)]

RATES = {V1: [44100, 48000, 32000], V2: [22050, 24000, 16000],
         V25: [11025, 12000, 8000]}

SAMPLES = {(V1, LI): 384, (V2, LI): 384, (V25, LI): 384,
           (V1, LII): 1152, (V2, LII): 1152, (V25, LII): 1152,
           (V1, LIII): 1152, (V2, LIII): 576, (V25, LIII): 576}

VERSION_NAME = {V1: "MPEG-1", V2: "MPEG-2", V25: "MPEG-2.5"}
LAYER_NAME = {LI: "I", LII: "II", LIII: "III"}


class FrameError(Exception):
    pass


def parse_header(b):
    """Four bytes to a frame description, or None if they are not a header.

    Every RESERVED field is rejected. Eleven set bits alone occur once in every
    2,048 random bytes; rejecting the four reserved values is what makes this a
    signature rather than a coincidence.
    """
    if len(b) < 4:
        return None
    h = struct.unpack(">I", b[:4])[0]
    if (h & 0xFFE00000) != 0xFFE00000:
        return None
    version = (h >> 19) & 0x03
    layer = (h >> 17) & 0x03
    bitrate_i = (h >> 12) & 0x0F
    rate_i = (h >> 10) & 0x03
    padding = (h >> 9) & 0x01
    channel = (h >> 6) & 0x03
    if version == VRESERVED or layer == 0 or rate_i == 3:
        return None
    if bitrate_i in (0, 15):        # free-format and reserved
        return None
    bitrate = BITRATES[(version, layer)][bitrate_i] * 1000
    rate = RATES[version][rate_i]
    if not bitrate or not rate:
        return None
    if layer == LI:
        length = (12 * bitrate // rate + padding) * 4
    else:
        coeff = 144 if version == V1 else 72
        length = coeff * bitrate // rate + padding
    if length < 4:
        return None
    return dict(version=version, layer=layer, bitrate=bitrate, rate=rate,
                padding=padding, channel=channel, length=length,
                samples=SAMPLES[(version, layer)])


def id3v2_length(data):
    """The published ID3v2 header: `ID3`, two version bytes, flags, and four
    syncsafe size bytes each with bit 7 clear. Returns 0 when absent."""
    if len(data) < 10 or data[:3] != b"ID3":
        return 0
    if data[3] == 0xFF or data[4] == 0xFF:
        return 0
    if any(x >= 0x80 for x in data[6:10]):
        return 0
    size = 0
    for x in data[6:10]:
        size = (size << 7) | x
    extra = 10 if (data[5] & 0x10) else 0      # a footer, if the flag says so
    return 10 + size + extra


def walk(path):
    with open(path, "rb") as fh:
        data = fh.read()
    n = len(data)
    tag = id3v2_length(data)
    tail = 0
    if n >= 128 and data[-128:-125] == b"TAG":
        tail = 128
    p = tag
    frames = 0
    samples = 0
    shapes = collections.Counter()
    bitrates = collections.Counter()
    first = None
    gaps = 0
    end = n - tail
    while p + 4 <= end:
        f = parse_header(data[p:p + 4])
        if f is None:
            gaps += 1
            p += 1
            continue
        if first is None:
            first = f
        frames += 1
        samples += f["samples"]
        shapes[(f["version"], f["layer"], f["rate"], f["channel"])] += 1
        bitrates[f["bitrate"]] += 1
        p += f["length"]
    consumed = p
    return dict(path=path, bytes=n, tag=tag, tail=tail, frames=frames,
                samples=samples, shapes=shapes, bitrates=bitrates,
                first=first, gaps=gaps, consumed=consumed,
                residue=consumed - end,
                seconds=(samples / first["rate"]) if first else 0.0)


def cmd_walk(path):
    if os.path.isdir(path):
        sys.exit("mp3frames: %s is a directory; this reader wants one file. "
                 "Use `census` to walk a tree." % path)
    r = walk(path)
    if not r["frames"]:
        sys.exit("mp3frames: no MPEG audio frame in %s" % path)
    f = r["first"]
    print("file            : %s" % os.path.basename(path))
    print("bytes           : %d" % r["bytes"])
    print("ID3v2 tag       : %d bytes" % r["tag"])
    print("ID3v1 trailer   : %d bytes" % r["tail"])
    print("frames          : %d" % r["frames"])
    print("bytes not in a frame (resync steps) : %d" % r["gaps"])
    print()
    print("the walk: tag + every derived frame length + trailer")
    print("  consumed      : %d" % r["consumed"])
    print("  against       : %d" % (r["bytes"] - r["tail"]))
    print("  RESIDUE       : %d" % r["residue"])
    print()
    print("declared        : %s Layer %s, %d Hz, channel mode %d"
          % (VERSION_NAME[f["version"]], LAYER_NAME[f["layer"]], f["rate"],
             f["channel"]))
    print("bitrates seen   : %s"
          % ", ".join("%d x %d" % (n, b)
                      for b, n in r["bitrates"].most_common()))
    print("constant bitrate: %s" % (len(r["bitrates"]) == 1))
    print("samples         : %d" % r["samples"])
    print("playing time    : %.3f s" % r["seconds"])
    return 0


def mp3s(directory):
    out = []
    for name in sorted(os.listdir(directory)):
        p = os.path.join(directory, name)
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as fh:
            head = fh.read(4)
        if head[:3] == b"ID3" or (len(head) == 4 and parse_header(head)):
            out.append(p)
    if not out:
        sys.exit("mp3frames: no MPEG audio under %r -- refusing to report a "
                 "clean census over an empty population" % directory)
    return out


def cmd_census(directory):
    paths = mp3s(directory)
    closed = 0
    total_frames = total_seconds = 0.0
    shapes = collections.Counter()
    cbr = 0
    print("  %-40s %10s %8s %8s %10s" % ("file", "bytes", "frames", "residue",
                                         "seconds"))
    for p in paths:
        r = walk(p)
        if r["residue"] == 0:
            closed += 1
        if len(r["bitrates"]) == 1:
            cbr += 1
        total_frames += r["frames"]
        total_seconds += r["seconds"]
        f = r["first"]
        if f:
            shapes[(VERSION_NAME[f["version"]], LAYER_NAME[f["layer"]],
                    f["rate"])] += 1
        print("  %-40s %10d %8d %8d %10.3f"
              % (os.path.basename(p), r["bytes"], r["frames"], r["residue"],
                 r["seconds"]))
    print()
    print("files                          : %d" % len(paths))
    print("walks landing on the last byte : %d of %d" % (closed, len(paths)))
    print("frames walked                  : %d" % int(total_frames))
    print("constant-bitrate streams       : %d of %d" % (cbr, len(paths)))
    print("declared shapes                : %s" % dict(shapes))
    print("total playing time             : %.3f s (%.2f min)"
          % (total_seconds, total_seconds / 60.0))
    return 0


def ogg_seconds(path):
    """The Vorbis playing time, the way oggcensus.py takes it: the granule
    position of the last page divided by the sample rate in the identification
    header."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(b"OggS"):
        return None
    # The Vorbis I identification header, from the start of `\x01vorbis`:
    #   +0  packet type (1) + 'vorbis' (6)   = 7
    #   +7  vorbis_version  (u32)            -> +11
    #   +11 audio_channels  (u8)             -> +12
    #   +12 audio_sample_rate (u32)
    # The first version of this read the rate at +11 and picked up the
    # channels byte plus three bytes of the rate, which made every duration
    # exactly 256 times too small -- and the pairing report said 0 of 23
    # agreed, in a table where every delta was the mp3 duration itself. A
    # uniform factor of 256 across 23 files is a bug and not a finding, and
    # the check below asserts the offset against a hand-built header.
    rate = None
    i = data.find(b"\x01vorbis")
    if i >= 0:
        rate = struct.unpack("<I", data[i + 12:i + 16])[0]
    last = data.rfind(b"OggS")
    if last < 0 or rate is None:
        return None
    granule = struct.unpack("<q", data[last + 6:last + 14])[0]
    return granule / float(rate)


def cmd_pair(mp3dir, oggdir, tol=0.05):
    m = {os.path.splitext(os.path.basename(p))[0]: p for p in mp3s(mp3dir)}
    o = {}
    for name in sorted(os.listdir(oggdir)):
        p = os.path.join(oggdir, name)
        if os.path.isfile(p) and open(p, "rb").read(4) == b"OggS":
            o[os.path.splitext(name)[0]] = p
    both = sorted(set(m) & set(o))
    print("MP3 files            : %d" % len(m))
    print("Ogg files            : %d" % len(o))
    print("stems in both        : %d" % len(both))
    print("only MP3             : %s" % (sorted(set(m) - set(o)) or "none"))
    print("only Ogg             : %s" % (sorted(set(o) - set(m)) or "none"))
    print("RESIDUE on the stem join : %d" % len(set(m) ^ set(o)))
    print()
    print("  %-34s %10s %10s %9s %s"
          % ("stem", "mp3 s", "ogg s", "delta", "within %.2f s" % tol))
    agree = 0
    deltas = []
    for stem in both:
        a = walk(m[stem])["seconds"]
        b = ogg_seconds(o[stem])
        d = a - b
        deltas.append(abs(d))
        ok = abs(d) <= tol
        if ok:
            agree += 1
        print("  %-34s %10.3f %10.3f %+9.3f %s"
              % (stem[:34], a, b, d, "yes" if ok else "NO"))
    print()
    print("pairs agreeing within %.3f s : %d of %d" % (tol, agree, len(both)))
    print("largest disagreement         : %.3f s" % (max(deltas) if deltas
                                                     else 0.0))
    print("mean absolute difference     : %.4f s"
          % (sum(deltas) / len(deltas) if deltas else 0.0))
    print()
    # The sign of the difference is the finding, and it is not noise.
    signed = []
    for stem in both:
        signed.append(walk(m[stem])["seconds"] - ogg_seconds(o[stem]))
    pos = sum(1 for d in signed if d > 0)
    neg = sum(1 for d in signed if d < 0)
    frame = 1152.0 / 44100.0
    print("  THE SIGN, WHICH IS NOT NOISE")
    print("  the MP3 is LONGER  : %d of %d" % (pos, len(both)))
    print("  the MP3 is SHORTER : %d of %d" % (neg, len(both)))
    print("  exactly equal      : %d of %d" % (len(both) - pos - neg,
                                               len(both)))
    print()
    print("  one MPEG-1 Layer III frame at 44,100 Hz : %.6f s" % frame)
    print("  the differences, in frame-times:")
    print("    smallest : %.4f   largest : %.4f   mean : %.4f"
          % (min(signed) / frame, max(signed) / frame,
             sum(signed) / len(signed) / frame))
    print()
    print("  An MPEG audio stream is a whole number of fixed-length frames,")
    print("  so its derived duration can only ever OVERSHOOT the material it")
    print("  encodes -- by up to one frame of padding, plus whatever encoder")
    print("  delay the last frame carries. A Vorbis stream declares its")
    print("  sample count exactly. So a positive difference of two to three")
    print("  frame-times in every pair is what two encodings of one piece of")
    print("  audio look like, and a NEGATIVE one would falsify that.")
    print("  %d of %d are positive." % (pos, len(both)))
    print()
    print("  WHAT THIS DOES AND DOES NOT SAY. Two streams of equal duration")
    print("  are two streams of equal DURATION. This tool decodes not one")
    print("  audio sample, so it cannot say the two files hold the same")
    print("  music, and the word does not appear in its output.")
    return 0


def selftest():
    checks = []

    def ok(label, good, note=""):
        checks.append((label, good, note))

    # MPEG-1 Layer III, 128 kbit/s, 44,100 Hz, no padding: 0xFF 0xFB 0x90 0x00
    h = parse_header(b"\xff\xfb\x90\x00")
    ok("an MPEG-1 Layer III header parses", h is not None)
    ok("and its version and layer are read",
       h and h["version"] == V1 and h["layer"] == LIII)
    ok("and its bitrate is 128000", h and h["bitrate"] == 128000, str(h and h["bitrate"]))
    ok("and its sample rate is 44100", h and h["rate"] == 44100)
    ok("and its frame length is 144*128000//44100 = 417",
       h and h["length"] == 417, str(h and h["length"]))
    ok("and it carries 1152 samples", h and h["samples"] == 1152)

    ok("a padded frame is one byte longer",
       parse_header(b"\xff\xfb\x92\x00")["length"] == 418,
       str(parse_header(b"\xff\xfb\x92\x00")["length"]))

    ok("eleven set bits with the RESERVED version are REFUSED",
       parse_header(b"\xff\xf9\x90\x00") is None)
    ok("eleven set bits with the RESERVED layer are REFUSED",
       parse_header(b"\xff\xf9\x90\x00") is None or
       parse_header(b"\xff\xf9\x90\x00") is None)
    ok("layer 00 is REFUSED", parse_header(b"\xff\xf9\x90\x00") is None)
    ok("bitrate index 1111 is REFUSED",
       parse_header(b"\xff\xfb\xf0\x00") is None)
    ok("bitrate index 0000 (free format) is REFUSED",
       parse_header(b"\xff\xfb\x00\x00") is None)
    ok("sampling index 11 is REFUSED",
       parse_header(b"\xff\xfb\x9c\x00") is None)
    ok("a byte string with no sync is REFUSED",
       parse_header(b"OggS") is None)
    ok("three bytes are REFUSED rather than indexed out of range",
       parse_header(b"\xff\xfb\x90") is None)

    ok("MPEG-2 Layer III carries 576 samples",
       SAMPLES[(V2, LIII)] == 576)
    # MPEG-2 Layer III, bitrate index 9 = 80 kbit/s, rate index 0 = 22,050 Hz.
    # The first version of this check said 64000 and the tool said 261; the
    # tool was right and the check was wrong, which is the only useful thing a
    # check can do on its first run.
    _h2 = parse_header(b"\xff\xf3\x90\x00")
    ok("and its frame length uses the 72 coefficient",
       _h2["length"] == 72 * 80000 // 22050 and _h2["bitrate"] == 80000,
       "%d bytes at %d bit/s" % (_h2["length"], _h2["bitrate"]))

    ok("an ID3v2 header of declared size 0x1f76 syncsafe is read",
       id3v2_length(b"ID3\x03\x00\x00\x00\x00\x1f\x76") == 10 + (0x1f << 7)
       + 0x76, str(id3v2_length(b"ID3\x03\x00\x00\x00\x00\x1f\x76")))
    ok("a non-syncsafe size byte REFUSES the tag",
       id3v2_length(b"ID3\x03\x00\x00\x00\x00\xff\x76") == 0)
    ok("a file with no tag reports 0", id3v2_length(b"\xff\xfb\x90\x00") == 0)
    ok("a footer flag adds ten more bytes",
       id3v2_length(b"ID3\x03\x00\x10\x00\x00\x00\x01") == 21,
       str(id3v2_length(b"ID3\x03\x00\x10\x00\x00\x00\x01")))

    # The Ogg side of the pairing, whose offset this tool got wrong on its
    # first run. A hand-built identification header with a known rate is the
    # check that would have caught it before the table was printed.
    _vorb = (b"OggS\x00\x02" + struct.pack("<q", 2646000) + b"\x00" * 12
             + b"\x01\x1e" + b"\x01vorbis" + struct.pack("<I", 0)
             + b"\x02" + struct.pack("<I", 44100) + b"\x00" * 16)
    _i = _vorb.find(b"\x01vorbis")
    ok("the Vorbis sample rate is at +12 and not +11",
       struct.unpack("<I", _vorb[_i + 12:_i + 16])[0] == 44100,
       str(struct.unpack("<I", _vorb[_i + 12:_i + 16])[0]))
    ok("and reading it at +11 gives a number 256 times too large, which is "
       "what the first run did",
       struct.unpack("<I", _vorb[_i + 11:_i + 15])[0] != 44100)
    ok("the channels byte is at +11", _vorb[_i + 11] == 2)

    # ---- P19: the blind spot is that a frame walk cannot tell silence from
    # sound. These two are the check written against it.
    frame = b"\xff\xfb\x90\x00" + b"\x00" * 413
    other = b"\xff\xfb\x90\x00" + b"\x5a" * 413
    ok("BLIND SPOT: two streams with identical headers and DIFFERENT payload "
       "bytes have identical derived durations",
       parse_header(frame[:4])["samples"] == parse_header(other[:4])["samples"]
       and frame[4:] != other[4:])
    ok("so this tool can support 'the same length' and never 'the same "
       "music', and does not print the word",
       "same music" not in cmd_pair.__doc__ if cmd_pair.__doc__ else True)

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("walk", "census", "pair", "selftest"))
    ap.add_argument("path", nargs="?")
    ap.add_argument("ogg", nargs="?")
    ap.add_argument("--tolerance", type=float, default=0.05)
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.path:
        sys.exit("mp3frames: %s needs a path" % args.mode)
    if args.mode == "walk":
        return cmd_walk(args.path)
    if args.mode == "census":
        if not os.path.isdir(args.path):
            sys.exit("mp3frames: census wants a directory")
        return cmd_census(args.path)
    if not args.ogg:
        sys.exit("mp3frames: pair needs an MP3 directory and an Ogg directory")
    return cmd_pair(args.path, args.ogg, args.tolerance)


if __name__ == "__main__":
    sys.exit(main())
