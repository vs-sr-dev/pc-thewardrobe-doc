#!/usr/bin/env python3
"""mp4box.py -- the ISO base media box tree, and the sample table under it.

WHY THIS EXISTS
---------------
`pc-rpgmakervxace-doc` shipped `mp3frames.py`, which walks MPEG-1 Layer III
frames, and used it to answer one question about 23 pairs of audio files: is
the frame-based format longer than the sample-based one, and by how much? It
was, in 23 of 23, by two to three frame-times, and the explanation is that a
frame-based format can only overshoot -- the last frame is padded out to a
whole frame whatever the source did.

`pc-rpgmakermv-doc` ships **1,341 `.ogg` and 1,341 `.m4a`**, the same stems on
both sides at residue 0 in both directions, and `mp3frames.py` will not read
one byte of an MPEG-4 file. This tool is the other side of that join.

THE FORMAT
----------
ISO/IEC 14496-12. A file is a sequence of boxes and nothing else. A box is

    u32 size | u32 type | payload

where `size` counts the header, `size == 1` means a 64-bit `largesize` follows
the type, and `size == 0` means the box runs to the end of the file. Container
boxes hold nothing but more boxes. There is no index and no directory: the tree
is walked by addition, which is why a walk that lands exactly on the last byte
is evidence and a walk that lands anywhere else is a refusal.

The duration is declared three times, and the three do not have to agree:

  * `mvhd`   the movie header -- duration / timescale, the container's claim;
  * `mdhd`   the media header of a track -- the same in the track's own units;
  * `stts`   the decoding-time-to-sample table -- sum of count x delta, which
             is what the SAMPLES actually add up to.

For AAC in an M4A the samples are access units of 1,024 PCM samples each, so
`stts` also gives the frame count, and one frame-time is 1024 / timescale.
**That is the unit the comparison against Ogg has to be quoted in**, because a
difference smaller than one frame-time is quantisation and a difference larger
than one is a different recording.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**A box tree that closes is not a file that plays.** This tool decodes no
audio. It reads the tables that say how long the audio is, and every one of
those tables is the encoder's assertion; a file whose `mdat` is entirely zeroes
walks, closes at residue 0, reports a duration and is silence. `--selftest`
therefore builds a file whose `stts` disagrees with its `mdhd` and requires the
tool to report BOTH rather than reconcile them, because a reader that quietly
prefers one number has thrown away the only evidence that something is wrong.

The second thing it cannot see is the **encoder delay**. An AAC stream begins
with priming samples that are not part of the recording, and the conventional
place to declare them is an edit list (`elst`) or an iTunes `----` atom. This
tool reports whether an `elst` is present and does not attempt to apply it, and
the census prints that count so that a session cannot silently assume the
durations are trimmed.

    python tools/mp4box.py validate rpgmakermv-steam/NewData/audio/bgm/x.m4a
    python tools/mp4box.py show <file>
    python tools/mp4box.py census rpgmakermv-steam
    python tools/mp4box.py --selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"udta",
              b"mvex", b"dinf", b"stsd", b"mp4a", b"wave", b"ilst"}
# `stsd` and `mp4a` are containers with a fixed preamble in front of the
# children; they are walked only by `show`, which knows the preamble lengths.
PREAMBLE = {b"stsd": 8, b"mp4a": 28}


class Mp4Error(Exception):
    pass


def boxes(blob, start=0, end=None, path="<bytes>"):
    """Yield (offset, size, type, payload_offset) over one level of the tree.

    Raises Mp4Error rather than returning a short walk, because a box tree that
    does not close is the finding and swallowing it produces a census over a
    population that was never verified.
    """
    if end is None:
        end = len(blob)
    p = start
    while p < end:
        if end - p < 8:
            raise Mp4Error("%s: %d trailing bytes at %d, which is less than a "
                           "box header" % (path, end - p, p))
        size, typ = struct.unpack_from(">I4s", blob, p)
        hdr = 8
        if size == 1:
            if end - p < 16:
                raise Mp4Error("%s: 64-bit size at %d with no room for it"
                               % (path, p))
            size = struct.unpack_from(">Q", blob, p + 8)[0]
            hdr = 16
        elif size == 0:
            size = end - p
        if size < hdr:
            raise Mp4Error("%s: box %r at %d declares size %d, shorter than "
                           "its own header" % (path, typ, p, size))
        if p + size > end:
            raise Mp4Error("%s: box %r at %d declares size %d and overruns "
                           "the file by %d" % (path, typ, p, size,
                                               p + size - end))
        yield (p, size, typ, p + hdr)
        p += size
    if p != end:
        raise Mp4Error("%s: walk ended at %d, not %d" % (path, p, end))


def _walk(blob, start, end, path, depth, out):
    for off, size, typ, poff in boxes(blob, start, end, path):
        out.append((depth, off, size, typ))
        if typ in CONTAINERS:
            _walk(blob, poff + PREAMBLE.get(typ, 0), off + size, path,
                  depth + 1, out)


def tree(blob, path="<bytes>"):
    out = []
    _walk(blob, 0, len(blob), path, 0, out)
    return out


def _find(blob, want, path):
    """Depth-first search for the first box of a given type. Returns
    (offset, size, payload_offset) or None."""
    stack = [(0, len(blob))]
    while stack:
        start, end = stack.pop(0)
        for off, size, typ, poff in boxes(blob, start, end, path):
            if typ == want:
                return (off, size, poff)
            if typ in CONTAINERS:
                stack.append((poff + PREAMBLE.get(typ, 0), off + size))
    return None


def _fullbox(blob, poff):
    """Version and flags of a FullBox; returns (version, flags, body_offset)."""
    v = blob[poff]
    flags = int.from_bytes(blob[poff + 1:poff + 4], "big")
    return v, flags, poff + 4


# ISO/IEC 14496-3, Table 1.18: the sampling frequency index of an
# AudioSpecificConfig. Index 15 means an explicit 24-bit rate follows.
ASC_FREQ = (96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
            16000, 12000, 11025, 8000, 7350, None, None, None)


def _descriptor(blob, p, end):
    """One MPEG-4 descriptor header: (tag, body_start, body_end).

    The length is a base-128 varint of at most four bytes, which is the one
    piece of MPEG-4 that is not a plain length-prefixed box and is therefore
    the one place a reader written from memory gets it wrong.
    """
    tag = blob[p]
    p += 1
    n = 0
    for _ in range(4):
        b = blob[p]
        p += 1
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            break
    return tag, p, min(p + n, end)


def audio_specific_config(blob, path="<bytes>"):
    """The AAC decoder's own declaration of rate and channels, from `esds`.

    WHY THIS IS NOT THE `mp4a` BOX'S FIELDS. The AudioSampleEntry carries a
    `channelcount` and a 16.16 `samplerate`, and for AAC both are advisory:
    ISO/IEC 14496-14 says the decoder configuration governs. On this object the
    two disagree about the channel count on **288 of 1,341 files**, the box
    claiming stereo where the configuration says mono. A tool reading only the
    box would have published a channel census that is wrong on 21 % of its
    population and closed at residue 0 while doing it.

    Returns None when there is no `esds`, which is itself a finding.
    """
    found = _find(blob, b"esds", path)
    if not found:
        return None
    _v, _f, b = _fullbox(blob, found[2])
    end = found[0] + found[1]
    tag, p, e = _descriptor(blob, b, end)
    if tag != 0x03:                       # ES_Descriptor
        return None
    p += 2                                # ES_ID
    flags = blob[p]
    p += 1
    if flags & 0x80:                      # streamDependenceFlag
        p += 2
    if flags & 0x40:                      # URL_Flag
        p += 1 + blob[p]
    if flags & 0x20:                      # OCRstreamFlag
        p += 2
    tag, p, e = _descriptor(blob, p, e)
    if tag != 0x04:                       # DecoderConfigDescriptor
        return None
    oti = blob[p]
    p += 13                               # oti, streamType+buffer, 2 bitrates
    tag, p, e = _descriptor(blob, p, e)
    if tag != 0x05:                       # DecoderSpecificInfo
        return None
    cfg = blob[p:e]
    if not cfg:
        return None
    bits = int.from_bytes(cfg[:5].ljust(5, b"\x00"), "big")
    aot = (bits >> 35) & 0x1F
    fi = (bits >> 31) & 0x0F
    ch = (bits >> 27) & 0x0F
    rate = ASC_FREQ[fi] if fi != 15 else (bits >> 7) & 0xFFFFFF
    return dict(object_type_indication=oti, audio_object_type=aot,
                freq_index=fi, rate=rate, channels=ch, config=cfg.hex())


def read(path):
    """Every figure this tool can produce about one file, in one dict."""
    dirguard.want_file(path, "mp4box")
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 12 or blob[4:8] != b"ftyp":
        raise Mp4Error("%s: does not begin with a File Type Box" % path)
    size = struct.unpack_from(">I", blob, 0)[0]
    brand = blob[8:12]
    minor = struct.unpack_from(">I", blob, 12)[0] if size >= 16 else None
    compat = [blob[i:i + 4] for i in range(16, min(size, len(blob)) - 3, 4)]

    top = collections.Counter()
    for _off, _sz, typ, _p in boxes(blob, 0, len(blob), path):
        top[typ.decode("latin-1")] += 1

    out = dict(path=path, bytes=len(blob), ftyp_size=size,
               major_brand=brand.decode("latin-1"), minor_version=minor,
               compatible=[c.decode("latin-1") for c in compat],
               top_level=dict(top), closes=True)

    mvhd = _find(blob, b"mvhd", path)
    if mvhd:
        v, _f, b = _fullbox(blob, mvhd[2])
        if v == 1:
            _c, _m, ts, dur = struct.unpack_from(">QQIQ", blob, b)
        else:
            _c, _m, ts, dur = struct.unpack_from(">IIII", blob, b)
        out.update(mvhd_timescale=ts, mvhd_duration=dur,
                   mvhd_seconds=dur / ts if ts else 0.0)

    mdhd = _find(blob, b"mdhd", path)
    if mdhd:
        v, _f, b = _fullbox(blob, mdhd[2])
        if v == 1:
            _c, _m, ts, dur = struct.unpack_from(">QQIQ", blob, b)
        else:
            _c, _m, ts, dur = struct.unpack_from(">IIII", blob, b)
        out.update(mdhd_timescale=ts, mdhd_duration=dur,
                   mdhd_seconds=dur / ts if ts else 0.0)

    stts = _find(blob, b"stts", path)
    if stts:
        _v, _f, b = _fullbox(blob, stts[2])
        n = struct.unpack_from(">I", blob, b)[0]
        samples = 0
        units = 0
        deltas = collections.Counter()
        for i in range(n):
            c, d = struct.unpack_from(">II", blob, b + 4 + i * 8)
            samples += c
            units += c * d
            deltas[d] += c
        ts = out.get("mdhd_timescale") or out.get("mvhd_timescale") or 0
        out.update(stts_entries=n, samples=samples, stts_units=units,
                   stts_seconds=units / ts if ts else 0.0,
                   sample_deltas=dict(deltas))
        if deltas:
            frame = max(deltas, key=deltas.get)
            out["frame_units"] = frame
            out["frame_seconds"] = frame / ts if ts else 0.0

    mp4a = _find(blob, b"mp4a", path)
    if mp4a:
        # The AudioSampleEntry preamble: 6 reserved, 2 data-reference index,
        # 8 reserved, 2 channel count, 2 sample size, 4 pre-defined+reserved,
        # 4 sample rate as 16.16 fixed point.
        b = mp4a[2]
        ch, ssz = struct.unpack_from(">HH", blob, b + 16)
        rate = struct.unpack_from(">I", blob, b + 24)[0] >> 16
        out.update(box_channels=ch, sample_size=ssz, box_rate=rate)

    cfg = audio_specific_config(blob, path)
    if cfg:
        out.update(asc=cfg, channels=cfg["channels"], sample_rate=cfg["rate"],
                   audio_object_type=cfg["audio_object_type"])
        out["box_agrees_channels"] = out.get("box_channels") == cfg["channels"]
        out["box_agrees_rate"] = out.get("box_rate") == cfg["rate"]
    else:
        # No decoder configuration: fall back on the advisory fields and SAY
        # SO, rather than presenting an advisory number as a measured one.
        out.update(channels=out.get("box_channels"),
                   sample_rate=out.get("box_rate"), asc=None)

    out["has_elst"] = _find(blob, b"elst", path) is not None
    return out


def mp4_files(root):
    """Every MPEG-4 file under a root, SELECTED BY MAGIC and not by name.

    Rule 0's amendment: a tool that selects files selects them by magic. This
    object's 1,341 MPEG-4 files all happen to end `.m4a`, and choosing them by
    that extension would have been a rule about this object rather than about
    the format.
    """
    if not os.path.isdir(root):
        sys.exit("mp4box: %s is not a directory" % root)
    out = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as fh:
                    head = fh.read(12)
            except OSError:
                continue
            if len(head) >= 12 and head[4:8] == b"ftyp":
                sz = struct.unpack_from(">I", head, 0)[0]
                if 16 <= sz <= 1024:
                    out.append(p)
    return out


def cmd_validate(path):
    try:
        r = read(path)
    except Mp4Error as e:
        print("REFUSED: %s" % e)
        return 1
    print("%s" % nameguard.safe(os.path.basename(path))
          if hasattr(nameguard, "safe") else os.path.basename(path))
    print("  bytes            : %d" % r["bytes"])
    print("  major brand      : %s   minor %s   compatible %s"
          % (r["major_brand"], r["minor_version"], " ".join(r["compatible"])))
    print("  top-level boxes  : %s" % r["top_level"])
    print("  mvhd             : %d / %d = %.6f s"
          % (r.get("mvhd_duration", 0), r.get("mvhd_timescale", 0),
             r.get("mvhd_seconds", 0.0)))
    print("  mdhd             : %d / %d = %.6f s"
          % (r.get("mdhd_duration", 0), r.get("mdhd_timescale", 0),
             r.get("mdhd_seconds", 0.0)))
    print("  stts             : %d samples, %d units = %.6f s"
          % (r.get("samples", 0), r.get("stts_units", 0),
             r.get("stts_seconds", 0.0)))
    print("  one frame        : %d units = %.6f s"
          % (r.get("frame_units", 0), r.get("frame_seconds", 0.0)))
    print("  edit list present: %s" % r["has_elst"])
    print("  THE BOX TREE CLOSES ON THE LAST BYTE")
    return 0


def cmd_show(path):
    dirguard.want_file(path, "mp4box")
    with open(path, "rb") as fh:
        blob = fh.read()
    try:
        rows = tree(blob, path)
    except Mp4Error as e:
        print("REFUSED: %s" % e)
        return 1
    for depth, off, size, typ in rows:
        print("  %s%-4s  offset %-10d size %d"
              % ("  " * depth, typ.decode("latin-1"), off, size))
    print()
    print("  %d boxes, and the walk closes on byte %d of %d"
          % (len(rows), len(blob), len(blob)))
    return 0


def cmd_census(root):
    nameguard.guard()
    files = mp4_files(root)
    if not files:
        sys.exit("mp4box: no file under %r begins with a File Type Box -- "
                 "refusing to report a census over an empty population" % root)
    brands = collections.Counter()
    rates = collections.Counter()
    chans = collections.Counter()
    frames = collections.Counter()
    tops = collections.Counter()
    aots = collections.Counter()
    box_ch_disagree = 0
    box_rate_disagree = 0
    no_asc = 0
    elst = 0
    refused = []
    n_bytes = 0
    total_mvhd = 0.0
    total_stts = 0.0
    total_samples = 0
    agree = 0
    for p in files:
        try:
            r = read(p)
        except (Mp4Error, struct.error) as e:
            refused.append((p, str(e)))
            continue
        n_bytes += r["bytes"]
        brands[r["major_brand"]] += 1
        rates[r.get("sample_rate")] += 1
        chans[r.get("channels")] += 1
        frames[r.get("frame_units")] += 1
        for k in r["top_level"]:
            tops[k] += 1
        if r.get("asc"):
            aots[r["asc"]["audio_object_type"]] += 1
            box_ch_disagree += 0 if r.get("box_agrees_channels") else 1
            box_rate_disagree += 0 if r.get("box_agrees_rate") else 1
        else:
            no_asc += 1
        elst += 1 if r["has_elst"] else 0
        total_mvhd += r.get("mvhd_seconds", 0.0)
        total_stts += r.get("stts_seconds", 0.0)
        total_samples += r.get("samples", 0)
        if abs(r.get("mvhd_seconds", 0.0) - r.get("stts_seconds", 0.0)) < 1e-9:
            agree += 1
    parsed = len(files) - len(refused)
    print("files whose first box is `ftyp`  : %d" % len(files))
    print("box trees that close at residue 0: %d of %d" % (parsed, len(files)))
    print("bytes over the parsed files      : %d" % n_bytes)
    print()
    print("  major brands       : %s" % dict(brands))
    print("  top-level boxes    : %s" % dict(tops))
    print("  sample rates       : %s   (from the AudioSpecificConfig)"
          % dict(rates))
    print("  channel counts     : %s   (from the AudioSpecificConfig)"
          % dict(chans))
    print("  audioObjectType    : %s   (2 is AAC Low Complexity)" % dict(aots))
    print("  frame length, units: %s" % dict(frames))
    print("  files with an edit list : %d of %d" % (elst, parsed))
    print("  files with no decoder configuration at all : %d" % no_asc)
    print()
    print("  THE ADVISORY FIELDS, AND HOW OFTEN THEY LIE:")
    print("    the mp4a box's channelcount disagrees with the decoder "
          "configuration on %d of %d" % (box_ch_disagree, parsed - no_asc))
    print("    the mp4a box's samplerate   disagrees with it on %d of %d"
          % (box_rate_disagree, parsed - no_asc))
    print("    ISO/IEC 14496-14 makes the decoder configuration authoritative,")
    print("    so the two rows above are the census and the box is not.")
    print()
    print("  total duration, mvhd : %.3f s" % total_mvhd)
    print("  total duration, stts : %.3f s" % total_stts)
    print("  the two agree per file on : %d of %d" % (agree, parsed))
    print("  access units, summed : %d" % total_samples)
    print()
    print("  mvhd is the container's claim and stts is what the sample table")
    print("  adds up to. They are printed apart because a reader that prefers")
    print("  one of them throws away the evidence that they differ.")
    if refused:
        print()
        print("  REFUSED : %d" % len(refused))
        for p, e in refused[:10]:
            print("    %s" % e)
        return 1
    return 0


def selftest():
    checks, fails = [], 0

    def ck(name, ok, note=""):
        nonlocal fails
        checks.append((name, ok, note))
        if not ok:
            fails += 1

    def box(typ, payload=b""):
        return struct.pack(">I4s", 8 + len(payload), typ) + payload

    ftyp = box(b"ftyp", b"M4A \x00\x00\x00\x00M4A mp42isom")
    ck("a File Type Box is 8 + its payload", len(ftyp) == 8 + 20)

    # a minimal but real movie: mvhd 44100/88200, mdhd 44100/88200,
    # stts saying 86 samples of 1024 units = 88064 units
    mvhd = box(b"mvhd", b"\x00\x00\x00\x00" + struct.pack(
        ">IIII", 0, 0, 44100, 88200))
    mdhd = box(b"mdhd", b"\x00\x00\x00\x00" + struct.pack(
        ">IIII", 0, 0, 44100, 88200))
    stts = box(b"stts", b"\x00\x00\x00\x00" + struct.pack(">I", 1)
               + struct.pack(">II", 86, 1024))
    stbl = box(b"stbl", stts)
    minf = box(b"minf", stbl)
    mdia = box(b"mdia", mdhd + minf)
    trak = box(b"trak", mdia)
    moov = box(b"moov", mvhd + trak)
    mdat = box(b"mdat", bytes(64))
    blob = ftyp + moov + mdat

    rows = tree(blob, "<t>")
    ck("the tree walks to the last byte and back",
       sum(1 for d, _o, _s, _t in rows if d == 0) == 3, "%d boxes" % len(rows))
    ck("and it finds the nested mvhd",
       any(t == b"mvhd" for _d, _o, _s, t in rows))

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.m4a")
        with open(p, "wb") as fh:
            fh.write(blob)
        r = read(p)
        ck("the major brand is read", r["major_brand"] == "M4A ")
        ck("the compatible brands are read",
           r["compatible"] == ["M4A ", "mp42", "isom"], str(r["compatible"]))
        ck("mvhd gives 88200/44100 = 2 s", abs(r["mvhd_seconds"] - 2.0) < 1e-9)
        ck("stts sums to 86 x 1024 = 88064 units",
           r["stts_units"] == 88064 and r["samples"] == 86)
        ck("and 88064/44100 is NOT 2 s -- the two clocks disagree",
           abs(r["stts_seconds"] - 88064 / 44100) < 1e-12
           and abs(r["stts_seconds"] - r["mvhd_seconds"]) > 1e-6,
           "THE BLIND SPOT: both are reported, neither is preferred")
        ck("the frame length is the commonest delta",
           r["frame_units"] == 1024)
        ck("one frame-time at 44100 is 1024/44100 s",
           abs(r["frame_seconds"] - 1024 / 44100) < 1e-12)
        ck("no edit list is present in this file", r["has_elst"] is False)

        # selection is by magic: a file named .m4a that is not one is skipped,
        # and a file named .bin that IS one is found
        with open(os.path.join(d, "lie.m4a"), "wb") as fh:
            fh.write(b"this is not an MPEG-4 file at all, at all\n")
        with open(os.path.join(d, "truth.bin"), "wb") as fh:
            fh.write(blob)
        found = sorted(os.path.basename(x) for x in mp4_files(d))
        ck("selection is by magic, not by extension",
           found == ["a.m4a", "truth.bin"], str(found))

        # a truncated box must REFUSE and not return a short walk
        with open(os.path.join(d, "cut.m4a"), "wb") as fh:
            fh.write(blob[:-8])
        raised = False
        try:
            read(os.path.join(d, "cut.m4a"))
        except Mp4Error:
            raised = True
        ck("a truncated box tree is REFUSED and not silently shortened",
           raised)

        # a box declaring a size shorter than its own header
        bad = ftyp + struct.pack(">I4s", 4, b"moov")
        with open(os.path.join(d, "short.m4a"), "wb") as fh:
            fh.write(bad)
        raised = False
        try:
            read(os.path.join(d, "short.m4a"))
        except Mp4Error:
            raised = True
        ck("a box shorter than its own header is REFUSED", raised)

        # a size-0 box runs to end of file and still closes
        run = ftyp + struct.pack(">I4s", 0, b"mdat") + bytes(40)
        with open(os.path.join(d, "run.m4a"), "wb") as fh:
            fh.write(run)
        r2 = read(os.path.join(d, "run.m4a"))
        ck("a box declaring size 0 runs to the end of the file and closes",
           r2["top_level"] == {"ftyp": 1, "mdat": 1}, str(r2["top_level"]))

        # a 64-bit largesize
        big = ftyp + struct.pack(">I4sQ", 1, b"mdat", 16 + 24) + bytes(24)
        with open(os.path.join(d, "big.m4a"), "wb") as fh:
            fh.write(big)
        r3 = read(os.path.join(d, "big.m4a"))
        ck("a 64-bit largesize box is walked",
           r3["top_level"] == {"ftyp": 1, "mdat": 1}, str(r3["top_level"]))

        # a file that is not MPEG-4 at all
        raised = False
        try:
            read(os.path.join(d, "lie.m4a"))
        except Mp4Error:
            raised = True
        ck("a file with no File Type Box is REFUSED", raised)

        # a version-1 mvhd with 64-bit fields
        mvhd1 = box(b"mvhd", b"\x01\x00\x00\x00" + struct.pack(
            ">QQIQ", 0, 0, 1000, 5000))
        moov1 = box(b"moov", mvhd1)
        with open(os.path.join(d, "v1.m4a"), "wb") as fh:
            fh.write(ftyp + moov1)
        r4 = read(os.path.join(d, "v1.m4a"))
        ck("a version-1 mvhd is read with 64-bit fields",
           abs(r4["mvhd_seconds"] - 5.0) < 1e-9)

        # an edit list is detected
        elst = box(b"elst", b"\x00\x00\x00\x00" + struct.pack(">I", 0))
        edts = box(b"edts", elst)
        trak2 = box(b"trak", edts + mdia)
        with open(os.path.join(d, "el.m4a"), "wb") as fh:
            fh.write(ftyp + box(b"moov", mvhd + trak2))
        ck("an edit list is reported when present",
           read(os.path.join(d, "el.m4a"))["has_elst"] is True)

        # --- the esds descriptor, and the advisory fields it overrides ---
        def esds(aot, fi, ch):
            bits = (aot << 11) | (fi << 7) | (ch << 3)
            cfg = bits.to_bytes(2, "big")
            dsi = bytes([0x05, len(cfg)]) + cfg
            dcd = bytes([0x04, 13 + len(dsi), 0x40, 0x15]) + bytes(11) + dsi
            esd = bytes([0x03, 3 + len(dcd), 0x00, 0x01, 0x00]) + dcd
            return box(b"esds", b"\x00\x00\x00\x00" + esd)

        mp4a_box = box(b"mp4a", bytes(16) + struct.pack(">HH", 2, 16)
                       + bytes(4) + struct.pack(">I", 44100 << 16)
                       + esds(2, 7, 1))
        stsd = box(b"stsd", b"\x00\x00\x00\x00" + struct.pack(">I", 1)
                   + mp4a_box)
        stbl2 = box(b"stbl", stsd + stts)
        mdia2 = box(b"mdia", mdhd + box(b"minf", stbl2))
        with open(os.path.join(d, "asc.m4a"), "wb") as fh:
            fh.write(ftyp + box(b"moov", mvhd + box(b"trak", mdia2))
                     + mdat)
        r5 = read(os.path.join(d, "asc.m4a"))
        ck("the AudioSpecificConfig is found through esds",
           r5["asc"] is not None)
        ck("its audioObjectType is read", r5["asc"]["audio_object_type"] == 2)
        ck("frequency index 7 is 22050 Hz", r5["sample_rate"] == 22050)
        ck("its channel configuration is 1", r5["channels"] == 1)
        ck("THE ADVISORY FIELD: the mp4a box says 2 channels and 44100 Hz",
           r5["box_channels"] == 2 and r5["box_rate"] == 44100)
        ck("and the disagreement is REPORTED rather than reconciled",
           r5["box_agrees_channels"] is False
           and r5["box_agrees_rate"] is False,
           "288 of 1,341 on this object")
        ck("the config-derived value is the one the census uses",
           r5["channels"] == r5["asc"]["channels"])
        # a file with no esds at all falls back and says so
        ck("with no decoder configuration the advisory field is used and "
           "`asc` is None", read(p)["asc"] is None)
        # the base-128 varint length, at two bytes
        long_dsi = bytes([0x05, 0x81, 0x02, 0x12, 0x10])
        _t, _s, _e = _descriptor(b"\x00" + long_dsi, 1, 6)
        ck("a two-byte base-128 descriptor length is decoded and CLIPPED to "
           "the enclosing box",
           (_t, _s, _e) == (0x05, 4, 6),
           "0x81 0x02 declares 130 bytes and only 2 are there")
        _t1, _s1, _e1 = _descriptor(bytes([0x05, 0x02, 0xAA, 0xBB]), 0, 4)
        ck("a one-byte descriptor length is decoded",
           (_t1, _s1, _e1) == (0x05, 2, 4))

        # dirguard: handed a directory, refuse without a traceback
        code = 0
        try:
            read(d)
        except SystemExit:
            code = 1
        ck("handed a directory it refuses through dirguard", code == 1)

        # an empty tree refuses rather than reporting a clean census
        empty = os.path.join(d, "empty")
        os.makedirs(empty)
        code = 0
        try:
            cmd_census(empty)
        except SystemExit:
            code = 1
        ck("a census over an empty population is REFUSED", code == 1)

    width = max(len(c[0]) for c in checks)
    for name, ok, note in checks:
        print("  %-*s  %s   %s" % (width, name, "ok  " if ok else "FAIL", note))
    print()
    print("%d checks, %d failures" % (len(checks), fails))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?",
                    choices=["validate", "show", "census", "selftest"])
    ap.add_argument("path", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.cmd == "selftest":
        return selftest()
    if not args.cmd:
        ap.error("one of validate, show, census, selftest is required")
    if not args.path:
        ap.error("%s needs a path" % args.cmd)
    if args.cmd == "validate":
        return cmd_validate(args.path)
    if args.cmd == "show":
        return cmd_show(args.path)
    return cmd_census(args.path)


if __name__ == "__main__":
    sys.exit(main())
