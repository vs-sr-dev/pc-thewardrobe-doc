#!/usr/bin/env python3
"""audiopair.py -- the same recording in two containers, paired one by one.

WHY THIS EXISTS
---------------
`pc-rpgmakervxace-doc/docs/02` took 23 stems shipped as both `.ogg` and `.mp3`,
computed each side's duration from its own container, and found the MP3 longer
in **23 of 23** by between 2.03 and 2.97 frame-times. The explanation is a
property of frame-based formats and not of that object: a frame carries a fixed
number of samples, the last frame is emitted whole however few samples are left
in it, so a frame-based encoding of an N-sample recording lasts
`ceil(N / frame) * frame` samples and can only overshoot.

`pc-rpgmakermv-doc` ships **1,341 stems in both Ogg Vorbis and MPEG-4 AAC**, and
its pre-briefing measured the two aggregates as 20,484.642 s and 20,590.750 s --
the MPEG-4 side longer by 106.108 s, or 0.0791 s per file. **That is an
aggregate, and an aggregate cannot tell 1,341 small overshoots from 1,300
identical files and 41 different recordings.** This tool does the pairing.

WHAT IT MEASURES
----------------
For every stem present on both sides:

    ogg_seconds  the last page's granule position over the identification
                 header's sample rate -- the number of PCM samples, exactly
    m4a_seconds  the sample table's sum of count x delta over the media
                 timescale -- the number of coded samples, exactly
    delta        m4a_seconds - ogg_seconds
    frames       delta expressed in the MPEG-4 file's own frame-time

and reports the distribution of `frames`. The prediction the previous object's
finding makes is specific and falsifiable: **every delta is positive and every
delta is under one frame-time**, because an AAC frame is 1,024 samples and the
overshoot is whatever the last frame had to be padded with. A delta above one
frame-time is not quantisation and has to be explained; a negative delta means
the MPEG-4 file is SHORTER, which padding cannot produce at all.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**Two files of equal duration are not the same recording.** This tool compares
clocks and nothing else; a stem re-recorded at the same length would pair
perfectly and be a different performance. It cannot say the music is the same
and it does not say so -- the strongest thing it is allowed to conclude is that
the durations are consistent with one source re-encoded twice, and the census
prints the number of pairs that are NOT so consistent so that the claim has a
denominator. `--selftest` asserts this by pairing two synthetic files of
identical duration and different content and requiring the tool to report them
as agreeing, which is the false positive, demonstrated.

The second thing it cannot see is **encoder delay**. AAC prepends priming
samples; the conventional declaration is an edit list, and this object's files
have none (`mp4box.py census`). Where an edit list exists this tool ignores it
and says so in its output rather than applying a correction it has not tested.

    python tools/audiopair.py rpgmakermv-steam
    python tools/audiopair.py rpgmakermv-steam --list --over 1.0
    python tools/audiopair.py --selftest
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mp4box
import nameguard
import oggcensus


def stem(path, root):
    """The join key: the path relative to the root, without its extension.

    THE BASENAME IS NOT THE KEY, and the first run of this tool proved it. On
    this object the two containers sit side by side in the SAME directory --
    `audio/bgm/Town1.ogg` next to `audio/bgm/Town1.m4a` -- and the same
    basename recurs in `NewData\\`, in `dlc\\BaseResource\\` and in eleven other
    packs. Keying on the basename collapsed 1,341 files per side into 497
    stems and silently paired one directory's Ogg against another directory's
    MPEG-4. Keying on the relative path pairs each file with its own
    neighbour, which is the join the object actually offers.
    """
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    return os.path.splitext(rel)[0]


def collect(root):
    """Return (ogg, m4a) as {stem: [paths]}, both SELECTED BY MAGIC."""
    ogg, m4a = {}, {}
    for p in oggcensus.ogg_files(root):
        ogg.setdefault(stem(p, root), []).append(p)
    for p in mp4box.mp4_files(root):
        m4a.setdefault(stem(p, root), []).append(p)
    return ogg, m4a


def pair(root):
    ogg, m4a = collect(root)
    both = sorted(set(ogg) & set(m4a))
    rows, refused = [], []
    for s in both:
        try:
            o = oggcensus.read(ogg[s][0])
            m = mp4box.read(m4a[s][0])
        except Exception as e:                       # noqa: BLE001
            refused.append((s, "%s: %s" % (type(e).__name__, e)))
            continue
        osec = o["seconds"]
        msec = m.get("stts_seconds", 0.0)
        frame = m.get("frame_seconds", 0.0)
        rows.append(dict(
            stem=s, ogg=osec, m4a=msec, delta=msec - osec,
            frame=frame, frames=(msec - osec) / frame if frame else None,
            ogg_rate=o["rate"], m4a_rate=m.get("sample_rate"),
            ogg_ch=o["channels"], m4a_ch=m.get("channels"),
            ogg_paths=len(ogg[s]), m4a_paths=len(m4a[s]),
            elst=m["has_elst"],
        ))
    return ogg, m4a, both, rows, refused


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?")
    ap.add_argument("--list", action="store_true",
                    help="print every pair, not just the summary")
    ap.add_argument("--over", type=float, default=1.0,
                    help="report pairs whose delta exceeds this many "
                         "frame-times (default 1.0)")
    ap.add_argument("--expect-pairs", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.root:
        ap.error("a root is required")
    nameguard.guard()

    ogg, m4a, both, rows, refused = pair(args.root)
    only_o = sorted(set(ogg) - set(m4a))
    only_m = sorted(set(m4a) - set(ogg))

    print("Ogg stems      : %d   over %d files"
          % (len(ogg), sum(len(v) for v in ogg.values())))
    print("MPEG-4 stems   : %d   over %d files"
          % (len(m4a), sum(len(v) for v in m4a.values())))
    print("in both        : %d" % len(both))
    print("only Ogg       : %d" % len(only_o))
    print("only MPEG-4    : %d" % len(only_m))
    print("residue        : %d"
          % (len(both) + len(only_o) - len(ogg)))
    print()
    if refused:
        print("REFUSED : %d" % len(refused))
        for s, e in refused[:10]:
            print("   %s  %s" % (s, e))
        print()
    if not rows:
        sys.exit("audiopair: no stem is present in both containers -- "
                 "refusing to report a comparison over an empty population")

    to = sum(r["ogg"] for r in rows)
    tm = sum(r["m4a"] for r in rows)
    print("total Ogg    : %12.3f s over %d pairs" % (to, len(rows)))
    print("total MPEG-4 : %12.3f s" % tm)
    print("difference   : %12.3f s   (MPEG-4 minus Ogg)" % (tm - to))
    print("per pair     : %12.6f s" % ((tm - to) / len(rows)))
    print()

    pos = sum(1 for r in rows if r["delta"] > 0)
    zero = sum(1 for r in rows if r["delta"] == 0)
    neg = sum(1 for r in rows if r["delta"] < 0)
    print("MPEG-4 LONGER  : %d of %d" % (pos, len(rows)))
    print("exactly equal  : %d" % zero)
    print("MPEG-4 SHORTER : %d   <- padding cannot produce this" % neg)
    print("  %d + %d + %d = %d, residue %d"
          % (pos, zero, neg, pos + zero + neg,
             pos + zero + neg - len(rows)))
    print()

    fr = [r["frames"] for r in rows if r["frames"] is not None]
    if fr:
        print("the delta in the MPEG-4 file's OWN frame-times:")
        print("  min %.6f   max %.6f   mean %.6f"
              % (min(fr), max(fr), sum(fr) / len(fr)))
        under = sum(1 for f in fr if 0 < f < 1.0)
        print("  strictly between 0 and 1 frame-time : %d of %d"
              % (under, len(fr)))
        band = collections.Counter()
        for f in fr:
            band["%.1f" % (int(f * 10) / 10.0)] += 1
        print("  by tenth of a frame : %s"
              % dict(sorted(band.items(), key=lambda kv: float(kv[0]))))
    print()
    under = sorted((r for r in rows
                    if r["frames"] is not None and r["frames"] < args.over),
                   key=lambda r: r["frames"])
    print("pairs whose delta is UNDER %.2f frame-times : %d -- the outliers"
          % (args.over, len(under)))
    for r in under[:20]:
        print("   %-46s ogg %9.4f  m4a %9.4f  %+.5f s = %+.4f frames  "
              "%d Hz / %d Hz"
              % (nameguard.safe(r["stem"]), r["ogg"], r["m4a"],
                 r["delta"], r["frames"], r["ogg_rate"], r["m4a_rate"]))
    print()
    over = [r for r in rows
            if r["frames"] is not None and abs(r["frames"]) >= args.over]
    print("pairs whose delta is at least %.2f frame-times : %d"
          % (args.over, len(over)))
    for r in over[:40]:
        print("   %-40s ogg %9.4f  m4a %9.4f  %+.4f s = %+.3f frames"
              % (nameguard.safe(r["stem"]), r["ogg"], r["m4a"],
                 r["delta"], r["frames"]))
    print()
    # The delta in SAMPLES of the MPEG-4 side's own clock. An AAC frame is
    # 1,024 samples; the conventional encoder delay is 2,048, which is exactly
    # two of them; the last frame is then padded by anything in [0, 1024).
    # If that is the mechanism the whole population sits in [2048, 3072).
    samp = sorted(round(r["delta"] * r["m4a_rate"]) for r in rows)
    if samp:
        print("the delta in SAMPLES of the MPEG-4 side's own clock:")
        print("  min %d   max %d   mean %.1f"
              % (samp[0], samp[-1], sum(samp) / len(samp)))
        inband = sum(1 for s in samp if 2048 <= s < 3072)
        print("  inside [2048, 3072) -- two frames of encoder delay plus a")
        print("  padded last frame  : %d of %d" % (inband, len(samp)))
        print("  below 2048         : %d" % sum(1 for s in samp if s < 2048))
        print("  at or above 3072   : %d" % sum(1 for s in samp if s >= 3072))
    print()
    rate_pairs = collections.Counter(
        (r["ogg_rate"], r["m4a_rate"]) for r in rows)
    ch_pairs = collections.Counter((r["ogg_ch"], r["m4a_ch"]) for r in rows)
    rate_ok = sum(1 for r in rows if r["ogg_rate"] == r["m4a_rate"])
    ch_ok = sum(1 for r in rows if r["ogg_ch"] == r["m4a_ch"])
    print("pairs agreeing on sample rate    : %d of %d" % (rate_ok, len(rows)))
    print("  (Ogg rate, MPEG-4 rate) : %s"
          % dict(sorted(rate_pairs.items(), key=lambda kv: -kv[1])))
    print("pairs agreeing on channel count  : %d of %d" % (ch_ok, len(rows)))
    print("  (Ogg channels, MPEG-4 channels) : %s"
          % dict(sorted(ch_pairs.items(), key=lambda kv: -kv[1])))
    print("MPEG-4 files carrying an edit list : %d of %d"
          % (sum(1 for r in rows if r["elst"]), len(rows)))
    print()
    print("  A pair that agrees on duration, rate and channel count is")
    print("  CONSISTENT WITH one source encoded twice. It is not proof that")
    print("  the two files carry the same performance, and this tool decodes")
    print("  no audio and does not claim it.")

    if args.list:
        print()
        for r in rows:
            print("  %-44s %9.4f %9.4f %+9.5f %+8.4f"
                  % (nameguard.safe(r["stem"]), r["ogg"], r["m4a"],
                     r["delta"], r["frames"] if r["frames"] is not None else 0))

    if args.expect_pairs is not None and len(rows) != args.expect_pairs:
        sys.exit("audiopair: --expect-pairs %d but paired %d"
                 % (args.expect_pairs, len(rows)))
    return 0


def selftest():
    import struct
    import tempfile
    checks, fails = [], 0

    def ck(name, ok, note=""):
        nonlocal fails
        checks.append((name, ok, note))
        if not ok:
            fails += 1

    def mp4(samples, delta=1024, timescale=44100, rate=44100, ch=2):
        def box(t, p=b""):
            return struct.pack(">I4s", 8 + len(p), t) + p
        units = samples * delta
        mvhd = box(b"mvhd", b"\x00\x00\x00\x00"
                   + struct.pack(">IIII", 0, 0, timescale, units))
        mdhd = box(b"mdhd", b"\x00\x00\x00\x00"
                   + struct.pack(">IIII", 0, 0, timescale, units))
        stts = box(b"stts", b"\x00\x00\x00\x00" + struct.pack(">I", 1)
                   + struct.pack(">II", samples, delta))
        mp4a = box(b"mp4a", bytes(16) + struct.pack(">HH", ch, 16)
                   + bytes(4) + struct.pack(">I", rate << 16))
        stsd = box(b"stsd", b"\x00\x00\x00\x00" + struct.pack(">I", 1) + mp4a)
        stbl = box(b"stbl", stsd + stts)
        mdia = box(b"mdia", mdhd + box(b"minf", stbl))
        return (box(b"ftyp", b"M4A \x00\x00\x00\x00M4A mp42isom")
                + box(b"moov", mvhd + box(b"trak", mdia))
                + box(b"mdat", bytes(32)))

    def ogg(samples, rate=44100, ch=2, serial=7):
        def page(htype, granule, seq, body):
            head = (b"OggS" + struct.pack("<BBqIIIB", 0, htype, granule,
                                          serial, seq, 0, 1)
                    + bytes([len(body)]))
            page_ = head + body
            crc = oggcensus.crc32_ogg(page_)
            return page_[:22] + struct.pack("<I", crc) + page_[26:]
        ident = (b"\x01vorbis" + struct.pack("<IBIiii", 0, ch, rate,
                                             0, 112000, 0) + b"\xb8\x01")
        return (page(0x02, 0, 0, ident)
                + page(0x04, samples, 1, b"end"))

    with tempfile.TemporaryDirectory() as d:
        # a pair that overshoots by less than one frame: 44100 PCM samples in
        # Ogg, 44 AAC frames of 1024 = 45056 in MPEG-4
        with open(os.path.join(d, "one.ogg"), "wb") as fh:
            fh.write(ogg(44100))
        with open(os.path.join(d, "one.m4a"), "wb") as fh:
            fh.write(mp4(44))
        _o, _m, both, rows, refused = pair(d)
        ck("one stem present in both containers pairs",
           both == ["one"] and len(rows) == 1 and not refused,
           str(refused))
        # THE KEY: two directories holding the same basename are two stems
        for sub in ("x", "y"):
            os.makedirs(os.path.join(d, sub))
            with open(os.path.join(d, sub, "same.ogg"), "wb") as fh:
                fh.write(ogg(44100))
            with open(os.path.join(d, sub, "same.m4a"), "wb") as fh:
                fh.write(mp4(44))
        _o, _m, both2, rows2, _r = pair(d)
        ck("the same basename in two directories is TWO pairs, not one",
           sorted(x for x in both2 if x.endswith("same"))
           == ["x/same", "y/same"], str(both2))
        ck("and pairing is within a directory, not across one",
           len(rows2) == 3)
        r = rows[0]
        ck("the Ogg side is 44100/44100 = 1 s", abs(r["ogg"] - 1.0) < 1e-9)
        ck("the MPEG-4 side is 45056/44100",
           abs(r["m4a"] - 45056 / 44100) < 1e-12)
        ck("the MPEG-4 side is LONGER, which is the prediction",
           r["delta"] > 0)
        ck("and the overshoot is under one frame-time",
           0 < r["frames"] < 1.0, "%.6f frames" % r["frames"])
        ck("the two sides agree on rate and channels",
           r["ogg_rate"] == r["m4a_rate"] == 44100
           and r["ogg_ch"] == r["m4a_ch"] == 2)

        # THE BLIND SPOT: identical durations, different content, reported as
        # agreeing. The false positive, on the record.
        with open(os.path.join(d, "two.ogg"), "wb") as fh:
            fh.write(ogg(45056))
        with open(os.path.join(d, "two.m4a"), "wb") as fh:
            fh.write(mp4(44))
        _o, _m, both, rows, _r = pair(d)
        two = [x for x in rows if x["stem"] == "two"][0]
        ck("THE BLIND SPOT: equal durations pair at delta 0 whatever the "
           "audio is", two["delta"] == 0.0)

        # a stem on one side only is excluded from the pairing, both ways
        with open(os.path.join(d, "lonely.ogg"), "wb") as fh:
            fh.write(ogg(1000))
        with open(os.path.join(d, "orphan.m4a"), "wb") as fh:
            fh.write(mp4(3))
        o2, m2, both2, rows2, _r = pair(d)
        ck("a stem present on one side only is not paired",
           "lonely" not in both2 and "orphan" not in both2
           and len(rows2) == 4, "%d rows: one, two, x/same, y/same"
           % len(rows2))
        ck("and it is still counted on its own side",
           "lonely" in o2 and "orphan" in m2)

        # a negative delta is reported and not clamped
        with open(os.path.join(d, "short.ogg"), "wb") as fh:
            fh.write(ogg(45056))
        with open(os.path.join(d, "short.m4a"), "wb") as fh:
            fh.write(mp4(43))
        _o, _m, _b, rows3, _r = pair(d)
        sh = [x for x in rows3 if x["stem"] == "short"][0]
        ck("a SHORTER MPEG-4 side is reported with a negative delta",
           sh["delta"] < 0 and sh["frames"] < 0)

        # selection is by magic on both sides
        with open(os.path.join(d, "fake.ogg"), "wb") as fh:
            fh.write(b"not an Ogg file at all\n")
        with open(os.path.join(d, "fake.m4a"), "wb") as fh:
            fh.write(b"not an MPEG-4 file at all\n")
        o3, m3, _b, _r3, _rf = pair(d)
        ck("a file named .ogg that is not one is not collected",
           "fake" not in o3)
        ck("a file named .m4a that is not one is not collected",
           "fake" not in m3)

        empty = os.path.join(d, "empty")
        os.makedirs(empty)
        code = 0
        try:
            pair(empty)
        except SystemExit:
            code = 1
        ck("an empty tree REFUSES rather than pairing zero against zero",
           code == 1, "oggcensus.ogg_files refuses first, and correctly")

    width = max(len(c[0]) for c in checks)
    for name, ok, note in checks:
        print("  %-*s  %s   %s" % (width, name, "ok  " if ok else "FAIL", note))
    print()
    print("%d checks, %d failures" % (len(checks), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
