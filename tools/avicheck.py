#!/usr/bin/env python3
"""avicheck.py -- validate an AVI's headers against the chunks it actually holds.

`avi.py` reports what an AVI *says*: dwTotalFrames and dwMicroSecPerFrame out
of the `avih`, dwLength and dwScale/dwRate out of each `strh`. Multiplying two
of those numbers gives a duration, and a duration obtained that way is a claim
by the header, not a measurement of the file.

This walks the `movi` list and counts the chunks that are really there --
`##dc`/`##db` for video, `##wb` for audio -- and puts the two answers side by
side. Where they disagree the file is either truncated, padded, or carrying a
header that was written before the last edit.

It also totals the audio payload and divides by the format's byte rate, which
is a second, independent duration for the same file.

Public definitions used, and named as used: RIFF (Microsoft/IBM Multimedia
Programming Interface, 1991) for the chunk tree; the AVI `avih`/`strh`/`strf`
layouts from the OpenDML AVI M-JPEG File Format Extensions and the Video for
Windows SDK; WAVEFORMATEX for `strf` on an audio stream. Nothing is decoded.

    python tools/avicheck.py DIR
    python tools/avicheck.py FILE --verbose
"""

import argparse
import os
import struct


def chunks(fh, start, end):
    """Yield (fourcc, start_of_payload, size, listtype) for one RIFF level."""
    fh.seek(start)
    pos = start
    while pos + 8 <= end:
        fh.seek(pos)
        hdr = fh.read(8)
        if len(hdr) < 8:
            return
        cid = hdr[0:4]
        sz = struct.unpack("<I", hdr[4:8])[0]
        if cid in (b"RIFF", b"LIST"):
            lt = fh.read(4)
            yield cid, pos + 12, sz - 4, lt
            pos += 8 + sz + (sz & 1)
        else:
            yield cid, pos + 8, sz, None
            pos += 8 + sz + (sz & 1)


def find(fh, start, end, want, listtype=None, depth=0):
    for cid, p, sz, lt in chunks(fh, start, end):
        if cid in (b"RIFF", b"LIST"):
            if listtype and lt == listtype and cid == b"LIST":
                return p, p + sz
            r = find(fh, p, p + sz, want, listtype, depth + 1)
            if r:
                return r
        elif want and cid == want:
            return p, p + sz
    return None


def read_avi(path):
    fh = open(path, "rb")
    size = os.path.getsize(path)
    out = {"path": path, "size": size}

    r = find(fh, 0, size, b"avih")
    if not r:
        fh.close()
        return None
    p, e = r
    fh.seek(p)
    avih = fh.read(56)
    (mspf, maxbytes, padgran, flags, total, initial, streams,
     bufsz, w, h) = struct.unpack("<10I", avih[:40])
    out["mspf"] = mspf
    out["avih_frames"] = total
    out["streams"] = streams
    out["width"] = w
    out["height"] = h

    # every strh/strf pair, in order
    strs = []
    def walk_hdrl(a, b):
        for cid, pp, sz, lt in chunks(fh, a, b):
            if cid == b"LIST" and lt == b"strl":
                info = {}
                for c2, p2, s2, l2 in chunks(fh, pp, pp + sz):
                    if c2 == b"strh":
                        fh.seek(p2)
                        d = fh.read(min(s2, 56))
                        info["type"] = d[0:4]
                        info["handler"] = d[4:8]
                        (scale, rate, start, length) = struct.unpack(
                            "<4I", d[20:36])
                        info["scale"] = scale
                        info["rate"] = rate
                        info["length"] = length
                    elif c2 == b"strf":
                        fh.seek(p2)
                        info["strf"] = fh.read(s2)
                strs.append(info)
            elif cid == b"LIST":
                walk_hdrl(pp, pp + sz)
    r = find(fh, 0, size, None, b"hdrl")
    if r:
        walk_hdrl(*r)
    out["strl"] = strs

    # the movi list, counted for real
    counts = {}
    audio_bytes = 0
    video_bytes = 0
    r = find(fh, 0, size, None, b"movi")
    if r:
        a, b = r
        for cid, p, sz, lt in chunks(fh, a, b):
            if cid == b"LIST":
                for c2, p2, s2, l2 in chunks(fh, p, p + sz):
                    counts[c2] = counts.get(c2, 0) + 1
                    if c2[2:4] == b"wb":
                        audio_bytes += s2
                    elif c2[2:4] in (b"dc", b"db"):
                        video_bytes += s2
                continue
            counts[cid] = counts.get(cid, 0) + 1
            if cid[2:4] == b"wb":
                audio_bytes += sz
            elif cid[2:4] in (b"dc", b"db"):
                video_bytes += sz
    out["movi_counts"] = counts
    out["audio_bytes"] = audio_bytes
    out["video_bytes"] = video_bytes
    fh.close()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--ext", nargs="*", default=[".avi"],
                    help="extensions to walk. The default is .avi because that "
                         "is what an AVI is normally called; on an object "
                         "where it is not, name the extension.")
    a = ap.parse_args()

    exts = tuple(e.lower() if e.startswith(".") else "." + e.lower()
                 for e in a.ext)
    targets = []
    if os.path.isdir(a.path):
        for dp, dn, fn in os.walk(a.path):
            for f in sorted(fn):
                if f.lower().endswith(exts):
                    targets.append(os.path.join(dp, f))
    else:
        targets = [a.path]

    print("%-14s %10s %7s %7s %6s %9s %9s %9s %-6s %-9s %10s"
          % ("file", "bytes", "avih", "chunks", "mspf", "hdr sec", "chunk sec",
             "audio sec", "codec", "size", "bytes/s"))
    tot_hdr = 0.0
    tot_chunk = 0.0
    tot_audio = 0.0
    tot_bytes = 0
    tot_frames = 0
    tot_chunkframes = 0
    mismatch = 0
    rates = {}
    movi_fourccs = {}
    peak = (0.0, None)
    for p in targets:
        d = read_avi(p)
        if d is None:
            print("%-14s  NOT AN AVI" % os.path.basename(p))
            continue
        vid = [s for s in d["strl"] if s.get("type") == b"vids"]
        aud = [s for s in d["strl"] if s.get("type") == b"auds"]
        # A movi chunk id is two ASCII digits naming the stream, then a
        # two-letter type. `dc` and `db` are what Video for Windows writes and
        # what every reader expects; they are a convention, not a requirement,
        # and Indeo 5 files on this object write `iv`. Counting only `dc`/`db`
        # returned 0 frames on 32 of 32 files and printed DISAGREE without
        # saying why. Take the stream number from the header instead, and count
        # every chunk belonging to the video stream that is not a palette
        # change. See docs/17-corrections.md, T1.
        vidx = None
        for i, s in enumerate(d["strl"]):
            if s.get("type") == b"vids":
                vidx = i
                break
        if vidx is None:
            nvid = 0
        else:
            pref = ("%02d" % vidx).encode("ascii")
            nvid = sum(v for k, v in d["movi_counts"].items()
                       if k[0:2] == pref and k[2:4] not in (b"pc", b"ix"))
        for k, v in d["movi_counts"].items():
            movi_fourccs[k] = movi_fourccs.get(k, 0) + v
        hdr_sec = d["avih_frames"] * d["mspf"] / 1e6
        chunk_sec = nvid * d["mspf"] / 1e6
        asec = 0.0
        if aud and len(aud[0].get("strf", b"")) >= 16:
            wf = struct.unpack("<HHIIHH", aud[0]["strf"][:16])
            byterate = wf[3]
            if byterate:
                asec = d["audio_bytes"] / byterate
        rates[round(1e6 / d["mspf"], 3)] = rates.get(
            round(1e6 / d["mspf"], 3), 0) + 1
        if nvid != d["avih_frames"]:
            mismatch += 1
        codec = "?"
        if vid and len(vid[0].get("strf", b"")) >= 20:
            codec = vid[0]["strf"][16:20].decode("latin1")
        rate_bs = d["size"] / chunk_sec if chunk_sec else 0.0
        print("%-14s %10d %7d %7d %6d %9.3f %9.3f %9.3f %-6s %4dx%-4d %10.1f"
              % (os.path.basename(p), d["size"], d["avih_frames"], nvid,
                 d["mspf"], hdr_sec, chunk_sec, asec, codec,
                 d["width"], d["height"], rate_bs))
        if rate_bs > peak[0]:
            peak = (rate_bs, os.path.basename(p))
        tot_hdr += hdr_sec
        tot_chunk += chunk_sec
        tot_audio += asec
        tot_bytes += d["size"]
        tot_frames += d["avih_frames"]
        tot_chunkframes += nvid

    print()
    print("files                         : %d" % len(targets))
    print("bytes                         : %d" % tot_bytes)
    print("frames, header-declared       : %d" % tot_frames)
    print("frames, counted in movi       : %d   %s"
          % (tot_chunkframes,
             "AGREE" if tot_chunkframes == tot_frames else "DISAGREE"))
    print("files where the two disagree  : %d of %d" % (mismatch, len(targets)))
    print("duration from headers         : %.4f s" % tot_hdr)
    print("duration from counted chunks  : %.4f s" % tot_chunk)
    print("duration from audio byte rate : %.4f s" % tot_audio)
    print("movi chunk ids, all files     : %s"
          % ", ".join("%s x%d" % (k.decode("latin1"), v)
                      for k, v in sorted(movi_fourccs.items())))
    print("fastest single file           : %.1f bytes/s (%s) -> needs %.2fx"
          % (peak[0], peak[1], peak[0] / 153600.0))
    print("distinct frame rates          : %s"
          % ", ".join("%.3f fps x%d" % (k, v)
                      for k, v in sorted(rates.items())))
    if tot_chunk:
        print("mean payload rate             : %.1f bytes/s" % (tot_bytes / tot_chunk))
        print("  1x CD-ROM Mode 1 delivers   : 153600 bytes/s  -> needs %.2fx"
              % (tot_bytes / tot_chunk / 153600.0))


if __name__ == "__main__":
    main()
