#!/usr/bin/env python3
"""sfd.py -- the .SFD films: an MPEG-1 program stream, walked pack by pack.

10 files, 183,687,168 bytes, 17.9726 % of the high-density file bytes. The
pre-briefing established that all ten begin 00 00 01 BA, which is an MPEG-1
pack start code, and stopped there.

`avi.py` in this toolbox does not apply and this tool was written after looking
at one of these rather than instead of looking: an AVI is a RIFF, its first four
bytes are 'RIFF', and these ten files' first four bytes are 00 00 01 BA on 10 of
10. Nothing in avi.py's chunk walker would have survived the first read.

WHAT IS BEING ASSERTED, AND FROM WHERE
--------------------------------------

The container is ISO/IEC 11172-1 (MPEG-1 systems) and the video elementary
stream is ISO/IEC 11172-2. Both are public definitions and this tool uses them
rather than deriving them, which the rules of this branch permit provided the
tool says so and provided it is validated on a case that must fail. The failing
case is `--negative`: any file whose first four bytes are not 00 00 01 BA is
rejected, and a .PVR and a .ADX from this same disc are fed to it to prove the
rejection is not vacuous.

    pack           00 00 01 BA  + 8 bytes  (MPEG-1: the 0x21 marker nibble)
    system header  00 00 01 BB  + u16 BE length + that many bytes
    packet         00 00 01 XX  + u16 BE length + that many bytes
                     XX = E0..EF  video elementary stream
                     XX = C0..DF  MPEG audio
                     XX = BD      private stream 1 -- where Sofdec puts ADX
                     XX = BE      padding
    end            00 00 01 B9

Inside the video stream:

    sequence header 00 00 01 B3 : 12 bits width, 12 bits height, 4 bits aspect,
                                  4 bits frame-rate code
    GOP             00 00 01 B8
    picture         00 00 01 00 : the frame count is the count of these

The frame-rate code is the one place where a wrong reading is invisible, so the
duration is published as frames AND as seconds with the code printed beside it.

Usage:
    python tools/sfd.py --census DIR
    python tools/sfd.py --walk FILE
    python tools/sfd.py --video FILE OUT.M1V     # the elementary stream
    python tools/sfd.py --frame FILE OUT.PPM [--n N]
    python tools/sfd.py --negative FILE...
"""
import os
import struct
import sys

FRAME_RATE = {1: 23.976, 2: 24.0, 3: 25.0, 4: 29.97, 5: 30.0,
              6: 50.0, 7: 59.94, 8: 60.0}


def demux(data):
    """Walk the program stream. Returns (video_bytes, stats)."""
    n = len(data)
    i = 0
    vid = bytearray()
    stats = dict(packs=0, packets={}, bytes={}, end=False, stopped_at=None)
    if data[0:4] != b"\x00\x00\x01\xba":
        raise ValueError("first four bytes are %r, not a pack start code"
                         % bytes(data[:4]))
    while i + 4 <= n:
        if data[i:i + 3] != b"\x00\x00\x01":
            stats["stopped_at"] = i
            break
        sid = data[i + 3]
        if sid == 0xBA:
            stats["packs"] += 1
            i += 12
            continue
        if sid == 0xB9:
            stats["end"] = True
            i += 4
            break
        if i + 6 > n:
            stats["stopped_at"] = i
            break
        ln = struct.unpack_from(">H", data, i + 4)[0]
        body = data[i + 6:i + 6 + ln]
        stats["packets"][sid] = stats["packets"].get(sid, 0) + 1
        stats["bytes"][sid] = stats["bytes"].get(sid, 0) + ln
        if 0xE0 <= sid <= 0xEF:
            p = 0
            while p < len(body) and body[p] == 0xFF:
                p += 1
            if p < len(body) and (body[p] & 0xC0) == 0x40:
                p += 2
            if p < len(body):
                f = body[p] & 0xF0
                if f == 0x20:
                    p += 5
                elif f == 0x30:
                    p += 10
                elif body[p] == 0x0F:
                    p += 1
            vid += body[p:]
        i += 6 + ln
    return bytes(vid), stats


def video_stats(v):
    """Count pictures and read the first sequence header."""
    pics = gops = seqs = 0
    w = h = fr = None
    i = 0
    n = len(v)
    while True:
        j = v.find(b"\x00\x00\x01", i)
        if j < 0 or j + 4 > n:
            break
        c = v[j + 3]
        if c == 0x00:
            pics += 1
        elif c == 0xB8:
            gops += 1
        elif c == 0xB3:
            seqs += 1
            if w is None and j + 12 <= n:
                b = v[j + 4:j + 12]
                w = (b[0] << 4) | (b[1] >> 4)
                h = ((b[1] & 0x0F) << 8) | b[2]
                fr = b[3] & 0x0F
        i = j + 3
    return dict(pictures=pics, gops=gops, sequence_headers=seqs,
                width=w, height=h, frame_rate_code=fr,
                fps=FRAME_RATE.get(fr))


def cmd_census(root):
    files = sorted(p for p in
                   (os.path.join(root, f) for f in os.listdir(root))
                   if p.upper().endswith(".SFD"))
    if not files:
        files = []
        for dirpath, _d, fs in os.walk(root):
            for f in sorted(fs):
                if f.upper().endswith(".SFD"):
                    files.append(os.path.join(dirpath, f))
    tot_bytes = tot_frames = 0
    tot_sec = 0.0
    ends = 0
    clean = 0
    rows = []
    allsids = {}
    for p in files:
        data = open(p, "rb").read()
        v, st = demux(data)
        vs = video_stats(v)
        if st["end"]:
            ends += 1
        if st["stopped_at"] is None:
            clean += 1
        sec = vs["pictures"] / vs["fps"] if vs["fps"] else 0.0
        tot_bytes += len(data)
        tot_frames += vs["pictures"]
        tot_sec += sec
        for k, c in st["packets"].items():
            allsids[k] = allsids.get(k, 0) + c
        rows.append((os.path.basename(p), len(data), len(v), vs, sec, st))
    print("=== sfd.py --census over %s ===" % root)
    print("files                                  : %d" % len(files))
    print("bytes                                  : %d" % tot_bytes)
    print("walked to a 00 00 01 B9 end code       : %d of %d" % (ends, len(files)))
    print("walked with no unparsable byte         : %d of %d" % (clean, len(files)))
    print("frames                                 : %d" % tot_frames)
    print("duration                               : %.2f s = %d m %05.2f s"
          % (tot_sec, int(tot_sec // 60), tot_sec % 60))
    print("stream ids seen, by packet count       : %s"
          % ", ".join("0x%02X x%d" % (k, v)
                      for k, v in sorted(allsids.items(), key=lambda kv: -kv[1])))
    print()
    print("%-14s %11s %11s %10s %7s %7s %9s" % (
        "file", "bytes", "video bytes", "frames", "w", "h", "seconds"))
    for nm, sz, vl, vs, sec, st in rows:
        print("%-14s %11d %11d %10d %7s %7s %9.2f" % (
            nm, sz, vl, vs["pictures"], vs["width"], vs["height"], sec))
    return 0


def cmd_walk(path):
    data = open(path, "rb").read()
    v, st = demux(data)
    vs = video_stats(v)
    print("%s: %d bytes" % (os.path.basename(path), len(data)))
    print("  packs                : %d" % st["packs"])
    print("  end code 00 00 01 B9 : %s" % st["end"])
    print("  stopped at           : %r" % st["stopped_at"])
    for k in sorted(st["packets"]):
        print("  stream 0x%02X          : %d packets, %d bytes"
              % (k, st["packets"][k], st["bytes"][k]))
    print("  video elementary     : %d bytes" % len(v))
    for k in sorted(vs):
        print("  %-20s : %r" % (k, vs[k]))
    return 0


def cmd_negative(paths):
    fired = 0
    for p in paths:
        data = open(p, "rb").read(4096)
        try:
            demux(data)
            print("  %-24s ACCEPTED -- the control does not fire"
                  % os.path.basename(p))
        except ValueError as e:
            print("  %-24s rejected: %s" % (os.path.basename(p), e))
            fired += 1
    print("fired on %d of %d" % (fired, len(paths)))
    return 0 if fired == len(paths) else 1


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if len(argv) < 3:
        raise SystemExit(__doc__)
    if argv[1] == "--census":
        return cmd_census(argv[2])
    if argv[1] == "--walk":
        return cmd_walk(argv[2])
    if argv[1] == "--video":
        v, _st = demux(open(argv[2], "rb").read())
        open(argv[3], "wb").write(v)
        print("%s -> %s : %d bytes of elementary stream"
              % (os.path.basename(argv[2]), argv[3], len(v)))
        return 0
    if argv[1] == "--negative":
        return cmd_negative(argv[2:])
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
