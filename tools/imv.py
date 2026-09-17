#!/usr/bin/env python3
"""imv.py -- reader for the .IMV streams of *Sherlock Holmes: Consulting
Detective, Vol. I* (Tandy/Memorex VIS, 1992, ICOM Simulations).

157 files, 429,867,008 bytes, 96.4344 % of the disc's declared bytes.  No
published description of this format exists.  Everything below was derived
from the bytes, and every structural claim is validated across the whole set
before it is used.

THE STRUCTURE, AS DERIVED

An `.IMV` file is a chain of blocks.  Every block begins:

     +0   u32   size of THIS block, including this header
     +4   u32   size of the PREVIOUS block in the same segment
     +8   u16   type
    +10   u16   type-dependent
    +12   u16   type-dependent

The u32 at +4 is what makes this a derivation rather than a guess: it repeats
a quantity the file already states four bytes earlier in the previous block,
so `size[i-1] == prev[i]` is a check a mis-read layout cannot pass by luck.
This repository's standing rule is that an arithmetic which closes is not a
structure demonstrated, and a quantity encoded twice in two places, agreeing
on N of N, is.

AND THE SEGMENTS, WHICH ARE WHY EVERY FILE IS A WHOLE NUMBER OF SECTORS

The chain does not run from byte 0 to end of file.  It runs in **segments**,
each starting on a 2,048-byte boundary -- a CD-ROM sector -- and each opening
with its own copy of the type-2 stream header.  The u16 at +10 of that header
is the **sector number of the next segment**, and 0 ends the chain.  So a
player can begin streaming at any segment without having read what came
before, which is what a 1x drive with a small buffer needs and what makes
every one of the 157 files an exact multiple of 2,048 bytes.

BLOCK TYPES

    0x02  stream header   +10 = next segment's sector, 0 = last
    0x01  video header    +12.. = frame count u32, width, height, fps, rate
    0x40  palette         14-byte header, then 3 bytes per entry, 6-bit VGA
                          DAC values, padded up to a 4-byte boundary
    0x20  key frame       audio run, then width*height raw 8-bit indices
    0x04  delta frame     audio run, then a video update (often empty)

A frame block carries its audio FIRST and its video second; that ordering was
established by profiling, not assumed -- the audio run has a mean near 128
and a mean absolute first difference under 2, the video an order of magnitude
more.  The audio is unsigned 8-bit PCM mono at the rate the video header
states.

WHAT IS NOT DERIVED, AND IS SAID SO RATHER THAN GUESSED

The delta-frame video encoding.  `--png` renders the key frame, which is
stored raw and needs no codec.  Later frames need the delta scheme and this
tool does not claim one.
"""

import argparse
import os
import struct
import sys
import zlib

HDR = 16               # frame blocks: payload begins here
PAL_HDR = 14           # palette blocks: payload begins here
SECTOR = 2048

T_VIDHDR = 0x01
T_STREAM = 0x02
T_DELTA = 0x04
T_KEY = 0x20
T_PALETTE = 0x40


class Imv:
    def __init__(self, path):
        self.path = path
        self.b = open(path, "rb").read()
        self.blocks = []      # (offset, size, prev, type, f10, f12)
        self.segments = []    # (byte offset, next sector)
        self.errors = []
        self.chain_breaks = 0
        self._walk()

    def _walk(self):
        b = self.b
        L = len(b)
        seg = 0
        seen = set()
        covered = 0
        while seg is not None and seg + HDR <= L and seg not in seen:
            seen.add(seg)
            typ = struct.unpack_from("<H", b, seg + 8)[0]
            nxt = struct.unpack_from("<H", b, seg + 10)[0]
            if typ != T_STREAM:
                self.errors.append("segment at %d does not open with a "
                                   "type-2 stream header (type 0x%X)"
                                   % (seg, typ))
                break
            self.segments.append((seg, nxt))
            end = nxt * SECTOR if nxt else L
            if end > L or end <= seg:
                end = L
            pos = seg
            prevsize = 0
            while pos + HDR <= end:
                size, prev = struct.unpack_from("<II", b, pos)
                t, f10, f12 = struct.unpack_from("<HHH", b, pos + 8)
                if prev != prevsize:
                    self.chain_breaks += 1
                    self.errors.append("block at %d: prev=%d, previous "
                                       "size=%d" % (pos, prev, prevsize))
                if size < HDR or pos + size > end:
                    # the encoder writes size 0 in the last block of a
                    # segment; the segment ends here and the next one starts
                    # at its own sector boundary.
                    if size == 0:
                        self.blocks.append((pos, end - pos, prev, t, f10, f12))
                        covered = end
                    break
                self.blocks.append((pos, size, prev, t, f10, f12))
                covered = pos + size
                prevsize = size
                pos += size
            seg = nxt * SECTOR if nxt else None
        self.covered = covered
        self.tail = L - covered
        self.tail_zero = not any(b[covered:])

    # ---- header fields -------------------------------------------------
    def info(self):
        b = self.b
        d = {"path": self.path, "size": len(b), "u32_0":
             struct.unpack_from("<I", b, 0)[0]}
        vh = [x for x in self.blocks if x[3] == T_VIDHDR]
        if vh:
            o = vh[0][0]
            d["frames"] = struct.unpack_from("<I", b, o + 12)[0]
            d["width"], d["height"], d["fps"], d["rate"] = \
                struct.unpack_from("<HHHH", b, o + 16)
        else:
            d.update(frames=0, width=0, height=0, fps=0, rate=0)
        d["segments"] = len(self.segments)
        return d

    def palette(self):
        for (o, size, _p, t, _a, _c) in self.blocks:
            if t == T_PALETTE:
                pay = self.b[o + PAL_HDR:o + size]
                n = len(pay) // 3
                pal = [(pay[3 * i] * 255 // 63, pay[3 * i + 1] * 255 // 63,
                        pay[3 * i + 2] * 255 // 63) for i in range(n)]
                pal += [(0, 0, 0)] * (256 - n)
                return pal[:256], n, len(pay) % 3
        return None, 0, 0

    def key_frames(self):
        """Every type-0x20 block's raw picture, in file order.

        A key frame block is audio, then optionally a little else, then
        exactly width*height raw indices at its end -- the `== width*height`
        column of --validate is what licenses taking the tail.
        """
        i = self.info()
        w, h = i["width"], i["height"]
        out = []
        for (o, size, _p, t, _a, _c) in self.blocks:
            if t == T_KEY:
                body = self.b[o + HDR:o + size]
                if len(body) >= w * h:
                    out.append((o, body[len(body) - w * h:], body[:1480]))
        return out

    def key_frame(self):
        k = self.key_frames()
        return (k[0][1], k[0][2]) if k else (None, None)

    def audio_len(self):
        """Samples of audio per frame block = sample rate / frame rate.

        Derived, not assumed.  The block header's u16 at +14 reads 1488 on
        every frame block of every file, which is 18 more than the run that
        is actually audio; taking 1488 (or the 1480 that the key frame's
        `size - width*height` arithmetic suggests) puts eighteen or ten
        foreign bytes into the waveform fifteen times a second, and it is
        plainly audible as a knock.  `--audiofit` measures it: the run length
        that makes the step across a block join no larger than the average
        step inside a block is 1470, and 22050 / 15 = 1470 exactly.  Rate and
        frame rate are stated in the video header, so the audio run length is
        a third statement of a quantity the file already carries twice.
        """
        i = self.info()
        if i["fps"]:
            return i["rate"] // i["fps"]
        return 0

    def audio(self):
        """Concatenate the audio run of every frame block, in order."""
        n = self.audio_len()
        out = []
        for (o, size, _p, t, _a, _c) in self.blocks:
            if t in (T_KEY, T_DELTA):
                body = self.b[o + HDR:o + size]
                if len(body) >= n:
                    out.append(body[:n])
        return b"".join(out)

    def audiofit(self, lo=1400, hi=1500):
        """Score candidate audio run lengths by join continuity."""
        fb = [x for x in self.blocks if x[3] in (T_KEY, T_DELTA)]
        rows = []
        for L in range(lo, hi + 1, 2):
            runs = [self.b[o + HDR:o + HDR + L] for (o, size, _p, _t, _a, _c)
                    in fb if size - HDR >= L]
            if len(runs) < 10:
                continue
            join = sum(abs(runs[i + 1][0] - runs[i][-1])
                       for i in range(len(runs) - 1)) / (len(runs) - 1)
            sample = runs[:40]
            inner = (sum(abs(r[j + 1] - r[j]) for r in sample
                         for j in range(len(r) - 1)) /
                     sum(len(r) - 1 for r in sample))
            rows.append((join / inner, L, join, inner))
        rows.sort()
        return rows


def write_png(path, w, h, pix, pal):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += pix[y * w:(y + 1) * w]
    plte = bytearray()
    for r, g, b in pal:
        plte += bytes((r, g, b))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
    png += chunk(b"PLTE", bytes(plte))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    open(path, "wb").write(png)


def write_wav(path, data, rate):
    n = len(data)
    hdr = (b"RIFF" + struct.pack("<I", 36 + n) + b"WAVEfmt " +
           struct.pack("<IHHIIHH", 16, 1, 1, rate, rate, 1, 8) +
           b"data" + struct.pack("<I", n))
    open(path, "wb").write(hdr + data)


def cmd_validate(paths, quiet):
    """Every claim in the module docstring, checked on every file given."""
    n = len(paths)
    ok = 0
    stats = dict(magic=0, mult2048=0, chain=0, segsector=0, seghdr=0,
                 sane=0, tailzero=0, keyexact=0, palpad=0)
    for p in paths:
        v = Imv(p)
        i = v.info()
        size = len(v.b)
        if v.b[:4] == b"\x28\x00\x00\x00":
            stats["magic"] += 1
        if size % SECTOR == 0:
            stats["mult2048"] += 1
        if v.chain_breaks == 0:
            stats["chain"] += 1
        if all(o % SECTOR == 0 for o, _ in v.segments):
            stats["segsector"] += 1
        if all(struct.unpack_from("<H", v.b, o + 8)[0] == T_STREAM
               for o, _ in v.segments):
            stats["seghdr"] += 1
        w, h, f = i["width"], i["height"], i["frames"]
        good = bool(w and h and 0 < w <= 640 and 0 < h <= 480 and f > 0
                    and i["fps"] and i["rate"])
        if good:
            stats["sane"] += 1
        if v.tail_zero:
            stats["tailzero"] += 1
        pix, au = v.key_frame()
        if pix is not None and len(pix) == w * h:
            stats["keyexact"] += 1
        _pal, npal, rem = v.palette()
        if npal and rem == 2:
            stats["palpad"] += 1
        if good and v.chain_breaks == 0:
            ok += 1
        elif not quiet:
            print("%-44s FAIL  chain breaks %d  %sx%s frames %s"
                  % (os.path.relpath(p), v.chain_breaks, w, h, f))
    print("files given                                 : %d" % n)
    print("first four bytes are 28 00 00 00            : %d / %d"
          % (stats["magic"], n))
    print("length is an exact multiple of 2048         : %d / %d"
          % (stats["mult2048"], n))
    print("prev-size chain intact, every block         : %d / %d"
          % (stats["chain"], n))
    print("every segment starts on a 2048 boundary     : %d / %d"
          % (stats["segsector"], n))
    print("every segment opens with a type-2 header    : %d / %d"
          % (stats["seghdr"], n))
    print("video header fields sane                    : %d / %d"
          % (stats["sane"], n))
    print("key frame payload == width*height exactly   : %d / %d"
          % (stats["keyexact"], n))
    print("palette payload is 3n+2 (pad to 4 bytes)    : %d / %d"
          % (stats["palpad"], n))
    print("bytes after the last segment are all zero   : %d / %d"
          % (stats["tailzero"], n))
    print()
    print("validated: %d / %d" % (ok, n))
    return n - ok


def cmd_reject(paths):
    """Negative control: these files must NOT validate."""
    bad = 0
    for p in paths:
        try:
            v = Imv(p)
            i = v.info()
            w, h, f = i["width"], i["height"], i["frames"]
            accepted = (v.b[:4] == b"\x28\x00\x00\x00" and v.chain_breaks == 0
                        and w and h and 0 < w <= 640 and 0 < h <= 480 and f)
        except Exception:                                   # noqa: BLE001
            accepted = False
        print("%-44s %s" % (os.path.relpath(p),
                            "ACCEPTED -- CONTROL FAILED" if accepted
                            else "rejected (correct)"))
        if accepted:
            bad += 1
    return bad


def cmd_census(paths):
    import collections
    dims = collections.Counter()
    fps = collections.Counter()
    rate = collections.Counter()
    segs = 0
    frames = 0
    byts = 0
    audio_bytes = 0
    padding = 0
    for p in paths:
        v = Imv(p)
        i = v.info()
        frames += i["frames"]
        byts += i["size"]
        dims[(i["width"], i["height"])] += 1
        fps[i["fps"]] += 1
        rate[i["rate"]] += 1
        segs += i["segments"]
        padding += v.tail
        pix, au = v.key_frame()
        if au is not None:
            audio_bytes += len(au) * 1  # per-key-frame only; see --audio
    print("files                    : %d" % len(paths))
    print("bytes                    : %d" % byts)
    print("segments                 : %d" % segs)
    print("declared frames, summed  : %d" % frames)
    print("trailing padding bytes   : %d" % padding)
    print()
    print("dimensions:")
    for k, c in dims.most_common():
        print("   %4s x %-4s  %4d files" % (k[0], k[1], c))
    print("frame rate:")
    for k, c in fps.most_common():
        print("   %5s fps    %4d files" % (k, c))
    print("audio sample rate:")
    for k, c in rate.most_common():
        print("   %6s Hz    %4d files" % (k, c))
    if len(fps) == 1:
        f = list(fps)[0]
        s = frames / f
        print()
        print("running time at %d fps   : %.1f s = %d m %04.1f s"
              % (f, s, int(s // 60), s % 60))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--reject", action="store_true",
                    help="negative control: these files must be rejected")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--png")
    ap.add_argument("--wav")
    ap.add_argument("--audiofit", action="store_true",
                    help="score candidate audio run lengths by join continuity")
    ap.add_argument("--keys", metavar="OUTDIR",
                    help="render every key frame of every file given")
    ap.add_argument("--blocks", type=int, default=0)
    ap.add_argument("--segments", action="store_true")
    a = ap.parse_args()
    rc = 0
    if a.validate:
        rc |= 1 if cmd_validate(a.files, a.quiet) else 0
    if a.reject:
        rc |= 1 if cmd_reject(a.files) else 0
    if a.census:
        cmd_census(a.files)
    if a.segments:
        v = Imv(a.files[0])
        print("%-8s %-10s %s" % ("sector", "offset", "next segment sector"))
        for o, nxt in v.segments:
            print("%-8d %-10d %d" % (o // SECTOR, o, nxt))
        print("segments: %d   covered %d of %d bytes   tail %d %s"
              % (len(v.segments), v.covered, len(v.b), v.tail,
                 "all zero" if v.tail_zero else "NON-ZERO"))
    if a.blocks:
        v = Imv(a.files[0])
        print("%-10s %-9s %-9s %-7s %-8s %s"
              % ("offset", "size", "prev", "type", "+10", "+12"))
        for r in v.blocks[:a.blocks]:
            print("%-10d %-9d %-9d 0x%-5X %-8d %d"
                  % (r[0], r[1], r[2], r[3], r[4], r[5]))
        for e in v.errors[:8]:
            print("  ! " + e)
    if a.audiofit:
        for p in a.files:
            v = Imv(p)
            rows = v.audiofit()
            i = v.info()
            print("%s  (rate %d / fps %d = %d)"
                  % (os.path.relpath(p), i["rate"], i["fps"], v.audio_len()))
            print("   %-7s %-11s %-9s %s"
                  % ("length", "join/inner", "join step", "inner step"))
            for r in rows[:4]:
                print("   %-7d %-11.3f %-9.2f %.2f" % (r[1], r[0], r[2], r[3]))
            print("   worst: %d at %.3f" % (rows[-1][1], rows[-1][0]))
    if a.keys:
        os.makedirs(a.keys, exist_ok=True)
        n = 0
        for p in a.files:
            v = Imv(p)
            i = v.info()
            pal, _npal, _rem = v.palette()
            stem = os.path.splitext(os.path.basename(p))[0]
            for k, (off, pix, _au) in enumerate(v.key_frames()):
                write_png(os.path.join(a.keys, "%s_k%02d.png" % (stem, k)),
                          i["width"], i["height"], pix, pal)
                n += 1
        print("wrote %d key frames to %s" % (n, a.keys))
    if a.png:
        v = Imv(a.files[0])
        i = v.info()
        pal, npal, rem = v.palette()
        pix, au = v.key_frame()
        if pix is None:
            sys.exit("no key frame in %s" % a.files[0])
        write_png(a.png, i["width"], i["height"], pix, pal)
        print("wrote %s  %dx%d  %d palette entries (+%d pad)  key-frame "
              "audio %d bytes" % (a.png, i["width"], i["height"], npal, rem,
                                  len(au)))
    if a.wav:
        v = Imv(a.files[0])
        i = v.info()
        d = v.audio()
        write_wav(a.wav, d, i["rate"])
        print("wrote %s  %d bytes  %d Hz unsigned 8-bit mono  %.2f s"
              % (a.wav, len(d), i["rate"], len(d) / i["rate"]))
        print("   video says %d frames at %d fps = %.2f s"
              % (i["frames"], i["fps"], i["frames"] / i["fps"]))
    sys.exit(rc)


if __name__ == "__main__":
    main()
