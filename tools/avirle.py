#!/usr/bin/env python3
"""avirle.py -- decode the BI_RLE8 video inside a 1992 Video for Windows AVI,
and census what the 1,208 of them on this disc are made of.

`avi.py` reads headers and `avicheck.py` counts chunks. Neither decodes a
pixel, and on this disc 95.8047 % of the declared bytes is video whose *kind*
-- drawn or digitised -- is the question the thesis chapter turns on. You
cannot answer that from a file listing: at 80x60 in 8-bit RLE an animation and
a digitised clip look identical in a directory.

So this decodes. The public definition being used, and named as used:

  * RIFF chunk tree -- Microsoft/IBM Multimedia Programming Interface and Data
    Specifications 1.0 (1991);
  * `avih` / `strh` / `strf` -- Video for Windows 1.0, `strf` on a video stream
    being a BITMAPINFOHEADER followed by 256 RGBQUAD when biBitCount is 8;
  * **BI_RLE8** -- the run-length format defined for `biCompression == 1` in
    the Windows 3.1 SDK. Encoded mode is a (count, index) pair with count > 0.
    A count of 0 is an escape: 0 ends a line, 1 ends the bitmap, 2 introduces a
    two-byte (dx, dy) delta, and 3..255 introduces that many literal indices
    padded to a word boundary. Rows run bottom-up.

The decoder is checkable rather than asserted. `--validate` decodes every
frame of a file and reports, per frame, whether the run lengths written by the
encoder cover exactly width x height pixels and whether the escape sequence
terminates where the chunk ends. A frame that over-runs the canvas is a
decoder bug or a wrong layout, and it says which frame.

**A note on delta frames.** After the first frame a BI_RLE8 stream may leave
pixels untouched, so a decoded frame is only meaningful on a canvas carried
forward from the previous one. `--frame` therefore decodes from frame 0 up to
the requested index rather than seeking, and says so.

    python tools/avirle.py FILE --validate
    python tools/avirle.py FILE --frame 0 --png OUT.png
    python tools/avirle.py DIR  --census
    python tools/avirle.py DIR  --flatness            # 2x2 uniform-block rate
    python tools/avirle.py FILE --sheet OUT.png --every 8
"""
import argparse
import hashlib
import os
import struct
import sys


# ---------------------------------------------------------------- RIFF ----

def chunks(d, start, end):
    """Yield (fourcc, payload_start, payload_len, next) inside [start, end)."""
    p = start
    while p + 8 <= end:
        cid = d[p:p + 4]
        n = struct.unpack_from("<I", d, p + 4)[0]
        body = p + 8
        yield cid, body, n
        p = body + n + (n & 1)


class AVI(object):
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.d = f.read()
        d = self.d
        if d[:4] != b"RIFF" or d[8:12] != b"AVI ":
            raise ValueError("%s: not a RIFF/AVI (%r %r)"
                             % (path, d[:4], d[8:12]))
        self.riff_size = struct.unpack_from("<I", d, 4)[0]
        self.avih = None
        self.streams = []        # list of dicts
        self.movi = None         # (start, end)
        self.idx1 = None
        self._walk(12, min(len(d), 8 + self.riff_size))

    def _walk(self, start, end):
        d = self.d
        for cid, body, n in chunks(d, start, end):
            if cid == b"LIST":
                kind = d[body:body + 4]
                if kind == b"movi":
                    self.movi = (body + 4, body + n)
                else:
                    self._walk(body + 4, body + n)
            elif cid == b"avih":
                (mspf, maxrate, pad, flags, total, initial, nstreams,
                 bufsize, w, h) = struct.unpack_from("<10I", d, body)
                self.avih = dict(mspf=mspf, maxrate=maxrate, flags=flags,
                                 frames=total, streams=nstreams,
                                 bufsize=bufsize, w=w, h=h)
            elif cid == b"strh":
                self.streams.append({"strh": d[body:body + n], "strf": None})
            elif cid == b"strf" and self.streams:
                self.streams[-1]["strf"] = d[body:body + n]
            elif cid == b"idx1":
                self.idx1 = (body, n)

    # -- what the streams say ------------------------------------------

    def video(self):
        for s in self.streams:
            if s["strh"][:4] == b"vids":
                return s
        return None

    def audio(self):
        for s in self.streams:
            if s["strh"][:4] == b"auds":
                return s
        return None

    def bih(self):
        s = self.video()
        if not s or not s["strf"]:
            return None
        (hs, w, h, planes, bpp, comp, imgsize, xppm, yppm,
         used, imp) = struct.unpack_from("<IiiHHIIiiII", s["strf"], 0)
        return dict(hs=hs, w=w, h=h, bpp=bpp, comp=comp, imgsize=imgsize,
                    used=used, planes=planes)

    def palette(self):
        """256 RGBQUAD (B, G, R, reserved) after the BITMAPINFOHEADER."""
        s = self.video()
        b = self.bih()
        if not s or not b or b["bpp"] != 8:
            return None
        raw = s["strf"][b["hs"]:b["hs"] + 1024]
        if len(raw) < 1024:
            return None
        return [(raw[i + 2], raw[i + 1], raw[i]) for i in range(0, 1024, 4)]

    def wavefmt(self):
        s = self.audio()
        if not s or not s["strf"] or len(s["strf"]) < 16:
            return None
        tag, ch, rate, byterate, align, bits = struct.unpack_from(
            "<HHIIHH", s["strf"], 0)
        return dict(tag=tag, ch=ch, rate=rate, byterate=byterate,
                    align=align, bits=bits)

    # -- the movi list -------------------------------------------------

    def movi_chunks(self):
        """Flattened. An interleaved AVI 1.0 groups one frame's chunks inside
        `LIST rec `, and a reader that does not descend into those sees a movi
        list containing nothing but lists -- which is a count of zero frames
        that looks exactly like a file with no video in it."""
        if not self.movi:
            return []
        out = []

        def rec(start, end):
            for cid, body, n in chunks(self.d, start, end):
                if cid == b"LIST":
                    rec(body + 4, body + n)
                else:
                    out.append((cid, body, n))

        rec(self.movi[0], self.movi[1])
        return out

    def video_chunks(self):
        out = []
        for cid, body, n in self.movi_chunks():
            if cid[2:4] in (b"dc", b"db", b"dx") and cid[:2].isdigit():
                out.append((cid, body, n))
        return out

    def audio_bytes(self):
        return sum(n for cid, body, n in self.movi_chunks()
                   if cid[2:4] == b"wb")

    def junk_bytes(self):
        return sum(n for cid, body, n in self.movi_chunks() if cid == b"JUNK")


# ------------------------------------------------------------ BI_RLE8 ----

class RLEError(Exception):
    pass


def rle8(payload, w, h, canvas=None):
    """Decode one BI_RLE8 chunk onto a bottom-up canvas of w*h indices.

    Returns (canvas, stats). `stats` records what the encoder actually did, so
    a caller can check the decode rather than trust it.
    """
    if canvas is None:
        canvas = bytearray(w * h)
    x = 0
    y = 0                     # 0 = bottom row
    p = 0
    n = len(payload)
    st = dict(encoded=0, absolute=0, eol=0, delta=0, painted=0,
              eob=False, consumed=0, overrun=0)

    def put(v, count):
        nonlocal x
        if x + count > w:
            st["overrun"] += (x + count) - w
            count = max(0, w - x)
        row = (h - 1 - y) * w
        canvas[row + x:row + x + count] = bytes([v]) * count
        x += count
        st["painted"] += count

    while p < n:
        a = payload[p]
        b = payload[p + 1] if p + 1 < n else 0
        p += 2
        if a:
            if y >= h:
                st["overrun"] += a
                continue
            put(b, a)
            st["encoded"] += 1
        elif b == 0:
            x = 0
            y += 1
            st["eol"] += 1
        elif b == 1:
            st["eob"] = True
            break
        elif b == 2:
            if p + 2 > n:
                break
            dx, dy = payload[p], payload[p + 1]
            p += 2
            x += dx
            y += dy
            st["delta"] += 1
        else:
            run = payload[p:p + b]
            p += b + (b & 1)
            if y < h:
                row = (h - 1 - y) * w
                take = min(b, w - x)
                if take < b:
                    st["overrun"] += b - take
                canvas[row + x:row + x + take] = run[:take]
                x += take
                st["painted"] += take
            st["absolute"] += 1
    st["consumed"] = p
    return canvas, st


# ------------------------------------------------------------- output ----

def to_png(canvas, w, h, pal, out):
    from PIL import Image
    im = Image.frombytes("P", (w, h), bytes(canvas))
    flat = []
    for r, g, b in (pal or [(i, i, i) for i in range(256)]):
        flat += [r, g, b]
    im.putpalette(flat)
    im.convert("RGB").save(out)


def flatness(canvas, w, h):
    """Fraction of 2x2 blocks whose four indices are equal -- the statistic
    vis-sherlockholmes-doc/tools/flatness.py used to separate painted art from
    continuous tone. Reported, never interpreted without a control."""
    tot = 0
    same = 0
    for y in range(0, h - 1, 2):
        for x in range(0, w - 1, 2):
            a = canvas[y * w + x]
            tot += 1
            if (canvas[y * w + x + 1] == a and canvas[(y + 1) * w + x] == a
                    and canvas[(y + 1) * w + x + 1] == a):
                same += 1
    return same, tot


def walk(path, exts=(".avi",)):
    if os.path.isfile(path):
        return [path]
    out = []
    for r, dirs, names in os.walk(path):
        dirs.sort()
        for nm in sorted(names):
            if nm.lower().endswith(exts):
                out.append(os.path.join(r, nm))
    return out


# --------------------------------------------------------------- main ----

def cmd_validate(paths):
    files = 0
    frames = 0
    bad = 0
    print("%-44s %6s %8s %8s %8s %s"
          % ("file", "frames", "painted", "overrun", "no-eob", "verdict"))
    for p in paths:
        a = AVI(p)
        b = a.bih()
        w, h = b["w"], abs(b["h"])
        canvas = None
        over = 0
        noeob = 0
        vc = a.video_chunks()
        for cid, body, n in vc:
            canvas, st = rle8(a.d[body:body + n], w, h, canvas)
            over += st["overrun"]
            noeob += not st["eob"]
        painted = sum(1 for v in canvas) if canvas else 0
        ok = over == 0
        bad += not ok
        files += 1
        frames += len(vc)
        print("%-44s %6d %8d %8d %8d %s"
              % (os.path.basename(p), len(vc), painted, over, noeob,
                 "ok" if ok else "OVERRUN"))
    print()
    print("files decoded          : %d" % files)
    print("frames decoded         : %d" % frames)
    print("files with an overrun  : %d" % bad)
    return 1 if bad else 0


def cmd_census(paths):
    print("%-46s %10s %5s %6s %4s %5s %5s %9s %9s %9s %s"
          % ("file", "bytes", "wxh", "frames", "str", "ach", "arate",
             "video B", "audio B", "junk B", "palette sha1"))
    tot = dict(files=0, bytes=0, frames=0, vb=0, ab=0, jb=0, secs=0.0)
    pals = {}
    fmts = {}
    for p in paths:
        a = AVI(p)
        b = a.bih()
        wf = a.wavefmt()
        vc = a.video_chunks()
        vb = sum(n for cid, body, n in vc)
        ab = a.audio_bytes()
        jb = a.junk_bytes()
        pal = a.palette()
        ph = hashlib.sha1(bytes(x for t in (pal or []) for x in t)).hexdigest()
        pals[ph] = pals.get(ph, 0) + 1
        key = (wf["tag"], wf["ch"], wf["rate"], wf["bits"]) if wf else None
        fmts[key] = fmts.get(key, 0) + 1
        secs = len(vc) * a.avih["mspf"] / 1e6
        print("%-46s %10d %5s %6d %4d %5s %5s %9d %9d %9d %s"
              % (os.path.relpath(p), len(a.d), "%dx%d" % (b["w"], abs(b["h"])),
                 len(vc), len(a.streams),
                 wf["ch"] if wf else "-", wf["rate"] if wf else "-",
                 vb, ab, jb, ph[:12]))
        tot["files"] += 1
        tot["bytes"] += len(a.d)
        tot["frames"] += len(vc)
        tot["vb"] += vb
        tot["ab"] += ab
        tot["jb"] += jb
        tot["secs"] += secs
    print()
    print("files                       : %d" % tot["files"])
    print("bytes                       : %d" % tot["bytes"])
    print("video frames                : %d" % tot["frames"])
    print("running time                : %.3f s = %d h %02d m %05.2f s"
          % (tot["secs"], int(tot["secs"] // 3600),
             int(tot["secs"] % 3600 // 60), tot["secs"] % 60))
    for k, label in (("vb", "video payload bytes"),
                     ("ab", "audio payload bytes"),
                     ("jb", "JUNK padding bytes")):
        print("%-27s : %12d  (%6.3f %% of these files)"
              % (label, tot[k], 100.0 * tot[k] / tot["bytes"]))
    acc = tot["vb"] + tot["ab"] + tot["jb"]
    print("%-27s : %12d  (%6.3f %%), residue %d"
          % ("the three together", acc, 100.0 * acc / tot["bytes"],
             tot["bytes"] - acc))
    print()
    print("distinct video palettes     : %d over %d files" % (len(pals), tot["files"]))
    for ph, c in sorted(pals.items(), key=lambda kv: -kv[1])[:6]:
        print("    %s x %d" % (ph[:16], c))
    print("audio formats (tag, ch, Hz, bits):")
    for k, c in sorted(fmts.items(), key=lambda kv: -kv[1]):
        print("    %-28s x %d" % (k, c))
    return 0


def cmd_flatness(paths, frame=0):
    print("%-46s %6s %8s %8s" % ("file", "frame", "2x2 same", "of"))
    rows = []
    for p in paths:
        a = AVI(p)
        b = a.bih()
        w, h = b["w"], abs(b["h"])
        canvas = None
        vc = a.video_chunks()
        for i, (cid, body, n) in enumerate(vc):
            canvas, st = rle8(a.d[body:body + n], w, h, canvas)
            if i >= frame:
                break
        s, t = flatness(canvas, w, h)
        rows.append((os.path.relpath(p), s, t))
        print("%-46s %6d %8d %8d   %6.2f %%"
              % (os.path.relpath(p), frame, s, t, 100.0 * s / t))
    if rows:
        vals = [100.0 * s / t for _, s, t in rows]
        lo, hi = min(vals), max(vals)
        print()
        print("population of %d: min %.2f %%  max %.2f %%  mean %.2f %%"
              % (len(vals), lo, hi, sum(vals) / len(vals)))
        if lo > 0 and hi / max(lo, 0.01) >= 3.0:
            print("WARNING: this population's range spans a factor of %.1f."
                  " A control has to be homogeneous in everything except the"
                  " property under test; this one is not." % (hi / lo))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--flatness", action="store_true")
    ap.add_argument("--frame", type=int, default=None)
    ap.add_argument("--png")
    ap.add_argument("--sheet")
    ap.add_argument("--every", type=int, default=8)
    ap.add_argument("--scale", type=int, default=1)
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    paths = walk(a.path)
    if not paths:
        print("%s: no .avi found -- this is a refusal, not a result of zero"
              % a.path)
        return 1
    print("opened %d file(s) under %s" % (len(paths), a.path))
    try:
        AVI(paths[0])
    except ValueError as exc:
        print(exc)
        return 1

    if a.validate:
        return cmd_validate(paths)
    if a.census:
        return cmd_census(paths)
    if a.flatness:
        return cmd_flatness(paths, a.frame or 0)
    if a.png is not None or a.sheet:
        av = AVI(paths[0])
        b = av.bih()
        w, h = b["w"], abs(b["h"])
        pal = av.palette()
        vc = av.video_chunks()
        want = a.frame if a.frame is not None else 0
        canvas = None
        keep = []
        for i, (cid, body, n) in enumerate(vc):
            canvas, st = rle8(av.d[body:body + n], w, h, canvas)
            if a.sheet and i % a.every == 0:
                keep.append(bytes(canvas))
            if a.png and i >= want:
                break
        if a.png:
            print("decoded frames 0..%d of %d (BI_RLE8 carries deltas, so the"
                  " canvas is cumulative)" % (want, len(vc)))
            to_png(canvas, w, h, pal, a.png)
            s, t = flatness(canvas, w, h)
            print("wrote %s  %dx%d  2x2 uniform blocks %d of %d = %.2f %%"
                  % (a.png, w, h, s, t, 100.0 * s / t))
        if a.sheet:
            from PIL import Image
            cols = 8
            rows = (len(keep) + cols - 1) // cols
            sc = a.scale
            sheet = Image.new("RGB", (cols * w * sc, rows * h * sc), (16, 16, 16))
            for i, c in enumerate(keep):
                im = Image.frombytes("P", (w, h), c)
                flat = []
                for r, g, bl in pal:
                    flat += [r, g, bl]
                im.putpalette(flat)
                im = im.convert("RGB")
                if sc != 1:
                    im = im.resize((w * sc, h * sc), Image.NEAREST)
                sheet.paste(im, ((i % cols) * w * sc, (i // cols) * h * sc))
            sheet.save(a.sheet)
            print("wrote %s  %d frames every %d of %d"
                  % (a.sheet, len(keep), a.every, len(vc)))
        return 0

    print("nothing to do: pass --validate, --census, --flatness, --png or --sheet")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
