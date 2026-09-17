#!/usr/bin/env python3
"""cvidmovie.py -- decode the FRME payloads of a 3DO Data Streamer film.

The `FHDR` sub-chunk of this disc's two stream files declares its compression
type as the four characters `cvid`, and `stripwalk.py` shows the payload at
offset +44 of every `FRME` chunk chains as Cinepak strips to the byte on 409
frames of 409. **Cinepak is a public format** and what follows is the public
definition, applied here and then checked against quantities this disc states
independently:

    the strips' heights sum to the height `FHDR` declares      (100 + 100 = 200)
    the strips' width equals the width `FHDR` declares         (320)
    the number of `FRME` chunks equals the count `FHDR` declares (409)

and finally by a person looking at a frame, which is the only check that
distinguishes a correct decode from an arithmetically consistent one.

THE FORMAT, as publicly defined

    strip     u16 id (0x1000 intra, 0x1100 inter), u16 size incl. header,
              u16 y0, u16 x0, u16 y1, u16 x1
              -- the rectangle is RELATIVE to the previous strip, which is why
                 both strips here say 0..100 and the frame is 200 tall

    inside a strip:  u16 id, u16 size INCLUDING this four-byte header
              -- which of the two readings is right was settled by walking
                 both over every strip of the file: inclusive chains to the
                 last byte on 818 strips of 818, exclusive on 0 of 818
              0x2000 V4 codebook, colour    0x2200 V1 codebook, colour
              0x2400 V4 codebook, mono      0x2600 V1 codebook, mono
              0x2100/0x2300/0x2500/0x2700   the same, as sparse updates
              0x3000 vectors, intra         0x3100 vectors, inter
              0x3200 vectors, V1 only

    a codebook entry is four Y bytes and, when colour, a signed u and v
    a macroblock is 4x4 pixels: one V1 entry scaled 2x, or four V4 entries

usage:
    cvidmovie.py FILE --frame N --png OUT.png
    cvidmovie.py FILE --census                 decode every frame, report
    cvidmovie.py FILE --contact OUT.png --grid 6x4
"""
import argparse
import struct
import sys


def chunks(data):
    off = 0
    out = []
    while off < len(data):
        tag = data[off:off + 4]
        size = struct.unpack(">I", data[off + 4:off + 8])[0]
        if size < 8 or off + size > len(data):
            raise SystemExit("bad chain at %d" % off)
        out.append((off, tag, size))
        off += size
    return out


def clip(x):
    return 0 if x < 0 else (255 if x > 255 else x)


class Codebook(object):
    def __init__(self):
        self.e = [[0, 0, 0, 0, 0, 0] for _ in range(256)]   # y0..y3, u, v

    def load(self, data, mono, sparse):
        n = 4 if mono else 6
        p = 0
        if sparse:
            i = 0
            while p + 4 <= len(data) and i < 256:
                mask = struct.unpack(">I", data[p:p + 4])[0]
                p += 4
                for b in range(32):
                    if i >= 256:
                        break
                    if mask & (0x80000000 >> b):
                        if p + n > len(data):
                            return
                        v = list(data[p:p + n])
                        p += n
                        if mono:
                            v = v + [128, 128]
                        self.e[i] = v
                    i += 1
        else:
            i = 0
            while p + n <= len(data) and i < 256:
                v = list(data[p:p + n])
                p += n
                if mono:
                    v = v + [128, 128]
                self.e[i] = v
                i += 1


def yuv(e, k):
    y = e[k]
    u = e[4] - 256 if e[4] > 127 else e[4]
    v = e[5] - 256 if e[5] > 127 else e[5]
    return (clip(y + (v * 2)), clip(y - (u // 2) - (v // 2)), clip(y + (u * 2)))


class Frame(object):
    def __init__(self, w, h):
        self.w = w
        self.h = h
        self.px = bytearray(w * h * 3)

    def put(self, x, y, rgb):
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 3
            self.px[i] = rgb[0]
            self.px[i + 1] = rgb[1]
            self.px[i + 2] = rgb[2]

    def block_v1(self, x, y, cb, idx):
        e = cb.e[idx]
        for k, (dx, dy) in enumerate(((0, 0), (2, 0), (0, 2), (2, 2))):
            c = yuv(e, k)
            for j in range(2):
                for i in range(2):
                    self.put(x + dx + i, y + dy + j, c)

    def block_v4(self, x, y, cb, idxs):
        for q, (dx, dy) in enumerate(((0, 0), (2, 0), (0, 2), (2, 2))):
            e = cb.e[idxs[q]]
            for k, (ex, ey) in enumerate(((0, 0), (1, 0), (0, 1), (1, 1))):
                self.put(x + dx + ex, y + dy + ey, yuv(e, k))


def decode_frame(payload, width, height, prev=None):
    """Decode one Cinepak frame. Returns a Frame and a report dict."""
    fr = Frame(width, height)
    if prev is not None:
        fr.px[:] = prev.px
    p = 0
    ytop = 0
    v1 = Codebook()
    v4 = Codebook()
    rep = dict(strips=0, subchunks=[], skipped=0, coded=0, overrun=0)
    while p + 12 <= len(payload):
        sid, ssz = struct.unpack(">2H", payload[p:p + 4])
        y0, x0, y1, x1 = struct.unpack(">4H", payload[p + 4:p + 12])
        if ssz < 12 or p + ssz > len(payload):
            rep["overrun"] += 1
            break
        sh = y1 - y0
        send = p + ssz
        q = p + 12
        rep["strips"] += 1
        while q + 4 <= send:
            cid, csz = struct.unpack(">2H", payload[q:q + 4])
            if csz < 4 or q + csz > send:
                rep["overrun"] += 1
                break
            body = payload[q + 4:q + csz]
            rep["subchunks"].append(cid)
            if cid in (0x2000, 0x2100, 0x2400, 0x2500):
                v4.load(body, cid & 0x0400, cid & 0x0100)
            elif cid in (0x2200, 0x2300, 0x2600, 0x2700):
                v1.load(body, cid & 0x0400, cid & 0x0100)
            elif cid in (0x3000, 0x3100, 0x3200):
                decode_vectors(fr, body, cid, v1, v4, x0, ytop + y0,
                               x1 - x0, sh, rep)
            q += csz
        ytop += sh
        p = send
    rep["height_from_strips"] = ytop
    return fr, rep


def decode_vectors(fr, body, cid, v1, v4, x0, y0, w, h, rep):
    p = 0
    x = x0
    y = y0
    ymax = y0 + h
    if cid == 0x3200:
        while p < len(body) and y < ymax:
            fr.block_v1(x, y, v1, body[p])
            rep["coded"] += 1
            p += 1
            x += 4
            if x >= x0 + w:
                x = x0
                y += 4
        return
    inter = (cid == 0x3100)
    mask = 0
    bit = 0
    while y < ymax:
        if bit == 0:
            if p + 4 > len(body):
                return
            mask = struct.unpack(">I", body[p:p + 4])[0]
            p += 4
            bit = 32
        take = bool(mask & 0x80000000)
        mask = (mask << 1) & 0xFFFFFFFF
        bit -= 1
        if inter and not take:
            rep["skipped"] += 1
        else:
            if inter:
                if bit == 0:
                    if p + 4 > len(body):
                        return
                    mask = struct.unpack(">I", body[p:p + 4])[0]
                    p += 4
                    bit = 32
                use4 = bool(mask & 0x80000000)
                mask = (mask << 1) & 0xFFFFFFFF
                bit -= 1
            else:
                use4 = take
            if use4:
                if p + 4 > len(body):
                    return
                fr.block_v4(x, y, v4, list(body[p:p + 4]))
                p += 4
            else:
                if p + 1 > len(body):
                    return
                fr.block_v1(x, y, v1, body[p])
                p += 1
            rep["coded"] += 1
        x += 4
        if x >= x0 + w:
            x = x0
            y += 4


def frames_of(data):
    cs = chunks(data)
    hdr = [c for c in cs if c[1] == b"FILM"
           and data[c[0] + 16:c[0] + 20] == b"FHDR"]
    if not hdr:
        raise SystemExit("no FHDR chunk")
    off = hdr[0][0]
    comp = data[off + 24:off + 28]
    height, width, rate, count = struct.unpack(">4I", data[off + 28:off + 44])
    fr = [c for c in cs if c[1] == b"FILM"
          and data[c[0] + 16:c[0] + 20] == b"FRME"]
    return comp, width, height, rate, count, fr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--frame", type=int, default=0)
    ap.add_argument("--png")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--contact")
    ap.add_argument("--grid", default="6x4")
    ap.add_argument("--payload", type=int, default=44)
    a = ap.parse_args()
    data = open(a.file, "rb").read()
    comp, width, height, rate, count, fr = frames_of(data)
    print("%s" % a.file)
    print("  FHDR says: compression %r, %d x %d, field at +36 = %d, frames = %d"
          % (comp, width, height, rate, count))
    print("  FRME chunks measured: %d   (declared %d, equal %s)"
          % (len(fr), count, len(fr) == count))
    if comp != b"cvid":
        print("  compression is not 'cvid'; this decoder does not apply")
        return

    from PIL import Image

    def dec_upto(n, keep=None):
        prev = None
        reps = []
        for i, (off, t, size) in enumerate(fr[:n + 1]):
            payload = data[off + a.payload:off + size]
            img, rep = decode_frame(payload, width, height, prev)
            reps.append(rep)
            prev = img
            if keep is not None and i in keep:
                keep[i] = img
        return prev, reps

    if a.census:
        prev = None
        heights = {}
        over = 0
        cover = []
        for off, t, size in fr:
            payload = data[off + a.payload:off + size]
            img, rep = decode_frame(payload, width, height, prev)
            prev = img
            heights[rep["height_from_strips"]] = heights.get(
                rep["height_from_strips"], 0) + 1
            over += rep["overrun"]
            cover.append(rep["coded"] + rep["skipped"])
        mb = (width // 4) * (height // 4)
        print("  frames decoded              : %d" % len(fr))
        print("  strip heights sum to        : %s"
              % ", ".join("%d (x%d)" % (k, v) for k, v in heights.items()))
        print("  frames with a sub-chunk overrun: %d" % over)
        print("  macroblocks per frame       : %d expected (%d x %d of 4x4)"
              % (mb, width // 4, height // 4))
        print("  frames accounting for all of them: %d of %d"
              % (sum(1 for c in cover if c == mb), len(cover)))
        return

    if a.contact:
        gw, gh = (int(x) for x in a.grid.split("x"))
        n = gw * gh
        step = max(1, (len(fr) - 1) // (n - 1)) if n > 1 else 1
        want = sorted(set(min(i * step, len(fr) - 1) for i in range(n)))
        keep = dict((i, None) for i in want)
        dec_upto(max(want), keep)
        sheet = Image.new("RGB", (gw * width, gh * height), (16, 16, 16))
        for k, i in enumerate(want):
            img = keep[i]
            if img is None:
                continue
            im = Image.frombytes("RGB", (width, height), bytes(img.px))
            sheet.paste(im, ((k % gw) * width, (k // gw) * height))
        sheet.save(a.contact)
        print("  contact sheet: %s   frames %s" % (a.contact, want))
        return

    img, reps = dec_upto(a.frame)
    rep = reps[-1]
    print("  frame %d: %d strip(s), heights sum to %d, %d coded, %d skipped, "
          "%d overrun" % (a.frame, rep["strips"], rep["height_from_strips"],
                          rep["coded"], rep["skipped"], rep["overrun"]))
    print("  sub-chunk ids: %s"
          % ", ".join("0x%04x" % c for c in rep["subchunks"]))
    if a.png:
        Image.frombytes("RGB", (width, height), bytes(img.px)).save(a.png)
        print("  wrote %s" % a.png)


if __name__ == "__main__":
    main()
