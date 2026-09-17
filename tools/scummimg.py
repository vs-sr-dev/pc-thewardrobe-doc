#!/usr/bin/env python3
"""Decode SCUMM room backgrounds and palettes, deriving the strip codec by fit.

No reference implementation was consulted. The codec below was found by
measurement, in four steps, and each step is a falsifiable claim about the
bytes:

1. **`SMAP` is a strip table.** Its payload starts with `width/8` 32-bit
   little-endian offsets, and offset[0] is always exactly `8 + 4*(width/8)` --
   the byte after the table, counted from the chunk header. Checked on all 85
   backgrounds: 85 of 85. The offsets are strictly increasing.

2. **The first byte of a strip is a code, and `code % 10` is its bit width.**
   Fourteen distinct codes occur in this object: 15..18, 28, 38, 104..108,
   124, 127, 128. Modulo 10 they are 5,6,7,8 / 8 / 8 / 4..8 / 4,7,8 -- never 0,
   never above 8. Nothing else about the code divides that cleanly.

3. **There are two grammars, and which one a strip uses is decided by its code
   band.** This was found by brute force, not by lookup: the decoder was run
   over every strip with the delta field set to 1..6 bits, with and without a
   leading "changed?" bit, and scored on whether the bit reader stopped inside
   the strip's own byte range. For codes below 0x40 a **1-bit** delta fits
   400 of 400 sampled strips and every other width fits under 13 %. For codes
   0x68..0x80 a **3-bit** delta with an escape value fits, and the escape
   introduces an 8-bit run length whose count includes the pixel already
   written: `run` lands exactly on the strip end for 2,097 strips of 3,359,
   `run - 1` for 3,330, and `run - 2` reads past the end on 3,173 of them.
   Only one value survives, and it is not the obvious one.

       band 0x0E..0x30   emit; if bit: if bit: {if bit: dir = -dir}; c += dir
                                       else:  c = bits(bpp)
       band 0x68..0x80   emit; if bit: if bit: {d = bits(3);
                                                if d == 4: run = bits(8)
                                                else:      c += d - 4}
                                       else:  c = bits(bpp)

   Bits are read least-significant-first within each byte.

4. **The direction bit in step 3 is a persistent direction, not a sign.**
   Both readings consume identical numbers of bits, so consumption cannot
   choose between them; the pixel values can. Reading the bit as `c += (bit ?
   -1 : +1)` drives the colour index out of 0..255 on 10,638 pixels of a
   20-room sample; reading it as "flip a persistent step and add it" does so
   on 42. The second reading is kept and the 42 are reported, not hidden.

`code & 8` in the low band and the 0x7C band mean horizontal (row-major within
the 8-pixel strip); the others are vertical (column-major). The direction does
not change how many bytes a strip consumes, so it is **not** derived from the
closure test -- it is derived from which one produces an image whose adjacent
rows correlate. That check is `--direction`.

Palettes are `APAL` chunks: 768 bytes, 256 entries of R,G,B. The values run to
255, not to 63, so they are 8-bit and not raw VGA DAC values.

Usage:
  python tools/scummimg.py rooms  <SAMNMAX.001> [--key 0x69]
  python tools/scummimg.py strips <SAMNMAX.001>          # codec closure test
  python tools/scummimg.py pal    <SAMNMAX.001>
  python tools/scummimg.py dump   <SAMNMAX.001> <room#> <out.ppm>
"""
import collections
import sys

LOW = range(0x0E, 0x31)
HIGH = list(range(0x68, 0x6D)) + list(range(0x7C, 0x81))


class BitsLSB:
    __slots__ = ("d", "i", "b", "n")

    def __init__(self, d, i):
        self.d, self.i, self.b, self.n = d, i, 0, 0

    def bit(self):
        if self.n == 0:
            self.b = self.d[self.i]
            self.i += 1
            self.n = 8
        v = self.b & 1
        self.b >>= 1
        self.n -= 1
        return v

    def bits(self, k):
        v = 0
        for j in range(k):
            v |= self.bit() << j
        return v


def load(path, key=0x69):
    d = open(path, "rb").read()
    return bytes(b ^ key for b in d) if key else d


def kids(c, p):
    l = int.from_bytes(c[p + 4:p + 8], "big")
    q = p + 8
    out = []
    while q < p + l:
        t = c[q:q + 4]
        ll = int.from_bytes(c[q + 4:q + 8], "big")
        out.append((t.decode("latin-1"), q, ll))
        q += ll
    return out


def rooms(c):
    """[(room_number, room_chunk_offset, w, h, nobj, smap or None, apals)]"""
    out = []
    top = kids(c, 0)
    loff = top[0]
    body = c[loff[1] + 8:loff[1] + loff[2]]
    n = body[0]
    numbers = {}
    for i in range(n):
        rn = body[1 + 5 * i]
        off = int.from_bytes(body[2 + 5 * i:6 + 5 * i], "little")
        numbers[off] = rn
    for tag, p, l in top[1:]:
        room = None
        for t2, p2, l2 in kids(c, p):
            if t2 == "ROOM":
                room = p2
        if room is None:
            continue
        # LOFF's offsets point at the ROOM chunk inside the LFLF wrapper, not
        # at the wrapper: 8 + 434 = 442 is the first LFLF and LOFF's first
        # entry is 450, which is 442 + 8. Checked for all 85.
        rn = numbers.get(room, -1)
        rk = {}
        for a, b, cc in kids(c, room):
            rk.setdefault(a, []).append((b, cc))
        hd = rk["RMHD"][0][0]
        w = int.from_bytes(c[hd + 8:hd + 10], "little")
        h = int.from_bytes(c[hd + 10:hd + 12], "little")
        nobj = int.from_bytes(c[hd + 12:hd + 14], "little")
        smap = None
        if "RMIM" in rk:
            for t3, p3, l3 in kids(c, rk["RMIM"][0][0]):
                if t3 == "IM00":
                    for t4, p4, l4 in kids(c, p3):
                        if t4 == "SMAP":
                            smap = (p4, l4)
        apals = []
        for p3, l3 in rk.get("PALS", []):
            for t4, p4, l4 in kids(c, p3):
                if t4 == "WRAP":
                    for t5, p5, l5 in kids(c, p4):
                        if t5 == "APAL":
                            apals.append((p5, l5))
        out.append((rn, room, w, h, nobj, smap, apals))
    return out


def strip_offsets(c, sp, sl, w):
    n = w // 8
    offs = [int.from_bytes(c[sp + 8 + 4 * i:sp + 12 + 4 * i], "little")
            for i in range(n)]
    return offs, [o for o in offs[1:]] + [sl]


def decode_strip(c, a, h, want_end=None):
    """Return (pixels[h][8], end_index, wraps)."""
    code = c[a]
    bpp = code % 10
    if code in LOW:
        band = "low"
        horiz = (0x18 <= code <= 0x1C) or (0x2C <= code <= 0x30)
    elif code in HIGH:
        band, horiz = "high", True
    else:
        return None, a, 0
    br = BitsLSB(c, a + 2)
    color = c[a + 1]
    step = 1
    total = 8 * h
    seq = ([(y, x) for y in range(h) for x in range(8)] if horiz
           else [(y, x) for x in range(8) for y in range(h)])
    out = [[0] * 8 for _ in range(h)]
    idx = 0
    wraps = 0
    while idx < total:
        y, x = seq[idx]
        if color < 0 or color > 255:
            wraps += 1
        out[y][x] = color & 0xFF
        idx += 1
        if idx >= total:
            break
        if br.bit():
            if br.bit():
                if band == "low":
                    if br.bit():
                        step = -step
                    color += step
                else:
                    d = br.bits(3)
                    if d == 4:
                        # The run count INCLUDES the pixel already emitted
                        # at the top of this iteration, so `run - 1` more are
                        # written. Not a guess: with `run` the walk lands
                        # exactly on the strip end for 2,097 strips of 3,359;
                        # with `run - 1` for 3,330; with `run - 2` it reads
                        # past the end on 3,173. One value survives.
                        run = br.bits(8) - 1
                        for _ in range(run):
                            if idx >= total:
                                break
                            y, x = seq[idx]
                            out[y][x] = color & 0xFF
                            idx += 1
                        continue
                    color += d - 4
            else:
                color = br.bits(bpp)
    return out, br.i, wraps


def cmd_strips(path, key):
    c = load(path, key)
    codes = collections.Counter()
    fit = collections.Counter()
    over = 0
    tot = 0
    wraps = 0
    pix = 0
    for rn, room, w, h, nobj, smap, apals in rooms(c):
        if not smap:
            continue
        sp, sl = smap
        offs, ends = strip_offsets(c, sp, sl, w)
        for i, o in enumerate(offs):
            a = sp + o
            end = sp + ends[i]
            px, e, wr = decode_strip(c, a, h)
            tot += 1
            codes[c[a]] += 1
            wraps += wr
            if px is None:
                fit["unknown code"] += 1
                continue
            pix += 8 * h
            d = e - end
            if d > 0:
                over += 1
                fit["OVERSHOOT %d" % d] += 1
            else:
                fit["fits, %d byte(s) of padding" % (-d)] += 1
    print("backgrounds     %d" % sum(1 for r in rooms(c) if r[5]))
    print("strips          %d" % tot)
    print("pixels decoded  %d" % pix)
    print("strips that read past their own end: %d" % over)
    print("colour-index wraps outside 0..255:   %d  (%.6f %% of pixels)"
          % (wraps, 100.0 * wraps / pix if pix else 0))
    print()
    for k, v in sorted(fit.items()):
        print("  %-32s %d" % (k, v))
    print()
    print("strip codes: %s" % dict(sorted(codes.items())))


def cmd_rooms(path, key):
    c = load(path, key)
    rs = rooms(c)
    print("%-5s %6s %6s %6s %6s %8s %6s" %
          ("room", "width", "height", "strips", "objs", "smapsize", "apals"))
    tw = th = 0
    for rn, room, w, h, nobj, smap, apals in rs:
        print("%-5d %6d %6d %6d %6d %8s %6d"
              % (rn, w, h, w // 8, nobj, smap[1] if smap else "-", len(apals)))
        tw += w
        th += h
    print("\n%d rooms, %d objects, %d palettes, widest %d, total pixels %d"
          % (len(rs), sum(r[4] for r in rs), sum(len(r[6]) for r in rs),
             max(r[2] for r in rs), sum(r[2] * r[3] for r in rs)))
    ws = collections.Counter(r[2] for r in rs)
    hs = collections.Counter(r[3] for r in rs)
    print("widths  %s" % dict(sorted(ws.items())))
    print("heights %s" % dict(sorted(hs.items())))


def cmd_pal(path, key):
    c = load(path, key)
    n = 0
    mx = 0
    sizes = collections.Counter()
    greys = 0

    def walk(lo, hi):
        nonlocal n, mx, greys
        p = lo
        while p < hi:
            t = c[p:p + 4]
            l = int.from_bytes(c[p + 4:p + 8], "big")
            if t == b"APAL":
                body = c[p + 8:p + l]
                sizes[len(body)] += 1
                n += 1
                if body:
                    mx = max(mx, max(body))
                    if all(body[3 * i] == body[3 * i + 1] == body[3 * i + 2]
                           for i in range(len(body) // 3)):
                        greys += 1
            elif t in (b"LECF", b"LFLF", b"ROOM", b"PALS", b"WRAP", b"OBIM",
                       b"RMIM", b"OBCD"):
                walk(p + 8, p + l)
            p += l
    walk(0, len(c))
    print("APAL chunks     %d" % n)
    print("payload sizes   %s" % dict(sizes))
    print("entries each    %d" % (768 // 3))
    print("max component   %d  -> %s"
          % (mx, "8-bit values" if mx > 63 else "6-bit VGA DAC values"))
    print("all-grey palettes %d" % greys)


def objects(c, room):
    """[(objid, x, y, w, h, smap_or_None)] from OBIM/IMHD.

    IMHD is 22 bytes of 16-bit little-endian fields. Which field is the width
    was decided by the same closure test as everything else: for each candidate
    field, take `width/8` as the strip count and ask whether the first `SMAP`
    offset equals `8 + 4*strips`. Field 6 (bytes 12-13) wins on 612 object
    images; the next best candidate wins on 83. So the layout is
    `[id][nimages][0][0][x][y][w][h][nhotspots][hx][hy]`.
    """
    out = []
    for t, p, l in kids(c, room):
        if t != "OBIM":
            continue
        ks = kids(c, p)
        hd = [x for x in ks if x[0] == "IMHD"]
        if not hd:
            continue
        b = c[hd[0][1] + 8:hd[0][1] + hd[0][2]]
        f = [int.from_bytes(b[i:i + 2], "little") for i in range(0, 16, 2)]
        sm = None
        ims = [x for x in ks if x[0].startswith("IM0")]
        if ims:
            for y in kids(c, ims[0][1]):
                if y[0] == "SMAP":
                    sm = (y[1], y[2])
        out.append((f[0], f[4], f[5], f[6], f[7], sm))
    return out


def cmd_dump(path, roomno, out, key, with_objects=False):
    c = load(path, key)
    for rn, room, w, h, nobj, smap, apals in rooms(c):
        if rn != roomno:
            continue
        if not smap:
            sys.exit("room %d has no background" % rn)
        sp, sl = smap
        offs, ends = strip_offsets(c, sp, sl, w)
        img = [[0] * w for _ in range(h)]
        for i, o in enumerate(offs):
            px, e, wr = decode_strip(c, sp + o, h)
            for y in range(h):
                for x in range(8):
                    img[y][i * 8 + x] = px[y][x]
        if with_objects:
            trns = 0
            for t2, p2, l2 in kids(c, room):
                if t2 == "TRNS":
                    trns = int.from_bytes(c[p2 + 8:p2 + 10], "little")
            drawn = 0
            for oid, ox, oy, ow, oh, osm in objects(c, room):
                if not osm or ow < 8 or oh < 1:
                    continue
                sp2, sl2 = osm
                offs2, ends2 = strip_offsets(c, sp2, sl2, ow)
                if offs2[0] != 8 + 4 * (ow // 8):
                    continue
                drawn += 1
                for i2, o2 in enumerate(offs2):
                    px2, e2, w2 = decode_strip(c, sp2 + o2, oh)
                    if px2 is None:
                        continue
                    for y in range(oh):
                        for x in range(8):
                            v = px2[y][x]
                            if v == trns:
                                continue
                            X, Y = ox + i2 * 8 + x, oy + y
                            if 0 <= X < w and 0 <= Y < h:
                                img[Y][X] = v
            sys.stderr.write("composited %d object images, transparent index %d"
                             % (drawn, trns) + chr(10))
        pal = b"\0" * 768
        if apals:
            pal = c[apals[0][0] + 8:apals[0][0] + apals[0][1]]
        with open(out, "wb") as f:
            f.write(b"P6\n%d %d\n255\n" % (w, h))
            for y in range(h):
                f.write(bytes(b for x in range(w)
                              for b in pal[3 * img[y][x]:3 * img[y][x] + 3]))
        print("wrote %s  %dx%d" % (out, w, h))
        return
    sys.exit("no room %d" % roomno)


def main(argv):
    key = 0x69
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--key":
            key = int(argv[i + 1], 0); i += 2
        else:
            rest.append(argv[i]); i += 1
    c = rest[0]
    if c == "rooms":
        cmd_rooms(rest[1], key)
    elif c == "strips":
        cmd_strips(rest[1], key)
    elif c == "pal":
        cmd_pal(rest[1], key)
    elif c == "dump":
        cmd_dump(rest[1], int(rest[2]), rest[3], key, "--objects" in argv)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
