#!/usr/bin/env python3
"""bfflic.py -- read the seventeen animation files of Theme Park.

They declare Autodesk's FLC magic `0xAF12` at offset 4 and Autodesk's frame
magic `0xF1FA` at offset 16, and the `u32` at offset 0 -- which in an Autodesk
FLC is the file's own length -- reads **12** on all seventeen. Twelve is not the
size of an eighteen-megabyte file.

Twelve is the size of the HEADER. These files carry the first twelve bytes of a
128-byte FLC header:

    +0   u32   12       the header length, i.e. the offset of the first frame
    +4   u16   0xAF12   Autodesk Animator Pro FLC magic
    +6   u16   frames   frame count, EXCLUDING the ring frame
    +8   u16   320      width
    +10  u16   200      height

and then the FLIC frame chain immediately, at offset 12 instead of at offset
128. Autodesk's `speed`, `flags`, `oframe1`, `oframe2` and the rest of the
128-byte header are simply not there. The frames themselves are ordinary FLIC:
a 16-byte frame header (`u32` size, `u16` 0xF1FA, `u16` chunk count, 8 bytes
reserved) followed by chunks with a `u32` size and a `u16` type.

That reading is not asserted, it is closed: walking the chunk sums from offset
12 lands exactly on the end of the file on **17 of 17** files, 145,695,310
bytes, residue 0 on every one.

One field is genuinely broken, and only one. **The size field of frame 0 is too
large on 17 of 17 files**, by 208 to 3,734 bytes, while the size field of the
other 5,842 frames is exact. So this reader walks by summing chunk lengths and
reports the frame-header size as a cross-check rather than trusting it -- which
is the only way it can close at all.

The FLIC chunk vocabulary is Autodesk's and public; the types this object uses
are 4 (`COLOR_256`), 7 (`DELTA_FLC`, word-oriented delta), 11 (`COLOR_64`),
12 (`DELTA_FLI`, byte-oriented delta), 13 (`BLACK`), 15 (`BYTE_RUN`, a
run-length coded full frame) and 16 (`LITERAL`, an uncompressed full frame).
The 12-byte header is NOT public and is derived here.

    python tools/bfflic.py validate <file>              header and first frame
    python tools/bfflic.py census   <dir-or-files...>   the closure table
    python tools/bfflic.py frames   <file> [n]          the frame table
    python tools/bfflic.py render   <file> <n> <out.png>  decode frame n
    python tools/bfflic.py selftest                     built specimens
"""
import os
import struct
import sys
import zlib

MAGIC = 0xAF12
FRAME_MAGIC = 0xF1FA
HDR_LEN = 12

CHUNK_NAMES = {
    3: "COLOR_64?",
    4: "COLOR_256",
    7: "DELTA_FLC",
    11: "COLOR_64",
    12: "DELTA_FLI",
    13: "BLACK",
    15: "BYTE_RUN",
    16: "LITERAL",
    18: "PSTAMP",
}


class Refused(Exception):
    """The file is not one of these. Raised loudly and never swallowed."""


def header(d):
    """The twelve bytes, checked. Refuses before it reads anything else."""
    if len(d) < HDR_LEN + 16:
        raise Refused("shorter than a header plus one frame header")
    hdr, magic, frames, w, h = struct.unpack_from("<IHHHH", d, 0)
    if magic != MAGIC:
        raise Refused("magic at offset 4 is 0x%04X, not 0x%04X" % (magic, MAGIC))
    if hdr != HDR_LEN:
        raise Refused("header length at offset 0 is %d, not %d" % (hdr, HDR_LEN))
    if struct.unpack_from("<H", d, hdr + 4)[0] != FRAME_MAGIC:
        raise Refused("no 0x%04X frame magic at offset %d" % (FRAME_MAGIC, hdr + 4))
    if not (0 < w <= 4096 and 0 < h <= 4096):
        raise Refused("implausible dimensions %dx%d" % (w, h))
    return {"hdr": hdr, "magic": magic, "frames": frames, "w": w, "h": h}


def walk(d):
    """Every frame, by summing chunk lengths. Returns (frames, residue).

    A frame is (offset, declared_size, true_size, chunk_count, [(type, size)]).
    """
    h = header(d)
    p = h["hdr"]
    out = []
    while p + 16 <= len(d):
        size, magic, nchunks = struct.unpack_from("<IHH", d, p)
        if magic != FRAME_MAGIC:
            raise Refused("frame %d at %d has magic 0x%04X" % (len(out), p, magic))
        q = p + 16
        chunks = []
        for _ in range(nchunks):
            if q + 6 > len(d):
                raise Refused("chunk header past end at %d" % q)
            csize, ctype = struct.unpack_from("<IH", d, q)
            if csize < 6 or q + csize > len(d):
                raise Refused("chunk of %d bytes at %d does not fit" % (csize, q))
            chunks.append((ctype, csize))
            q += csize
        out.append((p, size, q - p, nchunks, chunks))
        p = q
    return h, out, len(d) - p


# --- the decoder, which is Autodesk's published chunk vocabulary ------------

def _color256(buf, pal, wide):
    """COLOR_256 (6-bit when `wide` is False, i.e. COLOR_64)."""
    npk = struct.unpack_from("<H", buf, 0)[0]
    p = 2
    idx = 0
    for _ in range(npk):
        idx += buf[p]
        count = buf[p + 1]
        if count == 0:
            count = 256
        p += 2
        for _ in range(count):
            r, g, b = buf[p], buf[p + 1], buf[p + 2]
            if not wide:
                r, g, b = r * 255 // 63, g * 255 // 63, b * 255 // 63
            pal[idx] = (r, g, b)
            idx += 1
            p += 3


def _byte_run(buf, img, w, h):
    """BYTE_RUN: one run-length coded line at a time, whole frame."""
    p = 0
    for y in range(h):
        p += 1                      # the packet count byte, ignored in FLC
        x = 0
        while x < w:
            n = buf[p]
            p += 1
            if n & 0x80:            # signed negative: n literal pixels
                n = 256 - n
                img[y * w + x:y * w + x + n] = buf[p:p + n]
                p += n
            else:
                img[y * w + x:y * w + x + n] = bytes([buf[p]]) * n
                p += 1
            x += n


def _literal(buf, img, w, h):
    img[0:w * h] = buf[0:w * h]


def _delta_fli(buf, img, w, h):
    """DELTA_FLI (type 12): byte-oriented, a starting line and a line count."""
    y, nlines = struct.unpack_from("<HH", buf, 0)
    p = 4
    for _ in range(nlines):
        npk = buf[p]
        p += 1
        x = 0
        for _ in range(npk):
            x += buf[p]
            n = buf[p + 1]
            p += 2
            if n & 0x80:
                n = 256 - n
                img[y * w + x:y * w + x + n] = bytes([buf[p]]) * n
                p += 1
            else:
                img[y * w + x:y * w + x + n] = buf[p:p + n]
                p += n
            x += n
        y += 1


def _delta_flc(buf, img, w, h):
    """DELTA_FLC (type 7): word-oriented, with the skip/last-byte opcodes."""
    nlines = struct.unpack_from("<H", buf, 0)[0]
    p = 2
    y = 0
    for _ in range(nlines):
        while True:
            op = struct.unpack_from("<H", buf, p)[0]
            p += 2
            if op & 0xC000 == 0xC000:      # line skip count (negative)
                y += 65536 - op
            elif op & 0xC000 == 0x8000:    # last byte of the line
                img[y * w + w - 1] = op & 0xFF
            else:
                npk = op
                x = 0
                for _ in range(npk):
                    x += buf[p]
                    n = struct.unpack_from("<b", buf, p + 1)[0]
                    p += 2
                    if n >= 0:
                        img[y * w + x:y * w + x + n * 2] = buf[p:p + n * 2]
                        p += n * 2
                        x += n * 2
                    else:
                        n = -n
                        img[y * w + x:y * w + x + n * 2] = buf[p:p + 2] * n
                        p += 2
                        x += n * 2
                y += 1
                break


def decode(d, upto):
    """Decode frames 0..upto inclusive. Returns (image bytes, palette)."""
    h, frames, residue = walk(d)
    w, ht = h["w"], h["h"]
    img = bytearray(w * ht)
    pal = [(0, 0, 0)] * 256
    for i, (off, decl, true, n, chunks) in enumerate(frames):
        if i > upto:
            break
        q = off + 16
        for ctype, csize in chunks:
            buf = d[q + 6:q + csize]
            if ctype == 4:
                _color256(buf, pal, True)
            elif ctype == 11:
                _color256(buf, pal, False)
            elif ctype == 15:
                _byte_run(buf, img, w, ht)
            elif ctype == 16:
                _literal(buf, img, w, ht)
            elif ctype == 12:
                _delta_fli(buf, img, w, ht)
            elif ctype == 7:
                _delta_flc(buf, img, w, ht)
            elif ctype == 13:
                img = bytearray(w * ht)
            q += csize
    return img, pal, h


def write_png(path, img, pal, w, h):
    """An 8-bit palette PNG, written without a library."""
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))
    raw = b"".join(b"\0" + bytes(img[y * w:(y + 1) * w]) for y in range(h))
    plte = b"".join(bytes(c) for c in pal)
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
           + chunk(b"PLTE", plte)
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    open(path, "wb").write(png)


# --- the commands ----------------------------------------------------------

def cmd_validate(path):
    d = open(path, "rb").read()
    try:
        h = header(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    size, magic, nchunks = struct.unpack_from("<IHH", d, h["hdr"])
    print("%s  %d bytes" % (os.path.basename(path), len(d)))
    print("  header length   %d   (the offset of frame 0)" % h["hdr"])
    print("  magic           0x%04X" % h["magic"])
    print("  frames declared %d   (the ring frame is not counted)" % h["frames"])
    print("  dimensions      %d x %d" % (h["w"], h["h"]))
    print("  frame 0         declares %d bytes, %d chunks" % (size, nchunks))
    return 0


def cmd_frames(path, limit=None):
    d = open(path, "rb").read()
    h, frames, residue = walk(d)
    print("%s  %d bytes, %d x %d, %d declared, %d walked"
          % (os.path.basename(path), len(d), h["w"], h["h"],
             h["frames"], len(frames)))
    print("%6s %10s %10s %10s %8s  %s"
          % ("frame", "offset", "declared", "true", "delta", "chunks"))
    for i, (off, decl, true, n, chunks) in enumerate(frames):
        if limit and i >= limit:
            print("  ... %d more" % (len(frames) - limit))
            break
        cs = " ".join("%s/%d" % (CHUNK_NAMES.get(t, str(t)), s) for t, s in chunks)
        print("%6d %10d %10d %10d %8d  %s"
              % (i, off, decl, true, decl - true, cs))
    print("residue after the last frame: %d" % residue)
    return 0


def cmd_census(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    files.append(os.path.join(root, n))
        else:
            files.append(p)
    print("%-16s %10s %6s %6s %8s %8s %s"
          % ("file", "bytes", "decl", "walk", "residue", "bad size", "chunk types"))
    ok = bad = refused = 0
    tot = 0
    allchunks = {}
    for f in files:
        d = open(f, "rb").read()
        try:
            h, frames, residue = walk(d)
        except Refused as e:
            refused += 1
            continue
        counts = {}
        badsz = 0
        for off, decl, true, n, chunks in frames:
            if decl != true:
                badsz += 1
            for t, s in chunks:
                counts[t] = counts.get(t, 0) + 1
                allchunks[t] = allchunks.get(t, 0) + 1
        tot += len(d)
        if residue == 0:
            ok += 1
        else:
            bad += 1
        print("%-16s %10d %6d %6d %8d %8d %s"
              % (os.path.basename(f), len(d), h["frames"], len(frames),
                 residue, badsz,
                 " ".join("%s:%d" % (CHUNK_NAMES.get(t, t), c)
                          for t, c in sorted(counts.items()))))
    print()
    print("accepted %d, refused %d, closing with residue 0: %d of %d"
          % (ok + bad, refused, ok, ok + bad))
    print("bytes accounted: %d" % tot)
    print("chunk types over the whole population: %s"
          % " ".join("%s:%d" % (CHUNK_NAMES.get(t, t), c)
                     for t, c in sorted(allchunks.items())))
    return 0 if bad == 0 and ok else 3


def _specimen(hdr=12, magic=MAGIC, frames=1, w=320, h=200, framebody=None):
    body = framebody if framebody is not None else b""
    return struct.pack("<IHHHH", hdr, magic, frames, w, h) + body


def _one_frame(chunks):
    body = b"".join(struct.pack("<IH", len(c) + 6, t) + c for t, c in chunks)
    return struct.pack("<IHH", len(body) + 16, FRAME_MAGIC, len(chunks)) + b"\0" * 8 + body


def cmd_selftest():
    """Mostly rejections -- but not only rejections, which is the point.

    A selftest made of refusals alone passed a reader that read the wrong
    field, one session ago. So three of these specimens must be ACCEPTED and
    one of the three must decode to a known image.
    """
    cases = []
    # 1. a real, minimal, correct file: one BYTE_RUN frame of a known colour
    brun = b""
    for _ in range(200):
        # four packets of 80 pixels of colour 7. A run count is a SIGNED byte,
        # so 80 is a run and 255 would be a one-byte literal -- the first draft
        # of this specimen used 255 and the decoder ran off the end, which is
        # the positive control catching the test rather than the reader.
        brun += bytes([4, 80, 7, 80, 7, 80, 7, 80, 7])
    pal = struct.pack("<H", 1) + bytes([0, 0]) + bytes([63, 0, 0] * 256)
    good = _specimen(framebody=_one_frame([(11, pal), (15, brun)]))
    cases.append(("a minimal correct file, one BYTE_RUN frame", good, True))
    # 2. it decodes to colour 7 everywhere, and the palette is scaled from 6 bit
    # 3. wrong magic
    cases.append(("magic 0xAF11 (an FLI, not an FLC)",
                  _specimen(magic=0xAF11, framebody=_one_frame([(13, b"")])), False))
    # 4. an Autodesk FLC with the real 128-byte header
    real = struct.pack("<IHHHH", 100000, MAGIC, 1, 320, 200) + b"\0" * 116
    cases.append(("a genuine 128-byte-header Autodesk FLC", real, False))
    # 5. header length not 12
    cases.append(("header length 128",
                  _specimen(hdr=128, framebody=b"\0" * 116 + _one_frame([(13, b"")])),
                  False))
    # 6. no frame magic where the header says the frames start
    cases.append(("frame magic absent at offset 12",
                  _specimen(framebody=b"\0" * 64), False))
    # 7. truncated to the header alone
    cases.append(("the twelve header bytes and nothing else",
                  struct.pack("<IHHHH", 12, MAGIC, 1, 320, 200), False))
    # 8. a chunk that runs past the end
    bad = _specimen(framebody=struct.pack("<IHH", 40, FRAME_MAGIC, 1)
                    + b"\0" * 8 + struct.pack("<IH", 1 << 20, 15))
    cases.append(("a chunk declaring a megabyte inside 40 bytes", bad, False))
    # 9. implausible dimensions
    cases.append(("dimensions 0x0",
                  _specimen(w=0, h=0, framebody=_one_frame([(13, b"")])), False))
    # 10. a second acceptance: a BLACK frame, legal and empty
    cases.append(("a legal file whose only frame is BLACK",
                  _specimen(framebody=_one_frame([(13, b"")])), True))

    fails = 0
    for name, data, should_accept in cases:
        try:
            walk(data)
            got = True
            why = ""
        except Refused as e:
            got = False
            why = str(e)
        mark = "ok " if got == should_accept else "FAIL"
        if got != should_accept:
            fails += 1
        print("%s  %-46s expected %-8s got %-8s %s"
              % (mark, name, "accept" if should_accept else "refuse",
                 "accept" if got else "refuse", why))
    # the positive control that has to produce a picture, not just an accept
    img, pal, h = decode(cases[0][1], 0)
    solid = set(img)
    ok = solid == {7} and pal[0] == (255, 0, 0) and len(img) == 64000
    print("%s  %-46s %s"
          % ("ok " if ok else "FAIL",
             "the accepted file decodes to one known colour",
             "64,000 bytes of index 7, palette[0] = (255,0,0)" if ok
             else "decoded %d bytes, values %s, palette[0] %s"
                  % (len(img), sorted(solid)[:4], pal[0])))
    if not ok:
        fails += 1
    print()
    print("%d specimens, %d must be accepted, %d failures"
          % (len(cases) + 1, sum(1 for c in cases if c[2]) + 1, fails))
    return 1 if fails else 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "validate":
        return cmd_validate(rest[0])
    if cmd == "census":
        return cmd_census(rest)
    if cmd == "frames":
        return cmd_frames(rest[0], int(rest[1]) if len(rest) > 1 else None)
    if cmd == "render":
        d = open(rest[0], "rb").read()
        n = int(rest[1])
        img, pal, h = decode(d, n)
        write_png(rest[2], img, pal, h["w"], h["h"])
        print("frame %d of %s -> %s (%dx%d)"
              % (n, os.path.basename(rest[0]), rest[2], h["w"], h["h"]))
        return 0
    if cmd == "selftest":
        return cmd_selftest()
    print("unknown command %r" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
