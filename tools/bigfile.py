#!/usr/bin/env python3
"""bigfile.py -- /BIGFILE, the movie archive, and the movie format inside it.

/BIGFILE is 188,471,296 bytes, 33.90 % of the bytes in files on this disc, and
the executable names it once, in lower case, as `bigfile`. Beside it in the
same executable are `FMV_Open`, `FMV_DecompressFrame`, `FMV_PadSize = %ld`,
`FMV_Close`, `StartMovie`, `StopMovie`, `ServiceMovie` and `FMV's CCB buffer`.
The disc carries no `FILM`, no `STRM`, no `Cinepak` and no `CVID`: the 3DO Data
Streamer is not on this pressing, and the video is a Crystal Dynamics codec
drawn through a cel control block.

THE ARCHIVE

    +0    u32   136          the total number of members, across this file and
                             its named continuations
    +4    u32[12]            0 and 0x80000000, alternating, six pairs
    +52   (u32 len, u32 off)[131]     one per member held here
    +1104 char[8][5]         'EXTRA.0' .. 'EXTRA.4'
    pad to 2048

The 131 members are contiguous and each begins on a 2,048-byte boundary; the
last ends at 188,470,948, which rounds up to exactly the file's length. The
five names are the continuation files: **`/EXTRA.0`, `/EXTRA.1` and `/EXTRA.2`
are on the disc and `EXTRA.3` and `EXTRA.4` are not.** 131 + 5 = 136 = the word
at offset 0.

A MEMBER

    +0    u32   type         0 on 76 members, 4 on 55
    +4    u32   block width  4
    +8    u32   block height 4
    +12   u32   dictionary size, in blocks
    +16   u32   2            bytes per pixel
    +20   ...   the stream

The stream is one grammar throughout, read as 16-bit big-endian words:

    0xFFFF  <u16 id> <32 bytes>    define dictionary entry `id`
    0x0000                         this cell is unchanged
    0xFFFD                         this cell is unchanged (a second such code)
    else    <u16 id>               draw dictionary entry `id` in this cell

Cells are walked in raster order across a grid whose size comes from a
twelve-byte frame header after the opening run of definitions: on every member
measured it is `1, 32, 24`, so the picture is **32 x 24 blocks of 4 x 4 pixels
= 128 x 96**, and frames follow one another with no further header.

The 32 bytes of a block are sixteen 16-bit pixels, 5-5-5 with the top bit
always clear -- the same pixel as every other image on this disc -- laid out in
a **boustrophedon**: row 0 left to right, row 1 right to left, row 2 left to
right, row 3 right to left. That was not guessed. Taking the 2,400 blocks of
one member's opening run and measuring, for all 120 pairs of positions, the
mean colour distance between them, the sixteen closest pairs are the chain
0-1, 1-2, ... 14-15 **plus exactly (0,7), (1,6), (2,5), (3,4), (7,8), (4,11),
(11,12), (8,15)** -- which are the eight vertical neighbours a serpentine scan
produces and no other order does.

WHAT IS NOT DERIVED

The parse closes: on member 76 the grammar consumes 1,135,704 bytes of
1,135,704, in 20 + 26,067 x 36 + 12 + 98,630 x 2, and a definition payload of
32 bytes is the only length in 24..64 for which the file parses at all. The
first frame of a member decodes to a picture a person recognises. Later frames
degrade, so **something in the per-frame stream is still wrong** -- most likely
the meaning of 0x0000 and 0xFFFD, which are treated here as "unchanged" and
which cannot both mean that. This tool is published as a partial decoder and
says so; see docs/09.

    python tools/bigfile.py FILE --members
    python tools/bigfile.py FILE --member 76 --info
    python tools/bigfile.py FILE --member 76 --png OUT --frames 1
"""
import argparse
import os
import struct

FFFF = 0xFFFF
SKIP = (0x0000, 0xFFFD)


def members(path):
    fh = open(path, "rb")
    hdr = fh.read(2048)
    total = struct.unpack_from(">I", hdr, 0)[0]
    out = []
    o = 52
    size = os.path.getsize(path)
    last = -1
    while o + 8 <= 2048:
        raw = hdr[o:o + 8]
        # the member table is followed by the continuation names, which are
        # printable; that, not a zero length, is where it ends. Member 32 of
        # this disc's BIGFILE is a real record with length 0.
        if raw[0] and all(32 <= c < 127 for c in raw.rstrip(bytes(1))):
            break
        ln, off = struct.unpack_from(">II", hdr, o)
        if off < last or off >= size:
            break
        out.append((off, ln))
        last = off
        o += 8
    # between the member table and the names sits one u32 giving the length of
    # the name table: 40 = 5 x 8 on this disc. Step over anything that is not
    # a name until the names begin.
    names = []
    namelen = None
    while o + 8 <= 2048:
        n = hdr[o:o + 8].split(bytes(1))[0]
        if n and all(32 <= c < 127 for c in n):
            names.append(n.decode("latin-1"))
            o += 8
        elif names:
            break
        else:
            namelen = struct.unpack_from(">I", hdr, o)[0]
            o += 4
            if o > 1200:
                break
    fh.close()
    return total, out, names


def blockpos(j):
    """The boustrophedon: row 0 left to right, row 1 right to left, ..."""
    r, c = j // 4, j % 4
    return (c if r % 2 == 0 else 3 - c, r)


def rgb555(v):
    return (((v >> 10) & 31) * 255 // 31, ((v >> 5) & 31) * 255 // 31,
            (v & 31) * 255 // 31)


class NotVideo(Exception):
    """Raised for a member whose header is not the type-0 video header.

    53 of the 131 members open with the word 4 rather than 0, and their second
    word is 22052 or 33080 rather than a block width of 4. Their format is not
    derived; see docs/07. This guard exists because without it the video
    parser reads a grid size out of their bytes and walks off the end."""


def decode(data, want=None, png=None):
    typ, bw, bh, ndict, bpp = struct.unpack_from(">IIIII", data, 0)
    if typ != 0 or bw != 4 or bh != 4 or bpp != 2:
        raise NotVideo("header (%d, %d, %d, %d, %d) is not the video header"
                       % (typ, bw, bh, ndict, bpp))
    o = 20
    dic = {}
    pre = 0
    while data[o:o + 2] == b"\xff\xff":
        dic[struct.unpack_from(">H", data, o + 2)[0]] = data[o + 4:o + 36]
        o += 36
        pre += 1
    n, w, h = struct.unpack_from(">III", data, o)
    o += 12
    img = None
    if png:
        from PIL import Image
        img = Image.new("RGB", (w * bw, h * bh))
        px = img.load()
    frames = 0
    ndefs = pre
    nmap = 0
    while o + 2 <= len(data):
        c = 0
        while c < w * h and o + 2 <= len(data):
            v = struct.unpack_from(">H", data, o)[0]
            if v == FFFF:
                if o + 36 > len(data):
                    break
                dic[struct.unpack_from(">H", data, o + 2)[0]] = data[o + 4:o + 36]
                o += 36
                ndefs += 1
                continue
            o += 2
            nmap += 1
            if img is not None and v not in SKIP:
                b = dic.get(v)
                if b is not None:
                    bx, by = (c % w) * bw, (c // w) * bh
                    for j in range(bw * bh):
                        dx, dy = blockpos(j)
                        px[bx + dx, by + dy] = rgb555(
                            struct.unpack_from(">H", b, j * 2)[0])
            c += 1
        if c < w * h:
            break
        frames += 1
        if want and frames >= want:
            break
    return {"type": typ, "bw": bw, "bh": bh, "ndict": ndict, "bpp": bpp,
            "grid": (w, h), "frames": frames, "preamble": pre,
            "defs": ndefs, "map": nmap, "consumed": o, "size": len(data),
            "dict": len(dic), "image": img}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--members", action="store_true")
    ap.add_argument("--member", type=int)
    ap.add_argument("--info", action="store_true")
    ap.add_argument("--frames", type=int, default=1)
    ap.add_argument("--png")
    a = ap.parse_args()

    total, ms, names = members(a.file)
    print("%s: %d bytes" % (a.file, os.path.getsize(a.file)))
    print("members declared at offset 0 : %d" % total)
    print("member records in this file  : %d" % len(ms))
    print("continuation names           : %s" % ", ".join(names))
    print("zero-length members          : %d" % sum(1 for _, l in ms if l == 0))
    end = ms[-1][0] + ms[-1][1]
    print("last member ends at %d, rounded up to %d, file is %d"
          % (end, (end + 2047) // 2048 * 2048, os.path.getsize(a.file)))
    print("sum of member lengths        : %d = %.4f %% of the file"
          % (sum(l for _, l in ms),
             100.0 * sum(l for _, l in ms) / os.path.getsize(a.file)))
    gaps = sum(1 for i in range(len(ms) - 1)
               if (ms[i][0] + ms[i][1] + 2047) // 2048 * 2048 == ms[i + 1][0])
    print("contiguous, 2048-aligned     : %d of %d transitions"
          % (gaps, len(ms) - 1))

    if a.members:
        fh = open(a.file, "rb")
        print("\n%4s %12s %12s %6s %s" % ("n", "offset", "length", "type",
                                          "first 8 bytes"))
        for i, (off, ln) in enumerate(ms):
            fh.seek(off)
            b = fh.read(20)
            print("%4d %12d %12d %6d %s"
                  % (i, off, ln, struct.unpack_from(">I", b, 0)[0],
                     " ".join("%02x" % c for c in b[:8])))
        fh.close()

    if a.member is not None:
        off, ln = ms[a.member]
        fh = open(a.file, "rb")
        fh.seek(off)
        data = fh.read(ln)
        fh.close()
        r = decode(data, want=a.frames if a.png else None, png=a.png)
        print("\nmember %d: type %d, block %dx%d, dictionary %d, %d bytes/pixel"
              % (a.member, r["type"], r["bw"], r["bh"], r["ndict"], r["bpp"]))
        print("  grid            : %d x %d blocks = %d x %d pixels"
              % (r["grid"][0], r["grid"][1], r["grid"][0] * r["bw"],
                 r["grid"][1] * r["bh"]))
        print("  frames          : %d" % r["frames"])
        print("  opening defs    : %d" % r["preamble"])
        print("  definitions     : %d (distinct ids %d, declared %d)"
              % (r["defs"], r["dict"], r["ndict"]))
        print("  map entries     : %d" % r["map"])
        print("  bytes           : 20 + %d*36 + 12 + %d*2 = %d, member is %d"
              % (r["defs"], r["map"], 20 + r["defs"] * 36 + 12 + r["map"] * 2,
                 r["size"]))
        if r["image"]:
            r["image"].save(a.png)
            print("  wrote %s" % a.png)


if __name__ == "__main__":
    main()
