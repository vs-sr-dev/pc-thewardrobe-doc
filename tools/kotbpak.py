#!/usr/bin/env python3
"""kotbpak.py -- read the `.PAK` container of Kings of the Beach, derived from
the bytes of the object and from nothing else.

**This format is not public and no published definition was used.** Everything
below was derived from the 36 samples on the object plus one negative result
taken from the program itself, and the derivation is written out here because
the first four bytes invite exactly the wrong reading.

THE WRONG READING, WHICH IS THE OBVIOUS ONE

Every one of the 36 files begins `0x82`, and no other file on the object does.
That looks like a magic number, and the pre-briefing for this session wrote it
down as one: "all 36 begin with the byte 0x82", with bytes 1 and 2 as a
geometry and byte 3 unidentified over twelve values.

The geometry is real. The magic number is not, and the object says so:

    python -c "..."   # count CD-style compares of 0x82 in the unpacked overlays
    80 3E xx xx 82  (cmp byte ptr [abs],82h) : 0    expected by chance 0.0000
    80 7E xx    82  (cmp byte ptr [bp+d],82h): 0    expected by chance 0.0121

**The program never compares anything to 0x82.** On 204,704 bytes a four-byte
needle has a chance rate of 0.0000, so that zero is evidence rather than an
absence of evidence -- which is the inversion this object gets for free by
being half a megabyte instead of a quarter of a gigabyte.

`0x82` is not a signature. It is the first *command byte* of the compressed
stream, and it means "copy the next 2 bytes literally". Those 2 bytes are the
width and the height. **The geometry is not in a header; it is the first two
bytes of the decompressed output**, and byte 3 is simply the second command.
That is why byte 3 took twelve values and resisted identification: it was never
a field.

THE FORMAT

The whole file is one run-length stream starting at offset 0:

    c = data[i]; i += 1
    c <  0x80 : RUN     -- emit data[i] `c` times;  i += 1
    c >= 0x80 : LITERAL -- emit the next (c & 0x7F) bytes;  i += c & 0x7F

`c == 0x00` (a run of nothing) and `c == 0x80` (a literal of nothing) are both
no-ops and **neither occurs as a command in any of the 36 files**, which is the
check that the polarity is the right way round: the opposite reading makes
0x00 and 0x80 the two commonest commands on the object.

**The last two bytes of the file are a footer and not part of the stream**: a
little-endian u16 holding the exact decompressed length. That closes on 36 of
36 files, and it is the check the format carries about itself.

The decompressed stream is:

    [0]      width in bytes   (x8 for pixels)
    [1]      height in rows
    [2..]    width x rows x 4 bytes of EGA planar data, FOUR PLANES
             INTERLEAVED PER ROW: row 0 plane 0, row 0 plane 1, row 0 plane 2,
             row 0 plane 3, row 1 plane 0, ...

Plane p carries bit p of the colour index, plane 0 least significant. The
interleave was settled by rendering, not by arithmetic: both the row-interleaved
and the four-sequential-planes readings consume exactly the same number of
bytes and only one of them draws a beach.

THE FOUR SHORT ONES, WHICH THE FOOTER EXPLAINS

Four of the five court backdrops -- AUSCOURT, CHICOURT, HACOURT, SDCOURT --
declare a 320 x 200 geometry and a footer of 13,602, where a full screen's
footer is 32,002. 13,602 = 2 + 40 x **85** x 4, so they carry exactly 85 rows
of a 200-row screen, all four of them, and the rendered result is a complete
picture of the top of the screen that stops part-way down: a horizon, a crowd
and a row of sponsor banners, with the sand the game draws itself left out.

Without the footer this looked like four files that failed to close. With it
they close on their own declared length like the other thirty-two, and the
`rows` column says 85 instead of 200. RIOCOURT, the fifth court, is a full
screen and is the control that says the shortfall is a property of those four
files and not of the class.

    python tools/kotbpak.py --census kings
    python tools/kotbpak.py --validate kings/TITLE.PAK
    python tools/kotbpak.py --refuse kings/VBALL.EXE kings/MISC.DAT
    python tools/kotbpak.py kings/TITLE.PAK --render out.png [--scale 3]

Standard library only. It reads the object and writes only where told to, and
it never executes anything.
"""
import argparse
import glob
import os
import struct
import sys
import zlib

# The IBM EGA 16-colour text/graphics default. The game may program its own
# palette from inside the overlay; nothing in a `.PAK` file selects a colour,
# so this is a stated assumption and not a measurement. Any chapter that shows
# a rendering has to say so.
EGA_DEFAULT = [
    (0, 0, 0), (0, 0, 170), (0, 170, 0), (0, 170, 170),
    (170, 0, 0), (170, 0, 170), (170, 85, 0), (170, 170, 170),
    (85, 85, 85), (85, 85, 255), (85, 255, 85), (85, 255, 255),
    (255, 85, 85), (255, 85, 255), (255, 255, 85), (255, 255, 255),
]


class NotPak(Exception):
    pass


def decompress(data, stop=None):
    """Run the stream. Raises on any command that cannot be completed, which
    is what makes --refuse mean something.

    `stop` is an output-length cap, kept because it is what the first version
    of this reader needed before the footer was understood. It is not used by
    `read()` any more and it is left here on purpose: with the footer, nothing
    has to guess where the stream ends, and a reader that has to guess is the
    reader that reported twenty perfectly good files as `NOT A PAK`."""
    out = bytearray()
    i = 0
    n = len(data)
    runs = literals = 0
    nops = 0
    while i < n:
        if stop is not None and len(out) >= stop:
            break
        c = data[i]
        i += 1
        if c == 0x00 or c == 0x80:
            nops += 1
        if c < 0x80:
            if i >= n:
                raise NotPak("run command 0x%02X at %d has no byte after it"
                             % (c, i - 1))
            out += bytes([data[i]]) * c
            i += 1
            runs += 1
        else:
            k = c & 0x7F
            if i + k > n:
                raise NotPak("literal of %d at %d runs %d bytes past the end"
                             % (k, i - 1, i + k - n))
            out += data[i:i + k]
            i += k
            literals += 1
        if len(out) > 4 * 1024 * 1024:
            raise NotPak("stream does not terminate inside 4 MB")
    return bytes(out), {"runs": runs, "literals": literals, "nops": nops,
                        "consumed": i}


def read(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 4:
        raise NotPak("%d bytes is too short to be a stream" % len(data))
    # THE FOOTER. The last two bytes of the file are a little-endian u16
    # holding the exact decompressed length, and they are NOT part of the
    # stream. That closes on 36 of 36 files, and it is what turns the four
    # short court backdrops from an unexplained failure into a measurement:
    # they declare 13,602 = 2 + 40 x 85 x 4 and deliver exactly that. They
    # encode 85 rows of a 200-row screen and say so themselves.
    declared = struct.unpack_from("<H", data, len(data) - 2)[0]
    img, st = decompress(data[:-2])
    if len(img) != declared:
        raise NotPak("footer declares %d decompressed bytes, stream produced "
                     "%d" % (declared, len(img)))
    if len(img) < 2:
        raise NotPak("the stream does not produce two bytes of geometry")
    w, h = img[0], img[1]
    if not (1 <= w <= 80) or not (1 <= h <= 200):
        raise NotPak("decompressed geometry %d x %d is not a screen" % (w, h))
    need = w * h * 4
    body = img[2:2 + need]
    rows = (len(img) - 2) // (w * 4)
    st.update({"w": w, "h": h, "need": need, "got": len(img) - 2,
               "declared": declared, "rows": rows,
               "short": max(0, need - len(body)),
               "file_bytes": len(data)})
    return body, st


def png(path, w, h, rgb):
    raw = b"".join(b"\x00" + bytes(rgb[y * w * 3:(y + 1) * w * 3])
                   for y in range(h))

    def chunk(tag, payload):
        body = tag + payload
        return (struct.pack(">I", len(payload)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n"
                 + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                 + chunk(b"IDAT", zlib.compress(raw, 9))
                 + chunk(b"IEND", b""))


def render(body, w, h, path, scale=1):
    need = w * h * 4
    buf = bytearray(body) + bytes(need - len(body))
    W, H = w * 8 * scale, h * scale
    rgb = bytearray(W * H * 3)
    for y in range(h):
        base = y * 4 * w
        for xb in range(w):
            p0, p1, p2, p3 = (buf[base + xb], buf[base + w + xb],
                              buf[base + 2 * w + xb], buf[base + 3 * w + xb])
            for bit in range(8):
                m = 0x80 >> bit
                v = ((p0 & m) and 1) | ((p1 & m) and 2) | \
                    ((p2 & m) and 4) | ((p3 & m) and 8)
                r, g, b = EGA_DEFAULT[v]
                x = xb * 8 + bit
                for sy in range(scale):
                    row = (y * scale + sy) * W
                    for sx in range(scale):
                        k = (row + x * scale + sx) * 3
                        rgb[k] = r
                        rgb[k + 1] = g
                        rgb[k + 2] = b
    png(path, W, H, rgb)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--refuse", action="store_true",
                    help="assert none of the inputs is a PAK; exit 1 if one is")
    ap.add_argument("--render", metavar="OUT")
    ap.add_argument("--scale", type=int, default=1)
    args = ap.parse_args(argv)

    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.PAK")))
        else:
            files.append(p)
    if not files:
        raise SystemExit("kotbpak.py: no input files")

    if args.refuse:
        bad = 0
        for p in files:
            try:
                read(p)
            except NotPak as e:
                print("%-16s REFUSED: %s" % (os.path.basename(p), e))
            except Exception as e:
                print("%-16s REFUSED (%s): %s"
                      % (os.path.basename(p), type(e).__name__, e))
            else:
                print("%-16s DECODES -- CONTROL FAILED" % os.path.basename(p))
                bad += 1
        print("\nkotbpak.py: %d of %d refused" % (len(files) - bad, len(files)))
        return 1 if bad else 0

    if args.render:
        if len(files) != 1:
            raise SystemExit("kotbpak.py: --render takes exactly one input")
        body, st = read(files[0])
        render(body, st["w"], st["h"], args.render, args.scale)
        print("%s  %dx%d px  short %d  -> %s"
              % (os.path.basename(files[0]), st["w"] * 8, st["h"],
                 st["short"], args.render))
        return 0

    ok = short = 0
    tot_file = tot_img = 0
    print("%-16s %7s %5s %6s %9s %8s %5s %6s %6s %6s"
          % ("file", "bytes", "w", "h", "footer", "needed", "rows",
             "short", "runs", "lits"))
    for p in files:
        try:
            body, st = read(p)
        except NotPak as e:
            print("%-16s NOT A PAK: %s" % (os.path.basename(p), e))
            continue
        tot_file += st["file_bytes"]
        tot_img += st["need"]
        if st["short"]:
            short += 1
        else:
            ok += 1
        print("%-16s %7d %5d %6d %9d %8d %5d %6d %6d %6d"
              % (os.path.basename(p), st["file_bytes"], st["w"] * 8, st["h"],
                 st["declared"], st["need"] + 2, st["rows"], st["short"],
                 st["runs"], st["literals"]))
    print()
    print("files                       : %d" % len(files))
    print("complete rasters            : %d" % ok)
    print("short of their geometry     : %d" % short)
    print("bytes on disc / raster bytes: %d / %d   ratio %.4f"
          % (tot_file, tot_img, (tot_img / tot_file) if tot_file else 0))
    print("footer closed on the stream : %d of %d" % (ok + short, len(files)))
    if args.validate and short:
        print("VALIDATE FAILED: %d files do not fill their declared geometry"
              % short)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
