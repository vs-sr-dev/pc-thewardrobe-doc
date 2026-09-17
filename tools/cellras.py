#!/usr/bin/env python3
"""cellras.py -- the Links cell raster: an 8-bit sprite with per-row spans.

The sibling repository `vis-linksthechallengeofgolf-doc` measured the head of
this format on five `.BLK` specimens, guessed at "a big-endian u16 row prefix
equal to the width", found that no arithmetic it tried closed on any specimen,
and filed the format unsolved in its leftovers chapter. It was one field away.

The big-endian u16 was not a u16. It is TWO u8 FIELDS, and it only looked like
a width because on an opaque row the two happen to read as `00 <width>`.

    +0   u16 LE   width  in pixels
    +2   u16 LE   height in rows
    +4   u16 LE   total size of this record, INCLUDING these six bytes
                  -- PRESENT IN THE `.GPH` CELLS OF title.lnx, ABSENT IN `.BLK`
    +6            height rows, each:
                     u8  x      first stored column
                     u8  n      number of stored pixels
                     n bytes    8-bit palette indices
                  columns outside [x, x+n) are not stored: transparent.

Three quantities are encoded twice and all three are checked, which is the
whole point of the reader:

  * `size` against the actual length of the record;
  * `x + n <= width` on every row;
  * the walk consuming the record exactly, with no residue.

A record that fails any of them is REFUSED. There is no repair path, because a
reader that repairs cannot tell you whether the format is right.

`.BLK` members carry the same rows behind a FOUR-byte header with no size
field, and a `.BLK` file is a SEQUENCE of such records each padded up to a
16-byte boundary, run out to end of file. `--sequence` reads that form. It
closes on **80 of 80** `.BLK` members with every trailing pad byte zero, and
the record counts run 1, 2, 3, 8, 11, 16, 17, 18, 24 and 38 -- which is what a
sprite sheet and an animation look like in the same container.

    python tools/cellras.py FILE...            one line per record
    python tools/cellras.py FILE... --png DIR --pal PALFILE
    python tools/cellras.py FILE... --sequence --expect-ok 80
"""
import argparse
import os
import struct
import sys
import zlib


class CellError(Exception):
    pass


def parse(data, name="<data>"):
    if len(data) < 6:
        raise CellError("%s: %d bytes cannot hold a six-byte header"
                        % (name, len(data)))
    w, h, size = struct.unpack_from("<HHH", data, 0)
    if w == 0 or h == 0:
        raise CellError("%s: degenerate geometry %dx%d" % (name, w, h))
    if size != len(data):
        raise CellError("%s: declared size %d against %d bytes on disc"
                        % (name, size, len(data)))
    rows = []
    off = 6
    for r in range(h):
        if off + 2 > len(data):
            raise CellError("%s: row %d of %d: span header runs past the end "
                            "at %d" % (name, r, h, off))
        x, n = data[off], data[off + 1]
        off += 2
        if x + n > w:
            raise CellError("%s: row %d: x=%d + n=%d exceeds width %d"
                            % (name, r, x, n, w))
        if off + n > len(data):
            raise CellError("%s: row %d: span of %d runs past the end at %d"
                            % (name, r, n, off))
        rows.append((x, n, data[off:off + n]))
        off += n
    if off != len(data):
        raise CellError("%s: walk ended at %d of %d -- residue %d"
                        % (name, off, len(data), len(data) - off))
    return w, h, rows


def parse_sequence(data, name="<data>", align=16):
    """`.BLK`: a run of four-byte-header records, each padded up to `align`.

    No record carries a size field, so the only thing that can close this is
    the walk itself: every record's rows must fit, every pad byte must be
    zero, and the last record must end within `align` bytes of the file. A
    single wrong stride derails all three.
    """
    recs = []
    off = 0
    while off + 4 <= len(data):
        if not any(data[off:]):
            break
        w, h = struct.unpack_from("<HH", data, off)
        if w == 0 or h == 0:
            raise CellError("%s: record %d at %d has geometry %dx%d"
                            % (name, len(recs), off, w, h))
        o = off + 4
        rows = []
        for r in range(h):
            if o + 2 > len(data):
                raise CellError("%s: record %d row %d: span header past the "
                                "end at %d" % (name, len(recs), r, o))
            x, n = data[o], data[o + 1]
            o += 2
            if x + n > w or o + n > len(data):
                raise CellError("%s: record %d row %d: x=%d n=%d against "
                                "width %d" % (name, len(recs), r, x, n, w))
            rows.append((x, n, data[o:o + n]))
            o += n
        recs.append((w, h, rows))
        end = (o + align - 1) // align * align
        if any(data[o:min(end, len(data))]):
            raise CellError("%s: record %d: pad bytes at %d..%d are not zero"
                            % (name, len(recs) - 1, o, end))
        off = end
    if not recs:
        raise CellError("%s: no records" % name)
    if len(data) - off >= align:
        raise CellError("%s: %d bytes of tail after %d records, more than one "
                        "%d-byte pad" % (name, len(data) - off, len(recs),
                                         align))
    return recs


def coverage(w, h, rows):
    """Stored pixels over the bounding box, as a fraction."""
    return sum(n for _, n, _ in rows) / float(w * h)


def to_indices(w, h, rows, background=0):
    buf = bytearray([background]) * (w * h)
    for r, (x, n, px) in enumerate(rows):
        buf[r * w + x:r * w + x + n] = px
    return bytes(buf)


def read_palette(path):
    raw = open(path, "rb").read()
    if len(raw) != 768:
        raise CellError("%s: a palette is 768 bytes, this is %d"
                        % (path, len(raw)))
    hi = max(raw)
    if hi > 63:
        raise CellError("%s: max component %d, not a 6-bit VGA palette"
                        % (path, hi))
    return bytes(bytearray(v * 255 // 63 for v in raw))


def write_png(path, w, h, idx, pal):
    def chunk(tag, body):
        return (struct.pack(">I", len(body)) + tag + body
                + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))
    raw = b"".join(b"\x00" + idx[y * w:(y + 1) * w] for y in range(h))
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
           + chunk(b"PLTE", pal)
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(png)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--png", metavar="DIR")
    ap.add_argument("--pal", metavar="PALFILE")
    ap.add_argument("--expect-ok", type=int)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--sequence", action="store_true",
                    help="the `.BLK` form: four-byte headers, 16-byte aligned, "
                         "repeated to end of file")
    args = ap.parse_args()

    pal = read_palette(args.pal) if args.pal else None
    if args.png:
        if pal is None:
            raise SystemExit("cellras: --png needs --pal")
        os.makedirs(args.png, exist_ok=True)

    ok = bad = nrec = 0
    for p in args.files:
        name = os.path.basename(p)
        try:
            if args.sequence:
                recs = parse_sequence(open(p, "rb").read(), name)
            else:
                recs = [parse(open(p, "rb").read(), name)]
        except CellError as e:
            bad += 1
            print("REFUSED  %s" % e)
            continue
        ok += 1
        nrec += len(recs)
        if not args.quiet:
            w, h, rows = recs[0]
            print("OK       %-22s %4d x %-4d  %7d B  %2d record(s)  "
                  "coverage %6.2f %%"
                  % (name, w, h, os.path.getsize(p), len(recs),
                     100.0 * coverage(w, h, rows)))
        if args.png:
            for i, (w, h, rows) in enumerate(recs):
                suffix = ".png" if len(recs) == 1 else ".%02d.png" % i
                write_png(os.path.join(args.png, name + suffix), w, h,
                          to_indices(w, h, rows), pal)

    print()
    print("cellras: %d accepted, %d refused, %d files, %d records"
          % (ok, bad, ok + bad, nrec))
    if args.expect_ok is not None and ok != args.expect_ok:
        raise SystemExit("cellras: expected %d accepted, got %d"
                         % (args.expect_ok, ok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
