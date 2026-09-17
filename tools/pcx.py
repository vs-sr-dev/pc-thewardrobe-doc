#!/usr/bin/env python3
"""pcx.py -- read ZSoft PCX against the published specification.

THIS IS SOMEBODY ELSE'S FORMAT AND THAT IS SAID OUT LOUD. PCX was published
by ZSoft Corporation; the 128-byte header layout and the run-length scheme
below are the public specification and are not a finding of this pipeline.
Implementing it correctly is work; it is not reverse engineering, and any
coverage figure it earns should be reported with that sentence attached.

THE HEADER, 128 bytes, all multi-byte fields little-endian:

    +0    u8    manufacturer, 0x0A
    +1    u8    version -- 5 is "v3.0, 256-colour palette at end of file"
    +2    u8    encoding, 1 = run-length
    +3    u8    bits per pixel per plane
    +4    u16   xmin        +6  u16 ymin
    +8    u16   xmax        +10 u16 ymax
    +12   u16   hdpi        +14 u16 vdpi
    +16   48B   16-entry EGA palette
    +64   u8    reserved, documented as 0
    +65   u8    number of colour planes
    +66   u16   bytes per scan line per plane -- documented as always EVEN
    +68   u16   palette info, 1 = colour/BW, 2 = grayscale
    +70   u16   hscreensize +72 u16 vscreensize
    +74   54B   filler

THE RUN-LENGTH SCHEME, one page:

    read a byte b
    if (b & 0xC0) == 0xC0:  count = b & 0x3F; value = next byte
    else:                   count = 1;        value = b

decoded per scan line to exactly `nplanes * bytesPerLine` bytes. A run is NOT
permitted to straddle a scan-line boundary in the specification, and this
reader CHECKS that rather than assuming it: --strict-rows makes a straddle
fatal, and the census reports how many files straddle.

THE 256-COLOUR PALETTE, for version 5 at 8 bits and 1 plane, is the last 769
bytes of the file: a 0x0C marker followed by 256 RGB triples at 8 bits per
channel. Its absence is reported and never silently patched with a guess.

    python tools/pcx.py --validate _work/members/GAME/*.PCX
    python tools/pcx.py --census   _work/members/*/*.PCX
    python tools/pcx.py --render   _work/members/GAME/*.PCX --out _work/png
    python tools/pcx.py --palette-report _work/members/*/*.PCX

Validate before census, always. Every count this tool prints is a count of
files it actually opened, which is the defect `bmp.py` still has.
"""
import argparse
import collections
import os
import struct
import sys
import zlib

HEADER = 128
PALETTE_TAIL = 769


class PcxError(Exception):
    pass


def read_header(blob, path):
    if len(blob) < HEADER:
        raise PcxError('%s: %d bytes, shorter than the 128-byte header'
                       % (path, len(blob)))
    (manufacturer, version, encoding, bpp) = struct.unpack_from('<4B', blob, 0)
    (xmin, ymin, xmax, ymax, hdpi, vdpi) = struct.unpack_from('<6H', blob, 4)
    reserved, nplanes = struct.unpack_from('<2B', blob, 64)
    (bytes_per_line, palette_info) = struct.unpack_from('<2H', blob, 66)
    (hscreen, vscreen) = struct.unpack_from('<2H', blob, 70)

    if manufacturer != 0x0A:
        raise PcxError('%s: manufacturer byte is 0x%02X, not 0x0A -- not a PCX'
                       % (path, manufacturer))
    if encoding != 1:
        raise PcxError('%s: encoding is %d, and only 1 (RLE) is specified'
                       % (path, encoding))
    if xmax < xmin or ymax < ymin:
        raise PcxError('%s: window is empty: x %d..%d y %d..%d'
                       % (path, xmin, xmax, ymin, ymax))
    if nplanes == 0 or bytes_per_line == 0:
        raise PcxError('%s: nplanes=%d bytesPerLine=%d, one of them is zero'
                       % (path, nplanes, bytes_per_line))

    width = xmax - xmin + 1
    height = ymax - ymin + 1
    return {
        'path': path, 'bytes': len(blob),
        'manufacturer': manufacturer, 'version': version,
        'encoding': encoding, 'bpp': bpp, 'nplanes': nplanes,
        'width': width, 'height': height,
        'bytes_per_line': bytes_per_line, 'palette_info': palette_info,
        'reserved': reserved, 'hdpi': hdpi, 'vdpi': vdpi,
        'hscreen': hscreen, 'vscreen': vscreen,
        'row_bytes': nplanes * bytes_per_line,
    }


def decode(blob, head, strict_rows=False):
    """Decode the RLE stream. Returns (rows, consumed, straddles)."""
    path = head['path']
    row_bytes = head['row_bytes']
    height = head['height']
    has_palette = (len(blob) >= HEADER + PALETTE_TAIL
                   and blob[-PALETTE_TAIL] == 0x0C
                   and head['bpp'] == 8 and head['nplanes'] == 1)
    end = len(blob) - PALETTE_TAIL if has_palette else len(blob)

    pos = HEADER
    rows = []
    straddles = 0
    for row in range(height):
        line = bytearray()
        while len(line) < row_bytes:
            if pos >= end:
                raise PcxError('%s: RLE stream ran out at row %d of %d, %d of '
                               '%d bytes into the line'
                               % (path, row, height, len(line), row_bytes))
            marker = blob[pos]
            pos += 1
            if (marker & 0xC0) == 0xC0:
                count = marker & 0x3F
                if pos >= end:
                    raise PcxError('%s: run marker 0x%02X at %d has no value byte'
                                   % (path, marker, pos - 1))
                value = blob[pos]
                pos += 1
            else:
                count = 1
                value = marker
            if len(line) + count > row_bytes:
                straddles += 1
                if strict_rows:
                    raise PcxError('%s: run of %d at row %d overruns the '
                                   '%d-byte line by %d'
                                   % (path, count, row, row_bytes,
                                      len(line) + count - row_bytes))
                count = row_bytes - len(line)
            line.extend(bytes([value]) * count)
        rows.append(bytes(line))
    return rows, pos, straddles, has_palette, end


def palette(blob, has_palette):
    if not has_palette:
        return None
    return blob[-768:]


def write_png(path, width, height, pixels, pal):
    """8-bit indexed PNG, written with zlib and no image library."""
    raw = bytearray()
    for row in range(height):
        raw.append(0)
        raw.extend(pixels[row][:width])

    def chunk(tag, payload):
        body = tag + payload
        return (struct.pack('>I', len(payload)) + body
                + struct.pack('>I', zlib.crc32(body) & 0xFFFFFFFF))

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 3, 0, 0, 0))
    png += chunk(b'PLTE', bytes(pal))
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    png += chunk(b'IEND', b'')
    with open(path, 'wb') as handle:
        handle.write(png)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--render', action='store_true')
    ap.add_argument('--palette-report', action='store_true')
    ap.add_argument('--out', default=None)
    ap.add_argument('--strict-rows', action='store_true')
    ap.add_argument('--expect', type=int, default=None)
    args = ap.parse_args()

    if not (args.validate or args.census or args.render or args.palette_report):
        ap.error('pick one of --validate --census --render --palette-report')
    if args.render and not args.out:
        ap.error('--render needs --out')
    if args.render:
        os.makedirs(args.out, exist_ok=True)

    opened = 0
    clean = 0
    with_palette = 0
    straddling = 0
    geometry = collections.Counter()
    magic = collections.Counter()
    residues = collections.Counter()
    failures = []

    for path in sorted(args.files):
        try:
            with open(path, 'rb') as handle:
                blob = handle.read()
            head = read_header(blob, path)
            magic['%02X %02X %02X %02X' % (head['manufacturer'], head['version'],
                                           head['encoding'], head['bpp'])] += 1
            rows, consumed, straddles, has_pal, end = decode(
                blob, head, strict_rows=args.strict_rows)
        except PcxError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue

        opened += 1
        residue = end - consumed
        residues[residue] += 1
        if residue == 0:
            clean += 1
        if has_pal:
            with_palette += 1
        if straddles:
            straddling += 1
        geometry['%dx%d %dbpp %dpl' % (head['width'], head['height'],
                                       head['bpp'], head['nplanes'])] += 1

        if args.census:
            print('%-28s %6d B  %4dx%-4d %dbpp %dpl  bpl %4d  residue %+d  '
                  'pal %s  straddles %d'
                  % (os.path.basename(path), head['bytes'], head['width'],
                     head['height'], head['bpp'], head['nplanes'],
                     head['bytes_per_line'], residue, 'yes' if has_pal else 'NO',
                     straddles))

        if args.palette_report and has_pal:
            pal = palette(blob, has_pal)
            used = set()
            for row in rows:
                used.update(row[:head['width']])
            over63 = sum(1 for byte in pal if byte > 63)
            print('%-28s distinct indices used %3d   palette bytes >63: %d of 768'
                  % (os.path.basename(path), len(used), over63))

        if args.render:
            pal = palette(blob, has_pal)
            if pal is None:
                print('SKIP  %s: no 256-colour palette trailer, not rendering a '
                      'guess' % os.path.basename(path))
                continue
            stem = os.path.splitext(os.path.basename(path))[0]
            parent = os.path.basename(os.path.dirname(path))
            out = os.path.join(args.out, '%s_%s.png' % (parent, stem))
            write_png(out, head['width'], head['height'], rows, pal)

    print('')
    print('opened %d of %d files' % (opened, len(args.files)))
    print('decoded to declared geometry with residue 0: %d of %d' % (clean, opened))
    print('256-colour palette trailer present: %d of %d' % (with_palette, opened))
    print('files with a run straddling a scan line: %d of %d' % (straddling, opened))
    print('header magic:  ' + '   '.join('%s x%d' % (key, n) for key, n
                                         in sorted(magic.items())))
    print('geometry:      ' + '   '.join('%s x%d' % (key, n) for key, n
                                         in sorted(geometry.items())))
    print('residues:      ' + '   '.join('%+d x%d' % (key, n) for key, n
                                         in sorted(residues.items())))

    if failures:
        raise SystemExit('FATAL: %d of %d files failed' % (len(failures),
                                                           len(args.files)))
    if args.expect is not None and opened != args.expect:
        raise SystemExit('FATAL: expected %d files, opened %d'
                         % (args.expect, opened))


if __name__ == '__main__':
    main()
