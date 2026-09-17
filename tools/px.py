#!/usr/bin/env python3
"""px.py -- read the `PX` screen format of *Il grande gioco di Tangentopoli*.

THIS FORMAT IS NOT PUBLISHED AND NOBODY OWNS IT, AND THAT IS SAID OUT LOUD.
`pcx.py` in this same box opens with the opposite sentence: PCX was published
by ZSoft, its 128-byte header is a public specification, and implementing it
is work but not reverse engineering. **`PX` has no specification, no vendor
and no author's name anywhere in the object it came from.** Everything below
was derived from 23 files by testing a guess against all 23 at once, and every
claim in this docstring is a claim this tool re-checks at run time rather than
an assumption it makes.

THE GRAMMAR, WHICH CLOSES WITH RESIDUE ZERO
-------------------------------------------
    +0   2B   'PX'
    +2   u16  width, 320 on 23 of 23
    +4   u16  height, 200 on 23 of 23
    +6   ...  one run-length stream to the end of the file

The stream's rule is the smallest one available:

    FF <count> <byte>    a run of <count> copies of <byte>
    anything else        one literal byte of itself

and 0xFF is the commonest byte in every one of the 23 files, which is what a
run marker looks like from outside.

The stream decodes, on 23 of 23 files, to exactly

    10 bytes   preamble        five little-endian words: 247, 0, 0, 320, 200
    768 bytes  VGA palette     256 entries, six bits per channel
    64000      pixel indices   320 x 200, one byte each
    -------
    64778      and the residue is ZERO

WHY THE PRE-BRIEFING SAW A THIRTEEN-BYTE HEADER AND ONE BYTE OF RESIDUE
-----------------------------------------------------------------------
`_work/pxprobe.py` swept header lengths 0..24 and scored each one by asking
whether the first 768 decoded bytes were all below 64 -- a six-bit VGA
palette. It picked 13, where the decoded length is 64,769 and 768 + 320 x 200
is 64,768, and it reported **one byte of residue it could not explain**.

The probe's test was the thing that was wrong, not the grammar. **The
preamble's first byte is 0xF7 = 247, which is greater than 64**, so any header
length that leaves the preamble in the stream fails a "first 768 bytes are a
palette" test no matter how right it is. Thirteen is the offset at which the
preamble has been swallowed by the header down to its last byte -- and
`FF 05 00` sits at raw offset 7, so a raw-byte header of 13 is cutting an RLE
run in half and getting away with it only because the halves happen to decode
to nothing.

The arithmetic is exact and is checked by `--selftest`: decoding from offset 6
rather than 13 yields **9 more bytes** -- `F7`, the five zeros of `FF 05 00`,
and the literals `40 01 C8` -- and 64,769 + 9 = 64,778 = 10 + 768 + 64,000.

THE PALETTE, AND THE CLAIM IS STRONGER THAN "IT LOOKS EGA"
-----------------------------------------------------------
The first sixteen entries are not merely EGA-flavoured. They are the canonical
IBM EGA sixteen in canonical order -- black, blue, green, cyan, red, magenta,
brown, light grey, dark grey, light blue, light green, light cyan, light red,
light magenta, yellow, white -- in six-bit VGA DAC values, on **23 of 23
files**, and `--validate` fails loudly if that ever stops being true. The
files are 256-colour; the low sixteen are EGA. Those are two different
sentences and this tool does not merge them.

    python tools/px.py --validate iggdt/RESOURCE.FV1
    python tools/px.py --validate --recurse iggdt          (selects by magic)
    python tools/px.py --census   --recurse iggdt
    python tools/px.py --render   --recurse iggdt --out _work/png
    python tools/px.py --palette-report --recurse iggdt
    python tools/px.py --selftest

Validate before census, always, and `--recurse` selects on the two magic bytes
and never on a file name -- `HIGHSCOR.TNG` and `START.EXE` are in the same
flat folder and neither is a screen.
"""
import argparse
import collections
import hashlib
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

MAGIC = b'PX'
RUN = 0xFF
PREAMBLE = 10
PALETTE = 768
PIXELS = 320 * 200

# The canonical IBM EGA sixteen, in canonical order, in six-bit VGA DAC values.
# This is somebody else's table -- it is the EGA hardware palette and it is as
# public as a fact gets -- and it is written out here so that the claim made
# about it can be checked rather than believed.
EGA16 = [(0, 0, 0), (0, 0, 42), (0, 42, 0), (0, 42, 42),
         (42, 0, 0), (42, 0, 42), (42, 21, 0), (42, 42, 42),
         (21, 21, 21), (21, 21, 63), (21, 63, 21), (21, 63, 63),
         (63, 21, 21), (63, 21, 63), (63, 63, 21), (63, 63, 63)]


class PxError(Exception):
    """A file this reader will not pretend to understand."""


def is_px(blob):
    """Magic, and nothing else. Extensions are not evidence."""
    return len(blob) >= 6 and blob[:2] == MAGIC


def header(blob):
    if not is_px(blob):
        raise PxError('not a PX file: first two bytes are %s, wanted %r'
                      % (blob[:2].hex(' ') if blob else '(empty)', MAGIC))
    width, height = struct.unpack_from('<HH', blob, 2)
    if width == 0 or height == 0:
        raise PxError('degenerate geometry %dx%d' % (width, height))
    return {'width': width, 'height': height, 'bytes': len(blob)}


def unrle(blob, start=6):
    """FF <count> <byte> is a run; anything else is one literal byte.

    Returns (decoded, consumed). A truncated run at the very end of the file
    is reported rather than silently completed: this reader has never seen one
    and would rather say so than invent two bytes.
    """
    out = bytearray()
    pos = start
    end = len(blob)
    while pos < end:
        byte = blob[pos]
        if byte == RUN:
            if pos + 2 >= end:
                raise PxError('truncated run at offset %d: %d byte(s) left, '
                              'a run needs 3' % (pos, end - pos))
            out.extend(bytes([blob[pos + 2]]) * blob[pos + 1])
            pos += 3
        else:
            out.append(byte)
            pos += 1
    return bytes(out), pos


def decode(blob):
    """Return (head, preamble, palette, pixels, residue).

    `residue` is decoded-length minus (10 + 768 + width*height) and this
    reader's whole claim is that it is zero. It is returned rather than
    asserted so that `--census` can print it for every file and a reader of
    the output can see the zero rather than take it on trust.
    """
    head = header(blob)
    data, consumed = unrle(blob, 6)
    want = PREAMBLE + PALETTE + head['width'] * head['height']
    residue = len(data) - want
    if len(data) < PREAMBLE + PALETTE:
        raise PxError('decoded to %d bytes, too short for a preamble and a '
                      'palette (%d)' % (len(data), PREAMBLE + PALETTE))
    preamble = data[:PREAMBLE]
    palette = data[PREAMBLE:PREAMBLE + PALETTE]
    pixels = data[PREAMBLE + PALETTE:]
    head['consumed'] = consumed
    head['decoded'] = len(data)
    return head, preamble, palette, pixels, residue


def ega_prefix(palette):
    """How many of the sixteen EGA entries this palette gets right, in order."""
    hits = 0
    for i, want in enumerate(EGA16):
        got = (palette[i * 3], palette[i * 3 + 1], palette[i * 3 + 2])
        if got != want:
            break
        hits += 1
    return hits


def six_bit(palette):
    """A VGA DAC takes six bits per channel, so every byte must be < 64."""
    return sum(1 for byte in palette if byte > 63)


def to_rgb(palette):
    """Six-bit DAC values scaled to eight bits, the way the hardware does it.

    x -> (x << 2) | (x >> 4) reproduces the DAC's own expansion and sends 63
    to 255 rather than to 252, which the naive x*4 does not.
    """
    return bytes(((b & 0x3F) << 2) | ((b & 0x3F) >> 4) for b in palette)


def colour_class(rgb):
    """G, W, R or '.', on eight-bit values, independent of palette index.

    The three classes are deliberately wide. The point is not to identify a
    colour but to find the ARRANGEMENT green-light-red, and an artist shading
    a flag in mode 13h will not use pure primaries.
    """
    red, green, blue = rgb
    if green > 90 and red < green - 60 and blue < green - 60:
        return 'G'
    if red > 110 and green < red - 60 and blue < red - 60:
        return 'R'
    if red > 150 and green > 150 and blue > 150:
        return 'W'
    return '.'


def tricolour_runs(pixels, palette, width, height, window=12):
    """Every row position where green, then light, then red occur in order.

    WHY A READER OF AN ITALIAN GAME HAS THIS
    ----------------------------------------
    On this object the question "where is the tricolour" is a real question
    twice over. It found the label on the board that names a political party
    ([04](docs/04-the-screens.md)) -- and, more usefully, it established an
    ABSENCE: the small tricolour projectile the game throws is in none of the
    twenty-three screens. **An absence needs a command more than a presence
    does**, because a reader cannot check it by looking at a picture.

    The known tricolours in the object -- the two ONORE plaques and the title
    animation -- are the positive control. A run of this that does not light
    them up is a broken run, not an empty object.
    """
    rgb = to_rgb(palette)
    table = [colour_class((rgb[i * 3], rgb[i * 3 + 1], rgb[i * 3 + 2]))
             for i in range(256)]
    hits = []
    for y in range(height):
        row = [table[v] for v in pixels[y * width:(y + 1) * width]]
        for x, cell in enumerate(row):
            if cell != 'G':
                continue
            segment = row[x:x + window]
            if 'W' not in segment or 'R' not in segment:
                continue
            if 0 < segment.index('W') < segment.index('R'):
                hits.append((x, y))
    return hits


def crop_zoom(pixels, width, height, box=None, zoom=1):
    """Cut a rectangle out and magnify it by nearest neighbour.

    This exists because the only writing this object contains is DRAWN, not
    stored: the game's credits, its intro and its menus are pixels in a
    320 x 200 screen and there is no string anywhere to grep for. Reading
    them is a matter of magnifying a rectangle, so magnifying a rectangle is
    a command with arguments and not a screenshot somebody took.
    """
    if box is None:
        left, top, wide, tall = 0, 0, width, height
    else:
        left, top, wide, tall = box
    if left < 0 or top < 0 or wide <= 0 or tall <= 0 \
            or left + wide > width or top + tall > height:
        raise PxError('crop %r does not fit inside %dx%d'
                      % (box, width, height))
    out = bytearray()
    for row in range(tall):
        line = pixels[(top + row) * width + left:
                      (top + row) * width + left + wide]
        big = bytearray()
        for value in line:
            big.extend(bytes([value]) * zoom)
        for _ in range(zoom):
            out.extend(big)
    return bytes(out), wide * zoom, tall * zoom


def write_png(path, width, height, pixels, palette):
    """8-bit indexed PNG, written with zlib and no image library."""
    raw = bytearray()
    for row in range(height):
        raw.append(0)
        raw.extend(pixels[row * width:(row + 1) * width])

    def chunk(tag, payload):
        body = tag + payload
        return (struct.pack('>I', len(payload)) + body
                + struct.pack('>I', zlib.crc32(body) & 0xFFFFFFFF))

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 3, 0, 0, 0))
    png += chunk(b'PLTE', to_rgb(palette))
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    png += chunk(b'IEND', b'')
    with open(path, 'wb') as handle:
        handle.write(png)


def gather(args):
    """The file population, selected by MAGIC and never by name.

    A flat folder holding 23 screens, one DOS executable and a high-score
    table is exactly the population that punishes an extension filter --
    `mzcensus.py`'s `.EXE` glob is at its fourteenth appearance in this box's
    correction lists -- so this reader opens every candidate and reads two
    bytes.
    """
    if args.recurse:
        found = []
        for root, _dirs, names in os.walk(args.recurse):
            for name in sorted(names):
                path = os.path.join(root, name)
                try:
                    with open(path, 'rb') as handle:
                        if is_px(handle.read(6)):
                            found.append(path)
                except OSError:
                    continue
        return found
    return [dirguard.want_file(p, 'px') for p in args.files]


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the grammar, on bytes made here rather than on the object ----------
    want('a literal decodes to itself', unrle(b'PXaaaa\x01\x02', 6)[0],
         b'\x01\x02')
    want('a run expands', unrle(b'PXaaaa\xff\x04\x41', 6)[0], b'AAAA')
    want('a zero-count run expands to nothing',
         unrle(b'PXaaaa\xff\x00\x41', 6)[0], b'')
    want('a run of 255 expands to 255',
         len(unrle(b'PXaaaa\xff\xff\x41', 6)[0]), 255)
    want('literals and runs interleave',
         unrle(b'PXaaaa\x01\xff\x03\x02\x03', 6)[0],
         b'\x01\x02\x02\x02\x03')
    try:
        unrle(b'PXaaaa\xff\x04', 6)
        want('a truncated run is refused', 'no exception', 'PxError')
    except PxError:
        want('a truncated run is refused', 'PxError', 'PxError')

    # -- the magic, and the negative control --------------------------------
    want('PX is recognised', is_px(b'PX\x40\x01\xc8\x00'), True)
    want('MZ is not', is_px(b'MZ\x00\x00\x00\x00'), False)
    want('a short file is not', is_px(b'PX'), False)
    try:
        header(b'MZ\x00\x00\x00\x00')
        want('a non-PX header is refused', 'no exception', 'PxError')
    except PxError:
        want('a non-PX header is refused', 'PxError', 'PxError')

    # -- the arithmetic this tool's docstring turns on ----------------------
    # Decoding from 6 instead of 13 must yield exactly 9 more bytes on the
    # object's shared prefix, and 64769 + 9 must be 10 + 768 + 64000.
    prefix = bytes.fromhex('5058400 1c800f7ff050040 01c8ff0600'.replace(' ', ''))
    from6 = len(unrle(prefix + b'\x00' * 4, 6)[0])
    from13 = len(unrle(prefix + b'\x00' * 4, 13)[0])
    want('offset 6 yields 9 more bytes than offset 13', from6 - from13, 9)
    want('the accounting closes', PREAMBLE + PALETTE + PIXELS, 64778)
    want('64769 + 9 is 64778', 64769 + 9, PREAMBLE + PALETTE + PIXELS)

    # -- the EGA table, checked as a table ----------------------------------
    want('EGA16 has sixteen entries', len(EGA16), 16)
    want('EGA16 is six-bit', max(max(e) for e in EGA16), 63)
    good = bytes(v for entry in EGA16 for v in entry) + b'\x00' * (768 - 48)
    want('a canonical palette scores sixteen', ega_prefix(good), 16)
    bad = bytearray(good)
    bad[3] = 41
    want('one wrong channel scores one', ega_prefix(bytes(bad)), 1)
    want('a canonical palette is six-bit', six_bit(good), 0)
    over = bytearray(good)
    over[700] = 200
    want('an eight-bit byte is caught', six_bit(bytes(over)), 1)

    # -- the DAC expansion --------------------------------------------------
    want('63 expands to 255', to_rgb(b'\x3f')[0], 255)
    want('0 expands to 0', to_rgb(b'\x00')[0], 0)
    want('42 expands to 170', to_rgb(b'\x2a')[0], 170)
    want('21 expands to 85', to_rgb(b'\x15')[0], 85)

    # -- a whole synthetic file, round trip ---------------------------------
    body = bytearray()
    body += struct.pack('<HHHHH', 247, 0, 0, 4, 2)
    body += bytes(v for entry in EGA16 for v in entry) + b'\x00' * (768 - 48)
    body += bytes([1, 2, 3, 4, 5, 6, 7, 8])
    synth = b'PX' + struct.pack('<HH', 4, 2) + bytes(body)
    head, pre, pal, pix, residue = decode(synth)
    want('synthetic geometry', (head['width'], head['height']), (4, 2))
    want('synthetic residue is zero', residue, 0)
    want('synthetic preamble words', struct.unpack('<5H', pre),
         (247, 0, 0, 4, 2))
    want('synthetic palette is EGA', ega_prefix(pal), 16)
    want('synthetic pixels', list(pix), [1, 2, 3, 4, 5, 6, 7, 8])

    # -- and the same file one byte short, which must NOT report zero -------
    head2, _p, _q, _r, residue2 = decode(synth[:-1])
    want('one pixel short is residue -1', residue2, -1)

    # -- the colour classes and the tricolour run ---------------------------
    want('pure green classifies G', colour_class((0, 200, 0)), 'G')
    want('pure red classifies R', colour_class((200, 0, 0)), 'R')
    want('white classifies W', colour_class((255, 255, 255)), 'W')
    want('grey classifies as nothing', colour_class((128, 128, 128)), '.')
    want('a dark shade of green is still G', colour_class((10, 100, 10)), 'G')
    want('EGA green at eight bits is G', colour_class(tuple(to_rgb(b'\x00\x2a\x00'))), 'G')
    want('EGA red at eight bits is R', colour_class(tuple(to_rgb(b'\x2a\x00\x00'))), 'R')

    # A three-pixel flag planted in a 6x1 strip, and the same three pixels in
    # the wrong order, which must NOT be found.
    flagpal = bytearray(768)
    for idx, (r, g, b) in ((1, (0, 63, 0)), (2, (63, 63, 63)), (3, (63, 0, 0))):
        flagpal[idx * 3], flagpal[idx * 3 + 1], flagpal[idx * 3 + 2] = r, g, b
    want('a green-white-red run is found',
         tricolour_runs(bytes([0, 1, 2, 3, 0, 0]), bytes(flagpal), 6, 1),
         [(1, 0)])
    want('red-white-green is NOT a hit',
         tricolour_runs(bytes([0, 3, 2, 1, 0, 0]), bytes(flagpal), 6, 1), [])
    want('green-red-white is NOT a hit',
         tricolour_runs(bytes([0, 1, 3, 2, 0, 0]), bytes(flagpal), 6, 1), [])
    want('green and red with no light between is NOT a hit',
         tricolour_runs(bytes([0, 1, 3, 0, 0, 0]), bytes(flagpal), 6, 1), [])
    want('a run wider than the window is NOT a hit',
         tricolour_runs(bytes([1] + [0] * 20 + [2, 3]), bytes(flagpal), 23, 1,
                        window=12), [])
    want('the same run inside the window IS a hit',
         tricolour_runs(bytes([1] + [0] * 20 + [2, 3]), bytes(flagpal), 23, 1,
                        window=23), [(0, 0)])
    want('a second row is found at its own y',
         tricolour_runs(bytes([0, 0, 0, 0] + [1, 2, 3, 0]), bytes(flagpal),
                        4, 2), [(0, 1)])

    # -- the crop, on a 4x2 grid whose every pixel is distinguishable --------
    grid = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    want('a whole-image crop is the identity',
         crop_zoom(grid, 4, 2), (grid, 4, 2))
    want('a 2x1 crop takes the right two pixels',
         crop_zoom(grid, 4, 2, (1, 1, 2, 1))[0], bytes([6, 7]))
    want('zoom 2 doubles both axes',
         crop_zoom(grid, 4, 2, (0, 0, 2, 1), 2),
         (bytes([1, 1, 2, 2, 1, 1, 2, 2]), 4, 2))
    want('zoom 3 on one pixel is nine pixels',
         crop_zoom(grid, 4, 2, (3, 1, 1, 1), 3)[0], bytes([8] * 9))
    for label, spec in (('a crop past the right edge is refused', (3, 0, 2, 1)),
                        ('a crop past the bottom is refused', (0, 1, 1, 2)),
                        ('a negative origin is refused', (-1, 0, 1, 1)),
                        ('a zero-width crop is refused', (0, 0, 0, 1))):
        try:
            crop_zoom(grid, 4, 2, spec)
            want(label, 'no exception', 'PxError')
        except PxError:
            want(label, 'PxError', 'PxError')

    bad_pal = bytearray(synth)
    bad_pal[6 + 10 + 1] = 41
    _h, _p, pal2, _r, _s = decode(bytes(bad_pal))
    want('a broken EGA entry is visible', ega_prefix(pal2), 0)

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    bad_count = sum(1 for _l, ok, _d in checks if not ok)
    print('%d checks, %d failures' % (len(checks), bad_count))
    return 1 if bad_count else 0


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*')
    ap.add_argument('--recurse', metavar='DIR',
                    help='walk DIR and select files by the PX magic')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--render', action='store_true')
    ap.add_argument('--palette-report', action='store_true')
    ap.add_argument('--tricolour', action='store_true',
                    help='report green-light-red runs, and where they are')
    ap.add_argument('--out', default=None)
    ap.add_argument('--crop', metavar='X,Y,W,H',
                    help='render only this rectangle of the screen')
    ap.add_argument('--zoom', type=int, default=1,
                    help='magnify the rendered pixels by nearest neighbour')
    ap.add_argument('--expect', type=int, default=None)
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())
    if not args.files and not args.recurse:
        ap.error('give a file, or --recurse a directory')
    if args.render and not args.out:
        ap.error('--render needs --out')
    if args.zoom < 1:
        ap.error('--zoom wants a positive integer')
    box = None
    if args.crop:
        try:
            box = tuple(int(part) for part in args.crop.split(','))
        except ValueError:
            ap.error('--crop wants four integers X,Y,W,H')
        if len(box) != 4:
            ap.error('--crop wants four integers X,Y,W,H')

    paths = gather(args)
    if args.render:
        os.makedirs(args.out, exist_ok=True)

    opened = clean = ega = sixbit = tricolours = 0
    failures = []
    geometry = collections.Counter()
    residues = collections.Counter()
    preambles = collections.Counter()
    palettes = collections.Counter()

    for path in paths:
        with open(path, 'rb') as handle:
            blob = handle.read()
        try:
            head, preamble, palette, pixels, residue = decode(blob)
        except PxError as exc:
            failures.append('%s: %s' % (os.path.basename(path), exc))
            print('FAIL  %s: %s' % (os.path.basename(path), exc))
            continue

        opened += 1
        residues[residue] += 1
        clean += residue == 0
        hits = ega_prefix(palette)
        ega += hits == 16
        over = six_bit(palette)
        sixbit += over == 0
        geometry['%dx%d' % (head['width'], head['height'])] += 1
        preambles[preamble.hex(' ')] += 1
        digest = hashlib.sha1(palette).hexdigest()[:12]
        palettes[digest] += 1

        if args.census:
            print('%-16s %7d B -> %6d   %dx%-4d residue %+d   EGA %2d/16   '
                  'palette %s  indices %3d'
                  % (os.path.basename(path), head['bytes'], head['decoded'],
                     head['width'], head['height'], residue, hits, digest,
                     len(set(pixels))))

        if args.tricolour:
            runs = tricolour_runs(pixels, palette, head['width'],
                                  head['height'])
            tricolours += 1 if runs else 0
            print('%-16s green-light-red runs %4d   %s'
                  % (os.path.basename(path), len(runs),
                     runs[:4] if runs else 'none'))

        if args.palette_report:
            used = sorted(set(pixels))
            print('%-16s palette %s   bytes >63: %d of 768   distinct '
                  'indices %3d   highest %3d'
                  % (os.path.basename(path), digest, over, len(used),
                     used[-1] if used else -1))

        if args.render:
            if residue != 0:
                print('SKIP  %s: residue %+d, not writing a picture from a '
                      'stream that does not close'
                      % (os.path.basename(path), residue))
                continue
            stem = os.path.splitext(os.path.basename(path))[0]
            ext = os.path.splitext(os.path.basename(path))[1].lstrip('.')
            name = '%s_%s' % (stem, ext)
            grid, wide, tall = crop_zoom(pixels, head['width'], head['height'],
                                         box, args.zoom)
            if box or args.zoom != 1:
                name += '_%dx%d+%d+%d_x%d' % (box[2], box[3], box[0], box[1],
                                              args.zoom) if box \
                    else '_x%d' % args.zoom
            out = os.path.join(args.out, name + '.png')
            write_png(out, wide, tall, grid, palette)

    print('')
    print('opened                                   : %d of %d'
          % (opened, len(paths)))
    print('decoded with residue 0                   : %d of %d'
          % (clean, opened))
    print('palette is the canonical EGA 16, in order: %d of %d'
          % (ega, opened))
    print('palette is six-bit throughout            : %d of %d'
          % (sixbit, opened))
    print('geometry   : ' + '   '.join('%s x%d' % kv
                                       for kv in sorted(geometry.items())))
    print('residues   : ' + '   '.join('%+d x%d' % kv
                                       for kv in sorted(residues.items())))
    if args.tricolour:
        print('screens carrying a green-light-red run : %d of %d'
              % (tricolours, opened))
        print('  the two ONORE plaques and the title animation are the')
        print('  positive control: if they are not in that count, this')
        print('  measurement is broken and its zeroes mean nothing.')
    print('preambles  : %d distinct' % len(preambles))
    for hexed, count in preambles.most_common():
        words = struct.unpack('<5H', bytes.fromhex(hexed.replace(' ', '')))
        print('             %s  x%d   as words %s' % (hexed, count, list(words)))
    print('palettes   : %d distinct' % len(palettes))
    for digest, count in palettes.most_common():
        print('             %s  x%d' % (digest, count))

    if failures:
        raise SystemExit('FATAL: %d of %d files failed'
                         % (len(failures), len(paths)))
    if args.expect is not None and opened != args.expect:
        raise SystemExit('FATAL: expected %d files, opened %d'
                         % (args.expect, opened))


if __name__ == '__main__':
    main()
