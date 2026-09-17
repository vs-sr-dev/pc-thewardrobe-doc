#!/usr/bin/env python3
"""ilbm.py -- read EA IFF 85 / ILBM, which is somebody else's published format.

THIS FORMAT HAS A VENDOR, A DOCUMENT AND THIRTY YEARS OF INDEPENDENT READERS,
AND THAT IS THE OPPOSITE OF WHAT `px.py` IN THIS SAME BOX HAD TO SAY.
`px.py` opens by stating that its format is unpublished, unowned and derived
from twenty-three files by guessing. **Everything below is Electronic Arts'
"EA IFF 85 Standard for Interchange Format Files" (January 1985) and its ILBM
supplement**, and implementing it is work, not reverse engineering. Nothing in
this docstring was discovered here. The credit belongs to whoever wrote the
specification down and to the people who kept it readable for three decades;
what this tool contributes is one more independent implementation and the
arithmetic that proves it agrees with the file in front of it.

That distinction decides a bucket. A format with a vendor and a document earns
**SPECIFIED**; `PX`, which has neither, earned **DECODED**. The two words are
not synonyms for "we can read it" and this box does not let them become one.

THE GRAMMAR, WHICH IS A CHUNK WALK AND NOTHING CLEVERER
--------------------------------------------------------
    +0   4B    'FORM'
    +4   u32be  length of everything after this field
    +8   4B    'ILBM'   (or 'PBM ', DPaint II's chunky variant, which this
                         reader accepts and reports as a different form type)
    then, repeatedly, to the end of the FORM:
         4B    chunk id
         u32be chunk length
         ...   chunk body, padded to an EVEN length with one zero byte that
               is NOT counted in the declared length

The pad byte is the one thing an IFF reader gets wrong, so `--selftest` builds
a FORM whose first chunk has an odd length and requires the walk to find the
second one.

    BMHD  20 bytes  w, h, x, y, nPlanes, masking, compression, pad,
                    transparentColour, xAspect, yAspect, pageW, pageH
    CMAP  3n bytes  n palette entries, EIGHT bits per channel
    BODY  the rows, planar and interleaved:

        for each row:
            for each plane:      ceil(w/16)*2 bytes
            if masking == 1:     one more plane of the same width, the mask

    compression 0   the body is stored
    compression 1   ByteRun1, which is the Macintosh PackBits rule:
                        n in 0..127     copy the next n+1 bytes
                        n in 129..255   repeat the next byte 257-n times
                        n == 128        no operation

WHAT THIS READER REFUSES TO DO
------------------------------
It does not guess. If BODY is shorter than the declared geometry needs, it
raises rather than padding with zeros and reporting a picture; if the FORM
length disagrees with the file length, `--validate` says so with the signed
residue rather than rounding it away. A reader that always succeeds is a
reader whose successes mean nothing.

    python tools/ilbm.py --validate rovescino/SFONDO.LBM
    python tools/ilbm.py --validate --recurse rovescino    (selects by magic)
    python tools/ilbm.py --census   --recurse rovescino
    python tools/ilbm.py --render   rovescino/SFONDO.LBM --out _work/png
    python tools/ilbm.py --palette-report rovescino/SFONDO.LBM
    python tools/ilbm.py --selftest

Validate before census, always, and `--recurse` selects on the FORM/ILBM
structure and never on a `.LBM` name -- which matters in a folder where three
files are called `.ICO` and none of them is a Windows icon.
"""
import argparse
import collections
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard
# `crop_zoom` is palette-independent -- it moves indices around and never
# looks at a colour -- so it is the one function of `px.py` this reader can
# reuse unchanged. `px.write_png` is NOT reused and `write_png` below says why.
import px

FORM = b'FORM'
FORM_TYPES = (b'ILBM', b'PBM ')
BMHD_LEN = 20


class IlbmError(Exception):
    """A file this reader will not pretend to understand."""


def is_ilbm(blob):
    """Structure, not four letters.

    `FORM` alone is a four-byte string that occurs by accident. The magic this
    tool selects on is `FORM` PLUS a length field PLUS a known form type --
    the same standard `px.py`'s two-byte magic was held to, applied to a
    container where the cheap check would be cheaper still and worth less.
    """
    if len(blob) < 12 or blob[:4] != FORM:
        return False
    return blob[8:12] in FORM_TYPES


def walk(blob):
    """Every chunk in the FORM, with its offset, and where the walk stopped.

    Returns (form_type, chunks, declared, end), where `chunks` is a list of
    (id, offset, length) and `end` is the byte the walk stopped at, so the
    caller can subtract it from the file length and print a signed residue
    instead of a verdict.
    """
    if len(blob) < 12:
        raise IlbmError('%d bytes is shorter than a FORM header' % len(blob))
    if blob[:4] != FORM:
        raise IlbmError('does not begin with FORM')
    declared = struct.unpack('>I', blob[4:8])[0]
    form_type = blob[8:12]
    if form_type not in FORM_TYPES:
        raise IlbmError('form type %r is not ILBM or PBM ' % form_type)

    chunks = []
    at = 12
    limit = min(len(blob), 8 + declared)
    while at + 8 <= limit:
        cid = blob[at:at + 4]
        length = struct.unpack('>I', blob[at + 4:at + 8])[0]
        body = at + 8
        if body + length > len(blob):
            raise IlbmError('chunk %r at %d declares %d bytes and the file '
                            'has %d left' % (cid, at, length, len(blob) - body))
        chunks.append((cid, body, length))
        at = body + length
        if length & 1:          # the pad byte, which is not in the length
            at += 1
    return form_type, chunks, declared, at


def bmhd(blob, offset, length):
    if length < BMHD_LEN:
        raise IlbmError('BMHD is %d bytes and the header is %d'
                        % (length, BMHD_LEN))
    (w, h, x, y, planes, masking, compression, _pad,
     transparent, xasp, yasp, pagew, pageh) = struct.unpack(
        '>HHhhBBBBHBBhh', blob[offset:offset + BMHD_LEN])
    return {'width': w, 'height': h, 'x': x, 'y': y, 'planes': planes,
            'masking': masking, 'compression': compression,
            'transparent': transparent, 'xaspect': xasp, 'yaspect': yasp,
            'pagewidth': pagew, 'pageheight': pageh}


def unpackbits(blob, want):
    """ByteRun1, the PackBits rule, decoded to exactly `want` bytes.

    It stops the moment it has `want` and returns how many input bytes it ate,
    so a caller can check that the BODY was consumed and not merely sufficient.
    """
    out = bytearray()
    at = 0
    while len(out) < want:
        if at >= len(blob):
            raise IlbmError('ByteRun1 ran off the end with %d of %d bytes '
                            'decoded' % (len(out), want))
        n = blob[at]
        at += 1
        if n == 128:
            continue
        if n < 128:
            take = n + 1
            if at + take > len(blob):
                raise IlbmError('a literal run of %d wants bytes the chunk '
                                'does not have' % take)
            out.extend(blob[at:at + take])
            at += take
        else:
            if at >= len(blob):
                raise IlbmError('a repeat run has no byte to repeat')
            out.extend(bytes([blob[at]]) * (257 - n))
            at += 1
    return bytes(out[:want]), at


def rowbytes(width):
    """A plane row is padded to a WORD, which is where ceil(w/16)*2 comes from."""
    return ((width + 15) // 16) * 2


def deinterleave(rows, head):
    """Planar interleaved rows to one byte per pixel.

    The mask plane, when masking == 1, is read and DISCARDED here -- it is a
    transparency channel and not a colour bit, and folding it into the index
    would silently double the palette.
    """
    w, h, planes = head['width'], head['height'], head['planes']
    stride = rowbytes(w)
    per_row = stride * (planes + (1 if head['masking'] == 1 else 0))
    if len(rows) < per_row * h:
        raise IlbmError('the body holds %d bytes and %d x %d rows of %d '
                        'planes need %d' % (len(rows), h, planes, stride,
                                            per_row * h))
    pixels = bytearray(w * h)
    for y in range(h):
        base = y * per_row
        out = y * w
        for plane in range(planes):
            bit = 1 << plane
            start = base + plane * stride
            for byte_index in range(stride):
                byte = rows[start + byte_index]
                if not byte:
                    continue
                x0 = byte_index * 8
                for b in range(8):
                    if byte & (0x80 >> b):
                        x = x0 + b
                        if x < w:
                            pixels[out + x] |= bit
    return bytes(pixels)


def decode(blob):
    """The whole file, or an exception naming which arithmetic failed."""
    form_type, chunks, declared, end = walk(blob)
    seen = {}
    for cid, offset, length in chunks:
        seen.setdefault(cid, (offset, length))
    if b'BMHD' not in seen:
        raise IlbmError('no BMHD chunk')
    if b'BODY' not in seen:
        raise IlbmError('no BODY chunk')
    head = bmhd(blob, *seen[b'BMHD'])
    if head['planes'] < 1 or head['planes'] > 8:
        raise IlbmError('%d planes is outside this reader\'s range of 1..8'
                        % head['planes'])
    if head['compression'] not in (0, 1):
        raise IlbmError('compression %d is neither 0 (stored) nor 1 '
                        '(ByteRun1)' % head['compression'])

    palette = b''
    if b'CMAP' in seen:
        offset, length = seen[b'CMAP']
        palette = blob[offset:offset + length - (length % 3)]

    offset, length = seen[b'BODY']
    body = blob[offset:offset + length]
    planes = head['planes'] + (1 if head['masking'] == 1 else 0)
    want = rowbytes(head['width']) * planes * head['height']
    if head['compression'] == 0:
        if len(body) < want:
            raise IlbmError('a stored BODY of %d bytes cannot fill %d'
                            % (len(body), want))
        rows, eaten = body[:want], want
    else:
        if form_type == b'PBM ':
            want = head['width'] * head['height']
        rows, eaten = unpackbits(body, want)

    if form_type == b'PBM ':
        pixels = rows[:head['width'] * head['height']]
    else:
        pixels = deinterleave(rows, head)

    return {'form_type': form_type, 'declared': declared, 'end': end,
            'residue': len(blob) - end, 'chunks': chunks, 'head': head,
            'palette': palette, 'body_declared': length, 'body_eaten': eaten,
            'body_want': want, 'pixels': pixels}


def write_png(path, width, height, pixels, palette):
    """8-bit indexed PNG, written with zlib and no image library.

    `px.write_png` in this box does the same job and is NOT reused, for one
    reason worth writing down: it calls `px.to_rgb`, which expands six-bit VGA
    DAC values to eight. **An ILBM CMAP is already eight-bit**, so passing one
    through that expansion would darken every colour by masking off its top
    two bits. The shared thing between the two tools is the PNG grammar, which
    is fifteen lines; the unshared thing is the palette depth, which is the
    whole point.
    """
    raw = bytearray()
    for row in range(height):
        raw.append(0)
        raw.extend(pixels[row * width:(row + 1) * width])

    def chunk(tag, payload):
        body = tag + payload
        return (struct.pack('>I', len(payload)) + body
                + struct.pack('>I', zlib.crc32(body) & 0xFFFFFFFF))

    plte = bytearray(palette)
    while len(plte) < 3 * 256:
        plte.extend(b'\x00\x00\x00')
    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 3, 0, 0, 0))
    png += chunk(b'PLTE', bytes(plte[:3 * 256]))
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    png += chunk(b'IEND', b'')
    with open(path, 'wb') as handle:
        handle.write(png)


RAMP = ' .:-=+*#%@'


def ascii_art(pixels, width, height, palette, cols=96, aspect=2.1, ink=False):
    """The picture as characters, so that a text-only repository can show it.

    THIS REPOSITORY PUBLISHES `README`, `docs/`, `notes/`, `tools/` AND
    NOTHING ELSE, which has meant for nine objects that a chapter about
    pictures could describe them and not show them. This is the cheapest
    honest way round that: box-average the indices down to a character grid
    and print one character per cell, chosen by the LUMINANCE of the palette
    entry, so what a reader sees is the drawing and not an index map.

    THERE ARE TWO CELL RULES AND WHICH ONE IS RIGHT DEPENDS ON THE REDUCTION,
    which is worth saying because getting it wrong twice is how this function
    reached its present shape.

      * the MEAN of the cell is the default, and is right whenever the
        picture is being reduced a lot. A 640-wide screen at 104 characters
        is six pixels to a cell.
      * `ink=True` takes the DARKEST pixel in the cell instead, which keeps
        one-pixel black outlines that a mean would average away. It is right
        at or near one character per pixel -- a 64-wide playing card at 64
        columns -- and it SATURATES at large reductions, because once every
        cell contains one outline pixel every cell is black.

    Then the cell values are stretched over the range they actually occupy
    before they are mapped to characters, because a picture drawn in sixteen
    mid-tones uses about a third of the ramp otherwise.

    And the ramp is INK: a dark pixel becomes a dense character. Indexing it
    by luminance rather than by 1 - luminance prints the negative, which is
    how the first run of this came out.

    It is a rendering and it says so. Two colours of equal luminance collapse
    to the same character, `aspect` is a fudge for the fact that a terminal
    cell is about twice as tall as it is wide, and no argument in any chapter
    rests on one of these. The commands that made them are printed beside
    them and the PNG is one flag away.
    """
    rgb = bytearray(palette)
    while len(rgb) < 3 * 256:
        rgb.extend(b'\x00\x00\x00')
    luma = [(0.299 * rgb[i * 3] + 0.587 * rgb[i * 3 + 1]
             + 0.114 * rgb[i * 3 + 2]) / 255.0 for i in range(256)]
    cols = max(1, min(cols, width))
    scale = width / float(cols)
    rows = max(1, int(round(height / (scale * aspect))))
    cells = []
    for row in range(rows):
        y0 = int(row * height / rows)
        y1 = max(y0 + 1, int((row + 1) * height / rows))
        line = []
        for col in range(cols):
            x0 = int(col * width / cols)
            x1 = max(x0 + 1, int((col + 1) * width / cols))
            total = count = 0
            darkest = 1.0
            for y in range(y0, y1):
                base = y * width
                for x in range(x0, x1):
                    value = luma[pixels[base + x]]
                    total += value
                    count += 1
                    if value < darkest:
                        darkest = value
            line.append(darkest if ink
                        else (total / count if count else 0.0))
        cells.append(line)

    flat = [v for line in cells for v in line]
    low, high = min(flat), max(flat)
    span = (high - low) or 1.0
    top = len(RAMP) - 1
    return [''.join(RAMP[top - min(top, int((v - low) / span * len(RAMP)))]
                    for v in line)
            for line in cells]


def gather(args):
    """The population, selected by MAGIC and never by name."""
    if args.recurse:
        found = []
        for root, _dirs, names in os.walk(args.recurse):
            for name in sorted(names):
                path = os.path.join(root, name)
                try:
                    with open(path, 'rb') as handle:
                        if is_ilbm(handle.read(12)):
                            found.append(path)
                except OSError:
                    continue
        return found
    return [dirguard.want_file(p, 'ilbm') for p in args.files]


def make_form(chunks, form_type=b'ILBM'):
    """Build a FORM out of (id, payload) pairs, pad byte and all."""
    body = bytearray(form_type)
    for cid, payload in chunks:
        body.extend(cid)
        body.extend(struct.pack('>I', len(payload)))
        body.extend(payload)
        if len(payload) & 1:
            body.append(0)
    return FORM + struct.pack('>I', len(body)) + bytes(body)


def make_bmhd(w, h, planes, compression=0, masking=0):
    return struct.pack('>HHhhBBBBHBBhh', w, h, 0, 0, planes, masking,
                       compression, 0, 0, 1, 1, w, h)


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the magic is structural, and the cheap version is shown to be wrong -
    want('FORM alone is not enough', is_ilbm(b'FORM' + b'\x00' * 8), False)
    want('FORM + length + ILBM is', is_ilbm(b'FORM\x00\x00\x00\x04ILBM'), True)
    want('PBM  is accepted as a form type',
         is_ilbm(b'FORM\x00\x00\x00\x04PBM '), True)
    want('four letters in the middle of a file are not a FORM',
         is_ilbm(b'xxFORM\x00\x00\x00\x04ILBM'), False)

    # -- the pad byte, which is the thing IFF readers get wrong -------------
    odd = make_form([(b'ODDC', b'abc'), (b'NEXT', b'wxyz')])
    _t, chunks, _d, _e = walk(odd)
    want('an odd chunk is followed by a pad byte and the walk survives it',
         [c[0] for c in chunks], [b'ODDC', b'NEXT'])
    want('the pad byte is not counted in the declared length',
         chunks[0][2], 3)

    # -- the FORM length is checked against the file, signed ----------------
    _t, _c, declared, end = walk(odd)
    want('a well-formed FORM closes at residue zero', len(odd) - end, 0)
    want('8 + declared is the file length', 8 + declared, len(odd))

    # -- ByteRun1, on bytes made here ---------------------------------------
    want('a literal run copies n+1 bytes', unpackbits(b'\x02abc', 3)[0], b'abc')
    want('a repeat run repeats 257-n times',
         unpackbits(b'\xfeA', 3)[0], b'AAA')
    want('128 is a no-operation',
         unpackbits(b'\x80\x02abc', 3)[0], b'abc')
    want('literals and repeats interleave',
         unpackbits(b'\x00a\xffB\x00c', 4)[0], b'aBBc')
    try:
        unpackbits(b'\x02ab', 3)
        checks.append(('a truncated literal run raises', False, 'it did not'))
    except IlbmError:
        checks.append(('a truncated literal run raises', True, ''))

    # -- a whole picture, built here and read back --------------------------
    # two planes, 16 x 2, so that the row stride is exactly one WORD and the
    # plane bits have to be combined to make index 3.
    plane_rows = bytearray()
    for _y in range(2):
        plane_rows.extend(b'\xff\x00')     # plane 0 set on the left half
        plane_rows.extend(b'\x0f\x00')     # plane 1 set on the second nibble
    tiny = make_form([
        (b'BMHD', make_bmhd(16, 2, 2)),
        (b'CMAP', bytes([0, 0, 0, 17, 17, 17, 34, 34, 34, 51, 51, 51])),
        (b'BODY', bytes(plane_rows)),
    ])
    got = decode(tiny)
    want('the built picture closes at residue zero', got['residue'], 0)
    want('BMHD is read back', (got['head']['width'], got['head']['height'],
                               got['head']['planes']), (16, 2, 2))
    want('CMAP is four entries', len(got['palette']) // 3, 4)
    want('plane 0 alone gives index 1', got['pixels'][0], 1)
    want('plane 0 and plane 1 together give index 3', got['pixels'][4], 3)
    want('neither plane gives index 0', got['pixels'][8], 0)
    want('the second row decodes the same as the first',
         got['pixels'][16:32], got['pixels'][0:16])

    # -- the same picture, compressed, must decode identically --------------
    packed = bytearray()
    for _y in range(2):
        packed.extend(b'\x01\xff\x00')    # plane 0 row, as two literals
        packed.extend(b'\x01\x0f\x00')    # plane 1 row
    small = make_form([
        (b'BMHD', make_bmhd(16, 2, 2, compression=1)),
        (b'BODY', bytes(packed)),
    ])
    want('a ByteRun1 body decodes to the same pixels',
         decode(small)['pixels'], got['pixels'])

    # -- the mask plane is read and discarded, not folded into the index ----
    masked_rows = bytearray()
    for _y in range(2):
        masked_rows.extend(b'\xff\x00')   # plane 0
        masked_rows.extend(b'\x0f\x00')   # plane 1
        masked_rows.extend(b'\xff\xff')   # the mask, all opaque
    masked = make_form([
        (b'BMHD', make_bmhd(16, 2, 2, masking=1)),
        (b'BODY', bytes(masked_rows)),
    ])
    want('a mask plane does not become a colour bit',
         decode(masked)['pixels'], got['pixels'])

    # -- THE SPECIMENS THAT MUST FAIL ---------------------------------------
    def must_raise(label, blob):
        try:
            decode(blob)
            checks.append((label, False, 'it decoded'))
        except IlbmError:
            checks.append((label, True, ''))

    must_raise('a FORM with no BMHD is refused',
               make_form([(b'BODY', b'\x00' * 8)]))
    must_raise('a FORM with no BODY is refused',
               make_form([(b'BMHD', make_bmhd(16, 2, 2))]))
    must_raise('a short BODY is refused rather than zero-padded',
               make_form([(b'BMHD', make_bmhd(16, 2, 2)),
                          (b'BODY', b'\x00' * 4)]))
    must_raise('an unknown compression is refused',
               make_form([(b'BMHD', make_bmhd(16, 2, 2, compression=9)),
                          (b'BODY', b'\x00' * 8)]))
    must_raise('nine planes is refused rather than guessed at',
               make_form([(b'BMHD', make_bmhd(16, 2, 9)),
                          (b'BODY', b'\x00' * 72)]))
    must_raise('a chunk longer than the file is refused',
               FORM + struct.pack('>I', 40) + b'ILBM' + b'BODY'
               + struct.pack('>I', 4096))

    # -- the row stride, which is the other thing readers get wrong ---------
    want('a 640-wide row is 80 bytes', rowbytes(640), 80)
    want('a 17-wide row is padded to 4 bytes', rowbytes(17), 4)
    want('a 16-wide row is 2 bytes', rowbytes(16), 2)
    want('a 1-wide row is 2 bytes', rowbytes(1), 2)

    # -- dirguard is wired in -----------------------------------------------
    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def report(path, got):
    head = got['head']
    print('%s' % os.path.basename(path))
    print('  form type            : %s' % got['form_type'].decode('ascii'))
    print('  FORM length declared : %d   8 + it = %d'
          % (got['declared'], 8 + got['declared']))
    print('  walk ended at        : %d   residue against the file : %+d'
          % (got['end'], got['residue']))
    print('  chunks               : %s'
          % ' '.join(c[0].decode('ascii', 'replace') for c in got['chunks']))
    print('  geometry             : %d x %d, %d planes, compression %d, '
          'masking %d' % (head['width'], head['height'], head['planes'],
                          head['compression'], head['masking']))
    print('  colours declared     : %d planes = %d indices'
          % (head['planes'], 1 << head['planes']))
    print('  CMAP entries         : %d' % (len(got['palette']) // 3))
    print('  BODY declared        : %d   needed : %d   eaten : %d'
          % (got['body_declared'], got['body_want'], got['body_eaten']))
    print('  pixels               : %d = %d x %d'
          % (len(got['pixels']), head['width'], head['height']))


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*')
    ap.add_argument('--recurse', metavar='DIR',
                    help='walk DIR and select files by the FORM/ILBM structure')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--render', action='store_true')
    ap.add_argument('--palette-report', action='store_true')
    ap.add_argument('--ascii', action='store_true',
                    help='print the picture as characters, for a text-only '
                         'repository')
    ap.add_argument('--cols', type=int, default=96,
                    help='width of the --ascii rendering, in characters')
    ap.add_argument('--ink', action='store_true',
                    help='take each cell\'s darkest pixel instead of its '
                         'mean; keeps one-pixel outlines near 1:1, saturates '
                         'at large reductions')
    ap.add_argument('--out', default=None)
    ap.add_argument('--crop', metavar='X,Y,W,H',
                    help='render only this rectangle of the picture')
    ap.add_argument('--zoom', type=int, default=1,
                    help='magnify the rendered pixels by nearest neighbour')
    ap.add_argument('--name', default=None,
                    help='suffix for a cropped rendering, so that two crops '
                         'of one file do not overwrite each other')
    ap.add_argument('--expect', type=int, default=None,
                    help='fail unless exactly this many files were opened')
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

    opened = clean = 0
    failures = []
    geometry = collections.Counter()

    for path in paths:
        with open(path, 'rb') as handle:
            blob = handle.read()
        try:
            got = decode(blob)
        except IlbmError as exc:
            failures.append('%s: %s' % (os.path.basename(path), exc))
            print('FAIL  %s: %s' % (os.path.basename(path), exc))
            continue
        opened += 1
        clean += got['residue'] == 0
        head = got['head']
        geometry['%dx%dx%d' % (head['width'], head['height'],
                               head['planes'])] += 1
        if args.validate or args.census:
            report(path, got)
        if args.palette_report:
            pal = got['palette']
            print('  palette, %d entries, eight-bit:' % (len(pal) // 3))
            for i in range(len(pal) // 3):
                print('    %3d  %3d %3d %3d   #%02x%02x%02x'
                      % (i, pal[i * 3], pal[i * 3 + 1], pal[i * 3 + 2],
                         pal[i * 3], pal[i * 3 + 1], pal[i * 3 + 2]))
        if args.ascii:
            pixels, wide, tall = got['pixels'], head['width'], head['height']
            if box:
                pixels, wide, tall = px.crop_zoom(pixels, head['width'],
                                                  head['height'], box, 1)
            print('')
            for line in ascii_art(pixels, wide, tall, got['palette'],
                                  args.cols, ink=args.ink):
                print('  %s' % line)
            print('')
        if args.render:
            stem = os.path.splitext(os.path.basename(path))[0]
            pixels, wide, tall = got['pixels'], head['width'], head['height']
            if box or args.zoom > 1:
                pixels, wide, tall = px.crop_zoom(pixels, head['width'],
                                                  head['height'], box,
                                                  args.zoom)
                stem += '-%s' % (args.name or 'crop')
            out = os.path.join(args.out, stem + '.png')
            write_png(out, wide, tall, pixels, got['palette'])
            print('  wrote %s  %d x %d' % (os.path.basename(out), wide, tall))

    print('')
    print('files selected by magic : %d' % len(paths))
    print('opened                  : %d' % opened)
    print('residue zero            : %d of %d' % (clean, opened))
    for shape, count in sorted(geometry.items()):
        print('  geometry %-14s %d' % (shape, count))
    if failures:
        print('FAILURES                : %d' % len(failures))
        for line in failures:
            print('  %s' % line)
    if args.expect is not None and opened != args.expect:
        raise SystemExit('ilbm: --expect %d but %d files opened'
                         % (args.expect, opened))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
