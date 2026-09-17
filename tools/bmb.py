#!/usr/bin/env python3
"""bmb.py -- a reader for the two picture formats of BIANCO NATALE (Tecnoart
Software Development, Genova, 1994): `.BMB`, one 8-bit image, and `.BMA`, a
strip of N frames.

THE GRAMMAR, AND WHERE THE HEADER ENDS
--------------------------------------
    .BMB                                  .BMA
    +0  u16  width                        +0  u16  width
    +2  u16  height                       +2  u16  height
    +4  u8   'y' or 'n'                   +4  u8   'y' or 'n'
    +5  width x height pixels             +5  u16  count
                                          +7  count x width x height pixels
    768 bytes of 6-bit VGA palette, IF the flag byte is 'y'
    4 bytes: two u16                      6 bytes: three u16

    5 + w*h + (768 if 'y') + 4 == size    7 + n*w*h + (768 if 'y') + 6 == size

The flag byte is the ASCII letter for yes or no, and it agrees with the
presence of the palette on 16 of 16 files in the object. The closure holds at
residue zero on 12 of 12 `.BMB` and 4 of 4 `.BMA`.

**The closure does not say where the header ends.** A 9-byte header with the
pixels at +9 and nothing after the palette closes the same 64,777 bytes as a
5-byte header with a 4-byte trailer, and the pre-briefing for this object read
it the first way. Two measurements that the length cannot make settle it:

  * a VGA palette is 256 triplets, and 4 is not a multiple of 3, so the two
    readings put the triplet boundaries in different places. At `5 + w*h`,
    BCOUNTRY.BMB has 54 entries with r == g == b (a grey ramp) and entry 0 is
    (0,0,0) on 11 of 12 palettes; at `9 + w*h` it has 10 and entry 0 is black
    on 0 of 12. `--palette` prints both;
  * the byte value 0x00 never occurs among the 195,840 pixels of STORY.BMA,
    and the six bytes at the end of that file are six zeros. Under the long
    header those six would be the last six pixels of frame 20 -- the only
    zeros in the picture, in its bottom-right corner.

And the trailer is not padding: on COUNTRY.BMA it reads `(33, 1, 6)` as three
u16, and frame 0 of that file sits on BCOUNTRY.BMB at **x = 33, y = 1** with
24 of 46,046 pixels differing (`--fit`). The first two words are a screen
position. The third, and both words of the `.BMB` trailer (0, 0 on all
twelve), are not identified.

WHAT THIS TOOL SELECTS BY
-------------------------
The closure, never the name. A file is accepted when one of the two
arithmetics above lands on its last byte AND every palette byte, if there is a
palette, is <= 0x3F. `BN.EXE` fails on its flag byte (0x5F) and would fail
on its width (0x5A4D) after that. `FONT8X12.FNT` fails on its flag byte
(0x01). A `.BMB` with one byte appended or removed is
refused, and `--selftest` proves that with a positive control.

The bucket is DERIVED: nobody published this format; the producer's only
description of it is the symbol names its linker left in `BN.EXE`'s slack --
`_BMBimage_in`, `_readBMP`, `save_pal`, `x_bob`, `y_bob` -- and a name in a
symbol table is not a specification.

    python tools/bmb.py Bianco-Natale/BACK1.BMB               (--validate)
    python tools/bmb.py Bianco-Natale/BN.BMA --census
    python tools/bmb.py Bianco-Natale/BN.BMA --frames
    python tools/bmb.py Bianco-Natale/BACK1.BMB --palette
    python tools/bmb.py Bianco-Natale/COUNTRY.BMA --fit Bianco-Natale/BCOUNTRY.BMB
    python tools/bmb.py Bianco-Natale/STORY.BMA --extract --out _work/png \\
        --palette-from Bianco-Natale/B_STORY.BMB
    python tools/bmb.py --selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard
import px

FLAG_Y = 0x79
FLAG_N = 0x6E
PALETTE = 768
VGA_MAX = 0x3F
HDR_BMB = 5
HDR_BMA = 7
TRAIL_BMB = 4
TRAIL_BMA = 6
# A screen is 320 x 200 and a mouse cursor is 21 x 23; nothing this format was
# written for is wider than one VGA screen. The bound is what keeps a random
# five bytes from being accepted as a header by a head-reading classifier.
MAX_SIDE = 1024
MAX_FRAMES = 4096


class BmbError(Exception):
    """A file this reader will not pretend to understand."""


def _closure(w, h, flag, count, kind):
    pal = PALETTE if flag == FLAG_Y else 0
    if kind == 'BMB':
        return HDR_BMB + w * h + pal + TRAIL_BMB
    return HDR_BMA + count * w * h + pal + TRAIL_BMA


def parse(blob):
    """The record, by the closure. Raises BmbError with both residues."""
    size = len(blob)
    if size < HDR_BMA + TRAIL_BMA:
        raise BmbError('%d bytes is too short for either header' % size)
    w, h = struct.unpack_from('<HH', blob, 0)
    flag = blob[4]
    if flag not in (FLAG_Y, FLAG_N):
        raise BmbError("the flag byte at +4 is 0x%02X, not 'y' or 'n'" % flag)
    if not (1 <= w <= MAX_SIDE and 1 <= h <= MAX_SIDE):
        raise BmbError('%d x %d is not a picture this format was written for'
                       % (w, h))
    count = struct.unpack_from('<H', blob, 5)[0]
    want_bmb = _closure(w, h, flag, 1, 'BMB')
    want_bma = _closure(w, h, flag, count, 'BMA') if count else None
    if want_bmb == size:
        kind, count, hdr, trail = 'BMB', 1, HDR_BMB, TRAIL_BMB
    elif want_bma == size:
        kind, hdr, trail = 'BMA', HDR_BMA, TRAIL_BMA
    else:
        raise BmbError('neither closure lands on the last byte: as .BMB %d x '
                       '%d wants %d (residue %+d); as .BMA with count %d wants '
                       '%s (residue %s)'
                       % (w, h, want_bmb, want_bmb - size, count,
                          want_bma if want_bma else '-',
                          '%+d' % (want_bma - size) if want_bma else '-'))
    pal = PALETTE if flag == FLAG_Y else 0
    pixels_at = hdr
    pixels_end = hdr + count * w * h
    palette_at = pixels_end if pal else None
    trailer_at = pixels_end + pal
    trailer = blob[trailer_at:]
    return {'kind': kind, 'w': w, 'h': h, 'flag': chr(flag), 'count': count,
            'size': size, 'header': hdr, 'pixels_at': pixels_at,
            'pixels_end': pixels_end, 'palette_at': palette_at,
            'trailer_at': trailer_at, 'trailer': trailer,
            'trailer_words': struct.unpack('<%dH' % (len(trailer) // 2),
                                           trailer)}


def palette(blob, rec):
    if rec['palette_at'] is None:
        return None
    return blob[rec['palette_at']:rec['palette_at'] + PALETTE]


def validate(blob):
    """parse(), plus the palette legality the closure cannot see."""
    rec = parse(blob)
    pal = palette(blob, rec)
    if pal is not None and max(pal) > VGA_MAX:
        raise BmbError('the flag says y but the 768 bytes after the pixels '
                       'hold 0x%02X, which no 6-bit VGA palette does'
                       % max(pal))
    rec['palette_legal'] = pal is not None
    return rec


def looks_like(blob):
    try:
        validate(blob)
        return True
    except BmbError:
        return False


def looks_like_head(head, size=None):
    """The same magic on as much of the file as a classifier reads.

    `coverage.py` hands a probe the first 4,096 bytes, and a 320 x 200 `.BMB`
    is 64,777. A head cannot see the closure, the palette or the trailer.
    What it can see is five bytes -- two sides within a VGA screen and a flag
    byte that is the letter y or n -- and that is a **weaker warrant than
    `--validate`**, stated here rather than papered over.

    When the classifier also passes the file's length, one closure or the
    other must land on it, which decides .BMB against .BMA and is the second
    of the three checks `--validate` makes. When the whole file fits in the
    head, all three are made.
    """
    if len(head) < HDR_BMA + TRAIL_BMA:
        return False
    if size is not None and size <= len(head):
        return looks_like(head[:size])
    w, h = struct.unpack_from('<HH', head, 0)
    if head[4] not in (FLAG_Y, FLAG_N):
        return False
    if not (1 <= w <= MAX_SIDE and 1 <= h <= MAX_SIDE):
        return False
    if size is None:
        # Five bytes and nothing else: the head-only warrant.
        return True
    count = struct.unpack_from('<H', head, 5)[0]
    if _closure(w, h, head[4], 1, 'BMB') == size:
        return True
    return 1 <= count <= MAX_FRAMES and _closure(w, h, head[4], count,
                                                 'BMA') == size


def frames(blob, rec):
    n = rec['w'] * rec['h']
    at = rec['pixels_at']
    return [blob[at + i * n:at + (i + 1) * n] for i in range(rec['count'])]


def greys(pal):
    return sum(1 for i in range(256)
               if pal[3 * i] == pal[3 * i + 1] == pal[3 * i + 2])


def alignment(blob, rec):
    """The palette read where the closure puts it, against the last 768 bytes.

    Returns (greys_here, greys_last, entry0_here, entry0_last, entry255_here).
    On a .BMB the two windows are four bytes apart, which is not a multiple of
    three, so exactly one of them has the triplets aligned. On a .BMA they are
    six apart and the test cannot tell them apart; it is printed anyway so the
    reader sees that it cannot.
    """
    pal = palette(blob, rec)
    if pal is None:
        return None
    last = blob[-PALETTE:]
    return (greys(pal), greys(last), tuple(pal[0:3]), tuple(last[0:3]),
            tuple(pal[765:768]))


def index_ranges(used):
    out = []
    start = prev = used[0]
    for i in used[1:]:
        if i == prev + 1:
            prev = i
            continue
        out.append((start, prev))
        start = prev = i
    out.append((start, prev))
    return ' '.join('%d' % a if a == b else '%d-%d' % (a, b) for a, b in out)


def frame_diffs(fr, w):
    """(differing pixels, x0, x1, y0, y1) between consecutive frames."""
    out = []
    for i in range(len(fr) - 1):
        a, b = fr[i], fr[i + 1]
        xs, ys, n = [], [], 0
        for p in range(len(a)):
            if a[p] != b[p]:
                n += 1
                xs.append(p % w)
                ys.append(p // w)
        out.append((n, min(xs), max(xs), min(ys), max(ys)) if n
                   else (0, -1, -1, -1, -1))
    return out


def best_fit(frame, fw, fh, back, bw, bh):
    """The (differing, x, y) where `frame` matches `back` best. Exhaustive."""
    best = None
    for y in range(bh - fh + 1):
        for x in range(bw - fw + 1):
            diff = 0
            for r in range(fh):
                a = frame[r * fw:(r + 1) * fw]
                b = back[(y + r) * bw + x:(y + r) * bw + x + fw]
                if a != b:
                    diff += sum(1 for p, q in zip(a, b) if p != q)
                    if best is not None and diff >= best[0]:
                        break
            if best is None or diff < best[0]:
                best = (diff, x, y)
    return best


def read(path, who='bmb'):
    real = dirguard.want_file(path, who)
    with open(real, 'rb') as handle:
        blob = handle.read()
    try:
        rec = validate(blob)
    except BmbError as exc:
        raise BmbError('%s: %s' % (os.path.basename(real), exc))
    return real, blob, rec


# ---------------------------------------------------------------- selftest --

# The object-dependent block, declared here and verified wherever the object
# is reachable, so that the skip figure printed in a repository without the
# object cannot drift (the sixth standing rule, pc-hexxagon-doc/docs/10).
OBJECT_REL = 'Bianco-Natale'
OBJECT_CHECKS = 14


def _synthetic_bmb(w=3, h=2, with_palette=True, trailer=(0, 0)):
    pix = bytes(range(w * h))
    pal = bytes((i % 64) for i in range(PALETTE)) if with_palette else b''
    flag = b'y' if with_palette else b'n'
    return (struct.pack('<HH', w, h) + flag + pix + pal
            + struct.pack('<HH', *trailer))


def _synthetic_bma(w=2, h=2, count=3, with_palette=False, trailer=(5, 7, 9)):
    pix = bytes((i * 7) % 256 for i in range(count * w * h))
    pal = bytes((i % 64) for i in range(PALETTE)) if with_palette else b''
    flag = b'y' if with_palette else b'n'
    return (struct.pack('<HH', w, h) + flag + struct.pack('<H', count) + pix
            + pal + struct.pack('<HHH', *trailer))


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    def refused(label, blob, needle):
        try:
            validate(blob)
            checks.append((label, False, 'it parsed'))
        except BmbError as exc:
            ok = needle in str(exc)
            checks.append((label, ok, '' if ok else 'said %r' % str(exc)))

    # -- the two closures on files built here -----------------------------
    b = _synthetic_bmb()
    rec = validate(b)
    want('a 3 x 2 .BMB with a palette closes at 5 + 6 + 768 + 4',
         [rec['kind'], rec['size'], rec['w'], rec['h'], rec['count']],
         ['BMB', 783, 3, 2, 1])
    want('its pixels start at +5, not +9', rec['pixels_at'], 5)
    want('its palette starts right after the pixels', rec['palette_at'], 11)
    want('and the four bytes after the palette are the trailer',
         rec['trailer_words'], (0, 0))
    b = _synthetic_bmb(with_palette=False)
    want('a .BMB whose flag is n closes without a palette',
         [validate(b)['size'], validate(b)['palette_at']], [15, None])
    a = _synthetic_bma()
    rec = validate(a)
    want('a 2 x 2 x 3 .BMA closes at 7 + 12 + 6',
         [rec['kind'], rec['size'], rec['count'], rec['pixels_at']],
         ['BMA', 25, 3, 7])
    want('its six trailing bytes read as three u16',
         rec['trailer_words'], (5, 7, 9))
    want('frames() cuts the strip into count pieces of w x h',
         [len(frames(a, rec)), len(frames(a, rec)[0])], [3, 4])
    a = _synthetic_bma(with_palette=True)
    want('a .BMA with a palette puts it after the last frame',
         validate(a)['palette_at'], 7 + 12)

    # -- the refusals, which are the selection -----------------------------
    refused('a .BMB with one byte APPENDED is refused',
            _synthetic_bmb() + b'\x00', 'neither closure')
    refused('a .BMB with one byte REMOVED is refused',
            _synthetic_bmb()[:-1], 'neither closure')
    refused('a flag byte that is not y or n is refused',
            b'\x03\x00\x02\x00x' + bytes(6 + 4), 'flag byte')
    refused('a palette byte above 0x3F is refused',
            _synthetic_bmb()[:11] + b'\x40' + _synthetic_bmb()[12:],
            'no 6-bit VGA palette')
    refused('an MZ header is refused on its width',
            b'MZ\x36\x01y' + bytes(100), 'not a picture')
    # 3 x 3 and not 2 x 2: a 13-byte file whose header says 2 x 2 and n IS
    # a .BMB (5 + 4 + 4), which the first draft of this check forgot.
    refused('a .BMA whose count is zero is refused',
            struct.pack('<HH', 3, 3) + b'n' + struct.pack('<H', 0) + bytes(6),
            'neither closure')
    refused('a file shorter than any header is refused', b'\x01\x00\x01',
            'too short')
    want('a 9,216-byte font-shaped blob is not a picture',
         looks_like(bytes([1]) * 9216), False)

    # -- the head-reading magic, and its weaker warrant --------------------
    b = _synthetic_bmb()
    want('the whole file in the head: all three checks are made',
         looks_like_head(b, len(b)), True)
    want('a broken file in the head is refused with the length',
         looks_like_head(b + b'\x00', len(b) + 1), False)
    big = b'\x40\x01\xc8\x00y' + bytes(4091)
    want('a 320 x 200 head with no length passes on five bytes only',
         looks_like_head(big), True)
    want('the same head WITH the length closes as a .BMB at 64,777',
         looks_like_head(big, 64777), True)
    want('and is refused with a length one byte off',
         looks_like_head(big, 64778), False)
    strip = b'\x39\x00\x30\x00y\x56\x00' + bytes(4089)
    want('a 57 x 48 head with count 86 closes as a .BMA at 236,077',
         looks_like_head(strip, 236077), True)
    want('an MZ head is refused on its width',
         looks_like_head(b'MZ\x36\x01y' + bytes(4000), 70157), False)
    want('a font head is refused on its flag byte',
         looks_like_head(bytes([1]) * 4096, 9216), False)

    # -- the palette-alignment test, on a palette built here ---------------
    grey = bytes(v for i in range(256) for v in (i % 64, i % 64, i % 64))
    aligned = struct.pack('<HH', 2, 2) + b'y' + bytes(4) + grey + bytes(4)
    rec = validate(aligned)
    g_here, g_last, e0_here, e0_last, _e255 = alignment(aligned, rec)
    want('a grey-ramp palette shows 256 greys at the closure\'s window',
         g_here, 256)
    want('and fewer at the last-768-bytes window, four bytes later',
         g_last < 256, True)

    # -- and against the object, if it is beside the box -------------------
    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isdir(obj):
        before = len(checks)

        def load(name):
            with open(os.path.join(obj, name), 'rb') as handle:
                blob = handle.read()
            return blob, validate(blob)

        names = sorted(n for n in os.listdir(obj)
                       if n.upper().endswith(('.BMB', '.BMA')))
        closed = 0
        agree = 0
        black0 = 0
        pals = 0
        for n in names:
            blob, rec = load(n)
            closed += 1
            pal = palette(blob, rec)
            agree += (rec['flag'] == 'y') == (pal is not None)
            if pal is not None:
                pals += 1
                black0 += tuple(pal[0:3]) == (0, 0, 0)
        want('16 picture files, and 16 of 16 close at residue zero',
             [len(names), closed], [16, 16])
        want('the y/n flag agrees with the palette on 16 of 16', agree, 16)
        want('12 palettes, and entry 0 is black on 11 of them',
             [pals, black0], [12, 11])
        blob, rec = load('POINTER.BMB')
        want('POINTER.BMB is 21 x 23, flag n, and closes at 492 with the '
             'four-byte trailer',
             [rec['w'], rec['h'], rec['flag'], rec['size'],
              rec['trailer_words']], [21, 23, 'n', 492, (0, 0)])
        blob, rec = load('BACK1.BMB')
        want('BACK1.BMB is a 320 x 200 screen with a palette',
             [rec['w'], rec['h'], rec['flag'], rec['palette_at']],
             [320, 200, 'y', 64005])
        blob, rec = load('BN.BMA')
        want('BN.BMA is 86 frames of 57 x 48 with its own palette',
             [rec['count'], rec['w'], rec['h'], rec['flag']],
             [86, 57, 48, 'y'])
        want('and its frames use indices 0..31 and nothing else',
             max(max(f) for f in frames(blob, rec)), 31)
        blob, rec = load('COUNTRY.BMA')
        want('COUNTRY.BMA is 4 frames of 286 x 161 and its trailer is '
             '(33, 1, 6)', [rec['count'], rec['w'], rec['h'],
                            rec['trailer_words']], [4, 286, 161, (33, 1, 6)])
        blob, rec = load('STORY.BMA')
        want('the byte 0x00 never occurs among STORY.BMA\'s 195,840 pixels',
             [len(blob[rec['pixels_at']:rec['pixels_end']]),
              blob[rec['pixels_at']:rec['pixels_end']].count(0)],
             [195840, 0])
        want('so its six trailing zeros are a trailer and not pixels',
             rec['trailer'], bytes(6))
        blob, rec = load('BCOUNTRY.BMB')
        g_here, g_last, e0_here, e0_last, _e255 = alignment(blob, rec)
        want('BCOUNTRY.BMB: 54 greys at the closure\'s window, 10 at the '
             'other', [g_here, g_last], [54, 10])
        want('and entry 0 is black there and not at the other',
             [e0_here, e0_last], [(0, 0, 0), (6, 6, 10)])
        # The two files in the directory that are not pictures.
        with open(os.path.join(obj, 'BN.EXE'), 'rb') as handle:
            exe = handle.read()
        with open(os.path.join(obj, 'FONT8X12.FNT'), 'rb') as handle:
            fnt = handle.read()
        want('BN.EXE is refused', looks_like(exe), False)
        want('FONT8X12.FNT is refused', looks_like(fnt), False)
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((OBJECT_CHECKS,
                        '%s not beside the box; pass --object DIR to run '
                        'them' % OBJECT_REL))

    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))
    checks.append(('nameguard.guard is imported',
                   hasattr(nameguard, 'guard'), ''))

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    for count, why in skipped:
        print('  %-*s  SKIP   %d checks: %s' % (width, '(object block)',
                                                count, why))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    lost = sum(count for count, _why in skipped)
    print('%d checks, %d failures, %d skipped' % (len(checks), bad, lost))
    return 1 if bad else 0


# -------------------------------------------------------------------- main --

def cmd_validate(path, blob, rec):
    pal = PALETTE if rec['flag'] == 'y' else 0
    print('%s' % os.path.basename(path))
    print('  kind                      : .%s' % rec['kind'])
    print('  file bytes                : %d' % rec['size'])
    print('  width x height            : %d x %d' % (rec['w'], rec['h']))
    print('  flag byte                 : %r' % rec['flag'])
    if rec['kind'] == 'BMA':
        print('  frames                    : %d' % rec['count'])
    print('  header                    : %d bytes' % rec['header'])
    print('  pixels                    : %d .. %d  (%d bytes)'
          % (rec['pixels_at'], rec['pixels_end'],
             rec['pixels_end'] - rec['pixels_at']))
    if pal:
        print('  palette                   : %d .. %d  (768 bytes, every byte '
              '<= 0x3F)' % (rec['palette_at'], rec['palette_at'] + PALETTE))
    else:
        print('  palette                   : none, as the flag says')
    print('  trailer                   : %d .. %d  %s = u16 %s'
          % (rec['trailer_at'], rec['size'],
             ' '.join('%02x' % x for x in rec['trailer']),
             rec['trailer_words']))
    print('  %d + %d + %d + %d       : %d' % (
        rec['header'], rec['pixels_end'] - rec['pixels_at'], pal,
        len(rec['trailer']), rec['size']))
    print('  RESIDUE                   : +0')


def cmd_census(path, blob, rec):
    fr = frames(blob, rec)
    allpix = blob[rec['pixels_at']:rec['pixels_end']]
    hist = collections.Counter(allpix)
    used = sorted(hist)
    low = sum(hist[i] for i in range(32))
    print('%s  %s %d x %d%s' % (os.path.basename(path), rec['kind'],
                                rec['w'], rec['h'],
                                ' x %d frames' % rec['count']
                                if rec['kind'] == 'BMA' else ''))
    print('  pixel bytes               : %d' % len(allpix))
    print('  distinct index values     : %d' % len(used))
    print('  lowest .. highest         : %d .. %d' % (used[0], used[-1]))
    print('  pixels in indices 0..31   : %d  (%.4f %%)'
          % (low, 100.0 * low / len(allpix)))
    print('  pixels in indices 32..255 : %d  (%.4f %%)'
          % (len(allpix) - low, 100.0 * (len(allpix) - low) / len(allpix)))
    print('  ranges used               : %s' % index_ranges(used))
    print('  commonest index           : %d  (%d pixels, %.4f %%)'
          % (hist.most_common(1)[0][0], hist.most_common(1)[0][1],
             100.0 * hist.most_common(1)[0][1] / len(allpix)))
    if rec['kind'] == 'BMA':
        print('  distinct frames           : %d of %d'
              % (len(set(fr)), len(fr)))
    al = alignment(blob, rec)
    if al:
        g_here, g_last, e0_here, e0_last, e255 = al
        print('  palette entry 0           : %s   entry 255 : %s'
              % (e0_here, e255))
        print('  greys (r == g == b)       : %d at the closure\'s window, %d '
              'at the last 768 bytes' % (g_here, g_last))
        if rec['kind'] == 'BMA':
            print('    (the two windows are six bytes apart on a .BMA, which '
                  'is a multiple of three: this test cannot tell them apart)')


def cmd_frames(path, blob, rec):
    fr = frames(blob, rec)
    if len(fr) < 2:
        print('%s holds one frame; nothing to diff' % os.path.basename(path))
        return
    n = rec['w'] * rec['h']
    print('%s  %d frames of %d x %d = %d pixels'
          % (os.path.basename(path), len(fr), rec['w'], rec['h'], n))
    print('  %-12s %8s %9s   %s' % ('frames', 'differ', 'share', 'box x0..x1 y0..y1'))
    for i, (d, x0, x1, y0, y1) in enumerate(frame_diffs(fr, rec['w'])):
        if d:
            print('  %2d -> %-2d      %8d %8.4f %%   %3d..%3d %3d..%3d'
                  % (i, i + 1, d, 100.0 * d / n, x0, x1, y0, y1))
        else:
            print('  %2d -> %-2d      identical' % (i, i + 1))
    print('  distinct frames : %d of %d' % (len(set(fr)), len(fr)))


def cmd_palette(path, blob, rec):
    pal = palette(blob, rec)
    if pal is None:
        print('%s carries no palette (flag n)' % os.path.basename(path))
        return
    hist = collections.Counter(blob[rec['pixels_at']:rec['pixels_end']])
    print('%s  palette at %d, 6-bit VGA, printed as (r, g, b) and pixels using'
          ' the entry' % (os.path.basename(path), rec['palette_at']))
    for row in range(0, 256, 4):
        cells = []
        for i in range(row, row + 4):
            r, g, b = pal[3 * i:3 * i + 3]
            cells.append('%3d (%2d,%2d,%2d) %6d' % (i, r, g, b, hist[i]))
        print('  ' + '   '.join(cells))
    g_here, g_last, e0_here, e0_last, _e255 = alignment(blob, rec)
    print()
    print('  greys at this window : %d     at the last 768 bytes : %d'
          % (g_here, g_last))
    print('  entry 0 here         : %s   there : %s' % (e0_here, e0_last))


def cmd_fit(path, blob, rec, back_path, frame_no):
    real, back_blob, back = read(back_path)
    if back['kind'] != 'BMB':
        raise BmbError('%s is not a single image' % os.path.basename(real))
    fr = frames(blob, rec)
    if not (0 <= frame_no < len(fr)):
        raise BmbError('frame %d: the file has %d' % (frame_no, len(fr)))
    if rec['w'] > back['w'] or rec['h'] > back['h']:
        raise BmbError('a %d x %d frame does not fit on a %d x %d screen'
                       % (rec['w'], rec['h'], back['w'], back['h']))
    diff, x, y = best_fit(fr[frame_no], rec['w'], rec['h'],
                          back_blob[back['pixels_at']:back['pixels_end']],
                          back['w'], back['h'])
    n = rec['w'] * rec['h']
    print('%s frame %d over %s' % (os.path.basename(path), frame_no,
                                   os.path.basename(real)))
    print('  best position       : x = %d, y = %d' % (x, y))
    print('  differing pixels    : %d of %d  (%.4f %%)'
          % (diff, n, 100.0 * diff / n))
    print('  this file\'s trailer : u16 %s' % (rec['trailer_words'],))
    print('  (exhaustive search over every position; slow on a big frame)')


def _grid(fr, w, h, columns):
    rows = (len(fr) + columns - 1) // columns
    gw = columns * (w + 1) + 1
    gh = rows * (h + 1) + 1
    out = bytearray(b'\xff' * (gw * gh))
    for i, f in enumerate(fr):
        cx = (i % columns) * (w + 1) + 1
        cy = (i // columns) * (h + 1) + 1
        for y in range(h):
            out[(cy + y) * gw + cx:(cy + y) * gw + cx + w] = f[y * w:(y + 1) * w]
    return bytes(out), gw, gh


def cmd_extract(path, blob, rec, out_dir, palette_from):
    pal = palette(blob, rec)
    source = os.path.basename(path)
    if palette_from:
        real, pblob, prec = read(palette_from)
        pal = palette(pblob, prec)
        source = os.path.basename(real)
        if pal is None:
            raise BmbError('%s carries no palette to borrow' % source)
    if pal is None:
        pal = bytes(v for i in range(256) for v in (i >> 2, i >> 2, i >> 2))
        source = 'a grey ramp, because the file has no palette and none was '\
                 'given with --palette-from'
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.basename(path)
    fr = frames(blob, rec)
    # px.write_png expands the six-bit DAC values to eight itself.
    if len(fr) == 1:
        target = os.path.join(out_dir, base + '.png')
        px.write_png(target, rec['w'], rec['h'], fr[0], pal)
        print('wrote %s  (%d x %d, palette from %s)'
              % (target, rec['w'], rec['h'], source))
        return
    columns = 10 if len(fr) > 10 else len(fr)
    g, gw, gh = _grid(fr, rec['w'], rec['h'], columns)
    target = os.path.join(out_dir, base + '.png')
    px.write_png(target, gw, gh, g, pal)
    print('wrote %s  (%d frames on a %d x %d grid, palette from %s)'
          % (target, len(fr), gw, gh, source))
    for i, f in enumerate(fr):
        px.write_png(os.path.join(out_dir, '%s_%02d.png' % (base, i)),
                     rec['w'], rec['h'], f, pal)
    print('and %d single frames beside it' % len(fr))


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--frames', action='store_true')
    ap.add_argument('--palette', action='store_true')
    ap.add_argument('--fit', default=None, metavar='BACKGROUND.BMB',
                    help='where frame --frame of this .BMA sits on a screen')
    ap.add_argument('--frame', type=int, default=0)
    ap.add_argument('--extract', action='store_true')
    ap.add_argument('--out', default=None)
    ap.add_argument('--palette-from', default=None, metavar='OTHER.BMB',
                    help='render a flag-n file in another file\'s palette')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.file:
        ap.error('give a .BMB or .BMA file')
    try:
        path, blob, rec = read(args.file)
        if args.extract:
            if not args.out:
                ap.error('--extract needs --out')
            cmd_extract(path, blob, rec, args.out, args.palette_from)
        elif args.fit:
            cmd_fit(path, blob, rec, args.fit, args.frame)
        elif args.census:
            cmd_census(path, blob, rec)
        elif args.frames:
            cmd_frames(path, blob, rec)
        elif args.palette:
            cmd_palette(path, blob, rec)
        else:
            cmd_validate(path, blob, rec)
    except BmbError as exc:
        print('REFUSE  %s' % exc)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
