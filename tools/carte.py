#!/usr/bin/env python3
"""carte.py -- read `CARTE.IMG`, forty Italian playing cards with no header.

THE FORMAT HAS NO NAME, SO THIS TOOL IS NAMED AFTER THE FILE.
`ilbm.py` next door reads a format with a vendor, a specification and thirty
years of independent readers. **This one has none of that.** There is no
magic number, no header, no vendor and no document: there are 129,280 bytes
and an author who is not available to ask. Everything below was derived here,
by division, and the bucket that follows from that is **DECODED** and not
SPECIFIED -- the same argument `pc-ilgrandegiocoditangentopoli-doc/docs/03`
made about `PX`, applied to the file in this folder that deserves it.

The tool is called `carte` because *carte* is what the author called them, in
the file name and in `_PUTCARTE` and `_ORDINA_CARTE` and `_MESCOLA_MAZZO` in
his own symbol table. Naming it `cards.py` would have been translating a
primary source.

THE ARITHMETIC, WHICH CLOSES AT RESIDUE ZERO AND IS THE WHOLE ARGUMENT
----------------------------------------------------------------------
    129,280 / 40 = 3,232      remainder 0      an Italian deck
    129,280 / 52 = 2,486      remainder 8      a French deck: NO
    129,280 / 54 = 2,394      remainder 4      with jokers:   NO

    3,232 = 2^5 x 101, and a bit-planar card is planes x rows x (width / 8):

        4 planes x 101 rows x 8 bytes = 3,232      64 pixels wide
        8 planes x 101 rows x 4 bytes = 3,232      32 pixels wide

Forty is corroborated from a second direction that has nothing to do with
division: `_ORO`, `_COPPE`, `_MAZZE`, `_SPADE` are in the executable's symbol
table, and those are the four Italian suits.

THE TWO CHOICES THIS TOOL DOES NOT MAKE FOR YOU
------------------------------------------------
A planar image has a plane count AND a plane order, and both are guesses until
something is drawn. This reader takes them as arguments so that the wrong
answer can be looked at beside the right one:

    --planes 4 | 8              4 x 64 wide, or 8 x 32 wide
    --order plane | row         all of plane 0 then all of plane 1 ...
                                (`plane`, which is how a mode 12h
                                `getimage` written with the map-mask
                                register stores a sprite), or plane 0
                                of row 0, plane 1 of row 0, ...
                                (`row`, which is how ILBM stores one)

**`--sweep` renders all four combinations of the two**, so the choice is
something a reader can look at rather than something this docstring asserts.

THE PALETTE IS NOT IN THIS FILE AND THAT IS SAID OUT LOUD
----------------------------------------------------------
`CARTE.IMG` is indices and nothing else. `--dac` reads `DAC.INF`, the object's
768-byte six-bit VGA palette, and `--cmap` reads the sixteen eight-bit entries
out of `SFONDO.LBM`. Neither is proven to be the right one by this file; what
IS measurable is whether they agree with each other, and `--palette-compare`
prints that entry by entry.

    python tools/carte.py --validate rovescino/CARTE.IMG
    python tools/carte.py --census   rovescino/CARTE.IMG
    python tools/carte.py --sweep    rovescino/CARTE.IMG --out _work/png
    python tools/carte.py --sheet    rovescino/CARTE.IMG --out _work/png \\
        --dac rovescino/DAC.INF
    python tools/carte.py --card 0 --zoom 4 rovescino/CARTE.IMG \\
        --out _work/png --dac rovescino/DAC.INF
    python tools/carte.py --palette-compare rovescino/DAC.INF \\
        --cmap rovescino/SFONDO.LBM
    python tools/carte.py --selftest
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
import ilbm
import px

DECK = 40
CARD_BYTES = 3232
GEOMETRY = {4: (64, 101), 8: (32, 101)}

# The Italian suits, in the order the author declared them in his own symbol
# table -- `_ORO _COPPE _MAZZE _SPADE`, at four adjacent offsets. This is not
# this tool's guess at an ordering; it is a quotation, and whether the file
# agrees with it is a question `--sheet` lets a reader answer by looking.
SUITS = ('ORO', 'COPPE', 'MAZZE', 'SPADE')

# The rank order, ascending, exactly as REGOLE.DOC states it.
RANKS = ('4', '5', '6', '7', 'donna', 'cavallo', 're', 'asso', 'due', 'tre')


class CarteError(Exception):
    """A file this reader will not pretend to understand."""


def split(blob):
    """Forty cards, or an exception saying by how much the division failed."""
    if len(blob) % DECK:
        raise CarteError('%d bytes is not divisible by %d: remainder %d'
                         % (len(blob), DECK, len(blob) % DECK))
    per = len(blob) // DECK
    if per != CARD_BYTES:
        raise CarteError('%d bytes per card, and this reader knows %d'
                         % (per, CARD_BYTES))
    return [blob[i * per:(i + 1) * per] for i in range(DECK)]


def unplane(card, planes, order):
    """One card's bytes to one byte per pixel.

    `order` is the whole question. `plane` reads the card as `planes`
    consecutive bitmaps; `row` reads it as `rows` groups of `planes` rows.
    Getting it wrong does not raise -- it draws a comb -- which is exactly why
    `--sweep` exists and why this function refuses to prefer one.
    """
    if planes not in GEOMETRY:
        raise CarteError('%d planes is not 4 or 8' % planes)
    width, height = GEOMETRY[planes]
    stride = width // 8
    if len(card) != planes * stride * height:
        raise CarteError('a card is %d bytes and %d planes of %d x %d needs %d'
                         % (len(card), planes, width, height,
                            planes * stride * height))
    pixels = bytearray(width * height)
    for plane in range(planes):
        bit = 1 << plane
        for y in range(height):
            if order == 'plane':
                base = (plane * height + y) * stride
            elif order == 'row':
                base = (y * planes + plane) * stride
            else:
                raise CarteError('order %r is not plane or row' % order)
            out = y * width
            for byte_index in range(stride):
                byte = card[base + byte_index]
                if not byte:
                    continue
                x0 = byte_index * 8
                for b in range(8):
                    if byte & (0x80 >> b):
                        pixels[out + x0 + b] |= bit
    return bytes(pixels), width, height


def contiguity(pixels, width, height):
    """How often a pixel equals the one below it, as a fraction.

    A PICTURE IS VERTICALLY CONTIGUOUS AND A COMB IS NOT, and that is a
    measurement rather than a look. Reading a plane-major card as row-major
    (or the reverse) scatters each plane's bits into different rows, so
    neighbouring rows stop agreeing. This is the number `--sweep` prints
    beside each of the four renderings so that the choice between them is
    argued and not eyeballed.

    It is a WEAK test and is labelled as one: it can be fooled by an image of
    horizontal stripes, and it says nothing about which of two high-scoring
    orders is right. It is reported next to a PNG, never instead of one.
    """
    if height < 2:
        return 0.0
    same = 0
    for y in range(height - 1):
        a = pixels[y * width:(y + 1) * width]
        b = pixels[(y + 1) * width:(y + 2) * width]
        same += sum(1 for i in range(width) if a[i] == b[i])
    return same / float(width * (height - 1))


def read_dac(path):
    """DAC.INF as 256 six-bit entries, checked for six-bitness before use."""
    dirguard.want_file(path, 'carte --dac')
    with open(path, 'rb') as handle:
        blob = handle.read()
    if len(blob) != 768:
        raise CarteError('%s is %d bytes and a 256-entry DAC is 768'
                         % (os.path.basename(path), len(blob)))
    over = sum(1 for b in blob if b > 63)
    if over:
        raise CarteError('%d bytes of %s exceed 63 and a VGA DAC is six-bit'
                         % (over, os.path.basename(path)))
    return blob


def read_cmap(path):
    """The sixteen eight-bit CMAP entries out of an ILBM."""
    dirguard.want_file(path, 'carte --cmap')
    with open(path, 'rb') as handle:
        blob = handle.read()
    if not ilbm.is_ilbm(blob[:12]):
        raise CarteError('%s is not an ILBM' % os.path.basename(path))
    _form, chunks, _declared, _end = ilbm.walk(blob)
    for cid, offset, length in chunks:
        if cid == b'CMAP':
            return blob[offset:offset + length - (length % 3)]
    raise CarteError('%s has no CMAP' % os.path.basename(path))


def palette_compare(dac, cmap):
    """DAC.INF's low sixteen against the ILBM CMAP, both at eight bits.

    The DAC is six-bit and a CMAP is eight-bit, so the only honest comparison
    expands the DAC the way the hardware does -- `(x << 2) | (x >> 4)`, which
    is `px.to_rgb` -- and reports the difference per channel rather than a
    yes or a no.
    """
    wide = px.to_rgb(dac[:48])
    rows = []
    for i in range(min(len(cmap), len(wide)) // 3):
        a = tuple(wide[i * 3:i * 3 + 3])
        b = tuple(cmap[i * 3:i * 3 + 3])
        rows.append((i, tuple(dac[i * 3:i * 3 + 3]), a, b,
                     tuple(x - y for x, y in zip(a, b))))
    return rows


def truncation_test(dac, cmap):
    """Is the six-bit palette the eight-bit one with its low two bits cut off?

    THIS IS A STRONGER QUESTION THAN 'ARE THEY CLOSE' AND IT HAS A YES OR NO.
    Expanding six bits to eight has to invent two bits and every implementation
    invents them differently, so comparing an expanded DAC against a CMAP can
    only ever produce a small number and an argument about rounding. Going the
    other way throws information away instead of inventing it, and

        CMAP channel >> 2 == DAC channel

    is either true of a channel or it is not. Returns (hits, total).
    """
    hits = total = 0
    for i in range(min(len(cmap), len(dac)) // 3):
        for c in range(3):
            total += 1
            hits += (cmap[i * 3 + c] >> 2) == dac[i * 3 + c]
    return hits, total


def write_png(path, width, height, pixels, rgb):
    """8-bit indexed PNG. `rgb` is already eight-bit, as `ilbm.write_png` wants."""
    ilbm.write_png(path, width, height, pixels, rgb)


def sheet(cards, planes, order, columns=10):
    """All forty cards on one grid, in file order, with a one-pixel gutter."""
    width, height = GEOMETRY[planes]
    rows = (len(cards) + columns - 1) // columns
    sheet_w = columns * (width + 1) + 1
    sheet_h = rows * (height + 1) + 1
    out = bytearray(sheet_w * sheet_h)
    for index, card in enumerate(cards):
        pixels, _w, _h = unplane(card, planes, order)
        cx = (index % columns) * (width + 1) + 1
        cy = (index // columns) * (height + 1) + 1
        for y in range(height):
            start = (cy + y) * sheet_w + cx
            out[start:start + width] = pixels[y * width:(y + 1) * width]
    return bytes(out), sheet_w, sheet_h


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the division, which is the argument -------------------------------
    want('40 divides 129280 exactly', 129280 % 40, 0)
    want('and gives 3232', 129280 // 40, 3232)
    want('52 does not divide it', 129280 % 52, 8)
    want('54 does not divide it', 129280 % 54, 4)
    want('4 planes of 64 x 101 is 3232', 4 * (64 // 8) * 101, 3232)
    want('8 planes of 32 x 101 is 3232', 8 * (32 // 8) * 101, 3232)

    # -- split refuses rather than rounds ----------------------------------
    for label, blob in (('a file that 40 does not divide is refused',
                         b'\x00' * 129281),
                        ('a file with the wrong bytes per card is refused',
                         b'\x00' * 40)):
        try:
            split(blob)
            checks.append((label, False, 'it split'))
        except CarteError:
            checks.append((label, True, ''))
    want('a good file splits into forty', len(split(b'\x00' * 129280)), 40)

    # -- the two plane orders, on a card built here -------------------------
    # 4 planes, 64 x 101. Set plane 1 (bit 2) on row 0 only, plane-major.
    stride, height, planes = 8, 101, 4
    plane_major = bytearray(planes * stride * height)
    for i in range(stride):
        plane_major[1 * stride * height + i] = 0xFF     # plane 1, row 0
    pixels, w, h = unplane(bytes(plane_major), 4, 'plane')
    want('plane-major: row 0 is index 2', set(pixels[0:64]), {2})
    want('plane-major: row 1 is index 0', set(pixels[64:128]), {0})
    want('plane-major geometry is 64 x 101', (w, h), (64, 101))

    row_major = bytearray(planes * stride * height)
    for i in range(stride):
        row_major[(0 * planes + 1) * stride + i] = 0xFF  # row 0, plane 1
    pixels2, _w, _h = unplane(bytes(row_major), 4, 'row')
    want('row-major: row 0 is index 2', set(pixels2[0:64]), {2})
    want('row-major: row 1 is index 0', set(pixels2[64:128]), {0})
    want('the two orders are different layouts of the same picture',
         pixels, pixels2)

    # -- and reading one as the other is WRONG, which is the point ----------
    wrong, _w, _h = unplane(bytes(plane_major), 4, 'row')
    checks.append(('reading a plane-major card as row-major changes it',
                   wrong != pixels, ''))

    # -- the eight-plane geometry -------------------------------------------
    eight = bytearray(8 * 4 * 101)
    for i in range(4):
        eight[0 * 4 * 101 + i] = 0xFF                    # plane 0, all rows? no
    pixels8, w8, h8 = unplane(bytes(eight), 8, 'plane')
    want('eight planes give 32 x 101', (w8, h8), (32, 101))
    want('eight planes, plane 0 row 0 set, gives index 1',
         set(pixels8[0:32]), {1})

    # -- contiguity separates a picture from a comb -------------------------
    solid = bytes([7]) * (64 * 101)
    comb = bytearray(64 * 101)
    for y in range(101):
        comb[y * 64:(y + 1) * 64] = bytes([y % 16]) * 64
    checks.append(('contiguity: a solid block scores 1.0',
                   abs(contiguity(solid, 64, 101) - 1.0) < 1e-9, ''))
    checks.append(('contiguity: rows that all differ score 0.0',
                   contiguity(bytes(comb), 64, 101) == 0.0, ''))

    # -- refusals ------------------------------------------------------------
    for label, args in (('nine planes is refused', (b'\x00' * 3232, 9, 'plane')),
                        ('an unknown order is refused',
                         (b'\x00' * 3232, 4, 'diagonal')),
                        ('a short card is refused',
                         (b'\x00' * 100, 4, 'plane'))):
        try:
            unplane(*args)
            checks.append((label, False, 'it decoded'))
        except CarteError:
            checks.append((label, True, ''))

    # -- the sheet ----------------------------------------------------------
    grid, gw, gh = sheet([b'\x00' * 3232] * 40, 4, 'plane')
    want('a ten-wide sheet of 64 x 101 is 651 x 409', (gw, gh), (651, 409))
    want('the sheet holds gw x gh bytes', len(grid), gw * gh)

    # -- palettes -----------------------------------------------------------
    want('six-bit 63 expands to 255', px.to_rgb(bytes([63]))[0], 255)
    want('six-bit 42 expands to 170', px.to_rgb(bytes([42]))[0], 170)
    want('six-bit 0 expands to 0', px.to_rgb(bytes([0]))[0], 0)

    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def grey16():
    """A palette that shows INDICES and not colours, for the sweep.

    The sweep's question is 'which plane order draws a card', and answering it
    with the game's own palette invites the eye to argue about hue. Sixteen
    steps of grey answers it with shape alone.
    """
    return bytes(b for i in range(256) for b in (i * 17 % 256,) * 3)


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--planes', type=int, default=4, choices=(4, 8))
    ap.add_argument('--order', default='plane', choices=('plane', 'row'))
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--sweep', action='store_true',
                    help='render all four plane/order combinations')
    ap.add_argument('--sheet', action='store_true',
                    help='render all forty cards on one grid')
    ap.add_argument('--card', type=int, default=None,
                    help='render one card by its index in the file')
    ap.add_argument('--zoom', type=int, default=1)
    ap.add_argument('--ascii', action='store_true',
                    help='with --card, print it as characters as well')
    ap.add_argument('--cols', type=int, default=64)
    ap.add_argument('--aspect', type=float, default=2.1,
                    help='rows per character cell; 2.1 suits a terminal, 1.0 '
                         'keeps every pixel row when reading small lettering')
    ap.add_argument('--crop', metavar='X,Y,W,H',
                    help='with --card, render only this rectangle of it')
    ap.add_argument('--out', default=None)
    ap.add_argument('--dac', default=None, help='a 768-byte six-bit palette')
    ap.add_argument('--cmap', default=None, help='an ILBM to take a CMAP from')
    ap.add_argument('--palette-compare', action='store_true',
                    help='DAC.INF low sixteen against an ILBM CMAP')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())

    if args.palette_compare:
        if not args.file or not args.cmap:
            ap.error('--palette-compare wants a DAC file and --cmap AN.LBM')
        dac = read_dac(args.file)
        cmap = read_cmap(args.cmap)
        rows = palette_compare(dac, cmap)
        print('  i   DAC six-bit      DAC expanded     CMAP eight-bit   delta')
        exact = 0
        for i, raw, wide, got, delta in rows:
            exact += delta == (0, 0, 0)
            print('  %2d  %3d %3d %3d      %3d %3d %3d      %3d %3d %3d    '
                  '%+d %+d %+d' % ((i,) + raw + wide + got + delta))
        print('')
        print('  entries compared     : %d' % len(rows))
        print('  identical after an expansion : %d of %d' % (exact, len(rows)))
        worst = max((max(abs(d) for d in row[4]) for row in rows), default=0)
        print('  largest channel gap  : %d of 255' % worst)
        hits, total = truncation_test(dac, cmap)
        print('')
        print('  THE STRONGER TEST -- CMAP channel >> 2 == DAC channel:')
        print('  channels agreeing    : %d of %d' % (hits, total))
        print('  which is             : %s'
              % ('EXACT -- the six-bit file is the eight-bit one truncated'
                 if hits == total else 'not exact'))
        return 0

    if not args.file:
        ap.error('give CARTE.IMG')
    path = dirguard.want_file(args.file, 'carte')
    with open(path, 'rb') as handle:
        blob = handle.read()

    try:
        cards = split(blob)
    except CarteError as exc:
        print('FAIL  %s: %s' % (os.path.basename(path), exc))
        return 1

    rgb = grey16()
    if args.dac:
        rgb = px.to_rgb(read_dac(args.dac))
    elif args.cmap:
        rgb = read_cmap(args.cmap)

    if args.validate or args.census:
        print('%s' % os.path.basename(path))
        print('  bytes                : %d' % len(blob))
        print('  cards                : %d   bytes per card : %d   '
              'remainder : %d' % (len(cards), len(blob) // DECK,
                                  len(blob) % DECK))
        counts = collections.Counter()
        for card in cards:
            pixels, w, h = unplane(card, args.planes, args.order)
            counts.update(pixels)
        print('  geometry read as     : %d planes, %d x %d, order %s'
              % (args.planes, w, h, args.order))
        print('  indices used         : %d of %d'
              % (len(counts), 1 << args.planes))
        total = sum(counts.values())
        print('  pixels               : %d = 40 x %d x %d' % (total, w, h))
        for index, count in sorted(counts.items()):
            print('    index %3d  %8d  %7.4f %%'
                  % (index, count, 100.0 * count / total))

    if args.sweep:
        if not args.out:
            ap.error('--sweep needs --out')
        os.makedirs(args.out, exist_ok=True)
        print('')
        print('  planes  order   vertical contiguity   file')
        for planes in (4, 8):
            for order in ('plane', 'row'):
                grid, gw, gh = sheet(cards[:10], planes, order)
                score = contiguity(grid, gw, gh)
                name = 'CARTE-sweep-%dp-%s.png' % (planes, order)
                write_png(os.path.join(args.out, name), gw, gh, grid, grey16())
                print('  %6d  %-6s  %19.4f   %s' % (planes, order, score, name))

    if args.sheet:
        if not args.out:
            ap.error('--sheet needs --out')
        os.makedirs(args.out, exist_ok=True)
        grid, gw, gh = sheet(cards, args.planes, args.order)
        if args.zoom > 1:
            grid, gw, gh = px.crop_zoom(grid, gw, gh, None, args.zoom)
        name = 'CARTE-sheet-%dp-%s.png' % (args.planes, args.order)
        write_png(os.path.join(args.out, name), gw, gh, grid, rgb)
        print('  wrote %s  %d x %d' % (name, gw, gh))

    if args.card is not None:
        if not args.out and not args.ascii:
            ap.error('--card needs --out, or --ascii')
        if not 0 <= args.card < DECK:
            ap.error('--card wants an index in 0..%d' % (DECK - 1))
        pixels, w, h = unplane(cards[args.card], args.planes, args.order)
        box = None
        if args.crop:
            try:
                box = tuple(int(part) for part in args.crop.split(','))
            except ValueError:
                ap.error('--crop wants four integers X,Y,W,H')
            if len(box) != 4:
                ap.error('--crop wants four integers X,Y,W,H')
        if args.ascii:
            # The crop is applied FIRST, so that --ascii and --render show the
            # same rectangle. Printing the whole card and rendering a corner
            # of it under one command is how a chapter ends up quoting a
            # picture nothing produced.
            shown, sw, sh = ((px.crop_zoom(pixels, w, h, box, 1)) if box
                             else (pixels, w, h))
            print('  card %d, %d x %d%s, as characters:'
                  % (args.card, sw, sh, ' (cropped)' if box else ''))
            print('')
            for line in ilbm.ascii_art(shown, sw, sh, rgb, args.cols,
                                       aspect=args.aspect, ink=True):
                print('    %s' % line)
            print('')
        if not args.out:
            return 0
        os.makedirs(args.out, exist_ok=True)
        if box or args.zoom > 1:
            pixels, w, h = px.crop_zoom(pixels, w, h, box, args.zoom)
        name = 'CARTE-%02d-%dp-%s%s.png' % (args.card, args.planes, args.order,
                                            '-crop' if box else '')
        write_png(os.path.join(args.out, name), w, h, pixels, rgb)
        print('  wrote %s  %d x %d' % (name, w, h))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
