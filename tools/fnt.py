#!/usr/bin/env python3
"""fnt.py -- a reader for FONT8X12.FNT of BIANCO NATALE (Tecnoart, 1994): the
printable ASCII alphabet as 96 cells of 8 x 12, one byte per pixel.

THE GRAMMAR
-----------
    96 cells, in ASCII order from 32 (space) to 127
    each cell 8 columns x 12 rows, row-major, ONE BYTE PER PIXEL
    the byte is a colour index and takes three values in the object:
        1   background          4,960 bytes   53.82 %   (cell 0, space, is all 1)
        14  ink                 1,953 bytes   21.19 %
        0   outline             2,303 bytes   24.99 %   (a one-pixel rim round the ink)
    96 x 8 x 12 = 9,216 = the file, residue 0

Nothing in the file says 8, 12 or 96. The arithmetic allows several splits of
9,216 (12, 16, 24, 36, 48, 96, 144 ...), and the argument for this one is not
the arithmetic: **cell n drawn as 8 x 12 is the glyph for chr(32 + n)** --
cell 33 is a capital A, cell 34 a B, cell 17 the digit 1, cell 0 blank -- and
no other split does that. `--show` draws any string so a reader can check it
on the glyphs of their choice. `BN.EXE`'s slack names the fields as
`_FONT_X_SIZE`, `_FONT_Y_SIZE` and `_FONT_SIZE`, without their values.

WHAT THIS TOOL SELECTS BY
-------------------------
Length 9,216; at most three distinct byte values; the commonest value fills
cell 0 entirely. A `.BMB` is refused on its length, `BN.EXE` on its length and
on its 200-odd distinct values, and `--selftest` refuses a font with one byte
appended. The bucket is DERIVED: nobody published this.

    python tools/fnt.py Bianco-Natale/FONT8X12.FNT
    python tools/fnt.py Bianco-Natale/FONT8X12.FNT --show "Pugno !"
    python tools/fnt.py Bianco-Natale/FONT8X12.FNT --sheet --out _work/png
    python tools/fnt.py --selftest
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard
import px

CELL_W = 8
CELL_H = 12
CELLS = 96
FIRST = 32
CELL = CELL_W * CELL_H
SIZE = CELLS * CELL
MAX_VALUES = 3


class FntError(Exception):
    """A file this reader will not pretend to understand."""


def parse(blob):
    if len(blob) != SIZE:
        raise FntError('%d bytes; %d cells of %d x %d want %d (residue %+d)'
                       % (len(blob), CELLS, CELL_W, CELL_H, SIZE,
                          SIZE - len(blob)))
    hist = collections.Counter(blob)
    if len(hist) > MAX_VALUES:
        raise FntError('%d distinct byte values; a one-byte-per-pixel font '
                       'with an ink, an outline and a background has at most '
                       '%d' % (len(hist), MAX_VALUES))
    background = hist.most_common(1)[0][0]
    cells = [blob[i * CELL:(i + 1) * CELL] for i in range(CELLS)]
    if any(b != background for b in cells[0]):
        raise FntError('cell 0 (the space) is not blank')
    return {'hist': hist, 'background': background, 'cells': cells,
            'distinct': len(set(cells))}


def looks_like(blob):
    try:
        parse(blob)
        return True
    except FntError:
        return False


def looks_like_head(head, size=None):
    """A head-reading classifier gets 4,096 of the 9,216 bytes.

    With the length it can insist on 9,216; without it, only on the three
    values and the blank first cell over what it was given. **Weaker than
    `parse()`**, and said so.
    """
    if size is not None and size != SIZE:
        return False
    if len(head) < CELL:
        return False
    hist = collections.Counter(head)
    if len(hist) > MAX_VALUES:
        return False
    background = hist.most_common(1)[0][0]
    return all(b == background for b in head[:CELL])


def duplicates(cells):
    """Which cells are byte-identical to an earlier one."""
    seen = {}
    out = []
    for i, c in enumerate(cells):
        if c in seen:
            out.append((seen[c], i))
        else:
            seen[c] = i
    return out


def rim_share(rec, value):
    """What share of `value`'s pixels touch the background (4-neighbours,
    inside the cell). An outline is the value that touches it; ink is the
    value the outline keeps away from it."""
    touching = total = 0
    bg = rec['background']
    for cell in rec['cells']:
        for p, b in enumerate(cell):
            if b != value:
                continue
            total += 1
            x, y = p % CELL_W, p // CELL_W
            for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                nx, ny = x + dx, y + dy
                if 0 <= nx < CELL_W and 0 <= ny < CELL_H \
                        and cell[ny * CELL_W + nx] == bg:
                    touching += 1
                    break
    return (touching / float(total)) if total else 0.0


def ink_of(rec):
    """The non-background value that touches the background LEAST.

    Not the second commonest: on FONT8X12.FNT the outline (0, 2,303 bytes)
    outnumbers the ink (14, 1,953 bytes), because a one-pixel rim round a
    two-pixel stroke is longer than the stroke. The first draft of this
    function counted and called the rim the ink; this one measures adjacency
    and `--validate` prints the share for each value.
    """
    others = [v for v in rec['hist'] if v != rec['background']]
    if not others:
        return rec['background']
    return min(others, key=lambda v: rim_share(rec, v))


def art(rec, text, ink=None):
    """The string as ASCII art, one row of glyphs, 12 lines."""
    ink = rec['ink'] if ink is None else ink
    lines = []
    for row in range(CELL_H):
        line = []
        for ch in text:
            index = ord(ch) - FIRST
            if not (0 <= index < CELLS):
                index = 0
            cell = rec['cells'][index]
            for col in range(CELL_W):
                b = cell[row * CELL_W + col]
                line.append('#' if b == ink
                            else ('.' if b == rec['background'] else '+'))
        lines.append(''.join(line))
    return lines


def read(path, who='fnt'):
    real = dirguard.want_file(path, who)
    with open(real, 'rb') as handle:
        blob = handle.read()
    try:
        rec = parse(blob)
    except FntError as exc:
        raise FntError('%s: %s' % (os.path.basename(real), exc))
    rec['ink'] = ink_of(rec)
    return real, blob, rec


# ---------------------------------------------------------------- selftest --

OBJECT_REL = 'Bianco-Natale/FONT8X12.FNT'
OBJECT_CHECKS = 10


def _synthetic():
    """96 cells, all distinct but one: cell i carries the bits of i as ink
    dots down column 4, each with an outline dot either side, and cell 42 is
    a copy of cell 41 on purpose."""
    cells = []
    for i in range(CELLS):
        glyph = bytearray([1]) * CELL
        for bit in range(7):
            if i & (1 << bit):
                row = 2 + bit
                glyph[row * CELL_W + 3] = 0
                glyph[row * CELL_W + 4] = 14
                glyph[row * CELL_W + 5] = 0
        cells.append(bytes(glyph))
    cells[42] = cells[41]
    return b''.join(cells)


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    def refused(label, blob, needle):
        try:
            parse(blob)
            checks.append((label, False, 'it parsed'))
        except FntError as exc:
            ok = needle in str(exc)
            checks.append((label, ok, '' if ok else 'said %r' % str(exc)))

    blob = _synthetic()
    rec = parse(blob)
    rec['ink'] = ink_of(rec)
    want('a font built here parses: 96 cells, background 1',
         [len(rec['cells']), rec['background']], [96, 1])
    want('the ink is the value that touches the background least',
         rec['ink'], 14)
    want('and the outline touches it on every pixel',
         rim_share(rec, 0), 1.0)
    want('95 distinct cells, because one was duplicated on purpose',
         rec['distinct'], 95)
    want('and the duplicate is named', duplicates(rec['cells']), [(41, 42)])
    lines = art(rec, 'I')
    want('cell 41 draws as a stroke with an outline',
         lines[5], '...+#+..')
    want('a character outside 32..127 draws as the space',
         art(rec, chr(9))[5], '........')
    refused('a font with one byte appended is refused', blob + b'\x01',
            'residue -1')
    refused('a font with one byte removed is refused', blob[:-1],
            'residue +1')
    refused('a 9,216-byte file with four values is refused',
            blob[:-1] + b'\x07', 'distinct byte values')
    refused('a font whose cell 0 is not blank is refused',
            b'\x0e' + blob[1:], 'not blank')
    refused('an MZ header is refused', b'MZ' + bytes(60), 'residue')
    want('a 64,777-byte picture is refused on its length',
         looks_like(bytes(64777)), False)
    want('the head magic with the length insists on 9,216',
         looks_like_head(blob[:4096], 4096), False)
    want('and accepts the font\'s own head with its length',
         looks_like_head(blob[:4096], SIZE), True)
    want('without the length it accepts a blank first cell and three values',
         looks_like_head(blob[:4096]), True)
    want('a head with a fourth value is refused',
         looks_like_head(blob[:4095] + b'\x07', SIZE), False)

    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            fblob = handle.read()
        frec = parse(fblob)
        frec['ink'] = ink_of(frec)
        want('FONT8X12.FNT is 9,216 bytes of three values',
             sorted(frec['hist']), [0, 1, 14])
        want('the background is 1, 4,960 bytes of it',
             [frec['background'], frec['hist'][1]], [1, 4960])
        want('the ink is 14, 1,953 bytes; the outline 0, 2,303',
             [frec['ink'], frec['hist'][14], frec['hist'][0]],
             [14, 1953, 2303])
        want('94 of 96 cells are distinct', frec['distinct'], 94)
        want('the two repeats are cells 94 and 95 -- tilde and DEL -- and '
             'both are copies of the space',
             duplicates(frec['cells']), [(0, 94), (0, 95)])
        want('the outline value 0 touches the background on more of its '
             'pixels than the ink value 14 does',
             rim_share(frec, 0) > rim_share(frec, 14), True)
        # THE GLYPH, CONFIRMED: cell 33 is chr(65). Its fourth row from the
        # top is the narrow peak of an A and its seventh is the crossbar,
        # ink between two legs of outline.
        a = art(frec, 'A')
        want('cell 33 draws a capital A: row 3 is `.+####+.` and row 6 is '
             '`+#####+.`', [a[3], a[6]], ['.+####+.', '+#####+.'])
        one = art(frec, '1')
        want('cell 17 draws the digit 1: a single stroke down the middle',
             one[6], '..+##+..')
        want('cell 0 is blank and cell 65 (a) has ink',
             [max(frec['cells'][0]), frec['cells'][65].count(14) > 0],
             [1, True])
        want('every one of the 96 cells is 96 bytes',
             set(len(c) for c in frec['cells']), {96})
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((OBJECT_CHECKS,
                        '%s not beside the box; pass --object PATH to run '
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
    print('%s' % os.path.basename(path))
    print('  file bytes            : %d' % len(blob))
    print('  cells                 : %d of %d x %d = %d bytes each'
          % (CELLS, CELL_W, CELL_H, CELL))
    print('  %d x %d                : %d   RESIDUE +0' % (CELLS, CELL, SIZE))
    print('  cell n is chr(%d + n) : 32 .. 127, the printable ASCII set'
          % FIRST)
    print('  byte values           :')
    for value, count in rec['hist'].most_common():
        if value == rec['background']:
            role = 'background (the commonest; fills cell 0)'
        else:
            role = ('%s -- %.4f of its pixels touch the background'
                    % ('ink' if value == rec['ink'] else 'outline',
                       rim_share(rec, value)))
        print('      %3d  x%-5d  %6.2f %%   %s'
              % (value, count, 100.0 * count / len(blob), role))
    print('  distinct cells        : %d of %d' % (rec['distinct'], CELLS))
    dups = duplicates(rec['cells'])
    for first, again in dups:
        print('      cell %d repeats cell %d  (chr %d repeats chr %d)'
              % (again, first, again + FIRST, first + FIRST))
    inked = sum(1 for c in rec['cells'] if rec['ink'] in c)
    print('  cells with ink        : %d of %d' % (inked, CELLS))


def cmd_show(rec, text):
    for line in art(rec, text):
        print('    ' + line)


def cmd_sheet(path, rec, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    columns = 16
    rows = CELLS // columns
    gw = columns * (CELL_W + 1) + 1
    gh = rows * (CELL_H + 1) + 1
    grid = bytearray([2]) * (gw * gh)
    for i, cell in enumerate(rec['cells']):
        cx = (i % columns) * (CELL_W + 1) + 1
        cy = (i // columns) * (CELL_H + 1) + 1
        for y in range(CELL_H):
            for x in range(CELL_W):
                b = cell[y * CELL_W + x]
                grid[(cy + y) * gw + cx + x] = (
                    0 if b == rec['background'] else 1 if b == rec['ink']
                    else 3)
    # A four-entry palette of this tool's choosing: the file carries none.
    pal = bytes([0, 0, 0, 63, 63, 63, 20, 20, 20, 63, 0, 0]) + bytes(756)
    target = os.path.join(out_dir, os.path.basename(path) + '.png')
    px.write_png(target, gw, gh, bytes(grid), pal)
    print('wrote %s  (%d cells on a %d x %d grid; white ink, red outline, '
          'the colours are this tool\'s, not the file\'s)'
          % (target, CELLS, gw, gh))


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--show', default=None, metavar='TEXT')
    ap.add_argument('--sheet', action='store_true')
    ap.add_argument('--out', default=None)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.file:
        ap.error('give a .FNT file')
    try:
        path, blob, rec = read(args.file)
    except FntError as exc:
        print('REFUSE  %s' % exc)
        return 1
    if args.sheet:
        if not args.out:
            ap.error('--sheet needs --out')
        cmd_sheet(path, rec, args.out)
    elif args.show is not None:
        cmd_show(rec, args.show)
    else:
        cmd_validate(path, blob, rec)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
