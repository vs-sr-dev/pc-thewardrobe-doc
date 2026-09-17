#!/usr/bin/env python3
"""planar.py -- read a headerless bit-planar blob whose geometry is a guess.

THREE FILES IN THIS OBJECT ARE CALLED `.ICO` AND NONE OF THEM IS AN ICON.
A Windows icon begins `00 00 01 00`. `MOUSE.ICO`, `FONT.ICO` and
`FUMETTI.ICO` begin `ff ff ff ff`, `00 00 00 00` and `00 00 00 00`, and the
extension is somebody's habit and not a format. What they actually are is what
`_GET_BOX` and `_PUT_BOX` in this program's symbol table store: rectangles of
VGA memory, one bit per pixel per plane, with no header of any kind.

So the geometry is not in the file and this tool does not pretend otherwise.
**It takes the width, the plane count and the plane order as arguments**, and
`--sweep` tries every width that divides the file cleanly and scores each one,
so that choosing a geometry is an argument with a number in it rather than an
assertion.

    a blob of B bytes, W pixels wide, P planes, is  B / (P * W/8)  rows,
    and only widths for which that divides exactly are candidates.

THE SCORE, AND WHAT IT CANNOT DO
---------------------------------
`--sweep` ranks candidates by VERTICAL CONTIGUITY: the fraction of pixels
equal to the pixel below. A picture is vertically contiguous; a picture read
at the wrong width shears, and the score falls. **It is a weak test and it is
labelled as one.** It cannot tell 64 from 128 when the image is symmetric, it
prefers blank areas to busy ones, and it says nothing at all about the plane
count. It is printed BESIDE a rendering, never instead of one, and the widths
it likes are the ones to look at first and not the answer.

    python tools/planar.py --sweep rovescino/FUMETTI.ICO --planes 4
    python tools/planar.py rovescino/FUMETTI.ICO --planes 4 --width 88 \\
        --out _work/png --dac rovescino/DAC.INF
    python tools/planar.py rovescino/MOUSE.ICO --planes 1 --width 32 \\
        --out _work/png
    python tools/planar.py --font rovescino/FONT.ICO --cell 8x8 --out _work/png
    python tools/planar.py --selftest
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import carte
import dirguard
import ilbm
import nameguard
import px


class PlanarError(Exception):
    """A blob this reader will not pretend to understand."""


def geometries(size, planes, low=8, high=1024):
    """Every width in [low, high] that divides the blob into whole rows."""
    out = []
    for width in range(low, high + 1, 8):
        per_row = planes * (width // 8)
        if size % per_row == 0:
            out.append((width, size // per_row))
    return out


def period(blob, low=1, high=256):
    """Byte autocorrelation: for each lag, how often blob[i] == blob[i+lag].

    WHY THIS IS A BETTER INSTRUMENT THAN PIXEL CONTIGUITY FOR FINDING A STRIDE.
    Contiguity has to guess a geometry first and then score the picture that
    comes out, so it can only rank the candidates that divide the file. This
    asks the bytes directly, at every lag, and a bitmap's row stride shows up
    as a peak because a row of a drawing resembles the row above it -- most
    of all in the long constant runs a flat-shaded picture is mostly made of.

    It has its own blind spot and it is named here per P19: **a file that is
    mostly one repeated byte peaks at every lag**, so the number to look at
    is a lag's score against its NEIGHBOURS and not against 1.0. The report
    prints the local lift for that reason.
    """
    scores = []
    for lag in range(low, high + 1):
        if lag >= len(blob):
            break
        same = sum(1 for i in range(len(blob) - lag) if blob[i] == blob[i + lag])
        scores.append((lag, same / float(len(blob) - lag)))
    return scores


def lift(scores, window=4):
    """Each lag's score minus the mean of its neighbours, which is the signal."""
    out = []
    for i, (lag, score) in enumerate(scores):
        lo = max(0, i - window)
        hi = min(len(scores), i + window + 1)
        neighbours = [s for j, (_l, s) in enumerate(scores[lo:hi], lo)
                      if j != i]
        out.append((score - sum(neighbours) / len(neighbours), lag, score))
    return out


def segments(blob, stride):
    """Runs of all-zero rows at a given stride, which is how a sheet is cut.

    A sprite sheet with no header separates its sprites the only way a
    headerless format can: with blank rows. Reporting where those runs are
    turns "about sixteen balloons" into a count, a pitch and a residue, and
    the residue is the part that says whether the stride is right.
    """
    rows = len(blob) // stride
    blank = [all(b == 0 for b in blob[y * stride:(y + 1) * stride])
             for y in range(rows)]
    runs = []
    y = 0
    while y < rows:
        if blank[y]:
            start = y
            while y < rows and blank[y]:
                y += 1
            runs.append((start, y - start))
        else:
            y += 1
    return rows, len(blob) - rows * stride, runs


def unplane(blob, width, planes, order='plane', rows=None):
    """The blob to one byte per pixel, at the geometry the caller chose."""
    if width % 8:
        raise PlanarError('width %d is not a multiple of 8' % width)
    stride = width // 8
    per_row = planes * stride
    if rows is None:
        if len(blob) % per_row:
            raise PlanarError('%d bytes is not a whole number of %d-byte '
                              'rows at %d x %d planes'
                              % (len(blob), per_row, width, planes))
        rows = len(blob) // per_row
    if len(blob) < per_row * rows:
        raise PlanarError('%d bytes cannot hold %d rows of %d'
                          % (len(blob), rows, per_row))
    pixels = bytearray(width * rows)
    for plane in range(planes):
        bit = 1 << plane
        for y in range(rows):
            if order == 'plane':
                base = (plane * rows + y) * stride
            elif order == 'row':
                base = (y * planes + plane) * stride
            else:
                raise PlanarError('order %r is not plane or row' % order)
            out = y * width
            for i in range(stride):
                byte = blob[base + i]
                if not byte:
                    continue
                x0 = i * 8
                for b in range(8):
                    if byte & (0x80 >> b):
                        pixels[out + x0 + b] |= bit
    return bytes(pixels), width, rows


def font_sheet(blob, cell_w, cell_h, columns=16):
    """A one-plane font laid out as a grid, so its cell size can be looked at.

    A font file has no geometry either: 864 bytes is 108 cells of 8 x 8 and it
    is equally 96 cells of 8 x 9, and the only way to choose is to draw both
    and see which one has letters in it.
    """
    if cell_w % 8:
        raise PlanarError('a cell %d wide is not a multiple of 8' % cell_w)
    per_cell = (cell_w // 8) * cell_h
    if len(blob) % per_cell:
        raise PlanarError('%d bytes is not a whole number of %d x %d cells'
                          % (len(blob), cell_w, cell_h))
    count = len(blob) // per_cell
    rows = (count + columns - 1) // columns
    sheet_w = columns * (cell_w + 1) + 1
    sheet_h = rows * (cell_h + 1) + 1
    out = bytearray(sheet_w * sheet_h)
    for index in range(count):
        cx = (index % columns) * (cell_w + 1) + 1
        cy = (index // columns) * (cell_h + 1) + 1
        for y in range(cell_h):
            for xb in range(cell_w // 8):
                byte = blob[index * per_cell + y * (cell_w // 8) + xb]
                for b in range(8):
                    if byte & (0x80 >> b):
                        out[(cy + y) * sheet_w + cx + xb * 8 + b] = 15
    return bytes(out), sheet_w, sheet_h, count


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the candidate widths are a division and nothing else ---------------
    want('256 bytes at 1 plane offers 32 as a width',
         (32, 64) in geometries(256, 1), True)
    want('11000 bytes at 4 planes offers 88',
         (88, 250) in geometries(11000, 4), True)
    want('11000 bytes at 4 planes does NOT offer 64',
         any(w == 64 for w, _h in geometries(11000, 4)), False)
    # 864 bytes eight pixels wide is 864 rows of one byte, NOT 108 of eight.
    # This check is here because the first draft of it asserted 108, which is
    # the FONT CELL count and not a row count -- the same confusion the
    # `--font` mode exists to keep apart.
    want('864 bytes at 1 plane, 8 wide, is 864 rows of one byte',
         geometries(864, 1, low=8, high=8), [(8, 864)])

    # -- unplaning, on bytes made here --------------------------------------
    blob = bytes([0xF0, 0x0F])          # 1 plane, 16 wide, 1 row
    pixels, w, h = unplane(blob, 16, 1)
    want('one plane, sixteen wide, gives one row', (w, h), (16, 1))
    want('the high nibble is set and the next is not',
         list(pixels[:8]) + list(pixels[8:12]), [1] * 4 + [0] * 4 + [0] * 4)

    want('a width that is not a multiple of eight is refused',
         isinstance(_raises(unplane, blob, 12, 1), PlanarError), True)
    want('a blob that does not divide is refused',
         isinstance(_raises(unplane, b'\x00' * 7, 16, 1), PlanarError), True)
    want('an unknown order is refused',
         isinstance(_raises(unplane, blob, 16, 1, 'spiral'), PlanarError),
         True)

    # -- the font sheet -----------------------------------------------------
    sheet, sw, sh, count = font_sheet(b'\x00' * 864, 8, 8)
    want('864 bytes is 108 cells of 8 x 8', count, 108)
    want('a sixteen-wide sheet of 8 x 8 is 145 x 64', (sw, sh), (145, 64))
    want('the sheet holds sw x sh bytes', len(sheet), sw * sh)
    _s, _w, _h, count9 = font_sheet(b'\x00' * 864, 8, 9)
    want('and it is equally 96 cells of 8 x 9', count9, 96)
    want('a cell size that does not divide is refused',
         isinstance(_raises(font_sheet, b'\x00' * 864, 8, 7), PlanarError),
         True)

    # -- contiguity is borrowed from carte.py and behaves the same ----------
    want('contiguity of a solid block is 1.0',
         carte.contiguity(bytes([3]) * 64, 8, 8), 1.0)

    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def _raises(fn, *args):
    try:
        fn(*args)
    except Exception as exc:          # pylint: disable=broad-except
        return exc
    return None


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--planes', type=int, default=4)
    ap.add_argument('--width', type=int, default=None)
    ap.add_argument('--rows', type=int, default=None)
    ap.add_argument('--order', default='plane', choices=('plane', 'row'))
    ap.add_argument('--sweep', action='store_true')
    ap.add_argument('--period', action='store_true',
                    help='byte autocorrelation, to find a row stride')
    ap.add_argument('--segments', action='store_true',
                    help='runs of blank rows at a given stride, to cut a sheet')
    ap.add_argument('--top', type=int, default=12)
    ap.add_argument('--font', action='store_true',
                    help='read the blob as a one-plane character cell font')
    ap.add_argument('--cell', default='8x8', help='font cell size, e.g. 8x9')
    ap.add_argument('--zoom', type=int, default=1)
    ap.add_argument('--ascii', action='store_true',
                    help='print the blob as characters, for a text-only '
                         'repository')
    ap.add_argument('--cols', type=int, default=96)
    ap.add_argument('--out', default=None)
    ap.add_argument('--dac', default=None)
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())
    if not args.file:
        ap.error('give a file')
    path = dirguard.want_file(args.file, 'planar')
    with open(path, 'rb') as handle:
        blob = handle.read()

    # `carte.grey16` steps by 17 per index, which is right for sixteen indices
    # and useless for two: index 1 comes out at grey 17, which is black on any
    # screen. A one-plane blob rendered in it looks like an empty file, and
    # the first sweep of FUMETTI.ICO was read as a failed geometry when it was
    # a failed palette. One plane therefore gets black and white.
    rgb = carte.grey16() if args.planes > 1 else bytes(
        b for i in range(256) for b in (255 if i else 0,) * 3)
    if args.dac:
        rgb = px.to_rgb(carte.read_dac(args.dac))

    print('%s' % os.path.basename(path))
    print('  bytes                : %d' % len(blob))

    if args.font:
        try:
            cw, ch = (int(part) for part in args.cell.lower().split('x'))
        except ValueError:
            ap.error('--cell wants WxH, e.g. 8x8')
        sheet, sw, sh, count = font_sheet(blob, cw, ch)
        print('  cell                 : %d x %d   cells : %d' % (cw, ch, count))
        # A font is INK ON PAPER and the rest of this tool is the other way
        # round, so the sheet gets its own two-colour palette: index 15, which
        # `font_sheet` writes for a set bit, is black, and everything else is
        # white. Without it the ASCII rendering prints the letters as holes in
        # a solid block, which is legible and wrong.
        rgb = bytes(b for i in range(256)
                    for b in ((0, 0, 0) if i == 15 else (255, 255, 255)))
        if args.ascii:
            print('')
            for line in ilbm.ascii_art(sheet, sw, sh, rgb, args.cols,
                                       aspect=1.0, ink=True):
                print('    %s' % line)
            print('')
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            pixels, w, h = sheet, sw, sh
            if args.zoom > 1:
                pixels, w, h = px.crop_zoom(sheet, sw, sh, None, args.zoom)
            stem = os.path.splitext(os.path.basename(path))[0]
            name = '%s-font-%dx%d.png' % (stem, cw, ch)
            ilbm.write_png(os.path.join(args.out, name), w, h, pixels, rgb)
            print('  wrote %s  %d x %d' % (name, w, h))
        return 0

    if args.segments:
        if args.width is None:
            ap.error('--segments wants --width, and --planes to size a row')
        stride = args.planes * (args.width // 8)
        rows, residue, runs = segments(blob, stride)
        print('  stride               : %d bytes = %d px at %d planes'
              % (stride, args.width, args.planes))
        print('  rows                 : %d   residue : %d bytes'
              % (rows, residue))
        print('  runs of blank rows   : %d' % len(runs))
        last = None
        for start, length in runs:
            pitch = '' if last is None else '  pitch %d' % (start - last)
            print('    row %4d  x %d%s' % (start, length, pitch))
            last = start
        return 0

    if args.period:
        scores = period(blob)
        ranked = sorted(lift(scores), reverse=True)
        print('  byte autocorrelation, lags 1..%d' % len(scores))
        print('')
        print('    lag   same    lift over neighbours   divides the file')
        for value, lag, score in ranked[:args.top]:
            print('  %5d  %6.4f   %+18.4f   %s'
                  % (lag, score, value,
                     'yes' if len(blob) % lag == 0 else 'no'))
        return 0

    if args.sweep:
        candidates = geometries(len(blob), args.planes)
        scored = []
        for width, rows in candidates:
            pixels, w, h = unplane(blob, width, args.planes, args.order)
            scored.append((carte.contiguity(pixels, w, h), width, rows))
        scored.sort(reverse=True)
        print('  candidate widths at %d planes : %d'
              % (args.planes, len(candidates)))
        print('')
        print('  contiguity   width   rows')
        for score, width, rows in scored[:args.top]:
            print('  %10.4f   %5d   %4d' % (score, width, rows))
        return 0

    if args.width is None:
        ap.error('give --width, or --sweep to see the candidates')
    pixels, w, h = unplane(blob, args.width, args.planes, args.order,
                           args.rows)
    print('  read as              : %d x %d, %d planes, order %s'
          % (w, h, args.planes, args.order))
    print('  vertical contiguity  : %.4f' % carte.contiguity(pixels, w, h))
    used = sorted(set(pixels))
    print('  indices used         : %d of %d  %s'
          % (len(used), 1 << args.planes, used[:16]))
    if args.ascii:
        print('')
        for line in ilbm.ascii_art(pixels, w, h, rgb, args.cols, ink=True):
            print('    %s' % line)
        print('')
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        if args.zoom > 1:
            pixels, w, h = px.crop_zoom(pixels, w, h, None, args.zoom)
        stem = os.path.splitext(os.path.basename(path))[0]
        name = '%s-%dp-%dx%d-%s.png' % (stem, args.planes, args.width, h,
                                        args.order)
        ilbm.write_png(os.path.join(args.out, name), w, h, pixels, rgb)
        print('  wrote %s  %d x %d' % (name, w, h))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
