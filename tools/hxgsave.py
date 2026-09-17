#!/usr/bin/env python3
"""hxgsave.py -- a reader for the two files HEXXAGON writes, as opposed to the
one it ships with.

WHY THIS IS A SEPARATE TOOL FROM hxg.py
---------------------------------------
`GRAPHICS.HXG`, `BOARD1..5.HXG` and `CONFIG.HXG` share an extension and share
nothing else. `hxg.py` refuses all three of the small ones, by grammar, on the
first look -- which is the point of selecting by grammar and not by name. The
container is 626,424 bytes of art the authors shipped in 1993; these are 8,472
bytes the PROGRAM wrote, twelve years later, while somebody played it.

THE BOARD, WHICH COUNTS THE GAME
--------------------------------
1,690 bytes = 169 records of ten bytes, and 169 is 13 x 13: a hexagonal board
stored in a square array. Each record is five little-endian words:

    +0  u16  x        the cell's centre, in pixels, on a 320 x 200 screen
    +2  u16  y
    +4  u16  (zero on all 169 records of every board in the object)
    +6  u16  6 on the 108 cells OUTSIDE the hexagon, 0 on the 61 inside it
    +8  u16  the cell's state: 0 empty, 1 blocked, 2 and 3 the two players

**The board counts itself.** 169 minus the 108 sentinels is 61, and 61 is the
number of hexes on a Hexxagon board. And the 61 that remain are a hexagon in
the arithmetic sense, which `--geometry` checks and does not assume:

    9 columns, evenly spaced 33 pixels apart
    holding 5, 6, 7, 8, 9, 8, 7, 6, 5 cells      -- which sums to 61
    rows 22 pixels apart within a column
    neighbouring columns offset by 11, which is half a row
    x runs 8..272 and 272 + 48 = 320;  y runs 2..178 and 178 + 22 = 200

None of that was used to read the file. A hexagon of side 5 has nine columns
of exactly those heights; a hex grid offsets alternate columns by half a row;
and mode 13h is 320 x 200. Three independent things agree.

THE CONFIG, WHICH BRACKETS ITSELF
---------------------------------
22 bytes: `HXG\0`, seven little-endian words, `HXG\0`. 4 + 14 + 4 = 22 and the
file is 22. **What each of the seven words means is NOT established here** --
`HEXXAGON.DOC` lists the options the menu offers, and matching seven numbers
to a menu is a guess unless something checks it. This tool prints the seven
words and says that it is printing seven words.

    python tools/hxgsave.py Hexxagon/BOARD1.HXG
    python tools/hxgsave.py Hexxagon/BOARD1.HXG --geometry
    python tools/hxgsave.py Hexxagon/BOARD1.HXG --picture
    python tools/hxgsave.py Hexxagon/CONFIG.HXG
    python tools/hxgsave.py --selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

BOARD_RECORD = 10
BOARD_CELLS = 13 * 13
BOARD_BYTES = BOARD_CELLS * BOARD_RECORD          # 1690
HEXES = 61                                        # a Hexxagon board
OUTSIDE = 6                                       # word 3 on a cell off-board
CONFIG_MAGIC = b'HXG\0'
CONFIG_WORDS = 7
CONFIG_BYTES = len(CONFIG_MAGIC) * 2 + CONFIG_WORDS * 2   # 22

STATE_NAMES = {0: 'empty', 1: 'blocked', 2: 'player A', 3: 'player B'}

# A hexagon of side 5, which is what 61 cells in nine columns has to be.
HEX_SIDE = 5
HEX_COLUMNS = [HEX_SIDE + i for i in range(HEX_SIDE)] + \
              [2 * HEX_SIDE - 2 - i for i in range(HEX_SIDE - 1)]


class SaveError(Exception):
    """A file this reader will not pretend to understand."""


def is_board(blob):
    """Selection by grammar. The extension is `.HXG` and so is the 626 KB
    container's, which is exactly why the extension is not consulted."""
    if len(blob) != BOARD_BYTES:
        return False
    try:
        cells = board(blob)
    except SaveError:
        return False
    return sum(1 for c in cells if c['outside']) == BOARD_CELLS - HEXES


def is_config(blob):
    return (len(blob) == CONFIG_BYTES
            and blob[:4] == CONFIG_MAGIC
            and blob[-4:] == CONFIG_MAGIC)


def board(blob):
    if len(blob) != BOARD_BYTES:
        raise SaveError('a board is %d bytes and this is %d'
                        % (BOARD_BYTES, len(blob)))
    cells = []
    for i in range(BOARD_CELLS):
        x, y, w2, w3, state = struct.unpack_from('<5H', blob,
                                                 i * BOARD_RECORD)
        cells.append(dict(i=i, x=x, y=y, w2=w2, w3=w3, state=state,
                          outside=(w3 == OUTSIDE)))
    return cells


def config(blob):
    if not is_config(blob):
        raise SaveError('not a %d-byte file bracketed by %r'
                        % (CONFIG_BYTES, CONFIG_MAGIC))
    return list(struct.unpack_from('<%dH' % CONFIG_WORDS, blob, 4))


def geometry(cells):
    """Every count the hexagon claim rests on, derived and returned."""
    inside = [c for c in cells if not c['outside']]
    xs = sorted(set(c['x'] for c in inside))
    ys = sorted(set(c['y'] for c in inside))
    per_col = collections.Counter(c['x'] for c in inside)
    heights = [per_col[x] for x in xs]
    xgaps = sorted(set(xs[i + 1] - xs[i] for i in range(len(xs) - 1)))
    ygaps = sorted(set(ys[i + 1] - ys[i] for i in range(len(ys) - 1)))
    colgaps = set()
    tops = []
    for x in xs:
        col = sorted(c['y'] for c in inside if c['x'] == x)
        tops.append(col[0])
        for i in range(len(col) - 1):
            colgaps.add(col[i + 1] - col[i])
    offsets = sorted(set(abs(tops[i + 1] - tops[i])
                         for i in range(len(tops) - 1)))
    return dict(inside=len(inside), columns=len(xs), heights=heights,
                xgaps=xgaps, ygaps=ygaps, rowgap=sorted(colgaps),
                offsets=offsets, xs=xs, ys=ys,
                xmin=xs[0], xmax=xs[-1], ymin=ys[0], ymax=ys[-1])


def picture(cells):
    """The board drawn where the file says it is drawn.

    Laying the 13 x 13 array out as 13 x 13 gives a sheared rhombus, because
    that is how a hex grid is stored. Laying it out on the x and y the records
    carry gives the hexagon, which is the point: the coordinates are not a
    guess, and this is what they say.
    """
    inside = [c for c in cells if not c['outside']]
    if not inside:
        return []
    xs = sorted(set(c['x'] for c in inside))
    ys = sorted(set(c['y'] for c in inside))
    grid = [[' '] * len(xs) for _ in ys]
    for cell in inside:
        grid[ys.index(cell['y'])][xs.index(cell['x'])] = \
            {0: '.', 1: '#', 2: 'A', 3: 'B'}.get(cell['state'], '?')
    return [' '.join(row).rstrip() for row in grid]


# ---------------------------------------------------------------- selftest --

OBJECT_REL = 'Hexxagon/BOARD1.HXG'
OBJECT_CHECKS = 13


def _synthetic_board(states=None):
    """A board built here, so the grammar block runs in any repository."""
    cells = []
    # nine columns of 5,6,7,8,9,8,7,6,5, laid out the way the object lays out
    # its own -- which is the claim, so building it this way and then MEASURING
    # it back would be circular. It is used only for the refusal checks and for
    # the record layout; the geometry claim is checked against the object.
    for i in range(BOARD_CELLS):
        cells.append((0, 0, 0, OUTSIDE, 4))
    if states:
        for idx, (x, y, state) in states.items():
            cells[idx] = (x, y, 0, 0, state)
    return b''.join(struct.pack('<5H', *c) for c in cells)


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the record layout, on a board built here ---------------------------
    blob = _synthetic_board({0: (48, 96, 3), 5: (81, 118, 1)})
    cells = board(blob)
    want('a board is 169 records', len(cells), BOARD_CELLS)
    want('and 1,690 bytes', len(blob), BOARD_BYTES)
    want('record 0 reads back its five words',
         [cells[0]['x'], cells[0]['y'], cells[0]['w2'], cells[0]['w3'],
          cells[0]['state']], [48, 96, 0, 0, 3])
    want('word 3 == 6 marks a cell outside the hexagon',
         cells[1]['outside'], True)
    want('and word 3 == 0 marks one inside it', cells[0]['outside'], False)
    want('the state names cover 0..3', sorted(STATE_NAMES), [0, 1, 2, 3])

    # -- the config, built here --------------------------------------------
    made = CONFIG_MAGIC + struct.pack('<7H', 6, 1, 2, 2, 0, 2, 0) \
        + CONFIG_MAGIC
    want('a config built here is 22 bytes', len(made), CONFIG_BYTES)
    want('and reads back its seven words', config(made),
         [6, 1, 2, 2, 0, 2, 0])

    # -- the refusals, which are the whole point of grammar selection -------
    for label, blob_, fn in (
            ('a 22-byte file without the closing magic is refused',
             CONFIG_MAGIC + b'\x00' * 18, config),
            ('a board of the wrong length is refused',
             b'\x00' * (BOARD_BYTES - 1), board),
    ):
        try:
            fn(blob_)
            checks.append((label, False, 'it parsed'))
        except SaveError:
            checks.append((label, True, ''))
    want('a board is not mistaken for a config',
         is_config(_synthetic_board()), False)
    want('a config is not mistaken for a board', is_board(made), False)
    want('a board with no sentinels at all is refused by is_board',
         is_board(b'\x00' * BOARD_BYTES), False)

    # -- and against the object --------------------------------------------
    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            blob = handle.read()
        want('the object is a board', is_board(blob), True)
        cells = board(blob)
        want('108 cells carry the sentinel',
             sum(1 for c in cells if c['outside']), 108)
        want('and 61 do not, which is a Hexxagon board',
             sum(1 for c in cells if not c['outside']), HEXES)
        want('word 2 is zero on all 169',
             sum(1 for c in cells if c['w2'] == 0), BOARD_CELLS)
        geom = geometry(cells)
        # THE CONFIRMATIONS. None of these was used to parse anything.
        want('nine columns', geom['columns'], 9)
        want('holding 5, 6, 7, 8, 9, 8, 7, 6, 5 cells',
             geom['heights'], HEX_COLUMNS)
        want('which is a hexagon of side 5, and sums to 61',
             sum(geom['heights']), HEXES)
        want('the columns are evenly spaced', geom['xgaps'], [33])
        want('the rows within a column are evenly spaced',
             geom['rowgap'], [22])
        want('and neighbouring columns are offset by half a row',
             geom['offsets'], [11])
        want('the board ends exactly at the right edge of a 320-wide screen',
             geom['xmax'] + 48, 320)
        want('and exactly at the bottom of a 200-high one',
             geom['ymax'] + 22, 200)
        states = collections.Counter(c['state'] for c in cells
                                     if not c['outside'])
        want('the opening is 52 empty, 3 blocked, 3 and 3',
             [states[0], states[1], states[2], states[3]], [52, 3, 3, 3])
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

def report_board(name, blob, want_geometry, want_picture):
    cells = board(blob)
    inside = [c for c in cells if not c['outside']]
    states = collections.Counter(c['state'] for c in inside)
    print('%s' % name)
    print('  bytes                        : %d' % len(blob))
    print('  records of %d bytes           : %d'
          % (BOARD_RECORD, len(cells)))
    print('  169 = 13 x 13                : a hexagon in a square array')
    print('  cells marked outside (w3=6)  : %d' % (len(cells) - len(inside)))
    print('  cells on the board           : %d' % len(inside))
    print('  169 - 108                    : %d' % (len(cells) - 108))
    print()
    print('  the opening position:')
    for state in sorted(states):
        print('    state %d  %-9s : %d' % (state,
                                           STATE_NAMES.get(state, '?'),
                                           states[state]))
    print('    total                : %d' % sum(states.values()))
    if want_geometry:
        geom = geometry(cells)
        print()
        print('  THE GEOMETRY, derived and not assumed:')
        print('    columns                    : %d' % geom['columns'])
        print('    cells per column           : %s' % geom['heights'])
        print('    a hexagon of side %d wants  : %s'
              % (HEX_SIDE, HEX_COLUMNS))
        print('    MATCH                      : %s'
              % (geom['heights'] == HEX_COLUMNS))
        print('    sum                        : %d' % sum(geom['heights']))
        print('    column spacing, in pixels  : %s' % geom['xgaps'])
        print('    row spacing within a column: %s' % geom['rowgap'])
        print('    offset between columns     : %s   (half a row)'
              % geom['offsets'])
        print('    x runs %3d .. %3d          : %d + 48 = %d'
              % (geom['xmin'], geom['xmax'], geom['xmax'], geom['xmax'] + 48))
        print('    y runs %3d .. %3d          : %d + 22 = %d'
              % (geom['ymin'], geom['ymax'], geom['ymax'], geom['ymax'] + 22))
        print('    a mode 13h screen is       : 320 x 200')
    if want_picture:
        print()
        print('  the board where the coordinates put it -- `.` empty,')
        print('  `#` blocked, `A` and `B` the two players:')
        print()
        for row in picture(cells):
            print('      %s' % row)


def report_config(name, blob):
    words = config(blob)
    print('%s' % name)
    print('  bytes                        : %d' % len(blob))
    print('  first four                   : %r' % blob[:4])
    print('  last four                    : %r' % blob[-4:])
    print('  4 + %d x 2 + 4                : %d'
          % (CONFIG_WORDS, CONFIG_BYTES))
    print('  RESIDUE                      : %+d' % (CONFIG_BYTES - len(blob)))
    print('  the seven words              : %s'
          % ' '.join(str(w) for w in words))
    print()
    print('  WHAT EACH WORD MEANS IS NOT ESTABLISHED HERE. HEXXAGON.DOC')
    print('  lists the menu\'s options; matching seven numbers to a menu is')
    print('  a guess until something checks it, and nothing here does.')


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--geometry', action='store_true')
    ap.add_argument('--picture', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.file:
        ap.error('give a HEXXAGON board or config file')
    path = dirguard.want_file(args.file, 'hxgsave')
    with open(path, 'rb') as handle:
        blob = handle.read()
    name = os.path.basename(path)
    if is_board(blob):
        report_board(name, blob, args.geometry, args.picture)
        return 0
    if is_config(blob):
        report_config(name, blob)
        return 0
    print('REFUSE  %s: neither a %d-byte board with %d sentinels nor a '
          '%d-byte config bracketed by %r'
          % (name, BOARD_BYTES, BOARD_CELLS - HEXES, CONFIG_BYTES,
             CONFIG_MAGIC))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
