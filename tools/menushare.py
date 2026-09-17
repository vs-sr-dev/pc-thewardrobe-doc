#!/usr/bin/env python3
"""menushare.py -- how the bytes of a directory divide between named groups of
files, with the check that every file is assigned exactly once.

WHY THIS IS A TOOL AND NOT A TABLE
----------------------------------
BIANCO NATALE's menu has five entries and two of them are not the game:
`TECNOART`, the studio's page, and `InfoLibrary`, an advertisement for an
encyclopedia the same studio wrote for a publisher. "Nearly a third of a
Christmas game is an advertisement" is a sentence a reader will remember,
and it is only worth remembering if it is a sum: the pre-briefing for this
object put the advertisement at 22.3410 % by eye and 30.8596 % by counting,
and this session, having looked at the pictures and at the order of the
strings in `BN.EXE`, puts it at **13.5279 %** -- the difference being two
files, `COUNTRY.BMA` and `BCOUNTRY.BMB`, which the pre-briefing assigned to
the encyclopedia and which are the menu screen. The figure moved twice, so
it is computed here from an assignment given on the command line and printed
beside the assignment, and the assignment is a READING: which file belongs to
which screen is read off file names, the `y`/`n` palette flag, the pixels and
the order of the string table, and no code path in `BN.EXE` was traced.

    python tools/menushare.py Bianco-Natale --preset bianconatale
    python tools/menushare.py DIR --group "game=A.BIN,B.BIN" --group "rest=C.BIN"
    python tools/menushare.py --selftest

`--preset bianconatale` is the assignment the chapter uses, kept here so the
figure and the reading it rests on travel together; `--group` overrides it.
Refuses a directory whose files are not all assigned, or any assigned twice.
"""
import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

PRESETS = {
    'bianconatale': [
        # (group, files, the evidence the assignment rests on)
        ('the game (Il Gioco)',
         ['BN.BMA', 'BACK1.BMB', 'BACK2.BMB', 'BACK3.BMB', 'BACK4.BMB',
          'BACK5.BMB', 'GAMEOVER.BMA'],
         'named together in the string table between font8x12.fnt and the '
         'Level 1..4 / Pugno ! strings; the sprite sheet uses palette '
         'indices 0..31 and the five backgrounds leave 1..31 free'),
        ('the story (La Storia)',
         ['STORY.BMA', 'B_STORY.BMB'],
         'named together after the quit prompt; frame 15 of the animation is '
         'an exact crop of the background at (158, 60)'),
        ('the menu screen',
         ['COUNTRY.BMA', 'BCOUNTRY.BMB'],
         'named three times, the first immediately after the five menu '
         'strings and pointer.bmb; frame 0 fits the background at (33, 1), '
         'which is the animation\'s own trailer; the picture is a village '
         'with a signpost and a building drawn in it'),
        ('the studio pages (TECNOART)',
         ['TECNOART.BMB', 'TA.BMB'],
         'both pictures are the studio logo over "software development"'),
        ('the encyclopedia advert (InfoLibrary)',
         ['B_IL.BMB'],
         'the picture is an annotated mock-up of the encyclopedia\'s three '
         'windows; named beside ta.bmb'),
        ('shared furniture',
         ['TITLE.BMB', 'POINTER.BMB', 'FONT8X12.FNT'],
         'the title screen, the cursor and the font'),
        ('the program', ['BN.EXE'], 'the only executable'),
    ],
}

ADVERT = {'bianconatale': (['the studio pages (TECNOART)',
                            'the encyclopedia advert (InfoLibrary)'],
                           'the menu screen')}


class ShareError(Exception):
    pass


def shares(root, groups):
    """[(group, files, bytes, share)], total -- or ShareError."""
    present = sorted(os.listdir(root))
    sizes = {n: os.path.getsize(os.path.join(root, n)) for n in present}
    seen = {}
    for label, names, _why in groups:
        for n in names:
            if n not in sizes:
                raise ShareError('%s is assigned to %r and is not in %s'
                                 % (n, label, root))
            if n in seen:
                raise ShareError('%s is assigned twice: %r and %r'
                                 % (n, seen[n], label))
            seen[n] = label
    missing = [n for n in present if n not in seen]
    if missing:
        raise ShareError('%d file(s) assigned to no group: %s'
                         % (len(missing), ', '.join(missing)))
    total = sum(sizes.values())
    out = []
    for label, names, why in groups:
        b = sum(sizes[n] for n in names)
        out.append((label, names, b, 100.0 * b / total, why))
    return out, total


def parse_groups(specs):
    groups = []
    for spec in specs:
        if '=' not in spec:
            raise ShareError('a --group is NAME=FILE,FILE: %r' % spec)
        label, names = spec.split('=', 1)
        groups.append((label.strip(),
                       [n.strip() for n in names.split(',') if n.strip()],
                       'given on the command line'))
    return groups


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    with tempfile.TemporaryDirectory() as tmp:
        for name, size in (('A.BIN', 300), ('B.BIN', 100), ('C.BIN', 600)):
            with open(os.path.join(tmp, name), 'wb') as handle:
                handle.write(bytes(size))
        rows, total = shares(tmp, [('one', ['A.BIN', 'B.BIN'], ''),
                                   ('two', ['C.BIN'], '')])
        want('three files of 1,000 bytes divide 400 / 600',
             [(r[0], r[2]) for r in rows], [('one', 400), ('two', 600)])
        want('and the shares are 40 and 60 per cent',
             [round(r[3], 4) for r in rows], [40.0, 60.0])
        want('the total is the directory\'s', total, 1000)
        for label, groups, needle in (
                ('a file assigned twice is refused',
                 [('one', ['A.BIN'], ''), ('two', ['A.BIN', 'B.BIN', 'C.BIN'], '')],
                 'assigned twice'),
                ('a file assigned to no group is refused',
                 [('one', ['A.BIN', 'B.BIN'], '')], 'no group'),
                ('a file that is not there is refused',
                 [('one', ['A.BIN', 'B.BIN', 'C.BIN', 'D.BIN'], '')],
                 'not in')):
            try:
                shares(tmp, groups)
                checks.append((label, False, 'it summed'))
            except ShareError as exc:
                checks.append((label, needle in str(exc), str(exc)))
    want('--group parsing', parse_groups(['x=A.BIN, B.BIN'])[0][:2],
         ('x', ['A.BIN', 'B.BIN']))
    preset = PRESETS['bianconatale']
    names = [n for _l, ns, _w in preset for n in ns]
    want('the preset names 18 files, none twice',
         [len(names), len(set(names))], [18, 18])
    want('the preset\'s two advert groups exist',
         all(any(g[0] == a for g in preset) for a in ADVERT['bianconatale'][0]),
         True)
    checks.append(('dirguard.want_tree is imported',
                   hasattr(dirguard, 'want_tree'), ''))
    checks.append(('nameguard.guard is imported',
                   hasattr(nameguard, 'guard'), ''))
    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root', nargs='?')
    ap.add_argument('--preset', choices=sorted(PRESETS), default=None)
    ap.add_argument('--group', action='append', default=[])
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()
    if args.selftest:
        raise SystemExit(selftest())
    if not args.root:
        ap.error('give a directory')
    root = dirguard.want_tree(args.root, 'menushare')
    try:
        groups = parse_groups(args.group) if args.group else (
            PRESETS[args.preset] if args.preset else None)
        if groups is None:
            ap.error('give --preset or at least one --group')
        rows, total = shares(root, groups)
    except ShareError as exc:
        print('REFUSE  %s' % exc)
        return 1
    print('%s : %d files, %d bytes, every file assigned exactly once'
          % (root, len(os.listdir(root)), total))
    print()
    print('  %-40s %5s %10s %10s' % ('group', 'files', 'bytes', 'share'))
    for label, names, b, share, _why in rows:
        print('  %-40s %5d %10d %9.4f %%' % (label, len(names), b, share))
    print('  %-40s %5d %10d %9.4f %%'
          % ('SUM', sum(len(r[1]) for r in rows), sum(r[2] for r in rows),
             sum(r[3] for r in rows)))
    print('  residue against the directory : %+d'
          % (sum(r[2] for r in rows) - total))
    print()
    print('  THE ASSIGNMENT IS A READING. What each group rests on:')
    for label, names, _b, _s, why in rows:
        print('    %s' % label)
        print('        %s' % ', '.join(names))
        print('        %s' % why)
    if args.preset in ADVERT:
        strict, wider = ADVERT[args.preset]
        by = {r[0]: r for r in rows}
        b = sum(by[g][2] for g in strict)
        w = b + by[wider][2]
        game = [r for r in rows if r[0].startswith('the game')][0]
        print()
        print('  THE ADVERTISEMENT, TWO WAYS:')
        print('    the studio pages and the encyclopedia page : %d bytes = '
              '%.4f %%  (%.4f : 1 against the game)'
              % (b, 100.0 * b / total, b / float(game[2])))
        print('    with the menu screen counted in as well   : %d bytes = '
              '%.4f %%  (%.4f : 1 against the game)'
              % (w, 100.0 * w / total, w / float(game[2])))
        print('    the menu screen is a village with a TA signpost and an')
        print('    INFOLIB building painted into it; whether that is')
        print('    advertising is a judgement and both figures are printed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
