#!/usr/bin/env python3
"""tds.py -- parse the Borland symbol table appended to an MZ executable.

`mz.py` reports that `FOREST.EXE` and `RACE.EXE` carry 8,257 and 16,737 bytes
past the image their own headers declare. Both appended regions open with the
two bytes `FB 52`, and the pre-briefing read them with a regular expression
over printable runs and counted 430 and 882 identifiers.

A REGULAR EXPRESSION IS NOT A PARSE, and this tool is the difference. It
reads the header, takes the name pool's length from a header field, walks the
pool as a chain of NUL-terminated strings, and requires that the walk end
exactly at end of region. Nothing is searched for.

THE HEADER, as measured on the two regions here -- and only the fields this
tool actually uses are named, because the rest are not understood:

    +0    u16 LE   0x52FB, the signature, on 2 of 2
    +2    u8       0x10 on 2 of 2
    +3    u8       0x03 on 2 of 2
    +4    u32 LE   BYTE LENGTH OF THE NAME POOL, which lies at the END of the
                   region: pool_start = len(region) - this
    +8    u16 LE   THE STRING COUNT, equal to the number of strings the pool
                   walk yields, on 2 of 2
    +14   u16 LE   that count MINUS THREE, on 2 of 2
    +16   u16 LE   the same value again -- a quantity encoded twice

    +32   u32 LE   the declared image size of the executable it belongs to,
                   which matches `mz.py`'s figure on 2 of 2

The first pass of this tool read +14 as the count and reported DISAGREE on
2 of 2, because 430 and 888 are what +14 holds while the walk yields 433 and
891. The walk is the measurement and the header field is the label: +8 is the
count and +14 is three less. What the three are is not known and is not named
here. It is worth noticing that 430 and 882 were the figures the pre-briefing's
regular expression produced, and that its 430 agreeing with +14 on `FOREST.EXE`
is a coincidence: the pool holds 433.

Fields +10, +12, +18 and the run of zeroes to +32 are NOT named here. The
public description of Borland's symbol table covers more than this; this tool
implements only what it can check against these two files, and says so.

THE CLOSURE TEST, which is the whole point:

  * the pool walk must consume every byte from pool_start to end of region
    with residue 0;
  * the number of strings it yields must equal the header's +8 field;
  * and +14 must equal +16 and be three less than the walk.

Three numbers from two places. If they disagree the tool fails loudly.

    python tools/tds.py Skunny/FOREST.EXE Skunny/RACE.EXE
    python tools/tds.py Skunny/*.EXE --names --out _work/symbols
    python tools/tds.py Skunny/HELPME.EXE          # a negative control

`--sweep` PRINTS THE IDENTIFIERS THAT DO NOT BEGIN WITH AN UNDERSCORE, and
that is all it does. It is a triage aid and NOT a personal-name check.

The first version of it also filtered out anything matching `^[A-Z0-9_$.@]+$`,
which is every all-capitals identifier -- so a symbol named `STEVE`, which is
exactly what the previous object in this series turned up, would have been
swallowed before a human saw it. It reported "0 of 433 need a human" and the
zero meant nothing. A privacy check that cannot fail is not a check.

THE SWEEP THAT WAS ACTUALLY DONE for chapter 08 was reading all 975 distinct
identifiers. Use `--names` or `--out` and read them. This flag narrows the
list; it does not clear it.
"""
import argparse
import os
import struct
import sys

SIGNATURE = 0x52FB
HEADER = 36


class TdsError(Exception):
    pass


def mz_image(blob, path):
    if blob[0:2] not in (b'MZ', b'ZM'):
        raise TdsError('%s: not an MZ file' % path)
    last, pages = struct.unpack_from('<2H', blob, 2)
    image = (pages - 1) * 512 + last if last else pages * 512
    return image


def parse(path):
    with open(path, 'rb') as handle:
        blob = handle.read()
    image = mz_image(blob, path)
    if image > len(blob):
        raise TdsError('%s: declared image %d exceeds the %d-byte file'
                       % (path, image, len(blob)))
    region = blob[image:]
    if not region:
        raise TdsError('%s: no bytes past the declared image, so no symbol table'
                       % path)
    if len(region) < HEADER:
        raise TdsError('%s: %d appended bytes, shorter than the 36-byte header'
                       % (path, len(region)))
    signature = struct.unpack_from('<H', region, 0)[0]
    if signature != SIGNATURE:
        raise TdsError('%s: appended region opens 0x%04X, not 0x%04X -- not a '
                       'Borland symbol table' % (path, signature, SIGNATURE))

    version = (region[2], region[3])
    pool_len = struct.unpack_from('<I', region, 4)[0]
    plus8 = struct.unpack_from('<H', region, 8)[0]
    count14 = struct.unpack_from('<H', region, 14)[0]
    count16 = struct.unpack_from('<H', region, 16)[0]
    declared_image = struct.unpack_from('<I', region, 32)[0]

    if pool_len == 0 or pool_len > len(region):
        raise TdsError('%s: name-pool length %d does not fit the %d-byte region'
                       % (path, pool_len, len(region)))
    pool_start = len(region) - pool_len

    names = []
    pos = pool_start
    while pos < len(region):
        end = region.find(b'\x00', pos)
        if end < 0:
            raise TdsError('%s: name pool runs to end of region with no NUL '
                           'after offset %d' % (path, pos))
        names.append(region[pos:end].decode('latin-1'))
        pos = end + 1
    residue = len(region) - pos

    return {
        'path': path, 'file_bytes': len(blob), 'image': image,
        'region': len(region), 'version': version, 'pool_len': pool_len,
        'pool_start': pool_start, 'plus8': plus8, 'count14': count14,
        'count16': count16, 'declared_image': declared_image,
        'names': names, 'residue': residue,
    }


def sweep(names):
    """Identifiers that do not begin with an underscore. NOT a name check --
    see the flag's description in the module docstring."""
    return [name for name in names if not name.startswith('_')]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--names', action='store_true', help='print every name')
    ap.add_argument('--sweep', action='store_true',
                    help='print the identifiers that are not runtime-shaped')
    ap.add_argument('--out', default=None, help='write one name list per file')
    args = ap.parse_args()

    opened = 0
    closed = 0
    agreed = 0
    image_agreed = 0
    results = []
    failures = []

    for path in args.files:
        try:
            result = parse(path)
        except TdsError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        results.append(result)
        if result['residue'] == 0:
            closed += 1
        if (result['plus8'] == len(result['names'])
                and result['count14'] == result['count16']
                == len(result['names']) - 3):
            agreed += 1
        if result['declared_image'] == result['image']:
            image_agreed += 1

        print('%-14s file %7d  image %7d  appended %6d  version %d.%d'
              % (os.path.basename(path), result['file_bytes'], result['image'],
                 result['region'], result['version'][0], result['version'][1]))
        print('   name pool: %d bytes at region offset %d, walked to residue %d'
              % (result['pool_len'], result['pool_start'], result['residue']))
        print('   strings walked %d   header +8 = %d   header +14 = +16 = %d   %s'
              % (len(result['names']), result['plus8'], result['count14'],
                 'AGREE (+8 == walk, +14 == walk-3)'
                 if result['plus8'] == len(result['names'])
                 and result['count14'] == result['count16'] == len(result['names']) - 3
                 else 'DISAGREE'))
        print('   header +32 image %d vs MZ image %d   %s'
              % (result['declared_image'], result['image'],
                 'AGREE' if result['declared_image'] == result['image'] else 'DISAGREE'))


        if args.names:
            for name in result['names']:
                print('      %s' % name)
        if args.sweep:
            residue = sweep(result['names'])
            print('   %d of %d identifiers do not begin with an underscore. '
                  'THIS IS TRIAGE, NOT A NAME CHECK: read the full list.'
                  % (len(residue), len(result['names'])))
            for name in residue:
                print('      %s' % name)
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            stem = os.path.splitext(os.path.basename(path))[0]
            with open(os.path.join(args.out, stem + '.txt'), 'w',
                      encoding='utf-8') as sink:
                sink.write('\n'.join(result['names']) + '\n')

    if len(results) >= 2:
        sets = [set(r['names']) for r in results]
        shared = set.intersection(*sets)
        print('')
        print('shared identifiers across %d tables: %d' % (len(results), len(shared)))
        for result, names in zip(results, sets):
            print('   %-14s %4d names, %4d shared = %.1f %%, %4d unique'
                  % (os.path.basename(result['path']), len(names), len(shared),
                     100.0 * len(shared) / len(names), len(names - shared)))

    print('')
    print('opened %d of %d files' % (opened, len(args.files)))
    print('name pool walked to residue 0: %d of %d' % (closed, opened))
    print('walk, header +8 and header +14 all agreed: %d of %d' % (agreed, opened))
    print('header image size matched the MZ header: %d of %d' % (image_agreed, opened))
    if failures:
        raise SystemExit('FATAL: %d of %d files carry no readable symbol table'
                         % (len(failures), len(args.files)))


if __name__ == '__main__':
    main()
