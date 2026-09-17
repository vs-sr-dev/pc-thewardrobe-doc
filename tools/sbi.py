#!/usr/bin/env python3
"""sbi.py -- read `AUDIO.INS` as a bank of AdLib OPL2 instruments.

`RACE.EXE` and `FOREST.EXE` both carry the symbol `_LoadSBIFile`, and
`AUDIO.INS` is 2,048 bytes = 128 x 16 exactly. That is a hypothesis and this
tool is the test.

THE OPL2 INSTRUMENT IS SOMEBODY ELSE'S DEFINITION. Yamaha's YM3812 register
map and AdLib's eleven-byte instrument block are public; the field order below
is that public layout, used here as a predictor and not presented as a
discovery:

     0  modulator  AM / VIB / EG-type / KSR / multiplier
     1  carrier    the same
     2  modulator  key-scale level / output level
     3  carrier    the same
     4  modulator  attack / decay
     5  carrier    the same
     6  modulator  sustain / release
     7  carrier    the same
     8  modulator  WAVE SELECT -- a two-bit field, so 0..3
     9  carrier    WAVE SELECT -- a two-bit field, so 0..3
    10             FEEDBACK / CONNECTION -- 4 bits, so 0..15
    11..15         padding to the 16-byte slot

THREE RANGE TESTS, EACH OF WHICH COULD HAVE FAILED:

  * bytes 11..15 must be zero on every record, because the instrument is
    eleven bytes in a sixteen-byte slot;
  * bytes 8 and 9 must lie in 0..3, because wave select is two bits;
  * byte 10 must lie in 0..15, because feedback/connection is four bits.

Nothing constrains an arbitrary 2,048-byte file to satisfy all three. The
tool reports each as how many of 128 and refuses to call the file an
instrument bank if any of them fails.

    python tools/sbi.py Skunny/AUDIO.INS
    python tools/sbi.py Skunny/HI.TBL        # a negative control
"""
import argparse
import collections
import os
import sys

SLOT = 16
INSTRUMENT = 11


class SbiError(Exception):
    pass


def parse(path):
    with open(path, 'rb') as handle:
        blob = handle.read()
    if len(blob) % SLOT:
        raise SbiError('%s: %d bytes is not a whole number of %d-byte slots'
                       % (path, len(blob), SLOT))
    records = len(blob) // SLOT
    padding_clean = 0
    wave_ok = 0
    feedback_ok = 0
    live = 0
    waves = collections.Counter()
    feedback = collections.Counter()
    for index in range(records):
        slot = blob[index * SLOT:(index + 1) * SLOT]
        if not any(slot):
            pass
        else:
            live += 1
        if not any(slot[INSTRUMENT:]):
            padding_clean += 1
        if slot[8] <= 3 and slot[9] <= 3:
            wave_ok += 1
        waves[slot[8]] += 1
        waves[slot[9]] += 1
        if slot[10] <= 15:
            feedback_ok += 1
        feedback[slot[10]] += 1
    return {
        'path': path, 'bytes': len(blob), 'records': records, 'live': live,
        'padding_clean': padding_clean, 'wave_ok': wave_ok,
        'feedback_ok': feedback_ok, 'waves': waves, 'feedback': feedback,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    args = ap.parse_args()

    opened = 0
    accepted = 0
    failures = []
    for path in args.files:
        try:
            result = parse(path)
        except SbiError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        n = result['records']
        ok = (result['padding_clean'] == n and result['wave_ok'] == n
              and result['feedback_ok'] == n)
        accepted += 1 if ok else 0
        print('%-14s %5d B = %d slots of %d, %d of them non-zero'
              % (os.path.basename(path), result['bytes'], n, SLOT, result['live']))
        print('   bytes 11..15 all zero      : %3d of %3d' % (result['padding_clean'], n))
        print('   bytes 8,9 within 0..3      : %3d of %3d' % (result['wave_ok'], n))
        print('   byte 10 within 0..15       : %3d of %3d' % (result['feedback_ok'], n))
        print('   wave-select values observed: %s'
              % sorted(result['waves'].items()))
        print('   feedback/connection values : %s'
              % sorted(result['feedback'].items()))
        print('   verdict: %s' % ('an OPL2 instrument bank on all three tests'
                                  if ok else 'REFUSED, at least one range test failed'))

    print('')
    print('opened %d of %d files; accepted as an instrument bank %d of %d'
          % (opened, len(args.files), accepted, opened))
    if failures:
        raise SystemExit('FATAL: %d of %d files are not a whole number of slots'
                         % (len(failures), len(args.files)))


if __name__ == '__main__':
    main()
