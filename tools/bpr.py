#!/usr/bin/env python3
"""bpr.py -- read the twelve `.BPR` members of `BEEP.LID`.

NOTHING PUBLIC DESCRIBES THIS FORMAT. It was measured on the twelve members.

    +0    4 bytes   FF FF FF FF on 12 of 12
    +4    n records of 6 bytes:
            +0  u16 LE   zero on 483 of the 484 records measured
            +2  u16 LE   a small count, 1..4 on 483 of 484
            +4  u16 LE   AN 8253 TIMER DIVISOR
    end   1 byte    FF on 12 of 12

    len == 5 + 6n on 12 of 12.

WHY THE THIRD FIELD IS A DIVISOR AND NOT A SAMPLE. The PC's timer runs at
1,193,180 Hz and channel 2 drives the speaker; a square wave of frequency f
is produced by loading 1193180/f. Across all 484 records the third field
spans 291 to 11,931, which is 4,100 Hz down to 100.0 Hz -- and 11,931 is
1193180/100 exactly, so the low end is a round frequency and not a round
divisor. A 100 Hz floor and a 4 kHz ceiling is the range of a beeper tune.

AND THIS IS NOT PULSE-WIDTH MODULATION, WHICH MATTERS TO A NEIGHBOUR.
`pc-linksthechallengeofgolf-doc/docs/04-the-sound.md` measured Access
Software's `.RS` members as a 70-level unsigned amplitude stream played by
pulse-width modulation on the same speaker. The comparison was open and this
is its answer: **484 of 484 values here exceed 69**, they are not amplitudes,
and Copysoft's beeper track is a list of tones rather than a sampled
waveform. Two publishers, one piece of hardware, two techniques.

`RACE.EXE`'s symbol table carries `_PlayPWMBlock`, `_PWMPlaying` and
`_StopPWM` alongside `_beeper_sounds`, so the engine has a pulse-width
routine as well. What that routine plays is NOT settled by this tool, and
the obvious candidate -- the `.VCE` samples, on a machine with no Sound
Blaster -- is a hypothesis and is labelled as one.

    python tools/bpr.py --validate _work/members/BEEP/*.BPR
    python tools/bpr.py --census   _work/members/BEEP/*.BPR
"""
import argparse
import collections
import os
import struct
import sys

TIMER_HZ = 1193180
RECORD = 6


class BprError(Exception):
    pass


def parse(path, blob):
    if len(blob) < 5:
        raise BprError('%s: %d bytes, too short for a head and a terminator'
                       % (path, len(blob)))
    if blob[:4] != b'\xff\xff\xff\xff':
        raise BprError('%s: opens %s, not FF FF FF FF'
                       % (path, blob[:4].hex(' ')))
    if blob[-1] != 0xFF:
        raise BprError('%s: last byte is 0x%02X, not 0xFF' % (path, blob[-1]))
    payload = len(blob) - 5
    if payload % RECORD:
        raise BprError('%s: %d payload bytes is not a whole number of %d-byte '
                       'records -- residue %d'
                       % (path, payload, RECORD, payload % RECORD))
    count = payload // RECORD
    records = [struct.unpack_from('<3H', blob, 4 + RECORD * i)
               for i in range(count)]
    for index, (_, _, divisor) in enumerate(records):
        if divisor == 0:
            raise BprError('%s: record %d has divisor 0, which would divide by '
                           'zero on the timer' % (path, index))
    return records


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    args = ap.parse_args()
    if not (args.validate or args.census):
        ap.error('pick --validate or --census')

    opened = 0
    total = 0
    field0 = collections.Counter()
    field1 = collections.Counter()
    divisors = []
    failures = []

    for path in sorted(args.files):
        with open(path, 'rb') as handle:
            blob = handle.read()
        try:
            records = parse(path, blob)
        except BprError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        total += len(records)
        for a, b, c in records:
            field0[a] += 1
            field1[b] += 1
            divisors.append(c)
        lo = min(c for _, _, c in records)
        hi = max(c for _, _, c in records)
        print('%-12s %5d B  %3d records  divisor %5d..%5d  =  %4d..%4d Hz'
              % (os.path.basename(path), len(blob), len(records), lo, hi,
                 TIMER_HZ // hi, TIMER_HZ // lo))
        if args.census:
            for index, (a, b, c) in enumerate(records):
                print('     %3d  %6d %6d  divisor %5d -> %5d Hz'
                      % (index, a, b, c, TIMER_HZ // c))

    print('')
    print('opened %d of %d files' % (opened, len(args.files)))
    print('len == 5 + 6n with an FFFFFFFF head and an FF tail: %d of %d'
          % (opened, len(args.files)))
    print('%d records total' % total)
    print('field +0 values: %s' % field0.most_common(4))
    print('field +2 values: %s' % field1.most_common(6))
    if divisors:
        print('divisor range %d..%d, i.e. %d..%d Hz'
              % (min(divisors), max(divisors),
                 TIMER_HZ // max(divisors), TIMER_HZ // min(divisors)))
        print('divisors outside 0..69, the amplitude range of the previous '
              "object's .RS members: %d of %d"
              % (sum(1 for d in divisors if d > 69), len(divisors)))
    if failures:
        raise SystemExit('FATAL: %d of %d members did not close'
                         % (len(failures), len(args.files)))


if __name__ == '__main__':
    main()
