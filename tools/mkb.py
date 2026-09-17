#!/usr/bin/env python3
"""mkb.py -- read the six `RACE*.MKB` files and the seventeen `.MBI` members.

NOTHING PUBLIC DESCRIBES EITHER FORMAT. Both were measured here, and they are
in one tool because they are the object's two "fixed records with a declared
payload length" shapes and because reading them side by side is what showed
they are NOT the same format -- which is the sort of thing an expanded
abbreviation would have hidden. Neither `MKB` nor `MBI` is expanded here.

`.MKB`, six files outside the archives, 110 to 634 bytes:

    +0    u16 LE   PAYLOAD LENGTH, equal to the file length minus two on 6 of 6
    +2    payload, a whole number of 4-byte records on 6 of 6:
            +0  u8       a kind byte; ten values occur across the 507 records,
                         0x00 0x01 0x02 0x04 0x05 0x08 0x0A 0x10 0x11 0x12
            +1  u8       an argument byte
            +2  u16 LE   a value

`.MBI`, seventeen members of `GAME.LID`, 13 to 79 bytes:

    +0    u8       0x49, the ASCII letter I, on 17 of 17
    +1    u16 LE   RECORD SIZE, 6 on 17 of 17
    +3    u16 LE   PAYLOAD LENGTH, a whole multiple of the record size on 17/17
    +5    u8       a per-file value, one of 1, 100, 232, 244
    +6    payload, records of 6 bytes:
            +0  u8       an opcode letter -- only R, L, U, D, W, X, Y, Z occur
            +1  u8
            +2  u16 LE
            +4  u16 LE
    end   u8       0x45, the ASCII letter E, on 17 of 17

    len == 7 + payload on 17 of 17.

THE FOUR LETTERS R, L, U AND D ARE NOT ASSERTED TO MEAN ANYTHING. That they
are the initials of four directions is an observation about the alphabet.
What is measured is that the opcode byte takes exactly eight values across
all 62 records of all 17 members, and that four of the eight are those.

    python tools/mkb.py --mkb Skunny/RACE?.MKB
    python tools/mkb.py --mbi _work/members/GAME/*.MBI
"""
import argparse
import collections
import os
import struct
import sys


class MkbError(Exception):
    pass


def read_mkb(path, blob):
    if len(blob) < 2:
        raise MkbError('%s: %d bytes, shorter than the length field' % (path, len(blob)))
    declared = struct.unpack_from('<H', blob, 0)[0]
    if declared != len(blob) - 2:
        raise MkbError('%s: u16 at 0 is %d, file length minus two is %d'
                       % (path, declared, len(blob) - 2))
    if declared % 4:
        raise MkbError('%s: %d payload bytes is not a whole number of 4-byte '
                       'records -- residue %d' % (path, declared, declared % 4))
    return [(blob[2 + 4 * i], blob[3 + 4 * i],
             struct.unpack_from('<H', blob, 4 + 4 * i)[0])
            for i in range(declared // 4)]


def read_mbi(path, blob):
    if len(blob) < 7:
        raise MkbError('%s: %d bytes, shorter than a head and a terminator'
                       % (path, len(blob)))
    if blob[0:1] != b'I':
        raise MkbError('%s: opens 0x%02X, not 0x49 (I)' % (path, blob[0]))
    if blob[-1:] != b'E':
        raise MkbError('%s: ends 0x%02X, not 0x45 (E)' % (path, blob[-1]))
    record, payload = struct.unpack_from('<2H', blob, 1)
    fifth = blob[5]
    if record == 0 or payload % record:
        raise MkbError('%s: payload %d is not a whole number of %d-byte records'
                       % (path, payload, record))
    if len(blob) != payload + 7:
        raise MkbError('%s: %d bytes but payload %d needs %d -- residue %+d'
                       % (path, len(blob), payload, payload + 7,
                          len(blob) - payload - 7))
    return record, fifth, [blob[6 + record * i:6 + record * (i + 1)]
                           for i in range(payload // record)]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--mkb', action='store_true')
    ap.add_argument('--mbi', action='store_true')
    args = ap.parse_args()
    if args.mkb == args.mbi:
        ap.error('pick exactly one of --mkb and --mbi')

    opened = 0
    total = 0
    kinds = collections.Counter()
    fifths = collections.Counter()
    failures = []

    for path in sorted(args.files):
        with open(path, 'rb') as handle:
            blob = handle.read()
        try:
            if args.mkb:
                records = read_mkb(path, blob)
                for kind, _, _ in records:
                    kinds['0x%02X' % kind] += 1
                print('%-14s %5d B  u16 %5d == len-2  %3d records of 4'
                      % (os.path.basename(path), len(blob), len(blob) - 2,
                         len(records)))
            else:
                size, fifth, records = read_mbi(path, blob)
                fifths[fifth] += 1
                for record in records:
                    kinds[chr(record[0])] += 1
                print('%-14s %5d B  record %d  payload %3d  byte5 %3d  '
                      '%3d records  opcodes %s'
                      % (os.path.basename(path), len(blob), size,
                         len(blob) - 7, fifth, len(records),
                         ''.join(chr(r[0]) for r in records)))
        except MkbError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        total += len(records)

    print('')
    print('opened %d of %d files with residue 0' % (opened, len(args.files)))
    print('%d records' % total)
    print('kind/opcode values: %s' % sorted(kinds.items()))
    if fifths:
        print('byte-5 values: %s' % sorted(fifths.items()))
    if failures:
        raise SystemExit('FATAL: %d of %d files did not close'
                         % (len(failures), len(args.files)))


if __name__ == '__main__':
    main()
