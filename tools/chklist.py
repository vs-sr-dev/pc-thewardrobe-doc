#!/usr/bin/env python3
"""chklist.py -- read Microsoft Anti-Virus's `CHKLIST.MS`, which is a list of
files that WERE in a directory.

FIFTY-FOUR BYTES, AND THEY ARE THE MOST TALKATIVE FILE IN THIS OBJECT.
MSAV shipped with MS-DOS 6.0 in 1993 and left one of these behind in every
directory it scanned. It records, per file, the name, the attribute byte, the
DOS timestamp, the size and a checksum -- so a `CHKLIST.MS` in a folder that
no longer contains the files it names is a **written record of two absences**,
with dates and sizes attached.

THE RECORD LAYOUT WAS DERIVED HERE AND THEN CONFIRMED BY SOMETHING IT WAS NOT
FITTED TO, which is the only reason it is worth trusting:

    +0   13B   file name, NUL-padded
    +13   1B   0x01 -- constant on both records seen here; unread
    +14   1B   DOS attribute byte -- 0x20, archive, on both
    +15   2B   DOS time   hhhhhmmm mmmsssss, seconds in units of two
    +17   2B   DOS date   yyyyyyym mmmddddd, year from 1980
    +19   4B   file size, little-endian
    +23   4B   checksum -- not interpreted here
    ----
         27B   per record

**The confirmation.** Decoding the second record's date field this way gives
**10 May 1991** for `VBRUN100.DLL`, the Visual Basic 1.0 runtime -- and
Visual Basic 1.0 was released in May 1991. That date was not used to fit the
layout and it is not in the file as text; a wrong field offset would have
produced a wrong year. `--selftest` re-derives it from bytes built here.

WHAT THIS TOOL WILL NOT SAY. It will not say the named files were ever in the
directory it found the list in. MSAV wrote these per-directory, which is an
argument, and it is the reader's argument and not this tool's output.

    python tools/chklist.py rovescino/CHKLIST.MS
    python tools/chklist.py --recurse rovescino
    python tools/chklist.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

RECORD = 27
NAME = 13


class ChklistError(Exception):
    """A file this reader will not pretend to understand."""


def is_chklist(blob):
    """A whole number of records, each opening with a plausible 8.3 name.

    There is no magic number -- MSAV identified these by their file name, and
    this box does not select by name -- so what is checked is the grammar: the
    length divides by 27, and every record starts with a NUL-terminated run of
    bytes that could be a DOS file name and could not be anything else.
    """
    if not blob or len(blob) % RECORD:
        return False
    for at in range(0, len(blob), RECORD):
        name = blob[at:at + NAME]
        if b'\x00' not in name:
            return False
        stem = name.split(b'\x00', 1)[0]
        if not stem or len(stem) > 12:
            return False
        for byte in stem:
            if not (48 <= byte <= 57 or 65 <= byte <= 90 or byte in b'.$~_-!#'):
                return False
        if b'.' not in stem:
            return False
    return True


def dos_time(value):
    return (value >> 11) & 0x1F, (value >> 5) & 0x3F, (value & 0x1F) * 2


def dos_date(value):
    return 1980 + ((value >> 9) & 0x7F), (value >> 5) & 0x0F, value & 0x1F


def records(blob):
    if len(blob) % RECORD:
        raise ChklistError('%d bytes is not a whole number of %d-byte records'
                           % (len(blob), RECORD))
    out = []
    for at in range(0, len(blob), RECORD):
        chunk = blob[at:at + RECORD]
        name = chunk[:NAME].split(b'\x00', 1)[0].decode('ascii', 'replace')
        flag, attr, time, date, size = struct.unpack('<BBHHI', chunk[13:23])
        hour, minute, second = dos_time(time)
        year, month, day = dos_date(date)
        out.append({
            'offset': at, 'name': name, 'flag': flag, 'attr': attr,
            'size': size, 'checksum': chunk[23:27],
            'stamp': '%04d-%02d-%02d %02d:%02d:%02d'
                     % (year, month, day, hour, minute, second),
            'valid': 1980 <= year <= 2107 and 1 <= month <= 12
                     and 1 <= day <= 31 and hour < 24 and minute < 60,
        })
    return out


# Where the object-dependent block of `--selftest` lives, and how many checks
# it contributes. `pc-hexxagon-doc` found this tool printing `21 checks, 0
# failures` in a repository that does not hold `CHKLIST.MS` -- six assertions
# had vanished and the summary line said nothing, which is exactly the defect
# `pc-rovescino-doc/docs/10` C.4 named: a check that cannot fire reads like a
# check that fired and found nothing. The count below is DECLARED here and
# VERIFIED wherever the object is reachable.
OBJECT_REL = 'rovescino/CHKLIST.MS'
OBJECT_CHECKS = 6


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    want('a DOS date of 0x16AA is 10 May 1991', dos_date(0x16AA), (1991, 5, 10))
    want('a DOS date of 0x18F8 is 24 July 1992', dos_date(0x18F8), (1992, 7, 24))
    want('a DOS date of 0x0021 is 1 January 1980', dos_date(0x0021),
         (1980, 1, 1))
    want('a DOS time of 0x0800 is 01:00:00', dos_time(0x0800), (1, 0, 0))
    want('a DOS time of 0x0C4C is 01:34:24', dos_time(0x0C4C), (1, 34, 24))
    want('seconds are stored in units of two', dos_time(0x0001), (0, 0, 2))

    built = (b'TEST.EXE'.ljust(NAME, b'\x00')
             + struct.pack('<BBHHI', 1, 0x20, 0x0C4C, 0x18F8, 223161)
             + b'\x16\xff\xff\xff')
    want('a record is 27 bytes', len(built), RECORD)
    got = records(built)[0]
    want('the name is read back', got['name'], 'TEST.EXE')
    want('the size is read back', got['size'], 223161)
    want('the stamp is read back', got['stamp'], '1992-07-24 01:34:24')
    want('the attribute is archive', got['attr'], 0x20)
    checks.append(('the stamp is inside the range DOS can express',
                   got['valid'], ''))
    want('two records parse as two', len(records(built * 2)), 2)

    checks.append(('the grammar accepts a well-formed list',
                   is_chklist(built), ''))
    checks.append(('a length that does not divide by 27 is refused',
                   not is_chklist(built + b'\x00'), ''))
    checks.append(('a record with no name terminator is refused',
                   not is_chklist(b'A' * NAME + built[NAME:]), ''))
    checks.append(('a record whose name has no dot is refused',
                   not is_chklist(b'NODOT'.ljust(NAME, b'\x00')
                                  + built[NAME:]), ''))
    checks.append(('an empty file is refused rather than called a clean list',
                   not is_chklist(b''), ''))
    checks.append(('twenty-seven zero bytes are refused',
                   not is_chklist(bytes(RECORD)), ''))
    try:
        records(b'\x00' * 20)
        checks.append(('a short file raises', False, 'it parsed'))
    except ChklistError:
        checks.append(('a short file raises', True, ''))

    # -- and against the object, if it is beside the box --------------------
    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            blob = handle.read()
        want('the object\'s list is 54 bytes', len(blob), 54)
        want('which is two records', len(blob) // RECORD, 2)
        rows = records(blob)
        want('the first is SCOPA.EXE', rows[0]['name'], 'SCOPA.EXE')
        want('the second is VBRUN100.DLL', rows[1]['name'], 'VBRUN100.DLL')
        # THE CONFIRMATION: this date is not fitted, it is checked.
        want('VBRUN100.DLL is stamped May 1991, which is when Visual Basic '
             '1.0 shipped', rows[1]['stamp'][:7], '1991-05')
        checks.append(('both timestamps are dates DOS can express',
                       all(r['valid'] for r in rows), ''))
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


def gather(args):
    """Selected by GRAMMAR, never by the name `CHKLIST.MS`."""
    if args.recurse:
        found = []
        for root, _dirs, names in os.walk(args.recurse):
            for name in sorted(names):
                path = os.path.join(root, name)
                try:
                    with open(path, 'rb') as handle:
                        if is_chklist(handle.read(4096)):
                            found.append(path)
                except OSError:
                    continue
        return found
    return [dirguard.want_file(p, 'chklist') for p in args.files]


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*')
    ap.add_argument('--recurse', metavar='DIR')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.files and not args.recurse:
        ap.error('give a file, or --recurse a directory')

    paths = gather(args)
    total = 0
    for path in paths:
        with open(path, 'rb') as handle:
            blob = handle.read()
        try:
            rows = records(blob)
        except ChklistError as exc:
            print('FAIL  %s: %s' % (os.path.basename(path), exc))
            continue
        print('%s' % os.path.basename(path))
        print('  bytes                : %d   records : %d   residue : %d'
              % (len(blob), len(rows), len(blob) % RECORD))
        print('')
        print('  off  name          attr  size        stamp                '
              'checksum   present here')
        folder = os.path.dirname(os.path.abspath(path))
        for row in rows:
            here = os.path.exists(os.path.join(folder, row['name']))
            print('  %3d  %-12s  0x%02X  %10d  %s  %s   %s'
                  % (row['offset'], row['name'], row['attr'], row['size'],
                     row['stamp'], row['checksum'].hex(),
                     'yes' if here else '**NO**'))
            total += 0 if here else 1
        print('')
        print('  files named that are NOT in this directory : %d of %d'
              % (sum(1 for r in rows
                     if not os.path.exists(os.path.join(folder, r['name']))),
                 len(rows)))
    print('')
    print('lists read : %d   files named and absent : %d' % (len(paths), total))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
