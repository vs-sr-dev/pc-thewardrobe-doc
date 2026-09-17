#!/usr/bin/env python3
"""ltab.py -- read the eight `RACE.L*` tables of `GAME.LID`.

NOTHING PUBLIC DESCRIBES THIS FORMAT. It was measured on the eight members.

    +0    u16 LE   record count
    then count records of 32 bytes:
      +0    18 bytes   label, NUL-terminated, IN A DIRTY BUFFER
      +18   10 bytes   resource stem, NUL-terminated, dirty as well
      +28   u16 LE     total payload bytes of the named member
      +30   u16 LE     number of banks in the named member

The record length was fixed by arithmetic before any field was named: every
one of the eight files satisfies `len == 2 + 32 * count`, and the 18/10 split
was fixed by `SKUNNY UNBALANCE`, a sixteen-character label whose two trailing
NULs land exactly on the boundary.

THE CROSS-CHECK IS THE POINT. For a record naming a member that `sbank.py`
can walk, the identity

    member size == record.payload + 12 * record.banks

holds, and the two sides are measured by different means: the left by
`os.path.getsize`, the right by reading a table that never mentions it. The
tool reports how many of how many, in both directions, and a mismatch is
printed rather than hidden.

THE LETTERS ARE NOT EXPANDED. `L`, `S`, `HE`, `BA`, `BL`, `PI`, `SO`, `EF`,
`WE`, `PP`, `EN` and `DEF` are printed as they are found. The symbol table of
`RACE.EXE` carries `_HEROLIB`, `_BADLIB`, `_BLOCKLIB`, `_WEPLIB`,
`_PICKUPLIB`, `_PICLIB` and `_EFLIB`, and whether those correspond is a
question for a chapter with evidence in it, not for this tool.

    python tools/ltab.py _work/members/GAME/RACE.L*
    python tools/ltab.py _work/members/GAME/RACE.L* --members _work/members/GAME
"""
import argparse
import collections
import os
import struct
import sys

RECORD = 32
LABEL = 18
STEM = 10


class TableError(Exception):
    pass


def field(raw):
    """Return (text, dirty_tail) for a NUL-terminated field in a dirty buffer."""
    nul = raw.find(b'\x00')
    if nul < 0:
        return raw.decode('latin-1'), b''
    return raw[:nul].decode('latin-1'), raw[nul + 1:].rstrip(b'\x00')


def parse(path):
    with open(path, 'rb') as handle:
        blob = handle.read()
    if len(blob) < 2:
        raise TableError('%s: %d bytes, shorter than the count field'
                         % (path, len(blob)))
    count = struct.unpack_from('<H', blob, 0)[0]
    expect = 2 + RECORD * count
    if expect != len(blob):
        raise TableError('%s: count %d needs %d bytes, file is %d -- residue %+d'
                         % (path, count, expect, len(blob), len(blob) - expect))
    records = []
    for index in range(count):
        base = 2 + index * RECORD
        label, label_dirt = field(blob[base:base + LABEL])
        stem, stem_dirt = field(blob[base + LABEL:base + LABEL + STEM])
        payload, banks = struct.unpack_from('<2H', blob, base + LABEL + STEM)
        records.append({
            'index': index, 'label': label, 'label_dirt': label_dirt,
            'stem': stem, 'stem_dirt': stem_dirt,
            'payload': payload, 'banks': banks,
        })
    return records


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--members', default=None,
                    help='directory of extracted members, to cross-check sizes')
    args = ap.parse_args()

    sizes = {}
    if args.members:
        for name in os.listdir(args.members):
            stem = os.path.splitext(name)[0].upper()
            path = os.path.join(args.members, name)
            sizes.setdefault(stem, []).append(
                (os.path.splitext(name)[1].lstrip('.').upper(),
                 os.path.getsize(path)))

    opened = 0
    total_records = 0
    dirty_labels = 0
    dirty_stems = 0
    checked = 0
    agreed = 0
    unresolved = []
    failures = []

    for path in sorted(args.files):
        try:
            records = parse(path)
        except TableError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        total_records += len(records)
        print('=== %s : %d records, %d bytes, closes on 2 + 32n ==='
              % (os.path.basename(path), len(records), 2 + 32 * len(records)))
        for rec in records:
            dirty_labels += 1 if rec['label_dirt'] else 0
            dirty_stems += 1 if rec['stem_dirt'] else 0
            note = ''
            candidates = sizes.get(rec['stem'].upper(), [])
            if candidates:
                predicted = rec['payload'] + 12 * rec['banks']
                hits = [ext for ext, size in candidates if size == predicted]
                checked += 1
                if hits:
                    agreed += 1
                    note = 'size %d == payload+12*banks, member .%s' % (
                        predicted, '/.'.join(hits))
                else:
                    note = ('MISMATCH predicted %d, members %s'
                            % (predicted, candidates))
                    unresolved.append((os.path.basename(path), rec['stem'], note))
            elif args.members:
                note = 'no member named %s' % rec['stem']
                unresolved.append((os.path.basename(path), rec['stem'], note))
            print('  %2d  %-18s -> %-10s payload %6d  banks %2d   %s'
                  % (rec['index'], rec['label'], rec['stem'], rec['payload'],
                     rec['banks'], note))
            if rec['label_dirt'] or rec['stem_dirt']:
                print('      dirty buffer: label tail %r  stem tail %r'
                      % (rec['label_dirt'], rec['stem_dirt']))

    print('')
    print('opened %d of %d tables, %d records'
          % (opened, len(args.files), total_records))
    print('records with a dirty label tail: %d; with a dirty stem tail: %d'
          % (dirty_labels, dirty_stems))
    if args.members:
        print('size identity checked on %d of %d records, agreed on %d'
              % (checked, total_records, agreed))
        print('records naming no member on disc: %d'
              % sum(1 for _, _, note in unresolved if note.startswith('no member')))
    if failures:
        raise SystemExit('FATAL: %d of %d tables did not close'
                         % (len(failures), len(args.files)))


if __name__ == '__main__':
    main()
