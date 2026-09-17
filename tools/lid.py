#!/usr/bin/env python3
"""lid.py -- read the `.LID` archive of Copysoft's MS-DOS engine.

There is no magic number and there is no count field. The file opens with a
directory of fixed 22-byte records:

    +0    14 bytes   member name, NUL-terminated, in a DIRTY BUFFER
    +14   u32 LE     member size
    +18   u32 LE     member absolute offset from the start of the file

and the entry count is recovered from the arithmetic, because the first
entry's offset is where the directory ends:

    entries = offsets[0] / 22

The last entry is a TERMINATOR: its name begins with NUL and its size and
offset are both zero, so a directory of n entries carries n-1 members.

Two properties are checked and neither is assumed:

  * the member offsets form a CONTIGUOUS chain -- offset[i] + size[i] ==
    offset[i+1] -- with no gaps and no overlaps;
  * the last member ends exactly at end of file, residue 0.

THE NAME FIELD IS A DIRTY BUFFER. The writer copied each new name over the
previous one without clearing the 14 bytes first, so a short name is followed
by its NUL and then by the tail of whatever was there before:

    b'ODEAR.BPR\\x00\\x00\\x00\\x00\\x00'
    b'BNG.BPR\\x00R\\x00\\x00\\x00\\x00\\x00'   <- the R is ODEAR.BPR's ninth byte

The name is therefore everything up to the FIRST NUL and the rest is
forensic residue, reported by --dirty and never silently dropped.

    python tools/lid.py --validate Skunny/*.LID
    python tools/lid.py --census   Skunny/*.LID
    python tools/lid.py --dirty    Skunny/*.LID
    python tools/lid.py --extract  Skunny/GAME.LID --out _work/game

Validate before census, always. Failure is fatal and loud: this tool never
returns a partial directory, because a partial directory read out of a format
with no magic is indistinguishable from a wrong format.
"""
import argparse
import collections
import os
import struct
import sys

RECORD = 22
NAME_LEN = 14


class LidError(Exception):
    pass


def parse(path):
    """Return (entries, blob). entries is a list of dicts, terminator last."""
    with open(path, 'rb') as handle:
        blob = handle.read()
    if len(blob) < RECORD:
        raise LidError('%s: %d bytes, shorter than one directory record'
                       % (path, len(blob)))

    first_offset = struct.unpack_from('<I', blob, 18)[0]
    if first_offset == 0 or first_offset % RECORD != 0:
        raise LidError('%s: offsets[0] = %d is not a positive multiple of %d, '
                       'so the entry count cannot be recovered'
                       % (path, first_offset, RECORD))
    count = first_offset // RECORD
    if first_offset > len(blob):
        raise LidError('%s: directory of %d entries needs %d bytes, file is %d'
                       % (path, count, first_offset, len(blob)))

    entries = []
    for index in range(count):
        base = index * RECORD
        raw_name = blob[base:base + NAME_LEN]
        size, offset = struct.unpack_from('<II', blob, base + NAME_LEN)
        nul = raw_name.find(b'\x00')
        if nul < 0:
            raise LidError('%s: entry %d has no NUL in its 14-byte name field'
                           % (path, index))
        entries.append({
            'index': index,
            'name': raw_name[:nul].decode('latin-1'),
            'raw_name': raw_name,
            'dirty': raw_name[nul + 1:].rstrip(b'\x00'),
            'size': size,
            'offset': offset,
        })

    last = entries[-1]
    if last['raw_name'][0:1] != b'\x00' or last['size'] != 0 or last['offset'] != 0:
        raise LidError('%s: last entry is not a terminator: name=%r size=%d '
                       'offset=%d' % (path, last['raw_name'], last['size'],
                                      last['offset']))
    for entry in entries[:-1]:
        if entry['raw_name'][0:1] == b'\x00':
            raise LidError('%s: entry %d has a NUL-leading name before the end'
                           % (path, entry['index']))
    return entries, blob


def validate(path):
    """Check the chain and the residue. Returns a dict of the measurements."""
    entries, blob = parse(path)
    members = entries[:-1]
    if not members:
        raise LidError('%s: directory holds a terminator and nothing else' % path)

    cursor = entries[0]['offset']
    if cursor != len(entries) * RECORD:
        raise LidError('%s: offsets[0] = %d but %d entries need %d bytes'
                       % (path, cursor, len(entries), len(entries) * RECORD))
    for entry in members:
        if entry['offset'] != cursor:
            raise LidError('%s: member %d (%s) starts at %d, chain expected %d '
                           '-- gap or overlap of %d bytes'
                           % (path, entry['index'], entry['name'],
                              entry['offset'], cursor, entry['offset'] - cursor))
        if entry['offset'] + entry['size'] > len(blob):
            raise LidError('%s: member %d (%s) runs to %d past the %d-byte file'
                           % (path, entry['index'], entry['name'],
                              entry['offset'] + entry['size'], len(blob)))
        cursor += entry['size']
    residue = len(blob) - cursor
    return {
        'path': path,
        'bytes': len(blob),
        'entries': len(entries),
        'members': len(members),
        'directory': len(entries) * RECORD,
        'payload': cursor - entries[0]['offset'],
        'residue': residue,
        'list': members,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--dirty', action='store_true')
    ap.add_argument('--extract', action='store_true')
    ap.add_argument('--out', default=None)
    ap.add_argument('--expect-members', type=int, default=None)
    args = ap.parse_args()

    if not (args.validate or args.census or args.dirty or args.extract):
        ap.error('pick one of --validate --census --dirty --extract')
    if args.extract and not args.out:
        ap.error('--extract needs --out')

    opened = 0
    total_members = 0
    total_payload = 0
    total_bytes = 0
    residue_zero = 0
    extensions = collections.Counter()
    failures = []

    for path in args.files:
        try:
            result = validate(path)
        except LidError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        total_members += result['members']
        total_payload += result['payload']
        total_bytes += result['bytes']
        if result['residue'] == 0:
            residue_zero += 1

        if args.validate or args.census:
            print('%-14s %9d B  %3d entries = %3d members  dir %4d  '
                  'payload %9d  residue %d'
                  % (os.path.basename(path), result['bytes'], result['entries'],
                     result['members'], result['directory'], result['payload'],
                     result['residue']))

        for entry in result['list']:
            stem, dot, ext = entry['name'].rpartition('.')
            extensions[ext.upper() if dot else '(none)'] += 1
            if args.census:
                print('    %-14s %8d @ %8d' % (entry['name'], entry['size'],
                                               entry['offset']))
            if args.dirty and entry['dirty']:
                print('    %-14s dirty tail %r' % (entry['name'], entry['dirty']))

        if args.extract:
            with open(path, 'rb') as handle:
                blob = handle.read()
            out = os.path.join(args.out, os.path.basename(path).split('.')[0])
            os.makedirs(out, exist_ok=True)
            # NAMES ARE NOT UNIQUE. GAME.LID stores SFONT.SP twice, at two
            # offsets, byte-identical. Writing both under one name loses a
            # member silently and made the first extraction pass produce 160
            # files for 161 members; the collision is renamed, never dropped.
            seen = collections.Counter()
            collisions = 0
            for entry in result['list']:
                payload = blob[entry['offset']:entry['offset'] + entry['size']]
                if len(payload) != entry['size']:
                    raise SystemExit('FATAL %s: short read on %s'
                                     % (path, entry['name']))
                seen[entry['name']] += 1
                name = entry['name']
                if seen[name] > 1:
                    collisions += 1
                    name = '%s.dup%d' % (name, seen[entry['name']])
                with open(os.path.join(out, name), 'wb') as sink:
                    sink.write(payload)
            written = len(os.listdir(out))
            print('    extracted %d members to %s (%d distinct names, %d '
                  'collisions renamed, %d files on disc)'
                  % (result['members'], out, len(seen), collisions, written))
            if written != result['members']:
                raise SystemExit('FATAL %s: %d members but %d files written'
                                 % (path, result['members'], written))

    print('')
    print('opened %d of %d files, %d bytes' % (opened, len(args.files), total_bytes))
    print('residue 0 on %d of %d' % (residue_zero, opened))
    print('%d members, %d payload bytes' % (total_members, total_payload))
    if args.validate or args.census:
        print('extensions: ' + '  '.join('%s %d' % (ext, n) for ext, n
                                         in sorted(extensions.items())))

    if failures:
        raise SystemExit('FATAL: %d of %d files did not validate'
                         % (len(failures), len(args.files)))
    if args.expect_members is not None and total_members != args.expect_members:
        raise SystemExit('FATAL: expected %d members, counted %d'
                         % (args.expect_members, total_members))


if __name__ == '__main__':
    main()
