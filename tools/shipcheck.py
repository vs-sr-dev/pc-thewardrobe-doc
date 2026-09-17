#!/usr/bin/env python3
"""shipcheck.py -- three accounts of the same files, and which of them is the
source.

WHY THIS EXISTS
---------------
Most objects in this collection can be counted and hashed against themselves,
and nothing else. `pc-hexxagon-doc` is the first that can be checked against
what its authors put in the box, because it carries three independent accounts
of its own contents:

  1. a **manifest** the authors wrote -- `PACKING.LST`, twelve rows of a name
     and a byte count, in DOS directory-listing form;
  2. the **archive** it shipped as -- `HEXX01.EXE`, a PKZIP self-extractor,
     whose central directory carries a name, a size, a DOS timestamp and a
     **CRC-32** for every member;
  3. the **files on disk**.

A size can agree by accident. A CRC-32 over half a megabyte cannot. So (2)
against (3) settles whether the loose files ARE what shipped, and (1) against
(2) settles whether the paperwork was right.

**On HEXXAGON the paperwork is wrong twice, about its own package**, and the
archive sides with the disk both times. That is the finding this tool is for,
and it generalises: any object that ships a manifest and an archive of itself
can be put through it.

WHAT COUNTS AS A MANIFEST ROW
-----------------------------
`PACKING.LST` is a DOS directory listing: eight columns of name, three of
extension, then a decimal size. That is a GRAMMAR and not a guess, and rows
that do not match it are counted and reported rather than silently dropped --
because a manifest parser that quietly skips a row is a tool that can report
"nothing missing" about a file it never read.

    python tools/shipcheck.py --archive Hexxagon/HEXX01.EXE --tree Hexxagon \\
        --manifest Hexxagon/PACKING.LST
    python tools/shipcheck.py --archive Hexxagon/HEXX01.EXE --tree Hexxagon
    python tools/shipcheck.py --selftest

The archive may be a plain ZIP or a self-extractor: this reads the central
directory from the end of the file and never runs anything. `tools/zipdir.py`
prints the same directory in more detail and does not cross-check it.
"""
import argparse
import binascii
import collections
import datetime
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

EOCD = b'PK\x05\x06'
CEN = b'PK\x01\x02'
TAIL = 66000

# Eight columns of name, three of extension, then a decimal size. Anchored,
# because an unanchored version would find sizes inside prose.
ROW = re.compile(r'^([A-Za-z0-9_~!@#$%^&()\-{}]{1,8})\s+'
                 r'([A-Za-z0-9_]{1,3})\s+(\d+)\s')


class ShipError(Exception):
    """A file this tool will not pretend to understand."""


def dos_datetime(date, time):
    try:
        return datetime.datetime(1980 + ((date >> 9) & 0x7F),
                                 (date >> 5) & 0xF, date & 0x1F,
                                 (time >> 11) & 0x1F, (time >> 5) & 0x3F,
                                 (time & 0x1F) * 2)
    except ValueError:
        return None


def central_directory(path):
    """Names, sizes, CRCs and DOS stamps, read off the end of the file."""
    size = os.path.getsize(path)
    with open(path, 'rb') as handle:
        n = min(size, TAIL)
        handle.seek(size - n)
        tail = handle.read(n)
        at = tail.rfind(EOCD)
        if at < 0:
            raise ShipError('no end-of-central-directory record')
        (_sig, _dnum, _dcd, _ndisk, total, cdsize, cdoff,
         _clen) = struct.unpack_from('<IHHHHIIH', tail, at)
        handle.seek(cdoff)
        cd = handle.read(cdsize)
    rows = []
    p = 0
    while p + 46 <= len(cd) and cd[p:p + 4] == CEN:
        (_sig, _vmade, _vneed, flags, _method, mtime, mdate, crc, csize,
         usize, nlen, elen, klen, _ds, _ia, _ea,
         _lho) = struct.unpack_from('<IHHHHHHIIIHHHHHII', cd, p)
        raw = cd[p + 46:p + 46 + nlen]
        try:
            name = raw.decode('utf-8' if flags & 0x800 else 'cp437')
        except UnicodeDecodeError:
            name = raw.decode('latin-1')
        rows.append(dict(name=name, crc=crc, csize=csize, usize=usize,
                         stamp=dos_datetime(mdate, mtime)))
        p += 46 + nlen + elen + klen
    if len(rows) != total:
        raise ShipError('the end record says %d members and %d parsed'
                        % (total, len(rows)))
    return rows


def manifest(path):
    """Rows that match the grammar, and a count of the lines that did not."""
    with open(path, 'rb') as handle:
        blob = handle.read()
    text = blob.decode('cp437', errors='replace')
    rows = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        found = ROW.match(line)
        if not found:
            skipped += 1
            continue
        stem, ext, size = found.groups()
        rows.append(dict(name='%s.%s' % (stem.upper(), ext.upper()),
                         size=int(size), line=line.rstrip()))
    return rows, skipped


def crc_of(path):
    crc = 0
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(1 << 16)
            if not chunk:
                break
            crc = binascii.crc32(chunk, crc)
    return crc & 0xFFFFFFFF


# ---------------------------------------------------------------- selftest --

OBJECT_ARCHIVE = 'Hexxagon/HEXX01.EXE'
OBJECT_CHECKS = 11


def selftest(object_path=None, tree=None, manifest_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the manifest grammar, on rows written here -------------------------
    import tempfile
    sample = ('\r\n Header prose that is not a row.\r\n'
              'Name              Size  Description\r\n'
              '------------    ------  ---------------\r\n'
              'HEXX     EXE     42309  Main program.\r\n'
              'GRAPHICS HXG    594348  Program data file.\r\n'
              'FILE_ID  DIZ       354  Package description.\r\n')
    handle = tempfile.NamedTemporaryFile(delete=False, suffix='.lst')
    handle.write(sample.encode('cp437'))
    handle.close()
    try:
        rows, missed = manifest(handle.name)
        want('three rows match the DOS listing grammar', len(rows), 3)
        want('and the names come back with a dot',
             [r['name'] for r in rows],
             ['HEXX.EXE', 'GRAPHICS.HXG', 'FILE_ID.DIZ'])
        want('and the sizes come back as numbers',
             [r['size'] for r in rows], [42309, 594348, 354])
        # THE POINT: the lines that did not match are COUNTED, not dropped.
        want('and the three non-rows are counted, not silently skipped',
             missed, 3)
    finally:
        os.unlink(handle.name)

    want('a row of prose does not match', ROW.match('This is a sentence 42 '),
         None)
    want('a bare number does not match', ROW.match('   42309  '), None)
    checks.append(('a name and extension and size does match',
                   ROW.match('HEXX     EXE     42309  x') is not None, ''))

    # -- CRC-32, against a value computed the other way ---------------------
    handle = tempfile.NamedTemporaryFile(delete=False)
    handle.write(b'123456789')
    handle.close()
    try:
        # the standard CRC-32 check value for the string "123456789"
        want('CRC-32 of "123456789" is the published check value 0xCBF43926',
             crc_of(handle.name), 0xCBF43926)
    finally:
        os.unlink(handle.name)

    want('a DOS timestamp decodes', dos_datetime(0x2673, 0xA411),
         datetime.datetime(1999, 3, 19, 20, 32, 34))

    # -- and against the object --------------------------------------------
    here = os.path.dirname(os.path.abspath(__file__))
    arc = object_path or os.path.join(here, '..',
                                      *OBJECT_ARCHIVE.split('/'))
    root = tree or os.path.join(here, '..', 'Hexxagon')
    man = manifest_path or os.path.join(here, '..', 'Hexxagon',
                                        'PACKING.LST')
    if os.path.isfile(arc) and os.path.isdir(root) and os.path.isfile(man):
        before = len(checks)
        members = central_directory(arc)
        want('the archive holds 13 members', len(members), 13)
        rows, missed = manifest(man)
        want('the manifest names 12 files', len(rows), 12)
        # Three: the sentence, the column heading and the rule under it.
        # Blank lines are not counted, because a blank line is not a row that
        # failed to parse.
        want('and its three non-rows are counted', missed, 3)
        listed = {r['name'] for r in rows}
        held = {m['name'].upper() for m in members}
        want('one member is in the archive and not in the manifest',
             sorted(held - listed), ['COME.SEE'])
        want('and nothing is listed that the archive does not hold',
             sorted(listed - held), [])
        by_name = {m['name'].upper(): m for m in members}
        wrong = [(r['name'], r['size'], by_name[r['name']]['usize'])
                 for r in rows
                 if by_name[r['name']]['usize'] != r['size']]
        want('the manifest is wrong about two of its own twelve files',
             sorted(wrong),
             [('FILE_ID.DIZ', 354, 352), ('GRAPHICS.HXG', 594348, 626424)])
        same = diff = absent = 0
        for member in members:
            path = os.path.join(root, member['name'])
            if not os.path.isfile(path):
                absent += 1
            elif crc_of(path) == member['crc'] \
                    and os.path.getsize(path) == member['usize']:
                same += 1
            else:
                diff += 1
        # THE CONFIRMATION: a CRC-32 over half a megabyte does not agree by
        # accident, and this reads the file rather than trusting its size.
        want('twelve members are byte-identical to what shipped', same, 12)
        want('one is not', diff, 1)
        want('and none is missing', absent, 0)
        changed = [m['name'] for m in members
                   if os.path.isfile(os.path.join(root, m['name']))
                   and crc_of(os.path.join(root, m['name'])) != m['crc']]
        want('and the one that changed is HEXX.PIF', changed, ['HEXX.PIF'])
        stamps = collections.Counter(m['stamp'].year for m in members)
        want('every member in the archive is stamped 1993',
             [stamps[1993], len(members)], [13, 13])
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((OBJECT_CHECKS,
                        '%s and its tree not beside the box; pass --object, '
                        '--tree and --manifest to run them' % OBJECT_ARCHIVE))

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

def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archive')
    ap.add_argument('--tree')
    ap.add_argument('--manifest')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object, args.tree, args.manifest))
    if not args.archive:
        ap.error('give --archive, and --tree to check it against')
    arc = dirguard.want_file(args.archive, 'shipcheck')
    try:
        members = central_directory(arc)
    except ShipError as exc:
        print('REFUSE  %s: %s' % (os.path.basename(arc), exc))
        return 1

    print('=== THE ACCOUNTS ===')
    print('  archive           : %s, %d members'
          % (os.path.basename(arc), len(members)))
    rows = []
    if args.manifest:
        man = dirguard.want_file(args.manifest, 'shipcheck')
        rows, missed = manifest(man)
        print('  manifest          : %s, %d rows matched, %d lines did not'
              % (os.path.basename(man), len(rows), missed))
    if args.tree:
        names = sorted(os.listdir(args.tree))
        print('  tree              : %s, %d files'
              % (args.tree, sum(1 for n in names
                                if os.path.isfile(os.path.join(args.tree, n)))))
    print()

    by_name = {m['name'].upper(): m for m in members}
    if rows:
        listed = {r['name'] for r in rows}
        print('=== THE ARCHIVE AGAINST THE MANIFEST ===')
        extra = sorted(set(by_name) - listed)
        gone = sorted(listed - set(by_name))
        print('  in the archive and NOT in the manifest : %d   %s'
              % (len(extra), ' '.join(extra)))
        print('  in the manifest and NOT in the archive : %d   %s'
              % (len(gone), ' '.join(gone)))
        print()
        print('  %-14s %12s %16s %10s' % ('name', 'manifest', 'in the archive',
                                          'delta'))
        wrong = 0
        for row in rows:
            member = by_name.get(row['name'])
            if member is None:
                print('  %-14s %12d %16s' % (row['name'], row['size'],
                                             '(absent)'))
                continue
            delta = member['usize'] - row['size']
            if delta:
                wrong += 1
            print('  %-14s %12d %16d %+10d%s'
                  % (row['name'], row['size'], member['usize'], delta,
                     '   <<<' if delta else ''))
        print()
        print('  rows the archive contradicts : %d of %d' % (wrong, len(rows)))
        print()

    if args.tree:
        print('=== THE DISK AGAINST THE ARCHIVE, BY CRC-32 ===')
        print('  A size can agree by accident; a CRC-32 over half a megabyte')
        print('  cannot. This reads every byte of every file on disk.')
        print()
        print('  %-14s %12s %10s %10s   %s'
              % ('name', 'archive size', 'disk size', 'CRC-32', 'verdict'))
        same = diff = absent = 0
        for member in members:
            path = os.path.join(args.tree, member['name'])
            if not os.path.isfile(path):
                absent += 1
                print('  %-14s %12d %10s %10s   NOT ON DISK'
                      % (member['name'], member['usize'], '-', '-'))
                continue
            disk = os.path.getsize(path)
            crc = crc_of(path)
            if crc == member['crc'] and disk == member['usize']:
                same += 1
                verdict = 'identical to what shipped'
                mark = 'same'
            else:
                diff += 1
                verdict = '**CHANGED**'
                mark = 'DIFF'
            print('  %-14s %12d %10d %10s   %s'
                  % (member['name'], member['usize'], disk, mark, verdict))
        print()
        print('  members identical to what shipped : %d of %d'
              % (same, len(members)))
        print('  members changed on disk           : %d' % diff)
        print('  members not on disk               : %d' % absent)
        print()
        held = {m['name'].upper() for m in members}
        loose = [n for n in sorted(os.listdir(args.tree))
                 if os.path.isfile(os.path.join(args.tree, n))
                 and n.upper() not in held]
        print('=== ON DISK AND NOT IN THE ARCHIVE ===')
        for name in loose:
            print('  %-14s %10d bytes'
                  % (name, os.path.getsize(os.path.join(args.tree, name))))
        print('  count : %d' % len(loose))
        print()

    print('=== THE ARCHIVE\'S OWN CLOCK ===')
    print('  A DOS timestamp inside a ZIP is written by the packer and')
    print('  carries no timezone. It is not the file system\'s date and')
    print('  quoting one for the other is how a date gets moved.')
    print()
    waves = collections.Counter(str(m['stamp']) for m in members)
    for stamp, count in sorted(waves.items()):
        names = ' '.join(sorted(m['name'] for m in members
                                if str(m['stamp']) == stamp))
        print('  %s  x%-3d %s' % (stamp, count, names[:56]))
    if args.tree:
        print()
        print('  against the file system, on the members that are on disk:')
        offsets = collections.Counter()
        for member in members:
            path = os.path.join(args.tree, member['name'])
            if not os.path.isfile(path) or member['stamp'] is None:
                continue
            disk = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            offsets[round((member['stamp'] - disk).total_seconds())] += 1
        for seconds, count in sorted(offsets.items()):
            print('    archive ahead by %+d seconds (%+.4f hours) : %d members'
                  % (seconds, seconds / 3600.0, count))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
