#!/usr/bin/env python3
"""zipclocks.py -- the two clocks a ZIP member can carry, the third one an
extraction writes, and the production waves on the one that is the object's.

WHY THREE CLOCKS
----------------
A ZIP central-directory entry (PKWARE APPNOTE, a public format, read here
field by field) carries a **DOS date and time**: a local wall clock with no
timezone and two-second resolution, copied from the file the packer read. An
Info-ZIP `UT` extra field (id 0x5455) may follow, holding the same moment as
**Unix epoch seconds in UTC** -- written by the tool that made the archive,
on the machine and in the timezone it ran in. And when somebody extracts the
archive, `unzip` writes a **file-system mtime** derived from one of those two
and the extracting machine's own offset.

On `Bianco-Natale_DOS_IT.zip` the three disagree by whole hours:

    BACK1.BMB   DOS field   1994-10-07 19:06:26      the 1994 clock
                UT field    1994-10-08 01:06:26      +6 h: the repackager's UTC
                on disk     1994-10-08 03:06:26      +8 h: the extraction

The DOS field is the only one of the three that was written in 1994, and it is
the one a wave table has to be built on. A wave table built on the mtimes --
which a pre-briefing did -- puts seven of eight waves on the wrong calendar
day. `--waves` builds it on the DOS field, and `--tree DIR` adds the on-disk
column beside the other two so the offsets are printed and not remembered.

    python tools/zipclocks.py Bianco-Natale_DOS_IT.zip
    python tools/zipclocks.py Bianco-Natale_DOS_IT.zip --tree Bianco-Natale
    python tools/zipclocks.py Bianco-Natale_DOS_IT.zip --waves [--gap 3600]
    python tools/zipclocks.py --selftest

WHAT IT DOES NOT DO
-------------------
It does not extract anything and it does not say which clock is *right*: the
DOS field is the oldest and the only one with no later machine in it, and
that is a statement about provenance, not accuracy. It reads the central
directory only, as `zipdir.py` does, and refuses a file with no
end-of-central-directory record.
"""
import argparse
import collections
import datetime
import io
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

EOCD = b'PK\x05\x06'
CEN = b'PK\x01\x02'
UT_ID = 0x5455


class ZipClocksError(Exception):
    """A file this reader will not pretend to understand."""


def dos_datetime(date, time):
    try:
        return datetime.datetime(1980 + ((date >> 9) & 0x7F),
                                 (date >> 5) & 0xF, date & 0x1F,
                                 (time >> 11) & 0x1F, (time >> 5) & 0x3F,
                                 (time & 0x1F) * 2)
    except ValueError:
        return None


def ut_field(extra):
    """The Info-ZIP UT mtime as a naive UTC datetime, or None."""
    p = 0
    while p + 4 <= len(extra):
        ident, size = struct.unpack_from('<HH', extra, p)
        body = extra[p + 4:p + 4 + size]
        if ident == UT_ID and len(body) >= 5 and body[0] & 1:
            secs = struct.unpack_from('<I', body, 1)[0]
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(
                seconds=secs)
        p += 4 + size
    return None


def members(blob):
    """Every central-directory entry: name, DOS datetime, UT datetime,
    made-by, and the raw extra field."""
    at = blob.rfind(EOCD)
    if at < 0:
        raise ZipClocksError('no end-of-central-directory record')
    (_sig, _dn, _dc, _nd, total, cdsize, cdoff,
     _clen) = struct.unpack_from('<IHHHHIIH', blob, at)
    cd = blob[cdoff:cdoff + cdsize]
    out = []
    p = 0
    while p + 46 <= len(cd) and cd[p:p + 4] == CEN:
        (_s, made, _need, flags, _method, mtime, mdate, _crc, _csize, usize,
         nlen, elen, klen, _ds, _ia, _ea, _lho) = struct.unpack_from(
            '<IHHHHHHIIIHHHHHII', cd, p)
        name = cd[p + 46:p + 46 + nlen]
        extra = cd[p + 46 + nlen:p + 46 + nlen + elen]
        try:
            text = name.decode('utf-8' if flags & 0x800 else 'cp437')
        except UnicodeDecodeError:
            text = name.decode('latin-1')
        out.append({'name': text, 'size': usize,
                    'dos': dos_datetime(mdate, mtime), 'ut': ut_field(extra),
                    'made': made, 'extra_len': elen})
        p += 46 + nlen + elen + klen
    if len(out) != total:
        raise ZipClocksError('the directory declares %d entries and holds %d'
                             % (total, len(out)))
    if not out:
        raise ZipClocksError('an archive with no members')
    return out


def disk_mtime(tree, name):
    path = os.path.join(tree, *name.split('/'))
    if not os.path.isfile(path):
        return None
    return datetime.datetime.fromtimestamp(os.path.getmtime(path))


def offsets(rows, key):
    """Counter of (other clock - DOS clock) in whole seconds, for members
    that carry both."""
    out = collections.Counter()
    for r in rows:
        if r['dos'] is not None and r.get(key) is not None:
            out[int(round((r[key] - r['dos']).total_seconds()))] += 1
    return out


def waves(rows, gap):
    """Members clustered on the DOS clock by a gap threshold."""
    dated = sorted((r for r in rows if r['dos'] is not None),
                   key=lambda r: (r['dos'], r['name']))
    out = []
    cur = [dated[0]]
    for r in dated[1:]:
        if (r['dos'] - cur[-1]['dos']).total_seconds() > gap:
            out.append(cur)
            cur = [r]
        else:
            cur.append(r)
    out.append(cur)
    return out


def read(path, who='zipclocks'):
    real = dirguard.want_file(path, who)
    with open(real, 'rb') as handle:
        blob = handle.read()
    try:
        rows = members(blob)
    except ZipClocksError as exc:
        raise ZipClocksError('%s: %s' % (os.path.basename(real), exc))
    return real, rows


# ---------------------------------------------------------------- selftest --

OBJECT_REL = 'Bianco-Natale_DOS_IT.zip'
OBJECT_CHECKS = 8


def _build(entries, with_ut=True, hours_ahead=6):
    """A ZIP written with the standard library, each member carrying a DOS
    time and, if asked, an Info-ZIP UT field `hours_ahead` later."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, when, payload in entries:
            zi = zipfile.ZipInfo(name, date_time=when.timetuple()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            if with_ut:
                epoch = int((when - datetime.datetime(1970, 1, 1)
                             + datetime.timedelta(hours=hours_ahead))
                            .total_seconds())
                zi.extra = struct.pack('<HHB', UT_ID, 5, 1) + struct.pack(
                    '<I', epoch)
            z.writestr(zi, payload)
    return buf.getvalue()


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    t0 = datetime.datetime(1994, 10, 7, 19, 6, 26)
    entries = [('A.BIN', t0, b'a' * 10),
               ('B.BIN', t0 + datetime.timedelta(seconds=20), b'b' * 20),
               ('C.BIN', t0 + datetime.timedelta(days=1, hours=3), b'c' * 30)]
    blob = _build(entries)
    rows = members(blob)
    want('three members read back from an archive built here',
         [r['name'] for r in rows], ['A.BIN', 'B.BIN', 'C.BIN'])
    want('the DOS field round-trips to the second (an even one)',
         rows[0]['dos'], t0)
    want('the UT field reads as a datetime six hours ahead',
         rows[0]['ut'] - rows[0]['dos'], datetime.timedelta(hours=6))
    want('UT minus DOS is +21600 s on 3 of 3', offsets(rows, 'ut'),
         collections.Counter({21600: 3}))
    want('an archive without UT fields reports no UT clock',
         [r['ut'] for r in members(_build(entries, with_ut=False))],
         [None, None, None])
    w = waves(rows, 3600)
    want('two waves at a one-hour gap: A and B together, C alone',
         [[r['name'] for r in wave] for wave in w],
         [['A.BIN', 'B.BIN'], ['C.BIN']])
    want('one wave at a two-day gap', len(waves(rows, 2 * 86400)), 1)
    odd = datetime.datetime(1994, 10, 7, 19, 7, 55)
    rows_odd = members(_build([('O.BIN', odd, b'o')]))
    want('a DOS field cannot hold an odd second: 19:07:55 is stored as '
         '19:07:54', rows_odd[0]['dos'], odd.replace(second=54))
    want('so UT minus DOS is 6 h + 1 s on that member',
         offsets(rows_odd, 'ut'), collections.Counter({21601: 1}))
    try:
        members(b'not a zip at all')
        checks.append(('a file with no EOCD is refused', False, 'it parsed'))
    except ZipClocksError as exc:
        checks.append(('a file with no EOCD is refused',
                       'end-of-central' in str(exc), str(exc)))

    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            rows = members(handle.read())
        want('the object holds 18 members', len(rows), 18)
        want('every member carries a nine-byte extra field',
             set(r['extra_len'] for r in rows), {9})
        want('and every extra field is an Info-ZIP UT mtime',
             sum(1 for r in rows if r['ut'] is not None), 18)
        want('version made by is 0x0B17 on all 18: zip spec 2.3, host 11',
             set(r['made'] for r in rows), {0x0B17})
        want('UT minus DOS is +21600 s (6 h) on 17 members and +21598 on 1',
             offsets(rows, 'ut'), collections.Counter({21600: 17, 21598: 1}))
        want('the DOS clock runs from 1994-09-25 11:53:30 to 1994-10-08 '
             '22:04:10', [min(r['dos'] for r in rows),
                          max(r['dos'] for r in rows)],
             [datetime.datetime(1994, 9, 25, 11, 53, 30),
              datetime.datetime(1994, 10, 8, 22, 4, 10)])
        w = waves(rows, 3600)
        want('eight waves at a one-hour gap, and BN.EXE is the last, alone',
             [len(w), [r['name'] for r in w[-1]]], [8, ['BN.EXE']])
        want('the seven-file wave is BACK1..5, TECNOART and TA, on 7 October',
             [[r['name'] for r in wave] for wave in w if len(wave) == 7],
             [['BACK1.BMB', 'BACK2.BMB', 'BACK3.BMB', 'BACK4.BMB',
               'BACK5.BMB', 'TECNOART.BMB', 'TA.BMB']])
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

def fmt(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else '-'


def cmd_table(path, rows, tree):
    print('%s : %d members' % (os.path.basename(path), len(rows)))
    made = collections.Counter(r['made'] for r in rows)
    print('  version made by : %s'
          % ', '.join('0x%04X x%d (zip spec %d.%d, host %d)'
                      % (m, n, (m & 0xFF) // 10, (m & 0xFF) % 10, m >> 8)
                      for m, n in sorted(made.items())))
    print('  UT extra fields : %d of %d members'
          % (sum(1 for r in rows if r['ut']), len(rows)))
    print()
    print('  %-14s %-19s %-19s %s'
          % ('name', 'DOS field', 'UT field (UTC)',
             'on disk' if tree else ''))
    for r in rows:
        r['disk'] = disk_mtime(tree, r['name']) if tree else None
        print('  %-14s %-19s %-19s %s'
              % (r['name'], fmt(r['dos']), fmt(r['ut']),
                 fmt(r['disk']) if tree else ''))
    print()
    for key, label in (('ut', 'UT field minus DOS field'),
                       ('disk', 'on-disk mtime minus DOS field')):
        off = offsets(rows, key)
        if not off:
            continue
        print('  %s:' % label)
        for secs, n in sorted(off.items()):
            print('      %+7d s  (%+8.4f h) : %d members'
                  % (secs, secs / 3600.0, n))
    print()
    print('  The DOS field has no timezone and two-second resolution; it is')
    print('  the clock the packer copied from the file. The UT field is the')
    print('  repackager\'s UTC. The on-disk mtime is whatever unzip wrote on')
    print('  the machine that extracted this copy. Only the first is 1994\'s.')


def cmd_waves(path, rows, gap):
    w = waves(rows, gap)
    total = sum(r['size'] for r in rows)
    print('%s : %d members, waves on the DOS field, gap %d s = %.1f h'
          % (os.path.basename(path), len(rows), gap, gap / 3600.0))
    print()
    for i, wave in enumerate(w, 1):
        b = sum(r['size'] for r in wave)
        print('  wave %-2d %s .. %s  %2d files %10d bytes %8.4f %%'
              % (i, fmt(wave[0]['dos']), fmt(wave[-1]['dos']), len(wave), b,
                 100.0 * b / total))
    print()
    for i, wave in enumerate(w, 1):
        print('  --- wave %d (%d files) ---' % (i, len(wave)))
        for r in wave:
            print('      %s %10d  %s' % (fmt(r['dos']), r['size'], r['name']))
    first = min(r['dos'] for r in rows)
    last = max(r['dos'] for r in rows)
    print()
    print('  first to last : %s .. %s = %s'
          % (fmt(first), fmt(last), last - first))
    days = collections.Counter(r['dos'].date() for r in rows)
    print('  distinct calendar days on the DOS clock : %d' % len(days))


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('archive', nargs='?')
    ap.add_argument('--tree', default=None,
                    help='the extracted directory, for the on-disk column')
    ap.add_argument('--waves', action='store_true')
    ap.add_argument('--gap', type=int, default=3600)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.archive:
        ap.error('give a ZIP archive')
    try:
        path, rows = read(args.archive)
    except ZipClocksError as exc:
        print('REFUSE  %s' % exc)
        return 1
    if args.tree:
        dirguard.want_tree(args.tree, 'zipclocks')
    if args.waves:
        cmd_waves(path, rows, args.gap)
    else:
        cmd_table(path, rows, args.tree)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
