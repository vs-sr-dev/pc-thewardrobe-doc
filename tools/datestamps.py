#!/usr/bin/env python3
"""Every date this disc carries, from every source that carries one.

Seven independent dates came out of *Tales of the Tempest* and six from four
sources on *Tales of Innocence*.  A Nintendo optical disc is more talkative
than a cartridge, and this one has five sources:

  1. **the apploader**, which carries a `YYYY/MM/DD` string at a fixed offset
     0x2440 into every partition -- the cheapest date in the corpus, and there
     is one per partition;
  2. **the SDK component stamps** in `main.dol`: `<< RVL_SDK - XX  release
     build: Mon DD YYYY HH:MM:SS >>`, one per linked library, plus the `NW4R`
     ones, which are stamped `final` rather than `release`;
  3. **`__DATE__` / `__TIME__`**, if the build left any;
  4. **the `MSCF` file entries**, which carry an MS-DOS date and time per
     asset.  These date the *asset pipeline* rather than the disc, and on the
     2003 GameCube release they are what showed the pipeline running per
     character over two months;
  5. **`yymmdd` groups in file names**, which on some titles are the only
     dates there are.

Every one is printed with where it came from, because a date with no source is
not evidence.

    python datestamps.py PARTITION.bin [PARTITION2.bin ...]

Standard library only.
"""

import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import wiifs
except Exception:      # no Wii partition on this platform
    wiifs = None
try:
    import cab
except Exception:      # the 2003/2008 envelope is not on this disc
    cab = None

SDK = re.compile(rb'<<\s*([A-Za-z0-9_]+)\s*-\s*([A-Za-z0-9]+)\s*'
                 rb'(release|final|debug)?\s*build:\s*'
                 rb'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d\d:\d\d:\d\d)')
CDATE = re.compile(rb'([A-Z][a-z]{2} [ 0-9]\d \d{4})\x00')
YMD = re.compile(r'(?<!\d)(0[5-9]|1[0-2])(0[1-9]|1[012])(0[1-9]|[12]\d|3[01])'
                 r'(?!\d)')


def one_file(path):
    """Every date-shaped string in one plain file.

    The Wii path below reads a partition; this one reads whatever it is
    given, which on this platform is a decrypted ELF and a container index.
    It carries the fifteenth build's correction: the C preprocessor writes
    `Mmm dd yyyy` and pads a single-digit day with a **space**, so a pattern
    that requires two spaces matches `Jan  1 2008` and misses `Nov 19 2008`.
    Both shapes are matched here and the report says which is which.
    """
    data = open(path, 'rb').read()
    print('=== %s   (%s bytes)'
          % (os.path.basename(path), '{:,}'.format(len(data))))
    stamps = SDK.findall(data)
    print('SDK component stamps: %d' % len(stamps))
    for lib, part, kind, when in sorted(stamps, key=lambda x: x[3]):
        print('   %-16s %-8s %-8s %s'
              % (lib.decode(), part.decode(),
                 (kind or b'?').decode(), when.decode()))
    two = re.compile(rb'([A-Z][a-z]{2}  \d \d{4})')
    one_sp = re.compile(rb'([A-Z][a-z]{2} \d\d \d{4})')
    a = sorted(set(m.group(1).decode() for m in two.finditer(data)))
    b = sorted(set(m.group(1).decode() for m in one_sp.finditer(data)))
    print()
    print('__DATE__, two-space form (single-digit day): %d' % len(a))
    for x in a:
        print('   %s' % x)
    print('__DATE__, one-space form (two-digit day): %d' % len(b))
    for x in b:
        print('   %s' % x)
    tm = sorted(set(m.group().decode()
                    for m in re.finditer(rb'\d\d:\d\d:\d\d', data)))
    print()
    print('clock-shaped strings: %d' % len(tm))
    for x in tm[:20]:
        print('   %s' % x)
    ymd = sorted(set(m.group().decode() for m in re.finditer(
        rb'20[0-2][0-9][.\-/][0-9]{1,2}[.\-/][0-9]{1,2}', data)))
    print()
    print('year-month-day strings: %d' % len(ymd))
    for x in ymd[:20]:
        print('   %s' % x)
    ver = sorted(set(m.group().decode()
                     for m in re.finditer(rb'[Vv]er(?:sion)?[. ]?\s*'
                                          rb'\d+\.\d+[0-9.]*', data)))
    print()
    print('version-shaped strings: %d' % len(ver))
    for x in ver[:30]:
        print('   %s' % x)


def one(path):
    d = wiifs.WiiPartition(path)
    print('=== %s   (%s, %s)'
          % (os.path.basename(path),
             d.head[0:6].decode('ascii', 'replace'),
             d.title.decode('shift_jis', 'replace')))
    print('apploader build date      %s   (0x2440, fixed offset)'
          % d.apploader_date.decode('ascii', 'replace'))

    dol = d.dol()
    stamps = SDK.findall(dol)
    print()
    print('SDK component stamps in main.dol: %d' % len(stamps))
    print('%-10s %-8s %-8s %s' % ('LIBRARY', 'PART', 'KIND', 'BUILT'))
    for lib, part, kind, when in sorted(stamps, key=lambda x: x[3]):
        print('%-10s %-8s %-8s %s'
              % (lib.decode(), part.decode(),
                 (kind or b'?').decode(), when.decode()))

    other = set(m.group(1).decode() for m in CDATE.finditer(dol))
    other -= set(w.decode()[:11] for _l, _p, _k, w in stamps)
    if other:
        print()
        print('other date-shaped strings in main.dol: %d' % len(other))
        for x in sorted(other):
            print('   %s' % x)

    stamps2 = []
    for p, off, length, _i in d.files():
        head = d.read(off, min(length, 4096))
        if head[:4] != b'MSCF':
            continue
        h, files = cab.parse(head)
        for name, size, stamp, at, fi, coff, doff in files:
            stamps2.append((stamp, p, name, size, length - doff))
    if stamps2:
        stamps2.sort()
        days = collections.Counter(s[0][:10] for s in stamps2)
        print()
        print('MSCF per-asset timestamps: %d archives, %d distinct days'
              % (len(stamps2), len(days)))
        print('earliest  %s  %s' % (stamps2[0][0], stamps2[0][1]))
        print('latest    %s  %s' % (stamps2[-1][0], stamps2[-1][1]))
        print()
        print('%-12s %8s' % ('DAY', 'ARCHIVES'))
        for k in sorted(days):
            print('%-12s %8d' % (k, days[k]))

    names = [p for p, _o, _l, _i in d.files()]
    hits = collections.Counter()
    for n in names:
        for m in YMD.finditer(os.path.basename(n)):
            hits[m.group(0)] += 1
    print()
    print('yymmdd groups in file names: %d distinct' % len(hits))
    for k, v in hits.most_common(20):
        print('   %s  x%d' % (k, v))
    print()


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    plain = '--file' in argv
    for p in argv[1:]:
        if not p.startswith('--'):
            (one_file if plain else one)(p)


if __name__ == '__main__':
    main(sys.argv)
