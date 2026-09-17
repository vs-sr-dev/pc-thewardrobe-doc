#!/usr/bin/env python3
"""Names the assets call themselves, as opposed to names the file system gives.

On *Tales of the Tempest* this harvest produced `stan` and `dimlos`, two names
from a different game in the series, and on *Tales of Innocence* the same
harvest -- taught to descend into the container -- withdrew them.  It is the
cheapest cross-title instrument the corpus has and the one most easily run on
a fraction of the data by accident, so this tool prints its own coverage
first.

What it can and cannot see on this disc:

  * the studio's own index containers keep a directory of
    `u32 offset, u32 size, u16 length, name` records in plain text, so their
    members' names are readable;
  * `bres`, `REFF`, `REFT`, `RSAR` and `RSTM` carry NW4R string tables, also
    plain;
  * **1,506 `MSCF` payloads are compressed in a format this repository has not
    identified, so any name inside one of them is invisible to this harvest.**
    That is 813 MB, 19.9% of the file system, and it is stated here rather
    than left for the reader to infer from a low count.

    python internal_names.py PARTITION.bin
    python internal_names.py PARTITION.bin --grep rutee,stan,dimlos
    python internal_names.py DIR --dir            (a plain extracted tree)

Standard library only.
"""

import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import census

# A name is only counted when it is NUL-terminated and at least six
# characters long.  Without the terminator the harvest reads ASCII runs out of
# ADPCM and video and returns nine million "names", which is a measurement of
# nothing; with it the count is of strings something wrote as strings.
NAME = re.compile(rb'[A-Za-z][A-Za-z0-9_\-.]{5,63}\x00')

# Stream audio and video frames are entropy-coded and contain no strings.
# They are skipped rather than filtered, so the coverage line can say so.
SKIP_MAGIC = (b'RSTM', b'THP\x00')


def harvest_payload(buf):
    return set(m.group()[:-1] for m in NAME.finditer(buf))


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    src = argv[1]
    grep = []
    if '--grep' in argv:
        grep = [x.strip() for x in argv[argv.index('--grep') + 1].split(',')]

    names = collections.Counter()
    n_payload = 0
    n_bytes = 0
    opaque_n = 0
    opaque_b = 0
    media_n = 0
    media_b = 0
    if '--dir' in argv:
        for r, _ds, fs in os.walk(src):
            for f in fs:
                p = os.path.join(r, f)
                buf = open(p, 'rb').read()
                n_payload += 1
                n_bytes += len(buf)
                for x in harvest_payload(buf):
                    names[x] += 1
    else:
        for label, buf in census.payloads(src):
            n_payload += 1
            n_bytes += len(buf)
            if label.endswith('[MSCF payload]'):
                opaque_n += 1
                opaque_b += len(buf)
                continue
            if buf[:4] in SKIP_MAGIC or '[frame ' in label:
                media_n += 1
                media_b += len(buf)
                continue
            for x in harvest_payload(buf):
                names[x] += 1

    print('=== coverage')
    print('payloads read            {:,}'.format(n_payload))
    print('bytes read               {:,}'.format(n_bytes))
    if opaque_n:
        print('payloads skipped as an unreadable compressed stream  {:,}'
              .format(opaque_n))
        print('bytes in them            {:,}  ({:.2f}% of what was offered)'
              .format(opaque_b, 100.0 * opaque_b / n_bytes))
    if media_n:
        print('payloads skipped as entropy-coded media               {:,}'
              .format(media_n))
        print('bytes in them            {:,}  ({:.2f}% of what was offered)'
              .format(media_b, 100.0 * media_b / n_bytes))
    print('bytes actually searched  {:,}'
          .format(n_bytes - opaque_b - media_b))
    print('distinct names harvested {:,}'.format(len(names)))
    print()

    pre = collections.Counter()
    for x in names:
        s = x.decode('latin1')
        k = s.split('_')[0] if '_' in s else s[:3]
        pre[k] += 1
    print('=== the sixty commonest name prefixes')
    for k, v in pre.most_common(60):
        print('   %-24s %6d' % (k, v))

    if grep:
        print()
        print('=== named searches')
        for g in grep:
            gb = g.encode()
            hits = sorted(x for x in names if gb.lower() in x.lower())
            print('%-14s %d distinct names contain it' % (g, len(hits)))
            for h in hits[:24]:
                print('      %s  x%d' % (h.decode('latin1'), names[h]))

    if '--dump' in argv:
        out = argv[argv.index('--dump') + 1]
        with open(out, 'w', encoding='utf-8') as g:
            for x in sorted(names):
                g.write('%s\t%d\n' % (x.decode('latin1'), names[x]))
        print()
        print('wrote %s' % out)


if __name__ == '__main__':
    main(sys.argv)
