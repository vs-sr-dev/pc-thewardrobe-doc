#!/usr/bin/env python3
"""Does this disc hold compressed data?  Asked without any probe at all.

The counter-check that depends on nothing: run the whole medium through
`zlib.compress` and see how much comes off.  On *Tales of the Tempest* the raw
cartridge deflated to 52.6% and that was consistent with the data being stored
plain; on *Tales of Innocence* it deflated to 73.5%, and the number that
settled the question was not the total but **the split** -- 91.27% for the
already-compressed containers against 52.23% for everything else.

So this tool reports by class, and the classes come from `formats.py`, which
classifies by magic and never by extension.  The total is printed last and is
the least interesting line in the table.

The update partition is excluded, for the reason `formats.py` gives.

    python deflate_control.py PARTITION.bin
    python deflate_control.py PARTITION.bin --sample 4194304

Standard library only.
"""

import collections
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import wiifs
except Exception:
    wiifs = None
import formats
from formats import classify



def _walk(roots):
    import os
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dp, dn, fn in os.walk(root):
            dn.sort()
            for f in sorted(fn):
                yield os.path.join(dp, f)


def tree_main(argv):
    """Classify every file of an extracted tree, and deflate it by class.

    The Wii pipeline reads its file system through `wiifs`.  There is no Wii
    partition here, so this mode takes the tree the container was extracted
    to and walks that instead -- which is the same set of payloads, arrived
    at by the route this platform offers.
    """
    import collections
    import os
    import zlib
    roots = argv[argv.index('--tree') + 1].split(',')
    cap = (int(argv[argv.index('--sample') + 1], 0)
           if '--sample' in argv else 4 << 20)
    want_deflate = '--deflate' in argv
    n_by = collections.Counter()
    b_by = collections.Counter()
    raw = collections.Counter()
    out = collections.Counter()
    sampled = collections.Counter()
    why = {}
    total = 0
    for p in _walk(roots):
        size = os.path.getsize(p)
        total += size
        with open(p, 'rb') as f:
            head = f.read(64)
            kind, w = classify(p, head, size)
            n_by[kind] += 1
            b_by[kind] += size
            why.setdefault(kind, set()).add(w)
            if want_deflate:
                f.seek(0)
                take = min(size, cap)
                buf = f.read(take)
                raw[kind] += take
                out[kind] += len(zlib.compress(buf, 6))
                if take < size:
                    sampled[kind] += 1
    print('over %s' % ', '.join(roots))
    print('  %s files, %s bytes'
          % ('{:,}'.format(sum(n_by.values())), '{:,}'.format(total)))
    print()
    hdr = '  %-18s %9s %18s %9s' % ('CLASS', 'FILES', 'BYTES', 'SHARE')
    if want_deflate:
        hdr += ' %12s %12s %9s %8s' % ('SAMPLED', 'DEFLATED', 'RATIO',
                                       'CAPPED')
    print(hdr)
    for k in sorted(n_by, key=lambda x: -b_by[x]):
        line = ('  %-18s %9d %18s %8.3f%%'
                % (k, n_by[k], '{:,}'.format(b_by[k]),
                   100.0 * b_by[k] / total))
        if want_deflate:
            line += (' %12s %12s %8.2f%% %8d'
                     % ('{:,}'.format(raw[k]), '{:,}'.format(out[k]),
                        100.0 * out[k] / raw[k] if raw[k] else 0.0,
                        sampled[k]))
        print(line)
    if want_deflate:
        tr, to = sum(raw.values()), sum(out.values())
        print('  %-18s %9d %18s %8.3f%% %12s %12s %8.2f%%'
              % ('-- all', sum(n_by.values()), '{:,}'.format(total), 100.0,
                 '{:,}'.format(tr), '{:,}'.format(to),
                 100.0 * to / tr if tr else 0.0))
    print()
    print('  what each class was recognised by:')
    for k in sorted(why):
        print('    %-18s %s' % (k, '; '.join(sorted(x for x in why[k] if x))))
    return 0

def main(argv):
    if '--tree' in argv:
        return tree_main(argv)
    if len(argv) < 2:
        raise SystemExit(__doc__)
    d = wiifs.WiiPartition(argv[1])
    cap = (int(argv[argv.index('--sample') + 1], 0)
           if '--sample' in argv else 4 << 20)

    raw = collections.Counter()
    out = collections.Counter()
    nfiles = collections.Counter()
    sampled = collections.Counter()
    for p, off, length, _i in d.files():
        head = d.read(off, 32)
        kind, _why = formats.classify(p, head, length)
        take = min(length, cap)
        buf = d.read(off, take)
        raw[kind] += take
        out[kind] += len(zlib.compress(buf, 6))
        nfiles[kind] += 1
        if take < length:
            sampled[kind] += 1

    print('=== the disc through deflate, by class')
    print('files larger than {:,} bytes are sampled to that length; the'
          .format(cap))
    print('number of files that happened to is in the last column.')
    print()
    print('%-12s %8s %18s %18s %8s %8s'
          % ('CLASS', 'FILES', 'BYTES IN', 'BYTES OUT', 'RATIO', 'SAMPLED'))
    tr = to = 0
    for kind in sorted(raw, key=lambda k: -raw[k]):
        print('%-12s %8d %18s %18s %7.2f%% %8d'
              % (kind, nfiles[kind], '{:,}'.format(raw[kind]),
                 '{:,}'.format(out[kind]),
                 100.0 * out[kind] / raw[kind], sampled[kind]))
        tr += raw[kind]
        to += out[kind]
    print('%-12s %8d %18s %18s %7.2f%%'
          % ('total', sum(nfiles.values()), '{:,}'.format(tr),
             '{:,}'.format(to), 100.0 * to / tr))
    print()
    already = sum(out[k] for k in ('container', 'video', 'audio'))
    already_r = sum(raw[k] for k in ('container', 'video', 'audio'))
    rest = to - already
    rest_r = tr - already_r
    print('already-compressed classes (container, video, audio): %.2f%%'
          % (100.0 * already / already_r))
    print('everything else:                                      %.2f%%'
          % (100.0 * rest / rest_r))


if __name__ == '__main__':
    main(sys.argv)
