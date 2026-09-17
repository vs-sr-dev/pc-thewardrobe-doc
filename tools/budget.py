#!/usr/bin/env python3
"""Where every byte of the disc goes, and what the leftover actually is.

Three levels, each summing to the level above it:

  1. the **image** -- 6,949,961,728 bytes -- split into the thirty files the
     ISO 9660 directory names and the complement no file covers;
  2. the **container** -- `TLFILE.TLDAT` -- split by member extension, with
     the payload bytes and the plaintext bytes side by side;
  3. the **complement**, profiled rather than assumed.

Section 7's rule for the third one is the reason it is a separate pass:
*Vesperia*'s 19.08% of apparent emptiness was incompressible fill,
*Hearts*'s 6.95% was `0xFF` that deflates to 0.0974%, and *Graces*'s
239,646,720 bytes were Nintendo's junk fill read out of the generator state
rather than guessed from the entropy.  **Say what the padding is, not only
how much there is.**  This tool prints, for every complement region, its
length, its byte histogram, its entropy and how it deflates, so the answer is
a measurement.

    python budget.py --image IMAGE --index index.json --gaps DIR
    python budget.py --selftest

Standard library only.
"""

import collections
import json
import math
import os
import sys
import zlib


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = float(len(b))
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def describe(b):
    """What this region is, in one phrase, from its own bytes."""
    if not b:
        return 'empty'
    c = collections.Counter(b)
    top, n = c.most_common(1)[0]
    if len(c) == 1:
        return 'all 0x%02X' % top
    if n / float(len(b)) > 0.99:
        return '%.4f%% 0x%02X' % (100.0 * n / len(b), top)
    e = entropy(b)
    d = len(zlib.compress(b, 9)) / float(len(b))
    return ('%d distinct byte values, %.3f bits/byte, deflates to %.4f%%'
            % (len(c), e, 100.0 * d))


def main(argv):
    if '--selftest' in argv:
        assert describe(bytes(4096)) == 'all 0x00'
        assert describe(bytes(4095) + b'\x01').startswith('99.9')
        assert entropy(bytes(16)) == 0.0
        assert 7.9 < entropy(bytes(range(256)) * 8) <= 8.0
        print('budget selftest: 4 of 4 checks pass')
        return 0
    if '--image' not in argv:
        raise SystemExit(__doc__)
    img = argv[argv.index('--image') + 1]
    total = os.path.getsize(img)
    print('%s' % os.path.basename(img))
    print('  %s bytes' % '{:,}'.format(total))
    print()

    if '--files' in argv:
        rows = json.load(open(argv[argv.index('--files') + 1]))
        print('  level 1 -- the ISO 9660 directory')
        print('  %-40s %16s %8s' % ('FILE', 'BYTES', 'SHARE'))
        acc = 0
        for name, size in rows:
            acc += size
            print('  %-40s %16s %7.3f%%'
                  % (name, '{:,}'.format(size), 100.0 * size / total))
        print('  %-40s %16s %7.3f%%'
              % ('-- all %d files' % len(rows), '{:,}'.format(acc),
                 100.0 * acc / total))
        print('  %-40s %16s %7.3f%%'
              % ('-- the complement, no file covers it',
                 '{:,}'.format(total - acc),
                 100.0 * (total - acc) / total))
        print()

    if '--index' in argv:
        idx = json.load(open(argv[argv.index('--index') + 1]))
        pay = sum(e[1] for e in idx)
        plain = sum(e[0] for e in idx)
        by = collections.defaultdict(lambda: [0, 0, 0])
        for e in idx:
            r = by[e[4]]
            r[0] += 1
            r[1] += e[0]
            r[2] += e[1]
        print('  level 2 -- inside TLFILE.TLDAT')
        print('  %d members, %s bytes of payload, %s of plaintext'
              % (len(idx), '{:,}'.format(pay), '{:,}'.format(plain)))
        print('  %-12s %8s %16s %16s %8s %8s'
              % ('EXTENSION', 'MEMBERS', 'PLAINTEXT', 'PAYLOAD', 'RATIO',
                 'OF DISC'))
        for k in sorted(by, key=lambda x: -by[x][2]):
            n, pl, pa = by[k]
            print('  %-12s %8d %16s %16s %7.2f%% %7.3f%%'
                  % (k, n, '{:,}'.format(pl), '{:,}'.format(pa),
                     100.0 * pa / pl if pl else 0, 100.0 * pa / total))
        print()

    if '--gaps' in argv:
        d = argv[argv.index('--gaps') + 1]
        print('  level 3 -- the complement, profiled rather than assumed')
        print('  %-30s %14s  %s' % ('REGION', 'BYTES', 'WHAT IT IS'))
        tot = 0
        kinds = collections.Counter()
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            b = open(p, 'rb').read()
            tot += len(b)
            what = describe(b)
            kinds[what.split(',')[0]] += len(b)
            print('  %-30s %14s  %s' % (f, '{:,}'.format(len(b)), what))
        print()
        print('  %s bytes of complement, %.4f%% of the image'
              % ('{:,}'.format(tot), 100.0 * tot / total))
        for k, v in kinds.most_common():
            print('    %-40s %14s  %.4f%%'
                  % (k, '{:,}'.format(v), 100.0 * v / total))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv) or 0)
