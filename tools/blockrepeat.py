#!/usr/bin/env python3
"""Count repeated fixed-width blocks, which is how you ask a ciphertext
whether it is ECB without having a key.

A block cipher in ECB mode maps equal plaintext blocks to equal ciphertext
blocks.  Tabular game data -- rows of mostly-zero fields, repeated defaults,
padding -- has many equal 16-byte runs, so an ECB ciphertext of it has many
equal 16-byte ciphertext blocks.  CBC, CTR and any stream cipher do not: each
block is masked by something that changes, and the repeat count collapses to
what chance gives you.

The measurement is the same either way, which is the point.  It costs one pass
and it answers a question that guessing a cipher name does not.

What it reports, per file and in total:

    blocks            total blocks of the requested width
    distinct          how many distinct block values
    repeated          blocks - distinct
    top               the most-repeated value and its count
    birthday          how many collisions chance alone predicts, from
                      n(n-1)/2 / 2^128 for 16-byte blocks -- which for any
                      file on this object is astronomically less than one, so
                      **any** repeat at all is structure and not luck

and across files, whether any two share a block, which would say they share a
key and an IV.

    python blockrepeat.py DIR_OR_FILE... [--width 16]

Standard library only.  It reads; it never writes and never decrypts.
"""

import os
import sys
from collections import Counter


def files_of(args):
    out = []
    for a in args:
        if os.path.isdir(a):
            for dp, _, fn in os.walk(a):
                for n in fn:
                    out.append(os.path.join(dp, n))
        elif os.path.isfile(a):
            out.append(a)
    return sorted(out)


def main(argv):
    args = [a for a in argv[1:] if not a.startswith('--')]
    width = 16
    if '--width' in argv:
        width = int(argv[argv.index('--width') + 1])
    paths = files_of(args)
    if not paths:
        print(__doc__)
        return 2

    print('%-28s %10s %8s %8s %8s %9s'
          % ('file', 'bytes', 'blocks', 'distinct', 'repeated', 'top'))
    grand = Counter()
    owner = {}
    tot_blocks = tot_rep = 0
    aligned = 0
    for p in paths:
        data = open(p, 'rb').read()
        n = len(data) // width
        if len(data) % width == 0:
            aligned += 1
        c = Counter(data[i * width:(i + 1) * width] for i in range(n))
        rep = n - len(c)
        top = c.most_common(1)[0][1] if c else 0
        tot_blocks += n
        tot_rep += rep
        for k, v in c.items():
            grand[k] += v
            owner.setdefault(k, set()).add(os.path.basename(p))
        print('%-28s %10d %8d %8d %8d %9d'
              % (os.path.basename(p)[:28], len(data), n, len(c), rep, top))

    shared = [k for k, s in owner.items() if len(s) > 1]
    print()
    print('files                       %d' % len(paths))
    print('files whose size %% %d == 0  %d of %d' % (width, aligned,
                                                     len(paths)))
    print('blocks of %d bytes          %d' % (width, tot_blocks))
    print('repeated within a file      %d' % tot_rep)
    print('distinct across all files   %d' % len(grand))
    print('blocks shared by 2+ files   %d' % len(shared))
    if width == 16:
        pairs = tot_blocks * (tot_blocks - 1) / 2
        print('collisions chance predicts  %.3e  (n(n-1)/2 over 2**128)'
              % (pairs / float(1 << 128)))
    for k in shared[:5]:
        print('  shared %s  in %s' % (k.hex(), sorted(owner[k])))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
