#!/usr/bin/env python3
"""sigcount.py -- count a byte signature over a tree, at offset 0 and anywhere,
and report both numbers.

Why both numbers
-----------------

A zero is only a measurement if somebody looked for it, and *where* they looked
changes what the zero means.  Two questions get confused constantly:

  * **does any file BEGIN with this?**  That is the question for a container
    magic.  MS-NRBF streams, `UnityWeb` bundles and Lua chunks all start at
    offset 0, and a count of files starting with the signature is the honest
    answer for them;
  * **does this appear ANYWHERE?**  That is a different question and usually a
    noisier one.  On this object the nine-byte MS-NRBF stream header occurs 689
    times inside ten files and begins none of them, because
    `00 01 00 00 00 ff ff ff ff` is an integer 1 followed by an integer -1 in
    little-endian, which is the commonest possible pair of small values.

Printing only the second number would have produced 689 "hits" and a wrong
paragraph.  Printing only the first would have published a zero without saying
how hard it was to get.  So this prints both, and the per-file breakdown of the
second.

    python sigcount.py DIR --hex 000100000 0ffffffff
    python sigcount.py DIR --hex 0001000000ffffffff
    python sigcount.py DIR --text "UnityWeb"
    python sigcount.py DIR --hex 1b4c7561 --label "Lua chunk"

Standard library only.
"""

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard


def sig_from(args):
    if args.hex:
        h = ''.join(args.hex.split())
        if len(h) % 2:
            sys.exit('FATAL: --hex has an odd number of digits')
        try:
            return bytes.fromhex(h)
        except ValueError as ex:
            sys.exit('FATAL: --hex is not hexadecimal: %s' % ex)
    return args.text.encode('utf-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('root')
    ap.add_argument('--hex')
    ap.add_argument('--text')
    ap.add_argument('--label')
    ap.add_argument('--limit', type=int, default=20)
    args = ap.parse_args()
    if not (args.hex or args.text):
        ap.error('one of --hex or --text is required')
    sig = sig_from(args)
    if not sig:
        sys.exit('FATAL: an empty signature matches everything')
    # Handed a FILE this tool used to walk nothing and print `0 of 0`, exit 0,
    # and look exactly like a search that had found nothing. Recorded as a
    # defect on pc-ilgrandegiocoditangentopoli-doc (docs/09 C.6) and met again
    # on pc-rovescino-doc; two instances make a class and the class's repair
    # is `dirguard.want_tree`.
    dirguard.want_tree(args.root, 'sigcount')

    files = starts = 0
    anywhere = 0
    per = collections.Counter()
    starting = []
    for dirpath, _d, names in os.walk(args.root):
        for nm in sorted(names):
            p = os.path.join(dirpath, nm)
            try:
                with open(p, 'rb') as f:
                    d = f.read()
            except OSError:
                continue
            files += 1
            if d[:len(sig)] == sig:
                starts += 1
                starting.append(p)
            c = d.count(sig)
            if c:
                anywhere += c
                per[os.path.relpath(p, args.root)] = c

    label = args.label or (args.text if args.text else sig.hex())
    print('root      : %s' % args.root)
    print('signature : %s  (%d bytes)%s'
          % (' '.join('%02x' % b for b in sig), len(sig),
             '   %s' % label if args.label or args.text else ''))
    print()
    print('files searched                       : %d' % files)
    print('files BEGINNING with the signature   : %d of %d' % (starts, files))
    for p in starting[:args.limit]:
        print('   %s' % os.path.relpath(p, args.root).replace('\\', '/'))
    print('occurrences ANYWHERE                 : %d, in %d files'
          % (anywhere, len(per)))
    for p, c in per.most_common(args.limit):
        print('   %-56s %d' % (p.replace('\\', '/')[-56:], c))
    print()
    print('A signature that begins no file and appears inside many is not a')
    print('near miss.  It is a coincidence, and the two counts are printed')
    print('apart so that neither can be quoted as the other.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
