#!/usr/bin/env python3
"""Ask what these bundles weighed before the client rewrote them.

The accounting question on this object is that the client announced a 2.6 GB
download and 3,792,967,234 bytes landed.  `unityarc.py flags` shows why the
obvious answer is wrong: the bundles on disc are **not** stored decompressed.
88.98 % of their blocks are LZ4 and the archives hold 5,023,317,300 bytes of
content in 3,749,934,660 bytes of file.

What the flags do say is subtler.  Unity builds downloadable AssetBundles with
LZ4HC (block flag 3) or LZMA (flag 1).  Every compressed block here is flag
**2**, plain LZ4 -- which is what a runtime *recompression* writes, not what a
build writes.  So the file on disc is a rewrite, which is also why no digest of
it matches its own 20-byte `.hash` sidecar.

If the wire format was LZMA and the disc format is LZ4, the download was
smaller than the disc by whatever LZMA beats LZ4 by on this content.  That is
measurable without the network and without the server: take the archive's own
decompressed blocks and compress them with the standard library's LZMA, at the
settings Unity's bundle builder uses (LZMA1, no end marker, its own dictionary),
and compare.

  * the two sides of this comparison do not share a constant.  One is a figure
    the phone's own UI reported to a person; the other is a compressor run
    locally over bytes recovered from the archive.  This branch has lost a
    clause to a cross-check whose halves shared a divisor, and this one does
    not;
  * blocks already stored uncompressed (flag 0) are counted as-is on both
    sides, because a block LZ4 could not shrink is a block LZMA will not shrink
    either -- that assumption is stated, not hidden, and `--verify-stored`
    tests it on a sample.

    python bundlebudget.py sample DIR [--n 24] [--seed 50] [--verify-stored]

Sampling, never a census: 729 archives holding 5.02 GB do not get recompressed
in a session.  The tool prints how many of how many it opened, and every figure
it prints names its denominator.

Standard library only.
"""

import lzma
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unityarc

# LZMA1 with the filter Unity's bundle compressor uses.  The point is not to
# reproduce Unity's exact stream -- it is to measure what a competent LZMA gets
# on this content, as a lower bound on the wire size.
FILTERS = [{'id': lzma.FILTER_LZMA1, 'preset': 6}]


def lzma_size(data):
    c = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=FILTERS)
    out = c.compress(data)
    out += c.flush()
    return len(out)


def cmd_sample(argv):
    root = argv[2]
    n = 24
    seed = 50
    verify_stored = '--verify-stored' in argv
    if '--n' in argv:
        n = int(argv[argv.index('--n') + 1])
    if '--seed' in argv:
        seed = int(argv[argv.index('--seed') + 1])

    paths = []
    for dp, _, fn in os.walk(root):
        for f in fn:
            if not f.endswith('.hash'):
                paths.append(os.path.join(dp, f))
    paths.sort()
    total = len(paths)
    rng = random.Random(seed)
    pick = sorted(rng.sample(paths, min(n, total)))

    print('population %d archives; sample %d (seed %d)'
          % (total, len(pick), seed))
    print()
    print('%-34s %12s %12s %12s %12s %7s'
          % ('archive', 'file', 'content', 'lz4 blocks', 'lzma same', 'gain'))

    f_file = f_content = f_lz4c = f_lz4u = f_lzma = f_stored = 0
    stored_lzma = 0
    t0 = time.time()
    for p in pick:
        a = unityarc.UnityArchive(p)
        fsz = a.filesize
        lz4c = lz4u = stored = 0
        lz = 0
        sl = 0
        for i, b in enumerate(a.blocks):
            if b.flags & 0x3F == 0:
                stored += b.usize
                if verify_stored:
                    sl += lzma_size(a._block(i))
            else:
                lz4c += b.csize
                lz4u += b.usize
                lz += lzma_size(a._block(i))
        a.close()
        f_file += fsz
        f_content += lz4u + stored
        f_lz4c += lz4c
        f_lz4u += lz4u
        f_lzma += lz
        f_stored += stored
        stored_lzma += sl
        print('%-34s %12d %12d %12d %12d %6.3fx'
              % (os.path.basename(p)[:34], fsz, lz4u + stored, lz4c, lz,
                 (lz4c / lz) if lz else 0.0))

    el = time.time() - t0
    print()
    print('sample of %d of %d archives, %.1f s' % (len(pick), total, el))
    print('file bytes on disc          %16d' % f_file)
    print('content (decompressed)      %16d' % f_content)
    print('blocks stored uncompressed  %16d' % f_stored)
    print('compressible content        %16d' % f_lz4u)
    print('  as LZ4 on disc            %16d  ratio %.4f'
          % (f_lz4c, f_lz4u / f_lz4c if f_lz4c else 0))
    print('  as LZMA here              %16d  ratio %.4f'
          % (f_lzma, f_lz4u / f_lzma if f_lzma else 0))
    if f_lzma:
        print('LZMA beats LZ4 by           %16.4f x' % (f_lz4c / f_lzma))
    if verify_stored and f_stored:
        print('stored blocks as LZMA       %16d  ratio %.4f'
              % (stored_lzma, f_stored / stored_lzma))
    return 0


def cmd_whole(argv):
    """What the block boundaries cost.

    `sample` compresses each of an archive's blocks separately, because that is
    how they sit on disc.  Unity's LZMA bundle format does not: it compresses
    the whole concatenated stream as one, so its dictionary carries across the
    128 KiB boundaries that the block layout imposes.  Per-block LZMA is
    therefore an **upper bound** on the wire size, and this measures the gap
    between the bound and the thing.

        python bundlebudget.py whole DIR [--n 20] [--seed 50]
    """
    root = argv[2]
    n = int(argv[argv.index('--n') + 1]) if '--n' in argv else 20
    seed = int(argv[argv.index('--seed') + 1]) if '--seed' in argv else 50
    paths = []
    for dp, _, fn in os.walk(root):
        for f in fn:
            if not f.endswith('.hash'):
                paths.append(os.path.join(dp, f))
    paths.sort()
    pick = sorted(random.Random(seed).sample(paths, min(n, len(paths))))
    print('population %d archives; sample %d (seed %d)'
          % (len(paths), len(pick), seed))
    print('%-34s %12s %12s %12s %7s'
          % ('archive', 'content', 'per-block', 'whole', 'gain'))
    t_content = t_block = t_whole = 0
    t0 = time.time()
    for p in pick:
        a = unityarc.UnityArchive(p)
        parts = []
        blk = 0
        for i, b in enumerate(a.blocks):
            d = a._block(i)
            parts.append(d)
            blk += lzma_size(d)
        a.close()
        stream = b''.join(parts)
        whole = lzma_size(stream)
        t_content += len(stream)
        t_block += blk
        t_whole += whole
        print('%-34s %12d %12d %12d %6.3fx'
              % (os.path.basename(p)[:34], len(stream), blk, whole,
                 blk / whole if whole else 0))
    print()
    print('sample of %d of %d, %.1f s' % (len(pick), len(paths),
                                          time.time() - t0))
    print('content                     %16d' % t_content)
    print('LZMA per 128 KiB block      %16d  ratio %.4f'
          % (t_block, t_content / t_block if t_block else 0))
    print('LZMA over the whole stream  %16d  ratio %.4f'
          % (t_whole, t_content / t_whole if t_whole else 0))
    print('the block boundaries cost   %16.4f x'
          % (t_block / t_whole if t_whole else 0))
    return 0


CMDS = dict(sample=cmd_sample, whole=cmd_whole)


def main(argv):
    if len(argv) < 3 or argv[1] not in CMDS:
        print(__doc__)
        return 2
    return CMDS[argv[1]](argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
