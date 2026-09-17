#!/usr/bin/env python3
"""Longest identical byte run between two whole executables, at any alignment.

`prefix_scan.py` answers "does *this* routine appear in that file".  This tool
answers the question section 7 of tales-blockcodec-doc says to ask *before*
believing a negative: **was byte equality available at all?**  It is the
C-runtime control, run without having to know where the C runtime is -- take
both images, and find the longest run of bytes they share anywhere.

If two builds share hundreds of contiguous bytes of library code and tens of
bytes of decoder, the toolchain is excluded by measurement rather than by
argument.  That is the test that turned the 2004 result from "part toolchain,
part edit" into "the source had forked": 276 bytes of runtime against 17 of
decoder.

Two things keep the answer honest and both are the reason this is not simply
`prefix_scan.py` with a bigger needle:

  * **Only executable sections are compared by default.**  A DOL's data
    sections carry long runs of zeros, of 0xFF, and of shared SDK tables, and
    a match inside one of those is not evidence about a compiler.  `--data`
    compares the data sections instead, and prints its own answer separately.
  * **The winning run is printed with its byte histogram**, so a run that is
    all one value is visible as such rather than quoted as a result.

    python common_run.py A.dol B.dol
    python common_run.py A.dol B.dol --data
    python common_run.py A.dol B.dol --top 8
    python common_run.py A.dol B.dol --exclude C.dol[,D.dol,...]
    python common_run.py A.dol B.dol --enumerate 64 --exclude C.dol

`--enumerate K` answers the other half: not "how long is the longest run" but
"how much do these two share at all".  It indexes every K-byte window of B,
rolls A past it, extends every match to its maximal length, merges the
overlaps, and prints every distinct shared region with its address in both
files.  With `--exclude` the regions a control image also contains are
dropped, so what is printed is code the two builds share and a stranger does
not -- which is the measurement that says whether a studio's own library
survived from one build to the next.

`--exclude` is the third refinement and the one this disc forced.  A GameCube
and a Wii executable share over a kilobyte of Nintendo SDK boot and exception
code, and so do two Wii executables from unrelated publishers -- so the plain
answer measures the SDK, not the pair.  With `--exclude`, a candidate run is
rejected if it also occurs in the control image, and what is left is the code
these two builds share *and a stranger does not*.

Standard library only.
"""

import os
import struct
import sys

BASE = 0x100000001B3
PRIME = (1 << 61) - 1


def dol_sections(data):
    """[(name, file_off, addr, size)] for a Nintendo DOL."""
    offs = struct.unpack_from('>18I', data, 0)
    addrs = struct.unpack_from('>18I', data, 0x48)
    sizes = struct.unpack_from('>18I', data, 0x90)
    out = []
    for i, (o, a, z) in enumerate(zip(offs, addrs, sizes)):
        if z:
            out.append(('text%d' % i if i < 7 else 'data%d' % (i - 7),
                        o, a, z))
    return out


def pick(path, want_data):
    """(concatenated bytes, [(file_off, addr, size, start_in_blob)])."""
    data = open(path, 'rb').read()
    secs = dol_sections(data)
    if not secs:
        return data, [(0, 0, len(data), 0)]
    blob = bytearray()
    mapping = []
    for name, o, a, z in secs:
        is_text = name.startswith('text')
        if is_text == want_data:
            continue
        mapping.append((o, a, z, len(blob)))
        blob += data[o:o + z]
    if not blob:
        return data, [(0, 0, len(data), 0)]
    return bytes(blob), mapping


def where(mapping, pos):
    for o, a, z, start in mapping:
        if start <= pos < start + z:
            return a + (pos - start), o + (pos - start)
    return None, None


def kgram_index(hay, k):
    if k <= 0 or len(hay) < k:
        return {}
    h = 0
    top = pow(BASE, k - 1, PRIME)
    idx = {}
    for i in range(k):
        h = (h * BASE + hay[i]) % PRIME
    idx.setdefault(h, []).append(0)
    for i in range(k, len(hay)):
        h = ((h - hay[i - k] * top) * BASE + hay[i]) % PRIME
        idx.setdefault(h, []).append(i - k + 1)
    return idx


def match_at_length(a, b, k, excl=None):
    """All (offset_in_a, offset_in_b) sharing some k-gram, first few only."""
    if k <= 0:
        return [(0, 0)]
    if len(a) < k or len(b) < k:
        return []
    idx = kgram_index(b, k)
    h = 0
    top = pow(BASE, k - 1, PRIME)
    out = []
    for i in range(k):
        h = (h * BASE + a[i]) % PRIME
    for i in range(len(a) - k + 1):
        if i:
            h = ((h - a[i - 1] * top) * BASE + a[i + k - 1]) % PRIME
        for j in idx.get(h, ()):
            if a[i:i + k] == b[j:j + k]:
                if excl is not None and excl.find(a[i:i + k]) >= 0:
                    continue
                out.append((i, j))
                if len(out) >= 16:
                    return out
    return out


def longest(a, b, excl=None):
    lo, hi = 1, min(len(a), len(b))
    best = (0, [])
    while lo <= hi:
        mid = (lo + hi) // 2
        m = match_at_length(a, b, mid, excl)
        if m:
            best = (mid, m)
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def enumerate_shared(a, b, k, excl):
    """[(len, off_in_a, off_in_b)] for every maximal shared region >= k."""
    idx = kgram_index(b, k)
    h = 0
    top = pow(BASE, k - 1, PRIME)
    for i in range(k):
        h = (h * BASE + a[i]) % PRIME
    raw = []
    for i in range(len(a) - k + 1):
        if i:
            h = ((h - a[i - 1] * top) * BASE + a[i + k - 1]) % PRIME
        for j in idx.get(h, ()):
            if a[i:i + k] != b[j:j + k]:
                continue
            # extend both ways
            lo = 0
            while i - lo > 0 and j - lo > 0 and a[i - lo - 1] == b[j - lo - 1]:
                lo += 1
            hi = k
            while (i + hi < len(a) and j + hi < len(b)
                   and a[i + hi] == b[j + hi]):
                hi += 1
            raw.append((i - lo, j - lo, lo + hi))
            break
    seen = set()
    out = []
    for ia, ib, n in raw:
        if (ia, ib) in seen:
            continue
        seen.add((ia, ib))
        if out and ia <= out[-1][0] + out[-1][2] and ib - ia == out[-1][1] - out[-1][0]:
            continue
        if excl is not None and excl.find(a[ia:ia + n]) >= 0:
            continue
        out.append((ia, ib, n))
    return out


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    pa, pb = argv[1], argv[2]
    want_data = '--data' in argv
    top = int(argv[argv.index('--top') + 1], 0) if '--top' in argv else 4
    a, ma = pick(pa, want_data)
    b, mb = pick(pb, want_data)
    print('%-30s %s bytes of %s'
          % (os.path.basename(pa), '{:,}'.format(len(a)),
             'data' if want_data else 'executable'))
    print('%-30s %s bytes of %s'
          % (os.path.basename(pb), '{:,}'.format(len(b)),
             'data' if want_data else 'executable'))
    excl = None
    if '--exclude' in argv:
        blob = bytearray()
        for pc in argv[argv.index('--exclude') + 1].split(','):
            e = pick(pc, want_data)[0]
            blob += bytes(64) + e
            print('%-30s %s bytes, as a control to subtract'
                  % (os.path.basename(pc), '{:,}'.format(len(e))))
        excl = bytes(blob)
    if '--enumerate' in argv:
        k = int(argv[argv.index('--enumerate') + 1], 0)
        regions = enumerate_shared(a, b, k, excl)
        total = sum(r[2] for r in regions)
        print()
        print('shared regions of at least %d bytes: %d' % (k, len(regions)))
        print('total shared bytes: {:,} of {:,} in the smaller image '
              '({:.2f}%)'.format(total, min(len(a), len(b)),
                                 100.0 * total / min(len(a), len(b))))
        print()
        print('%10s  %-22s %-22s %s'
              % ('BYTES', os.path.basename(pa), os.path.basename(pb),
                 'DISTINCT BYTE VALUES'))
        for ia, ib, n in sorted(regions, key=lambda r: -r[2]):
            va_a, off_a = where(ma, ia)
            va_b, off_b = where(mb, ib)
            print('%10d  0x%08X (0x%-8X) 0x%08X (0x%-8X) %d'
                  % (n, va_a or 0, off_a or 0, va_b or 0, off_b or 0,
                     len(set(a[ia:ia + n]))))
        return
    n, hits = longest(a, b, excl)
    print()
    print('longest identical run at any alignment: %d bytes' % n)
    if not n:
        return
    for i, j in hits[:top]:
        va_a, off_a = where(ma, i)
        va_b, off_b = where(mb, j)
        win = a[i:i + n]
        hist = len(set(win))
        print('  %s at 0x%08X (file 0x%X)   %s at 0x%08X (file 0x%X)'
              % (os.path.basename(pa), va_a or 0, off_a or 0,
                 os.path.basename(pb), va_b or 0, off_b or 0))
        print('      %d distinct byte values in the run%s'
              % (hist, '  -- constant fill, not evidence' if hist <= 2
                 else ''))
        print('      %s' % ' '.join('%02x' % c for c in win[:24]))


if __name__ == '__main__':
    main(sys.argv)
