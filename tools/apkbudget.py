#!/usr/bin/env python3
"""Where every byte of the package goes, and what each part actually is.

Three levels, each summing to the one above it:

  1. **the file on disk** -- 101,922,396 bytes -- split into the zip entries'
     stored bytes and the complement no entry covers: local headers, the
     central directory, the end-of-central-directory record, and the alignment
     padding an APK carries so that shared libraries and uncompressed assets
     land on a page boundary.
  2. **the entries**, grouped by what they are, with stored and expanded bytes
     side by side, because on this platform those are different numbers and
     the interesting ratio is between them.
  3. **inside the big ones**: the native libraries one by one, and the Unity
     object graph by class.

Section 7's rule for the complement is why level 1 is a separate pass.  On
*Tales of Vesperia* 19.08% of the disc was apparent emptiness that turned out
to be incompressible fill; on *Tales of Hearts* 6.95% was 0xFF that deflates to
0.0974%; on *Tales of Graces* 239,646,720 bytes were Nintendo's junk fill read
out of the generator state rather than guessed at from the entropy.  **Say what
the padding is, not only how much of it there is.**  So every complement region
is profiled: length, dominant byte, entropy, and how it deflates.

    python apkbudget.py APK [--unpacked DIR]
    python apkbudget.py --selftest

Standard library only.
"""

import collections
import math
import os
import struct
import sys
import zlib
import zipfile


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = float(len(b))
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def describe(b):
    """What a run of bytes actually is, in one line."""
    if not b:
        return 'empty'
    c = collections.Counter(b)
    top, n = c.most_common(1)[0]
    frac = 100.0 * n / len(b)
    if len(c) == 1:
        return 'all 0x%02X' % top
    d = zlib.compress(bytes(b), 9)
    return ('%.1f%% 0x%02X, %d distinct values, entropy %.3f, '
            'deflates to %.4f%%'
            % (frac, top, len(c), entropy(b), 100.0 * len(d) / len(b)))


CATEGORIES = [
    ('native code and libraries', lambda n: n.startswith('lib/')),
    ('Unity IL2CPP metadata',
     lambda n: n.startswith('assets/bin/Data/Managed/Metadata/')),
    ('Unity Mono runtime configuration',
     lambda n: n.startswith('assets/bin/Data/Managed/')),
    ('Unity serialized assets',
     lambda n: n.startswith('assets/bin/Data/')),
    ('the protector (AppGuard)', lambda n: n.startswith('assets/appguard/')),
    ('other assets', lambda n: n.startswith('assets/')),
    ('Java bytecode', lambda n: n.endswith('.dex')),
    ('Android resources', lambda n: n.startswith('res/')
     or n == 'resources.arsc'),
    ('the manifest', lambda n: n == 'AndroidManifest.xml'),
    ('signature and library version stamps',
     lambda n: n.startswith('META-INF/')),
    ('build-tool property files', lambda n: n.endswith('.properties')),
]


def categorise(name):
    for label, pred in CATEGORIES:
        if pred(name):
            return label
    return 'everything else'


def gaps(path, z):
    """Byte ranges of the file that no entry's stored data covers."""
    covered = []
    data = open(path, 'rb').read()
    for i in z.infolist():
        hdr = i.header_offset
        # local file header: 30 fixed bytes, then name and extra
        n, e = struct.unpack_from('<HH', data, hdr + 26)
        start = hdr + 30 + n + e
        covered.append((hdr, start, i.filename, 'local header'))
        covered.append((start, start + i.compress_size, i.filename, 'data'))
    covered.sort()
    end = max(c[1] for c in covered) if covered else 0
    holes = []
    pos = 0
    for s, e, _n, _k in covered:
        if s > pos:
            holes.append((pos, s - pos))
        pos = max(pos, e)
    if pos < len(data):
        holes.append((pos, len(data) - pos))
    return data, holes, end, covered


def main(argv):
    if '--selftest' in argv:
        ok = 0
        ok += describe(bytes(4096)) == 'all 0x00'
        ok += describe(b'') == 'empty'
        ok += entropy(bytes(16)) == 0.0
        ok += 7.9 < entropy(bytes(range(256)) * 8) <= 8.0
        ok += categorise('lib/arm64-v8a/libil2cpp.so') == \
            'native code and libraries'
        ok += categorise('assets/bin/Data/level0') == 'Unity serialized assets'
        ok += categorise('classes.dex') == 'Java bytecode'
        print('apkbudget selftest: %d of 7 checks pass' % ok)
        return 0 if ok == 7 else 1
    if len(argv) < 2:
        raise SystemExit(__doc__)
    path = argv[1]
    total = os.path.getsize(path)
    z = zipfile.ZipFile(path)
    infos = z.infolist()

    print('%s' % os.path.basename(path))
    print('  %s bytes, %d entries' % ('{:,}'.format(total), len(infos)))
    print()

    data, holes, last, covered = gaps(path, z)
    stored = sum(i.compress_size for i in infos)
    lhdr = sum(30 + len(i.filename.encode()) + len(i.extra or b'')
               for i in infos)
    hole_bytes = sum(h[1] for h in holes)

    print('  level 1 -- the file, and what is not entry data')
    print('  %-46s %14s %8s' % ('PART', 'BYTES', 'SHARE'))
    rows = [('entry data, as stored (compressed where compressed)', stored),
            ('local file headers, names and extra fields', lhdr),
            ('everything else: central directory, EOCD, alignment padding',
             total - stored - lhdr)]
    for label, n in rows:
        print('  %-46s %14d %7.3f%%' % (label[:46], n, 100.0 * n / total))
    print('  %-46s %14d %7.3f%%' % ('TOTAL', total, 100.0))
    print()
    print('  the complement, profiled rather than assumed:')
    print('  %-14s %12s  %s' % ('OFFSET', 'LENGTH', 'WHAT IT IS'))
    holes.sort(key=lambda h: -h[1])
    for off, ln in holes[:12]:
        print('  %-14d %12d  %s' % (off, ln, describe(data[off:off + ln])))
    if len(holes) > 12:
        rest = sum(h[1] for h in holes[12:])
        allrest = b''.join(data[o:o + l] for o, l in holes[12:])
        print('  %-14s %12d  %s'
              % ('(%d more)' % (len(holes) - 12), rest, describe(allrest)))
    print('  %d gaps, %d bytes, %.3f%% of the file'
          % (len(holes), hole_bytes, 100.0 * hole_bytes / total))
    print()

    print('  level 2 -- the entries, by what they are')
    by = collections.defaultdict(lambda: [0, 0, 0])
    for i in infos:
        c = categorise(i.filename)
        by[c][0] += 1
        by[c][1] += i.compress_size
        by[c][2] += i.file_size
    print('  %-40s %6s %14s %8s %14s %7s'
          % ('WHAT', 'N', 'STORED', 'SHARE', 'EXPANDED', 'RATIO'))
    tot_s = tot_u = 0
    for c, (n, s, u) in sorted(by.items(), key=lambda kv: -kv[1][1]):
        tot_s += s
        tot_u += u
        print('  %-40s %6d %14d %7.2f%% %14d %6.2fx'
              % (c[:40], n, s, 100.0 * s / total, u, u / s if s else 0))
    print('  %-40s %6d %14d %7.2f%% %14d %6.2fx'
          % ('TOTAL', len(infos), tot_s, 100.0 * tot_s / total, tot_u,
             tot_u / tot_s if tot_s else 0))
    print()

    print('  level 3a -- the native libraries, one by one')
    print('  %-46s %14s %8s %14s' % ('FILE', 'STORED', 'SHARE', 'EXPANDED'))
    libs = sorted((i for i in infos if i.filename.startswith('lib/')),
                  key=lambda i: -i.compress_size)
    for i in libs:
        print('  %-46s %14d %7.2f%% %14d'
              % (i.filename[4:], i.compress_size,
                 100.0 * i.compress_size / total, i.file_size))
    print()

    print('  level 3b -- the ten largest entries of any kind')
    print('  %-52s %14s %8s' % ('FILE', 'STORED', 'SHARE'))
    for i in sorted(infos, key=lambda i: -i.compress_size)[:10]:
        print('  %-52s %14d %7.2f%%'
              % (i.filename[:52], i.compress_size,
                 100.0 * i.compress_size / total))
    print()

    print('  level 3c -- how much of the package is compressed at all')
    comp = [i for i in infos if i.compress_type != 0]
    raw = [i for i in infos if i.compress_type == 0]
    print('  %d entries deflated: %d stored bytes from %d expanded (%.2fx)'
          % (len(comp), sum(i.compress_size for i in comp),
             sum(i.file_size for i in comp),
             (sum(i.file_size for i in comp) /
              sum(i.compress_size for i in comp))
             if comp else 0))
    print('  %d entries stored uncompressed: %d bytes'
          % (len(raw), sum(i.compress_size for i in raw)))
    for i in sorted(raw, key=lambda i: -i.file_size)[:10]:
        print('     %-50s %12d' % (i.filename[:50], i.file_size))
    print()
    print('  An Android package stores a shared library or an asset the loader')
    print('  will mmap uncompressed and page-aligned, so the uncompressed set')
    print('  is a statement about what gets mapped rather than about what')
    print('  compresses badly.')


if __name__ == '__main__':
    main(sys.argv)
