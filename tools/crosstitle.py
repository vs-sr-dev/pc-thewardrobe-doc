#!/usr/bin/env python3
"""This disc against the disc it is a sequel to, in four independent ways.

*Tales of Symphonia* shipped on the GameCube in 2003 and this is its direct
sequel, five years later, on the same processor family from the same studio.
That is the strongest cross-title comparison the corpus has ever had available
at the *asset* level, so it is run four ways and each is reported separately:

  1. **whole files, by SHA-1** -- an asset carried across unchanged would show
     up here and nowhere else;
  2. **`MSCF` member names** -- the envelope both releases use carries the
     asset's own name and its uncompressed length, so a re-packed asset would
     appear under the same name with the same declared length, which is how
     the 2003/2004 packer comparison was made;
  3. **the `MSCF` payload signature** -- the first bytes of the compressed
     stream, tabulated position by position over every payload on both discs.
     If a byte is constant across both sets, the same compressor wrote both;
  4. **internal names**, harvested from both and intersected.

    python crosstitle.py WII_FS_DIR GC_FS_DIR
    python crosstitle.py WII_FS_DIR GC_FS_DIR --names

Both arguments are directories of extracted files, because the two releases
have different disc formats and this tool is about their contents.

Standard library only.
"""

import re as _re
import collections
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import cab
except Exception:      # the 2003/2008 envelope is not on this disc
    cab = None


def walk(root):
    for r, _ds, fs in os.walk(root):
        for f in fs:
            yield os.path.join(r, f)


def sha1(p):
    h = hashlib.sha1()
    n = 0
    with open(p, 'rb') as g:
        while True:
            b = g.read(1 << 22)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def mscf(root):
    """{member name: [(path, declared, stored, stamp, payload head)]}"""
    out = collections.defaultdict(list)
    for p in walk(root):
        try:
            b = open(p, 'rb').read(8192)
        except OSError:
            continue
        if b[:4] != b'MSCF':
            continue
        h, files = cab.parse(b)
        if not files:
            continue
        name, decl, stamp, at, fi, coff, doff = files[0]
        out[name.upper()].append((p, decl, os.path.getsize(p) - doff, stamp,
                                  b[doff:doff + 32]))
    return out



# ---------------------------------------------------------------------------
# Added for the PlayStation 3 build.  The two releases compared there have no
# container in common at all -- no `MSCF`, no `FPS4` -- so passes 2 and 3
# above have nothing to work on, and the two that remain are the ones that
# still mean something: whole payloads by SHA-1, and the internal-name
# intersection **read rather than counted**, which is the rule the sixteenth
# build wrote after an uppercase-run harvester lifted words out of compressed
# data by chance on 6.5 GB.
# ---------------------------------------------------------------------------

NAME_RE = _re.compile(rb'[A-Za-z0-9_./-]{6,}\x00')


def harvest_names(root):
    """Every NUL-terminated name in a tree, with its count."""
    import collections as _c
    out = _c.Counter()
    for p in walk(root):
        with open(p, 'rb') as fh:
            b = fh.read()
        for m in NAME_RE.finditer(b):
            out[m.group()[:-1].decode('latin-1')] += 1
    return out


def load_names(path):
    """A `name<TAB>count` list, the shape the other pipelines publish."""
    out = {}
    for line in open(path, encoding='latin-1'):
        parts = line.rstrip().split(chr(9))
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return out


def cmd_sha(a_root, b_root, a_label, b_label):
    import collections as _c
    a, b = _c.defaultdict(list), _c.defaultdict(list)
    for root, d in ((a_root, a), (b_root, b)):
        for p in walk(root):
            h, n = sha1(p)
            d[h].append((p, n))
    print('%-14s %s payloads, %s distinct SHA-1'
          % (a_label, '{:,}'.format(sum(len(v) for v in a.values())),
             '{:,}'.format(len(a))))
    print('%-14s %s payloads, %s distinct SHA-1'
          % (b_label, '{:,}'.format(sum(len(v) for v in b.values())),
             '{:,}'.format(len(b))))
    common = sorted(set(a) & set(b))
    print()
    print('byte-identical on both: %d' % len(common))
    for h in common[:60]:
        print('  %s  %10d  %s  <->  %s'
              % (h[:12], a[h][0][1], os.path.basename(a[h][0][0]),
                 os.path.basename(b[h][0][0])))


def cmd_names(a_names, b_names, a_label, b_label, limit=400):
    import collections as _c
    print('The name intersection is READ rather than counted, because on a')
    print('multi-gigabyte medium an uppercase-run harvester lifts words out')
    print('of compressed data by chance.')
    print()
    print('%-14s %d distinct names' % (a_label, len(a_names)))
    print('%-14s %d distinct names' % (b_label, len(b_names)))
    inter = sorted(set(a_names) & set(b_names))
    print('intersection   %d' % len(inter))
    print()
    buckets = _c.Counter()
    for n in inter:
        if _re.fullmatch(r'[A-Za-z]+', n):
            buckets['a bare word'] += 1
        elif n.startswith(('BONE_', 'IK_', 'JOINT_', 'KO_', 'ATT_')):
            buckets['a skeleton or attachment name'] += 1
        elif _re.search(r'[0-9]{2,}', n):
            buckets['a numbered asset name'] += 1
        else:
            buckets['other'] += 1
    for k, v in buckets.most_common():
        print('   %-36s %d' % (k, v))
    print()
    print('%-46s %10s %10s' % ('NAME', a_label, b_label))
    for n in inter[:limit]:
        print('%-46s %10d %10d' % (n[:46], a_names[n], b_names[n]))
    if len(inter) > limit:
        print('... and %d more' % (len(inter) - limit))


def main(argv):
    if '--sha' in argv or '--names' in argv and '--list' in argv:
        pass
    if '--sha' in argv:
        return cmd_sha(argv[1], argv[2],
                       argv[argv.index('--labels') + 1].split(',')[0]
                       if '--labels' in argv else 'A',
                       argv[argv.index('--labels') + 1].split(',')[1]
                       if '--labels' in argv else 'B')
    if '--namelist' in argv:
        la, lb = (argv[argv.index('--labels') + 1].split(',')
                  if '--labels' in argv else ('A', 'B'))
        return cmd_names(harvest_names(argv[1]),
                         load_names(argv[argv.index('--namelist') + 1]),
                         la, lb)
    if len(argv) < 3:
        raise SystemExit(__doc__)
    wii, gc = argv[1], argv[2]

    print('=== 1. whole files, by SHA-1')
    a = collections.defaultdict(list)
    b = collections.defaultdict(list)
    for root, d in ((wii, a), (gc, b)):
        for p in walk(root):
            h, n = sha1(p)
            d[h].append((p, n))
    na = sum(len(v) for v in a.values())
    nb = sum(len(v) for v in b.values())
    print('Wii 2008      {:,} files, {:,} distinct'.format(na, len(a)))
    print('GameCube 2003 {:,} files, {:,} distinct'.format(nb, len(b)))
    common = set(a) & set(b)
    print('byte-identical across the two releases: {:,}'.format(len(common)))
    for h in sorted(common, key=lambda h: -a[h][0][1]):
        print('   %14s  %s   <->   %s'
              % ('{:,}'.format(a[h][0][1]), a[h][0][0], b[h][0][0]))
    dup = [(h, v) for h, v in a.items() if len(v) > 1]
    red = sum((len(v) - 1) * v[0][1] for _h, v in dup)
    tot = sum(v[0][1] * len(v) for v in a.values())
    print()
    print('duplication inside the Wii disc: {:,} redundant of {:,} = {:.2f}%'
          .format(red, tot, 100.0 * red / tot))
    for h, v in sorted(dup, key=lambda x: -x[1][0][1])[:10]:
        print('   %12s x%d  %s'
              % ('{:,}'.format(v[0][1]), len(v),
                 ', '.join(os.path.basename(x[0]) for x in v[:4])))

    print()
    print('=== 2. MSCF member names')
    ma, mb = mscf(wii), mscf(gc)
    print('Wii 2008      {:,} archives, {:,} distinct member names'
          .format(sum(len(v) for v in ma.values()), len(ma)))
    print('GameCube 2003 {:,} archives, {:,} distinct member names'
          .format(sum(len(v) for v in mb.values()), len(mb)))
    shared = sorted(set(ma) & set(mb))
    print('names on both: {:,}'.format(len(shared)))
    for k in shared:
        p1, d1, s1, t1, _h1 = ma[k][0]
        p2, d2, s2, t2, _h2 = mb[k][0]
        print('   %-24s 2008 decl %10d stored %9d %s' % (k, d1, s1, t1))
        print('   %-24s 2003 decl %10d stored %9d %s' % ('', d2, s2, t2))

    print()
    print('=== 3. the MSCF payload signature, byte by byte')
    sets = [('Wii 2008', [x[4] for v in ma.values() for x in v]),
            ('GameCube 2003', [x[4] for v in mb.values() for x in v])]
    sets.append(('both', sets[0][1] + sets[1][1]))
    for label, S in sets:
        print('--- %s: %d payloads' % (label, len(S)))
        for i in range(16):
            c = collections.Counter(x[i] for x in S if len(x) > i)
            if not c:
                continue
            top, n = c.most_common(1)[0]
            flag = '  <-- constant' if len(c) == 1 else ''
            print('   byte +%-2d  0x%02x  %5d/%d  %5.1f%%  %3d distinct%s'
                  % (i, top, n, len(S), 100.0 * n / len(S), len(c), flag))

    if '--names' in argv:
        print()
        print('=== 4. internal names')
        print('run internal_names.py --dump on each side and intersect the')
        print('two dumps; this tool does not duplicate that harvest.')


if __name__ == '__main__':
    main(sys.argv)
