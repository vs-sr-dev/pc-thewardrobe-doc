#!/usr/bin/env python3
"""Classify every file on the disc, and account for every byte of it.

Classification is by **magic and arithmetic, never by extension**.  On this
disc that distinction does real work: 1,506 files whose names end `.bin` or
`.dat` are the studio's own `MSCF`-headed envelope, and the eleven that end
`.arc` are Nintendo's `U8` -- two different containers with names that say
nothing about either.

Two passes, as on *Tales of Innocence*, and for the same reason: attributing a
container's bytes to its members' classes would be an estimate where these two
tables are measurements.

  * **pass 1** -- the files as the file system stores them;
  * **pass 2** -- the members inside the containers this repository can open:
    `THP` frames, `U8` nodes, and the `MSCF` header/payload split.  The `MSCF`
    payload cannot be descended into, because the format it is compressed in is
    not identified; it is counted as one member and said to be so.

The update partition is **not** counted here.  It is Nintendo's IOS and System
Menu, it is boilerplate on every Wii disc of the period, and folding it into
the game's budget would overstate the game by 3.9% of the disc.  Point this
tool at `update.bin` separately if you want its own table.

    python formats.py PARTITION.bin
    python formats.py PARTITION.bin --csv per-file.csv

Standard library only.
"""

import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import wiifs
except Exception:
    wiifs = None
try:
    import cab
except Exception:      # the 2003/2008 envelope is not on this disc
    cab = None

MAGIC = [
    (b'RSTM', 'audio', 'NW4R stream, BRSTM'),
    (b'RSAR', 'audio', 'NW4R sound archive, BRSAR'),
    (b'THP\x00', 'video', 'Nintendo THP'),
    (b'bres', 'model', 'NW4R binary resource, BRRES'),
    (b'REFF', 'effect', 'NW4R effect'),
    (b'REFT', 'effect', 'NW4R effect texture'),
    (b'MSCF', 'container', "the studio's own envelope"),
    (b'\x55\xAA\x38\x2D', 'container', 'Nintendo U8 archive'),
    (b'\x00\x20\xAF\x30', 'texture', 'Nintendo TPL'),
    (b'iPck', 'audio', 'LVD sound pack'),
    # what this disc actually carries, which the Ratatosk table did not know
    (b'CPK ', 'container', "CRI's CPK, this build's bulk container"),
    (b'FPS4', 'container', "the studio's own archive, big-endian here"),
    (b'CRILAYLA', 'compressed', "CRI's CPK member compressor"),
    (bytes((0, 0, 1, 0xBA)), 'video', 'MPEG-2 program stream, CRI Sofdec'),
    (b'@UTF', 'index', "CRI's column-store table"),
    (b'ADXF', 'audio', 'CRI ADX'),
    (b'AHXF', 'audio', 'CRI AHX'),
    (bytes((0x80, 0, 0, 0x20)), 'audio', 'CRI ADX stream header'),
]

# The nine-byte block header is not a magic number; it is a method byte and
# two lengths, so it has to be tested rather than matched.  A file that is
# exactly one block is this build's `.slz`.
def is_block(head, size):
    if len(head) < 9 or head[0] not in (0, 1, 3):
        return None
    packed = int.from_bytes(head[1:5], 'little')
    unpacked = int.from_bytes(head[5:9], 'little')
    if packed == 0 or unpacked == 0:
        return None
    if 9 + packed != size:
        return None
    return ('compressed', 'one nine-byte codec block, whole file')


# A Wii relocatable module has no magic: its header is a module id of zero
# for the .sel and a section count that has to be plausible.
def is_rso(head, size):
    if len(head) < 0x30:
        return None
    import struct as _s
    ident, nxt, nsec, secoff = _s.unpack_from('>IIII', head, 0)
    if ident == 0 and nxt == 0 and 1 < nsec < 64 and 0 < secoff < size:
        return ('module', 'Wii relocatable module, RSO/SEL')
    return None


PS3_MAGIC = [
    (b'TLZC', 'tlzc', "this build (LZMA envelope)"),
    (b'BIKi', 'video', 'RAD Game Tools Bink'),
    (b'BIKb', 'video', 'RAD Game Tools Bink'),
    (b'RIFF', 'audio', 'RIFF WAVE'),
    (b'SHBP', 'audio', 'sound bank'),
    (b'SE3 ', 'audio', 'sound effect bank'),
    (b'SE4D', 'audio', 'sound effect bank'),
    (b'SPKD', 'container', 'sound pack directory'),
    (b'MANM', 'animation', "the studio's own animation format"),
    (b'MTEX', 'texture-header', "the studio's own texture header"),
    (b'MSPM', 'shape-header', "the studio's own shape header"),
    (b'MHRC', 'hierarchy', "the studio's own node hierarchy"),
    (b'TRSH', 'terrain', "the studio's own terrain format"),
    (b'SCFO', 'scene', "the studio's own scene format"),
    (b'nusc', 'audio', 'Nu-Sound bank'),
    (b'\x89PNG', 'image', 'PNG'),
    (b'SCE\x00', 'executable', 'an SCE container'),
    (b'\x7fELF', 'executable', 'an ELF'),
    (b'<?xml', 'text', 'XML'),
]


def classify(name, head, size):
    for m, kind, why in PS3_MAGIC:
        if head[:len(m)] == m:
            return kind, why
    hit = is_block(head, size)
    if hit:
        return hit
    for m, kind, why in MAGIC:
        if head[:len(m)] == m:
            return kind, why
    if name.endswith('.coll'):
        return 'collision', 'plain table, name in the first bytes'
    if name.endswith('.csv') and head[:2] == b'\xfe\xff':
        return 'text', 'UTF-16 BE csv'
    if name.endswith('.txt'):
        return 'text', 'plain text'
    if name in ('/boot.bin', '/bi2.bin', '/fst.bin'):
        return 'system', 'disc structure'
    if head[:4] == b'\x00\x00\x00\x00':
        return 'index', 'offset-table container, big-endian u32 entries'
    return 'unknown', ''



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
    part = argv[1]
    d = wiifs.WiiPartition(part)
    csv = argv[argv.index('--csv') + 1] if '--csv' in argv else None

    n_by = collections.Counter()
    b_by = collections.Counter()
    why = {}
    rows = []
    for p, off, length, _i in d.files():
        head = d.read(off, 32)
        kind, w = classify(p, head, length)
        n_by[kind] += 1
        b_by[kind] += length
        why.setdefault(kind, set()).add(w)
        rows.append((p, off, length, kind, w))

    total_files = sum(n_by.values())
    total_bytes = sum(b_by.values())
    print('=== pass 1: the file system as it stands')
    print('files                   {:,}'.format(total_files))
    print('bytes in files          {:,}'.format(total_bytes))
    print('partition               {:,}'.format(d.size))
    print()
    print('%-12s %8s %18s %8s  %s'
          % ('CLASS', 'FILES', 'BYTES', 'SHARE', 'IDENTIFIED BY'))
    for kind, n in n_by.most_common():
        print('%-12s %8d %18s %7.2f%%  %s'
              % (kind, n, '{:,}'.format(b_by[kind]),
                 100.0 * b_by[kind] / total_bytes,
                 '; '.join(sorted(x for x in why[kind] if x))[:52]))
    print('%-12s %8d %18s %7.2f%%'
          % ('total', total_files, '{:,}'.format(total_bytes), 100.0))

    # -- pass 2 ---------------------------------------------------------
    mem_n = collections.Counter()
    mem_b = collections.Counter()
    mscf_decl = 0
    mscf_stored = 0
    thp_frames = 0
    for p, off, length, _i in d.files():
        head = d.read(off, 64)
        if head[:4] == b'MSCF':
            buf = d.read(off, min(length, 8192))
            h, files = cab.parse(buf)
            if files:
                name, decl, stamp, at, fi, coff, doff = files[0]
                mem_n['MSCF payload'] += 1
                mem_b['MSCF payload'] += length - doff
                mscf_decl += decl
                mscf_stored += length - doff
                continue
        if head[:4] == b'THP\x00':
            n_frames = struct.unpack_from('>I', head, 0x14)[0]
            thp_frames += n_frames
            mem_n['THP frame'] += n_frames
            mem_b['THP frame'] += length
            continue
        if head[:4] == b'\x55\xAA\x38\x2D':
            buf = d.read(off, length)
            import census
            nodes = census.u8_nodes(buf) or []
            mem_n['U8 node'] += len(nodes)
            mem_b['U8 node'] += sum(s for _o, s in nodes)
            continue
        mem_n['not a container'] += 1
        mem_b['not a container'] += length
    print()
    print('=== pass 2: inside the containers')
    print('%-18s %10s %18s' % ('MEMBER KIND', 'COUNT', 'BYTES'))
    for k, n in mem_n.most_common():
        print('%-18s %10d %18s' % (k, n, '{:,}'.format(mem_b[k])))
    if mscf_stored:
        print()
        print('MSCF payloads: {:,} stored bytes standing for {:,} declared '
              'bytes, {:.2f}x'.format(mscf_stored, mscf_decl,
                                      mscf_decl / float(mscf_stored)))
        print('The payload format is not identified; see docs/04.')

    if csv:
        with open(csv, 'w', encoding='utf-8') as g:
            g.write('path,offset,length,class,identified_by\n')
            for p, off, length, kind, w in rows:
                g.write('"%s",%d,%d,%s,"%s"\n' % (p, off, length, kind, w))


if __name__ == '__main__':
    main(sys.argv)
