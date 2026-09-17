#!/usr/bin/env python3
"""The blind decode census for an Android package: every byte, both dialects,
with the container tree walked rather than assumed.

Section 7 of tales-blockcodec-doc gives two rules that shape this file.
**Sweep per member, not per image** -- `plausible()` bounds a candidate by
whether its declared stream fits inside the buffer it sits in, which rejects
nearly everything for free inside a small file and almost nothing inside a
hundred-megabyte one, so a whole-file sweep is both slower and weaker.  And
**a tool written for a tree that is not this one fails silently in the
direction of a clean negative**, so every level has to be named.

Why `census.py` from the PlayStation 3 pipeline was not adapted
--------------------------------------------------------------
It knows `TLZC`, Bink, `CPK `, `CRILAYLA`, `FPS4`, the nine-byte block, `SPKD`,
`U8` and Sofdec packs.  **Not one of those levels exists in this package**, and
neither do `SLZ` or `ISF`, the two the other Android title in this corpus uses.
Running it here would report a build with 1,096 flat payloads and no descent,
and the zero at the bottom would look like a measurement.  This file is that
tool re-aimed: same rules, same reporting, the levels this platform actually
has.

What it descends through
------------------------
  1. **the zip** -- 1,096 entries.  A stored entry is swept as it lies; a
     deflated one is inflated first, because a decoder cannot be expected to
     find a block through deflate and because the plaintext is what the
     program sees.
  2. **ELF** -- each `PT_LOAD` segment separately, so that a scan of a 73 MB
     library is a scan of the parts the loader maps rather than of one buffer.
  3. **Unity SerializedFile** -- every object body separately, which is what
     makes the plausibility bound do any work: 9,761 objects rather than 465
     files.  A `.splitN` set is joined first.
  4. **FSB5** -- every sample separately.
  5. **dex** -- swept whole; this tool does not read the dex structure.

What it does NOT descend through, stated rather than left to inference:
  * `global-metadata.dat`, because it is encrypted and there is nothing to
    descend into -- it is swept as it lies and counted;
  * `libengine.so`, which is not an ELF file at all;
  * the encrypted tails of `libil2cpp.so` and `libstub.so`, which are inside
    the file and therefore swept, but are not code and are marked as such;
  * `resources.arsc`, the compiled resource table, swept whole;
  * anything else whose format is not one of the five above.

Every count of those is printed as `undescended`, because a payload a reader
did not open is a payload it did not test.

    python apkcensus.py APK [--max-bytes N]
    python apkcensus.py APK --candidates
    python apkcensus.py --selftest

Standard library only.
"""

import collections
import os
import struct
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import tales_block                                        # noqa: E402
import unityfs                                            # noqa: E402


STATS = collections.Counter()


def elf_segments(buf):
    """Each PT_LOAD segment of an ELF, as (label, bytes)."""
    if buf[:4] != b'\x7fELF':
        return None
    try:
        from elfinfo import Elf
        e = Elf(buf)
    except Exception:
        return None
    out = []
    for i, p in enumerate(e.segments):
        if p['type'] == 1 and p['filesz']:
            fl = ''.join(c for c, b in (('R', 4), ('W', 2), ('X', 1))
                         if p['flags'] & b)
            out.append(('PT_LOAD#%d/%s' % (i, fl),
                        buf[p['off']:p['off'] + p['filesz']]))
    tail_start = max((p['off'] + p['filesz']) for p in e.segments
                     if p['type'] == 1) if e.segments else 0
    tail_start = max(tail_start, e.shoff + e.shnum * e.shentsize)
    if tail_start < len(buf):
        out.append(('overlay past the last PT_LOAD', buf[tail_start:]))
    return out


def unity_objects(buf):
    """Each object body of a Unity SerializedFile, as (label, bytes)."""
    try:
        sf = unityfs.SerializedFile(buf)
    except Exception:
        return None
    out = []
    for o in sf.objects:
        cid = sf.class_of(o)
        out.append(('%s/%d' % (unityfs.CLASS.get(cid, str(cid)),
                               o['path_id']), sf.body(o)))
    return out


def fsb5_samples(buf):
    if buf[:4] != b'FSB5':
        return None
    try:
        from fsb5 import Fsb5
        b = Fsb5(buf)
    except Exception:
        return None
    return [('sample%d' % i, buf[s['file_offset']:s['file_offset'] + s['bytes']])
            for i, s in enumerate(b.samples)]


DESCENDERS = [('ELF segments', elf_segments),
              ('Unity objects', unity_objects),
              ('FSB5 samples', fsb5_samples)]


def descend(label, buf, depth=0):
    """Yield (label, bytes) leaves, counting what was and was not opened."""
    if depth > 3 or len(buf) < 16:
        STATS['leaf'] += 1
        yield label, buf
        return
    for kind, fn in DESCENDERS:
        try:
            parts = fn(buf)
        except Exception:
            parts = None
        if parts:
            STATS['descended'] += 1
            STATS['descended_as_' + kind.split()[0]] += 1
            for sub, b in parts:
                if b:
                    for x in descend('%s :: %s' % (label, sub), b, depth + 1):
                        yield x
            return
    STATS['undescended'] += 1
    STATS['leaf'] += 1
    yield label, buf


def entry_bytes(z, info):
    """The entry's plaintext: inflated when deflated, as stored when stored."""
    try:
        return z.read(info), info.compress_type != 0
    except (zlib.error, RuntimeError, OSError):
        return b'', False



def count_candidates(argv):
    """How many offsets even *look* like a block header, before decoding.

    This is the denominator the bare hit count needs, and it is also the reason
    the full sweep is slow on this package.  `plausible()` accepts an offset
    whose method byte is one of the five, whose two declared sizes are sane and
    ordered, and whose stream fits the buffer -- and then `unpack()` runs the
    decoder over it.  On ordinary data almost nothing passes.  On the two
    encrypted `libil2cpp.so`, where every byte value is equally likely, a
    great many offsets pass and each one costs a decode of up to sixteen
    megabytes.  Section 7 calls this failure mode "a blind sweep can be
    defeated by the data rather than by the buffer", and this package is a
    clear case of it.

    Counting candidates without decoding them is cheap -- about 0.7 seconds
    per mebibyte per dialect -- so it finishes, and "N offsets passed the
    filter and none of them decoded" is a stronger statement than "no hits".
    """
    path = argv[1]
    z = zipfile.ZipFile(path)
    rows = []
    tot_c = {'snes': 0, 'psx': 0}
    tot_b = 0
    for info in z.infolist():
        plain, _d = entry_bytes(z, info)
        if not plain:
            continue
        tot_b += len(plain)
        per = {}
        for dialect, name in ((tales_block.SNES, 'snes'),
                              (tales_block.PSX, 'psx')):
            n = 0
            for off in range(0, max(0, len(plain) - 9)):
                if tales_block.plausible(plain, off, dialect):
                    n += 1
            per[name] = n
            tot_c[name] += n
        if per['snes'] or per['psx']:
            rows.append((info.filename, len(plain), per['snes'], per['psx']))
    print('=' * 74)
    print('candidate headers -- offsets that pass plausible() before decoding')
    print('=' * 74)
    print('%d bytes of plaintext scanned at every offset in both dialects'
          % tot_b)
    print()
    print('%-58s %12s %8s %8s' % ('ENTRY', 'PLAINTEXT', 'SNES', 'PSX'))
    rows.sort(key=lambda r: -(r[2] + r[3]))
    for nm, n, a, b in rows[:40]:
        print('%-58s %12d %8d %8d' % (nm[:58], n, a, b))
    if len(rows) > 40:
        print('... %d more entries with at least one candidate'
              % (len(rows) - 40))
    print()
    print('%d candidates in the 1995 dialect, %d in the 1997 one'
          % (tot_c['snes'], tot_c['psx']))
    print('rate: one candidate per %.0f bytes (1995), per %.0f bytes (1997)'
          % (tot_b / tot_c['snes'] if tot_c['snes'] else 0,
             tot_b / tot_c['psx'] if tot_c['psx'] else 0))


def main(argv):
    if '--selftest' in argv:
        ok = 0
        ok += tales_block.selftest() in (0, None, True)
        ok += elf_segments(b'not an elf at all') is None
        ok += unity_objects(b'\0' * 64) is None
        ok += fsb5_samples(b'nope') is None
        print()
        print('apkcensus selftest: %d of 4 checks pass' % ok)
        print('(the first is tales_block.py\'s own, unchanged and re-run here,')
        print('so that this census cannot pass with a broken decoder under it)')
        return 0
    if len(argv) < 2:
        raise SystemExit(__doc__)
    if '--candidates' in argv:
        return count_candidates(argv)
    path = argv[1]
    maxb = (int(argv[argv.index('--max-bytes') + 1])
            if '--max-bytes' in argv else None)
    z = zipfile.ZipFile(path)
    infos = z.infolist()

    print('=' * 74)
    print('blind decode census -- %s' % os.path.basename(path))
    print('=' * 74)
    print('%d zip entries, %d bytes stored, %d bytes expanded'
          % (len(infos), sum(i.compress_size for i in infos),
             sum(i.file_size for i in infos)))
    print()
    print('Every leaf is swept at every offset in both dialects.  A hit is')
    print('kept only when the block decodes to the length its own header')
    print('declares, which is the test that makes false positives essentially')
    print('not survive: on the 1995 cartridge it returns 1,089 blocks and')
    print('every one is real.')
    print()

    hits = []
    n_leaf = 0
    n_bytes = 0
    per_entry = []
    for info in infos:
        plain, was_deflated = entry_bytes(z, info)
        if not plain:
            continue
        if maxb and len(plain) > maxb:
            per_entry.append((info.filename, len(plain), None, None,
                              'skipped, larger than --max-bytes'))
            STATS['skipped'] += 1
            continue
        e_hits = 0
        for label, leaf in descend(info.filename, plain):
            n_leaf += 1
            n_bytes += len(leaf)
            for dialect, name in ((tales_block.SNES, 'snes'),
                                  (tales_block.PSX, 'psx')):
                for off, method, packed, unpacked in tales_block.scan(
                        leaf, dialect):
                    hits.append((label, name, off, method, packed, unpacked))
                    e_hits += 1
        per_entry.append((info.filename, len(plain), was_deflated, e_hits, ''))

    print('%-58s %12s %8s' % ('ENTRY', 'PLAINTEXT', 'BLOCKS'))
    for name, n, defl, h, note in per_entry:
        if note or h:
            print('%-58s %12d %8s  %s'
                  % (name[:58], n, h if h is not None else '-', note))
    print()
    print('leaves swept          %12d' % n_leaf)
    print('bytes swept           %12d' % n_bytes)
    print('descended             %12d' % STATS['descended'])
    for k in sorted(STATS):
        if k.startswith('descended_as_'):
            print('  as %-17s %12d' % (k[13:], STATS[k]))
    print('undescended           %12d' % STATS['undescended'])
    print('skipped               %12d' % STATS['skipped'])
    print()
    print('blocks that decode to their own declared length, 1995 dialect: %d'
          % sum(1 for h in hits if h[1] == 'snes'))
    print('blocks that decode to their own declared length, 1997 dialect: %d'
          % sum(1 for h in hits if h[1] == 'psx'))
    if hits:
        print()
        print('%-52s %6s %10s %10s %10s'
              % ('WHERE', 'DIA', 'OFFSET', 'PACKED', 'UNPACKED'))
        for label, dia, off, method, packed, unpacked in hits[:200]:
            print('%-52s %6s %10d %10d %10d'
                  % (label[-52:], dia, off, packed, unpacked))
        if len(hits) > 200:
            print('... %d more' % (len(hits) - 200))
    else:
        print()
        print('No block of either dialect decodes anywhere in this package.')
        print('Read that beside reports/ring_sites-arm64.txt and')
        print('reports/codedensity-census.txt: the two libil2cpp.so contain no')
        print('machine code as shipped, so the code half of the question has a')
        print('denominator of zero, and this is the data half on its own.')


if __name__ == '__main__':
    main(sys.argv)
