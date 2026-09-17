#!/usr/bin/env python3
"""Count a fixed list of needles across a tree, with the chance rate beside
every count -- including the zeros.

This is the measurement the corpus keeps asking for and that an ad-hoc `grep`
keeps failing to give.  A count of three means nothing on its own: three
four-byte hits in a hundred megabytes is *below* what uniform random bytes
would produce, and three eleven-byte hits is a certainty.  So every needle is
printed with

    * its length, because that is what sets the rate;
    * the number of hits;
    * the number of hits uniform random bytes of the same total length would
      give, which is `(N - L + 1) / 256**L` for an L-byte needle;

and needles that score zero are printed too, because a category that is silent
has to be visible as a zero rather than as an omission.  The groups are the
questions this repository is trying to answer, one group per question, so that
"the engine is not ASKA" and "the compressor is not SLZ" are separate rows of
evidence rather than one impression.

Strings are searched in ASCII, Shift-JIS and UTF-16LE, because a build that
names nobody in the first may name everybody in the second -- the rule the
fourteenth build of the corpus added.  Byte needles (container magics) are
searched as given.

    python needles.py PATH [PATH...] [--group NAME] [--groups] [--min-hits N]
    python needles.py PATH [PATH...] --needle TEXT [--needle TEXT ...]
    python needles.py --selftest

Standard library only.
"""

import os
import struct
import sys

# ---------------------------------------------------------------- the needles

GROUPS = {
    # Is this ASKA, the engine of the other Android title in this corpus?
    # Tales of Crestoria proves the answer is visible from the outside: the
    # namespace, the activity, the containers, the formats.
    'aska': [
        'Aska', 'ASKA', 'aska0000', 'AskaActivity', 'jb.Aska', 'tri-Ace',
        'triAce', 'tri_Ace', 'Epic', 'libEpic', 'EpicActivity',
        'tales-of-epic', 'SLZ', 'ISF', 'AIF', 'AHA3', 'MRON', 'AAC ',
        'Anamnesis', 'InfiniteUndiscovery', 'StarOcean',
    ],
    # Is it a commercial engine, and which?  Outcome 4 of the session prompt
    # has to be excluded or confirmed by measurement, not by the absence of
    # something else.
    'engine': [
        'UnityPlayer', 'libunity', 'globalgamemanagers', 'UnityFS',
        'il2cpp', 'IL2CPP', 'libil2cpp', 'unity default resources',
        'libUE4', 'UE4Game', 'UnrealEngine', 'CoreUObject',
        'cocos2d', 'Cocos', 'CocosStudio', 'libcocos2d',
        'Godot', 'libgodot', 'defold', 'Xenko', 'Stride',
    ],
    # What compresses, if anything.  SLZ method 7 is Crestoria's answer.
    'compressor': [
        'SLZ', 'ZSTD', 'zstd', 'Zstandard', 'LZ4', 'lz4', 'lzma', 'LZMA',
        'brotli', 'Brotli', 'zlib', 'deflate', 'inflate', 'CRILAYLA',
        'TLZC', 'CPK ', 'FPS4', 'BLZ', 'LZ77',
    ],
    # Who made it.  The prompt's needle list, plus what a COLOPL title would
    # be expected to carry.
    'studio': [
        'colopl', 'COLOPL', 'Colopl', 'jp.colopl', 'ColoplNative',
        'namco', 'Namco', 'NAMCO', 'bandai', 'Bandai', 'BANDAI',
        'bandainamcoent', 'namco-talesstudio.co.jp', 'talesstudio',
        'Tales Studio', 'cyclamen.cgi', 'Siren14', 'Nu-Sound', 'nusound',
        'Wolf Team', 'wolfteam', 'Alfa System', 'Ganbarion', 'Dimps',
        'tri-Crescendo', 'Media.Vision', 'Prizm', 'prizm',
    ],
    # The project tag.  TO7..TO13 are known; the gap between TO11 and TO13 is
    # open, and a gacha may carry no tag at all.
    'projecttag': [
        'TO7', 'TO8', 'TO9', 'TO10', 'TO11', 'TO12', 'TO13', 'TO14', 'TO15',
        'TO16', 'TOL', 'TOLM', 'ToL', 'to12', 'to14',
        'Luminaria', 'luminaria', 'LUMINARIA', 'toluminaria',
        'Crestoria', 'crestoria', 'Xillia', 'Berseria',
        'Tales of', 'TalesOf', 'tales_of',
    ],
    # Does it download?  The scaffolding prediction stands or falls here.
    'downloader': [
        'AssetBundle', 'assetbundle', 'catalog.json', 'manifest',
        'Manifest', '.cdn', 'cdn.', 'https://', 'http://',
        'DownloadHandler', 'UnityWebRequest', 'AssetService',
        'FileDownload', 'ResourceManager', 'BundleCache',
    ],
    # The protector.  Named because the manifest names it, and measured
    # because the manifest is not evidence of what shipped.
    'protector': [
        'AppGuard', 'appguard', 'com.inca.security', 'inca', 'INCA',
        'DexProtect', 'libstub', 'libengine', 'libcompatible', 'libasset2',
        'nProtect', 'SecNeo', 'Bangcle', 'DexGuard', 'Tencent',
    ],
    # The cast, in every convention the corpus has met.  Graces writes four
    # letters, Xillia writes three from the Japanese romanisation, Crestoria
    # writes the English name.  Searching one convention and reporting the
    # zero is the mistake this list exists to avoid.
    'cast': [
        # Luminaria's own leads
        'leo', 'Leo', 'kingsman', 'Kingsman', 'celia', 'Celia',
        'michelle', 'Michelle', 'yuri', 'Yuri', 'jibril', 'Jibril',
        'lucius', 'Lucius', 'leonne', 'Leonne', 'vanessa', 'Vanessa',
        # Crestoria, the other gacha
        'kanata', 'misella', 'vicious', 'yuna',
        # the mainline builds of the corpus
        'asbel', 'sophie', 'jude', 'milla', 'estelle', 'lloyd', 'emil',
        'veigue', 'rutee', 'stan', 'luke', 'senel', 'reid', 'cress',
        # and the short forms the corpus has actually met
        'ASBE', 'SOFI', 'JUR', 'MIR', 'REI', 'LOE',
    ],
    # Audio and media middleware.
    'media': [
        'FSB5', 'FSB4', 'fmod', 'FMOD', 'CriWare', 'CRIWARE', 'criware',
        'CRI Middleware', 'ADX', 'HCA', 'Sofdec', 'USM', 'Vorbis',
        'OggS', 'Opus', 'wwise', 'Wwise', 'Audiokinetic',
    ],
}

BYTE_NEEDLES = {
    'PK\x03\x04 (zip local header)': b'PK\x03\x04',
    'zstd frame magic 0xFD2FB528': b'\x28\xb5\x2f\xfd',
    'gzip 1f 8b 08': b'\x1f\x8b\x08',
    'LZ4 frame magic 0x184D2204': b'\x04\x22\x4d\x18',
    'xz magic': b'\xfd7zXZ\x00',
    'ELF magic': b'\x7fELF',
    'dex magic': b'dex\n',
    'PNG magic': b'\x89PNG\r\n\x1a\n',
    'FSB5 (FMOD sound bank 5)': b'FSB5',
    'AAC  (ASKA audio container)': b'AAC ',
    'AIF  (ASKA texture)': b'AIF\x00',
    'SLZ  (ASKA compressed resource)': b'SLZ\x00',
    'ISF  (ASKA package)': b'ISF\x00',
    'AI node field magic 0x0131F119': struct.pack('<I', 0x0131F119),
    'AI node field magic, big-endian': struct.pack('>I', 0x0131F119),
}


def encode_all(text):
    """(label, bytes) for each encoding a needle is searched in."""
    out = [('ascii', text.encode('ascii', 'ignore'))]
    for label, enc in (('shift-jis', 'shift_jis'), ('utf-16le', 'utf-16le')):
        try:
            b = text.encode(enc)
        except UnicodeEncodeError:
            continue
        if b and b != out[0][1]:
            out.append((label, b))
    return [(l, b) for l, b in out if b]


def count_in(blob, needle):
    n = start = 0
    while True:
        i = blob.find(needle, start)
        if i < 0:
            return n
        n += 1
        start = i + 1


def chance(total_bytes, needle_len):
    if needle_len <= 0 or total_bytes < needle_len:
        return 0.0
    return (total_bytes - needle_len + 1) / (256.0 ** needle_len)


def gather(paths):
    blobs = []
    total = 0
    for root in paths:
        if os.path.isfile(root):
            files = [root]
        else:
            files = [os.path.join(d, n)
                     for d, _s, ns in os.walk(root) for n in sorted(ns)]
        for f in files:
            try:
                b = open(f, 'rb').read()
            except OSError:
                continue
            blobs.append((f, b))
            total += len(b)
    return blobs, total


def run_group(name, needles, blobs, total, min_hits):
    print('-- %s --' % name)
    print('   %-30s %5s %8s %12s  %s'
          % ('NEEDLE', 'LEN', 'HITS', 'BY CHANCE', 'WHERE'))
    for text in needles:
        rows = []
        for enc, raw in encode_all(text):
            hits = 0
            where = {}
            for path, blob in blobs:
                c = count_in(blob, raw)
                if c:
                    hits += c
                    where[os.path.basename(path)] = c
            if hits or enc == 'ascii':
                rows.append((enc, len(raw), hits, where))
        for enc, ln, hits, where in rows:
            if hits < min_hits and enc != 'ascii':
                continue
            w = ', '.join('%s x%d' % (k, v)
                          for k, v in sorted(where.items(),
                                             key=lambda kv: -kv[1])[:3])
            label = text if enc == 'ascii' else '%s [%s]' % (text, enc)
            print('   %-30s %5d %8d %12.4f  %s'
                  % (label[:30], ln, hits, chance(total, ln), w))
    print()


def selftest():
    print('needles.py --selftest')
    print()
    blob = b'x' * 1000 + b'UnityPlayer' + b'y' * 1000 + b'UnityPlayer'
    n = count_in(blob, b'UnityPlayer')
    print('  two planted occurrences found: %d  %s' % (n, 'ok' if n == 2 else 'FAILED'))
    n = count_in(b'aaaa', b'aa')
    print('  overlapping "aa" in "aaaa" counted as 3: %d  %s'
          % (n, 'ok' if n == 3 else 'FAILED'))
    print()
    print('  the chance rate this tool quotes, at a few lengths, over the')
    print('  101,922,396 bytes of this package:')
    for ln in (3, 4, 5, 6, 8, 11):
        print('    %2d-byte needle   %14.6f expected hits' % (ln, chance(101922396, ln)))
    print()
    print('  Read the four-byte row before believing any four-byte magic: at')
    print('  0.024 expected hits a single hit is real, which is the inversion')
    print('  section 7 describes on a small medium.  And read the three-byte')
    print('  row before believing any three-byte one, where it is not.')
    return 0


def main(argv):
    if '--selftest' in argv:
        raise SystemExit(selftest())
    if '--groups' in argv:
        for g in sorted(GROUPS):
            print('%-14s %d needles' % (g, len(GROUPS[g])))
        return
    paths = [a for a in argv[1:] if not a.startswith('--')]
    skip = set()
    for flag in ('--group', '--min-hits'):
        if flag in argv:
            skip.add(argv[argv.index(flag) + 1])
    custom = []
    i = 0
    while '--needle' in argv[i:]:
        j = argv.index('--needle', i)
        custom.append(argv[j + 1])
        skip.add(argv[j + 1])
        i = j + 1
    paths = [p for p in paths if p not in skip]
    if not paths:
        raise SystemExit(__doc__)
    only = argv[argv.index('--group') + 1] if '--group' in argv else None
    min_hits = int(argv[argv.index('--min-hits') + 1]) if '--min-hits' in argv else 0

    blobs, total = gather(paths)
    print('=' * 74)
    print('needle census')
    print('=' * 74)
    print('%d files, %d bytes' % (len(blobs), total))
    print()
    print('BY CHANCE is how many hits uniform random bytes of this total')
    print('length would give: (N - L + 1) / 256**L.  A count below it is')
    print('noise however large it looks; a count of one above it is real.')
    print('Zeros are printed, because a silent group is a result.')
    print()
    groups = {only: GROUPS[only]} if only else dict(GROUPS)
    if custom:
        groups = {'custom': custom}
    for name in sorted(groups):
        run_group(name, groups[name], blobs, total, min_hits)
    if not custom and not only:
        print('-- container magics, as bytes --')
        print('   %-40s %5s %8s %12s' % ('MAGIC', 'LEN', 'HITS', 'BY CHANCE'))
        for label, raw in sorted(BYTE_NEEDLES.items()):
            hits = sum(count_in(b, raw) for _p, b in blobs)
            print('   %-40s %5d %8d %12.4f'
                  % (label, len(raw), hits, chance(total, len(raw))))
        print()


if __name__ == '__main__':
    main(sys.argv)
