#!/usr/bin/env python3
"""isaccount.py -- account for every byte of this object, twice.

`acaccount.py` in this box was written for `pc-academagia-doc` and its bucket
rules name that object's directories; pointed here it files everything into one
bucket, which is recorded in docs/13 rather than patched.  This is the same
idea rewritten for this object, and it is written so that it **cannot** report
a closure it has not earned: the family of every file is decided by reading its
first bytes, not by its extension or its path, and any file that no rule claims
lands in `UNCLAIMED` and makes the exit code non-zero.

Two accountings, deliberately different
----------------------------------------

  1. **By container family** -- what format each byte is in.  Six rows, and
     they must sum to the tree.
  2. **By what the bytes are for** -- game content, audio, third-party code,
     engine.  This is the harder one and it is a judgement, so every rule is
     printed with the row it produced and the ambiguous cases are named.

The second accounting needs one decision stated out loud: **the 35 Unity
SerializedFiles and the 145 bundles are the studio's content inside the
engine's container.**  They are counted as game content, not as engine, and
the engine row is what is left: the player, the Mono runtime, the class
libraries and the plugins.  The alternative -- counting the container as
engine -- is stated in docs/10 with the number it would give, so the reader
can take the other view without re-running anything.

    python isaccount.py selftest
    python isaccount.py families ROOT
    python isaccount.py purpose  ROOT
    python isaccount.py check    ROOT --expect 1471268535

Standard library only.
"""

import argparse
import collections
import os
import struct
import sys

MAGIC_RULES = (
    # (family, test on the first 16 bytes)
    ('Unity AssetBundle (UnityWeb)', lambda h: h[:9] == b'UnityWeb\0'),
    ('CRIWARE @UTF table', lambda h: h[:4] == b'@UTF'),
    ('CRIWARE AFS2 bank', lambda h: h[:4] == b'AFS2'),
    ('CRIWARE CPK archive', lambda h: h[:4] == b'CPK '),
    ('Lua 5.2 bytecode', lambda h: h[:4] == b'\x1bLua'),
    ('PE/COFF', lambda h: h[:2] == b'MZ'),
)


def is_serialized(h):
    if len(h) < 20:
        return False
    meta, fsize, version, doff = struct.unpack_from('>IIII', h, 0)
    return (5 <= version <= 30 and h[16] in (0, 1) and 0 < doff <= fsize
            and 0 < meta + 20 <= fsize)


def is_text(h):
    if not h:
        return False
    if h[:5] == b'<?xml' or h[:1] == b'<':
        return True
    return all(9 <= b < 127 or b in (10, 13) for b in h)


def family_of(path):
    try:
        with open(path, 'rb') as f:
            h = f.read(64)
    except OSError:
        return 'UNREADABLE'
    for name, test in MAGIC_RULES:
        if test(h):
            return name
    if is_serialized(h):
        # a real header declares the file's own length; check it, because
        # `is_serialized` on 20 bytes alone would claim anything
        fsize, = struct.unpack_from('>I', h, 4)
        if fsize == os.path.getsize(path):
            return 'Unity SerializedFile v15'
        return 'UNCLAIMED'
    if is_text(h):
        return 'text, XML and configuration'
    return 'UNCLAIMED'


# The purpose rules are path-shaped and that is the point: a byte's *format*
# is in its first bytes, but what it is *for* is only knowable from where the
# build put it.  Each rule is printed with the row it produced.
PURPOSE_RULES = (
    ('game content (Lua script)',
     'SETSUNA_Data/StreamingAssets/data/event'),
    ('audio (CRIWARE)', 'SETSUNA_Data/StreamingAssets/x86_64'),
    ('engine (Mono runtime and class libraries)', 'SETSUNA_Data/Mono'),
    ('engine (Unity managed assemblies)', 'SETSUNA_Data/Managed'),
    ('engine (Unity built-in resources)', 'SETSUNA_Data/Resources'),
    ('third-party code (native plugins)', 'SETSUNA_Data/Plugins'),
)


def purpose_of(path, root, family):
    rel = os.path.relpath(path, root).replace('\\', '/')
    name = os.path.basename(rel)
    if name == 'steam_api.dll':
        return 'third-party code (Steamworks)'
    if name == 'SETSUNA.exe':
        return 'engine (the Unity player)'
    if rel.startswith('SETSUNA_Data/Managed/Assembly-CSharp'):
        return 'game content (the studio\'s own code)'
    for label, prefix in PURPOSE_RULES:
        if rel.startswith(prefix):
            if label == 'audio (CRIWARE)' and family.startswith('Unity'):
                return 'game content (Unity bundle)'
            return label
    if family in ('Unity SerializedFile v15',
                  'Unity AssetBundle (UnityWeb)'):
        return 'game content (Unity container)'
    return 'UNCLAIMED'


def walk(root):
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            yield os.path.join(dirpath, nm)


def tally(root):
    fam = collections.Counter()
    fam_b = collections.Counter()
    pur = collections.Counter()
    pur_b = collections.Counter()
    unclaimed = []
    n = total = 0
    for p in walk(root):
        size = os.path.getsize(p)
        f = family_of(p)
        u = purpose_of(p, root, f)
        n += 1
        total += size
        fam[f] += 1
        fam_b[f] += size
        pur[u] += 1
        pur_b[u] += size
        if f == 'UNCLAIMED' or u == 'UNCLAIMED':
            unclaimed.append((p, size, f, u))
    return n, total, fam, fam_b, pur, pur_b, unclaimed


def _table(title, counts, byts, total):
    print('%-44s %6s %14s' % (title, 'FILES', 'BYTES'))
    n = b = 0
    for k in sorted(counts, key=lambda k: -byts[k]):
        print('%-44s %6d %14d' % (k, counts[k], byts[k]))
        n += counts[k]
        b += byts[k]
    print('%-44s %6d %14d' % ('TOTAL', n, b))
    print('residue against the tree: %d' % (total - b))
    return b


def cmd_families(args):
    n, total, fam, fam_b, _p, _pb, unclaimed = tally(args.root)
    print('files %d, bytes %d' % (n, total))
    print()
    b = _table('FAMILY, decided by the first bytes', fam, fam_b, total)
    if unclaimed:
        print()
        print('%d unclaimed:' % len(unclaimed))
        for p, size, f, u in unclaimed[:20]:
            print('  %-56s %10d  %s / %s'
                  % (os.path.relpath(p, args.root)[-56:], size, f, u))
    return 0 if (b == total and not unclaimed) else 2


def cmd_purpose(args):
    n, total, _f, _fb, pur, pur_b, unclaimed = tally(args.root)
    print('files %d, bytes %d' % (n, total))
    print()
    b = _table('PURPOSE, decided by where the build put it', pur, pur_b, total)
    print()
    groups = collections.Counter()
    gf = collections.Counter()
    for k in pur:
        g = k.split(' (')[0]
        groups[g] += pur_b[k]
        gf[g] += pur[k]
    print('%-44s %6s %14s' % ('ROLLED UP', 'FILES', 'BYTES'))
    for g in sorted(groups, key=lambda g: -groups[g]):
        print('%-44s %6d %14d' % (g, gf[g], groups[g]))
    print('%-44s %6d %14d' % ('TOTAL', sum(gf.values()), sum(groups.values())))
    data = groups.get('game content', 0) + groups.get('audio', 0)
    code = groups.get('engine', 0) + groups.get('third-party code', 0)
    print()
    print('data %d against code %d' % (data, code))
    if code:
        print('ratio, as two integers: %d to %d' % (data, code))
        print('        which is %.2f to 1' % (float(data) / code))
    if unclaimed:
        print()
        print('%d unclaimed' % len(unclaimed))
        for p, size, f, u in unclaimed[:20]:
            print('  %-56s %10d  %s / %s'
                  % (os.path.relpath(p, args.root)[-56:], size, f, u))
    return 0 if (b == total and not unclaimed) else 2


def cmd_check(args):
    n, total, fam, fam_b, pur, pur_b, unclaimed = tally(args.root)
    fb = sum(fam_b.values())
    pb = sum(pur_b.values())
    print('files                       : %d' % n)
    print('bytes, walked               : %d' % total)
    print('bytes, summed by family     : %d   residue %d' % (fb, total - fb))
    print('bytes, summed by purpose    : %d   residue %d' % (pb, total - pb))
    print('unclaimed files             : %d' % len(unclaimed))
    ok = (fb == total == pb and not unclaimed)
    if args.expect is not None:
        print('expected                    : %d   residue %d'
              % (args.expect, args.expect - total))
        ok = ok and args.expect == total
    print('VERDICT                     : %s'
          % ('closes at residue 0' if ok else 'DOES NOT CLOSE'))
    return 0 if ok else 2


def cmd_selftest(_args):
    """A tree built in a temporary directory, with the answer known."""
    import shutil
    import tempfile
    root = tempfile.mkdtemp(prefix='isaccount')
    ok = bad = 0
    try:
        os.makedirs(os.path.join(root, 'SETSUNA_Data', 'Managed'))
        os.makedirs(os.path.join(root, 'SETSUNA_Data', 'StreamingAssets',
                                 'x86_64', 'bgm', 'acb'))
        os.makedirs(os.path.join(root, 'SETSUNA_Data', 'StreamingAssets',
                                 'data', 'event'))
        specimens = [
            ('SETSUNA.exe', b'MZ' + b'\0' * 62,
             'PE/COFF', 'engine (the Unity player)'),
            (os.path.join('SETSUNA_Data', 'Managed',
                          'Assembly-CSharp.dll'), b'MZ' + b'\0' * 62,
             'PE/COFF', "game content (the studio's own code)"),
            (os.path.join('SETSUNA_Data', 'StreamingAssets', 'x86_64', 'bgm',
                          'acb', 'a.acb'), b'@UTF' + b'\0' * 60,
             'CRIWARE @UTF table', 'audio (CRIWARE)'),
            (os.path.join('SETSUNA_Data', 'StreamingAssets', 'data', 'event',
                          'a.lua.out'), b'\x1bLua' + b'\0' * 60,
             'Lua 5.2 bytecode', 'game content (Lua script)'),
            (os.path.join('SETSUNA_Data', 'StreamingAssets', 'x86_64',
                          'ma_0000_01'), b'UnityWeb\0' + b'\0' * 55,
             'Unity AssetBundle (UnityWeb)', 'game content (Unity bundle)'),
        ]
        for rel, blob, fam, pur in specimens:
            p = os.path.join(root, rel)
            with open(p, 'wb') as f:
                f.write(blob)
            gf = family_of(p)
            gp = purpose_of(p, root, gf)
            if (gf, gp) == (fam, pur):
                print('  ok      %-38s %s / %s' % (os.path.basename(rel),
                                                   gf, gp))
                ok += 1
            else:
                print('  WRONG   %-38s %s / %s, wanted %s / %s'
                      % (os.path.basename(rel), gf, gp, fam, pur))
                bad += 1
        # a file no rule should claim
        p = os.path.join(root, 'mystery.bin')
        with open(p, 'wb') as f:
            f.write(bytes(range(200, 256)) * 2)
        if family_of(p) == 'UNCLAIMED':
            print('  ok      %-38s refuses to guess' % 'mystery.bin')
            ok += 1
        else:
            print('  WRONG   %-38s %s' % ('mystery.bin', family_of(p)))
            bad += 1
        # a SerializedFile header whose declared length is a lie
        p = os.path.join(root, 'liar')
        with open(p, 'wb') as f:
            f.write(struct.pack('>IIII', 8, 999999, 15, 32) + b'\0' * 44)
        if family_of(p) == 'UNCLAIMED':
            print('  ok      %-38s declared length is a lie' % 'liar')
            ok += 1
        else:
            print('  WRONG   %-38s %s' % ('liar', family_of(p)))
            bad += 1
        n, total, fam, fam_b, pur, pur_b, unclaimed = tally(root)
        if len(unclaimed) == 2 and n == 7:
            print('  ok      %-38s 7 files, 2 unclaimed, non-zero exit'
                  % 'the tally')
            ok += 1
        else:
            print('  WRONG   %-38s %d files, %d unclaimed'
                  % ('the tally', n, len(unclaimed)))
            bad += 1
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'families', 'purpose',
                                     'check'))
    ap.add_argument('root', nargs='?')
    ap.add_argument('--expect', type=int)
    args = ap.parse_args()
    if args.mode != 'selftest' and not args.root:
        ap.error('%s needs a root' % args.mode)
    return globals()['cmd_' + args.mode](args)


if __name__ == '__main__':
    sys.exit(main())
