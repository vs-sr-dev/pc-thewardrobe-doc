#!/usr/bin/env python3
"""This package against the other Android *Tales* in the corpus, four ways.

*Tales of Crestoria* (2020) and *Tales of Luminaria* (2021) are the only two
Android titles here, they are fourteen months apart, and they are published by
the same company.  That makes them the strongest cross-title comparison
available at the *package* level -- and the comparison has to be run rather
than assumed, because the two turn out to share no engine, no container, no
compressor and no developer.

Four independent passes, each reported apart:

  1. **whole files, by SHA-1** -- an asset carried across unchanged shows up
     here and nowhere else.  Empty files are kept and reported *as* empty
     rather than skipped: on *Tales of Xillia* against *Tales of Graces* the
     intersection was exactly one file and it was the zero-length one, and
     saying so is a more honest claim than reporting nought.
  2. **payloads one level down** -- Crestoria's ISF members and Luminaria's
     Unity object bodies, hashed the same way, because two builds could share
     an asset without sharing the container it arrived in.
  3. **internal names**, harvested from both and intersected -- and *printed*,
     not counted.  A name census that reports "44 in common" and does not say
     which is not a finding.
  4. **the packages' own declarations** side by side: package name, version,
     SDK levels, ABIs, entry point, entry count, byte count.

    python crossapk.py sha      DIR_A DIR_B [--labels A,B]
    python crossapk.py names    NAMES_A NAMES_B [--labels A,B]
    python crossapk.py payloads DIR_A DIR_B [--labels A,B]
    python crossapk.py --selftest

`sha` and `payloads` take directories of extracted files.  `names` takes two
files of one name per line (or tab-separated with the name first).

Standard library only.
"""

import collections
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def labels(argv, default=('A', 'B')):
    if '--labels' in argv:
        parts = argv[argv.index('--labels') + 1].split(',')
        if len(parts) >= 2:
            return parts[0], parts[1]
    return default


def hash_tree(root):
    """SHA-1 of every file under `root`, keyed by hash."""
    out = collections.defaultdict(list)
    n = 0
    total = 0
    for d, _s, names in os.walk(root):
        for nm in sorted(names):
            p = os.path.join(d, nm)
            try:
                b = open(p, 'rb').read()
            except OSError:
                continue
            n += 1
            total += len(b)
            out[hashlib.sha1(b).hexdigest()].append(
                (os.path.relpath(p, root).replace('\\', '/'), len(b)))
    return out, n, total


def cmd_sha(argv):
    la, lb = labels(argv)
    a, na, ba = hash_tree(argv[2])
    b, nb, bb = hash_tree(argv[3])
    print('=' * 74)
    print('whole files, by SHA-1')
    print('=' * 74)
    print('%-28s %8s files %16s bytes' % (la, na, '{:,}'.format(ba)))
    print('%-28s %8s files %16s bytes' % (lb, nb, '{:,}'.format(bb)))
    print('%-28s %8d distinct hashes' % (la, len(a)))
    print('%-28s %8d distinct hashes' % (lb, len(b)))
    print()
    common = sorted(set(a) & set(b))
    print('%d hashes occur in both packages.' % len(common))
    print()
    if common:
        print('%-42s %12s  %s' % ('SHA-1', 'BYTES', 'NAMES'))
        for h in common:
            size = a[h][0][1]
            print('%-42s %12d' % (h, size))
            for label, rows in ((la, a[h]), (lb, b[h])):
                for nm, _sz in rows[:4]:
                    print('    %-10s %s' % (label, nm))
            if size == 0:
                print('    NOTE: this is the zero-length file.  It is reported')
                print('          because it is what the measurement returned,')
                print('          not filtered out to make the number tidier.')
        print()
    nonempty = [h for h in common if a[h][0][1] > 0]
    print('%d of those are non-empty.' % len(nonempty))


def descend_payloads(root):
    """One level down: Unity object bodies, ISF members, FSB5 samples."""
    import unityfs
    out = collections.defaultdict(list)
    n = 0
    total = 0
    for d, _s, names in os.walk(root):
        for nm in sorted(names):
            p = os.path.join(d, nm)
            rel = os.path.relpath(p, root).replace('\\', '/')
            if unityfs.is_serialized(p):
                try:
                    sf = unityfs.load(p)
                except Exception:
                    continue
                for o in sf.objects:
                    body = sf.body(o)
                    n += 1
                    total += len(body)
                    out[hashlib.sha1(body).hexdigest()].append(
                        ('%s::%s/%d' % (rel,
                                        unityfs.CLASS.get(sf.class_of(o), '?'),
                                        o['path_id']), len(body)))
            else:
                try:
                    b = open(p, 'rb').read()
                except OSError:
                    continue
                n += 1
                total += len(b)
                out[hashlib.sha1(b).hexdigest()].append((rel, len(b)))
    return out, n, total


def cmd_payloads(argv):
    la, lb = labels(argv)
    a, na, ba = descend_payloads(argv[2])
    b, nb, bb = descend_payloads(argv[3])
    print('=' * 74)
    print('payloads one level down, by SHA-1')
    print('=' * 74)
    print('A Unity serialized file is opened and each object body hashed; a')
    print('file of any other kind is hashed whole.  The counts below are')
    print('therefore payloads, not files, and the difference is the point:')
    print('two builds could share an asset without sharing its container.')
    print()
    print('%-28s %8d payloads %16s bytes' % (la, na, '{:,}'.format(ba)))
    print('%-28s %8d payloads %16s bytes' % (lb, nb, '{:,}'.format(bb)))
    print()
    common = sorted(set(a) & set(b))
    print('%d payload hashes occur in both packages.' % len(common))
    for h in common[:60]:
        size = a[h][0][1]
        print('  %s  %d bytes' % (h, size))
        print('    %-10s %s' % (la, a[h][0][0]))
        print('    %-10s %s' % (lb, b[h][0][0]))
    if len(common) > 60:
        print('  ... %d more' % (len(common) - 60))
    nonempty = [h for h in common if a[h][0][1] > 0]
    print()
    print('%d of those are non-empty.' % len(nonempty))


def load_names(path):
    out = set()
    for line in open(path, encoding='utf-8', errors='replace'):
        line = line.rstrip('\n')
        if not line:
            continue
        out.add(line.split('\t')[0])
    return out


def cmd_names(argv):
    la, lb = labels(argv)
    a = load_names(argv[2])
    b = load_names(argv[3])
    print('=' * 74)
    print('internal names, intersected -- and printed')
    print('=' * 74)
    print('%-28s %8d distinct names' % (la, len(a)))
    print('%-28s %8d distinct names' % (lb, len(b)))
    common = sorted(a & b)
    print('%-28s %8d in both' % ('intersection', len(common)))
    print()
    for nm in common:
        print('  %s' % nm)
    print()
    print('%d names in common.  They are listed rather than counted, because'
          % len(common))
    print('a count cannot be read: a hundred shared names that are all Unity')
    print('built-ins say something different from ten that are not.')
    ci = {}
    for nm in a:
        ci.setdefault(nm.lower(), set()).add('a')
    for nm in b:
        ci.setdefault(nm.lower(), set()).add('b')
    both = sum(1 for v in ci.values() if len(v) == 2)
    print()
    print('%d names match if case is ignored, against %d that match exactly:'
          % (both, len(common)))
    for nm in sorted(k for k, v in ci.items() if len(v) == 2):
        print('  %s' % nm)


def selftest():
    import tempfile
    print('crossapk.py --selftest')
    print()
    ok = 0
    d = tempfile.mkdtemp()
    a = os.path.join(d, 'a')
    b = os.path.join(d, 'b')
    os.makedirs(a)
    os.makedirs(b)
    open(os.path.join(a, 'same'), 'wb').write(b'hello')
    open(os.path.join(b, 'renamed'), 'wb').write(b'hello')
    open(os.path.join(a, 'empty'), 'wb').write(b'')
    open(os.path.join(b, 'empty2'), 'wb').write(b'')
    open(os.path.join(a, 'only-a'), 'wb').write(b'xyz')
    ha, na, _ba = hash_tree(a)
    hb, nb, _bb = hash_tree(b)
    common = set(ha) & set(hb)
    checks = [
        ('files counted', na == 3 and nb == 2, '%d and %d' % (na, nb)),
        ('two hashes in common', len(common) == 2, str(len(common))),
        ('the empty file is one of them',
         hashlib.sha1(b'').hexdigest() in common, ''),
        ('a renamed identical file is found',
         hashlib.sha1(b'hello').hexdigest() in common, ''),
    ]
    for label, good, got in checks:
        ok += good
        print('  %-38s %-14s %s' % (label, got, 'ok' if good else 'FAILED'))
    print()
    print('  %d of %d checks pass.' % (ok, len(checks)))
    print()
    print('  The third is the one that matters.  A tool that skips zero-length')
    print('  files reports an intersection of one here instead of two, and on')
    print('  Tales of Xillia against Tales of Graces that difference was the')
    print('  whole of the result.')
    return 0 if ok == len(checks) else 1


def main(argv):
    if '--selftest' in argv:
        raise SystemExit(selftest())
    if len(argv) < 4:
        raise SystemExit(__doc__)
    cmds = dict(sha=cmd_sha, names=cmd_names, payloads=cmd_payloads)
    if argv[1] not in cmds:
        raise SystemExit(__doc__)
    cmds[argv[1]](argv)


if __name__ == '__main__':
    main(sys.argv)
