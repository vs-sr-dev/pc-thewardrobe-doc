#!/usr/bin/env python3
"""tngscore.py -- read `HIGHSCOR.TNG` by narrowing 512 candidate keys in three
declared stages, and refuse to pick a winner until the third one is supplied.

WHAT THE PRE-BRIEFING GOT AND WHERE IT STOPPED
-----------------------------------------------
`_work/hiscore.py` established the shape of the file and stopped in the right
place: 104 bytes = 4 records of 26, every record opening with six 0xFE, filler
0xDA. It argued for the one-byte complement -- ~0xDA is `%`, ~0xFE is 0x01 --
read out

    SNCDSUN   FTFMHDMLN   UHLNUIX   LHBIDMD

and said, correctly, that those are not Italian names and that the reading
stopped there.

**The complement was one bit away.** The probe swept the affine family `k - x`
and the single mask `x ^ 0x80`; it never swept `x ^ k` over all 256 keys. The
key is **0xFE**, which differs from `x ^ 0xFF` in the low bit alone, so every
letter the probe printed is the right letter with its bottom bit flipped:
`S`/`R`, `N`/`O`, `C`/`B`, `U`/`T`.

THE THREE STAGES, AND NONE OF THEM IS "IT LOOKS RIGHT"
-------------------------------------------------------
**Stage 1, structure. 512 -> 6.** All 256 keys of `x ^ k` and all 256 of
`k - x`, kept only if every record's 20-byte name field is a run of A-Z
followed by a run of one single non-letter filler, with at least three letters
and at least one filler byte. Nothing in that test mentions 0xFE or `$`.

**Stage 2, the score field. 6 -> 2.** A shipped default table has no scores in
it, so the six-byte score field is required to be six zero bytes. Two keys
survive -- `x ^ 0xFE` and `0xFE - x` -- and, pleasingly, they agree on the
filler as well: both make it `$`, which is the DOS INT 21h AH=09 string
terminator and exactly what a 1990s DOS program pads a printable field with.

**Stage 3, corroboration, and it comes from OUTSIDE this file.** The two
survivors read

    x ^ 0xFE     ROBERTO   GUGLIELMO   TIMOTHY   MICHELE
    0xFE - x     RMBCRTM   FKFNIBNJO   TIJORHW   NIAEBKB

and picking between them by eye would be fitting. `--credits` takes the names
that the object states somewhere else -- they are drawn in the pixels of
`RESOURCE.FV3`, which is a picture and not a string, and are recovered with
`px.py --render --crop` -- and counts exact matches. **The corroborating
artefact is independent of this file**, which is what makes the third stage a
measurement rather than a preference.

    python tools/px.py --render iggdt/RESOURCE.FV3 --out _work/png \\
        --crop 20,125,280,60 --zoom 3        # read the credits, then:
    python tools/tngscore.py iggdt/HIGHSCOR.TNG
    python tools/tngscore.py iggdt/HIGHSCOR.TNG \\
        --credits GUGLIELMO,ROBERTO,MICHELE,THIMOTY
    python tools/tngscore.py --selftest

WHAT THIS TOOL DOES NOT CLAIM
------------------------------
It does not claim the six zero bytes are a Turbo Pascal 6-byte `Real`, though
six is that type's width and zero is its zero. Nothing in 104 bytes tells a
`Real` from six zeroed bytes of anything else, so the output says "six zero
bytes".

It does not claim `TIMOTHY` and the credits screen's `Thimoty` are a
contradiction to be resolved. They are two spellings of one person in the only
two places this object says who made it, and the mismatch is reported as a
mismatch: stage 3 scores **3 of 4** exact and names the one that differs.
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

RECORD = 26
SCORE = 6
NAME = 20


def records(blob):
    if len(blob) % RECORD:
        raise ValueError('%d bytes is not a whole number of %d-byte records'
                         % (len(blob), RECORD))
    return [blob[i:i + RECORD] for i in range(0, len(blob), RECORD)]


def apply_key(blob, kind, key):
    if kind == 'xor':
        return bytes(b ^ key for b in blob)
    if kind == 'sub':
        return bytes((key - b) & 0xFF for b in blob)
    raise ValueError('unknown transform %r' % kind)


def split(rec):
    """(score bytes, name letters, filler byte, filler count) for one record."""
    field = rec[SCORE:SCORE + NAME]
    letters = 0
    while letters < NAME and 0x41 <= field[letters] <= 0x5A:
        letters += 1
    return (rec[:SCORE], field[:letters], field[letters:letters + 1],
            NAME - letters)


def structural(plain):
    """Stage 1: A-Z run, then one repeated non-letter filler. No key named."""
    for rec in records(plain):
        _score, name, filler, pad = split(rec)
        if len(name) < 3 or pad == 0:
            return False
        if len(set(rec[SCORE + len(name):SCORE + NAME])) != 1:
            return False
        if 0x41 <= filler[0] <= 0x5A:
            return False
    return True


def zero_scores(plain):
    """Stage 2: a shipped default table has no scores in it."""
    return all(split(rec)[0] == b'\x00' * SCORE for rec in records(plain))


def names(plain):
    return [split(rec)[1].decode('ascii') for rec in records(plain)]


def sweep(blob, stage=1):
    """Every key that survives `stage` filters, as (kind, key) pairs."""
    out = []
    for kind in ('xor', 'sub'):
        for key in range(256):
            plain = apply_key(blob, kind, key)
            if not structural(plain):
                continue
            if stage >= 2 and not zero_scores(plain):
                continue
            out.append((kind, key))
    return out


def corroborate(plain, wanted):
    """Stage 3: exact matches against names stated elsewhere in the object."""
    pool = [w.strip().upper() for w in wanted if w.strip()]
    got = names(plain)
    hits = sum(1 for name in got if name in pool)
    return hits, [name for name in got if name not in pool]


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    want('records splits 104 into four', len(records(b'\x00' * 104)), 4)
    try:
        records(b'\x00' * 103)
        want('a ragged length is refused', 'no exception', 'ValueError')
    except ValueError:
        want('a ragged length is refused', 'ValueError', 'ValueError')

    want('xor 0 is the identity', apply_key(b'\x01\x02', 'xor', 0),
         b'\x01\x02')
    want('xor is an involution',
         apply_key(apply_key(b'\x01\x02', 'xor', 0xFE), 'xor', 0xFE),
         b'\x01\x02')
    want('sub 0xFF is the complement', apply_key(b'\x00\x01', 'sub', 0xFF),
         b'\xff\xfe')

    def build(rows, key, kind='xor', score=b'\x00' * SCORE):
        raw = bytearray()
        for name in rows:
            raw += score + name.encode('ascii').ljust(NAME, b'$')
        return apply_key(bytes(raw), kind, key)

    planted = ['ALFA', 'BRAVOCHARLIE', 'DELTA', 'ECHO']
    made = build(planted, 0x5B)
    stage1 = sweep(made, 1)
    stage2 = sweep(made, 2)
    want('the planted key survives stage 1', ('xor', 0x5B) in stage1, True)
    want('the planted key survives stage 2', ('xor', 0x5B) in stage2, True)
    want('stage 2 is at least as strict as stage 1',
         set(stage2) <= set(stage1), True)
    want('the planted names come back',
         names(apply_key(made, 'xor', 0x5B)), planted)
    want('the planted filler is $',
         {split(r)[2] for r in records(apply_key(made, 'xor', 0x5B))}, {b'$'})

    # Stage 2 must actually bite: the same table with a non-zero score must
    # fail it under its own key.
    scored = build(planted, 0x5B, score=b'\x01' * SCORE)
    want('a non-zero score fails stage 2',
         ('xor', 0x5B) in sweep(scored, 2), False)
    want('a non-zero score still passes stage 1',
         ('xor', 0x5B) in sweep(scored, 1), True)

    # Stage 3 must discriminate, and must count a mismatch as a mismatch.
    plain = apply_key(made, 'xor', 0x5B)
    want('four of four corroborate',
         corroborate(plain, ['ALFA', 'BRAVOCHARLIE', 'DELTA', 'ECHO']),
         (4, []))
    want('three of four corroborate, and the odd one is named',
         corroborate(plain, ['ALFA', 'BRAVOCHARLIE', 'DELTA']),
         (3, ['ECHO']))
    want('nothing corroborates against an empty list',
         corroborate(plain, [])[0], 0)

    # And the structural test must REJECT the shapes it is meant to reject.
    digit = bytearray(b'\x00' * SCORE + b'AL7A'.ljust(NAME, b'$')) * 4
    want('a digit inside a name fails stage 1', structural(bytes(digit)), False)
    ragged = bytearray(b'\x00' * SCORE + b'ALFA'.ljust(NAME, b'$')) * 4
    ragged[SCORE + NAME - 1] = 0x21
    want('a ragged filler fails stage 1', structural(bytes(ragged)), False)
    want('an all-filler field fails stage 1',
         structural(bytes(b'\x00' * SCORE + b'$' * NAME) * 4), False)
    want('an all-letter field fails stage 1',
         structural(bytes(b'\x00' * SCORE + b'A' * NAME) * 4), False)
    want('a two-letter name fails stage 1',
         structural(bytes(b'\x00' * SCORE + b'AB'.ljust(NAME, b'$')) * 4),
         False)

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--credits', default=None,
                    help='comma-separated names stated elsewhere in the '
                         'object, for stage 3')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())
    if not args.file:
        ap.error('give a file, or --selftest')
    dirguard.want_file(args.file, 'tngscore')
    with open(args.file, 'rb') as handle:
        blob = handle.read()

    print('file            : %s' % os.path.basename(args.file))
    print('bytes           : %d = %d records of %d = %d score + %d name'
          % (len(blob), len(blob) // RECORD, RECORD, SCORE, NAME))
    hist = collections.Counter(blob)
    print('distinct values : %d   commonest %s'
          % (len(hist), hist.most_common(3)))
    print('')

    stage1 = sweep(blob, 1)
    stage2 = sweep(blob, 2)
    print('STAGE 1  structure      : 512 keys tried, %d survive' % len(stage1))
    print('             %s' % '  '.join('%s 0x%02X' % kv for kv in stage1))
    print('STAGE 2  score is zero  : %d of those %d survive'
          % (len(stage2), len(stage1)))
    print('             %s' % '  '.join('%s 0x%02X' % kv for kv in stage2))
    print('')
    print('what the survivors of stage 2 read out:')
    for kind, key in stage2:
        plain = apply_key(blob, kind, key)
        filler = {split(r)[2].decode('latin-1') for r in records(plain)}
        print('  %-4s 0x%02X  filler %-4s %s'
              % (kind, key, ''.join(sorted(filler)),
                 '   '.join('%-10s' % n for n in names(plain))))
    print('')

    if not stage2:
        raise SystemExit('tngscore: nothing survives stage 2')
    if not args.credits:
        if len(stage2) > 1:
            print('STAGE 3  corroboration  : NOT RUN. %d keys still stand and '
                  'this tool will not' % len(stage2))
            print('             pick between them by eye. Pass --credits with '
                  'the names the object')
            print('             states elsewhere -- they are drawn in '
                  'RESOURCE.FV3 and come out of')
            print('             px.py --render --crop -- and the choice '
                  'becomes a count.')
            raise SystemExit(2)
        chosen = stage2[0]
    else:
        wanted = args.credits.split(',')
        print('STAGE 3  corroboration  : against %d name(s) stated elsewhere '
              'in the object' % len([w for w in wanted if w.strip()]))
        scored = []
        for kind, key in stage2:
            hits, misses = corroborate(apply_key(blob, kind, key), wanted)
            scored.append((hits, kind, key, misses))
            print('  %-4s 0x%02X  %d of %d exact%s'
                  % (kind, key, hits, len(blob) // RECORD,
                     '' if not misses else '   not matched: %s'
                     % ', '.join(misses)))
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] == scored[1][0]:
            raise SystemExit('tngscore: stage 3 is a tie at %d; the reading '
                             'is not forced' % scored[0][0])
        if scored[0][0] == 0:
            raise SystemExit('tngscore: no survivor corroborates at all')
        chosen = (scored[0][1], scored[0][2])

    kind, key = chosen
    plain = apply_key(blob, kind, key)
    print('')
    print('THE KEY         : %s 0x%02X' % (kind, key))
    print('    it differs from x ^ 0xFF, the pre-briefing\'s reading, '
          'in %d bit(s)' % bin(key ^ 0xFF).count('1'))
    print('')
    print('  %-4s %-20s %-12s %s' % ('rec', 'score', 'name', 'field'))
    for i, rec in enumerate(records(plain), 1):
        score, name, filler, pad = split(rec)
        print('  %-4d %-20s %-12s %d letters + %d x %r'
              % (i, score.hex(' '), name.decode('ascii'), len(name), pad,
                 filler.decode('latin-1')))
    print('')
    print('distinct scores : %d' % len({split(r)[0] for r in records(plain)}))
    print('distinct fillers: %s'
          % ''.join(sorted({split(r)[2].decode('latin-1')
                            for r in records(plain)})))


if __name__ == '__main__':
    main()
