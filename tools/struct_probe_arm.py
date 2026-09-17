#!/usr/bin/env python3
"""The codec's structure, when the constant scan has already come back empty.

Section 7, step 3 of the Java variant: stop relying on the constant, because a
constant can be computed.  Look for what a compiler cannot rewrite away -- the
4,096-byte ring, the mask, the control-register refill, the nibble split, and
the run escape's `+3` and `+19`.  These are section 3's fingerprints in
another encoding.

On ARM the encoding matters, and it cuts both ways:

  * `orr rX, rX, #0xFF00` **is** encodable (0xFF ror #24), so the control
    refill would appear as a plain immediate and this scan would see it.
  * `and rX, rY, #0x0FFF` is **not** encodable -- 4095 needs twelve bits.  A
    compiler masks to twelve bits with `lsl #20` / `lsr #20`, or loads 4095
    from the literal pool.  All three forms are counted.
  * `4096` **is** encodable (1 ror #20), so a 4,096-byte stack frame or an
    allocation argument is visible as an immediate.
  * `+3` and `+19` are ordinary small immediates and are noise on their own.
    They are only reported where they occur *together* inside one routine, and
    the count of each on its own is printed as the denominator.

Every count comes with the number of instructions it was drawn from, because
a zero means nothing without one.

    python struct_probe.py FILE [--base VA] [--window 200]
    python struct_probe.py DIR --dir [--window 200]
    python struct_probe.py --selftest

`--dir` runs the probe over every `.bin` in a directory and prints one row per
module and a totals row.  A Nintendo DS build is thirty-three modules, and a
fingerprint count taken from `arm9.bin` alone is a count over under a third of
the code.

**This probe has never been run against an ARM build that contains the
codec, because no such build is known.**  Section 7 of the corpus records
that a structural probe is calibrated against one toolchain's idiom and that
a new toolchain is a new calibration -- it scored zero on a true positive on
the Xbox 360 until it was taught Microsoft's spelling of the refill.  The
same failure mode is available here and there is nothing to calibrate
against, so a zero from this file is worth less on ARM than the same zero was
worth on PowerPC, and that has to be said next to the number rather than
after it.

Two things are done about it rather than nothing.  The refill test does
**not** require the destination and source registers to be the same, so both
of the spellings that caught out the PowerPC probe are counted here.  And
`--selftest` assembles each fingerprint by hand, in every form this file
looks for, and checks that the detector fires on it -- which demonstrates
that the detectors work and does **not** demonstrate that an ARM compiler
would spell a real decoder the way they expect.

Standard library only.
"""

import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0].rsplit('/', 1)[0])
from ring_sites import ror32, ARM_DP


def arm_dp(data):
    """Yield (offset, opcode, rd, rn, value) for every ARM DP-immediate."""
    for i in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, i)[0]
        if (w >> 28) == 0xF:
            continue
        if (w >> 26) & 3 or not (w >> 25) & 1:
            continue
        opc = (w >> 21) & 0xF
        if 8 <= opc <= 11 and not (w >> 20) & 1:
            continue
        yield (i, opc, (w >> 12) & 0xF, (w >> 16) & 0xF,
               ror32(w & 0xFF, ((w >> 8) & 0xF) * 2))


def arm_shifts(data):
    """Yield (offset, type, amount, rd, rm) for every ARM register shift."""
    for i in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, i)[0]
        if (w >> 28) == 0xF:
            continue
        if (w >> 26) & 3 or (w >> 25) & 1 or (w >> 4) & 1:
            continue
        opc = (w >> 21) & 0xF
        if opc != 13:                       # mov only -- the shift idiom
            continue
        yield (i, (w >> 5) & 3, (w >> 7) & 0x1F, (w >> 12) & 0xF, w & 0xF)


def thumb_imm(data):
    """Yield (offset, op, rd, imm8) for THUMB mov/cmp/add/sub #imm8.

    This build is mostly THUMB -- there are seventeen times as many THUMB
    shifts as ARM ones -- so a probe that looked only at ARM would be looking
    at the wrong instruction set."""
    for i in range(0, len(data) - 1, 2):
        h = struct.unpack_from('<H', data, i)[0]
        if (h >> 13) != 1:
            continue
        yield (i, (h >> 11) & 3, (h >> 8) & 7, h & 0xFF)


def thumb_shifts(data):
    """Yield (offset, type, amount) for every THUMB lsl/lsr/asr immediate."""
    for i in range(0, len(data) - 1, 2):
        h = struct.unpack_from('<H', data, i)[0]
        if (h >> 13) != 0:
            continue
        t = (h >> 11) & 3
        if t == 3:
            continue
        yield (i, t, (h >> 6) & 0x1F)


def selftest():
    """Assemble each fingerprint and check the detector fires on it.

    This is a test of the instrument, not a control on the result.  A control
    would be an ARM build known to contain this codec, and there is not one.
    """
    def w(x):
        return struct.pack('<I', x)

    checks = []

    # 1. the refill, in both spellings: orr rX,rX,#0xFF00 and orr rX,rY,#0xFF00
    buf = w(0xE38CCCFF) + w(0xE38B1CFF)          # orr r12,r12,#0xFF00 ; orr r1,r11,#0xFF00
    got = [(i, o) for i, o, _rd, _rn, v in arm_dp(buf) if v == 0xFF00 and o == 12]
    checks.append(('refill `orr rX,rX,#0xFF00` and `orr rX,rY,#0xFF00`', len(got), 2))

    # 2a. the mask as lsl #20 / lsr #20
    buf = w(0xE1A00A00) + w(0xE1A00A20)          # mov r0,r0,lsl #20 ; mov r0,r0,lsr #20
    sh = list(arm_shifts(buf))
    byoff = {i: (t, a) for i, t, a, _rd, _rm in sh}
    ok = sum(1 for i, t, a, _rd, _rm in sh
             if t == 0 and a == 20 and byoff.get(i + 4) == (1, 20))
    checks.append(('mask `lsl #20` then `lsr #20`', ok, 1))

    # 2b. the mask as a literal-pool 4095
    buf = w(4095)
    ok = sum(1 for i in range(0, len(buf) - 3, 4)
             if struct.unpack_from('<I', buf, i)[0] == 4095)
    checks.append(('mask as a literal-pool 4095', ok, 1))

    # 3. a 4,096-byte ring on the stack: sub sp,sp,#4096
    buf = w(0xE24DDA01)
    ok = sum(1 for i, o, _rd, rn, v in arm_dp(buf)
             if o in (2, 4) and rn == 13 and 4096 <= v <= 4400)
    checks.append(('ring on the stack, `sub sp,sp,#4096`', ok, 1))

    # 4. the nibble split: and rX,rY,#15 beside lsr #4
    buf = w(0xE200000F) + w(0xE1A01221)          # and r0,r0,#15 ; mov r1,r1,lsr #4
    and15 = [i for i, o, _rd, _rn, v in arm_dp(buf) if v == 15 and o == 0]
    lsr4 = [i for i, t, a, _rd, _rm in arm_shifts(buf) if t == 1 and a == 4]
    checks.append(('nibble split, `and #15` near `lsr #4`',
                   1 if (and15 and lsr4) else 0, 1))

    # 5. the run escape: add #3 and add #19, ARM and THUMB
    buf = w(0xE2800003) + w(0xE2800013)          # add r0,r0,#3 ; add r0,r0,#19
    add3 = [i for i, o, _rd, _rn, v in arm_dp(buf) if v == 3 and o == 4]
    add19 = [i for i, o, _rd, _rn, v in arm_dp(buf) if v == 19 and o == 4]
    checks.append(('run escape, ARM `add #3` and `add #19`',
                   len(add3) + len(add19), 2))
    buf = struct.pack('<HH', 0x3003, 0x3013)     # add r0,#3 ; add r0,#19  (THUMB)
    t3 = [i for i, o, _rd, v in thumb_imm(buf) if o == 2 and v == 3]
    t19 = [i for i, o, _rd, v in thumb_imm(buf) if o == 2 and v == 19]
    checks.append(('run escape, THUMB `add #3` and `add #19`',
                   len(t3) + len(t19), 2))

    print('struct_probe.py -- detector self-test')
    print('')
    print('Each fingerprint is hand-assembled and fed to the detector that')
    print('looks for it.  This shows the detectors work.  It does NOT show')
    print('that an ARM compiler would spell a real decoder this way, and no')
    print('ARM build containing this codec is known to exist to check against.')
    print('')
    bad = 0
    for name, got, want in checks:
        ok = got >= want
        bad += 0 if ok else 1
        print('  %-52s found %d of %d  %s' % (name, got, want, 'OK' if ok else 'FAILED'))
    print('')
    print('%d of %d detectors fire on a hand-assembled positive.'
          % (len(checks) - bad, len(checks)))
    return 1 if bad else 0


def probe_counts(data, win=200):
    """The six fingerprints as numbers, so a directory can be totalled."""
    dp = list(arm_dp(data))
    sh = list(arm_shifts(data))
    tsh = list(thumb_shifts(data))
    timm = list(thumb_imm(data))
    lit = {}
    for i in range(0, len(data) - 3, 4):
        lit.setdefault(struct.unpack_from('<I', data, i)[0], []).append(i)

    orr = [i for i, o, _rd, _rn, v in dp if v == 0xFF00 and o == 12]
    ff00 = [i for i, o, _rd, _rn, v in dp if v == 0xFF00]
    byoff = {i: (t, a) for i, t, a, _rd, _rm in sh}
    pairs = [i for i, t, a, _rd, _rm in sh
             if t == 0 and a == 20 and byoff.get(i + 4) == (1, 20)]
    tby = {i: (t, a) for i, t, a in tsh}
    tpairs = [i for i, t, a in tsh
              if t == 0 and a == 20 and tby.get(i + 2) == (1, 20)]
    lit4095 = lit.get(4095, [])
    frames = [i for i, o, _rd, rn, v in dp
              if o in (2, 4) and rn == 13 and 4096 <= v <= 4400]
    and15 = set(i for i, o, _rd, _rn, v in dp if v == 15 and o == 0)
    lsr4 = set(i for i, t, a, _rd, _rm in sh if t == 1 and a == 4)
    near = [i for i in and15 if any(abs(i - j) <= 32 for j in lsr4)]
    add3 = sorted([i for i, o, _rd, _rn, v in dp if v == 3 and o == 4]
                  + [i for i, o, _rd, v in timm if o == 2 and v == 3])
    add19 = sorted([i for i, o, _rd, _rn, v in dp if v == 19 and o == 4]
                   + [i for i, o, _rd, v in timm if o == 2 and v == 19])
    escape = [(a, b) for a in add19 for b in add3 if abs(a - b) <= win * 4]

    marks = ([('mask', i) for i in pairs + tpairs]
             + [('refill', i) for i in orr]
             + [('ring', i) for i in frames]
             + [('nibble', i) for i in near]
             + [('escape', i) for i, _ in escape])
    marks.sort(key=lambda m: m[1])
    clusters = 0
    for a in range(len(marks)):
        kinds = set()
        for b in range(a, len(marks)):
            if marks[b][1] - marks[a][1] > win * 4:
                break
            kinds.add(marks[b][0])
        if len(kinds) >= 3:
            clusters += 1
    return {
        'words': len(data) // 4, 'dp': len(dp), 'thumb': len(timm),
        'ff00': len(ff00), 'refill': len(orr),
        'mask': len(pairs) + len(tpairs), 'lit4095': len(lit4095),
        'ring': len(frames), 'nibble': len(near),
        'add3': len(add3), 'add19': len(add19), 'escape': len(escape),
        'clusters': clusters,
    }


def cmd_dir(root, win):
    import os
    names = sorted(n for n in os.listdir(root) if n.endswith('.bin'))
    print('# structural probe over %d modules in %s' % (len(names), root))
    print('#')
    print('# refill  = `orr rX,rY,#0xFF00`, either spelling (the Xbox 360')
    print('#           revision: the destination need not be the source)')
    print('# mask    = `lsl #20` then `lsr #20`, ARM or THUMB')
    print('# 4095    = a literal-pool 4095, the other form of the mask')
    print('# ring    = add/sub on sp with a 4096..4400 immediate')
    print('# nibble  = `and #15` within eight instructions of an `lsr #4`')
    print('# escape  = an `add #19` within %d instructions of an `add #3`' % win)
    print('# cluster = three or more distinct fingerprints inside %d instructions'
          % win)
    print('')
    hdr = ('%-12s %9s %8s %7s %6s %5s %5s %7s %6s %7s %8s'
           % ('module', 'words', 'ARM dp', 'refill', 'mask', '4095', 'ring',
              'nibble', 'add19', 'escape', 'clusters'))
    print(hdr)
    print('-' * len(hdr))
    tot = {}
    for n in names:
        r = probe_counts(open(os.path.join(root, n), 'rb').read(), win)
        print('%-12s %9d %8d %7d %6d %5d %5d %7d %6d %7d %8d'
              % (n[:-4], r['words'], r['dp'], r['refill'], r['mask'],
                 r['lit4095'], r['ring'], r['nibble'], r['add19'],
                 r['escape'], r['clusters']))
        for k, v in r.items():
            tot[k] = tot.get(k, 0) + v
    print('-' * len(hdr))
    print('%-12s %9d %8d %7d %6d %5d %5d %7d %6d %7d %8d'
          % ('TOTAL', tot['words'], tot['dp'], tot['refill'], tot['mask'],
             tot['lit4095'], tot['ring'], tot['nibble'], tot['add19'],
             tot['escape'], tot['clusters']))
    print('')
    print('The load-bearing columns are `refill` and `cluster`.  On the 2003')
    print('GameCube positive the same probe finds 14 refills and 4 clusters,')
    print('one cluster per decoder copy, without being told where to look.')
    print('')
    print('No ARM build carrying this codec is known, so a zero here has no')
    print('same-toolchain positive standing behind it.  `--selftest` shows the')
    print('detectors fire on hand-assembled instances of what they look for.')
    return 0


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    if '--selftest' in argv:
        return selftest()
    path = argv[1]
    if '--dir' in argv:
        w = int(argv[argv.index('--window') + 1], 0) if '--window' in argv else 200
        return cmd_dir(path, w)
    data = open(path, 'rb').read()
    base = int(argv[argv.index('--base') + 1], 0) if '--base' in argv else 0
    win = int(argv[argv.index('--window') + 1], 0) if '--window' in argv else 200

    dp = list(arm_dp(data))
    sh = list(arm_shifts(data))
    tsh = list(thumb_shifts(data))
    words = len(data) // 4
    lit = {}
    for i in range(0, len(data) - 3, 4):
        lit.setdefault(struct.unpack_from('<I', data, i)[0], []).append(i)

    print('%s' % path)
    print('  %d bytes, %d aligned words, load address 0x%08X'
          % (len(data), words, base))
    print('  %d ARM data-processing immediates, %d ARM mov-shifts, '
          '%d THUMB shifts' % (len(dp), len(sh), len(tsh)))
    print()

    def imm_sites(v):
        return [(i, o) for i, o, _rd, _rn, val in dp if val == v]

    print('  1. the control-register refill, `flags = byte | 0xFF00`')
    orr = [(i, o) for i, o, _rd, _rn, v in dp if v == 0xFF00 and o == 12]
    anyv = imm_sites(0xFF00)
    print('     %d immediates equal to 0xFF00, of which %d are `orr`'
          % (len(anyv), len(orr)))
    for i, o in orr[:20]:
        print('       0x%08X  %s' % (base + i, ARM_DP[o]))
    print()

    print('  2. the ring mask, `& 0x0FFF`')
    print('     4095 is not encodable as an ARM immediate, so it has three')
    print('     possible forms; all three are counted.')
    and4095 = [(i, o) for i, o, _rd, _rn, v in dp if v == 4095]
    print('     %d `and`-with-4095 immediates (expected 0 -- not encodable)'
          % len(and4095))
    print('     %d literal-pool words equal to 4095' % len(lit.get(4095, [])))
    pairs = []
    byoff = {i: (t, a, rd, rm) for i, t, a, rd, rm in sh}
    for i, t, a, rd, rm in sh:
        if t == 0 and a == 20 and (i + 4) in byoff:
            t2, a2, rd2, rm2 = byoff[i + 4]
            if t2 == 1 and a2 == 20:
                pairs.append(i)
    tpairs = []
    tby = {i: (t, a) for i, t, a in tsh}
    for i, t, a in tsh:
        if t == 0 and a == 20 and (i + 2) in tby and tby[i + 2] == (1, 20):
            tpairs.append(i)
    print('     %d ARM `lsl #20` immediately followed by `lsr #20`' % len(pairs))
    print('     %d THUMB `lsl #20` immediately followed by `lsr #20`'
          % len(tpairs))
    nib = [i for i, t, a in tsh
           if t == 0 and a == 28 and tby.get(i + 2) == (1, 28)]
    print('     (and %d THUMB `lsl #28`/`lsr #28` pairs, the four-bit mask)'
          % len(nib))
    for i in (pairs + tpairs)[:20]:
        print('       0x%08X' % (base + i))
    print()

    print('  3. a 4,096-byte ring')
    a4096 = imm_sites(4096)
    frames = [(i, o, v) for i, o, _rd, rn, v in dp
              if o in (2, 4) and rn == 13 and 4096 <= v <= 4400]
    print('     %d immediates equal to 4096, out of %d' % (len(a4096), len(dp)))
    print('     %d `add`/`sub` on sp with a 4096..4400 immediate '
          '(a ring on the stack)' % len(frames))
    for i, o, v in frames[:20]:
        print('       0x%08X  %s sp, #%d' % (base + i, ARM_DP[o], v))
    print()

    print('  4. the nibble split, `>> 4` next to `& 0x0F`')
    and15 = set(i for i, o, _rd, _rn, v in dp if v == 15 and o == 0)
    lsr4 = set(i for i, t, a, _rd, _rm in sh if t == 1 and a == 4)
    tlsr4 = set(i for i, t, a in tsh if t == 1 and a == 4)
    near = [i for i in and15 if any(abs(i - j) <= 32 for j in lsr4)]
    print('     %d `and #15`, %d ARM `lsr #4`, %d THUMB `lsr #4`'
          % (len(and15), len(lsr4), len(tlsr4)))
    print('     %d `and #15` within eight instructions of an ARM `lsr #4`'
          % len(near))
    print()

    print('  5. the run escape, `+3` and `+19`')
    timm = list(thumb_imm(data))
    add3 = sorted([i for i, o, _rd, _rn, v in dp if v == 3 and o == 4]
                  + [i for i, o, _rd, v in timm if o == 2 and v == 3])
    add19 = sorted([i for i, o, _rd, _rn, v in dp if v == 19 and o == 4]
                   + [i for i, o, _rd, v in timm if o == 2 and v == 19])
    print('     %d THUMB mov/cmp/add/sub #imm8 instructions as well' % len(timm))
    print('     %d `add #3`, %d `add #19`, both instruction sets'
          % (len(add3), len(add19)))
    both = [(a, b) for a in add19 for b in add3 if abs(a - b) <= win * 4]
    print('     %d pairs within %d instructions of each other' % (len(both), win))
    for a, b in both[:20]:
        print('       add #19 at 0x%08X, add #3 at 0x%08X' % (base + a, base + b))
    print()

    print('  6. all five together')
    print('     A routine implementing this format has the mask, the refill,')
    print('     the nibble split and both run constants inside a few hundred')
    print('     instructions of each other.  Sites where at least three of the')
    print('     five land within %d instructions:' % win)
    marks = ([('mask', i) for i in pairs + tpairs]
             + [('refill', i) for i, _ in orr]
             + [('nibble', i) for i in near]
             + [('+3', i) for i in add3]
             + [('+19', i) for i in add19]
             + [('ring', i) for i, _, _ in frames])
    marks.sort(key=lambda m: m[1])
    found = 0
    for k in range(len(marks)):
        grp = [m for m in marks if 0 <= m[1] - marks[k][1] <= win * 4]
        kinds = set(x[0] for x in grp)
        if len(kinds) >= 3 and '+3' in kinds and len(kinds - {'+3', '+19'}) >= 1:
            print('       0x%08X  %s' % (base + marks[k][1],
                                         ', '.join(sorted(kinds))))
            found += 1
            if found > 30:
                print('       ... (truncated)')
                break
    if not found:
        print('       none.')


if __name__ == '__main__':
    main(sys.argv)
