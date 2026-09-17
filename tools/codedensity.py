#!/usr/bin/env python3
"""Measure whether a region of a file is machine code, and how much of it is.

A constant scan reports hits out of a denominator, and the denominator is only
meaningful if the bytes it counts are code.  Section 7 of tales-blockcodec-doc
records four builds where they were not -- a compressed DS overlay, a
zero-filled Xbox 360 image, an encrypted PlayStation 3 executable, and the
hollowed `libEpic.so` of *Tales of Crestoria* -- and in every one of them the
scan returned zero and the zero meant nothing.

The check this tool runs is deliberately crude, because a crude check can be
calibrated.  Each instruction set has a handful of encodings that are single
fixed 32-bit words and appear in essentially every compiled function:

  * **AArch64**  `ret` is exactly `0xD65F03C0`.  `stp x29, x30, [sp, #imm]!`
    (the frame push) is `0xA9B?7BFD`, and `ldp x29, x30, [sp], #imm` is
    `0xA8C?7BFD`.
  * **ARM32**    `bx lr` is `0xE12FFF1E`.  `push {..., lr}` is `0xE92D4???`
    and `pop {..., pc}` is `0xE8BD8???`.
  * **THUMB**    `bx lr` is `0x4770`, `push {..., lr}` is `0xB5??`.

Counting those per megabyte gives a *rate*, and the rate is compared against a
control taken from the same package: on Android, `libunity.so` is a normally
linked library from the same build of the same application, so it says what
this compiler's code looks like at this optimisation level.  A region whose
rate is within a factor of a few of the control is code.  A region whose rate
is a hundredth of it is not, whatever its entropy says.

Entropy alone cannot do this.  Compiled ARM sits near 6 bits/byte and so does
compressed texture data; zeros sit at 0 and so does alignment padding.  A
frame-pointer push is a *structure*, and structure is what separates them.

    python codedensity.py FILE [--off N] [--size N] [--arch arm64|arm|thumb]
    python codedensity.py FILE --regions          -- one row per PT_LOAD
    python codedensity.py --compare FILE [FILE...] [--arch ...]
    python codedensity.py DIR census
    python codedensity.py --selftest

`--selftest` hand-assembles every word the counter looks for and checks that
the counter finds it, and hand-assembles near misses and checks that it does
not.  Section 7 asks for that from the first day on any new instruction set,
after two probes in this corpus returned false results on their first run.

Standard library only.
"""

import struct
import sys

MB = 1024 * 1024


def count_arm64(b):
    """Fixed AArch64 words that appear in almost every compiled function."""
    n = len(b) // 4
    ret = fpush = fpop = bl = 0
    for i in range(0, n * 4, 4):
        w = struct.unpack_from('<I', b, i)[0]
        if w == 0xD65F03C0:                       # ret
            ret += 1
        elif (w & 0xFFC00000) == 0xA9800000 and (w & 0x7FFF) == 0x7BFD:
            fpush += 1                            # stp x29,x30,[sp,#imm]!
        elif (w & 0xFFC00000) == 0xA8C00000 and (w & 0x7FFF) == 0x7BFD:
            fpop += 1                             # ldp x29,x30,[sp],#imm
        elif (w & 0xFC000000) == 0x94000000:      # bl
            bl += 1
    return dict(words=n, ret=ret, fpush=fpush, fpop=fpop, bl=bl,
                marks=ret + fpush + fpop)


def count_arm(b):
    n = len(b) // 4
    bxlr = push = pop = bl = 0
    for i in range(0, n * 4, 4):
        w = struct.unpack_from('<I', b, i)[0]
        if w == 0xE12FFF1E:                       # bx lr
            bxlr += 1
        elif (w & 0x0FFFF000) == 0x092D4000:      # push {...,lr}
            push += 1
        elif (w & 0x0FFFF000) == 0x08BD8000:      # pop {...,pc}
            pop += 1
        elif (w & 0x0F000000) == 0x0B000000:      # bl
            bl += 1
    return dict(words=n, ret=bxlr, fpush=push, fpop=pop, bl=bl,
                marks=bxlr + push + pop)


def count_thumb(b):
    n = len(b) // 2
    bxlr = push = pop = 0
    for i in range(0, n * 2, 2):
        h = struct.unpack_from('<H', b, i)[0]
        if h == 0x4770:                           # bx lr
            bxlr += 1
        elif (h & 0xFF00) == 0xB500:              # push {...,lr}
            push += 1
        elif (h & 0xFF00) == 0xBD00:              # pop {...,pc}
            pop += 1
    return dict(words=n, ret=bxlr, fpush=push, fpop=pop, bl=0,
                marks=bxlr + push + pop)


COUNTERS = dict(arm64=count_arm64, arm=count_arm, thumb=count_thumb)

# How many bits of each 32-bit word (16-bit halfword, in THUMB) the test above
# pins down.  This is the whole reason the counts are quoted with a chance rate
# beside them: `ret` on either 32-bit encoding fixes all 32 bits and turns up
# once per four gigawords by accident, but the THUMB frame push fixes only the
# high byte and turns up once every 256 halfwords in anything at all.  A raw
# count of THUMB pushes over sixty megabytes is a measurement of sixty
# megabytes, not of code.  Section 7 of tales-blockcodec-doc has the rule --
# print the chance rate beside the count -- and this is the case that needs it.
BITS = {
    'arm64': dict(ret=32, fpush=25, fpop=25, bl=6),
    'arm':   dict(ret=32, fpush=16, fpop=16, bl=4),
    'thumb': dict(ret=16, fpush=8, fpop=8, bl=99),
}
UNIT = dict(arm64=4, arm=4, thumb=2)


def expected(arch, field, nbytes):
    """How many hits this test would return on uniform random bytes."""
    pos = nbytes // UNIT[arch]
    return pos / (2.0 ** BITS[arch][field])


def report(name, b, arch):
    c = COUNTERS[arch](b)
    mb = len(b) / MB if len(b) else 1
    zero = b.count(0) / len(b) * 100 if b else 0
    er = expected(arch, 'ret', len(b))
    strong = c['ret']
    ratio = (strong / er) if er > 0 else float('inf') if strong else 0.0
    print('%-40s %10d %7.2f%% %9d %9.1f %8.1fx %9d %9d %10.1f'
          % (name[:40], len(b), zero, c['ret'], er, ratio,
             c['fpush'], c['fpop'], c['marks'] / mb))
    return c


def header():
    print('%-40s %10s %8s %9s %9s %9s %9s %9s %10s'
          % ('REGION', 'BYTES', 'ZERO%', 'RET', 'BYCHANCE', 'RATIO',
             'FRAMEPUSH', 'FRAMEPOP', 'MARKS/MB'))
    print('%-40s %10s %8s %9s %9s %9s %9s %9s %10s'
          % ('', '', '', '(strong)', '', '', '(weak)', '(weak)', ''))


def selftest():
    print('codedensity.py --selftest')
    print('  every word the counter looks for, hand-assembled, and near misses')
    print()
    ok = 0
    cases = [
        ('arm64', 0xD65F03C0, 'ret', 'ret'),
        ('arm64', 0xA9BF7BFD, 'fpush', 'stp x29,x30,[sp,#-16]!'),
        ('arm64', 0xA9B77BFD, 'fpush', 'stp x29,x30,[sp,#-144]!'),
        ('arm64', 0xA8C17BFD, 'fpop', 'ldp x29,x30,[sp],#16'),
        ('arm64', 0x94000001, 'bl', 'bl +4'),
        ('arm64', 0xA9BF7BFC, None, 'stp x28,x30 -- wrong registers'),
        ('arm64', 0xD65F03C1, None, 'ret with a stray bit'),
        ('arm', 0xE12FFF1E, 'ret', 'bx lr'),
        ('arm', 0xE92D4010, 'fpush', 'push {r4,lr}'),
        ('arm', 0xE8BD8010, 'fpop', 'pop {r4,pc}'),
        ('arm', 0xEB000001, 'bl', 'bl +4'),
        ('arm', 0xE92D0010, None, 'push {r4} -- no lr'),
        ('thumb', 0x4770, 'ret', 'bx lr'),
        ('thumb', 0xB5F0, 'fpush', 'push {r4-r7,lr}'),
        ('thumb', 0xBDF0, 'fpop', 'pop {r4-r7,pc}'),
        ('thumb', 0xB4F0, None, 'push {r4-r7} -- no lr'),
    ]
    print('  %-8s %-12s %-30s %s' % ('ARCH', 'WORD', 'MEANING', 'RESULT'))
    for arch, w, field, text in cases:
        b = struct.pack('<H' if arch == 'thumb' else '<I', w)
        c = COUNTERS[arch](b)
        if field is None:
            good = c['ret'] == c['fpush'] == c['fpop'] == c['bl'] == 0
            got = 'not counted' if good else 'COUNTED -- false positive'
        else:
            good = c[field] == 1
            got = ('counted as %s' % field if good
                   else 'MISSED -- %r' % {k: v for k, v in c.items() if v})
        ok += good
        print('  %-8s 0x%08X   %-30s %s' % (arch, w, text, got))
    print()
    print('  %d of %d cases behave as documented.' % (ok, len(cases)))
    print()
    print('  and the rate a run of zeros produces, which is the number a')
    print('  hollowed image gives:')
    for arch in ('arm64', 'arm', 'thumb'):
        c = COUNTERS[arch](b'\0' * MB)
        print('    %-8s %d marks per megabyte of zeros' % (arch, c['marks']))
    return 0 if ok == len(cases) else 1


def guess_arch(data):
    if data[:4] == b'\x7fELF':
        m = struct.unpack_from('<H', data, 18)[0]
        if m == 183:
            return 'arm64'
        if m == 40:
            return 'arm'
    return 'arm64'


def regions(path, arch):
    sys.path.insert(0, __file__.rsplit('/', 1)[0] if '/' in __file__ else '.')
    from elfinfo import Elf
    data = open(path, 'rb').read()
    e = Elf(data)
    header()
    for i, p in enumerate(e.segments):
        if p['type'] != 1 or not p['filesz']:
            continue
        fl = ''.join(c for c, bit in (('R', 4), ('W', 2), ('X', 1))
                     if p['flags'] & bit)
        b = data[p['off']:p['off'] + p['filesz']]
        report('PT_LOAD #%d %s' % (i, fl), b, arch)


def census(root):
    """Every file under a directory, its executable image, measured.

    The point of doing it over a whole `lib/` tree rather than over one file is
    that the control comes free: a package that ships one protected library
    also ships a dozen ordinary ones, built by the same toolchain for the same
    ABI, and their rate is what this build's code is supposed to look like.
    """
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from elfinfo import Elf, exec_regions
    rows = []
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            p = os.path.join(dirpath, nm)
            data = open(p, 'rb').read()
            rel = os.path.relpath(p, root).replace('\\', '/')
            if data[:4] != b'\x7fELF':
                rows.append((rel, 'not ELF', None, None))
                continue
            e = Elf(data)
            m = struct.unpack_from('<H', data, 18)[0]
            arch = {183: 'arm64', 40: 'arm'}.get(m)
            if arch is None:
                rows.append((rel, 'machine %d' % m, None, None))
                continue
            b = b''.join(data[o:o + s] for _n, o, s, _v in exec_regions(e))
            rows.append((rel, arch, b, COUNTERS[arch](b)))
            if arch == 'arm':
                # Android ARM32 is compiled mostly to THUMB, so the ARM-only
                # count understates a real library by an order of magnitude.
                # Both are run and both are printed; neither alone is the
                # denominator.
                rows.append((rel + '  [same bytes, THUMB]', 'thumb', b,
                             COUNTERS['thumb'](b)))
    print('Executable image of every native library in the package, and how')
    print('many unmistakable instructions it contains.  MARKS/MB counts `ret`,')
    print('the frame push and the frame pop together.  A library that is code')
    print('has hundreds to thousands.  A library that is not has none, and')
    print('having none is not a property entropy can see.')
    print()
    print('%-46s %-7s %12s %8s %9s %11s %10s'
          % ('FILE', 'ARCH', 'EXEC BYTES', 'ZERO%', 'RET', 'BYCHANCE',
             'MARKS/MB'))
    for rel, arch, b, c in rows:
        if c is None:
            print('%-46s %-7s %12s %8s %9s %11s %10s'
                  % (rel[:46], arch, '-', '-', '-', '-', '-'))
            continue
        er = expected(arch, 'ret', len(b))
        mb = len(b) / MB if len(b) else 1
        print('%-46s %-7s %12d %7.2f%% %9d %11.4f %10.1f'
              % (rel[:46], arch, len(b), b.count(0) / len(b) * 100 if b else 0,
                 c['ret'], er, c['marks'] / mb))
    print()
    print('RET is quoted because it is the strong mark: on both 32-bit')
    print('encodings it fixes all thirty-two bits, so BYCHANCE is what the')
    print('same test returns on random bytes of the same length.  The frame')
    print('push and pop are printed by the per-region view but not here,')
    print('because their masks are narrower and on a large enough region they')
    print('measure the region rather than the code in it.')


def main(argv):
    if '--selftest' in argv:
        raise SystemExit(selftest())
    if len(argv) >= 3 and argv[2] == 'census':
        return census(argv[1])
    if len(argv) < 2:
        raise SystemExit(__doc__)
    arch = argv[argv.index('--arch') + 1] if '--arch' in argv else None
    if '--compare' in argv:
        paths = [a for a in argv[argv.index('--compare') + 1:]
                 if not a.startswith('--')]
        header()
        for p in paths:
            data = open(p, 'rb').read()
            a = arch or guess_arch(data)
            report('%s [%s]' % (p.rsplit('/', 1)[-1], a), data, a)
        return
    path = argv[1]
    data = open(path, 'rb').read()
    arch = arch or guess_arch(data)
    print('%s, %s' % (path, arch))
    print()
    if '--regions' in argv:
        regions(path, arch)
        return
    off = int(argv[argv.index('--off') + 1], 0) if '--off' in argv else 0
    size = int(argv[argv.index('--size') + 1], 0) if '--size' in argv else len(data) - off
    header()
    report('%s+%d' % (path.rsplit('/', 1)[-1], off), data[off:off + size], arch)


if __name__ == '__main__':
    main(sys.argv)
