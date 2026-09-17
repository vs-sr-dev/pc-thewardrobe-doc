#!/usr/bin/env python3
"""Find the block codec's ring constants in an executable, on four CPUs.

Section 7 of tales-blockcodec-doc gives the shortcut: scan for the immediates
4078 and 4079 (and, since 2004, 4080; and, since the tenth build, 4070 and
4071, which are the bound of a ring clear unrolled by eight).  They are the
packer's constants, not the programmer's, and nothing else in a game has a
reason to load 4,078.  It works in the negative too: an executable with no
4078 anywhere does not contain the decoder.

The shortcut was written for MIPS and extended to PowerPC.  Both are
fixed-width machines with a 16-bit immediate field, so "scan the words" is a
complete search.  **On ARM it is not**, and that is the reason this file
exists:

  * An ARM data-processing immediate is an 8-bit value rotated right by an
    even amount.  **4078 (0xFEE) and 4079 (0xFEF) cannot be encoded at all**
    -- they need nine significant bits.  A compiler emits them as 32-bit words
    in the literal pool, loaded with `ldr rX, [pc, #off]`.
  * **4080 (0xFF0) can** be encoded: 0xFF ror 28.  So the three constants of
    the corpus behave in two different ways on this machine, which is itself a
    datum about what a hit means.
  * 4070 (0xFE6) and 4071 (0xFE7) cannot be encoded either.
  * In THUMB, `mov rd, #imm8` reaches 255 and no further, so every one of
    these constants is a literal-pool word there too.

**On the SPU it is two scans as well, and for a different reason.** The
PlayStation 3 is the first machine in this corpus with two instruction sets in
one executable: a PowerPC PPU, which `--ppc` already handles, and six SPUs
whose ISA is not PowerPC at all.  A decompressor is precisely the kind of work
a PS3 port moves onto an SPU, so a `--ppc` scan that returns zero has covered
one of the two processors.

The SPU is a 32-bit fixed-width machine, so "scan the words" is the right
shape -- but its immediate fields do not all reach:

  * **RI10** -- `ai`, `ahi`, `sfi`, `andi`, `ori`, `xori`, `ceqi`, `cgti`,
    `clgti` -- carries a **signed 10-bit** field, so it reaches -512..511.
    **None of the five constants can be encoded in it.**  A scan that looks
    only there finds nothing on a machine that might well contain them, which
    is the ARM trap in a new key.
  * **RI16** -- `il` (signed 16), `iohl` (unsigned 16) -- reaches all five.
    `ilh` splats its 16 bits into every halfword and `ilhu` into the upper
    half of every word, so a hit there is the constant shifted, not the
    constant; both are decoded and reported with that said.
  * **RI18** -- `ila` -- carries eighteen bits and reaches all five.
  * and **`lqd` / `stqd`** carry a signed 10-bit field **scaled by sixteen**,
    so they reach 4080 and cannot reach 4078, 4079, 4070 or 4071.  That is
    not a curiosity: 4080 is 4078 rounded up to a multiple of sixteen, which
    is exactly the shape the 2004 PlayStation 2 build produced when a
    quadword store was wanted, and the SPU has nothing but quadword stores.

So `--spu` runs an immediate pass over the forms that can hold the value, a
scaled pass over the quadword displacements, and a data pass over every
aligned word of the module -- because a constant the compiler could not
encode reaches an SPU as a word in the module's own local-store image.  All
three denominators are printed.

So the ARM scan is two scans, and both are run and both denominators are
printed:

  1. **immediate fields** -- every ARM data-processing instruction with I=1,
     and every THUMB instruction carrying a literal, decoded and compared;
  2. **literal-pool words** -- every 4-byte-aligned u32 equal to a wanted
     constant, then cross-referenced against every PC-relative load in the
     image to say whether any instruction actually points at it.

A raw word match is weak on its own: a specific 32-bit value turns up by
chance about once per 4 GB of uniform random data, but code is not uniform and
small integers are common.  The cross-reference is what makes a hit mean
something, and the denominator is printed either way, because "zero hits" is
worth nothing without "out of how many words".

    python ring_sites.py FILE --arm64 [--base VA --off FILEOFF --size N]
    python ring_sites.py FILE --arm  [--base VA] [--imm 4078,4079,4080]
    python ring_sites.py FILE --mips [--base VA --off FILEOFF]
    python ring_sites.py FILE --ppc  [--base VA --off FILEOFF]
    python ring_sites.py FILE --spu  [--base VA --off FILEOFF --size N]
    python ring_sites.py --selftest [--arm64]

Standard library only.
"""

import struct
import sys

# ---------------------------------------------------------------- MIPS / PPC

MIPS_IMM = {
    4: 'beq', 5: 'bne', 6: 'blez', 7: 'bgtz', 8: 'addi', 9: 'addiu',
    10: 'slti', 11: 'sltiu', 12: 'andi', 13: 'ori', 14: 'xori',
    15: 'lui', 24: 'daddi', 25: 'daddiu',
}
MIPS_SKIP = {4, 5, 6, 7, 15}

PPC_IMM = {
    7: 'mulli', 8: 'subfic', 10: 'cmplwi', 11: 'cmpwi', 12: 'addic',
    13: 'addic.', 14: 'addi', 15: 'addis', 24: 'ori', 25: 'oris',
    28: 'andi.', 29: 'andis.',
}
PPC_SKIP = {15, 25, 29}


def scan_fixed(data, arch, base, off, size, wanted):
    fmt = '<I' if arch == 'mips' else '>I'
    hits = []
    for i in range(0, size - 3, 4):
        w = struct.unpack_from(fmt, data, off + i)[0]
        imm = w & 0xFFFF
        if imm not in wanted:
            continue
        op = w >> 26
        if arch == 'mips':
            if op not in MIPS_IMM or op in MIPS_SKIP:
                continue
            name = MIPS_IMM[op]
        else:
            if op not in PPC_IMM or op in PPC_SKIP:
                continue
            name = PPC_IMM[op]
        hits.append((base + i, w, name, imm))
    return hits


def fixed_routine_start(data, arch, base, off, va, limit=8192):
    """Walk back to the first instruction after the previous return.

    Section 7 of tales-blockcodec-doc says to disassemble from the *top* of the
    routine rather than around the hit, because on Tales of the Abyss the hit
    was 135 words in.  This is the MIPS/PowerPC half of that, carried over from
    the GameCube build of this tool; the ARM half is `arm_routine_start`.
    """
    fmt = '<I' if arch == 'mips' else '>I'
    ret = 0x03E00008 if arch == 'mips' else 0x4E800020   # jr ra / blr
    a = va
    for _ in range(limit // 4):
        a -= 4
        if a < base:
            return None
        w = struct.unpack_from(fmt, data, off + a - base)[0]
        if w == ret:
            return a + (8 if arch == 'mips' else 4)
    return None


# ---------------------------------------------------------------------- SPU
#
# All formats are 32 bits, big-endian.  The opcode is the top of the word and
# its width is what names the format:
#
#   RI10  bits  0-7  opcode, 8-17  I10 (signed),  18-24 RA, 25-31 RT
#   RI16  bits  0-8  opcode, 9-24  I16,                      25-31 RT
#   RI18  bits  0-6  opcode, 7-24  I18,                      25-31 RT

SPU_RI10 = {
    0x04: 'ori', 0x05: 'orhi', 0x0C: 'sfi', 0x0D: 'sfhi',
    0x14: 'andi', 0x15: 'andhi', 0x1C: 'ai', 0x1D: 'ahi',
    0x44: 'xori', 0x45: 'xorhi', 0x4C: 'cgti', 0x4D: 'cgthi',
    0x5C: 'clgti', 0x5D: 'clgthi', 0x74: 'mpyi', 0x75: 'mpyui',
    0x7C: 'ceqi', 0x7D: 'ceqhi',
}
SPU_RI10_MEM = {0x34: 'lqd', 0x24: 'stqd'}
SPU_RI16 = {0x081: 'il', 0x082: 'ilhu', 0x083: 'ilh', 0x0C1: 'iohl'}
SPU_RI18 = {0x21: 'ila'}

SPU_RETURN = 0x35000000        # bi $lr   -- $lr is $0 on this machine


def _sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def spu_decode(w):
    """Return (form, mnemonic, value, text) or None.

    `value` is the constant the instruction actually puts in a register, so
    `ilhu` reports imm << 16 and `lqd`/`stqd` report the displacement times
    sixteen.  Reporting the encoded field instead would make a scan for 4080
    miss `stqd $r, 4080($sp)` and report `stqd $r, 255($sp)` as a hit for 255.
    """
    op9 = w >> 23
    if op9 in SPU_RI16:
        imm = (w >> 7) & 0xFFFF
        rt = w & 0x7F
        name = SPU_RI16[op9]
        if name == 'il':
            val = _sx(imm, 16) & 0xFFFFFFFF
        elif name == 'ilhu':
            val = (imm << 16) & 0xFFFFFFFF
        else:
            val = imm
        return ('RI16', name, val, '%s $%d,%d' % (name, rt, imm))
    op7 = w >> 25
    if op7 in SPU_RI18:
        imm = (w >> 7) & 0x3FFFF
        rt = w & 0x7F
        return ('RI18', 'ila', imm, 'ila $%d,%d' % (rt, imm))
    op8 = w >> 24
    if op8 in SPU_RI10:
        imm = _sx((w >> 14) & 0x3FF, 10)
        ra = (w >> 7) & 0x7F
        rt = w & 0x7F
        name = SPU_RI10[op8]
        return ('RI10', name, imm & 0xFFFFFFFF,
                '%s $%d,$%d,%d' % (name, rt, ra, imm))
    if op8 in SPU_RI10_MEM:
        disp = _sx((w >> 14) & 0x3FF, 10) * 16
        ra = (w >> 7) & 0x7F
        rt = w & 0x7F
        name = SPU_RI10_MEM[op8]
        return ('RI10x16', name, disp & 0xFFFFFFFF,
                '%s $%d,%d($%d)' % (name, rt, disp, ra))
    return None


def spu_scan(data, off, size, base, wanted):
    """Three passes; every denominator is returned whether or not it hits."""
    imm_hits, mem_hits = [], []
    n_ri10 = n_ri16 = n_ri18 = n_mem = 0
    for i in range(0, size - 3, 4):
        w = struct.unpack_from('>I', data, off + i)[0]
        d = spu_decode(w)
        if d is None:
            continue
        form, name, val, text = d
        if form == 'RI10':
            n_ri10 += 1
        elif form == 'RI16':
            n_ri16 += 1
        elif form == 'RI18':
            n_ri18 += 1
        else:
            n_mem += 1
        if val in wanted:
            (mem_hits if form == 'RI10x16' else imm_hits).append(
                (base + i, w, text, val, form))
    word_hits = []
    n_words = 0
    for i in range(0, size - 3, 4):
        n_words += 1
        w = struct.unpack_from('>I', data, off + i)[0]
        if w in wanted:
            word_hits.append((base + i, w))
    return (imm_hits, mem_hits, word_hits,
            dict(ri10=n_ri10, ri16=n_ri16, ri18=n_ri18, mem=n_mem,
                 words=n_words))


def spu_routine_start(data, off, size, base, va, limit=8192):
    a = va
    for _ in range(limit // 4):
        a -= 4
        if a < base:
            return None
        w = struct.unpack_from('>I', data, off + a - base)[0]
        if w == SPU_RETURN:
            return a + 4
    return None


def spu_encodable(value):
    """Which SPU forms can hold `value` at all.  This is the honest half."""
    out = []
    if -32768 <= value <= 32767:
        out.append('il (RI16, signed 16)')
    if 0 <= value <= 0xFFFF:
        out.append('iohl (RI16, unsigned 16)')
    if 0 <= value < (1 << 18):
        out.append('ila (RI18, 18 bits)')
    if -512 <= value <= 511:
        out.append('RI10 (ai/ori/andi/ceqi..., signed 10)')
    if value % 16 == 0 and -8192 <= value <= 8176:
        out.append('lqd/stqd displacement (signed 10, scaled by 16)')
    return out



# ------------------------------------------------------------------ AArch64

def a64_logical_imm(value, width=64):
    """Is `value` expressible as an AArch64 logical bitmask immediate?

    The encoding can only produce a run of ones, rotated, repeated at some
    power-of-two element size.  Rather than invert it, enumerate it.
    """
    if value in (0, (1 << width) - 1):
        return None
    for esize in (2, 4, 8, 16, 32, 64):
        if esize > width:
            break
        mask = (1 << esize) - 1
        e = value & mask
        v, ok = value, True
        for _ in range(width // esize):
            if v & mask != e:
                ok = False
                break
            v >>= esize
        if not ok:
            continue
        for ones in range(1, esize):
            base = (1 << ones) - 1
            for rot in range(esize):
                cand = ((base >> rot) | (base << (esize - rot))) & mask
                if cand == e:
                    return (esize, ones, rot)
    return None


def a64_encodable(value):
    """Which AArch64 forms can carry `value` as an immediate.

    This is the third ARM machine in the corpus and the first 64-bit one, and
    it inverts the rule the two Nintendo DS builds established.  On ARM32 a
    data-processing immediate is an 8-bit value rotated by an even amount, so
    4078 and 4079 -- the two constants this document calls the packer's --
    cannot be encoded at all and reach the image only as literal-pool words.
    AArch64 is not ARM32:

      * movz/movk/movn carry a 16-bit immediate with a 16-bit-aligned shift,
        so all five constants fit in a single movz with no shift;
      * add/sub/cmp (immediate) carry 12 bits, optionally shifted by 12, so
        all five fit there too -- 4080 is 0xFF0 and 4078 is 0xFEE, both inside
        0..4095;
      * the logical immediates (and/orr/eor) use the bitmask encoding, which
        can only express a rotated repeating run of ones.  4078, 4079, 4070
        and 4071 cannot be written that way; 4095 can, twelve ones, so the ring
        mask `and xN, xM, #0xFFF` is a plain immediate here where on ARM32 it
        had to be a literal or a shift pair.

    So on this machine the immediate pass is the strong one and finds all five,
    which is the opposite of the ARM32 situation.  The literal-pool pass is
    still run, because a compiler is free to materialise a constant either way.
    Both denominators are printed, as section 7 requires.
    """
    forms = []
    if 0 <= value <= 0xFFFF:
        forms.append('movz/movk (16-bit immediate, no shift)')
    if 0 <= value <= 0xFFF:
        forms.append('add/sub/cmp immediate (12-bit)')
    if a64_logical_imm(value) is not None:
        forms.append('and/orr/eor bitmask immediate')
    return forms


A64_MOV = {0: 'movn', 2: 'movz', 3: 'movk'}


def a64_immediates(data, base, wanted):
    """Every AArch64 instruction whose immediate operand is in `wanted`.

    Two families are decoded and reported apart, because they mean different
    things.  A movz of 4078 is a constant being materialised, which is what a
    ring cursor looks like.  An add/sub/cmp of 4078 is an arithmetic use of it,
    which is what a loop bound looks like.
    """
    mov_hits, alu_hits = [], []
    n_mov = n_alu = 0
    for i in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, i)[0]
        if (w & 0x1F800000) == 0x12800000:
            opc = (w >> 29) & 3
            if opc == 1:
                continue
            n_mov += 1
            hw = (w >> 21) & 3
            imm = (w >> 5) & 0xFFFF
            rd = w & 0x1F
            sf = (w >> 31) & 1
            val = imm << (hw * 16)
            if opc == 0:
                val = (~val) & (0xFFFFFFFFFFFFFFFF if sf else 0xFFFFFFFF)
            if val in wanted:
                mov_hits.append((base + i, w,
                                 '%s %s%d, #%d%s'
                                 % (A64_MOV[opc], 'x' if sf else 'w', rd, imm,
                                    ', lsl #%d' % (hw * 16) if hw else ''),
                                 val))
        elif (w & 0x1F000000) == 0x11000000:
            n_alu += 1
            sh = (w >> 22) & 1
            imm = (w >> 10) & 0xFFF
            val = imm << 12 if sh else imm
            if val in wanted:
                op = 'sub' if (w >> 30) & 1 else 'add'
                if (w >> 29) & 1:
                    op += 's'
                rd, rn = w & 0x1F, (w >> 5) & 0x1F
                r = 'x' if (w >> 31) & 1 else 'w'
                # register 31 is the zero register when the flags are set and
                # the stack pointer when they are not; naming it w31 would be
                # wrong in both readings.
                zr = (r + 'zr') if (w >> 29) & 1 else 'sp'
                nd = zr if rd == 31 else '%s%d' % (r, rd)
                nn = ('sp' if rn == 31 else '%s%d' % (r, rn))
                alu_hits.append((base + i, w,
                                 '%s %s, %s, #%d' % (op, nd, nn, val), val))
    return mov_hits, alu_hits, n_mov, n_alu


def a64_literal_targets(data, base):
    """Every ldr-literal and adr, and the address it points at.

    A literal-pool word matters only if something reads it: a word some
    instruction points at is a constant, a word nothing points at is data.
    """
    targets = {}
    n_ldr = n_adr = 0
    for i in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, i)[0]
        if (w & 0x3B000000) == 0x18000000:
            imm19 = (w >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            targets.setdefault(base + i + imm19 * 4, []).append(('ldr', base + i))
            n_ldr += 1
        elif (w & 0x9F000000) == 0x10000000:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            targets.setdefault(base + i + imm, []).append(('adr', base + i))
            n_adr += 1
    return targets, n_ldr, n_adr


def a64_routine_start(data, base, va, limit=8192):
    """Walk back to the nearest ret and call the word after it the entry.

    Section 7 says to disassemble from the top of the routine, not around the
    hit, because on Tales of the Abyss the hit was 135 words in.  AArch64 makes
    that cheap: ret is exactly 0xD65F03C0 and nothing else is.
    """
    a = va
    for _ in range(limit // 4):
        a -= 4
        if a < base or a - base + 4 > len(data):
            return None
        if struct.unpack_from('<I', data, a - base)[0] == 0xD65F03C0:
            return a + 4
    return None


def a64_selftest():
    """Hand-assemble every AArch64 form the scan looks for and decode it back.

    Section 7 asks for this from the first day on a new instruction set.  The
    SPU scan got one after two probes in this corpus returned false results on
    their first run; this is the second scan in the corpus to have one before
    it has any output.
    """
    cases = [
        (0x5281FDC0, 'movz w0, #4078', 4078),
        (0x5281FDE1, 'movz w1, #4079', 4079),
        (0x5281FE02, 'movz w2, #4080', 4080),
        (0x5281FCC3, 'movz w3, #4070', 4070),
        (0x5281FCE4, 'movz w4, #4071', 4071),
        (0x929FDE20, 'movn x0, #4079 -- a negated form, not our constant', None),
        (0xD2A00020, 'movz x0, #1, lsl #16', 0x10000),
        (0x113FB800, 'add w0, w0, #4078', 4078),
        (0x513FB821, 'sub w1, w1, #4078', 4078),
        (0x713FBC1F, 'subs wzr, w0, #4079 (cmp)', 4079),
        (0xD65F03C0, 'ret -- must not decode as an immediate', None),
        (0xF9400000, 'ldr x0,[x0] -- must not decode', None),
    ]
    ok = 0
    print('ring_sites.py --selftest --arm64')
    print('  every AArch64 form the scan looks for, hand-assembled, decoded back')
    print()
    print('  %-12s %-36s %10s  %s' % ('WORD', 'EXPECTED', 'VALUE', 'RESULT'))
    for w, text, val in cases:
        blob = struct.pack('<I', w)
        wanted = (val,) if val is not None else (4078, 4079, 4080)
        mov, alu, _nm, _na = a64_immediates(blob, 0, wanted)
        hits = mov + alu
        if val is None:
            good = not hits
            got = 'not decoded' if good else 'DECODED -- false positive'
        else:
            good = len(hits) == 1 and hits[0][3] == val
            got = hits[0][2] if hits else 'MISSED'
        ok += good
        print('  0x%08X   %-36s %10s  %s'
              % (w, text, val if val is not None else '-', got))
    print()
    print('  %d of %d forms behave as documented.' % (ok, len(cases)))
    print()
    print('  and which AArch64 forms can hold each constant at all -- the row')
    print('  that separates this machine from the two Nintendo DS builds:')
    for c in (4070, 4071, 4078, 4079, 4080, 4095, 4096):
        forms = a64_encodable(c)
        print('    %5d (0x%03X)  %s'
              % (c, c, '; '.join(forms) if forms else 'nothing'))
    print()
    print('  On ARM32, 4078 and 4079 are NOT encodable and reach an image only')
    print('  as literal-pool words.  Here every one of the five fits a single')
    print('  movz.  A single-pass immediate scan is a complete search on this')
    print('  machine and was not on the last one, and that difference is the')
    print('  reason this mode had to be written rather than reused.')
    return 0 if ok == len(cases) else 1


def a64_scan(data, off, size, base, wanted):
    body = data[off:off + size]
    mov_hits, alu_hits, n_mov, n_alu = a64_immediates(body, base, wanted)
    targets, n_ldr, n_adr = a64_literal_targets(body, base)
    lit_hits = []
    n_words = 0
    for i in range(0, len(body) - 3, 4):
        n_words += 1
        w = struct.unpack_from('<I', body, i)[0]
        if w in wanted:
            lit_hits.append((base + i, w, targets.get(base + i, [])))
    return (mov_hits, alu_hits, lit_hits,
            dict(mov=n_mov, alu=n_alu, ldr=n_ldr, adr=n_adr, words=n_words,
                 targets=len(targets)),
            body)


# ---------------------------------------------------------------------- ARM

ARM_DP = ['and', 'eor', 'sub', 'rsb', 'add', 'adc', 'sbc', 'rsc',
          'tst', 'teq', 'cmp', 'cmn', 'orr', 'mov', 'bic', 'mvn']
COND = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
        'hi', 'ls', 'ge', 'lt', 'gt', 'le', '', 'nv']


def ror32(v, n):
    n &= 31
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def arm_encodable(value):
    """Return (imm8, rot) if `value` fits an ARM data-processing immediate."""
    for rot in range(0, 32, 2):
        cand = ror32(value, 32 - rot) if rot else value
        # value == ror(imm8, rot)  <=>  imm8 == rol(value, rot)
        imm8 = ((value << rot) | (value >> (32 - rot))) & 0xFFFFFFFF if rot else value
        if imm8 <= 0xFF:
            return imm8, rot
    return None


def arm_immediates(data, base, wanted):
    """Every ARM data-processing instruction whose immediate is in `wanted`."""
    hits = []
    total = 0
    for i in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, i)[0]
        if (w >> 28) == 0xF:                    # unconditional space
            continue
        if (w >> 26) & 3 or not (w >> 25) & 1:  # not a DP-immediate
            continue
        opc = (w >> 21) & 0xF
        s = (w >> 20) & 1
        if 8 <= opc <= 11 and not s:            # MSR / undefined
            continue
        total += 1
        rot = (w >> 8) & 0xF
        imm8 = w & 0xFF
        val = ror32(imm8, rot * 2)
        if val in wanted:
            rd, rn = (w >> 12) & 0xF, (w >> 16) & 0xF
            hits.append((base + i, w,
                         '%s%s r%d,r%d,#%d' % (ARM_DP[opc], COND[w >> 28], rd, rn, val),
                         val))
    return hits, total


def thumb_immediates(data, base, wanted):
    """Every THUMB instruction carrying a literal, decoded.

    `mov/cmp/add/sub rd,#imm8` reaches 255; `add/sub rd,rn,#imm3` reaches 7;
    `add sp,#imm7*4` reaches 508; the shifted forms carry a shift count, not a
    value.  None of them can hold a four-digit constant, which is the point.
    """
    hits = []
    total = 0
    for i in range(0, len(data) - 1, 2):
        h = struct.unpack_from('<H', data, i)[0]
        val = None
        if (h >> 13) == 0b001:                       # mov/cmp/add/sub imm8
            val = h & 0xFF
        elif (h >> 10) == 0b0001111 or (h >> 10) == 0b0001110:
            val = (h >> 6) & 7                       # add/sub imm3
        elif (h >> 8) == 0b10110000:                 # add/sub sp, #imm7*4
            val = (h & 0x7F) * 4
        if val is None:
            continue
        total += 1
        if val in wanted:
            hits.append((base + i, h, 'thumb #%d' % val, val))
    return hits, total


def pc_relative_targets(data, base):
    """Map every PC-relative load in the image to the address it reads.

    Both encodings, because a NitroSDK build is a mixture of the two:
      ARM    ldr rd,[pc,#+/-imm12]   target = (addr + 8) +/- imm12
      THUMB  ldr rd,[pc,#imm8*4]     target = ((addr + 4) & ~3) + imm8*4
    """
    targets = {}
    n_arm = n_thumb = 0
    for i in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, i)[0]
        if (w >> 28) == 0xF:
            continue
        if (w >> 26) & 3 != 1:
            continue
        if (w >> 25) & 1:                 # register offset
            continue
        if not (w >> 24) & 1:             # post-indexed
            continue
        if (w >> 22) & 1:                 # byte
            continue
        if not (w >> 20) & 1:             # store
            continue
        if (w >> 16) & 0xF != 15:         # not PC-relative
            continue
        imm = w & 0xFFF
        t = base + i + 8 + (imm if (w >> 23) & 1 else -imm)
        targets.setdefault(t, []).append(('arm', base + i))
        n_arm += 1
    for i in range(0, len(data) - 1, 2):
        h = struct.unpack_from('<H', data, i)[0]
        if (h >> 11) != 0b01001:
            continue
        t = (((base + i + 4) & ~3) + (h & 0xFF) * 4)
        targets.setdefault(t, []).append(('thumb', base + i))
        n_thumb += 1
    return targets, n_arm, n_thumb


def literal_words(data, base, wanted, targets):
    hits = []
    total = 0
    for i in range(0, len(data) - 3, 4):
        total += 1
        w = struct.unpack_from('<I', data, i)[0]
        if w in wanted:
            hits.append((base + i, w, targets.get(base + i, [])))
    return hits, total


def arm_routine_start(data, base, va, limit=8192):
    """Walk back to something that looks like a function entry.

    `stmfd sp!, {...,lr}` is the ARM prologue an SDK build emits; `push {..,lr}`
    is the THUMB one.  Neither is guaranteed, so this is a hint, not a claim.
    """
    a = va
    for _ in range(limit // 4):
        a -= 4
        if a < base:
            return None
        w = struct.unpack_from('<I', data, a - base)[0]
        if (w & 0x0FFF0000) == 0x092D0000 and (w & 0x4000):    # stmfd sp!,{..lr}
            return a
    return None


def selftest():
    """Hand-assemble every SPU form the scan looks for and check it decodes.

    The fifteenth build added `--selftest` to the ARM structural probe and the
    sixteenth to the PowerPC one, both after a probe returned a false negative
    on a true positive.  This is the first instruction set in the corpus whose
    scan has one from the first day, which is what section 7 asks for.
    """
    cases = [
        (0x4087F700, 'il', 4078, 'il $0,4078'),
        (0x4087F781, 'il', 4079, 'il $1,4079'),
        (0x4207F702, 'ila', 4078, 'ila $2,4078'),
        (0x4187F703, 'ilh', 4078, 'ilh $3,4078'),
        (0x4107F704, 'ilhu', 4078 << 16, 'ilhu $4,4078'),
        (0x6087F705, 'iohl', 4078, 'iohl $5,4078'),
        (0x4087F800, 'il', 4080, 'il $0,4080'),
        (0x243FC1A1, 'stqd', 4080, 'stqd $33,4080($3)'),
        (0x343FC1A1, 'lqd', 4080, 'lqd $33,4080($3)'),
        (0x1C000806, 'ai', 0, 'ai $6,$16,0'),
    ]
    ok = 0
    print('ring_sites.py --selftest, SPU')
    print('  every form the scan looks for, hand-assembled and decoded back')
    print()
    print('  %-12s %-10s %14s  %s' % ('WORD', 'FORM', 'VALUE', 'DECODED'))
    for w, mnem, val, text in cases:
        d = spu_decode(w)
        good = d is not None and d[1] == mnem and d[2] == val
        ok += good
        print('  0x%08X   %-10s %14s  %-24s %s'
              % (w, mnem, val, d[3] if d else '(not decoded)',
                 'ok' if good else 'FAILED -- got %r' % (d,)))
    print()
    print('  %d of %d decoders return the value the encoding carries.'
          % (ok, len(cases)))
    print()
    print('  and which forms can hold each constant at all:')
    for c in (4070, 4071, 4078, 4079, 4080):
        forms = spu_encodable(c)
        print('    %5d  %s' % (c, ', '.join(forms) if forms else 'nothing'))
    print()
    print('  Note the row that matters: 4080 is the only one of the five a')
    print('  quadword displacement can hold, because it is the only multiple')
    print('  of sixteen -- and on this machine every store is a quadword.')
    return 0 if ok == len(cases) else 1


def main(argv):
    if '--selftest' in argv:
        if '--arm64' in argv:
            raise SystemExit(a64_selftest())
        raise SystemExit(selftest())
    if len(argv) < 3:
        raise SystemExit(__doc__)
    path = argv[1]
    arch = ('arm64' if '--arm64' in argv else 'arm' if '--arm' in argv
            else 'mips' if '--mips' in argv
            else 'ppc' if '--ppc' in argv
            else 'spu' if '--spu' in argv else None)
    if arch is None:
        raise SystemExit('say --arm64, --arm, --mips, --ppc or --spu')
    data = open(path, 'rb').read()
    base = int(argv[argv.index('--base') + 1], 0) if '--base' in argv else 0
    off = int(argv[argv.index('--off') + 1], 0) if '--off' in argv else 0
    size = len(data) - off
    if '--size' in argv:
        size = int(argv[argv.index('--size') + 1], 0)
    wanted = (4078, 4079)
    if '--imm' in argv:
        wanted = tuple(int(x, 0) for x in argv[argv.index('--imm') + 1].split(','))

    if arch == 'arm64':
        mov_hits, alu_hits, lit_hits, den, body = a64_scan(
            data, off, size, base, wanted)
        print('%s' % path)
        print('  %d bytes scanned from offset %d, load address 0x%08X, AArch64'
              % (len(body), off, base))
        print('  looking for %s' % ', '.join(str(x) for x in wanted))
        print()
        print('  which AArch64 forms can hold each constant at all:')
        for c in wanted:
            forms = a64_encodable(c)
            print('    %5d (0x%03X)  %s'
                  % (c, c, '; '.join(forms) if forms else 'nothing'))
        print()
        print('  This is the opposite of ARM32, where 4078 and 4079 cannot be')
        print('  encoded as immediates at all.  Here pass 1 is a complete')
        print('  search on its own; pass 2 is run anyway, because a compiler')
        print('  may still choose the literal pool for a 64-bit value.')
        print()
        print('  pass 1a -- move-wide immediates (movz/movk/movn)')
        print('    %8d move-wide instructions scanned' % den['mov'])
        print('    %8d hits' % len(mov_hits))
        for va, w, text, val in mov_hits[:200]:
            st = a64_routine_start(body, base, va)
            print('      0x%08X  0x%08X  %-32s  %s'
                  % (va, w, text,
                     ('routine 0x%08X (+%d words)' % (st, (va - st) // 4))
                     if st else '?'))
        if len(mov_hits) > 200:
            print('      ... %d more' % (len(mov_hits) - 200))
        print()
        print('  pass 1b -- add/sub/cmp immediates (12-bit)')
        print('    %8d add/sub immediate instructions scanned' % den['alu'])
        print('    %8d hits' % len(alu_hits))
        for va, w, text, val in alu_hits[:200]:
            st = a64_routine_start(body, base, va)
            print('      0x%08X  0x%08X  %-32s  %s'
                  % (va, w, text,
                     ('routine 0x%08X (+%d words)' % (st, (va - st) // 4))
                     if st else '?'))
        if len(alu_hits) > 200:
            print('      ... %d more' % (len(alu_hits) - 200))
        print()
        print('  pass 2 -- 32-bit words in the literal pool')
        print('    %8d aligned words scanned' % den['words'])
        print('    %8d ldr-literal + %d adr, %d distinct targets'
              % (den['ldr'], den['adr'], den['targets']))
        print('    %8d hits' % len(lit_hits))
        for va, w, refs in lit_hits[:200]:
            r = (', '.join('%s @0x%08X' % (k, a) for k, a in refs[:4])
                 if refs else 'NOT the target of any ldr-literal or adr here')
            print('      0x%08X  = %d  <- %s' % (va, w, r))
        if len(lit_hits) > 200:
            print('      ... %d more' % (len(lit_hits) - 200))
        print()
        if not (mov_hits or alu_hits or lit_hits):
            print('  no %s anywhere in this image, in any encoding.'
                  % ' or '.join(str(x) for x in wanted))
            print('  On AArch64 every one of the five constants fits a single')
            print('  movz, so pass 1 alone is a complete search and this is a')
            print('  strong negative -- PROVIDED the bytes scanned are code.')
            print('  Check that separately with codedensity.py: a scan over an')
            print('  encrypted or zero-filled image returns this same zero.')
        return

    if arch == 'spu':
        imm_hits, mem_hits, word_hits, den = spu_scan(
            data, off, size, base, wanted)
        print('%s' % path)
        print('  %d bytes scanned from offset %d, load address 0x%08X, SPU'
              % (size, off, base))
        print('  looking for %s' % ', '.join(str(x) for x in wanted))
        print()
        print('  which SPU forms can hold each constant at all:')
        for c in wanted:
            forms = spu_encodable(c)
            print('    %5d  %s' % (c, ', '.join(forms) if forms else 'nothing'))
        print()
        print('  pass 1 -- immediate fields that can hold the value')
        print('    %8d RI16 instructions (il, ilh, ilhu, iohl)' % den['ri16'])
        print('    %8d RI18 instructions (ila)' % den['ri18'])
        print('    %8d RI10 instructions -- signed 10 bits, so none of the '
              'five fits' % den['ri10'])
        print('    %8d hits' % len(imm_hits))
        for va, w, text, val, form in imm_hits:
            st = spu_routine_start(data, off, size, base, va)
            print('      0x%08X  0x%08X  %-26s = %d  %s'
                  % (va, w, text, val,
                     ('routine 0x%08X (+%d words)' % (st, (va - st) // 4))
                     if st else '?'))
        print()
        print('  pass 2 -- quadword displacements, scaled by sixteen')
        print('    %8d lqd/stqd instructions' % den['mem'])
        print('    %8d hits' % len(mem_hits))
        for va, w, text, val, form in mem_hits:
            st = spu_routine_start(data, off, size, base, va)
            print('      0x%08X  0x%08X  %-26s = %d  %s'
                  % (va, w, text, val,
                     ('routine 0x%08X (+%d words)' % (st, (va - st) // 4))
                     if st else '?'))
        print()
        print('  pass 3 -- 32-bit words in the local-store image')
        print('    %8d aligned words scanned' % den['words'])
        print('    %8d hits' % len(word_hits))
        for va, w in word_hits:
            print('      0x%08X  = %d' % (va, w))
        print()
        if not (imm_hits or mem_hits or word_hits):
            print('  no %s anywhere in this module, in any encoding.'
                  % ' or '.join(str(x) for x in wanted))
        return

    if arch != 'arm':
        hits = scan_fixed(data, arch, base, off, size, wanted)
        print('%s, %s, %d words scanned, looking for %s'
              % (path, arch, size // 4, '/'.join(str(x) for x in wanted)))
        if not hits:
            print('\nno %s immediate anywhere in this image.'
                  % ' or '.join(str(x) for x in wanted))
            return
        print('\n%-12s %-10s %-8s %6s  %s'
              % ('ADDRESS', 'WORD', 'FORM', 'IMM', 'ROUTINE'))
        for va, w, name, imm in hits:
            st = fixed_routine_start(data, arch, base, off, va)
            print('0x%08X   0x%08X %-8s %6d  %s'
                  % (va, w, name, imm,
                     ('0x%08X (+%d words)' % (st, (va - st) // 4))
                     if st else '?'))
        print('\n%d sites' % len(hits))
        return

    body = data[off:off + size]
    print('%s' % path)
    print('  %d bytes, load address 0x%08X, ARM/THUMB' % (len(body), base))
    print('  looking for %s' % ', '.join(str(x) for x in wanted))
    print()
    print('  encodability as an ARM data-processing immediate '
          '(8 bits rotated by an even amount):')
    for c in wanted:
        e = arm_encodable(c)
        if e:
            print('    %5d (0x%03X)  YES  0x%02X ror #%d'
                  % (c, c, e[0], e[1]))
        else:
            print('    %5d (0x%03X)  NO   -- must be a literal-pool word'
                  % (c, c))
    print()

    imm_hits, imm_total = arm_immediates(body, base, wanted)
    th_hits, th_total = thumb_immediates(body, base, wanted)
    targets, n_arm_ldr, n_thumb_ldr = pc_relative_targets(body, base)
    lit_hits, lit_total = literal_words(body, base, wanted, targets)

    print('  pass 1 -- immediate fields')
    print('    %8d ARM data-processing instructions with an immediate operand'
          % imm_total)
    print('    %8d THUMB instructions carrying a literal' % th_total)
    print('    %8d hits' % (len(imm_hits) + len(th_hits)))
    for va, w, name, val in imm_hits + th_hits:
        s = arm_routine_start(body, base, va)
        print('      0x%08X  0x%08X  %-28s  %s'
              % (va, w, name,
                 ('prologue 0x%08X (+%d words)' % (s, (va - s) // 4)) if s else '?'))
    print()
    print('  pass 2 -- 32-bit words in the literal pool')
    print('    %8d aligned words scanned' % lit_total)
    print('    %8d ARM + %d THUMB PC-relative loads, %d distinct targets'
          % (n_arm_ldr, n_thumb_ldr, len(targets)))
    print('    %8d hits' % len(lit_hits))
    for va, w, refs in lit_hits:
        if refs:
            r = ', '.join('%s ldr @0x%08X' % (k, a) for k, a in refs[:4])
        else:
            r = 'NOT the target of any PC-relative load in this image'
        print('      0x%08X  = %d  <- %s' % (va, w, r))
    print()
    if not (imm_hits or th_hits or lit_hits):
        print('  no %s anywhere in this image, in either encoding.'
              % ' or '.join(str(x) for x in wanted))
        print('  By section 7 of the codec specification that is evidence the')
        print('  decoder is not present, not merely that it was not found --')
        print('  and on ARM the literal-pool pass is the half that matters,')
        print('  because the two cursors cannot be encoded as immediates.')


if __name__ == '__main__':
    main(sys.argv)
