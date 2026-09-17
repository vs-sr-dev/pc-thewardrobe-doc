#!/usr/bin/env python3
"""dosdis.py -- a strict 16-bit 8086 disassembler that STOPS on an opcode it
does not know, so that a listing it produces is a listing and not a guess.

WHY STRICT IS THE WHOLE POINT
------------------------------
A permissive disassembler prints `db 0x8F` and carries on, and the reader has
no way to tell a correct listing from one that lost the instruction boundary
three bytes ago and has been printing plausible nonsense ever since. On a hand
-written DOS unpacker stub -- 588 bytes with no symbols, no relocations inside
it, and data interleaved with code -- that failure is silent and total.

So this refuses. Every opcode is either in the table below, decoded, and
printed; or it is not in the table, and the run ends with the offset, the
byte, and how far it got. **A listing that reaches the end of its range is a
listing every byte of which was decoded by a table entry**, and `--coverage`
prints that as a fraction so the claim is a number.

The table covers the 8086/80186 subset this collection's DOS objects have
actually needed. It is deliberately NOT complete: adding an opcode is a line,
and an opcode nobody has met should not be in a table nobody has tested.

WHAT IT DOES NOT DO, PER P19
-----------------------------
It does not follow jumps, does not separate code from data, and does not know
where a basic block ends. Handed a range that contains a jump table it will
decode the table as instructions and report success, because every byte of a
jump table is a valid opcode somewhere. **The check against that is the
reader's, not this tool's**, and the way to make it is `--annotate`: control
transfers are marked, and a listing whose jumps all land on decoded
instruction boundaries is one whose boundaries are probably right. `--targets`
prints exactly that -- every branch target in range, and whether it fell on an
instruction start or into the middle of one.

    python tools/dosdis.py iggdt/START.EXE --at 96 --length 64 --org 0x100
    python tools/dosdis.py iggdt/START.EXE --at 164 --length 588 --targets
    python tools/dosdis.py --selftest
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

R16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
R8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']
SREG = ['es', 'cs', 'ss', 'ds']
RM = ['bx+si', 'bx+di', 'bp+si', 'bp+di', 'si', 'di', 'bp', 'bx']
ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
SHIFT = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar']
CC = ['o', 'no', 'b', 'nb', 'z', 'nz', 'be', 'nbe',
      's', 'ns', 'p', 'np', 'l', 'nl', 'le', 'nle']
GRP1 = ['test', '?', 'not', 'neg', 'mul', 'imul', 'div', 'idiv']
GRP2 = ['inc', 'dec', 'call', 'callf', 'jmp', 'jmpf', 'push', '?']

BRANCH = {'jmp', 'call', 'loop', 'loope', 'loopne', 'jcxz'}


class DisError(Exception):
    """An opcode this disassembler will not pretend to know."""


def imm(blob, pos, size):
    if pos + size > len(blob):
        raise DisError('immediate runs off the end at %d' % pos)
    value = blob[pos] if size == 1 else blob[pos] | (blob[pos + 1] << 8)
    return value, pos + size


def sign8(value):
    return value - 256 if value & 0x80 else value


def hexed(value):
    """Assembler convention: a literal whose first digit is A-F gets a 0."""
    digits = '%X' % value
    return ('0' + digits + 'h') if digits[0].isalpha() else (digits + 'h')


def modrm(blob, pos, wide):
    """Return (mod-r/m text, register field, new position)."""
    if pos >= len(blob):
        raise DisError('modrm runs off the end at %d' % pos)
    byte = blob[pos]
    pos += 1
    mod, reg, rm = byte >> 6, (byte >> 3) & 7, byte & 7
    names = R16 if wide else R8
    if mod == 3:
        return names[rm], reg, pos
    if mod == 0 and rm == 6:
        disp, pos = imm(blob, pos, 2)
        return '[%s]' % hexed(disp), reg, pos
    text = RM[rm]
    if mod == 1:
        disp, pos = imm(blob, pos, 1)
        disp = sign8(disp)
        text += ('%+d' % disp) if disp else ''
    elif mod == 2:
        disp, pos = imm(blob, pos, 2)
        text += '+%s' % hexed(disp)
    return '[%s]' % text, reg, pos


def one(blob, pos, org):
    """Decode one instruction. Returns (text, length, target-or-None)."""
    start = pos
    op = blob[pos]
    pos += 1
    target = None

    # 00..3F: the eight ALU operations, six forms each
    if op < 0x40 and (op & 7) < 6:
        name = ALU[op >> 3]
        form = op & 7
        wide = form & 1
        if form in (0, 1, 2, 3):
            text, reg, pos = modrm(blob, pos, wide)
            other = (R16 if wide else R8)[reg]
            args = ('%s, %s' % (text, other)) if form < 2 \
                else ('%s, %s' % (other, text))
        else:
            value, pos = imm(blob, pos, 2 if wide else 1)
            args = '%s, %s' % ('ax' if wide else 'al', hexed(value))
        return '%-6s %s' % (name, args), pos - start, None

    if op in (0x06, 0x0E, 0x16, 0x1E):
        return '%-6s %s' % ('push', SREG[op >> 3]), pos - start, None
    if op in (0x07, 0x17, 0x1F):
        return '%-6s %s' % ('pop', SREG[op >> 3]), pos - start, None
    if op in (0x26, 0x2E, 0x36, 0x3E):
        return '%s:' % SREG[(op >> 3) & 3], pos - start, None
    if 0x40 <= op <= 0x47:
        return '%-6s %s' % ('inc', R16[op & 7]), pos - start, None
    if 0x48 <= op <= 0x4F:
        return '%-6s %s' % ('dec', R16[op & 7]), pos - start, None
    if 0x50 <= op <= 0x57:
        return '%-6s %s' % ('push', R16[op & 7]), pos - start, None
    if 0x58 <= op <= 0x5F:
        return '%-6s %s' % ('pop', R16[op & 7]), pos - start, None
    # 80186 additions, met on pc-teenagent-doc's unpacked engine (entry
    # `pusha` at 0000:000C): pusha/popa, push imm, imul r,r/m,imm,
    # enter/leave. Each is a line; each has a selftest.
    if op == 0x60:
        return 'pusha', pos - start, None
    if op == 0x61:
        return 'popa', pos - start, None
    if op in (0x68, 0x6A):
        value, pos = imm(blob, pos, 2 if op == 0x68 else 1)
        if op == 0x6A:
            value = sign8(value) & 0xFFFF
        return '%-6s %s' % ('push', hexed(value)), pos - start, None
    if op in (0x69, 0x6B):
        text, reg, pos = modrm(blob, pos, True)
        value, pos = imm(blob, pos, 2 if op == 0x69 else 1)
        if op == 0x6B:
            value = sign8(value) & 0xFFFF
        return '%-6s %s, %s, %s' % ('imul', R16[reg], text, hexed(value)), \
            pos - start, None
    if 0x6C <= op <= 0x6F:
        return ('insb', 'insw', 'outsb', 'outsw')[op - 0x6C], pos - start, None
    if op == 0xC8:
        size, pos = imm(blob, pos, 2)
        level, pos = imm(blob, pos, 1)
        return '%-6s %s, %s' % ('enter', hexed(size), hexed(level)), \
            pos - start, None
    if op == 0xC9:
        return 'leave', pos - start, None
    if 0x70 <= op <= 0x7F:
        rel, pos = imm(blob, pos, 1)
        target = (org + (pos - start) + sign8(rel)) & 0xFFFF
        return '%-6s %s' % ('j' + CC[op & 15], hexed(target)), pos - start, target
    if op in (0x80, 0x81, 0x83):
        text, reg, pos = modrm(blob, pos, op != 0x80)
        value, pos = imm(blob, pos, 2 if op == 0x81 else 1)
        if op == 0x83:
            value = sign8(value) & 0xFFFF
        return '%-6s %s, %s' % (ALU[reg], text, hexed(value)), pos - start, None
    if op in (0x84, 0x85):
        text, reg, pos = modrm(blob, pos, op & 1)
        return '%-6s %s, %s' % ('test', text, (R16 if op & 1 else R8)[reg]), \
            pos - start, None
    if op in (0x86, 0x87):
        text, reg, pos = modrm(blob, pos, op & 1)
        return '%-6s %s, %s' % ('xchg', text, (R16 if op & 1 else R8)[reg]), \
            pos - start, None
    if 0x88 <= op <= 0x8B:
        wide = op & 1
        text, reg, pos = modrm(blob, pos, wide)
        other = (R16 if wide else R8)[reg]
        args = ('%s, %s' % (text, other)) if op < 0x8A \
            else ('%s, %s' % (other, text))
        return '%-6s %s' % ('mov', args), pos - start, None
    if op in (0x8C, 0x8E):
        text, reg, pos = modrm(blob, pos, True)
        args = ('%s, %s' % (text, SREG[reg & 3])) if op == 0x8C \
            else ('%s, %s' % (SREG[reg & 3], text))
        return '%-6s %s' % ('mov', args), pos - start, None
    if op == 0x8D:
        text, reg, pos = modrm(blob, pos, True)
        return '%-6s %s, %s' % ('lea', R16[reg], text), pos - start, None
    if op == 0x8F:
        text, _reg, pos = modrm(blob, pos, True)
        return '%-6s %s' % ('pop', text), pos - start, None
    if op == 0x90:
        return 'nop', pos - start, None
    if 0x91 <= op <= 0x97:
        return '%-6s ax, %s' % ('xchg', R16[op & 7]), pos - start, None
    if op == 0x98:
        return 'cbw', pos - start, None
    if op == 0x99:
        return 'cwd', pos - start, None
    if op == 0x9A:
        off, pos = imm(blob, pos, 2)
        seg, pos = imm(blob, pos, 2)
        return '%-6s %s:%s' % ('callf', hexed(seg), hexed(off)), pos - start, None
    if op == 0x9C:
        return 'pushf', pos - start, None
    if op == 0x9D:
        return 'popf', pos - start, None
    if op == 0x9E:
        return 'sahf', pos - start, None
    if op == 0x9F:
        return 'lahf', pos - start, None
    if 0xA0 <= op <= 0xA3:
        off, pos = imm(blob, pos, 2)
        reg = 'ax' if op & 1 else 'al'
        args = ('%s, [%s]' % (reg, hexed(off))) if op < 0xA2 \
            else ('[%s], %s' % (hexed(off), reg))
        return '%-6s %s' % ('mov', args), pos - start, None
    if op in (0xA4, 0xA5):
        return 'movs%s' % ('w' if op & 1 else 'b'), pos - start, None
    if op in (0xA6, 0xA7):
        return 'cmps%s' % ('w' if op & 1 else 'b'), pos - start, None
    if op in (0xA8, 0xA9):
        value, pos = imm(blob, pos, 2 if op & 1 else 1)
        return '%-6s %s, %s' % ('test', 'ax' if op & 1 else 'al',
                                hexed(value)), pos - start, None
    if op in (0xAA, 0xAB):
        return 'stos%s' % ('w' if op & 1 else 'b'), pos - start, None
    if op in (0xAC, 0xAD):
        return 'lods%s' % ('w' if op & 1 else 'b'), pos - start, None
    if op in (0xAE, 0xAF):
        return 'scas%s' % ('w' if op & 1 else 'b'), pos - start, None
    if 0xB0 <= op <= 0xB7:
        value, pos = imm(blob, pos, 1)
        return '%-6s %s, %s' % ('mov', R8[op & 7], hexed(value)), pos - start, None
    if 0xB8 <= op <= 0xBF:
        value, pos = imm(blob, pos, 2)
        return '%-6s %s, %s' % ('mov', R16[op & 7], hexed(value)), pos - start, None
    if op in (0xC0, 0xC1, 0xC2, 0xCA):
        if op in (0xC2, 0xCA):
            value, pos = imm(blob, pos, 2)
            return '%-6s %s' % ('retf' if op == 0xCA else 'ret',
                                hexed(value)), pos - start, None
        text, reg, pos = modrm(blob, pos, op & 1)
        value, pos = imm(blob, pos, 1)
        return '%-6s %s, %s' % (SHIFT[reg], text, hexed(value)), pos - start, None
    if op == 0xC3:
        return 'ret', pos - start, None
    if op == 0xCB:
        return 'retf', pos - start, None
    if op in (0xC4, 0xC5):
        text, reg, pos = modrm(blob, pos, True)
        return '%-6s %s, %s' % ('les' if op == 0xC4 else 'lds',
                                R16[reg], text), pos - start, None
    if op in (0xC6, 0xC7):
        wide = op & 1
        text, _reg, pos = modrm(blob, pos, wide)
        value, pos = imm(blob, pos, 2 if wide else 1)
        return '%-6s %s, %s' % ('mov', text, hexed(value)), pos - start, None
    if op == 0xCD:
        value, pos = imm(blob, pos, 1)
        return '%-6s %s' % ('int', hexed(value)), pos - start, None
    if op == 0xCC:
        return 'int3', pos - start, None
    if op == 0xCF:
        return 'iret', pos - start, None
    if 0xD0 <= op <= 0xD3:
        text, reg, pos = modrm(blob, pos, op & 1)
        count = '1' if op < 0xD2 else 'cl'
        return '%-6s %s, %s' % (SHIFT[reg], text, count), pos - start, None
    if op == 0xD7:
        return 'xlat', pos - start, None
    if 0xE0 <= op <= 0xE3:
        rel, pos = imm(blob, pos, 1)
        target = (org + (pos - start) + sign8(rel)) & 0xFFFF
        name = ['loopne', 'loope', 'loop', 'jcxz'][op & 3]
        return '%-6s %s' % (name, hexed(target)), pos - start, target
    if op in (0xE4, 0xE5, 0xE6, 0xE7):
        value, pos = imm(blob, pos, 1)
        reg = 'ax' if op & 1 else 'al'
        args = ('%s, %s' % (reg, hexed(value))) if op < 0xE6 \
            else ('%s, %s' % (hexed(value), reg))
        return '%-6s %s' % ('in' if op < 0xE6 else 'out', args), pos - start, None
    if op == 0xE8:
        rel, pos = imm(blob, pos, 2)
        rel = rel - 0x10000 if rel & 0x8000 else rel
        target = (org + (pos - start) + rel) & 0xFFFF
        return '%-6s %s' % ('call', hexed(target)), pos - start, target
    if op == 0xE9:
        rel, pos = imm(blob, pos, 2)
        rel = rel - 0x10000 if rel & 0x8000 else rel
        target = (org + (pos - start) + rel) & 0xFFFF
        return '%-6s %s' % ('jmp', hexed(target)), pos - start, target
    if op == 0xEA:
        off, pos = imm(blob, pos, 2)
        seg, pos = imm(blob, pos, 2)
        return '%-6s %s:%s' % ('jmpf', hexed(seg), hexed(off)), pos - start, None
    if op == 0xEB:
        rel, pos = imm(blob, pos, 1)
        target = (org + (pos - start) + sign8(rel)) & 0xFFFF
        return '%-6s %s' % ('jmp', hexed(target)), pos - start, target
    if op in (0xEC, 0xED, 0xEE, 0xEF):
        reg = 'ax' if op & 1 else 'al'
        args = ('%s, dx' % reg) if op < 0xEE else ('dx, %s' % reg)
        return '%-6s %s' % ('in' if op < 0xEE else 'out', args), pos - start, None
    if op == 0xF2:
        return 'repne', pos - start, None
    if op == 0xF3:
        return 'rep', pos - start, None
    if op == 0xF4:
        return 'hlt', pos - start, None
    if op == 0xF5:
        return 'cmc', pos - start, None
    if op in (0xF6, 0xF7):
        wide = op & 1
        text, reg, pos = modrm(blob, pos, wide)
        if reg == 0:
            value, pos = imm(blob, pos, 2 if wide else 1)
            return '%-6s %s, %s' % ('test', text, hexed(value)), pos - start, None
        if reg == 1:
            raise DisError('group 3 /1 is not an instruction')
        return '%-6s %s' % (GRP1[reg], text), pos - start, None
    if op == 0xF8:
        return 'clc', pos - start, None
    if op == 0xF9:
        return 'stc', pos - start, None
    if op == 0xFA:
        return 'cli', pos - start, None
    if op == 0xFB:
        return 'sti', pos - start, None
    if op == 0xFC:
        return 'cld', pos - start, None
    if op == 0xFD:
        return 'std', pos - start, None
    if op in (0xFE, 0xFF):
        text, reg, pos = modrm(blob, pos, op & 1)
        if op == 0xFE and reg > 1:
            raise DisError('group 4 /%d is not an instruction' % reg)
        if GRP2[reg] == '?':
            raise DisError('group 5 /7 is not an instruction')
        return '%-6s %s' % (GRP2[reg], text), pos - start, None

    raise DisError('opcode 0x%02X at offset %d is not in this table'
                   % (op, start))


def walk(blob, org):
    """Decode from the start to the end, or until an unknown opcode."""
    out = []
    pos = 0
    while pos < len(blob):
        try:
            text, size, target = one(blob, pos, org + pos)
        except DisError as exc:
            return out, pos, str(exc)
        out.append((org + pos, blob[pos:pos + size], text, target))
        pos += size
    return out, pos, None


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    def text(hexbytes, org=0):
        rows, _pos, err = walk(bytes.fromhex(hexbytes), org)
        if err:
            return 'ERROR: ' + err
        return '; '.join(r[2].strip() for r in rows)

    want('a register move', text('8bc2'), 'mov    ax, dx')
    want('an immediate move', text('b84d58'), 'mov    ax, 584Dh')
    want('a byte immediate move', text('b204'), 'mov    dl, 4h')
    want('a segment move', text('8ec5'), 'mov    es, bp')
    want('a segment store', text('8ccd'), 'mov    bp, cs')
    want('a memory compare', text('3b060200'), 'cmp    ax, [2h]')
    want('an add with a word immediate', text('050000'), 'add    ax, 0h')
    want('a sign-extended add', text('83c339'), 'add    bx, 39h')
    want('a shift by cl', text('d3e6'), 'shl    si, cl')
    want('a shift by one', text('d1e9'), 'shr    cx, 1')
    want('pusha / popa (80186)', text('6061'), 'pusha; popa')
    want('push imm16 (80186)', text('683412'), 'push   1234h')
    want('push imm8 sign-extended (80186)', text('6aff'), 'push   0FFFFh')
    want('imul r16, r/m16, imm8 (80186)', text('6bc00a'), 'imul   ax, ax, 0Ah')
    want('enter / leave (80186)', text('c8040000c9'), 'enter  4h, 0h; leave')
    want('insb insw outsb outsw (80186)', text('6c6d6e6f'),
         'insb; insw; outsb; outsw')
    want('and with a byte immediate', text('80e40f'), 'and    ah, 0Fh')
    want('a literal starting A-F takes a leading zero', hexed(0xA96), '0A96h')
    want('a literal starting 0-9 does not', hexed(0x584D), '584Dh')
    want('inc of a byte register', text('fec6'), 'inc    dh')
    want('the string primitives', text('fca5adaaacab'),
         'cld; movsw; lodsw; stosb; lodsb; stosw')
    want('a rep prefix is its own line', text('f3a5'), 'rep; movsw')
    want('a far return', text('cb'), 'retf')
    want('an interrupt', text('cd21'), 'int    21h')
    want('a push and a pop', text('5307'), 'push   bx; pop    es')
    want('an xchg with ax', text('95'), 'xchg   ax, bp')
    want('a subtract of registers', text('2be8'), 'sub    bp, ax')
    want('a xor of registers', text('32c2'), 'xor    al, dl')

    # Branch targets are relative to the END of the instruction.
    want('a short jump forward', text('eb3a', 0x44), 'jmp    80h')
    rows, _p, _e = walk(bytes.fromhex('75ed'), 0x33)
    want('a conditional jump backward', rows[0][2].strip(), 'jnz    22h')
    want('the branch target is reported', rows[0][3], 0x22)
    rows, _p, _e = walk(bytes.fromhex('e90001'), 0x100)
    want('a near jump', rows[0][2].strip(), 'jmp    203h')

    # The bug this pair was written to catch: a branch target computed from
    # the walk's origin rather than from the branch's own address. Both of
    # these decode correctly when the branch is the FIRST instruction, so a
    # selftest that only ever put one instruction in the blob passed while
    # `jnb` off the object's entry stub was pointing seven bytes past its
    # real target. Every branch below is preceded by padding on purpose.
    rows, _p, _e = walk(bytes.fromhex('9090909075ed'), 0x30)
    want('a conditional branch at a non-zero offset',
         rows[-1][2].strip(), 'jnz    23h')
    want('and its reported target agrees', rows[-1][3], 0x23)
    rows, _p, _e = walk(bytes.fromhex('90eb3a'), 0x44)
    want('a short jump at a non-zero offset', rows[-1][2].strip(), 'jmp    81h')
    rows, _p, _e = walk(bytes.fromhex('90e90001'), 0x100)
    want('a near jump at a non-zero offset', rows[-1][2].strip(), 'jmp    204h')
    # The object's own case, worked by hand: 73 1A at 010D is two bytes long,
    # so the next address is 010F and the target is 010F + 1A = 0129.
    rows, _p, _e = walk(bytes.fromhex('b84d58ba960a0500003b060200731a'), 0x100)
    want('the object entry stub branch lands at 129h',
         rows[-1][2].strip(), 'jnb    129h')

    # And the refusal, which is the reason this tool exists.
    rows, pos, err = walk(bytes.fromhex('90900f'), 0)
    want('an unknown opcode stops the walk', pos, 2)
    want('two instructions survive it', len(rows), 2)
    want('and the refusal names the byte', '0x0F' in (err or ''), True)
    want('a truncated immediate stops the walk', walk(b'\xb8\x4d', 0)[1], 0)

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
    ap.add_argument('--at', type=lambda s: int(s, 0), default=0,
                    help='file offset to start at')
    ap.add_argument('--length', type=lambda s: int(s, 0), default=64)
    ap.add_argument('--org', type=lambda s: int(s, 0), default=0,
                    help='the address the first byte has when it runs')
    ap.add_argument('--targets', action='store_true',
                    help='report every branch target and whether it landed '
                         'on an instruction boundary')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())
    if not args.file:
        ap.error('give a file, or --selftest')
    dirguard.want_file(args.file, 'dosdis')
    with open(args.file, 'rb') as handle:
        handle.seek(args.at)
        blob = handle.read(args.length)
    if len(blob) < args.length:
        print('note: wanted %d bytes at %d, the file gave %d'
              % (args.length, args.at, len(blob)))

    rows, reached, err = walk(blob, args.org)
    for addr, raw, text, _target in rows:
        print('  %04X  %-14s %s' % (addr, raw.hex(' '), text))
    print('')
    print('bytes in range        : %d' % len(blob))
    print('bytes decoded         : %d' % reached)
    print('instructions          : %d' % len(rows))
    print('coverage              : %.4f %%'
          % (100.0 * reached / len(blob) if blob else 0.0))
    if err:
        print('STOPPED               : %s' % err)
    else:
        print('STOPPED               : no -- every byte in range decoded')

    if args.targets:
        starts = {addr for addr, _r, _t, _g in rows}
        lo, hi = args.org, args.org + reached
        inside = [(addr, target) for addr, _r, _t, target in rows
                  if target is not None and lo <= target < hi]
        clean = [t for _a, t in inside if t in starts]
        print('')
        print('branch targets in range   : %d' % len(inside))
        print('landing on a boundary     : %d of %d'
              % (len(clean), len(inside)))
        for addr, target in inside:
            if target not in starts:
                print('    %04X -> %04X   LANDS MID-INSTRUCTION'
                      % (addr, target))
    if err:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
