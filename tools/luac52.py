#!/usr/bin/env python3
"""luac52.py -- read and disassemble Lua 5.2 precompiled chunks.

The claim this tool makes about its own format, stated plainly
---------------------------------------------------------------

Lua 5.2's bytecode is **published as source and not as a specification**.
`lundump.c` writes it and reads it back; `lopcodes.h` gives the instruction
layout and the opcode order.  That is a weaker claim than a published
specification -- there is no document that says what the format *is*, only a
program that agrees with itself -- and it is written down here rather than
quietly upgraded to "published".

What makes the reading checkable anyway is arithmetic: a chunk that is read
correctly **consumes the file exactly**.  Every count in the format is
explicit, nothing is padded, and the last byte of the last debug string is the
last byte of the file.  That is the closure this tool reports, and it is the
only positive control the format offers.

The header, 18 bytes, verified on 392 of 392 files in this object
------------------------------------------------------------------

    1b 4c 75 61   "\\x1bLua"
    52            version 5.2
    00            official format
    01            endianness: 1 = little
    04            sizeof(int)
    04            sizeof(size_t)
    04            sizeof(Instruction)
    04            sizeof(lua_Number)     <- FOUR, so lua_Number is a float
    00            lua_Number is not integral
    19 93 0d 0a 1a 0a   LUAC_TAIL, the "did anything mangle this" tail

A function, recursively
------------------------

    i32 linedefined, i32 lastlinedefined
    u8 numparams, u8 is_vararg, u8 maxstacksize
    i32 sizecode,      then that many u32 instructions
    i32 sizek,         then that many constants (u8 tag, then the value)
    i32 sizep,         then that many nested functions
    i32 sizeupvalues,  then that many (u8 instack, u8 idx)
    string source
    i32 sizelineinfo,  then that many i32
    i32 sizelocvars,   then that many (string name, i32 startpc, i32 endpc)
    i32 sizeupvalues,  then that many strings

A string is a size_t length that **includes the terminating NUL**, and a
length of zero means no string at all.  Getting that off by one desynchronises
the rest of the chunk, and the closure catches it.

The instruction word, from lopcodes.h
--------------------------------------

    31          23          14      6         0
    |    B(9)   |    C(9)   | A(8)  |  OP(6)  |     iABC
    |         Bx(18)        | A(8)  |  OP(6)  |     iABx / iAsBx (sBx-131071)
    |              Ax(26)           |  OP(6)  |     iAx

RK(x): when the ninth bit is set the operand is constant number x & 0xff,
otherwise it is register x.  A global read is `GETTABUP A B C` with B naming
the `_ENV` upvalue, so the constant behind C is the global's name -- which is
how `globals` recovers the game's own API without a symbol table.

    python luac52.py selftest
    python luac52.py validate DIR|FILE...   -- the 18-byte header
    python luac52.py close    DIR|FILE...   -- does the parse consume the file
    python luac52.py dump     FILE [--proto N.N] [--limit N]
    python luac52.py census   DIR
    python luac52.py globals  DIR [--limit N]
    python luac52.py strings  FILE [--limit N]

Standard library only.
"""

import argparse
import collections
import os
import struct
import sys

HEADER = bytes([0x1b, 0x4c, 0x75, 0x61, 0x52, 0x00, 0x01,
                0x04, 0x04, 0x04, 0x04, 0x00,
                0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a])

OPNAMES = [
    'MOVE', 'LOADK', 'LOADKX', 'LOADBOOL', 'LOADNIL', 'GETUPVAL',
    'GETTABUP', 'GETTABLE', 'SETTABUP', 'SETUPVAL', 'SETTABLE', 'NEWTABLE',
    'SELF', 'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW', 'UNM', 'NOT', 'LEN',
    'CONCAT', 'JMP', 'EQ', 'LT', 'LE', 'TEST', 'TESTSET', 'CALL', 'TAILCALL',
    'RETURN', 'FORLOOP', 'FORPREP', 'TFORCALL', 'TFORLOOP', 'SETLIST',
    'CLOSURE', 'VARARG', 'EXTRAARG',
]
# iABC = 0, iABx = 1, iAsBx = 2, iAx = 3
OPMODE = {
    'LOADK': 1, 'LOADKX': 1, 'GETGLOBAL': 1, 'SETGLOBAL': 1, 'CLOSURE': 1,
    'JMP': 2, 'FORLOOP': 2, 'FORPREP': 2, 'TFORLOOP': 2,
    'EXTRAARG': 3,
}
# which operands are RK-encoded, per opcode
RK_B = {'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW', 'EQ', 'LT', 'LE',
        'CONCAT', 'SETTABLE', 'SETTABUP'}
RK_C = {'GETTABLE', 'GETTABUP', 'SETTABLE', 'SETTABUP', 'SELF', 'ADD', 'SUB',
        'MUL', 'DIV', 'MOD', 'POW', 'EQ', 'LT', 'LE'}

LUA_TNIL, LUA_TBOOLEAN, LUA_TNUMBER, LUA_TSTRING = 0, 1, 3, 4


class Refused(Exception):
    """A refusal with a reason.  Never an exit code of 0."""


class Reader(object):
    def __init__(self, d, p=0):
        self.d = d
        self.p = p

    def need(self, n):
        if self.p + n > len(self.d):
            raise Refused('wanted %d bytes at %d of %d'
                          % (n, self.p, len(self.d)))

    def u8(self):
        self.need(1)
        v = self.d[self.p]
        self.p += 1
        return v

    def i32(self):
        self.need(4)
        v, = struct.unpack_from('<i', self.d, self.p)
        self.p += 4
        return v

    def u32(self):
        self.need(4)
        v, = struct.unpack_from('<I', self.d, self.p)
        self.p += 4
        return v

    def f32(self):
        self.need(4)
        v, = struct.unpack_from('<f', self.d, self.p)
        self.p += 4
        return v

    def string(self):
        """size_t length INCLUDING the NUL; zero means no string."""
        n = self.u32()
        if n == 0:
            return None
        if n > 1 << 24:
            raise Refused('string of %d bytes at %d is not credible'
                          % (n, self.p))
        self.need(n)
        s = self.d[self.p:self.p + n - 1]
        term = self.d[self.p + n - 1]
        self.p += n
        if term != 0:
            raise Refused('string of %d at %d does not end in NUL'
                          % (n, self.p - n))
        return s.decode('utf-8', 'replace')


class Proto(object):
    def __init__(self, r, path, depth=0, index=()):
        if depth > 200:
            raise Refused('nested functions more than 200 deep')
        self.path = path
        self.index = index
        self.line_defined = r.i32()
        self.last_line_defined = r.i32()
        self.num_params = r.u8()
        self.is_vararg = r.u8()
        self.max_stack = r.u8()
        n = r.i32()
        if not 0 <= n <= 1 << 22:
            raise Refused('sizecode %d is not credible' % n)
        self.code = [r.u32() for _ in range(n)]
        n = r.i32()
        if not 0 <= n <= 1 << 20:
            raise Refused('sizek %d is not credible' % n)
        self.k = []
        for _ in range(n):
            t = r.u8()
            if t == LUA_TNIL:
                self.k.append(None)
            elif t == LUA_TBOOLEAN:
                self.k.append(bool(r.u8()))
            elif t == LUA_TNUMBER:
                self.k.append(r.f32())
            elif t == LUA_TSTRING:
                self.k.append(r.string())
            else:
                raise Refused('constant type %d at %d is not one of the four'
                              % (t, r.p - 1))
        n = r.i32()
        if not 0 <= n <= 1 << 18:
            raise Refused('sizep %d is not credible' % n)
        self.protos = [Proto(r, path, depth + 1, index + (i,))
                       for i in range(n)]
        n = r.i32()
        if not 0 <= n <= 1 << 16:
            raise Refused('sizeupvalues %d is not credible' % n)
        self.upvalues = [(r.u8(), r.u8()) for _ in range(n)]
        self.source = r.string()
        n = r.i32()
        if not 0 <= n <= 1 << 22:
            raise Refused('sizelineinfo %d is not credible' % n)
        self.lineinfo = [r.i32() for _ in range(n)]
        n = r.i32()
        if not 0 <= n <= 1 << 20:
            raise Refused('sizelocvars %d is not credible' % n)
        self.locvars = [(r.string(), r.i32(), r.i32()) for _ in range(n)]
        n = r.i32()
        if not 0 <= n <= 1 << 16:
            raise Refused('upvalue name count %d is not credible' % n)
        self.upvalue_names = [r.string() for _ in range(n)]

    def walk(self):
        yield self
        for p in self.protos:
            for q in p.walk():
                yield q


class Chunk(object):
    def __init__(self, data, path='<memory>'):
        self.path = path
        self.data = data
        if len(data) < 18:
            raise Refused('%d bytes is shorter than a Lua header' % len(data))
        if data[:4] != b'\x1bLua':
            raise Refused('signature %r, not %r' % (data[:4], b'\x1bLua'))
        if data[4] != 0x52:
            raise Refused('version byte 0x%02x; this reader is 5.2 (0x52) '
                          'only' % data[4])
        if data[:18] != HEADER:
            raise Refused('header %s differs from the one this object uses: '
                          '%s' % (data[:18].hex(), HEADER.hex()))
        r = Reader(data, 18)
        self.main = Proto(r, path)
        self.end = r.p
        # THE CLOSURE: the parse must land on the last byte of the file.
        self.residue = len(data) - r.p

    @property
    def closes(self):
        return self.residue == 0

    def protos(self):
        return list(self.main.walk())


def load(path):
    with open(path, 'rb') as f:
        return Chunk(f.read(), path)


def walk(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            yield os.path.join(dirpath, nm)


def candidates(roots):
    out = []
    for root in roots:
        for p in walk(root):
            try:
                with open(p, 'rb') as f:
                    if f.read(4) == b'\x1bLua':
                        out.append(p)
            except OSError:
                continue
    return out


# ------------------------------------------------------------ disassembly

def decode(word):
    op = word & 0x3f
    name = OPNAMES[op] if op < len(OPNAMES) else '?%d' % op
    a = (word >> 6) & 0xff
    c = (word >> 14) & 0x1ff
    b = (word >> 23) & 0x1ff
    bx = (word >> 14) & 0x3ffff
    ax = (word >> 6) & 0x3ffffff
    sbx = bx - 131071
    return name, a, b, c, bx, sbx, ax


def _rk(v, k):
    if v & 0x100:
        i = v & 0xff
        if i < len(k):
            return 'K%d(%s)' % (i, _kshow(k[i]))
        return 'K%d(?)' % i
    return 'R%d' % v


def _kshow(v):
    if isinstance(v, str):
        s = v if len(v) <= 30 else v[:27] + '...'
        return '"%s"' % s.replace('\n', '\\n')
    if v is None:
        return 'nil'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, float) and v == int(v) and abs(v) < 1e15:
        return '%d' % int(v)
    return repr(v)


def disasm(p, limit=10 ** 9):
    out = []
    for i, w in enumerate(p.code):
        if i >= limit:
            break
        name, a, b, c, bx, sbx, ax = decode(w)
        mode = OPMODE.get(name, 0)
        if mode == 1:
            args = '%d %d' % (a, bx)
            if name in ('LOADK',) and bx < len(p.k):
                args += '   ; %s' % _kshow(p.k[bx])
            elif name == 'CLOSURE':
                args += '   ; function %d' % bx
        elif mode == 2:
            args = '%d %d' % (a, sbx)
            args += '   ; to %d' % (i + 1 + sbx)
        elif mode == 3:
            args = '%d' % ax
        else:
            sb = _rk(b, p.k) if name in RK_B else str(b)
            sc = _rk(c, p.k) if name in RK_C else str(c)
            args = '%d %s %s' % (a, sb, sc)
            if name in ('GETTABUP', 'SETTABUP') and b < len(p.upvalue_names) \
                    and p.upvalue_names[b] == '_ENV':
                args += '   ; _ENV'
        line = p.lineinfo[i] if i < len(p.lineinfo) else 0
        out.append('%5d  [%4d]  %-10s %s' % (i + 1, line, name, args))
    return out


def globals_of(p):
    """Every global name read or written through the _ENV upvalue.

    These chunks are stripped: `source` is NULL, `lineinfo` is empty and the
    upvalue NAME array is empty, so `_ENV` cannot be identified by name.  It
    can be identified by position, and the identification is a derivation and
    not a guess: Lua 5.2 gives a main chunk exactly one upvalue and that
    upvalue is `_ENV` (lparser.c, `mainfunc`).  Every one of this object's 392
    main chunks has `sizeupvalues == 1`, which is the check, and it is
    reported by `census`.  Where the names survive they are used instead.
    """
    names = set()
    single_env = not p.upvalue_names and len(p.upvalues) == 1
    for w in p.code:
        name, a, b, c, bx, sbx, ax = decode(w)
        if name not in ('GETTABUP', 'SETTABUP'):
            continue
        if single_env:
            if b != 0:
                continue
        elif b >= len(p.upvalue_names) or p.upvalue_names[b] != '_ENV':
            continue
        if not (c & 0x100):
            continue
        i = c & 0xff
        if i < len(p.k) and isinstance(p.k[i], str):
            names.add(p.k[i])
    return names


# ----------------------------------------------------------------- selftest

def _pack_string(s):
    if s is None:
        return struct.pack('<I', 0)
    b = s.encode()
    return struct.pack('<I', len(b) + 1) + b + b'\0'


def _build(code=(0,), consts=('hello',), nested=0, break_what=None):
    def proto(depth):
        out = bytearray()
        out += struct.pack('<ii', 0, 0)
        out += bytes([0, 1, 2])
        out += struct.pack('<i', len(code))
        for w in code:
            out += struct.pack('<I', w)
        out += struct.pack('<i', len(consts))
        for c in consts:
            if isinstance(c, str):
                out += bytes([LUA_TSTRING]) + _pack_string(c)
            elif isinstance(c, float):
                out += bytes([LUA_TNUMBER]) + struct.pack('<f', c)
            elif isinstance(c, bool):
                out += bytes([LUA_TBOOLEAN, 1 if c else 0])
            else:
                out += bytes([LUA_TNIL])
        kids = depth - 1
        out += struct.pack('<i', 1 if kids > 0 else 0)
        if kids > 0:
            out += proto(kids)
        out += struct.pack('<i', 1)
        out += bytes([1, 0])
        out += _pack_string('@test.lua')
        out += struct.pack('<i', len(code))
        for _ in code:
            out += struct.pack('<i', 1)
        out += struct.pack('<i', 0)
        out += struct.pack('<i', 1)
        out += _pack_string('_ENV')
        return out

    head = bytearray(HEADER)
    if break_what == 'version':
        head[4] = 0x53
    if break_what == 'sig':
        head[0:4] = b'\x1bLuB'
    if break_what == 'number_size':
        head[10] = 8
    body = proto(nested + 1)
    if break_what == 'truncate':
        body = body[:-2]
    if break_what == 'trailing':
        body = body + b'\0\0'
    if break_what == 'string_nul':
        i = bytes(body).find(b'hello')
        body[i + 5] = 0x41
    if break_what == 'consttype':
        i = bytes(body).find(b'\x04' + struct.pack('<I', 6))
        body[i] = 9
    return bytes(head) + bytes(body)


def cmd_selftest(_args):
    print('luac52.py selftest -- chunks built in memory, most of them')
    print('required to be REFUSED.  The format offers one positive control --')
    print('the parse consumes the file exactly -- so most of these break that')
    print('and nothing else.')
    print()
    ok = bad = 0

    def expect_ok(name, blob, protos):
        nonlocal ok, bad
        try:
            c = Chunk(blob)
            n = len(c.protos())
            if c.closes and n == protos:
                print('  ACCEPT  %-38s %d functions, residue 0' % (name, n))
                ok += 1
            else:
                print('  ACCEPT  %-38s *** %d functions, residue %d'
                      % (name, n, c.residue))
                bad += 1
        except Refused as ex:
            print('  ACCEPT  %-38s *** WRONGLY REFUSED: %s' % (name, ex))
            bad += 1

    def expect_refuse(name, blob, because, closure=False):
        nonlocal ok, bad
        try:
            c = Chunk(blob)
            if closure and not c.closes:
                print('  REFUSE  %-38s residue %d, the parse does not consume '
                      'the file' % (name, c.residue))
                ok += 1
                return
            print('  REFUSE  %-38s *** WRONGLY ACCEPTED (%s)' % (name, because))
            bad += 1
        except Refused as ex:
            print('  REFUSE  %-38s %s' % (name, ex))
            ok += 1

    expect_ok('one function', _build(), 1)
    expect_ok('four nested functions', _build(nested=3), 4)
    expect_ok('mixed constants',
              _build(consts=('a', 1.5, True, None)), 1)
    expect_refuse('signature LuB', _build(break_what='sig'), 'wrong container')
    expect_refuse('version 5.3', _build(break_what='version'),
                  'this reader is 5.2 only')
    expect_refuse('sizeof(lua_Number) = 8',
                  _build(break_what='number_size'),
                  'a double build is a different file')
    expect_refuse('truncated by two bytes', _build(break_what='truncate'),
                  'runs off the end')
    expect_refuse('two trailing bytes', _build(break_what='trailing'),
                  'the closure', closure=True)
    expect_refuse('a string without its NUL',
                  _build(break_what='string_nul'), 'the length includes it')
    expect_refuse('constant type 9', _build(break_what='consttype'),
                  'only four types exist')
    expect_refuse('empty', b'', 'too short')
    expect_refuse('a UnityWeb bundle', b'UnityWeb\0' + b'\0' * 64,
                  'wrong container')
    expect_refuse('an @UTF table', b'@UTF' + b'\0' * 64, 'wrong container')
    # the decoder itself, against words whose meaning is known
    print()
    w = 0 | (3 << 6) | (7 << 23)                             # MOVE A=3 B=7
    name, a, b, c, bx, sbx, ax = decode(w)
    if (name, a, b) == ('MOVE', 3, 7):
        print('  ok      iABC field extraction              MOVE 3 7')
        ok += 1
    else:
        print('  WRONG   iABC field extraction              %s %d %d'
              % (name, a, b))
        bad += 1
    w = 1 | (2 << 6) | (300 << 14)                           # LOADK A=2 Bx=300
    name, a, b, c, bx, sbx, ax = decode(w)
    if (name, a, bx) == ('LOADK', 2, 300):
        print('  ok      iABx field extraction              LOADK 2 300')
        ok += 1
    else:
        print('  WRONG   iABx field extraction              %s %d %d'
              % (name, a, bx))
        bad += 1
    w = 23 | (0 << 6) | ((131071 - 5) << 14)                 # JMP sBx=-5
    name, a, b, c, bx, sbx, ax = decode(w)
    if (name, sbx) == ('JMP', -5):
        print('  ok      iAsBx bias of 131071                JMP 0 -5')
        ok += 1
    else:
        print('  WRONG   iAsBx bias of 131071                %s %d'
              % (name, sbx))
        bad += 1
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


# ----------------------------------------------------------------- commands

def short(p, keep=52):
    p = p.replace('\\', '/')
    return p if len(p) <= keep else '...' + p[-(keep - 3):]


def cmd_validate(args):
    paths = candidates(args.paths)
    same = diff = 0
    for p in paths:
        with open(p, 'rb') as f:
            h = f.read(18)
        if h == HEADER:
            same += 1
        else:
            diff += 1
            print('%-52s %s' % (short(p), h.hex()))
    print('files beginning \\x1bLua : %d' % len(paths))
    print('carrying the exact 18-byte header : %d of %d' % (same, len(paths)))
    print('header, as bytes : %s' % ' '.join('%02x' % b for b in HEADER))
    print('  version 5.2, official format, little-endian, int 4, size_t 4,')
    print('  Instruction 4, lua_Number 4 and NOT integral -- a float build')
    return 0 if diff == 0 else 2


def cmd_close(args):
    paths = candidates(args.paths)
    n = closed = 0
    residue = 0
    refused = []
    for p in paths:
        try:
            c = load(p)
        except Refused as ex:
            refused.append((p, str(ex)))
            continue
        n += 1
        if c.closes:
            closed += 1
        else:
            residue += c.residue
            print('%-52s residue %d' % (short(p), c.residue))
    print()
    print('chunks parsed        : %d of %d' % (n, len(paths)))
    print('consuming the file exactly (residue 0) : %d of %d' % (closed, n))
    print('bytes left over in total : %d' % residue)
    if refused:
        print('refused : %d' % len(refused))
        for p, why in refused[:10]:
            print('  %-52s %s' % (short(p), why))
    return 0 if (n == len(paths) and closed == n) else 2


def cmd_dump(args):
    c = load(args.paths[0])
    p = c.main
    if args.proto:
        for part in args.proto.split('.'):
            i = int(part)
            if i >= len(p.protos):
                raise Refused('no nested function %d' % i)
            p = p.protos[i]
    print('%s' % short(args.paths[0], 200))
    print('source %r  lines %d..%d  params %d  vararg %d  stack %d'
          % (p.source, p.line_defined, p.last_line_defined, p.num_params,
             p.is_vararg, p.max_stack))
    print('%d instructions, %d constants, %d nested functions, %d upvalues'
          % (len(p.code), len(p.k), len(p.protos), len(p.upvalues)))
    print('upvalues: %s' % ', '.join('%s(instack=%d,idx=%d)'
                                     % (nm, iv[0], iv[1])
                                     for nm, iv in
                                     zip(p.upvalue_names + ['?'] * 8,
                                         p.upvalues)))
    print('file %d bytes, parse consumed %d, residue %d'
          % (len(c.data), c.end, c.residue))
    print()
    for line in disasm(p, args.limit):
        print(line)
    if p.k:
        print()
        print('constants:')
        for i, v in enumerate(p.k[:args.limit]):
            print('  %3d  %s' % (i, _kshow(v)))
    return 0


def cmd_census(args):
    paths = candidates(args.paths)
    files = protos = instrs = consts = one_upvalue = 0
    strings = 0
    bytes_ = 0
    ops = collections.Counter()
    closed = 0
    sources = collections.Counter()
    per_dir = collections.defaultdict(lambda: [0, 0, 0])
    refused = []
    for p in paths:
        try:
            c = load(p)
        except Refused as ex:
            refused.append((p, str(ex)))
            continue
        files += 1
        bytes_ += len(c.data)
        if c.closes:
            closed += 1
        d = os.path.relpath(os.path.dirname(p), args.paths[0]).replace(
            '\\', '/')
        for f in c.protos():
            protos += 1
            instrs += len(f.code)
            consts += len(f.k)
            strings += sum(1 for v in f.k if isinstance(v, str))
            for w in f.code:
                ops[OPNAMES[w & 0x3f] if (w & 0x3f) < len(OPNAMES)
                    else '?%d' % (w & 0x3f)] += 1
            if f.source:
                sources[f.source] += 1
        per_dir[d][0] += 1
        per_dir[d][1] += sum(len(f.code) for f in c.protos())
        per_dir[d][2] += len(c.protos())
        if len(c.main.upvalues) == 1:
            one_upvalue += 1
    print('chunks            : %d' % files)
    print('bytes             : %d' % bytes_)
    print('residue 0         : %d of %d' % (closed, files))
    print('functions         : %d  (the chunk plus every nested prototype)'
          % protos)
    print('instructions      : %d' % instrs)
    print('constants         : %d, of which strings %d' % (consts, strings))
    print('distinct sources  : %d  (0 means the debug info is stripped)'
          % len(sources))
    print('chunks with exactly one upvalue : %d of %d  -- Lua 5.2 gives a main'
          % (one_upvalue, files))
    print('  chunk exactly one upvalue and it is _ENV, which is how the')
    print('  globals are recovered without a name array')
    print()
    print('%-24s %8s %10s %10s' % ('DIRECTORY', 'FILES', 'FUNCTIONS',
                                   'INSTRUCTIONS'))
    tf = tp = ti = 0
    for d in sorted(per_dir):
        print('%-24s %8d %10d %10d'
              % (d, per_dir[d][0], per_dir[d][2], per_dir[d][1]))
        tf += per_dir[d][0]
        tp += per_dir[d][2]
        ti += per_dir[d][1]
    print('%-24s %8d %10d %10d' % ('TOTAL', tf, tp, ti))
    print()
    print('%-14s %9s   %-14s %9s' % ('OPCODE', 'COUNT', 'OPCODE', 'COUNT'))
    items = ops.most_common()
    half = (len(items) + 1) // 2
    for i in range(half):
        left = '%-14s %9d' % items[i]
        right = '%-14s %9d' % items[i + half] if i + half < len(items) else ''
        print('%s   %s' % (left, right))
    print()
    print('opcodes used : %d of the 40 Lua 5.2 defines' % len(ops))
    if refused:
        print('refused : %d' % len(refused))
        for p, why in refused[:10]:
            print('  %-52s %s' % (short(p), why))
    return 0


def cmd_globals(args):
    paths = candidates(args.paths)
    names = collections.Counter()
    for p in paths:
        try:
            c = load(p)
        except Refused:
            continue
        for f in c.protos():
            for nm in globals_of(f):
                names[nm] += 1
    print('%d distinct global names read or written through _ENV'
          % len(names))
    print()
    print('%-40s %8s' % ('NAME', 'CHUNKS'))
    for nm, n in names.most_common(args.limit):
        print('%-40s %8d' % (nm, n))
    return 0


def cmd_strings(args):
    c = load(args.paths[0])
    n = 0
    for f in c.protos():
        for v in f.k:
            if isinstance(v, str):
                n += 1
                if n <= args.limit:
                    print('%s' % v)
    print()
    print('%d string constants in %d functions' % (n, len(c.protos())))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'validate', 'close', 'dump',
                                     'census', 'globals', 'strings'))
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--proto')
    ap.add_argument('--limit', type=int, default=60)
    args = ap.parse_args()
    if args.mode != 'selftest' and not args.paths:
        ap.error('%s needs a path' % args.mode)
    try:
        return globals()['cmd_' + args.mode](args)
    except Refused as ex:
        sys.stderr.write('REFUSED: %s\n' % ex)
        return 2


if __name__ == '__main__':
    sys.exit(main())
