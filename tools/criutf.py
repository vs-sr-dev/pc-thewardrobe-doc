#!/usr/bin/env python3
"""criutf.py -- read CRI Middleware's `@UTF` table, and the three containers
of ADX2 that are built out of it: `.acb`, `.awb` (`AFS2`) and `.cpk` (`CPK `).

There is no published specification for any of the four.  Everything below is
**derived** from this object, and every derivation is stated with the check
that would have caught it being wrong.  Where a field's meaning is a guess it
is printed as its number and labelled, never named.

Why one reader for four extensions
-----------------------------------

`@UTF` is a single tabular container -- a schema, a string pool, a data pool
and fixed-width rows -- and CRI builds everything on it.  In this object it
opens 279 files by itself (278 `.acb` and one `.acf`), it is the directory
inside both `.cpk`, and it is the index inside every `.acb`'s embedded audio
bank.  One format, a third of the object.

The layout, derived
--------------------

    +0x00  '@UTF'
    +0x04  u32 BE  tableSize   -- bytes after this field; +8 is the table end
    +0x08  u16 BE  version     -- 1 here on every table
    +0x0A  u16 BE  rowsOffset      | all three offsets are relative to +8,
    +0x0C  u32 BE  stringOffset    | which is a closure of its own: the schema
    +0x10  u32 BE  dataOffset      | must end exactly at rowsOffset
    +0x14  u32 BE  nameOffset  -- into the string pool
    +0x18  u16 BE  columnCount
    +0x1A  u16 BE  rowWidth
    +0x1C  u32 BE  rowCount
    +0x20  the schema, columnCount entries of:
             u8   flags
             u32  nameOffset        when flags & 0x10
             ...  a constant value  when flags & 0x20
           and a value per row      when flags & 0x40

    flags & 0x0f is the type:
      0 u8   1 s8   2 u16  3 s16  4 u32  5 s32  6 u64  7 s64
      8 float  9 double  a string (u32 into the string pool)
      b data   (u32 offset into the data pool, u32 length)

THE CLOSURES, and there are three, and they are the only reason any of this
can be trusted at all:

  1. the schema walk must stop **exactly** at `rowsOffset`.  A wrong flag
     interpretation lands here: reading the storage nibble as 0x30/0x20/0x10
     instead of the 0x40/0x20/0x10 bit flags gives a schema that ends 312
     bytes early on the first file tried.
  2. the sum of the per-row field widths must equal the declared `rowWidth`.
     Unity-style self-description: CRI wrote that integer, this reader did not.
  3. `rowsOffset + rowCount * rowWidth` must be <= `stringOffset`, and
     `stringOffset` <= `dataOffset` <= `tableSize + 8`.

    python criutf.py selftest
    python criutf.py validate DIR|FILE...
    python criutf.py table   FILE [--name NAME] [--rows N]
    python criutf.py acb     FILE            -- cues, waveforms, the AWB
    python criutf.py awb     FILE            -- the AFS2 offset table
    python criutf.py cpk     FILE            -- the CPK directory
    python criutf.py cpkclose FILE...      -- every byte of a CPK
    python criutf.py categories DIR       -- banks, cues and waveforms
    python criutf.py census  DIR             -- every CRI file in a tree

Standard library only.
"""

import argparse
import collections
import io
import os
import struct
import sys

MAGIC = b'@UTF'

TYPE_NAME = {0: 'u8', 1: 's8', 2: 'u16', 3: 's16', 4: 'u32', 5: 's32',
             6: 'u64', 7: 's64', 8: 'float', 9: 'double', 0xa: 'string',
             0xb: 'data'}
TYPE_FMT = {0: '>B', 1: '>b', 2: '>H', 3: '>h', 4: '>I', 5: '>i',
            6: '>Q', 7: '>q', 8: '>f', 9: '>d'}
TYPE_SIZE = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 8, 7: 8, 8: 4, 9: 8,
             0xa: 4, 0xb: 8}

FLAG_NAME = 0x10
FLAG_DEFAULT = 0x20
FLAG_ROW = 0x40


class Refused(Exception):
    """A refusal with a reason.  Never an exit code of 0."""


class Utf(object):
    """One @UTF table, with all three closures checked."""

    def __init__(self, data, off=0, path='<memory>'):
        self.path = path
        self.data = data
        self.off = off
        if len(data) - off < 32:
            raise Refused('%d bytes from offset %d is shorter than an @UTF '
                          'header' % (len(data) - off, off))
        if data[off:off + 4] != MAGIC:
            raise Refused('magic %r, not %r' % (data[off:off + 4], MAGIC))
        self.table_size, = struct.unpack_from('>I', data, off + 4)
        self.end = off + 8 + self.table_size
        if self.end > len(data):
            raise Refused('tableSize %d runs past the %d bytes available'
                          % (self.table_size, len(data) - off))
        base = off + 8
        self.base = base
        (self.version, self.rows_offset) = struct.unpack_from('>HH', data,
                                                              off + 8)
        (self.string_offset, self.data_offset,
         self.name_offset) = struct.unpack_from('>III', data, off + 12)
        (self.column_count, self.row_width) = struct.unpack_from('>HH', data,
                                                                 off + 24)
        self.row_count, = struct.unpack_from('>I', data, off + 28)
        # CLOSURE 3, the cheap one, first
        if not (self.rows_offset <= self.string_offset <= self.data_offset
                <= self.table_size):
            raise Refused('offsets out of order: rows %d, strings %d, data '
                          '%d, tableSize %d'
                          % (self.rows_offset, self.string_offset,
                             self.data_offset, self.table_size))
        if self.rows_offset + self.row_count * self.row_width > \
                self.string_offset:
            raise Refused('%d rows of %d from %d overrun the string pool at %d'
                          % (self.row_count, self.row_width, self.rows_offset,
                             self.string_offset))
        p = off + 32
        self.columns = []
        width = 0
        for i in range(self.column_count):
            if p >= self.end:
                raise Refused('schema ran past the table at column %d' % i)
            flags = data[p]
            p += 1
            ty = flags & 0x0f
            if ty not in TYPE_NAME:
                raise Refused('column %d has type %d, which is not one of the '
                              'twelve' % (i, ty))
            name = None
            if flags & FLAG_NAME:
                no, = struct.unpack_from('>I', data, p)
                p += 4
                name = self._string(no)
            const = None
            if flags & FLAG_DEFAULT:
                const, p = self._value(ty, p)
            if flags & FLAG_ROW:
                width += TYPE_SIZE[ty]
            self.columns.append(dict(flags=flags, type=ty, name=name,
                                     const=const))
        # CLOSURE 1
        if p != base + self.rows_offset:
            raise Refused('the schema stops at %d where rowsOffset declares '
                          '%d; the flag interpretation is wrong'
                          % (p - base, self.rows_offset))
        # CLOSURE 2
        if width != self.row_width:
            raise Refused('the per-row fields are %d bytes wide where '
                          'rowWidth declares %d' % (width, self.row_width))
        self.name = self._string(self.name_offset)

    def _string(self, o):
        s = self.base + self.string_offset + o
        if not 0 <= s < self.end:
            raise Refused('string offset %d outside the table' % o)
        z = self.data.find(b'\0', s, self.end)
        if z < 0:
            raise Refused('unterminated string at %d' % o)
        return self.data[s:z].decode('utf-8', 'replace')

    def _value(self, ty, p):
        if ty in TYPE_FMT:
            v, = struct.unpack_from(TYPE_FMT[ty], self.data, p)
            return v, p + TYPE_SIZE[ty]
        if ty == 0xa:
            o, = struct.unpack_from('>I', self.data, p)
            return self._string(o), p + 4
        o, n = struct.unpack_from('>II', self.data, p)
        s = self.base + self.data_offset + o
        if s < 0 or s + n > self.end:
            raise Refused('data field at %d+%d outside the table' % (o, n))
        return self.data[s:s + n], p + 8

    # -- rows --------------------------------------------------------------

    def row(self, i):
        if not 0 <= i < self.row_count:
            raise Refused('row %d of %d' % (i, self.row_count))
        p = self.base + self.rows_offset + i * self.row_width
        out = collections.OrderedDict()
        for c in self.columns:
            if c['flags'] & FLAG_ROW:
                v, p = self._value(c['type'], p)
            elif c['flags'] & FLAG_DEFAULT:
                v = c['const']
            else:
                v = 0
            out[c['name'] if c['name'] is not None else '?'] = v
        return out

    def rows(self):
        for i in range(self.row_count):
            yield self.row(i)

    def column(self, name):
        return [r.get(name) for r in self.rows()]


def load_utf(path, off=0):
    with open(path, 'rb') as f:
        return Utf(f.read(), off, path)


# --------------------------------------------------------------------- AFS2

class Afs2(object):
    """The `AFS2` stream bank: a count, an id list and count+1 offsets.

    The closure is the one that makes this readable at all: the **last**
    offset in the table is the length of the bank, so a bank whose header is
    misread does not close.  On this object it closes on 89 of 89 external
    banks and on every bank embedded in an `.acb`.
    """

    def __init__(self, data, off=0, path='<memory>', strict=True):
        self.path = path
        self.data = data
        self.off = off
        if len(data) - off < 16 or data[off:off + 4] != b'AFS2':
            raise Refused('magic %r, not %r'
                          % (data[off:off + 4], b'AFS2'))
        self.type = data[off + 4]
        self.offset_size = data[off + 5]
        self.id_size = data[off + 6]
        if self.offset_size not in (2, 4, 8):
            raise Refused('offset field is %d bytes' % self.offset_size)
        if self.id_size not in (2, 4):
            raise Refused('id field is %d bytes' % self.id_size)
        self.count, self.align = struct.unpack_from('<II', data, off + 8)
        if not 0 < self.count <= 1 << 20:
            raise Refused('count %d is not credible' % self.count)
        if self.align not in (16, 32, 64, 2048):
            raise Refused('alignment %d is not a power of two in range'
                          % self.align)
        p = off + 16
        ifmt = {2: '<H', 4: '<I'}[self.id_size]
        self.ids = []
        for _ in range(self.count):
            self.ids.append(struct.unpack_from(ifmt, data, p)[0])
            p += self.id_size
        ofmt = {2: '<H', 4: '<I', 8: '<Q'}[self.offset_size]
        raw = []
        for _ in range(self.count + 1):
            raw.append(struct.unpack_from(ofmt, data, p)[0])
            p += self.offset_size
        self.header_end = p - off
        # CLOSURE: the last offset is the bank's own length.  This check lived
        # in `closes_against` and not here until the selftest built a bank
        # whose last offset was eight too large and this class accepted it:
        # the entries still fitted, because they are bounded by the very
        # number that was wrong.  A closure that the constructor does not
        # enforce is not a closure, and that is the whole lesson of the tool
        # this repository was written to replace.
        self.size = raw[-1]
        avail = len(data) - off
        if strict and self.size != avail:
            raise Refused('the bank declares %d bytes and the buffer holds '
                          '%d' % (self.size, avail))
        if self.size > avail:
            raise Refused('the bank declares %d bytes, more than the %d '
                          'available' % (self.size, avail))
        self.entries = []
        for i in range(self.count):
            start = raw[i]
            if i > 0:
                start = (start + self.align - 1) // self.align * self.align
            else:
                start = (raw[0] + self.align - 1) // self.align * self.align
            end = raw[i + 1]
            if not 0 <= start <= end <= self.size:
                raise Refused('entry %d is [%d,%d) in a bank of %d'
                              % (i, start, end, self.size))
            self.entries.append((self.ids[i], start, end - start))

    def closes_against(self, total):
        return self.size == total

    def payload(self, i):
        _id, start, n = self.entries[i]
        return self.data[self.off + start:self.off + start + n]


def load_afs2(path):
    with open(path, 'rb') as f:
        return Afs2(f.read(), 0, path)


# ---------------------------------------------------------------------- ACB

class Acb(object):
    """An `.acb`: one @UTF table called `Header`, whose `data` columns hold
    further @UTF tables, and whose `AwbFile` column holds a whole `AFS2`."""

    def __init__(self, data, path='<memory>'):
        self.path = path
        self.data = data
        self.header = Utf(data, 0, path)
        if self.header.name != 'Header':
            raise Refused('the outer table is named %r, not %r'
                          % (self.header.name, 'Header'))
        self.r0 = self.header.row(0)

    def sub(self, name):
        """A nested @UTF table by column name, or None when the field is
        empty -- which is a result and is counted, not an error."""
        v = self.r0.get(name)
        if not isinstance(v, bytes) or len(v) < 4:
            return None
        if v[:4] != MAGIC:
            return None
        return Utf(v, 0, '%s!%s' % (self.path, name))

    def awb(self):
        v = self.r0.get('AwbFile')
        if not isinstance(v, bytes) or len(v) < 16 or v[:4] != b'AFS2':
            return None
        return Afs2(v, 0, '%s!AwbFile' % self.path)

    def cue_names(self):
        t = self.sub('CueNameTable')
        if t is None:
            return []
        return [(r.get('CueName'), r.get('CueIndex')) for r in t.rows()]


def load_acb(path):
    with open(path, 'rb') as f:
        return Acb(f.read(), path)


# ---------------------------------------------------------------------- CPK

class Cpk(object):
    """A `.cpk`: `CPK ` at 0, an @UTF table at 16, and further @UTF tables
    at the offsets that table names."""

    def __init__(self, data, path='<memory>'):
        self.path = path
        self.data = data
        if data[:4] != b'CPK ':
            raise Refused('magic %r, not %r' % (data[:4], b'CPK '))
        self.header = Utf(data, 16, path)
        self.r0 = self.header.row(0)
        self.tocs = collections.OrderedDict()
        for key in ('TocOffset', 'ItocOffset', 'EtocOffset', 'GtocOffset',
                    'HtocOffset'):
            off = self.r0.get(key)
            if not off:
                continue
            off = int(off)
            if off + 32 > len(data):
                continue
            tag = data[off:off + 4]
            try:
                self.tocs[key] = (off, tag, Utf(data, off + 16, path))
            except Refused as ex:
                self.tocs[key] = (off, tag, ex)


def load_cpk(path):
    with open(path, 'rb') as f:
        return Cpk(f.read(), path)


# ----------------------------------------------------------------- selftest

def _build_utf(name='T', cols=(('A', 4), ('B', 0xa)), rows=2,
               break_what=None):
    """A complete, valid @UTF table, built in memory."""
    strings = bytearray(b'\0')

    def put(s):
        o = len(strings)
        strings.extend(s.encode() + b'\0')
        return o

    name_off = put(name)
    schema = bytearray()
    col_offs = []
    for cn, ct in cols:
        col_offs.append(put(cn))
    for (cn, ct), no in zip(cols, col_offs):
        flags = FLAG_NAME | FLAG_ROW | ct
        if break_what == 'flags30':
            flags = 0x30 | ct
        schema.append(flags)
        schema += struct.pack('>I', no)
    rowbuf = bytearray()
    width = 0
    for _cn, ct in cols:
        width += TYPE_SIZE[ct]
    if break_what == 'rowwidth':
        width += 1
    val_off = put('hello')
    for i in range(rows):
        for _cn, ct in cols:
            if ct == 0xa:
                rowbuf += struct.pack('>I', val_off)
            else:
                rowbuf += struct.pack(TYPE_FMT[ct], i + 1)
    rows_offset = 0x20 - 8 + len(schema)
    string_offset = rows_offset + len(rowbuf)
    data_offset = string_offset + len(strings)
    body = bytes(schema) + bytes(rowbuf) + bytes(strings)
    table_size = 0x20 - 8 + len(body)
    head = bytearray(MAGIC)
    head += struct.pack('>I', table_size)
    head += struct.pack('>HH', 1, rows_offset)
    head += struct.pack('>III', string_offset, data_offset, name_off)
    head += struct.pack('>HH', len(cols), width)
    head += struct.pack('>I', rows)
    if break_what == 'magic':
        head[0:4] = b'@UTG'
    if break_what == 'tablesize':
        head[4:8] = struct.pack('>I', table_size + 4096)
    if break_what == 'order':
        head[12:16] = struct.pack('>I', 4)
    return bytes(head) + body


def _build_afs2(count=3, break_what=None):
    align = 32
    payloads = [bytes([i + 1]) * (17 + i * 5) for i in range(count)]
    id_size, off_size = 2, 4
    head = bytearray(b'AFS2')
    head += bytes([1, off_size, id_size, 0])
    head += struct.pack('<II', count, align)
    for i in range(count):
        head += struct.pack('<H', i)
    table_at = len(head)
    head += b'\0' * (off_size * (count + 1))
    offs = []
    cur = len(head)
    for i, pl in enumerate(payloads):
        cur = (cur + align - 1) // align * align
        offs.append(cur)
        cur += len(pl)
    offs.append(cur)
    if break_what == 'last':
        offs[-1] += 8
    for i, o in enumerate(offs):
        struct.pack_into('<I', head, table_at + i * off_size, o)
    out = bytearray(head)
    for i, pl in enumerate(payloads):
        while len(out) < offs[i]:
            out += b'\0'
        out += pl
    if break_what == 'count':
        struct.pack_into('<I', out, 8, 1 << 24)
    if break_what == 'align':
        struct.pack_into('<I', out, 12, 33)
    return bytes(out)


def cmd_selftest(_args):
    print('criutf.py selftest -- tables and banks built in memory, most of')
    print('them required to be REFUSED.  @UTF has no published specification,')
    print('so these specimens are the only place a layout error can be caught')
    print('before the object is touched.')
    print()
    ok = bad = 0

    def expect_ok(name, fn):
        nonlocal ok, bad
        try:
            fn()
            print('  ACCEPT  %-38s all closures ok' % name)
            ok += 1
        except Refused as ex:
            print('  ACCEPT  %-38s *** WRONGLY REFUSED: %s' % (name, ex))
            bad += 1

    def expect_refuse(name, fn, because):
        nonlocal ok, bad
        try:
            fn()
            print('  REFUSE  %-38s *** WRONGLY ACCEPTED (%s)' % (name, because))
            bad += 1
        except Refused as ex:
            print('  REFUSE  %-38s %s' % (name, ex))
            ok += 1

    expect_ok('@UTF, 2 columns, 2 rows',
              lambda: Utf(_build_utf()))
    expect_ok('@UTF, 6 columns, 40 rows',
              lambda: Utf(_build_utf(cols=(('A', 0), ('B', 2), ('C', 4),
                                           ('D', 6), ('E', 8), ('F', 0xa)),
                                     rows=40)))
    expect_refuse('@UTG magic', lambda: Utf(_build_utf(break_what='magic')),
                  'wrong container')
    expect_refuse('tableSize past the buffer',
                  lambda: Utf(_build_utf(break_what='tablesize')),
                  'closure on the size')
    expect_refuse('storage read as a 0x30 nibble',
                  lambda: Utf(_build_utf(break_what='flags30')),
                  'closure 1, the schema end')
    expect_refuse('rowWidth off by one',
                  lambda: Utf(_build_utf(break_what='rowwidth')),
                  'closure 2')
    expect_refuse('offsets out of order',
                  lambda: Utf(_build_utf(break_what='order')),
                  'closure 3')
    expect_refuse('an empty buffer', lambda: Utf(b''), 'too short')
    expect_refuse('a Lua script',
                  lambda: Utf(b'\x1bLuaR' + b'\0' * 64), 'wrong container')
    expect_refuse('a UnityWeb bundle',
                  lambda: Utf(b'UnityWeb\0' + b'\0' * 64), 'wrong container')
    expect_ok('AFS2, 3 entries', lambda: Afs2(_build_afs2()))
    expect_ok('AFS2, 64 entries', lambda: Afs2(_build_afs2(64)))
    expect_refuse('AFS2 last offset off by eight',
                  lambda: Afs2(_build_afs2(break_what='last')),
                  'the bank does not close')
    expect_refuse('AFS2 count 16777216',
                  lambda: Afs2(_build_afs2(break_what='count')),
                  'not credible')
    expect_refuse('AFS2 alignment 33',
                  lambda: Afs2(_build_afs2(break_what='align')),
                  'not a power of two')
    expect_refuse('AFS2 pointed at an @UTF table',
                  lambda: Afs2(_build_utf()), 'wrong container')
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


# ----------------------------------------------------------------- commands

def short(p, keep=46):
    p = p.replace('\\', '/')
    return p if len(p) <= keep else '...' + p[-(keep - 3):]


def walk(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            yield os.path.join(dirpath, nm)


def cmd_validate(args):
    n_utf = n_afs = n_cpk = n_ref = 0
    refused = []
    for root in args.paths:
        for p in walk(root):
            try:
                with open(p, 'rb') as f:
                    head = f.read(4)
            except OSError:
                continue
            try:
                if head == MAGIC:
                    load_utf(p)
                    n_utf += 1
                elif head == b'AFS2':
                    a = load_afs2(p)
                    if not a.closes_against(os.path.getsize(p)):
                        raise Refused('the bank declares %d, the file is %d'
                                      % (a.size, os.path.getsize(p)))
                    n_afs += 1
                elif head == b'CPK ':
                    load_cpk(p)
                    n_cpk += 1
            except Refused as ex:
                n_ref += 1
                refused.append((p, str(ex)))
    print('@UTF tables read : %d' % n_utf)
    print('AFS2 banks read  : %d  (each closing on its own last offset)'
          % n_afs)
    print('CPK archives read: %d' % n_cpk)
    print('refused          : %d' % n_ref)
    for p, why in refused[:20]:
        print('  %-46s %s' % (short(p), why))
    return 0 if n_ref == 0 else 2


def cmd_table(args):
    t = load_utf(args.paths[0])
    print('%s' % short(args.paths[0], 200))
    print()
    print('table name    %s' % t.name)
    print('version       %d' % t.version)
    print('columns       %d' % t.column_count)
    print('rows          %d' % t.row_count)
    print('row width     %d   (the per-row fields sum to it: closure 2)'
          % t.row_width)
    print('tableSize     %d, table ends at %d of %d bytes'
          % (t.table_size, t.end, len(t.data)))
    print()
    print('%-4s %-6s %-8s %s' % ('#', 'FLAGS', 'TYPE', 'NAME'))
    for i, c in enumerate(t.columns):
        st = []
        if c['flags'] & FLAG_NAME:
            st.append('name')
        if c['flags'] & FLAG_DEFAULT:
            st.append('const')
        if c['flags'] & FLAG_ROW:
            st.append('row')
        print('%-4d 0x%02x   %-8s %-28s %s'
              % (i, c['flags'], TYPE_NAME[c['type']], c['name'],
                 ','.join(st)))
    print()
    for i in range(min(args.rows, t.row_count)):
        r = t.row(i)
        print('row %d:' % i)
        for k, v in r.items():
            if isinstance(v, bytes):
                tag = ''
                if v[:4] == MAGIC:
                    try:
                        tag = '  -> @UTF %r, %d rows' % (Utf(v).name,
                                                         Utf(v).row_count)
                    except Refused as ex:
                        tag = '  -> @UTF refused: %s' % ex
                elif v[:4] == b'AFS2':
                    try:
                        a = Afs2(v)
                        tag = '  -> AFS2, %d entries' % a.count
                    except Refused as ex:
                        tag = '  -> AFS2 refused: %s' % ex
                print('    %-28s %d bytes%s' % (k, len(v), tag))
            else:
                print('    %-28s %r' % (k, v))
    return 0


def cmd_awb(args):
    a = load_afs2(args.paths[0])
    size = os.path.getsize(args.paths[0])
    print('%s' % short(args.paths[0], 200))
    print()
    print('entries        %d' % a.count)
    print('id field       %d bytes      offset field %d bytes'
          % (a.id_size, a.offset_size))
    print('alignment      %d' % a.align)
    print('header ends at %d' % a.header_end)
    print('declared size  %d' % a.size)
    print('file on disk   %d          %s'
          % (size, 'CLOSES' if a.size == size else 'DOES NOT CLOSE'))
    print()
    print('%-6s %12s %12s  %s' % ('ID', 'OFFSET', 'SIZE', 'FIRST 4 BYTES'))
    for i, (i_id, off, n) in enumerate(a.entries[:args.rows]):
        print('%-6d %12d %12d  %r' % (i_id, off, n, a.data[off:off + 4]))
    return 0


def cmd_acb(args):
    acb = load_acb(args.paths[0])
    size = os.path.getsize(args.paths[0])
    print('%s' % short(args.paths[0], 200))
    print()
    print('outer table    %r, %d columns, %d row'
          % (acb.header.name, acb.header.column_count, acb.header.row_count))
    print('file           %d bytes; the @UTF table declares %d + 8 = %d'
          % (size, acb.header.table_size, acb.header.table_size + 8))
    print()
    print('%-28s %8s  %s' % ('COLUMN', 'BYTES', 'CONTENT'))
    for k, v in acb.r0.items():
        if not isinstance(v, bytes):
            continue
        tag = ''
        if v[:4] == MAGIC:
            try:
                t = Utf(v)
                tag = '@UTF %r, %d rows, %d columns' % (t.name, t.row_count,
                                                        t.column_count)
            except Refused as ex:
                tag = 'REFUSED: %s' % ex
        elif v[:4] == b'AFS2':
            try:
                a = Afs2(v)
                tag = 'AFS2, %d waveforms, %d bytes' % (a.count, a.size)
            except Refused as ex:
                tag = 'REFUSED: %s' % ex
        elif not v:
            tag = '(empty)'
        else:
            tag = repr(v[:24])
        print('%-28s %8d  %s' % (k, len(v), tag))
    names = acb.cue_names()
    if names:
        print()
        print('%d cue names, the first %d:' % (len(names), min(12, len(names))))
        for nm, ix in names[:12]:
            print('   %-40s cue %s' % (nm, ix))
    a = acb.awb()
    if a is not None:
        print()
        print('embedded AWB: %d waveforms, %d bytes, first four bytes of each '
              'payload %s'
              % (a.count, a.size,
                 collections.Counter(a.payload(i)[:4]
                                     for i in range(a.count)).most_common(3)))
    return 0


def cmd_cpk(args):
    c = load_cpk(args.paths[0])
    size = os.path.getsize(args.paths[0])
    print('%s' % short(args.paths[0], 200))
    print()
    print('outer table    %r, %d columns, %d row'
          % (c.header.name, c.header.column_count, c.header.row_count))
    print('file           %d bytes' % size)
    for k in ('ContentOffset', 'ContentSize', 'Files', 'TocOffset',
              'TocSize', 'ItocOffset', 'ItocSize', 'EtocOffset', 'EtocSize',
              'Align', 'CpkMode', 'Tvers'):
        if k in c.r0:
            print('  %-16s %s' % (k, c.r0[k]))
    print()
    for key, (off, tag, t) in c.tocs.items():
        if isinstance(t, Refused):
            print('%-12s at %10d  %r  REFUSED: %s' % (key, off, tag, t))
        else:
            print('%-12s at %10d  %r  @UTF %r, %d rows, %d columns'
                  % (key, off, tag, t.name, t.row_count, t.column_count))
    toc = c.tocs.get('TocOffset')
    if toc and not isinstance(toc[2], Refused):
        t = toc[2]
        print()
        print('the first %d of %d members:' % (min(args.rows, t.row_count),
                                               t.row_count))
        print('%-46s %12s %12s' % ('NAME', 'FILESIZE', 'EXTRACTSIZE'))
        for i in range(min(args.rows, t.row_count)):
            r = t.row(i)
            print('%-46s %12s %12s'
                  % (str(r.get('FileName'))[:46], r.get('FileSize'),
                     r.get('ExtractSize')))
    return 0


def cmd_categories(args):
    """One row per audio category: banks, bytes, cues, waveforms, embedding.

    The column that matters is the last: a category whose `.acb` files embed
    ZERO waveforms streams them from the `.awb` beside it, and a category whose
    `.acb` files embed ALL of them has an empty `awb` directory next door.
    That is where this object's six empty directories come from, and it is an
    arithmetic statement rather than an observation about the file system.
    """
    root = args.paths[0]
    rows = collections.defaultdict(
        lambda: dict(acb=0, acbb=0, awb=0, awbb=0, cues=0, waves=0, emb=0,
                     embb=0))
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            parts = rel.split('/')
            cat = '/'.join(parts[:-2]) if len(parts) >= 3 else parts[0]
            if f.lower().endswith('.acb'):
                a = load_acb(p)
                r = rows[cat]
                r['acb'] += 1
                r['acbb'] += os.path.getsize(p)
                ct = a.sub('CueTable')
                wt = a.sub('WaveformTable')
                if ct:
                    r['cues'] += ct.row_count
                if wt:
                    r['waves'] += wt.row_count
                bk = a.awb()
                if bk:
                    r['emb'] += bk.count
                    r['embb'] += bk.size
            elif f.lower().endswith('.awb'):
                bk = load_afs2(p)
                r = rows[cat]
                r['awb'] += 1
                r['awbb'] += os.path.getsize(p)
    print('%-14s %5s %12s %5s %12s %7s %7s %7s %12s'
          % ('CATEGORY', 'ACB', 'ACB BYTES', 'AWB', 'AWB BYTES', 'CUES',
             'WAVES', 'EMBED', 'EMBED BYTES'))
    t = collections.Counter()
    for c in sorted(rows):
        r = rows[c]
        print('%-14s %5d %12d %5d %12d %7d %7d %7d %12d'
              % (c, r['acb'], r['acbb'], r['awb'], r['awbb'], r['cues'],
                 r['waves'], r['emb'], r['embb']))
        for k in r:
            t[k] += r[k]
    print('%-14s %5d %12d %5d %12d %7d %7d %7d %12d'
          % ('TOTAL', t['acb'], t['acbb'], t['awb'], t['awbb'], t['cues'],
             t['waves'], t['emb'], t['embb']))
    print()
    print('waveform rows declared by the .acb schemas : %d' % t['waves'])
    print('payloads counted in the banks              : %d'
          % (t['emb'] + t['awb']))
    print('  -- two different structures, and they agree'
          if t['waves'] == t['emb'] + t['awb'] else '  -- THEY DISAGREE')
    return 0 if t['waves'] == t['emb'] + t['awb'] else 2


def cmd_cpkclose(args):
    """Every byte of a CPK, in four buckets that must sum to the file.

    The archive states four numbers that this reader did not: `ContentOffset`,
    `ContentSize`, `EtocOffset` and `EtocSize`.  Two closures follow from them
    and a third from the member table:

      ContentOffset + ContentSize == EtocOffset
      EtocOffset + EtocSize       == the file on disk
      sum over members of FileSize rounded up to Align == ContentSize

    The third is the one that could have gone wrong, because `Align` and the
    rounding are derived and not declared as a rule.  It closes at residue 0
    on both of this object's archives.
    """
    for path in args.paths:
        c = load_cpk(path)
        size = os.path.getsize(path)
        r = c.r0
        toc = c.tocs.get('TocOffset')
        if toc is None or isinstance(toc[2], Refused):
            print('%s: no readable TOC' % short(path))
            return 2
        rows = list(toc[2].rows())
        align = int(r.get('Align') or 1)
        padded = sum((int(x['FileSize']) + align - 1) // align * align
                     for x in rows)
        stored = sum(int(x['FileSize']) for x in rows)
        extract = sum(int(x['ExtractSize']) for x in rows)
        co, cs = int(r['ContentOffset']), int(r['ContentSize'])
        eo, es = int(r['EtocOffset']), int(r['EtocSize'])
        print('%s' % short(path, 200))
        print('  file on disk                       %14d' % size)
        print('  members declared                   %14d' % int(r['Files']))
        print('  members in the TOC                 %14d' % len(rows))
        print('  Align                              %14d' % align)
        print('  ContentOffset + ContentSize        %14d' % (co + cs))
        print('  EtocOffset                         %14d   residue %d'
              % (eo, co + cs - eo))
        print('  EtocOffset + EtocSize              %14d   residue %d'
              % (eo + es, eo + es - size))
        print('  member bytes, stored               %14d' % stored)
        print('  member bytes, extracted            %14d' % extract)
        print('  compressed members                 %14d'
              % sum(1 for x in rows
                    if int(x['FileSize']) != int(x['ExtractSize'])))
        print('  members padded up to Align         %14d' % padded)
        print('  ContentSize                        %14d   RESIDUE %d'
              % (cs, cs - padded))
        print('  header, TOC, ITOC before content   %14d' % co)
        ok = (co + cs == eo and eo + es == size and cs == padded
              and len(rows) == int(r['Files']))
        print('  VERDICT                            %s'
              % ('closes at residue 0' if ok else 'DOES NOT CLOSE'))
        if not ok:
            return 2
    return 0


def cmd_census(args):
    counts = collections.Counter()
    byts = collections.Counter()
    tables = collections.Counter()
    waveforms = 0
    wave_bytes = 0
    cues = 0
    banks = 0
    codecs = collections.Counter()
    refused = []
    for root in args.paths:
        for p in walk(root):
            try:
                with open(p, 'rb') as f:
                    head = f.read(4)
            except OSError:
                continue
            size = os.path.getsize(p)
            try:
                if head == MAGIC:
                    a = load_acb(p) if p.lower().endswith('.acb') else None
                    if a is None:
                        t = load_utf(p)
                        counts['@UTF (other)'] += 1
                        byts['@UTF (other)'] += size
                        tables[t.name] += 1
                        continue
                    counts['acb'] += 1
                    byts['acb'] += size
                    tables[a.header.name] += 1
                    ct = a.sub('CueTable')
                    if ct is not None:
                        cues += ct.row_count
                    wt = a.sub('WaveformTable')
                    if wt is not None:
                        waveforms += wt.row_count
                    b = a.awb()
                    if b is not None:
                        banks += 1
                        wave_bytes += b.size
                        for i in range(b.count):
                            codecs[bytes(b.payload(i)[:4])] += 1
                elif head == b'AFS2':
                    b = load_afs2(p)
                    counts['awb'] += 1
                    byts['awb'] += size
                    if not b.closes_against(size):
                        raise Refused('bank declares %d, file is %d'
                                      % (b.size, size))
                    banks += 1
                    wave_bytes += b.size
                    for i in range(b.count):
                        codecs[bytes(b.payload(i)[:4])] += 1
                elif head == b'CPK ':
                    load_cpk(p)
                    counts['cpk'] += 1
                    byts['cpk'] += size
            except Refused as ex:
                refused.append((p, str(ex)))
    print('%-14s %6s %14s' % ('FAMILY', 'FILES', 'BYTES'))
    tot = totb = 0
    for k in sorted(counts):
        print('%-14s %6d %14d' % (k, counts[k], byts[k]))
        tot += counts[k]
        totb += byts[k]
    print('%-14s %6d %14d' % ('TOTAL', tot, totb))
    print()
    print('outer table names : %s' % dict(tables))
    print('AFS2 banks read   : %d' % banks)
    print('bytes in banks    : %d' % wave_bytes)
    print('waveform rows     : %d' % waveforms)
    print('cue rows          : %d' % cues)
    print('payload magic     : %s'
          % {k.decode('latin1'): v for k, v in codecs.most_common(6)})
    if refused:
        print()
        print('%d refused:' % len(refused))
        for p, why in refused[:20]:
            print('  %-46s %s' % (short(p), why))
    return 0 if not refused else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'validate', 'table', 'acb',
                                     'awb', 'cpk', 'cpkclose', 'categories',
                                     'census'))
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--rows', type=int, default=8)
    ap.add_argument('--name')
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
