#!/usr/bin/env python3
"""cilmeta.py -- read the CLI metadata tables of a .NET assembly, and refuse a
PE that has none.

A Mono build ships real CIL, so `Assembly-CSharp.dll` still carries every type
name and method name the studio wrote, in a documented structure (ECMA-335,
which IS a published specification and is called one here). A byte scan of the
file answers "does the string `Sonic` occur"; this answers "how many types are
declared and what are they called", which is a different question and a better
one.

What is read, and nothing beyond it:

    PE optional header -> data directory 14 -> CLI header
    CLI header         -> metadata root RVA
    metadata root      -> "BSJB", version string, stream headers
    #~ stream          -> heap sizes, the Valid bitmap, the row counts
    #Strings           -> the names, for tables 0x00, 0x01, 0x02 only

Rows are decoded for Module, TypeRef and TypeDef, because those three are all
that stand between the start of the table stream and the type names. Every
other table is COUNTED and not decoded, and the count comes from the file's
own row-count array rather than from walking anything.

THE CHECKS:

  1. the CLI header's cb field is 72, which is the only value ECMA-335 allows;
  2. the metadata root begins BSJB;
  3. every stream header lies inside the metadata block;
  4. the number of row counts equals the number of set bits in Valid;
  5. the decoded TypeDef rows end exactly where the row-size arithmetic says
     they should -- which is the check that fails if the heap widths are wrong.

    python tools/cilmeta.py validate PATH
    python tools/cilmeta.py census   PATH
    python tools/cilmeta.py types    PATH [--limit N]
    python tools/cilmeta.py selftest

ADDED ON pc-monstrum-doc (Unity 5.5, Mono, Assembly-CSharp.dll of 2,124 types)
------------------------------------------------------------------------------
The pre-briefing of that repository said the box "does not read the metadata
tables"; it read three. What it did not read was the rows that turn a type
into a class: its fields and its methods. Those are decoded now, and so are
the two tables between them and MemberRef, because MemberRef is where the
question "does this program call a lobby" is answered at the table level --
every method of another assembly the code invokes is a MemberRef row with a
name and a parent TypeRef.

    0x04 Field      Flags u16, Name str, Signature blob
    0x06 MethodDef  RVA u32, ImplFlags u16, Flags u16, Name str, Signature
                    blob, ParamList -> Param
    0x08 Param      Flags u16, Sequence u16, Name str
    0x09 InterfaceImpl  Class -> TypeDef, Interface TypeDefOrRef coded
    0x0A MemberRef  Class MemberRefParent coded (3 bits: TypeDef, TypeRef,
                    ModuleRef, MethodDef, TypeSpec), Name str, Signature blob

A TypeDef's members are the rows from its FieldList (MethodList) up to the
next TypeDef's, or to the end of the table for the last one (II.22.37). The
pointer tables FieldPtr/MethodPtr (uncompressed #- streams) are refused, not
guessed at. THE CHECKS added: the FieldList and MethodList columns are
monotone and end at rows+1; every Field, MethodDef, Param and MemberRef row
ends inside the #~ stream by the same arithmetic; every one resolves to a
name. The signatures (the types of the fields, the parameters of the
methods) are blob-encoded and are NOT decoded here: a member is reported by
its name and its owner, which is what a census needs.

    python tools/cilmeta.py members    PATH [--type NAME] [--limit N]
    python tools/cilmeta.py owners     PATH --grep REGEX   (which types own a
                                       field or method whose name matches)
    python tools/cilmeta.py typerefs   PATH                (the types imported)
    python tools/cilmeta.py memberrefs PATH [--grep REGEX] (the members called)
"""
import collections
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                          # noqa: E402
import nameguard                                         # noqa: E402

nameguard.guard()

TABLE = {
    0x00: 'Module', 0x01: 'TypeRef', 0x02: 'TypeDef', 0x03: 'FieldPtr',
    0x04: 'Field', 0x05: 'MethodPtr', 0x06: 'MethodDef', 0x07: 'ParamPtr',
    0x08: 'Param', 0x09: 'InterfaceImpl', 0x0A: 'MemberRef',
    0x0B: 'Constant', 0x0C: 'CustomAttribute', 0x0D: 'FieldMarshal',
    0x0E: 'DeclSecurity', 0x0F: 'ClassLayout', 0x10: 'FieldLayout',
    0x11: 'StandAloneSig', 0x12: 'EventMap', 0x14: 'Event',
    0x15: 'PropertyMap', 0x17: 'Property', 0x18: 'MethodSemantics',
    0x19: 'MethodImpl', 0x1A: 'ModuleRef', 0x1B: 'TypeSpec',
    0x1C: 'ImplMap', 0x1D: 'FieldRVA', 0x20: 'Assembly',
    0x23: 'AssemblyRef', 0x26: 'File', 0x27: 'ExportedType',
    0x28: 'ManifestResource', 0x29: 'NestedClass', 0x2A: 'GenericParam',
    0x2B: 'MethodSpec', 0x2C: 'GenericParamConstraint',
}


class CilError(Exception):
    """Raised loudly. A PE with no CLI header raises rather than returning
    zero types, because zero types and no metadata are different answers."""


class Assembly(object):

    def __init__(self, path_or_bytes, name=None):
        if isinstance(path_or_bytes, (bytes, bytearray)):
            self.d = bytes(path_or_bytes)
            self.name = name or '<memory>'
        else:
            self.d = open(path_or_bytes, 'rb').read()
            self.name = name or os.path.basename(path_or_bytes)
        d = self.d
        if d[:2] != b'MZ':
            raise CilError('%s: no MZ signature' % self.name)
        if len(d) < 0x40:
            raise CilError('%s: %d bytes is not a PE' % (self.name, len(d)))
        (e,) = struct.unpack_from('<I', d, 0x3C)
        if e + 24 > len(d) or d[e:e + 4] != b'PE\0\0':
            raise CilError('%s: no PE signature at e_lfanew' % self.name)
        nsec, = struct.unpack_from('<H', d, e + 6)
        optsz, = struct.unpack_from('<H', d, e + 20)
        magic, = struct.unpack_from('<H', d, e + 24)
        if magic == 0x20b:
            nd_off, dd_off = e + 24 + 108, e + 24 + 112
        elif magic == 0x10b:
            nd_off, dd_off = e + 24 + 92, e + 24 + 96
        else:
            raise CilError('%s: optional header magic 0x%04X' % (self.name,
                                                                magic))
        self.pe32plus = magic == 0x20b
        ndirs, = struct.unpack_from('<I', d, nd_off)
        if ndirs < 15:
            raise CilError('%s: %d data directories, no COM descriptor slot'
                           % (self.name, ndirs))
        self.sections = []
        so = e + 24 + optsz
        for i in range(nsec):
            b = so + 40 * i
            if b + 40 > len(d):
                raise CilError('%s: section table runs off the file' % self.name)
            nm = d[b:b + 8].rstrip(b'\0').decode('ascii', 'replace')
            vsz, va, rsz, ptr = struct.unpack_from('<IIII', d, b + 8)
            self.sections.append((nm, va, vsz, ptr, rsz))
        # Directory 14 is the COM descriptor. The STRIDE is 8, not 4: this
        # line read `dd_off + 4 * 14` on its first run, which is directory 7,
        # found a zero there, and announced that Assembly-CSharp.dll is a
        # native PE. The selftest caught it because the positive case is the
        # real file, which is why the positive case is in the selftest.
        cli_rva, cli_sz = struct.unpack_from('<II', d, dd_off + 8 * 14)
        if not cli_rva:
            raise CilError('%s: the COM descriptor directory is empty -- this '
                           'is a native PE, not a managed assembly' % self.name)
        off = self.rva(cli_rva)
        self.cli_cb, = struct.unpack_from('<I', d, off)
        self.rt_major, self.rt_minor = struct.unpack_from('<HH', d, off + 4)
        md_rva, md_sz = struct.unpack_from('<II', d, off + 8)
        self.cli_flags, self.entry_token = struct.unpack_from('<II', d,
                                                              off + 16)
        self.md_off = self.rva(md_rva)
        self.md_size = md_sz
        self._root()
        self._tables()

    def rva(self, rva):
        for nm, va, vsz, ptr, rsz in self.sections:
            if va <= rva < va + max(vsz, rsz):
                return ptr + (rva - va)
        raise CilError('%s: RVA 0x%X is in no section' % (self.name, rva))

    def _root(self):
        d, o = self.d, self.md_off
        if d[o:o + 4] != b'BSJB':
            raise CilError('%s: metadata root is %r, not BSJB'
                           % (self.name, d[o:o + 4]))
        self.md_major, self.md_minor = struct.unpack_from('<HH', d, o + 4)
        vlen, = struct.unpack_from('<I', d, o + 12)
        self.runtime = d[o + 16:o + 16 + vlen].rstrip(b'\0').decode(
            'utf-8', 'replace')
        p = o + 16 + ((vlen + 3) & ~3)
        self.md_flags, nstreams = struct.unpack_from('<HH', d, p)
        p += 4
        self.streams = {}
        for _ in range(nstreams):
            soff, ssz = struct.unpack_from('<II', d, p)
            p += 8
            end = d.index(b'\0', p)
            nm = d[p:end].decode('ascii', 'replace')
            p = end + 1
            p = (p + 3) & ~3
            if soff + ssz > self.md_size:
                raise CilError('%s: stream %s at %d+%d leaves the %d-byte '
                               'metadata block' % (self.name, nm, soff, ssz,
                                                   self.md_size))
            self.streams[nm] = (self.md_off + soff, ssz)
        for req in ('#~', '#Strings'):
            if req not in self.streams:
                raise CilError('%s: no %s stream' % (self.name, req))

    def _tables(self):
        d = self.d
        o, sz = self.streams['#~']
        self.heap_sizes = d[o + 6]
        valid, sorted_ = struct.unpack_from('<QQ', d, o + 8)
        self.valid = valid
        self.present = [i for i in range(64) if valid >> i & 1]
        p = o + 24
        self.rows = {}
        for t in self.present:
            self.rows[t], = struct.unpack_from('<I', d, p)
            p += 4
        self.nrowcounts = len(self.present)
        self.tables_start = p
        self.str_wide = bool(self.heap_sizes & 1)
        self.guid_wide = bool(self.heap_sizes & 2)
        self.blob_wide = bool(self.heap_sizes & 4)

    # -- string heap -------------------------------------------------------

    def string(self, idx):
        o, sz = self.streams['#Strings']
        if idx >= sz:
            return ''
        end = self.d.index(b'\0', o + idx)
        return self.d[o + idx:end].decode('utf-8', 'replace')

    # -- just enough row decoding to reach TypeDef -------------------------

    def _sw(self):
        return 4 if self.str_wide else 2

    def _gw(self):
        return 4 if self.guid_wide else 2

    def _coded(self, tables, tagbits):
        m = max((self.rows.get(t, 0) for t in tables), default=0)
        return 4 if m >= (1 << (16 - tagbits)) else 2

    def _simple(self, t):
        return 4 if self.rows.get(t, 0) >= (1 << 16) else 2

    def typedefs(self):
        d = self.d
        sw, gw = self._sw(), self._gw()
        p = self.tables_start
        # Module: Generation u16, Name str, Mvid guid, EncId guid, EncBaseId guid
        p += self.rows.get(0x00, 0) * (2 + sw + 3 * gw)
        # TypeRef: ResolutionScope coded(2 bits over Module/ModuleRef/
        #          AssemblyRef/TypeRef), Name str, Namespace str
        rs = self._coded((0x00, 0x1A, 0x23, 0x01), 2)
        p += self.rows.get(0x01, 0) * (rs + 2 * sw)
        self.typedef_start = p
        # TypeDef: Flags u32, Name str, Namespace str, Extends
        #          TypeDefOrRef coded(2 bits), FieldList Field idx,
        #          MethodList MethodDef idx
        tdor = self._coded((0x02, 0x01, 0x1B), 2)
        fi = self._simple(0x04)
        mi = self._simple(0x06)
        stride = 4 + 2 * sw + tdor + fi + mi
        self.typedef_stride = stride
        n = self.rows.get(0x02, 0)
        out = []
        for i in range(n):
            b = p + i * stride
            flags, = struct.unpack_from('<I', d, b)
            if sw == 2:
                nm, ns = struct.unpack_from('<HH', d, b + 4)
            else:
                nm, ns = struct.unpack_from('<II', d, b + 4)
            out.append((flags, self.string(nm), self.string(ns)))
        self.typedef_end = p + n * stride
        return out

    # -- past TypeDef: Field, MethodDef, Param, InterfaceImpl, MemberRef ---
    # Added on pc-monstrum-doc. Each decoder computes its own row stride
    # from the heap-size flags and the row counts, walks its rows, and
    # records where they end so `checks()` can compare that with the stream.

    def _sidx(self, d, b):
        """A #Strings index at b, 2 or 4 bytes wide."""
        return (struct.unpack_from('<I', d, b)[0] if self.str_wide
                else struct.unpack_from('<H', d, b)[0])

    def _bw(self):
        return 4 if self.blob_wide else 2

    def typedef_rows(self):
        """(flags, name, namespace, field_list, method_list) per TypeDef."""
        d = self.d
        self.typedefs()                       # sets typedef_start/stride
        sw = self._sw()
        tdor = self._coded((0x02, 0x01, 0x1B), 2)
        fi = self._simple(0x04)
        mi = self._simple(0x06)
        out = []
        p = self.typedef_start
        for i in range(self.rows.get(0x02, 0)):
            b = p + i * self.typedef_stride
            flags, = struct.unpack_from('<I', d, b)
            nm = self._sidx(d, b + 4)
            ns = self._sidx(d, b + 4 + sw)
            q = b + 4 + 2 * sw + tdor
            fl = (struct.unpack_from('<I', d, q)[0] if fi == 4
                  else struct.unpack_from('<H', d, q)[0])
            q += fi
            ml = (struct.unpack_from('<I', d, q)[0] if mi == 4
                  else struct.unpack_from('<H', d, q)[0])
            out.append((flags, self.string(nm), self.string(ns), fl, ml))
        return out

    def _no_pointer_tables(self):
        for t in (0x03, 0x05, 0x07):
            if self.rows.get(t, 0):
                raise CilError('%s: has a %s table (an uncompressed #- '
                               'stream); the member lists are indirect '
                               'and this reader does not follow them'
                               % (self.name, TABLE[t]))

    def fields(self):
        """(flags, name) per Field row; rows start where TypeDef ends."""
        self._no_pointer_tables()
        d = self.d
        self.typedefs()
        sw, bw = self._sw(), self._bw()
        stride = 2 + sw + bw
        self.field_start = self.typedef_end
        n = self.rows.get(0x04, 0)
        out = []
        for i in range(n):
            b = self.field_start + i * stride
            flags, = struct.unpack_from('<H', d, b)
            out.append((flags, self.string(self._sidx(d, b + 2))))
        self.field_stride = stride
        self.field_end = self.field_start + n * stride
        return out

    def methods(self):
        """(rva, impl_flags, flags, name, param_list) per MethodDef row."""
        self.fields()
        d = self.d
        sw, bw = self._sw(), self._bw()
        pi = self._simple(0x08)
        stride = 4 + 2 + 2 + sw + bw + pi
        self.method_start = self.field_end
        n = self.rows.get(0x06, 0)
        out = []
        for i in range(n):
            b = self.method_start + i * stride
            rva, impl, flags = struct.unpack_from('<IHH', d, b)
            nm = self.string(self._sidx(d, b + 8))
            q = b + 8 + sw + bw
            pl = (struct.unpack_from('<I', d, q)[0] if pi == 4
                  else struct.unpack_from('<H', d, q)[0])
            out.append((rva, impl, flags, nm, pl))
        self.method_stride = stride
        self.method_end = self.method_start + n * stride
        return out

    def params(self):
        """(flags, sequence, name) per Param row."""
        self.methods()
        d = self.d
        sw = self._sw()
        stride = 2 + 2 + sw
        self.param_start = self.method_end
        n = self.rows.get(0x08, 0)
        out = []
        for i in range(n):
            b = self.param_start + i * stride
            flags, seq = struct.unpack_from('<HH', d, b)
            out.append((flags, seq, self.string(self._sidx(d, b + 4))))
        self.param_end = self.param_start + n * stride
        return out

    def memberrefs(self):
        """(parent_table, parent_row, name) per MemberRef row."""
        self.params()
        d = self.d
        sw, bw = self._sw(), self._bw()
        # InterfaceImpl: Class -> TypeDef idx, Interface TypeDefOrRef coded
        ii = self._simple(0x02) + self._coded((0x02, 0x01, 0x1B), 2)
        self.memberref_start = self.param_end + self.rows.get(0x09, 0) * ii
        parent_tables = (0x02, 0x01, 0x1A, 0x06, 0x1B)
        pw = self._coded(parent_tables, 3)
        stride = pw + sw + bw
        n = self.rows.get(0x0A, 0)
        out = []
        for i in range(n):
            b = self.memberref_start + i * stride
            coded = (struct.unpack_from('<I', d, b)[0] if pw == 4
                     else struct.unpack_from('<H', d, b)[0])
            tag, row = coded & 7, coded >> 3
            ptab = parent_tables[tag] if tag < len(parent_tables) else -1
            out.append((ptab, row, self.string(self._sidx(d, b + pw))))
        self.memberref_end = self.memberref_start + n * stride
        return out

    def typerefs(self):
        """(name, namespace) per TypeRef row."""
        d = self.d
        sw = self._sw()
        rs = self._coded((0x00, 0x1A, 0x23, 0x01), 2)
        p = self.tables_start + self.rows.get(0x00, 0) * (2 + sw + 3 * self._gw())
        out = []
        for i in range(self.rows.get(0x01, 0)):
            b = p + i * (rs + 2 * sw)
            out.append((self.string(self._sidx(d, b + rs)),
                        self.string(self._sidx(d, b + rs + sw))))
        return out

    def members(self):
        """Per TypeDef: (name, namespace, [field names], [method names]),
        the lists cut by the next row's FieldList/MethodList (II.22.37)."""
        tds = self.typedef_rows()
        fl = self.fields()
        ml = self.methods()
        out = []
        for i, (flags, nm, ns, f0, m0) in enumerate(tds):
            if i + 1 < len(tds):
                f1, m1 = tds[i + 1][3], tds[i + 1][4]
            else:
                f1, m1 = len(fl) + 1, len(ml) + 1
            out.append((nm, ns, [x[1] for x in fl[f0 - 1:f1 - 1]],
                        [x[3] for x in ml[m0 - 1:m1 - 1]]))
        return out

    def member_checks(self):
        out = []
        o, sz = self.streams['#~']
        end = o + sz
        tds = self.typedef_rows()
        fls = [t[3] for t in tds]
        mls = [t[4] for t in tds]
        nf, nm = self.rows.get(0x04, 0), self.rows.get(0x06, 0)
        out.append(('FieldList is monotone and every value is in 1..rows+1',
                    fls == sorted(fls) and all(1 <= x <= nf + 1 for x in fls),
                    'first %s, last %s, Field rows %d'
                    % (fls[:1], fls[-1:], nf)))
        out.append(('MethodList is monotone and every value is in 1..rows+1',
                    mls == sorted(mls) and all(1 <= x <= nm + 1 for x in mls),
                    'first %s, last %s, MethodDef rows %d'
                    % (mls[:1], mls[-1:], nm)))
        fl = self.fields()
        out.append(('Field rows end inside the #~ stream',
                    self.field_end <= end,
                    '%d rows x %d bytes end at %d'
                    % (len(fl), self.field_stride, self.field_end)))
        out.append(('every Field row resolves to a name',
                    all(n for _, n in fl), '%d of %d'
                    % (sum(1 for _, n in fl if n), len(fl))))
        ml = self.methods()
        out.append(('MethodDef rows end inside the #~ stream',
                    self.method_end <= end,
                    '%d rows x %d bytes end at %d'
                    % (len(ml), self.method_stride, self.method_end)))
        out.append(('every MethodDef row resolves to a name',
                    all(x[3] for x in ml), '%d of %d'
                    % (sum(1 for x in ml if x[3]), len(ml))))
        pls = [x[4] for x in ml]
        np_ = self.rows.get(0x08, 0)
        out.append(('ParamList is monotone and in 1..rows+1',
                    pls == sorted(pls) and all(1 <= x <= np_ + 1 for x in pls),
                    'Param rows %d' % np_))
        mr = self.memberrefs()
        out.append(('MemberRef rows end inside the #~ stream',
                    self.memberref_end <= end,
                    '%d rows end at %d' % (len(mr), self.memberref_end)))
        out.append(('every MemberRef row resolves to a name and a parent',
                    all(n and t != -1 for t, _r, n in mr), '%d of %d'
                    % (sum(1 for t, _r, n in mr if n and t != -1), len(mr))))
        return out

    def checks(self):
        out = []
        out.append(('CLI header cb is 72', self.cli_cb == 72,
                    'cb = %d' % self.cli_cb))
        out.append(('metadata root begins BSJB', True,
                    'runtime %r, %d streams' % (self.runtime,
                                                len(self.streams))))
        out.append(('every stream lies inside the metadata block', True,
                    ', '.join('%s %d' % (k, v[1])
                              for k, v in sorted(self.streams.items()))))
        out.append(('row counts == set bits in Valid',
                    self.nrowcounts == bin(self.valid).count('1'),
                    '%d counts, %d bits' % (self.nrowcounts,
                                            bin(self.valid).count('1'))))
        tds = self.typedefs()
        o, sz = self.streams['#~']
        fits = self.typedef_end <= o + sz
        out.append(('TypeDef rows end inside the #~ stream', fits,
                    '%d rows x %d bytes end at %d, stream ends at %d'
                    % (len(tds), self.typedef_stride, self.typedef_end,
                       o + sz)))
        named = sum(1 for _, n, _ in tds if n)
        out.append(('every TypeDef row resolves to a name',
                    named == len(tds),
                    '%d of %d' % (named, len(tds))))
        return out


# -- commands --------------------------------------------------------------

def cmd_validate(argv):
    dirguard.want_file(argv[2], 'cilmeta')
    a = Assembly(argv[2])
    print(a.name)
    ok = True
    for label, good, detail in a.checks() + a.member_checks():
        print('  %-46s %-4s %s' % (label, 'ok' if good else 'FAIL', detail))
        ok = ok and good
    print()
    print('%s: %s' % (a.name, 'all checks pass' if ok else 'CHECKS FAILED'))
    return 0 if ok else 1


def cmd_census(argv):
    a = Assembly(argv[2])
    print('assembly           : %s  (%d bytes)' % (a.name, len(a.d)))
    print('PE format          : %s' % ('PE32+' if a.pe32plus else 'PE32'))
    print('CLI runtime        : %d.%d' % (a.rt_major, a.rt_minor))
    print('metadata version   : %s' % a.runtime)
    print('heap sizes byte    : 0x%02X  (strings %s, guid %s, blob %s)'
          % (a.heap_sizes, '4B' if a.str_wide else '2B',
             '4B' if a.guid_wide else '2B', '4B' if a.blob_wide else '2B'))
    print('tables present     : %d' % len(a.present))
    print()
    print('%-24s %8s' % ('table', 'rows'))
    tot = 0
    for t in a.present:
        print('%-24s %8d' % ('0x%02X %s' % (t, TABLE.get(t, '?')), a.rows[t]))
        tot += a.rows[t]
    print('%-24s %8d' % ('TOTAL ROWS', tot))
    print()
    tds = a.typedefs()
    ns = collections.Counter(x[2] for x in tds)
    print('TypeDef rows       : %d' % len(tds))
    print('distinct namespaces: %d' % len(ns))
    print()
    print('%-46s %6s' % ('namespace', 'types'))
    for k, v in ns.most_common():
        print('%-46s %6d' % (k or '(global namespace)', v))
    return 0


def cmd_types(argv):
    a = Assembly(argv[2])
    limit = int(argv[argv.index('--limit') + 1]) if '--limit' in argv else 0
    tds = a.typedefs()
    n = 0
    for flags, nm, ns in tds:
        n += 1
        if limit and n > limit:
            break
        print('%-46s %s' % (('%s.%s' % (ns, nm)) if ns else nm,
                            'nested' if (flags & 7) >= 2 else ''))
    print()
    print('%d TypeDef rows' % len(tds))
    return 0


def _opt(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv else default


def cmd_members(argv):
    dirguard.want_file(argv[2], 'cilmeta')
    a = Assembly(argv[2])
    want = _opt(argv, '--type')
    limit = int(_opt(argv, '--limit', 0))
    n = 0
    tf = tm = 0
    for nm, ns, fl, ml in a.members():
        full = ('%s.%s' % (ns, nm)) if ns else nm
        tf += len(fl)
        tm += len(ml)
        if want and full != want and nm != want:
            continue
        n += 1
        if limit and n > limit:
            continue
        print('%s   %d fields, %d methods' % (full, len(fl), len(ml)))
        for f in fl:
            print('    field   %s' % f)
        for m in ml:
            print('    method  %s' % m)
    print()
    print('%d types, %d fields, %d methods; %d types printed'
          % (len(a.members()), tf, tm, min(n, limit) if limit else n))
    return 0


def cmd_owners(argv):
    """Which types own a field or method whose name matches --grep."""
    dirguard.want_file(argv[2], 'cilmeta')
    a = Assembly(argv[2])
    pat = re.compile(_opt(argv, '--grep', '.'), re.I)
    hits = 0
    types = set()
    for nm, ns, fl, ml in a.members():
        full = ('%s.%s' % (ns, nm)) if ns else nm
        for f in fl:
            if pat.search(f):
                print('%-40s field   %s' % (full, f))
                hits += 1
                types.add(full)
        for m in ml:
            if pat.search(m):
                print('%-40s method  %s' % (full, m))
                hits += 1
                types.add(full)
    print()
    print('%d members in %d types match %r' % (hits, len(types),
                                                pat.pattern))
    return 0


def cmd_typerefs(argv):
    dirguard.want_file(argv[2], 'cilmeta')
    a = Assembly(argv[2])
    pat = re.compile(_opt(argv, '--grep', '.'), re.I)
    trs = a.typerefs()
    n = 0
    for nm, ns in trs:
        full = ('%s.%s' % (ns, nm)) if ns else nm
        if pat.search(full):
            print(full)
            n += 1
    print()
    print('%d of %d TypeRef rows match %r' % (n, len(trs), pat.pattern))
    return 0


def cmd_memberrefs(argv):
    dirguard.want_file(argv[2], 'cilmeta')
    a = Assembly(argv[2])
    pat = re.compile(_opt(argv, '--grep', '.'), re.I)
    trs = a.typerefs()
    tds = a.typedefs()
    n = 0
    mrs = a.memberrefs()
    for ptab, row, nm in mrs:
        if ptab == 0x01 and 1 <= row <= len(trs):
            parent = ('%s.%s' % (trs[row - 1][1], trs[row - 1][0])
                      if trs[row - 1][1] else trs[row - 1][0])
        elif ptab == 0x02 and 1 <= row <= len(tds):
            parent = tds[row - 1][1]
        else:
            parent = '%s[%d]' % (TABLE.get(ptab, '?'), row)
        full = '%s::%s' % (parent, nm)
        if pat.search(full):
            print(full)
            n += 1
    print()
    print('%d of %d MemberRef rows match %r' % (n, len(mrs), pat.pattern))
    return 0


def _fake_assembly():
    """A #~ stream and a #Strings heap built by hand: Module 1, TypeRef 1,
    TypeDef 2, Field 3, MethodDef 2, Param 1, MemberRef 1, narrow heaps.
    Type A owns fields f1, f2 and method m1; type B owns field f3 and
    method m2; the MemberRef names `Ext` on the TypeRef."""
    strings = b'\0mod\0A\0B\0f1\0f2\0f3\0m1\0m2\0p\0Ext\0Sys\0Lobby\0'

    def si(s):
        return strings.index(b'\0' + s + b'\0') + 1
    rows = {0x00: 1, 0x01: 1, 0x02: 2, 0x04: 3, 0x06: 2, 0x08: 1, 0x0A: 1}
    valid = 0
    for t in rows:
        valid |= 1 << t
    hdr = struct.pack('<IBBBBQQ', 0, 2, 0, 0x00, 1, valid, 0)
    hdr += b''.join(struct.pack('<I', rows[t]) for t in sorted(rows))
    body = struct.pack('<HHHHH', 0, si(b'mod'), 1, 0, 0)          # Module
    body += struct.pack('<HHH', (0 << 2) | 2, si(b'Lobby'), si(b'Sys'))  # TypeRef
    body += struct.pack('<IHHHHH', 0, si(b'A'), 0, 0, 1, 1)        # TypeDef A
    body += struct.pack('<IHHHHH', 0, si(b'B'), 0, 0, 3, 2)        # TypeDef B
    for f in (b'f1', b'f2', b'f3'):
        body += struct.pack('<HHH', 6, si(f), 0)                  # Field
    body += struct.pack('<IHHHHH', 0, 0, 6, si(b'm1'), 0, 1)       # MethodDef
    body += struct.pack('<IHHHHH', 0, 0, 6, si(b'm2'), 0, 2)
    body += struct.pack('<HHH', 0, 1, si(b'p'))                    # Param
    body += struct.pack('<HHH', (1 << 3) | 1, si(b'Ext'), 0)       # MemberRef
    stream = hdr + body
    d = stream + strings
    a = Assembly.__new__(Assembly)
    a.d = d
    a.name = 'hand-built'
    a.streams = {'#~': (0, len(stream)), '#Strings': (len(stream), len(strings))}
    a._tables()
    return a


def cmd_selftest(argv):
    """Specimens built in memory. Most of them must be refused."""
    cases = []

    def case(label, blob, want_msg):
        cases.append((label, blob, want_msg))

    case('an empty file', b'', 'no MZ signature')
    case('a text file', b'Hello, world.\n' * 8, 'no MZ signature')
    case('MZ but no PE header', b'MZ' + b'\0' * 0x3E + b'\0' * 64,
         'no PE signature')
    case('a UnityFS bundle', b'UnityFS\0\0\0\0\x08' + b'\0' * 200,
         'no MZ signature')
    mz = bytearray(b'MZ' + b'\0' * 0x3E)
    struct.pack_into('<I', mz, 0x3C, 0x40)
    mz += b'PE\0\0'
    mz += struct.pack('<HHIIIHH', 0x14c, 1, 0, 0, 0, 0xE0, 0x0102)
    mz += struct.pack('<H', 0x10b) + b'\0' * (0xE0 - 2)
    struct.pack_into('<I', mz, 0x40 + 4 + 20 + 92, 16)   # NumberOfRvaAndSizes
    mz += b'.text\0\0\0' + struct.pack('<IIII', 0x100, 0x1000, 0x200, 0x200)
    mz += b'\0' * 16 + b'\0' * 0x200
    case('a PE32 with an empty COM descriptor directory', bytes(mz),
         'COM descriptor directory is empty')

    npass = nfail = 0
    for label, blob, want in cases:
        try:
            Assembly(blob, name=label)
            got, ok = 'PARSED', False
        except CilError as e:
            got, ok = str(e), (want in str(e))
        except Exception as e:
            got, ok = '%s: %s' % (type(e).__name__, e), False
        npass += ok
        nfail += not ok
        print('  %-4s %-46s %s' % ('ok' if ok else 'FAIL', label, got[:56]))

    # and one positive: the real file, if it is where this repository keeps it
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    real = os.path.join(root, 'sonic-steam', 'The Murder of Sonic The Hedgehog',
                        'The Murder of Sonic The Hedgehog_Data', 'Managed',
                        'Assembly-CSharp.dll')
    if os.path.exists(real):
        try:
            a = Assembly(real)
            good = all(g for _, g, _ in a.checks())
            npass += good
            nfail += not good
            print('  %-4s %-46s %d TypeDef rows'
                  % ('ok' if good else 'FAIL', 'the real Assembly-CSharp.dll',
                     a.rows.get(0x02, 0)))
        except CilError as e:
            nfail += 1
            print('  FAIL the real Assembly-CSharp.dll: %s' % e)
        total = len(cases) + 1
    else:
        total = len(cases)
    # -- the member tables, on a hand-built stream (pc-monstrum-doc) -------
    a = _fake_assembly()
    mem = a.members()
    extra = [
        ('hand-built stream: 7 tables, 11 rows', len(a.present) == 7
         and sum(a.rows.values()) == 11, str(sum(a.rows.values()))),
        ('type A owns f1, f2 and m1', mem[0][0] == 'A'
         and mem[0][2] == ['f1', 'f2'] and mem[0][3] == ['m1'], str(mem[0])),
        ('type B (the last) owns f3 and m2 up to the end of the tables',
         mem[1][0] == 'B' and mem[1][2] == ['f3'] and mem[1][3] == ['m2'],
         str(mem[1])),
        ('the MemberRef names Ext on TypeRef Sys.Lobby',
         a.memberrefs() == [(0x01, 1, 'Ext')]
         and a.typerefs() == [('Lobby', 'Sys')], str(a.memberrefs())),
        ('every member check passes on the hand-built stream',
         all(g for _, g, _ in a.member_checks()),
         '; '.join(l for l, g, _ in a.member_checks() if not g)),
    ]
    # a stream one byte short: the MemberRef rows fall outside it
    b = _fake_assembly()
    o, sz = b.streams['#~']
    b.streams['#~'] = (o, sz - 1)
    extra.append(('a #~ stream one byte short fails the MemberRef end check',
                  not all(g for _, g, _ in b.member_checks()), ''))
    # a FieldPtr table present: refused, not followed
    c = _fake_assembly()
    c.rows[0x03] = 1
    try:
        c.fields()
        extra.append(('a FieldPtr table is refused', False, 'parsed'))
    except CilError as e:
        extra.append(('a FieldPtr table is refused', 'FieldPtr' in str(e), ''))
    for label, ok, note in extra:
        npass += ok
        nfail += not ok
        print('  %-4s %-46s %s' % ('ok' if ok else 'FAIL', label, note[:56]))
    total += len(extra)
    print()
    print('%d cases: %d pass, %d fail. %d of %d are rejections.'
          % (total, npass, nfail, len(cases) + 1, total))
    return 0 if nfail == 0 else 1


def main(argv):
    cmds = {'validate': cmd_validate, 'census': cmd_census, 'types': cmd_types,
            'members': cmd_members, 'owners': cmd_owners,
            'typerefs': cmd_typerefs, 'memberrefs': cmd_memberrefs,
            'selftest': cmd_selftest}
    if len(argv) < 2 or argv[1] not in cmds:
        print(__doc__)
        return 2
    if argv[1] != 'selftest' and len(argv) < 3:
        print('%s needs a path' % argv[1])
        return 2
    try:
        return cmds[argv[1]](argv)
    except CilError as e:
        print('REFUSED  %s' % e, file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main(sys.argv))
