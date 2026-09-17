#!/usr/bin/env python3
"""Read an ELF shared object with no toolchain: headers, sections, segments,
dynamic symbols, initialisers, and how much of `.text` is actually there.

Written for the Android build of *Tales of Luminaria*, but the reason it exists
is a trap section 7 of tales-blockcodec-doc documents in four forms.  On *Tales
of Crestoria* -- the other Android title in this corpus -- `libEpic.so` ships
with 99.7% of `.text` zero-filled and the real image appended past the end of
every loadable segment as an encrypted blob.  A constant scan over a `.text` of
zeros returns zero, and zero is indistinguishable from a clean negative.

So before any scan of a native image, measure the image:

  * `zero`     -- how much of each executable section is zero bytes.  A normal
                  compiled `.text` runs a few per cent; a hollowed one runs
                  above ninety.
  * `entropy`  -- Shannon entropy per section and for the tail past the last
                  segment.  Compiled ARM code sits near 6 bits/byte; an
                  encrypted blob sits above 7.9.
  * `overlay`  -- bytes in the file that no PT_LOAD segment covers.  That is
                  where Crestoria's 24 MB lives.
  * `init`     -- DT_INIT and DT_INIT_ARRAY: how many initialisers there are,
                  and how many point inside bytes that have any content.

None of those measurements is a claim about protection by itself.  Together
they say whether a scan of this file is a scan of the code.

    python elfinfo.py FILE header
    python elfinfo.py FILE sections
    python elfinfo.py FILE segments
    python elfinfo.py FILE dynsym  [--defined] [--grep PATTERN]
    python elfinfo.py FILE init
    python elfinfo.py FILE zero    [--block N]
    python elfinfo.py FILE entropy [--block N]
    python elfinfo.py FILE overlay
    python elfinfo.py FILE exec
    python elfinfo.py FILE runs    [--least N] [--top N]
    python elfinfo.py DIR  census
    python elfinfo.py FILE summary
    python elfinfo.py FILE text

The last one prints the offset, size and load address of .text in the form
ring_sites.py wants for --off / --size / --base, so that a constant scan is a
scan of the executable section rather than of the whole file.

Standard library only.
"""

import math
import struct
import sys

ET = {0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}
EM = {3: 'x86', 40: 'ARM', 62: 'x86-64', 183: 'AArch64'}
PT = {0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB',
      6: 'PHDR', 7: 'TLS', 0x6474E550: 'GNU_EH_FRAME', 0x6474E551: 'GNU_STACK',
      0x6474E552: 'GNU_RELRO', 0x70000001: 'ARM_EXIDX'}
SHT = {0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
       5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL',
       11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY', 16: 'PREINIT_ARRAY',
       17: 'GROUP', 18: 'SYMTAB_SHNDX', 0x6FFFFFF6: 'GNU_HASH',
       0x6FFFFFFD: 'GNU_verdef', 0x6FFFFFFE: 'GNU_verneed',
       0x6FFFFFFF: 'GNU_versym', 0x70000001: 'ARM_EXIDX',
       0x70000003: 'ARM_ATTRIBUTES'}
STT = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE',
       6: 'TLS', 10: 'GNU_IFUNC'}
STB = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK'}


class Elf(object):
    def __init__(self, data):
        self.data = data
        if data[:4] != b'\x7fELF':
            raise ValueError('not an ELF file')
        self.cls = data[4]
        self.le = data[5] == 1
        self.bits = 64 if self.cls == 2 else 32
        e = '<' if self.le else '>'
        self.e = e
        if self.bits == 64:
            (self.type, self.machine, _v, self.entry, self.phoff, self.shoff,
             self.flags, self.ehsize, self.phentsize, self.phnum,
             self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from(
                e + 'HHIQQQIHHHHHH', data, 16)
        else:
            (self.type, self.machine, _v, self.entry, self.phoff, self.shoff,
             self.flags, self.ehsize, self.phentsize, self.phnum,
             self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from(
                e + 'HHIIIIIHHHHHH', data, 16)
        self._read_sections()
        self._read_segments()

    def _read_sections(self):
        self.sections = []
        e = self.e
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            if o + self.shentsize > len(self.data):
                break
            if self.bits == 64:
                v = struct.unpack_from(e + 'IIQQQQIIQQ', self.data, o)
            else:
                v = struct.unpack_from(e + 'IIIIIIIIII', self.data, o)
            nm, ty, fl, addr, off, size, link, info, align, entsize = v
            self.sections.append(dict(nameoff=nm, type=ty, flags=fl, addr=addr,
                                      off=off, size=size, link=link, info=info,
                                      align=align, entsize=entsize, name='?'))
        if self.shstrndx < len(self.sections):
            base = self.sections[self.shstrndx]['off']
            for s in self.sections:
                s['name'] = self.cstr(base + s['nameoff'])

    def _read_segments(self):
        self.segments = []
        e = self.e
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            if o + self.phentsize > len(self.data):
                break
            if self.bits == 64:
                ty, fl, off, va, pa, filesz, memsz, align = struct.unpack_from(
                    e + 'IIQQQQQQ', self.data, o)
            else:
                ty, off, va, pa, filesz, memsz, fl, align = struct.unpack_from(
                    e + 'IIIIIIII', self.data, o)
            self.segments.append(dict(type=ty, flags=fl, off=off, vaddr=va,
                                      filesz=filesz, memsz=memsz, align=align))

    def cstr(self, off):
        if off <= 0 or off >= len(self.data):
            return ''
        end = self.data.find(b'\0', off)
        if end < 0:
            end = len(self.data)
        return self.data[off:end].decode('utf-8', 'replace')

    def section(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def body(self, s):
        if s['type'] == 8:
            return b''
        return self.data[s['off']:s['off'] + s['size']]

    def dynamic(self):
        s = self.section('.dynamic')
        if s is None:
            for p in self.segments:
                if p['type'] == 2:
                    s = dict(off=p['off'], size=p['filesz'], type=1)
                    break
        if s is None:
            return []
        out = []
        fmt = self.e + ('QQ' if self.bits == 64 else 'II')
        step = 16 if self.bits == 64 else 8
        for o in range(s['off'], s['off'] + s['size'] - step + 1, step):
            tag, val = struct.unpack_from(fmt, self.data, o)
            out.append((tag, val))
            if tag == 0:
                break
        return out

    def vaddr_to_off(self, va):
        for p in self.segments:
            if p['type'] == 1 and p['vaddr'] <= va < p['vaddr'] + p['filesz']:
                return p['off'] + (va - p['vaddr'])
        return None

    def dynsym(self):
        sym = self.section('.dynsym')
        strt = self.section('.dynstr')
        if sym is None or strt is None:
            return []
        sbase = strt['off']
        out = []
        if self.bits == 64:
            step, fmt = 24, self.e + 'IBBHQQ'
        else:
            step, fmt = 16, self.e + 'IIIBBH'
        for o in range(sym['off'], sym['off'] + sym['size'] - step + 1, step):
            if self.bits == 64:
                nm, info, other, shndx, value, size = struct.unpack_from(
                    fmt, self.data, o)
            else:
                nm, value, size, info, other, shndx = struct.unpack_from(
                    fmt, self.data, o)
            out.append(dict(name=self.cstr(sbase + nm), value=value, size=size,
                            type=info & 0xF, bind=info >> 4, shndx=shndx))
        return out

    def init_array(self):
        d = {}
        for tag, val in self.dynamic():
            d.setdefault(tag, val)
        init = d.get(12)
        arr, arrsz = d.get(25), d.get(27, 0)
        addrs = []
        if arr is not None and arrsz:
            off = self.vaddr_to_off(arr)
            if off is not None:
                step = 8 if self.bits == 64 else 4
                fmt = self.e + ('Q' if self.bits == 64 else 'I')
                for i in range(0, arrsz, step):
                    if off + i + step <= len(self.data):
                        addrs.append(struct.unpack_from(fmt, self.data, off + i)[0])
        return init, addrs


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    return -sum((k / n) * math.log2(k / n) for k in c if k)


def zerofrac(b):
    return b.count(0) / len(b) if b else 0.0


def cmd_header(e, argv):
    print('class          ELF%d, %s-endian' % (e.bits, 'little' if e.le else 'big'))
    print('type           %s' % ET.get(e.type, hex(e.type)))
    print('machine        %s (%d)' % (EM.get(e.machine, '?'), e.machine))
    print('entry          0x%X' % e.entry)
    print('sections       %d' % e.shnum)
    print('segments       %d' % e.phnum)
    d = e.dynamic()
    strt = e.section('.dynstr')
    soname = None
    needed = []
    for tag, val in d:
        if strt and tag == 14:
            soname = e.cstr(strt['off'] + val)
        if strt and tag == 1:
            needed.append(e.cstr(strt['off'] + val))
    print('soname         %s' % (soname or '(none)'))
    print('needed         %s' % (', '.join(needed) if needed else '(none)'))
    bid = e.section('.note.gnu.build-id')
    if bid:
        print('build-id       %s' % e.body(bid)[16:].hex())
    com = e.section('.comment')
    if com:
        parts = [p.decode('utf-8', 'replace')
                 for p in e.body(com).split(b'\0') if p]
        for p in parts:
            print('comment        %s' % p)


def cmd_sections(e, argv):
    print('%-26s %-12s %12s %12s %12s %8s %8s' %
          ('NAME', 'TYPE', 'ADDR', 'OFFSET', 'SIZE', 'ZERO%', 'ENTROPY'))
    for s in e.sections:
        b = e.body(s)
        z = '%7.2f' % (zerofrac(b) * 100) if b else '      -'
        h = '%7.3f' % entropy(b) if b else '      -'
        print('%-26s %-12s 0x%010X %12d %12d %8s %8s' %
              (s['name'][:26], SHT.get(s['type'], hex(s['type'])),
               s['addr'], s['off'], s['size'], z, h))


def cmd_segments(e, argv):
    print('%-14s %-6s %12s %12s %14s %14s' %
          ('TYPE', 'FLAGS', 'OFFSET', 'VADDR', 'FILESZ', 'MEMSZ'))
    for p in e.segments:
        fl = ''.join(c for c, bit in (('R', 4), ('W', 2), ('X', 1))
                     if p['flags'] & bit)
        print('%-14s %-6s %12d 0x%010X %14d %14d' %
              (PT.get(p['type'], hex(p['type'])), fl, p['off'], p['vaddr'],
               p['filesz'], p['memsz']))


def cmd_overlay(e, argv):
    loads = [p for p in e.segments if p['type'] == 1]
    end = max((p['off'] + p['filesz']) for p in loads) if loads else 0
    sh_end = e.shoff + e.shnum * e.shentsize
    n = len(e.data)
    cut = max(end, sh_end)
    print('file size                       %14d' % n)
    print('last byte covered by a PT_LOAD  %14d' % end)
    print('section headers end at          %14d' % sh_end)
    tail = n - cut
    print('bytes past both                 %14d  (%.4f%% of the file)'
          % (tail, 100.0 * tail / n if n else 0))
    if tail > 0:
        b = e.data[cut:]
        print('  entropy of that tail          %14.4f bits/byte' % entropy(b))
        print('  zero fraction                 %13.2f%%' % (zerofrac(b) * 100))
        print('  first 32 bytes                %s' % b[:32].hex())
    else:
        print('  nothing lives past the last loadable segment.')


def cmd_zero(e, argv):
    blk = int(argv[argv.index('--block') + 1]) if '--block' in argv else 4096
    print('Zero-byte fraction per section, and how many %d-byte blocks inside' % blk)
    print('each are entirely zero.  A compiled .text runs a few per cent; the')
    print('hollowed libEpic.so of Tales of Crestoria runs 99.7%.')
    print()
    print('%-26s %12s %9s %10s %10s' %
          ('SECTION', 'SIZE', 'ZERO%', 'ZEROBLKS', 'BLOCKS'))
    for s in e.sections:
        b = e.body(s)
        if not b:
            continue
        nb = zb = 0
        for i in range(0, len(b), blk):
            nb += 1
            if not any(b[i:i + blk]):
                zb += 1
        print('%-26s %12d %8.2f%% %10d %10d' %
              (s['name'][:26], len(b), zerofrac(b) * 100, zb, nb))


def cmd_entropy(e, argv):
    blk = int(argv[argv.index('--block') + 1]) if '--block' in argv else 65536
    print('Shannon entropy, bits per byte.  Compiled ARM sits near 6; packed or')
    print('encrypted data sits above 7.9; a run of zeros sits at 0.')
    print()
    print('%-26s %12s %10s' % ('SECTION', 'SIZE', 'ENTROPY'))
    for s in e.sections:
        b = e.body(s)
        if not b:
            continue
        print('%-26s %12d %10.4f' % (s['name'][:26], len(b), entropy(b)))
    print()
    n = len(e.data)
    hi = tot = 0
    for i in range(0, n, blk):
        tot += 1
        if entropy(e.data[i:i + blk]) > 7.9:
            hi += 1
    print('whole file in %d-byte blocks: %d of %d above 7.9 bits/byte (%.2f%%)'
          % (blk, hi, tot, 100.0 * hi / tot if tot else 0))


def cmd_dynsym(e, argv):
    syms = e.dynsym()
    pat = argv[argv.index('--grep') + 1].lower() if '--grep' in argv else None
    defined = '--defined' in argv
    n = 0
    for s in syms:
        if defined and s['shndx'] == 0:
            continue
        if pat and pat not in s['name'].lower():
            continue
        n += 1
        print('0x%012X %10d %-8s %-7s %s' %
              (s['value'], s['size'], STT.get(s['type'], '?'),
               STB.get(s['bind'], '?'), s['name']))
    print()
    print('%d of %d dynamic symbols listed' % (n, len(syms)))


def cmd_init(e, argv):
    init, addrs = e.init_array()
    print('DT_INIT        %s' % ('0x%X' % init if init else '(none)'))
    print('DT_INIT_ARRAY  %d entries' % len(addrs))
    if not addrs:
        return
    print()
    print('%-16s %-26s %s' % ('ADDRESS', 'SECTION', 'BYTES THERE'))
    live = dead = outside = 0
    for a in addrs:
        t = a & ~1
        off = e.vaddr_to_off(t)
        sec = '?'
        for s in e.sections:
            if s['flags'] & 2 and s['addr'] <= t < s['addr'] + s['size']:
                sec = s['name']
                break
        if off is None:
            outside += 1
            what = 'outside every PT_LOAD'
        else:
            w = e.data[off:off + 16]
            if not any(w):
                dead += 1
                what = 'zero-filled'
            else:
                live += 1
                what = w[:8].hex()
        print('0x%014X %-26s %s' % (a, sec[:26], what))
    print()
    print('%d point at bytes with content, %d at zero-fill, %d outside a segment'
          % (live, dead, outside))


def exec_regions(e):
    """The executable bytes of the file, named however they can be named.

    A stripped library has no .text -- AppGuard's rewrite of libil2cpp.so keeps
    four section headers and none of them is code -- so the section table
    cannot be the unit of measurement.  The program headers survive, because
    the loader needs them, and PT_LOAD with PF_X is the executable image
    whether or not anything names it.  Prefer .text when it is there, because
    it is narrower; fall back to the segment when it is not, and say which was
    used, so a zero fraction is never quoted without saying what it is over.
    """
    t = e.section('.text')
    if t is not None and t['size'] and t['type'] != 8:
        return [('.text (section)', t['off'], t['size'], t['addr'])]
    out = []
    for i, p in enumerate(e.segments):
        if p['type'] == 1 and p['flags'] & 1 and p['filesz']:
            out.append(('PT_LOAD #%d, PF_X (segment)' % i,
                        p['off'], p['filesz'], p['vaddr']))
    return out


def cmd_exec(e, argv):
    regs = exec_regions(e)
    if not regs:
        print('no executable bytes in this file at all.')
        return
    print('The executable image, measured.  Where a .text section survives it')
    print('is used; where it does not, every executable PT_LOAD is, because a')
    print('stripped library still has to tell the loader what to map.')
    print()
    print('%-34s %12s %12s %9s %9s' %
          ('REGION', 'OFFSET', 'SIZE', 'ZERO%', 'ENTROPY'))
    for name, off, size, va in regs:
        b = e.data[off:off + size]
        print('%-34s %12d %12d %8.2f%% %9.4f' %
              (name, off, size, zerofrac(b) * 100, entropy(b)))
    print()
    for name, off, size, va in regs:
        b = e.data[off:off + size]
        blk = 4096
        nb = zb = 0
        for i in range(0, len(b), blk):
            nb += 1
            if not any(b[i:i + blk]):
                zb += 1
        print('%s: %d of %d 4096-byte blocks entirely zero (%.2f%%)'
              % (name, zb, nb, 100.0 * zb / nb if nb else 0))


def cmd_text(e, argv):
    for name, off, size, va in exec_regions(e):
        print('%s' % name)
        print('  offset 0x%X  size %d  vaddr 0x%X' % (off, size, va))
        print('  feed:  --off %d --size %d --base %d' % (off, size, va))
    if not exec_regions(e):
        print('no executable bytes')


def cmd_summary(e, argv):
    cmd_header(e, argv)
    print()
    for name, off, size, va in exec_regions(e):
        b = e.data[off:off + size]
        print('executable     %-30s %d bytes, %.2f%% zero, entropy %.3f'
              % (name, len(b), zerofrac(b) * 100, entropy(b)))
    if not exec_regions(e):
        print('executable     none')
    print()
    cmd_overlay(e, argv)
    print()
    init, addrs = e.init_array()
    live = 0
    for a in addrs:
        off = e.vaddr_to_off(a & ~1)
        if off is not None and any(e.data[off:off + 16]):
            live += 1
    print('initialisers   %d in DT_INIT_ARRAY, %d point at bytes with content'
          % (len(addrs), live))


def cmd_runs(e, argv):
    """The longest contiguous zero runs in the file, with where they are.

    A hollowed library and a normally-linked one both contain zeros; what
    separates them is the shape.  Ordinary alignment padding gives thousands of
    runs of a few bytes.  A hollowed .text gives one run of megabytes.  Printing
    the runs rather than the fraction is what tells the two apart, and it is
    also what says whether a zero fraction over a whole segment is one hole or
    a scatter.
    """
    least = int(argv[argv.index('--least') + 1]) if '--least' in argv else 4096
    top = int(argv[argv.index('--top') + 1]) if '--top' in argv else 25
    data = e.data
    runs = []
    i, n = 0, len(data)
    while i < n:
        if data[i]:
            i += 1
            continue
        j = i
        while j < n and not data[j]:
            j += 1
        if j - i >= least:
            runs.append((i, j - i))
        i = j
    total = sum(r[1] for r in runs)
    print('zero runs of at least %d bytes' % least)
    print('  %d runs, %d bytes, %.2f%% of the file'
          % (len(runs), total, 100.0 * total / n if n else 0))
    print()
    runs.sort(key=lambda r: -r[1])
    print('%-14s %14s  %s' % ('OFFSET', 'LENGTH', 'INSIDE'))
    for off, ln in runs[:top]:
        where = []
        for s in e.sections:
            if s['type'] != 8 and s['off'] <= off < s['off'] + s['size']:
                where.append(s['name'])
        for k, p in enumerate(e.segments):
            if p['type'] == 1 and p['off'] <= off < p['off'] + p['filesz']:
                fl = ''.join(c for c, b in (('R', 4), ('W', 2), ('X', 1))
                             if p['flags'] & b)
                where.append('PT_LOAD #%d %s' % (k, fl))
        print('%-14d %14d  %s' % (off, ln, ', '.join(where) or '(no segment)'))
    if len(runs) > top:
        print('... %d more' % (len(runs) - top))


def cmd_census(argv):
    """Every file in a directory tree, ELF or not, measured the same way."""
    import os
    root = argv[1]
    files = []
    for dirpath, _dirs, names in os.walk(root):
        for nm in sorted(names):
            files.append(os.path.join(dirpath, nm))
    print('%-46s %12s %-9s %5s %12s %7s %7s %12s' %
          ('FILE', 'BYTES', 'MACHINE', 'SECS', 'EXEC BYTES', 'ZERO%',
           'ENTROPY', 'TAIL'))
    n_elf = n_not = 0
    for path in sorted(files):
        data = open(path, 'rb').read()
        rel = os.path.relpath(path, root).replace('\\', '/')
        if data[:4] != b'\x7fELF':
            n_not += 1
            print('%-46s %12d %-9s %5s %12s %7s %7.3f %12s' %
                  (rel[:46], len(data), 'NOT ELF', '-', '-', '-',
                   entropy(data), '-'))
            continue
        n_elf += 1
        e = Elf(data)
        regs = exec_regions(e)
        xb = b''.join(data[o:o + s] for _n, o, s, _v in regs)
        loads = [p for p in e.segments if p['type'] == 1]
        end = max((p['off'] + p['filesz']) for p in loads) if loads else 0
        cut = max(end, e.shoff + e.shnum * e.shentsize)
        print('%-46s %12d %-9s %5d %12d %6.2f%% %7.3f %12d' %
              (rel[:46], len(data), EM.get(e.machine, str(e.machine)),
               e.shnum, len(xb), zerofrac(xb) * 100 if xb else 0,
               entropy(xb) if xb else 0, max(0, len(data) - cut)))
    print()
    print('%d ELF files, %d that are not ELF at all' % (n_elf, n_not))
    print()
    print('TAIL is the count of bytes past both the last PT_LOAD and the')
    print('section header table -- the place Tales of Crestoria hides 24 MB.')


CMDS = dict(header=cmd_header, sections=cmd_sections, segments=cmd_segments,
            dynsym=cmd_dynsym, init=cmd_init, zero=cmd_zero,
            entropy=cmd_entropy, overlay=cmd_overlay, summary=cmd_summary,
            text=cmd_text, exec=cmd_exec, runs=cmd_runs)


def main(argv):
    if len(argv) >= 3 and argv[2] == 'census':
        return cmd_census(argv)
    if len(argv) < 3 or argv[2] not in CMDS:
        raise SystemExit(__doc__)
    e = Elf(open(argv[1], 'rb').read())
    print('%s' % argv[1])
    print()
    CMDS[argv[2]](e, argv)


if __name__ == '__main__':
    main(sys.argv)
