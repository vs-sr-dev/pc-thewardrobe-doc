#!/usr/bin/env python3
"""mdmp.py -- list the streams, the modules and the exception record of a
Windows minidump, from the public layout and nothing else.

The format is Microsoft's and is published: `minidumpapiset.h` in the Windows
SDK, mirrored on the documentation site.  What this tool reads of it:

    MINIDUMP_HEADER (32 bytes)
        +0   "MDMP"
        +4   u32 Version        low 16 bits = MINIDUMP_VERSION 0xA793,
                                high 16 bits = the writer's own
        +8   u32 NumberOfStreams
        +12  u32 StreamDirectoryRva
        +16  u32 CheckSum
        +20  u32 TimeDateStamp   seconds since 1970, UTC
        +24  u64 Flags           MINIDUMP_TYPE bits

    MINIDUMP_DIRECTORY (12 bytes each, NumberOfStreams of them)
        u32 StreamType, u32 DataSize, u32 Rva

    MINIDUMP_MODULE_LIST  (stream 4): u32 count, then 108-byte modules:
        u64 BaseOfImage, u32 SizeOfImage, u32 CheckSum, u32 TimeDateStamp,
        u32 ModuleNameRva (-> MINIDUMP_STRING: u32 byte length, UTF-16LE),
        VS_FIXEDFILEINFO (52 bytes), two MINIDUMP_LOCATION_DESCRIPTORs (16)
    MINIDUMP_EXCEPTION_STREAM (stream 6): u32 ThreadId, u32 pad, then
        MINIDUMP_EXCEPTION: u32 ExceptionCode, u32 ExceptionFlags,
        u64 ExceptionRecord, u64 ExceptionAddress, u32 NumberParameters,
        u32 pad, u64 ExceptionInformation[15]; then the context's location
    MINIDUMP_SYSTEM_INFO (stream 7): u16 ProcessorArchitecture, u16 Level,
        u16 Revision, u8 NumberOfProcessors, u8 ProductType, u32 MajorVersion,
        u32 MinorVersion, u32 BuildNumber, u32 PlatformId, u32 CSDVersionRva
    MINIDUMP_THREAD_LIST (stream 3): u32 count, then 48-byte threads
    MINIDUMP_MEMORY_LIST (stream 5): u32 count, then 16-byte ranges

THE CHECKS: the version word; the directory and every stream inside the file;
each list's count x record size == the stream's DataSize; every module name
string inside the file.  A layout error fails one of them instead of printing
a plausible table.

THE PATHS.  A module list is a list of file paths on the machine that crashed,
and on this object one of them carries a Windows account name.  Every path
printed goes through `mask()`, which keeps the file name and replaces the
directory with `<dir>`; `--paths` prints them whole for a reader working in
`_work\\`, never for `notes\\`.  This is rule 6 of the collection applied to
the object's own bytes rather than to this machine's.

    python tools/mdmp.py info    FILE
    python tools/mdmp.py streams FILE
    python tools/mdmp.py modules FILE [--paths]
    python tools/mdmp.py selftest

What is NOT read: the thread contexts (register sets), the memory ranges'
contents, the handle and unloaded-module streams, the misc-info stream.
Standard library only.
"""

import argparse
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                            # noqa: E402
import nameguard                                           # noqa: E402

nameguard.guard()

STREAM = {
    0: 'UnusedStream', 1: 'ReservedStream0', 2: 'ReservedStream1',
    3: 'ThreadListStream', 4: 'ModuleListStream', 5: 'MemoryListStream',
    6: 'ExceptionStream', 7: 'SystemInfoStream', 8: 'ThreadExListStream',
    9: 'Memory64ListStream', 10: 'CommentStreamA', 11: 'CommentStreamW',
    12: 'HandleDataStream', 13: 'FunctionTableStream',
    14: 'UnloadedModuleListStream', 15: 'MiscInfoStream',
    16: 'MemoryInfoListStream', 17: 'ThreadInfoListStream',
    18: 'HandleOperationListStream', 19: 'TokenStream',
    20: 'JavaScriptDataStream', 21: 'SystemMemoryInfoStream',
    22: 'ProcessVmCountersStream', 23: 'IptTraceStream',
    24: 'ThreadNamesStream',
}
ARCH = {0: 'x86', 5: 'ARM', 6: 'IA64', 9: 'x64', 12: 'ARM64', 0xFFFF: 'unknown'}
CODES = {0xC0000005: 'EXCEPTION_ACCESS_VIOLATION',
         0xC0000094: 'EXCEPTION_INT_DIVIDE_BY_ZERO',
         0xC00000FD: 'EXCEPTION_STACK_OVERFLOW',
         0x80000003: 'EXCEPTION_BREAKPOINT',
         0xE0434352: 'CLR exception (0xE0434352 "CCR")',
         0xE0434F4D: 'CLR exception (0xE0434F4D "COM")'}


class Refused(Exception):
    pass


def mask(path):
    """The file name, with the directory replaced: `<dir>\\name.dll`."""
    p = path.replace('/', '\\')
    if '\\' not in p:
        return p
    return '<dir>\\' + p.rsplit('\\', 1)[1]


class Minidump(object):
    def __init__(self, data, name='?'):
        self.d = data
        self.name = name
        if len(data) < 32 or data[:4] != b'MDMP':
            raise Refused('%s: no MDMP signature' % name)
        (self.version, self.nstreams, self.dir_rva, self.checksum,
         self.stamp, self.flags) = struct.unpack_from('<IIIIIQ', data, 4)
        if self.version & 0xFFFF != 0xA793:
            raise Refused('%s: version word 0x%08X, low half is not 0xA793'
                          % (name, self.version))
        if self.dir_rva < 32 or self.dir_rva + 12 * self.nstreams > len(data):
            raise Refused('%s: stream directory %d+%d x 12 leaves a %d-byte '
                          'file' % (name, self.dir_rva, self.nstreams,
                                    len(data)))
        self.streams = []
        for i in range(self.nstreams):
            t, sz, rva = struct.unpack_from('<III', data, self.dir_rva + 12 * i)
            if rva + sz > len(data):
                raise Refused('%s: stream %d (type %d) %d+%d leaves the file'
                              % (name, i, t, rva, sz))
            self.streams.append((t, sz, rva))

    def stream(self, kind):
        for t, sz, rva in self.streams:
            if t == kind:
                return self.d[rva:rva + sz], rva
        return None, None

    def mstring(self, rva):
        if rva + 4 > len(self.d):
            raise Refused('%s: string at %d leaves the file' % (self.name, rva))
        n, = struct.unpack_from('<I', self.d, rva)
        if rva + 4 + n > len(self.d):
            raise Refused('%s: string at %d of %d bytes leaves the file'
                          % (self.name, rva, n))
        return self.d[rva + 4:rva + 4 + n].decode('utf-16-le', 'replace')

    def modules(self):
        s, rva = self.stream(4)
        if s is None:
            return []
        n, = struct.unpack_from('<I', s, 0)
        if 4 + n * 108 != len(s):
            raise Refused('%s: module list says %d modules, %d bytes is not '
                          '4 + %d x 108' % (self.name, n, len(s), n))
        out = []
        for i in range(n):
            b = 4 + i * 108
            base, size, chk, stamp, name_rva = struct.unpack_from('<QIIII', s, b)
            # VS_FIXEDFILEINFO: dwSignature, dwStrucVersion, dwFileVersionMS,
            # dwFileVersionLS, dwProductVersionMS, dwProductVersionLS ...
            sig, _sv, fms, fls = struct.unpack_from('<IIII', s, b + 24)
            ver = ('%d.%d.%d.%d' % (fms >> 16, fms & 0xFFFF, fls >> 16,
                                    fls & 0xFFFF) if sig == 0xFEEF04BD else '')
            out.append(dict(base=base, size=size, stamp=stamp,
                            name=self.mstring(name_rva), version=ver))
        return out

    def threads(self):
        s, rva = self.stream(3)
        if s is None:
            return None
        n, = struct.unpack_from('<I', s, 0)
        if 4 + n * 48 != len(s):
            raise Refused('%s: thread list says %d threads, %d bytes is not '
                          '4 + %d x 48' % (self.name, n, len(s), n))
        return [struct.unpack_from('<I', s, 4 + i * 48)[0] for i in range(n)]

    def memory_ranges(self):
        s, rva = self.stream(5)
        if s is None:
            return None
        n, = struct.unpack_from('<I', s, 0)
        if 4 + n * 16 != len(s):
            raise Refused('%s: memory list says %d ranges, %d bytes is not '
                          '4 + %d x 16' % (self.name, n, len(s), n))
        return [struct.unpack_from('<QII', s, 4 + i * 16) for i in range(n)]

    def exception(self):
        s, rva = self.stream(6)
        if s is None:
            return None
        if len(s) < 8 + 152 + 8:
            raise Refused('%s: exception stream is %d bytes' % (self.name,
                                                                 len(s)))
        tid, = struct.unpack_from('<I', s, 0)
        code, flags, rec, addr, nparams = struct.unpack_from('<IIQQI', s, 8)
        params = struct.unpack_from('<15Q', s, 8 + 32)
        return dict(thread=tid, code=code, flags=flags, address=addr,
                    params=list(params[:nparams]))

    def system(self):
        s, rva = self.stream(7)
        if s is None:
            return None
        arch, lvl, rev, ncpu, ptype, maj, mnr, build, plat, csd = \
            struct.unpack_from('<HHHBBIIIII', s, 0)
        return dict(arch=ARCH.get(arch, str(arch)), cpus=ncpu, major=maj,
                    minor=mnr, build=build,
                    csd=self.mstring(csd) if csd else '')

    def owner_of(self, address):
        for m in self.modules():
            if m['base'] <= address < m['base'] + m['size']:
                return m
        return None


def load(path):
    dirguard.want_file(path, 'mdmp')
    with open(path, 'rb') as f:
        return Minidump(f.read(), os.path.basename(path))


def utc(stamp):
    return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(stamp))


def cmd_streams(args):
    m = load(args.path)
    print('%-3s %-28s %10s %10s' % ('#', 'STREAM', 'SIZE', 'RVA'))
    for i, (t, sz, rva) in enumerate(m.streams):
        print('%-3d %-28s %10d %10d' % (i, STREAM.get(t, 'type %d' % t), sz,
                                        rva))
    print()
    print('%d streams; directory at %d; file %d bytes'
          % (m.nstreams, m.dir_rva, len(m.d)))
    return 0


def cmd_modules(args):
    m = load(args.path)
    mods = m.modules()
    print('%-18s %10s %-24s %-16s %s'
          % ('BASE', 'SIZE', 'COFF STAMP (UTC)', 'VERSION', 'NAME'))
    for x in mods:
        print('%-18s %10d %-24s %-16s %s'
              % ('0x%016X' % x['base'], x['size'], utc(x['stamp']),
                 x['version'], x['name'] if args.paths else mask(x['name'])))
    print()
    print('%d modules' % len(mods))
    if not args.paths:
        print('(directories masked; --paths prints them, for _work only)')
    return 0


def cmd_info(args):
    m = load(args.path)
    print('%s   %d bytes' % (os.path.basename(args.path), len(m.d)))
    print('  version word     0x%08X  (MINIDUMP_VERSION 0x%04X, writer 0x%04X)'
          % (m.version, m.version & 0xFFFF, m.version >> 16))
    print('  time stamp       %d = %s' % (m.stamp, utc(m.stamp)))
    print('  flags            0x%X' % m.flags)
    print('  streams          %d' % m.nstreams)
    sysinfo = m.system()
    if sysinfo:
        print('  system           %s, %d processors, Windows %d.%d build %d%s'
              % (sysinfo['arch'], sysinfo['cpus'], sysinfo['major'],
                 sysinfo['minor'], sysinfo['build'],
                 (' ' + sysinfo['csd']) if sysinfo['csd'] else ''))
    th = m.threads()
    if th is not None:
        print('  threads          %d' % len(th))
    mr = m.memory_ranges()
    if mr is not None:
        print('  memory ranges    %d, %d bytes captured'
              % (len(mr), sum(r[1] for r in mr)))
    mods = m.modules()
    print('  modules          %d' % len(mods))
    ex = m.exception()
    if ex:
        print('  exception        0x%08X %s, thread %d, address 0x%016X'
              % (ex['code'], CODES.get(ex['code'], ''), ex['thread'],
                 ex['address']))
        if ex['code'] == 0xC0000005 and len(ex['params']) >= 2:
            print('                   %s at 0x%016X'
                  % ({0: 'read', 1: 'write', 8: 'execute'}.get(
                      ex['params'][0], 'access %d' % ex['params'][0]),
                     ex['params'][1]))
        own = m.owner_of(ex['address'])
        if own:
            print('                   in %s + 0x%X (base 0x%016X, size %d)'
                  % (mask(own['name']), ex['address'] - own['base'],
                     own['base'], own['size']))
        else:
            print('                   in no listed module')
    return 0


# ------------------------------------------------------------------ selftest

def _build(nstreams_extra=0, module_name='C:\\Users\\someone\\app.exe',
           bad_count=False):
    """A minidump by hand: SystemInfo, ModuleList (1 module), Exception,
    ThreadList (1), MemoryList (0)."""
    parts = []
    # layout: header 32, directory 5 x 12 = 60 -> 92; then streams
    pos = 92
    sysinfo = struct.pack('<HHHBBIIIII', 9, 6, 0, 8, 1, 10, 0, 19045, 2, 0)
    sysinfo += bytes(56 - len(sysinfo))
    s_sys = (7, pos, sysinfo)
    pos += len(sysinfo)
    name = module_name.encode('utf-16-le')
    mstr = struct.pack('<I', len(name)) + name + b'\0\0'
    mstr_rva = pos
    pos += len(mstr)
    mod = struct.pack('<QIIII', 0x140000000, 0x1000000, 0, 0x5837004A,
                      mstr_rva)
    mod += struct.pack('<IIII', 0xFEEF04BD, 0x10000, (5 << 16) | 5, 0)
    mod += bytes(108 - len(mod))
    mlist = struct.pack('<I', 2 if bad_count else 1) + mod
    s_mod = (4, pos, mlist)
    pos += len(mlist)
    exc = struct.pack('<II', 1234, 0)
    exc += struct.pack('<IIQQI', 0xC0000005, 0, 0, 0x140ABCDEF, 2)
    exc += struct.pack('<I', 0) + struct.pack('<15Q', 0, 0x260, *([0] * 13))
    exc += struct.pack('<II', 0, 0)                  # context location
    s_exc = (6, pos, exc)
    pos += len(exc)
    tl = struct.pack('<I', 1) + bytes(48)
    s_thr = (3, pos, tl)
    pos += len(tl)
    ml = struct.pack('<I', 0)
    s_mem = (5, pos, ml)
    pos += len(ml)
    streams = [s_sys, s_mod, s_exc, s_thr, s_mem]
    blobs = sorted([(rva, body) for _t, rva, body in streams]
                   + [(mstr_rva, mstr)])
    hdr = b'MDMP' + struct.pack('<IIIIIQ', 0xA0EEA793, len(streams), 32, 0,
                                1544890734, 0)
    d = hdr
    for t, rva, body in streams:
        d += struct.pack('<III', t, len(body), rva)
    for rva, body in blobs:
        assert len(d) == rva, (len(d), rva)
        d += body
    return d


def cmd_selftest(_args):
    checks = []
    d = _build()
    m = Minidump(d, 'hand-built')
    checks.append(('a hand-built minidump parses with 5 streams',
                   m.nstreams == 5 and len(m.streams) == 5, ''))
    checks.append(('the time stamp reads as 2018-12-15 16:18:54 UTC',
                   utc(m.stamp) == '2018-12-15 16:18:54 UTC', utc(m.stamp)))
    mods = m.modules()
    checks.append(('one module at 0x140000000 with version 5.5.0.0 and its '
                   'name',
                   len(mods) == 1 and mods[0]['base'] == 0x140000000
                   and mods[0]['version'] == '5.5.0.0'
                   and mods[0]['name'].endswith('app.exe'),
                   str(mods[0]) if mods else ''))
    checks.append(('the module name is masked to <dir>\\app.exe',
                   mask(mods[0]['name']) == '<dir>\\app.exe',
                   mask(mods[0]['name'])))
    ex = m.exception()
    checks.append(('the exception is an access violation reading 0x260 at '
                   'an address inside the module',
                   ex['code'] == 0xC0000005 and ex['params'] == [0, 0x260]
                   and m.owner_of(ex['address']) is mods[0]
                   or (ex['code'] == 0xC0000005 and ex['params'] == [0, 0x260]
                       and m.owner_of(ex['address'])['base'] == 0x140000000),
                   str(ex)))
    checks.append(('SystemInfo reads x64, 8 processors, Windows 10.0.19045',
                   m.system()['arch'] == 'x64' and m.system()['cpus'] == 8
                   and m.system()['build'] == 19045, str(m.system())))
    checks.append(('one thread, zero memory ranges',
                   m.threads() == [0] and m.memory_ranges() == [], ''))
    # refusals
    def refuses(blob):
        try:
            Minidump(blob, 'x')
        except Refused:
            return True
        return False
    checks.append(('a wrong version word is refused',
                   refuses(d[:4] + struct.pack('<I', 0xA0EE0000) + d[8:]), ''))
    checks.append(('a directory past the end is refused',
                   refuses(d[:12] + struct.pack('<I', len(d)) + d[16:]), ''))
    checks.append(('a stream past the end is refused',
                   refuses(d[:36] + struct.pack('<I', 10 ** 6) + d[40:]), ''))
    try:
        Minidump(_build(bad_count=True), 'x').modules()
        checks.append(('a module count off the stream size is refused',
                       False, ''))
    except Refused:
        checks.append(('a module count off the stream size is refused',
                       True, ''))
    checks.append(('a random blob is refused', refuses(bytes(64)), ''))
    w = max(len(c[0]) for c in checks)
    bad = 0
    for label, ok, note in checks:
        print('  %-*s  %s  %s' % (w, label, 'ok  ' if ok else 'FAIL',
                                  note[:60]))
        bad += not ok
    print()
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd')
    for n in ('info', 'streams', 'modules'):
        p = sub.add_parser(n)
        p.add_argument('path')
        if n == 'modules':
            p.add_argument('--paths', action='store_true')
    sub.add_parser('selftest')
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        return {'info': cmd_info, 'streams': cmd_streams,
                'modules': cmd_modules, 'selftest': cmd_selftest}[args.cmd](args)
    except Refused as e:
        sys.exit('mdmp: refused -- %s' % e)


if __name__ == '__main__':
    sys.exit(main())
