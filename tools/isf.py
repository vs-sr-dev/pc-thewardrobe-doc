#!/usr/bin/env python3
"""
isf.py - reader for the ASKA package format used by Tales of Crestoria (Android).

The game's .csf (UI packages) and .spk (sound packages) are, once the SLZ wrapper
is removed, the same container: a flat directory of named members. The engine
writes the fourcc byte-reversed, so the file begins with the bytes 00 49 53 46
("\0ISF"); read as a little-endian u32 that is 0x46534900. See docs/formats/isf.md.

Each member carries a 32-bit additive checksum taken over its payload padded up
to a 32-byte boundary; `verify` checks every one of them.

Standalone Python 3, no dependencies. Feed it files already unwrapped by slz.py.
"""
import argparse, os, struct, sys

MAGIC = b'\x00ISF'
VERSION = 0x20130304
ENTRY_SIZE = 32
ALIGN = 32

class IsfError(Exception):
    pass

class Entry:
    __slots__ = ('index','name','offset','size','checksum','reserved')
    def __init__(self, index, name, offset, size, checksum, reserved):
        self.index, self.name, self.offset = index, name, offset
        self.size, self.checksum, self.reserved = size, checksum, reserved
    @property
    def padded_size(self):
        return (self.size + ALIGN - 1) // ALIGN * ALIGN

class Archive:
    def __init__(self, data):
        if data[:4] != MAGIC:
            raise IsfError('not an ISF package (magic %r)' % data[:4])
        self.data = data
        self.version, self.count, self.pad = struct.unpack_from('<III', data, 4)
        self.entries = []
        for i in range(self.count):
            f = struct.unpack_from('<8I', data, 0x10 + i * ENTRY_SIZE)
            name_off, off, res0, size, cksum = f[0], f[1], f[2], f[3], f[4]
            end = data.find(b'\0', name_off)
            name = data[name_off:end].decode('utf-8', 'replace')
            self.entries.append(Entry(i, name, off, size, cksum, (res0,) + f[5:]))

    def read(self, e):
        return self.data[e.offset:e.offset + e.size]

    def checksum_of(self, e):
        """The engine's checksum: byte sum over the payload padded to 32 bytes."""
        return sum(self.data[e.offset:e.offset + e.padded_size]) & 0xFFFFFFFF

def load(path):
    return Archive(open(path, 'rb').read())

def _walk(paths):
    for path in paths:
        if os.path.isdir(path):
            for dp, _, fn in os.walk(path):
                for x in sorted(fn):
                    yield os.path.join(dp, x)
        else:
            yield path

def _archives(paths):
    for f in _walk(paths):
        with open(f, 'rb') as fh:
            if fh.read(4) != MAGIC:
                continue
        yield f, load(f)

def cmd_list(args):
    for f, a in _archives(args.paths):
        print('== %s  version=0x%08x  members=%d' % (os.path.relpath(f), a.version, a.count))
        for e in a.entries:
            print('   %4d  %10d  0x%08x  0x%08x  %s' % (e.index, e.size, e.offset, e.checksum, e.name))

def cmd_verify(args):
    total = bad = 0
    for f, a in _archives(args.paths):
        if a.version != VERSION:
            print('%s: unexpected version 0x%08x' % (os.path.relpath(f), a.version))
        for e in a.entries:
            total += 1
            if a.checksum_of(e) != e.checksum:
                bad += 1
                print('  BAD %s :: %s (stored 0x%08x, computed 0x%08x)' %
                      (os.path.relpath(f), e.name, e.checksum, a.checksum_of(e)))
    print('checksum: %d/%d members verified' % (total - bad, total))
    return 1 if bad else 0

def cmd_extract(args):
    n = 0
    for f, a in _archives(args.paths):
        stem = os.path.splitext(os.path.basename(f))[0]
        outdir = os.path.join(args.out, stem)
        os.makedirs(outdir, exist_ok=True)
        for e in a.entries:
            open(os.path.join(outdir, e.name), 'wb').write(a.read(e))
            n += 1
    print('extracted %d member(s) to %s' % (n, args.out))

def cmd_census(args):
    import collections
    ext = collections.Counter(); size = collections.Counter(); pkgs = 0
    for f, a in _archives(args.paths):
        pkgs += 1
        for e in a.entries:
            k = e.name.rsplit('.', 1)[-1].lower() if '.' in e.name else '(none)'
            ext[k] += 1; size[k] += e.size
    print('%-10s %8s %14s' % ('member', 'count', 'bytes'))
    for k, v in ext.most_common():
        print('%-10s %8d %14d' % (k, v, size[k]))
    print('-- %d package(s), %d member(s), %d bytes' % (pkgs, sum(ext.values()), sum(size.values())))

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name, fn, helptext in (('list', cmd_list, 'list members'),
                               ('verify', cmd_verify, 'check every member checksum'),
                               ('census', cmd_census, 'count members by extension')):
        p = sub.add_parser(name, help=helptext); p.add_argument('paths', nargs='+'); p.set_defaults(fn=fn)
    p = sub.add_parser('extract', help='write members out'); p.add_argument('paths', nargs='+')
    p.add_argument('-o', '--out', required=True); p.set_defaults(fn=cmd_extract)
    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)

if __name__ == '__main__':
    main()
