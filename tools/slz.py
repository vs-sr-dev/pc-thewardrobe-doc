#!/usr/bin/env python3
"""
slz.py - reader for the SLZ container as shipped by Tales of Crestoria (Android).

Every packed asset under assets/data/ in the Crestoria APK is an SLZ file whose
method byte is 7. That method is a chunked Zstandard stream: the payload is a
run of [u16 compressed_size][zstd frame] records, each frame decoding to at most
65536 bytes. A compressed_size of zero marks a chunk that is stored verbatim
instead, because zstd could not get it under the 65535-byte length field. Earlier tri-Ace titles used the same "SLZ" fourcc with different
method bytes (XCompress on Xbox 360, tri-Ace's own LZ77 on PlayStation); method
7 is the variant this game ships and is documented in docs/formats/slz.md.

Standalone; needs Python 3.14 for compression.zstd (or the `zstandard` package).
"""
import argparse, os, struct, sys

try:
    from compression import zstd as _z
    def _zdec(buf): return _z.ZstdDecompressor().decompress(buf)
except ImportError:                                     # pragma: no cover
    import zstandard
    def _zdec(buf): return zstandard.ZstdDecompressor().decompressobj().decompress(buf)

MAGIC = b'SLZ'
CHUNK_MAX = 65536

class SlzError(Exception):
    pass

class Header:
    SIZE = 0x30
    __slots__ = ('method','flags4','payload_size','uncompressed_size','reserved18',
                 'header_size','flags20','reserved24','total_size')
    def __init__(self, buf):
        if buf[:3] != MAGIC:
            raise SlzError('not an SLZ file (magic %r)' % buf[:4])
        self.method = buf[3]
        (self.flags4,) = struct.unpack_from('<I', buf, 0x04)
        (self.payload_size, self.uncompressed_size) = struct.unpack_from('<QQ', buf, 0x08)
        (self.reserved18, self.header_size) = struct.unpack_from('<II', buf, 0x18)
        (self.flags20, self.reserved24) = struct.unpack_from('<II', buf, 0x20)
        (self.total_size,) = struct.unpack_from('<Q', buf, 0x28)

    def describe(self):
        return ('method=%d flags4=0x%08x payload=%d uncompressed=%d header=%d '
                'flags20=0x%08x total=%d' % (self.method, self.flags4, self.payload_size,
                self.uncompressed_size, self.header_size, self.flags20, self.total_size))

def read_header(data):
    return Header(data)

def decompress(data):
    """Return the decoded payload of an SLZ method-7 file."""
    h = Header(data)
    if h.method != 7:
        raise SlzError('unsupported SLZ method %d (only 7 / chunked zstd is known)' % h.method)
    p = h.header_size
    out = bytearray()
    while len(out) < h.uncompressed_size:
        if p + 2 > len(data):
            raise SlzError('truncated at chunk header, offset 0x%x' % p)
        (clen,) = struct.unpack_from('<H', data, p)
        p += 2
        if clen == 0:
            # A chunk that zstd could not shrink below the u16 length field is
            # stored verbatim and flagged with a zero length.
            take = min(CHUNK_MAX, h.uncompressed_size - len(out))
            out += data[p:p+take]
            p += take
            continue
        frame = data[p:p+clen]
        if len(frame) != clen:
            raise SlzError('truncated chunk at 0x%x (want %d, have %d)' % (p, clen, len(frame)))
        p += clen
        out += _zdec(frame)
    if len(out) != h.uncompressed_size:
        raise SlzError('size mismatch: got %d, header says %d' % (len(out), h.uncompressed_size))
    return bytes(out)

def chunk_table(data):
    """Return [(offset, compressed_size, decoded_size)] without keeping the payload."""
    h = Header(data)
    p, total, rows = h.header_size, 0, []
    while total < h.uncompressed_size:
        (clen,) = struct.unpack_from('<H', data, p)
        if clen == 0:
            n = min(CHUNK_MAX, h.uncompressed_size - total)
            rows.append((p, 0, n))
            p += 2 + n
        else:
            n = len(_zdec(data[p+2:p+2+clen]))
            rows.append((p, clen, n))
            p += 2 + clen
        total += n
    return rows

def _walk(paths):
    for path in paths:
        if os.path.isdir(path):
            for dp, _, fn in os.walk(path):
                for x in sorted(fn):
                    yield os.path.join(dp, x)
        else:
            yield path

def cmd_info(args):
    print('%-44s %10s %10s %10s %6s %s' % ('file','size','payload','decoded','chunks','flags20'))
    for f in _walk(args.paths):
        data = open(f,'rb').read()
        if data[:3] != MAGIC:
            if args.all: print('%-44s %10d  (not SLZ: %r)' % (os.path.relpath(f), len(data), data[:4]))
            continue
        h = Header(data)
        try:
            rows = chunk_table(data); nch = len(rows); dec = sum(r[2] for r in rows)
        except Exception as e:
            nch, dec = -1, -1
        print('%-44s %10d %10d %10d %6d 0x%08x%s' % (
            os.path.relpath(f), len(data), h.payload_size, h.uncompressed_size, nch,
            h.flags20, '' if dec == h.uncompressed_size else '   <-- MISMATCH decoded=%d' % dec))

def cmd_unpack(args):
    os.makedirs(args.out, exist_ok=True)
    n = 0
    for f in _walk(args.paths):
        data = open(f,'rb').read()
        if data[:3] != MAGIC: continue
        rel = os.path.relpath(f, args.paths[0] if os.path.isdir(args.paths[0]) else os.path.dirname(f))
        dst = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            open(dst,'wb').write(decompress(data)); n += 1
        except SlzError as e:
            print('  !! %s: %s' % (rel, e), file=sys.stderr)
    print('unpacked %d file(s) to %s' % (n, args.out))

def cmd_chunks(args):
    data = open(args.path,'rb').read()
    h = Header(data)
    print(h.describe())
    print('%6s %10s %10s %10s' % ('#','offset','comp','decoded'))
    for i,(o,c,n) in enumerate(chunk_table(data)):
        print('%6d 0x%08x %10d %10d' % (i,o,c,n))

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('info', help='summarise SLZ headers'); p.add_argument('paths', nargs='+')
    p.add_argument('--all', action='store_true', help='also list non-SLZ files'); p.set_defaults(fn=cmd_info)
    p = sub.add_parser('unpack', help='decode SLZ files into a tree'); p.add_argument('paths', nargs='+')
    p.add_argument('-o','--out', required=True); p.set_defaults(fn=cmd_unpack)
    p = sub.add_parser('chunks', help='list the chunk table of one file'); p.add_argument('path')
    p.set_defaults(fn=cmd_chunks)
    a = ap.parse_args(); a.fn(a)

if __name__ == '__main__':
    main()
