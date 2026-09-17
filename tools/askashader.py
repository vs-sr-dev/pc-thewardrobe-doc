#!/usr/bin/env python3
"""
askashader.py - readers for the two shader containers in the Crestoria APK.

`assets/disc1/f00003.bin` is a shader archive: a big-endian table of offsets,
each pointing at a short binding header followed by GLSL ES 3.00 source in the
clear, and the file closes with the ASCII marker `@EOF` stored byte-reversed.

`assets/data/AHSLDiskCacheGLES3` is the engine's compiled-shader disk cache,
stamped `AHA3` (byte-reversed to `3AHA` in the file). Its payload is
LZ-compressed and this tool does not decode it, but the header is readable and
the parameter names and Direct3D 9 profile tokens the cache carries are worth
reporting on their own. See docs/formats/shaders.md.

Standalone Python 3, no dependencies.
"""
import argparse, os, re, struct
from collections import Counter

EOF_MARKER = b'FOE@'          # '@EOF' byte-reversed
AHA3_MAGIC = b'3AHA'          # 'AHA3' byte-reversed
FLAG_BIT = 0x80000000


class ShaderError(Exception):
    pass


# ---------------------------------------------------------------- GLSL archive

TABLE_OFFSET = 0x10           # the entry table always starts here in an archive


def archive_header(data, base=0):
    """Return (word0, entry_count) for the archive starting at base.

    Word 0 is 0x1c in every archive seen here and its meaning is unknown; word 1
    is the entry count. The table begins at base+0x10, and its first entry points
    at base + 0x10 + count*4 -- straight past the table. That self-consistency is
    what fixes the layout, and it is checked here so a wrong guess fails loudly
    instead of yielding plausible garbage.
    """
    word0, count = struct.unpack_from('>II', data, base)
    if not 0 < count < 100000 or base + TABLE_OFFSET + count * 4 > len(data):
        raise ShaderError('no shader archive at 0x%x (word0=0x%x count=%d)'
                          % (base, word0, count))
    first = struct.unpack_from('>I', data, base + TABLE_OFFSET)[0] & ~FLAG_BIT
    if first != TABLE_OFFSET + count * 4:
        raise ShaderError('archive at 0x%x: first entry 0x%x does not follow a '
                          '%d-entry table' % (base, first, count))
    return word0, count


def archives(data):
    """Yield the base offset of each archive in a file.

    A shader file holds several archives back to back. Each ends with the ASCII
    marker `@EOF`, stored byte-reversed, and the next begins right after it.
    """
    base = 0
    while base + TABLE_OFFSET < len(data):
        try:
            archive_header(data, base)
        except ShaderError:
            return
        yield base
        m = data.find(EOF_MARKER, base + TABLE_OFFSET)
        if m < 0:
            return
        base = m + 4


def entries(data, base=0):
    """Yield (index, flagged, offset, payload) for one archive's entries.

    Table offsets are relative to the start of the archive, not to the file; the
    offsets yielded here are absolute.
    """
    _word0, count = archive_header(data, base)
    offs = [struct.unpack_from('>I', data, base + TABLE_OFFSET + i * 4)[0]
            for i in range(count)]
    m = data.find(EOF_MARKER, base + TABLE_OFFSET)
    end = (m if m >= 0 else len(data)) - base
    for i, raw in enumerate(offs):
        a = raw & ~FLAG_BIT
        b = (offs[i + 1] & ~FLAG_BIT) if i + 1 < count else end
        if not 0 <= a <= b <= len(data) - base:
            continue
        yield i, bool(raw & FLAG_BIT), base + a, data[base + a:base + b]


def source_of(payload):
    """The GLSL text inside one entry, or None.

    The binding header before the source is variable length -- it grows with the
    number of slots the shader declares -- so the source is located by its
    `#version` directive rather than by a fixed offset.
    """
    i = payload.find(b'#version')
    if i < 0:
        return None
    return payload[i:].split(b'\0', 1)[0].decode('utf-8', 'replace')


def cmd_list(args):
    data = open(args.path, 'rb').read()
    for a, base in enumerate(archives(data)):
        _w0, count = archive_header(data, base)
        print('== archive %d at 0x%06x: %d entries' % (a, base, count))
        print('%6s %5s %10s %8s %8s %s' % ('#', 'flag', 'offset', 'size', 'hdr', 'first line'))
        for i, flagged, off, payload in entries(data, base):
            src = source_of(payload)
            hdr = payload.find(b'#version') if src else -1
            first = src.splitlines()[0] if src else '(no GLSL)'
            print('%6d %5d 0x%08x %8d %8d %s' % (i, flagged, off, len(payload), hdr, first))


def cmd_extract(args):
    data = open(args.path, 'rb').read()
    os.makedirs(args.out, exist_ok=True)
    n = 0
    for a, base in enumerate(archives(data)):
        for i, _flagged, _off, payload in entries(data, base):
            src = source_of(payload)
            if src is None:
                continue
            name = 'archive%02d_shader%03d.glsl' % (a, i)
            open(os.path.join(args.out, name), 'w', encoding='utf-8').write(src)
            n += 1
    print('wrote %d shader(s) to %s' % (n, args.out))


def cmd_stats(args):
    data = open(args.path, 'rb').read()
    kinds = Counter()
    decls = Counter()
    total = n_arch = n_ent = 0
    for base in archives(data):
        n_arch += 1
        for _i, _f, _o, payload in entries(data, base):
            n_ent += 1
            src = source_of(payload)
            if src is None:
                kinds['no GLSL'] += 1
                continue
            total += len(src)
            kinds['fragment' if 'out vec4' in src or ') out ' in src else 'vertex'] += 1
            for m in re.finditer(r'^\s*(uniform|in|out|layout)\b', src, re.M):
                decls[m.group(1)] += 1
    print('archives: %d, entries: %d' % (n_arch, n_ent))
    print('entries by kind: %s' % dict(kinds))
    print('declaration keywords: %s' % dict(decls))
    print('total GLSL source: %d bytes' % total)


# ------------------------------------------------------------------ AHA3 cache

def aha3_header(data):
    if data[:4] != AHA3_MAGIC:
        raise ShaderError('not an AHA3 cache (magic %r)' % data[:4])
    return struct.unpack_from('<12I', data, 0)


def cmd_cache(args):
    for path in args.paths:
        data = open(path, 'rb').read()
        off = data.find(AHA3_MAGIC)
        if off < 0:
            print('%s: no AHA3 cache found' % os.path.relpath(path))
            continue
        w = aha3_header(data[off:])
        print('== %s  (cache at 0x%x, %d bytes to end of file)'
              % (os.path.relpath(path), off, len(data) - off))
        print('   version=%d  f2=%d  entries=%d  f4=0x%08x' % (w[1], w[2], w[3], w[4]))
        blob = data[off:]
        profiles = Counter(m.group().decode() for m in re.finditer(rb'[vpgc]s_\d_\d', blob))
        compilers = Counter(m.group().decode() for m in re.finditer(rb'\d+\.\d+\.\d+\.\d+', blob))
        # The payload is LZ-compressed, so only match identifiers that start
        # right after a non-identifier byte; anything else is a back-reference
        # fragment cut out of the middle of a word.
        names = Counter(m.group(1).decode() for m in
                        re.finditer(rb'(?:^|[^A-Za-z0-9_])([a-z]{1,2}[A-Z][A-Za-z0-9_]{3,})', blob))
        print('   shader profiles : %s' % (dict(profiles) or '(none)'))
        print('   compiler stamps : %s' % (dict(compilers) or '(none)'))
        print('   GLSL directives : #version x%d, uniform x%d'
              % (len(re.findall(rb'#version', blob)), len(re.findall(rb'uniform', blob))))
        print('   parameter names : %d distinct (word-initial only):' % len(names))
        for k, v in names.most_common(args.top):
            print('       %-34s x%d' % (k, v))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('list', help='list archive entries')
    p.add_argument('path')
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser('extract', help='write each GLSL source to a file')
    p.add_argument('path')
    p.add_argument('-o', '--out', required=True)
    p.set_defaults(fn=cmd_extract)
    p = sub.add_parser('stats', help='summarise an archive')
    p.add_argument('path')
    p.set_defaults(fn=cmd_stats)
    p = sub.add_parser('cache', help='report on an AHA3 disk cache')
    p.add_argument('paths', nargs='+')
    p.add_argument('--top', type=int, default=15)
    p.set_defaults(fn=cmd_cache)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
