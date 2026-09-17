#!/usr/bin/env python3
"""
askaudio.py - reader for the audio containers in the Tales of Crestoria APK.

Files named `.aac` are not raw AAC. They are ASKA chunk containers whose fourccs
are stored byte-reversed, so the file opens with the bytes " CAA" for the tag
`AAC `. Inside, an `AAOB` object bank describes the streams and a `WAVB` bank
carries the encoded audio -- which, in every file this APK ships, is a complete
Ogg Vorbis stream with intact page CRCs.

The `.mou` members that sit beside voice clips inside a `.spk` package are
16-byte records of lip-sync intervals.

See docs/formats/audio.md. Standalone Python 3, no dependencies.
"""
import argparse, os, struct

HEADER = 16
OGG = b'OggS'


class AudioError(Exception):
    pass


def tag_at(data, off):
    """Return the logical fourcc at off, or None if it is not printable ASCII."""
    raw = data[off:off + 4]
    if len(raw) != 4 or not all(0x20 <= c < 0x7F for c in raw):
        return None
    return raw[::-1].decode('ascii')


def chunks(data, start=0, end=None, skip_limit=64):
    """Walk the chunk list in [start, end), yielding (tag, offset, size, f2, f3).

    A container may open with a short descriptor block before its first child
    chunk, so a limited number of unrecognised 16-byte slots are stepped over
    rather than treated as the end of the list.
    """
    end = len(data) if end is None else end
    p, skipped = start, 0
    while p + HEADER <= end:
        tag = tag_at(data, p)
        size = struct.unpack_from('<I', data, p + 4)[0] if tag else 0
        if tag is None or not HEADER <= size <= end - p:
            skipped += 1
            if skipped > skip_limit:
                return
            p += HEADER
            continue
        f2, f3 = struct.unpack_from('<II', data, p + 8)
        yield tag, p, size, f2, f3
        p += size


# Tags known to hold further chunks. WAVB holds encoded audio, and recursing
# into it would happily mistake an Ogg page header for a chunk tag.
CONTAINERS = {'AAC ', 'AAOB', 'AAO ', 'AAF ', 'AAFB'}


def tree(data, start=0, end=None, depth=0, max_depth=3):
    for tag, off, size, f2, f3 in chunks(data, start, end):
        yield depth, tag, off, size, f2, f3
        if depth < max_depth and size > HEADER and tag in CONTAINERS:
            yield from tree(data, off + HEADER, off + size, depth + 1, max_depth)


def find_ogg(data):
    """Offset of the Ogg stream inside a container, or -1."""
    return data.find(OGG)


_CRC = None


def _crc_table():
    global _CRC
    if _CRC is None:
        t = []
        for i in range(256):
            c = i << 24
            for _ in range(8):
                c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
            t.append(c)
        _CRC = t
    return _CRC


def ogg_pages(data, start):
    """Yield (offset, length, stored_crc, computed_crc) for each Ogg page."""
    t = _crc_table()
    p = start
    while p + 27 <= len(data) and data[p:p + 4] == OGG:
        nseg = data[p + 26]
        segs = data[p + 27:p + 27 + nseg]
        total = 27 + nseg + sum(segs)
        page = bytearray(data[p:p + total])
        if len(page) != total:
            return
        stored = struct.unpack_from('<I', page, 22)[0]
        page[22:26] = b'\0\0\0\0'
        crc = 0
        for b in page:
            crc = ((crc << 8) ^ t[((crc >> 24) ^ b) & 0xFF]) & 0xFFFFFFFF
        yield p, total, stored, crc
        p += total


def vorbis_info(data, start):
    """Return (channels, rate, nominal_bitrate, vendor) from the Vorbis headers."""
    i = data.find(b'\x01vorbis', start)
    if i < 0:
        raise AudioError('no Vorbis identification header')
    _ver, channels, rate = struct.unpack_from('<IBI', data, i + 7)
    _bmax, bnom, _bmin = struct.unpack_from('<iii', data, i + 16)
    vendor = None
    j = data.find(b'\x03vorbis', start)
    if j >= 0:
        n = struct.unpack_from('<I', data, j + 7)[0]
        vendor = data[j + 11:j + 11 + n]
    return channels, rate, bnom, vendor


def ascii_safe(raw):
    """Vendor strings carry non-ASCII; keep them printable on any console."""
    return raw.decode('utf-8', 'replace').encode('ascii', 'backslashreplace').decode('ascii')


def lipsync(data):
    """Decode a .mou file into (start_ms, value, end_ms, reserved) records."""
    if len(data) % 16:
        raise AudioError('.mou length %d is not a multiple of 16' % len(data))
    return [struct.unpack_from('<4i', data, i * 16) for i in range(len(data) // 16)]


def _walk(paths, exts):
    for path in paths:
        if os.path.isdir(path):
            for dp, _, fn in os.walk(path):
                for x in sorted(fn):
                    if x.lower().endswith(exts):
                        yield os.path.join(dp, x)
        else:
            yield path


def cmd_tree(args):
    for f in _walk(args.paths, ('.aac',)):
        data = open(f, 'rb').read()
        print('== %s  %d bytes' % (os.path.relpath(f), len(data)))
        for depth, tag, off, size, f2, f3 in tree(data, max_depth=args.depth):
            print('   %s%-5s @0x%06x size=%-9d f2=%-9d f3=%d'
                  % ('  ' * depth, tag, off, size, f2, f3))


def cmd_info(args):
    print('%-46s %10s %4s %7s %9s %s' % ('file', 'bytes', 'ch', 'rate', 'nominal', 'vendor'))
    for f in _walk(args.paths, ('.aac',)):
        data = open(f, 'rb').read()
        i = find_ogg(data)
        if i < 0:
            print('%-46s %10d  (no Ogg stream)' % (os.path.relpath(f), len(data)))
            continue
        try:
            ch, rate, bnom, vendor = vorbis_info(data, i)
        except AudioError as e:
            print('%-46s %10d  !! %s' % (os.path.relpath(f), len(data), e))
            continue
        print('%-46s %10d %4d %7d %9d %s'
              % (os.path.relpath(f), len(data), ch, rate, bnom,
                 '(none)' if vendor is None else ascii_safe(vendor)))


def cmd_verify(args):
    total = bad = files = 0
    for f in _walk(args.paths, ('.aac',)):
        data = open(f, 'rb').read()
        i = find_ogg(data)
        if i < 0:
            continue
        files += 1
        for _off, _n, stored, crc in ogg_pages(data, i):
            total += 1
            if stored != crc:
                bad += 1
    print('Ogg page CRCs: %d/%d valid across %d file(s)' % (total - bad, total, files))
    return 1 if bad else 0


def cmd_extract(args):
    os.makedirs(args.out, exist_ok=True)
    n = 0
    for f in _walk(args.paths, ('.aac',)):
        data = open(f, 'rb').read()
        i = find_ogg(data)
        if i < 0:
            continue
        last = i
        for off, size, _s, _c in ogg_pages(data, i):
            last = off + size
        dst = os.path.join(args.out, os.path.splitext(os.path.basename(f))[0] + '.ogg')
        open(dst, 'wb').write(data[i:last])
        n += 1
    print('extracted %d Ogg stream(s) to %s' % (n, args.out))


def cmd_mou(args):
    for f in _walk(args.paths, ('.mou',)):
        rows = lipsync(open(f, 'rb').read())
        print('== %s  %d interval(s)' % (os.path.relpath(f), len(rows)))
        for a, v, b, r in rows:
            print('   %8d .. %-8d  value=%d reserved=%d' % (a, b, v, r))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('tree', help='walk the chunk structure')
    p.add_argument('paths', nargs='+')
    p.add_argument('--depth', type=int, default=2)
    p.set_defaults(fn=cmd_tree)
    p = sub.add_parser('info', help='report the Vorbis stream parameters')
    p.add_argument('paths', nargs='+')
    p.set_defaults(fn=cmd_info)
    p = sub.add_parser('verify', help='check every Ogg page CRC')
    p.add_argument('paths', nargs='+')
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser('extract', help='write the Ogg stream out as .ogg')
    p.add_argument('paths', nargs='+')
    p.add_argument('-o', '--out', required=True)
    p.set_defaults(fn=cmd_extract)
    p = sub.add_parser('mou', help='decode .mou lip-sync tables')
    p.add_argument('paths', nargs='+')
    p.set_defaults(fn=cmd_mou)
    a = ap.parse_args()
    raise SystemExit(a.fn(a) or 0)


if __name__ == '__main__':
    main()
