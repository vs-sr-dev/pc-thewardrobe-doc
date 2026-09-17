#!/usr/bin/env python3
"""
askadisc.py - reader for the ASKA disc images in the Tales of Crestoria APK.

`assets/aska0000.bin` and the `assets/disc1/f0000N.bin` set are the engine's
virtual-disc containers, addressed in 512-byte blocks. An image is formatted by
filling it with a repeating 192-byte pattern; sector 0 then holds a 160-byte
header stamped 0x34829314 stored XORed against that same pattern, and payload
files are written in over the fill in the clear. Because most of a shipped image
was never written, the pattern is sitting right there in the file, which is what
makes sector 0 readable at all.

This tool recovers the pattern from the image itself, decodes the header, checks
that the allocation chain is self-consistent, and reports which sectors actually
carry data. See docs/formats/disc.md.

Standalone Python 3, no dependencies.
"""
import argparse, os, struct
from collections import Counter

SECTOR = 512
KEY_PERIOD = 192
HEADER_SIZE = 0xA0
MAGIC = 0x34829314


class DiscError(Exception):
    pass


def derive_keystream(data, period=KEY_PERIOD):
    """Recover the fill pattern from the image itself.

    An image is formatted by filling it with a repeating 192-byte pattern, and
    sector 0 is stored XORed against that same pattern. Any stretch of the image
    that was never written is therefore exactly periodic, and the longest such
    stretch hands over the pattern with its phase intact.
    """
    if len(data) < period * 8:
        raise DiscError('image too small to recover a fill pattern')
    best_start = best_len = 0
    i, n = 0, len(data)
    while i < n - period:
        j = i
        while j < n - period and data[j] == data[j + period]:
            j += 1
        if j - i > best_len:
            best_start, best_len = i, j - i
        i = j + 1
    if best_len < period * 4:
        raise DiscError('no long periodic run: image does not look formatted')
    phase = best_start % period
    run = data[best_start:best_start + period]
    return run[-phase:] + run[:-phase] if phase else run


def decode(data, keystream, offset=0):
    return bytes(c ^ keystream[(offset + i) % len(keystream)] for i, c in enumerate(data))


class Header:
    __slots__ = ('version', 'revision', 'magic', 'entry_count', 'entry_bytes',
                 'payload_lba', 'words')

    def describe(self):
        return ('magic=0x%08x version=%d.%d entries=%d (%d bytes) payload_lba=%d'
                % (self.magic, self.version, self.revision, self.entry_count,
                   self.entry_bytes, self.payload_lba))


def read_header(data, keystream):
    h = Header()
    raw = decode(data[:HEADER_SIZE], keystream)
    h.words = struct.unpack_from('<40I', raw, 0)
    h.version, h.revision, h.magic = h.words[0], h.words[1], h.words[2]
    if h.magic != MAGIC:
        raise DiscError('sector 0 is not an ASKA disc header (got 0x%08x)' % h.magic)
    h.entry_count, h.entry_bytes = h.words[6], h.words[7]
    h.payload_lba = h.words[8]
    return h


def allocations(header):
    """The (block_count, byte_size, start_lba) triples the header chains.

    Files are laid out end to end in 512-byte blocks. Each record gives a block
    count, a byte size and the LBA the file starts at; the next record's LBA is
    always this one's LBA plus this one's block count, which is what identifies
    the three fields as a group.
    """
    w = header.words
    out = []
    i = 6
    while i + 2 < len(w) and w[i]:
        out.append((w[i], w[i + 1], w[i + 2]))
        i += 3
    return out


def classify(data, keystream):
    """Count sectors that are empty (bare keystream), literal zeros, or written."""
    counts = Counter()
    written = []
    for s in range(len(data) // SECTOR):
        sec = data[s * SECTOR:(s + 1) * SECTOR]
        ks = bytes(keystream[(s * SECTOR + i) % len(keystream)] for i in range(SECTOR))
        if sec == ks:
            counts['unwritten'] += 1
        elif not any(sec):
            counts['zero'] += 1
        else:
            counts['written'] += 1
            written.append(s)
    return counts, written


def runs(sectors):
    out = []
    start = prev = None
    for s in sectors:
        if start is None:
            start = s
        elif s != prev + 1:
            out.append((start, prev))
            start = s
        prev = s
    if start is not None:
        out.append((start, prev))
    return out


def _walk(paths):
    for path in paths:
        if os.path.isdir(path):
            for dp, _, fn in os.walk(path):
                for x in sorted(fn):
                    yield os.path.join(dp, x)
        else:
            yield path


def cmd_info(args):
    for f in _walk(args.paths):
        data = open(f, 'rb').read()
        if len(data) < KEY_PERIOD * 8:
            continue
        ks = derive_keystream(data)
        print('== %s  %d bytes (%d sectors)' % (os.path.relpath(f), len(data), len(data) // SECTOR))
        try:
            h = read_header(data, ks)
        except DiscError as e:
            print('   %s' % e)
            continue
        print('   %s' % h.describe())
        print('   %6s %10s %12s %s' % ('lba', 'blocks', 'bytes', 'chain'))
        expect = None
        for count, size, lba in allocations(h):
            note = '' if expect is None else ('ok' if lba == expect else 'BREAK (expected %d)' % expect)
            print('   %6d %10d %12d %s' % (lba, count, size, note))
            expect = lba + count


def cmd_map(args):
    for f in _walk(args.paths):
        data = open(f, 'rb').read()
        if len(data) < KEY_PERIOD * 8:
            continue
        ks = derive_keystream(data)
        counts, written = classify(data, ks)
        print('== %s' % os.path.relpath(f))
        print('   sectors: written=%d unwritten=%d zero=%d'
              % (counts['written'], counts['unwritten'], counts['zero']))
        print('   written runs: %s' % ', '.join('%d-%d' % r for r in runs(written)[:16]))


def cmd_keystream(args):
    data = open(args.path, 'rb').read()
    ks = derive_keystream(data)
    for i in range(0, len(ks), 32):
        print('  %04x: %s' % (i, ks[i:i + 32].hex()))


def cmd_decode(args):
    data = open(args.path, 'rb').read()
    ks = derive_keystream(data)
    open(args.out, 'wb').write(decode(data, ks))
    print('wrote %s (%d bytes)' % (args.out, len(data)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('info', help='decode the header and allocation chain')
    p.add_argument('paths', nargs='+')
    p.set_defaults(fn=cmd_info)
    p = sub.add_parser('map', help='classify every sector')
    p.add_argument('paths', nargs='+')
    p.set_defaults(fn=cmd_map)
    p = sub.add_parser('keystream', help='print the recovered 192-byte keystream')
    p.add_argument('path')
    p.set_defaults(fn=cmd_keystream)
    p = sub.add_parser('decode', help='XOR a whole image against its keystream')
    p.add_argument('path')
    p.add_argument('-o', '--out', required=True)
    p.set_defaults(fn=cmd_decode)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
