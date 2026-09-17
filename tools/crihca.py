#!/usr/bin/env python3
"""crihca.py -- read CRI Middleware's `HCA` audio stream: its chunked header,
its frame grid, and the CRC-16 that every frame carries.

What this tool does and does not do, said first
------------------------------------------------

It reads the **container** completely and checks it three ways, one of which is
a CRC.  It does **not** decode HCA to PCM, and the refusal is deliberate and is
costed in docs/15.  The short version: HCA's inverse quantiser needs four
constant tables that are not derivable from an audio stream, and inventing them
would produce a decoder that runs, emits a wave file, and is wrong -- which is
precisely the defect this repository was opened to document in `unityfs.py`.

The tables are, however, **inside this object**, in
`SETSUNA_Data\\Plugins\\cri_ware_unity.dll`, and this tool locates them and
prints their offsets so that a later session can finish the job from the object
rather than from memory.  `tables` is that mode.  That same DLL carries the
decoder's own build banner, which `tables` prints.

The header, derived
--------------------

    'HCA\\0'  u16 BE version, u16 BE headerSize
    then chunks until headerSize, each named by four bytes whose high bit may
    be set (CRI masks the header of an encrypted file, so every tag is read
    with & 0x7f):

    'fmt\\0'  u8 channels, u24 BE sampleRate, u32 BE blockCount,
             u16 BE encoderDelay, u16 BE encoderPadding
    'comp'   u16 BE blockSize, then eight bytes: minResolution,
             maxResolution, trackCount, channelConfig, totalBandCount,
             baseBandCount, stereoBandCount, bandsPerHfrGroup, and two reserved
    'dec\\0'  the older form of 'comp'
    'vbr\\0' 'ath\\0' 'loop' 'ciph' 'rva\\0' 'comm' 'pad\\0'

THE CLOSURES, and there are three
----------------------------------

  1. `headerSize + blockCount * blockSize` equals the length of the stream.
     On this object that holds on 1,096 of 1,096 waveforms.
  2. every frame begins with the sync word 0xFFFF.
  3. **CRC-16/BUYPASS** (polynomial 0x8005, initial value 0, no reflection)
     over each whole frame including its own trailing checksum is **zero**.
     That is a sixteen-bit check on every one of the object's frames, and it
     is far stronger than a reader that merely does not crash.

    python crihca.py selftest
    python crihca.py info    FILE.hca
    python crihca.py verify  DIR|FILE...   -- every HCA in every CRI container
    python crihca.py census  DIR
    python crihca.py extract FILE --index N --out OUT.hca
    python crihca.py tables  DLL           -- the decoder tables, in the object

Standard library only.
"""

import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import criutf                                               # noqa: E402

SAMPLES_PER_FRAME = 1024


class Refused(Exception):
    pass


def _crc_table():
    t = []
    for i in range(256):
        v = i << 8
        for _ in range(8):
            v = ((v << 1) ^ 0x8005) & 0xffff if v & 0x8000 else (v << 1) & 0xffff
        t.append(v)
    return t


_CRC = _crc_table()


def crc16(b):
    """CRC-16/BUYPASS: poly 0x8005, init 0, no reflection, no final xor.

    Table-driven because the object holds 318,497,117 bytes of frame and the
    bit-at-a-time form is not a measurement anybody would wait for.  The
    selftest checks the standard vector crc16(b"123456789") == 0xFEE8, so the
    table is validated against a number that does not come from this object.
    """
    v = 0
    for x in b:
        v = ((v << 8) ^ _CRC[((v >> 8) ^ x) & 0xff]) & 0xffff
    return v


def _tag(d, o):
    return bytes(b & 0x7f for b in d[o:o + 4])


class Hca(object):
    def __init__(self, data, path='<memory>'):
        self.path = path
        self.data = data
        if len(data) < 8 or _tag(data, 0) != b'HCA\0':
            raise Refused('magic %r, not %r' % (data[:4], b'HCA\0'))
        self.version, self.header_size = struct.unpack_from('>HH', data, 4)
        if not 8 <= self.header_size <= len(data):
            raise Refused('headerSize %d in a %d-byte stream'
                          % (self.header_size, len(data)))
        self.chunks = collections.OrderedDict()
        self.channels = self.sample_rate = self.block_count = 0
        self.encoder_delay = self.encoder_padding = 0
        self.block_size = 0
        self.comp = None
        self.loop = None
        self.ciph = 0
        self.ath = 0
        o = 8
        while o < self.header_size - 2:
            t = _tag(data, o)
            if t == b'fmt\0':
                self.channels = data[o + 4]
                self.sample_rate = int.from_bytes(data[o + 5:o + 8], 'big')
                self.block_count, = struct.unpack_from('>I', data, o + 8)
                (self.encoder_delay,
                 self.encoder_padding) = struct.unpack_from('>HH', data, o + 12)
                self.chunks['fmt'] = 16
                o += 16
            elif t == b'comp':
                self.block_size, = struct.unpack_from('>H', data, o + 4)
                self.comp = list(data[o + 6:o + 16])
                self.chunks['comp'] = 16
                o += 16
            elif t == b'dec\0':
                self.block_size, = struct.unpack_from('>H', data, o + 4)
                self.comp = list(data[o + 6:o + 12])
                self.chunks['dec'] = 12
                o += 12
            elif t == b'vbr\0':
                self.chunks['vbr'] = 8
                o += 8
            elif t == b'ath\0':
                self.ath, = struct.unpack_from('>H', data, o + 4)
                self.chunks['ath'] = 6
                o += 6
            elif t == b'loop':
                s, e, a, b = struct.unpack_from('>IIHH', data, o + 4)
                self.loop = (s, e, a, b)
                self.chunks['loop'] = 16
                o += 16
            elif t == b'ciph':
                self.ciph, = struct.unpack_from('>H', data, o + 4)
                self.chunks['ciph'] = 6
                o += 6
            elif t == b'rva\0':
                self.chunks['rva'] = 8
                o += 8
            elif t == b'comm':
                n = data[o + 4]
                self.chunks['comm'] = 5 + n
                o += 5 + n
            elif t == b'pad\0':
                self.chunks['pad'] = self.header_size - o
                break
            else:
                raise Refused('unknown header chunk %r at offset %d' % (t, o))
        if not self.channels or not self.block_size:
            raise Refused('no fmt or no comp/dec chunk')
        # CLOSURE 1
        self.declared = self.header_size + self.block_count * self.block_size
        if self.declared != len(data):
            raise Refused('headerSize %d + %d frames of %d = %d against a '
                          '%d-byte stream'
                          % (self.header_size, self.block_count,
                             self.block_size, self.declared, len(data)))

    # -- frames ------------------------------------------------------------

    def frame(self, i):
        o = self.header_size + i * self.block_size
        return self.data[o:o + self.block_size]

    def check_frames(self):
        """(sync ok, crc ok, total) over every frame."""
        sync = crc = 0
        for i in range(self.block_count):
            f = self.frame(i)
            if struct.unpack_from('>H', f, 0)[0] == 0xFFFF:
                sync += 1
            if crc16(f) == 0:
                crc += 1
        return sync, crc, self.block_count

    @property
    def samples(self):
        """Sounding samples: the frame grid less the encoder's own padding."""
        return (self.block_count * SAMPLES_PER_FRAME - self.encoder_delay -
                self.encoder_padding)

    @property
    def seconds(self):
        return float(self.samples) / self.sample_rate if self.sample_rate else 0


# ------------------------------------------------------- finding every HCA

def every_hca(roots):
    """Yield (container path, index, name, bytes) for every HCA in the tree.

    An HCA lives in exactly two places in this object: inside an external
    `AFS2` bank (`.awb`), or inside the `AwbFile` column of an `.acb`.  Both
    are reached through `criutf.py`, so this walk inherits that reader's
    closures rather than scanning for a magic number.
    """
    for root in roots:
        for p in criutf.walk(root):
            try:
                with open(p, 'rb') as f:
                    head = f.read(4)
            except OSError:
                continue
            try:
                if head == b'AFS2':
                    b = criutf.load_afs2(p)
                    for i in range(b.count):
                        yield p, i, 'awb', b.payload(i)
                elif head == criutf.MAGIC and p.lower().endswith('.acb'):
                    a = criutf.load_acb(p)
                    b = a.awb()
                    if b is None:
                        continue
                    for i in range(b.count):
                        yield p, i, 'acb', b.payload(i)
            except criutf.Refused:
                continue


# ----------------------------------------------------------------- selftest

def _build(blocks=3, block_size=64, break_what=None):
    head = bytearray(b'HCA\0')
    head += struct.pack('>HH', 0x0200, 0)
    head += b'fmt\0' + bytes([2]) + (48000).to_bytes(3, 'big')
    head += struct.pack('>IHH', blocks, 1152, 329)
    head += b'comp' + struct.pack('>H', block_size)
    head += bytes([1, 15, 1, 0, 128, 128, 0, 0, 0, 0])
    head += b'ciph' + struct.pack('>H', 0)
    head += b'pad\0'
    while len(head) % 16:
        head += b'\0'
    hs = len(head)
    struct.pack_into('>H', head, 6, hs)
    body = bytearray()
    for i in range(blocks):
        f = bytearray(struct.pack('>H', 0xFFFF))
        f += bytes(((i * 31 + j) & 0xff) for j in range(block_size - 4))
        f += struct.pack('>H', crc16(bytes(f)))
        body += f
    out = bytearray(head + body)
    if break_what == 'crc':
        out[hs + 5] ^= 0x01
    if break_what == 'sync':
        out[hs] = 0x00
    if break_what == 'blocks':
        struct.pack_into('>I', out, 16, blocks + 1)
    if break_what == 'magic':
        out[0:4] = b'HCB\0'
    if break_what == 'chunk':
        # the 'ciph' tag, at 8 + fmt(16) + comp(16); corrupting the padding
        # instead would prove nothing, because 'pad' ends the walk
        out[40:44] = b'zzzz'
    return bytes(out)


def cmd_selftest(_args):
    print('crihca.py selftest -- streams built in memory, most of them')
    print('required to be REFUSED, and the CRC-16 checked against a frame')
    print('this file computed itself.')
    print()
    ok = bad = 0

    def expect_ok(name, blob, want_crc):
        nonlocal ok, bad
        try:
            h = Hca(blob)
            s, c, n = h.check_frames()
            if (s, c) == (n, n) == (want_crc, want_crc):
                print('  ACCEPT  %-38s %d frames, sync %d, crc %d'
                      % (name, n, s, c))
                ok += 1
            else:
                print('  ACCEPT  %-38s *** sync %d crc %d of %d'
                      % (name, s, c, n))
                bad += 1
        except Refused as ex:
            print('  ACCEPT  %-38s *** WRONGLY REFUSED: %s' % (name, ex))
            bad += 1

    def expect_refuse(name, blob, because, frames=False):
        nonlocal ok, bad
        try:
            h = Hca(blob)
            if frames:
                s, c, n = h.check_frames()
                if c != n:
                    print('  REFUSE  %-38s crc fails on %d of %d frames'
                          % (name, n - c, n))
                    ok += 1
                    return
                if s != n:
                    print('  REFUSE  %-38s sync fails on %d of %d frames'
                          % (name, n - s, n))
                    ok += 1
                    return
            print('  REFUSE  %-38s *** WRONGLY ACCEPTED (%s)' % (name, because))
            bad += 1
        except Refused as ex:
            print('  REFUSE  %-38s %s' % (name, ex))
            ok += 1

    print('  CRC-16/BUYPASS check vector: crc16(b"123456789") = 0x%04X, '
          'expected 0xFEE8' % crc16(b'123456789'))
    if crc16(b'123456789') == 0xFEE8:
        ok += 1
    else:
        bad += 1
    print()
    expect_ok('3 frames of 64', _build(), 3)
    expect_ok('40 frames of 1024', _build(40, 1024), 40)
    expect_refuse('HCB magic', _build(break_what='magic'), 'wrong container')
    expect_refuse('blockCount off by one', _build(break_what='blocks'),
                  'closure 1')
    expect_refuse('an unknown header chunk', _build(break_what='chunk'),
                  'never guess a chunk')
    expect_refuse('one bit flipped in a frame', _build(break_what='crc'),
                  'the CRC', frames=True)
    expect_refuse('a broken sync word', _build(break_what='sync'),
                  'closure 2', frames=True)
    expect_refuse('an @UTF table', b'@UTF' + b'\0' * 64, 'wrong container')
    expect_refuse('an AFS2 bank', b'AFS2' + b'\0' * 64, 'wrong container')
    expect_refuse('empty', b'', 'too short')
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


# ----------------------------------------------------------------- commands

def cmd_info(args):
    with open(args.paths[0], 'rb') as f:
        h = Hca(f.read(), args.paths[0])
    s, c, n = h.check_frames()
    print(args.paths[0])
    print()
    print('version          %d.%02d' % (h.version >> 8, h.version & 0xff))
    print('headerSize       %d' % h.header_size)
    print('chunks           %s' % ', '.join('%s(%d)' % kv
                                            for kv in h.chunks.items()))
    print('channels         %d' % h.channels)
    print('sample rate      %d' % h.sample_rate)
    print('frames           %d of %d bytes' % (h.block_count, h.block_size))
    print('encoder delay    %d      padding %d'
          % (h.encoder_delay, h.encoder_padding))
    print('samples          %d      %.3f seconds' % (h.samples, h.seconds))
    if h.comp:
        names = ('minResolution', 'maxResolution', 'trackCount',
                 'channelConfig', 'totalBandCount', 'baseBandCount',
                 'stereoBandCount', 'bandsPerHfrGroup')
        for nm, v in zip(names, h.comp):
            print('  %-16s %d' % (nm, v))
    if h.loop:
        print('loop             start frame %d, end frame %d, %d/%d'
              % h.loop)
    print('cipher           %d%s' % (h.ciph,
                                     '  (none)' if h.ciph == 0 else ''))
    print('ath              %d' % h.ath)
    print()
    print('closure 1  headerSize + frames x frameSize = %d, stream is %d'
          % (h.declared, len(h.data)))
    print('closure 2  sync word 0xFFFF on %d of %d frames' % (s, n))
    print('closure 3  CRC-16 zero on %d of %d frames' % (c, n))
    return 0


def cmd_verify(args):
    n = 0
    sync_ok = crc_ok = frames = 0
    refused = []
    for p, i, kind, blob in every_hca(args.paths):
        try:
            h = Hca(blob, '%s[%d]' % (p, i))
        except Refused as ex:
            refused.append(('%s[%d]' % (p, i), str(ex)))
            continue
        n += 1
        s, c, fn = h.check_frames()
        sync_ok += s
        crc_ok += c
        frames += fn
        if args.limit and n >= args.limit:
            break
    print('HCA streams read           : %d' % n)
    print('frames                     : %d' % frames)
    print('sync word 0xFFFF           : %d of %d' % (sync_ok, frames))
    print('CRC-16 zero over the frame : %d of %d' % (crc_ok, frames))
    print('refused                    : %d' % len(refused))
    for p, why in refused[:10]:
        print('  %-48s %s' % (p[-48:], why))
    return 0 if (n and sync_ok == frames == crc_ok and not refused) else 2


def cmd_census(args):
    rates = collections.Counter()
    chans = collections.Counter()
    versions = collections.Counter()
    ciphers = collections.Counter()
    comps = collections.Counter()
    loops = 0
    n = 0
    samples = 0
    seconds = 0.0
    bytes_ = 0
    per_kind = collections.Counter()
    per_dir = collections.defaultdict(lambda: [0, 0.0])
    refused = []
    for p, i, kind, blob in every_hca(args.paths):
        try:
            h = Hca(blob)
        except Refused as ex:
            refused.append(('%s[%d]' % (p, i), str(ex)))
            continue
        n += 1
        bytes_ += len(blob)
        rates[h.sample_rate] += 1
        chans[h.channels] += 1
        versions['%d.%02d' % (h.version >> 8, h.version & 0xff)] += 1
        ciphers[h.ciph] += 1
        if h.comp:
            comps[tuple(h.comp[:8])] += 1
        if h.loop:
            loops += 1
        samples += h.samples
        seconds += h.seconds
        per_kind[kind] += 1
        d = os.path.basename(os.path.dirname(os.path.dirname(p)))
        per_dir[d][0] += 1
        per_dir[d][1] += h.seconds
    print('HCA streams        : %d' % n)
    print('  in external .awb : %d' % per_kind['awb'])
    print('  in .acb AwbFile  : %d' % per_kind['acb'])
    print('bytes              : %d' % bytes_)
    print('sample rates       : %s' % dict(rates))
    print('channels           : %s' % dict(chans))
    print('versions           : %s' % dict(versions))
    print('ciphers            : %s' % dict(ciphers))
    print('with a loop chunk  : %d' % loops)
    print('total samples      : %d' % samples)
    print('total playing time : %.1f seconds = %d min %02d s'
          % (seconds, int(seconds) // 60, int(seconds) % 60))
    print()
    print('%-16s %8s %14s' % ('BRANCH', 'STREAMS', 'SECONDS'))
    for d in sorted(per_dir):
        print('%-16s %8d %14.1f' % (d, per_dir[d][0], per_dir[d][1]))
    print()
    print('comp parameter sets: %d distinct' % len(comps))
    for k, v in comps.most_common(5):
        print('  %s  x%d' % (list(k), v))
    if refused:
        print()
        print('%d refused:' % len(refused))
        for p, why in refused[:10]:
            print('  %s  %s' % (p[-48:], why))
    return 0


def cmd_extract(args):
    for p, i, kind, blob in every_hca([args.paths[0]]):
        if i != args.index:
            continue
        h = Hca(blob)
        with open(args.out, 'wb') as f:
            f.write(blob)
        s, c, n = h.check_frames()
        print('%s[%d] -> %s, %d bytes' % (p, i, args.out, len(blob)))
        print('  %d channels, %d Hz, %d frames, %.3f seconds'
              % (h.channels, h.sample_rate, h.block_count, h.seconds))
        print('  sync %d of %d, CRC-16 zero %d of %d' % (s, n, c, n))
        return 0
    raise Refused('no HCA at index %d' % args.index)


# -------------------------------------------------- the tables, in the object

# Each table is found by a byte pattern rather than by an absolute offset, so
# that the finding survives a different build of the DLL and so that nothing
# here is a magic number typed from a disassembler.
ANCHORS = (
    ('invert table (resolution from curvature)', 66,
     bytes([14, 14, 14, 14, 14, 14, 13, 13, 13, 13, 13, 13, 12, 12, 12, 12])),
    ('max bits per resolution', 16,
     bytes([0, 2, 3, 3, 4, 4, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12])),
)
BANNER = b'HCA Decoder'


# A CRI component signs itself with a name, a version and, for most of them,
# the compiler's __DATE__ and __TIME__ in the build machine's local time.  The
# pattern is deliberately loose about the name and strict about `Ver.`, so a
# component that has no build stamp is still found.
import re                                                   # noqa: E402
_BANNER = re.compile(
    rb'[A-Za-z][A-Za-z0-9 ()/_.\-]{4,70}Ver\.[0-9][0-9.]*'
    rb' ?(?:Build:[A-Za-z]{3} [ 0-9]{1,2} [0-9]{4} [0-9:]{8})?')


def banners(data):
    out = []
    seen = set()
    for m in _BANNER.finditer(data):
        s = m.group().decode('latin1').strip()
        if s not in seen:
            seen.add(s)
            out.append((m.start(), s))
    return out


def cmd_tables(args):
    with open(args.paths[0], 'rb') as f:
        d = f.read()
    print('%s, %d bytes' % (args.paths[0], len(d)))
    print()
    i = d.find(BANNER)
    if i >= 0:
        z = d.find(b'\0', i)
        print('decoder banner at %d:' % i)
        for line in d[i:z].decode('latin1').split('\n'):
            if line.strip():
                print('  %s' % line.strip())
        print()
    b = banners(d)
    if b:
        print('%d component banners, each a name, a version and (mostly) the'
              % len(b))
        print('compiler\'s __DATE__ and __TIME__ in the build machine\'s')
        print('LOCAL time:')
        for off, s in b:
            print('  %9d  %s' % (off, s))
        # sorted by parsed time, not lexicographically: "Apr 18 2016" sorts
        # before "May 14 2015" as a string and after it as a date, and the
        # first version of this printed the wrong pair.
        import time
        stamps = []
        for _o, s in b:
            if 'Build:' not in s:
                continue
            t = s.split('Build:')[1].strip()
            try:
                stamps.append((time.strptime(t, '%b %d %Y %H:%M:%S'), t))
            except ValueError:
                continue
        stamps.sort()
        if stamps:
            print()
            print('components with a build stamp : %d of %d'
                  % (len(stamps), len(b)))
            print('earliest build stamp : %s' % stamps[0][1])
            print('latest build stamp   : %s' % stamps[-1][1])
        print()
    print('%-42s %10s %6s' % ('TABLE', 'OFFSET', 'BYTES'))
    found = 0
    for name, size, pat in ANCHORS:
        o = d.find(pat)
        if o < 0:
            print('%-42s %10s %6s' % (name, 'not found', '-'))
            continue
        found += 1
        print('%-42s %10d %6d' % (name, o, size))
        print('     %s' % ' '.join(str(b) for b in d[o:o + min(size, 40)]))
    print()
    print('%d of %d anchors found.  These are constants an inverse quantiser'
          % (found, len(ANCHORS)))
    print('needs and which an audio stream does not contain; they are')
    print('published here so that a later session can take them from the')
    print('object instead of from memory.  This tool does not decode HCA to')
    print('PCM and says so in docs/15 with the reason.')
    return 0 if found == len(ANCHORS) else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'info', 'verify', 'census',
                                     'extract', 'tables'))
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--index', type=int, default=0)
    ap.add_argument('--out')
    ap.add_argument('--limit', type=int, default=0)
    args = ap.parse_args()
    if args.mode != 'selftest' and not args.paths:
        ap.error('%s needs a path' % args.mode)
    if args.mode == 'extract' and not args.out:
        ap.error('extract needs --out')
    try:
        return globals()['cmd_' + args.mode](args)
    except Refused as ex:
        sys.stderr.write('REFUSED: %s\n' % ex)
        return 2


if __name__ == '__main__':
    sys.exit(main())
