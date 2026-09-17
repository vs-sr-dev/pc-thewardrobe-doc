#!/usr/bin/env python3
"""Read FMOD Sound Bank version 5 headers: what audio a Unity build ships.

The `.resource` files beside a Unity serialized file are where AudioClip data
goes, and on this build they are FSB5 banks -- FMOD's container, which Unity
uses as its own.  That is a different answer from *Tales of Crestoria*, whose
`.aac` files hold Ogg Vorbis inside tri-Ace's own `AAC ` chunk container, and
the difference is the point: the audio pipeline came with the engine both
times, and the engine is not the same engine.

The format, as this build writes it:

    +0x00  "FSB5"
    +0x04  u32  version (0 or 1)
    +0x08  u32  sample count
    +0x0C  u32  size of the sample header block
    +0x10  u32  size of the name table
    +0x14  u32  size of the sample data
    +0x18  u32  codec
    +0x1C  8 zero bytes, 16 bytes of hash, 8 unused
    (version 0 has one extra u32 here)

then one 64-bit word per sample, bit-packed:

    bit  0        another parameter chunk follows
    bits 1..4     sample rate, as an index into a fixed table
    bit  5        channel count minus one
    bits 6..33    data offset, in units of 32 bytes
    bits 34..63   length in samples

and then, optionally, per-sample parameter chunks in the same shape, a name
table of u32 offsets followed by NUL-terminated names, and the sample data.

The positive control is free and it is the one this repository asks every
container for: the header declares `sampleHeadersSize`, `nameTableSize` and
`dataSize`, and 60 + those three must equal the file.  A reader with the layout
wrong fails that sum rather than producing plausible nonsense.

    python fsb5.py info FILE...
    python fsb5.py census DIR
    python fsb5.py walk FILE... [--names]   -- a file of banks end to end
    python fsb5.py clips DIR [--list]       -- AudioClip records vs the banks
    python fsb5.py --selftest

Standard library only.  Nothing here decodes audio; it reads headers.

`clips` reads the AudioClip objects (class 83) of every serialized file in
a tree with `unityfs.py`, at the version-17 layout measured on this object:

    aligned string  m_Name
    i32 m_LoadType, i32 m_Channels, i32 m_Frequency, i32 m_BitsPerSample,
    f32 m_Length, u8 m_IsTrackerFormat, align, i32 m_SubsoundIndex,
    u8 m_PreloadAudioData, u8 m_LoadInBackground, u8 m_Legacy3D, align,
    m_Resource: aligned string m_Source, u64 m_Offset, u64 m_Size,
    i32 m_CompressionFormat (0 PCM, 1 Vorbis, 2 ADPCM, 3 MP3 ...)

and matches each record to the bank that starts at its offset in the
named `.resource`.  THE CHECKS: the record's size is the bank's length; the
clip's channels and frequency are the bank's; the clip's compression format
agrees with the bank's codec (0 <-> PCM16, 1 <-> Vorbis); every bank is
claimed by exactly one clip.  The clip's m_Name is the bank's name, since
the banks carry none.

ADDED ON pc-monstrum-doc (Unity 5.5.0f3, four `.resource` files).  There a
`.resource` is not one bank: it is one bank PER AUDIOCLIP, laid end to end,
each pointed at by its clip's `m_Resource` (offset, size) in the serialized
file, and each with its own `FSB5` head, its own codec and usually no name
table (the name is the AudioClip's).  `info` on such a file reads the first
bank and reports DISAGREES on the size, which is right and useless.  `walk`
steps from bank to bank by each one's declared length and closes on the
file: the last bank must end at the last byte, every head must read `FSB5`,
and the count, the codecs, the sample rates, the channels and the seconds
are summed over the chain.  A `.resource` that fails the closure is reported
with the offset where the chain broke, not silently truncated.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                            # noqa: E402
import nameguard                                           # noqa: E402

nameguard.guard()

RATES = [0, 8000, 11000, 11025, 16000, 22050, 24000, 32000, 44100, 48000,
         96000]

CODEC = {
    0: 'none', 1: 'PCM8', 2: 'PCM16', 3: 'PCM24', 4: 'PCM32', 5: 'PCMFLOAT',
    6: 'GCADPCM', 7: 'IMAADPCM', 8: 'VAG', 9: 'HEVAG', 10: 'XMA', 11: 'MPEG',
    12: 'CELT', 13: 'ATRAC9', 14: 'XWMA', 15: 'Vorbis', 16: 'FADPCM',
    17: 'Opus',
}

CHUNK = {1: 'channels', 2: 'frequency', 3: 'loop', 6: 'xmaseek',
         7: 'dspcoeff', 9: 'xwmadata', 10: 'vorbisdata'}


class Fsb5(object):
    def __init__(self, data, path='?'):
        if data[:4] != b'FSB5':
            raise ValueError('not an FSB5 bank')
        self.data = data
        self.path = path
        (self.version, self.n_samples, self.hdr_size, self.name_size,
         self.data_size, self.codec) = struct.unpack_from('<6I', data, 4)
        self.base = 60 if self.version == 1 else 64
        self.declared = self.base + self.hdr_size + self.name_size + self.data_size
        self.samples = []
        pos = self.base
        end = self.base + self.hdr_size
        for _ in range(self.n_samples):
            if pos + 8 > len(data):
                break
            raw = struct.unpack_from('<Q', data, pos)[0]
            pos += 8
            more = raw & 1
            rate_i = (raw >> 1) & 0xF
            chans = ((raw >> 5) & 1) + 1
            off = ((raw >> 6) & 0xFFFFFFF) * 32
            nsamp = (raw >> 34) & 0x3FFFFFFF
            chunks = []
            while more and pos + 4 <= end:
                c = struct.unpack_from('<I', data, pos)[0]
                pos += 4
                more = c & 1
                size = (c >> 1) & 0xFFFFFF
                kind = (c >> 25) & 0x7F
                body = data[pos:pos + size]
                if kind == 1 and size >= 1:
                    chans = body[0]
                elif kind == 2 and size >= 4:
                    rate_i = -1
                    self._freq = struct.unpack_from('<I', body, 0)[0]
                chunks.append((kind, size))
                pos += size
            rate = (RATES[rate_i] if 0 <= rate_i < len(RATES)
                    else getattr(self, '_freq', 0))
            self.samples.append(dict(offset=off, samples=nsamp, rate=rate,
                                     channels=chans, chunks=chunks))
        self.names = []
        if self.name_size:
            nbase = self.base + self.hdr_size
            try:
                offs = struct.unpack_from('<%dI' % self.n_samples, data, nbase)
                for o in offs:
                    p = nbase + o
                    e = data.find(b'\0', p)
                    self.names.append(data[p:e].decode('utf-8', 'replace'))
            except struct.error:
                pass
        # sizes: each sample runs to the next one's offset, the last to the end
        dbase = self.base + self.hdr_size + self.name_size
        for i, s in enumerate(self.samples):
            nxt = (self.samples[i + 1]['offset'] if i + 1 < len(self.samples)
                   else self.data_size)
            s['bytes'] = nxt - s['offset']
            s['file_offset'] = dbase + s['offset']
            s['seconds'] = s['samples'] / s['rate'] if s['rate'] else 0.0


def walk_banks(data):
    """Every bank in a file of banks laid end to end: (offset, Fsb5).

    Stops at the first offset that does not read `FSB5` and reports it; the
    caller decides whether that is the end of the file (closure) or a break.
    """
    banks = []
    pos = 0
    while pos + 64 <= len(data):
        if data[pos:pos + 4] != b'FSB5':
            break
        # sample headers and names are read relative to the bank, so hand
        # the parser the bank's own slice, cut by its declared length
        version, n, hdr, names, dsize = struct.unpack_from('<5I', data, pos + 4)
        base = 60 if version == 1 else 64
        end = pos + base + hdr + names + dsize
        b = Fsb5(data[pos:end], 'bank@%d' % pos)
        banks.append((pos, b))
        if end <= pos:
            break
        pos = end
    return banks, pos


def cmd_walk(argv):
    names = '--names' in argv
    for path in [a for a in argv[2:] if not a.startswith('--')]:
        dirguard.want_file(path, 'fsb5')
        data = open(path, 'rb').read()
        if data[:4] != b'FSB5':
            print('%s: does not begin with FSB5' % path)
            continue
        banks, end = walk_banks(data)
        codecs = {}
        rates = {}
        chans = {}
        secs = 0.0
        nsamp = 0
        named = 0
        for off, b in banks:
            codecs[CODEC.get(b.codec, str(b.codec))] = \
                codecs.get(CODEC.get(b.codec, str(b.codec)), 0) + 1
            for s in b.samples:
                rates[s['rate']] = rates.get(s['rate'], 0) + 1
                chans[s['channels']] = chans.get(s['channels'], 0) + 1
                secs += s['seconds']
            nsamp += len(b.samples)
            named += bool(b.names)
        print('=' * 72)
        print('%s   %d bytes' % (path, len(data)))
        print('=' * 72)
        print('  banks              %d' % len(banks))
        print('  samples            %d' % nsamp)
        print('  chain ends at      %d   %s'
              % (end, 'the last byte: CLOSES' if end == len(data)
                 else 'NOT the file end (%d bytes remain)' % (len(data) - end)))
        print('  banks with names   %d' % named)
        print('  codecs             %s'
              % ', '.join('%s x%d' % kv for kv in sorted(codecs.items())))
        print('  sample rates       %s'
              % ', '.join('%d x%d' % kv for kv in sorted(rates.items())))
        print('  channels           %s'
              % ', '.join('%d x%d' % kv for kv in sorted(chans.items())))
        print('  seconds            %.2f  (%.2f minutes)' % (secs, secs / 60))
        if names:
            print()
            print('  %-10s %-10s %8s %6s %3s %10s %8s'
                  % ('OFFSET', 'CODEC', 'SAMPLES', 'RATE', 'CH', 'BYTES',
                     'SECONDS'))
            for off, b in banks:
                for s in b.samples:
                    print('  %-10d %-10s %8d %6d %3d %10d %8.2f'
                          % (off, CODEC.get(b.codec, str(b.codec)),
                             s['samples'], s['rate'], s['channels'],
                             s['bytes'], s['seconds']))
        print()


def read_clip(body, little=True):
    """One AudioClip body at serialization version 17; None if it does not
    parse to the last byte (+0..3 of padding)."""
    e = '<' if little else '>'
    if len(body) < 4:
        return None
    n, = struct.unpack_from(e + 'i', body, 0)
    if not 0 <= n <= 4096 or 4 + n > len(body):
        return None
    name = body[4:4 + n].decode('utf-8', 'replace')
    p = (4 + n + 3) & ~3
    if p + 20 > len(body):
        return None
    load, ch, freq, bits = struct.unpack_from(e + '4i', body, p)
    length, = struct.unpack_from(e + 'f', body, p + 16)
    p += 20
    p = (p + 1 + 3) & ~3                       # m_IsTrackerFormat, align
    if p + 4 > len(body):
        return None
    p += 4                                     # m_SubsoundIndex
    p = (p + 3 + 3) & ~3                       # three bools, align
    if p + 4 > len(body):
        return None
    sn, = struct.unpack_from(e + 'i', body, p)
    if not 0 <= sn <= 1024 or p + 4 + sn > len(body):
        return None
    source = body[p + 4:p + 4 + sn].decode('utf-8', 'replace')
    p = (p + 4 + sn + 3) & ~3
    if p + 20 > len(body):
        return None
    off, size = struct.unpack_from(e + 'QQ', body, p)
    fmt, = struct.unpack_from(e + 'i', body, p + 16)
    end = p + 20
    if not 0 <= len(body) - end <= 3:
        return None
    return dict(name=name, load_type=load, channels=ch, frequency=freq,
                bits=bits, length=length, source=source, offset=off,
                size=size, format=fmt)


CLIP_FORMAT = {0: 'PCM', 1: 'Vorbis', 2: 'ADPCM', 3: 'MP3', 4: 'VAG',
               5: 'HEVAG', 6: 'XMA', 7: 'AAC', 8: 'GCADPCM', 9: 'ATRAC9'}
CODEC_OF_FORMAT = {0: 'PCM16', 1: 'Vorbis', 2: 'IMAADPCM', 3: 'MPEG'}


def cmd_clips(argv):
    import unityfs
    root = argv[2]
    dirguard.want_tree(root, 'fsb5')
    listing = '--list' in argv
    clips = []
    unparsed = 0
    for p in unityfs.walk(root):
        if not unityfs.is_serialized(p):
            continue
        sf = unityfs.load(p)
        for o in sf.objects:
            if sf.class_of(o) != 83:
                continue
            c = read_clip(sf.body(o), sf.endianness == 0)
            if c is None:
                unparsed += 1
                continue
            c['file'] = os.path.relpath(p, root).replace(os.sep, '/')
            clips.append(c)
    # the banks, by resource file
    banks = {}
    for c in clips:
        src_ = c['source']
        if src_ and src_ not in banks:
            fp = os.path.join(root, src_)
            if os.path.isfile(fp):
                data = open(fp, 'rb').read()
                bl, end = walk_banks(data)
                banks[src_] = (dict(bl), len(data), end)
            else:
                banks[src_] = ({}, -1, -1)
    per_src = {}
    size_ok = ch_ok = fr_ok = codec_ok = matched = 0
    claimed = {}
    fmts = {}
    no_source = 0
    for c in clips:
        fmts[CLIP_FORMAT.get(c['format'], str(c['format']))] = \
            fmts.get(CLIP_FORMAT.get(c['format'], str(c['format'])), 0) + 1
        if not c['source']:
            no_source += 1
            continue
        per_src[c['source']] = per_src.get(c['source'], 0) + 1
        bl, fsize, end = banks.get(c['source'], ({}, -1, -1))
        b = bl.get(c['offset'])
        if b is None:
            continue
        matched += 1
        claimed[(c['source'], c['offset'])] = \
            claimed.get((c['source'], c['offset']), 0) + 1
        size_ok += (b.declared == c['size'])
        s = b.samples[0] if b.samples else {}
        ch_ok += (s.get('channels') == c['channels'])
        fr_ok += (s.get('rate') == c['frequency'])
        codec_ok += (CODEC.get(b.codec) == CODEC_OF_FORMAT.get(c['format']))
    print('AudioClip objects        %d  (%d bodies did not parse)'
          % (len(clips), unparsed))
    print('with a resource record   %d   without %d' % (len(clips) - no_source,
                                                       no_source))
    print('matched to a bank        %d' % matched)
    print('  size == bank length    %d' % size_ok)
    print('  channels agree         %d' % ch_ok)
    print('  frequency agrees       %d' % fr_ok)
    print('  codec agrees           %d' % codec_ok)
    print('clip compression formats %s'
          % ', '.join('%s x%d' % kv for kv in sorted(fmts.items())))
    print()
    print('%-28s %6s %6s %8s  %s' % ('RESOURCE', 'CLIPS', 'BANKS', 'CLAIMED',
                                     'CHAIN'))
    for s_ in sorted(banks):
        bl, fsize, end = banks[s_]
        cl = sum(1 for k in claimed if k[0] == s_)
        multi = sum(1 for k, v in claimed.items() if k[0] == s_ and v > 1)
        print('%-28s %6d %6d %8d  %s%s'
              % (s_, per_src.get(s_, 0), len(bl), cl,
                 'closes' if end == fsize else 'open at %d of %d' % (end, fsize),
                 ('; %d banks claimed by more than one clip' % multi)
                 if multi else ''))
    if listing:
        print()
        print('%-44s %-9s %2s %6s %8s %-26s %s'
              % ('NAME', 'FORMAT', 'CH', 'HZ', 'SECONDS', 'SOURCE', 'FILE'))
        for c in sorted(clips, key=lambda c: c['name']):
            print('%-44s %-9s %2d %6d %8.2f %-26s %s'
                  % (c['name'][:44], CLIP_FORMAT.get(c['format'],
                                                     str(c['format'])),
                     c['channels'], c['frequency'], c['length'],
                     c['source'] or '(none)', c['file']))
    return 0


def cmd_info(argv):
    for path in [a for a in argv[2:] if not a.startswith('--')]:
        dirguard.want_file(path, 'fsb5')
        data = open(path, 'rb').read()
        try:
            b = Fsb5(data, path)
        except ValueError as e:
            print('%s: %s' % (path, e))
            continue
        print('=' * 72)
        print('%s   %d bytes' % (path, len(data)))
        print('=' * 72)
        print('  version            %d  (header %d bytes)' % (b.version, b.base))
        print('  samples            %d' % b.n_samples)
        print('  codec              %s (%d)'
              % (CODEC.get(b.codec, '?'), b.codec))
        print('  sample headers     %d bytes' % b.hdr_size)
        print('  name table         %d bytes, %d names read'
              % (b.name_size, len(b.names)))
        print('  sample data        %d bytes' % b.data_size)
        print('  60 + the three     %d' % b.declared)
        print('  file size          %d   %s'
              % (len(data),
                 'agrees' if b.declared == len(data) else 'DISAGREES'))
        print()
        print('  %-34s %10s %9s %5s %12s %9s'
              % ('NAME', 'SAMPLES', 'RATE', 'CH', 'BYTES', 'SECONDS'))
        for i, s in enumerate(b.samples):
            nm = b.names[i] if i < len(b.names) else '(unnamed)'
            print('  %-34s %10d %9d %5d %12d %9.2f'
                  % (nm[:34], s['samples'], s['rate'], s['channels'],
                     s['bytes'], s['seconds']))
        total = sum(s['seconds'] for s in b.samples)
        print()
        print('  %d samples, %.2f seconds of audio in total (%.2f minutes)'
              % (len(b.samples), total, total / 60))
        print()


def cmd_census(argv):
    root = argv[2]
    dirguard.want_tree(root, 'fsb5')
    files = []
    for d, _s, ns in os.walk(root):
        for n in sorted(ns):
            files.append(os.path.join(d, n))
    banks = 0
    n_samp = 0
    secs = 0.0
    nbytes = 0
    ok = 0
    print('%-46s %8s %10s %10s %10s %9s'
          % ('FILE', 'SAMPLES', 'CODEC', 'BYTES', 'SIZE OK', 'SECONDS'))
    for p in files:
        try:
            data = open(p, 'rb').read(16)
        except OSError:
            continue
        if data[:4] != b'FSB5':
            continue
        data = open(p, 'rb').read()
        b = Fsb5(data, p)
        banks += 1
        n_samp += len(b.samples)
        t = sum(s['seconds'] for s in b.samples)
        secs += t
        nbytes += len(data)
        good = b.declared == len(data)
        ok += good
        print('%-46s %8d %10s %10d %10s %9.2f'
              % (os.path.relpath(p, root).replace('\\', '/')[:46],
                 len(b.samples), CODEC.get(b.codec, str(b.codec)), len(data),
                 'yes' if good else 'NO', t))
    print()
    print('%d FSB5 banks, %d samples, %d bytes, %.2f seconds (%.2f minutes)'
          % (banks, n_samp, nbytes, secs, secs / 60))
    print('%d of %d banks declare a size that matches the file on disk'
          % (ok, banks))


def selftest():
    """Build a bank by hand and read it back.

    The point is the size identity: 60 + sampleHeadersSize + nameTableSize +
    dataSize has to equal the file, and a bit-packing error in the sample word
    shows up as a wrong offset rather than as a parse failure, so the offsets
    are checked against values chosen to be unambiguous.
    """
    print('fsb5.py --selftest')
    print()
    hdrs = b''
    # sample 0: 44100 Hz (index 8), stereo, offset 0, 65536 samples
    raw = (0) | (8 << 1) | (1 << 5) | (0 << 6) | (65536 << 34)
    hdrs += struct.pack('<Q', raw)
    # sample 1: 22050 Hz (index 5), mono, offset 32*100 = 3200, 1000 samples
    raw = (0) | (5 << 1) | (0 << 5) | (100 << 6) | (1000 << 34)
    hdrs += struct.pack('<Q', raw)
    names = b''
    nt = struct.pack('<2I', 8, 8 + 5)
    names = nt + b'BGM\0' + b'\0' + b'se00\0'
    names += b'\0' * ((4 - len(names) % 4) % 4)
    body = b'\0' * 4096
    head = (b'FSB5' + struct.pack('<6I', 1, 2, len(hdrs), len(names),
                                  len(body), 15)
            + b'\0' * 8 + b'\0' * 16 + b'\0' * 8)
    blob = head + hdrs + names + body
    b = Fsb5(blob)
    checks = [
        ('file size identity', b.declared == len(blob), '%d vs %d'
         % (b.declared, len(blob))),
        ('sample count', len(b.samples) == 2, str(len(b.samples))),
        ('codec is Vorbis', CODEC.get(b.codec) == 'Vorbis', CODEC.get(b.codec)),
        ('sample 0 rate 44100', b.samples[0]['rate'] == 44100,
         str(b.samples[0]['rate'])),
        ('sample 0 stereo', b.samples[0]['channels'] == 2,
         str(b.samples[0]['channels'])),
        ('sample 0 length 65536', b.samples[0]['samples'] == 65536,
         str(b.samples[0]['samples'])),
        ('sample 1 rate 22050', b.samples[1]['rate'] == 22050,
         str(b.samples[1]['rate'])),
        ('sample 1 mono', b.samples[1]['channels'] == 1,
         str(b.samples[1]['channels'])),
        ('sample 1 offset 3200', b.samples[1]['offset'] == 3200,
         str(b.samples[1]['offset'])),
    ]
    # the walk: three banks end to end close on the buffer; one byte more
    # and the chain does not; a bank whose length runs past the buffer is
    # not read
    chain = blob + blob + blob
    banks, end = walk_banks(chain)
    checks.append(('walk: 3 banks end to end', len(banks) == 3,
                   str(len(banks))))
    checks.append(('walk: the chain ends at the last byte',
                   end == len(chain), '%d vs %d' % (end, len(chain))))
    checks.append(('walk: 6 samples over the chain',
                   sum(len(b.samples) for _o, b in banks) == 6, ''))
    checks.append(('walk: the second bank starts at the first one\'s length',
                   banks[1][0] == len(blob), str(banks[1][0])))
    banks2, end2 = walk_banks(chain + b'\0')
    checks.append(('walk: one trailing byte leaves the chain open',
                   len(banks2) == 3 and end2 == len(chain), ''))
    banks3, end3 = walk_banks(chain[:-10])
    checks.append(('walk: a truncated last bank is still parsed, and the '
                   'chain stops short',
                   end3 == len(chain) and len(banks3) == 3
                   and banks3[2][1].declared > len(chain[:-10]) - banks3[2][0],
                   ''))
    # an AudioClip body at version 17, by hand
    cb = struct.pack('<i', 7) + b'ENV_Fie' + b'\0'          # name, align
    cb += struct.pack('<4if', 1, 1, 44100, 16, 2.98)
    cb += b'\0' + b'\0' * 3                                 # tracker, align
    cb += struct.pack('<i', 0)                              # subsound
    cb += b'\x01\x00\x01' + b'\0'                           # 3 bools, align
    cb += struct.pack('<i', 22) + b'sharedassets3.resource' + b'\0\0'
    cb += struct.pack('<QQi', 262944, 13632, 0)
    c = read_clip(cb)
    checks.append(('clip: name, 44100 Hz mono, PCM',
                   c is not None and c['name'] == 'ENV_Fie'
                   and c['frequency'] == 44100 and c['channels'] == 1
                   and c['format'] == 0, str(c)[:40]))
    checks.append(('clip: source, offset and size',
                   c is not None and c['source'] == 'sharedassets3.resource'
                   and c['offset'] == 262944 and c['size'] == 13632, ''))
    checks.append(('clip: a body 4 bytes long is not a clip',
                   read_clip(cb + bytes(4)) is None and read_clip(cb[:-1]) is None,
                   ''))
    ok = 0
    for label, good, got in checks:
        ok += good
        print('  %-28s %-12s %s' % (label, got, 'ok' if good else 'FAILED'))
    print()
    print('  %d of %d checks pass.' % (ok, len(checks)))
    return 0 if ok == len(checks) else 1


def main(argv):
    if '--selftest' in argv:
        raise SystemExit(selftest())
    if len(argv) < 3:
        raise SystemExit(__doc__)
    if argv[1] == 'info':
        return cmd_info(argv)
    if argv[1] == 'census':
        return cmd_census(argv)
    if argv[1] == 'walk':
        return cmd_walk(argv)
    if argv[1] == 'clips':
        return cmd_clips(argv)
    raise SystemExit(__doc__)


if __name__ == '__main__':
    main(sys.argv)
