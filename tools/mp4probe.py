#!/usr/bin/env python3
"""Walk an ISO Base Media (MP4) file and name what is actually in it.

Written because "it starts with `ftyp mp42`" is a magic-number match, not a
format identification, and this repository's whole point is the difference.
The two movies inside DISSIDIA's largest asset bundle are 172 MB each at
480x640, which is a claim about bitrate that ought to be checked against the
container rather than divided out of a file size.

What it reads, all of it public (ISO/IEC 14496-12 for the container, 14496-15
for the AVC sample entry):

    ftyp                    major brand and compatible brands
    moov/mvhd               timescale and duration -> seconds
    moov/trak/tkhd          track id, and width/height for video
    moov/trak/mdia/mdhd     per-track timescale and duration
    moov/trak/mdia/hdlr     handler: 'vide', 'soun', 'text'
    .../minf/stbl/stsd      the sample entry, whose four-character code IS
                            the codec: avc1/hvc1/av01 for video,
                            mp4a/ac-3/Opus for audio
    stsd/avc1/avcC          AVC decoder config: profile, level, and the
                            SPS/PPS the decoder needs
    stsd/mp4a               channel count, sample size, sample rate
    stsz                    sample count and total sample bytes -> real bitrate

The check: `stsz` gives the number of samples and their total size per track,
and the track's own duration gives the seconds.  Bitrate derived from those two
is a track-level figure that does not share a constant with the file's length
on disc -- so when the two agree, they agree for a reason.

    python mp4probe.py FILE...
    python mp4probe.py --boxes FILE      -- the whole box tree

Standard library only.  It does not decode pictures and does not claim to.
"""

import os
import struct
import sys

CONTAINERS = {b'moov', b'trak', b'mdia', b'minf', b'stbl', b'dinf', b'edts',
              b'udta', b'mvex', b'moof', b'traf'}


def boxes(d, start, end, depth=0):
    p = start
    while p + 8 <= end:
        size = struct.unpack_from('>I', d, p)[0]
        typ = d[p + 4:p + 8]
        hdr = 8
        if size == 1:
            if p + 16 > end:
                return
            size = struct.unpack_from('>Q', d, p + 8)[0]
            hdr = 16
        elif size == 0:
            size = end - p
        if size < hdr or p + size > end:
            return
        yield depth, typ, p + hdr, p + size
        if typ in CONTAINERS:
            for x in boxes(d, p + hdr, p + size, depth + 1):
                yield x
        p += size


def full(d, p):
    """version+flags of a FullBox; returns (version, flags, new position)."""
    v = d[p]
    fl = struct.unpack_from('>I', d, p)[0] & 0xFFFFFF
    return v, fl, p + 4


AVC_PROFILE = {66: 'Baseline', 77: 'Main', 88: 'Extended', 100: 'High',
               110: 'High 10', 122: 'High 4:2:2', 244: 'High 4:4:4'}


def probe(path, data=None, label=None):
    d = data if data is not None else open(path, 'rb').read()
    name = label or os.path.basename(path)
    print('=== %s  %d bytes' % (name, len(d)))
    tracks = []
    cur = None
    movie_ts = movie_dur = None
    for depth, typ, s, e in boxes(d, 0, len(d)):
        if typ == b'ftyp':
            major = d[s:s + 4].decode('latin-1')
            minor = struct.unpack_from('>I', d, s + 4)[0]
            compat = [d[i:i + 4].decode('latin-1')
                      for i in range(s + 8, e, 4)]
            print('  brand      %s (minor %d), compatible %s'
                  % (major, minor, ' '.join(compat)))
        elif typ == b'mvhd':
            v, _, p = full(d, s)
            if v == 1:
                ts = struct.unpack_from('>I', d, p + 16)[0]
                dur = struct.unpack_from('>Q', d, p + 20)[0]
            else:
                ts = struct.unpack_from('>I', d, p + 8)[0]
                dur = struct.unpack_from('>I', d, p + 12)[0]
            movie_ts, movie_dur = ts, dur
            print('  movie      timescale %d, duration %d = %.3f s'
                  % (ts, dur, dur / ts if ts else 0))
        elif typ == b'tkhd':
            cur = dict(w=None, h=None, kind=None, codec=None, ts=None,
                       dur=None, samples=0, bytes=0, extra='')
            tracks.append(cur)
            v, _, p = full(d, s)
            off = p + (32 if v == 1 else 20)
            # TrackHeaderBox: after version+flags come creation and
            # modification times, 8 bytes each at version 1 and 4 at version 0,
            # and the track id follows them.  Reading it at the wrong offset
            # gives both tracks the same absurd id, which is how this was
            # caught -- two tracks cannot share one.
            cur['id'] = struct.unpack_from(
                '>I', d, p + (16 if v == 1 else 8))[0]
            w = struct.unpack_from('>I', d, e - 8)[0] >> 16
            h = struct.unpack_from('>I', d, e - 4)[0] >> 16
            if w and h:
                cur['w'], cur['h'] = w, h
        elif typ == b'mdhd' and cur is not None:
            v, _, p = full(d, s)
            if v == 1:
                cur['ts'] = struct.unpack_from('>I', d, p + 16)[0]
                cur['dur'] = struct.unpack_from('>Q', d, p + 20)[0]
            else:
                cur['ts'] = struct.unpack_from('>I', d, p + 8)[0]
                cur['dur'] = struct.unpack_from('>I', d, p + 12)[0]
        elif typ == b'hdlr' and cur is not None and cur['kind'] is None:
            # There are two hdlr boxes on a QuickTime-derived track: the media
            # handler in `mdia` ('vide', 'soun') and a data handler in `minf`
            # ('alis').  The first one is the media handler; taking the last
            # reports every track as 'alis', which is what this printed before
            # the guard was added.
            cur['kind'] = d[s + 8:s + 12].decode('latin-1')
        elif typ == b'stsd' and cur is not None:
            v, _, p = full(d, s)
            n = struct.unpack_from('>I', d, p)[0]
            p += 4
            if n and p + 8 <= e:
                esz = struct.unpack_from('>I', d, p)[0]
                cur['codec'] = d[p + 4:p + 8].decode('latin-1')
                _sample_entry(d, p, p + esz, cur)
        elif typ == b'stsz' and cur is not None:
            v, _, p = full(d, s)
            usz = struct.unpack_from('>I', d, p)[0]
            cnt = struct.unpack_from('>I', d, p + 4)[0]
            cur['samples'] = cnt
            if usz:
                cur['bytes'] = usz * cnt
            else:
                q = p + 8
                tot = 0
                for _ in range(min(cnt, (e - q) // 4)):
                    tot += struct.unpack_from('>I', d, q)[0]
                    q += 4
                cur['bytes'] = tot

    print('  tracks     %d' % len(tracks))
    for t in tracks:
        secs = (t['dur'] / t['ts']) if t.get('ts') else 0
        rate = (t['bytes'] * 8 / secs) if secs else 0
        dim = ('%dx%d' % (t['w'], t['h'])) if t['w'] else '-'
        print('    #%-2s %-5s %-6s %-11s %7d samples %12d B '
              '%8.3f s %9.0f bit/s  %s'
              % (t.get('id', '?'), t['kind'], t['codec'], dim, t['samples'],
                 t['bytes'], secs, rate, t['extra']))
    tb = sum(t['bytes'] for t in tracks)
    print('  sample bytes %d of %d in the file  (%.2f%%)'
          % (tb, len(d), 100.0 * tb / len(d) if d else 0))
    return tracks


def _sample_entry(d, s, e, cur):
    codec = cur['codec']
    if codec in ('avc1', 'avc3', 'hvc1', 'hev1', 'av01'):
        p = s + 8 + 78          # SampleEntry(8) + VisualSampleEntry(78)
        for depth, typ, cs, ce in boxes(d, p, e):
            if typ == b'avcC':
                prof, compat, lvl = d[cs + 1], d[cs + 2], d[cs + 3]
                cur['extra'] = ('AVC %s profile, level %.1f'
                                % (AVC_PROFILE.get(prof, str(prof)),
                                   lvl / 10.0))
            elif typ == b'hvcC':
                cur['extra'] = 'HEVC config'
            elif typ == b'av1C':
                cur['extra'] = 'AV1 config'
    elif codec in ('mp4a', 'ac-3', 'Opus', 'ec-3'):
        # `s` is the start of the sample entry box, header included:
        # 8 size+type, 8 SampleEntry (6 reserved + 2 data_reference_index),
        # 8 AudioSampleEntry preamble (version, revision, vendor), and only
        # then channelcount, samplesize, and a 16.16 sample rate at +32.
        ch = struct.unpack_from('>H', d, s + 24)[0]
        bits = struct.unpack_from('>H', d, s + 26)[0]
        sr = struct.unpack_from('>I', d, s + 32)[0] >> 16
        cur['extra'] = '%d ch, %d-bit, %d Hz' % (ch, bits, sr)
        for depth, typ, cs, ce in boxes(d, s + 36, e):
            if typ == b'esds':
                oti = _esds_object_type(d, cs, ce)
                if oti is not None:
                    cur['extra'] += ', object type 0x%02X%s' % (
                        oti, ' (AAC LC)' if oti == 0x40 else '')


def _esds_object_type(d, s, e):
    p = s + 4
    # ES_Descriptor(0x03) -> DecoderConfigDescriptor(0x04), whose first byte
    # after the tag/length is the objectTypeIndication.
    while p < e:
        tag = d[p]
        p += 1
        ln = 0
        for _ in range(4):
            b = d[p]
            p += 1
            ln = (ln << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        if tag == 0x03:
            p += 3
            continue
        if tag == 0x04:
            return d[p]
        p += ln
    return None


def track_samples(path, kind):
    """Concatenate one track's media samples, in decode order.

    Needed because "do these two movies share their soundtrack" is a question
    about the samples, not about the files: two MP4s carrying the same audio
    still differ in every byte of their headers, their video, and their
    interleaving.  The sample table says exactly which bytes are the track's --
    `stsc` maps chunks to samples, `stco`/`co64` gives chunk offsets, `stsz`
    gives each sample's length -- and walking it yields the elementary stream
    with nothing of the container in it.
    """
    d = open(path, 'rb').read()
    cur = None
    tracks = []
    for depth, typ, s, e in boxes(d, 0, len(d)):
        if typ == b'tkhd':
            cur = dict(kind=None, sizes=[], chunks=[], stsc=[])
            tracks.append(cur)
        elif typ == b'hdlr' and cur is not None and cur['kind'] is None:
            cur['kind'] = d[s + 8:s + 12].decode('latin-1')
        elif typ == b'stsz' and cur is not None:
            _, _, p = full(d, s)
            usz, cnt = struct.unpack_from('>II', d, p)
            if usz:
                cur['sizes'] = [usz] * cnt
            else:
                cur['sizes'] = list(struct.unpack_from('>%dI' % cnt, d,
                                                       p + 8))
        elif typ in (b'stco', b'co64') and cur is not None:
            _, _, p = full(d, s)
            cnt = struct.unpack_from('>I', d, p)[0]
            fmt = '>%dI' % cnt if typ == b'stco' else '>%dQ' % cnt
            cur['chunks'] = list(struct.unpack_from(fmt, d, p + 4))
        elif typ == b'stsc' and cur is not None:
            _, _, p = full(d, s)
            cnt = struct.unpack_from('>I', d, p)[0]
            cur['stsc'] = [struct.unpack_from('>III', d, p + 4 + i * 12)
                           for i in range(cnt)]
    for t in tracks:
        if t['kind'] != kind:
            continue
        out = bytearray()
        si = 0
        runs = t['stsc']
        for i, (first, per, _) in enumerate(runs):
            last = runs[i + 1][0] - 1 if i + 1 < len(runs) else len(t['chunks'])
            for ci in range(first - 1, last):
                if ci >= len(t['chunks']):
                    break
                off = t['chunks'][ci]
                for _ in range(per):
                    if si >= len(t['sizes']):
                        break
                    n = t['sizes'][si]
                    out += d[off:off + n]
                    off += n
                    si += 1
        return bytes(out), si
    return b'', 0


def cmd_track(argv):
    kind = argv[3]
    data, n = track_samples(argv[2], kind)
    import hashlib
    print('%-42s %-5s %8d samples %12d bytes  sha1 %s'
          % (os.path.basename(argv[2]), kind, n, len(data),
             hashlib.sha1(data).hexdigest()))
    if len(argv) > 4:
        open(argv[4], 'wb').write(data)
        print('  wrote %s' % argv[4])
    return 0


def main(argv):
    if len(argv) > 1 and argv[1] == 'track':
        return cmd_track(argv)
    args = [a for a in argv[1:] if not a.startswith('--')]
    if not args:
        print(__doc__)
        return 2
    if '--boxes' in argv:
        d = open(args[0], 'rb').read()
        for depth, typ, s, e in boxes(d, 0, len(d)):
            print('%s%s  %d bytes' % ('  ' * depth,
                                      typ.decode('latin-1'), e - s))
        return 0
    for a in args:
        probe(a)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
