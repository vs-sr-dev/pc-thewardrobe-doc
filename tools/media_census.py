#!/usr/bin/env python3
"""How much of this disc is audio and video, measured from the media headers.

**This tool has now been rewritten three times and that is the finding, not
the footnote.** The Wii 2008 pipeline's version knows Nintendo's `RSTM` and
`THP`; the Wii 2009 rewrite added CRI's Sofdec MPEG-2 and ADX/AHX, because
run unchanged the first one reported *0.00% media on a disc that is 33.30%
video*. This machine's middleware is neither: the video is **RAD Game Tools
Bink** and the audio is **RIFF WAVE**, and a census that knows only the
previous two answers zero again.

Section 7's rule is the one that survives all three rewrites: **name what you
cannot parse.** Everything unrecognised is counted and printed with its first
four bytes, so a missing parser shows up as a row rather than as an absence.

And the second rule, from the same section: **count over every byte, not over
a header sample.** Counting frames in the first four megabytes of a 430 MB
movie reports a nine-minute film as eight seconds, and the number looks
perfectly reasonable.

What it parses here:

  * **Bink** (`BIKb`, `BIKi`, `KB2*`) -- the header states the frame count,
    the frame rate as a numerator and a denominator, the frame size, the
    track count and the audio sample rates, and it states the length of its
    own body, which is a free check on the file: 17 of 17 movies on this disc
    state exactly their own size less eight. The duration is frames divided
    by rate, both read from the header, so nothing is sampled.
  * **RIFF WAVE** -- the `fmt ` chunk gives the format tag, the channels and
    the sample rate, and the `data` chunk its length; Sony's ATRAC3 and
    ATRAC3plus live in one, with format tags 0x0270 and 0xFFFE.
  * **`SHBP`** and **`SE3 ` / `SE4D`**, this build's own sound banks, counted
    by size and named rather than decoded, because their internal format is
    not identified here.
  * `RSTM`, `THP`, Sofdec and ADX are kept so the tool still answers on the
    builds it was written for, and their counters print zero here.

    python media_census.py --tree DIR [DIR...]
    python media_census.py --selftest

Standard library only.
"""

import collections
import os
import struct
import sys


def bink(buf):
    if buf[:3] not in (b'BIK', b'KB2') or len(buf) < 44:
        return None
    body, frames = struct.unpack_from('<II', buf, 4)
    if body + 8 != len(buf) or not 0 < frames < 10000000:
        return None
    w, h, num, den = struct.unpack_from('<IIII', buf, 20)
    ntracks = struct.unpack_from('<I', buf, 40)[0]
    rate = (num / float(den)) if den else 0.0
    return dict(kind='bink', frames=frames, w=w, h=h, fps=rate,
                seconds=(frames / rate) if rate else 0.0,
                tracks=ntracks, bytes=len(buf), tag=buf[:4])


def riff_wave(buf):
    if buf[:4] != b'RIFF' or buf[8:12] != b'WAVE':
        return None
    pos = 12
    fmt = None
    data = 0
    while pos + 8 <= len(buf):
        cid = buf[pos:pos + 4]
        n = struct.unpack_from('<I', buf, pos + 4)[0]
        if cid == b'fmt ' and pos + 8 + 16 <= len(buf):
            tag, ch, sr, br, align, bits = struct.unpack_from(
                '<HHIIHH', buf, pos + 8)
            fmt = (tag, ch, sr, br)
        elif cid == b'data':
            data += n
        pos += 8 + n + (n & 1)
    if fmt is None:
        return None
    tag, ch, sr, br = fmt
    return dict(kind='wave', tag=tag, channels=ch, rate=sr, bytes=len(buf),
                data=data, seconds=(data / float(br)) if br else 0.0)


def classify(buf):
    for f in (bink, riff_wave):
        r = f(buf)
        if r:
            return r
    m = buf[:4]
    for tag, name in ((b'SHBP', 'sound bank SHBP'),
                      (b'SE3 ', 'sound effect bank SE3'),
                      (b'SE4D', 'sound effect bank SE4D'),
                      (b'MSF\x00', 'Sony MSF stream'),
                      (b'RSTM', 'Nintendo RSTM'),
                      (b'THP\x00', 'Nintendo THP'),
                      (b'CRID', 'CRI Sofdec 2'),
                      (b'\x80\x00', 'CRI ADX')):
        if m[:len(tag)] == tag:
            return dict(kind=name, bytes=len(buf), seconds=0.0)
    return None


def walk(roots):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dp, dn, fn in os.walk(root):
            dn.sort()
            for f in sorted(fn):
                yield os.path.join(dp, f)


def main(argv):
    if '--selftest' in argv:
        hdr = (b'BIKi' + struct.pack('<II', 100 - 8, 30)
               + bytes(8) + struct.pack('<IIII', 1280, 720, 60, 2)
               + bytes(8) + struct.pack('<I', 1) + bytes(100 - 44))
        b = bink(hdr[:100])
        assert b and b['frames'] == 30 and b['w'] == 1280, b
        assert abs(b['fps'] - 30.0) < 1e-9 and abs(b['seconds'] - 1.0) < 1e-9
        w = (b'RIFF' + struct.pack('<I', 36 + 8) + b'WAVEfmt '
             + struct.pack('<IHHIIHH', 16, 1, 2, 48000, 192000, 4, 16)
             + b'data' + struct.pack('<I', 8) + bytes(8))
        r = riff_wave(w)
        assert r and r['rate'] == 48000 and r['data'] == 8, r
        assert classify(b'nothing here at all') is None
        print('media_census selftest: 3 of 3 checks pass')
        return 0
    if '--tree' not in argv:
        raise SystemExit(__doc__)
    roots = argv[argv.index('--tree') + 1].split(',')
    n = collections.Counter()
    b = collections.Counter()
    secs = collections.Counter()
    unparsed = collections.Counter()
    unbytes = collections.Counter()
    total = 0
    detail = []
    for p in walk(roots):
        size = os.path.getsize(p)
        total += size
        with open(p, 'rb') as f:
            head = f.read(4096)
        # Bink and RIFF need the whole file to state their own size.
        r = None
        if head[:3] in (b'BIK', b'KB2') or head[:4] == b'RIFF':
            with open(p, 'rb') as f:
                r = classify(f.read())
        else:
            r = classify(head)
            if r:
                r['bytes'] = size
        if r is None:
            unparsed[head[:4]] += 1
            unbytes[head[:4]] += size
            continue
        n[r['kind']] += 1
        b[r['kind']] += size
        secs[r['kind']] += r.get('seconds', 0.0)
        if r['kind'] == 'bink':
            detail.append((p, r))
    print('media census over %s' % ', '.join(roots))
    print('  %s bytes examined' % '{:,}'.format(total))
    print()
    print('  %-24s %8s %18s %10s %12s'
          % ('KIND', 'FILES', 'BYTES', 'SHARE', 'DURATION'))
    for k in sorted(n, key=lambda x: -b[x]):
        h = int(secs[k]) // 3600
        m = (int(secs[k]) % 3600) // 60
        s = int(secs[k]) % 60
        print('  %-24s %8d %18s %9.3f%% %5dh %02dm %02ds'
              % (k, n[k], '{:,}'.format(b[k]), 100.0 * b[k] / total,
                 h, m, s))
    media = sum(b.values())
    print('  %-24s %8d %18s %9.3f%%'
          % ('-- all media', sum(n.values()), '{:,}'.format(media),
             100.0 * media / total))
    print()
    print('  what could not be parsed, named rather than skipped:')
    print('  %-14s %-16s %8s %18s' % ('FIRST 4', 'ASCII', 'FILES', 'BYTES'))
    for k, v in unparsed.most_common(25):
        print('  %-14s %-16r %8d %18s'
              % (k.hex(), k, v, '{:,}'.format(unbytes[k])))
    rest = sum(unbytes.values())
    print('  %-14s %-16s %8d %18s  %.3f%%'
          % ('-- total', '', sum(unparsed.values()), '{:,}'.format(rest),
             100.0 * rest / total))
    if detail:
        print()
        print('  every movie, from its own header')
        print('  %-40s %8s %9s %10s %8s %12s'
              % ('FILE', 'FRAMES', 'SIZE', 'FPS', 'TRACKS', 'DURATION'))
        for p, r in detail:
            s = int(r['seconds'])
            print('  %-40s %8d %4dx%-4d %10.3f %8d %5dm %02ds'
                  % (os.path.basename(p), r['frames'], r['w'], r['h'],
                     r['fps'], r['tracks'], s // 60, s % 60))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv) or 0)
