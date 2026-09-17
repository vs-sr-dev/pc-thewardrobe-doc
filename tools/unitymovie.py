#!/usr/bin/env python3
"""unitymovie.py -- the `MovieTexture` objects of a Unity 5 serialized file:
each one an Ogg stream (Theora video, Vorbis audio) held whole inside the
object body, sliced out and walked page by page.

Unity 5's MovieTexture keeps its movie in the serialized file itself, not in
a `.resS` sidecar -- which is why `resources.assets` on MONSTRUM is 127 MB of
which 127.5 MB are nine movies (the file is smaller than the sum only because
the census's TOTAL counts object bytes and the header is separate).  The body,
at serialization version 17, as measured on the first of them:

    aligned string  m_Name
    u8              m_Loop, then align 4
    PPtr            m_AudioClip  (i32 fileID, i64 pathID)
    u32             m_MovieData length
    ...             that many bytes: an Ogg physical stream (`OggS` at +0)
    i32             m_ColorSpace

THE CLOSURE: the body must end at the last byte of m_ColorSpace, plus 0..3
of padding; the movie length must equal what the page walk tiles.  The page
walk is `oggcensus.py`'s (RFC 3533: page lengths from the segment table,
the Ogg CRC on every page) and is imported, not copied.  A MovieTexture's Ogg
is multiplexed -- two logical streams, one serial each -- so what this tool
adds over `oggcensus` is the split by serial and the two identification
headers: Vorbis I (`\\x01vorbis`, again `oggcensus`'s reader) and Theora
(`\\x80theora`, Xiph's Theora specification section 6.2: version 3 bytes,
frame width and height in macroblocks u16 BE, picture width and height u24
BE, offsets, frame rate numerator and denominator u32 BE, aspect ratio,
colour space, target bitrate u24, quality, keyframe granule shift).

    python tools/unitymovie.py list   FILE|DIR
    python tools/unitymovie.py census FILE|DIR      -- pages, streams, size, fps, seconds
    python tools/unitymovie.py slice  FILE --out DIR [--name NAME]  (writes .ogg)
    python tools/unitymovie.py selftest

Playing time: the Vorbis stream's last granule position over its sample
rate (the audio), and the Theora stream's last granule decoded with the
keyframe shift over its frame rate (the video); both are printed, and they
should agree to within a second.  Standard library only, plus `unityfs.py`,
`oggcensus.py`, `dirguard.py`, `nameguard.py` from this folder.
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                            # noqa: E402
import nameguard                                           # noqa: E402
import oggcensus                                           # noqa: E402
import unityfs                                             # noqa: E402

nameguard.guard()


class Refused(Exception):
    pass


class Movie(object):
    def __init__(self, body, little=True):
        e = '<' if little else '>'
        if len(body) < 4:
            raise Refused('a %d-byte body' % len(body))
        n, = struct.unpack_from(e + 'i', body, 0)
        if not 0 <= n <= 4096 or 4 + n > len(body):
            raise Refused('m_Name length %d' % n)
        self.name = body[4:4 + n].decode('utf-8', 'replace')
        p = (4 + n + 3) & ~3
        if p + 4 + 12 + 4 > len(body):
            raise Refused('%s: body ends before m_MovieData' % self.name)
        self.loop = body[p]
        p += 4
        self.audio_file, self.audio_path = struct.unpack_from(e + 'iq', body, p)
        p += 12
        size, = struct.unpack_from(e + 'I', body, p)
        p += 4
        if p + size + 4 > len(body):
            raise Refused('%s: m_MovieData of %d bytes runs past a %d-byte '
                          'body' % (self.name, size, len(body)))
        self.data = body[p:p + size]
        p = (p + size + 3) & ~3
        self.colour_space, = struct.unpack_from(e + 'i', body, p)
        self.padding = len(body) - (p + 4)
        self.closed = 0 <= self.padding <= 3

    def walk(self):
        """Pages by serial; identification headers; durations."""
        if self.data[:4] != b'OggS':
            raise Refused('%s: m_MovieData does not begin OggS' % self.name)
        streams = {}
        npages = 0
        bad_crc = 0
        end = 0
        for (off, ln, htype, granule, serial, seq, ok,
             payload) in oggcensus.pages(self.data, self.name):
            npages += 1
            bad_crc += not ok
            end = off + ln
            s = streams.setdefault(serial, dict(pages=0, first=None,
                                                last_granule=0, eos=False,
                                                bytes=0))
            s['pages'] += 1
            s['bytes'] += ln
            if s['first'] is None:
                s['first'] = payload
            if granule >= 0:
                s['last_granule'] = max(s['last_granule'], granule)
            if htype & 4:
                s['eos'] = True
        for serial, s in streams.items():
            head = s['first']
            if head[:7] == b'\x01vorbis':
                s['kind'] = 'vorbis'
                s.update(oggcensus.identification(head, self.name))
                s['seconds'] = (s['last_granule'] / s['rate']
                                if s['rate'] else 0.0)
            elif head[:7] == b'\x80theora':
                s['kind'] = 'theora'
                vmaj, vmin, vrev = head[7], head[8], head[9]
                fmbw, fmbh = struct.unpack_from('>HH', head, 10)
                picw = int.from_bytes(head[14:17], 'big')
                pich = int.from_bytes(head[17:20], 'big')
                frn, frd = struct.unpack_from('>II', head, 22)
                parn = int.from_bytes(head[30:33], 'big')
                pard = int.from_bytes(head[33:36], 'big')
                cs = head[36]
                nombr = int.from_bytes(head[37:40], 'big')
                q_kfg = struct.unpack_from('>H', head, 40)[0]
                qual = (q_kfg >> 10) & 0x3F
                kfg = (q_kfg >> 5) & 0x1F
                s.update(version='%d.%d.%d' % (vmaj, vmin, vrev),
                         width=picw, height=pich, fps=(frn / frd if frd else 0),
                         fps_num=frn, fps_den=frd, aspect=(parn, pard),
                         colour=cs, bitrate=nombr, quality=qual, kfg=kfg,
                         frame_mb=(fmbw, fmbh))
                g = s['last_granule']
                frames = (g >> kfg) + (g & ((1 << kfg) - 1))
                s['frames'] = frames
                s['seconds'] = frames / s['fps'] if s['fps'] else 0.0
            else:
                s['kind'] = 'unknown'
                s['seconds'] = 0.0
        return dict(pages=npages, bad_crc=bad_crc, tiled=(end == len(self.data)),
                    streams=streams)


def movies_of(path):
    """Every MovieTexture body of one file as `(Movie | Refused, obj)`; a
    file that is not a SerializedFile yields ONE `(Refused, None)` and
    stops (pc-thewardrobe-doc: `SaveIcon.png` passed the old
    `is_serialized` as "version 13" and `unityfs.load` died with a
    `struct.error` that killed the census whole -- a reader refuses, it
    does not raise)."""
    try:
        sf = unityfs.load(path)
    except unityfs.NotSerialized as e:
        yield Refused('not a SerializedFile: %s' % e), None
        return
    for o in sf.objects:
        if sf.class_of(o) != 152:
            continue
        try:
            yield Movie(sf.body(o), sf.endianness == 0), o
        except Refused as e:
            yield e, o


def files_of(root):
    if os.path.isfile(root):
        return [root]
    return [p for p in unityfs.walk(root) if unityfs.is_serialized(p)]


def cmd_list(args):
    if not os.path.isdir(args.path):
        dirguard.want_file(args.path, 'unitymovie')
    n = 0
    print('%-28s %11s %-5s %-6s %s' % ('NAME', 'BYTES', 'LOOP', 'CLOSE',
                                       'FILE'))
    for p in files_of(args.path):
        for m, o in movies_of(p):
            if isinstance(m, Refused):
                print('REFUSED %s' % m)
                continue
            print('%-28s %11d %-5d %-6s %s'
                  % (m.name[:28], len(m.data), m.loop,
                     'yes' if m.closed else 'NO', os.path.basename(p)))
            n += 1
    print()
    print('%d MovieTexture objects' % n)
    return 0


def cmd_census(args):
    if not os.path.isdir(args.path):
        dirguard.want_file(args.path, 'unitymovie')
    rows = []
    for p in files_of(args.path):
        for m, o in movies_of(p):
            if isinstance(m, Refused):
                rows.append((str(m), None, None))
                continue
            w = m.walk()
            rows.append((m.name, m, w))
    print('%-26s %11s %6s %4s %-9s %5s %-9s %7s %7s %-5s'
          % ('NAME', 'BYTES', 'PAGES', 'CRC', 'VIDEO', 'FPS', 'AUDIO',
             'V SEC', 'A SEC', 'TILE'))
    tot_pages = tot_bytes = 0
    tot_v = tot_a = 0.0
    closed = 0
    for name, m, w in rows:
        if m is None:
            print('REFUSED %s' % name)
            continue
        th = [s for s in w['streams'].values() if s['kind'] == 'theora']
        vo = [s for s in w['streams'].values() if s['kind'] == 'vorbis']
        video = '%dx%d' % (th[0]['width'], th[0]['height']) if th else '-'
        fps = '%.2f' % th[0]['fps'] if th else '-'
        audio = ('%dHz/%dch' % (vo[0]['rate'], vo[0]['channels'])) if vo else '-'
        vs = th[0]['seconds'] if th else 0.0
        as_ = vo[0]['seconds'] if vo else 0.0
        tot_v += vs
        tot_a += as_
        tot_pages += w['pages']
        tot_bytes += len(m.data)
        closed += m.closed and w['tiled']
        print('%-26s %11d %6d %4d %-9s %5s %-9s %7.1f %7.1f %-5s'
              % (name[:26], len(m.data), w['pages'], w['bad_crc'], video, fps,
                 audio, vs, as_, 'yes' if w['tiled'] else 'NO'))
    print()
    print('%d movies, %d bytes of Ogg, %d pages; %d close on body and pages'
          % (len(rows), tot_bytes, tot_pages, closed))
    print('video %.1f s (%.2f min), audio %.1f s (%.2f min)'
          % (tot_v, tot_v / 60, tot_a, tot_a / 60))
    return 0


def cmd_slice(args):
    dirguard.want_file(args.path, 'unitymovie')
    os.makedirs(args.out, exist_ok=True)
    n = 0
    for m, o in movies_of(args.path):
        if isinstance(m, Refused):
            continue
        if args.name and m.name != args.name:
            continue
        safe = ''.join(c if c.isalnum() or c in '-_' else '_' for c in m.name)
        out = os.path.join(args.out, safe + '.ogg')
        with open(out, 'wb') as f:
            f.write(m.data)
        print('%s: %d bytes -> %s' % (m.name, len(m.data), out))
        n += 1
    print('%d movies sliced' % n)
    return 0


# ------------------------------------------------------------------ selftest

def _page(serial, seq, granule, payload, htype=0):
    segs = []
    rest = len(payload)
    while rest >= 255:
        segs.append(255)
        rest -= 255
    segs.append(rest)
    hdr = b'OggS' + struct.pack('<BBqIIIB', 0, htype, granule, serial, seq, 0,
                                len(segs)) + bytes(segs)
    raw = hdr + payload
    crc = oggcensus.crc32_ogg(raw)
    return raw[:22] + struct.pack('<I', crc) + raw[26:]


def _theora_ident(w, h, frn, frd, kfg):
    b = b'\x80theora' + bytes((3, 2, 1))
    b += struct.pack('>HH', (w + 15) // 16, (h + 15) // 16)
    b += w.to_bytes(3, 'big') + h.to_bytes(3, 'big') + bytes(2)
    b += struct.pack('>II', frn, frd)
    b += (1).to_bytes(3, 'big') + (1).to_bytes(3, 'big') + bytes((0,))
    b += (0).to_bytes(3, 'big')
    b += struct.pack('>H', (40 << 10) | (kfg << 5))
    return b


def _vorbis_ident(ch, rate):
    return b'\x01vorbis' + struct.pack('<IBIiiiBB', 0, ch, rate, 0, 0, 0,
                                       0xB8, 1)


def _movie_body(name, ogg, loop=0):
    nb = name.encode('utf-8')
    b = struct.pack('<i', len(nb)) + nb
    b += bytes((-len(b)) % 4)
    b += bytes((loop, 0, 0, 0)) + struct.pack('<iq', 0, 0)
    b += struct.pack('<I', len(ogg)) + ogg
    b += bytes((-len(b)) % 4)
    b += struct.pack('<i', 1)
    return b


def cmd_selftest(_args):
    kfg = 6
    ogg = _page(7, 0, 0, _theora_ident(1280, 720, 30, 1, kfg), 2)
    ogg += _page(9, 0, 0, _vorbis_ident(2, 44100), 2)
    # 60 frames at 30 fps = 2 s: granule = (keyframe 60) << kfg | 0
    ogg += _page(7, 1, 60 << kfg, bytes(100))
    ogg += _page(9, 1, 88200, bytes(50), 4)
    ogg += _page(7, 2, 60 << kfg, bytes(10), 4)
    body = _movie_body('Escape_Test', ogg, loop=0)
    m = Movie(body)
    checks = [('the body parses and closes', m.name == 'Escape_Test'
               and m.closed and len(m.data) == len(ogg)
               and m.colour_space == 1, ''),
              ]
    w = m.walk()
    th = [s for s in w['streams'].values() if s['kind'] == 'theora'][0]
    vo = [s for s in w['streams'].values() if s['kind'] == 'vorbis'][0]
    checks += [
        ('5 pages tile the movie, 0 bad CRCs', w['pages'] == 5
         and w['bad_crc'] == 0 and w['tiled'], str(w['pages'])),
        ('two streams, one Theora and one Vorbis',
         len(w['streams']) == 2 and th['pages'] == 3 and vo['pages'] == 2, ''),
        ('Theora 1280 x 720 at 30 fps, keyframe shift 6',
         th['width'] == 1280 and th['height'] == 720 and th['fps'] == 30.0
         and th['kfg'] == 6, str((th['width'], th['height'], th['fps']))),
        ('Theora granule 60 << 6 is 60 frames = 2.0 s',
         th['frames'] == 60 and abs(th['seconds'] - 2.0) < 1e-9,
         str(th['seconds'])),
        ('Vorbis 44100 Hz stereo, granule 88200 = 2.0 s',
         vo['rate'] == 44100 and vo['channels'] == 2
         and abs(vo['seconds'] - 2.0) < 1e-9, str(vo['seconds'])),
        ('the end-of-stream flag is seen on both', th['eos'] and vo['eos'], ''),
    ]
    try:
        Movie(body[:-6])
        checks.append(('a body cut inside the movie is refused', False, ''))
    except Refused:
        checks.append(('a body cut inside the movie is refused', True, ''))
    try:
        Movie(_movie_body('x', b'notogg' + bytes(30))).walk()
        checks.append(('a movie that is not Ogg is refused', False, ''))
    except Refused:
        checks.append(('a movie that is not Ogg is refused', True, ''))
    bad = bytearray(ogg)
    bad[100] ^= 1
    wb = Movie(_movie_body('y', bytes(bad))).walk()
    checks.append(('a flipped bit is one bad CRC', wb['bad_crc'] == 1,
                   str(wb['bad_crc'])))
    checks.append(('a body with 4 bytes of padding does not close',
                   not Movie(body + bytes(4)).closed, ''))
    # pc-thewardrobe-doc: a PNG on disk is refused, not raised
    import tempfile
    tmp = tempfile.mkdtemp()
    try:
        png = os.path.join(tmp, 'SaveIcon.png')
        with open(png, 'wb') as f:
            f.write(b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR'
                    + struct.pack('>II', 64, 64) + b'\x08\x06\0\0\0'
                    + bytes(100))
        r = list(movies_of(png))
        checks.append(('a PNG handed to movies_of is REFUSED, not raised',
                       len(r) == 1 and isinstance(r[0][0], Refused)
                       and r[0][1] is None, ''))
        checks.append(('files_of() no longer selects the PNG',
                       png not in files_of(tmp), ''))
    finally:
        os.unlink(png)
        os.rmdir(tmp)
    wd = max(len(c[0]) for c in checks)
    nb = 0
    for label, ok, note in checks:
        print('  %-*s  %s  %s' % (wd, label, 'ok  ' if ok else 'FAIL', note[:50]))
        nb += not ok
    print()
    print('%d checks, %d failures' % (len(checks), nb))
    return 1 if nb else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd')
    sub.add_parser('list').add_argument('path')
    sub.add_parser('census').add_argument('path')
    p = sub.add_parser('slice')
    p.add_argument('path')
    p.add_argument('--out', required=True)
    p.add_argument('--name')
    sub.add_parser('selftest')
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        return {'list': cmd_list, 'census': cmd_census, 'slice': cmd_slice,
                'selftest': cmd_selftest}[args.cmd](args)
    except (Refused, oggcensus.OggError) as e:
        sys.exit('unitymovie: refused -- %s' % e)


if __name__ == '__main__':
    sys.exit(main())
