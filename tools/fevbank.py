#!/usr/bin/env python3
"""fevbank.py -- walk an FMOD Studio bank (`RIFF` form `FEV `) and hand the
FSB5 inside its `SND ` chunk to `fsb5.py`, which closes it.

WHY THIS EXISTS
---------------
`fsb5.py walk` reads a bare FSB5 and refuses a `.bank` ("does not begin with
FSB5"): right, and useless, because on pc-thewardrobe-doc the FSB5 is INSIDE
a RIFF whose form is `FEV ` -- FMOD Studio's bank container, which wraps the
project's buses, events and timelines around the sample bank. `riffwalk.py`
closes the RIFF (482 of 482 at residue 0) but does not know the chunks;
`coverage.py` filed the 482 as OPAQUE until its `_fev_bank` probe. This is
the walker in between: it reads the chunk tree, finds the sample bank, and
calls `fsb5.Fsb5` on exactly the bytes the chunk holds.

THE CONTAINER, as read from the bytes of this object
----------------------------------------------------
    RIFF <u32 length> "FEV "                 length + 8 == the file
      FMT  8                                 8 bytes
      LIST PROJ                              the project: BNKI (32 bytes: a GUID
                                             and a count), LIST IBSS / GBSS /
                                             MBSS (buses), LIST EVTS (events:
                                             EVTB), LIST TLNS (timelines), LIST
                                             WAIS (wave instances), LIST WAVS
                                             (WAV, 30 bytes each), LIST SNAS,
                                             SNDH, STDT, STBL, HASH, DEL, MUTE,
                                             REFI, PLAT ...
      SND  <u32 length>                      ONE FSB5, after 0..31 bytes of
                                             padding that aligns it to 32
                                             (the pre-briefing said "at +0 of
                                             the chunk": measured, it is not)

    SNDH, 12 bytes inside LIST PROJ, when the bank has a SND:
      u16 u16                                (3, 8 on every bank measured)
      u32 absolute offset of the FSB5        == where the walk finds it
      u32 length of the FSB5                 == the FSB5's own declared length
    -- a second, independent closure on the sample bank, written by FMOD.

    master_bank.strings.bank                 no SND; its STDT (292,313 bytes)
                                             is the event-name table in a
                                             packed, trie-like form (single
                                             characters with 24-bit links) and
                                             is COUNTED, not decoded here.

THE CHECKS: the RIFF length closes on the file; every chunk lies inside its
parent and the walk ends on the last byte (residue 0); `FMT ` is 8 bytes;
zero or one `SND `; the FSB5's declared length + its padding == the SND
chunk's length; the SNDH offset and length equal the walk's; fsb5.py's own
closure holds. A bank with no SND is a SHELL (494 bytes on this object).

THE BUCKET: FMOD's format, unpublished; read by third parties (vgmstream's
`fsb5_fev` meta reads the SND chunk of exactly this container); DECODED in
coverage.py, and the chunk names above are this session's reading of the
bytes, not FMOD's documentation.

    python tools/fevbank.py tree     FILE            -- the chunk tree, and where the FSB5 sits
    python tools/fevbank.py census   DIR             -- every bank by magic: shells, closures, samples, seconds
    python tools/fevbank.py samples  DIR             -- every FSB5 sample: bank, name, codec, rate, ch, seconds (TSV)
    python tools/fevbank.py selftest

Standard library only. Nothing decodes audio; fsb5.py reads headers.
"""

import argparse
import collections
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                            # noqa: E402
import nameguard                                           # noqa: E402
import fsb5                                                # noqa: E402


class Refused(Exception):
    pass


def is_fev(path):
    """By magic: RIFF, form FEV, length closing on the file."""
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            h = f.read(12)
    except OSError:
        return False
    return (len(h) == 12 and h[:4] == b'RIFF' and h[8:12] == b'FEV '
            and struct.unpack_from('<I', h, 4)[0] + 8 == size)


def walk_chunks(b, off, end, depth=0, out=None):
    """(depth, id, body offset, length, form) for every chunk; raises Refused
    on a chunk that runs past its parent."""
    out = [] if out is None else out
    while off + 8 <= end:
        cid = b[off:off + 4]
        ln = struct.unpack_from('<I', b, off + 4)[0]
        if off + 8 + ln > end:
            raise Refused('chunk %r at %d: %d bytes run past %d' % (cid, off, ln, end))
        if cid in (b'LIST', b'RIFF'):
            form = b[off + 8:off + 12]
            out.append((depth, cid, off + 8, ln, form))
            walk_chunks(b, off + 12, off + 8 + ln, depth + 1, out)
        else:
            out.append((depth, cid, off + 8, ln, b''))
        off += 8 + ln + (ln & 1)
    if off != end:
        raise Refused('walk ends at %d, parent ends at %d' % (off, end))
    return out


class Bank(object):
    def __init__(self, data, path='?'):
        self.data = data
        self.path = path
        if data[:4] != b'RIFF' or data[8:12] != b'FEV ':
            raise Refused('%s is not a RIFF FEV bank' % os.path.basename(path))
        self.riff_len = struct.unpack_from('<I', data, 4)[0]
        if self.riff_len + 8 != len(data):
            raise Refused('%s: RIFF length %d + 8 != %d bytes'
                          % (os.path.basename(path), self.riff_len, len(data)))
        self.chunks = walk_chunks(data, 12, len(data))
        self.residue = 0                       # walk_chunks raised otherwise
        top = [c for c in self.chunks if c[0] == 0]
        self.fmt_ok = bool(top) and top[0][1] == b'FMT ' and top[0][3] == 8
        snds = [c for c in top if c[1] == b'SND ']
        if len(snds) > 1:
            raise Refused('%s: %d SND chunks' % (os.path.basename(path), len(snds)))
        self.snd = snds[0] if snds else None
        self.fsb = None
        self.fsb_off = None
        self.pad = None
        self.snd_closes = None
        self.sndh = None
        self.sndh_ok = None
        for c in self.chunks:
            if c[1] == b'SNDH' and c[3] == 12:
                self.sndh = struct.unpack_from('<HHII', data, c[2])
            if c[1] == b'STDT':
                self.stdt_len = c[3]
        if self.snd:
            _d, _id, body, ln, _f = self.snd
            i = data.find(b'FSB5', body, body + 64)
            if i < 0:
                raise Refused('%s: SND chunk with no FSB5 in its first 64 bytes'
                              % os.path.basename(path))
            self.pad = i - body
            self.fsb_off = i
            self.fsb = fsb5.Fsb5(data[i:body + ln], os.path.basename(path))
            self.snd_closes = (self.pad + self.fsb.declared == ln)
            if self.sndh:
                self.sndh_ok = (self.sndh[2] == i and self.sndh[3] == self.fsb.declared)

    @property
    def shell(self):
        return self.snd is None

    def seconds(self):
        return sum(s['seconds'] for s in self.fsb.samples) if self.fsb else 0.0


def load(path):
    return Bank(open(path, 'rb').read(), path)


def banks_under(root):
    out = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            if is_fev(p):
                out.append(p)
    return out


def kind_of(name):
    """The bank's class by its file name: vo_ita, vo_eng, sfx, master, strings, ost, other."""
    n = name.lower()
    if n.endswith('.strings.bank'):
        return 'strings'
    if n.startswith('master_bank'):
        return 'master'
    m = re.search(r'_(vo_[a-z]{3}|sfx)\.bank$', n)
    if m:
        return m.group(1)
    if n == 'ost.bank':
        return 'ost'
    return 'other'


# ------------------------------------------------------------------ commands

def cmd_tree(args):
    dirguard.want_file(args.path, 'fevbank')
    if not is_fev(args.path):
        sys.exit('fevbank: %s is not a RIFF FEV bank whose length closes on the file'
                 % os.path.basename(args.path))
    bk = load(args.path)
    print('%s: %d bytes, RIFF length %d (+8 = file), %d chunks, residue %d'
          % (os.path.basename(args.path), len(bk.data), bk.riff_len, len(bk.chunks), bk.residue))
    counts = collections.Counter()
    for depth, cid, body, ln, form in bk.chunks:
        counts[cid] += 1
        if depth <= args.depth:
            print('  ' * depth + '%s %s %d' % (cid.decode('latin-1'),
                                                 form.decode('latin-1'), ln))
    print()
    print('chunk ids: %s' % ' '.join('%s:%d' % (k.decode('latin-1'), v)
                                      for k, v in counts.most_common()))
    if bk.sndh:
        print('SNDH: %r  offset %d length %d' % (bk.sndh[:2], bk.sndh[2], bk.sndh[3]))
    if bk.shell:
        print('no SND chunk: a shell')
        return 0
    f = bk.fsb
    print('SND: %d bytes; FSB5 at +%d of the chunk (file offset %d); declared %d; '
          'pad + declared == chunk: %s; SNDH agrees: %s'
          % (bk.snd[3], bk.pad, bk.fsb_off, f.declared,
             'yes' if bk.snd_closes else 'NO', bk.sndh_ok))
    print('FSB5 version %d, %d samples, codec %d (%s), names %s'
          % (f.version, f.n_samples, f.codec, fsb5.CODEC.get(f.codec, '?'),
             'yes' if f.names else 'no'))
    for i, s in enumerate(f.samples[:args.limit]):
        nm = f.names[i] if i < len(f.names) else ''
        print('  %-40s %6d Hz %d ch %8.2f s %10d bytes' % (nm[:40], s['rate'], s['channels'], s['seconds'], s['bytes']))
    if f.n_samples > args.limit:
        print('  ... %d more' % (f.n_samples - args.limit))
    return 0


def cmd_census(args):
    dirguard.want_tree(args.path, 'fevbank')
    paths = banks_under(args.path)
    if not paths:
        sys.exit('fevbank: no RIFF FEV bank under %s' % args.path)
    n = shells = closed = sndh_ok = sndh_seen = fsb_closed = 0
    refused = []
    pads = collections.Counter()
    kinds = collections.defaultdict(lambda: dict(banks=0, shells=0, samples=0, seconds=0.0, bytes=0, data=0))
    codecs = collections.Counter()
    rates = collections.Counter()
    chans = collections.Counter()
    versions = collections.Counter()
    names_yes = 0
    chunk_ids = collections.Counter()
    for p in paths:
        try:
            bk = load(p)
        except (Refused, ValueError, struct.error) as e:
            refused.append((os.path.basename(p), str(e)))
            continue
        n += 1
        k = kind_of(os.path.basename(p))
        kinds[k]['banks'] += 1
        kinds[k]['bytes'] += len(bk.data)
        for c in bk.chunks:
            chunk_ids[c[1]] += 1
        if bk.shell:
            shells += 1
            kinds[k]['shells'] += 1
            continue
        closed += bk.snd_closes
        fsb_closed += (bk.fsb.declared == len(bk.fsb.data))
        pads[bk.pad] += 1
        if bk.sndh:
            sndh_seen += 1
            sndh_ok += bool(bk.sndh_ok)
        f = bk.fsb
        versions[f.version] += 1
        codecs[f.codec] += 1
        names_yes += bool(f.names)
        kinds[k]['samples'] += f.n_samples
        kinds[k]['seconds'] += bk.seconds()
        kinds[k]['data'] += f.data_size
        for s in f.samples:
            rates[s['rate']] += 1
            chans[s['channels']] += 1
    print('banks by magic          %d under %s (RIFF + FEV + length == file)' % (n + len(refused), os.path.basename(args.path.rstrip('/\\'))))
    print('walked to residue 0     %d of %d' % (n, n + len(refused)))
    print('shells (no SND)         %d' % shells)
    print('with a SND              %d; FSB5 pad + declared == chunk: %d; fsb5 closes: %d'
          % (n - shells, closed, fsb_closed))
    print('SNDH present            %d; offset and length agree with the walk: %d' % (sndh_seen, sndh_ok))
    print('FSB5 padding in SND     %s' % ' '.join('+%d:%d' % kv for kv in sorted(pads.items())))
    print('FSB5 versions           %s' % dict(versions))
    print('codecs                  %s' % ' '.join('%s:%d' % (fsb5.CODEC.get(c, c), v) for c, v in codecs.most_common()))
    print('sample rates            %s' % ' '.join('%d:%d' % kv for kv in sorted(rates.items())))
    print('channels                %s' % ' '.join('%d:%d' % kv for kv in sorted(chans.items())))
    print('banks with a name table %d of %d' % (names_yes, n - shells))
    print()
    print('%-10s %6s %7s %8s %10s %14s %14s' % ('KIND', 'BANKS', 'SHELLS', 'SAMPLES', 'SECONDS', 'FILE BYTES', 'SAMPLE BYTES'))
    tot = dict(banks=0, shells=0, samples=0, seconds=0.0, bytes=0, data=0)
    for k in sorted(kinds):
        d = kinds[k]
        print('%-10s %6d %7d %8d %10.1f %14d %14d' % (k, d['banks'], d['shells'], d['samples'], d['seconds'], d['bytes'], d['data']))
        for kk in tot:
            tot[kk] += d[kk]
    print('%-10s %6d %7d %8d %10.1f %14d %14d' % ('TOTAL', tot['banks'], tot['shells'], tot['samples'], tot['seconds'], tot['bytes'], tot['data']))
    print()
    print('chunk ids over every bank: %s' % ' '.join('%s:%d' % (k.decode('latin-1'), v) for k, v in chunk_ids.most_common()))
    if refused:
        print()
        print('%d banks REFUSED:' % len(refused))
        for nm, why in refused:
            print('  %-40s %s' % (nm, why))
    return 0 if not refused and closed == n - shells else 1


def cmd_samples(args):
    dirguard.want_tree(args.path, 'fevbank')
    paths = banks_under(args.path)
    if not paths:
        sys.exit('fevbank: no RIFF FEV bank under %s' % args.path)
    print('\t'.join(('bank', 'kind', 'index', 'name', 'codec', 'rate', 'channels', 'seconds', 'bytes')))
    n = 0
    for p in paths:
        try:
            bk = load(p)
        except (Refused, ValueError, struct.error):
            continue
        if bk.shell:
            continue
        f = bk.fsb
        for i, s in enumerate(f.samples):
            nm = f.names[i] if i < len(f.names) else ''
            n += 1
            print('\t'.join((os.path.basename(p), kind_of(os.path.basename(p)), str(i), nm,
                             fsb5.CODEC.get(f.codec, str(f.codec)), str(s['rate']),
                             str(s['channels']), '%.3f' % s['seconds'], str(s['bytes']))))
    print('# %d samples' % n, file=sys.stderr)
    return 0


# ------------------------------------------------------------------ selftest

def _chunk(cid, body):
    return cid + struct.pack('<I', len(body)) + body + (b'\0' if len(body) & 1 else b'')


def _list(form, body):
    return _chunk(b'LIST', form + body)


def _fsb(names=('a', 'b'), rate_i=8, nsamp=44100):
    """A two-sample FSB5 v1, Vorbis (15), with a name table, from fsb5.py's layout."""
    hdr = b''
    off = 0
    for _ in names:
        w = (0) | (rate_i << 1) | (0 << 5) | ((off // 32) << 6) | (nsamp << 34)
        hdr += struct.pack('<Q', w)
        off += 64
    ntab = struct.pack('<%dI' % len(names), *[4 * len(names) + sum(len(x) + 1 for x in names[:i]) for i in range(len(names))])
    ntab += b''.join(x.encode() + b'\0' for x in names)
    data = bytes(64 * len(names))
    head = b'FSB5' + struct.pack('<6I', 1, len(names), len(hdr), len(ntab), len(data), 15) + bytes(60 - 28)
    return head + hdr + ntab + data


def _bank(with_snd=True, pad=14, sndh=True):
    fsb = _fsb() if with_snd else b''
    proj = _chunk(b'BNKI', bytes(32))
    proj += _list(b'IBSS', _chunk(b'LCNT', struct.pack('<I', 0)))
    body_before = 12 + 8 + 8 + 8 + 4          # RIFF hdr, FMT chunk, LIST hdr, form, BNKI hdr...
    fev = b'RIFF' + b'\0\0\0\0' + b'FEV ' + _chunk(b'FMT ', bytes(8))
    # the SNDH must know the absolute FSB5 offset: compute the layout twice
    snd_off_guess = None
    for _ in range(2):
        p = proj
        if with_snd and sndh:
            p = proj + _chunk(b'SNDH', struct.pack('<HHII', 3, 8, snd_off_guess or 0, len(fsb)))
        p += _chunk(b'STDT', b'')
        out = fev + _list(b'PROJ', p)
        if with_snd:
            snd_body_at = len(out) + 8
            snd_off_guess = snd_body_at + pad
            out += _chunk(b'SND ', bytes(pad) + fsb)
    out = out[:4] + struct.pack('<I', len(out) - 8) + out[8:]
    return out


def cmd_selftest(_args):
    import tempfile
    checks = []
    b = _bank()
    bk = Bank(b, 'fake.bank')
    checks.append(('a hand-built FEV bank walks to residue 0', bk.residue == 0 and bk.fmt_ok, ''))
    checks.append(('its FSB5 is found after 14 bytes of padding and closes on the SND chunk',
                   bk.pad == 14 and bk.snd_closes is True, '%r %r' % (bk.pad, bk.snd_closes)))
    checks.append(('SNDH offset and length agree with the walk', bk.sndh_ok is True, str(bk.sndh)))
    checks.append(('two named samples of one second at 44,100 Hz',
                   bk.fsb.n_samples == 2 and bk.fsb.names == ['a', 'b'] and abs(bk.seconds() - 2.0) < 1e-6,
                   '%r %.3f' % (bk.fsb.names, bk.seconds())))
    sh = Bank(_bank(with_snd=False), 'shell.bank')
    checks.append(('a bank without SND is a shell and still walks', sh.shell and sh.residue == 0, ''))
    bad = b[:4] + struct.pack('<I', len(b) - 7) + b[8:]
    try:
        Bank(bad, 'bad')
        r = False
    except Refused:
        r = True
    checks.append(('a RIFF length one byte off is refused', r, ''))
    b2 = bytearray(_bank(pad=14))
    # corrupt the SND chunk length: +1 makes the walk run past the file
    i = b2.find(b'SND ')
    ln = struct.unpack_from('<I', b2, i + 4)[0]
    struct.pack_into('<I', b2, i + 4, ln + 1)
    try:
        Bank(bytes(b2), 'bad2')
        r = False
    except Refused:
        r = True
    checks.append(('a SND chunk running past the file is refused', r, ''))
    checks.append(('kind_of reads vo_ita / vo_eng / sfx / strings / master / ost from the name',
                   [kind_of(x) for x in ('cut_x_vo_ita.bank', 'buf_call_vo_eng.bank', 'cut_x_sfx.bank',
                                         'master_bank.strings.bank', 'master_bank.bank', 'ost.bank', 'z.bank')]
                   == ['vo_ita', 'vo_eng', 'sfx', 'strings', 'master', 'ost', 'other'], ''))
    d = tempfile.mkdtemp()
    try:
        p1 = os.path.join(d, 'x_vo_ita.bank')
        with open(p1, 'wb') as f:
            f.write(b)
        p2 = os.path.join(d, 'y.bank')
        with open(p2, 'wb') as f:
            f.write(b'RIFF' + struct.pack('<I', 4) + b'WAVE')
        p3 = os.path.join(d, 'z.bank')
        with open(p3, 'wb') as f:
            f.write(b[:-1])
        checks.append(('banks_under selects by magic and length, not by extension',
                       banks_under(d) == [p1], str([os.path.basename(x) for x in banks_under(d)])))
    finally:
        for nm in os.listdir(d):
            os.unlink(os.path.join(d, nm))
        os.rmdir(d)
    width = max(len(c[0]) for c in checks)
    bad_n = 0
    for label, ok, note in checks:
        print('  %-*s  %s  %s' % (width, label, 'ok  ' if ok else 'FAIL', note))
        bad_n += not ok
    print()
    print('%d checks, %d failures' % (len(checks), bad_n))
    return 1 if bad_n else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('tree')
    p.add_argument('path')
    p.add_argument('--depth', type=int, default=1)
    p.add_argument('--limit', type=int, default=40)
    sub.add_parser('census').add_argument('path')
    sub.add_parser('samples').add_argument('path')
    sub.add_parser('selftest')
    args = ap.parse_args()
    nameguard.guard()
    return {'tree': cmd_tree, 'census': cmd_census, 'samples': cmd_samples,
            'selftest': cmd_selftest}[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())
