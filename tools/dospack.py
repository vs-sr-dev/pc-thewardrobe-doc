#!/usr/bin/env python3
"""dospack.py -- what a packed DOS MZ says about itself when no packer signs
it: the header, the reserved area, the entry stub's arithmetic worked out, and
a signature sweep wide enough that its zero means something.

WHY A WIDER SWEEP, AND WHY A ZERO FROM IT IS WORTH MORE
-------------------------------------------------------
`pc-popcorn-doc` is this collection's precedent and its lesson is in
`exepack.py`'s own docstring: **seven of the eight names that session searched
for are strings a packed file really contains, and the eighth is not.**
`EXEPACK` is the name of Microsoft's tool and appears in the tool, not in its
output; searching for it is a check that cannot fire. The image was found by
testing the `RB` signature's POSITION instead.

So the table below records, for every signature, **where the string is
supposed to be** -- anywhere, or at a computed offset -- and `--sweep` reports
both. A hit anywhere is a lead; a hit at the right place is an
identification; and a tool name that only ever occurs in the tool is marked
`tool-only` and excluded from the denominator of the claim, because counting
it would inflate a zero.

THE ENTRY STUB'S ARITHMETIC, WHICH IS A COMPUTATION AND NOT A READING
----------------------------------------------------------------------
`--relocator` works the mover out rather than describing it. A DOS packer's
entry stub typically checks free memory, copies itself to the top of the
allocation and far-returns into the copy; the copy's file offset and length
are computable from the header and the stub, and knowing them is what turns
"there is a decompressor in here somewhere" into a range you can hand to a
disassembler. On this object the answer is **file offsets 164..751, 588
bytes**, and `dosdis.py` decodes 526 of those with every branch target landing
on an instruction boundary.

    python tools/dospack.py iggdt/START.EXE
    python tools/dospack.py iggdt/START.EXE --sweep
    python tools/dospack.py iggdt/START.EXE --relocator
    python tools/dospack.py --selftest
"""
import argparse
import collections
import math
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

# (name, needle, where, tool-only)
#   where       'any'    the string occurs somewhere in a packed image
#               'head'   in the MZ header's first 64 bytes
#               'tail'   in the last 4 KB, near the stub
#   tool-only   True when the string names the COMPRESSOR and is therefore
#               not expected in its OUTPUT -- pc-popcorn's lesson, kept as a
#               column rather than as a paragraph.
SIGNATURES = [
    ('LZEXE 0.90', b'LZ09', 'head', False),
    ('LZEXE 0.91', b'LZ91', 'head', False),
    ('PKLITE', b'PKLITE', 'any', False),
    ('PKLITE (mixed case)', b'PKlite', 'any', False),
    ('PKLITE Copr.', b'PKLITE Copr.', 'any', False),
    ('Microsoft EXEPACK', b'RB', 'tail', False),
    ('EXEPACK error string', b'Packed file is corrupt', 'any', False),
    ('EXEPACK (the tool)', b'EXEPACK', 'any', True),
    ('DIET', b'diet', 'any', False),
    ('DIET 1.02', b'\xb4\x4a\xbb\xff\xff\xcd\x21', 'any', False),
    ('TINYPROG', b'TINYPROG', 'any', False),
    ('WWPACK', b'WWP', 'any', False),
    ('WWPACK (full)', b'WWPACK', 'any', True),
    ('PROPACK / RJSX', b'RJSX', 'any', False),
    ('PROPACK / RJSW', b'RJSW', 'any', False),
    ('UPX', b'UPX!', 'any', False),
    ('UPX banner', b'UPX ', 'any', False),
    ('aPACK', b'aPACK', 'any', False),
    ('aPLib', b'AP32', 'any', False),
    ('LZPAK', b'LZPAK', 'any', False),
    ('SCRNCH', b'SCRNCH', 'any', False),
    ('COMPACK', b'COMPACK', 'any', False),
    ('AINEXE', b'AINEXE', 'any', False),
    ('CRUNCHER', b'CRUNCHER', 'any', False),
    ('EXE Shield', b'ExeShield', 'any', False),
    ('PGMPAK', b'PGMPAK', 'any', False),
    ('RELOX', b'RELOX', 'any', False),
    ('SHRINK', b'SHRINK', 'any', False),
    ('TinyProg banner', b'Tiny', 'any', False),
    ('LZEXE banner', b'LZEXE', 'any', True),
    ('Borland copyright', b'Borland', 'any', False),
    ('Turbo Pascal runtime', b'Runtime error', 'any', False),
    ('Microsoft C runtime', b'Microsoft C', 'any', False),
]

FIELDS = ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc',
          'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc',
          'e_ovno']


def header(blob):
    if len(blob) < 28 or blob[:2] not in (b'MZ', b'ZM'):
        raise ValueError('not an MZ executable')
    values = struct.unpack_from('<14H', blob, 0)
    head = dict(zip(FIELDS, values))
    head['header_bytes'] = head['e_cparhdr'] * 16
    head['image_bytes'] = (head['e_cp'] - 1) * 512 + (head['e_cblp'] or 512) \
        if head['e_cp'] else 0
    head['slack'] = len(blob) - head['image_bytes']
    head['entry_offset'] = head['header_bytes'] + \
        ((head['e_cs'] - 0x10000 if head['e_cs'] & 0x8000 else head['e_cs'])
         * 16) + head['e_ip']
    head['minalloc_bytes'] = head['e_minalloc'] * 16
    return head


def reserved(blob):
    """The bytes between the last declared field and the relocation table."""
    head = header(blob)
    start, stop = 0x1C, head['e_lfarlc']
    if stop <= start or stop > len(blob):
        return start, b''
    return start, blob[start:stop]


def printable(chunk):
    return ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in chunk)


def sweep(blob):
    """Every signature, with where it was found and whether that is the place."""
    head = header(blob)
    rows = []
    for name, needle, where, tool_only in SIGNATURES:
        at = blob.find(needle)
        if where == 'head':
            placed = blob[:64].find(needle)
        elif where == 'tail':
            entry = head['entry_offset']
            placed = entry - len(needle) \
                if 0 <= entry - len(needle) and \
                blob[entry - len(needle):entry] == needle else -1
        else:
            placed = at
        rows.append((name, needle, where, tool_only, at, placed))
    return rows


def entropy(chunk):
    if not chunk:
        return 0.0
    hist = collections.Counter(chunk)
    total = len(chunk)
    return -sum((n / total) * math.log2(n / total) for n in hist.values())


def relocator(blob):
    """Work the entry stub's self-move out into a file range.

    The pattern this recognises, and it recognises it rather than assuming it:

        mov cx, <words>     B9 xx xx
        xor di, di          33 FF
        push di             57
        mov si, <offset>    BE xx xx
        cld                 FC
        rep movsw           F3 A5
        retf                CB

    Anything else and this returns None instead of a number, because a
    computed file range that came from the wrong instructions is worse than
    no file range at all.
    """
    head = header(blob)
    entry = head['entry_offset']
    window = blob[entry:entry + 96]
    pat = window.find(b'\x33\xff\x57\xbe')
    if pat < 4 or window[pat - 3] != 0xB9:
        return None
    words = struct.unpack_from('<H', window, pat - 2)[0]
    source_ip = struct.unpack_from('<H', window, pat + 4)[0]
    rest = window[pat + 6:pat + 10]
    if not rest.startswith(b'\xfc\xf3\xa5\xcb'):
        return None
    # DS is the PSP at entry and the image begins at PSP:0100, so an offset
    # in DS maps to a file offset by subtracting 0x100 and adding the header.
    start = head['header_bytes'] + source_ip - 0x100
    return {'words': words, 'bytes': words * 2, 'source_ip': source_ip,
            'file_start': start, 'file_end': start + words * 2 - 1}


def stub_code(blob):
    """The packer named by the CODE at the entry point, not by a marker.

    pc-teenagent-doc: `TEENAGNT.EXE` and `SOUNDSET.EXE` are LZEXE 0.91 with
    the `LZ91` at 1Ch replaced by `0C 0A 09 01`. The 33-signature sweep
    above says "0 of 30 in place" and is right about the markers and wrong
    about the file. LZEXE's decompressor begins with 29 bytes that do not
    change from file to file (tools/lzexe.py, ENTRY, read with dosdis.py);
    this compares them at cs:ip and says so. Returns a dict, or None when
    the entry is not LZEXE's.
    """
    import lzexe
    head = header(blob)
    entry = head['entry_offset']
    window = blob[entry:entry + len(lzexe.ENTRY)]
    if window != lzexe.ENTRY:
        return None
    marker = blob[0x1C:0x20]
    return {'packer': 'LZEXE 0.91', 'entry': entry,
            'marker': marker,
            'marker_ok': marker in (b'LZ91', b'LZ90'),
            'decoder': (blob[entry + len(lzexe.ENTRY):
                             entry + len(lzexe.ENTRY) + len(lzexe.DECODER)]
                        == lzexe.DECODER)}


def selftest():
    checks = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # A synthetic MZ built here, with fields chosen so the arithmetic is
    # checkable by hand.
    def mz(cparhdr=6, cs=0xFFF0, ip=0x100, lfarlc=0x1C, extra=b'', image=b''):
        head = struct.pack('<14H', 0x5A4D, 0, 1, 0, cparhdr, 0, 0xFFFF,
                           0, 0x200, 0, ip, cs, lfarlc, 0)
        pad = b'\x00' * (cparhdr * 16 - len(head) - len(extra))
        return head + extra + pad + image

    blob = mz()
    want('an MZ is recognised', header(blob)['e_magic'], 0x5A4D)
    try:
        header(b'PX' + b'\x00' * 40)
        want('a non-MZ is refused', 'no exception', 'ValueError')
    except ValueError:
        want('a non-MZ is refused', 'ValueError', 'ValueError')
    want('the header size is paragraphs times sixteen',
         header(blob)['header_bytes'], 96)
    want('cs 0xFFF0 with ip 0x100 is the first image byte',
         header(blob)['entry_offset'], 96)

    msg = b'HELLO'
    blob = mz(lfarlc=0x1C + len(msg), extra=msg)
    want('the reserved area is found', reserved(blob)[1], msg)
    want('and it starts at 0x1C', reserved(blob)[0], 0x1C)
    want('an empty reserved area is empty', reserved(mz())[1], b'')

    want('printable renders text', printable(b'AB\x00C'), 'AB.C')

    stub = (b'\xb8\x4d\x58\xba\x96\x0a\x05\x00\x00\x3b\x06\x02\x00\x73\x1a'
            b'\x2d\x20\x00\xfa\x8e\xd0\xfb\x2d\x25\x00\x8e\xc0\x50'
            b'\xb9\x26\x01\x33\xff\x57\xbe\x44\x01\xfc\xf3\xa5\xcb')
    blob = mz(image=stub)
    got = relocator(blob)
    want('the relocator word count is read', got['words'], 0x126)
    want('the relocator byte count is twice that', got['bytes'], 588)
    want('the source offset is read', got['source_ip'], 0x144)
    want('the file range starts at 96 + 0x44', got['file_start'], 164)
    want('and ends 588 bytes later', got['file_end'], 751)

    broken = bytearray(blob)
    broken[96 + 40] = 0x90          # retf -> nop
    want('a stub that does not far-return returns nothing',
         relocator(bytes(broken)), None)
    want('a stub with no move at all returns nothing',
         relocator(mz(image=b'\x90' * 40)), None)

    want('entropy of one repeated byte is zero', entropy(b'\x00' * 100), 0.0)
    want('entropy of a balanced pair is one', entropy(b'\x00\x01'), 1.0)
    want('entropy of nothing is zero', entropy(b''), 0.0)

    rows = sweep(mz(image=b'LZ91' + b'\x00' * 40))
    found = {name: (at, placed) for name, _n, _w, _t, at, placed in rows}
    want('a signature in the image is found but not placed in the head',
         found['LZEXE 0.91'][1], -1)
    rows = sweep(mz(lfarlc=0x20, extra=b'LZ91'))
    found = {name: (at, placed) for name, _n, _w, _t, at, placed in rows}
    want('a signature in the header IS placed', found['LZEXE 0.91'][1], 0x1C)
    want('the table marks tool-only names',
         sum(1 for _n, _x, _w, tool, _a, _p in rows if tool), 3)

    # the packer by its CODE: an LZEXE 0.91 entry at cs:ip with no marker
    import lzexe
    stub = b'\0' * 14 + lzexe.ENTRY + lzexe.DECODER
    packed = mz(cparhdr=2, cs=0, ip=0x0E, image=stub)
    got = stub_code(packed)
    want('an LZEXE 0.91 entry with no marker is named by its code',
         (got or {}).get('packer'), 'LZEXE 0.91')
    want('and the missing marker is reported', (got or {}).get('marker_ok'),
         False)
    want('and the decoder after it is checked', (got or {}).get('decoder'),
         True)
    damaged = bytearray(packed)
    damaged[32 + 14 + 5] ^= 0xFF
    want('one byte changed in the entry -> not named',
         stub_code(bytes(damaged)), None)
    want('a plain entry is not LZEXE',
         stub_code(mz(image=b'\x90' * 40)), None)
    here = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'Teenagent', 'TEENAGNT.EXE')
    if os.path.isfile(here):
        with open(here, 'rb') as fh:
            real = stub_code(fh.read())
        want('TEENAGNT.EXE: LZEXE 0.91 by code, marker 0C0A0901h',
             (real['packer'], real['marker'], real['decoder']),
             ('LZEXE 0.91', b'\x0c\x0a\x09\x01', True))
    else:
        print('  (TEENAGNT.EXE not here: 1 check skipped)')

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--sweep', action='store_true')
    ap.add_argument('--relocator', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())
    if not args.file:
        ap.error('give a file, or --selftest')
    dirguard.want_file(args.file, 'dospack')
    with open(args.file, 'rb') as handle:
        blob = handle.read()
    try:
        head = header(blob)
    except ValueError as exc:
        raise SystemExit('dospack: %s' % exc)

    print('file                  : %s' % os.path.basename(args.file))
    print('bytes                 : %d' % len(blob))
    for field in FIELDS:
        print('  %-10s 0x%04x %7d' % (field, head[field], head[field]))
    print('  header bytes        %7d' % head['header_bytes'])
    print('  image bytes         %7d' % head['image_bytes'])
    print('  slack after image   %7d' % head['slack'])
    print('  entry file offset   %7d' % head['entry_offset'])
    print('  e_minalloc bytes    %7d   (extra memory demanded)'
          % head['minalloc_bytes'])
    print('')

    start, area = reserved(blob)
    print('THE RESERVED AREA, 0x%02X .. 0x%02X, %d bytes'
          % (start, start + len(area) - 1 if area else start, len(area)))
    if area:
        print('  %r' % printable(area))
        print('  it ends exactly at the relocation table: %s'
              % (start + len(area) == head['e_lfarlc']))
    print('')

    if args.relocator:
        got = relocator(blob)
        print('THE ENTRY STUB\'S SELF-MOVE')
        if not got:
            print('  no move of the recognised shape; nothing computed')
        else:
            print('  words copied        %7d' % got['words'])
            print('  bytes copied        %7d' % got['bytes'])
            print('  source, in DS       0x%04X' % got['source_ip'])
            print('  FILE RANGE          %d .. %d'
                  % (got['file_start'], got['file_end']))
            print('  that range is %.4f %% of the file'
                  % (100.0 * got['bytes'] / len(blob)))
        print('')

    code = stub_code(blob)
    print('THE ENTRY STUB\'S CODE')
    if code:
        print('  LZEXE 0.91 decompressor entry at file %d: MATCH (29 bytes), '
              'decoder %s' % (code['entry'],
                              'MATCH' if code['decoder'] else 'DIFFERS'))
        print('  marker at header 1Ch: %s -- %s'
              % (code['marker'].hex(' '),
                 'present' if code['marker_ok']
                 else 'ABSENT: the packer is named by the code, and the '
                      'signature sweep below is wrong about it'))
    else:
        print('  not LZEXE 0.91\'s entry (the only stub this tool knows by '
              'code; the sweep below is by marker)')
    print('')

    rows = sweep(blob)
    real = [r for r in rows if not r[3]]
    hits = [r for r in real if r[4] >= 0]
    placed = [r for r in real if r[5] >= 0]
    if args.sweep:
        print('  %-24s %-26s %-6s %-9s %s'
              % ('signature', 'needle', 'where', 'anywhere', 'in place'))
        for name, needle, where, tool_only, at, place in rows:
            print('  %-24s %-26s %-6s %-9s %s%s'
                  % (name, repr(needle)[1:], where,
                     at if at >= 0 else '-', place if place >= 0 else '-',
                     '   (tool-only, not counted)' if tool_only else ''))
        print('')
    print('signatures in the table       : %d' % len(rows))
    print('  of those, tool-only         : %d   (excluded: a compressor\'s '
          'name is in the compressor, not in its output)'
          % sum(1 for r in rows if r[3]))
    print('  countable                   : %d' % len(real))
    print('  found ANYWHERE              : %d of %d' % (len(hits), len(real)))
    print('  found IN THE RIGHT PLACE    : %d of %d' % (len(placed), len(real)))
    print('')

    image = blob[head['header_bytes']:]
    print('the image after the header    : %d bytes' % len(image))
    print('  entropy, whole image        : %.4f bits/byte' % entropy(image))
    print('  entropy, last 32 KB         : %.4f bits/byte'
          % entropy(image[-32768:]))
    hist = collections.Counter(image)
    print('  distinct byte values        : %d of 256' % len(hist))
    print('  commonest                   : %s'
          % [(hex(v), n) for v, n in hist.most_common(4)])


if __name__ == '__main__':
    main()
