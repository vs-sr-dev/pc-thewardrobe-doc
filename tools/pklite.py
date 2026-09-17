#!/usr/bin/env python3
"""pklite.py -- unpack a PKLITE 1.x DOS executable, from a grammar read out of
the file's own decompressor.

THE BUCKET THIS SITS IN IS NEITHER OF THE OTHER TWO, AND THAT IS THE POINT.
`ilbm.py` reads a format with a vendor AND a published document: SPECIFIED.
`carte.py` reads a format with neither: DECODED. **PKLITE is the third case.**
The vendor is named, by the file itself, in fifty-two bytes of MZ header
padding --

    offset 0x1D   !PKLITE Copr. 1990 PKWARE Inc. All Rights Reserved

-- and PKWARE never published the bit grammar. So the producer is known and
the format is not, and this tool did not read a specification: it read the
582-byte decompressor that PKLITE stapled to the front of this program, with
`dosdis.py`, at 99.8282 % coverage, and wrote down what the machine code does.
**Every table below is quoted from the object at a named offset** and
`--selftest` re-reads them out of the file rather than trusting the copies.

RULE 3, OUT LOUD
----------------
This box does not execute, install or emulate. **Decompressing is none of the
three.** No 8086 instruction is executed here; the stub was read as data by a
disassembler and re-implemented as arithmetic on a byte string. The result is
a file this session wrote, not a program this session ran, and it is kept in
`_work/` and never published.

THE LAYOUT, ALL OF IT DERIVED FROM THE STUB AT `--at 144` AND `--at 216`
-------------------------------------------------------------------------
    file +144   entry stub, 72 bytes: a memory check, then it copies
                0x123 words from ds:0x148 to a high segment and `retf`s
                into it. `ds` is the PSP and the image loads at PSP:0x100,
                so ds:0x148 is image offset 0x48 = **file 216**.
    file +198   " Not enough memory$"
    file +216   the decompressor, 582 bytes, ending in four tables
    file +800   THE BIT STREAM

The stream is one pointer. Sixteen-bit words little-endian feed a bit buffer
consumed LSB first; literal bytes are read from the same pointer in between.

    bit 0                    one literal byte follows
    bit 1                    a match: a length code, then an offset code,
                             then one raw low byte of the offset

    LENGTH, a prefix code over 2..25 built from four tables in the stub:
        1x        (2 bits)   length = the two bits, i.e. 2 or 3
        000       (3 bits)   table @0x208[0]  = 4
        0010..    (4 bits)   table @0x208[2..4]   = 5, 6, 7
        (5 bits)  bx 10..12  table @0x208[10..12] = 8, 9, 10
        (escapes) bx 13..15  a second level @0x213, then a third @0x21E,
                             giving 11..24 and the escape value 25
        length 25            read one more byte and ADD it, so a match can
                             reach 25 + 255 = 280 bytes

    OFFSET HIGH BYTE, a prefix code over 0..31 (an 8 KB window):
        1                    high byte 0
        0 + 3 bits < 2       table @0x22E[0..1]   = 1, 2
        0 + 4 bits < 8       table @0x22E[4..7]   = 3, 4, 5, 6
        0 + 5 bits < 23      table @0x22E[16..22] = 7 .. 13
        0 + 6 bits           (bits & 0xDF)        = 14 .. 31
    and a match of length 2 skips the code entirely: its high byte is 0.

    THE TWO ESCAPES that are not matches at all. When the extra length byte
    is 0xFE the decompressor renormalises `ds` and `es` and carries on; when
    it is **0xFF the stream is over**. Neither copies a byte, and a reader
    that treats them as matches produces 280 bytes of garbage and no error.

    AFTER THE STREAM comes the relocation table the packer took out of the MZ
    header -- repeated [count byte][segment word][offset word x count],
    ended by a zero count -- and then four words: ss, sp, cs, ip.

WHAT THIS TOOL WILL NOT DO
--------------------------
It will not guess. If the stream ends without a 0xFF, if a match reaches
behind the start of the output, or if the relocation table runs off the end,
it raises and names the offset. **An unpacker that always produces something
is an unpacker whose output means nothing.**

    python tools/pklite.py --validate rovescino/ROVESCIN.EXE
    python tools/pklite.py --unpack   rovescino/ROVESCIN.EXE --out _work/unpacked
    python tools/pklite.py --strings  rovescino/ROVESCIN.EXE --min 4
    python tools/pklite.py --tables   rovescino/ROVESCIN.EXE
    python tools/pklite.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

SIGNATURE = b'PKLITE Copr. 1990 PKWARE Inc.'
SIG_OFFSET = 0x1E

# The version wording this unpacker was built against, and the prefix every
# build of the packer shares. `pc-hexxagon-doc` supplied the second specimen
# the tool's own `pc-rovescino-doc/docs/05` §7 said it had never had, and it
# was `PKLITE Copr. **1990-92** PKWARE Inc.` -- so `is_pklite` said "no PKLITE
# signature", which is a true refusal reported with a false reason. A reader
# would have concluded the file was not PKLITE at all. `banner()` separates
# the two questions: is this the packer, and is this the build I read.
SIG_PREFIX = b'PKLITE Copr. '
BANNER_MAX = 64

# Where the object-dependent block of `--selftest` lives, and how many checks
# it contributes. The count is DECLARED here and VERIFIED whenever the object
# is reachable, so a skip figure printed in a repository that does not hold
# the object cannot silently drift away from the truth.
OBJECT_REL = 'rovescino/ROVESCIN.EXE'
OBJECT_CHECKS = 17

# Where the pieces live in THIS packer's output. They are constants of the
# PKLITE 1.x layout, not of this game, and `--validate` re-derives every one
# of them from the header and the stub rather than assuming them.
STUB_AT = 216
STUB_LEN = 582
STREAM_AT = 800

# The four tables, at their offsets inside the 582-byte decompressor. These
# are COPIES, kept here so the code reads, and `tables()` reads the originals
# out of the file so that `--selftest` can require the copies to be right.
LEN_T1 = 0x208        # cs:[bx+208h] at stub offset 0x0C1
LEN_T2 = 0x213        # cs:[bx+213h] at stub offset 0x160
LEN_T3 = 0x21E        # cs:[bx+21Eh] at stub offset 0x1C3
OFF_T = 0x22E         # cs:[bx+22Eh] at stub offset 0x0F4

END_MARK = 0xFF
NORMALISE_MARK = 0xFE
LENGTH_ESCAPE = 25


class PkliteError(Exception):
    """A file this unpacker will not pretend to understand."""


def is_pklite(blob):
    """The packer's own copyright string, where the packer puts it."""
    return blob[SIG_OFFSET:SIG_OFFSET + len(SIGNATURE)] == SIGNATURE


def banner(blob):
    """Any PKLITE copyright banner at 0x1E, whatever version it names.

    Returns the ASCII banner, or None if the bytes there are not a PKLITE
    banner at all. This answers "is this the packer"; `is_pklite` answers the
    narrower "is this the build whose tables I read", and the two answers are
    different on `pc-hexxagon-doc`'s `HEXX01.EXE`.
    """
    chunk = blob[SIG_OFFSET:SIG_OFFSET + BANNER_MAX]
    if not chunk.startswith(SIG_PREFIX):
        return None
    out = []
    for byte in chunk:
        if 32 <= byte < 127:
            out.append(chr(byte))
        else:
            break
    return ''.join(out)


def header(blob):
    """The MZ header fields this unpacker needs, and the slack."""
    if blob[:2] not in (b'MZ', b'ZM'):
        raise PkliteError('not an MZ executable')
    (cblp, cp, crlc, cparhdr, minalloc, maxalloc, ss, sp, csum,
     ip, cs, lfarlc) = struct.unpack('<HHHHHHHHHHHH', blob[2:26])
    image = (cp - 1) * 512 + cblp if cblp else cp * 512
    return {'cblp': cblp, 'cp': cp, 'crlc': crlc, 'cparhdr': cparhdr,
            'headerlen': cparhdr * 16, 'image': image, 'ss': ss, 'sp': sp,
            'ip': ip, 'cs': cs, 'lfarlc': lfarlc,
            'slack': len(blob) - image}


def tables(blob):
    """The four decode tables, read out of the stub in the file."""
    stub = blob[STUB_AT:STUB_AT + STUB_LEN]
    if len(stub) < STUB_LEN:
        raise PkliteError('the file is too short to hold a %d-byte stub'
                          % STUB_LEN)
    return {'len1': stub[LEN_T1:LEN_T1 + 32],
            'len2': stub[LEN_T2:LEN_T2 + 16],
            'len3': stub[LEN_T3:LEN_T3 + 16],
            'off': stub[OFF_T:OFF_T + 32],
            'stub': stub}


class Bits(object):
    """One pointer over the stream: sixteen-bit words for bits, bytes between.

    The stub reads a word into `bp`, shifts it right one bit at a time, and
    reloads when a counter of sixteen runs out -- and it reloads AFTER the
    shift, so the bit already in the carry flag survives the reload. Getting
    that one detail wrong shifts the whole stream by one bit and still
    decodes, for a while, which is why it is written down here.
    """

    def __init__(self, blob, at):
        self.blob = blob
        self.at = at
        self.buf = self.word()
        self.left = 16

    def word(self):
        if self.at + 2 > len(self.blob):
            raise PkliteError('the stream ran off the end at %d' % self.at)
        value = self.blob[self.at] | (self.blob[self.at + 1] << 8)
        self.at += 2
        return value

    def byte(self):
        if self.at >= len(self.blob):
            raise PkliteError('a literal ran off the end at %d' % self.at)
        value = self.blob[self.at]
        self.at += 1
        return value

    def bit(self):
        value = self.buf & 1
        self.buf >>= 1
        self.left -= 1
        if self.left == 0:
            self.buf = self.word()
            self.left = 16
        return value


def decode_length(bits, tab):
    """A prefix code over 2..25, exactly as the stub's five compares walk it."""
    bx = bits.bit()
    bx = (bx << 1) | bits.bit()
    if bx >= 2:                         # 2 bits: 10 -> 2, 11 -> 3
        return bx
    bx = (bx << 1) | bits.bit()         # 3 bits
    if bx == 0:
        return tab['len1'][0]
    bx = (bx << 1) | bits.bit()         # 4 bits
    if bx < 5:
        return tab['len1'][bx]
    bx = (bx << 1) | bits.bit()         # 5 bits
    if bx <= 0x0C:
        return tab['len1'][bx]

    bx &= 3                             # first escape, table two
    bx = (bx << 1) | bits.bit()
    if bx < 5:
        return tab['len2'][bx]
    bx = (bx << 1) | bits.bit()
    if bx <= 0x0C:
        return tab['len2'][bx]

    bx &= 3                             # second escape, table three
    bx = (bx << 1) | bits.bit()
    if bx < 5:
        return tab['len3'][bx]
    bx = (bx << 1) | bits.bit()
    return tab['len3'][bx]


def decode_offset_high(bits, tab, length):
    """The high byte of the match distance, 0..31, an eight-kilobyte window."""
    if length == 2:
        return 0
    if bits.bit():
        return 0
    bx = bits.bit()
    bx = (bx << 1) | bits.bit()
    bx = (bx << 1) | bits.bit()         # 3 bits
    if bx < 2:
        return tab['off'][bx]
    bx = (bx << 1) | bits.bit()         # 4 bits
    if bx < 8:
        return tab['off'][bx]
    bx = (bx << 1) | bits.bit()         # 5 bits
    if bx < 0x17:
        return tab['off'][bx]
    bx = (bx << 1) | bits.bit()         # 6 bits
    return bx & 0xDF


def decompress(blob, at=STREAM_AT, limit=1 << 22):
    """The stream to the program image, plus where the stream stopped.

    Returns (image, cursor, stats). `cursor` is the byte after the 0xFF that
    ended the stream, which is where the relocation table begins, so the
    caller can check the two halves join instead of assuming they do.
    """
    tab = tables(blob)
    bits = Bits(blob, at)
    out = bytearray()
    stats = {'literals': 0, 'matches': 0, 'normalise': 0, 'longest': 0,
             'furthest': 0}
    while True:
        if len(out) > limit:
            raise PkliteError('the output passed %d bytes without an end '
                              'marker' % limit)
        if not bits.bit():
            out.append(bits.byte())
            stats['literals'] += 1
            continue
        length = decode_length(bits, tab)
        if length == LENGTH_ESCAPE:
            extra = bits.byte()
            length += extra
            if extra >= NORMALISE_MARK:
                # NOT a match. 0xFE renormalises the segment registers and
                # goes round again; 0xFF is the end of the stream.
                if extra == END_MARK:
                    return bytes(out), bits.at, stats
                stats['normalise'] += 1
                continue
        high = decode_offset_high(bits, tab, length)
        distance = (high << 8) | bits.byte()
        if distance == 0:
            raise PkliteError('a match at output %d has distance zero'
                              % len(out))
        if distance > len(out):
            raise PkliteError('a match at output %d reaches %d bytes back, '
                              'behind the start' % (len(out), distance))
        start = len(out) - distance
        for i in range(length):
            out.append(out[start + i])
        stats['matches'] += 1
        stats['longest'] = max(stats['longest'], length)
        stats['furthest'] = max(stats['furthest'], distance)


def relocations(blob, at):
    """The table the packer took out of the header, and then ss, sp, cs, ip."""
    items = []
    cursor = at
    while True:
        if cursor >= len(blob):
            raise PkliteError('the relocation table ran off the end at %d'
                              % cursor)
        count = blob[cursor]
        cursor += 1
        if count == 0:
            break
        if cursor + 2 + 2 * count > len(blob):
            raise PkliteError('a relocation block of %d at %d runs off the '
                              'end' % (count, cursor))
        segment = struct.unpack('<H', blob[cursor:cursor + 2])[0]
        cursor += 2
        for _i in range(count):
            offset = struct.unpack('<H', blob[cursor:cursor + 2])[0]
            cursor += 2
            items.append((segment, offset))
    if cursor + 8 > len(blob):
        raise PkliteError('no room for ss, sp, cs and ip at %d' % cursor)
    ss, sp, cs, ip = struct.unpack('<hHhH', blob[cursor:cursor + 8])
    return items, {'ss': ss, 'sp': sp, 'cs': cs, 'ip': ip}, cursor + 8


def build_exe(image, items, regs):
    """A plain MZ file around the unpacked image, with the relocations back in.

    This is the one place the tool writes a DOS executable, and it is worth
    being explicit: **the output is a file, not a process.** It exists so the
    image can be read with the same census tools as any other MZ, and it is
    written to `_work/` and is not published.
    """
    header_paras = (28 + 4 * len(items) + 15) // 16
    header_paras = max(header_paras, 2)
    headerlen = header_paras * 16
    total = headerlen + len(image)
    cp = (total + 511) // 512
    cblp = total % 512
    head = bytearray(headerlen)
    struct.pack_into('<2sHHHHHHhHHHHH', head, 0, b'MZ', cblp, cp, len(items),
                     header_paras, 0x10, 0xFFFF, regs['ss'] & 0xFFFF,
                     regs['sp'], 0, regs['ip'], regs['cs'] & 0xFFFF, 28)
    at = 28
    for segment, offset in items:
        struct.pack_into('<HH', head, at, offset, segment)
        at += 4
    return bytes(head) + image


def runs(blob, minimum=4):
    """Every run of `minimum`+ printable cp437 bytes, with its offset."""
    found = []
    start = None
    for i, byte in enumerate(blob):
        printable = 32 <= byte < 127
        if printable and start is None:
            start = i
        elif not printable and start is not None:
            if i - start >= minimum:
                found.append((start, blob[start:i].decode('ascii')))
            start = None
    if start is not None and len(blob) - start >= minimum:
        found.append((start, blob[start:].decode('ascii')))
    return found


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the bit reader, which is the one thing worth testing alone ----------
    # 0x0001 = bit 0 set, then fifteen zeroes; then 0xFFFF.
    bits = Bits(b'\x01\x00\xff\xff', 0)
    want('the first bit read is bit 0 of the first word', bits.bit(), 1)
    want('the next fifteen bits are the rest of that word',
         [bits.bit() for _ in range(15)], [0] * 15)
    want('and then the second word arrives', bits.bit(), 1)

    # a literal byte is taken from the same pointer, between words
    bits = Bits(b'\x00\x00Z', 0)
    want('a byte is read from the stream pointer', bits.byte(), ord('Z'))

    # -- a stream built here, against the grammar ----------------------------
    tab = {'len1': bytes(32), 'len2': bytes(16), 'len3': bytes(16),
           'off': bytes(32)}
    # 'AB', then a match of length 2 at distance 2, then the end escape.
    #   bit 0, 'A'      bit 0, 'B'
    #   bit 1, length code '10' -> 2, no offset code (length 2), byte 2
    #   bit 1, length code -> 25 via the escape path, extra byte 0xFF
    # The five bits of the length escape are 1,1,1,1,1 then 1,1 then 1,1 --
    # which is what the tables make of it, so build it from the tables the
    # object actually carries instead. This synthetic case therefore tests
    # only the literal and the short match, and the object tests the rest.
    stream = bytearray()
    word = 0
    word |= 0 << 0          # literal
    word |= 0 << 1          # literal
    word |= 1 << 2          # match
    word |= 1 << 3          # length bit 1
    word |= 0 << 4          # length bit 0  -> bx = 10b = 2
    stream += struct.pack('<H', word)
    stream += b'AB'         # the two literals
    stream += b'\x02'       # the offset low byte: distance 2
    stream += struct.pack('<H', 0)   # a fresh word of zero bits, unused

    class Stop(Exception):
        pass

    bits = Bits(bytes(stream), 0)
    out = bytearray()
    for _step in range(3):
        if not bits.bit():
            out.append(bits.byte())
            continue
        length = decode_length(bits, tab)
        high = decode_offset_high(bits, tab, length)
        distance = (high << 8) | bits.byte()
        start = len(out) - distance
        for i in range(length):
            out.append(out[start + i])
    want('two literals and a length-2 match give ABAB', bytes(out), b'ABAB')

    # -- the tables, read out of the object, against the copies above -------
    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            blob = handle.read()
        want('the object is signed by PKLITE', is_pklite(blob), True)
        tab = tables(blob)
        want('length table 1, entry 0, is 4', tab['len1'][0], 4)
        want('length table 1, entries 2..4, are 5 6 7',
             list(tab['len1'][2:5]), [5, 6, 7])
        want('length table 1, entries 10..12, are 8 9 10',
             list(tab['len1'][10:13]), [8, 9, 10])
        want('length table 2 carries the escape value 25',
             tab['len2'][4], 25)
        want('length table 3 tops out at 24', tab['len3'][15], 24)
        want('offset table entries 0 and 1 are 1 and 2',
             list(tab['off'][0:2]), [1, 2])
        want('offset table entries 4..7 are 3 4 5 6',
             list(tab['off'][4:8]), [3, 4, 5, 6])
        want('offset table entries 16..22 are 7..13',
             list(tab['off'][16:23]), [7, 8, 9, 10, 11, 12, 13])
        want('the stream begins with a word of sixteen zero bits, so the '
             'first sixteen bytes are literals',
             struct.unpack('<H', blob[STREAM_AT:STREAM_AT + 2])[0], 0)
        image, cursor, stats = decompress(blob)
        want('the whole stream decompresses', stats['normalise'] >= 0, True)
        checks.append(('the stream ends inside the declared image',
                       cursor <= header(blob)['image'], ''))
        checks.append(('the unpacked image is bigger than the packed file',
                       len(image) > len(blob), ''))
        checks.append(('no match reaches further back than 8191',
                       stats['furthest'] <= 8191, ''))
        checks.append(('no match is longer than 280',
                       stats['longest'] <= 280, ''))
        items, regs, _end = relocations(blob, cursor)
        checks.append(('the relocation table parses',
                       isinstance(items, list), ''))
        # Borland's C0 startup begins `mov dx,imm; cs: mov [1FFh],dx;
        # mov ah,30h; int 21h` -- a positive control on the very first bytes.
        want('the image opens with Borland C0: mov dx / cs: mov / int 21h',
             image[3:11].hex(' '), '2e 89 16 ff 01 b4 30 cd')
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        # NOT a failure. A selftest that reports FAILURE in every repository
        # but the one it was written in cannot keep the contract a green
        # selftest is supposed to be. It is a SKIP, it is counted, and the
        # count is printed rather than left as a subtraction for the reader.
        skipped.append((OBJECT_CHECKS,
                        '%s not beside the box; pass --object PATH to run '
                        'them' % OBJECT_REL))

    # -- refusals ------------------------------------------------------------
    try:
        header(b'XX' + b'\x00' * 60)
        checks.append(('a file that is not MZ is refused', False, 'it parsed'))
    except PkliteError:
        checks.append(('a file that is not MZ is refused', True, ''))
    try:
        decompress(b'MZ' + b'\x00' * 1200, at=800, limit=64)
        checks.append(('a stream with no end marker is refused', False,
                       'it returned'))
    except PkliteError:
        checks.append(('a stream with no end marker is refused', True, ''))

    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    for count, why in skipped:
        print('  %-*s  SKIP   %d checks: %s' % (width, '(object block)',
                                                count, why))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    lost = sum(count for count, _why in skipped)
    print('%d checks, %d failures, %d skipped' % (len(checks), bad, lost))
    return 1 if bad else 0


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--tables', action='store_true')
    ap.add_argument('--unpack', action='store_true')
    ap.add_argument('--strings', action='store_true')
    ap.add_argument('--min', type=int, default=4)
    ap.add_argument('--out', default=None)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.file:
        ap.error('give a PKLITE-packed .EXE')
    path = dirguard.want_file(args.file, 'pklite')
    with open(path, 'rb') as handle:
        blob = handle.read()

    if not is_pklite(blob):
        seen = banner(blob)
        if seen is None:
            print('FAIL  %s: no PKLITE signature at 0x%02X'
                  % (os.path.basename(path), SIG_OFFSET))
        else:
            # The packer, but not the build. Refuse and say which, because
            # "no signature" would be a false statement about this file.
            print('REFUSE  %s: this IS PKLITE, and it is not the build this '
                  'unpacker reads.' % os.path.basename(path))
            print('  banner at 0x%02X : %s' % (SIG_OFFSET, seen))
            print('  built against  : %s' % SIGNATURE.decode('ascii'))
            print('  the tables at STUB_AT=%d are that build\'s and would be '
                  'read out of the wrong bytes here.' % STUB_AT)
        return 1

    head = header(blob)
    image, cursor, stats = decompress(blob)
    items, regs, end = relocations(blob, cursor)

    if args.validate or args.tables or args.unpack or args.strings:
        print('%s' % os.path.basename(path))
        print('  packed file          : %d bytes' % len(blob))
        print('  declared image       : %d   slack past it : %d = %.4f %%'
              % (head['image'], head['slack'],
                 100.0 * head['slack'] / len(blob)))
        print('  signature at 0x%02X     : %s'
              % (SIG_OFFSET, SIGNATURE.decode('ascii')))
        print('  stream begins        : %d' % STREAM_AT)
        print('  stream ends          : %d   relocations end : %d'
              % (cursor, end))
        print('  against the image    : %+d' % (end - head['image']))
        print('  UNPACKED IMAGE       : %d bytes = %.4f x the packed file'
              % (len(image), len(image) / float(len(blob))))
        print('  literals             : %d' % stats['literals'])
        print('  matches              : %d   longest %d   furthest back %d'
              % (stats['matches'], stats['longest'], stats['furthest']))
        print('  segment renormalises : %d' % stats['normalise'])
        print('  relocation entries   : %d   (the MZ header says %d)'
              % (len(items), head['crlc']))
        print('  entry ss:sp          : %04x:%04x'
              % (regs['ss'] & 0xFFFF, regs['sp']))
        print('  entry cs:ip          : %04x:%04x'
              % (regs['cs'] & 0xFFFF, regs['ip']))

    if args.tables:
        tab = tables(blob)
        print('')
        print('  the four decode tables, read out of the stub at file %d:'
              % STUB_AT)
        for name, offset, table in (('length 1', LEN_T1, tab['len1']),
                                    ('length 2', LEN_T2, tab['len2']),
                                    ('length 3', LEN_T3, tab['len3']),
                                    ('offset  ', OFF_T, tab['off'])):
            print('    %s @0x%03X  %s' % (name, offset, table.hex(' ')))

    if args.unpack:
        if not args.out:
            ap.error('--unpack needs --out')
        os.makedirs(args.out, exist_ok=True)
        stem = os.path.splitext(os.path.basename(path))[0]
        raw = os.path.join(args.out, stem + '.img')
        exe = os.path.join(args.out, stem + '-unpacked.exe')
        with open(raw, 'wb') as handle:
            handle.write(image)
        with open(exe, 'wb') as handle:
            handle.write(build_exe(image, items, regs))
        print('  wrote %s  %d bytes' % (os.path.basename(raw), len(image)))
        print('  wrote %s  %d bytes'
              % (os.path.basename(exe),
                 len(build_exe(image, items, regs))))

    if args.strings:
        found = runs(image, args.min)
        print('')
        print('  runs of %d+ printable bytes in the UNPACKED image : %d'
              % (args.min, len(found)))
        for offset, text in found:
            print('  %7d  %s' % (offset, text))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
