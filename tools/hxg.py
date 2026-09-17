#!/usr/bin/env python3
"""hxg.py -- a reader for the HXG container and both of its compressors.

WHAT AN HXG FILE IS
-------------------
`GRAPHICS.HXG` is the resource file of HEXXAGON (Argo Games / Software
Creations, 1993, MS-DOS). It has no textual magic. What it has instead is an
arithmetic one, and it is a stronger identifier than four ASCII bytes:

    +0    u16   count
    then `count` records of fourteen bytes:
      +0   u16   kind        0 stored, 1 LZ77, 2 RLE
      +2   u32   offset      absolute, from the start of the file
      +6   u16   a           the member's size once decoded
      +8   u16   length      the member's size as stored
      +10  u16   c           width  in pixels, where the member is a bitmap
      +12  u16   d           height in pixels, where the member is a bitmap

    2 + count x 14 == the first record's offset       -- the directory ends
                                                         where the data begins
    offset + length == the next record's offset       -- on every link
    the last record ends on the last byte of the file

A file that satisfies all three is an HXG file, and a file that does not is
not going to satisfy them by accident: on `GRAPHICS.HXG` that is 452 records,
451 chained links and two residues of zero. `--validate` checks all three and
refuses anything that fails, which is how `--census` and `--extract` select
their input. **Never by the extension.**

THE TWO COMPRESSORS
-------------------
`kind 2` is a byte-oriented run encoder:

    n == 0          end of stream
    n & 0x80        (n & 0x7F) copies of the next byte
    otherwise       n literal bytes follow

`kind 1` is an LZ77 with a flag byte:

    a flag byte, read LSB first, governs the next eight items
      bit set     one literal byte
      bit clear   a two-byte token
                    distance = b0 | ((b1 & 0x0F) << 8)     1 .. 4095, backwards
                    length   = (b1 >> 4) + 2               2 .. 17
    decoding stops when `a` bytes have been produced; what remains is the
    zero padding of the final flag group

Neither grammar was fitted to a member. The `kind 2` rule was read off record
1 -- nineteen bytes that make 768 -- and then held on the other nineteen
members. The `kind 1` framing was read off record 449 and then consumed
exactly `length` bytes on 335 of 335 members before any output was produced;
the token layout came from correlating the output each member OWES against
every candidate field, and `(b1 >> 4) + 2` tracked it from 2.38 to 15.62.

WHAT CLOSES
-----------
    every member decodes to exactly its declared `a`      452 of 452
    total decoded                                         1,542,014 bytes
    which is the sum of every `a` in the directory        residue 0
    no copy reaches before the start of its member        452 of 452
    every 768-byte member is a legal 6-bit VGA palette    10 of 10
    the padding past the last needed byte is all zero     335 of 335

The palette check is the one worth having: a 256-entry VGA palette holds
values 0..63, the decoder is never told so, and a decoder that is even
slightly wrong produces bytes above 0x3F within a few hundred bytes.

WHAT THIS TOOL DOES NOT CLAIM
-----------------------------
`HEXXAGON.DOC` has a section called TECH-WEENIE STUFF in which the programmer
names four tools he wrote -- DIFR, DIFRC, VGRAB, SSED -- and says DIFRC uses
"a vaguely LZSS-like method". **That is prose in a user manual, not a
specification**, and this tool does not use it: every rule above is read out
of the bytes and is checked against a count. `--census --kinds` reports the
measurement that bears on it, which is that one frame shape appears 43 times
split across both compressed kinds -- so `kind` records which method won on
that member, not which program produced it.

    python tools/hxg.py --validate Hexxagon/GRAPHICS.HXG
    python tools/hxg.py --list     Hexxagon/GRAPHICS.HXG
    python tools/hxg.py --census   Hexxagon/GRAPHICS.HXG
    python tools/hxg.py --census   Hexxagon/GRAPHICS.HXG --kinds
    python tools/hxg.py --widths   Hexxagon/GRAPHICS.HXG
    python tools/hxg.py --extract  Hexxagon/GRAPHICS.HXG --out _work/members
    python tools/hxg.py --selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

HEADER = 2
RECORD = 14

KIND_STORED = 0
KIND_LZ77 = 1
KIND_RLE = 2
KIND_NAMES = {0: 'stored', 1: 'LZ77', 2: 'RLE'}

# The LZ77 token, which is the whole of the format's cleverness.
LZ_MIN_MATCH = 2
LZ_WINDOW = 4095

# Below this stride, a flat area of colour makes every candidate score well,
# so `--widths` does not search there and says that it does not.
STRIDE_LOW = 16
STRIDE_HIGH = 1024

# A VGA palette is 256 entries of three 6-bit components.
PALETTE_BYTES = 768
VGA_MAX = 0x3F


class HxgError(Exception):
    """A file this reader will not pretend to understand."""


def directory(blob):
    """The directory, or a refusal. Nothing here is optional."""
    if len(blob) < HEADER:
        raise HxgError('shorter than a header')
    count = struct.unpack_from('<H', blob, 0)[0]
    if count == 0:
        raise HxgError('a count of zero')
    end = HEADER + count * RECORD
    if end > len(blob):
        raise HxgError('a directory of %d records does not fit in %d bytes'
                       % (count, len(blob)))
    recs = []
    for i in range(count):
        kind, offset, a, length, c, d = struct.unpack_from(
            '<HIHHHH', blob, HEADER + i * RECORD)
        recs.append(dict(i=i, kind=kind, offset=offset, a=a, length=length,
                         c=c, d=d))
    return recs


def validate(blob):
    """The three closures. Returns a report; raises when one fails."""
    recs = directory(blob)
    end = HEADER + len(recs) * RECORD
    if recs[0]['offset'] != end:
        raise HxgError('the directory ends at %d and the first member starts '
                       'at %d' % (end, recs[0]['offset']))
    links = 0
    for i in range(len(recs) - 1):
        if recs[i]['offset'] + recs[i]['length'] != recs[i + 1]['offset']:
            raise HxgError('member %d ends at %d and member %d starts at %d'
                           % (i, recs[i]['offset'] + recs[i]['length'],
                              i + 1, recs[i + 1]['offset']))
        links += 1
    last = recs[-1]['offset'] + recs[-1]['length']
    if last != len(blob):
        raise HxgError('the last member ends at %d and the file is %d bytes'
                       % (last, len(blob)))
    if any(r['kind'] not in KIND_NAMES for r in recs):
        raise HxgError('a member carries a kind this reader does not know')
    return dict(count=len(recs), directory_end=end, links=links,
                last=last, size=len(blob))


def looks_like_hxg(blob):
    """Selection by grammar, which is this format's only magic."""
    try:
        validate(blob)
    except HxgError:
        return False
    return True


def looks_like_hxg_head(head, min_links=8):
    """The same magic, on as much of the file as a classifier reads.

    `coverage.py` classifies from a 512-byte head, which is 36 records and so
    35 links -- enough for the first closure (the directory ends where the data
    begins) and for every link that fits, but not for the third (the last
    member ends on the last byte). **This is a weaker warrant than
    `--validate`, deliberately, and it is the one a head-reading classifier can
    honestly have.** `min_links` is the floor: a file that cannot show at least
    that many chained links in its head is not accepted.
    """
    if len(head) < HEADER + RECORD:
        return False
    count = struct.unpack_from('<H', head, 0)[0]
    if count == 0:
        return False
    want_end = HEADER + count * RECORD
    visible = min(count, (len(head) - HEADER) // RECORD)
    if visible < 1:
        return False
    recs = []
    for i in range(visible):
        recs.append(struct.unpack_from('<HIHHHH', head, HEADER + i * RECORD))
    if recs[0][1] != want_end:
        return False
    if any(r[0] not in KIND_NAMES for r in recs):
        return False
    links = 0
    for i in range(visible - 1):
        if recs[i][1] + recs[i][3] != recs[i + 1][1]:
            return False
        links += 1
    # A one-record file cannot show a link, so it must be checkable whole.
    if count == 1:
        return looks_like_hxg(head)
    return links >= min(min_links, count - 1)


def decode_rle(data, want=None):
    """kind 2. Returns (bytes, bytes consumed)."""
    out = bytearray()
    p = 0
    n = len(data)
    while p < n:
        item = data[p]
        p += 1
        if item == 0:
            break
        if item & 0x80:
            if p >= n:
                raise HxgError('a run count with no value byte')
            out += bytes([data[p]]) * (item & 0x7F)
            p += 1
        else:
            if p + item > n:
                raise HxgError('a literal string runs past the end')
            out += data[p:p + item]
            p += item
    if want is not None and len(out) != want:
        raise HxgError('RLE produced %d bytes and the directory wants %d'
                       % (len(out), want))
    return bytes(out), p


def decode_lz77(data, want):
    """kind 1. Returns (bytes, bytes consumed, stats)."""
    out = bytearray()
    p = 0
    n = len(data)
    stats = dict(literals=0, tokens=0, longest=0, furthest=0)
    while len(out) < want:
        if p >= n:
            raise HxgError('the stream ended with %d of %d bytes produced'
                           % (len(out), want))
        flags = data[p]
        p += 1
        for bit in range(8):
            if len(out) >= want or p >= n:
                break
            if flags & (1 << bit):
                out.append(data[p])
                p += 1
                stats['literals'] += 1
            else:
                if p + 2 > n:
                    raise HxgError('a token straddles the end of the stream')
                b0, b1 = data[p], data[p + 1]
                p += 2
                distance = b0 | ((b1 & 0x0F) << 8)
                length = (b1 >> 4) + LZ_MIN_MATCH
                if distance == 0:
                    raise HxgError('a copy from distance zero')
                if distance > len(out):
                    raise HxgError('a copy from %d back with only %d bytes '
                                   'written' % (distance, len(out)))
                start = len(out) - distance
                for k in range(length):
                    out.append(out[start + k])
                stats['tokens'] += 1
                stats['longest'] = max(stats['longest'], length)
                stats['furthest'] = max(stats['furthest'], distance)
    return bytes(out), p, stats


def decode(blob, rec):
    """One member, by its kind, checked against its declared size."""
    data = blob[rec['offset']:rec['offset'] + rec['length']]
    if rec['kind'] == KIND_STORED:
        if len(data) != rec['a']:
            raise HxgError('member %d is stored, and %d != %d'
                           % (rec['i'], len(data), rec['a']))
        return data, len(data)
    if rec['kind'] == KIND_RLE:
        out, used = decode_rle(data, rec['a'])
        return out, used
    out, used, _stats = decode_lz77(data, rec['a'])
    return out, used


def stride_scores(raw, low=STRIDE_LOW, high=STRIDE_HIGH):
    """How often a byte equals the byte `w` earlier, for each candidate w."""
    top = min(high, len(raw) // 2)
    scores = {}
    for w in range(low, top + 1):
        same = 0
        for i in range(w, len(raw)):
            if raw[i] == raw[i - w]:
                same += 1
        scores[w] = same / float(len(raw) - w)
    return scores


def read(path, who='hxg'):
    real = dirguard.want_file(path, who)
    with open(real, 'rb') as handle:
        blob = handle.read()
    if not looks_like_hxg(blob):
        try:
            validate(blob)
        except HxgError as exc:
            raise HxgError('%s: %s' % (os.path.basename(real), exc))
    return real, blob


# ---------------------------------------------------------------- selftest --

# The object-dependent block, declared and then verified wherever the object
# is reachable. `pc-hexxagon-doc` inherited three tools whose selftests fell
# silently from 27 checks to 21 when the box moved to a repository without
# their object; this tool is written not to be the fourth.
OBJECT_REL = 'Hexxagon/GRAPHICS.HXG'
OBJECT_CHECKS = 11


def _synthetic_rle():
    """A kind-2 stream built here, so this block runs everywhere."""
    # 0x83 0x41 -> 'AAA'; 0x02 'BC' -> literals; 0x00 -> end
    return bytes([0x83, 0x41, 0x02, 0x42, 0x43, 0x00]), b'AAABC'


def _synthetic_lz77():
    """A kind-1 stream built here, against the grammar in the docstring."""
    # flags 0b00000111: three literals then five tokens' worth of bits, but
    # the decoder stops at `want`, so only what is needed is read.
    #   literals 'A' 'B' 'C'   then a token: distance 3, length 2 -> 'AB'
    flags = 0b00000111
    token_lo = 3                       # distance 3
    token_hi = (0 << 4) | 0            # length (0 >> 4) + 2 = 2, distance high 0
    stream = bytes([flags, 0x41, 0x42, 0x43, token_lo, token_hi])
    return stream, b'ABCAB'


def _build_container():
    """A whole HXG file built here: three members, one of each kind."""
    stored = b'0123456789'
    rle_stream, rle_out = _synthetic_rle()
    lz_stream, lz_out = _synthetic_lz77()
    members = [
        (KIND_STORED, stored, len(stored), 5, 2),
        (KIND_RLE, rle_stream, len(rle_out), 0, 0),
        (KIND_LZ77, lz_stream, len(lz_out), 0, 0),
    ]
    end = HEADER + len(members) * RECORD
    blob = bytearray(struct.pack('<H', len(members)))
    offset = end
    payload = bytearray()
    for kind, data, a, c, d in members:
        blob += struct.pack('<HIHHHH', kind, offset, a, len(data), c, d)
        payload += data
        offset += len(data)
    return bytes(blob + payload), [m[1] for m in members], \
        [stored, rle_out, lz_out]


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the two compressors, on streams built here ------------------------
    stream, expected = _synthetic_rle()
    out, used = decode_rle(stream)
    want('RLE: a run of three and two literals give AAABC', out, expected)
    want('RLE: it consumes the whole stream including the end byte',
         used, len(stream))
    out, _used = decode_rle(bytes([0x82, 0x5A, 0x00]))
    want('RLE: the high bit is a run and the low seven bits are its count',
         out, b'ZZ')

    stream, expected = _synthetic_lz77()
    out, used, stats = decode_lz77(stream, len(expected))
    want('LZ77: three literals then a distance-3 length-2 copy give ABCAB',
         out, expected)
    want('LZ77: one token was read', stats['tokens'], 1)
    want('LZ77: the length is (b1 >> 4) + 2, so 0 means 2',
         stats['longest'], LZ_MIN_MATCH)
    # an overlapping copy, which is the case a naive slice gets wrong
    stream = bytes([0b00000001, 0x58, 0x01, 0x30])
    out, _used, _stats = decode_lz77(stream, 6)
    want('LZ77: a copy that overlaps itself repeats the byte, XXXXXX',
         out, b'X' * 6)

    # -- the refusals -------------------------------------------------------
    for label, fn in (
            ('a copy from distance zero is refused',
             lambda: decode_lz77(bytes([0x00, 0x00, 0x00]), 4)),
            ('a copy from beyond the start is refused',
             lambda: decode_lz77(bytes([0b00000001, 0x41, 0x09, 0x00]), 4)),
            ('a truncated LZ77 stream is refused',
             lambda: decode_lz77(bytes([0b11111111, 0x41]), 8)),
            ('an RLE literal string past the end is refused',
             lambda: decode_rle(bytes([0x40, 0x41]))),
            ('a container shorter than a header is refused',
             lambda: directory(b'\x01')),
            ('a container with a count of zero is refused',
             lambda: directory(b'\x00\x00')),
            ('a directory that does not fit is refused',
             lambda: directory(struct.pack('<H', 900) + b'\x00' * 10)),
    ):
        try:
            fn()
            checks.append((label, False, 'it returned'))
        except HxgError:
            checks.append((label, True, ''))

    # -- the container, built here -----------------------------------------
    blob, _streams, outs = _build_container()
    want('a container built here validates', looks_like_hxg(blob), True)
    report = validate(blob)
    want('and it reports three members', report['count'], 3)
    want('and two chained links', report['links'], 2)
    want('and the last member ends on the last byte',
         report['last'], report['size'])
    recs = directory(blob)
    want('each member decodes to what went in',
         [decode(blob, r)[0] for r in recs], outs)

    # THE POSITIVE CONTROL THAT MUST FIRE: break one link and require refusal.
    broken = bytearray(blob)
    struct.pack_into('<I', broken, HEADER + RECORD + 2,
                     recs[1]['offset'] + 1)
    want('a container with ONE byte added to ONE offset is refused',
         looks_like_hxg(bytes(broken)), False)
    broken = bytearray(blob)
    broken[-1] = broken[-1]  # unchanged, but the file gets one byte longer
    want('a container with one byte appended is refused',
         looks_like_hxg(bytes(broken) + b'\x00'), False)

    # -- and against the object, if it is beside the box -------------------
    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            blob = handle.read()
        report = validate(blob)
        want('the object holds 452 members', report['count'], 452)
        want('its directory ends where its data begins',
             report['directory_end'], directory(blob)[0]['offset'])
        want('451 of 451 links chain', report['links'], 451)
        want('the last member ends on the last byte',
             report['last'], report['size'])
        recs = directory(blob)
        kinds = collections.Counter(r['kind'] for r in recs)
        want('97 stored, 335 LZ77, 20 RLE',
             [kinds[0], kinds[1], kinds[2]], [97, 335, 20])
        total = 0
        exact = 0
        palettes = 0
        clean = 0
        for r in recs:
            out, _used = decode(blob, r)
            total += len(out)
            if len(out) == r['a']:
                exact += 1
            if r['a'] == PALETTE_BYTES:
                palettes += 1
                if max(out) <= VGA_MAX:
                    clean += 1
        want('every member decodes to exactly its declared size',
             exact, len(recs))
        want('the total decoded is the sum of every `a`',
             total, sum(r['a'] for r in recs))
        want('which is 1,542,014 bytes', total, 1542014)
        # THE CONFIRMATION: not fitted, and not something a wrong decoder gets.
        want('every 768-byte member is a legal 6-bit VGA palette',
             [palettes, clean], [10, 10])
        # and a member the reader has never been given the answer to
        rec7 = recs[7]
        out, _used = decode(blob, rec7)
        want('member 7 is a 320 x 200 screen and decodes to 64,000 bytes',
             [rec7['c'], rec7['d'], len(out)], [320, 200, 64000])
        want('member 6 is stored and is a palette',
             [recs[6]['kind'], recs[6]['a'], recs[6]['length']],
             [KIND_STORED, 768, 768])
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((OBJECT_CHECKS,
                        '%s not beside the box; pass --object PATH to run '
                        'them' % OBJECT_REL))

    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))
    checks.append(('nameguard.guard is imported',
                   hasattr(nameguard, 'guard'), ''))

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


# -------------------------------------------------------------------- main --

def cmd_validate(path, blob):
    report = validate(blob)
    print('%s' % os.path.basename(path))
    print('  file bytes                : %d' % report['size'])
    print('  members                   : %d' % report['count'])
    print('  2 + %d x 14               : %d' % (report['count'],
                                                report['directory_end']))
    print('  first member starts at    : %d' % directory(blob)[0]['offset'])
    print('  RESIDUE                   : %+d'
          % (directory(blob)[0]['offset'] - report['directory_end']))
    print('  links that chain          : %d of %d'
          % (report['links'], report['count'] - 1))
    print('  last member ends at       : %d' % report['last'])
    print('  RESIDUE                   : %+d' % (report['last']
                                                 - report['size']))


def cmd_list(path, blob, limit):
    recs = directory(blob)
    print('    #  kind    offset        a   length      c      d')
    for r in recs[:limit]:
        print('%5d %5d %9d %8d %8d %6d %6d'
              % (r['i'], r['kind'], r['offset'], r['a'], r['length'],
                 r['c'], r['d']))
    if len(recs) > limit:
        print('    ... %d more (use --limit)' % (len(recs) - limit))


def cmd_census(path, blob, kinds):
    recs = directory(blob)
    total_a = 0
    exact = 0
    palettes = 0
    clean = 0
    per_kind = collections.Counter()
    bytes_kind = collections.Counter()
    for r in recs:
        out, _used = decode(blob, r)
        total_a += len(out)
        if len(out) == r['a']:
            exact += 1
        per_kind[r['kind']] += 1
        bytes_kind[r['kind']] += len(out)
        if r['a'] == PALETTE_BYTES:
            palettes += 1
            if max(out) <= VGA_MAX:
                clean += 1
    print('%s' % os.path.basename(path))
    print('  members                        : %d' % len(recs))
    print('  decoded to exactly `a`         : %d of %d' % (exact, len(recs)))
    print('  bytes decoded                  : %d' % total_a)
    print('  the directory\'s sum of `a`     : %d' % sum(r['a'] for r in recs))
    print('  RESIDUE                        : %+d'
          % (total_a - sum(r['a'] for r in recs)))
    print('  stored bytes on disk           : %d'
          % sum(r['length'] for r in recs))
    print('  ratio                          : %.4f : 1'
          % (total_a / float(sum(r['length'] for r in recs))))
    print()
    for kind in sorted(per_kind):
        print('  kind %d  %-7s members %4d   decoded %9d bytes'
              % (kind, KIND_NAMES[kind], per_kind[kind], bytes_kind[kind]))
    print()
    print('  768-byte members               : %d' % palettes)
    print('  whose every byte is <= 0x3F    : %d   (a VGA palette is 6-bit)'
          % clean)
    if not kinds:
        return
    print()
    print('=== DOES `kind` NAME A PRODUCER, OR A CHOICE? ===')
    shapes = collections.defaultdict(set)
    counts = collections.Counter()
    for r in recs:
        shapes[(r['a'], r['c'], r['d'])].add(r['kind'])
        counts[(r['a'], r['c'], r['d'])] += 1
    mixed = [(s, k) for s, k in shapes.items() if len(k) > 1]
    print('  distinct (a, c, d) shapes                   : %d' % len(shapes))
    print('  shapes appearing under MORE THAN ONE kind   : %d' % len(mixed))
    for shape, ks in sorted(mixed, key=lambda x: -counts[x[0]])[:6]:
        split = collections.Counter(r['kind'] for r in recs
                                    if (r['a'], r['c'], r['d']) == shape)
        print('    a %6d  c %4d  d %4d : %d members, %s'
              % (shape[0], shape[1], shape[2], counts[shape],
                 ', '.join('kind %d x%d' % (k, split[k])
                           for k in sorted(split))))
    print('  A frame shape that appears under two kinds is one animation')
    print('  compressed two ways, which is a choice per member and not a')
    print('  producer per file.')


def cmd_widths(path, blob):
    recs = directory(blob)
    claim = [r for r in recs
             if r['c'] and r['d'] and r['c'] * r['d'] in (r['a'], r['a'] - 1)]
    print('%s' % os.path.basename(path))
    print('  members where c x d is `a` or `a` - 1 : %d of %d'
          % (len(claim), len(recs)))
    print('  strides searched per member           : %d to %d'
          % (STRIDE_LOW, STRIDE_HIGH))
    print('  (below %d a flat area makes every stride score well)'
          % STRIDE_LOW)
    print()
    where = collections.Counter()
    for r in claim:
        out, _used = decode(blob, r)
        scores = stride_scores(out)
        if not scores:
            where['too short to search'] += 1
            continue
        best = max(scores, key=lambda w: scores[w])
        if best == r['c']:
            where['exactly c'] += 1
        elif best == r['c'] - 1:
            where['c - 1'] += 1
        elif best == r['c'] + 1:
            where['c + 1'] += 1
        else:
            where['something else'] += 1
    for label, count in where.most_common():
        print('    best stride is %-18s %3d of %d' % (label, count,
                                                      len(claim)))
    within = where['exactly c'] + where['c - 1'] + where['c + 1']
    print('    within one of c                 %3d of %d' % (within,
                                                             len(claim)))
    print()
    print('  THE CONTROL: members that carry a c and a d but whose c x d is')
    print('  NOT the decoded size. If the search is easy to satisfy, these')
    print('  will land on c just as often.')
    other = [r for r in recs
             if r['c'] and r['d']
             and r['c'] * r['d'] not in (r['a'], r['a'] - 1)]
    sample = other[:40]
    hit = 0
    for r in sample:
        out, _used = decode(blob, r)
        scores = stride_scores(out)
        if scores:
            best = max(scores, key=lambda w: scores[w])
            if best in (r['c'] - 1, r['c'], r['c'] + 1):
                hit += 1
    print('    such members                    : %d' % len(other))
    print('    sampled                         : %d of %d  (a SAMPLE)'
          % (len(sample), len(other)))
    print('    whose best stride is within one of c : %d' % hit)


def cmd_extract(path, blob, out_dir):
    recs = directory(blob)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    written = 0
    total = 0
    for r in recs:
        data, _used = decode(blob, r)
        name = 'm%04d_k%d_%dx%d.bin' % (r['i'], r['kind'], r['c'], r['d'])
        with open(os.path.join(out_dir, name), 'wb') as handle:
            handle.write(data)
        written += 1
        total += len(data)
    print('  members written : %d' % written)
    print('  bytes written   : %d' % total)
    print('  into            : %s' % out_dir)


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--limit', type=int, default=24)
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--kinds', action='store_true',
                    help='with --census, ask whether `kind` is a producer')
    ap.add_argument('--widths', action='store_true')
    ap.add_argument('--extract', action='store_true')
    ap.add_argument('--out', default=None)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.file:
        ap.error('give an HXG container')
    try:
        path, blob = read(args.file)
    except HxgError as exc:
        print('REFUSE  %s' % exc)
        return 1

    if args.extract:
        if not args.out:
            ap.error('--extract needs --out')
        cmd_extract(path, blob, args.out)
        return 0
    if args.list:
        cmd_list(path, blob, args.limit)
        return 0
    if args.census:
        cmd_census(path, blob, args.kinds)
        return 0
    if args.widths:
        cmd_widths(path, blob)
        return 0
    cmd_validate(path, blob)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
