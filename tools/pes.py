#!/usr/bin/env python3
"""pes.py -- read the .PES (EGA) and .PCS (CGA) shape files of OUT RUN
(SEGA, MS-DOS, 1989): a two-stage compressed container of named sprites,
decoded to the byte with a grammar read out of the game's own decompressor.

WHAT THE FILE IS
----------------
Every `.PES`, `.PCS` and `HJKA.0OK` in the object begins with the byte 0x82.
It is not a magic number in the usual sense: bit 7 says "packed" and the low
seven bits count the compression STAGES stacked on the payload -- two, on all
93 members. The stages are run in file order and each one's output is the
next one's input:

    82 | u24 final size | stage 2 header ... bits | -> stage 1 header ... | -> payload

    stage type 2 : canonical Huffman over bytes
        02 | u24 out | u8 L (bit 7 = delta mode) | count[1..L] | symbols | bits
        codes are canonical, assigned in symbol order within each length,
        shorter lengths first; bits are taken LSB-first from each byte.
    stage type 1 : run codes behind ten escape bytes, plus a repeat bracket
        01 | u24 out | u32 body | u8 F (low 7 bits = 10) | tab[10] | body
        pre-pass, only when F <= 0x80 (F != 1): tab[1] <bytes> tab[1] n
            -> <bytes> repeated n times, at the byte level, un-nested
        run pass, k = 1-based position of the escape in tab:
            k=1  : E n b      -> b x n              k=2  : E b -> b
            k=3  : E lo hi b  -> b x (hi<<8|lo)     k>=4 : E b -> b x (k-1)

The payload is a shape directory: `u32 total`, `u16 count`, `count` four-
character tags, `count` u32 offsets from the end of the directory, then the
records -- a 16-byte header (`u16 w` in bytes, `u16 h`, `i16 x`, `u16 h'`,
four more u16) and `k * w * h` bytes of column-major planes, k = 0..4. A
tag in capitals is a MASK (1 bit per pixel, set = transparent) and its lower-
case twin is the COLOUR data for the same pixels.

WHERE THE GRAMMAR CAME FROM, AND WHY THAT IS THE CLAIM
------------------------------------------------------
The first Huffman table was read off `STUMP.PES`: nine counts whose Kraft
sum is exactly 1.0 followed by 78 sorted symbols. The rest was NOT guessed
from the bytes. `CORV.PES`, which `coverage.py` filed as an executable, IS
one: a Microsoft EXEPACK image of the EGA road engine (see `docs/03`), and
`exepack.py` unpacks it. Inside it the loader that prints `%s NOT PACKED
FILE` and `%s INVALID PACK TYPE` dispatches on the stage type through a
two-entry table at 0277:40EE to the two decoders at 0277:3DC2 (type 1) and
0277:4C34 (type 2). `dosdis.py` decoded both, 534 of 534 and 399 of 400
bytes, and every rule above is a line of that listing -- including the two
that no amount of staring at the bytes had produced: the repeat bracket is
a SEPARATE pass that runs before the run codes and does not know about them,
and `tab[2]` is the 16-bit run, not a run of two.

THE CLOSURE THE DECODER WAS NOT TOLD
------------------------------------
Each stage declares its output size and the file declares the final one.
This reader decodes every member to exactly those numbers -- 93 of 93 in the
object -- and then finds, in the payload, a directory whose `u32 total`
equals the byte count it just produced and whose records tile it with no
gap. The decoder was fitted to STUMP.PES; the other 92 members, the totals
and the tiling are the closure it was never shown. Rule 3: nothing here is
executed. The decoders were read as data by a disassembler and re-written as
arithmetic on a byte string, as `pklite.py` did before.

    python tools/pes.py OutRun/PALM.PES                 # stages and closure
    python tools/pes.py OutRun/PALM.PES --dir           # the shape directory
    python tools/pes.py OutRun/PALM.PES --render shp1   # a palm, in text
    python tools/pes.py --census OutRun                 # all 93, and the 3 MZ
    python tools/pes.py --selftest [--object OutRun]

Standard library only. It writes nothing unless told to with --png/--out,
and the repository publishes no asset it produces.
"""
import argparse
import collections
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

OBJECT_REL = 'OutRun'
OBJECT_CHECKS = 17

# The EGA 16-colour palette, RGB, for --png. Plane bit 0 = blue, 1 = green,
# 2 = red, 3 = intensity, as the standard IRGB order has it.
EGA_RGB = [
    (0, 0, 0), (0, 0, 170), (0, 170, 0), (0, 170, 170),
    (170, 0, 0), (170, 0, 170), (170, 85, 0), (170, 170, 170),
    (85, 85, 85), (85, 85, 255), (85, 255, 85), (85, 255, 255),
    (255, 85, 85), (255, 85, 255), (255, 255, 85), (255, 255, 255)]
# CGA palette 1, high intensity -- black, cyan, magenta, white. The .PCS
# records carry no palette information at all; this choice is a rendering
# convention and is said to be one wherever it is used.
CGA_RGB = [(0, 0, 0), (85, 255, 255), (255, 85, 255), (255, 255, 255)]


class PesError(Exception):
    pass


def _u24(b, p):
    if p + 3 > len(b):
        raise PesError('header runs off the end at +%d' % p)
    return b[p] | b[p + 1] << 8 | b[p + 2] << 16


# ------------------------------------------------------------ stage type 2 --

def huffman_header(b, p):
    """Parse a type-2 header at p. Returns (n_out, maxlen, delta, counts,
    symbols, body_offset)."""
    if b[p] != 2:
        raise PesError('stage at +%d is type %d, not the Huffman stage'
                       % (p, b[p]))
    n_out = _u24(b, p + 1)
    if p + 5 > len(b):
        raise PesError('Huffman header truncated')
    lbyte = b[p + 4]
    maxlen = lbyte & 0x7f
    delta = bool(lbyte & 0x80)
    if not 1 <= maxlen <= 16:
        raise PesError('Huffman code length %d is outside 1..16' % maxlen)
    counts = list(b[p + 5:p + 5 + maxlen])
    if len(counts) != maxlen:
        raise PesError('Huffman count table truncated')
    kraft = sum(c * 2 ** -(i + 1) for i, c in enumerate(counts))
    if kraft != 1.0:
        raise PesError('Huffman counts have Kraft sum %.6f, not 1.0: not a '
                       'complete prefix code' % kraft)
    nsym = sum(counts)
    q = p + 5 + maxlen
    symbols = b[q:q + nsym]
    if len(symbols) != nsym:
        raise PesError('Huffman symbol list truncated: %d of %d'
                       % (len(symbols), nsym))
    if len(set(symbols)) != nsym:
        raise PesError('Huffman symbol list repeats a byte')
    return n_out, maxlen, delta, counts, symbols, q + nsym


def huffman_decode(b, p, limit=None):
    """Stage type 2 at p. Returns (out, bytes_consumed_from_p, info).

    Canonical code, as 0277:4C34 builds it: for each length l a base and a
    limit; the accumulator dx takes one bit at a time (`shr ah,1; rcl dx,1`
    -- LSB-first out of each byte), and a code is complete when dx is below
    that length's limit; the symbol is symbols[base + dx]. Delta mode (bit 7
    of the length byte) adds each symbol to the previous output byte; no
    member of the object sets it and the selftest exercises it on a file
    built here.
    """
    n_out, maxlen, delta, counts, symbols, q = huffman_header(b, p)
    if limit is not None and n_out > limit:
        raise PesError('Huffman stage declares %d bytes, more than the %d '
                       'the file declares' % (n_out, limit))
    table = {}
    code = 0
    i = 0
    for ln, c in enumerate(counts, 1):
        for s in symbols[i:i + c]:
            table[(ln, code)] = s
            code += 1
        i += c
        code <<= 1
    out = bytearray()
    ln = 0
    acc = 0
    prev = 0
    pos = q
    bit = 0
    nbits = (len(b) - q) * 8
    consumed_bits = 0
    while len(out) < n_out:
        if consumed_bits >= nbits:
            raise PesError('Huffman bitstream ran out after %d of %d '
                           'symbols' % (len(out), n_out))
        acc = acc << 1 | (b[pos] >> bit) & 1
        bit += 1
        if bit == 8:
            bit = 0
            pos += 1
        consumed_bits += 1
        ln += 1
        s = table.get((ln, acc))
        if s is not None:
            if delta:
                s = (s + prev) & 0xff
                prev = s
            out.append(s)
            ln = 0
            acc = 0
        elif ln > maxlen:
            raise PesError('Huffman code longer than %d bits at bit %d'
                           % (maxlen, consumed_bits))
    used = (consumed_bits + 7) // 8
    info = {'type': 2, 'n_out': n_out, 'maxlen': maxlen, 'delta': delta,
            'counts': counts, 'nsym': len(symbols), 'header': q - p,
            'bits': consumed_bits, 'body_bytes': len(b) - q}
    return bytes(out), (q - p) + used, info


# ------------------------------------------------------------ stage type 1 --

def runpack_decode(b, p, limit=None):
    """Stage type 1 at p, exactly as 0277:3DC2 does it. Returns (out,
    bytes_consumed_from_p, info)."""
    if b[p] != 1:
        raise PesError('stage at +%d is type %d, not the run stage'
                       % (p, b[p]))
    n_out = _u24(b, p + 1)
    if limit is not None and n_out > limit:
        raise PesError('run stage declares %d bytes, more than the %d the '
                       'file declares' % (n_out, limit))
    if p + 9 > len(b):
        raise PesError('run-stage header truncated')
    n_body = struct.unpack_from('<I', b, p + 4)[0]
    F = b[p + 8]
    ntab = F & 0x7f
    tab = list(b[p + 9:p + 9 + ntab])
    if len(tab) != ntab:
        raise PesError('escape table truncated')
    if ntab < 4:
        # the decoder indexes tab[1] for the bracket and tab[2] for the wide
        # run; a shorter table would read past it. 10 on every member.
        raise PesError('escape table of %d entries is too short' % ntab)
    q = p + 9 + ntab
    body = b[q:q + n_body]
    if len(body) != n_body:
        raise PesError('run-stage body declares %d bytes, %d present'
                       % (n_body, len(body)))
    groups = 0
    if F <= 0x80 and F != 1:
        e1 = tab[1]
        mid = bytearray()
        i = 0
        n = len(body)
        while i < n:
            c = body[i]
            i += 1
            if c != e1:
                mid.append(c)
                continue
            start = len(mid)
            while i < n and body[i] != e1:
                mid.append(body[i])
                i += 1
            if i + 1 >= n:
                raise PesError('repeat bracket opened at body+%d is never '
                               'closed' % (i - 1))
            times = body[i + 1]
            i += 2
            if times < 2:
                # the decoder's `dec dl; jnz` would loop 255 times on 1 and
                # 256 on 0; no member does this and the reader refuses it
                raise PesError('repeat bracket with count %d' % times)
            mid += bytes(mid[start:]) * (times - 1)
            groups += 1
        body = bytes(mid)
    code = {}
    for k, e in enumerate(tab, 1):
        code[e] = k          # a later duplicate overwrites, as the table build does
    out = bytearray()
    i = 0
    n = len(body)
    used = collections.Counter()
    literals = 0
    while i < n:
        c = body[i]
        k = code.get(c, 0)
        try:
            if k == 0:
                out.append(c)
                i += 1
            elif k == 1:
                out += bytes([body[i + 2]]) * body[i + 1]
                i += 3
            elif k == 2:
                out.append(body[i + 1])
                i += 2
            elif k == 3:
                out += bytes([body[i + 3]]) * (body[i + 1] | body[i + 2] << 8)
                i += 4
            else:
                out += bytes([body[i + 1]]) * (k - 1)
                i += 2
        except IndexError:
            raise PesError('run code k=%d at body+%d runs off the end'
                           % (k, i))
        if k:
            used[k] += 1
        else:
            literals += 1
        if len(out) > n_out:
            raise PesError('run stage overran its declared %d bytes' % n_out)
    if len(out) != n_out:
        raise PesError('run stage produced %d bytes, declared %d'
                       % (len(out), n_out))
    info = {'type': 1, 'n_out': n_out, 'n_body': n_body, 'F': F, 'tab': tab,
            'groups': groups, 'codes': dict(used), 'literals': literals,
            'header': q - p}
    return bytes(out), (q - p) + n_body, info


# ------------------------------------------------------------------ chain --

def unpack(blob):
    """Run the stage chain of a 0x8N file. Returns a record with the final
    bytes and one info dict per stage, or raises PesError."""
    if len(blob) < 10:
        raise PesError('%d bytes is shorter than any header' % len(blob))
    if not blob[0] & 0x80:
        raise PesError('byte 0 is 0x%02X: the packed bit is not set'
                       % blob[0])
    nstages = blob[0] & 0x7f
    if not 1 <= nstages <= 2:
        raise PesError('%d stages declared; the loader accepts 1 or 2'
                       % nstages)
    final = _u24(blob, 1)
    if final == 0:
        raise PesError('final size 0')
    p = 4
    cur = blob
    stages = []
    consumed_first = None
    for s in range(nstages):
        t = cur[p]
        if t == 2:
            out, used, info = huffman_decode(cur, p, limit=final)
        elif t == 1:
            out, used, info = runpack_decode(cur, p, limit=final)
        else:
            raise PesError('stage %d has pack type %d; the loader knows 1 and '
                           '2 (INVALID PACK TYPE)' % (s + 1, t))
        stages.append(info)
        if s == 0:
            consumed_first = p + used
        cur = out
        p = 0
    if len(cur) != final:
        raise PesError('chain produced %d bytes, file declares %d'
                       % (len(cur), final))
    slack = len(blob) - consumed_first
    flush = False
    if slack == 1 and stages[0]['type'] == 2 and stages[0]['bits'] % 8 == 0 \
            and blob[-1] == 0:
        # THE ENCODER'S FLUSH BYTE. When the bitstream ends exactly on a
        # byte boundary the packer wrote one more byte, 0x00 -- an empty
        # accumulator flushed. 23 of the 93 members end on a boundary and
        # all 23 carry it; none of the other 70 does. It is allowed on
        # exactly those terms and refused on any other.
        flush = True
    elif slack != 0:
        raise PesError('%d byte(s) after the compressed stream' % slack)
    return {'size': len(blob), 'nstages': nstages, 'final': final,
            'stages': stages, 'payload': cur, 'flush': flush}


# -------------------------------------------------------------- directory --

HDR = struct.Struct('<HHhHHHHH')


def directory(payload):
    """Cut the payload into its named records. Raises PesError when the
    directory does not tile the payload."""
    if len(payload) < 6:
        raise PesError('payload too short for a directory')
    total, count = struct.unpack_from('<IH', payload, 0)
    if total != len(payload):
        raise PesError('directory total %d, payload %d' % (total, len(payload)))
    base = 6 + 8 * count
    if count == 0 or base > len(payload):
        raise PesError('directory of %d records does not fit' % count)
    tags = []
    for k in range(count):
        t = payload[6 + 4 * k:10 + 4 * k]
        if not all(32 <= x < 127 for x in t):
            raise PesError('tag %d is not printable ASCII: %r' % (k, t))
        tags.append(t.decode('ascii'))
    offs = struct.unpack_from('<%dI' % count, payload, 6 + 4 * count)
    starts = sorted(set(base + o for o in offs))
    if len(starts) != count:
        raise PesError('two records share an offset')
    if starts[0] != base:
        raise PesError('first record at %d, directory ends at %d'
                       % (starts[0], base))
    bounds = starts + [len(payload)]
    recs = []
    for k in range(count):
        lo = base + offs[k]
        hi = bounds[bounds.index(lo) + 1]
        if hi - lo < 16:
            raise PesError('record %s is %d bytes, shorter than its header'
                           % (tags[k], hi - lo))
        w, h, x, h2, a, bb, c, d = HDR.unpack_from(payload, lo)
        data = payload[lo + 16:hi]
        per = w * h
        if per == 0:
            if data:
                raise PesError('record %s has 0 x %d cells and %d data bytes'
                               % (tags[k], h, len(data)))
            planes = 0
        else:
            if len(data) % per:
                raise PesError('record %s: %d data bytes is not a multiple '
                               'of %d x %d' % (tags[k], len(data), w, h))
            planes = len(data) // per
            if planes > 4:
                raise PesError('record %s would have %d planes'
                               % (tags[k], planes))
        recs.append({'tag': tags[k], 'off': lo, 'size': hi - lo, 'w': w,
                     'h': h, 'x': x, 'h2': h2, 'a': a, 'b': bb, 'c': c,
                     'd': d, 'planes': planes, 'data': data})
    return recs


def depth(recs):
    """'ega', 'cga' or 'unknown', from the record headers alone.

    In every EGA member the mask records carry 0x000F in the seventh header
    word and the colour records carry 1..4 planes with non-zero plane words;
    in every CGA member the masks carry 0x0201 and the colour records ONE
    plane with the word zero. Members without masks (title screens) decide on
    the colour records."""
    masks = [r for r in recs if r['tag'].isupper() and r['planes'] == 1]
    colour = [r for r in recs if not r['tag'].isupper() and r['planes'] >= 1]
    ega = cga = 0
    for r in masks:
        if r['c'] == 0x000f:
            ega += 1
        elif r['c'] == 0x0201:
            cga += 1
    for r in colour:
        if r['planes'] >= 2 or (r['c'] & 0x0f0f and r['c'] != 0x0201):
            ega += 1
        elif r['planes'] == 1 and r['c'] == 0:
            cga += 1
    if ega and not cga:
        return 'ega'
    if cga and not ega:
        return 'cga'
    return 'unknown'


def read(path):
    dirguard.want_file(path, 'pes')
    with open(path, 'rb') as fh:
        blob = fh.read()
    rec = unpack(blob)
    rec['records'] = directory(rec['payload'])
    rec['depth'] = depth(rec['records'])
    return blob, rec


def looks_like_head(head, size=None):
    """For coverage.py: what a 4,096-byte head can say. The packed bit, a
    stage count of 1 or 2, a first stage of type 1 or 2 and -- for type 2,
    which is every member here -- a count table whose Kraft sum is exactly
    1.0 over distinct symbols. It cannot run the chain; `--census` does."""
    try:
        if len(head) < 10 or not head[0] & 0x80:
            return False
        if not 1 <= (head[0] & 0x7f) <= 2:
            return False
        final = _u24(head, 1)
        if final == 0:
            return False
        if size is not None and size > 2 * final + 64:
            return False
        t = head[4]
        if t == 2:
            n_out, maxlen, delta, counts, symbols, q = huffman_header(head, 4)
            return 0 < n_out <= final
        if t == 1:
            return 0 < _u24(head, 5) <= final
        return False
    except (PesError, IndexError):
        return False


# --------------------------------------------------------------- pixels --

def pixels(rec, mode):
    """Rows of pixel values for a colour or mask record. EGA: planes combined
    bit p of value = stored plane p (the plane words in the header then map
    each stored plane to an EGA plane mask -- see plane_map). CGA: 2 bits per
    pixel, MSB first. Column-major storage: plane[x * h + y]."""
    w, h, pl, data = rec['w'], rec['h'], rec['planes'], rec['data']
    per = w * h
    rows = []
    if mode == 'cga':
        for y in range(h):
            row = []
            for x in range(w):
                byte = data[x * h + y]
                for sh in (6, 4, 2, 0):
                    row.append((byte >> sh) & 3)
            rows.append(row)
        return rows
    for y in range(h):
        row = []
        for x in range(w):
            for bit in range(7, -1, -1):
                v = 0
                for p in range(pl):
                    v |= ((data[p * per + x * h + y] >> bit) & 1) << p
                row.append(v)
        rows.append(row)
    return rows


def plane_map(rec):
    """The four bytes of header words 7 and 8 read as one EGA plane mask per
    stored plane -- 01 02 04 08 on every four-plane record, which is the
    identity; 0x78 on the one-plane tyres (intensity only: dark grey);
    0x12/0x04/0x78 on the three-plane palm. Low four bits only; what the
    high bits carry is NOT established (see docs/04)."""
    return [rec['c'] & 0xff, rec['c'] >> 8, rec['d'] & 0xff, rec['d'] >> 8]


def ega_colour(rec, v):
    pm = plane_map(rec)
    col = 0
    for p in range(rec['planes']):
        if v >> p & 1:
            col |= pm[p] & 0x0f
    return col


def mask_rows(recs, rec, mode):
    m = [r for r in recs if r['tag'] == rec['tag'].upper() and r is not rec
         and r['w'] == rec['w'] and r['h'] == rec['h'] and r['planes'] == 1]
    if not m:
        return None
    rows = pixels(m[0], mode)
    if mode == 'cga':
        return [[v == 3 for v in row] for row in rows]
    return [[v == 1 for v in row] for row in rows]


def render_text(recs, rec, mode, mapped=True):
    rows = pixels(rec, mode)
    mask = mask_rows(recs, rec, mode) if not rec['tag'].isupper() else None
    lines = []
    for y, row in enumerate(rows):
        s = ''
        for x, v in enumerate(row):
            if mask is not None and mask[y][x]:
                s += '.'
            elif mode == 'ega' and mapped and not rec['tag'].isupper():
                s += '%x' % ega_colour(rec, v)
            else:
                s += '%x' % v
        lines.append(s)
    return lines


def _png(width, height, rgb_rows):
    raw = b''.join(b'\x00' + bytes(c for px in row for c in px)
                   for row in rgb_rows)

    def chunk(kind, data):
        c = struct.pack('>I', len(data)) + kind + data
        return c + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def render_png(recs, rec, mode, scale=1, transparent=(255, 0, 255)):
    rows = pixels(rec, mode)
    mask = mask_rows(recs, rec, mode) if not rec['tag'].isupper() else None
    out = []
    for y, row in enumerate(rows):
        line = []
        for x, v in enumerate(row):
            if mask is not None and mask[y][x]:
                c = transparent
            elif rec['tag'].isupper():
                c = (255, 255, 255) if v else (0, 0, 0)
            elif mode == 'cga':
                c = CGA_RGB[v]
            else:
                c = EGA_RGB[ega_colour(rec, v)]
            line.extend([c] * scale)
        for _ in range(scale):
            out.append(line)
    return _png(len(out[0]), len(out), out)


# --------------------------------------------------------------- census --

def census(root):
    dirguard.want_tree(root, 'pes')
    rows = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            continue
        with open(p, 'rb') as fh:
            blob = fh.read()
        if not blob[:1]:
            rows.append((name, len(blob), 'skip', 'empty file'))
            continue
        if not blob[0] & 0x80:
            rows.append((name, len(blob), 'skip',
                         'byte 0 is 0x%02X: packed bit clear' % blob[0]))
            continue
        if (blob[0] & 0x7f) > 2:
            rows.append((name, len(blob), 'skip',
                         'byte 0 is 0x%02X: packed bit set but %d stages, the loader '
                         'takes 1 or 2' % (blob[0], blob[0] & 0x7f)))
            continue
        try:
            rec = unpack(blob)
            recs = directory(rec['payload'])
            rows.append((name, len(blob), depth(recs), rec, recs))
        except PesError as exc:
            rows.append((name, len(blob), 'refused', str(exc)))
    return rows


def report_census(root):
    rows = census(root)
    closed = [r for r in rows if r[2] in ('ega', 'cga', 'unknown')]
    refused = [r for r in rows if r[2] == 'refused']
    skipped = [r for r in rows if r[2] == 'skip']
    print('%s: %d files; %d with the packed bit that CLOSE, %d refused, %d '
          'not 0x8N files' % (root, len(rows), len(closed), len(refused),
                              len(skipped)))
    print()
    print('  %-14s %7s %8s %6s %5s %4s %5s %5s  %s' % (
        'file', 'bytes', 'final', 'ratio', 'depth', 'recs', 'masks', 'brkts',
        'stage-2 out / codes'))
    tot_in = tot_out = 0
    depths = collections.Counter()
    pix = collections.Counter()
    for name, size, dep, rec, recs in closed:
        s2, s1 = rec['stages']
        masks = sum(1 for r in recs if r['tag'].isupper())
        tot_in += size
        tot_out += rec['final']
        depths[dep] += 1
        for r in recs:
            if not r['tag'].isupper() and r['planes']:
                pix[dep] += (r['w'] * (4 if dep == 'cga' else 8)) * r['h']
        print('  %-14s %7d %8d %6.3f %5s %4d %5d %5d  %d / %s' % (
            name, size, rec['final'], rec['final'] / float(size), dep,
            len(recs), masks, s1['groups'], s2['n_out'],
            ' '.join('k%d:%d' % kv for kv in sorted(s1['codes'].items()))))
    print()
    print('  members closing at every declared size : %d of %d 0x8N files'
          % (len(closed), len(closed) + len(refused)))
    print('  compressed bytes in / decoded bytes out: %d / %d = 1 : %.4f'
          % (tot_in, tot_out, tot_out / float(tot_in) if tot_in else 0))
    print('  depth by header words                  : %s' % dict(depths))
    print('  colour pixels (w*8 EGA, w*4 CGA) x h   : %s' % dict(pix))
    for name, size, _r, why in refused:
        print('  REFUSED %-14s %7d  %s' % (name, size, why))
    for name, size, _s, why in skipped:
        print('  not a 0x8N file %-14s %7d  %s' % (name, size, why))
    return 0 if not refused else 1


# --------------------------------------------------------------- selftest --

def _huff_encode(payload, delta=False):
    """A canonical Huffman encoder for the selftest: length-limited only by
    the size of the alphabet it is handed (<= 16 symbols keeps lengths small)."""
    import heapq
    raw = payload
    if delta:
        prev = 0
        d = bytearray()
        for x in raw:
            d.append((x - prev) & 0xff)
            prev = x
        payload = bytes(d)
    freq = collections.Counter(payload)
    if len(freq) < 2:
        freq[(payload[0] + 1) & 0xff] += 0   # a second symbol with weight 0
    heap = [(f, [s]) for s, f in freq.items()]
    heapq.heapify(heap)
    lengths = collections.Counter()
    while len(heap) > 1:
        f1, s1 = heapq.heappop(heap)
        f2, s2 = heapq.heappop(heap)
        for s in s1 + s2:
            lengths[s] += 1
        heapq.heappush(heap, (f1 + f2, s1 + s2))
    maxlen = max(lengths.values())
    counts = [0] * maxlen
    for s, ln in lengths.items():
        counts[ln - 1] += 1
    symbols = []
    codes = {}
    code = 0
    for ln in range(1, maxlen + 1):
        for s in sorted(s for s, l in lengths.items() if l == ln):
            symbols.append(s)
            codes[s] = (ln, code)
            code += 1
        code <<= 1
    bits = []
    for s in payload:
        ln, c = codes[s]
        for i in range(ln - 1, -1, -1):
            bits.append((c >> i) & 1)
    body = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for j, bit in enumerate(bits[i:i + 8]):
            v |= bit << j
        body.append(v)
    hdr = bytes([2]) + struct.pack('<I', len(raw))[:3] + \
        bytes([maxlen | (0x80 if delta else 0)]) + bytes(counts) + bytes(symbols)
    return hdr + bytes(body)


def _run_encode(payload, tab, body_tokens, F=10):
    hdr = bytes([1]) + struct.pack('<I', len(payload))[:3] + \
        struct.pack('<I', len(body_tokens)) + bytes([F]) + bytes(tab)
    return hdr + body_tokens


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r' % (got, expected)))

    def refused(label, blob, needle):
        try:
            rec = unpack(blob)
            directory(rec['payload'])
            checks.append((label, False, 'it parsed'))
        except PesError as exc:
            ok = needle in str(exc)
            checks.append((label, ok, '' if ok else 'said %r' % str(exc)))

    def member_of(payload, toks, F=10, delta=False, nstages=2, tab=None):
        tab = tab or [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]
        s1 = _run_encode(payload, tab, bytes(toks), F=F)
        if nstages == 1:
            return bytes([0x81]) + struct.pack('<I', len(payload))[:3] + s1
        return bytes([0x82]) + struct.pack('<I', len(payload))[:3] + _huff_encode(s1, delta)

    # -- a member built here, run-coded by hand so every code kind is used --
    mask = HDR.pack(1, 40, 0, 40, 0, 0, 0x000f, 0) + bytes([0x0f] * 40)
    col = HDR.pack(1, 40, 0, 40, 0, 0, 0x0807, 0) + bytes([0x10] * 40 + [0x20] * 40)
    total = 6 + 16 + len(mask) + len(col)
    payload = struct.pack('<IH', total, 2) + b'AAAAaaaa' + \
        struct.pack('<II', 0, len(mask)) + mask + col
    toks = bytearray()
    toks += payload[:6] + b'AAAAaaaa'          # literals
    toks += bytes([0xf2, 0x04, 0x00, 0x00])    # k=3  wide run : 4 x 00
    toks += bytes([0x38])                      # literal 0x38 = offset of aaaa
    toks += bytes([0xf3, 0x00])                # k=4           : 3 x 00
    toks += mask[:16]                          # header, literal
    toks += bytes([0xf0, 40, 0x0f])            # k=1           : 0f x 40
    toks += col[:16]
    toks += bytes([0xf1, 0x10, 0x10, 0xf1, 20])  # bracket {10 10} x 20
    toks += bytes([0xf3, 0x20])                # k=4           : 3 x 20
    toks += bytes([0xf2, 37, 0x00, 0x20])      # k=3           : 37 x 20
    member = member_of(payload, toks)
    rec = unpack(member)
    want('a member built here decodes through both stages to its payload',
         rec['payload'] == payload, True)
    want('its run stage saw one repeat bracket and codes k=1,3,4',
         [rec['stages'][1]['groups'], sorted(rec['stages'][1]['codes'])], [1, [1, 3, 4]])
    recs = directory(rec['payload'])
    want('its directory tiles into a mask and a two-plane colour record',
         [(r['tag'], r['planes']) for r in recs], [('AAAA', 1), ('aaaa', 2)])
    want('and the header words call it EGA', depth(recs), 'ega')
    want('the two-plane record renders through the plane map 07/08 as colours 7 and 8',
         set(render_text(recs, recs[1], 'ega')), {'0087....'})
    # a second file: F bit 7 (no bracket pass), the k=2 escaped literal,
    # delta-mode Huffman, and a record with no cells
    pay2 = struct.pack('<IH', 22 + 16 + 76, 2) + b'BBBBCCCC' + struct.pack('<II', 0, 16) + \
        HDR.pack(0, 0, 0, 0, 0, 0, 0, 0) + HDR.pack(1, 60, 0, 60, 0, 0, 0x000f, 0) + bytes(60)
    toks2 = pay2[:14] + bytes([0xf1, 0x00, 0xf0, 3, 0x00, 0x10, 0xf0, 3, 0x00, 0xf0, 16, 0x00]) + \
        pay2[38:54] + bytes([0xf2, 60, 0x00, 0x00])
    m2 = member_of(pay2, toks2, F=0x8a, delta=True)
    r2 = unpack(m2)
    want('a delta-mode Huffman stage over a no-bracket run stage with an escaped '
         'literal (k=2) decodes', r2['payload'] == pay2, True)
    want('its Huffman info says delta and its run codes are k=1, k=2 and the wide k=3',
         [r2['stages'][0]['delta'], sorted(r2['stages'][1]['codes'])], [True, [1, 2, 3]])
    want('a record with 0 x 0 cells is allowed with no data, beside a 1 x 60 mask',
         [r['planes'] for r in directory(r2['payload'])], [0, 1])
    want('a one-stage member (0x81) runs the run stage alone',
         unpack(member_of(pay2, toks2, F=0x8a, nstages=1))['payload'] == pay2, True)

    # -- refusals ----------------------------------------------------------
    refused('a byte appended is refused when the stream did not end on a boundary',
            member + b'\x00', 'after the compressed stream')
    want('the built member did not end on a boundary (so that check means something)',
         rec['stages'][0]['bits'] % 8 != 0, True)
    refused('two bytes appended are refused', member + b'\x00\x00', 'after the compressed stream')
    refused('a byte removed is refused', member[:-1], 'ran out')
    refused('MZ is refused on its first byte', b'MZ' + bytes(100), 'packed bit')
    refused('a stage count of 3 is refused', b'\x83' + member[1:], '1 or 2')
    refused('a pack type of 3 is refused (INVALID PACK TYPE)',
            member[:4] + b'\x03' + member[5:], 'INVALID PACK TYPE')
    bad = bytearray(member)
    bad[9] += 1                                    # a count -> Kraft != 1
    refused('a count table whose Kraft sum is not 1 is refused', bytes(bad), 'Kraft')
    refused('a repeat bracket with count 1 is refused',
            member_of(payload, bytes(toks) + bytes([0xf1, 0x00, 0xf1, 1])), 'count 1')
    payx = bytearray(payload)
    payx[0] += 1                                   # the directory total, off by one
    refused('a directory total that disagrees with the payload is refused',
            member_of(bytes(payx), bytes([toks[0] + 1]) + bytes(toks[1:])), 'directory total')
    want('looks_like_head accepts the built member', looks_like_head(member, len(member)), True)
    want('looks_like_head refuses MZ', looks_like_head(b'MZ' + bytes(100), 102), False)
    want('looks_like_head refuses a file far larger than its declared final size',
         looks_like_head(member, 10 * len(member)), False)

    # -- the object block --------------------------------------------------
    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', OBJECT_REL)
    probe = os.path.join(obj, 'STUMP.PES')
    if os.path.isfile(probe):
        before = len(checks)
        rows = census(obj)
        closed = [r for r in rows if r[2] in ('ega', 'cga', 'unknown')]
        refusedr = [r for r in rows if r[2] == 'refused']
        others = [r for r in rows if r[2] == 'skip']
        want('93 members with the packed bit close at every declared size',
             len(closed), 93)
        want('none is refused', len(refusedr), 0)
        want('17 files are not 0x8N files (110 - 93)', len(others), 17)
        byname = {r[0]: r for r in closed}
        want('the 49 .PES minus the three MZ engines are 46 members and all EGA',
             sum(1 for n, s, d, r, rs in closed if n.endswith('.PES') and d == 'ega'), 46)
        want('the 46 .PCS are all CGA',
             sum(1 for n, s, d, r, rs in closed if n.endswith('.PCS') and d == 'cga'), 46)
        want('HJKA.0OK is EGA and decodes to the same payload as SEGA.PES',
             [byname['HJKA.0OK'][2], byname['HJKA.0OK'][3]['payload'] == byname['SEGA.PES'][3]['payload']],
             ['ega', True])
        want('no member sets Huffman delta mode',
             sum(1 for r in closed if r[3]['stages'][0]['delta']), 0)
        want('23 members end their bitstream on a byte boundary and carry the flush byte',
             [sum(1 for r in closed if r[3]['flush']),
              sum(1 for r in closed if r[3]['stages'][0]['bits'] % 8 == 0)], [23, 23])
        want('STUMP.PES: 564 bytes from 411 from 360, 12 records',
             [byname['STUMP.PES'][3]['final'], byname['STUMP.PES'][3]['stages'][0]['n_out'],
              byname['STUMP.PES'][1], len(byname['STUMP.PES'][4])], [564, 411, 360, 12])
        want('STUMP.PES escape table is 0a 0e 12 14 15 16 17 19 1b 1c',
             byname['STUMP.PES'][3]['stages'][1]['tab'],
             [0x0a, 0x0e, 0x12, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1b, 0x1c])
        want('five members set bit 7 of the run-stage flag byte (no bracket pass)',
             sorted(n for n, s, d, r, rs in closed if r['stages'][1]['F'] & 0x80),
             ['ENDGAME3.PES', 'ENDMAP.PES', 'GROUNDS.PES', 'HORIZON.PES', 'TITLES.PES'])
        palm = byname['PALM.PES'][4]
        shp1 = [r for r in palm if r['tag'] == 'shp1'][0]
        want('PALM.PES shp1 is 4 x 47 bytes, three planes, plane words 0412 0038',
             [shp1['w'], shp1['h'], shp1['planes'], shp1['c'], shp1['d']],
             [4, 47, 3, 0x0412, 0x0038])
        lines = render_text(palm, shp1, 'ega')
        want('its fronds render green (2) and its trunk red (4) through the plane map',
             [lines[6][10], lines[30][12]], ['2', '4'])
        sega = byname['SEGA.PES'][4]
        shp0 = [r for r in sega if r['tag'] == 'shp0'][0]
        want('SEGA.PES shp0 is a 32 x 30 four-plane record with the identity plane map '
             '(low nibbles 1 2 4 8; the raw bytes are 01 02 f4 08)',
             [shp0['w'] * 8, shp0['h'], shp0['planes'], [v & 0x0f for v in plane_map(shp0)],
              plane_map(shp0)], [32, 30, 4, [1, 2, 4, 8], [0x01, 0x02, 0xf4, 0x08]])
        for n in ('CORV.PES', 'CHEVY.PES', 'BEETLE.PES'):
            want('%s is not a 0x8N file (it is MZ)' % n,
                 [r[2] for r in rows if r[0] == n], ['skip'])
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((OBJECT_CHECKS,
                        '%s not beside the box; pass --object DIR to run them'
                        % OBJECT_REL))

    checks.append(('dirguard.want_file is imported', hasattr(dirguard, 'want_file'), ''))
    checks.append(('nameguard.guard is imported', hasattr(nameguard, 'guard'), ''))
    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    for count, why in skipped:
        print('  %-*s  SKIP   %d checks: %s' % (width, '(object block)', count, why))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    lost = sum(count for count, _why in skipped)
    print('%d checks, %d failures, %d skipped' % (len(checks), bad, lost))
    return 1 if bad else 0


# ------------------------------------------------------------------- main --

def cmd_validate(path, blob, rec):
    print(os.path.basename(path))
    print('  file bytes                : %d' % len(blob))
    print('  byte 0                    : 0x%02X = packed, %d stages' % (blob[0], rec['nstages']))
    print('  declared final size       : %d  (1 : %.4f against the file)'
          % (rec['final'], rec['final'] / float(len(blob))))
    for i, s in enumerate(rec['stages'], 1):
        if s['type'] == 2:
            print('  stage %d  Huffman           : out %d, max code length %d, %d symbols, '
                  '%d header bytes, %d of %d body bits used%s'
                  % (i, s['n_out'], s['maxlen'], s['nsym'], s['header'], s['bits'],
                     s['body_bytes'] * 8, ', DELTA' if s['delta'] else ''))
        else:
            print('  stage %d  runs              : out %d from %d body bytes, flag 0x%02X, '
                  'escapes %s' % (i, s['n_out'], s['n_body'], s['F'],
                                  ' '.join('%02x' % x for x in s['tab'])))
            print('           bracket pass      : %s, %d repeat bracket(s)'
                  % ('skipped (bit 7)' if s['F'] & 0x80 else 'run', s['groups']))
            print('           run codes used    : %s'
                  % (' '.join('k%d:%d' % kv for kv in sorted(s['codes'].items())) or 'none'))
    recs = rec['records']
    print('  payload                   : %d bytes = directory total, %d records, '
          '%d masks, tiles with no gap' % (rec['final'], len(recs),
                                            sum(1 for r in recs if r['tag'].isupper())))
    print('  depth by header words     : %s' % rec['depth'].upper())
    print('  CLOSES')


def cmd_dir(path, blob, rec):
    print('%s: %d records, depth %s' % (os.path.basename(path), len(rec['records']), rec['depth']))
    print('  %-4s %6s %5s  %4s %4s %5s %5s  %6s %6s %6s %6s  %s' % (
        'tag', 'offset', 'bytes', 'w', 'h', 'x', "h'", 'word5', 'word6', 'word7', 'word8', 'planes / pixels'))
    px = 8 if rec['depth'] == 'ega' else 4
    for r in rec['records']:
        print('  %-4s %6d %5d  %4d %4d %5d %5d  %6.4x %6.4x %6.4x %6.4x  %d  %d x %d' % (
            r['tag'], r['off'], r['size'], r['w'], r['h'], r['x'], r['h2'], r['a'], r['b'],
            r['c'], r['d'], r['planes'], r['w'] * px, r['h']))


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--dir', action='store_true', help='list the shape directory')
    ap.add_argument('--render', metavar='TAG', help='text render of one record')
    ap.add_argument('--raw', action='store_true',
                    help='with --render on EGA: print plane indices, not mapped colours')
    ap.add_argument('--png', metavar='TAG', help='write one record as PNG (needs --out)')
    ap.add_argument('--scale', type=int, default=1)
    ap.add_argument('--out', default=None)
    ap.add_argument('--census', metavar='DIR', help='every 0x8N file under DIR')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has travelled' % OBJECT_REL)
    args = ap.parse_args()
    if args.selftest:
        raise SystemExit(selftest(args.object))
    if args.census:
        raise SystemExit(report_census(args.census))
    if not args.file:
        ap.error('give a .PES or .PCS file, or --census DIR')
    try:
        blob, rec = read(args.file)
        if args.dir:
            cmd_dir(args.file, blob, rec)
        elif args.render or args.png:
            tag = args.render or args.png
            hits = [r for r in rec['records'] if r['tag'] == tag]
            if not hits:
                print('REFUSE  no record tagged %r in %s' % (tag, os.path.basename(args.file)))
                return 1
            r = hits[0]
            mode = rec['depth'] if rec['depth'] != 'unknown' else 'ega'
            if args.png:
                if not args.out:
                    ap.error('--png needs --out')
                with open(args.out, 'wb') as fh:
                    fh.write(render_png(rec['records'], r, mode, args.scale))
                print('wrote %s: %s %s, %d x %d pixels, %s' % (
                    args.out, os.path.basename(args.file), tag,
                    r['w'] * (8 if mode == 'ega' else 4), r['h'], mode.upper()))
            else:
                print('%s %s: %d x %d pixels, %d plane(s), %s, header words %s'
                      % (os.path.basename(args.file), tag, r['w'] * (8 if mode == 'ega' else 4),
                         r['h'], r['planes'], mode.upper(),
                         ' '.join('%04x' % v for v in (r['a'], r['b'], r['c'], r['d']))))
                if mode == 'ega' and not r['tag'].isupper() and not args.raw:
                    print('  (digits are EGA colours through the plane map %s; . = masked)'
                          % ' '.join('%02x' % v for v in plane_map(r)[:r['planes']]))
                for line in render_text(rec['records'], r, mode, mapped=not args.raw):
                    print('  ' + line)
        else:
            cmd_validate(args.file, blob, rec)
    except PesError as exc:
        print('REFUSE  %s: %s' % (os.path.basename(args.file), exc))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
