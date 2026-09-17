#!/usr/bin/env python3
"""placement.py -- read the `ma_NNNN_NNPlacement` tables that Unity's
`resources.assets` carries as TextAssets, and recover the map graph.

What this answers
------------------

The object holds 145 AssetBundles in 51 directories named `ma_NNNN`, with
files named `ma_NNNN_NN`, and the second number is not documented anywhere.
`resources.assets` turns out to hold 46 `TextAsset` objects named
`ma_NNNN_NNPlacement`, and their contents name the same two numbers again, in
records of the form `MJ_0005_01_03` pointing at `MA_0005_02`.  **The second
number is a sub-area of the map**, and the tables are the doors between them.

The format, derived, with a residue-0 closure on 46 of 46 tables
-----------------------------------------------------------------

A table is a flat sequence of sections and nothing else:

    u16 kind, u16 count, then `count` records of that kind's size

    kind 0   248 bytes            map jumps      MJ_<map>_<area>_<n>
    kind 1   376 bytes            placed objects IBX_ (item box), SPT_ (spot)
    kind 2   112 + n * 308        battles        BTL_/EBT_, n encounter slots
                                  with n at +108 of the record's own header
    kind 3   404 bytes            areas          AR_ (NPC and event triggers)
    kind 4   208 bytes            event calls    EC_

Strings inside a record are fixed-width UTF-16LE slots, NUL-padded: a map jump
is 88 bytes of name, then four 40-byte slots -- the trigger area, the
destination map, the destination point, and the trigger type (`TOUCH`).

THE CLOSURE: the section walk must consume the TextAsset exactly.  It does, on
46 of 46, and a wrong record size for any one kind moves the end of the last
section.  That is the only check this format offers and it is the reason the
sizes above are stated rather than guessed: each one was found by requiring
all 46 to close at once.

    python placement.py selftest
    python placement.py list    ASSETS            -- the 46 tables
    python placement.py close   ASSETS            -- the residue, per table
    python placement.py dump    ASSETS --name N
    python placement.py graph   ASSETS            -- the map connection graph
    python placement.py census  ASSETS

Standard library only.
"""

import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sfv15                                                # noqa: E402

KIND_NAME = {0: 'map jump', 1: 'object', 2: 'battle', 3: 'area',
             4: 'event call'}
FIXED = {0: 248, 1: 376, 3: 404, 4: 208}
BATTLE_HEADER = 112
BATTLE_SLOT = 308
BATTLE_COUNT_AT = 108


class Refused(Exception):
    pass


def record_size(kind, blob, off):
    if kind in FIXED:
        return FIXED[kind]
    if kind == 2:
        if off + BATTLE_HEADER > len(blob):
            raise Refused('battle record header runs past the table')
        n, = struct.unpack_from('<H', blob, off + BATTLE_COUNT_AT)
        if n > 64:
            raise Refused('battle record claims %d encounter slots' % n)
        return BATTLE_HEADER + n * BATTLE_SLOT
    raise Refused('section kind %d is not one of the five' % kind)


def sections(blob):
    """Every section, with the walk required to consume the table exactly."""
    o = 0
    out = []
    while o < len(blob):
        if o + 4 > len(blob):
            raise Refused('%d bytes left, too few for a section header'
                          % (len(blob) - o))
        kind, count = struct.unpack_from('<HH', blob, o)
        o += 4
        # A count of zero would make four bytes of trailing padding parse as
        # a valid empty section, and the selftest caught exactly that on its
        # first run: four zero bytes appended to a good table were accepted
        # "kind 0, count 0" and the residue stayed at zero.  None of the 114
        # sections in the object's 46 tables has a count of zero, so the
        # refusal costs nothing and closes the hole.
        if count == 0:
            raise Refused('a section of kind %d with a count of zero at %d; '
                          'the object has none and four zero bytes of padding '
                          'would look exactly like this' % (kind, o - 4))
        recs = []
        for _ in range(count):
            sz = record_size(kind, blob, o)
            if o + sz > len(blob):
                raise Refused('a %s record of %d at %d runs past the %d-byte '
                              'table' % (KIND_NAME.get(kind, kind), sz, o,
                                         len(blob)))
            recs.append((o, sz))
            o += sz
        out.append(dict(kind=kind, count=count, records=recs))
    return out


def utf16_slot(blob, off, width):
    b = blob[off:off + width]
    z = b.find(b'\0\0')
    if z >= 0:
        b = b[:z + (z & 1)]
    return b.decode('utf-16le', 'replace').rstrip('\0')


def record_name(blob, off, kind):
    width = 88 if kind == 0 else 40
    return utf16_slot(blob, off, width)


def map_jump(blob, off):
    return dict(name=utf16_slot(blob, off, 88),
                area=utf16_slot(blob, off + 88, 40),
                dest_map=utf16_slot(blob, off + 128, 40),
                dest_point=utf16_slot(blob, off + 168, 40),
                trigger=utf16_slot(blob, off + 208, 40))


# ------------------------------------------------------- finding the tables

def load_tables(paths):
    """{name: bytes} for every TextAsset whose name ends in `Placement`."""
    out = collections.OrderedDict()
    for p in sfv15.candidates(paths):
        sf = sfv15.load(p)
        for o in sf.objects:
            if o['class_id'] != 49:
                continue
            b = sf.body(o)
            n, = struct.unpack_from('<i', b, 0)
            if not 0 <= n <= 4096 or 4 + n > len(b):
                continue
            name = b[4:4 + n].decode('utf-8', 'replace')
            q = (4 + n + 3) & ~3
            if q + 4 > len(b):
                continue
            m, = struct.unpack_from('<i', b, q)
            if m < 0 or q + 4 + m > len(b):
                continue
            if not name.endswith('Placement'):
                continue
            out[name] = b[q + 4:q + 4 + m]
    return out


# ----------------------------------------------------------------- selftest

def _build(kinds=((0, 2), (2, 1), (4, 1)), break_what=None):
    out = bytearray()
    for kind, count in kinds:
        out += struct.pack('<HH', kind, count)
        for i in range(count):
            if kind == 2:
                n = 2
                rec = bytearray(BATTLE_HEADER + n * BATTLE_SLOT)
                struct.pack_into('<H', rec, BATTLE_COUNT_AT, n)
                rec[0:26] = 'BTL_0005_01_A'.encode('utf-16le')
                out += rec
            else:
                rec = bytearray(FIXED[kind])
                nm = 'MJ_0005_01_%02d' % (i + 1)
                rec[0:len(nm) * 2] = nm.encode('utf-16le')
                if kind == 0:
                    rec[88:88 + 18] = 'mjarea_01'.encode('utf-16le')
                    rec[128:128 + 20] = 'MA_0000_01'.encode('utf-16le')
                    rec[168:168 + 20] = 'mjpoint_04'.encode('utf-16le')
                    rec[208:208 + 10] = 'TOUCH'.encode('utf-16le')
                out += rec
    if break_what == 'trailing':
        out += b'\0\0\0\0'
    if break_what == 'truncate':
        out = out[:-8]
    if break_what == 'kind':
        struct.pack_into('<H', out, 0, 9)
    if break_what == 'slots':
        struct.pack_into('<H', out, 4 + 2 * FIXED[0] + 4 + BATTLE_COUNT_AT,
                         999)
    return bytes(out)


def cmd_selftest(_args):
    print('placement.py selftest -- tables built in memory, most of them')
    print('required to be REFUSED.  The only control this format offers is')
    print('that the section walk consumes the table exactly, so most of these')
    print('break that and nothing else.')
    print()
    ok = bad = 0

    def expect_ok(name, blob, nsec):
        nonlocal ok, bad
        try:
            s = sections(blob)
            if len(s) == nsec:
                print('  ACCEPT  %-38s %d sections, residue 0' % (name, nsec))
                ok += 1
            else:
                print('  ACCEPT  %-38s *** %d sections, wanted %d'
                      % (name, len(s), nsec))
                bad += 1
        except Refused as ex:
            print('  ACCEPT  %-38s *** WRONGLY REFUSED: %s' % (name, ex))
            bad += 1

    def expect_refuse(name, blob, because):
        nonlocal ok, bad
        try:
            sections(blob)
            print('  REFUSE  %-38s *** WRONGLY ACCEPTED (%s)' % (name, because))
            bad += 1
        except Refused as ex:
            print('  REFUSE  %-38s %s' % (name, ex))
            ok += 1

    expect_ok('three sections', _build(), 3)
    expect_ok('one map jump', _build(kinds=((0, 1),)), 1)
    expect_refuse('four trailing bytes', _build(break_what='trailing'),
                  'a short section header')
    expect_refuse('truncated by eight', _build(break_what='truncate'),
                  'the last record runs past the end')
    expect_refuse('section kind 9', _build(break_what='kind'),
                  'only five kinds exist')
    expect_refuse('a battle claiming 999 slots',
                  _build(break_what='slots'), 'not credible')
    expect_refuse('an empty section header', b'\x00\x00',
                  'too few bytes')
    expect_refuse('a Lua chunk', b'\x1bLuaR' + b'\0' * 200, 'wrong container')
    # the slot decoder, against a value known in advance
    blob = bytearray(248)
    blob[0:26] = 'MJ_0005_01_03'.encode('utf-16le')
    blob[128:148] = 'MA_0005_02'.encode('utf-16le')
    j = map_jump(bytes(blob), 0)
    if j['name'] == 'MJ_0005_01_03' and j['dest_map'] == 'MA_0005_02':
        print('  ok      %-38s %s -> %s' % ('UTF-16 slot decode', j['name'],
                                            j['dest_map']))
        ok += 1
    else:
        print('  WRONG   %-38s %r' % ('UTF-16 slot decode', j))
        bad += 1
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


# ----------------------------------------------------------------- commands

def cmd_list(args):
    t = load_tables(args.paths)
    print('%-28s %10s' % ('NAME', 'BYTES'))
    for k, v in t.items():
        print('%-28s %10d' % (k, len(v)))
    print()
    print('%d Placement tables, %d bytes'
          % (len(t), sum(len(v) for v in t.values())))
    return 0


def cmd_close(args):
    t = load_tables(args.paths)
    n = ok = 0
    refused = []
    counts = collections.Counter()
    for k, v in t.items():
        n += 1
        try:
            s = sections(v)
        except Refused as ex:
            refused.append((k, str(ex)))
            continue
        ok += 1
        for sec in s:
            counts[sec['kind']] += sec['count']
    print('Placement tables            : %d' % n)
    print('section walk consumes them  : %d of %d' % (ok, n))
    print()
    print('%-14s %8s' % ('SECTION', 'RECORDS'))
    for k in sorted(counts):
        print('%-14s %8d' % (KIND_NAME.get(k, k), counts[k]))
    print('%-14s %8d' % ('TOTAL', sum(counts.values())))
    if refused:
        print()
        for k, why in refused:
            print('  %-28s %s' % (k, why))
    return 0 if ok == n and n else 2


def cmd_dump(args):
    t = load_tables(args.paths)
    if args.name not in t:
        raise Refused('no Placement table named %r' % args.name)
    blob = t[args.name]
    print('%s, %d bytes' % (args.name, len(blob)))
    print()
    for sec in sections(blob):
        print('section kind %d (%s), %d records'
              % (sec['kind'], KIND_NAME.get(sec['kind'], '?'), sec['count']))
        for off, sz in sec['records'][:args.limit]:
            if sec['kind'] == 0:
                j = map_jump(blob, off)
                print('    %-18s %-12s -> %-12s %-12s %s'
                      % (j['name'], j['area'], j['dest_map'], j['dest_point'],
                         j['trigger']))
            else:
                print('    %-30s %d bytes'
                      % (record_name(blob, off, sec['kind']), sz))
    return 0


def cmd_graph(args):
    t = load_tables(args.paths)
    edges = []
    for k, v in t.items():
        src = k[:-len('Placement')]
        for sec in sections(v):
            if sec['kind'] != 0:
                continue
            for off, _sz in sec['records']:
                j = map_jump(v, off)
                edges.append((src, j['dest_map'], j['area'], j['dest_point'],
                              j['trigger']))
    dests = collections.Counter(e[1] for e in edges)
    srcs = collections.Counter(e[0] for e in edges)
    trig = collections.Counter(e[4] for e in edges)
    print('map jumps           : %d' % len(edges))
    print('source sub-areas    : %d' % len(srcs))
    print('destination names   : %d' % len(dests))
    print('trigger types       : %s' % dict(trig))
    print()
    print('%-18s %-18s %-14s %s' % ('FROM', 'TO', 'AT', 'ARRIVING AT'))
    for e in edges[:args.limit]:
        print('%-18s %-18s %-14s %s' % (e[0], e[1], e[2], e[3]))
    print()
    print('destinations, by how many doors lead to them:')
    for d, n in dests.most_common(12):
        print('  %-18s %d' % (d, n))
    return 0


def cmd_census(args):
    t = load_tables(args.paths)
    per_map = collections.defaultdict(collections.Counter)
    prefixes = collections.Counter()
    for k, v in t.items():
        m = k[:7]
        for sec in sections(v):
            per_map[m][sec['kind']] += sec['count']
            for off, _sz in sec['records']:
                nm = record_name(v, off, sec['kind'])
                if '_' in nm:
                    prefixes[nm.split('_')[0]] += 1
    print('%-10s %10s %8s %8s %8s %8s' %
          ('MAP', 'MAP JUMPS', 'OBJECTS', 'BATTLES', 'AREAS', 'EVENTS'))
    tot = collections.Counter()
    for m in sorted(per_map):
        c = per_map[m]
        print('%-10s %10d %8d %8d %8d %8d'
              % (m, c[0], c[1], c[2], c[3], c[4]))
        tot.update(c)
    print('%-10s %10d %8d %8d %8d %8d'
          % ('TOTAL', tot[0], tot[1], tot[2], tot[3], tot[4]))
    print()
    print('record name prefixes: %s' % dict(prefixes.most_common(12)))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'list', 'close', 'dump',
                                     'graph', 'census'))
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--name')
    ap.add_argument('--limit', type=int, default=40)
    args = ap.parse_args()
    if args.mode != 'selftest' and not args.paths:
        ap.error('%s needs a path' % args.mode)
    if args.mode == 'dump' and not args.name:
        ap.error('dump needs --name')
    try:
        return globals()['cmd_' + args.mode](args)
    except Refused as ex:
        sys.stderr.write('REFUSED: %s\n' % ex)
        return 2


if __name__ == '__main__':
    sys.exit(main())
