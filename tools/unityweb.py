#!/usr/bin/env python3
"""unityweb.py -- read Unity **UnityWeb** AssetBundles (format 3), the
LZMA-compressed bundle Unity 5 wrote before `UnityFS`.

Why this file exists rather than `unityarc.py`
-----------------------------------------------

The box holds `unityarc.py`, which reads `UnityFS`: a different signature, a
different header, a per-block flags word and four compression codecs.  This
object has **no** `UnityFS` archive.  Its 145 bundles are `UnityWeb`, whose
header is 60 bytes, whose payload is one LZMA stream in the `alone` framing,
and whose decompressed body is a **big-endian** node table followed by whole
SerializedFiles.  Pointing `unityarc.py` here is recorded as a refusal in
docs/13; it is not patched, because the two formats share only a vendor.

The layout, derived from the object and checked against it
-----------------------------------------------------------

    cstr    signature            "UnityWeb"
    u32 BE  format               3
    cstr    playerVersion        "5.x.x"
    cstr    engineVersion        "5.2.2p3"
    u32 BE  minimumStreamedBytes
    u32 BE  headerSize           60 on every bundle here
    u32 BE  numberOfLevelsToDownloadBeforeStreaming
    i32 BE  levelCount
            levelCount x (u32 BE compressedSize, u32 BE uncompressedSize)
    u32 BE  completeFileSize     -- the file's own length      (format >= 2)
    u32 BE  fileInfoHeaderSize                                 (format >= 3)
    u8      padding
    ... at offset headerSize: the LZMA stream

    decompressed, and BIG-ENDIAN, which is the trap:
    i32 BE  nodeCount
            nodeCount x (cstr path, u32 BE offset, u32 BE size)
    ... then the node bodies, each a version-15 SerializedFile

THE CLOSURES, and there are four
---------------------------------

  1. `completeFileSize` equals the length of the file on disk.
  2. `headerSize + compressedSize` equals the length of the file on disk --
     that is, the LZMA stream runs to the last byte and nothing follows it.
  3. the LZMA stream decompresses to exactly `uncompressedSize`, which is a
     number Unity wrote and this reader did not.
  4. every node's `offset + size` lies inside the decompressed blob, and the
     last one ends at its last byte.

A reader that has the node table's endianness wrong fails 4 loudly -- the
first node claims 1,342,177,280 bytes -- which is how the big-endian was
found here rather than assumed.

    python unityweb.py selftest
    python unityweb.py validate DIR|FILE...    -- header only
    python unityweb.py info    FILE
    python unityweb.py list    FILE            -- the node table
    python unityweb.py census  DIR             -- every bundle, with closures
    python unityweb.py inside  DIR             -- every node, as a v15 file
    python unityweb.py extract FILE --node N --out FILE

Standard library only: `lzma` is in it.
"""

import argparse
import collections
import lzma
import os
import struct
import sys

SIGNATURE = b'UnityWeb'


class Refused(Exception):
    """A refusal with a reason.  Never an exit code of 0."""


def _cstr(d, o, limit=256):
    z = d.find(b'\0', o)
    if z < 0 or z - o > limit:
        raise Refused('unterminated string at offset %d' % o)
    return d[o:z], z + 1


class UnityWeb(object):
    def __init__(self, data, path='<memory>'):
        self.path = path
        self.data = data
        if len(data) < 60:
            raise Refused('%d bytes is shorter than a UnityWeb header'
                          % len(data))
        sig, o = _cstr(data, 0, 32)
        if sig != SIGNATURE:
            raise Refused('signature %r, not %r' % (sig[:16], SIGNATURE))
        self.format, = struct.unpack_from('>I', data, o)
        o += 4
        if self.format != 3:
            raise Refused('bundle format %d; this reader is format 3 only'
                          % self.format)
        pv, o = _cstr(data, o, 64)
        ev, o = _cstr(data, o, 64)
        self.player_version = pv.decode('ascii', 'replace')
        self.engine_version = ev.decode('ascii', 'replace')
        (self.min_streamed, self.header_size, self.levels_before,
         self.level_count) = struct.unpack_from('>IIIi', data, o)
        o += 16
        if not 0 < self.level_count <= 64:
            raise Refused('levelCount %d is not credible' % self.level_count)
        self.levels = []
        for _ in range(self.level_count):
            c, u = struct.unpack_from('>II', data, o)
            o += 8
            self.levels.append((c, u))
        self.complete_size, = struct.unpack_from('>I', data, o)
        o += 4
        self.file_info_header_size, = struct.unpack_from('>I', data, o)
        o += 4
        self.header_end = o
        # CLOSURE 1
        if self.complete_size != len(data):
            raise Refused('completeFileSize %d against %d bytes on disk'
                          % (self.complete_size, len(data)))
        if not 0 < self.header_size <= len(data):
            raise Refused('headerSize %d outside a file of %d'
                          % (self.header_size, len(data)))
        # CLOSURE 2
        comp = self.levels[0][0]
        if self.header_size + comp != len(data):
            raise Refused('headerSize %d + compressedSize %d = %d against %d '
                          'bytes on disk' % (self.header_size, comp,
                                             self.header_size + comp,
                                             len(data)))
        self._blob = None
        self._nodes = None

    # -- the payload -------------------------------------------------------

    @property
    def compressed_size(self):
        return self.levels[0][0]

    @property
    def uncompressed_size(self):
        return self.levels[0][1]

    def blob(self):
        """The LZMA payload, decompressed, checked against Unity's own size."""
        if self._blob is not None:
            return self._blob
        raw = self.data[self.header_size:self.header_size +
                        self.compressed_size]
        d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        try:
            out = d.decompress(raw)
        except lzma.LZMAError as ex:
            raise Refused('LZMA: %s' % ex)
        # CLOSURE 3
        if len(out) != self.uncompressed_size:
            raise Refused('decompressed to %d where the header declares %d'
                          % (len(out), self.uncompressed_size))
        self._blob = out
        return out

    def nodes(self):
        """The node table, big-endian, with the fourth closure checked."""
        if self._nodes is not None:
            return self._nodes
        b = self.blob()
        n, = struct.unpack_from('>i', b, 0)
        if not 0 < n <= 4096:
            raise Refused('nodeCount %d is not credible; if it is a large '
                          'power of two the endianness is wrong' % n)
        o = 4
        out = []
        for _ in range(n):
            nm, o = _cstr(b, o, 512)
            off, size = struct.unpack_from('>II', b, o)
            o += 8
            if off + size > len(b):
                raise Refused('node %r at %d+%d runs past the %d-byte blob'
                              % (nm[:40], off, size, len(b)))
            out.append(dict(name=nm.decode('utf-8', 'replace'),
                            offset=off, size=size))
        # CLOSURE 4
        end = max(x['offset'] + x['size'] for x in out)
        if end != len(b):
            raise Refused('the last node ends at %d, the blob is %d'
                          % (end, len(b)))
        self._nodes = out
        return out

    def node_bytes(self, i):
        b = self.blob()
        x = self.nodes()[i]
        return b[x['offset']:x['offset'] + x['size']]


def load(path):
    with open(path, 'rb') as f:
        return UnityWeb(f.read(), path)


def looks_unityweb(head):
    return head[:9] == SIGNATURE + b'\0'


def walk(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            yield os.path.join(dirpath, nm)


def candidates(roots):
    out = []
    for root in roots:
        for p in walk(root):
            try:
                with open(p, 'rb') as f:
                    head = f.read(9)
            except OSError:
                continue
            if looks_unityweb(head):
                out.append(p)
    return out


def short(p, keep=48):
    p = p.replace('\\', '/')
    return p if len(p) <= keep else '...' + p[-(keep - 3):]


# ----------------------------------------------------------------- selftest

def _build(nodes=2, break_what=None):
    """A complete, valid, tiny UnityWeb bundle, built in memory."""
    body = bytearray()
    table = bytearray()
    entries = []
    payload = bytearray()
    for i in range(nodes):
        entries.append(('BuildPlayer-x_%02d' % i, 32 + i))
    # first pass to size the table
    tbl = bytearray(struct.pack('>i', nodes))
    off = 0
    sizes = []
    for nm, sz in entries:
        tbl += nm.encode() + b'\0' + struct.pack('>II', 0, sz)
        sizes.append(sz)
    base = len(tbl)
    tbl = bytearray(struct.pack('>i', nodes))
    off = base
    for (nm, sz) in entries:
        tbl += nm.encode() + b'\0' + struct.pack('>II', off, sz)
        off += sz
    blob = bytearray(tbl)
    for _nm, sz in entries:
        blob += bytes((i * 7) & 0xff for i in range(sz))
    if break_what == 'endian_nodes':
        blob[0:4] = struct.pack('<i', nodes)
    comp = lzma.compress(bytes(blob), format=lzma.FORMAT_ALONE)
    unc = len(blob)
    if break_what == 'uncompressed':
        unc += 1
    head = bytearray()
    head += SIGNATURE + b'\0'
    head += struct.pack('>I', 21 if break_what == 'format' else 3)
    head += b'5.x.x\0'
    head += b'5.2.2p3\0'
    fixed = len(head) + 16 + 8 + 4 + 4 + 1
    header_size = fixed
    total = header_size + len(comp)
    if break_what == 'complete':
        total += 1
    head += struct.pack('>IIIi', total, header_size, 1, 1)
    head += struct.pack('>II', len(comp), unc)
    head += struct.pack('>I', total)
    head += struct.pack('>I', 80)
    head += b'\0'
    assert len(head) == header_size, (len(head), header_size)
    return bytes(head) + comp


def cmd_selftest(_args):
    print('unityweb.py selftest -- bundles built in memory, most of them')
    print('required to be REFUSED.')
    print()
    ok = bad = 0

    def expect_ok(name, blob, nodes):
        nonlocal ok, bad
        try:
            b = UnityWeb(blob)
            n = b.nodes()
            if len(n) != nodes:
                print('  ACCEPT  %-34s *** %d nodes, wanted %d'
                      % (name, len(n), nodes))
                bad += 1
                return
            print('  ACCEPT  %-34s %d nodes, 4 closures ok' % (name, len(n)))
            ok += 1
        except Refused as ex:
            print('  ACCEPT  %-34s *** WRONGLY REFUSED: %s' % (name, ex))
            bad += 1

    def expect_refuse(name, blob, because):
        nonlocal ok, bad
        try:
            b = UnityWeb(blob)
            b.nodes()
            print('  REFUSE  %-34s *** WRONGLY ACCEPTED (%s)' % (name, because))
            bad += 1
        except Refused as ex:
            print('  REFUSE  %-34s %s' % (name, ex))
            ok += 1

    expect_ok('two nodes', _build(2), 2)
    expect_ok('nine nodes', _build(9), 9)
    expect_refuse('format 21', _build(break_what='format'), 'UnityFS era')
    expect_refuse('completeFileSize off by one',
                  _build(break_what='complete'), 'closure 1')
    expect_refuse('uncompressedSize off by one',
                  _build(break_what='uncompressed'), 'closure 3')
    expect_refuse('little-endian node table',
                  _build(break_what='endian_nodes'), 'closure 4')
    expect_refuse('empty file', b'', 'too short')
    expect_refuse('a UnityFS archive', b'UnityFS\0' + b'\0' * 128,
                  'wrong signature')
    expect_refuse('a v15 SerializedFile',
                  struct.pack('>IIII', 8, 64, 15, 32) + b'\0' * 64,
                  'wrong container')
    expect_refuse('an @UTF table', b'@UTF' + b'\0' * 128, 'wrong container')
    print()
    print('%d correct, %d wrong' % (ok, bad))
    return 1 if bad else 0


# ----------------------------------------------------------------- commands

def cmd_validate(args):
    paths = candidates(args.paths)
    print('%-48s %10s %10s  %s'
          % ('FILE', 'DECLARED', 'ON DISK', 'VERDICT'))
    n_ok = n_ref = 0
    for p in paths:
        size = os.path.getsize(p)
        try:
            b = load(p)
            print('%-48s %10d %10d  header ok, engine %s'
                  % (short(p), b.complete_size, size, b.engine_version))
            n_ok += 1
        except Refused as ex:
            print('%-48s %10s %10d  REFUSED: %s' % (short(p), '-', size, ex))
            n_ref += 1
    print()
    print('%d headers read, %d refused, of %d files beginning UnityWeb'
          % (n_ok, n_ref, len(paths)))
    return 0 if n_ref == 0 else 2


def cmd_info(args):
    b = load(args.paths[0])
    print(short(args.paths[0], 200))
    print()
    print('signature            UnityWeb')
    print('format               %d' % b.format)
    print('player version       %s' % b.player_version)
    print('engine version       %s' % b.engine_version)
    print('headerSize           %d' % b.header_size)
    print('  header parsed to   %d, then %d bytes of padding'
          % (b.header_end, b.header_size - b.header_end))
    print('levelCount           %d' % b.level_count)
    for i, (c, u) in enumerate(b.levels):
        print('  level %d            compressed %d  uncompressed %d'
              % (i, c, u))
    print('completeFileSize     %d' % b.complete_size)
    print('  on disk            %d          closure 1 CLOSES'
          % len(b.data))
    print('  headerSize + compressed %d     closure 2 CLOSES'
          % (b.header_size + b.compressed_size))
    blob = b.blob()
    print('decompressed         %d          closure 3 CLOSES' % len(blob))
    nodes = b.nodes()
    print('nodes                %d          closure 4 CLOSES' % len(nodes))
    for i, x in enumerate(nodes):
        print('  [%d] %-44s %10d @ %d' % (i, x['name'], x['size'],
                                          x['offset']))
    return 0


def cmd_list(args):
    b = load(args.paths[0])
    for i, x in enumerate(b.nodes()):
        print('%2d  %10d  %s' % (i, x['size'], x['name']))
    return 0


def cmd_extract(args):
    b = load(args.paths[0])
    data = b.node_bytes(args.node)
    with open(args.out, 'wb') as f:
        f.write(data)
    print('%d bytes -> %s' % (len(data), args.out))
    return 0


def cmd_census(args):
    paths = candidates(args.paths)
    n = 0
    comp = unc = ondisk = 0
    nodes = 0
    engines = collections.Counter()
    players = collections.Counter()
    formats = collections.Counter()
    headers = collections.Counter()
    per_dir = collections.Counter()
    refused = []
    node_names = collections.Counter()
    for p in paths:
        try:
            b = load(p)
        except Refused as ex:
            refused.append((p, str(ex)))
            continue
        n += 1
        ondisk += len(b.data)
        comp += b.compressed_size
        unc += b.uncompressed_size
        engines[b.engine_version] += 1
        players[b.player_version] += 1
        formats[b.format] += 1
        headers[b.header_size] += 1
        per_dir[os.path.basename(os.path.dirname(p))] += 1
        if args.deep:
            try:
                nn = b.nodes()
            except Refused as ex:
                refused.append((p, 'payload: %s' % ex))
                continue
            nodes += len(nn)
            for x in nn:
                node_names[x['name'].split('-')[0]] += 1
    print('bundles read        : %d' % n)
    print('bytes on disk       : %d' % ondisk)
    print('compressed payload  : %d' % comp)
    print('header bytes        : %d' % (ondisk - comp))
    print('format              : %s' % dict(formats))
    print('headerSize          : %s' % dict(headers))
    print('player version      : %s' % dict(players))
    print('engine version      : %s' % dict(engines))
    print('directories         : %d' % len(per_dir))
    if args.deep:
        print('declared uncompressed : %d' % unc)
        print('nodes                 : %d' % nodes)
        print('node name prefixes    : %s' % dict(node_names.most_common(8)))
        if unc:
            print('expansion             : %d / %d = %.4f'
                  % (unc, comp, float(unc) / comp))
    if refused:
        print()
        print('%d refused:' % len(refused))
        for p, why in refused[:20]:
            print('  %-48s %s' % (short(p), why))
    return 0 if not refused else 2


def cmd_inside(args):
    """Decompress every bundle and read each node as a v15 SerializedFile.

    This is where the two readers meet: `unityweb.py` gets the LZMA off and
    finds the nodes, `sfv15.py` closes each node on its own declared length.
    A node that is not a SerializedFile, or that is one and does not close, is
    reported rather than skipped.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sfv15                                            # noqa: E402
    paths = candidates(args.paths)
    per = collections.Counter()
    byt = collections.Counter()
    nodes = closed = notsf = 0
    bundles = 0
    node_bytes = 0
    objects = 0
    refused = []
    for p in paths:
        try:
            b = load(p)
            nn = b.nodes()
        except Refused as ex:
            refused.append((p, str(ex)))
            continue
        bundles += 1
        for i, nd in enumerate(nn):
            nodes += 1
            node_bytes += nd['size']
            blob = b.node_bytes(i)
            try:
                sf = sfv15.SerializedFile15(blob, nd['name'])
            except sfv15.Refused as ex:
                notsf += 1
                refused.append(('%s!%s' % (p, nd['name']), str(ex)))
                continue
            if sf.closes():
                closed += 1
            objects += len(sf.objects)
            for o in sf.objects:
                per[o['class_id']] += 1
                byt[o['class_id']] += o['size']
    print('bundles read                : %d' % bundles)
    print('nodes                       : %d' % nodes)
    print('nodes that are v15 files    : %d' % (nodes - notsf))
    print('  closing on their own size : %d' % closed)
    print('node bytes, decompressed    : %d' % node_bytes)
    print('objects                     : %d' % objects)
    print('object bytes                : %d' % sum(byt.values()))
    print()
    print('%-32s %9s %14s %8s' % ('CLASS', 'OBJECTS', 'BYTES', 'SHARE'))
    total = sum(byt.values())
    for cid, n in per.most_common(args.limit):
        print('%-32s %9d %14d %7.2f%%'
              % ('%s (%d)' % (sfv15.CLASS.get(cid, '?'), cid), n, byt[cid],
                 100.0 * byt[cid] / total if total else 0.0))
    print('%-32s %9d %14d %7.2f%%' % ('TOTAL', objects, total, 100.0))
    print()
    print('negative class IDs          : %d' % sum(1 for c in per if c < 0))
    if refused:
        print()
        print('%d refused:' % len(refused))
        for p, why in refused[:20]:
            print('  %-48s %s' % (short(p), why))
    return 0 if (bundles and closed == nodes and not refused) else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('selftest', 'validate', 'info', 'list',
                                     'census', 'inside', 'extract'))
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--node', type=int, default=0)
    ap.add_argument('--out')
    ap.add_argument('--limit', type=int, default=30)
    ap.add_argument('--deep', action='store_true',
                    help='decompress every payload and read its node table')
    args = ap.parse_args()
    if args.mode != 'selftest' and not args.paths:
        ap.error('%s needs a path' % args.mode)
    if args.mode == 'extract' and not args.out:
        ap.error('extract needs --out')
    try:
        return globals()['cmd_' + args.mode](args)
    except Refused as ex:
        sys.stderr.write('REFUSED: %s\n' % ex)
        return 2


if __name__ == '__main__':
    sys.exit(main())
