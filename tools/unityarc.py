#!/usr/bin/env python3
"""Read UnityFS archives -- the layer `unityfs.py` did not have.

`unityfs.py` reads a Unity **SerializedFile**, which is what *Tales of
Luminaria* shipped and what this object's base APK ships in
`assets/bin/Data/`.  The other half of this object -- 729 files and 98.88 % of
its bytes -- is wrapped in a **UnityFS archive** first, and there are three
levels to get through before a SerializedFile appears:

    archive header -> block table -> concatenated blocks -> node directory
                   -> a SerializedFile inside one node

This module does the first three and hands the fourth to `unityfs.py`, which
it imports rather than reimplements.  A reader that stops at level one and
finds nothing does not report zero, it reports `ok` -- so every level here is
checked against a quantity the file states twice, and `validate` prints the
checks one per line whether they pass or fail.

THE FORMAT, as measured on this object (729 of 729 at format version 8):

    char[8]  "UnityFS\\0"
    u32 BE   format version                     8
    cstr     unity version                      "5.x.x"   (a placeholder)
    cstr     player version                     "0.0.0"   (a placeholder)
    u64 BE   size            == the file's own length, on 729 of 729
    u32 BE   compressedBlocksInfoSize
    u32 BE   uncompressedBlocksInfoSize
    u32 BE   flags

    flags & 0x3F   compression of the blocks-info block
                   0 none, 1 LZMA, 2 LZ4, 3 LZ4HC
    flags & 0x40   blocksAndDirectoryInfoCombined
    flags & 0x80   blockInfoAtEnd -- seek to size - compressedBlocksInfoSize
    flags & 0x100  oldWebPluginCompatibility
    flags & 0x200  blockInfoNeedPaddingAtStart -- the block data is aligned to
                   16 bytes after the blocks-info, not butted against it
    flags & 0x400  usesAssetBundleEncryption

    REPAIRED on pc-themurderofsonicthehedgehog-doc, and both halves of the
    repair are one bit apart.  This reader had 0x200 as the encryption flag and
    had no padding at all before the block data.  On a bundle whose flags read
    0x243 that produced two failures at once: check 3 came up 6 bytes short,
    and `usesAssetBundleEncryption clear` failed on an archive that is not
    encrypted.  Aligning the block data to 16 bytes closes check 3 to residue
    0 on all four bundles of that object AND makes the first block decode,
    which it did not before -- so the correction is not a citation, it is two
    numbers the file states about itself.  0x400 is the encryption bit.

    blocks-info block, once located and decompressed:
      byte[16]  hash of the uncompressed data
      i32 BE    block count, then per block:
                  u32 BE uncompressedSize, u32 BE compressedSize, u16 BE flags
      i32 BE    node count, then per node:
                  i64 BE offset, i64 BE size, u32 BE flags, cstr path

THE CHECKS, and each one is a quantity the file states twice:

  1. the header `size` field equals the file's own length;
  2. every block's decoded length equals its declared uncompressedSize --
     this fires once per block and cannot be satisfied by a wrong layout;
  3. the sum of compressed block sizes plus the header and block table equals
     the file length exactly, residue 0;
  4. the node extents tile the concatenated decompressed blocks: each node
     lies inside it, and the last node's end is covered;
  5. the SerializedFile inside each node states its own `fileSize`, which must
     equal the node's size.

Nothing here decompresses more than it is asked to: blocks are decoded on
demand for the byte range a node needs, so a 344 MB archive can be described
without 344 MB of memory.

    python unityarc.py header   PATH...            -- one line per archive
    python unityarc.py validate PATH...            -- the five checks, per file
    python unityarc.py nodes    PATH               -- the node directory
    python unityarc.py blocks   PATH [--limit N]   -- the block table
    python unityarc.py extract  PATH OUTDIR        -- write every node out
    python unityarc.py census   DIR  [--out FILE]  -- every object of every
                                                      bundle, by class
    python unityarc.py flags    DIR                -- per-block compression
                                                      across a whole tree

Standard library only.  LZ4 block decoding is implemented here because Python
has no LZ4 and a forty-line decoder that checks its own output length against
a declared one is cheaper and more honest than a dependency.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nameguard                                        # noqa: E402

# See unityfs.py: this prints the names of the archives it refuses, and one of
# them is Japanese.
nameguard.guard()
import unityfs

MAGIC = b'UnityFS\0'

COMPRESSION = {0: 'none', 1: 'lzma', 2: 'lz4', 3: 'lz4hc'}


class ArchiveError(Exception):
    """Raised loudly.  Nothing in this module returns an empty result for a
    file it could not read; a file it cannot read raises."""


def lz4_block_decompress(src, expected):
    """Decode one raw LZ4 block.

    Not the LZ4 *frame* format -- there is no magic, no checksum and no
    trailer, because Unity stores bare blocks and states the decoded length
    beside them.  That declared length is the whole positive control: this
    function raises if it does not reach it exactly.
    """
    out = bytearray(expected)
    op = 0
    ip = 0
    n = len(src)
    while ip < n:
        token = src[ip]
        ip += 1
        lit = token >> 4
        if lit == 15:
            while True:
                if ip >= n:
                    raise ArchiveError('lz4: literal length ran off the block')
                b = src[ip]
                ip += 1
                lit += b
                if b != 255:
                    break
        if lit:
            if ip + lit > n or op + lit > expected:
                raise ArchiveError('lz4: literal run of %d overruns' % lit)
            out[op:op + lit] = src[ip:ip + lit]
            ip += lit
            op += lit
        if ip >= n:
            break                       # last sequence: literals and no match
        if ip + 2 > n:
            raise ArchiveError('lz4: truncated match offset')
        offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if offset == 0:
            raise ArchiveError('lz4: match offset 0')
        ml = token & 0x0F
        if ml == 15:
            while True:
                if ip >= n:
                    raise ArchiveError('lz4: match length ran off the block')
                b = src[ip]
                ip += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = op - offset
        if start < 0:
            raise ArchiveError('lz4: match before start of output')
        if op + ml > expected:
            raise ArchiveError('lz4: match of %d overruns declared length' % ml)
        if offset >= ml:
            out[op:op + ml] = out[start:start + ml]
            op += ml
        else:
            # Overlapping match: LZ4 allows the copy to read bytes it has just
            # written, which is how it encodes runs.  Copy by the offset-sized
            # chunk rather than byte by byte.
            while ml > 0:
                take = offset if offset < ml else ml
                out[op:op + take] = out[start:start + take]
                op += take
                start += take
                ml -= take
    if op != expected:
        raise ArchiveError('lz4: decoded %d bytes, block declares %d'
                           % (op, expected))
    return bytes(out)


def lzma_block_decompress(src, expected):
    import lzma
    # Unity writes a 5-byte LZMA1 properties header and then the stream, with
    # no end marker and no size field: the size is the block table's.
    props = src[:5]
    filt = [{'id': lzma.FILTER_LZMA1}]
    lc, lp, pb, dict_size = _lzma_props(props)
    filt[0].update(dict(lc=lc, lp=lp, pb=pb, dict_size=dict_size))
    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filt)
    out = d.decompress(src[5:], expected)
    if len(out) != expected:
        raise ArchiveError('lzma: decoded %d bytes, block declares %d'
                           % (len(out), expected))
    return out


def _lzma_props(props):
    if len(props) < 5:
        raise ArchiveError('lzma: short properties header')
    d = props[0]
    if d >= 9 * 5 * 5:
        raise ArchiveError('lzma: bad properties byte 0x%02x' % d)
    lc = d % 9
    d //= 9
    lp = d % 5
    pb = d // 5
    dict_size = struct.unpack_from('<I', props, 1)[0]
    return lc, lp, pb, dict_size


class Block(object):
    __slots__ = ('usize', 'csize', 'flags', 'coff', 'uoff')

    def __init__(self, usize, csize, flags, coff, uoff):
        self.usize = usize
        self.csize = csize
        self.flags = flags
        self.coff = coff
        self.uoff = uoff

    @property
    def method(self):
        return COMPRESSION.get(self.flags & 0x3F, 'unknown(%d)'
                               % (self.flags & 0x3F))


class Node(object):
    __slots__ = ('offset', 'size', 'flags', 'path')

    def __init__(self, offset, size, flags, path):
        self.offset = offset
        self.size = size
        self.flags = flags
        self.path = path


class UnityArchive(object):
    def __init__(self, path):
        self.path = path
        self.filesize = os.path.getsize(path)
        self.fh = open(path, 'rb')
        head = self.fh.read(8)
        if head != MAGIC:
            raise ArchiveError('%s: magic is %r, not %r'
                               % (path, head, MAGIC))
        self.format = struct.unpack('>I', self.fh.read(4))[0]
        if self.format != 8:
            raise ArchiveError('%s: format version %d, this reader handles 8'
                               % (path, self.format))
        self.unity_version = self._cstr()
        self.player_version = self._cstr()
        (self.size, self.ci_size, self.ui_size,
         self.flags) = struct.unpack('>QIII', self.fh.read(20))
        self.header_end = self.fh.tell()
        self.blocks_at_end = bool(self.flags & 0x80)
        self.combined = bool(self.flags & 0x40)
        self.pad_at_start = bool(self.flags & 0x200)
        self.encrypted = bool(self.flags & 0x400)
        self.bi_method = COMPRESSION.get(self.flags & 0x3F,
                                         'unknown(%d)' % (self.flags & 0x3F))
        self._read_blocks_info()
        self._cache = {}

    def _cstr(self):
        out = bytearray()
        while True:
            c = self.fh.read(1)
            if not c:
                raise ArchiveError('%s: string ran off the end' % self.path)
            if c == b'\0':
                return out.decode('utf-8', 'replace')
            out += c

    def _read_blocks_info(self):
        if self.blocks_at_end:
            self.bi_offset = self.filesize - self.ci_size
        else:
            # Unity aligns the blocks-info to 16 bytes when it follows the
            # header directly at format version >= 7.
            self.bi_offset = (self.header_end + 15) & ~15
        if self.bi_offset < 0 or self.bi_offset + self.ci_size > self.filesize:
            raise ArchiveError('%s: blocks-info at %d+%d is outside the file'
                               % (self.path, self.bi_offset, self.ci_size))
        self.fh.seek(self.bi_offset)
        raw = self.fh.read(self.ci_size)
        m = self.flags & 0x3F
        if m == 0:
            bi = raw
        elif m in (2, 3):
            bi = lz4_block_decompress(raw, self.ui_size)
        elif m == 1:
            bi = lzma_block_decompress(raw, self.ui_size)
        else:
            raise ArchiveError('%s: blocks-info compression %d unknown'
                               % (self.path, m))
        if len(bi) != self.ui_size:
            raise ArchiveError('%s: blocks-info decoded to %d, declared %d'
                               % (self.path, len(bi), self.ui_size))
        self.bi_hash = bi[:16]
        p = 16
        nblocks = struct.unpack_from('>i', bi, p)[0]
        p += 4
        if not 0 <= nblocks <= 1 << 20:
            raise ArchiveError('%s: %d blocks is not credible'
                               % (self.path, nblocks))
        self.blocks = []
        coff = 0
        uoff = 0
        for _ in range(nblocks):
            u, c, f = struct.unpack_from('>IIH', bi, p)
            p += 10
            self.blocks.append(Block(u, c, f, coff, uoff))
            coff += c
            uoff += u
        self.total_uncompressed = uoff
        self.total_compressed = coff
        nnodes = struct.unpack_from('>i', bi, p)[0]
        p += 4
        if not 0 <= nnodes <= 1 << 20:
            raise ArchiveError('%s: %d nodes is not credible'
                               % (self.path, nnodes))
        self.nodes = []
        for _ in range(nnodes):
            off, size, flags = struct.unpack_from('>qqI', bi, p)
            p += 20
            end = bi.index(b'\0', p)
            path = bi[p:end].decode('utf-8', 'replace')
            p = end + 1
            self.nodes.append(Node(off, size, flags, path))
        self.bi_parsed = p
        # Where the data blocks start.  With blockInfoAtEnd the blocks follow
        # the header; otherwise they follow the blocks-info.  At format
        # version >= 7 Unity aligns the stream to 16 bytes after the header,
        # and the header on this object is 44 bytes long -- 8 magic, 4
        # version, 6 and 6 for the two placeholder strings, 20 for the four
        # size fields -- so the blocks begin at 48 and not at 44.
        #
        # That four-byte pad is not guessed.  Check 3 below states the file
        # length twice and it came up short by exactly 4 on the first bundle
        # read, which is how the alignment was found rather than assumed.
        #
        # And the same argument, run a second time on a second object, found
        # the second pad.  When flag 0x200 is set the block data is aligned to
        # 16 bytes AFTER the blocks-info as well; without that, check 3 on the
        # smallest bundle of pc-themurderofsonicthehedgehog-doc read 39521
        # against 39527 and block 0 raised `lz4: match offset 0`.  With it,
        # residue 0 and the block decodes.  Neither number was looked up.
        if self.blocks_at_end:
            self.data_offset = (self.header_end + 15) & ~15 \
                if self.format >= 7 else self.header_end
            self.header_pad = self.data_offset - self.header_end
        else:
            raw = self.bi_offset + self.ci_size
            self.data_offset = (raw + 15) & ~15 if self.pad_at_start else raw
            self.header_pad = self.data_offset - raw

    # -- the five checks ---------------------------------------------------

    def checks(self):
        out = []
        out.append(('header size == file length',
                    self.size == self.filesize,
                    '%d vs %d' % (self.size, self.filesize)))
        out.append(('blocks-info parsed to its declared length',
                    self.bi_parsed == self.ui_size,
                    '%d of %d' % (self.bi_parsed, self.ui_size)))
        # 3: header + blocks + block table == file length
        if self.blocks_at_end:
            acc = self.data_offset + self.total_compressed + self.ci_size
        else:
            acc = self.data_offset + self.total_compressed
        out.append(('header + blocks + table == file length',
                    acc == self.filesize,
                    '%d vs %d, residue %d'
                    % (acc, self.filesize, self.filesize - acc)))
        inside = all(0 <= n.offset and
                     n.offset + n.size <= self.total_uncompressed
                     for n in self.nodes)
        out.append(('every node lies inside the decompressed stream',
                    inside,
                    '%d nodes, stream %d' % (len(self.nodes),
                                             self.total_uncompressed)))
        if self.nodes:
            end = max(n.offset + n.size for n in self.nodes)
            covered = end <= self.total_uncompressed
            out.append(('nodes reach the end of the stream',
                        covered,
                        'last node ends at %d, stream %d, slack %d'
                        % (end, self.total_uncompressed,
                           self.total_uncompressed - end)))
        out.append(('usesAssetBundleEncryption (0x400) clear',
                    not self.encrypted,
                    'flags 0x%X, pad-at-start %s, block pad %d'
                    % (self.flags, 'set' if self.pad_at_start else 'clear',
                       self.header_pad)))
        return out

    # -- data --------------------------------------------------------------

    def _block(self, i):
        b = self.blocks[i]
        hit = self._cache.get(i)
        if hit is not None:
            return hit
        self.fh.seek(self.data_offset + b.coff)
        raw = self.fh.read(b.csize)
        if len(raw) != b.csize:
            raise ArchiveError('%s: block %d short read' % (self.path, i))
        m = b.flags & 0x3F
        if m == 0:
            if b.csize != b.usize:
                raise ArchiveError('%s: block %d stored but %d != %d'
                                   % (self.path, i, b.csize, b.usize))
            data = raw
        elif m in (2, 3):
            data = lz4_block_decompress(raw, b.usize)
        elif m == 1:
            data = lzma_block_decompress(raw, b.usize)
        else:
            raise ArchiveError('%s: block %d compression %d unknown'
                               % (self.path, i, m))
        if len(data) != b.usize:
            raise ArchiveError('%s: block %d decoded %d, declared %d'
                               % (self.path, i, len(data), b.usize))
        if len(self._cache) > 24:
            self._cache.clear()
        self._cache[i] = data
        return data

    def read(self, offset, size):
        """Bytes [offset, offset+size) of the concatenated decompressed
        stream, decoding only the blocks that range touches."""
        if offset < 0 or offset + size > self.total_uncompressed:
            raise ArchiveError('%s: read %d+%d outside stream of %d'
                               % (self.path, offset, size,
                                  self.total_uncompressed))
        out = bytearray()
        want_end = offset + size
        for i, b in enumerate(self.blocks):
            if b.uoff >= want_end:
                break
            if b.uoff + b.usize <= offset:
                continue
            data = self._block(i)
            lo = max(0, offset - b.uoff)
            hi = min(b.usize, want_end - b.uoff)
            out += data[lo:hi]
        if len(out) != size:
            raise ArchiveError('%s: assembled %d bytes for a %d-byte read'
                               % (self.path, len(out), size))
        return bytes(out)

    def node_bytes(self, node):
        return self.read(node.offset, node.size)

    def close(self):
        self.fh.close()


# -- commands --------------------------------------------------------------

FLAGS_WITH_VALUE = ('--out', '--limit', '--n', '--seed')


def _paths(args):
    out = []
    skip = False
    kept = []
    for a in args:
        if skip:
            skip = False
            continue
        if a in FLAGS_WITH_VALUE:
            skip = True
            continue
        if a.startswith('--'):
            continue
        kept.append(a)
    args = kept
    for a in args:
        if os.path.isdir(a):
            for dp, _, fn in os.walk(a):
                for n in fn:
                    if not n.endswith('.hash'):
                        out.append(os.path.join(dp, n))
        else:
            out.append(a)
    return sorted(out)


def cmd_header(argv):
    paths = _paths(argv[2:])
    bad = 0
    for p in paths:
        try:
            a = UnityArchive(p)
        except ArchiveError as e:
            bad += 1
            print('REFUSED  %s' % e)
            continue
        print('%-34s v%d  %-7s %-7s size=%d %s blocks=%d nodes=%d flags=0x%X'
              % (os.path.basename(p), a.format, a.unity_version,
                 a.player_version, a.size,
                 'ok' if a.size == a.filesize else 'MISMATCH',
                 len(a.blocks), len(a.nodes), a.flags))
        a.close()
    print('\n%d archives, %d refused' % (len(paths), bad))
    return 1 if bad and len(paths) == 1 else 0


def cmd_validate(argv):
    paths = _paths(argv[2:])
    npass = nfail = nrefused = 0
    for p in paths:
        try:
            a = UnityArchive(p)
        except ArchiveError as e:
            nrefused += 1
            print('REFUSED  %s' % e)
            continue
        rows = a.checks()
        ok = all(r[1] for r in rows)
        if len(paths) <= 8:
            print(os.path.basename(p))
            for name, good, detail in rows:
                print('  %-46s %-4s %s' % (name, 'ok' if good else 'FAIL',
                                           detail))
        elif not ok:
            print('FAIL %s' % p)
            for name, good, detail in rows:
                if not good:
                    print('  %-46s FAIL %s' % (name, detail))
        npass += ok
        nfail += not ok
        a.close()
    print('\n%d archives: %d pass, %d fail, %d refused'
          % (len(paths), npass, nfail, nrefused))
    return 1 if (nfail or (nrefused and len(paths) == 1)) else 0


def cmd_nodes(argv):
    a = UnityArchive(argv[2])
    print('%s\n%d nodes over %d decompressed bytes'
          % (argv[2], len(a.nodes), a.total_uncompressed))
    for n in a.nodes:
        print('  %12d %12d  flags=%d  %s' % (n.offset, n.size, n.flags,
                                             n.path))
    a.close()
    return 0


def cmd_blocks(argv):
    a = UnityArchive(argv[2])
    limit = 40
    if '--limit' in argv:
        limit = int(argv[argv.index('--limit') + 1])
    print('%s\n%d blocks, %d compressed, %d uncompressed'
          % (argv[2], len(a.blocks), a.total_compressed, a.total_uncompressed))
    counts = {}
    for b in a.blocks:
        counts[b.method] = counts.get(b.method, 0) + 1
    print('methods: %s' % ', '.join('%s=%d' % kv
                                    for kv in sorted(counts.items())))
    for i, b in enumerate(a.blocks[:limit]):
        print('  %5d  u=%9d c=%9d  flags=0x%04X  %s'
              % (i, b.usize, b.csize, b.flags, b.method))
    if len(a.blocks) > limit:
        print('  ... %d more' % (len(a.blocks) - limit))
    a.close()
    return 0


def cmd_extract(argv):
    a = UnityArchive(argv[2])
    outdir = argv[3]
    os.makedirs(outdir, exist_ok=True)
    total = 0
    for n in a.nodes:
        safe = n.path.replace('\\', '_').replace('/', '_')
        dest = os.path.join(outdir, safe)
        data = a.node_bytes(n)
        if len(data) != n.size:
            raise ArchiveError('node %s: got %d of %d'
                               % (n.path, len(data), n.size))
        with open(dest, 'wb') as f:
            f.write(data)
        total += len(data)
        print('  %12d  %s' % (len(data), safe))
    print('%d nodes, %d bytes' % (len(a.nodes), total))
    a.close()
    return 0


def cmd_flags(argv):
    """Per-block compression across a whole tree.  This is the measurement the
    accounting question turns on: whether the bundles on disc are stored
    compressed or not."""
    paths = _paths(argv[2:])
    counts = {}
    ubytes = {}
    cbytes = {}
    nblocks = 0
    narch = 0
    refused = 0
    tot_u = tot_c = 0
    for p in paths:
        try:
            a = UnityArchive(p)
        except ArchiveError as e:
            refused += 1
            print('REFUSED  %s' % e)
            continue
        narch += 1
        for b in a.blocks:
            m = b.method
            counts[m] = counts.get(m, 0) + 1
            ubytes[m] = ubytes.get(m, 0) + b.usize
            cbytes[m] = cbytes.get(m, 0) + b.csize
            nblocks += 1
            tot_u += b.usize
            tot_c += b.csize
        a.close()
    print('%d archives read, %d refused, %d blocks' % (narch, refused,
                                                       nblocks))
    print('%-10s %10s %6s %16s %16s %7s' % ('method', 'blocks', 'share',
                                            'uncompressed', 'compressed',
                                            'ratio'))
    for m in sorted(counts):
        u, c = ubytes[m], cbytes[m]
        print('%-10s %10d %5.2f%% %16d %16d %7s'
              % (m, counts[m], 100.0 * counts[m] / nblocks, u, c,
                 '%.4f' % (u / c) if c else '-'))
    print('%-10s %10d %5.2f%% %16d %16d %7s'
          % ('TOTAL', nblocks, 100.0, tot_u, tot_c,
             '%.4f' % (tot_u / tot_c) if tot_c else '-'))
    return 0


def cmd_census(argv):
    """Every object of every bundle, by class.  Three levels down, and it
    prints the count at each level so that a reader which failed to descend
    says zero rather than ok."""
    paths = _paths(argv[2:])
    out = None
    if '--out' in argv:
        out = open(argv[argv.index('--out') + 1], 'w', encoding='utf-8')

    by_class_n = {}
    by_class_b = {}
    narch = nnodes = nsf = nobj = 0
    ncand = nbad = nsize_ok = nsize_bad = 0
    badmsg = []
    refused = []
    node_ext = {}
    for p in paths:
        try:
            a = UnityArchive(p)
        except ArchiveError as e:
            refused.append(str(e))
            continue
        narch += 1
        for n in a.nodes:
            nnodes += 1
            ext = os.path.splitext(n.path)[1].lower() or '(none)'
            node_ext[ext] = node_ext.get(ext, 0) + 1
            # Which nodes hold a SerializedFile is stated by the node's own
            # flags bit 2, not by its filename.  Filtering on the extension
            # instead skips every `CAB-*.sharedAssets` node -- which is most of
            # them -- and a census that skips them does not print zero, it
            # prints a smaller number that looks like an answer.  The counts
            # by extension above are printed so that the reader can see which
            # nodes were considered and which were not.
            if not (n.flags & 4):
                continue
            ncand += 1
            try:
                data = a.node_bytes(n)
                sf = unityfs.SerializedFile(data, n.path)
            except Exception as e:
                nbad += 1
                if len(badmsg) < 10:
                    badmsg.append('%s :: %s :: %s: %s'
                                  % (os.path.basename(p), n.path,
                                     type(e).__name__, e))
                continue
            nsf += 1
            if sf.file_size != n.size:
                nsize_bad += 1
            else:
                nsize_ok += 1
            for o in sf.objects:
                cid = sf.class_of(o)
                by_class_n[cid] = by_class_n.get(cid, 0) + 1
                by_class_b[cid] = by_class_b.get(cid, 0) + o['size']
                nobj += 1
                if out:
                    out.write('%s\t%s\t%d\t%d\t%d\n'
                              % (os.path.basename(p), n.path, o['path_id'],
                                 cid, o['size']))
        a.close()
    if out:
        out.close()
    print('archives read      %d' % narch)
    print('archives refused   %d' % len(refused))
    print('nodes              %d' % nnodes)
    print('  by extension     %s'
          % ', '.join('%s=%d' % kv for kv in sorted(node_ext.items())))
    print('nodes flagged 4    %d   (SerializedFile candidates)' % ncand)
    print('serialized files   %d' % nsf)
    print('  refused to parse %d' % nbad)
    print('  fileSize agrees  %d of %d, disagrees %d'
          % (nsize_ok, nsf, nsize_bad))
    print('objects            %d' % nobj)
    for m in badmsg:
        print('  PARSE FAIL %s' % m)
    print()
    print('%-10s %-30s %10s %16s %8s' % ('class', 'name', 'objects', 'bytes',
                                         'share'))
    tot = sum(by_class_b.values()) or 1
    for cid in sorted(by_class_b, key=lambda c: -by_class_b[c]):
        print('%-10d %-30s %10d %16d %7.4f%%'
              % (cid, unityfs.CLASS.get(cid, '?'), by_class_n[cid],
                 by_class_b[cid], 100.0 * by_class_b[cid] / tot))
    print('%-10s %-30s %10d %16d %7.4f%%' % ('TOTAL', '', nobj, tot, 100.0))
    for r in refused[:10]:
        print('REFUSED  %s' % r)
    return 0


def _archive(compression=0, flags_extra=0x240, blocks=None, nodes=None,
             size=None, bad_bi_len=None, fmt=8):
    """Build a UnityFS archive in memory. selftest only.

    Written on pc-themurderofsonicthehedgehog-doc, because this reader had six
    checks and no selftest -- so every one of the six had only ever been fired
    by real files, and a check that has never been shown to FAIL is a check
    nobody has tested.
    """
    import lzma  # noqa: F401  (kept beside the module's own import path)
    blocks = blocks if blocks is not None else [b'hello world' * 16]
    payload = b''.join(blocks)
    nodes = nodes if nodes is not None else [(0, len(payload), 4, 'CAB-test')]
    bi = bytearray(b'\x00' * 16)
    bi += struct.pack('>i', len(blocks))
    for b in blocks:
        bi += struct.pack('>IIH', len(b), len(b), 0)      # stored blocks
    bi += struct.pack('>i', len(nodes))
    for off, sz, fl, path in nodes:
        bi += struct.pack('>qqI', off, sz, fl) + path.encode() + b'\0'
    bi = bytes(bi)
    head = bytearray(MAGIC)
    head += struct.pack('>I', fmt)
    head += b'5.x.x\0' + b'2021.3.9f1\0'
    ui = bad_bi_len if bad_bi_len is not None else len(bi)
    tail = struct.pack('>III', len(bi), ui, compression | flags_extra)
    pad1 = (-(len(head) + 8 + len(tail))) % 16
    body_off = len(head) + 8 + len(tail) + pad1 + len(bi)
    pad2 = (-body_off) % 16 if flags_extra & 0x200 else 0
    total = body_off + pad2 + len(payload)
    out = bytes(head) + struct.pack('>Q', size if size is not None else total)
    out += tail + b'\0' * pad1 + bi + b'\0' * pad2 + payload
    return out


def cmd_selftest(argv):
    """Specimens built in memory. Most of them must be refused, and the two
    that must be ACCEPTED are there because a reader that refuses everything
    passes a refusal-only selftest."""
    cases = []

    def case(label, blob, want_ok, want=None):
        cases.append((label, blob, want_ok, want))

    case('a well-formed archive, pad-at-start set', _archive(), True)
    case('a well-formed archive, pad-at-start clear',
         _archive(flags_extra=0x40), True)

    case('an empty file', b'', False, 'magic')
    case('a PE executable', b'MZ\x90\x00' + b'\0' * 400, False, 'magic')
    case('UnityFS but format version 6', _archive(fmt=6), False,
         'format version 6')
    case('the size field disagrees with the file length',
         _archive(size=999999), False, None)
    case('blocks-info declares a length it does not decode to',
         _archive(bad_bi_len=4096), False, 'blocks-info')
    case('a compression method this reader does not know',
         _archive(compression=7), False, 'compression 7')
    case('the header says LZ4HC and the blocks-info is not LZ4',
         _archive(compression=3), False, 'lz4')
    case('a node that runs past the decompressed stream',
         _archive(nodes=[(0, 1 << 30, 4, 'CAB-test')]), False, None)
    case('the blocks-info is truncated inside the file',
         _archive()[:60], False, None)

    npass = nfail = 0
    for label, blob, want_ok, want in cases:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '_selftest.tmp')
        open(p, 'wb').write(blob)
        try:
            a = UnityArchive(p)
            checks = a.checks()
            a._block(0)
            got_ok = all(g for _, g, _ in checks)
            msg = ('%d of %d checks pass'
                   % (sum(1 for _, g, _ in checks if g), len(checks)))
            a.close()
        except Exception as e:
            got_ok, msg = False, '%s: %s' % (type(e).__name__, e)
        finally:
            os.unlink(p)
        ok = (got_ok == want_ok) and (want is None or want in msg or want_ok)
        npass += ok
        nfail += not ok
        print('  %-4s %-52s %s' % ('ok' if ok else 'FAIL', label, msg[:56]))
    print()
    rej = sum(1 for c in cases if not c[2])
    print('%d cases: %d pass, %d fail. %d of %d are rejections.'
          % (len(cases), npass, nfail, rej, len(cases)))
    return 0 if nfail == 0 else 1


CMDS = dict(header=cmd_header, validate=cmd_validate, nodes=cmd_nodes,
            blocks=cmd_blocks, extract=cmd_extract, census=cmd_census,
            flags=cmd_flags, selftest=cmd_selftest)


def main(argv):
    if argv[1:2] == ['selftest']:
        return cmd_selftest(argv)
    if len(argv) < 3 or argv[1] not in CMDS:
        print(__doc__)
        return 2
    return CMDS[argv[1]](argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
