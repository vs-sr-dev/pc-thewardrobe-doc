#!/usr/bin/env python3
"""Deserialise Unity objects using the type tree the file carries.

`unityfs.py` finds objects and names their classes; it reads names by knowing
where each class puts `m_Name`, which is a hand-written table and stops at the
classes somebody wrote an entry for.  DISSIDIA's bundles ship the **type tree**
-- typeTreePresent is 1 on all 816 SerializedFiles inside the 729 archives --
and a type tree is a description of every field of every class in the file.
With it, an object can be read without knowing anything about the class in
advance, and a field can be named rather than guessed at.

That matters twice on this object:

  * **the byte census is wrong without it.**  A Texture2D's serialized body is
    a header; its pixels live in a `.resS` node and the body only says where.
    Same for AudioClip and its `.resource`.  Counting object bodies gives
    Texture2D 0.47 % of this object, which is not a measurement of anything;
  * **the thesis column needs the stream data**, because "moving picture and
    recorded sound" is exactly the bytes that are not in the object bodies.

How a type tree is read: the nodes are a flat array carrying a level, so the
tree is rebuilt by depth.  Leaves are primitives named by their type string;
`vector`, `set` and `staticvector` wrap an `Array` whose first child is the
count and whose second is the element; `string` is an array of `char`;
`TypelessData` is a count followed by that many raw bytes.  A node whose
metaFlag has 0x4000 aligns the stream to four bytes after it is read.

The control: the reader is handed the object's declared byte range, and after
reading it must have consumed a length consistent with it.  `check` reports,
per class, how many objects were read to exactly their declared size -- a
generic reader that has the format wrong does not fail quietly, it lands in the
wrong place and the count says so.

    python unityasset.py dump    BUNDLE PATHID
    python unityasset.py textures DIR [--out FILE]  -- every Texture2D, with
                                                       format, size and stream
    python unityasset.py audio    DIR [--out FILE]  -- every AudioClip
    python unityasset.py video    DIR [--out FILE]  -- every VideoClip
    python unityasset.py streams  DIR               -- who owns the .resS and
                                                       .resource bytes
    python unityasset.py check    DIR [--limit N]   -- read-to-declared-size

Standard library only.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unityarc
import unityfs

PRIM = {
    'SInt8': ('b', 1), 'UInt8': ('B', 1), 'char': ('B', 1), 'bool': ('?', 1),
    'SInt16': ('h', 2), 'UInt16': ('H', 2), 'short': ('h', 2),
    'unsigned short': ('H', 2),
    'SInt32': ('i', 4), 'int': ('i', 4), 'UInt32': ('I', 4),
    'unsigned int': ('I', 4), 'Type*': ('I', 4),
    'SInt64': ('q', 8), 'long long': ('q', 8), 'UInt64': ('Q', 8),
    'unsigned long long': ('Q', 8), 'FileSize': ('Q', 8),
    'float': ('f', 4), 'double': ('d', 8),
}


class TreeReader(object):
    def __init__(self, data, little=True):
        self.d = data
        self.p = 0
        self.e = '<' if little else '>'

    def prim(self, kind):
        fmt, n = PRIM[kind]
        v = struct.unpack_from(self.e + fmt, self.d, self.p)[0]
        self.p += n
        return v

    def raw(self, n):
        v = self.d[self.p:self.p + n]
        if len(v) != n:
            raise ValueError('ran off the object body wanting %d bytes' % n)
        self.p += n
        return v

    def align(self, n=4):
        self.p = (self.p + n - 1) & ~(n - 1)


def build(nodes):
    """Flat level-tagged array -> nested. Returns the root node with
    'children' filled in."""
    root = dict(nodes[0])
    root['children'] = []
    stack = [root]
    for nd in nodes[1:]:
        n = dict(nd)
        n['children'] = []
        while len(stack) > n['level']:
            stack.pop()
        if not stack:
            raise ValueError('type tree level %d with no parent' % n['level'])
        stack[-1]['children'].append(n)
        stack.append(n)
    return root


def read_value(r, node):
    t = node['type']
    if t in PRIM and not node['children']:
        v = r.prim(t)
        if node['meta'] & 0x4000:
            r.align()
        return v
    if t == 'string':
        arr = node['children'][0]
        n = r.prim('int')
        v = r.raw(n)
        if arr['meta'] & 0x4000 or node['meta'] & 0x4000:
            r.align()
        return v.decode('utf-8', 'replace')
    if t == 'TypelessData':
        n = r.prim('int')
        v = r.raw(n)
        if node['meta'] & 0x4000:
            r.align()
        return v
    if node['children'] and node['children'][0]['type'] == 'Array':
        arr = node['children'][0]
        v = read_array(r, arr)
        if node['meta'] & 0x4000:
            r.align()
        return v
    if t == 'Array':
        return read_array(r, node)
    out = {}
    for c in node['children']:
        out[c['name']] = read_value(r, c)
    if node['meta'] & 0x4000:
        r.align()
    return out


def read_array(r, node):
    size_node, elem = node['children'][0], node['children'][1]
    n = r.prim(size_node['type'] if size_node['type'] in PRIM else 'int')
    if n < 0 or n > 1 << 28:
        raise ValueError('array count %d is not credible' % n)
    if elem['type'] in PRIM and not elem['children'] and \
            PRIM[elem['type']][1] == 1:
        v = r.raw(n)
    else:
        v = [read_value(r, elem) for _ in range(n)]
    if node['meta'] & 0x4000:
        r.align()
    return v


class Bundle(object):
    """One UnityFS archive, with its SerializedFiles parsed and its stream
    nodes indexed by the name the objects reference them under."""

    def __init__(self, path):
        self.arc = unityarc.UnityArchive(path)
        self.path = path
        self.sfs = []
        self.streams = {}
        for n in self.arc.nodes:
            if n.flags & 4:
                data = self.arc.node_bytes(n)
                sf = unityfs.SerializedFile(data, n.path)
                if sf.file_size != n.size:
                    raise ValueError('%s: node %s declares %d, file says %d'
                                     % (path, n.path, n.size, sf.file_size))
                self.sfs.append((n, sf))
            else:
                self.streams[n.path] = n

    def objects(self):
        for node, sf in self.sfs:
            for o in sf.objects:
                yield node, sf, o

    def read(self, sf, o):
        ti = o['type_index']
        if not (0 <= ti < len(sf.types)):
            raise ValueError('type index %d out of range' % ti)
        tree = sf.types[ti]['tree']
        if not tree:
            raise ValueError('no type tree for class %d' % sf.class_of(o))
        root = build(tree)
        body = sf.body(o)
        r = TreeReader(body, little=(sf.endianness == 0))
        v = read_value(r, root)
        return v, r.p, len(body)

    def stream_size(self, path):
        base = os.path.basename(path.replace('\\', '/'))
        for k, n in self.streams.items():
            if os.path.basename(k) == base:
                return n.size
        return None

    def close(self):
        self.arc.close()


def bundles_in(root):
    out = []
    if os.path.isfile(root):
        return [root]
    for dp, _, fn in os.walk(root):
        for f in fn:
            if not f.endswith('.hash'):
                out.append(os.path.join(dp, f))
    return sorted(out)


# Unity TextureFormat, the values this object actually uses plus the
# neighbours that make the table legible.  Anything not here prints as its
# number rather than as a guess.
TEXFMT = {
    1: 'Alpha8', 2: 'ARGB4444', 3: 'RGB24', 4: 'RGBA32', 5: 'ARGB32',
    7: 'RGB565', 9: 'R16', 10: 'DXT1', 12: 'DXT5', 13: 'RGBA4444',
    14: 'BGRA32', 15: 'RHalf', 16: 'RGHalf', 17: 'RGBAHalf',
    18: 'RFloat', 19: 'RGFloat', 20: 'RGBAFloat', 21: 'YUY2',
    22: 'RGB9e5Float', 24: 'BC6H', 25: 'BC7', 26: 'BC4', 27: 'BC5',
    28: 'DXT1Crunched', 29: 'DXT5Crunched',
    30: 'PVRTC_RGB2', 31: 'PVRTC_RGBA2', 32: 'PVRTC_RGB4',
    33: 'PVRTC_RGBA4', 34: 'ETC_RGB4', 41: 'EAC_R', 42: 'EAC_R_SIGNED',
    43: 'EAC_RG', 44: 'EAC_RG_SIGNED', 45: 'ETC2_RGB', 46: 'ETC2_RGBA1',
    47: 'ETC2_RGBA8',
    48: 'ASTC_4x4', 49: 'ASTC_5x5', 50: 'ASTC_6x6', 51: 'ASTC_8x8',
    52: 'ASTC_10x10', 53: 'ASTC_12x12',
    54: 'ETC_RGB4_3DS', 55: 'ETC_RGBA8_3DS',
    56: 'RG16', 57: 'R8', 58: 'ETC_RGB4Crunched', 59: 'ETC2_RGBA8Crunched',
    60: 'ASTC_HDR_4x4', 61: 'ASTC_HDR_5x5', 62: 'ASTC_HDR_6x6',
    63: 'ASTC_HDR_8x8', 64: 'ASTC_HDR_10x10', 65: 'ASTC_HDR_12x12',
    66: 'RG32', 67: 'RGB48', 68: 'RGBA64',
}

AUDIOFMT = {
    0: 'PCM', 1: 'Vorbis', 2: 'ADPCM', 3: 'MP3', 4: 'PSMVAG', 5: 'HEVAG',
    6: 'XMA', 7: 'AAC', 8: 'GCADPCM', 9: 'ATRAC9',
}


def _walk(root, want_class, fn, limit=None):
    paths = bundles_in(root)
    seen = 0
    bad = 0
    badmsg = []
    for p in paths:
        try:
            b = Bundle(p)
        except Exception as e:
            bad += 1
            if len(badmsg) < 5:
                badmsg.append('%s: %s' % (os.path.basename(p), e))
            continue
        for node, sf, o in b.objects():
            if sf.class_of(o) != want_class:
                continue
            try:
                v, used, total = b.read(sf, o)
            except Exception as e:
                bad += 1
                if len(badmsg) < 5:
                    badmsg.append('%s %s: %s' % (os.path.basename(p),
                                                 o['path_id'], e))
                continue
            seen += 1
            fn(b, node, sf, o, v, used, total)
            if limit and seen >= limit:
                b.close()
                return paths, seen, bad, badmsg
        b.close()
    return paths, seen, bad, badmsg


def cmd_textures(argv):
    root = argv[2]
    out = None
    if '--out' in argv:
        out = open(argv[argv.index('--out') + 1], 'w', encoding='utf-8')
        out.write('bundle\tname\twidth\theight\tformat\tmips\tdata\tstream\n')
    fmt_n = {}
    fmt_b = {}
    inline = streamed = 0
    dims = {}

    def each(b, node, sf, o, v, used, total):
        f = v.get('m_TextureFormat', -1)
        w, h = v.get('m_Width', 0), v.get('m_Height', 0)
        sd = v.get('m_StreamData') or {}
        size = sd.get('size') or 0
        nonlocal inline, streamed
        if size:
            streamed += size
        else:
            size = len(v.get('image data') or b'')
            inline += size
        name = fmt_n.get(f, 0)
        fmt_n[f] = name + 1
        fmt_b[f] = fmt_b.get(f, 0) + size
        dims[(w, h)] = dims.get((w, h), 0) + 1
        if out:
            out.write('%s\t%s\t%d\t%d\t%s\t%s\t%d\t%s\n'
                      % (os.path.basename(b.path), v.get('m_Name', ''), w, h,
                         TEXFMT.get(f, f), v.get('m_MipCount', ''), size,
                         sd.get('path', '')))

    paths, seen, bad, badmsg = _walk(root, 28, each)
    if out:
        out.close()
    tot = sum(fmt_b.values()) or 1
    print('bundles %d, Texture2D read %d, failures %d' % (len(paths), seen,
                                                          bad))
    print('pixel bytes inline %d, streamed %d, total %d'
          % (inline, streamed, inline + streamed))
    print()
    print('%-22s %8s %16s %8s' % ('format', 'count', 'bytes', 'share'))
    for f in sorted(fmt_b, key=lambda x: -fmt_b[x]):
        print('%-22s %8d %16d %7.3f%%'
              % (TEXFMT.get(f, str(f)), fmt_n[f], fmt_b[f],
                 100.0 * fmt_b[f] / tot))
    print()
    print('most common dimensions:')
    for d in sorted(dims, key=lambda x: -dims[x])[:12]:
        print('   %5d x %-5d %6d' % (d[0], d[1], dims[d]))
    for m in badmsg:
        print('FAIL %s' % m)
    return 0


def cmd_audio(argv):
    root = argv[2]
    out = None
    if '--out' in argv:
        out = open(argv[argv.index('--out') + 1], 'w', encoding='utf-8')
        out.write('bundle\tname\tformat\tchannels\trate\tbits\tlength\t'
                  'bytes\tstream\n')
    fmt_n = {}
    fmt_b = {}
    seconds = 0.0
    rates = {}

    def each(b, node, sf, o, v, used, total):
        f = v.get('m_CompressionFormat', -1)
        res = v.get('m_Resource') or {}
        size = res.get('m_Size') or 0
        fmt_n[f] = fmt_n.get(f, 0) + 1
        fmt_b[f] = fmt_b.get(f, 0) + size
        nonlocal seconds
        seconds += float(v.get('m_Length') or 0.0)
        rates[v.get('m_Frequency')] = rates.get(v.get('m_Frequency'), 0) + 1
        if out:
            out.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n'
                      % (os.path.basename(b.path), v.get('m_Name', ''),
                         AUDIOFMT.get(f, f), v.get('m_Channels'),
                         v.get('m_Frequency'), v.get('m_BitsPerSample'),
                         v.get('m_Length'), size, res.get('m_Source', '')))

    paths, seen, bad, badmsg = _walk(root, 83, each)
    if out:
        out.close()
    tot = sum(fmt_b.values()) or 1
    print('bundles %d, AudioClip read %d, failures %d' % (len(paths), seen,
                                                          bad))
    print('sample bytes %d, total declared length %.1f s = %.2f h'
          % (tot, seconds, seconds / 3600.0))
    print()
    print('%-14s %8s %16s %8s' % ('format', 'count', 'bytes', 'share'))
    for f in sorted(fmt_b, key=lambda x: -fmt_b[x]):
        print('%-14s %8d %16d %7.3f%%'
              % (AUDIOFMT.get(f, str(f)), fmt_n[f], fmt_b[f],
                 100.0 * fmt_b[f] / tot))
    print('sample rates: %s' % ', '.join('%s=%d' % kv
                                         for kv in sorted(rates.items(),
                                                          key=lambda x: -x[1])))
    for m in badmsg:
        print('FAIL %s' % m)
    return 0


def cmd_video(argv):
    root = argv[2]
    rows = []

    def each(b, node, sf, o, v, used, total):
        res = v.get('m_ExternalResources') or {}
        rows.append((os.path.basename(b.path), v.get('m_Name', ''),
                     v.get('Width'), v.get('Height'),
                     v.get('m_FrameRate'), v.get('m_FrameCount'),
                     res.get('m_Size') or 0, res.get('m_Source', '')))

    paths, seen, bad, badmsg = _walk(root, 329, each)
    print('bundles %d, VideoClip read %d, failures %d' % (len(paths), seen,
                                                          bad))
    tot = sum(r[6] for r in rows)
    print('video bytes %d' % tot)
    print('%-34s %-24s %6s %6s %8s %8s %12s'
          % ('bundle', 'name', 'w', 'h', 'fps', 'frames', 'bytes'))
    for r in sorted(rows, key=lambda x: -x[6]):
        print('%-34s %-24s %6s %6s %8s %8s %12d'
              % (r[0][:34], str(r[1])[:24], r[2], r[3], r[4], r[5], r[6]))
    for m in badmsg:
        print('FAIL %s' % m)
    return 0


def cmd_streams(argv):
    """Who owns the resource-stream bytes.  Every Texture2D, AudioClip and
    VideoClip that streams its payload says which node and which byte range,
    so the stream nodes can be attributed rather than assumed."""
    root = argv[2]
    paths = bundles_in(root)
    node_bytes = {}
    claimed = {'Texture2D': 0, 'AudioClip': 0, 'VideoClip': 0, 'Mesh': 0}
    nclaim = {'Texture2D': 0, 'AudioClip': 0, 'VideoClip': 0, 'Mesh': 0}
    total_stream = 0
    bad = 0
    for p in paths:
        try:
            b = Bundle(p)
        except Exception:
            bad += 1
            continue
        for k, n in b.streams.items():
            ext = os.path.splitext(k)[1].lower() or '(none)'
            node_bytes[ext] = node_bytes.get(ext, 0) + n.size
            total_stream += n.size
        for node, sf, o in b.objects():
            c = sf.class_of(o)
            if c not in (28, 83, 329, 43):
                continue
            try:
                v, _, _ = b.read(sf, o)
            except Exception:
                bad += 1
                continue
            if c == 28:
                sz = ((v.get('m_StreamData') or {}).get('size') or 0)
                claimed['Texture2D'] += sz
                nclaim['Texture2D'] += bool(sz)
            elif c == 83:
                sz = ((v.get('m_Resource') or {}).get('m_Size') or 0)
                claimed['AudioClip'] += sz
                nclaim['AudioClip'] += bool(sz)
            elif c == 329:
                sz = ((v.get('m_ExternalResources') or {}).get('m_Size') or 0)
                claimed['VideoClip'] += sz
                nclaim['VideoClip'] += bool(sz)
            else:
                si = v.get('m_StreamData') or {}
                sz = si.get('size') or 0
                claimed['Mesh'] += sz
                nclaim['Mesh'] += bool(sz)
        b.close()
    print('bundles %d, failures %d' % (len(paths), bad))
    print('stream node bytes by extension:')
    for e in sorted(node_bytes, key=lambda x: -node_bytes[x]):
        print('   %-12s %16d' % (e, node_bytes[e]))
    print('   %-12s %16d' % ('TOTAL', total_stream))
    print()
    print('claimed by class:')
    for k in sorted(claimed, key=lambda x: -claimed[x]):
        print('   %-12s %16d  %8d objects  %6.3f%% of stream'
              % (k, claimed[k], nclaim[k],
                 100.0 * claimed[k] / total_stream if total_stream else 0))
    s = sum(claimed.values())
    print('   %-12s %16d  residue %d' % ('CLAIMED', s, total_stream - s))
    return 0


def cmd_check(argv):
    root = argv[2]
    limit = 400
    if '--limit' in argv:
        limit = int(argv[argv.index('--limit') + 1])
    paths = bundles_in(root)[:limit]
    exact = short = over = fail = 0
    byclass = {}
    for p in paths:
        try:
            b = Bundle(p)
        except Exception:
            fail += 1
            continue
        for node, sf, o in b.objects():
            c = sf.class_of(o)
            try:
                v, used, total = b.read(sf, o)
            except Exception:
                fail += 1
                byclass.setdefault(c, [0, 0, 0, 0])[3] += 1
                continue
            slot = byclass.setdefault(c, [0, 0, 0, 0])
            if used == total:
                exact += 1
                slot[0] += 1
            elif used < total:
                short += 1
                slot[1] += 1
            else:
                over += 1
                slot[2] += 1
        b.close()
    tot = exact + short + over + fail
    print('bundles %d, objects %d' % (len(paths), tot))
    print('read to exactly the declared size  %d  %.4f%%'
          % (exact, 100.0 * exact / tot if tot else 0))
    print('read short                         %d' % short)
    print('read past the end                  %d' % over)
    print('refused                            %d' % fail)
    print()
    print('%-10s %-24s %8s %8s %8s %8s' % ('class', 'name', 'exact', 'short',
                                           'over', 'fail'))
    for c in sorted(byclass, key=lambda x: -sum(byclass[x])):
        s = byclass[c]
        print('%-10d %-24s %8d %8d %8d %8d'
              % (c, unityfs.CLASS.get(c, '?'), s[0], s[1], s[2], s[3]))
    return 0


def cmd_dump(argv):
    b = Bundle(argv[2])
    want = int(argv[3])
    for node, sf, o in b.objects():
        if o['path_id'] != want:
            continue
        v, used, total = b.read(sf, o)
        print('class %d (%s)  body %d bytes, read %d'
              % (sf.class_of(o), unityfs.CLASS.get(sf.class_of(o), '?'),
                 total, used))
        _pp(v, 0)
        return 0
    print('path id %d not found' % want)
    return 1


def _pp(v, ind):
    pad = '  ' * ind
    if isinstance(v, dict):
        for k, x in v.items():
            if isinstance(x, (dict, list)):
                print('%s%s:' % (pad, k))
                _pp(x, ind + 1)
            elif isinstance(x, bytes):
                print('%s%s: %d bytes %s' % (pad, k, len(x), x[:16].hex()))
            else:
                print('%s%s: %r' % (pad, k, x))
    elif isinstance(v, list):
        print('%s[%d items]' % (pad, len(v)))
        for x in v[:4]:
            _pp(x, ind + 1)
    else:
        print('%s%r' % (pad, v))


def cmd_dumpaudio(argv):
    """Write AudioClip payloads out as the FSB5 banks they are.

    An AudioClip's samples live in a `.resource` node at an offset and length
    the clip states; slicing that range gives a complete FMOD sound bank with
    its own header, which `tools/fsb5.py` reads and ordinary audio tools play.
    Nothing is transcoded and nothing is decoded: the bytes written are the
    bytes shipped.

    `--match` takes a regular expression against the clip name, so one track
    per family can be pulled without extracting 11,976 of them.
    """
    root, outdir = argv[2], argv[3]
    pat = re.compile(argv[argv.index('--match') + 1]) \
        if '--match' in argv else None
    limit = int(argv[argv.index('--limit') + 1]) if '--limit' in argv else 0
    one_per = argv[argv.index('--one-per') + 1] \
        if '--one-per' in argv else None
    os.makedirs(outdir, exist_ok=True)
    seen_groups = set()
    n = 0
    for p in bundles_in(root):
        try:
            b = Bundle(p)
        except Exception:
            continue
        for node, sf, o in b.objects():
            if sf.class_of(o) != 83:
                continue
            v, _, _ = b.read(sf, o)
            name = v.get('m_Name') or ''
            if pat and not pat.search(name):
                continue
            if one_per:
                m = re.search(one_per, name)
                if not m:
                    continue
                g = m.group(0)
                if g in seen_groups:
                    continue
                seen_groups.add(g)
            res = v.get('m_Resource') or {}
            if not res.get('m_Size'):
                continue
            src = os.path.basename(res['m_Source'].replace('\\', '/'))
            node2 = None
            for k, nn in b.streams.items():
                if os.path.basename(k) == src:
                    node2 = nn
                    break
            if node2 is None:
                print('  %s: stream %s not in this archive' % (name, src))
                continue
            data = b.arc.read(node2.offset + res['m_Offset'], res['m_Size'])
            if data[:4] != b'FSB5':
                print('  %s: payload does not open FSB5, it opens %r'
                      % (name, data[:4]))
            safe = ''.join(c if c.isalnum() or c in '._-' else '_'
                           for c in name)
            dest = os.path.join(outdir, safe + '.fsb')
            with open(dest, 'wb') as f:
                f.write(data)
            print('  %-42s %2d ch %6d Hz %8.2f s %10d B  %s'
                  % (name[:42], v.get('m_Channels'), v.get('m_Frequency'),
                     v.get('m_Length'), len(data), os.path.basename(p)))
            n += 1
            if limit and n >= limit:
                b.close()
                print('%d written' % n)
                return 0
        b.close()
    print('%d written' % n)
    return 0


import re  # noqa: E402

CMDS = dict(textures=cmd_textures, audio=cmd_audio, video=cmd_video,
            streams=cmd_streams, check=cmd_check, dump=cmd_dump,
            dumpaudio=cmd_dumpaudio)


def main(argv):
    if len(argv) < 3 or argv[1] not in CMDS:
        print(__doc__)
        return 2
    return CMDS[argv[1]](argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
