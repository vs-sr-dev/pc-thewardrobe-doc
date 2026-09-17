#!/usr/bin/env python3
"""
apkinfo.py - read an APK without the Android SDK.

Decodes binary AndroidManifest.xml and any other compiled XML resource, reads
the string pool out of resources.arsc, lists the classes in classes.dex, and
summarises what the archive is made of. Written for the Tales of Crestoria APK
but nothing here is specific to it.

Standalone Python 3, no dependencies -- no aapt, apktool or jadx required.
"""
import argparse, os, re, struct, zipfile
from collections import Counter

# ---------------------------------------------------------------- string pools

def _len8(buf, p):
    n = buf[p]; p += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | buf[p]; p += 1
    return n, p


def _len16(buf, p):
    n = struct.unpack_from('<H', buf, p)[0]; p += 2
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', buf, p)[0]; p += 2
    return n, p


def string_pool(buf, off):
    """Decode a RES_STRING_POOL_TYPE chunk; return (strings, offset_after)."""
    _typ, _hsz, size = struct.unpack_from('<HHI', buf, off)
    count, _styles, flags, start, _stystart = struct.unpack_from('<IIIII', buf, off + 8)
    utf8 = bool(flags & (1 << 8))
    offs = struct.unpack_from('<%dI' % count, buf, off + 28)
    base = off + start
    out = []
    for o in offs:
        p = base + o
        if utf8:
            _chars, p = _len8(buf, p)
            nbytes, p = _len8(buf, p)
            out.append(buf[p:p + nbytes].decode('utf-8', 'replace'))
        else:
            n, p = _len16(buf, p)
            out.append(buf[p:p + n * 2].decode('utf-16-le', 'replace'))
    return out, off + size


# -------------------------------------------------------------------- axml

_TYPE_NULL, _TYPE_REFERENCE, _TYPE_ATTRIBUTE, _TYPE_STRING = 0, 1, 2, 3
_TYPE_FLOAT, _TYPE_INT_DEC, _TYPE_INT_HEX, _TYPE_INT_BOOL = 4, 16, 17, 18


def _value(strings, typ, data):
    if typ == _TYPE_STRING:
        return strings[data] if data < len(strings) else '?'
    if typ in (_TYPE_REFERENCE, _TYPE_ATTRIBUTE):
        return '@%08x' % data
    if typ == _TYPE_INT_BOOL:
        return 'true' if data else 'false'
    if typ == _TYPE_FLOAT:
        return str(struct.unpack('<f', struct.pack('<I', data & 0xFFFFFFFF))[0])
    if typ == _TYPE_INT_HEX:
        return '0x%08x' % (data & 0xFFFFFFFF)
    if typ == _TYPE_INT_DEC:
        return str(struct.unpack('<i', struct.pack('<I', data & 0xFFFFFFFF))[0])
    return '%d(type%d)' % (data, typ)


def axml_to_text(buf):
    """Render a compiled Android XML resource as indented text."""
    strings, p = string_pool(buf, 8)
    resids, lines, ns, depth = [], [], {}, 0
    while p + 8 <= len(buf):
        ctyp, chsz, csz = struct.unpack_from('<HHI', buf, p)
        if csz == 0:
            break
        if ctyp == 0x0180:                                   # resource map
            resids = list(struct.unpack_from('<%dI' % ((csz - chsz) // 4), buf, p + chsz))
        elif ctyp == 0x0100:                                 # start namespace
            prefix, uri = struct.unpack_from('<II', buf, p + 16)
            ns[strings[uri]] = strings[prefix]
        elif ctyp == 0x0102:                                 # start element
            _nsi, name = struct.unpack_from('<ii', buf, p + 16)
            astart, asize, acount = struct.unpack_from('<HHH', buf, p + 24)
            parts = ['<' + strings[name]]
            ap = p + 16 + astart
            for i in range(acount):
                ansi, an, araw, atyp, adata = struct.unpack_from('<iiiIi', buf, ap + i * asize)
                atyp >>= 24
                nm = strings[an] or ('attr_0x%08x' % resids[an] if an < len(resids) else '?')
                pfx = (ns.get(strings[ansi], 'ns') + ':') if ansi >= 0 else ''
                v = strings[araw] if (araw >= 0 and atyp == _TYPE_STRING) else _value(strings, atyp, adata)
                parts.append('%s%s="%s"' % (pfx, nm, v))
            lines.append('  ' * depth + ' '.join(parts) + '>')
            depth += 1
        elif ctyp == 0x0103:                                 # end element
            depth -= 1
            _nsi, name = struct.unpack_from('<ii', buf, p + 16)
            lines.append('  ' * depth + '</' + strings[name] + '>')
        p += csz
    return '\n'.join(lines)


# --------------------------------------------------------------------- dex

class Dex:
    def __init__(self, data):
        self.d = data
        if data[:4] != b'dex\n':
            raise ValueError('not a dex file')
        h = struct.unpack_from('<20I', data, 32)
        (self.file_size, self.header_size, self.endian, self.link_size, self.link_off,
         self.map_off, self.string_ids_size, self.string_ids_off, self.type_ids_size,
         self.type_ids_off, self.proto_ids_size, self.proto_ids_off, self.field_ids_size,
         self.field_ids_off, self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off, self.data_size, self.data_off) = h
        self.version = data[4:7].decode()

    def _uleb(self, p):
        r = s = 0
        while True:
            b = self.d[p]; p += 1
            r |= (b & 0x7F) << s; s += 7
            if not b & 0x80:
                return r, p

    def string(self, idx):
        off = struct.unpack_from('<I', self.d, self.string_ids_off + idx * 4)[0]
        _n, p = self._uleb(off)
        return self.d[p:self.d.find(b'\0', p)].decode('utf-8', 'replace')

    def type_name(self, idx):
        return self.string(struct.unpack_from('<I', self.d, self.type_ids_off + idx * 4)[0])

    def classes(self):
        for i in range(self.class_defs_size):
            cid, _flags, sup, _ifo, _srcf, _anno, _cd, _sv = struct.unpack_from(
                '<8I', self.d, self.class_defs_off + i * 32)
            yield (self.type_name(cid),
                   self.type_name(sup) if sup != 0xFFFFFFFF else None)


def _java(desc):
    return desc[1:-1].replace('/', '.') if desc and desc.startswith('L') else desc


# ------------------------------------------------------------------ commands

def _open(path, member=None):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            return z.read(member)
    return open(path, 'rb').read()


def cmd_manifest(args):
    print(axml_to_text(_open(args.apk, 'AndroidManifest.xml')))


def cmd_xml(args):
    print(axml_to_text(_open(args.apk, args.member)))



# Strings that a shipped package embeds and a repository should not.  These are
# not secrets in the usual sense -- a Firebase Android API key is designed to be
# compiled into the client, it identifies a project rather than authorising
# anything, and access is gated by the package name and signing certificate --
# but they are credential-shaped, they trip automated scanning, and this
# repository's own scope says it contains no data extracted from the game.  So
# the tool redacts them and prints the shape rather than the value.  What is
# analytically interesting about them -- that this package carries *two*
# different Firebase projects with two different project numbers -- survives
# redaction intact.
REDACT = [
    (re.compile(r'AIza[0-9A-Za-z_\-]{35}'), 'AIzaSy[REDACTED, 39 chars]'),
    (re.compile(r'\b\d{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com'),
     '[REDACTED].apps.googleusercontent.com'),
    (re.compile(r'\bghp_[0-9A-Za-z]{36}\b'), 'ghp_[REDACTED]'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
     '-----BEGIN [REDACTED] PRIVATE KEY-----'),
]


def redact(s):
    for pat, rep in REDACT:
        s = pat.sub(rep, s)
    return s


def cmd_strings(args):
    data = _open(args.apk, 'resources.arsc')
    pool, _ = string_pool(data, 12)
    n = 0
    for s in dict.fromkeys(pool):
        if args.grep and args.grep.lower() not in s.lower():
            continue
        t = redact(s)
        if t != s:
            n += 1
        print(t)
    if n:
        print()
        print('# %d string(s) redacted: credential-shaped, see REDACT in this'
              ' file' % n)


def cmd_resolve(args):
    """Resolve a resource id -- `@7f0f000a` -- to the string it names.

    Added for android-dissidiaduellum-doc.  That package's `android:label` is a
    reference and not a literal, so the application's own name is two parses
    away from the manifest and not one: AndroidManifest.xml gives the id, and
    only `resources.arsc` turns the id into a word.  Grepping the string pool
    for a plausible answer is not the same thing, because the pool holds every
    string in the package and finding one that looks right proves nothing about
    which id points at it.

    A resource id is packed as 0xPPTTEEEE: package, type, entry.  The table is
    a chunk tree -- RES_TABLE(0x0002) holding a global value pool and
    RES_TABLE_PACKAGE(0x0200) chunks, each with a type-name pool, a key-name
    pool, and RES_TABLE_TYPE(0x0201) chunks carrying one entry array per
    configuration.  This walks it for the requested id and prints every
    configuration that defines it, which is how a per-language label would show
    up as several rows rather than as one.
    """
    data = _open(args.apk, 'resources.arsc')
    want = int(args.id.lstrip('@#'), 16)
    pkg_id, type_id, entry_id = (want >> 24) & 0xFF, (want >> 16) & 0xFF, \
        want & 0xFFFF
    gpool, _ = string_pool(data, 12)
    _t, hsz, _sz = struct.unpack_from('<HHI', data, 0)
    pkgcount = struct.unpack_from('<I', data, 8)[0]
    p = 12
    _sp, p = string_pool(data, p)
    found = 0
    print('resource 0x%08X = package 0x%02X, type 0x%02X, entry 0x%04X'
          % (want, pkg_id, type_id, entry_id))
    for _ in range(pkgcount):
        ptyp, phsz, psz = struct.unpack_from('<HHI', data, p)
        if ptyp != 0x0200:
            break
        pid = struct.unpack_from('<I', data, p + 8)[0]
        name = data[p + 12:p + 12 + 256].decode('utf-16-le').split('\0')[0]
        # ResTable_package: id at +8, a 256-byte UTF-16 name at +12, then
        # typeStrings, lastPublicType, keyStrings, lastPublicKey.  keyStrings
        # is at +276 and not at +272; reading lastPublicType as the key pool
        # offset sends the pool reader off the end of the file, loudly.
        toff = struct.unpack_from('<I', data, p + 268)[0]
        koff = struct.unpack_from('<I', data, p + 276)[0]
        typepool, _ = string_pool(data, p + toff)
        keypool, _ = string_pool(data, p + koff)
        print('  package 0x%02X %r, %d type names, %d key names'
              % (pid, name, len(typepool), len(keypool)))
        if pid == pkg_id:
            q = p + koff
            _kt, _kh, ksz = struct.unpack_from('<HHI', data, q)
            q += ksz
            while q < p + psz:
                ct, chsz, csz = struct.unpack_from('<HHI', data, q)
                if csz <= 0:
                    break
                if ct == 0x0201:
                    tid = data[q + 8]
                    tflags = data[q + 9]
                    count = struct.unpack_from('<I', data, q + 12)[0]
                    entstart = struct.unpack_from('<I', data, q + 16)[0]
                    # The offset array begins at the chunk's own headerSize,
                    # not at a fixed +20: a ResTable_config of variable length
                    # sits between. Indexing at +20 reads the config as
                    # offsets and resolves every entry to a different, wrong
                    # key -- which is exactly what it did until the same entry
                    # id came back with three different names.
                    abase = q + chsz
                    off = None
                    if tflags & 0x01:            # sparse: (u16 idx, u16 off/4)
                        for i in range(count):
                            idx, o = struct.unpack_from('<HH', data,
                                                        abase + i * 4)
                            if idx == entry_id:
                                off = o * 4
                                break
                    elif tflags & 0x02:          # offset16
                        if entry_id < count:
                            o = struct.unpack_from('<H', data,
                                                   abase + entry_id * 2)[0]
                            off = None if o == 0xFFFF else o * 4
                    elif entry_id < count:
                        o = struct.unpack_from('<I', data,
                                               abase + entry_id * 4)[0]
                        off = None if o == 0xFFFFFFFF else o
                    if tid == type_id and off is not None:
                        found += _print_entry(data, q + entstart + off,
                                              gpool, keypool, typepool,
                                              tid)
                q += csz
        p += psz
    if not found:
        print('  NOT FOUND: no configuration defines that entry')
        return 1
    print('  %d configuration(s) define it' % found)
    return 0


def _print_entry(data, e, gpool, keypool, typepool, tid):
    esz, eflags, ekey = struct.unpack_from('<HHI', data, e)
    key = keypool[ekey] if ekey < len(keypool) else '?'
    tname = typepool[tid - 1] if 0 < tid <= len(typepool) else '?'
    if eflags & 0x0001:          # complex/bag, not a plain value
        print('    %s/%s = <bag>' % (tname, key))
        return 1
    vsz, _r, vtype, vdata = struct.unpack_from('<HBBI', data, e + esz)
    if vtype == _TYPE_STRING:
        val = gpool[vdata] if vdata < len(gpool) else '?'
        safe = redact(val).encode('unicode_escape').decode('ascii')
        print("    %s/%s = '%s'" % (tname, key, safe))
    else:
        print('    %s/%s = type %d, 0x%08X' % (tname, key, vtype, vdata))
    return 1


def cmd_classes(args):
    dx = Dex(_open(args.apk, args.dex))
    print('dex %s: %d strings, %d types, %d methods, %d classes'
          % (dx.version, dx.string_ids_size, dx.type_ids_size,
             dx.method_ids_size, dx.class_defs_size))
    if args.packages:
        pkgs = Counter()
        for name, _sup in dx.classes():
            pkgs['.'.join(_java(name).split('.')[:3])] += 1
        for k, v in pkgs.most_common(args.top):
            print('%6d  %s' % (v, k))
        return
    for name, sup in dx.classes():
        n = _java(name)
        if args.prefix and not n.startswith(args.prefix):
            continue
        print('%-64s : %s' % (n, _java(sup) or ''))


def cmd_contents(args):
    with zipfile.ZipFile(args.apk) as z:
        infos = z.infolist()
    raw = Counter(); packed = Counter(); files = Counter()
    for i in infos:
        top = i.filename.split('/')[0] if '/' in i.filename else i.filename
        raw[top] += i.file_size; packed[top] += i.compress_size; files[top] += 1
    print('%-30s %6s %14s %14s %7s' % ('entry', 'files', 'uncompressed', 'in APK', 'ratio'))
    for k in sorted(raw, key=lambda x: -packed[x]):
        print('%-30s %6d %14d %14d %6.1f%%'
              % (k, files[k], raw[k], packed[k], 100 * packed[k] / raw[k] if raw[k] else 0))
    print('%-30s %6d %14d %14d' % ('TOTAL', sum(files.values()),
                                   sum(raw.values()), sum(packed.values())))
    print('file on disk: %d bytes' % os.path.getsize(args.apk))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('apk', help='path to the APK (or to a bare .xml/.arsc/.dex)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('manifest', help='decode AndroidManifest.xml').set_defaults(fn=cmd_manifest)
    sub.add_parser('contents', help='summarise the archive').set_defaults(fn=cmd_contents)
    p = sub.add_parser('xml', help='decode any compiled XML resource')
    p.add_argument('member')
    p.set_defaults(fn=cmd_xml)
    p = sub.add_parser('strings', help='dump the resources.arsc string pool')
    p.add_argument('--grep')
    p.set_defaults(fn=cmd_strings)
    p = sub.add_parser('resolve', help='resolve a resource id to its value')
    p.add_argument('id', help='hex id, e.g. 7f0f000a or @7f0f000a')
    p.set_defaults(fn=cmd_resolve)
    p = sub.add_parser('classes', help='list dex classes')
    p.add_argument('--dex', default='classes.dex')
    p.add_argument('--prefix')
    p.add_argument('--packages', action='store_true')
    p.add_argument('--top', type=int, default=40)
    p.set_defaults(fn=cmd_classes)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
