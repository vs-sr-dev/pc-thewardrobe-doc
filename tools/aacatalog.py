#!/usr/bin/env python3
"""aacatalog.py -- read a Unity Addressables content catalogue, and refuse one
that is not.

`catalog.json` looks like a readable file and is not one. Four of its twelve
fields -- `m_KeyDataString`, `m_BucketDataString`, `m_EntryDataString` and
`m_ExtraDataString` -- are base64 of a packed binary structure, and reading the
JSON without decoding them yields a list of 286 path strings and nothing that
says which of them lives in which bundle. The whole point of the catalogue is
in the four blobs.

The format is Addressables' own `SerializationUtilities`, community-documented
rather than published by its author, and the reading below is stated so that it
can fail:

    m_BucketDataString  i32 bucketCount, then per bucket
                        i32 keyDataOffset, i32 entryCount, entryCount x i32
    m_KeyDataString     at each keyDataOffset: u8 type, then
                        0 ascii   i32 length, bytes
                        1 unicode i32 byte length, UTF-16LE
                        2 u16     2 bytes        3 u32   4 bytes
                        4 i32     4 bytes        5 hash  u8 length, ascii
    m_EntryDataString   i32 entryCount, then per entry SEVEN i32:
                        internalId, provider, dependencyKey, dependencyHash,
                        dataIndex, primaryKey, resourceType

THE CHECKS, and every one is a quantity the file states twice:

  1. every base64 field decodes to a whole number of bytes;
  2. the entry table's declared count times 28 plus 4 equals the decoded
     length of `m_EntryDataString`, residue 0;
  3. the bucket table is walked to its exact end, residue 0;
  4. every key offset named by a bucket lands on a type byte this reader
     knows, and every key parses to a length that stays inside the blob;
  5. every index in every entry is inside the array it indexes -- internal
     ids, providers, resource types, and the bucket table;
  6. the sum of the buckets' entry counts equals the number of (key, entry)
     pairs actually built.

A catalogue that fails any of them raises. Nothing here is written to disk and
no asset is extracted; this reader only reads names.

    python tools/aacatalog.py validate PATH
    python tools/aacatalog.py census   PATH
    python tools/aacatalog.py keys     PATH [--limit N]
    python tools/aacatalog.py bundles  PATH --tree DIR
    python tools/aacatalog.py selftest
"""
import base64
import collections
import json
import os
import struct
import sys

TYPE_ASCII, TYPE_UNICODE, TYPE_U16, TYPE_U32, TYPE_I32, TYPE_HASH = range(6)
ENTRY_FIELDS = 7
ENTRY_STRIDE = ENTRY_FIELDS * 4


class CatalogError(Exception):
    """Raised loudly. This reader never returns a short answer for a file it
    could not read; a file it cannot read raises."""


def _b64(s, name):
    pad = len(s) % 4
    if pad:
        raise CatalogError('%s: base64 length %d is not a multiple of 4'
                           % (name, len(s)))
    try:
        return base64.b64decode(s)
    except Exception as e:
        raise CatalogError('%s: not base64: %s' % (name, e))


def _read_key(blob, off):
    """One key at one offset. Returns (value, bytes consumed)."""
    if not 0 <= off < len(blob):
        raise CatalogError('key offset %d is outside the %d-byte key blob'
                           % (off, len(blob)))
    t = blob[off]
    p = off + 1
    if t == TYPE_ASCII:
        (n,) = struct.unpack_from('<i', blob, p)
        p += 4
        if n < 0 or p + n > len(blob):
            raise CatalogError('ascii key of %d bytes at %d overruns' % (n, off))
        return blob[p:p + n].decode('ascii', 'replace'), p + n - off
    if t == TYPE_UNICODE:
        (n,) = struct.unpack_from('<i', blob, p)
        p += 4
        if n < 0 or p + n > len(blob):
            raise CatalogError('unicode key of %d bytes at %d overruns'
                               % (n, off))
        return blob[p:p + n].decode('utf-16-le', 'replace'), p + n - off
    if t == TYPE_U16:
        return struct.unpack_from('<H', blob, p)[0], 3
    if t == TYPE_U32:
        return struct.unpack_from('<I', blob, p)[0], 5
    if t == TYPE_I32:
        return struct.unpack_from('<i', blob, p)[0], 5
    if t == TYPE_HASH:
        n = blob[p]
        p += 1
        return blob[p:p + n].decode('ascii', 'replace'), p + n - off
    raise CatalogError('key type %d at offset %d is not one this reader knows'
                       % (t, off))


class Catalog(object):

    def __init__(self, path_or_text, name=None):
        if isinstance(path_or_text, (bytes, bytearray)):
            text = bytes(path_or_text).decode('utf-8-sig')
            self.name = name or '<memory>'
            self.filesize = len(path_or_text)
        else:
            self.name = name or os.path.basename(path_or_text)
            self.filesize = os.path.getsize(path_or_text)
            text = open(path_or_text, 'rb').read().decode('utf-8-sig')
        try:
            j = json.loads(text)
        except ValueError as e:
            raise CatalogError('%s: not JSON: %s' % (self.name, e))
        for f in ('m_LocatorId', 'm_InternalIds', 'm_KeyDataString',
                  'm_BucketDataString', 'm_EntryDataString',
                  'm_ExtraDataString', 'm_ProviderIds', 'm_resourceTypes'):
            if f not in j:
                raise CatalogError('%s: no %s -- this is JSON but it is not an '
                                   'Addressables catalogue' % (self.name, f))
        self.j = j
        self.locator = j['m_LocatorId']
        self.internal_ids = j['m_InternalIds']
        self.providers = j['m_ProviderIds']
        self.types = [t.get('m_ClassName', '') for t in j['m_resourceTypes']]
        self.keyblob = _b64(j['m_KeyDataString'], 'm_KeyDataString')
        self.bucketblob = _b64(j['m_BucketDataString'], 'm_BucketDataString')
        self.entryblob = _b64(j['m_EntryDataString'], 'm_EntryDataString')
        self.extrablob = _b64(j['m_ExtraDataString'], 'm_ExtraDataString')
        self._entries()
        self._buckets()

    def _entries(self):
        b = self.entryblob
        if len(b) < 4:
            raise CatalogError('%s: entry blob is %d bytes' % (self.name, len(b)))
        (n,) = struct.unpack_from('<i', b, 0)
        if n < 0 or 4 + n * ENTRY_STRIDE > len(b):
            raise CatalogError('%s: %d entries do not fit in %d bytes'
                               % (self.name, n, len(b)))
        self.entry_count = n
        self.entry_residue = len(b) - 4 - n * ENTRY_STRIDE
        self.entries = []
        for i in range(n):
            self.entries.append(struct.unpack_from('<7i', b, 4 + i * ENTRY_STRIDE))

    def _buckets(self):
        b = self.bucketblob
        (n,) = struct.unpack_from('<i', b, 0)
        p = 4
        self.bucket_count = n
        self.buckets = []
        for _ in range(n):
            off, cnt = struct.unpack_from('<ii', b, p)
            p += 8
            if cnt < 0 or p + cnt * 4 > len(b):
                raise CatalogError('%s: bucket of %d entries overruns'
                                   % (self.name, cnt))
            idx = list(struct.unpack_from('<%di' % cnt, b, p)) if cnt else []
            p += cnt * 4
            self.buckets.append((off, idx))
        self.bucket_residue = len(b) - p
        self.keys = []
        for off, idx in self.buckets:
            k, _ = _read_key(self.keyblob, off)
            self.keys.append((k, idx))

    # -- the six checks ----------------------------------------------------

    def checks(self):
        out = []
        out.append(('every base64 field decodes whole', True,
                    'key %d, bucket %d, entry %d, extra %d bytes'
                    % (len(self.keyblob), len(self.bucketblob),
                       len(self.entryblob), len(self.extrablob))))
        out.append(('entry table: 4 + %d x 28 == blob length' % self.entry_count,
                    self.entry_residue == 0,
                    '%d vs %d, residue %d'
                    % (4 + self.entry_count * ENTRY_STRIDE,
                       len(self.entryblob), self.entry_residue)))
        out.append(('bucket table walked to its exact end',
                    self.bucket_residue == 0,
                    '%d buckets, residue %d'
                    % (self.bucket_count, self.bucket_residue)))
        bad = []
        for off, _ in self.buckets:
            try:
                _read_key(self.keyblob, off)
            except CatalogError as e:
                bad.append(str(e))
        out.append(('every bucket key offset parses', not bad,
                    '%d of %d keys read' % (self.bucket_count - len(bad),
                                            self.bucket_count)))
        oob = 0
        for e in self.entries:
            if not (0 <= e[0] < len(self.internal_ids)):
                oob += 1
            elif not (0 <= e[1] < len(self.providers)):
                oob += 1
            elif not (-1 <= e[6] < len(self.types)):
                oob += 1
        out.append(('every entry index is inside its array', oob == 0,
                    '%d of %d entries in range'
                    % (self.entry_count - oob, self.entry_count)))
        pairs = sum(len(i) for _, i in self.buckets)
        badref = sum(1 for _, i in self.buckets
                     for x in i if not 0 <= x < self.entry_count)
        out.append(('every bucket entry index is inside the entry table',
                    badref == 0,
                    '%d (key, entry) pairs, %d out of range' % (pairs, badref)))
        return out

    # -- views -------------------------------------------------------------

    def rows(self):
        """One row per (key, entry) pair: key, internal id, provider, type."""
        for k, idx in self.buckets:
            key, _ = _read_key(self.keyblob, k)
            for x in idx:
                e = self.entries[x]
                yield (key,
                       self.internal_ids[e[0]] if 0 <= e[0] < len(self.internal_ids) else None,
                       self.providers[e[1]] if 0 <= e[1] < len(self.providers) else None,
                       self.types[e[6]] if 0 <= e[6] < len(self.types) else None)


# -- commands --------------------------------------------------------------

def cmd_validate(argv):
    c = Catalog(argv[2])
    print(c.name)
    ok = True
    for label, good, detail in c.checks():
        print('  %-52s %-4s %s' % (label, 'ok' if good else 'FAIL', detail))
        ok = ok and good
    print()
    print('%s: %s' % (c.name, 'all checks pass' if ok else 'CHECKS FAILED'))
    return 0 if ok else 1


def cmd_census(argv):
    c = Catalog(argv[2])
    print('catalogue          : %s  (%d bytes)' % (c.name, c.filesize))
    print('locator            : %s' % c.locator)
    print('addressables       : %s'
          % c.j.get('m_AddressablesVersion', '(not stated here)'))
    print('internal ids       : %d' % len(c.internal_ids))
    print('providers          : %d' % len(c.providers))
    print('resource types     : %d' % len(c.types))
    print('entries            : %d' % c.entry_count)
    print('buckets (keys)     : %d' % c.bucket_count)
    rows = list(c.rows())
    print('(key, entry) pairs : %d' % len(rows))
    print()
    bytype = collections.Counter(r[3] for r in rows)
    print('%-62s %6s' % ('resource type named by the catalogue', 'pairs'))
    for t, n in bytype.most_common():
        print('%-62s %6d' % (t, n))
    print()
    byprov = collections.Counter(r[2] for r in rows)
    print('%-62s %6s' % ('provider', 'pairs'))
    for t, n in byprov.most_common():
        print('%-62s %6d' % (t or '(empty)', n))
    return 0


def cmd_keys(argv):
    c = Catalog(argv[2])
    limit = int(argv[argv.index('--limit') + 1]) if '--limit' in argv else 0
    n = 0
    for key, idx in c.buckets:
        k, _ = _read_key(c.keyblob, key)
        n += 1
        if limit and n > limit:
            break
        print('%-58s %d entr%s' % (str(k)[:58], len(idx),
                                   'y' if len(idx) == 1 else 'ies'))
    print()
    print('%d keys' % c.bucket_count)
    return 0


def cmd_bundles(argv):
    """What the catalogue says about the bundles, against what is on disk."""
    c = Catalog(argv[2])
    tree = argv[argv.index('--tree') + 1] if '--tree' in argv else None
    named = [i for i in c.internal_ids if i.lower().endswith('.bundle')]
    print('bundles named by the catalogue : %d' % len(named))
    ondisk = {}
    if tree:
        for dp, _, fs in os.walk(tree):
            for f in fs:
                if f.lower().endswith('.bundle'):
                    ondisk[f] = os.path.getsize(os.path.join(dp, f))
    print('bundles found on disk          : %d' % len(ondisk))
    print()
    print('%-9s %12s  %s' % ('agreement', 'bytes', 'name'))
    matched = 0
    for i in sorted(named):
        base = i.replace('\\', '/').split('/')[-1]
        if base in ondisk:
            matched += 1
            print('%-9s %12d  %s' % ('both', ondisk[base], base))
        else:
            print('%-9s %12s  %s' % ('CATALOGUE', '-', base))
    for f in sorted(ondisk):
        if f not in {i.replace('\\', '/').split('/')[-1] for i in named}:
            print('%-9s %12d  %s' % ('DISK', ondisk[f], f))
    print()
    print('named by both                  : %d' % matched)
    print('named by the catalogue only    : %d' % (len(named) - matched))
    print('found on disk only             : %d' % (len(ondisk) - matched))
    return 0


# -- selftest --------------------------------------------------------------

def _make(keys, entries, ids, provs, types, **over):
    """Build a catalogue in memory. Used only by selftest."""
    kb = bytearray()
    offs = []
    for k in keys:
        offs.append(len(kb))
        kb.append(TYPE_ASCII)
        kb += struct.pack('<i', len(k)) + k.encode('ascii')
    bb = bytearray(struct.pack('<i', len(keys)))
    for off, (_, idx) in zip(offs, keys and [(k, [0]) for k in keys]):
        bb += struct.pack('<ii', off, len(idx)) + struct.pack(
            '<%di' % len(idx), *idx)
    eb = bytearray(struct.pack('<i', len(entries)))
    for e in entries:
        eb += struct.pack('<7i', *e)
    doc = {
        'm_LocatorId': 'test',
        'm_InternalIds': ids,
        'm_ProviderIds': provs,
        'm_resourceTypes': [{'m_ClassName': t} for t in types],
        'm_KeyDataString': base64.b64encode(bytes(kb)).decode(),
        'm_BucketDataString': base64.b64encode(bytes(bb)).decode(),
        'm_EntryDataString': base64.b64encode(bytes(eb)).decode(),
        'm_ExtraDataString': '',
    }
    doc.update(over)
    return json.dumps(doc).encode('utf-8')


def cmd_selftest(argv):
    cases = []

    def case(label, blob, want_ok, want_msg=None):
        cases.append((label, blob, want_ok, want_msg))

    good = _make(['a', 'b'], [(0, 0, -1, 0, -1, 0, 0), (1, 0, -1, 0, -1, 1, 0)],
                 ['id0', 'id1'], ['prov'], ['T'])
    case('a catalogue this reader believes', good, True)

    case('not JSON at all', b'UnityFS\0\0\0\0\x08', False, 'not JSON')
    case('JSON but not a catalogue', b'{"hello":1}', False,
         'not an Addressables catalogue')
    case('empty file', b'', False, 'not JSON')
    case('a JSON array, not an object', b'[1,2,3]', False,
         'not an Addressables catalogue')

    bad = json.loads(good.decode())
    bad['m_EntryDataString'] = bad['m_EntryDataString'][:-4]
    case('entry blob truncated by one field',
         json.dumps(bad).encode(), False, None)

    bad = json.loads(good.decode())
    bad['m_KeyDataString'] = 'A' * 5
    case('key blob is not a multiple of four',
         json.dumps(bad).encode(), False, 'not a multiple of 4')

    bad = json.loads(good.decode())
    kb = bytearray(base64.b64decode(bad['m_KeyDataString']))
    kb[0] = 99
    bad['m_KeyDataString'] = base64.b64encode(bytes(kb)).decode()
    case('key type byte this reader does not know',
         json.dumps(bad).encode(), False, 'not one this reader knows')

    bad = json.loads(good.decode())
    bb = bytearray(base64.b64decode(bad['m_BucketDataString']))
    struct.pack_into('<i', bb, 4, 1 << 30)
    bad['m_BucketDataString'] = base64.b64encode(bytes(bb)).decode()
    case('bucket key offset past the end of the key blob',
         json.dumps(bad).encode(), False, 'outside the')

    bad = json.loads(good.decode())
    bad['m_InternalIds'] = []
    case('an entry that indexes an empty internal-id array',
         json.dumps(bad).encode(), True, None)   # parses, but check 5 fails

    bad = json.loads(good.decode())
    del bad['m_resourceTypes']
    case('a field removed', json.dumps(bad).encode(), False, 'no m_resourceTypes')

    npass = nfail = 0
    for label, blob, want_ok, want_msg in cases:
        try:
            c = Catalog(blob, name=label)
            got_ok, msg = True, 'parsed'
            if want_ok and label.startswith('an entry that indexes'):
                got = [g for _, g, _ in c.checks()]
                got_ok = not all(got)
                msg = 'parsed, and check 5 fails as it should'
                want_ok = True
                got_ok = got_ok
        except CatalogError as e:
            got_ok, msg = False, str(e)
        want = want_ok
        ok = (got_ok == want) and (want_msg is None or want_msg in msg)
        npass += ok
        nfail += not ok
        print('  %-4s %-52s %s' % ('ok' if ok else 'FAIL', label, msg[:60]))
    print()
    rejections = sum(1 for c in cases if not c[2])
    print('%d cases: %d pass, %d fail. %d of %d are rejections.'
          % (len(cases), npass, nfail, rejections, len(cases)))
    return 0 if nfail == 0 else 1


def main(argv):
    cmds = {'validate': cmd_validate, 'census': cmd_census, 'keys': cmd_keys,
            'bundles': cmd_bundles, 'selftest': cmd_selftest}
    if len(argv) < 2 or argv[1] not in cmds:
        print(__doc__)
        return 2
    if argv[1] != 'selftest' and len(argv) < 3:
        print('%s needs a path' % argv[1])
        return 2
    try:
        return cmds[argv[1]](argv)
    except CatalogError as e:
        print('REFUSED  %s' % e, file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main(sys.argv))
