#!/usr/bin/env python3
"""Read an APK's signing certificate with no Android SDK and no dependencies.

`META-INF/*.RSA` is a PKCS#7 SignedData blob and the certificate inside it is
an X.509 one.  Both are DER, which is a tag-length-value encoding simple enough
to walk with `struct` and a loop -- so the issuer, the subject, the validity
dates and the key size are readable without cryptography and without a
toolchain.  That matters here because the question the corpus keeps asking --
*who made it* -- is one an APK answers in a place a disc image has no
equivalent of: the signer's distinguished name is a statement by whoever holds
the key, written at build time, and it is not marketing text.

What this tool does NOT do is verify anything.  It does not check the
signature, the digest, or the chain.  It reads names and dates out of a
structure and prints them, and a forged certificate would be printed exactly
the same way.  Use it as a source of identity claims, not of proof.

    python apkcert.py APK
    python apkcert.py FILE.RSA
    python apkcert.py APK --raw          -- the DER structure, indented
    python apkcert.py --selftest

Standard library only.
"""

import datetime
import os
import sys
import zipfile

OID = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.4': 'SN', '2.5.4.42': 'GN',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSA',
    '1.2.840.113549.1.1.11': 'sha256WithRSA',
    '1.2.840.113549.1.1.13': 'sha512WithRSA',
    '1.2.840.10045.2.1': 'ecPublicKey',
    '1.2.840.10045.4.3.2': 'ecdsaWithSHA256',
    '1.2.840.113549.1.7.2': 'signedData',
}

CLASSES = {0: 'universal', 1: 'application', 2: 'context', 3: 'private'}
TAGS = {1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING',
        5: 'NULL', 6: 'OID', 12: 'UTF8String', 16: 'SEQUENCE', 17: 'SET',
        19: 'PrintableString', 20: 'T61String', 22: 'IA5String',
        23: 'UTCTime', 24: 'GeneralizedTime', 26: 'VisibleString',
        30: 'BMPString'}


def der_read(data, pos):
    """One TLV: returns (tag, constructed, value_bytes, next_position)."""
    b = data[pos]
    tag = b & 0x1F
    constructed = bool(b & 0x20)
    pos += 1
    if tag == 0x1F:
        tag = 0
        while True:
            c = data[pos]
            pos += 1
            tag = (tag << 7) | (c & 0x7F)
            if not c & 0x80:
                break
    ln = data[pos]
    pos += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
    return tag, constructed, data[pos:pos + ln], pos + ln


def der_tree(data, depth=0, limit=40):
    """The DER structure as a tree: [(tag, constructed, value, children)].

    A flat list loses the one thing name parsing needs -- which SETs belong to
    which SEQUENCE -- and a PKCS#7 blob contains the issuer name twice, once in
    the certificate and once in SignerInfo's issuerAndSerialNumber.  Flattened,
    the second one runs into the first and a self-signed certificate comes out
    with a twelve-component subject.  The tree is what stops that.
    """
    out = []
    pos = 0
    while pos < len(data):
        try:
            tag, cons, val, pos = der_read(data, pos)
        except (IndexError, ValueError):
            return out
        kids = der_tree(val, depth + 1, limit) if cons and depth < limit else []
        out.append((tag, cons, val, kids))
    return out


def der_walk(data, depth=0, out=None, limit=40):
    """The same structure flattened, for --raw."""
    out = [] if out is None else out

    def rec(nodes, d):
        for tag, cons, val, kids in nodes:
            out.append((d, tag, cons, val))
            rec(kids, d + 1)
    rec(der_tree(data, 0, limit), depth)
    return out


def decode_oid(b):
    if not b:
        return ''
    parts = [str(b[0] // 40), str(b[0] % 40)]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(str(v))
            v = 0
    return '.'.join(parts)


def decode_time(b):
    s = b.decode('ascii', 'replace')
    try:
        if len(s) >= 15 and s.endswith('Z'):
            return datetime.datetime.strptime(s[:14], '%Y%m%d%H%M%S')
        if len(s) >= 13:
            y = int(s[:2])
            y += 2000 if y < 50 else 1900
            return datetime.datetime(y, int(s[2:4]), int(s[4:6]),
                                     int(s[6:8]), int(s[8:10]), int(s[10:12]))
    except ValueError:
        pass
    return s


def rdn_of(setnode):
    """One RelativeDistinguishedName: SET { SEQUENCE { OID, value } }."""
    tag, cons, _val, kids = setnode
    if tag != 17 or not cons:
        return None
    for _t, _c, _v, pair in kids:
        if len(pair) >= 2 and pair[0][0] == 6:
            oid = decode_oid(pair[0][2])
            txt = pair[1][2].decode('utf-8', 'replace')
            return (OID.get(oid, oid), txt)
    return None


def find_names(tree, out=None):
    """Every X.501 Name: a SEQUENCE whose children are all SETs of one RDN."""
    out = [] if out is None else out
    for tag, cons, _val, kids in tree:
        if tag == 16 and cons and kids and all(k[0] == 17 for k in kids):
            parts = [rdn_of(k) for k in kids]
            parts = [p for p in parts if p]
            if parts:
                out.append(parts)
                continue
        if cons:
            find_names(kids, out)
    return out


def find_first(tree, pred, out=None):
    out = [] if out is None else out
    for node in tree:
        if pred(node):
            out.append(node)
        if node[1]:
            find_first(node[3], pred, out)
    return out


def parse_cert(der):
    """Issuer, subject, validity, serial and key size, read off the tree.

    A PKCS#7 SignedData carries the certificate and then repeats the issuer in
    SignerInfo, so `find_names` returns three Names for a self-signed APK
    certificate and the third is a duplicate of the first.  It is reported as
    what it is rather than folded away, because a build signed by one party and
    issued by another would show up here as three *different* names.
    """
    tree = der_tree(der)
    names = find_names(tree)
    times = [decode_time(n[2])
             for n in find_first(tree, lambda n: n[0] in (23, 24) and not n[1])]
    sigalg = None
    for n in find_first(tree, lambda n: n[0] == 6 and not n[1]):
        oid = decode_oid(n[2])
        if oid in ('1.2.840.113549.1.1.5', '1.2.840.113549.1.1.11',
                   '1.2.840.113549.1.1.13', '1.2.840.10045.4.3.2'):
            sigalg = OID.get(oid, oid)
            break
    serial = None
    for n in find_first(tree, lambda n: n[0] == 2 and not n[1]):
        if len(n[2]) >= 4:
            serial = int.from_bytes(n[2], 'big')
            break
    keybits = None
    for n in find_first(tree, lambda n: n[0] == 3 and not n[1]):
        if len(n[2]) > 100:
            keybits = (len(n[2]) - 1) * 8
            break
    nodes = der_walk(der)
    return dict(names=names, times=times, serial=serial, keybits=keybits,
                sigalg=sigalg, nodes=nodes)


def show(label, der, argv):
    info = parse_cert(der)
    print('%s   %d bytes DER' % (label, len(der)))
    print()
    roles = ['issuer', 'subject', 'signer ref']
    for i, parts in enumerate(info['names'][:4]):
        print('  %-10s %s' % (roles[i] if i < len(roles) else 'name %d' % i,
                              ', '.join('%s=%s' % p for p in parts)))
    if len(info['names']) >= 3:
        same = info['names'][0] == info['names'][2]
        print('  %-10s %s' % ('',
              'the signer reference repeats the issuer'
              if same else 'the signer reference DIFFERS from the issuer'))
    if len(info['names']) >= 2 and info['names'][0] == info['names'][1]:
        print('  %-10s %s' % ('', 'issuer == subject: self-signed'))
    if info['times']:
        print('  %-10s %s' % ('not before', info['times'][0]))
    if len(info['times']) > 1:
        print('  %-10s %s' % ('not after', info['times'][1]))
        try:
            span = info['times'][1] - info['times'][0]
            print('  %-10s %d days (%.1f years)'
                  % ('validity', span.days, span.days / 365.25))
        except TypeError:
            pass
    if info['serial'] is not None:
        print('  %-10s %d (0x%X)' % ('serial', info['serial'], info['serial']))
    if info['sigalg']:
        print('  %-10s %s' % ('signature', info['sigalg']))
    if info['keybits']:
        print('  %-10s about %d bits' % ('public key', info['keybits']))
    print()
    if '--raw' in argv:
        for d, tag, cons, val in info['nodes'][:400]:
            name = TAGS.get(tag, 'tag %d' % tag)
            extra = ''
            if tag == 6 and not cons:
                o = decode_oid(val)
                extra = '  %s' % OID.get(o, o)
            elif not cons and tag in (12, 19, 22, 20, 26):
                extra = '  %r' % val.decode('utf-8', 'replace')[:60]
            print('%s%-16s %5d%s' % ('  ' * d, name, len(val), extra))
        print()


def selftest():
    print('apkcert.py --selftest')
    print()
    ok = 0
    cases = [
        (b'\x55\x04\x03', '2.5.4.3', 'CN'),
        (b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b',
         '1.2.840.113549.1.1.11', 'sha256WithRSA'),
        (b'\x2a\x86\x48\xce\x3d\x02\x01', '1.2.840.10045.2.1', 'ecPublicKey'),
    ]
    print('  OID decoding:')
    for raw, want, label in cases:
        got = decode_oid(raw)
        good = got == want
        ok += good
        print('    %-26s -> %-24s %s' % (raw.hex(), got,
                                         'ok (%s)' % label if good
                                         else 'FAILED, wanted %s' % want))
    print()
    print('  DER length decoding:')
    for blob, want in ((b'\x04\x03abc', 3), (b'\x04\x81\x80' + b'x' * 128, 128)):
        _t, _c, v, _p = der_read(blob, 0)
        good = len(v) == want
        ok += good
        print('    %-26s -> %3d bytes  %s' % (blob[:6].hex(), len(v),
                                              'ok' if good else 'FAILED'))
    print()
    print('  time decoding:')
    for raw, want in ((b'210901123000Z', '2021-09-01 12:30:00'),
                      (b'20210901123000Z', '2021-09-01 12:30:00')):
        got = str(decode_time(raw))
        good = got == want
        ok += good
        print('    %-26s -> %-22s %s' % (raw.decode(), got,
                                         'ok' if good else 'FAILED'))
    print()
    print('  %d of 7 checks pass.' % ok)
    return 0 if ok == 7 else 1


def main(argv):
    if '--selftest' in argv:
        raise SystemExit(selftest())
    if len(argv) < 2:
        raise SystemExit(__doc__)
    path = argv[1]
    print('=' * 72)
    print('APK signing certificate')
    print('=' * 72)
    print('This tool reads names and dates.  It verifies nothing: the')
    print('signature is not checked and the chain is not validated, so what')
    print('follows is what the signer claims, not what has been proved.')
    print()
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        blobs = [(i.filename, z.read(i))
                 for i in z.infolist()
                 if i.filename.upper().startswith('META-INF/')
                 and i.filename.upper().endswith(('.RSA', '.DSA', '.EC'))]
        others = [i.filename for i in z.infolist()
                  if i.filename.upper().startswith('META-INF/')]
        print('%d entries under META-INF/, %d of them a signature block'
              % (len(others), len(blobs)))
        for n in sorted(others):
            print('   %s' % n)
        print()
        if not blobs:
            print('no v1 (JAR) signature block in this package.')
            return
    else:
        blobs = [(os.path.basename(path), open(path, 'rb').read())]
    for name, blob in blobs:
        show(name, blob, argv)


if __name__ == '__main__':
    main(sys.argv)
