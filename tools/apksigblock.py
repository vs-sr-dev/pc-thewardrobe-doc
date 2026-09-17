#!/usr/bin/env python3
"""Read the APK Signing Block, which is where a modern APK keeps its identity.

`apkcert.py` reads `META-INF/` -- the JAR signature, APK Signature Scheme v1 --
and on this object it correctly reports **61 entries and 0 signature blocks**.
That zero is not a failure of the tool, it is a fact about the package: since
Android 7 an APK can be signed with v2/v3 alone, and the signature then lives
in a block wedged between the end of the entries and the ZIP central directory,
where no ZIP reader looks.

    ... entries ...
    APK Signing Block:
        u64        size of the block (excluding this field)
        pairs of:  u64 length, u32 id, (length-4) bytes of value
        u64        size of the block again      <- stated twice, and checked
        char[16]   "APK Sig Block 42"
    central directory
    end of central directory

Known ids:
    0x7109871A  APK Signature Scheme v2
    0xF05368C0  APK Signature Scheme v3
    0x1B93AD61  verity padding
    0x42726577  padding ("Brew")
    0x2146444E  Google Play source stamp
    0x6DFF800D  Google Play metadata ("frosting")

Inside a v2/v3 block: a length-prefixed sequence of signers; each signer is
signed-data, signatures and a public key; the signed data begins with a
length-prefixed sequence of digests and then a length-prefixed sequence of
**X.509 certificates in DER**.  The first certificate is the signer's.

This tool does **not verify anything**.  It does not check a digest, does not
validate a chain and does not confirm that the file it is reading is the file
that was signed.  What it prints is what the signer wrote down.  The names in
an X.509 subject are read by walking the DER for its text primitives rather
than by implementing a full ASN.1 parser, and the tool says that is what it
did.

    python apksigblock.py APK...

Standard library only.
"""

import os
import struct
import sys

MAGIC = b'APK Sig Block 42'

IDS = {
    0x7109871A: 'APK Signature Scheme v2',
    0xF05368C0: 'APK Signature Scheme v3',
    0x1B93AD61: 'verity padding',
    0x42726577: 'padding',
    0x2146444E: 'Google Play source stamp',
    0x6DFF800D: 'Google Play metadata',
}

# ASN.1 text tags whose contents are printable identity strings
TEXT_TAGS = {0x0C: 'UTF8String', 0x13: 'PrintableString', 0x16: 'IA5String',
             0x1E: 'BMPString'}

# Object identifiers that label the parts of a distinguished name
OID_NAMES = {
    b'\x55\x04\x03': 'CN', b'\x55\x04\x06': 'C', b'\x55\x04\x07': 'L',
    b'\x55\x04\x08': 'ST', b'\x55\x04\x0a': 'O', b'\x55\x04\x0b': 'OU',
}


def find_block(d):
    i = d.rfind(MAGIC)
    if i < 0:
        return None
    size2 = struct.unpack_from('<Q', d, i - 8)[0]
    start = i + 16 - 8 - size2
    if start < 0 or start + 8 > len(d):
        return None
    size1 = struct.unpack_from('<Q', d, start)[0]
    return dict(offset=start, size1=size1, size2=size2, magic_at=i,
                agree=(size1 == size2), end=i - 8)


def pairs(d, blk):
    p = blk['offset'] + 8
    while p + 12 <= blk['end']:
        ln = struct.unpack_from('<Q', d, p)[0]
        if ln < 4 or p + 8 + ln > blk['end'] + 8:
            return
        kid = struct.unpack_from('<I', d, p + 8)[0]
        yield kid, d[p + 12:p + 8 + ln]
        p += 8 + ln


def lenpref(buf, p):
    n = struct.unpack_from('<I', buf, p)[0]
    return buf[p + 4:p + 4 + n], p + 4 + n


def certificates(value):
    """First signer's certificate list from a v2/v3 block value."""
    out = []
    signers, _ = lenpref(value, 0)
    signer, _ = lenpref(signers, 0)
    signed, _ = lenpref(signer, 0)
    digests, p = lenpref(signed, 0)
    certs, _ = lenpref(signed, p)
    q = 0
    while q + 4 <= len(certs):
        c, q = lenpref(certs, q)
        if c:
            out.append(c)
    return out


def der_names(cert):
    """Walk the DER for AttributeTypeAndValue pairs and report them as
    `OID=text`.  Not a parser: a scan for the six name OIDs followed by a text
    primitive.  It is enough to name a signer and it is honest about being a
    scan."""
    out = []
    i = 0
    while i + 5 < len(cert):
        if cert[i] == 0x06 and cert[i + 1] == 3:
            oid = cert[i + 2:i + 5]
            if oid in OID_NAMES:
                j = i + 5
                if j + 2 <= len(cert) and cert[j] in TEXT_TAGS:
                    ln = cert[j + 1]
                    if ln < 0x80:
                        txt = cert[j + 2:j + 2 + ln]
                        try:
                            s = txt.decode('utf-8')
                        except UnicodeDecodeError:
                            s = txt.decode('latin-1')
                        out.append('%s=%s' % (OID_NAMES[oid], s))
        i += 1
    return out


def probe(path):
    d = open(path, 'rb').read()
    print('=== %s  %d bytes' % (os.path.basename(path), len(d)))
    blk = find_block(d)
    if not blk:
        print('  no APK Signing Block: this package is v1-signed or unsigned')
        return 1
    print('  block at %d, %d bytes, size stated twice as %d and %d -> %s'
          % (blk['offset'], blk['size1'], blk['size1'], blk['size2'],
             'agree' if blk['agree'] else 'DISAGREE'))
    seen = []
    for kid, val in pairs(d, blk):
        print('  id 0x%08X  %-26s %d bytes'
              % (kid, IDS.get(kid, 'unknown'), len(val)))
        seen.append(kid)
    for kid in (0x7109871A, 0xF05368C0):
        for k, val in pairs(d, blk):
            if k != kid:
                continue
            try:
                certs = certificates(val)
            except Exception as e:
                print('  %s: could not walk to the certificates: %s'
                      % (IDS[kid], e))
                continue
            print('  %s: %d certificate(s)' % (IDS[kid], len(certs)))
            for c in certs:
                names = der_names(c)
                print('    DER %d bytes' % len(c))
                for n in names:
                    print('      %s' % n)
            break
    print('  signature schemes present: %s'
          % ', '.join(IDS.get(k, hex(k)) for k in seen if k in IDS))
    print('  NOT VERIFIED: no digest checked, no chain validated.')
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    for a in argv[1:]:
        rc |= probe(a)
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv))
