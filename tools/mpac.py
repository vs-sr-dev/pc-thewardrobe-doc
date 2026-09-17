#!/usr/bin/env python3
"""
mpac.py - reader for the .mpac UI documents inside Tales of Crestoria packages.

Every .csf package carries a set of .mpac members. They are plain MessagePack
maps describing one UI scene: an identity block (GUID, authoring-tool version,
name) and a Content tree of nodes, animation timelines and sprite references.
Nothing is encrypted and nothing is game-specific about the encoding, so this
file is a small self-contained MessagePack decoder plus a few commands that
summarise what the documents contain. See docs/formats/mpac.md.

Standalone Python 3, no dependencies.
"""
import argparse, json, os, struct
from collections import Counter


class MsgpackError(Exception):
    pass


class _Reader:
    def __init__(self, buf):
        self.b = buf
        self.p = 0

    def u(self, n):
        v = self.b[self.p:self.p + n]
        if len(v) != n:
            raise MsgpackError('truncated at 0x%x' % self.p)
        self.p += n
        return v

    def value(self):
        c = self.u(1)[0]
        if c <= 0x7F:
            return c
        if c >= 0xE0:
            return c - 0x100
        if 0x80 <= c <= 0x8F:
            return self.map(c & 0x0F)
        if 0x90 <= c <= 0x9F:
            return self.array(c & 0x0F)
        if 0xA0 <= c <= 0xBF:
            return self.u(c & 0x1F).decode('utf-8', 'replace')
        if c == 0xC0:
            return None
        if c == 0xC2:
            return False
        if c == 0xC3:
            return True
        if c == 0xC4:
            return self.u(self.u(1)[0])
        if c == 0xC5:
            return self.u(struct.unpack('>H', self.u(2))[0])
        if c == 0xC6:
            return self.u(struct.unpack('>I', self.u(4))[0])
        if c in (0xC7, 0xC8, 0xC9):          # ext 8 / 16 / 32
            n = {0xC7: 1, 0xC8: 2, 0xC9: 4}[c]
            size = int.from_bytes(self.u(n), 'big')
            return ('ext', self.u(1)[0], self.u(size))
        if c == 0xCA:
            return struct.unpack('>f', self.u(4))[0]
        if c == 0xCB:
            return struct.unpack('>d', self.u(8))[0]
        if c in (0xCC, 0xCD, 0xCE, 0xCF):    # uint 8/16/32/64
            return int.from_bytes(self.u(1 << (c - 0xCC)), 'big')
        if c in (0xD0, 0xD1, 0xD2, 0xD3):    # int 8/16/32/64
            return int.from_bytes(self.u(1 << (c - 0xD0)), 'big', signed=True)
        if 0xD4 <= c <= 0xD8:                # fixext 1/2/4/8/16
            return ('ext', self.u(1)[0], self.u(1 << (c - 0xD4)))
        if c == 0xD9:
            return self.u(self.u(1)[0]).decode('utf-8', 'replace')
        if c == 0xDA:
            return self.u(struct.unpack('>H', self.u(2))[0]).decode('utf-8', 'replace')
        if c == 0xDB:
            return self.u(struct.unpack('>I', self.u(4))[0]).decode('utf-8', 'replace')
        if c == 0xDC:
            return self.array(struct.unpack('>H', self.u(2))[0])
        if c == 0xDD:
            return self.array(struct.unpack('>I', self.u(4))[0])
        if c == 0xDE:
            return self.map(struct.unpack('>H', self.u(2))[0])
        if c == 0xDF:
            return self.map(struct.unpack('>I', self.u(4))[0])
        raise MsgpackError('unknown msgpack tag 0x%02x at 0x%x' % (c, self.p - 1))

    def array(self, n):
        return [self.value() for _ in range(n)]

    def map(self, n):
        out = {}
        for _ in range(n):
            k = self.value()
            out[k if isinstance(k, (str, int)) else repr(k)] = self.value()
        return out


def loads(buf):
    r = _Reader(buf)
    v = r.value()
    return v


def load(path):
    return loads(open(path, 'rb').read())


def _walk(paths):
    for path in paths:
        if os.path.isdir(path):
            for dp, _, fn in os.walk(path):
                for x in sorted(fn):
                    if x.lower().endswith('.mpac'):
                        yield os.path.join(dp, x)
        else:
            yield path


def _keys(node, acc, depth=0):
    if isinstance(node, dict):
        for k, v in node.items():
            acc[k] += 1
            _keys(v, acc, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _keys(v, acc, depth + 1)


def cmd_info(args):
    print('%-46s %-38s %-10s %s' % ('file', 'ID', 'Version', 'Name'))
    for f in _walk(args.paths):
        try:
            d = load(f)
        except MsgpackError as e:
            print('%-46s !! %s' % (os.path.relpath(f), e))
            continue
        print('%-46s %-38s %-10s %s' % (os.path.relpath(f), d.get('ID'),
                                        d.get('Version'), d.get('Name')))


def cmd_keys(args):
    acc = Counter()
    n = 0
    for f in _walk(args.paths):
        try:
            _keys(load(f), acc)
            n += 1
        except MsgpackError:
            pass
    print('%8s  %s' % ('count', 'key'))
    for k, v in acc.most_common(args.top):
        print('%8d  %s' % (v, k))
    print('-- over %d document(s)' % n)


def cmd_dump(args):
    d = load(args.path)
    print(json.dumps(d, indent=2, ensure_ascii=False, default=repr)[:args.limit])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('info', help='identity line per document')
    p.add_argument('paths', nargs='+')
    p.set_defaults(fn=cmd_info)
    p = sub.add_parser('keys', help='key census across documents')
    p.add_argument('paths', nargs='+')
    p.add_argument('--top', type=int, default=60)
    p.set_defaults(fn=cmd_keys)
    p = sub.add_parser('dump', help='pretty-print one document as JSON')
    p.add_argument('path')
    p.add_argument('--limit', type=int, default=20000)
    p.set_defaults(fn=cmd_dump)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
