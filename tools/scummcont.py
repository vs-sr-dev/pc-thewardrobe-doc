#!/usr/bin/env python3
"""Walk the LucasArts chunk container of an encrypted SCUMM data file.

Derived from the bytes of this object and nothing else. No reference
implementation of this format was read, quoted or used to validate. What the
tool assumes is written down here, and every assumption is one the file itself
forces:

* **The cipher is a single-byte XOR.** `SAMNMAX.000` begins
  `3b 27 28 24 69`; XOR 0x69 gives `RNAM` and a big-endian 9. The fifth byte
  being the key itself is the giveaway: a length field whose top byte is zero
  encrypts to the key. `--key` overrides; default 0x69.

* **A chunk is `[tag:4][length:4 big-endian][payload]` and the length
  INCLUDES the eight-byte header.** Forced by `LECF` declaring 13,789,910 on a
  file of exactly 13,789,910 bytes, and re-forced at every level by the tiling
  test below.

* **A chunk is a container if, and only if, its payload tiles exactly into
  child chunks.** The tool does not carry a list of container tags. It tries
  to parse each payload as a sequence of `[tag][length]` records; if every tag
  is four printable characters, every length is >= 8, and the children consume
  the payload to the last byte with nothing left over, the chunk is a
  container. Otherwise it is a leaf. `LOFF`'s payload begins `55 01 c2 01 00`,
  which is not a printable tag, so `LOFF` is a leaf on the first test.

  This is the same discipline as the index: *nine chunks that consume 9,080 of
  9,080 bytes are not a coincidence of reading.* A wrong guess about the
  header size or the endianness does not tile.

Output is a tree, a tag census, and an ownership map over every byte of the
file: how many bytes are chunk headers, how many are leaf payload, how many
are owned by nobody (gap) and how many by more than one (overlap). A container
format that closes has zero of the last two.

Usage:
  python tools/scummcont.py tree   <file> [--key 0x69] [--depth N]
  python tools/scummcont.py census <file> [--key 0x69]
  python tools/scummcont.py map    <file> [--key 0x69]
  python tools/scummcont.py dump   <file> <path> [--key 0x69] [--out F]
      path is slash-separated with 1-based sibling indices, e.g.
      LECF/LFLF#1/ROOM/RMHD
"""
import collections
import sys

TAGCHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _")


def load(path, key):
    d = open(path, "rb").read()
    if key:
        d = bytes(b ^ key for b in d)
    return d


def is_tag(b):
    return len(b) == 4 and all(c in TAGCHARS for c in b)


def tiles(data, lo, hi):
    """True if data[lo:hi] is an exact sequence of well-formed chunks."""
    if hi - lo < 8:
        return False
    p = lo
    n = 0
    while p < hi:
        if p + 8 > hi:
            return False
        if not is_tag(data[p:p + 4]):
            return False
        ln = int.from_bytes(data[p + 4:p + 8], "big")
        if ln < 8 or p + ln > hi:
            return False
        p += ln
        n += 1
    return p == hi and n > 0


class Node:
    __slots__ = ("tag", "off", "size", "kids", "idx")

    def __init__(self, tag, off, size, idx):
        self.tag, self.off, self.size, self.idx = tag, off, size, idx
        self.kids = []


def parse(data, lo, hi, depth=0):
    out = []
    p = lo
    seen = collections.Counter()
    while p < hi:
        tag = data[p:p + 4]
        ln = int.from_bytes(data[p + 4:p + 8], "big")
        seen[tag] += 1
        n = Node(tag.decode("latin-1"), p, ln, seen[tag])
        if tiles(data, p + 8, p + ln):
            n.kids = parse(data, p + 8, p + ln, depth + 1)
        out.append(n)
        p += ln
    return out


def roots(data):
    if not tiles(data, 0, len(data)):
        sys.stderr.write("top level does not tile; refusing to guess\n")
        # still parse what we can, loudly
    return parse(data, 0, len(data))


def walk(nodes):
    for n in nodes:
        yield n
        yield from walk(n.kids)


def cmd_tree(path, key, maxdepth):
    data = load(path, key)
    def rec(nodes, d):
        for n in nodes:
            if d <= maxdepth:
                print("%s%-4s off=%-10d size=%-10d %s"
                      % ("  " * d, n.tag, n.off, n.size,
                         "container(%d)" % len(n.kids) if n.kids else "leaf"))
            if n.kids:
                rec(n.kids, d + 1)
    rec(roots(data), 0)


def cmd_census(path, key):
    data = load(path, key)
    r = roots(data)
    cnt = collections.Counter()
    tot = collections.Counter()
    biggest = {}
    leaf = collections.Counter()
    for n in walk(r):
        cnt[n.tag] += 1
        tot[n.tag] += n.size
        if n.tag not in biggest or n.size > biggest[n.tag][0]:
            biggest[n.tag] = (n.size, n.off)
        if not n.kids:
            leaf[n.tag] += 1
    print("%-6s %7s %7s %14s %12s %12s" %
          ("tag", "count", "leaves", "total bytes", "largest", "at"))
    for tag in sorted(cnt, key=lambda t: -tot[t]):
        print("%-6s %7d %7d %14d %12d %12d"
              % (tag, cnt[tag], leaf[tag], tot[tag], biggest[tag][0],
                 biggest[tag][1]))
    print("\ndistinct tags %d   chunks %d   file %d"
          % (len(cnt), sum(cnt.values()), len(data)))


def cmd_map(path, key):
    data = load(path, key)
    own = bytearray(len(data))
    hdr = 0
    payload = 0
    for n in walk(roots(data)):
        for i in range(n.off, n.off + 8):
            own[i] += 1
        hdr += 8
        if not n.kids:
            payload += n.size - 8
            for i in range(n.off + 8, n.off + n.size):
                own[i] += 1
    gap = sum(1 for v in own if v == 0)
    over = sum(1 for v in own if v > 1)
    once = sum(1 for v in own if v == 1)
    print("file bytes        %d" % len(data))
    print("chunk headers     %d" % hdr)
    print("leaf payload      %d" % payload)
    print("headers+payload   %d" % (hdr + payload))
    print("owned exactly one %d" % once)
    print("owned by nobody   %d" % gap)
    print("owned by two+     %d" % over)
    if gap == 0 and over == 0 and once == len(data):
        print("\nCLOSES EXACTLY")
    else:
        print("\nDOES NOT CLOSE")
        # be loud about where
        i = 0
        shown = 0
        while i < len(own) and shown < 20:
            if own[i] != 1:
                j = i
                while j < len(own) and own[j] == own[i]:
                    j += 1
                print("  %-8s at %d..%d (%d bytes) owners=%d"
                      % ("gap" if own[i] == 0 else "overlap", i, j - 1,
                         j - i, own[i]))
                shown += 1
                i = j
            else:
                i += 1


def find(nodes, parts):
    if not parts:
        return None
    want = parts[0]
    idx = 1
    if "#" in want:
        want, s = want.split("#")
        idx = int(s)
    for n in nodes:
        if n.tag == want and n.idx == idx:
            return n if len(parts) == 1 else find(n.kids, parts[1:])
    return None


def cmd_dump(path, spec, key, out):
    data = load(path, key)
    n = find(roots(data), spec.split("/"))
    if n is None:
        sys.exit("no such chunk: %s" % spec)
    body = data[n.off + 8:n.off + n.size]
    sys.stderr.write("%s off=%d size=%d payload=%d\n"
                     % (n.tag, n.off, n.size, len(body)))
    if out:
        open(out, "wb").write(body)
    else:
        sys.stdout.write(body[:512].hex(" "))
        sys.stdout.write("\n")


def main(argv):
    key = 0x69
    out = None
    maxdepth = 99
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--key":
            key = int(argv[i + 1], 0); i += 2
        elif a == "--out":
            out = argv[i + 1]; i += 2
        elif a == "--depth":
            maxdepth = int(argv[i + 1]); i += 2
        else:
            rest.append(a); i += 1
    c = rest[0]
    if c == "tree":
        cmd_tree(rest[1], key, maxdepth)
    elif c == "census":
        cmd_census(rest[1], key)
    elif c == "map":
        cmd_map(rest[1], key)
    elif c == "dump":
        cmd_dump(rest[1], rest[2], key, out)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
