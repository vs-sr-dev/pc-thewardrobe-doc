#!/usr/bin/env python3
"""streamread.py -- the 3DO Data Streamer container, derived from the bytes.

The platform notes carried `[deleted]` against this format for two discs:
`FILM`, `STRM`, `SNDS`, `SHDR`, `CTRL` and `MDAG` occurred zero times on the
first and once, inside an English sentence, on the second. The third disc has
555 `FILM`, 253 `SNDS`, 6 `SHDR` and 4 `CTRL`, and two files whose first four
bytes are `SHDR`. Nothing below is taken from documentation. Every field named
here is named because a measurement over this disc forced the name, and every
field that is not forced is printed as a number with no name at all.

THE CONTAINER

    +0   char[4]  type
    +4   u32      size, INCLUDING these eight bytes
    chunks are laid end to end and the last one ends at end of file

Big-endian, like every other structure on this platform.

WHAT IS FORCED, AND BY WHAT

  * `SHDR` is 244 bytes and is the first chunk of both files. Its word at +24
    reads 20,480 and **both files are an exact whole multiple of 20,480 bytes**
    (499 and 71 of them). Its word at +48 reads 3, and exactly three four-byte
    tags follow at +116: `FILM`, `SNDS`, `CTRL`. So +24 is the stream's block
    size, +48 is the number of subscriber tags, and the tags are the chunk types
    the stream will contain. All three are checked, not assumed.
  * `FILL` exists and pads: header 244 + fill 20,236 = 20,480 exactly.
  * every chunk after the header carries two more words, at +8 and +12, before
    its own payload. The one at +8 rises monotonically within a channel over
    the whole file and never falls, on both files; the one at +12 takes very
    few distinct values. Those are the properties of a timestamp and a channel
    and the tool reports both rather than asserting either.

usage:
    streamread.py validate            negative controls; must fail
    streamread.py FILE                chain it, census the chunks
    streamread.py FILE --chunks N     print the first N chunk records
    streamread.py FILE --type FILM    dump the sub-structure of one type
"""
import argparse
import collections
import struct
import sys

PRINTABLE = set(range(0x20, 0x7F))


class Bad(Exception):
    pass


def is_tag(b):
    return len(b) == 4 and all(x in PRINTABLE for x in b)


def chunks(data, limit=None):
    """Walk the chunk chain. Raises Bad rather than guessing."""
    off = 0
    n = len(data)
    out = []
    while off < n:
        if off + 8 > n:
            raise Bad("chunk header at %d runs past end of file (%d bytes left)"
                      % (off, n - off))
        tag = data[off:off + 4]
        size = struct.unpack(">I", data[off + 4:off + 8])[0]
        if not is_tag(tag):
            raise Bad("chunk at %d has a non-printable type %r" % (off, tag))
        if size < 8:
            raise Bad("chunk %r at %d declares size %d, below the 8-byte header"
                      % (tag, off, size))
        if off + size > n:
            raise Bad("chunk %r at %d declares %d bytes, only %d remain"
                      % (tag, off, size, n - off))
        out.append((off, tag, size))
        off += size
        if limit and len(out) >= limit:
            break
    return out


def validate():
    ok = True
    cases = [
        ("2,048 zero bytes", b"\0" * 2048),
        ("the string iamaduck", b"iamaduck" * 256),
        ("an AIF image", b"\xe1\xa0\x00\x00" * 4 + b"\xef\x00\x00\x11" + b"\0" * 64),
        ("a chunk that overruns", b"SHDR" + struct.pack(">I", 4096) + b"\0" * 64),
        ("a chunk of size 4", b"SHDR" + struct.pack(">I", 4)),
    ]
    for name, data in cases:
        try:
            chunks(data)
            print("FAIL: %-34s was ACCEPTED as a chunk chain" % name)
            ok = False
        except Bad as e:
            print("ok  : %-34s rejected -- %s" % (name, e))
    good = (b"SHDR" + struct.pack(">I", 16) + b"\0" * 8
            + b"FILM" + struct.pack(">I", 12) + b"\0" * 4)
    try:
        got = chunks(good)
        assert len(got) == 2, got
        assert got[1][0] + got[1][2] == len(good)
        print("ok  : %-34s accepted, %d chunks, chain ends at EOF"
              % ("positive control", len(got)))
    except (Bad, AssertionError) as e:
        print("FAIL: positive control rejected -- %s" % e)
        ok = False
    return 0 if ok else 1


def header_fields(data, off, size):
    """The SHDR chunk, printed as numbers, with the three forced names."""
    w = struct.unpack(">%dI" % (min(size, 116) // 4), data[off:off + (min(size, 116) // 4) * 4])
    tags = []
    p = off + 116
    while p + 8 <= off + size:
        t = data[p:p + 4]
        v = struct.unpack(">I", data[p + 4:p + 8])[0]
        if t == b"\0\0\0\0":
            break
        if not is_tag(t):
            break
        tags.append((t, v))
        p += 8
    return w, tags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--chunks", type=int, default=0)
    ap.add_argument("--type")
    a = ap.parse_args()
    if a.file == "validate":
        raise SystemExit(validate())

    data = open(a.file, "rb").read()
    cs = chunks(data)
    end = cs[-1][0] + cs[-1][2]
    print("file                  : %s" % a.file)
    print("bytes                 : %d" % len(data))
    print("chunks                : %d" % len(cs))
    print("chain ends at         : %d   (end of file: %s)"
          % (end, end == len(data)))

    first = cs[0]
    if first[1] != b"SHDR":
        raise Bad("first chunk is %r, not SHDR" % first[1])
    w, tags = header_fields(data, first[0], first[2])
    print()
    print("SHDR, %d bytes. Words 0..28, as numbers:" % first[2])
    for i in range(len(w)):
        note = ""
        if i == 6:
            note = "   <- reads as the stream block size"
        if i == 12:
            note = "   <- reads as the number of subscriber tags"
        print("   +%-4d 0x%08x  %10d%s" % (i * 4, w[i], w[i], note))
    print()
    print("subscriber tags at +116: %s"
          % ", ".join("%s=%d" % (t.decode("latin1"), v) for t, v in tags))
    blk = w[6]
    print()
    print("CHECK the block size: word at +24 is %d" % blk)
    print("   file %% block  = %d   (0 means the file is a whole number of blocks)"
          % (len(data) % blk if blk else -1))
    print("   file // block = %d blocks" % (len(data) // blk if blk else -1))
    print("CHECK the tag count: word at +48 is %d, tags found %d, equal %s"
          % (w[12], len(tags), w[12] == len(tags)))
    hdrblock = first[2] + (cs[1][2] if len(cs) > 1 and cs[1][1] == b"FILL" else 0)
    print("CHECK the header block: SHDR %d + FILL %d = %d, block size %d, equal %s"
          % (first[2], hdrblock - first[2], hdrblock, blk, hdrblock == blk))

    census = collections.Counter(t for _, t, _ in cs)
    bytes_by = collections.Counter()
    for _, t, s in cs:
        bytes_by[t] += s
    print()
    print("%-8s %8s %12s %8s" % ("type", "count", "bytes", "share"))
    for t, c in census.most_common():
        print("%-8s %8d %12d %7.4f %%"
              % (t.decode("latin1"), c, bytes_by[t],
                 100.0 * bytes_by[t] / len(data)))

    # the two words after the header of every non-SHDR chunk
    print()
    print("the words at +8 and +12 of every chunk that is not SHDR:")
    per = collections.defaultdict(list)
    chans = collections.defaultdict(collections.Counter)
    for off, t, s in cs:
        if t == b"SHDR" or s < 16:
            continue
        t8, t12 = struct.unpack(">2I", data[off + 8:off + 16])
        per[t].append(t8)
        chans[t][t12] += 1
    for t in sorted(per, key=lambda x: -len(per[x])):
        v = per[t]
        rises = all(v[i] <= v[i + 1] for i in range(len(v) - 1))
        print("   %-6s %5d chunks   +8 from %d to %d, never falls: %-5s   "
              "+12 takes %d value(s): %s"
              % (t.decode("latin1"), len(v), min(v), max(v), rises,
                 len(chans[t]), ", ".join(str(k) for k in sorted(chans[t]))))

    if a.chunks:
        print()
        print("the first %d chunks:" % a.chunks)
        for off, t, s in cs[:a.chunks]:
            extra = data[off + 8:off + 24]
            print("   %9d  %-6s %8d   %s"
                  % (off, t.decode("latin1"), s,
                     " ".join("%08x" % x for x in
                              struct.unpack(">4I", extra)) if len(extra) == 16 else ""))

    if a.type:
        want = a.type.encode("latin1")
        want = want + b" " * (4 - len(want))
        sel = [c for c in cs if c[1] == want]
        print()
        print("%d chunks of type %r. The first three, 64 bytes each:"
              % (len(sel), a.type))
        for off, t, s in sel[:3]:
            print("   at %d, %d bytes" % (off, s))
            for i in range(0, min(64, s), 16):
                row = data[off + i:off + i + 16]
                print("     +%-4d %-48s %s"
                      % (i, " ".join("%02x" % x for x in row),
                         "".join(chr(x) if x in PRINTABLE else "." for x in row)))
        subs = collections.Counter(data[off + 16:off + 20] for off, t, s in sel
                                   if s >= 20)
        print("   the word at +16, as four characters: %s"
              % ", ".join("%r x%d" % (k, v) for k, v in subs.most_common(8)))


if __name__ == "__main__":
    main()
