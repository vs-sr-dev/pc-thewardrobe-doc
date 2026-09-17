#!/usr/bin/env python3
"""slzx.py -- decode an FSAS `SLZX` block: LZ77 triples over INI and UTF-16
text, the wrapper LOST HORIZON's engine puts around its game text.

THIS IS NOT `slz.py`. `slz.py` reads Tales of Crestoria's SLZ (Zstandard in
chunks with a method byte, Android); the two names are one letter apart and
the two formats share nothing. Do not point either at the other.

The block, read out of the bytes on pc-losthorizon-doc
-------------------------------------------------------

    +0   "SLZX"
    +4   u32  N   the unpacked length
    +8   u32  N   the same number again (equal on 139 of 139 heads in data.spr
                  and 112 of 112 in loca.spr before this tool; the tool counts
                  again and refuses a block where they differ)
    +12  the stream: a FLAG byte, then eight tokens, bit k of the flag
         (least significant first) naming token k:
           bit clear  one literal byte
           bit set    a TRIPLE  (lo, hi, c):
                        position = lo | (hi & 7) << 8      (11 bits, into a
                                     2,048-byte window that SLIDES: absolute
                                     while fewer than 2,048 bytes are out,
                                     then pos + (out - 2,048))
                        length   = hi >> 3                 (5 bits: 0..31)
                        then the literal c is appended after the copy -- unless the
         copy itself reached N, in which case the three bytes are still
         consumed and c is dropped (seen on loca_patch.spr +56, N = 888)

That is Lempel-Ziv 1977 as published -- (offset, length, next character)
triples -- with a position into the last 2,048 bytes rather than a distance
back, and a flag byte to skip the triple for runs of literals. The
decoder stops when N bytes are out; the stream's length is whatever it took,
and that is how the block is MEASURED inside an archive that does not say
where it ends.

The closure, which is the whole warrant: the output is exactly N bytes long
AND parses as what it claims -- an INI (`[Section]` lines, `key=value`) or a
UTF-16 text behind a `FF FE` BOM. A wrong LZ decoder produces plausible text
for twenty bytes and rubbish after; the length alone would not catch it, the
parse does. The first block (data.spr +56, N = 237) decodes to the INI
`[Cursor]` with its comments, 181 stream bytes, and was checked by eye.

    python tools/slzx.py block FILE --at OFF        decode one block and print it
    python tools/slzx.py census FILE                every block found by magic
    python tools/slzx.py dump FILE DIR              write every block's text
    python tools/slzx.py selftest
"""
import argparse
import collections
import mmap
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                  # noqa: E402
import nameguard                                 # noqa: E402

nameguard.guard()

MAGIC = b"SLZX"
WINDOW = 2048


class Bad(Exception):
    pass


def decode(blob, at=0):
    """(text bytes, end offset). Raises Bad on a block that does not close."""
    if blob[at:at + 4] != MAGIC:
        raise Bad("no SLZX at %d" % at)
    if at + 12 > len(blob):
        raise Bad("head cut at %d" % at)
    n1, n2 = struct.unpack_from("<II", blob, at + 4)
    if n1 != n2:
        raise Bad("the two lengths differ: %d and %d" % (n1, n2))
    out = bytearray()
    i = at + 12
    end = len(blob)
    before_start = 0
    pad = 0
    while len(out) < n1:
        if i >= end:
            raise Bad("stream ends at %d with %d of %d bytes out" % (i, len(out), n1))
        flags = blob[i]
        i += 1
        for k in range(8):
            if len(out) >= n1:
                # THE LAST GROUP IS WRITTEN WHOLE. The encoder emits eight
                # tokens per flag byte and does not stop short: after the
                # N-th byte the unused tokens of the group are still on disk
                # (loca_patch.spr +56: six 's' after the 888th byte; data.spr
                # +56: three 't' after the 237th), and the next block begins
                # where the group ends. They are consumed by the flag bits --
                # one byte for a literal, three for a triple -- so that the
                # block's extent on disk is the block's and not a gap.
                if flags & (1 << k):
                    i += 3
                    pad += 3
                else:
                    i += 1
                    pad += 1
                continue
            if flags & (1 << k):
                if i + 3 > end:
                    raise Bad("triple cut at %d" % i)
                lo, hi, c = blob[i], blob[i + 1], blob[i + 2]
                i += 3
                pos = lo | ((hi & 7) << 8)
                ln = hi >> 3
                # THE WINDOW SLIDES, IT DOES NOT WRAP. The position indexes
                # the last WINDOW bytes of output as they stood when the
                # token was emitted: absolute while fewer than WINDOW bytes
                # are out, then `pos + (out - WINDOW)`. A ring buffer
                # (`out[pos & 2047]`) reads the same bytes below 2,048 and
                # the wrong ones above -- the first draft of this decoder
                # did that, closed on every length, and produced UTF-16
                # off by one byte from byte 2,050 of loca_patch.spr +544
                # ("r \0n\0e\0c" for "receive"). The length closure did not
                # catch it; the parse did.
                src = pos + max(0, len(out) - WINDOW)
                if ln and src >= len(out):
                    before_start += 1
                for _ in range(ln):
                    out.append(out[src] if src < len(out) else 0)
                    src += 1
                # A triple whose copy reaches N carries a literal that is NOT
                # part of the text: the encoder writes three bytes regardless
                # (loca_patch.spr +56: N = 888, the last triple's copy lands
                # on 888 and its 's' would be the 889th). The three bytes are
                # consumed, the literal is dropped.
                if len(out) < n1:
                    out.append(c)
            else:
                if i >= end:
                    raise Bad("literal cut at %d" % i)
                out.append(blob[i])
                i += 1
    if len(out) != n1:
        raise Bad("decoded %d bytes, head says %d" % (len(out), n1))
    if before_start:
        raise Bad("%d references point before the start of the output" % before_start)
    if i > end:
        raise Bad("the last group runs %d bytes past the end" % (i - end))
    return bytes(out), i


INI_LINE = re.compile(rb"^\s*(\[[^\]\r\n]+\]|[^=\r\n;#]+=.*|;.*|#.*|)\s*$")


def kind_of(text):
    """What the decoded bytes are: ('ini', sections) | ('utf16', chars) |
    ('text', None) | ('other', None)."""
    if text[:2] == b"\xff\xfe":
        try:
            s = text[2:].decode("utf-16-le")
        except UnicodeDecodeError:
            return "other", None
        if all(c.isprintable() or c in "\t\r\n" for c in s):
            return "utf16", s
        return "other", None
    if all(32 <= x < 127 or x in (9, 10, 13) for x in text):
        lines = text.split(b"\n")
        if all(INI_LINE.match(ln) for ln in lines):
            secs = re.findall(rb"^\s*\[([^\]\r\n]+)\]", text, re.M)
            if secs:
                return "ini", [s.decode("latin-1") for s in secs]
            return "text", None
        return "text", None
    if all(x >= 32 or x in (9, 10, 13) for x in text):
        return "text8", None
    return "other", None


def find_blocks(blob):
    out = []
    i = blob.find(MAGIC)
    while i >= 0:
        if i + 12 <= len(blob):
            n1, n2 = struct.unpack_from("<II", blob, i + 4)
            if n1 == n2 and n1 > 0:
                out.append(i)
        i = blob.find(MAGIC, i + 1)
    return out


def load(path):
    """The file, memory-mapped: the blocks live inside 1.6 GB archives and
    `decode` only indexes and slices."""
    dirguard.want_file(path, "slzx")
    fh = open(path, "rb")
    return mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)


def cmd_block(a):
    blob = load(a.paths[0])
    try:
        text, end = decode(blob, a.at)
    except Bad as e:
        sys.exit("slzx: %s" % e)
    n = struct.unpack_from("<I", blob, a.at + 4)[0]
    kind, extra = kind_of(text)
    print("block at %d: head says %d, decoded %d, stream ends at %d "
          "(%d bytes on disk); kind %s%s"
          % (a.at, n, len(text), end, end - a.at, kind,
             " sections %s" % extra if kind == "ini" else ""))
    print("-" * 60)
    if kind == "utf16":
        sys.stdout.write(extra)
    else:
        sys.stdout.write(text.decode("latin-1"))
    print()
    return 0


def cmd_census(a):
    blob = load(a.paths[0])
    offs = find_blocks(blob)
    kinds = collections.Counter()
    secs = collections.Counter()
    ok = bad = 0
    total_in = total_out = 0
    ends = []
    for o in offs:
        try:
            text, end = decode(blob, o)
        except Bad as e:
            bad += 1
            if a.verbose:
                print("  %d: REFUSED %s" % (o, e))
            continue
        ok += 1
        total_in += end - o
        total_out += len(text)
        ends.append((o, end))
        kind, extra = kind_of(text)
        kinds[kind] += 1
        if kind == "ini":
            for s in extra:
                secs[re.sub(r"[0-9]+$", "#", s)] += 1
        if a.verbose:
            print("  %10d  %6d -> %6d  %-6s %s" % (o, end - o, len(text), kind,
                                                  extra[:4] if kind == "ini" else
                                                  (extra[:40].replace("\r", " ").replace("\n", " ")
                                                   if kind == "utf16" else "")))
    print("%s: %d SLZX heads by magic (two equal u32); %d decoded to closure, "
          "%d refused" % (nameguard.safe(a.paths[0]), len(offs), ok, bad))
    print("bytes on disk %d -> decoded %d (x%.2f)" % (total_in, total_out,
                                                    total_out / total_in if total_in else 0))
    print("kinds: %s" % dict(kinds))
    if secs:
        print("INI sections (trailing digits folded to #): %d distinct" % len(secs))
        for s, n in secs.most_common(a.top):
            print("  %5d  [%s]" % (n, s))
    return 0


def cmd_dump(a):
    blob = load(a.paths[0])
    outdir = a.paths[1]
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for o in find_blocks(blob):
        try:
            text, end = decode(blob, o)
        except Bad:
            continue
        kind, extra = kind_of(text)
        ext = {"ini": "ini", "utf16": "txt", "text": "txt"}.get(kind, "bin")
        with open(os.path.join(outdir, "%010d.%s" % (o, ext)), "wb") as fh:
            fh.write(text)
        n += 1
    print("wrote %d blocks to %s" % (n, nameguard.safe(outdir)))
    return 0


# ----------------------------------------------------------------- selftest
def _encode_literal_run(data, pad=b"p"):
    """A stream of literals only, for the tests; the last group is written
    whole, as the encoder writes it."""
    out = bytearray()
    for i in range(0, len(data), 8):
        out.append(0)
        grp = data[i:i + 8]
        out += grp + pad * (8 - len(grp))
    return bytes(out)


def _block(text, stream=None):
    stream = _encode_literal_run(text) if stream is None else stream
    return MAGIC + struct.pack("<II", len(text), len(text)) + stream


def cmd_selftest(_a):
    checks = []
    plain = b"[Cursor]\r\nXHotSpot=13\r\n"
    blk = _block(plain)
    text, end = decode(blk)
    checks.append(("a literal-only block decodes to its text", text == plain, repr(text)))
    checks.append(("and its end is the stream's end", end == len(blk), "%d/%d" % (end, len(blk))))
    # "abcabcabcX": literals 'abc', then a triple (pos 0, len 6, 'X')
    stream = bytes([0x08]) + b"abc" + bytes([0x00, 6 << 3, ord("X")]) + b"pppp"
    blk = _block(b"abcabcabcX", stream)
    text, end = decode(blk)
    checks.append(("a triple (pos 0, len 6, 'X') copies with overlap and appends",
                   text == b"abcabcabcX", repr(text)))
    checks.append(("the flag bit is the token's index, least significant first",
                   end == len(blk), ""))
    # position bits: lo | (hi & 7) << 8 -- position 256 needs hi bit 0
    big = bytes(range(256)) * 2                       # 512 bytes of literals
    stream = _encode_literal_run(big) + bytes([0x01, 0x00, (4 << 3) | 1, ord("Z")]) + b"p" * 7
    blk = _block(big + big[256:260] + b"Z", stream)
    text, end = decode(blk)
    checks.append(("position 256 is lo=0 hi&7=1", text[-5:] == big[256:260] + b"Z", repr(text[-5:])))
    # a triple whose copy lands exactly on N: 'abc' + (pos 0, len 3, 'Q')
    stream = bytes([0x08]) + b"abc" + bytes([0x00, 3 << 3, ord("Q")]) + b"pppp"
    blk = _block(b"abcabc", stream)
    text, end = decode(blk)
    checks.append(("a triple whose copy reaches N drops its literal and still "
                   "consumes three bytes",
                   text == b"abcabc" and end == len(blk), "%r %d/%d" % (text, end, len(blk))))
    # the last group is written whole: 3 literals of text, then 5 unused
    # literal tokens ('p' x5) -- the end is after the eighth token
    blk = _block(b"xyz", bytes([0x00]) + b"xyz" + b"ppppp")
    text, end = decode(blk)
    checks.append(("the unused tokens of the last group are consumed as the block's",
                   text == b"xyz" and end == len(blk), "%r %d/%d" % (text, end, len(blk))))
    # ... and an unused TRIPLE token consumes three bytes
    blk = _block(b"xyz", bytes([0x08]) + b"xyz" + b"QQQ" + b"pppp")
    text, end = decode(blk)
    checks.append(("an unused triple token in the last group consumes three bytes",
                   text == b"xyz" and end == len(blk), "%r %d/%d" % (text, end, len(blk))))
    # past 2,048 bytes the window slides: 2,056 literals (257 full groups),
    # then a triple at pos 0 must copy out[8..] (the last 2,048 bytes begin
    # at 8), not out[0..]
    long = bytes((i * 7) & 0xFF for i in range(2056))
    stream = _encode_literal_run(long) + bytes([0x01, 0x00, 5 << 3, ord("W")]) + b"p" * 7
    blk = _block(long + long[8:13] + b"W", stream)
    text, end = decode(blk)
    checks.append(("past 2,048 bytes a position indexes the LAST 2,048 (slides, "
                   "does not wrap)",
                   text[-6:] == long[8:13] + b"W" and end == len(blk), repr(text[-6:])))
    checks.append(("two lengths that differ are REFUSED",
                   _refuses(MAGIC + struct.pack("<II", 5, 6) + _encode_literal_run(b"hello")), ""))
    checks.append(("a stream that ends before N bytes are out is REFUSED",
                   _refuses(MAGIC + struct.pack("<II", 9, 9) + _encode_literal_run(b"hello")), ""))
    checks.append(("a reference before the start of the output is REFUSED",
                   _refuses(_block(b"???X", bytes([0x01, 0x10, 3 << 3, ord("X")]) + b"p" * 7)), ""))
    checks.append(("a last group cut short is REFUSED",
                   _refuses(_block(b"xyz", bytes([0x00]) + b"xyz" + b"pp")), ""))
    checks.append(("kind_of names an INI and its sections",
                   kind_of(b"[Cursor]\r\nX=1\r\n; c\r\n[Diary]\r\n") == ("ini", ["Cursor", "Diary"]),
                   str(kind_of(b"[Cursor]\r\nX=1\r\n"))))
    checks.append(("kind_of names UTF-16 behind a BOM",
                   kind_of(b"\xff\xfe" + "Agent\r\n".encode("utf-16-le"))[0] == "utf16", ""))
    checks.append(("kind_of does not call a binary blob an INI",
                   kind_of(bytes([0, 1, 2, 200]))[0] == "other", ""))
    checks.append(("find_blocks selects by magic AND the equal pair",
                   find_blocks(b"xxSLZX\x05\x00\x00\x00\x05\x00\x00\x00" + b"SLZX\x01\x00\x00\x00\x02\x00\x00\x00")
                   == [2], ""))
    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL", note))
        failed += 0 if ok else 1
    print()
    print("%d checks, %d failures (0 skipped: the selftest builds its own blocks)"
          % (len(checks), failed))
    return 1 if failed else 0


def _refuses(blob):
    try:
        decode(blob)
    except Bad:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("selftest", "block", "census", "dump"))
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--at", type=int, default=0)
    ap.add_argument("--top", type=int, default=60)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    if a.mode == "selftest":
        return cmd_selftest(a)
    if not a.paths:
        ap.error("give a file")
    if a.mode == "dump" and len(a.paths) < 2:
        ap.error("dump wants FILE DIR")
    return {"block": cmd_block, "census": cmd_census, "dump": cmd_dump}[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
