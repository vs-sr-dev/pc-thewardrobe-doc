#!/usr/bin/env python3
"""comunpack.py -- unpack a .COM whose stub is the one read in CRACK.COM of
Polanie (dosdis.py, 015Fh..01FFh, 96 instructions), written from that
listing and not from a packer's name -- the stub carries none.

THE STUB, AS IT READS
---------------------
    0100  jmp 015Fh
    015F  es = cs + 1000h; copy 6D60h words from cs:0100 to es:0100;
          retf into the copy at 0177h
    0177  ds = the copy, es = the original segment; si = 0200h, di = 0100h;
          call the decoder (0197h); clear the registers; retf to es:0100
    0199  getbit: every 16 bits `lodsw` into bp; the bit is bp's top bit
          (`add bp,bp` -> carry), dl counts them
    01A8  gamma:  cx = 0; do { bit -> rcl cx,1 } while (next bit == 1);
          cx += 1                                      (values 1, 2, 3 ...)
    01B6  main:   u16 at si (skipped, never used by the decoder); then
          bit 0        literal run:  n = gamma; copy n bytes from si
          bit 1        n = gamma
              n != 1   match: bit 0 -> 8-bit distance, bit 1 -> 16-bit;
                       copy n bytes from di - distance (overlap repeats)
              n == 1   m = gamma
                  m != 1   fill: one byte, written m times
                  m == 1   END

Bits are taken MSB-first out of 16-bit little-endian words, so the stream
is words, not bytes; a gamma value is read two bits at a time (data bit,
continue bit). The packed payload starts at file offset 0100h (= 0200h in
memory); the 91 bytes between the jump and its target (0103h..015Eh) are
the crack's own resident code, not the packer's, and are kept as they are.

    python tools/comunpack.py FILE OUT        unpack; the output is the
                                              .COM as it runs at 0100h
    python tools/comunpack.py --selftest
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

STUB = bytes.fromhex(
    "8cc80500108ec0bf00018bf7fcb9606df3a506b8770150cb1e061f07be0002bf0001"
    "0657e8110033c08bd88bc88bd08bf08bf88be8061fcbeb1d80e20f750550ad8be858"
    "fec203edc333c9e8ecffd1d1e8e7ff72f641c332d28b0446465057fce8d7ff7207"
    "e8e1fff3a4ebf4e8daff83f9017419e8c3ff720532e4aceb01ad1e56061f8bf72bf0"
    "f3a45e1febd3e8b9ff83f9017405acf3aaebc6588bcf2bc858c3")
STUB_AT = 0x15F
PAYLOAD_AT = 0x200


class Refused(Exception):
    pass


class _Bits:
    def __init__(self, src, pos):
        self.src = src
        self.pos = pos
        self.bp = 0
        self.n = 0

    def bit(self):
        if self.n == 0:
            if self.pos + 2 > len(self.src):
                raise Refused("ran off the packed stream at %d" % self.pos)
            self.bp = struct.unpack_from("<H", self.src, self.pos)[0]
            self.pos += 2
            self.n = 16
        self.n -= 1
        b = (self.bp >> 15) & 1
        self.bp = (self.bp << 1) & 0xFFFF
        return b

    def gamma(self):
        cx = 0
        while True:
            cx = ((cx << 1) | self.bit()) & 0xFFFF
            if self.bit() == 0:
                break
        return cx + 1

    def byte(self):
        if self.pos >= len(self.src):
            raise Refused("ran off the packed stream at %d" % self.pos)
        v = self.src[self.pos]
        self.pos += 1
        return v

    def word(self):
        if self.pos + 2 > len(self.src):
            raise Refused("ran off the packed stream at %d" % self.pos)
        v = struct.unpack_from("<H", self.src, self.pos)[0]
        self.pos += 2
        return v


def decode(src, pos):
    """Return (output bytes, stats)."""
    r = _Bits(src, pos)
    r.word()                                 # the u16 the stub skips
    out = bytearray()
    st = dict(literals=0, matches=0, fills=0, lit_bytes=0, match_bytes=0,
              fill_bytes=0, max_dist=0)
    while True:
        if r.bit() == 0:
            n = r.gamma()
            for _ in range(n):
                out.append(r.byte())
            st["literals"] += 1
            st["lit_bytes"] += n
            continue
        n = r.gamma()
        if n != 1:
            dist = r.word() if r.bit() else r.byte()
            if dist == 0 or dist > len(out):
                raise Refused("match distance %d with %d bytes written"
                              % (dist, len(out)))
            for _ in range(n):
                out.append(out[-dist])
            st["matches"] += 1
            st["match_bytes"] += n
            st["max_dist"] = max(st["max_dist"], dist)
            continue
        m = r.gamma()
        if m == 1:
            break
        v = r.byte()
        out += bytes([v]) * m
        st["fills"] += 1
        st["fill_bytes"] += m
    st["consumed"] = r.pos - pos
    st["bits_left"] = r.n
    return bytes(out), st


def parse(data):
    if len(data) < PAYLOAD_AT - 0x100 + 4:
        raise Refused("shorter than the stub")
    if data[0] != 0xE9 or struct.unpack_from("<H", data, 1)[0] != STUB_AT - 0x103:
        raise Refused("does not start with `jmp %04Xh`" % STUB_AT)
    got = data[STUB_AT - 0x100:STUB_AT - 0x100 + len(STUB)]
    if got != STUB:
        differ = sum(1 for a, b in zip(got, STUB) if a != b)
        raise Refused("stub at %04Xh differs in %d of %d bytes"
                      % (STUB_AT, differ, len(STUB)))
    return dict(payload=PAYLOAD_AT - 0x100, resident=data[3:STUB_AT - 0x100])


def pairs(image):
    """CRACK.COM's payload, once unpacked, holds a table of strings each
    ended by F0h: a Polish string from SLAVS.EXE followed by its English
    replacement, space-padded to the SAME length (the TSR overwrites in
    place). Returns [(polish, english)] and the number of odd runs."""
    runs = []
    i = image.find(b"\xf0")
    start = image.rfind(b"\0", 0, i) + 1
    p = start
    while True:
        q = image.find(b"\xf0", p)
        if q < 0:
            break
        run = image[p:q]
        if not run or any(b < 0x20 for b in run):
            break
        runs.append(run.decode("latin-1"))
        p = q + 1
    out = [(runs[k], runs[k + 1]) for k in range(0, len(runs) - 1, 2)]
    return out, len(runs) % 2, start


def cmd_pairs(path):
    data = open(path, "rb").read()
    f = parse(data)
    out, st = decode(data, f["payload"])
    table, odd, start = pairs(out)
    same = sum(1 for a, b in table if len(a) == len(b))
    print("%s: %d string pairs from unpacked offset %04Xh, %d with equal "
          "lengths, %d odd run(s)" % (os.path.basename(path), len(table),
                                      start + 0x100, same, odd))
    for a, b in table:
        print("  %-36r -> %r" % (a, b))
    return 0


def main(argv=None):
    nameguard.guard()
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--selftest":
        return selftest()
    if len(argv) == 2 and argv[0] == "--pairs":
        dirguard.want_file(argv[1], "comunpack.py")
        return cmd_pairs(argv[1])
    if len(argv) != 2:
        print(__doc__)
        return 2
    dirguard.want_file(argv[0], "comunpack.py")
    data = open(argv[0], "rb").read()
    try:
        f = parse(data)
        out, st = decode(data, f["payload"])
    except Refused as e:
        print("comunpack.py: REFUSED: %s" % e)
        return 1
    print("%s: %d bytes, stub matches at %04Xh, payload at file %d"
          % (os.path.basename(argv[0]), len(data), STUB_AT, f["payload"]))
    print("  unpacked                 : %d bytes from %d of %d payload bytes, "
          "%d bits unread"
          % (len(out), st["consumed"], len(data) - f["payload"], st["bits_left"]))
    print("  literal runs / matches / fills : %d / %d / %d  (%d / %d / %d bytes), "
          "farthest match %d"
          % (st["literals"], st["matches"], st["fills"], st["lit_bytes"],
             st["match_bytes"], st["fill_bytes"], st["max_dist"]))
    print("  resident code 0103h..%04Xh : %d bytes, kept in the output at the "
          "same place" % (STUB_AT - 1, len(f["resident"])))
    with open(argv[1], "wb") as fh:
        fh.write(out)
    print("  written                  : %s" % argv[1])
    return 0


# ---------------------------------------------------------------- selftest
class _Writer:
    def __init__(self):
        self.words = []
        self.acc = 0
        self.n = 0
        self.bytes_after = {}
        self.stream = bytearray()

    def _flush_word(self):
        self.stream += struct.pack("<H", self.acc)
        self.acc = 0
        self.n = 0

    def bit(self, b):
        if self.n == 0:
            self.word_at = len(self.stream)
            self.stream += b"\0\0"
        self.acc = (self.acc << 1) | b
        self.n += 1
        if self.n == 16:
            struct.pack_into("<H", self.stream, self.word_at, self.acc)
            self.acc = 0
            self.n = 0

    def gamma(self, v):
        assert v >= 1
        v -= 1
        bits = bin(v)[2:] if v else "0"
        for i, ch in enumerate(bits):
            self.bit(int(ch))
            self.bit(1 if i < len(bits) - 1 else 0)

    def raw(self, b):
        self.stream += b

    def finish(self):
        if self.n:
            self.acc <<= (16 - self.n)
            struct.pack_into("<H", self.stream, self.word_at, self.acc)
        return bytes(self.stream)


def _encode(plan):
    w = _Writer()
    w.raw(b"\0\0")
    out = bytearray()
    for tok in plan:
        if tok[0] == "lit":
            w.bit(0)
            w.gamma(len(tok[1]))
            w.raw(tok[1])
            out += tok[1]
        elif tok[0] == "match":
            n, dist = tok[1], tok[2]
            w.bit(1)
            w.gamma(n)
            if dist > 255:
                w.bit(1)
                w.raw(struct.pack("<H", dist))
            else:
                w.bit(0)
                w.raw(bytes([dist]))
            for _ in range(n):
                out.append(out[-dist])
        elif tok[0] == "fill":
            m, v = tok[1], tok[2]
            w.bit(1)
            w.gamma(1)
            w.gamma(m)
            w.raw(bytes([v]))
            out += bytes([v]) * m
    w.bit(1)
    w.gamma(1)
    w.gamma(1)
    return w.finish(), bytes(out)


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-56s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    plan = [("lit", b"COM-selftest"), ("match", 4, 4), ("fill", 300, 0x90),
            ("lit", bytes(range(200))), ("match", 2, 1), ("match", 50, 300),
            ("match", 7, 512), ("lit", b"end")]
    packed, image = _encode(plan)
    out, st = decode(packed, 0)
    check("round trip through the stub's grammar, %d bytes" % len(image), out == image)
    check("literal / match / fill counts", (st["literals"], st["matches"], st["fills"]) == (3, 4, 1))
    check("16-bit distance taken", st["max_dist"] == 512)
    com = b"\xe9\x5c\x00" + bytes(STUB_AT - 0x103) + STUB
    com += bytes(PAYLOAD_AT - 0x100 - len(com)) + packed
    f = parse(com)
    out, st = decode(com, f["payload"])
    check("a built .COM with the stub parses and unpacks", out == image)
    bad = bytearray(com)
    bad[STUB_AT - 0x100 + 10] ^= 1
    try:
        parse(bytes(bad))
        check("stub damaged -> refused", False)
    except Refused as e:
        check("stub damaged -> refused", "differs in 1" in str(e))
    try:
        decode(packed[:-6], 0)
        check("truncated stream -> refused", False)
    except Refused:
        check("truncated stream -> refused", True)
    print("\ncomunpack.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
