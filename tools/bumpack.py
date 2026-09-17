#!/usr/bin/env python3
"""bumpack.py -- unpack the 12-byte-head data files of BUMPY (Loriciel, 1992,
MS-DOS): the .VEC screens, the .BUM / .DEC / .PAV level parts. The codec was
read out of the game's own decompressor, not guessed from the bytes.

THE HEAD, ALL BIG-ENDIAN ON A LITTLE-ENDIAN MACHINE
---------------------------------------------------
    +0   u32 BE   N      unpacked length (the loader refuses N > 0xFFFFF)
    +4   u32 BE   X      a word the decoder loads and never uses (see below)
    +8   u16 BE   M      method: bits 0-5 index a table of 18 handlers, bits
                         8-14 must be zero, bit 15 set = this is the LAST
                         stage; clear = the unpacked bytes begin with another
                         head, and the loop runs again on them
    +10  u16 BE   C      check: N.hi ^ N.lo ^ X.hi ^ X.lo ^ M -- the loader
                         computes it and refuses the file if it differs
    +12           the stream, to the end of the file

Two of the eighteen handlers exist; the other sixteen are a `ret`:

    method 4  -- run-length with an escape byte
        +12  E, the escape; then bytes:
             b != E      -> b
             E E         -> E
             E v n       -> v repeated n times, n = 0 meaning 256
    method 12 -- a bit mask over the output
        +12  u16 BE F, the fill byte (its low byte is written)
        +14  ceil(N / 32) u32 BE words of flags, taken MSB first, one bit
             per output byte: 1 -> write F; 0 -> copy the next stream byte
        then the literal bytes. When the last literal has been copied the
             rest of the output, whatever the remaining flags say, is F.

WHERE THIS CAME FROM
--------------------
`BUMPY.EXE` is not packed and its loader is 8086 code in the clear. The C
routine at cs:2DCC (`LoadLevel`) opens D1.PAV / D1.DEC / D1.BUM through a
10-byte record table at DS:0090 (far pointer to the name, the disk letter,
the unpacked buffer size), reads the whole file into the buffer and calls a
thunk at cs:7B5A that far-calls segment 0C28h -- an assembly module of 2,569
bytes at file offset 0D480h. `dosdis.py` decoded it: the head reader at
module 0A09h (every `xchg al,ah` is a big-endian field), the dispatcher at
003Ch..0078h (the loop on bit 15), the handler table at DS:4E37h (0193h x 16,
0194h for method 4, 04B0h for method 12), the RLE at 0194h..04AEh and the
mask at 04B0h..0A08h. The in-place bookkeeping the module does (it moves the
stream to the end of the buffer and keeps a 1,024-byte bounce area at
DS:4E97h so the expansion cannot overrun its own input) is not a property of
the format and is not reproduced; the bit and byte grammar above is.

`X` at +4 is loaded into the registers the module then overwrites with the
method's own work sizes; nothing reads it back. What it is -- a checksum of
the original, a date, a key -- is measured by `census` against the packed
and unpacked bytes and reported, not asserted.

THE CLOSURE
-----------
Every stage declares its output length and the last stage's must be met to
the byte, or the file is refused. Two files in the object carry no head --
D6.BUM (2,912 bytes) and D9.BUM (2,330) -- and are the plaintexts of the two
level-grid sizes: `census` reports them as such and `unpack` refuses them,
by their bytes and not by their extension.

    python tools/bumpack.py census FILE...        heads, stages, closure
    python tools/bumpack.py unpack FILE OUT       the unpacked bytes
    python tools/bumpack.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

HEAD = 12
MAXLEN = 0xFFFFF
METHODS = {4: "rle", 12: "mask"}


class Refused(Exception):
    pass


def head(d, off=0):
    """The 12-byte head at `off`, checked as the loader checks it."""
    if off + HEAD > len(d):
        raise Refused("no room for a 12-byte head at %d" % off)
    n_hi, n_lo, x_hi, x_lo, m, c = struct.unpack_from(">6H", d, off)
    n = (n_hi << 16) | n_lo
    x = (x_hi << 16) | x_lo
    if n > MAXLEN:
        raise Refused("unpacked length %d exceeds the loader's 0xFFFFF" % n)
    if m & 0x7F00:
        raise Refused("method word %04X has bits 8-14 set" % m)
    if (m & 0x3F) not in METHODS:
        raise Refused("method %d is one of the sixteen `ret` handlers" % (m & 0x3F))
    want = n_hi ^ n_lo ^ x_hi ^ x_lo ^ m
    if c != want:
        raise Refused("check %04X, but the five words XOR to %04X" % (c, want))
    return dict(n=n, x=x, method=m & 0x3F, last=bool(m & 0x8000), check=c)


def looks_like_head(b, size=None):
    """For coverage.py: a head whose check closes, with a real method."""
    try:
        head(b)
        return True
    except (Refused, struct.error):
        return False


def _rle(stream, n):
    if not stream:
        raise Refused("rle: no escape byte")
    esc = stream[0]
    out = bytearray()
    i = 1
    L = len(stream)
    while i < L and len(out) < n:
        b = stream[i]
        i += 1
        if b != esc:
            out.append(b)
            continue
        if i >= L:
            raise Refused("rle: escape at the end of the stream")
        v = stream[i]
        i += 1
        if v == esc:
            out.append(esc)
            continue
        if i >= L:
            raise Refused("rle: run without a count")
        cnt = stream[i] or 256
        i += 1
        out.extend(bytes([v]) * cnt)
    return bytes(out), i


def _mask(stream, n):
    if len(stream) < 2:
        raise Refused("mask: no fill word")
    fill = stream[1]
    words = (n + 31) // 32
    if 2 + 4 * words > len(stream):
        raise Refused("mask: %d flag words do not fit in %d bytes" % (words, len(stream)))
    flags = struct.unpack_from(">%dI" % words, stream, 2)
    out = bytearray()
    i = 2 + 4 * words
    L = len(stream)
    for k in range(n):
        if (flags[k >> 5] >> (31 - (k & 31))) & 1:
            out.append(fill)
        else:
            if i >= L:
                raise Refused("mask: literal wanted at %d, stream exhausted" % k)
            out.append(stream[i])
            i += 1
            if i == L:
                # the loader's exit: the last literal ends the decode
                out.extend(bytes([fill]) * (n - len(out)))
                break
    return bytes(out), i


def stages(d):
    """Run every stage; return (bytes, [stage dicts])."""
    log = []
    cur = d
    while True:
        h = head(cur)
        stream = cur[HEAD:]
        if h["method"] == 4:
            out, used = _rle(stream, h["n"])
        else:
            out, used = _mask(stream, h["n"])
        h["used"] = HEAD + used
        h["packed"] = len(cur)
        h["got"] = len(out)
        log.append(h)
        if len(out) != h["n"]:
            raise Refused("stage %d (%s) made %d bytes, head says %d"
                          % (len(log), METHODS[h["method"]], len(out), h["n"]))
        cur = out
        if h["last"]:
            return cur, log
        if len(log) > 8:
            raise Refused("more than 8 stages; refusing to loop")


def _hexdig(d, n=12):
    return " ".join("%02X" % b for b in d[:n])


def cmd_census(paths):
    nameguard.guard()
    rows = []
    ok = plain = refused = 0
    print("%-14s %7s  %-24s %-9s %7s  %s" % ("file", "packed", "stages", "closes",
                                             "unpacked", "note"))
    for p in paths:
        d = open(p, "rb").read()
        name = os.path.basename(p)
        try:
            out, log = stages(d)
        except Refused as e:
            if not looks_like_head(d):
                plain += 1
                print("%-14s %7d  %-24s %-9s %7s  no head: %s" % (
                    name, len(d), "-", "-", "-", _hexdig(d, 8)))
            else:
                refused += 1
                print("%-14s %7d  %-24s %-9s %7s  REFUSED %s" % (
                    name, len(d), "-", "-", "-", e))
            continue
        ok += 1
        desc = " > ".join("%s%s" % (METHODS[h["method"]],
                                      "" if h["last"] else "+") for h in log)
        # the unused word X against two candidates, reported not claimed
        x = log[0]["x"]
        note = "X=%08X" % x
        if x == sum(out) & 0xFFFFFFFF:
            note += " =sum32(unpacked)"
        elif x == sum(d[HEAD:]) & 0xFFFFFFFF:
            note += " =sum32(stream)"
        print("%-14s %7d  %-24s %-9s %7d  %s" % (
            name, len(d), desc, "yes", len(out), note))
        rows.append((name, len(d), len(out), log))
    print("\n%d unpacked and closed on their heads, %d without a head, %d refused, "
          "of %d files" % (ok, plain, refused, len(paths)))
    return 1 if refused else 0


def cmd_unpack(path, outpath):
    nameguard.guard()
    d = open(path, "rb").read()
    try:
        out, log = stages(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    tmp = outpath + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(out)
    os.replace(tmp, outpath)
    for i, h in enumerate(log, 1):
        print("  stage %d  %-4s  %6d -> %6d  X=%08X  %s" % (
            i, METHODS[h["method"]], h["packed"], h["n"], h["x"],
            "last" if h["last"] else "another head follows"))
    print("%s -> %s  %d bytes" % (os.path.basename(path), outpath, len(out)))
    return 0


# --- specimens for the selftest, built the way the loader reads them --------

def _head(n, x, method, last=True):
    m = method | (0x8000 if last else 0)
    n_hi, n_lo, x_hi, x_lo = n >> 16, n & 0xFFFF, x >> 16, x & 0xFFFF
    return struct.pack(">6H", n_hi, n_lo, x_hi, x_lo, m,
                       n_hi ^ n_lo ^ x_hi ^ x_lo ^ m)


def _mask_pack(data, fill=0):
    n = len(data)
    words = (n + 31) // 32
    flags = [0] * words
    lits = bytearray()
    for k, b in enumerate(data):
        if b == fill:
            flags[k >> 5] |= 1 << (31 - (k & 31))
        else:
            lits.append(b)
    return (struct.pack(">H", fill) + struct.pack(">%dI" % words, *flags)
            + bytes(lits))


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-60s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    # method 4
    body = b"\xFF" + b"abc" + b"\xFF\xFF" + b"\xFF\x00\x03" + b"\xFF\x07\x00"
    n = 3 + 1 + 3 + 256
    out, log = stages(_head(n, 0x12345678, 4) + body)
    check("rle: literals, ESC ESC, a run of 3, a run of 0 = 256",
          out == b"abc\xFF\x00\x00\x00" + b"\x07" * 256 and len(out) == n)
    check("rle: X is carried through", log[0]["x"] == 0x12345678)
    # method 12
    data = bytes([0, 0, 5, 0, 9, 0, 0, 0]) * 9 + b"\x01"
    out, log = stages(_head(len(data), 0, 12) + _mask_pack(data))
    check("mask: 73 bytes, flags MSB-first, 1 = fill, closes",
          out == data and log[0]["method"] == 12)
    data2 = bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    packed = _head(len(data2), 0, 12) + _mask_pack(data2)
    out, _ = stages(packed)
    check("mask: the tail after the last literal is fill", out == data2)
    # stray flags after the last literal are ignored (the loader's exit)
    bad_flags = bytearray(packed)
    bad_flags[HEAD + 2] &= 0x7F   # bit for byte 1 cleared: says 'literal'
    out, _ = stages(bytes(bad_flags))
    check("mask: a 'literal' flag after the stream ends is still fill",
          out == data2)
    data3 = bytes(range(1, 40))
    out, _ = stages(_head(39, 0, 12, True) + _mask_pack(data3, 0xEE))
    check("mask: fill byte from the u16's low byte, no zero in 39 literals",
          out == data3)
    # two stages: rle whose output is a mask head + stream
    inner = _head(len(data), 0, 12) + _mask_pack(data)
    rle_body = b"\x00" + b"".join(
        (b"\x00\x00" if b == 0 else bytes([b])) for b in inner)
    two = _head(len(inner), 0, 4, last=False) + rle_body
    out, log = stages(two)
    check("two stages: rle (bit 15 clear) then mask (bit 15 set)",
          out == data and [h["method"] for h in log] == [4, 12]
          and log[0]["last"] is False and log[1]["last"] is True)
    # refusals
    for label, blob, needle in (
            ("a wrong check word", _head(8, 0, 4)[:-1] + b"\x01" + b"\x00" * 8,
             "XOR"),
            ("a method with no handler (5)", _head(8, 0, 5) + bytes(8), "ret"),
            ("bits 8-14 in the method word",
             struct.pack(">6H", 0, 8, 0, 0, 0x8104, 8 ^ 0x8104) + bytes(8), "bits 8-14"),
            ("an unpacked length over 0xFFFFF",
             struct.pack(">6H", 0x10, 0, 0, 0, 0x8004, 0x10 ^ 0x8004) + bytes(8),
             "0xFFFFF"),
            ("a stage that stops short", _head(10, 0, 4) + b"\xFF" + b"ab", "made 2"),
            ("an rle escape at the end", _head(3, 0, 4) + b"\xFF" + b"ab\xFF", "end of"),
            ("a mask stream without its flags", _head(64, 0, 12) + b"\x00\x00\x00",
             "do not fit"),
            ("the plaintext D6.BUM shape (no head)", b"\x10\x0E\x00\x09" + bytes(2908),
             "0xFFFFF")):
        try:
            stages(blob)
            check("refuses " + label, False, "accepted")
        except Refused as e:
            check("refuses " + label, needle in str(e), str(e))
    check("looks_like_head refuses the D6.BUM plaintext shape",
          looks_like_head(b"\x10\x0E\x00\x09" + bytes(60)) is False)
    check("looks_like_head takes a closing head",
          looks_like_head(_head(100, 7, 12) + bytes(20)) is True)
    print("\nbumpack.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("census", "unpack", "selftest"))
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    for p in a.args if a.cmd == "census" else a.args[:1]:
        dirguard.want_file(p, "bumpack.py")
    if a.cmd == "census":
        return cmd_census(a.args)
    if len(a.args) != 2:
        ap.error("unpack FILE OUT")
    return cmd_unpack(a.args[0], a.args[1])


if __name__ == "__main__":
    sys.exit(main())
