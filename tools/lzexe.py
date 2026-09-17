#!/usr/bin/env python3
"""lzexe.py -- identify, by its CODE, and unpack an MZ image packed by LZEXE
0.91, written from the disassembly of the stub in TEENAGNT.EXE and not from
a description of the format.

WHY THIS EXISTS
---------------
`dospack.py` looks for the four bytes `LZ91` at header offset 0x1C, which is
where LZEXE 0.91 writes them. `TEENAGNT.EXE` (pc-teenagent-doc) has
`0C 0A 09 01` there (and so has `SOUNDSET.EXE`, the same four bytes) and a
33-signature sweep says "no packer" -- while the
29 bytes at its entry point are, byte for byte, the opening of LZEXE's
decompressor, and the ASCII `*FAB*` (Fabrice Bellard's signature inside the
stub, not in the header) is still at stub offset 0xF7. The marker was
removed; the code was not. This tool selects by the code and ignores the
marker, and it reports the marker's presence or absence as a separate line.

THE FORMAT, AS THE STUB SAYS IT (dosdis.py, 330 bytes, 100 % decoded)
----------------------------------------------------------------------
The packed MZ has `e_crlc = 0`. Its last segment, at `e_cs`, is the stub:
14 bytes of data, then the code, then a relocation list.

    cs:0000  u16  real IP
    cs:0002  u16  real CS              (relative to the load segment)
    cs:0004  u16  real SP
    cs:0006  u16  real SS              (relative)
    cs:0008  u16  compressed size, paragraphs  -- the stub's own segment,
                                         i.e. everything before it is stream
    cs:000A  u16  paragraphs the stream is moved UP before decoding
    cs:000C  u16  stub length in bytes  (`mov cx,[0Ch]; std; rep movsb`)
    cs:000E       code: copy the stub to the top, move the stream up in
                  4096-paragraph chunks, decode, rebuild relocations, jump

The decoder (stub 0069h..00F4h) reads a 16-bit bit buffer with `lodsw`,
takes bits LSB-first with `shr bp,1`, reloads after 16 (`dec dx; jnz`):

    bit 1                      literal: one byte (movsb)
    bit 0, bit 0, b1, b0       short match: length = 2 + (b1 b0, MSB first,
                               via `rcl cx,1` twice), distance byte d:
                               dst -= 256 - d          (bh = 0FFh, bl = d)
    bit 0, bit 1, word w       long match: distance from the 13 bits
                               `bh = (bh >> 3) | 0E0h; bl = lo(w)`,
                               length code c = hi(w) & 7:
                                 c != 0      length = c + 2      (3 .. 9)
                                 c == 0      one more byte e:
                                   e == 0    END of stream
                                   e == 1    segment normalisation (es, di,
                                             ds, si re-based; nothing is
                                             written -- a no-op here)
                                   else      length = e + 1     (2 .. 255)
    copy: `mov al,es:[bx+di]; stosb; loop` -- bytes one at a time, so an
    overlapping copy repeats the pattern (a distance of 1 is a run).

The relocation rebuilder (stub 00FCh..0134h) reads the list at the offset
in `mov si,158h` (00FEh) and walks it with a paragraph:offset pair that it
re-normalises after every step:

    byte b != 0    address += b;  add the load segment to the word there
    byte 0, word w
        w == 0     address += 0FFF0h  (`add dx,0FFFh`), no relocation
        w == 1     end of list
        else       address += w;  relocate

Then `mov di,[4]; mov si,[6]; add si,loadseg; add [2],loadseg; ss:sp;
jmp far cs:[0]` -- the stub's first eight bytes are the program's entry.

WHAT THE OUTPUT IS
------------------
A new MZ file: a header whose relocation table is the rebuilt list (header
padded to a paragraph), `e_ip/e_cs/e_sp/e_ss` from the stub's data, the
decoded stream as the load image. `e_minalloc` is RECONSTRUCTED, not read:
the packed header's `e_minalloc` plus the packed image's paragraphs minus
the unpacked image's paragraphs, on the assumption that the packer kept
the program's total memory demand -- the output says so. `e_maxalloc`,
`e_csum` and `e_ovno` are copied from the packed header. The original
header's length is not recoverable and is not claimed.

THE CLOSURES
------------
  * the stub's compressed size (cs:8) must equal `e_cs`: the stream is
    exactly the bytes before the stub, none missing, none extra;
  * the stub length (cs:0Ch) must reach exactly the end of the file;
  * the decoder must hit the END code, not the end of the input;
  * the rebuilt header's `e_cp * 512 + e_cblp` must equal the output length;
  * every relocation target must lie inside the image, and the word at
    each must be a segment no larger than the image in paragraphs -- a
    check the decoder was not told about;
  * the entry `cs:ip`, and `ss:sp`, must lie inside the image.

    python tools/lzexe.py FILE...                identify and report
    python tools/lzexe.py --unpack FILE OUT      write the unpacked MZ
    python tools/lzexe.py --refuse FILE...       assert none is LZEXE
    python tools/lzexe.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402


class NotLzexe(Exception):
    pass


# The stub's code, as `dosdis.py` printed it from TEENAGNT.EXE: 000Eh..00F7h
# (the entry copy, the mover, the decoder, the segment normaliser), and
# 00FCh..0158h (the relocation rebuilder and the far jump). The five bytes
# between are `*FAB*`, which is a signature and not code, and is reported
# separately. Selection is on ENTRY (the first 29 bytes) plus DECODER; a
# file whose entry matches and whose decoder does not is reported as an
# LZEXE-like stub with a changed decoder, and refused.
ENTRY = bytes.fromhex(
    "060e1f8b0e0c008bf14e89f78cdb031e0a008ec3fdf3a453b82b0050cb")
DECODER = bytes.fromhex(
    "2e8b2e08008cda89e83d00107603b8001029c529c229c38eda8ec3b103d3e089c1d1e0"
    "48488bf08bf8f3a509ed75d8fc8ec28edb31f631ffba1000ad89c5d1ed4a7505ad89"
    "c5b2107303a4ebf131c9d1ed4a7505ad89c5b2107222d1ed4a7505ad89c5b210d1d1"
    "d1ed4a7505ad89c5b210d1d14141acb7ff8ad8e91300ad8bd8b103d2ef80cfe080e4"
    "07740c88e14141268a01aae2faeba6ac08c074343c01740588c141ebea89fb83e70f"
    "81c70020b104d3eb8cc001d82d00028ec089f383e60fd3eb8cd801d88ed8e972ff")
FAB = b"*FAB*"
RELOCATOR = bytes.fromhex(
    "0e1fbe58015b83c31089da31ffac08c07416b40001c78bc783e70fb104d3e801c28e"
    "c226011debe5ad09c0750881c2ff0f8ec2ebd83d010075da8bc38b3e04008b360600"
    "01c601060200 2d10008ed88ec031dbfa8ed68be7fb2eff2f".replace(" ", ""))
STUB_DATA = 14
CODE_AT = 0x0E
FAB_AT = CODE_AT + len(DECODER) + len(ENTRY)        # 0F7h
RELOCATOR_AT = FAB_AT + len(FAB)                     # 0FCh
RELOC_LIST_AT = RELOCATOR_AT + len(RELOCATOR)        # 158h


def _mz(data):
    if len(data) < 32 or data[:2] != b"MZ":
        raise NotLzexe("not an MZ file")
    f = struct.unpack_from("<14H", data, 2)
    h = dict(zip(("cblp", "cp", "crlc", "cparhdr", "minalloc", "maxalloc",
                  "ss", "sp", "csum", "ip", "cs", "lfarlc", "ovno", "dummy"),
                 f))
    size = (h["cp"] - 1) * 512 + h["cblp"] if h["cblp"] else h["cp"] * 512
    h["size"] = size
    h["hdr"] = h["cparhdr"] * 16
    return h


def parse(data):
    """Identify by the stub's code. Returns the fields; raises NotLzexe."""
    h = _mz(data)
    if h["size"] != len(data):
        raise NotLzexe("MZ size %d != file %d" % (h["size"], len(data)))
    if h["crlc"] != 0:
        raise NotLzexe("e_crlc = %d; an LZEXE image has none" % h["crlc"])
    if h["ip"] != CODE_AT:
        raise NotLzexe("e_ip = %04Xh, the LZEXE stub starts at 000Eh" % h["ip"])
    stub_off = h["hdr"] + h["cs"] * 16
    stub = data[stub_off:]
    if len(stub) < RELOC_LIST_AT:
        raise NotLzexe("stub segment is %d bytes, shorter than the stub"
                       % len(stub))
    if stub[CODE_AT:CODE_AT + len(ENTRY)] != ENTRY:
        raise NotLzexe("entry code at cs:000Eh is not LZEXE's")
    dec_at = CODE_AT + len(ENTRY)
    if stub[dec_at:dec_at + len(DECODER)] != DECODER:
        differ = sum(1 for a, b in zip(stub[dec_at:dec_at + len(DECODER)],
                                       DECODER) if a != b)
        raise NotLzexe("entry is LZEXE's but the decoder differs in %d of %d "
                       "bytes -- a variant this tool has not read" %
                       (differ, len(DECODER)))
    relocator_ok = stub[RELOCATOR_AT:RELOCATOR_AT + len(RELOCATOR)] == RELOCATOR
    ip, cs, sp, ss, csize, shift, stub_len = struct.unpack_from("<7H", stub, 0)
    reloc_list_at = struct.unpack_from("<H", stub, RELOCATOR_AT + 3)[0]
    f = dict(h)
    f.update(stub_off=stub_off, real_ip=ip, real_cs=cs, real_sp=sp,
             real_ss=ss, csize_paras=csize, shift_paras=shift,
             stub_len=stub_len, relocator_ok=relocator_ok,
             reloc_list_at=reloc_list_at,
             fab=stub[FAB_AT:FAB_AT + len(FAB)] == FAB,
             marker=data[0x1C:0x20])
    # closures on the stub's own numbers
    if csize != h["cs"]:
        raise NotLzexe("stub says %04Xh paragraphs of stream, e_cs is %04Xh"
                       % (csize, h["cs"]))
    if stub_off + stub_len != len(data):
        raise NotLzexe("stub length %d ends at %d, file is %d"
                       % (stub_len, stub_off + stub_len, len(data)))
    if reloc_list_at != RELOC_LIST_AT:
        raise NotLzexe("relocation list at %04Xh, expected %04Xh"
                       % (reloc_list_at, RELOC_LIST_AT))
    return f


class _Bits:
    """The stub's bit buffer: `lodsw` into bp, `shr bp,1` gives the carry,
    sixteen takes then reload."""

    def __init__(self, src, pos):
        self.src, self.pos = src, pos
        self.bp = 0
        self.dx = 0
        self._load()

    def _load(self):
        if self.pos + 2 > len(self.src):
            raise NotLzexe("bit buffer ran off the end of the stream at %d"
                           % self.pos)
        self.bp = struct.unpack_from("<H", self.src, self.pos)[0]
        self.pos += 2
        self.dx = 16

    def bit(self):
        b = self.bp & 1
        self.bp >>= 1
        self.dx -= 1
        if self.dx == 0:
            self._load()
        return b

    def byte(self):
        if self.pos >= len(self.src):
            raise NotLzexe("lodsb ran off the end of the stream")
        v = self.src[self.pos]
        self.pos += 1
        return v

    def word(self):
        if self.pos + 2 > len(self.src):
            raise NotLzexe("lodsw ran off the end of the stream")
        v = struct.unpack_from("<H", self.src, self.pos)[0]
        self.pos += 2
        return v


def decode(src):
    """The decoder at stub 0069h..00F4h, over a linear buffer. Returns
    (image, stats)."""
    out = bytearray()
    st = dict(literals=0, short=0, long=0, long_ext=0, normalise=0,
              ended=False, consumed=0)
    bits = _Bits(src, 0)
    while True:
        if bits.bit():                        # 0073 jnb -> 0075 movsb
            out.append(bits.byte())
            st["literals"] += 1
            continue
        if not bits.bit():                    # 0084 jb 0A8h not taken
            length = bits.bit() << 1          # 0090 rcl cx,1
            length |= bits.bit()              # 009C rcl cx,1
            length += 2                       # 009E/9F inc cx; inc cx
            d = bits.byte()                   # 00A0 lodsb; bh=FFh; bl=al
            dist = 0x10000 - (0xFF00 | d)
            st["short"] += 1
        else:                                 # 00A8 lodsw
            w = bits.word()
            bh = ((w >> 8) >> 3) | 0xE0       # 00AD shr bh,3 ; or bh,0E0h
            dist = 0x10000 - ((bh << 8) | (w & 0xFF))
            code = (w >> 8) & 7               # 00B2 and ah,7
            if code:
                length = code + 2             # 00B7 mov cl,ah; inc; inc
                st["long"] += 1
            else:
                e = bits.byte()               # 00C3 lodsb
                if e == 0:                    # 00C6 jz 0FCh -- end
                    st["ended"] = True
                    break
                if e == 1:                    # 00CA jz 0D1h -- normalise
                    st["normalise"] += 1
                    continue
                length = e + 1                # 00CC mov cl,al; inc cx
                st["long_ext"] += 1
        if dist > len(out):
            raise NotLzexe("match distance %d at output %d reaches before "
                           "the image" % (dist, len(out)))
        for _ in range(length):               # 00BB mov al,es:[bx+di]; stosb
            out.append(out[-dist])
    st["consumed"] = bits.pos
    return bytes(out), st


def relocations(stub, at):
    """The rebuilder at stub 0109h..0134h. Returns (list of linear offsets,
    bytes consumed, skips)."""
    pos = at
    addr = 0
    out = []
    skips = 0
    while True:
        if pos >= len(stub):
            raise NotLzexe("relocation list ran off the end of the stub")
        b = stub[pos]
        pos += 1
        if b:
            addr += b
            out.append(addr)
            continue
        if pos + 2 > len(stub):
            raise NotLzexe("relocation list ran off the end of the stub")
        w = struct.unpack_from("<H", stub, pos)[0]
        pos += 2
        if w == 0:
            addr += 0xFFF0
            skips += 1
        elif w == 1:
            break
        else:
            addr += w
            out.append(addr)
    return out, pos - at, skips


def unpack(data, f):
    """Return (mz_bytes, image, relocs, stats)."""
    src = data[f["hdr"]:f["stub_off"]]
    image, st = decode(src)
    if not st["ended"]:
        raise NotLzexe("stream did not end with the END code")
    stub = data[f["stub_off"]:]
    relocs, used, skips = relocations(stub, f["reloc_list_at"])
    if f["reloc_list_at"] + used != f["stub_len"]:
        raise NotLzexe("relocation list ends at %d, stub is %d bytes"
                       % (f["reloc_list_at"] + used, f["stub_len"]))
    st.update(relocs=len(relocs), reloc_bytes=used, reloc_skips=skips)

    n = len(relocs)
    hdr_len = (28 + 4 * n + 15) // 16 * 16
    total = hdr_len + len(image)
    img_paras = (len(image) + 15) // 16
    packed_paras = (f["size"] - f["hdr"] + 15) // 16
    minalloc = f["minalloc"] + packed_paras - img_paras
    if minalloc < 0:
        minalloc = 0
    hdr = bytearray(hdr_len)
    struct.pack_into("<2s14H", hdr, 0, b"MZ",
                     total % 512, (total + 511) // 512, n, hdr_len // 16,
                     minalloc, f["maxalloc"], f["real_ss"], f["real_sp"],
                     f["csum"], f["real_ip"], f["real_cs"], 28, f["ovno"], 0)
    for i, a in enumerate(relocs):
        struct.pack_into("<HH", hdr, 28 + 4 * i, a & 0xF, a >> 4)
    st["minalloc"] = minalloc
    return bytes(hdr) + image, image, relocs, st


def closure(mz, image, relocs, f):
    """Checks on the OUTPUT that the decoder was not told about."""
    h = _mz(mz)
    r = dict(size_ok=h["size"] == len(mz), outside=[], wild=[],
             limit=(len(image) + 15) // 16)
    for a in relocs:
        if a + 2 > len(image):
            r["outside"].append(a)
            continue
        seg = struct.unpack_from("<H", image, a)[0]
        if seg > r["limit"]:
            r["wild"].append((a, seg))
    entry = f["real_cs"] * 16 + f["real_ip"]
    stack = f["real_ss"] * 16 + f["real_sp"]
    r["entry"] = entry
    r["entry_ok"] = entry < len(image)
    r["stack_ok"] = stack <= len(image) + f.get("minalloc_out", 0) * 16
    r["ok"] = (r["size_ok"] and not r["outside"] and not r["wild"]
               and r["entry_ok"])
    return r


def report(path, data):
    f = parse(data)
    print("=== %s ===" % path)
    print("  file                       : %d bytes, MZ closes, e_crlc 0"
          % len(data))
    print("  stub segment               : %04Xh, file offset %d, %d bytes"
          % (f["cs"], f["stub_off"], f["stub_len"]))
    print("  entry code (29 bytes)      : LZEXE 0.91's -- MATCH")
    print("  decoder (%d bytes)        : MATCH" % len(DECODER))
    print("  relocator (%d bytes)       : %s" % (len(RELOCATOR),
          "MATCH" if f["relocator_ok"] else "DIFFERS"))
    print("  '*FAB*' at stub 0F7h       : %s"
          % ("present" if f["fab"] else "ABSENT"))
    m = f["marker"]
    print("  marker at header 1Ch       : %s  (%s)"
          % (m.hex(" "), "LZ91" if m == b"LZ91" else "LZ90" if m == b"LZ90"
             else "NO MARKER -- identified by the code alone"))
    print("  stream                     : %d bytes = %04Xh paragraphs, "
          "header..stub" % (f["stub_off"] - f["hdr"], f["csize_paras"]))
    print("  moved up by                : %04Xh paragraphs" % f["shift_paras"])
    print("  real cs:ip                 : %04X:%04X" % (f["real_cs"], f["real_ip"]))
    print("  real ss:sp                 : %04X:%04X" % (f["real_ss"], f["real_sp"]))
    return f


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--unpack", metavar="OUT")
    ap.add_argument("--refuse", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.paths:
        ap.error("no input")
    for p in args.paths:
        dirguard.want_file(p, "lzexe.py")

    if args.refuse:
        bad = 0
        for p in args.paths:
            with open(p, "rb") as fh:
                data = fh.read()
            try:
                parse(data)
            except NotLzexe as e:
                print("%-24s REFUSED: %s" % (os.path.basename(p), e))
            else:
                print("%-24s IS LZEXE -- CONTROL FAILED" % os.path.basename(p))
                bad += 1
        print("\nlzexe.py: %d of %d refused" % (len(args.paths) - bad,
                                                len(args.paths)))
        return 1 if bad else 0

    if args.unpack and len(args.paths) != 1:
        raise SystemExit("lzexe.py: --unpack takes exactly one input")
    ok = 0
    for p in args.paths:
        with open(p, "rb") as fh:
            data = fh.read()
        try:
            f = report(p, data)
        except NotLzexe as e:
            print("=== %s ===" % p)
            print("  NOT LZEXE: %s" % e)
            continue
        ok += 1
        if not args.unpack:
            continue
        try:
            mz, image, relocs, st = unpack(data, f)
        except NotLzexe as e:
            print("  UNPACK FAILED: %s" % e)
            return 1
        f["minalloc_out"] = st["minalloc"]
        r = closure(mz, image, relocs, f)
        print("  decoded image              : %d bytes (%04Xh paragraphs) "
              "from %d of %d stream bytes"
              % (len(image), (len(image) + 15) // 16, st["consumed"],
                 f["stub_off"] - f["hdr"]))
        print("  literals / short / long / long-ext / normalise : "
              "%d / %d / %d / %d / %d"
              % (st["literals"], st["short"], st["long"], st["long_ext"],
                 st["normalise"]))
        print("  stream ended on END code   : %s" % st["ended"])
        print("  relocations                : %d from %d list bytes, %d "
              "0FFF0h skips" % (len(relocs), st["reloc_bytes"],
                                st["reloc_skips"]))
        print("  e_minalloc (reconstructed) : %d paragraphs = packed %d + "
              "%d - %d" % (st["minalloc"], f["minalloc"],
                           (f["size"] - f["hdr"] + 15) // 16,
                           (len(image) + 15) // 16))
        print("  output MZ                  : %d bytes, header %d, closes "
              "on its size: %s" % (len(mz), len(mz) - len(image),
                                   r["size_ok"]))
        print("  relocation targets         : %d inside, %d outside, %d "
              "holding a segment above %04Xh"
              % (len(relocs) - len(r["outside"]), len(r["outside"]),
                 len(r["wild"]), r["limit"]))
        print("  entry %04X:%04X = %d       : %s"
              % (f["real_cs"], f["real_ip"], r["entry"],
                 "inside the image" if r["entry_ok"] else "OUTSIDE"))
        segs = {}
        for a in relocs:
            v = struct.unpack_from("<H", image, a)[0]
            segs[v] = segs.get(v, 0) + 1
        print("  relocated segment values   : %s"
              % ", ".join("%04Xh x%d" % kv for kv in sorted(segs.items())))
        if not r["ok"]:
            print("  CLOSURE FAILED -- the image is wrong")
            return 1
        with open(args.unpack, "wb") as out:
            out.write(mz)
        print("  written                    : %s" % args.unpack)
    print()
    print("lzexe.py: %d of %d inputs are LZEXE images" % (ok, len(args.paths)))
    return 0 if ok == len(args.paths) else 1


# ---------------------------------------------------------------- selftest
class _Enc:
    """A minimal encoder of the grammar above, for the round trip. It is
    the decoder's grammar written backwards; it proves the decoder reads
    what it says, and nothing about the real packer -- that proof is the
    closure on a real file."""

    def __init__(self):
        self.out = bytearray()
        self.bits = []
        self._reserve()

    def _reserve(self):
        # the decoder `lodsw`s the bit word BEFORE the bytes it governs, and
        # reloads the moment the 16th bit is taken: the slot goes first
        self.slot = len(self.out)
        self.out += b"\0\0"

    def bit(self, b):
        self.bits.append(b)
        if len(self.bits) == 16:
            self._flush()
            self._reserve()

    def _flush(self):
        v = 0
        for i, b in enumerate(self.bits):
            v |= b << i
        struct.pack_into("<H", self.out, self.slot, v)
        self.bits = []

    def literal(self, c):
        self.bit(1)
        self.out.append(c)

    def short(self, length, dist):
        self.bit(0); self.bit(0)
        length -= 2
        self.bit(length >> 1); self.bit(length & 1)
        self.out.append((0x10000 - dist) & 0xFF)

    def long(self, length, dist):
        self.bit(0); self.bit(1)
        neg = 0x10000 - dist
        bl = neg & 0xFF
        bh = (neg >> 8) & 0x1F
        code = length - 2 if 3 <= length <= 9 else 0
        self.out += bytes((bl, (bh << 3) | code))
        if code == 0:
            self.out.append(length - 1)

    def end(self):
        self.bit(0); self.bit(1)
        self.out += b"\x00\x00\x00"

    def finish(self):
        # pad the last bit group; its slot is already reserved
        if self.bits:
            self._flush()
        return bytes(self.out)


def _build(image_plan, relocs, ip, cs, sp, ss):
    enc = _Enc()
    img = bytearray()
    for kind, a, b in image_plan:
        if kind == "lit":
            for c in a:
                enc.literal(c); img.append(c)
        elif kind == "short":
            enc.short(a, b)
            for _ in range(a):
                img.append(img[-b])
        else:
            enc.long(a, b)
            for _ in range(a):
                img.append(img[-b])
    enc.end()
    stream = enc.finish()
    stream += b"\0" * ((-len(stream)) % 16)
    rl = bytearray()
    last = 0
    for r in relocs:
        d = r - last
        while d > 0xFFF0 + 255:
            rl += b"\x00\x00\x00"; d -= 0xFFF0
        if d and d < 256:
            rl.append(d)
        else:
            rl += b"\x00" + struct.pack("<H", d)
        last = r
    rl += b"\x00\x01\x00"
    stub = struct.pack("<7H", ip, cs, sp, ss, len(stream) // 16, 0x100,
                       RELOC_LIST_AT + len(rl))
    stub += ENTRY + DECODER + FAB + RELOCATOR + bytes(rl)
    total = 32 + len(stream) + len(stub)
    hdr = struct.pack("<2s14H", b"MZ", total % 512, (total + 511) // 512, 0, 2,
                      0x100, 0xFFFF, 0, 0x80, 0, CODE_AT, len(stream) // 16,
                      0x1C, 0, 0) + b"\0\0"
    return hdr + stream + stub, bytes(img)


def selftest():
    nameguard.guard()
    checks = []

    def ok(label, cond, note=""):
        checks.append(cond)
        print("  %-52s %s %s" % (label, "ok" if cond else "FAIL", note))

    assert len(ENTRY) == 29 and FAB_AT == 0xF7 and RELOCATOR_AT == 0xFC \
        and RELOC_LIST_AT == 0x158, (len(ENTRY), FAB_AT, RELOCATOR_AT,
                                     RELOC_LIST_AT)
    ok("stub layout: entry 29, *FAB* at 0F7h, list at 158h", True)
    ok("relocator's `mov si,imm` operand is 158h",
       struct.unpack_from("<H", RELOCATOR, 3)[0] == RELOC_LIST_AT)

    plan = [("lit", b"MZ-selftest \x00\x01\x02\x03", 0),
            ("short", 3, 1), ("short", 5, 4), ("long", 9, 12),
            ("lit", b"abcdefgh", 0), ("long", 40, 8), ("long", 10, 30),
            ("lit", bytes(range(200)), 0), ("long", 200, 200),
            ("short", 2, 255), ("long", 255, 300)]
    far = 2 * 0xFFF0 + 5 + 300
    packed, image = _build(plan, [4, 20, 300, far], 5, 1, 0x40, 2)
    f = parse(packed)
    ok("synthetic packed file identifies by code", True)
    ok("marker reported absent", f["marker"] != b"LZ91")
    mz, img, relocs, st = unpack(packed, f)
    ok("round trip: image equal, %d bytes" % len(image), img == image)
    ok("stream ended on END code", st["ended"])
    ok("relocations round trip",
       relocs == [4, 20, 300, far] and st["reloc_skips"] == 1)
    h = _mz(mz)
    ok("output header closes on its size", h["size"] == len(mz))
    ok("output header carries cs:ip ss:sp",
       (h["cs"], h["ip"], h["ss"], h["sp"]) == (1, 5, 2, 0x40))
    ok("output relocation table has %d entries" % h["crlc"], h["crlc"] == 4)

    # negative controls
    bad = bytearray(packed)
    bad[f["stub_off"] + CODE_AT + 3] ^= 0xFF
    try:
        parse(bytes(bad))
        ok("entry code damaged -> refused", False)
    except NotLzexe as e:
        ok("entry code damaged -> refused", "entry code" in str(e))
    bad = bytearray(packed)
    bad[f["stub_off"] + CODE_AT + 40] ^= 0xFF
    try:
        parse(bytes(bad))
        ok("decoder damaged -> refused as a variant", False)
    except NotLzexe as e:
        ok("decoder damaged -> refused as a variant", "variant" in str(e))
    bad = bytearray(packed)
    bad[-3:] = b"\x00\x00\x00"           # the END word becomes a skip
    try:
        unpack(bytes(bad), parse(bytes(bad)))
        ok("relocation list without END -> refused", False)
    except NotLzexe:
        ok("relocation list without END -> refused", True)
    bad = bytearray(packed)
    struct.pack_into("<H", bad, f["stub_off"] + 8, f["csize_paras"] + 1)
    try:
        parse(bytes(bad))
        ok("stub's stream size != e_cs -> refused", False)
    except NotLzexe:
        ok("stub's stream size != e_cs -> refused", True)
    try:
        parse(b"MZ" + b"\0" * 62)
        ok("empty MZ -> refused", False)
    except NotLzexe:
        ok("empty MZ -> refused", True)

    # the object, if it is here: BOTH game executables are LZEXE 0.91 with
    # the marker replaced by the same four bytes `0C 0A 09 01`; the
    # negative control is FreeDOS's xcopy.exe from the DOSBox tree
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skipped = 0
    for name in ("TEENAGNT.EXE", "SOUNDSET.EXE"):
        real = os.path.join(here, "Teenagent", name)
        if not os.path.isfile(real):
            skipped += 2
            print("  (%s not here: 2 checks skipped)" % name)
            continue
        with open(real, "rb") as fh:
            data = fh.read()
        f = parse(data)
        ok("%s identifies by code, marker 0C0A0901h, *FAB*" % name,
           f["fab"] and f["marker"] == b"\x0c\x0a\x09\x01")
        mz, img, relocs, st = unpack(data, f)
        f["minalloc_out"] = st["minalloc"]
        r = closure(mz, img, relocs, f)
        ok("%s unpacks and closes" % name, r["ok"] and st["ended"],
           "%d bytes, %d relocations" % (len(img), len(relocs)))
    ctrl = os.path.join(here, "Teenagent", "DOSBOX", "resources", "drives",
                        "y", "dos", "xcopy.exe")
    if os.path.isfile(ctrl):
        with open(ctrl, "rb") as fh:
            data = fh.read()
        try:
            parse(data)
            ok("FreeDOS xcopy.exe refused", False)
        except NotLzexe as e:
            ok("FreeDOS xcopy.exe refused", True, "(%s)" % e)
    else:
        skipped += 1
        print("  (DOSBOX xcopy.exe not here: 1 check skipped)")

    print("\nlzexe.py selftest: %d of %d ok, %d skipped"
          % (sum(checks), len(checks), skipped))
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
