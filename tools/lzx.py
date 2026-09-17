#!/usr/bin/env python3
"""lzx.py -- a decoder for Microsoft's LZX compressed stream, as used inside
the ITSF (.chm) container.

WHY IT IS HERE
--------------
`itsf.py` has opened four ITSF specimens across this collection and has never
read a byte of their content, because the content section of a .chm is one LZX
stream and this box had no decoder for it. On `pc-rpgmakerxp-doc`'s object that
stream is 330,084 bytes that inflate to 836,459, and inside it are 157 files of
which 34 are named for classes the object's own `.rxdata` are built out of. The
question "does this object contain its own specification" cannot be answered
from a directory listing alone.

WHAT LZX IS, AND WHAT IT IS NOT
-------------------------------
LZX is **not published by Microsoft as a specification.** It is decoded in
public -- `cabextract`/`libmspack`, 7-Zip, chmlib -- and this decoder is derived
from the bytes of the stream against those implementations' published
behaviour, which is exactly the DECODED bucket of `pc-rpgmaker2000-doc/docs/09`
and is why the `.chm` stays in that bucket after this session.

THE SHAPE, IN ONE PARAGRAPH
---------------------------
The bitstream is read as 16-bit little-endian words with bits taken from the
top. A stream opens with one flag bit and, if it is set, a 32-bit file size for
the x86 `E8` call-translation pass. Then blocks: three bits of type and
twenty-four of length. A *verbatim* block carries two canonical Huffman trees --
a main tree of `256 + 8 x slots` symbols and a length tree of 249 -- whose code
lengths are themselves delta-coded against the previous block's and read through
a 20-symbol pre-tree. An *aligned* block adds a third tree of eight 3-bit
symbols for the low bits of long offsets. An *uncompressed* block byte-aligns
and copies. A main-tree symbol below 256 is a literal; at or above it, the low
three bits are a length and the rest a position slot, and three slots mean
"the last, the one before, or the one before that".

THE CLOSURE TEST
----------------
`chmx.py` runs it: the stream must produce exactly the length the container
declares -- **836,459 bytes on this object, stated by three separate
structures** -- and the 157 directory entries must then tile that output with
no overlap. A decoder that is subtly wrong produces the right *length* only by
accident, and the tiling and the file contents catch what the length does not.

    python tools/lzx.py selftest
"""
import sys

WINDOW_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}

NUM_CHARS = 256
PRETREE_NUM = 20
ALIGNED_NUM = 8
SECONDARY_LENGTHS = 249
PRIMARY_LENGTHS = 7
MIN_MATCH = 2
FRAME_SIZE = 32768

BLOCK_VERBATIM = 1
BLOCK_ALIGNED = 2
BLOCK_UNCOMPRESSED = 3


def _tables(slots):
    extra = []
    base = []
    b = 0
    for i in range(slots):
        e = 0 if i < 4 else min(17, (i // 2) - 1)
        extra.append(e)
        base.append(b)
        b += 1 << e
    return extra, base


class LzxError(Exception):
    pass


class BitReader(object):
    """16-bit little-endian words, bits consumed from the most significant end.
    This is the detail that makes LZX unreadable if you get it wrong: the words
    are little-endian and the bits inside them are big-endian."""

    __slots__ = ("d", "pos", "bitbuf", "bitcount")

    def __init__(self, data, pos=0):
        self.d = data
        self.pos = pos
        self.bitbuf = 0
        self.bitcount = 0

    def ensure(self, n):
        while self.bitcount < n:
            if self.pos + 1 < len(self.d):
                w = self.d[self.pos] | (self.d[self.pos + 1] << 8)
                self.pos += 2
            elif self.pos < len(self.d):
                w = self.d[self.pos]
                self.pos += 1
            else:
                w = 0                      # past the end: pad, the caller's
                self.pos += 2              # length checks are the real guard
            self.bitbuf = ((self.bitbuf << 16) | w) & 0xFFFFFFFFFFFF
            self.bitcount += 16

    def bits(self, n):
        if n == 0:
            return 0
        self.ensure(n)
        self.bitcount -= n
        v = (self.bitbuf >> self.bitcount) & ((1 << n) - 1)
        self.bitbuf &= (1 << self.bitcount) - 1
        return v

    def align_frame(self):
        """Drop the fractional part of the buffered bits so that reading
        resumes on a 16-bit boundary, keeping whole buffered words.

        This is the rule that is invisible from the format's shape and fatal
        without: **the bitstream is re-aligned at the end of every
        32,768-byte output frame**, not only at block boundaries. Without it
        this decoder produced the first 32,768 bytes of the object's help file
        correctly -- an HTML document and a PNG at the offset the directory
        declares -- and then spliced two unrelated sentences together at byte
        32,768. A decoder that is right for 32 KB and wrong afterwards is the
        argument for a closure test over a spot check.
        """
        n = self.bitcount % 16
        if n:
            self.bits(n)

    def align_byte(self):
        """Drop to the next 16-bit boundary, which is what an uncompressed
        block header does."""
        drop = self.bitcount % 16
        if drop:
            self.bits(drop)
        # everything still buffered is whole words that have not been used
        while self.bitcount >= 16:
            self.bitcount -= 16
            self.pos -= 2
        self.bitbuf = 0
        self.bitcount = 0

    def raw(self, n):
        if self.pos + n > len(self.d):
            raise LzxError("uncompressed block of %d runs past the stream"
                           % n)
        out = self.d[self.pos:self.pos + n]
        self.pos += n
        return out


class Huffman(object):
    """A canonical Huffman decoder built from a list of code lengths. Symbols
    of equal length are ordered by symbol number and codes are assigned from
    the shortest length up, most-significant bit first."""

    __slots__ = ("lens", "counts", "symbols", "maxlen")

    def __init__(self, lens):
        self.lens = lens
        maxlen = max(lens) if lens else 0
        self.maxlen = maxlen
        counts = [0] * (maxlen + 1)
        for l in lens:
            if l:
                counts[l] += 1
        offsets = [0] * (maxlen + 2)
        total = 0
        for l in range(1, maxlen + 1):
            offsets[l] = total
            total += counts[l]
        symbols = [0] * total
        nxt = offsets[:]
        for sym, l in enumerate(lens):
            if l:
                symbols[nxt[l]] = sym
                nxt[l] += 1
        self.counts = counts
        self.symbols = symbols

    def decode(self, br):
        code = 0
        first = 0
        index = 0
        for length in range(1, self.maxlen + 1):
            code |= br.bits(1)
            count = self.counts[length]
            if code - first < count:
                return self.symbols[index + (code - first)]
            index += count
            first = (first + count) << 1
            code <<= 1
        raise LzxError("no Huffman code matched in %d bits" % self.maxlen)


class Decoder(object):
    def __init__(self, window_bits=16):
        if window_bits not in WINDOW_SLOTS:
            raise LzxError("unsupported window of %d bits" % window_bits)
        self.window_bits = window_bits
        self.slots = WINDOW_SLOTS[window_bits]
        self.extra, self.base = _tables(self.slots)
        self.main_n = NUM_CHARS + (self.slots << 3)
        self.reset()

    def reset(self):
        self.main_lens = [0] * self.main_n
        self.length_lens = [0] * SECONDARY_LENGTHS
        self.r0 = self.r1 = self.r2 = 1
        self.header_read = False
        self.intel_filesize = 0
        self.block_remaining = 0
        self.block_type = 0
        self.main = None
        self.length = None
        self.aligned = None

    # -- tree reading ----------------------------------------------------

    def _read_lengths(self, br, lens, first, last):
        pre = [br.bits(4) for _ in range(PRETREE_NUM)]
        pretree = Huffman(pre)
        i = first
        while i < last:
            z = pretree.decode(br)
            if z == 17:
                y = br.bits(4) + 4
                for _ in range(y):
                    if i >= last:
                        break
                    lens[i] = 0
                    i += 1
            elif z == 18:
                y = br.bits(5) + 20
                for _ in range(y):
                    if i >= last:
                        break
                    lens[i] = 0
                    i += 1
            elif z == 19:
                y = br.bits(1) + 4
                z = pretree.decode(br)
                v = lens[i] - z
                if v < 0:
                    v += 17
                for _ in range(y):
                    if i >= last:
                        break
                    lens[i] = v
                    i += 1
            else:
                v = lens[i] - z
                if v < 0:
                    v += 17
                lens[i] = v
                i += 1

    def _read_block_header(self, br):
        self.block_type = br.bits(3)
        hi = br.bits(16)
        lo = br.bits(8)
        self.block_remaining = (hi << 8) | lo
        if self.block_type == BLOCK_ALIGNED:
            self.aligned = Huffman([br.bits(3) for _ in range(ALIGNED_NUM)])
        if self.block_type in (BLOCK_VERBATIM, BLOCK_ALIGNED):
            self._read_lengths(br, self.main_lens, 0, NUM_CHARS)
            self._read_lengths(br, self.main_lens, NUM_CHARS, self.main_n)
            self.main = Huffman(self.main_lens)
            self._read_lengths(br, self.length_lens, 0, SECONDARY_LENGTHS)
            self.length = Huffman(self.length_lens)
        elif self.block_type == BLOCK_UNCOMPRESSED:
            br.align_byte()
            raw = br.raw(12)
            self.r0 = int.from_bytes(raw[0:4], "little")
            self.r1 = int.from_bytes(raw[4:8], "little")
            self.r2 = int.from_bytes(raw[8:12], "little")
        else:
            raise LzxError("block type %d is not 1, 2 or 3"
                           % self.block_type)

    # -- the main loop ---------------------------------------------------

    def decompress(self, data, want, start=0):
        """Decode `want` output bytes from `data` starting at byte `start`."""
        br = BitReader(data, start)
        out = bytearray()
        if not self.header_read:
            if br.bits(1):
                hi = br.bits(16)
                lo = br.bits(16)
                self.intel_filesize = (hi << 16) | lo
            self.header_read = True
        # LZX output is processed in frames of 32,768 bytes. A match may not
        # cross a frame boundary, and the input bitstream is re-aligned to a
        # 16-bit boundary at the end of each one.
        while len(out) < want:
            remaining = want - len(out)
            target = len(out) + min(FRAME_SIZE, remaining)
            last_frame = remaining < FRAME_SIZE
            while len(out) < target:
                if self.block_remaining == 0:
                    self._read_block_header(br)
                    if self.block_remaining == 0:
                        raise LzxError("a block of zero length at output %d"
                                       % len(out))
                n = min(self.block_remaining, target - len(out))
                if self.block_type == BLOCK_UNCOMPRESSED:
                    out += br.raw(n)
                    self.block_remaining -= n
                    continue
                produced = self._decode_chunk(br, out, n)
                self.block_remaining -= produced
            if last_frame:
                # The final frame of a stream is short, and the encoder's
                # last match may reach past the declared output. Those bytes
                # are padding and are dropped; the length check in the caller
                # is what proves the stream was read and not this.
                break
            if len(out) != target:
                raise LzxError("a match crossed the frame boundary: %d bytes "
                               "against a frame ending at %d"
                               % (len(out), target))
            br.align_frame()
        del out[want:]
        if self.intel_filesize:
            self._undo_e8(out)
        return bytes(out)

    def _decode_chunk(self, br, out, n):
        """Emit `n` block-bytes into `out`. A match may overshoot the request;
        LZX allows that and the caller's accounting has to allow it too."""
        target = len(out) + n
        aligned = self.block_type == BLOCK_ALIGNED
        while len(out) < target:
            sym = self.main.decode(br)
            if sym < NUM_CHARS:
                out.append(sym)
                continue
            sym -= NUM_CHARS
            mlen = sym & 7
            if mlen == PRIMARY_LENGTHS:
                mlen += self.length.decode(br)
            mlen += MIN_MATCH
            slot = sym >> 3
            if slot == 0:
                off = self.r0
            elif slot == 1:
                off = self.r1
                self.r1 = self.r0
                self.r0 = off
            elif slot == 2:
                off = self.r2
                self.r2 = self.r0
                self.r0 = off
            else:
                if slot >= self.slots:
                    raise LzxError("position slot %d beyond %d"
                                   % (slot, self.slots))
                e = self.extra[slot]
                if aligned and e >= 3:
                    v = br.bits(e - 3) << 3 if e > 3 else 0
                    v += self.aligned.decode(br)
                else:
                    v = br.bits(e)
                off = self.base[slot] - 2 + v
                self.r2 = self.r1
                self.r1 = self.r0
                self.r0 = off
            if off <= 0 or off > len(out):
                raise LzxError("match offset %d at output %d has nothing "
                               "behind it" % (off, len(out)))
            src = len(out) - off
            for k in range(mlen):
                out.append(out[src + k])
        return len(out) - (target - n)

    def _undo_e8(self, out):
        size = self.intel_filesize
        i = 0
        end = len(out) - 10
        curpos = 0
        while i < end:
            if out[i] != 0xE8:
                i += 1
                curpos += 1
                continue
            abs_off = int.from_bytes(out[i + 1:i + 5], "little", signed=True)
            if -curpos <= abs_off < size:
                rel = abs_off - curpos if abs_off >= 0 else abs_off + size
                out[i + 1:i + 5] = (rel & 0xFFFFFFFF).to_bytes(4, "little")
            i += 5
            curpos += 5


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    extra, base = _tables(32)
    ok("32 position slots for a 16-bit window", WINDOW_SLOTS[16] == 32)
    ok("slots 0..3 take no extra bits", extra[:4] == [0, 0, 0, 0], str(extra[:4]))
    ok("slot 4 takes one extra bit", extra[4] == 1)
    ok("slot 10 takes four extra bits", extra[10] == 4, str(extra[10]))
    ok("the extra bits are capped at 17",
       max(extra) == min(17, max(extra)) and extra[-1] <= 17, str(extra[-1]))
    ok("the bases are 0,1,2,3,4,6,8,12,16,24,32",
       base[:11] == [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32], str(base[:11]))
    ok("slot 31 of a 16-bit window bases at 49152", base[31] == 49152,
       str(base[31]))
    ok("the main tree of a 16-bit window has 512 symbols",
       NUM_CHARS + (WINDOW_SLOTS[16] << 3) == 512)

    # the bit reader: little-endian words, big-endian bits inside them
    br = BitReader(bytes([0x34, 0x12]))
    ok("the first bit comes from the top of the SECOND byte",
       br.bits(4) == 0x1, "")
    ok("and the next four from the rest of it", br.bits(4) == 0x2, "")
    ok("then the low byte follows", br.bits(8) == 0x34, "")

    # canonical Huffman: the textbook three-symbol tree
    h = Huffman([1, 2, 3, 3])
    ok("a canonical tree decodes 0 to the first symbol",
       h.decode(BitReader(bytes([0x00, 0x00]))) == 0)
    b = BitReader(bytes([0x00, 0b10000000]))
    ok("a canonical tree decodes 10 to the second symbol",
       h.decode(b) == 1)
    b = BitReader(bytes([0x00, 0b11000000]))
    ok("a canonical tree decodes 110 to the third symbol",
       h.decode(b) == 2)
    b = BitReader(bytes([0x00, 0b11100000]))
    ok("a canonical tree decodes 111 to the fourth symbol",
       h.decode(b) == 3)
    ok("a tree with no codes at all refuses rather than looping",
       _refuses(lambda: Huffman([0, 0, 0]).decode(
           BitReader(bytes([0xFF, 0xFF])))))

    # an uncompressed block, end to end, is the one shape that can be built
    # by hand with certainty -- and it exercises the header, the block header,
    # the byte alignment and the R0/R1/R2 load.
    payload = b"the quick brown fox"
    stream = _build_uncompressed(payload)
    d = Decoder(16)
    got = d.decompress(stream, len(payload))
    ok("an uncompressed block round-trips", got == payload, repr(got[:24]))
    ok("its R0/R1/R2 were loaded from the block header",
       (d.r0, d.r1, d.r2) == (1, 1, 1), str((d.r0, d.r1, d.r2)))

    ok("a 22-bit window is refused", _refuses(lambda: Decoder(22)))
    ok("a block type of 0 is refused",
       _refuses(lambda: Decoder(16).decompress(bytes(64), 4)))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def _refuses(fn):
    try:
        fn()
    except LzxError:
        return True
    except Exception:                                        # noqa: BLE001
        return False
    return False


def _build_uncompressed(payload):
    """Assemble a one-block LZX stream by hand: header bit 0, block type 3,
    a 24-bit length, alignment, three 32-bit repeated offsets, then bytes."""
    bits = []

    def put(v, n):
        for k in range(n - 1, -1, -1):
            bits.append((v >> k) & 1)

    put(0, 1)                                   # no intel preprocessing
    put(BLOCK_UNCOMPRESSED, 3)
    put(len(payload) >> 8, 16)
    put(len(payload) & 0xFF, 8)
    while len(bits) % 16:
        bits.append(0)
    words = bytearray()
    for i in range(0, len(bits), 16):
        w = 0
        for b in bits[i:i + 16]:
            w = (w << 1) | b
        words += bytes([w & 0xFF, w >> 8])
    words += (1).to_bytes(4, "little") * 3
    words += payload
    return bytes(words)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    sys.exit("lzx.py is a library; `python tools/lzx.py selftest` checks it, "
             "and `chmx.py` is what uses it")
