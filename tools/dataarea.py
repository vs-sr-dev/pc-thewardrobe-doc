#!/usr/bin/env python3
"""dataarea.py -- identify, by its CODE, and unpack an MZ image packed by the
self-relocating LZ packer whose stub carries the string `DATA_area_`, written
from the disassembly of the stub in SLAVS.EXE (pc-polanie-doc) and not from a
description of any format.

WHY THIS EXISTS, AND WHY IT HAS NO BETTER NAME
----------------------------------------------
`SLAVS.EXE`, `SETUP.EXE` and `PLAYER.EXE` of Polanie share one shape: a
512-byte header, `e_crlc = 0`, entry at `xxxx:0100` with `ss:sp = cs:0000`,
entropy 7.85, and 1,744 bytes of stub as the last segment. `dospack.py`
finds 0 of 30 packer markers; `lzexe.py` refuses all three at `e_ip`
(0100h, not 000Eh) and is right to. The stub, read whole with `dosdis.py`
(1,415 code bytes, 100 % decoded, identical in the three files), is not
LZEXE, not EXEPACK, not PKLITE: it is a compiled-C decompressor with an
assembly loader around it, and the only text in it is `DATA_area_`, which
is a symbol and not a product name. The code does not say who wrote it, so
this tool does not either; it is named after the one string it has.

THE FORMAT, AS THE STUB SAYS IT (dosdis.py on SLAVS.EXE, stub 0100h..0687h)
---------------------------------------------------------------------------
The packed MZ's load image is three regions:

    image 0                  the packed stream, `plen` bytes
    image ceil16(plen)       the relocation groups (see below)
    image e_cs*16 = stub     the stub segment, exactly 06D0h bytes:
        stub 0000..00FF      zeros -- the stub was assembled as a .COM
                             (org 100h) and appended as the last segment
        stub 0100..0686      1,415 bytes of code, the SAME in every file
        stub 0687..0697      zeros, then u16 [696h] = 64h (never read)
        stub 0698            `DATA_area_\\0`
        stub 06A3..06BE      the ORIGINAL 28-byte MZ header, verbatim
                             (e_crlc at [6A9h], e_maxalloc at [6AFh],
                             e_ss/e_sp at [6B1h]/[6B3h], e_ip/e_cs at
                             [6B7h]/[6B9h] are what the stub reads)
        stub 06BF            u32 unpacked image length, paragraph-rounded
        stub 06C3            u32 packed stream length `plen`
        stub 06C7            u32, never read by the stub (packer metadata)
        stub 06CB..06CF      zeros

The loader (0100h..02BDh): `mov bp,[2]` takes the top of memory from the
PSP; `int 21h/4Ah` twice (grow to the maximum, then to what is available);
computes the segment just above the unpacked image (`[6BFh]` rounded up,
plus 10h for the PSP), copies everything from the end of the packed stream
to the end of its own parameter block up there with `std; rep movsw`
(01BFh, and again at 01E4h), re-bases `ss`, and `retf`s into its own copy
at 020Ah. There it calls the decompressor (060Dh) with five arguments
(load segment, `plen` as a u32, unpacked length as a u32), rebuilds the
relocations from the groups now at its own cs:0000, restores `ss:sp` from
the original header, resizes the block to `e_maxalloc` if that is not
FFFFh, and `jmpf` to the original `cs:ip`.

The decompressor (0316h..060Ch) reads the packed stream BACKWARDS from
its last byte through a 4 KB ring buffer at stub 06DAh (refilled 1 KB at a
time by 033Fh, which `ret`s into the continuation held in `bp`), and
writes the output BACKWARDS from its last byte (`[6D6h]:[6D8h]`, stepping
the segment down by 1000h paragraphs on offset underflow). Bits come out
of `dh` MSB-first (`shl dh,1; jb`), `dl` counting the bits left, a new
byte loaded when it reaches zero:

    bit 0                      literal: the next 8 bits are one byte
    bit 1                      match:
      k ones then a zero (k <= 5; after five ones no zero is read),
      then n = k+1 bits f:     length = (2^n - 1) + f + 2      (3 .. 128)
      k ones then a zero (k <= 4; after four ones no zero is read),
      then n = k+1 bits g, then 8 bits b:
                               distance = 200h*(2^k - 1) + g*256 + b + 1
                                                            (1 .. 15872)
      copy `length` bytes descending, source = destination + distance,
      one byte at a time (`std; rep movsb`), so an overlap repeats.

It stops when the 32-bit count of bytes written (`[6CEh]:[6D0h]`) reaches
the unpacked length; there is no end code.

The relocation groups (023Ah..0273h), `e_crlc` entries from the original
header: a u16 group head whose low 12 bits are a count N and whose high 4
bits are a 64 KB segment number, then N u16 offsets in that segment. An
offset of FFFFh is handled specially by the stub (the segment is advanced
by F00h paragraphs and the offset masked to FFFh) but names the same
linear address `segment*10000h + FFFFh`. At each address the load segment
is added to the word there.

WHAT THE OUTPUT IS
------------------
The original file, re-laid: the 28 header bytes verbatim from the stub,
zeros to `e_lfarlc`, the relocation table as `offset:segment` pairs
(the linear address split as `linear & 0Fh`, `linear >> 4`; the original
pairs' split is not recoverable and is not claimed), zeros to
`e_cparhdr*16`, then the decoded image trimmed to the length the original
header declares (the packer padded it to a paragraph; the padding is
reported). Every header field -- `e_minalloc` included -- is the original's,
not a reconstruction.

THE CLOSURES
------------
  * the stub segment must be exactly 06D0h bytes and end the file, with
    zeros at 0000h..00FFh and the 1,415 code bytes at 0100h;
  * the stub's paragraph-rounded unpacked length must equal the original
    header's own `e_cp/e_cblp/e_cparhdr` arithmetic, rounded;
  * the packed stream plus the relocation groups must fit before the stub,
    and the groups must consume `e_crlc` entries with fewer than 16 bytes
    left before the stub (paragraph padding);
  * the decoder must write exactly the unpacked length, never underrun the
    output or the input, and never reach above the output;
  * the rebuilt header's `e_cp*512 + e_cblp` must equal the output length;
  * every relocation target must lie inside the image, and the word at
    each must be a segment no larger than the image in paragraphs -- a
    check the decoder was not told about;
  * the entry `cs:ip` must lie inside the image; `ss:sp` inside it or
    within `e_minalloc` above it.

    python tools/dataarea.py FILE...                identify and report
    python tools/dataarea.py --unpack FILE OUT      write the unpacked MZ
    python tools/dataarea.py --refuse FILE...       assert none is this packer
    python tools/dataarea.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402


class NotDataArea(Exception):
    pass


# The stub's code, stub 0100h..0686h, as `dosdis.py` printed it from
# SLAVS.EXE: the loader, the buffer filler, the decompressor and its
# C-style entry. SETUP.EXE and PLAYER.EXE carry the same 1,415 bytes.
CODE = bytes.fromhex(
    "8cca8b2e02008eda8c0690068cda2bea8b3e940681ff00017307bf0001893e940681c7de"
    "16033e9206b104d3ef47d3e7fa8ed28be7fbe800005657558becb44a8e069006bbffffcd"
    "21b44a8e069006cd218b36c3068b16c50683c60f83d200b104d3eeb10cd3e20bf283c610"
    "033690068b3ebf068b16c10683c70f83d200b104d3efb10cd3e20bfa83c7102e893e0802"
    "033e90068cdbb104d3e381c3cc068bd6d3e22bda56571e8bcd2bcc83c10a8cd003c72bc6"
    "8ec08bfc03f94f8cd08ed88bf7fdf6c1017401a44e4fd1e9f3a5fc1f5f5e8cd203d72bd6"
    "fa5217fb8cca03d72bd6571e8bcb8ec78bf94f8ede8bf7fdf6c1017401a44f4ed1e9f3a5"
    "fc1f52b80a0250cb0000000000008edaa1900605100050ff36c506ff36c306ff36c106ff"
    "36bf06e8e70383c40a07a1a90633db33f68b16900683c210eb340bdb7510268b0c8bd981"
    "e3ff0f81e100f083c6024b268b3c83c60206508bc103c283ffff750705000f81e7ff0f8e"
    "c026011558070bc0740348ebc58bf2a1b1068b1eb3068b0eb9068b16b70603c603ce2e89"
    "1604022e890e06028b3eaf068b0e90068ec18ed9fa8ed08be383ffff740bb44a8bdf2e03"
    "1e0802cd21fb2eff2e04025f5ec35657b90010c43eda162bf9732d8cc281ea00108916dc"
    "16893eda161e07bfda061ec536da168cda8bc683e60fd1e8d1e8d1e8d1e803d08edaeb10"
    "893eda168bf78cc01e07bfda061e8ed846d1e9f3a51fbbff0f33d25f5ec35657c706d006"
    "0000c706ce060000b8fe05833ed406007403b8a4032ea33d038ab7da06b208eb7c000055"
    "56575251504bb90004c43eda162bf973308cc281ea00108916dc16893eda161e078bfb81"
    "c7db061ec536da168cda8bc683e60fd1e8d1e8d1e8d1e803d08edaeb11893eda161e078b"
    "fb81c7db061ec536da1646d1e9f3a51f81e3ff0f58595a5f5ec3eb9b0ad2751180ca08bd"
    "b503f7c3ff0374ee4b8ab7da06fecad0e672740ad27510bdcd03f7c3ff0374d64b8a87da"
    "06eb1e8ac6bddf03f7c3ff0374c44b8ab7da068ae68acad2ec0ac4b1082acad2e6c43ed6"
    "0626880583ef01720f893ed606ff06ce06740f2eff263d038cc02d0010a3d806ebe7ff06"
    "d0068b3ed0063b3ed40675072ec7063d03fe052eff263d03e90cffbf01008bf70ad27459"
    "fecad0e67308d1d74683fe067cee0ad2751180ca08bd5b04f7c3ff0374d64b8ab7da06b9"
    "08002bce8aeed2ed8ac232e43bf07e602bf0ba08002bd6bd8104f7c3ff0374b04b8ab7da"
    "068ac6b1082bced2e80ac58bced2e6eb4380ca08bda204f7c3ff03748f4b8ab7da06feca"
    "d0e673b3d1d74683fe067cf2eba9e986feff06d0068b3ed0063b3ed406751d2ec7063d03"
    "fe05eb142bd68ac58bced2e603f883c70257013ece0672d533ffbe01000ad2751180ca08"
    "bdfa04f7c3ff0374bd4b8ab7da06fecad0e6730cd1e781cf00024683fe057cd9570ad275"
    "1180ca08bd2205f7c3ff0374954b8ab7da06b908002bce8aeed2ed8ac232e43bf07e282b"
    "f0ba08002bd6bd4805f7c3ff0374154b8ab7da068ac6b1082bced2e80ac58bced2e6eb0b"
    "e9e0fd2bd68ac58bced2e6500ad2751180ca08bd7905f7c3ff0374e44b8ab7da0633c08a"
    "c68bf880e207741cbd9205f7c3ff0374cb4b8ab7da068ac68acad2e80bf8b1082acad2e6"
    "588ae032c08bcf32ed03c15903c14059c43ed606290ed60672348cc60bf67410f7c70080"
    "750a81cf008081ee00088ec61e061f8bf703f0730b81ce00808cd80500088ed8fdf3a4fc"
    "1f2eff263d038cc681ee00108936d806ebc0a1ce063b06d2067303e99afd5f5ec3558bec"
    "56568b760c8b560a8b46082d010083da008bd8b104d3ebb10cd3e20bda03de250f008bd3"
    "b104d3e203c281e300f0891edc16a3da168b56068b46048916d406a3d2062d010083da00"
    "8bd8b104d3ebb10cd3e20bda03de250f008bd3b104d3e203c281e300f0891ed806a3d606"
    "fce83efce893fc5e5e5dc3")
CODE_AT = 0x100
STRING_AT = 0x698
STRING = b"DATA_area_\x00"
ORIG_HDR_AT = 0x6A3
ULEN_AT = 0x6BF
PLEN_AT = 0x6C3
META_AT = 0x6C7
STUB_LEN = 0x6D0
MAX_LENGTH = 128
MAX_DIST = 0x1E00 + 0x1FFF + 1        # 15872


def _mz(data):
    if len(data) < 32 or data[:2] != b"MZ":
        raise NotDataArea("not an MZ file")
    f = struct.unpack_from("<14H", data, 2)
    h = dict(zip(("cblp", "cp", "crlc", "cparhdr", "minalloc", "maxalloc",
                  "ss", "sp", "csum", "ip", "cs", "lfarlc", "ovno", "dummy"),
                 f))
    h["size"] = (h["cp"] - 1) * 512 + h["cblp"] if h["cblp"] else h["cp"] * 512
    h["hdr"] = h["cparhdr"] * 16
    return h


def parse(data):
    """Identify by the stub's code. Returns the fields; raises NotDataArea."""
    h = _mz(data)
    if h["size"] != len(data):
        raise NotDataArea("MZ size %d != file %d" % (h["size"], len(data)))
    if h["crlc"] != 0:
        raise NotDataArea("e_crlc = %d; a packed image of this kind has none"
                          % h["crlc"])
    if h["ip"] != CODE_AT:
        raise NotDataArea("e_ip = %04Xh, this stub's entry is 0100h" % h["ip"])
    stub_off = h["hdr"] + h["cs"] * 16
    stub = data[stub_off:]
    if len(stub) != STUB_LEN:
        raise NotDataArea("stub segment is %d bytes, this stub is %d"
                          % (len(stub), STUB_LEN))
    if stub[:CODE_AT] != bytes(CODE_AT):
        raise NotDataArea("stub 0000h..00FFh is not all zero")
    got = stub[CODE_AT:CODE_AT + len(CODE)]
    if got != CODE:
        differ = sum(1 for a, b in zip(got, CODE) if a != b)
        head = got[:29] == CODE[:29]
        raise NotDataArea("stub code differs in %d of %d bytes%s -- a variant "
                          "this tool has not read"
                          % (differ, len(CODE),
                             " (the entry's first 29 bytes match)" if head
                             else ""))
    oh = struct.unpack_from("<2s13H", stub, ORIG_HDR_AT)
    if oh[0] != b"MZ":
        raise NotDataArea("original header at stub 6A3h does not start MZ")
    orig = dict(zip(("cblp", "cp", "crlc", "cparhdr", "minalloc", "maxalloc",
                     "ss", "sp", "csum", "ip", "cs", "lfarlc", "ovno"),
                    oh[1:]))
    orig["size"] = ((orig["cp"] - 1) * 512 + orig["cblp"] if orig["cblp"]
                    else orig["cp"] * 512)
    orig["hdr"] = orig["cparhdr"] * 16
    orig["image"] = orig["size"] - orig["hdr"]
    ulen, plen, meta = struct.unpack_from("<III", stub, ULEN_AT)
    f = dict(h)
    f.update(stub_off=stub_off, orig=orig, ulen=ulen, plen=plen, meta=meta,
             string=stub[STRING_AT:STRING_AT + len(STRING)] == STRING,
             w696=struct.unpack_from("<H", stub, 0x696)[0])
    # closures on the stub's own numbers
    if orig["image"] < 0 or (orig["image"] + 15) // 16 * 16 != ulen:
        raise NotDataArea("stub says %d unpacked bytes, the original header "
                          "says %d (rounded %d)"
                          % (ulen, orig["image"], (orig["image"] + 15) // 16 * 16))
    reloc_at = (plen + 15) // 16 * 16            # an IMAGE offset
    if reloc_at > stub_off - h["hdr"]:
        raise NotDataArea("packed stream of %d bytes runs past the stub at "
                          "image %d" % (plen, stub_off - h["hdr"]))
    f["reloc_at"] = reloc_at
    f["reloc_room"] = stub_off - h["hdr"] - reloc_at
    return f


class _Bits:
    """The stub's bit buffer: `dh` holds the byte, `dl` the bits left, bits
    leave by `shl dh,1`, and the bytes come off the END of the stream."""

    def __init__(self, src):
        self.src = src
        self.p = len(src)
        self.dh = 0
        self.dl = 0

    def byte(self):
        if self.p == 0:
            raise NotDataArea("ran off the front of the packed stream")
        self.p -= 1
        return self.src[self.p]

    def bit(self):
        if self.dl == 0:
            self.dh = self.byte()
            self.dl = 8
        self.dl -= 1
        b = self.dh >> 7
        self.dh = (self.dh << 1) & 0xFF
        return b

    def bits(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | self.bit()
        return v


def decode(src, out_len):
    """Return (image, stats). Raises NotDataArea on anything the stub would
    have done to memory outside the image."""
    r = _Bits(src)
    out = bytearray(out_len)
    q = out_len
    st = dict(literals=0, matches=0, max_length=0, max_dist=0,
              length_codes=[0] * 6, dist_codes=[0] * 5)
    while q > 0:
        if r.bit() == 0:
            q -= 1
            out[q] = r.bits(8)
            st["literals"] += 1
            continue
        k = 0
        while k < 5 and r.bit() == 1:
            k += 1
        n = k + 1
        length = (1 << n) - 1 + r.bits(n) + 2
        st["length_codes"][k] += 1
        k = 0
        while k < 4 and r.bit() == 1:
            k += 1
        n = k + 1
        g = r.bits(n)
        b = r.bits(8)
        dist = 0x200 * ((1 << k) - 1) + (g << 8) + b + 1
        st["dist_codes"][k] += 1
        if q - length < 0:
            raise NotDataArea("match of %d bytes underruns the output with %d "
                              "left to write" % (length, q))
        if q + dist > out_len:
            raise NotDataArea("match distance %d reaches above the output "
                              "(%d left to write)" % (dist, q))
        for _ in range(length):
            q -= 1
            out[q] = out[q + dist]
        st["matches"] += 1
        st["max_length"] = max(st["max_length"], length)
        st["max_dist"] = max(st["max_dist"], dist)
    st["consumed"] = len(src) - r.p
    st["bits_unused"] = r.dl
    return bytes(out), st


def relocations(groups, count):
    """The stub's group walk: returns (linear addresses, bytes used, groups)."""
    addrs = []
    pos = 0
    left = 0
    seg = 0
    ngroups = 0
    while len(addrs) < count:
        if left == 0:
            if pos + 2 > len(groups):
                raise NotDataArea("relocation groups end after %d of %d "
                                  "entries" % (len(addrs), count))
            head = struct.unpack_from("<H", groups, pos)[0]
            pos += 2
            left = head & 0xFFF
            seg = head >> 12
            ngroups += 1
            if left == 0:
                raise NotDataArea("relocation group with a count of 0 at %d"
                                  % (pos - 2))
        if pos + 2 > len(groups):
            raise NotDataArea("relocation groups end after %d of %d entries"
                              % (len(addrs), count))
        off = struct.unpack_from("<H", groups, pos)[0]
        pos += 2
        left -= 1
        addrs.append(seg * 0x10000 + off)
    if left != 0:
        raise NotDataArea("last relocation group promises %d more entries "
                          "than e_crlc = %d" % (left, count))
    return addrs, pos, ngroups


def unpack(data, f):
    """Return (mz_bytes, image, relocs, stats)."""
    src = data[f["hdr"]:f["hdr"] + f["plen"]]
    image, st = decode(src, f["ulen"])
    groups = data[f["hdr"] + f["reloc_at"]:f["stub_off"]]
    o = f["orig"]
    relocs, used, ngroups = relocations(groups, o["crlc"])
    if len(groups) - used >= 16:
        raise NotDataArea("relocation groups use %d of %d bytes before the "
                          "stub; %d left is more than paragraph padding"
                          % (used, len(groups), len(groups) - used))
    st.update(relocs=len(relocs), reloc_bytes=used, reloc_groups=ngroups,
              reloc_pad=len(groups) - used)

    pad = f["ulen"] - o["image"]
    st["pad"] = pad
    st["pad_bytes"] = image[o["image"]:]
    image = image[:o["image"]]
    if o["lfarlc"] < 28 or o["lfarlc"] + 4 * len(relocs) > o["hdr"]:
        raise NotDataArea("original header cannot hold %d relocations at "
                          "%04Xh in %d bytes" % (len(relocs), o["lfarlc"],
                                                 o["hdr"]))
    hdr = bytearray(o["hdr"])
    hdr[:28] = data[f["stub_off"] + ORIG_HDR_AT:f["stub_off"] + ORIG_HDR_AT + 28]
    for i, a in enumerate(relocs):
        struct.pack_into("<HH", hdr, o["lfarlc"] + 4 * i, a & 0xF, a >> 4)
    return bytes(hdr) + image, image, relocs, st


def closure(mz, image, relocs, f):
    """Checks on the OUTPUT that the decoder was not told about."""
    h = _mz(mz)
    o = f["orig"]
    r = dict(size_ok=h["size"] == len(mz), outside=[], wild=[],
             limit=(len(image) + 15) // 16)
    for a in relocs:
        if a + 2 > len(image):
            r["outside"].append(a)
            continue
        seg = struct.unpack_from("<H", image, a)[0]
        if seg > r["limit"]:
            r["wild"].append((a, seg))
    r["entry"] = o["cs"] * 16 + o["ip"]
    r["entry_ok"] = r["entry"] < len(image)
    r["stack"] = o["ss"] * 16 + o["sp"]
    r["stack_ok"] = r["stack"] <= len(image) + o["minalloc"] * 16
    r["ok"] = (r["size_ok"] and not r["outside"] and not r["wild"]
               and r["entry_ok"] and r["stack_ok"])
    return r


def report(path, data):
    f = parse(data)
    o = f["orig"]
    print("=== %s ===" % path)
    print("  file                       : %d bytes, MZ closes, e_crlc 0, "
          "header %d" % (len(data), f["hdr"]))
    print("  stub segment               : %04Xh, file offset %d, %d bytes = "
          "06D0h, ends the file" % (f["cs"], f["stub_off"], STUB_LEN))
    print("  stub code (1,415 bytes)    : MATCH, byte for byte")
    print("  'DATA_area_' at stub 698h  : %s"
          % ("present" if f["string"] else "ABSENT"))
    print("  packed stream              : %d bytes at image 0" % f["plen"])
    print("  relocation groups          : at image %d, %d bytes of room"
          % (f["reloc_at"], f["reloc_room"]))
    print("  unpacked length (stub)     : %d bytes = %d paragraphs"
          % (f["ulen"], f["ulen"] // 16))
    print("  original header (stub 6A3h): cblp %d cp %d -> %d bytes, crlc %d, "
          "cparhdr %d (%d bytes), lfarlc %04Xh, image %d"
          % (o["cblp"], o["cp"], o["size"], o["crlc"], o["cparhdr"],
             o["hdr"], o["lfarlc"], o["image"]))
    print("  original minalloc/maxalloc : %d / %04Xh" % (o["minalloc"],
                                                         o["maxalloc"]))
    print("  original cs:ip, ss:sp      : %04X:%04X, %04X:%04X"
          % (o["cs"], o["ip"], o["ss"], o["sp"]))
    print("  unread stub words          : [696h] = %d, [6C7h] = %08Xh"
          % (f["w696"], f["meta"]))
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
        dirguard.want_file(p, "dataarea.py")

    if args.refuse:
        bad = 0
        for p in args.paths:
            with open(p, "rb") as fh:
                data = fh.read()
            try:
                parse(data)
            except NotDataArea as e:
                print("%-24s REFUSED: %s" % (os.path.basename(p), e))
            else:
                print("%-24s IS THIS PACKER -- CONTROL FAILED"
                      % os.path.basename(p))
                bad += 1
        print("\ndataarea.py: %d of %d refused" % (len(args.paths) - bad,
                                                   len(args.paths)))
        return 1 if bad else 0

    if args.unpack and len(args.paths) != 1:
        raise SystemExit("dataarea.py: --unpack takes exactly one input")
    ok = 0
    for p in args.paths:
        with open(p, "rb") as fh:
            data = fh.read()
        try:
            f = report(p, data)
        except NotDataArea as e:
            print("=== %s ===" % p)
            print("  NOT THIS PACKER: %s" % e)
            continue
        ok += 1
        if not args.unpack:
            continue
        try:
            mz, image, relocs, st = unpack(data, f)
        except NotDataArea as e:
            print("  UNPACK FAILED: %s" % e)
            return 1
        r = closure(mz, image, relocs, f)
        o = f["orig"]
        print("  decoded image              : %d bytes, trimmed to %d (%d "
              "pad bytes %s), from %d of %d stream bytes, %d bits unused"
              % (f["ulen"], len(image), st["pad"], st["pad_bytes"].hex(" "),
                 st["consumed"], f["plen"], st["bits_unused"]))
        print("  literals / matches         : %d / %d, longest match %d, "
              "farthest %d" % (st["literals"], st["matches"],
                               st["max_length"], st["max_dist"]))
        print("  length codes k=0..5        : %s"
              % " ".join(str(c) for c in st["length_codes"]))
        print("  distance codes k=0..4      : %s"
              % " ".join(str(c) for c in st["dist_codes"]))
        print("  relocations                : %d from %d bytes in %d groups, "
              "%d pad bytes before the stub"
              % (st["relocs"], st["reloc_bytes"], st["reloc_groups"],
                 st["reloc_pad"]))
        print("  output MZ                  : %d bytes = header %d + image "
              "%d, closes on the original header's size: %s"
              % (len(mz), o["hdr"], len(image), r["size_ok"]))
        print("  relocation targets         : %d inside, %d outside, %d "
              "holding a segment above %04Xh"
              % (len(relocs) - len(r["outside"]), len(r["outside"]),
                 len(r["wild"]), r["limit"]))
        print("  entry %04X:%04X = %d       : %s"
              % (o["cs"], o["ip"], r["entry"],
                 "inside the image" if r["entry_ok"] else "OUTSIDE"))
        print("  stack %04X:%04X = %d       : %s"
              % (o["ss"], o["sp"], r["stack"],
                 "inside image + minalloc" if r["stack_ok"] else "OUTSIDE"))
        segs = {}
        for a in relocs:
            if a + 2 <= len(image):
                v = struct.unpack_from("<H", image, a)[0]
                segs[v] = segs.get(v, 0) + 1
        top = sorted(segs.items(), key=lambda kv: -kv[1])[:8]
        print("  relocated segment values   : %d distinct; most common %s"
              % (len(segs), ", ".join("%04Xh x%d" % kv for kv in top)))
        if not r["ok"]:
            print("  CLOSURE FAILED -- the image is wrong")
            return 1
        with open(args.unpack, "wb") as out:
            out.write(mz)
        print("  written                    : %s" % args.unpack)
    print()
    print("dataarea.py: %d of %d inputs are images of this packer"
          % (ok, len(args.paths)))
    return 0 if ok == len(args.paths) else 1


# ---------------------------------------------------------------- selftest
class _Writer:
    """The encoder the stub implies: bits MSB-first into bytes, and the
    byte sequence REVERSED at the end so the stub reads it from the end."""

    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def bit(self, b):
        self.acc = (self.acc << 1) | (b & 1)
        self.n += 1
        if self.n == 8:
            self.out.append(self.acc)
            self.acc = 0
            self.n = 0

    def bits(self, v, n):
        for i in range(n - 1, -1, -1):
            self.bit((v >> i) & 1)

    def literal(self, c):
        self.bit(0)
        self.bits(c, 8)

    def match(self, length, dist):
        assert 3 <= length <= MAX_LENGTH and 1 <= dist <= MAX_DIST
        self.bit(1)
        k = 0
        while length - 2 - ((1 << (k + 1)) - 1) >= (1 << (k + 1)):
            k += 1
        n = k + 1
        f = length - 2 - ((1 << n) - 1)
        for _ in range(k):
            self.bit(1)
        if k < 5:
            self.bit(0)
        self.bits(f, n)
        d = dist - 1
        k = 0
        while d - 0x200 * ((1 << k) - 1) >= (1 << (k + 1 + 8)):
            k += 1
        n = k + 1
        rest = d - 0x200 * ((1 << k) - 1)
        for _ in range(k):
            self.bit(1)
        if k < 4:
            self.bit(0)
        self.bits(rest >> 8, n)
        self.bits(rest & 0xFF, 8)

    def finish(self):
        while self.n:
            self.bit(0)
        return bytes(reversed(self.out))


def _build(plan, relocs, orig):
    """plan: tokens applied from the END of the image backwards, as the
    stub writes it. Returns (packed file bytes, image)."""
    # first pass: the image, so the paragraph pad is known
    image = bytearray()
    for tok in plan:
        if tok[0] == "lit":
            image[0:0] = tok[1]
        else:
            for _ in range(tok[1]):
                image.insert(0, image[tok[2] - 1])
    ulen = (len(image) + 15) // 16 * 16
    # second pass: the bits. The pad bytes are the LAST of the padded image,
    # so the decoder meets them first: they lead the stream as literal zeros.
    w = _Writer()
    for _ in range(ulen - len(image)):
        w.literal(0)
    for tok in plan:
        if tok[0] == "lit":
            for c in reversed(tok[1]):
                w.literal(c)
        else:
            w.match(tok[1], tok[2])
    stream = w.finish()
    # relocation groups
    groups = bytearray()
    by_seg = {}
    for a in relocs:
        by_seg.setdefault(a >> 16, []).append(a & 0xFFFF)
    for seg in sorted(by_seg):
        offs = by_seg[seg]
        groups += struct.pack("<H", (seg << 12) | len(offs))
        for off in offs:
            groups += struct.pack("<H", off)
    reloc_at = (len(stream) + 15) // 16 * 16
    body = bytearray(stream) + bytes(reloc_at - len(stream)) + groups
    body += bytes((-len(body)) % 16)
    stub_seg = len(body) // 16
    stub = bytearray(STUB_LEN)
    stub[CODE_AT:CODE_AT + len(CODE)] = CODE
    struct.pack_into("<H", stub, 0x696, 0x64)
    stub[STRING_AT:STRING_AT + len(STRING)] = STRING
    o = dict(orig)
    o["size"] = o["hdr"] + len(image)
    struct.pack_into("<2s13H", stub, ORIG_HDR_AT, b"MZ", o["size"] % 512,
                     (o["size"] + 511) // 512, len(relocs), o["hdr"] // 16,
                     o["minalloc"], o["maxalloc"], o["ss"], o["sp"], 0,
                     o["ip"], o["cs"], o["lfarlc"], 0)
    struct.pack_into("<III", stub, ULEN_AT, ulen, len(stream), 0x12345678)
    body += stub
    total = 512 + len(body)
    hdr = bytearray(512)
    struct.pack_into("<2s14H", hdr, 0, b"MZ", total % 512, (total + 511) // 512,
                     0, 32, 100, 0xFFFF, stub_seg, 0, 0, CODE_AT, stub_seg,
                     0x1C, 0, 0)
    return bytes(hdr) + bytes(body), bytes(image)


def selftest():
    nameguard.guard()
    checks = []

    def ok(label, cond, note=""):
        checks.append(cond)
        print("  %-56s %s %s" % (label, "ok" if cond else "FAIL", note))

    ok("stub code constant is 1,415 bytes (0100h..0686h)", len(CODE) == 1415)
    ok("code ends with the C epilogue `pop si; pop si; pop bp; ret`",
       CODE[-4:] == bytes.fromhex("5e5e5dc3"))

    # every length and every distance class round-trips through the writer
    # and the decoder's arithmetic
    plan = [("lit", b"MZ-selftest \x00\x01\x02\x03")]
    for length in (3, 4, 5, 8, 9, 16, 17, 32, 33, 64, 65, 128):
        plan.append(("match", length, 1))
    plan.append(("lit", bytes(range(256))))
    # a far distance needs a real image behind it: 15,900 bytes, then one
    # match on each edge of every distance class
    plan.append(("lit", bytes(i * 7 & 0xFF for i in range(15900))))
    for dist in (1, 2, 256, 512, 513, 1024, 1536, 1537, 3584, 3585, 7680,
                 7681, 15872):
        plan.append(("lit", bytes([dist & 0xFF, dist >> 8])))
        plan.append(("match", 3 + dist % 5, dist))
    plan.append(("match", 100, 15872))
    plan.append(("lit", b"tail"))
    orig = dict(hdr=13824, minalloc=2815, maxalloc=0xFFFF, ss=0x3715,
                sp=0x80, ip=0, cs=0, lfarlc=0x3E)
    relocs = [4, 20, 300, 0xFFFF, 0x10004, 0x1FFFF, 0x20010]
    packed, image = _build(plan, relocs, orig)
    ok("synthetic image built, %d bytes" % len(image), len(image) > 16000)
    f = parse(packed)
    ok("synthetic packed file identifies by code", True)
    ok("'DATA_area_' reported present", f["string"])
    mz, img, rl, st = unpack(packed, f)
    ok("round trip: image equal, %d bytes" % len(image), img == image)
    ok("decoder consumed the whole stream",
       st["consumed"] == f["plen"] and st["bits_unused"] < 8)
    ok("every length class seen (k=0..5)", all(st["length_codes"]))
    ok("every distance class seen (k=0..4)", all(st["dist_codes"]))
    ok("longest match 128, farthest 15872",
       st["max_length"] == 128 and st["max_dist"] == 15872)
    ok("relocations round trip (7, in 3 segments)",
       rl == relocs and st["reloc_groups"] == 3)
    h = _mz(mz)
    ok("output header closes on its size", h["size"] == len(mz))
    ok("output header is the original's (minalloc 2815, lfarlc 3Eh)",
       h["minalloc"] == 2815 and h["lfarlc"] == 0x3E and h["crlc"] == 7)
    ok("output relocation table re-reads to the same addresses",
       [struct.unpack_from("<HH", mz, 0x3E + 4 * i)[1] * 16
        + struct.unpack_from("<HH", mz, 0x3E + 4 * i)[0]
        for i in range(7)] == relocs)

    # negative controls
    bad = bytearray(packed)
    bad[f["stub_off"] + CODE_AT + 3] ^= 0xFF
    try:
        parse(bytes(bad))
        ok("entry code damaged -> refused", False)
    except NotDataArea as e:
        ok("entry code damaged -> refused", "differs in 1 of" in str(e))
    bad = bytearray(packed)
    bad[f["stub_off"] + CODE_AT + 0x300] ^= 0xFF
    try:
        parse(bytes(bad))
        ok("decoder damaged -> refused, entry noted as matching", False)
    except NotDataArea as e:
        ok("decoder damaged -> refused, entry noted as matching",
           "29 bytes match" in str(e))
    bad = bytearray(packed)
    struct.pack_into("<I", bad, f["stub_off"] + ULEN_AT, f["ulen"] + 16)
    try:
        parse(bytes(bad))
        ok("unpacked length != original header -> refused", False)
    except NotDataArea:
        ok("unpacked length != original header -> refused", True)
    bad = bytearray(packed)
    struct.pack_into("<H", bad, f["stub_off"] + ORIG_HDR_AT + 6,
                     len(relocs) + 1)
    try:
        unpack(bytes(bad), parse(bytes(bad)))
        ok("e_crlc one more than the groups hold -> refused", False)
    except NotDataArea:
        ok("e_crlc one more than the groups hold -> refused", True)
    bad = bytearray(packed)
    bad[512 + f["plen"] - 1] ^= 0x80          # the very first bit read
    try:
        img2 = unpack(bytes(bad), parse(bytes(bad)))[1]
        ok("first stream bit flipped -> image differs", img2 != image)
    except NotDataArea:
        ok("first stream bit flipped -> image differs", True, "(refused)")
    try:
        parse(b"MZ" + b"\0" * 62)
        ok("empty MZ -> refused", False)
    except NotDataArea:
        ok("empty MZ -> refused", True)
    bad = bytearray(packed)
    struct.pack_into("<H", bad, 0x14, 0x0E)
    try:
        parse(bytes(bad))
        ok("e_ip 000Eh (LZEXE's) -> refused", False)
    except NotDataArea as e:
        ok("e_ip 000Eh (LZEXE's) -> refused", "0100h" in str(e))

    print("\ndataarea.py selftest: %d of %d checks pass, 0 skipped (the "
          "object is synthetic)" % (sum(checks), len(checks)))
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
