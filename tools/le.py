#!/usr/bin/env python3
"""le.py -- read a Linear Executable: object table, page map, fixups, image.

`LE` is the 32-bit executable format a DOS extender loads. It is documented by
IBM (the OS/2 2.0 Linear Executable specification) and by Phar Lap, and this
tool uses that public description and says so. What is derived here is nothing
about the format and everything about the three specimens: how much of each
file is image and how much is bookkeeping, and what is in the image.

**Prior art, which exists and is named rather than quietly re-invented.**
`pc-hurl-doc/tools/hurlle.py` is a working LE loader written for one object:
it maps the objects at their relocation bases and offers `info`, `dis`,
`xref`, `func` and `strings`. It is **not** in this session's toolbox, because
this lineage came down through `pc-streetsofkamurocho-doc` and that repository
never had it. Three courses were open -- copy it, rewrite it, or cite it -- and
this file is the second, for two reasons that are about the code and not about
pride: it imports `hurllib`, a per-object module that does not exist here, and
it hard-codes one executable's file name. What is *not* re-derived is the
insight that the page map is three big-endian bytes and a flag byte, which
`hurlle.py` had already established and which this tool checks rather than
assumes.

The header fields this reads, all little-endian, all offsets relative to the
`LE` signature:

    +0x00  char[2]  'LE'
    +0x08  u8       cpu type       2 = 80386
    +0x0A  u8       os type        1 = OS/2, and DOS extenders use it anyway
    +0x14  u32      page count
    +0x18  u32      EIP object number      +0x1C  u32  EIP
    +0x20  u32      ESP object number      +0x24  u32  ESP
    +0x28  u32      page size
    +0x2C  u32      bytes in the last page
    +0x40  u32      object table offset    +0x44  u32  object count
    +0x48  u32      object page map offset
    +0x68  u32      fixup page table offset
    +0x6C  u32      fixup record table offset
    +0x80  u32      data pages offset, relative to the FILE not the header

An object table entry is 24 bytes: virtual size, relocation base, flags,
page-map index, page count, reserved. A page-map entry is 4 bytes: a 3-byte
big-endian page number and a flag byte.

    python tools/le.py info    <file>
    python tools/le.py map     <file>
    python tools/le.py strings <file> [minlen]
    python tools/le.py find    <file> <text>
    python tools/le.py selftest
"""
import os
import re
import struct
import sys

OBJ_FLAGS = [(0x0001, "readable"), (0x0002, "writable"), (0x0004, "executable"),
             (0x0008, "resource"), (0x0010, "discardable"), (0x0020, "shared"),
             (0x0040, "preload"), (0x0080, "invalid"), (0x0100, "zero-filled"),
             (0x0200, "resident"), (0x2000, "16:16 alias"), (0x4000, "big/default-bit")]


class Refused(Exception):
    pass


class LE(object):
    def __init__(self, data, name="<memory>"):
        self.data = data
        self.name = name
        if len(data) < 0x40:
            raise Refused("shorter than an MZ header")
        if data[:2] not in (b"MZ", b"ZM"):
            raise Refused("no MZ signature")
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if off <= 0 or off + 0x88 > len(data):
            raise Refused("e_lfanew %d does not point inside the file" % off)
        if data[off:off + 2] != b"LE":
            raise Refused("signature at e_lfanew is %r, not 'LE'"
                          % data[off:off + 2])
        self.off = off
        h = data[off:]
        self.cpu = h[0x08]
        self.os = h[0x0A]
        (self.pages, self.eip_obj, self.eip, self.esp_obj, self.esp,
         self.page_size, self.last_page) = struct.unpack_from("<7I", h, 0x14)
        self.obj_off = struct.unpack_from("<I", h, 0x40)[0]
        self.nobj = struct.unpack_from("<I", h, 0x44)[0]
        self.map_off = struct.unpack_from("<I", h, 0x48)[0]
        self.fixpage_off = struct.unpack_from("<I", h, 0x68)[0]
        self.fixrec_off = struct.unpack_from("<I", h, 0x6C)[0]
        self.data_off = struct.unpack_from("<I", h, 0x80)[0]
        if self.page_size == 0 or self.page_size > 1 << 20:
            raise Refused("page size %d is implausible" % self.page_size)
        if not 0 < self.nobj < 4096:
            raise Refused("object count %d is implausible" % self.nobj)
        if off + self.obj_off + self.nobj * 24 > len(data):
            raise Refused("object table of %d entries runs past the end" % self.nobj)
        self.objects = []
        for i in range(self.nobj):
            vsize, base, flags, pidx, pcnt, _ = struct.unpack_from(
                "<6I", h, self.obj_off + i * 24)
            self.objects.append({"n": i + 1, "vsize": vsize, "base": base,
                                 "flags": flags, "page_index": pidx,
                                 "page_count": pcnt})

    # -- the image ---------------------------------------------------------

    def page_bytes(self, num):
        """Page `num` (1-based, as the page map states it) out of the file."""
        if num < 1 or num > self.pages:
            return b""
        start = self.data_off + (num - 1) * self.page_size
        size = self.page_size
        if num == self.pages and self.last_page:
            size = self.last_page
        return self.data[start:start + size]

    def map_entry(self, i):
        """Page-map entry i (0-based): 3 big-endian bytes and a flag byte."""
        e = self.off + self.map_off + i * 4
        h = self.data
        return ((h[e] << 16) | (h[e + 1] << 8) | h[e + 2]), h[e + 3]

    def load(self):
        """Every object as (object, bytes), zero-filled to its virtual size."""
        out = []
        for o in self.objects:
            buf = bytearray(o["vsize"])
            pos = 0
            for k in range(o["page_count"]):
                num, flag = self.map_entry(o["page_index"] - 1 + k)
                b = self.page_bytes(num)
                buf[pos:pos + len(b)] = b
                pos += self.page_size
            out.append((o, bytes(buf)))
        return out

    def accounting(self):
        """Where every byte of the file goes, by declaration."""
        stub = self.off
        hdr_end = self.off + self.data_off if self.data_off < self.off else self.data_off
        image = (self.pages - 1) * self.page_size + (self.last_page or self.page_size)
        return {"file": len(self.data), "stub": stub,
                "le_header_and_tables": self.data_off - stub,
                "image": image,
                "tail": len(self.data) - self.data_off - image}


def flagnames(f):
    got = [n for bit, n in OBJ_FLAGS if f & bit]
    return ",".join(got) if got else "-"


def cmd_info(path):
    d = open(path, "rb").read()
    try:
        le = LE(d, path)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    a = le.accounting()
    print("%s  %d bytes" % (os.path.basename(path), len(d)))
    print("  MZ stub            %d bytes, LE at 0x%X" % (le.off, le.off))
    print("  cpu type %d, os type %d, page size %d, pages %d, last page %d"
          % (le.cpu, le.os, le.page_size, le.pages, le.last_page))
    print("  entry point        object %d : 0x%08X" % (le.eip_obj, le.eip))
    print("  initial stack      object %d : 0x%08X" % (le.esp_obj, le.esp))
    print("  objects            %d" % le.nobj)
    print("  %-3s %10s %10s %8s %6s %6s  %s"
          % ("obj", "vsize", "base", "pageidx", "pages", "flags", "meaning"))
    total = 0
    for o in le.objects:
        total += o["vsize"]
        print("  %-3d %10d 0x%08X %8d %6d 0x%04X  %s"
              % (o["n"], o["vsize"], o["base"], o["page_index"],
                 o["page_count"], o["flags"], flagnames(o["flags"])))
    print("  virtual sizes sum  %d" % total)
    print()
    print("  the file, by declaration:")
    print("    MS-DOS stub                 %9d" % a["stub"])
    print("    LE header, tables, fixups   %9d" % a["le_header_and_tables"])
    print("    page data                   %9d" % a["image"])
    print("    after the last page         %9d" % a["tail"])
    print("    total                       %9d  (file %d, residue %d)"
          % (a["stub"] + a["le_header_and_tables"] + a["image"] + a["tail"],
             a["file"],
             a["file"] - (a["stub"] + a["le_header_and_tables"] + a["image"]
                          + a["tail"])))
    return 0


def cmd_map(path):
    d = open(path, "rb").read()
    le = LE(d, path)
    print("%s: %d pages of %d bytes" % (os.path.basename(path), le.pages, le.page_size))
    seen = {}
    for i in range(le.pages):
        num, flag = le.map_entry(i)
        seen[flag] = seen.get(flag, 0) + 1
    print("  page-map flag values: %s"
          % ", ".join("%d x%d" % (f, c) for f, c in sorted(seen.items())))
    inorder = all(le.map_entry(i)[0] == i + 1 for i in range(le.pages))
    print("  page numbers are the identity permutation: %s" % inorder)
    return 0


def cmd_strings(path, minlen=6):
    d = open(path, "rb").read()
    le = LE(d, path)
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % minlen)
    for o, buf in le.load():
        for m in pat.finditer(buf):
            print("obj%d+0x%06X  0x%08X  %s"
                  % (o["n"], m.start(), o["base"] + m.start(),
                     m.group().decode("latin-1")))
    return 0


def cmd_find(path, text):
    d = open(path, "rb").read()
    le = LE(d, path)
    needle = text.encode("latin-1")
    n = 0
    for o, buf in le.load():
        i = -1
        while True:
            i = buf.find(needle, i + 1)
            if i < 0:
                break
            n += 1
            ctx = buf[max(0, i - 24):i + len(needle) + 24]
            print("obj%d+0x%06X  0x%08X  %r"
                  % (o["n"], i, o["base"] + i, ctx.decode("latin-1", "replace")))
    print("%d occurrences of %r" % (n, text))
    return 0


def _make(sig=b"LE", nobj=1, page_size=4096, pages=1, stub=64):
    """A minimal LE, built in memory, for the selftest."""
    hdr = bytearray(0x88)
    hdr[0:2] = sig
    hdr[0x08] = 2
    hdr[0x0A] = 1
    struct.pack_into("<7I", hdr, 0x14, pages, 1, 0x1000, 1, 0x2000,
                     page_size, page_size)
    struct.pack_into("<I", hdr, 0x40, 0x88)          # object table right after
    struct.pack_into("<I", hdr, 0x44, nobj)
    struct.pack_into("<I", hdr, 0x48, 0x88 + nobj * 24)
    objs = b""
    for i in range(nobj):
        objs += struct.pack("<6I", page_size, 0x10000 * (i + 1), 0x2005,
                            1 + i, 1, 0)
    pmap = b""
    for i in range(pages):
        pmap += bytes([0, 0, i + 1, 0])
    body = bytes(hdr) + objs + pmap
    data_off = stub + len(body)
    struct.pack_into("<I", hdr, 0x80, data_off)
    body = bytes(hdr) + objs + pmap
    mz = bytearray(stub)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, stub)
    return bytes(mz) + body + (b"THE SELFTEST STRING" .ljust(page_size, b"\0"))


def cmd_selftest():
    cases = []
    good = _make()
    cases.append(("a minimal one-object LE built here", good, True))
    cases.append(("two objects", _make(nobj=2, pages=2), True))
    bad = bytearray(good)
    bad[0x40 + 0] = ord("N")
    cases.append(("signature NE at e_lfanew", bytes(bad), False))
    cases.append(("no MZ at all", b"\0" * 256, False))
    cases.append(("e_lfanew past the end",
                  b"MZ" + b"\0" * 58 + struct.pack("<I", 1 << 24) + b"\0" * 8,
                  False))
    ps0 = bytearray(good)
    struct.pack_into("<I", ps0, 64 + 0x28, 0)
    cases.append(("page size 0", bytes(ps0), False))
    no = bytearray(good)
    struct.pack_into("<I", no, 64 + 0x44, 999999)
    cases.append(("999999 objects", bytes(no), False))
    fails = 0
    for name, data, ok in cases:
        try:
            LE(data)
            got, why = True, ""
        except Refused as e:
            got, why = False, str(e)
        mark = "ok " if got == ok else "FAIL"
        if got != ok:
            fails += 1
        print("%s  %-42s expected %-7s got %-7s %s"
              % (mark, name, "accept" if ok else "refuse",
                 "accept" if got else "refuse", why))
    le = LE(good)
    objs = le.load()
    hit = b"THE SELFTEST STRING" in objs[0][1]
    print("%s  %-42s %s" % ("ok " if hit else "FAIL",
                            "the accepted image contains its own string",
                            "found at object 1" if hit else "NOT FOUND"))
    if not hit:
        fails += 1
    print()
    print("%d specimens, %d must be accepted, %d failures"
          % (len(cases) + 1, sum(1 for c in cases if c[2]) + 1, fails))
    return 1 if fails else 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "info":
        return cmd_info(rest[0])
    if cmd == "map":
        return cmd_map(rest[0])
    if cmd == "strings":
        return cmd_strings(rest[0], int(rest[1]) if len(rest) > 1 else 6)
    if cmd == "find":
        return cmd_find(rest[0], rest[1])
    if cmd == "selftest":
        return cmd_selftest()
    print("unknown command %r" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
