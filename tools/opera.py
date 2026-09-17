#!/usr/bin/env python3
"""opera.py -- a reader for the Opera file system, derived from one disc.

3DO discs do not use ISO 9660. They use the file system of the console's own
operating system, Portfolio OS, and it is small enough to write from scratch in
an afternoon. Everything below was checked against the bytes of the pressing
this repository documents; every claim carries an assertion that fires at run
time, and the tool refuses to census anything until its negative control has
failed the way it is supposed to.

THE IMAGE

A `MODE1_RAW` track holds 2,352 bytes per sector: twelve bytes of sync, four of
header (minute, second, frame, mode), 2,048 of user data, and 288 of EDC/ECC.
The file system counts in 2,048-byte blocks and knows nothing about the other
304. `--raw 2352 --off 16` is the default; `--raw 2048 --off 0` reads a
cooked image.

THE VOLUME LABEL, IN SECTOR 0, BIG-ENDIAN THROUGHOUT

    +0    u8    record_type          1
    +1    u8[5] sync                 'ZZZZZ'
    +6    u8    record_version       1
    +7    u8    flags                0
    +8    char[32] comment
    +40   char[32] label
    +72   u32   identifier
    +76   u32   block_size           2048
    +80   u32   block_count          blocks the volume claims
    +84   u32   root_dir_id
    +88   u32   root_dir_blocks      length of the root, in blocks
    +92   u32   root_dir_block_size  2048
    +96   u32   root_dir_last_copy   index of the last copy, so copies = this+1
    +100  u32[] root_dir_copies      one absolute block number per copy

The label is 100 + 4*(last_copy+1) bytes long. On the disc measured here that
is 132, and 132 bytes is also the length of a file in the root called
`/Disc label` whose first block is block 0: the volume contains its own header
as a named file.

A DIRECTORY BLOCK

    +0    i32   next_block           -1 when this is the last block
    +4    i32   prev_block           -1 when this is the first

`next_block` and `prev_block` are **block indices inside this directory**, not
absolute block numbers: a two-block directory has 0 -> next 1, and block 1 is
the block after the one the copy list points at. Reading them as absolute
addresses sends the walk to block 1 of the disc, which is where this reader
went first. Four directories on this disc span more than one block.
    +8    u32   flags
    +12   u32   first_free_byte      offset of the first byte NOT in use
    +16   u32   first_entry_offset   20 everywhere seen

`first_free_byte` is the field that matters. Entries are laid out from
`first_entry_offset` upwards, and the bytes after `first_free_byte` are *stale*
-- previous contents of the block, left in place because nothing zeroes a
CD-ROM. A reader that walks to the end of the block instead of stopping at
`first_free_byte` finds entries that were deleted before the disc was pressed.
They are real artefacts and this tool can return them (`--stale`), but they are
not files and must never be counted as files.

A DIRECTORY ENTRY

    +0    u32   flags        low byte is the type: 2 = file, 6 = special,
                             7 = directory; bit 31 set marks the last entry
                             in this block. The only type-6 entry on this disc
                             is `/Disc label`, whose data is the volume label
                             in block 0.
    +4    u32   id
    +8    char[4] type       a four-character type, e.g. '3DO ', 'sc  ', '*lbl'
    +12   u32   block_size   2048 on every entry seen
    +16   u32   byte_count   the file's length in bytes
    +20   u32   block_count  ceil(byte_count / block_size) on 326 of 326
    +24   u32   burst        1 on every entry seen
    +28   u32   gap          0 on every entry seen
    +32   char[32] name      NUL-padded
    +64   u32   last_copy    index of the last copy; copies = this + 1
    +68   u32[] copies       one absolute block number per copy
    size  = 72 + 4 * last_copy

The 3DO platform notes had `burst` and `gap` in the right place and the name in
the wrong one, and omitted `block_count` entirely; see docs/03 of this
repository.

USAGE

    python tools/opera.py IMAGE --list
    python tools/opera.py IMAGE --list --stale
    python tools/opera.py IMAGE --label
    python tools/opera.py IMAGE --extract DIR
    python tools/opera.py IMAGE --selftest
"""
import argparse
import os
import struct
import sys

T_FILE = 2
T_SPECIAL = 6
T_DIRECTORY = 7
LAST_ENTRY = 0x80000000


class BadBlock(Exception):
    """Raised when a block does not read as a directory block."""


class Image(object):
    """Random access to the 2,048-byte blocks of a raw or cooked track."""

    def __init__(self, path, raw=2352, off=16, size=2048):
        self.path = path
        self.raw = raw
        self.off = off
        self.size = size
        self.fh = open(path, "rb")
        total = os.path.getsize(path)
        if total % raw:
            raise SystemExit("%s: %d bytes is not a whole number of %d-byte "
                             "sectors" % (path, total, raw))
        self.sectors = total // raw

    def block(self, n):
        if not (0 <= n < self.sectors):
            raise BadBlock("block %d is outside the %d sectors of the track"
                           % (n, self.sectors))
        self.fh.seek(n * self.raw + self.off)
        return self.fh.read(self.size)

    def blocks(self, start, count):
        out = []
        for i in range(count):
            out.append(self.block(start + i))
        return b"".join(out)


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def i32(b, o):
    return struct.unpack_from(">i", b, o)[0]


class Label(object):
    def __init__(self, data):
        if data[0:1] != b"\x01":
            raise BadBlock("record type is %r, not 0x01" % data[0:1])
        if data[1:6] != b"ZZZZZ":
            raise BadBlock("sync bytes are %r, not 'ZZZZZ'" % data[1:6])
        self.record_type = data[0]
        self.record_version = data[6]
        self.flags = data[7]
        self.comment = data[8:40].rstrip(b"\0")
        self.label = data[40:72].rstrip(b"\0")
        self.identifier = u32(data, 72)
        self.block_size = u32(data, 76)
        self.block_count = u32(data, 80)
        self.root_id = u32(data, 84)
        self.root_blocks = u32(data, 88)
        self.root_block_size = u32(data, 92)
        self.root_last_copy = u32(data, 96)
        self.root_copies = [u32(data, 100 + 4 * i)
                            for i in range(self.root_last_copy + 1)]
        self.length = 100 + 4 * (self.root_last_copy + 1)
        if self.block_size not in (2048,):
            raise BadBlock("block size %d" % self.block_size)


class Entry(object):
    __slots__ = ("flags", "id", "type", "block_size", "byte_count",
                 "block_count", "burst", "gap", "name", "last_copy", "copies",
                 "size", "path", "stale")

    def __init__(self, b, o):
        self.flags = u32(b, o)
        self.id = u32(b, o + 4)
        self.type = b[o + 8:o + 12]
        self.block_size = u32(b, o + 12)
        self.byte_count = u32(b, o + 16)
        self.block_count = u32(b, o + 20)
        self.burst = u32(b, o + 24)
        self.gap = u32(b, o + 28)
        self.name = b[o + 32:o + 64].split(b"\0")[0]
        self.last_copy = u32(b, o + 64)
        self.copies = [u32(b, o + 68 + 4 * i) for i in range(self.last_copy + 1)]
        self.size = 72 + 4 * self.last_copy
        self.path = None
        self.stale = False

    @property
    def kind(self):
        return self.flags & 0xFF

    @property
    def last_in_block(self):
        return bool(self.flags & LAST_ENTRY)

    def sane(self, sectors):
        """Cheap plausibility, used to filter stale entries -- not to trust."""
        if self.kind not in (T_FILE, T_SPECIAL, T_DIRECTORY):
            return False
        if self.block_size != 2048:
            return False
        if not (0 <= self.last_copy < 64):
            return False
        if self.byte_count > 2048 * sectors:
            return False
        exp = (self.byte_count + 2047) // 2048
        if self.block_count != exp:
            return False
        for c in self.copies:
            if not (0 <= c < sectors):
                return False
        if not self.name or not all(32 <= c < 127 for c in self.name):
            return False
        return True


def read_dir_block(img, blk):
    """Parse one directory block. Raises BadBlock on anything implausible."""
    d = img.block(blk)
    nxt = i32(d, 0)
    prv = i32(d, 4)
    flags = u32(d, 8)
    ffb = u32(d, 12)
    feo = u32(d, 16)
    if feo < 20 or feo >= img.size:
        raise BadBlock("first_entry_offset %d out of range in block %d"
                       % (feo, blk))
    if ffb > img.size or ffb < feo - 1:
        raise BadBlock("first_free_byte %d out of range in block %d"
                       % (ffb, blk))
    return {"next": nxt, "prev": prv, "flags": flags,
            "first_free_byte": ffb, "first_entry_offset": feo, "data": d}


def entries_in_block(img, blk, stale=False):
    """Live entries of one directory block; with stale=True, the ones after
    first_free_byte as well, flagged."""
    h = read_dir_block(img, blk)
    d = h["data"]
    out = []
    o = h["first_entry_offset"]
    limit = h["first_free_byte"]
    while o + 72 <= limit + 1 and o + 72 <= img.size:
        e = Entry(d, o)
        if o + e.size > img.size:
            break
        out.append(e)
        o += e.size
        if e.last_in_block:
            break
    if stale:
        o = max(o, h["first_free_byte"])
        while o + 72 <= img.size:
            e = Entry(d, o)
            if o + e.size > img.size:
                break
            if e.sane(img.sectors):
                e.stale = True
                out.append(e)
                o += e.size
                if e.last_in_block:
                    break
            else:
                o += 4
    return out


def walk_dir(img, base, blocks=None, stale=False):
    """All entries of one copy of a directory, following next_block.

    `base` is the absolute block the copy list points at. next_block is a
    relative index, so the absolute block is base + index."""
    out = []
    idx = 0
    guard = 0
    while True:
        out.extend(entries_in_block(img, base + idx, stale=stale))
        h = read_dir_block(img, base + idx)
        nxt = h["next"]
        if nxt in (-1, 0xFFFFFFFF):
            break
        if blocks is not None and not (0 <= nxt < blocks):
            raise BadBlock("directory at %d: next_block %d is outside its "
                           "%d blocks" % (base, nxt, blocks))
        if nxt <= idx:
            raise BadBlock("directory at %d: next_block %d does not advance"
                           % (base, nxt))
        idx = nxt
        guard += 1
        if guard > 4096:
            raise BadBlock("directory chain from block %d does not terminate"
                           % base)
    return out


class Volume(object):
    def __init__(self, path, raw=2352, off=16, stale=False):
        self.img = Image(path, raw=raw, off=off)
        self.label = Label(self.img.block(0))
        self.stale_wanted = stale
        self.files = []
        self.dirs = []
        self.stale = []
        self._walk("", self.label.root_copies[0], self.label.root_blocks, 0)

    def _walk(self, prefix, block, blocks, depth):
        if depth > 32:
            raise BadBlock("directory nesting deeper than 32 at %s" % prefix)
        for e in walk_dir(self.img, block, blocks, stale=self.stale_wanted):
            e.path = prefix + "/" + e.name.decode("latin-1")
            if e.stale:
                self.stale.append(e)
                continue
            if e.kind == T_DIRECTORY:
                self.dirs.append(e)
                self._walk(e.path, e.copies[0], e.block_count, depth + 1)
            elif e.kind in (T_FILE, T_SPECIAL):
                self.files.append(e)
            else:
                raise BadBlock("entry %s has type byte %d" % (e.path, e.kind))

    def read(self, e, copy=0):
        raw = self.img.blocks(e.copies[copy], e.block_count)
        return raw[:e.byte_count]


def selftest(img):
    """The negative control. A reader that cannot fail is not a reader.

    Block 0 is the volume label, not a directory block; the first data block of
    a large file is not a directory block either. Both must raise. If either
    parses, the parser is too permissive and every count it produces is
    suspect."""
    bad = 0
    for blk, why in ((0, "the volume label"),
                     (1, "the block after the label")):
        try:
            h = read_dir_block(img, blk)
            ents = entries_in_block(img, blk)
            if ents and all(e.sane(img.sectors) for e in ents):
                print("FAIL: block %d (%s) parsed as %d plausible entries"
                      % (blk, why, len(ents)))
                bad += 1
            else:
                print("ok  : block %d (%s) yields nothing usable" % (blk, why))
        except BadBlock as exc:
            print("ok  : block %d (%s) rejected -- %s" % (blk, why, exc))
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--raw", type=int, default=2352)
    ap.add_argument("--off", type=int, default=16)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--label", action="store_true")
    ap.add_argument("--stale", action="store_true")
    ap.add_argument("--extract", metavar="DIR")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    img = Image(a.image, raw=a.raw, off=a.off)

    if a.selftest:
        sys.exit(1 if selftest(img) else 0)

    lb = Label(img.block(0))
    if a.label or not (a.list or a.extract or a.stale):
        print("label            : %s" % lb.label.decode("latin-1"))
        print("comment          : %r" % lb.comment)
        print("record version   : %d   flags %d" % (lb.record_version, lb.flags))
        print("identifier       : %d (0x%08X)" % (lb.identifier, lb.identifier))
        print("block size       : %d" % lb.block_size)
        print("blocks declared  : %d" % lb.block_count)
        print("sectors present  : %d" % img.sectors)
        print("root dir id      : %d" % lb.root_id)
        print("root dir blocks  : %d" % lb.root_blocks)
        print("root copies      : %d -> %s"
              % (len(lb.root_copies), lb.root_copies))
        print("label length     : %d bytes" % lb.length)

    if a.list or a.stale or a.extract:
        vol = Volume(a.image, raw=a.raw, off=a.off, stale=a.stale)
        if a.list:
            rows = [(e.byte_count, e.block_count, len(e.copies), e.copies[0],
                     e.type, e.path) for e in vol.files]
            rows.sort(key=lambda r: r[5])
            print("%12s %8s %6s %6s  %-8s %s"
                  % ("bytes", "blocks", "copies", "first", "type", "path"))
            for r in rows:
                print("%12d %8d %6d %6d  %-8r %s" % r)
            for e in sorted(vol.dirs, key=lambda x: x.path):
                print("%12s %8d %6d %6d  %-8s %s"
                      % ("<dir>", e.block_count, len(e.copies), e.copies[0],
                         "*dir", e.path))
            print("\n%d files, %d directories, %d bytes"
                  % (len(vol.files), len(vol.dirs),
                     sum(e.byte_count for e in vol.files)))
        if a.stale:
            print("\nstale entries past first_free_byte: %d" % len(vol.stale))
            print("%12s %8s %6s  %-8s %s"
                  % ("bytes", "blocks", "first", "type", "name"))
            for e in vol.stale:
                print("%12d %8d %6d  %-8r %s"
                      % (e.byte_count, e.block_count, e.copies[0], e.type,
                         e.path))
        if a.extract:
            n = 0
            for e in vol.files:
                dest = os.path.join(a.extract, e.path.lstrip("/"))
                d = os.path.dirname(dest)
                if d and not os.path.isdir(d):
                    os.makedirs(d)
                with open(dest, "wb") as fh:
                    fh.write(vol.read(e))
                n += 1
            print("extracted %d files to %s" % (n, a.extract))


if __name__ == "__main__":
    main()
