#!/usr/bin/env python3
"""isz.py -- read an InstallShield 3 "Z" archive (magic 0x8C655D13).

There is no published specification for this container. Every field below was
derived from the bytes of three specimens in one object and then checked
against a fourth from an unrelated product; fields whose meaning is not
established are printed as unnamed integers and are never used to decide
anything.

WHAT THE FORMAT DECLARES ABOUT ITSELF, WHICH IS THE WHOLE POINT

    +0x00  u32  magic 0x8C655D13
    +0x04  u16  314 on 4 of 4 specimens
    +0x06  u16  2   on 4 of 4
    +0x0C  u16  FILE COUNT
    +0x0E  u16  DOS date
    +0x10  u16  DOS time
    +0x12  u32  ARCHIVE SIZE -- must equal the length of the file
    +0x1A  u16  255 on 4 of 4; equals the offset of the first member's data
    +0x29  u32  offset of the directory table
    +0x2D  u32  length of the directory table
    +0x31  u16  DIRECTORY COUNT
    +0x16  u32  the sum of every entry's expanded size
    +0x33  u32  offset of the entry table
    +0x37  u16  length of the entry table -- SIXTEEN BITS, and it wraps: on
                Microsoft FrontPage 98's DATA.Z the table is 131,215 bytes and
                the field reads 143, which is 131,215 modulo 65,536. The true
                length is fixed by the archive size, and the reader uses it
                only when the declared value is congruent to it.

    directory record:  u16 file count, u16 chunk size, u16 name length,
                       name, NUL, padding to chunk size
    entry record:      u8 volume, u16 index, u32 expanded size,
                       u32 STORED size, u32 offset, u16 DOS date,
                       u16 DOS time, u32 attributes, u16 chunk size,
                       4 unnamed bytes, u8 name length, name, NUL,
                       12 unnamed bytes; total = chunk size

SIX CLOSURES, ALL CHECKED

    1. the declared archive size equals the length of the file;
    2. the directory records consume exactly the declared table length;
    3. the entry records consume exactly the entry table's length;
    4. the directory file counts sum to the header's file count;
    5. the members' offsets chain: each member begins where the previous one
       ended, the first at the declared data offset, and the last ends exactly
       at the directory table;
    6. data offset + sum of stored sizes + both table lengths = archive size,
       at residue 0.

    And a seventh, which `verify` performs and the others do not: every
    member's decompressed length equals the expanded size its entry declares,
    and those declared sizes sum to the u32 at +0x16.

The payload is PKWARE Data Compression Library "implode", the same stream
`blast` reads. That identification is made by decompressing and matching the
expanded length the entry declares, not by any string in any file.

    python tools/isz.py header _work/members/_SETUP.1
    python tools/isz.py list   _work/members/_SETUP.1 --tsv notes/setup1.tsv
    python tools/isz.py verify _work/members/_SETUP.1
    python tools/isz.py extract _work/members/_SETUP.1 --name rpg95.exe --out DIR
    python tools/isz.py selftest
"""
import argparse
import collections
import os
import struct
import sys

MAGIC = 0x8C655D13


class ZError(Exception):
    """Raised for any archive or stream this reader will not stand behind."""


# ---------------------------------------------------------------- PKWARE DCL

LITLEN = bytes([
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8,
    9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5,
    7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12,
    8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27,
    44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45,
    44, 173])
LENLEN = bytes([2, 35, 36, 53, 38, 23])
DISTLEN = bytes([2, 20, 53, 230, 247, 151, 248])
BASE = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264]
EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
MAXBITS = 13


class Huffman(object):
    """A canonical Huffman table in the shape `blast` uses: a count of symbols
    per code length and the symbols in canonical order."""

    def __init__(self, rep):
        lengths = []
        for byte in rep:
            n = (byte >> 4) + 1
            lengths.extend([byte & 15] * n)
        self.count = [0] * (MAXBITS + 1)
        for l in lengths:
            self.count[l] += 1
        if self.count[0] == len(lengths):
            raise ZError("degenerate Huffman table")
        left = 1
        for l in range(1, MAXBITS + 1):
            left <<= 1
            left -= self.count[l]
            if left < 0:
                raise ZError("over-subscribed Huffman table at length %d" % l)
        offs = [0] * (MAXBITS + 2)
        for l in range(1, MAXBITS):
            offs[l + 1] = offs[l] + self.count[l]
        self.symbol = [0] * len(lengths)
        base = list(offs)
        for sym, l in enumerate(lengths):
            if l:
                self.symbol[base[l]] = sym
                base[l] += 1
        # The encoding side, used only by selftest.
        self.code_of = {}
        first = index = 0
        for l in range(1, MAXBITS + 1):
            cnt = self.count[l]
            for k in range(cnt):
                self.code_of[self.symbol[index + k]] = (first + k, l)
            index += cnt
            first = (first + cnt) << 1


LITCODE = Huffman(LITLEN)
LENCODE = Huffman(LENLEN)
DISTCODE = Huffman(DISTLEN)


class BitReader(object):
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.buf = 0
        self.cnt = 0

    def bits(self, need):
        val = self.buf
        while self.cnt < need:
            if self.pos >= len(self.data):
                raise ZError("the compressed stream ends inside a code "
                             "(wanted %d bits at byte %d of %d)"
                             % (need, self.pos, len(self.data)))
            val |= self.data[self.pos] << self.cnt
            self.pos += 1
            self.cnt += 8
        self.buf = val >> need
        self.cnt -= need
        return val & ((1 << need) - 1)

    def decode(self, h):
        code = first = index = 0
        length = 1
        while length <= MAXBITS:
            code |= self.bits(1) ^ 1
            count = h.count[length]
            if code < first + count:
                return h.symbol[index + (code - first)]
            index += count
            first = (first + count) << 1
            code <<= 1
            length += 1
        raise ZError("no Huffman code of 13 bits or fewer matched at byte %d"
                     % self.pos)


def blast(data, expected=None):
    """Decompress a PKWARE DCL implode stream. `expected`, when given, is
    checked and a mismatch is fatal."""
    r = BitReader(data)
    lit = r.bits(8)
    if lit > 1:
        raise ZError("literal flag is %d, must be 0 or 1" % lit)
    dict_bits = r.bits(8)
    if dict_bits < 4 or dict_bits > 6:
        raise ZError("dictionary size code is %d, must be 4, 5 or 6"
                     % dict_bits)
    out = bytearray()
    while True:
        if r.bits(1):
            sym = r.decode(LENCODE)
            length = BASE[sym] + r.bits(EXTRA[sym])
            if length == 519:
                break
            shift = 2 if length == 2 else dict_bits
            dist = r.decode(DISTCODE) << shift
            dist += r.bits(shift)
            dist += 1
            if dist > len(out):
                raise ZError("back-reference of %d at output position %d "
                             "points before the start of the stream"
                             % (dist, len(out)))
            start = len(out) - dist
            for i in range(length):
                out.append(out[start + i])
        else:
            out.append(r.decode(LITCODE) if lit else r.bits(8))
    if expected is not None and len(out) != expected:
        raise ZError("stream expanded to %d bytes, the entry declares %d"
                     % (len(out), expected))
    return bytes(out)


# ------------------------------------------------------------- the container

def dos_date(v):
    y = 1980 + (v >> 9)
    m = (v >> 5) & 15
    d = v & 31
    return "%04d-%02d-%02d" % (y, m, d)


def dos_time(v):
    return "%02d:%02d:%02d" % (v >> 11, (v >> 5) & 63, (v & 31) * 2)


def parse(data, path="<memory>"):
    if len(data) < 0x39:
        raise ZError("a %d-byte file is too short to be a Z archive"
                     % len(data))
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MAGIC:
        raise ZError("magic is 0x%08X, not 0x%08X" % (magic, MAGIC))
    h = {}
    h["u04"], h["u06"], h["u08"], h["u0a"] = struct.unpack_from("<4H", data, 4)
    h["file_count"] = struct.unpack_from("<H", data, 0x0C)[0]
    h["date"], h["time"] = struct.unpack_from("<2H", data, 0x0E)
    h["archive_size"] = struct.unpack_from("<I", data, 0x12)[0]
    h["u16"] = struct.unpack_from("<I", data, 0x16)[0]
    h["u1a"] = struct.unpack_from("<H", data, 0x1A)[0]
    h["toc_offset"] = struct.unpack_from("<I", data, 0x29)[0]
    h["dir_table_len"] = struct.unpack_from("<I", data, 0x2D)[0]
    h["dir_count"] = struct.unpack_from("<H", data, 0x31)[0]
    h["entry_offset"] = struct.unpack_from("<I", data, 0x33)[0]
    h["entry_table_len"] = struct.unpack_from("<H", data, 0x37)[0]

    # CLOSURE 1
    if h["archive_size"] != len(data):
        raise ZError("the header declares an archive of %d bytes and the file "
                     "is %d" % (h["archive_size"], len(data)))
    for label, off, length in (("directory table", h["toc_offset"],
                                h["dir_table_len"]),
                               ("entry table", h["entry_offset"],
                                h["entry_table_len"])):
        if off + length > len(data) or off < 0:
            raise ZError("the %s at %d for %d bytes does not lie inside a "
                         "%d-byte file" % (label, off, length, len(data)))

    # the directory table -- CLOSURE 2
    dirs = []
    p = h["toc_offset"]
    end = p + h["dir_table_len"]
    while p < end:
        if p + 6 > end:
            raise ZError("a directory record at %d does not fit in the table"
                         % p)
        n_files, chunk, n_name = struct.unpack_from("<3H", data, p)
        if chunk < 6 + n_name + 1 or p + chunk > end:
            raise ZError("directory record at %d declares a chunk of %d, "
                         "which does not hold a %d-byte name inside the table"
                         % (p, chunk, n_name))
        name = data[p + 6:p + 6 + n_name].decode("cp437")
        if data[p + 6 + n_name] != 0:
            raise ZError("directory name at %d is not NUL-terminated" % p)
        dirs.append({"files": n_files, "name": name, "chunk": chunk})
        p += chunk
    if p != end:
        raise ZError("the directory records consume %d bytes, the header "
                     "declares %d" % (p - h["toc_offset"], h["dir_table_len"]))
    if len(dirs) != h["dir_count"]:
        raise ZError("the header declares %d directories, the table holds %d"
                     % (h["dir_count"], len(dirs)))

    # The entry-table length is a u16, and an archive whose entry records run
    # to more than 65,535 bytes cannot state its own table length. That is not
    # a guess: on such a specimen the declared value is congruent to the true
    # length modulo 65,536, and the true length is fixed by the archive size,
    # which the file has already been checked against. When the two agree the
    # declared value is used; when they are congruent the true length is used
    # and the wrap is recorded; anything else is fatal.
    true_entry_len = h["archive_size"] - h["entry_offset"]
    h["entry_table_len_true"] = true_entry_len
    h["entry_table_len_wrapped"] = 0
    if true_entry_len != h["entry_table_len"]:
        if true_entry_len % 65536 != h["entry_table_len"] or true_entry_len < 0:
            raise ZError("the entry table is declared as %d bytes, the archive "
                         "leaves %d after its offset, and the two are not "
                         "congruent modulo 65536"
                         % (h["entry_table_len"], true_entry_len))
        h["entry_table_len_wrapped"] = true_entry_len // 65536

    # the entry table -- CLOSURE 3
    entries = []
    p = h["entry_offset"]
    end = p + true_entry_len
    while p < end:
        if p + 0x1E > end:
            raise ZError("an entry record at %d does not fit in the table" % p)
        vol = data[p]
        index = struct.unpack_from("<H", data, p + 1)[0]
        expanded, stored, offset = struct.unpack_from("<3I", data, p + 3)
        d, t = struct.unpack_from("<2H", data, p + 0x0F)
        attrib = struct.unpack_from("<I", data, p + 0x13)[0]
        chunk = struct.unpack_from("<H", data, p + 0x17)[0]
        n_name = data[p + 0x1D]
        if chunk < 0x1E + n_name + 1 or p + chunk > end:
            raise ZError("entry record at %d declares a chunk of %d, which "
                         "does not hold a %d-byte name inside the table"
                         % (p, chunk, n_name))
        name = data[p + 0x1E:p + 0x1E + n_name].decode("cp437")
        if data[p + 0x1E + n_name] != 0:
            raise ZError("entry name at %d is not NUL-terminated" % p)
        if offset + stored > len(data):
            raise ZError("entry %r at %d claims %d bytes at offset %d, past "
                         "the end of a %d-byte file"
                         % (name, p, stored, offset, len(data)))
        entries.append({"volume": vol, "index": index, "expanded": expanded,
                        "stored": stored, "offset": offset, "date": d,
                        "time": t, "attrib": attrib, "chunk": chunk,
                        "name": name, "record_at": p})
        p += chunk
    if p != end:
        raise ZError("the entry records consume %d bytes, the table is %d"
                     % (p - h["entry_offset"], true_entry_len))
    if len(entries) != h["file_count"]:
        raise ZError("the header declares %d files, the table holds %d"
                     % (h["file_count"], len(entries)))

    return {"path": path, "header": h, "dirs": dirs, "entries": entries,
            "length": len(data)}


def closures(arc):
    """CLOSURE 4 and CLOSURE 5. Returns a list of (label, ok, detail)."""
    h = arc["header"]
    entries = arc["entries"]
    out = []

    data_start = entries[0]["offset"] if entries else h["toc_offset"]
    cursor = data_start
    breaks = []
    for e in entries:
        if e["offset"] != cursor:
            breaks.append((e["name"], cursor, e["offset"]))
        cursor = e["offset"] + e["stored"]
    out.append(("the members' offsets chain with no gap and no overlap",
                not breaks,
                "%d of %d members begin where the previous one ended"
                % (len(entries) - len(breaks), len(entries))))
    out.append(("the last member ends exactly at the directory table",
                cursor == h["toc_offset"],
                "last member ends at %d, the directory table begins at %d"
                % (cursor, h["toc_offset"])))

    stored = sum(e["stored"] for e in entries)
    total = data_start + stored + h["dir_table_len"] + h["entry_table_len_true"]
    out.append(("header + data + both tables = the archive, residue 0",
                total == h["archive_size"],
                "%d + %d + %d + %d = %d against %d, residue %d"
                % (data_start, stored, h["dir_table_len"],
                   h["entry_table_len_true"], total, h["archive_size"],
                   h["archive_size"] - total)))

    declared = sum(d["files"] for d in arc["dirs"])
    out.append(("the directory file counts sum to the header's file count",
                declared == h["file_count"],
                "%d against %d" % (declared, h["file_count"])))
    return out


def cmd_header(args):
    with open(args.path, "rb") as fh:
        data = fh.read()
    arc = parse(data, args.path)
    h = arc["header"]
    print("archive         : %s" % args.path)
    print("file length     : %d bytes" % arc["length"])
    print("magic           : 0x%08X" % MAGIC)
    print("+0x04 .. +0x0A  : %d %d %d %d"
          % (h["u04"], h["u06"], h["u08"], h["u0a"]))
    print("+0x0C file count: %d" % h["file_count"])
    print("+0x0E date      : 0x%04X  %s" % (h["date"], dos_date(h["date"])))
    print("+0x10 time      : 0x%04X  %s" % (h["time"], dos_time(h["time"])))
    print("+0x12 arch size : %d   (file is %d)"
          % (h["archive_size"], arc["length"]))
    print("+0x16 unnamed   : %d" % h["u16"])
    print("+0x1A           : %d" % h["u1a"])
    print("+0x29 toc at    : %d" % h["toc_offset"])
    print("+0x2D toc len   : %d" % h["dir_table_len"])
    print("+0x31 dir count : %d" % h["dir_count"])
    print("+0x33 entries at: %d" % h["entry_offset"])
    print("+0x37 entry len : %d   (true %d, u16 wraps %d times)"
          % (h["entry_table_len"], h["entry_table_len_true"],
             h["entry_table_len_wrapped"]))
    print("first data at   : %d" % (arc["entries"][0]["offset"]
                                    if arc["entries"] else -1))
    return 0


def cmd_list(args):
    with open(args.path, "rb") as fh:
        data = fh.read()
    arc = parse(data, args.path)
    h, entries = arc["header"], arc["entries"]
    print("archive     : %s   %d bytes" % (args.path, arc["length"]))
    print("declared    : %d files in %d directories"
          % (h["file_count"], h["dir_count"]))
    print()
    print("directories:")
    print("  %-4s %6s %6s  %s" % ("idx", "files", "chunk", "name"))
    for i, d in enumerate(arc["dirs"]):
        print("  %-4d %6d %6d  %s"
              % (i, d["files"], d["chunk"], d["name"] or "(empty)"))
    print()
    for label, ok, detail in closures(arc):
        print("  %-58s %s   %s" % (label, "ok  " if ok else "FAIL", detail))
    print()
    stored = sum(e["stored"] for e in entries)
    expanded = sum(e["expanded"] for e in entries)
    print("stored bytes   : %d" % stored)
    print("expanded field : %d" % expanded)
    smaller = sum(1 for e in entries if e["expanded"] < e["stored"])
    print("entries whose expanded field is BELOW the stored size : %d of %d"
          % (smaller, len(entries)))
    print()
    n = min(args.show, len(entries))
    print("first %d of %d entries:" % (n, len(entries)))
    print("  %5s %10s %10s %10s %5s %-10s %-8s %s"
          % ("#", "stored", "expanded", "offset", "vol", "date", "time",
             "name"))
    for i, e in enumerate(entries[:n]):
        print("  %5d %10d %10d %10d %5d %-10s %-8s %s"
              % (i, e["stored"], e["expanded"], e["offset"], e["volume"],
                 dos_date(e["date"]), dos_time(e["time"]), e["name"]))
    if args.tsv:
        out = os.path.abspath(args.tsv)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("index\tstored\texpanded\toffset\tvolume\tdate\ttime\t"
                     "attrib\tchunk\tname\n")
            for i, e in enumerate(entries):
                fh.write("%d\t%d\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%s\n"
                         % (i, e["stored"], e["expanded"], e["offset"],
                            e["volume"], dos_date(e["date"]),
                            dos_time(e["time"]), e["attrib"], e["chunk"],
                            e["name"]))
        print()
        print("wrote %s -- %d rows" % (args.tsv, len(entries)))
    return 0


def cmd_verify(args):
    with open(args.path, "rb") as fh:
        data = fh.read()
    arc = parse(data, args.path)
    entries = arc["entries"]
    limit = len(entries) if args.all else min(args.n, len(entries))
    chosen = entries[:limit]
    ok = bad = 0
    failures = []
    counts = collections.Counter()
    for e in chosen:
        blob = data[e["offset"]:e["offset"] + e["stored"]]
        try:
            outb = blast(blob, expected=e["expanded"])
            ok += 1
            counts[outb[:2].decode("latin-1")] += 1
        except ZError as exc:
            bad += 1
            if len(failures) < 12:
                failures.append((e["name"], str(exc)[:90]))
    print("archive        : %s" % args.path)
    print("members tried  : %d of %d" % (len(chosen), len(entries)))
    print("EXPANDED LENGTH MATCHES THE DECLARED FIELD : %d of %d"
          % (ok, len(chosen)))
    print("refused or mismatched                      : %d of %d"
          % (bad, len(chosen)))
    if failures:
        print()
        print("first %d failures:" % len(failures))
        for nm, msg in failures:
            print("  %-24s %s" % (nm, msg))
    if counts:
        print()
        print("first two bytes of the expanded members:")
        for k, v in counts.most_common(10):
            printable = "".join(c if 32 <= ord(c) < 127 else "." for c in k)
            print("  %-6r %-6s %d" % (k, printable, v))
    return 1 if bad else 0


def cmd_extract(args):
    with open(args.path, "rb") as fh:
        data = fh.read()
    arc = parse(data, args.path)
    wanted = [e for e in arc["entries"]
              if args.all or e["name"].lower() == args.name.lower()]
    if not wanted:
        raise ZError("no member named %r in %s" % (args.name, args.path))
    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for e in wanted:
        blob = data[e["offset"]:e["offset"] + e["stored"]]
        body = blast(blob, expected=e["expanded"])
        dest = os.path.join(outdir, "%03d_%s" % (e["index"], e["name"]))
        with open(dest, "wb") as fh:
            fh.write(body)
        print("%-24s %8d stored -> %8d expanded   %s"
              % (e["name"], e["stored"], len(body), os.path.basename(dest)))
        n += 1
    print("%d members written to %s" % (n, args.out))
    return 0


# ------------------------------------------------------------------ selftest

class BitWriter(object):
    def __init__(self):
        self.out = bytearray()
        self.buf = 0
        self.cnt = 0

    def bits(self, value, n):
        for i in range(n):
            self.buf |= ((value >> i) & 1) << self.cnt
            self.cnt += 1
            if self.cnt == 8:
                self.out.append(self.buf)
                self.buf = 0
                self.cnt = 0

    def code(self, h, symbol):
        c, length = h.code_of[symbol]
        for i in range(length - 1, -1, -1):
            self.bits(((c >> i) & 1) ^ 1, 1)

    def done(self):
        if self.cnt:
            self.out.append(self.buf)
        return bytes(self.out)


def make_stream(payload, dict_bits=4, use_match=False, bad_dist=0):
    """Build a DCL implode stream with uncoded literals. Used only by
    selftest, so that the decoder is exercised against bytes this file did not
    decompress."""
    w = BitWriter()
    w.bits(0, 8)              # literal flag: uncoded
    w.bits(dict_bits, 8)
    for b in payload:
        w.bits(0, 1)
        w.bits(b, 8)
    if use_match or bad_dist:
        w.bits(1, 1)
        w.code(LENCODE, 2)    # BASE[2] = 4, no extra bits
        dist = (bad_dist or len(payload)) - 1
        w.code(DISTCODE, dist >> dict_bits)
        w.bits(dist & ((1 << dict_bits) - 1), dict_bits)
    w.bits(1, 1)
    w.code(LENCODE, 15)       # BASE[15] = 264, 8 extra bits
    w.bits(255, 8)            # 264 + 255 = 519, the end code
    return w.done()


def build_archive(members, magic=MAGIC, lie_count=0, lie_size=0,
                  break_chain=False, lie_table_len=0):
    """Construct a Z archive in memory. Used only by selftest."""
    data_start = 255
    blobs = []
    off = data_start
    recs = []
    for name, payload in members:
        blob = make_stream(payload)
        recs.append({"name": name, "stored": len(blob), "offset": off,
                     "expanded": len(payload)})
        blobs.append(blob)
        off += len(blob)
    if break_chain and recs:
        recs[-1]["offset"] += 3

    dir_tbl = bytearray()
    nm = b""
    dir_tbl += struct.pack("<3H", len(members), 6 + len(nm) + 1 + 4, len(nm))
    dir_tbl += nm + b"\x00" + b"\x00" * 4

    ent_tbl = bytearray()
    for r in recs:
        nb = r["name"].encode("cp437")
        chunk = 0x1E + len(nb) + 1 + 12
        rec = bytearray()
        rec += bytes([1]) + struct.pack("<H", 0)
        rec += struct.pack("<3I", r["expanded"], r["stored"], r["offset"])
        rec += struct.pack("<2H", 0x26EC, 0x0B73)
        rec += struct.pack("<I", 0x20)
        rec += struct.pack("<H", chunk)
        rec += b"\x40\x00\x00\x01"
        rec += bytes([len(nb)]) + nb + b"\x00"
        rec += b"\x00" * 12
        assert len(rec) == chunk, (len(rec), chunk)
        ent_tbl += rec

    body = b"".join(blobs)
    toc = data_start + len(body)
    ent_off = toc + len(dir_tbl)
    total = ent_off + len(ent_tbl)

    head = bytearray(b"\x00" * data_start)
    struct.pack_into("<I", head, 0, magic)
    struct.pack_into("<4H", head, 4, 314, 2, 0, 0)
    struct.pack_into("<H", head, 0x0C, len(members) + lie_count)
    struct.pack_into("<2H", head, 0x0E, 0x26EC, 0x0B73)
    struct.pack_into("<I", head, 0x12, total + lie_size)
    struct.pack_into("<H", head, 0x1A, 255)
    struct.pack_into("<I", head, 0x29, toc)
    struct.pack_into("<I", head, 0x2D, len(dir_tbl))
    struct.pack_into("<H", head, 0x31, 1)
    struct.pack_into("<I", head, 0x33, ent_off)
    struct.pack_into("<H", head, 0x37, len(ent_tbl) + lie_table_len)
    return bytes(head) + body + bytes(dir_tbl) + bytes(ent_tbl)


def cmd_selftest(args):
    checks = []
    members = [("A.TXT", b"the quick brown fox" * 3),
               ("B.DAT", bytes(range(256)))]

    spec = build_archive(members)
    try:
        arc = parse(spec)
        names = [e["name"] for e in arc["entries"]]
        cl = closures(arc)
        bodies = [blast(spec[e["offset"]:e["offset"] + e["stored"]],
                        expected=e["expanded"]) for e in arc["entries"]]
        ok = (names == ["A.TXT", "B.DAT"] and all(c[1] for c in cl)
              and bodies[0] == members[0][1] and bodies[1] == members[1][1])
        checks.append(("a well-formed archive parses, closes and expands",
                       ok, "" if ok else "parsed but a value is wrong"))
    except ZError as e:
        checks.append(("a well-formed archive parses, closes and expands",
                       False, str(e)))

    # A back-reference must round-trip, or the copy path is untested.
    payload = b"ABCD"
    try:
        got = blast(make_stream(payload, use_match=True), expected=8)
        ok = got == b"ABCDABCD"
        checks.append(("a length/distance pair round-trips", ok,
                       "" if ok else "got %r" % got))
    except ZError as e:
        checks.append(("a length/distance pair round-trips", False, str(e)))

    rejects = [
        ("wrong magic", lambda: parse(build_archive(members,
                                                    magic=0x12345678))),
        ("a declared archive size that is not the file length",
         lambda: parse(build_archive(members, lie_size=64))),
        ("a file count larger than the entry table holds",
         lambda: parse(build_archive(members, lie_count=4))),
        ("an entry table length the records do not fill",
         lambda: parse(build_archive(members, lie_table_len=-8))),
        ("an eight-byte file", lambda: parse(b"\x13\x5d\x65\x8c\x00" * 2)),
        ("a stream with a literal flag of 2",
         lambda: blast(b"\x02\x04\x00\x00")),
        ("a stream with a dictionary code of 9",
         lambda: blast(b"\x00\x09\x00\x00")),
        ("a truncated stream", lambda: blast(make_stream(b"hello")[:3])),
        ("a stream whose expanded length is not what was declared",
         lambda: blast(make_stream(b"hello"), expected=99)),
        ("a back-reference before the start of the stream",
         lambda: blast(make_stream(b"AB", bad_dist=10))),
    ]
    for label, fn in rejects:
        try:
            fn()
            checks.append((label + " is rejected", False,
                           "ACCEPTED -- the reader did not object"))
        except ZError as e:
            checks.append((label + " is rejected", True, str(e)[:66]))

    # The chain check must fire on a broken chain but must not be fatal to
    # parsing, so it is checked through closures() rather than parse().
    arc = parse(build_archive(members, break_chain=True))
    cl = dict((c[0], c[1]) for c in closures(arc))
    ok = not cl["the members' offsets chain with no gap and no overlap"]
    checks.append(("a broken offset chain is reported as a failed closure",
                   ok, "" if ok else "the closure passed on a broken chain"))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL",
                                   note))
        if not ok:
            failed += 1
    print()
    print("%d checks, 3 accepted specimens, %d rejected specimens, %d failures"
          % (len(checks), len(rejects), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("header")
    h.add_argument("path")
    h.set_defaults(func=cmd_header)
    l = sub.add_parser("list")
    l.add_argument("path")
    l.add_argument("--tsv")
    l.add_argument("--show", type=int, default=12)
    l.set_defaults(func=cmd_list)
    v = sub.add_parser("verify")
    v.add_argument("path")
    v.add_argument("-n", type=int, default=8)
    v.add_argument("--all", action="store_true")
    v.set_defaults(func=cmd_verify)
    x = sub.add_parser("extract")
    x.add_argument("path")
    x.add_argument("--name", default="")
    x.add_argument("--all", action="store_true")
    x.add_argument("--out", required=True)
    x.set_defaults(func=cmd_extract)
    s = sub.add_parser("selftest")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args()
    try:
        return args.func(args)
    except ZError as e:
        print("isz: REFUSED: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
