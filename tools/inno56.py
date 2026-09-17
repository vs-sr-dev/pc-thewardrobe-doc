#!/usr/bin/env python3
"""inno56.py -- a reader for Inno Setup 5.6.2 Unicode installers whose file
data lives in an external `idska32` disk slice.

WHY THIS IS NOT `inno.py`
--------------------------------------------------------------------------
`tools/inno.py` is a real reader, 31,848 bytes, written for `pc-lucignolo-doc`
on two **Inno Setup 5.2.1 ANSI** installers whose payload sat inside the
executable. It refuses on this object at line 119 and the refusal is correct:

    InnoError: no SetupLdrOffsetTable ID at 0xC988: got b'^[\\xc3\\x90SVWU...'

It names the offset it looked at, prints the twelve bytes it found instead,
and stops. That defect belongs to the repository that owns the tool, so it is
reported there and not patched here. This file is a second reader for a
version the first one was not derived from, and every place the two differ is
listed below with the measurement that settled it.

    property            5.2.1 ANSI (inno.py)      5.6.2 Unicode (here)
    ----------------    ----------------------    ------------------------
    offset table at     a hard-coded 0xC988       FOUND, by its 12-byte ID
    strings             ANSI, u32 char count      UTF-16LE, u32 BYTE count
    file entry fixed    79 bytes                  43 bytes
    location stride     70 bytes  (MD5)           74 bytes  (SHA-1)
    header block codec  LZMA1                     LZMA1  (unchanged)
    location block      LZMA1                     STORED (compressed flag 0)
    file data codec     LZMA1, one solid chunk    LZMA2, one chunk per member
    payload lives in    the .exe, at Offset1      an external .bin, Offset1=0

**The offset is derived, never assumed.** `LDR_ID` occurs exactly once in the
897,832 bytes of this object's stub, at 0x2E36C, and that offset is also
reachable without a byte search at all: it is the content of the PE resource
`RCDATA 11111`, whose RVA 0x3816C maps through the `.rsrc` section header to
file offset 0x3816C - 0x1E000 + 0x14200 = 0x2E36C. Both routes are
implemented; `ldr` prints both and says whether they agree.

WHAT THE FORMAT LOOKS LIKE, AS MEASURED
--------------------------------------------------------------------------
The stub's nine PE sections end at Offset0 and everything after them is data:

    [ PE image | setup header @Offset0 | locations | setup.e32 @OffsetEXE
      | 53 bytes of GOG | Authenticode certificate table ]

A block is

    64 bytes  a NUL-padded identification string   (only at Offset0)
    uint32    CRC-32 of the next five bytes
    uint32    stored_size, framed, INCLUDING the per-chunk CRCs
    uint8     compressed: 1 = LZMA1, 0 = stored
    then repeating: uint32 chunk CRC-32, then up to 4096 bytes

That framing is byte-for-byte what `inno.py` derived on 5.2.1 and it did not
change. What changed is that on this object the SECOND block -- the file
location array -- has the compressed flag **0**, so its payload is the array
verbatim and there is no LZMA1 header to feed anything.

A `String` in a Unicode build is a uint32 **byte** count followed by that many
bytes of UTF-16LE. A reader that walks it as ANSI finds nothing at all.

    TSetupFileEntry  = 10 strings, then 43 fixed bytes:
        MinVersion             10   (WinVersion u32, NTVersion u32, SP u16)
        OnlyBelowVersion       10
        LocationEntry           4   signed; -1 means "no data"
        Attribs                 4
        ExternalSize            8
        PermissionsEntry        2   signed
        Options                 4
        FileType                1
                              ----
                               43

    the ten strings, in order:
        SourceFilename DestName InstallFontName StrongAssemblyName
        Components Tasks Languages Check BeforeInstall AfterInstall

**43 was measured, not recalled.** `find_file_entries` walks candidate
offsets, and the distance from the end of a record's tenth string to the start
of the next record's first string is a constant across the whole array; the
histogram of that distance over the array has one bucket.

    TSetupFileLocationEntry = 74 bytes:
        FirstSlice u32, LastSlice u32, StartOffset u32,
        ChunkSuboffset u64, OriginalSize u64, ChunkCompressedSize u64,
        SHA1Sum 20, SourceTimeStamp FILETIME u64,
        FileVersionMS u32, FileVersionLS u32, Flags u8, Sign u8

**74 was proved by division, exactly as 70 was on the older object.** The
location block is 81,770 bytes. 74 divides it 1,105 times and 70 does not
divide it at all, so the digest is the 20-byte SHA-1 that Inno adopted at
5.3.9 and the version is above 5.3.9 -- which corroborates the identification
string instead of believing it. (130 also divides, 629 times; 130 is not a
plausible record size for these fields and the SHA-1 verification below is
what actually settles it.)

THE SLICE
--------------------------------------------------------------------------
    12 bytes    b'idska32\\x1a' + a uint32 that is the slice's OWN SIZE
                (2,890,625,276 here, agreeing with the file to the byte --
                 one specimen, so `slice` prints both and says whether they
                 agree rather than asserting a rule about the format)
    then, at each location entry's StartOffset:
        4 bytes     b'zlb\\x1a'
        csz bytes   the member, stored or LZMA2-compressed
        2 bytes     b'\\x0c\\x00', present ONLY after a compressed chunk

A compressed chunk's first byte is the LZMA2 dictionary-size property and the
rest is a raw LZMA2 stream. The two trailing bytes are constant across all 194
compressed chunks on this object and what they are is **not** identified here;
`slice` reports them and the leftovers chapter records the question.

FLAGS, AND ONE THAT MATTERS
--------------------------------------------------------------------------
    0x01 VersionInfoValid   0x02 VersionInfoNotValid
    0x10 CallInstructionOptimized       0x80 ChunkCompressed

`CallInstructionOptimized` means Inno rewrote the operands of CALL/JMP in a PE
file before compressing it, and the stored SHA-1 is of the file **before** that
rewrite. A reader that does not reverse the filter gets a digest mismatch on
exactly those members and on no others. This tool does not reverse it; it
reports the mismatches and the flag beside them, because a checksum that finds
a known bug is worth more than one that is quietly skipped.

    python tools/inno56.py ldr      SETUP.EXE
    python tools/inno56.py blocks   SETUP.EXE
    python tools/inno56.py entries  SETUP.EXE
    python tools/inno56.py census   SETUP.EXE
    python tools/inno56.py slice    SETUP.EXE --slice SETUP-1.bin
    python tools/inno56.py extract  SETUP.EXE --slice SETUP-1.bin --out DIR
    python tools/inno56.py verify   SETUP.EXE --slice SETUP-1.bin
    python tools/inno56.py magic    SETUP.EXE --slice SETUP-1.bin
    python tools/inno56.py e32      SETUP.EXE
    python tools/inno56.py selftest

`selftest` builds specimens in memory and requires the bad ones to be refused;
it needs no object on disk and it is the `validate` that runs before any
`census`.
"""
import argparse
import binascii
import collections
import hashlib
import lzma
import os
import struct
import sys

LDR_ID = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a"
SLICE_ID = b"idska32\x1a"
CHUNK_MAGIC = b"zlb\x1a"
CRC_CHUNK = 4096
FILE_ENTRY_FIXED = 43
LOCATION_STRIDE = 74

FLAG_NAMES = [
    (0x01, "VersionInfoValid"),
    (0x02, "VersionInfoNotValid"),
    (0x04, "TimeStampInUTC"),
    (0x08, "IsUninstallExe"),
    (0x10, "CallInstructionOptimized"),
    (0x20, "Touch"),
    (0x40, "ChunkEncrypted"),
    (0x80, "ChunkCompressed"),
]


class InnoError(Exception):
    pass


# ---------------------------------------------------------------- the table

def find_ldr_table(data):
    """Return every offset at which the 12-byte SetupLdrOffsetTable ID occurs.

    Derived from the population rather than assumed: `inno.py` carries
    LDR_TABLE_OFFSET = 0xC988, which was true of the file it was written for
    and is wrong here by 137,700 bytes."""
    out = []
    i = data.find(LDR_ID)
    while i >= 0:
        out.append(i)
        i = data.find(LDR_ID, i + 1)
    return out


def rsrc_11111_offset(data):
    """Locate RCDATA 11111 through the PE headers, without a byte search.

    Returns (file_offset, size) or None. This is a second, independent route
    to the same table and `ldr` compares the two."""
    try:
        if data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return None
        coff = e_lfanew + 4
        nsec, = struct.unpack("<H", data[coff + 2:coff + 4])
        opt_size, = struct.unpack("<H", data[coff + 16:coff + 18])
        opt = coff + 20
        rsrc_rva, = struct.unpack("<I", data[opt + 112:opt + 116])
        secs = []
        p = opt + opt_size
        for _ in range(nsec):
            name = data[p:p + 8].rstrip(b"\0")
            vsize, vaddr, rawsize, rawoff = struct.unpack("<IIII",
                                                          data[p + 8:p + 24])
            secs.append((name, vsize, vaddr, rawsize, rawoff))
            p += 40

        def to_file(rva):
            for _n, vsize, vaddr, rawsize, rawoff in secs:
                if vaddr <= rva < vaddr + max(vsize, rawsize):
                    return rva - vaddr + rawoff
            return None

        base = to_file(rsrc_rva)
        if base is None:
            return None

        def walk(off, depth, wanted):
            nent = struct.unpack("<H", data[off + 12:off + 14])[0]
            nid = struct.unpack("<H", data[off + 14:off + 16])[0]
            for k in range(nent + nid):
                e = off + 16 + 8 * k
                name, sub = struct.unpack("<II", data[e:e + 8])
                if depth < len(wanted) and wanted[depth] is not None:
                    if name != wanted[depth]:
                        continue
                if sub & 0x80000000:
                    r = walk(base + (sub & 0x7FFFFFFF), depth + 1, wanted)
                    if r:
                        return r
                else:
                    d = base + sub
                    rva, size = struct.unpack("<II", data[d:d + 8])
                    return to_file(rva), size
            return None

        # type 10 = RCDATA, name 11111
        return walk(base, 0, [10, 11111, None])
    except Exception:
        return None


def read_offset_table(data, offset):
    raw = data[offset:offset + 44]
    if len(raw) < 44:
        raise InnoError("offset table at 0x%X is truncated" % offset)
    if raw[:12] != LDR_ID:
        raise InnoError("no SetupLdrOffsetTable ID at 0x%X: got %r"
                        % (offset, raw[:12]))
    fields = struct.unpack("<8I", raw[12:44])
    computed = binascii.crc32(raw[:40]) & 0xFFFFFFFF
    t = dict(zip(("version", "total_size", "offset_exe", "uncompressed_exe",
                  "crc_exe", "offset0", "offset1", "table_crc"), fields))
    t["at"] = offset
    t["table_crc_computed"] = computed
    t["table_crc_ok"] = computed == t["table_crc"]
    return t


# ---------------------------------------------------------------- the blocks

def unframe(blob, stored_size):
    out = bytearray()
    checks = []
    pos = 0
    idx = 0
    while pos < stored_size:
        if pos + 4 > stored_size:
            raise InnoError("chunk %d: truncated CRC at %d" % (idx, pos))
        stored, = struct.unpack("<I", blob[pos:pos + 4])
        pos += 4
        n = min(CRC_CHUNK, stored_size - pos)
        piece = blob[pos:pos + n]
        pos += n
        checks.append((idx, stored, binascii.crc32(piece) & 0xFFFFFFFF))
        out += piece
        idx += 1
    return bytes(out), checks


def lzma1_alone(payload):
    """Inno writes 5 bytes of LZMA1 properties; FORMAT_ALONE wants 13."""
    head = payload[:5] + b"\xff" * 8
    return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
        head + payload[5:])


def read_block(data, offset, expect_id=False):
    info = {"offset": offset}
    p = offset
    if expect_id:
        ident = data[p:p + 64]
        info["id"] = ident.rstrip(b"\0")
        info["id_padding_ok"] = set(ident[len(info["id"]):]) <= {0}
        p += 64
    else:
        info["id"] = None
        info["id_padding_ok"] = None
    if p + 9 > len(data):
        raise InnoError("block at %d: no room for a header" % offset)
    crc_stored, = struct.unpack("<I", data[p:p + 4])
    stored_size, compressed = struct.unpack("<IB", data[p + 4:p + 9])
    crc_computed = binascii.crc32(data[p + 4:p + 9]) & 0xFFFFFFFF
    if crc_stored != crc_computed:
        raise InnoError("block at %d: header CRC 0x%08X, computed 0x%08X"
                        % (offset, crc_stored, crc_computed))
    data_at = p + 9
    blob = data[data_at:data_at + stored_size]
    if len(blob) < stored_size:
        raise InnoError("block at %d: wanted %d framed bytes, got %d"
                        % (offset, stored_size, len(blob)))
    payload, checks = unframe(blob, stored_size)
    bad = [c for c in checks if c[1] != c[2]]
    info.update({
        "header_crc": crc_stored,
        "stored_size": stored_size,
        "compressed": compressed,
        "data_at": data_at,
        "end": data_at + stored_size,
        "chunks": len(checks),
        "chunks_bad": len(bad),
        "framed": payload,
    })
    if bad:
        raise InnoError("block at %d: %d chunk CRCs of %d are wrong"
                        % (offset, len(bad), len(checks)))
    if compressed:
        props = payload[0]
        info["lzma_props"] = (props, props % 9, (props // 9) % 5,
                              (props // 9) // 5,
                              struct.unpack("<I", payload[1:5])[0])
        info["data"] = lzma1_alone(payload)
    else:
        info["lzma_props"] = None
        info["data"] = payload
    return info


def read_header_blocks(data, table):
    b1 = read_block(data, table["offset0"], expect_id=True)
    b2 = read_block(data, b1["end"], expect_id=False)
    if b2["end"] != table["offset_exe"]:
        raise InnoError("the second block ends at %d, OffsetEXE is %d"
                        % (b2["end"], table["offset_exe"]))
    return b1, b2


# ---------------------------------------------------------------- the arrays

def rdstr(buf, p):
    n, = struct.unpack("<I", buf[p:p + 4])
    if n % 2:
        raise InnoError("UTF-16 string at %d has an odd byte count %d" % (p, n))
    return p + 4 + n, buf[p + 4:p + 4 + n].decode("utf-16le", "replace")


def parse_file_entry(buf, p):
    ss = []
    for _ in range(10):
        p, s = rdstr(buf, p)
        ss.append(s)
    f = buf[p:p + FILE_ENTRY_FIXED]
    if len(f) < FILE_ENTRY_FIXED:
        raise InnoError("file entry at %d is truncated" % p)
    loc, attribs = struct.unpack("<ii", f[20:28])
    ext_size, = struct.unpack("<q", f[28:36])
    perm, = struct.unpack("<h", f[36:38])
    options, = struct.unpack("<I", f[38:42])
    return p + FILE_ENTRY_FIXED, {
        "source": ss[0], "dest": ss[1], "font": ss[2], "assembly": ss[3],
        "components": ss[4], "tasks": ss[5], "languages": ss[6],
        "check": ss[7], "before": ss[8], "after": ss[9],
        "location": loc, "attribs": attribs, "external_size": ext_size,
        "permissions": perm, "options": options, "file_type": f[42],
    }


def _probe(buf, p, n, count):
    """Try to parse n entries starting at p. Return the locations or None."""
    locs = []
    for _ in range(n):
        try:
            q = p
            names = []
            for _k in range(10):
                if q + 4 > len(buf):
                    return None
                ln, = struct.unpack("<I", buf[q:q + 4])
                if ln > 4000 or ln % 2:
                    return None
                q += 4
                if q + ln > len(buf):
                    return None
                names.append(buf[q:q + ln])
                q += ln
            if q + FILE_ENTRY_FIXED > len(buf):
                return None
            loc, = struct.unpack("<i", buf[q + 20:q + 24])
            if not (-1 <= loc < count):
                return None
            dest = names[1]
            if dest and dest[0:2] != b"{\x00":
                return None
            locs.append(loc)
            p = q + FILE_ENTRY_FIXED
        except Exception:
            return None
    return locs, p


def find_file_entries(buf, num_entries, num_locations, probe=20, start=0):
    """Locate the TSetupFileEntry array by requiring `probe` consecutive
    records to parse with in-range, non-decreasing location indices and a
    destination that is empty or begins with a brace -- then requiring the
    whole array of `num_entries` to chain from there.

    This is the same discipline `inno.py` used on 5.2.1 and it is the reason
    the array's offset is never written down as a constant."""
    for q in range(start, len(buf)):
        r = _probe(buf, q, probe, num_locations)
        if not r:
            continue
        locs, _ = r
        if locs != sorted(locs) or len(set(locs)) != probe:
            continue
        full = _probe(buf, q, num_entries, num_locations)
        if full:
            return q, full[1]
    raise InnoError("no TSetupFileEntry array of %d records found" % num_entries)


def read_file_entries(buf, num_entries, num_locations, start=0):
    at, end = find_file_entries(buf, num_entries, num_locations, start=start)
    p = at
    ents = []
    for _ in range(num_entries):
        p, e = parse_file_entry(buf, p)
        ents.append(e)
    return at, end, ents


def parse_locations(buf):
    if len(buf) % LOCATION_STRIDE:
        raise InnoError("the location block is %d bytes, which %d does not "
                        "divide" % (len(buf), LOCATION_STRIDE))
    out = []
    for i in range(len(buf) // LOCATION_STRIDE):
        r = buf[i * LOCATION_STRIDE:(i + 1) * LOCATION_STRIDE]
        first, last, start = struct.unpack("<III", r[0:12])
        sub, orig, csz = struct.unpack("<QQQ", r[12:36])
        ts, = struct.unpack("<Q", r[56:64])
        vms, vls = struct.unpack("<II", r[64:72])
        out.append({
            "index": i, "first_slice": first, "last_slice": last,
            "start": start, "suboffset": sub, "original_size": orig,
            "compressed_size": csz, "sha1": r[36:56], "timestamp": ts,
            "version_ms": vms, "version_ls": vls,
            "flags": r[72], "sign": r[73],
        })
    return out


def flag_words(v):
    return [n for b, n in FLAG_NAMES if v & b]


def filetime_iso(v):
    if not v:
        return "-"
    import datetime
    return (datetime.datetime(1601, 1, 1)
            + datetime.timedelta(microseconds=v // 10)).strftime(
                "%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- the header

def read_header_counts(buf):
    """Walk the leading strings of TSetupHeader, then read the 16 counts.

    The strings are walked rather than indexed, so the count block's offset is
    derived on every run. The walk stops at the first field whose length is
    absurd for a string -- on this object that is CompiledCodeText, 326,640
    bytes of `IFPS` compiled Pascal Script, which is an AnsiString and is
    therefore skipped by length rather than decoded."""
    p = 0
    strings = []
    while True:
        if p + 4 > len(buf):
            raise InnoError("ran off the end of the header walking strings")
        n, = struct.unpack("<I", buf[p:p + 4])
        if n > 4000:
            break
        strings.append(buf[p + 4:p + 4 + n].decode("utf-16le", "replace"))
        p += 4 + n
    # three AnsiString licence/info fields have already been consumed as
    # zero-length strings; the oversized one is CompiledCodeText.
    big_at = p
    big_len, = struct.unpack("<I", buf[p:p + 4])
    p += 4 + big_len
    names = ("languages", "custom_messages", "permissions", "types",
             "components", "tasks", "dirs", "files", "file_locations",
             "icons", "ini", "registry", "install_delete",
             "uninstall_delete", "run", "uninstall_run")
    counts = dict(zip(names, struct.unpack("<16i", buf[p:p + 64])))
    return {
        "strings": strings,
        "code_at": big_at, "code_len": big_len,
        "code_magic": buf[big_at + 4:big_at + 8],
        "counts_at": p, "counts": counts, "after_counts": p + 64,
    }


# ---------------------------------------------------------------- the slice

def open_slice(path):
    f = open(path, "rb")
    head = f.read(12)
    if head[:8] != SLICE_ID:
        f.close()
        raise InnoError("%s does not begin with %r: got %r"
                        % (os.path.basename(path), SLICE_ID, head[:8]))
    return f, head


def read_member(f, loc):
    f.seek(loc["start"])
    magic = f.read(4)
    if magic != CHUNK_MAGIC:
        raise InnoError("location %d: no %r at %d, got %r"
                        % (loc["index"], CHUNK_MAGIC, loc["start"], magic))
    blob = f.read(loc["compressed_size"])
    if len(blob) != loc["compressed_size"]:
        raise InnoError("location %d: wanted %d bytes, slice gave %d"
                        % (loc["index"], loc["compressed_size"], len(blob)))
    if loc["flags"] & 0x80:
        prop = blob[0]
        dict_size = 0xFFFFFFFF if prop == 40 else (2 | (prop & 1)) << (prop // 2 + 11)
        d = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}])
        out = d.decompress(blob[1:])
    else:
        out = blob
    return out


# ---------------------------------------------------------------- commands

def load(path, slice_path=None):
    data = open(path, "rb").read()
    hits = find_ldr_table(data)
    if not hits:
        raise InnoError("%s carries no SetupLdrOffsetTable ID anywhere in its "
                        "%d bytes" % (os.path.basename(path), len(data)))
    table = read_offset_table(data, hits[0])
    if not table["table_crc_ok"]:
        raise InnoError("offset table CRC 0x%08X, computed 0x%08X"
                        % (table["table_crc"], table["table_crc_computed"]))
    b1, b2 = read_header_blocks(data, table)
    head = read_header_counts(b1["data"])
    locs = parse_locations(b2["data"])
    if len(locs) != head["counts"]["file_locations"]:
        raise InnoError("the header declares %d file locations and the block "
                        "holds %d" % (head["counts"]["file_locations"],
                                      len(locs)))
    at, end, ents = read_file_entries(b1["data"], head["counts"]["files"],
                                      len(locs), start=head["after_counts"])
    return dict(data=data, ldr_hits=hits, table=table, b1=b1, b2=b2,
                head=head, locations=locs, entries=ents,
                entries_at=at, entries_end=end, path=path)


def cmd_ldr(args):
    data = open(args.path, "rb").read()
    hits = find_ldr_table(data)
    print("file            : %s" % os.path.basename(args.path))
    print("bytes           : %d" % len(data))
    print("ID occurrences  : %d  %s" % (len(hits), [hex(h) for h in hits]))
    r = rsrc_11111_offset(data)
    if r:
        print("RCDATA 11111 at : 0x%X, %d bytes" % (r[0], r[1]))
        print("routes agree    : %s" % (bool(hits) and r[0] == hits[0]))
    else:
        print("RCDATA 11111    : not found")
    if not hits:
        raise InnoError("no SetupLdrOffsetTable ID in this file")
    t = read_offset_table(data, hits[0])
    for k in ("version", "total_size", "offset_exe", "uncompressed_exe",
              "crc_exe", "offset0", "offset1"):
        print("  %-20s %12d  0x%08X" % (k, t[k], t[k]))
    print("  %-20s 0x%08X computed 0x%08X  %s"
          % ("table_crc", t["table_crc"], t["table_crc_computed"],
             "OK" if t["table_crc_ok"] else "WRONG"))
    print("TotalSize vs file size: %d vs %d, difference %d"
          % (t["total_size"], len(data), len(data) - t["total_size"]))


def cmd_blocks(args):
    o = load(args.path)
    for name, b in (("setup header", o["b1"]), ("file locations", o["b2"])):
        print("=== %s at %d ===" % (name, b["offset"]))
        if b["id"] is not None:
            print("  identification  : %r  (padding all NUL: %s)"
                  % (b["id"], b["id_padding_ok"]))
        print("  header CRC      : 0x%08X OK" % b["header_crc"])
        print("  stored_size     : %d (framed)" % b["stored_size"])
        print("  compressed flag : %d  (%s)"
              % (b["compressed"], "LZMA1" if b["compressed"] else "stored"))
        print("  chunks of 4096  : %d, %d with a bad CRC"
              % (b["chunks"], b["chunks_bad"]))
        if b["lzma_props"]:
            p, lc, lp, pb, dic = b["lzma_props"]
            print("  LZMA1 props     : 0x%02X  lc=%d lp=%d pb=%d dict=%d"
                  % (p, lc, lp, pb, dic))
        print("  decompressed    : %d bytes" % len(b["data"]))
        print("  block ends at   : %d" % b["end"])
    n = len(o["b2"]["data"])
    print("=== the stride, by division ===")
    for s in (70, 74):
        print("  %d divides %d : %-5s  %s" % (
            s, n, n % s == 0, ("%d records" % (n // s)) if n % s == 0 else ""))


def cmd_header(args):
    o = load(args.path)
    h = o["head"]
    print("header block    : %d bytes" % len(o["b1"]["data"]))
    print("leading strings : %d" % len(h["strings"]))
    for i, s in enumerate(h["strings"]):
        if s:
            print("  [%2d] %s" % (i, s))
    print("compiled code   : %d bytes at %d, magic %r"
          % (h["code_len"], h["code_at"], h["code_magic"]))
    print("counts at       : %d" % h["counts_at"])
    for k, v in h["counts"].items():
        print("  %-18s %d" % (k, v))
    if args.save:
        open(args.save, "wb").write(o["b1"]["data"])
        print("saved           : %s" % args.save)


def cmd_entries(args):
    o = load(args.path)
    ents, locs = o["entries"], o["locations"]
    print("file entry array starts : %d" % o["entries_at"])
    print("file entry array ends   : %d" % o["entries_end"])
    print("file entries            : %d" % len(ents))
    print("data entries            : %d" % len(locs))
    used = [e["location"] for e in ents if e["location"] >= 0]
    print("entries with data       : %d" % len(used))
    print("entries without data    : %d" % (len(ents) - len(used)))
    print("distinct locations used : %d" % len(set(used)))
    print("locations are 0..N-1    : %s"
          % (sorted(set(used)) == list(range(len(locs)))))
    print("data entries unreferenced: %d"
          % (len(locs) - len(set(used))))
    print("fixed part of the record: [%d]" % FILE_ENTRY_FIXED)
    print("shared locations        : %d entries over %d locations"
          % (len(used) - len(set(used)) + 0, len(set(used))))
    print("sum of OriginalSize     : %d" % sum(l["original_size"] for l in locs))
    print("sum of ChunkCompressed  : %d"
          % sum(l["compressed_size"] for l in locs))
    hist = collections.Counter(l["flags"] for l in locs)
    print("=== location flags ===")
    for v, n in sorted(hist.items()):
        print("  0x%02X  x%-6d %s" % (v, n, ", ".join(flag_words(v))))
    subs = set(l["suboffset"] for l in locs)
    print("distinct ChunkSuboffset : %d  -> solid: %s"
          % (len(subs), len(subs) != len(locs) and len(locs) > 1
             and max(subs) > 0))
    ts = [l["timestamp"] for l in locs if l["timestamp"]]
    if ts:
        print("SourceTimeStamp range   : %s .. %s over %d records"
              % (filetime_iso(min(ts)), filetime_iso(max(ts)), len(ts)))


def cmd_census(args):
    o = load(args.path)
    ents, locs = o["entries"], o["locations"]
    print("files                   : %d" % len(ents))
    print("data entries            : %d" % len(locs))
    print("total uncompressed bytes: %d" % sum(l["original_size"] for l in locs))
    by_dir = collections.Counter()
    by_dir_b = collections.Counter()
    by_ext = collections.Counter()
    by_ext_b = collections.Counter()
    for e in ents:
        d = e["dest"].replace("/", "\\")
        top = d.split("\\")[0] if d else "(empty)"
        size = (locs[e["location"]]["original_size"]
                if e["location"] >= 0 else 0)
        by_dir[top] += 1
        by_dir_b[top] += size
        base = d.split("\\")[-1]
        ext = ("." + base.rsplit(".", 1)[1].lower()) if "." in base else "(none)"
        by_ext[ext] += 1
        by_ext_b[ext] += size
    total = sum(by_dir_b.values()) or 1
    print("=== by top-level directory ===")
    for k, n in by_dir.most_common():
        print("  %-28s %6d %14d  %7.3f%%"
              % (k, n, by_dir_b[k], 100.0 * by_dir_b[k] / total))
    print("=== by extension ===")
    for k, n in by_ext.most_common(20):
        print("  %-28s %6d %14d  %7.3f%%"
              % (k, n, by_ext_b[k], 100.0 * by_ext_b[k] / total))


def cmd_slice(args):
    o = load(args.path)
    locs = o["locations"]
    size = os.path.getsize(args.slice)
    f, head = open_slice(args.slice)
    print("slice           : %s" % os.path.basename(args.slice))
    print("bytes           : %d" % size)
    declared, = struct.unpack("<I", head[8:12])
    print("identifier      : %r + %s" % (head[:8], head[8:12].hex(" ")))
    print("declared size   : %d  (the four bytes after the identifier)" % declared)
    print("actual size     : %d   agree: %s" % (size, declared == size))
    order = sorted(locs, key=lambda l: l["start"])
    magic_bad = 0
    trailers = collections.Counter()
    prev_end = 12
    holes = 0
    for i, l in enumerate(order):
        f.seek(l["start"])
        if f.read(4) != CHUNK_MAGIC:
            magic_bad += 1
        gap = l["start"] - prev_end
        if gap:
            f.seek(prev_end)
            trailers[f.read(gap)] += 1
        if gap not in (0, 2):
            holes += 1
        prev_end = l["start"] + 4 + l["compressed_size"]
    f.seek(prev_end)
    tail = f.read()
    f.close()
    ncomp = sum(1 for l in locs if l["flags"] & 0x80)
    body = sum(l["compressed_size"] for l in locs)
    accounted = 12 + body + 4 * len(locs) + 2 * ncomp
    print("chunks          : %d, %d with a wrong magic" % (len(locs), magic_bad))
    print("stored chunks   : %d" % (len(locs) - ncomp))
    print("compressed      : %d" % ncomp)
    print("inter-chunk fillers:")
    for k, n in trailers.most_common():
        print("    %-16s x%d" % (k.hex(" ") or "(none)", n))
    print("tail after last : %s" % (tail.hex(" ") or "(none)"))
    print("=== the arithmetic ===")
    print("  12 header + %d member bytes + 4 x %d magics + 2 x %d trailers"
          % (body, len(locs), ncomp))
    print("  accounted     : %d" % accounted)
    print("  slice size    : %d" % size)
    print("  RESIDUE       : %d" % (size - accounted))
    print("  out-of-order or holed gaps: %d" % holes)


def cmd_magic(args):
    """Count a needle in the slice, state the uniform-random model FIRST, and
    then say how many of the hits are chunk starts the records predict.

    This exists because a magic-word count is not a block count, and on this
    object the difference is measurable rather than arguable: the records give
    the true positives, so the false positives can be subtracted instead of
    guessed at."""
    needle = args.needle.encode("latin1").decode("unicode_escape").encode(
        "latin1") if "\\x" in args.needle else args.needle.encode("latin1")
    size = os.path.getsize(args.slice)
    model = size / float(256 ** len(needle))
    print("slice           : %s" % os.path.basename(args.slice))
    print("bytes           : %d" % size)
    print("needle          : %r  (%d bytes)" % (needle, len(needle)))
    print("uniform model   : %.10f expected occurrences" % model)
    found = []
    tail = b""
    base = 0
    with open(args.slice, "rb") as f:
        while True:
            b = f.read(1 << 24)
            if not b:
                break
            buf = tail + b
            i = 0
            while True:
                j = buf.find(needle, i)
                if j < 0:
                    break
                found.append(base - len(tail) + j)
                i = j + 1
            tail = buf[-(len(needle) - 1):] if len(needle) > 1 else b""
            base += len(b)
    print("observed        : %d" % len(found))
    if model:
        print("observed/model  : %.1f x" % (len(found) / model))
    if args.path:
        o = load(args.path)
        starts = set(l["start"] for l in o["locations"])
        spur = [x for x in found if x not in starts]
        missing = [x for x in starts if x not in set(found)]
        print("chunk starts the records predict : %d" % len(starts))
        print("hits that ARE a chunk start      : %d" % (len(found) - len(spur)))
        print("hits that are NOT               : %d" % len(spur))
        for x in spur:
            print("    at %d (0x%X)" % (x, x))
        print("chunk starts with no hit         : %d" % len(missing))
        if model and spur:
            print("MEASURED false-positive rate     : %d observed against a "
                  "model of %.4f = %.2f x" % (len(spur), model,
                                              len(spur) / model))


def cmd_verify(args):
    o = load(args.path)
    locs = o["locations"]
    f, _ = open_slice(args.slice)
    ok = bad = 0
    short = 0
    bad_list = []
    byloc = {}
    for e in o["entries"]:
        if e["location"] >= 0:
            byloc.setdefault(e["location"], e["dest"])
    limit = args.limit or len(locs)
    for l in locs[:limit]:
        try:
            out = read_member(f, l)
        except Exception as exc:
            bad += 1
            bad_list.append((l["index"], byloc.get(l["index"], ""), str(exc)))
            continue
        if len(out) != l["original_size"]:
            short += 1
            bad_list.append((l["index"], byloc.get(l["index"], ""),
                             "length %d, declared %d"
                             % (len(out), l["original_size"])))
            continue
        if hashlib.sha1(out).digest() == l["sha1"]:
            ok += 1
        else:
            bad += 1
            bad_list.append((l["index"], byloc.get(l["index"], ""),
                             "SHA-1 mismatch, flags %s"
                             % ",".join(flag_words(l["flags"]))))
    f.close()
    print("members checked : %d" % min(limit, len(locs)))
    print("SHA-1 verified  : %d" % ok)
    print("wrong length    : %d" % short)
    print("SHA-1 mismatch or error : %d" % bad)
    for i, name, why in bad_list[:40]:
        print("    %5d  %-52s %s" % (i, name[:52], why))
    if ok + bad + short:
        print("rate            : %d of %d = %.4f %%"
              % (ok, ok + bad + short, 100.0 * ok / (ok + bad + short)))


def cmd_extract(args):
    o = load(args.path)
    locs = o["locations"]
    f, _ = open_slice(args.slice)
    os.makedirs(args.out, exist_ok=True)
    byloc = collections.defaultdict(list)
    for e in o["entries"]:
        if e["location"] >= 0:
            byloc[e["location"]].append(e["dest"])
    written = 0
    total = 0
    for l in locs:
        names = byloc.get(l["index"], [])
        if args.only and not any(args.only.lower() in n.lower() for n in names):
            continue
        out = read_member(f, l)
        name = (names[0] if names else "loc%05d" % l["index"])
        safe = name.replace("{", "_").replace("}", "_")
        safe = safe.replace("/", os.sep).replace("\\", os.sep)
        dest = os.path.join(args.out, safe)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as g:
            g.write(out)
        written += 1
        total += len(out)
    f.close()
    print("files written   : %d" % written)
    print("bytes written   : %d" % total)


def cmd_e32(args):
    o = load(args.path)
    t = o["table"]
    b = read_block(o["data"], t["offset_exe"], expect_id=False)
    crc = binascii.crc32(b["data"]) & 0xFFFFFFFF
    print("setup.e32 at    : %d" % t["offset_exe"])
    print("stored_size     : %d (framed)" % b["stored_size"])
    print("compressed flag : %d" % b["compressed"])
    print("chunks of 4096  : %d, %d bad" % (b["chunks"], b["chunks_bad"]))
    print("decompressed    : %d bytes" % len(b["data"]))
    print("UncompressedSizeEXE declared : %d" % t["uncompressed_exe"])
    print("lengths agree   : %s" % (len(b["data"]) == t["uncompressed_exe"]))
    print("CRC-32 computed : 0x%08X" % crc)
    print("CRCEXE declared : 0x%08X" % t["crc_exe"])
    print("CRCs agree      : %s" % (crc == t["crc_exe"]))
    print("block ends at   : %d" % b["end"])
    # The engine is itself a PE, and its link timestamp is the one thing about
    # it that can be compared with an uninstaller in another repository.
    e = b["data"]
    print("first 4 bytes   : %r" % e[:4])
    lfanew = struct.unpack("<I", e[0x3C:0x40])[0]
    if e[lfanew:lfanew + 4] == b"PE\0\0":
        import datetime
        machine, nsec, ts = struct.unpack("<HHI", e[lfanew + 4:lfanew + 12])
        print("e_lfanew        : 0x%X  machine 0x%04X  sections %d"
              % (lfanew, machine, nsec))
        print("COFF timestamp  : 0x%08X = %s UTC"
              % (ts, datetime.datetime(1970, 1, 1)
                 + datetime.timedelta(seconds=ts)))
    if args.save:
        open(args.save, "wb").write(b["data"])
        print("saved           : %s" % args.save)


# ---------------------------------------------------------------- selftest

def _frame(payload):
    out = bytearray()
    pos = 0
    while pos < len(payload):
        piece = payload[pos:pos + CRC_CHUNK]
        out += struct.pack("<I", binascii.crc32(piece) & 0xFFFFFFFF)
        out += piece
        pos += len(piece)
    return bytes(out)


def _block(payload, ident=None):
    framed = _frame(payload)
    head = struct.pack("<IB", len(framed), 0)
    out = b""
    if ident is not None:
        out += ident.ljust(64, b"\0")
    out += struct.pack("<I", binascii.crc32(head) & 0xFFFFFFFF) + head + framed
    return out


def cmd_selftest(args):
    """Five specimens, four of which must be refused."""
    results = []

    def check(label, fn, must_fail):
        try:
            fn()
            ok = not must_fail
            results.append((label, ok, "accepted"))
        except Exception as exc:
            ok = must_fail
            results.append((label, ok, "REFUSED: %s" % str(exc)[:70]))

    good_table = LDR_ID + struct.pack("<8I", 1, 100, 0, 0, 0, 0, 0, 0)
    good_table = good_table[:40]
    good_table += struct.pack("<I", binascii.crc32(good_table) & 0xFFFFFFFF)

    check("a well-formed offset table (must be accepted)",
          lambda: read_offset_table(good_table, 0), False)

    bad_id = b"XXXXXXXXXXXX" + good_table[12:]
    check("wrong 12-byte identifier",
          lambda: read_offset_table(bad_id, 0), True)

    bad_crc = good_table[:40] + struct.pack("<I", 0xDEADBEEF)
    check("a table whose own CRC is wrong",
          lambda: read_offset_table(bad_crc, 0)
          if read_offset_table(bad_crc, 0)["table_crc_ok"]
          else (_ for _ in ()).throw(InnoError("table CRC wrong")), True)

    blk = _block(b"A" * 5000, ident=b"Inno Setup Setup Data (5.6.2) (u)")
    check("a hand-built stored block (must be accepted)",
          lambda: read_block(blk, 0, expect_id=True), False)

    holed = bytearray(blk)
    holed[70] ^= 0xFF
    check("a flipped byte in the block header",
          lambda: read_block(bytes(holed), 0, expect_id=True), True)

    holed2 = bytearray(blk)
    holed2[90] ^= 0xFF
    check("a flipped byte inside a framed chunk",
          lambda: read_block(bytes(holed2), 0, expect_id=True), True)

    check("a location block 73 bytes long",
          lambda: parse_locations(b"\0" * 73), True)

    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".bin")
    os.write(fd, b"NOTASLICE" + b"\0" * 40)
    os.close(fd)

    def _bad_slice():
        f, _h = open_slice(tmp)
        f.close()

    check("a slice file that does not begin with idska32", _bad_slice, True)

    fd2, tmp2 = tempfile.mkstemp(suffix=".bin")
    os.write(fd2, SLICE_ID + b"\0" * 40)
    os.close(fd2)

    def _good_slice():
        f, _h = open_slice(tmp2)
        f.close()

    check("a slice file that does (must be accepted)", _good_slice, False)
    os.unlink(tmp)
    os.unlink(tmp2)

    for label, ok, note in results:
        print("  [%s] %-46s -> %s" % ("ok" if ok else "FAIL", label, note))
    failed = sum(1 for _l, ok, _n in results if not ok)
    print("%d specimens, %d failed" % (len(results), failed))
    if failed:
        sys.exit(3)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    for name in ("ldr", "blocks", "entries", "census", "e32", "header"):
        p = sub.add_parser(name)
        p.add_argument("path")
        if name in ("header", "e32"):
            p.add_argument("--save")
    p = sub.add_parser("magic")
    p.add_argument("path", nargs="?")
    p.add_argument("--slice", required=True)
    p.add_argument("--needle", default="zlb\x1a")
    for name in ("slice", "verify", "extract"):
        p = sub.add_parser(name)
        p.add_argument("path")
        p.add_argument("--slice", required=True)
        if name == "extract":
            p.add_argument("--out", required=True)
            p.add_argument("--only")
        if name == "verify":
            p.add_argument("--limit", type=int)
    sub.add_parser("selftest")
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        sys.exit(2)
    fn = {
        "ldr": cmd_ldr, "blocks": cmd_blocks, "entries": cmd_entries,
        "census": cmd_census, "slice": cmd_slice, "verify": cmd_verify,
        "extract": cmd_extract, "e32": cmd_e32, "header": cmd_header,
        "magic": cmd_magic, "selftest": cmd_selftest,
    }[args.cmd]
    # On pc-monstrum-doc `ldr` and `header` were handed GOG's uninstaller
    # stub, which carries no SetupLdrOffsetTable, and the InnoError that
    # names that fact reached the user as a traceback with this machine's
    # paths in it. A refusal is one line: the tool, the reason, exit 1.
    try:
        fn(args)
    except InnoError as e:
        sys.exit("inno56: refused -- %s" % e)


if __name__ == "__main__":
    main()
