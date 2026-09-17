#!/usr/bin/env python3
"""itsf.py -- read the directory of a Microsoft ITSF container (a compiled HTML
Help file, `.chm`) and close it on the quantities it declares about itself.

WHAT THIS FORMAT IS, AND WHAT IT IS NOT
--------------------------------------
Microsoft never published a specification for ITSF. What exists is
reverse-engineering work done in public by the `chmlib` and 7-Zip projects and
described on the `chm-spec` pages that grew out of them. **This repository does
not treat that as a specification and does not read from it while deriving.**
Every field below was derived from the bytes of one specimen and is accepted
only where an arithmetic closure forces it; the public work was consulted
afterwards, for names, and where a name here matches theirs that is agreement
and not a citation.

THE HEADER, DERIVED
-------------------
The ITSF header is 96 bytes and says so at `+0x08`:

    +0x00  char[4]  'ITSF'
    +0x04  u32      version                            3 on the specimen
    +0x08  u32      header length                      96, and the header IS 96
    +0x0C  u32      1
    +0x10  u32      a monotone value, not decoded here (see --clocks)
    +0x14  u32      a Windows LCID
    +0x18  uuid[16] {7C01FD10-7BAA-11D0-9E0C-00A0C922E6EC}
    +0x28  uuid[16] {7C01FD11-7BAA-11D0-9E0C-00A0C922E6EC}
    +0x38  u64      offset of header section 0
    +0x40  u64      length of header section 0
    +0x48  u64      offset of header section 1, the directory
    +0x50  u64      length of header section 1
    +0x58  u64      offset of content section 0        (version 3 only)

**Three closures fall straight out of those five integers**, and they are the
reason the layout above is believed rather than guessed:

    header length + section-0 length            == directory offset
    directory offset + directory length         == content offset
    header section 0 declares the FILE's total length, and it matches the
        byte count on disk

The last of those is the one that matters. Header section 0 is 24 bytes of three
`u64`, and the second of them is the size of the whole container. **A `.chm`
states its own byte count**, which is the strongest self-check any file in this
object carries.

THE DIRECTORY, DERIVED
----------------------
    ITSP  +0x00  char[4]  'ITSP'
          +0x04  u32      version                      1
          +0x08  u32      header length                84, and it IS 84
          +0x0C  u32      10
          +0x10  u32      directory chunk size         4096
          +0x14  u32      quickref density             2
          +0x18  u32      index tree depth             2
          +0x1C  i32      chunk number of the root index chunk
          +0x20  i32      chunk number of the FIRST PMGL chunk
          +0x24  i32      chunk number of the LAST PMGL chunk
          +0x28  i32      -1
          +0x2C  u32      NUMBER OF DIRECTORY CHUNKS
          +0x30  u32      a Windows LCID
          +0x34  uuid[16] {5D02929A-212E-11D0-9DF9-00A0C922E6EC}
          +0x44  u32      header length again
          +0x48  i32 x3   -1, -1, -1

**`+0x2C` is where the chunk count is, and `+0x20` is not.** The pre-briefing of
this session read a chunk count as a `u32` at `+0x20` and got **zero** on a file
holding five chunks. Zero is the correct value of `+0x20` -- it is the index of
the first PMGL chunk, and the first PMGL chunk is chunk 0. The reading was of the
wrong field, not of the wrong bytes, and the count at `+0x2C` is checked here
against two independent things: the chunk arithmetic, and the number of PMGL and
PMGI tags actually present.

    ITSP header length + chunk count * chunk size == the declared directory length

Each chunk is `chunk size` bytes and begins with a tag. `PMGL` is a listing
chunk and `PMGI` an index chunk:

    PMGL  +0x00 'PMGL'   +0x04 u32 quickref/free bytes at the chunk's end
          +0x08 u32 0    +0x0C i32 previous chunk    +0x10 i32 next chunk
          +0x14 entries, each:
                    ENCINT name length, that many bytes of name,
                    ENCINT content section, ENCINT offset, ENCINT length

`ENCINT` is a big-endian seven-bit-per-byte integer, high bit set meaning
continue -- the same shape as a MIDI variable-length quantity and the opposite
byte order from the little-endian varints elsewhere in this collection. An
entry's `offset` and `length` are inside its content section, which for section 1
is a *decompressed* stream and may therefore be far larger than the file.

    python tools/itsf.py header <file.chm>
    python tools/itsf.py list <file.chm>
    python tools/itsf.py list <file.chm> --tsv notes/itsf-toc.tsv
    python tools/itsf.py find <root>            # every ITSF file under a tree
    python tools/itsf.py selftest
"""
import argparse
import collections
import os
import struct
import sys
import uuid


class Bad(Exception):
    pass


def guid(b):
    return "{%s}" % str(uuid.UUID(bytes_le=b)).upper()


def encint(buf, i):
    """A big-endian seven-bit varint. Returns (value, bytes consumed)."""
    v = 0
    n = 0
    while True:
        if i + n >= len(buf):
            raise Bad("an ENCINT runs off the end of the chunk at %d" % i)
        b = buf[i + n]
        v = (v << 7) | (b & 0x7F)
        n += 1
        if not b & 0x80:
            return v, n
        if n > 9:
            raise Bad("an ENCINT longer than nine bytes at %d" % i)


def read_header(blob):
    if len(blob) < 96:
        raise Bad("shorter than a 96-byte ITSF header: %d bytes" % len(blob))
    if blob[:4] != b"ITSF":
        raise Bad("no ITSF signature at 0: %r" % blob[:4])
    (version, hlen, one, stamp, lcid) = struct.unpack_from("<IIIII", blob, 4)
    if version != 3:
        raise Bad("ITSF version %d; this reader derives version 3 only"
                  % version)
    if hlen != 96:
        raise Bad("ITSF version 3 declares a header length of %d, not 96"
                  % hlen)
    g1 = guid(blob[0x18:0x28])
    g2 = guid(blob[0x28:0x38])
    (s0off, s0len, s1off, s1len, coff) = struct.unpack_from("<QQQQQ", blob,
                                                            0x38)
    h = dict(version=version, header_length=hlen, unknown_0C=one,
             stamp=stamp, lcid=lcid, guid1=g1, guid2=g2,
             s0_offset=s0off, s0_length=s0len,
             dir_offset=s1off, dir_length=s1len, content_offset=coff)
    # Closure 1: the header and header section 0 must run up to the directory.
    h["closure_dir_offset"] = hlen + s0len - s1off
    # Closure 2: the directory must run up to content section 0.
    h["closure_content_offset"] = s1off + s1len - coff
    # Header section 0 is three u64 and the second is the container's own size.
    if s0off + s0len <= len(blob) and s0len >= 24:
        a, total, c = struct.unpack_from("<QQQ", blob, s0off)
        h["s0_words"] = (a, total, c)
        h["declared_total"] = total
        h["closure_total"] = total - len(blob)
    else:
        h["s0_words"] = None
        h["declared_total"] = None
        h["closure_total"] = None
    h["file_length"] = len(blob)
    return h


def read_itsp(blob, off):
    if blob[off:off + 4] != b"ITSP":
        raise Bad("no ITSP signature at %d: %r" % (off, blob[off:off + 4]))
    (version, hlen, ten, chunksize, density, depth, root, first, last,
     minus, nchunks, lcid) = struct.unpack_from("<IIIIIiiiiiIi", blob, off + 4)
    if version != 1:
        raise Bad("ITSP version %d; this reader derives version 1 only"
                  % version)
    if hlen != 84:
        raise Bad("ITSP declares a header length of %d, not 84" % hlen)
    if chunksize <= 0 or chunksize & (chunksize - 1):
        raise Bad("ITSP declares a chunk size of %d, which is not a power of "
                  "two" % chunksize)
    if nchunks <= 0:
        raise Bad("ITSP declares %d directory chunks" % nchunks)
    return dict(version=version, header_length=hlen, unknown_0C=ten,
                chunk_size=chunksize, density=density, depth=depth,
                root_chunk=root, first_pmgl=first, last_pmgl=last,
                minus_one=minus, chunk_count=nchunks, lcid=lcid,
                guid=guid(blob[off + 0x34:off + 0x44]),
                header_length_again=struct.unpack_from("<I", blob,
                                                       off + 0x44)[0],
                tail=struct.unpack_from("<iii", blob, off + 0x48))


def read_chunks(blob, dir_off, itsp):
    """Walk every directory chunk. Returns (entries, chunk_kinds, refusals)."""
    size = itsp["chunk_size"]
    base = dir_off + itsp["header_length"]
    entries = []
    kinds = []
    refusals = []
    for n in range(itsp["chunk_count"]):
        off = base + n * size
        if off + size > len(blob):
            refusals.append("chunk %d at %d overruns the file" % (n, off))
            break
        chunk = blob[off:off + size]
        tag = chunk[:4]
        kinds.append(tag.decode("ascii", "replace"))
        if tag == b"PMGL":
            (free, zero, prev, nxt) = struct.unpack_from("<IIii", chunk, 4)
            i = 20
            stop = size - free
            while i < stop:
                start = i
                try:
                    nlen, k = encint(chunk, i)
                    i += k
                    if i + nlen > stop:
                        raise Bad("a name of %d bytes at %d overruns the "
                                  "chunk's used area" % (nlen, i))
                    name = chunk[i:i + nlen]
                    i += nlen
                    sect, k = encint(chunk, i)
                    i += k
                    eoff, k = encint(chunk, i)
                    i += k
                    elen, k = encint(chunk, i)
                    i += k
                except Bad as e:
                    refusals.append("chunk %d at entry offset %d: %s"
                                    % (n, start, e))
                    break
                entries.append(dict(chunk=n, name=name.decode("utf-8",
                                                              "replace"),
                                    section=sect, offset=eoff, length=elen))
        elif tag == b"PMGI":
            (free,) = struct.unpack_from("<I", chunk, 4)
            i = 8
            stop = size - free
            while i < stop:
                try:
                    nlen, k = encint(chunk, i)
                    i += k
                    name = chunk[i:i + nlen]
                    i += nlen
                    child, k = encint(chunk, i)
                    i += k
                except Bad as e:
                    refusals.append("index chunk %d at %d: %s" % (n, i, e))
                    break
                entries.append(dict(chunk=n, name=name.decode("utf-8",
                                                              "replace"),
                                    section=None, offset=None, length=child,
                                    index=True))
        else:
            refusals.append("chunk %d at %d begins %r, which is neither PMGL "
                            "nor PMGI" % (n, off, tag))
    return entries, kinds, refusals


def show_header(path, blob=None):
    blob = blob if blob is not None else open(path, "rb").read()
    h = read_header(blob)
    print("file                        : %s" % path)
    print("bytes on disk               : %d" % h["file_length"])
    print()
    print("--- the ITSF header, 96 bytes ---------------------------------")
    print("  version                   : %d" % h["version"])
    print("  header length declared    : %d" % h["header_length"])
    print("  u32 at +0x0C              : %d" % h["unknown_0C"])
    print("  u32 at +0x10              : %d (0x%08X)" % (h["stamp"],
                                                          h["stamp"]))
    print("  u32 at +0x14, an LCID     : %d (0x%04X)" % (h["lcid"], h["lcid"]))
    print("  guid 1                    : %s" % h["guid1"])
    print("  guid 2                    : %s" % h["guid2"])
    print("  header section 0          : offset %d, length %d"
          % (h["s0_offset"], h["s0_length"]))
    print("  header section 1 (the dir): offset %d, length %d"
          % (h["dir_offset"], h["dir_length"]))
    print("  content section 0         : offset %d" % h["content_offset"])
    print()
    print("--- the three closures ---------------------------------------")
    print("  %d (header) + %d (section 0) = %d against a directory offset "
          "of %d" % (h["header_length"], h["s0_length"],
                     h["header_length"] + h["s0_length"], h["dir_offset"]))
    print("      residue %d" % h["closure_dir_offset"])
    print("  %d (dir offset) + %d (dir length) = %d against a content offset "
          "of %d" % (h["dir_offset"], h["dir_length"],
                     h["dir_offset"] + h["dir_length"], h["content_offset"]))
    print("      residue %d" % h["closure_content_offset"])
    if h["declared_total"] is not None:
        print("  header section 0 is three u64 : %s" % (h["s0_words"],))
        print("  the second declares the container's own length : %d"
              % h["declared_total"])
        print("  against %d bytes on disk       residue %d"
              % (h["file_length"], h["closure_total"]))
    return h


def cmd_header(args):
    h = show_header(args.path)
    blob = open(args.path, "rb").read()
    itsp = read_itsp(blob, h["dir_offset"])
    print()
    print("--- the ITSP directory header, 84 bytes ----------------------")
    for k in ("version", "header_length", "unknown_0C", "chunk_size",
              "density", "depth", "root_chunk", "first_pmgl", "last_pmgl",
              "minus_one", "chunk_count"):
        print("  %-25s : %d" % (k, itsp[k]))
    print("  %-25s : %d (0x%04X)" % ("lcid", itsp["lcid"], itsp["lcid"]))
    print("  %-25s : %s" % ("guid", itsp["guid"]))
    print("  %-25s : %d" % ("header_length_again", itsp["header_length_again"]))
    print("  %-25s : %s" % ("tail", itsp["tail"]))
    print()
    print("--- the fourth closure, and it is the chunk count ------------")
    got = itsp["header_length"] + itsp["chunk_count"] * itsp["chunk_size"]
    print("  %d (ITSP header) + %d chunks x %d bytes = %d"
          % (itsp["header_length"], itsp["chunk_count"], itsp["chunk_size"],
             got))
    print("  against a declared directory length of %d    residue %d"
          % (h["dir_length"], got - h["dir_length"]))
    print()
    print("  THE COUNT IS AT +0x2C AND IT IS %d." % itsp["chunk_count"])
    print("  The u32 at +0x20 is %d, which is the index of the first PMGL"
          % itsp["first_pmgl"])
    print("  chunk and not a count. Reading +0x20 as the count is the")
    print("  error this session's pre-briefing recorded against itself.")
    return 0


def cmd_list(args):
    blob = open(args.path, "rb").read()
    h = read_header(blob)
    itsp = read_itsp(blob, h["dir_offset"])
    entries, kinds, refusals = read_chunks(blob, h["dir_offset"], itsp)
    listing = [e for e in entries if not e.get("index")]
    index = [e for e in entries if e.get("index")]

    print("file                     : %s" % args.path)
    print("bytes                    : %d" % len(blob))
    print("declared total inside    : %s" % h["declared_total"])
    print("residue against the disc : %s" % h["closure_total"])
    print()
    print("chunk size               : %d" % itsp["chunk_size"])
    print("chunk count declared     : %d  (at +0x2C of ITSP)"
          % itsp["chunk_count"])
    print("chunks walked            : %d" % len(kinds))
    print("chunk tags in order      : %s" % " ".join(kinds))
    print("PMGL tags counted        : %d" % kinds.count("PMGL"))
    print("PMGI tags counted        : %d" % kinds.count("PMGI"))
    print("first/last PMGL declared : %d / %d"
          % (itsp["first_pmgl"], itsp["last_pmgl"]))
    print("PMGL chunks that implies : %d"
          % (itsp["last_pmgl"] - itsp["first_pmgl"] + 1))
    print("root index chunk declared: %d" % itsp["root_chunk"])
    print("refusals                 : %d" % len(refusals))
    for r in refusals:
        print("   %s" % r)
    print()
    print("listing entries          : %d" % len(listing))
    print("index entries            : %d" % len(index))
    print()
    bysect = collections.Counter(e["section"] for e in listing)
    print("-- entries by content section --------------------------------")
    for s, n in sorted(bysect.items()):
        tot = sum(e["length"] for e in listing if e["section"] == s)
        print("   section %-3s %5d entries   %12d declared bytes" % (s, n, tot))
    print()
    internal = [e for e in listing if e["name"].startswith("::")]
    content = [e for e in listing if not e["name"].startswith("::")]
    print("-- the two populations ---------------------------------------")
    print("   names beginning '::'  (the container's own machinery) : %d"
          % len(internal))
    print("   names beginning '/'   (the help project's own files)  : %d"
          % len(content))
    print()
    print("-- every '::' entry, which is where the 11 ::DataSpace hits go --")
    for e in sorted(internal, key=lambda x: x["name"]):
        print("   %-58s sect %s off %10d len %10d"
              % (e["name"], e["section"], e["offset"], e["length"]))
    print()
    ext = collections.Counter(
        (os.path.splitext(e["name"])[1] or "(none)").lower()
        for e in content)
    print("-- the help project's files, by extension --------------------")
    for k, n in ext.most_common():
        tot = sum(e["length"] for e in content
                  if (os.path.splitext(e["name"])[1] or "(none)").lower() == k)
        print("   %-10s %6d files %14d declared bytes" % (k, n, tot))
    print("   %-10s %6d files %14d declared bytes"
          % ("TOTAL", len(content), sum(e["length"] for e in content)))
    print()
    zero = [e for e in content if e["length"] == 0]
    print("   entries declaring zero length (directories) : %d" % len(zero))
    if args.head:
        print()
        print("-- the first %d content entries by declared offset ---------"
              % args.head)
        for e in sorted((e for e in content if e["length"]),
                        key=lambda x: (x["section"], x["offset"]))[:args.head]:
            print("   sect %s off %10d len %9d  %s"
                  % (e["section"], e["offset"], e["length"], e["name"]))
    if args.biggest:
        print()
        print("-- the %d largest content entries -------------------------"
              % args.biggest)
        for e in sorted(content, key=lambda x: -x["length"])[:args.biggest]:
            print("   len %9d  sect %s  %s"
                  % (e["length"], e["section"], e["name"]))
    if args.tsv:
        with open(args.tsv, "w", encoding="utf-8") as fh:
            fh.write("chunk\tkind\tname\tsection\toffset\tlength\n")
            for e in entries:
                fh.write("%d\t%s\t%s\t%s\t%s\t%d\n"
                         % (e["chunk"], "PMGI" if e.get("index") else "PMGL",
                            e["name"],
                            "-" if e["section"] is None else e["section"],
                            "-" if e["offset"] is None else e["offset"],
                            e["length"]))
        print()
        print("full table : %s (%d rows)" % (args.tsv, len(entries)))
    ok = (not refusals
          and h["closure_total"] == 0
          and h["closure_dir_offset"] == 0
          and h["closure_content_offset"] == 0
          and kinds.count("PMGL") == itsp["last_pmgl"] - itsp["first_pmgl"] + 1)
    return 0 if ok else 1


EPOCH_1601 = 11644473600  # seconds between 1601-01-01 and 1970-01-01, both UTC


def filetime(v):
    """A Windows FILETIME as an ISO string, or None if it is out of range."""
    import datetime
    try:
        return (datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
                + datetime.timedelta(microseconds=v // 10)).strftime(
                    "%Y-%m-%d %H:%M:%S.%f UTC")
    except (OverflowError, OSError, ValueError):
        return None


def unixtime(v):
    import datetime
    try:
        return datetime.datetime.fromtimestamp(
            v, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return None


SYSTEM_CODE = {
    0: "contents file", 1: "index file", 2: "default topic", 3: "title",
    4: "binary: LCID, flags and a FILETIME", 5: "default window",
    6: "compiled file name", 7: "binary index", 9: "compiler version",
    10: "a u32 clock", 12: "u32", 13: "a copy of /#IDXHDR", 15: "u32",
    16: "default font",
}


def cmd_internals(args):
    """Every stream the container keeps about itself that is NOT compressed.

    Content section 0 is stored uncompressed; content section 1 is the LZX
    stream. Everything reported here is in section 0 and therefore readable
    with no decompressor at all -- which is the whole reason this subcommand
    exists and is where the object's only true authoring clock survives.
    """
    blob = open(args.path, "rb").read()
    h = read_header(blob)
    itsp = read_itsp(blob, h["dir_offset"])
    entries, kinds, refusals = read_chunks(blob, h["dir_offset"], itsp)
    base = h["content_offset"]
    sect0 = {e["name"]: e for e in entries
             if not e.get("index") and e["section"] == 0}

    def raw(name):
        e = sect0[name]
        return blob[base + e["offset"]:base + e["offset"] + e["length"]], e

    print("file                 : %s" % args.path)
    print("content section 0 at : %d, and it is UNCOMPRESSED" % base)
    print("entries in section 0 : %d" % len(sect0))
    print()

    print("--- ::DataSpace/NameList, which declares its own length ------")
    d, e = raw("::DataSpace/NameList")
    words, count = struct.unpack_from("<HH", d, 0)
    print("  entry declares      : %d bytes at +%d" % (e["length"], e["offset"]))
    print("  u16 at +0           : %d, a length in 16-bit words = %d bytes"
          % (words, words * 2))
    print("  residue against the entry's declared length : %d"
          % (words * 2 - e["length"]))
    print("  u16 at +2, entries  : %d" % count)
    i = 4
    for k in range(count):
        (nlen,) = struct.unpack_from("<H", d, i)
        name = d[i + 2:i + 2 + nlen * 2].decode("utf-16-le")
        print("  section %d           : %r (%d characters)" % (k, name, nlen))
        i += 2 + nlen * 2 + 2
    print("  residue after the walk : %d of %d" % (len(d) - i, len(d)))
    print()

    print("--- ::DataSpace/Storage/MSCompressed/ControlData --------------")
    d, e = raw("::DataSpace/Storage/MSCompressed/ControlData")
    w = struct.unpack("<%dI" % (len(d) // 4), d)
    print("  %d bytes at +%d, as %d u32 : %s" % (e["length"], e["offset"],
                                                 len(w), w))
    print("  u32 at +0            : %d, the count of u32 that follow" % w[0])
    print("  bytes 4..8           : %r   <- the LZXC tag, at absolute %d"
          % (d[4:8], base + e["offset"] + 4))
    print("  version              : %d" % w[2])
    print("  reset interval       : %d" % w[3])
    print("  window size          : %d" % w[4])
    print("  cache size           : %d" % w[5])
    print("  trailing u32         : %d" % w[6])
    print()

    print("--- ::DataSpace/Storage/MSCompressed/ResetTable --------------")
    d, e = raw("::DataSpace/Storage/MSCompressed/Transform/"
               "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable")
    ver, nblocks, esz, tof = struct.unpack_from("<IIII", d, 0)
    unc, comp, bsz = struct.unpack_from("<QQQ", d, 16)
    print("  %d bytes at +%d" % (e["length"], e["offset"]))
    print("  version              : %d" % ver)
    print("  block count          : %d" % nblocks)
    print("  entry size           : %d" % esz)
    print("  table offset         : %d" % tof)
    print("  uncompressed length  : %d" % unc)
    print("  compressed length    : %d" % comp)
    print("  LZX block size       : %d" % bsz)
    print("  %d + %d x %d = %d against a declared %d   residue %d"
          % (tof, nblocks, esz, tof + nblocks * esz, e["length"],
             tof + nblocks * esz - e["length"]))
    tab = [struct.unpack_from("<Q", d, tof + i * esz)[0] for i in range(nblocks)]
    print("  first five entries   : %s" % tab[:5])
    print("  last entry           : %d" % tab[-1])
    print("  monotone increasing  : %s"
          % all(tab[i] < tab[i + 1] for i in range(nblocks - 1)))
    print("  every entry inside the compressed stream : %s"
          % all(t <= comp for t in tab))
    print("  %d blocks x %d = %d, so the last block holds %d bytes"
          % (nblocks, bsz, nblocks * bsz, unc - (nblocks - 1) * bsz))
    print()

    print("--- the closures that cross two structures -------------------")
    cnt = sect0["::DataSpace/Storage/MSCompressed/Content"]
    print("  the Content entry declares %d bytes at +%d"
          % (cnt["length"], cnt["offset"]))
    print("  %d + %d + %d = %d against %d bytes on disc   residue %d"
          % (base, cnt["offset"], cnt["length"],
             base + cnt["offset"] + cnt["length"], len(blob),
             base + cnt["offset"] + cnt["length"] - len(blob)))
    print("  ResetTable's compressed length %d against the Content entry's "
          "%d   residue %d" % (comp, cnt["length"], comp - cnt["length"]))
    span, se = raw("::DataSpace/Storage/MSCompressed/SpanInfo")
    (spanv,) = struct.unpack("<Q", span)
    s1 = [e for e in entries if not e.get("index") and e["section"] == 1]
    reach = max(e["offset"] + e["length"] for e in s1)
    print("  SpanInfo declares %d" % spanv)
    print("  ResetTable's uncompressed length is %d   residue %d"
          % (unc, unc - spanv))
    print("  the furthest reach of the %d section-1 entries is %d   residue %d"
          % (len(s1), reach, reach - spanv))
    print("  their declared lengths sum to %d, which is %d less than the span"
          % (sum(e["length"] for e in s1), spanv - sum(e["length"] for e in s1)))
    print()
    print("--- does the directory TILE the decompressed stream? ----------")
    print("  The sum above is not the question; the layout is. Walked in")
    print("  offset order, every gap and every overlap is printed.")
    prev = 0
    gaps = []
    overlaps = []
    for e in sorted(s1, key=lambda x: (x["offset"], x["length"])):
        if e["offset"] > prev:
            gaps.append((prev, e["offset"] - prev, e["name"]))
        elif e["offset"] < prev:
            overlaps.append((e["offset"], prev - e["offset"], e["name"]))
        prev = max(prev, e["offset"] + e["length"])
    print("  entries        : %d" % len(s1))
    print("  overlaps       : %d" % len(overlaps))
    for o in overlaps[:8]:
        print("     %d bytes at %d, at %s" % (o[1], o[0], o[2]))
    print("  gaps           : %d, totalling %d bytes"
          % (len(gaps), sum(g[1] for g in gaps)))
    for g in gaps[:8]:
        print("     %d bytes at %d, before %s" % (g[1], g[0], g[2]))
    print("  furthest reach : %d against a declared span of %d   residue %d"
          % (prev, spanv, prev - spanv))
    if len(gaps) == 1:
        same = [e["name"] for e in s1 if e["length"] == gaps[0][1]]
        if same:
            print("  and the single gap is exactly the declared length of %s,"
                  % ", ".join(same))
            print("  which is declared %d bytes further into the stream. That"
                  % min(e["offset"] for e in s1 if e["length"] == gaps[0][1]))
            print("  is an observation and not a reading: settling it needs an")
            print("  LZX decoder, which this session did not write.")
    print()

    print("--- /#SYSTEM, which is in section 0 and therefore readable ---")
    d, e = raw("/#SYSTEM")
    (sysver,) = struct.unpack_from("<I", d, 0)
    print("  %d bytes at +%d (absolute %d)"
          % (e["length"], e["offset"], base + e["offset"]))
    print("  version              : %d" % sysver)
    i = 4
    rows = []
    while i + 4 <= len(d):
        code, ln = struct.unpack_from("<HH", d, i)
        i += 4
        if i + ln > len(d):
            print("  code %d declares %d bytes and the stream ends" % (code, ln))
            break
        rows.append((code, ln, d[i:i + ln]))
        i += ln
    print("  entries walked       : %d" % len(rows))
    print("  residue after the walk : %d of %d" % (len(d) - i, len(d)))
    print()
    clocks = []
    for code, ln, p in rows:
        label = SYSTEM_CODE.get(code, "?")
        if code in (0, 1, 2, 3, 5, 6, 9, 16):
            print("  code %-3d %-36s %r" % (code, label,
                                            p.rstrip(b"\x00").decode("ascii",
                                                                     "replace")))
        elif code == 10 and ln == 4:
            (v,) = struct.unpack("<I", p)
            print("  code %-3d %-36s %d -> %s" % (code, label, v, unixtime(v)))
            clocks.append(("/#SYSTEM code 10, a u32 Unix time", unixtime(v)))
        elif code == 4:
            (lcid,) = struct.unpack_from("<I", p, 0)
            (ft,) = struct.unpack_from("<Q", p, 20)
            print("  code %-3d %-36s LCID 0x%04X, FILETIME at +20 = 0x%016X"
                  % (code, label, lcid, ft))
            print("      %-36s -> %s" % ("", filetime(ft)))
            clocks.append(("/#SYSTEM code 4, a FILETIME at +20", filetime(ft)))
            hi = ft >> 32
            paired = (hi << 32) | h["stamp"]
            print()
            print("  AND THIS IS WHAT DATES THE ITSF HEADER.")
            print("  The u32 at +0x10 of the ITSF header is 0x%08X." % h["stamp"])
            print("  It is not a Unix time and it is not a date on its own.")
            print("  Paired with the high dword 0x%08X of the FILETIME above" % hi)
            print("  -- which is in a different structure written by the same")
            print("  pass -- it reads %s," % filetime(paired))
            print("  which is %+.4f s from that FILETIME. A field whose low"
                  % ((h["stamp"] - (ft & 0xFFFFFFFF)) / 1e7))
            print("  half lands within milliseconds of a timestamp found")
            print("  elsewhere in the same file is a timestamp; the high half")
            print("  is supplied here and that is stated, not hidden.")
            clocks.append(("the ITSF header's u32 at +0x10, paired",
                           filetime(paired)))
            print()
        elif ln == 4:
            print("  code %-3d %-36s u32 = %d"
                  % (code, label, struct.unpack("<I", p)[0]))
        else:
            print("  code %-3d %-36s %d bytes, beginning %r"
                  % (code, label, ln, p[:8]))
    print()
    print("--- every clock this container carries -----------------------")
    for what, when in clocks:
        print("  %-42s %s" % (what, when))
    print()

    print("--- the 11 ::DataSpace occurrences, placed -------------------")
    print("  `sigcount.py` counts the literal bytes. This says where they are")
    print("  and whether the chunk they sit in is using them.")
    off = 0
    inside = tail = 0
    while True:
        j = blob.find(b"::DataSpace", off)
        if j < 0:
            break
        n = (j - (h["dir_offset"] + itsp["header_length"])) // itsp["chunk_size"]
        co = h["dir_offset"] + itsp["header_length"] + n * itsp["chunk_size"]
        (free,) = struct.unpack_from("<I", blob, co + 4)
        used = itsp["chunk_size"] - free
        rel = j - co
        live = rel < used
        inside += live
        tail += not live
        print("  %8d  chunk %d (%s) at +%-5d  %s"
              % (j, n, kinds[n] if n < len(kinds) else "?", rel,
                 "in the used area" if live else "IN THE UNUSED TAIL"))
        off = j + 1
    print("  in a used area : %d      in an unused tail : %d      total : %d"
          % (inside, tail, inside + tail))
    print("  directory entries whose name begins '::' : %d"
          % sum(1 for e in entries if e["name"].startswith("::")))
    print()
    print("  The three in the tail sit at the SAME chunk offsets as three")
    print("  live ones in the chunk before, and so does the quickref table")
    print("  beside them: the packer reused one 4096-byte buffer, wrote a")
    print("  shorter chunk into it and did not clear the rest. A signature")
    print("  count cannot know that, and this is why it reports more")
    print("  occurrences than the directory has entries.")
    return 0


def cmd_find(args):
    hits = []
    n = 0
    for dp, dn, fn in os.walk(args.root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            n += 1
            try:
                with open(p, "rb") as fh:
                    if fh.read(4) == b"ITSF":
                        hits.append((p, os.path.getsize(p)))
            except OSError:
                pass
    print("files opened              : %d" % n)
    print("files beginning with ITSF : %d" % len(hits))
    for p, s in hits:
        print("   %12d  %s" % (s, p))
    return 0


# ---------------------------------------------------------------- selftest

def build(version=3, hlen=96, s0len=24, dirlen=None, chunksize=4096,
          nchunks=1, itsp_hlen=84, itsp_version=1, first=0, last=0, root=0,
          entries=None, total=None, tag=b"PMGL", trailer=b"",
          declared_total_delta=0):
    """Construct an ITSF container in memory. Most specimens are broken."""
    if entries is None:
        entries = [(b"/", 0, 0, 0), (b"::DataSpace/NameList", 0, 0, 40)]
    if dirlen is None:
        dirlen = itsp_hlen + nchunks * chunksize
    dir_off = hlen + s0len
    content_off = dir_off + dirlen

    def enc(v):
        if v == 0:
            return b"\x00"
        out = bytearray()
        while v:
            out.insert(0, v & 0x7F)
            v >>= 7
        for i in range(len(out) - 1):
            out[i] |= 0x80
        return bytes(out)

    body = bytearray()
    for name, sect, off, ln in entries:
        body += enc(len(name)) + name + enc(sect) + enc(off) + enc(ln)
    chunks = bytearray()
    for c in range(nchunks):
        payload = bytearray()
        if tag == b"PMGL":
            used = body if c == 0 else b""
            free = chunksize - 20 - len(used)
            payload += b"PMGL" + struct.pack("<IIii", free, 0,
                                             c - 1 if c else -1,
                                             c + 1 if c + 1 < nchunks else -1)
            payload += used
        else:
            free = chunksize - 8
            payload += tag + struct.pack("<I", free)
        payload += bytes(chunksize - len(payload))
        chunks += payload

    itsp = bytearray()
    itsp += b"ITSP" + struct.pack("<IIIIIiiiiiIi", itsp_version, itsp_hlen, 10,
                                  chunksize, 2, 2, root, first, last, -1,
                                  nchunks, 0x0409)
    itsp += uuid.UUID("5D02929A-212E-11D0-9DF9-00A0C922E6EC").bytes_le
    itsp += struct.pack("<Iiii", itsp_hlen, -1, -1, -1)
    itsp += bytes(max(0, itsp_hlen - len(itsp)))

    content = b"CONTENTBYTES"
    # The declared total is the length of the CONTAINER, deliberately excluding
    # `trailer`. A trailer models bytes appended after a container that still
    # describes itself correctly, which is the case the closure has to catch --
    # and the first version of this builder folded the trailer into the total,
    # so the closure came back 0 and the check passed for the wrong reason. The
    # selftest caught it on its first run.
    filelen = content_off + len(content)
    s0 = struct.pack("<QQQ", 510, (total if total is not None else filelen)
                     + declared_total_delta, 0)
    s0 += bytes(max(0, s0len - len(s0)))

    head = bytearray()
    head += b"ITSF" + struct.pack("<IIIII", version, hlen, 1, 0xB4478377,
                                  0x0C07)
    head += uuid.UUID("7C01FD10-7BAA-11D0-9E0C-00A0C922E6EC").bytes_le
    head += uuid.UUID("7C01FD11-7BAA-11D0-9E0C-00A0C922E6EC").bytes_le
    head += struct.pack("<QQQQQ", hlen, s0len, dir_off, dirlen, content_off)
    head += bytes(max(0, hlen - len(head)))

    return bytes(head) + bytes(s0) + bytes(itsp) + bytes(chunks) + content \
        + trailer


def selftest():
    checks = []

    def ok(name, cond):
        checks.append((name, bool(cond)))

    def refuses(name, thunk, fragment):
        try:
            thunk()
        except Bad as e:
            ok(name + " (" + fragment + ")", fragment in str(e))
        else:
            ok(name + " (" + fragment + ")", False)

    blob = build()
    h = read_header(blob)
    ok("a constructed ITSF v3 parses", h["version"] == 3)
    ok("header + section 0 lands on the directory offset",
       h["closure_dir_offset"] == 0)
    ok("directory offset + length lands on the content offset",
       h["closure_content_offset"] == 0)
    ok("the declared total equals the constructed length",
       h["closure_total"] == 0)
    itsp = read_itsp(blob, h["dir_offset"])
    ok("ITSP parses and declares 1 chunk", itsp["chunk_count"] == 1)
    ok("ITSP header length + count*size equals the declared directory length",
       itsp["header_length"] + itsp["chunk_count"] * itsp["chunk_size"]
       == h["dir_length"])
    entries, kinds, refs = read_chunks(blob, h["dir_offset"], itsp)
    ok("the two constructed entries come back", len(entries) == 2)
    ok("their names come back exactly",
       [e["name"] for e in entries] == ["/", "::DataSpace/NameList"])
    ok("the second entry's declared length comes back",
       entries[1]["length"] == 40)
    ok("no refusals on a good specimen", refs == [])

    refuses("empty input", lambda: read_header(b""), "shorter than")
    refuses("a PNG", lambda: read_header(b"\x89PNG\r\n\x1a\n" + bytes(100)),
            "no ITSF signature")
    refuses("an MZP executable",
            lambda: read_header(b"MZP\x00" + bytes(100)), "no ITSF signature")
    refuses("ITSF version 2",
            lambda: read_header(build(version=2)), "version 2")
    refuses("a header length of 88 on version 3",
            lambda: read_header(build(hlen=88)), "not 96")
    refuses("ITSP version 3",
            lambda: read_itsp(build(itsp_version=3), 120), "version 3")
    refuses("an ITSP header length of 80",
            lambda: read_itsp(build(itsp_hlen=80), 120), "not 84")
    refuses("no ITSP where the header points",
            lambda: read_itsp(b"ITSF" + bytes(200), 96), "no ITSP signature")

    def bad_chunksize():
        b = bytearray(build())
        struct.pack_into("<I", b, 120 + 0x10, 3000)
        read_itsp(bytes(b), 120)
    refuses("a chunk size of 3000", bad_chunksize, "not a power of")

    def zero_chunks():
        b = bytearray(build())
        struct.pack_into("<I", b, 120 + 0x2C, 0)
        read_itsp(bytes(b), 120)
    refuses("a chunk count of zero", zero_chunks, "0 directory chunks")

    h = read_header(build(declared_total_delta=7))
    ok("a declared total seven bytes too large is reported, not silently used",
       h["closure_total"] == 7)

    h = read_header(build(trailer=b"appended"))
    ok("eight appended bytes make the total closure -8, not 0",
       h["closure_total"] == -8)

    blob = build(nchunks=3, first=0, last=2)
    h = read_header(blob)
    itsp = read_itsp(blob, h["dir_offset"])
    entries, kinds, refs = read_chunks(blob, h["dir_offset"], itsp)
    ok("three chunks give three tags", kinds == ["PMGL", "PMGL", "PMGL"])
    ok("first/last PMGL implies the same 3 chunks",
       itsp["last_pmgl"] - itsp["first_pmgl"] + 1 == 3)

    blob = build(tag=b"XXXX")
    h = read_header(blob)
    itsp = read_itsp(blob, h["dir_offset"])
    entries, kinds, refs = read_chunks(blob, h["dir_offset"], itsp)
    ok("a chunk tagged neither PMGL nor PMGI is refused with its offset",
       any("neither PMGL" in r for r in refs))

    ok("ENCINT reads a single byte", encint(b"\x2f", 0) == (47, 1))
    ok("ENCINT reads two bytes big-endian",
       encint(b"\x81\x00", 0) == (128, 2))
    ok("ENCINT is big-endian, not little",
       encint(b"\x83\x75", 0) == ((3 << 7) | 0x75, 2))
    try:
        encint(b"\x80", 0)
    except Bad as e:
        ok("an ENCINT with the continue bit at the end refuses",
           "runs off the end" in str(e))
    else:
        ok("an ENCINT with the continue bit at the end refuses", False)

    width = max(len(n) for n, _ in checks)
    for n, g in checks:
        print("  %-*s %s" % (width, n, "ok" if g else "FAIL"))
    bad = [n for n, g in checks if not g]
    print("%d checks, %d failures" % (len(checks), len(bad)))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("header")
    a.add_argument("path")
    b = sub.add_parser("list")
    b.add_argument("path")
    b.add_argument("--tsv")
    b.add_argument("--head", type=int, default=0)
    b.add_argument("--biggest", type=int, default=0)
    c = sub.add_parser("find")
    c.add_argument("root")
    e = sub.add_parser("internals")
    e.add_argument("path")
    sub.add_parser("selftest")
    args = ap.parse_args()
    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "header":
        return cmd_header(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "internals":
        return cmd_internals(args)
    return cmd_find(args)


if __name__ == "__main__":
    sys.exit(main())
