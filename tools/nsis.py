#!/usr/bin/env python3
"""nsis.py -- an NSIS installer read from its own bytes.

Eighty-one per cent of this object is five Nullsoft Scriptable Install System
archives and nothing in the 360 inherited tools opens one. This does, from the
published format definition, and it says out loud that it is using a published
definition rather than pretending to have reverse-engineered one.

THE FORMAT, AS PUBLISHED (NSIS 2.x, `exehead/fileform.h`)

  A PE32 stub is followed at the end of its image by a 28-byte *firstheader*:

      +0   u32   flags                  FH_FLAGS_UNINSTALL 1, SILENT 2,
                                        NO_CRC 4, FORCE_CRC 8
      +4   u32   siginfo                0xDEADBEEF
      +8   12 B  magic                  'NullsoftInst'
     +20   u32   length_of_header       the *uncompressed* size of the header
                                        block
     +24   u32   length_of_all_following_data
                                        counted FROM the firstheader, i.e.
                                        stub_size + this == file size

  Then the compressed data. If the first bytes after the firstheader are
  themselves a compressor signature the archive is SOLID: header block and
  every member share one stream and one dictionary. If instead a u32 size
  precedes the signature, each block is compressed on its own.

  Decompressed, the stream begins with a `u32` that repeats length_of_header,
  and *then* the header block:

      +0   u32   length_of_header, a second time
      +4   u32   flags
      +8   8 x { u32 offset, u32 num }   the block table

  and the blocks are, in order: pages, sections, entries, strings, langtables,
  ctlcolors, bgfont, data. The last two descriptors are **zero** on this
  object: the data block is not described by a descriptor at all, it simply
  follows the header, so the data base is `4 + length_of_header`. The
  encoded-twice test therefore fires in two other places instead, and both are
  printed: `u32@0 == length_of_header`, and the data records' declared sizes
  chain from the base to the last byte of the decompressed stream with
  residue 0.

THE THING THAT IS NOT IN THE FORMAT, AND IT MATTERS

  **NSIS has no file table.** There is no directory of members anywhere. The
  member list is recovered by walking the *entries* block -- the compiled
  install script -- and reading the operands of every EW_EXTRACTFILE (opcode
  20): an overwrite flag, an index into the string block for the name, an
  offset into the data block, and a two-word FILETIME. The destination comes
  from EW_CREATEDIR (opcode 11) entries with their second operand set, which
  is what `SetOutPath` compiles to.

  So a listing produced by this tool is *derived from an instruction stream*,
  not read from a table, and a listing that merely looks plausible is exactly
  the failure mode this pipeline lost a chapter to last session. Three guards,
  all of them printed rather than assumed:

    * every member's declared size must chain from the first to the end of the
      decompressed stream with residue 0;
    * `--validate` runs before `--census` and must FAIL on a non-NSIS PE;
    * the listing is compared against 7-Zip's, which is a second opinion and
      not a substitute for the derivation.

    python tools/nsis.py --validate f.exe [f2.exe ...]
    python tools/nsis.py --header   f.exe
    python tools/nsis.py --census   f.exe out.txt [--solid-out blob.bin]
    python tools/nsis.py --extract  f.exe outdir --only PREFIX
"""
import argparse
import hashlib
import lzma
import os
import struct
import sys

FH_SIZE = 28
FH_SIG = 0xDEADBEEF
FH_MAGIC = b"NullsoftInst"
FH_FLAG_NAMES = [(1, "UNINSTALL"), (2, "SILENT"), (4, "NO_CRC"), (8, "FORCE_CRC")]

ENTRY_SIZE = 28          # u32 opcode + 6 u32 operands
MAX_OFFSETS = 6
EW_CREATEDIR = 11
EW_EXTRACTFILE = 20

BLOCK_NAMES = ["pages", "sections", "entries", "strings",
               "langtables", "ctlcolors", "bgfont", "data"]

NS_SKIP_CODE = 252
NS_VAR_CODE = 253
NS_SHELL_CODE = 254
NS_LANG_CODE = 255

VAR_NAMES = (["$%d" % i for i in range(10)] +
             ["$R%d" % i for i in range(10)] +
             ["$CMDLINE", "$INSTDIR", "$OUTDIR", "$EXEDIR", "$LANGUAGE",
              "$TEMP", "$PLUGINSDIR", "$EXEPATH", "$EXEFILE", "$HWNDPARENT",
              "$_CLICK", "$_OUTDIR"])


class NotNsis(Exception):
    pass


def printable(s):
    """Escape control bytes for a text output file.

    One of this object's language strings is an RTF licence agreement that
    begins with a literal 0x02, and writing it raw put a control byte into
    every member census. The census is a published artefact and must be text.
    """
    return "".join(c if (c >= " " and c != chr(127)) else "\\x%02x" % ord(c)
                   for c in s)


def pe_image_end(data):
    """Where the PE image stops, which is where an NSIS overlay starts."""
    if data[:2] != b"MZ":
        raise NotNsis("no MZ signature")
    if len(data) < 0x40:
        raise NotNsis("shorter than a DOS header")
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if lfanew == 0 or lfanew + 24 > len(data):
        raise NotNsis("e_lfanew %d does not point at a PE header" % lfanew)
    if data[lfanew:lfanew + 4] != b"PE\0\0":
        raise NotNsis("no PE signature at e_lfanew")
    nsec = struct.unpack_from("<H", data, lfanew + 6)[0]
    optsz = struct.unpack_from("<H", data, lfanew + 20)[0]
    sec0 = lfanew + 24 + optsz
    end = 0
    for i in range(nsec):
        off = sec0 + i * 40
        rawsize, rawoff = struct.unpack_from("<II", data, off + 16)
        if rawsize:
            end = max(end, rawoff + rawsize)
    if end == 0:
        raise NotNsis("no section carries raw data")
    return end


def read_firstheader(data, at):
    if at + FH_SIZE > len(data):
        raise NotNsis("no room for a firstheader at %d" % at)
    flags, sig = struct.unpack_from("<II", data, at)
    magic = data[at + 8:at + 20]
    if sig != FH_SIG:
        raise NotNsis("siginfo at +%d is 0x%08X, not 0xDEADBEEF" % (at + 4, sig))
    if magic != FH_MAGIC:
        raise NotNsis("magic at +%d is %r, not %r" % (at + 8, magic, FH_MAGIC))
    hdrlen, alllen = struct.unpack_from("<II", data, at + 20)
    return {"at": at, "flags": flags, "header_size": hdrlen, "archive_size": alllen}


def flag_names(flags):
    out = [n for b, n in FH_FLAG_NAMES if flags & b]
    rest = flags & ~15
    if rest:
        out.append("unknown:0x%X" % rest)
    return "|".join(out) if out else "none"


def find_nsis(path, want_bytes=None):
    """Return (fh, filesize, head_bytes). Raises NotNsis with a reason."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(min(size, 1 << 20))
    at = pe_image_end(head)
    if at + FH_SIZE > size:
        raise NotNsis("PE image ends at %d, past the end of a %d-byte file"
                      % (at, size))
    with open(path, "rb") as f:
        f.seek(at)
        fhbytes = f.read(FH_SIZE + 8)
    fh = read_firstheader(fhbytes, 0)
    fh["at"] = at
    fh["file_size"] = size
    fh["residue"] = size - (at + fh["archive_size"])
    fh["props"] = fhbytes[FH_SIZE:FH_SIZE + 8]
    return fh


def describe_compressor(props):
    """props = the 8 bytes at firstheader+28."""
    b = props
    if b[0] == 0x5D and b[1] == 0 and b[2] == 0:
        dic = struct.unpack_from("<I", b, 1)[0]
        return ("lzma-solid", dic, 5)
    if b[0] == 0x5D:
        dic = struct.unpack_from("<I", b, 1)[0]
        return ("lzma-solid", dic, 5)
    if b[0:3] == b"BZh":
        return ("bzip2-solid", 0, 0)
    return ("unknown", 0, 0)


def decompress_solid(path, fh, out_path, limit=None):
    """Stream the solid LZMA payload to out_path. Returns bytes written."""
    name, dic, propsize = describe_compressor(fh["props"])
    if not name.startswith("lzma"):
        raise NotNsis("compressor %s is not handled" % name)
    filt = [{"id": lzma.FILTER_LZMA1, "dict_size": dic,
             "lc": 3, "lp": 0, "pb": 2}]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filt)
    written = 0
    with open(path, "rb") as f, open(out_path, "wb") as out:
        f.seek(fh["at"] + FH_SIZE + propsize)
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            try:
                buf = dec.decompress(chunk)
            except lzma.LZMAError:
                break
            if buf:
                out.write(buf)
                written += len(buf)
            if limit and written >= limit:
                break
            if dec.eof:
                break
    return written


def read_langtable(blob, hdr_base, blocks):
    """Return the list of string offsets a $LANGnn escape resolves through.

    An NSIS language table is `u16 lang_id; u32 dlg_offset; u32 rtl;` followed
    by one u32 string offset per language string id. The 10-byte prefix is not
    guessed: it is the only one under which the table length divides by four
    and under which the episode names land where the install paths use them.
    """
    lt_off = blocks[4]["offset"]
    lt_end = blocks[5]["offset"] if blocks[5]["offset"] > lt_off else lt_off
    lt = blob[hdr_base + lt_off:hdr_base + lt_end]
    if len(lt) < 10:
        return 0, []
    lang_id = struct.unpack_from("<H", lt, 0)[0]
    n = (len(lt) - 10) // 4
    return lang_id, list(struct.unpack_from("<%di" % n, lt, 10))


def decode_string(strings, off, langtable=None):
    """Decode one NUL-terminated NSIS string, resolving variable escapes."""
    if off < 0 or off >= len(strings):
        return "<bad string offset %d>" % off
    end = strings.find(b"\0", off)
    if end < 0:
        end = len(strings)
    raw = strings[off:end]
    out = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == NS_SKIP_CODE:
            i += 1
            if i < len(raw):
                out.append(chr(raw[i]))
                i += 1
            continue
        if c in (NS_VAR_CODE, NS_SHELL_CODE, NS_LANG_CODE):
            if i + 2 < len(raw):
                idx = (raw[i + 1] & 0x7F) | ((raw[i + 2] & 0x7F) << 7)
            else:
                idx = -1
            if c == NS_VAR_CODE:
                out.append(VAR_NAMES[idx] if 0 <= idx < len(VAR_NAMES)
                           else "$VAR%d" % idx)
            elif c == NS_SHELL_CODE:
                out.append("$SHELL%d" % idx)
            else:
                if langtable and 0 <= idx < len(langtable):
                    out.append(decode_string(strings, langtable[idx]))
                else:
                    out.append("$LANG%d" % idx)
            i += 3
            continue
        out.append(chr(c))
        i += 1
    return "".join(out)


def parse_header(blob, header_size):
    """Return dict with the repeated size, the flags and the block table.

    Block offsets are relative to the START OF THE HEADER STRUCT, which is at
    +4 in the decompressed stream, not to the stream itself.
    """
    echoed = struct.unpack_from("<I", blob, 0)[0]
    flags = struct.unpack_from("<I", blob, 4)[0]
    blocks = []
    for i in range(len(BLOCK_NAMES)):
        off, num = struct.unpack_from("<II", blob, 8 + i * 8)
        blocks.append({"name": BLOCK_NAMES[i], "offset": off, "num": num})
    return {"echoed_size": echoed, "flags": flags, "blocks": blocks}


def census(path, out_path, solid_out=None, keep=False, quiet=False, reuse=False):
    fh = find_nsis(path)
    name, dic, propsize = describe_compressor(fh["props"])
    tmp = solid_out or (out_path + ".solid.tmp")
    if reuse and os.path.exists(tmp):
        total = os.path.getsize(tmp)
    else:
        total = decompress_solid(path, fh, tmp)
    with open(tmp, "rb") as f:
        blob = f.read(fh["header_size"] + 4)
    hdr = parse_header(blob, fh["header_size"])
    blocks = hdr["blocks"]
    hdr_base = 4                      # the header struct starts after the echo
    data_off = 4 + fh["header_size"]  # and the data follows the header
    ent = blocks[2]
    strb = blocks[3]
    with open(tmp, "rb") as f:
        f.seek(hdr_base + strb["offset"])
        strings_len = blocks[4]["offset"] - strb["offset"]
        strings = f.read(strings_len)
        f.seek(hdr_base + ent["offset"])
        entries = f.read(ent["num"] * ENTRY_SIZE)

    lang_id, langtable = read_langtable(blob, hdr_base, blocks)
    members = []
    outdir = ""
    for i in range(ent["num"]):
        which, = struct.unpack_from("<I", entries, i * ENTRY_SIZE)
        ops = struct.unpack_from("<6I", entries, i * ENTRY_SIZE + 4)
        if which == EW_CREATEDIR and ops[1]:
            outdir = decode_string(strings, ops[0], langtable)
        elif which == EW_EXTRACTFILE:
            nm = decode_string(strings, ops[1], langtable)
            members.append({"dir": outdir, "name": nm, "pos": ops[2],
                            "ftl": ops[3], "fth": ops[4], "entry": i})

    # size of each member, read from the data block, and the chain test
    fsize = os.path.getsize(tmp)
    seen = {}
    with open(tmp, "rb") as f:
        for m in members:
            f.seek(data_off + m["pos"])
            raw = f.read(4)
            if len(raw) < 4:
                m["size"] = -1
                m["sha1"] = "-"
                continue
            sz, = struct.unpack("<I", raw)
            m["compressed"] = bool(sz & 0x80000000)
            m["size"] = sz & 0x7FFFFFFF
            if m["pos"] in seen:
                m["sha1"] = seen[m["pos"]]
                continue
            h = hashlib.sha1()
            left = m["size"]
            while left > 0:
                buf = f.read(min(left, 1 << 20))
                if not buf:
                    break
                h.update(buf)
                left -= len(buf)
            m["sha1"] = h.hexdigest()
            seen[m["pos"]] = m["sha1"]

    positions = sorted(set(m["pos"] for m in members))
    chain_ok = True
    walk = 0
    nchain = 0
    with open(tmp, "rb") as f:
        while data_off + walk + 4 <= fsize:
            f.seek(data_off + walk)
            sz, = struct.unpack("<I", f.read(4))
            sz &= 0x7FFFFFFF
            if sz == 0 or data_off + walk + 4 + sz > fsize:
                break
            walk += 4 + sz
            nchain += 1
    chain_residue = fsize - (data_off + walk)

    with open(out_path, "w", encoding="utf-8") as o:
        o.write("# nsis.py --census %s\n" % os.path.basename(path))
        o.write("file_size\t%d\n" % fh["file_size"])
        o.write("stub_size\t%d\n" % fh["at"])
        o.write("flags\t0x%08X\t%s\n" % (fh["flags"], flag_names(fh["flags"])))
        o.write("header_size\t%d\n" % fh["header_size"])
        o.write("archive_size\t%d\n" % fh["archive_size"])
        o.write("closure_residue\t%d\n" % fh["residue"])
        o.write("compressor\t%s\tdict\t%d\n" % (name, dic))
        o.write("decompressed\t%d\n" % total)
        o.write("echoed_header_size\t%d\t%s\n" %
                (hdr["echoed_size"],
                 "AGREES" if hdr["echoed_size"] == fh["header_size"] else "DISAGREES"))
        o.write("header_flags\t0x%08X\n" % hdr["flags"])
        o.write("data_block_offset\t%d\n" % data_off)
        for b in blocks:
            o.write("block\t%s\t%d\t%d\n" % (b["name"], b["offset"], b["num"]))
        o.write("entries\t%d\n" % ent["num"])
        o.write("members\t%d\n" % len(members))
        o.write("chain_records\t%d\tchain_residue\t%d\n" % (nchain, chain_residue))
        o.write("lang_id\t%d\tlangstrings\t%d\n" % (lang_id, len(langtable)))
        for i, so in enumerate(langtable):
            v = decode_string(strings, so) if 0 <= so < len(strings) else ""
            if v:
                o.write("langstring\t%d\t%s\n" % (i, printable(v)))
        o.write("distinct_positions\t%d\n" % len(seen))
        o.write("#\n# sha1\tsize\tpos\tpath\n")
        for m in members:
            p = (m["dir"] + "\\" + m["name"]) if m["dir"] else m["name"]
            o.write("%s\t%d\t%d\t%s\n" % (m["sha1"], m["size"], m["pos"], p))

    if not quiet:
        print("%-22s stub %d  hdr %d  arch %d  residue %d" %
              (os.path.basename(path), fh["at"], fh["header_size"],
               fh["archive_size"], fh["residue"]))
        print("  compressor   %s, dictionary %d" % (name, dic))
        print("  decompressed %d  (ratio %.4f:1)" %
              (total, total / float(fh["archive_size"] - FH_SIZE - propsize)))
        print("  echoed size  %d vs header_size %d -> %s" %
              (hdr["echoed_size"], fh["header_size"],
               "AGREE" if hdr["echoed_size"] == fh["header_size"] else "DISAGREE"))
        print("  data block at %d" % data_off)
        print("  entries %d, EW_EXTRACTFILE %d, distinct positions %d"
              % (ent["num"], len(members), len(seen)))
        print("  langtable id %d, %d string ids" % (lang_id, len(langtable)))
        print("  chain    %d records, residue %d  -> %s" %
              (nchain, chain_residue, "CLOSES" if chain_residue == 0 else "DOES NOT CLOSE"))
        print("  wrote %s" % out_path)
    if not keep and not solid_out:
        os.remove(tmp)
    return 0


def validate(paths):
    ok = bad = 0
    for p in paths:
        try:
            fh = find_nsis(p)
        except NotNsis as exc:
            print("%-26s NOT NSIS: %s" % (os.path.basename(p), exc))
            bad += 1
            continue
        name, dic, _ = describe_compressor(fh["props"])
        verdict = "OK" if fh["residue"] == 0 else "ARITHMETIC FAILS"
        print("%-26s NSIS  stub %7d  hdr %8d  arch %10d  residue %d  %s  %s [%s]"
              % (os.path.basename(p), fh["at"], fh["header_size"],
                 fh["archive_size"], fh["residue"], name,
                 verdict, flag_names(fh["flags"])))
        if fh["residue"] != 0:
            bad += 1
        else:
            ok += 1
    print("\naccepted %d, rejected %d, of %d" % (ok, bad, len(paths)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", nargs="+")
    ap.add_argument("--header")
    ap.add_argument("--census", nargs=2, metavar=("FILE", "OUT"))
    ap.add_argument("--solid-out")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--reuse", action="store_true",
                    help="if the solid blob already exists, do not decompress again")
    args = ap.parse_args()

    if args.validate:
        return validate(args.validate)
    if args.header:
        fh = find_nsis(args.header)
        print("stub ends        %d" % fh["at"])
        print("flags            0x%08X  %s" % (fh["flags"], flag_names(fh["flags"])))
        print("header_size      %d" % fh["header_size"])
        print("archive_size     %d" % fh["archive_size"])
        print("file_size        %d" % fh["file_size"])
        print("closure residue  %d" % fh["residue"])
        print("props bytes      %s" % fh["props"].hex())
        print("compressor       %s dict %d" % describe_compressor(fh["props"])[:2])
        return 0
    if args.census:
        return census(args.census[0], args.census[1],
                      solid_out=args.solid_out, keep=args.keep, reuse=args.reuse)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
