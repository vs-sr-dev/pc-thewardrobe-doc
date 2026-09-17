#!/usr/bin/env python3
"""kfpkg.py -- read the Unreal packages of this object: header, compressed
chunk table, name table, import table, export table.

WHAT IS DERIVED HERE AND WHAT IS NOT
------------------------------------
The UE3 package layout is **described by third parties** -- it is not
published by Epic and it is not undocumented either, and this repository names
that as its own category. What this file takes from that description is the
*order and meaning* of the summary fields, the 28-byte import record, the
LZO constant and the shape of `FCompressedChunkHeader`. What it derives from
the object is every number: the field offsets are confirmed against this
object's own arithmetic before anything is read out of them, and a record
width that does not close is a fatal error rather than a warning.

THE ARITHMETIC THAT HAS TO CLOSE BEFORE ANYTHING IS BELIEVED
------------------------------------------------------------
    ImportOffset  - NameOffset    == bytes consumed reading NameCount names
    ExportOffset  - ImportOffset  == ImportCount * 28
    DependsOffset - ExportOffset  == bytes consumed reading ExportCount exports
    for a compressed package: the chunks tile [first UncompressedOffset, end)
                              and their CompressedOffset/Size tile the file
                              from the end of the summary to its end

`validate` runs before `census`, always, and the specimen that must fail is in
the object: the three `.tfc` carry the package tag and are not packages.

    python tools/kfpkg.py --selftest
    python tools/kfpkg.py --validate
    python tools/kfpkg.py --census
    python tools/kfpkg.py --chunks
    python tools/kfpkg.py --names  KFGame/CookedPC/Core.u
    python tools/kfpkg.py --tables KFGame/CookedPC/Core.u
    python tools/kfpkg.py --classcensus --limit 12
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzo1x import decompress, LzoError            # noqa: E402

ROOT = "karmaflow-steam"
TAG = 0x9E2A83C1
PKG_STORE_COMPRESSED = 0x02000000
COMPRESS_ZLIB, COMPRESS_LZO, COMPRESS_LZX = 1, 2, 4
CODEC = {0: "none", 1: "ZLIB", 2: "LZO", 4: "LZX"}
IMPORT_RECORD = 28


class NotAPackage(Exception):
    pass


def fstring(d, o):
    if o + 4 > len(d):
        raise NotAPackage("string length field runs off the end at %d" % o)
    (n,) = struct.unpack_from("<i", d, o)
    o += 4
    if n == 0:
        return "", o
    if n > 0:
        if n > 1024 or o + n > len(d):
            raise NotAPackage("string of %d bytes at %d is not a folder name"
                              % (n, o))
        return d[o:o + n - 1].decode("latin-1"), o + n
    n = -n
    if n > 1024 or o + n * 2 > len(d):
        raise NotAPackage("wide string of %d chars at %d is not a folder name"
                          % (n, o))
    return d[o:o + n * 2 - 2].decode("utf-16-le"), o + n * 2


class Summary(object):
    """The package summary, parsed and then checked against the file."""

    def __init__(self, data, filesize, path="<memory>"):
        self.path = path
        self.filesize = filesize
        d = data
        if len(d) < 32:
            raise NotAPackage("%d bytes is too short for a summary" % len(d))
        (tag,) = struct.unpack_from("<I", d, 0)
        if tag != TAG:
            raise NotAPackage("tag is 0x%08X, not 0x%08X" % (tag, TAG))
        self.version, self.licensee = struct.unpack_from("<HH", d, 4)
        (self.header_size,) = struct.unpack_from("<i", d, 8)
        self.folder, o = fstring(d, 12)
        (self.flags, self.name_count, self.name_offset,
         self.export_count, self.export_offset,
         self.import_count, self.import_offset,
         self.depends_offset) = struct.unpack_from("<I7i", d, o)
        o += 32
        (self.ieg_offset, self.import_guids,
         self.export_guids) = struct.unpack_from("<3i", d, o)
        o += 12
        (self.thumbnail_offset,) = struct.unpack_from("<i", d, o)
        o += 4
        self.guid = d[o:o + 16]
        o += 16
        (ngen,) = struct.unpack_from("<i", d, o)
        o += 4
        if not 0 <= ngen <= 4096:
            raise NotAPackage("generation count %d is not credible" % ngen)
        self.generations = []
        for _ in range(ngen):
            self.generations.append(struct.unpack_from("<3i", d, o))
            o += 12
        (self.engine_version, self.cooker_version,
         self.compression_flags) = struct.unpack_from("<iiI", d, o)
        o += 12
        (nchunk,) = struct.unpack_from("<i", d, o)
        o += 4
        if not 0 <= nchunk <= 65536:
            raise NotAPackage("chunk count %d is not credible" % nchunk)
        self.chunks = []
        for _ in range(nchunk):
            self.chunks.append(struct.unpack_from("<4i", d, o))
            o += 16
        (self.package_source,) = struct.unpack_from("<I", d, o)
        o += 4
        (nadd,) = struct.unpack_from("<i", d, o)
        o += 4
        if not 0 <= nadd <= 4096:
            raise NotAPackage("additional-package count %d is not credible"
                              % nadd)
        self.additional = []
        for _ in range(nadd):
            s, o = fstring(d, o)
            self.additional.append(s)
        # FTextureAllocations, and it is an ARRAY and not a count. The first
        # run of --validate complained on 79 of 113 packages that the first
        # chunk did not begin where the summary ended; the gap was this array,
        # and it is 24 bytes plus a counted list of i32 export indices per
        # entry. The complaint was the check doing its job.
        (self.texture_allocations,) = struct.unpack_from("<i", d, o)
        o += 4
        if not 0 <= self.texture_allocations <= 1 << 20:
            raise NotAPackage("texture-allocation count %d is not credible"
                              % self.texture_allocations)
        self.tex_alloc = []
        for _ in range(self.texture_allocations):
            sx, sy, mips, fmt, cflags = struct.unpack_from("<5i", d, o)
            o += 20
            (n_exp,) = struct.unpack_from("<i", d, o)
            o += 4
            if not 0 <= n_exp <= 1 << 20:
                raise NotAPackage("texture allocation names %d exports" % n_exp)
            o += 4 * n_exp
            self.tex_alloc.append((sx, sy, mips, fmt, cflags, n_exp))
        self.summary_end = o

    @property
    def compressed(self):
        return bool(self.flags & PKG_STORE_COMPRESSED)

    def validate(self):
        """Every check that can be made without decompressing anything.

        Returns a list of complaints; empty means the file is self-consistent.
        """
        bad = []
        if self.version != 868:
            bad.append("file version %d, not 868" % self.version)
        for label, count, off in (("name", self.name_count, self.name_offset),
                                  ("import", self.import_count,
                                   self.import_offset),
                                  ("export", self.export_count,
                                   self.export_offset)):
            if count < 0:
                bad.append("%s count is negative" % label)
            if off < 0 or off > self.header_size:
                bad.append("%s offset %d is outside the declared header"
                           % (label, off))
        if not (self.name_offset <= self.import_offset
                <= self.export_offset <= self.depends_offset):
            bad.append("the four table offsets are not in ascending order")
        span = self.export_offset - self.import_offset
        if self.import_count and span != self.import_count * IMPORT_RECORD:
            bad.append("import table spans %d bytes for %d records; %d each "
                       "does not divide it"
                       % (span, self.import_count, IMPORT_RECORD))
        if self.compressed:
            if not self.chunks:
                bad.append("PKG_StoreCompressed is set and there are no chunks")
            if self.compression_flags == 0:
                bad.append("PKG_StoreCompressed is set and the codec is none")
        else:
            if self.chunks:
                bad.append("chunks declared on a package that is not "
                           "PKG_StoreCompressed")
            if self.header_size > self.filesize:
                bad.append("header %d exceeds file %d on a stored package"
                           % (self.header_size, self.filesize))
        # the chunks must tile the file
        if self.chunks:
            prev_u = None
            for (uo, us, co, cs) in self.chunks:
                if us <= 0 or cs <= 0:
                    bad.append("a chunk declares a non-positive size")
                if co < self.summary_end:
                    bad.append("a chunk starts at %d, inside the summary "
                               "which ends at %d" % (co, self.summary_end))
                if co + cs > self.filesize:
                    bad.append("a chunk runs to %d past the file end %d"
                               % (co + cs, self.filesize))
                if prev_u is not None and uo != prev_u:
                    bad.append("chunk gap: uncompressed %d follows %d"
                               % (uo, prev_u))
                prev_u = uo + us
            first = self.chunks[0]
            if first[2] != self.summary_end:
                bad.append("the first chunk starts at %d, not at the end of "
                           "the summary %d" % (first[2], self.summary_end))
            last = self.chunks[-1]
            if last[2] + last[3] != self.filesize:
                bad.append("the last chunk ends at %d, not at the file end %d"
                           % (last[2] + last[3], self.filesize))
        return bad


class Package(object):
    def __init__(self, path):
        self.path = path
        self.filesize = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(min(self.filesize, 1 << 16))
        self.summary = Summary(head, self.filesize, path)
        self._logical = None

    def logical(self, need=None):
        """The uncompressed byte stream the offsets in the summary refer to.

        `need` is a byte count: chunks that lie entirely beyond it are not
        decompressed. The three tables all live below `header_size`, and on
        the big maps that is a per-cent of the package -- decompressing all
        698 megabytes of `KF-W5_Climax.kf` to read its name table would be
        thirty minutes for nothing.
        """
        if self._logical is not None and (need is None
                                          or len(self._logical) >= need):
            return self._logical
        s = self.summary
        with open(self.path, "rb") as fh:
            raw = fh.read()
        if not s.chunks:
            self._logical = raw
            return raw
        end = max(uo + us for (uo, us, _co, _cs) in s.chunks)
        buf = bytearray(end)
        # everything before the first chunk's uncompressed offset is the
        # summary, stored in the clear at the head of the file
        head_len = s.chunks[0][0]
        buf[:head_len] = raw[:head_len]
        for (uo, us, co, cs) in s.chunks:
            if need is not None and uo >= need:
                break
            blob = raw[co:co + cs]
            tag, block, tot_c, tot_u = struct.unpack_from("<4I", blob, 0)
            if tag != TAG:
                raise NotAPackage("chunk at %d has no FCompressedChunkHeader"
                                  % co)
            nb = (tot_u + block - 1) // block
            o = 16
            sizes = []
            for _ in range(nb):
                sizes.append(struct.unpack_from("<2I", blob, o))
                o += 8
            if sum(c for c, _ in sizes) != tot_c:
                raise NotAPackage("block compressed sizes sum to %d, header "
                                  "says %d" % (sum(c for c, _ in sizes), tot_c))
            if sum(u for _, u in sizes) != tot_u:
                raise NotAPackage("block uncompressed sizes sum to %d, header "
                                  "says %d" % (sum(u for _, u in sizes), tot_u))
            if o + tot_c != cs:
                raise NotAPackage("chunk of %d bytes holds a %d-byte header "
                                  "and %d of data" % (cs, o, tot_c))
            pos = uo
            for (c, u) in sizes:
                part = blob[o:o + c]
                o += c
                if s.compression_flags == COMPRESS_LZO:
                    dec = decompress(part, expected=u)
                elif s.compression_flags == COMPRESS_ZLIB:
                    import zlib
                    dec = zlib.decompress(part)
                    if len(dec) != u:
                        raise NotAPackage("zlib block gave %d, wanted %d"
                                          % (len(dec), u))
                else:
                    raise NotAPackage("codec %d is not implemented"
                                      % s.compression_flags)
                buf[pos:pos + u] = dec
                pos += u
        self._logical = bytes(buf)
        return self._logical

    def header_need(self):
        """How much of the logical stream the three tables occupy."""
        s = self.summary
        return max(s.header_size, s.depends_offset, s.export_offset,
                   s.import_offset, s.name_offset) + 1

    # ---- the three tables ------------------------------------------------

    def names(self):
        s = self.summary
        d = self.logical(need=self.header_need())
        o = s.name_offset
        out = []
        for i in range(s.name_count):
            txt, o = fstring(d, o)
            o += 8                      # QWORD name flags
            out.append(txt)
        self.name_residue = s.import_offset - o
        return out

    def imports(self, names):
        s = self.summary
        d = self.logical(need=self.header_need())
        o = s.import_offset
        out = []
        for _ in range(s.import_count):
            (cp_i, cp_n, cn_i, cn_n, outer, on_i,
             on_n) = struct.unpack_from("<7i", d, o)
            o += IMPORT_RECORD
            out.append({
                "class_package": _fname(names, cp_i, cp_n),
                "class": _fname(names, cn_i, cn_n),
                "outer": outer,
                "name": _fname(names, on_i, on_n),
            })
        self.import_residue = s.export_offset - o
        return out

    def exports(self, names):
        s = self.summary
        d = self.logical(need=self.header_need())
        o = s.export_offset
        out = []
        for _ in range(s.export_count):
            (cls, sup, outer, n_i, n_n, arch) = struct.unpack_from("<6i", d, o)
            o += 24
            (obj_flags,) = struct.unpack_from("<Q", d, o)
            o += 8
            (ser_size, ser_off, exp_flags) = struct.unpack_from("<2iI", d, o)
            o += 12
            (n_net,) = struct.unpack_from("<i", d, o)
            o += 4
            if not 0 <= n_net <= 1 << 20:
                raise NotAPackage("net object count %d is not credible" % n_net)
            o += 4 * n_net
            o += 16                     # package guid
            o += 4                      # package flags
            out.append({
                "class": cls, "super": sup, "outer": outer,
                "name": _fname(names, n_i, n_n), "archetype": arch,
                "flags": obj_flags, "size": ser_size, "offset": ser_off,
                "export_flags": exp_flags, "net": n_net,
            })
        self.export_residue = s.depends_offset - o
        return out


def _fname(names, idx, number):
    if 0 <= idx < len(names):
        base = names[idx]
    else:
        base = "<name %d>" % idx
    return base if number == 0 else "%s_%d" % (base, number - 1)


def resolve(idx, exports, imports):
    """UE3 object index: >0 export, <0 import, 0 nothing."""
    if idx > 0:
        return exports[idx - 1]["name"] if idx - 1 < len(exports) else "?"
    if idx < 0:
        return imports[-idx - 1]["name"] if -idx - 1 < len(imports) else "?"
    return None


# ------------------------------------------------------------------ walking

def walk(root=ROOT):
    for r, _dirs, fs in os.walk(root):
        for f in sorted(fs):
            yield os.path.join(r, f)


def tagged(root=ROOT):
    """Every file whose first four bytes are the package tag."""
    for p in walk(root):
        try:
            with open(p, "rb") as fh:
                head = fh.read(4)
        except OSError:
            continue
        if len(head) == 4 and struct.unpack_from("<I", head, 0)[0] == TAG:
            yield p


def rel(p):
    return os.path.relpath(p, ROOT).replace("\\", "/")


# ----------------------------------------------------------------- commands

def cmd_validate(args):
    ok, refused, complaints = [], [], []
    for p in tagged(args.root):
        try:
            pkg = Package(p)
        except (NotAPackage, struct.error) as e:
            refused.append((rel(p), str(e)))
            continue
        bad = pkg.summary.validate()
        if bad:
            complaints.append((rel(p), bad))
        ok.append(pkg)
    print("files carrying the package tag : %d" % (len(ok) + len(refused)))
    print("   parsed as a package         : %d" % len(ok))
    print("   REFUSED                     : %d" % len(refused))
    for r, why in refused:
        print("      %-44s %s" % (r, why))
    print()
    print("packages whose own arithmetic does not close : %d of %d"
          % (len(complaints), len(ok)))
    for r, bad in complaints:
        print("   %s" % r)
        for b in bad:
            print("      %s" % b)
    if not complaints:
        print("   every parsed package passes every check in Summary.validate")
    return 0


def cmd_census(args):
    rows = []
    for p in tagged(args.root):
        try:
            pkg = Package(p)
        except (NotAPackage, struct.error):
            continue
        rows.append(pkg)
    print("packages : %d" % len(rows))
    vers = collections.Counter((r.summary.version, r.summary.licensee)
                               for r in rows)
    print("versions (file, licensee) : %s" % dict(vers))
    print("folder name field         : %s"
          % dict(collections.Counter(r.summary.folder for r in rows)))
    print("engine version            : %s"
          % dict(collections.Counter(r.summary.engine_version for r in rows)))
    print("cooker version            : %s"
          % dict(collections.Counter(r.summary.cooker_version for r in rows)))
    print("by extension              : %s"
          % dict(collections.Counter(os.path.splitext(r.path)[1].lower()
                                     for r in rows)))
    print()
    print("names   %d" % sum(r.summary.name_count for r in rows))
    print("exports %d" % sum(r.summary.export_count for r in rows))
    print("imports %d" % sum(r.summary.import_count for r in rows))
    print()
    comp = [r for r in rows if r.summary.compressed]
    plain = [r for r in rows if not r.summary.compressed]
    print("PKG_StoreCompressed set : %d   clear : %d" % (len(comp), len(plain)))
    print("codec on the compressed : %s"
          % dict(collections.Counter(CODEC.get(r.summary.compression_flags,
                                               "0x%X"
                                               % r.summary.compression_flags)
                                     for r in comp)))
    print("codec on the others     : %s"
          % dict(collections.Counter(CODEC.get(r.summary.compression_flags,
                                               "?") for r in plain)))
    print("header > file           : %d of %d compressed, %d of %d plain"
          % (sum(1 for r in comp if r.summary.header_size > r.filesize),
             len(comp),
             sum(1 for r in plain if r.summary.header_size > r.filesize),
             len(plain)))
    print()
    print("additional packages to cook, non-empty : %d"
          % sum(1 for r in rows if r.summary.additional))
    print("texture allocations, non-zero          : %d"
          % sum(1 for r in rows if r.summary.texture_allocations))
    return 0


def cmd_chunks(args):
    tot_c = tot_u = 0
    nch = 0
    per = []
    tiles = 0
    files = 0
    for p in tagged(args.root):
        try:
            pkg = Package(p)
        except (NotAPackage, struct.error):
            continue
        s = pkg.summary
        if not s.chunks:
            continue
        files += 1
        c = sum(x[3] for x in s.chunks)
        u = sum(x[1] for x in s.chunks)
        tot_c += c
        tot_u += u
        nch += len(s.chunks)
        if not s.validate():
            tiles += 1
        per.append((rel(p), pkg.filesize, len(s.chunks), c, u,
                    s.compression_flags))
    print("compressed packages       : %d" % files)
    print("chunks in total           : %d" % nch)
    print("codec, distinct values    : %s"
          % dict(collections.Counter(x[5] for x in per)))
    print("chunk payload, compressed : %d" % tot_c)
    print("chunk payload, declared uncompressed : %d" % tot_u)
    print("ratio uncompressed / compressed      : %.4f" % (tot_u / float(tot_c)))
    print("packages whose chunk extents tile the file with no gap : %d of %d"
          % (tiles, files))
    print()
    print("%-52s %12s %5s %12s %12s %7s"
          % ("file", "on disk", "chks", "compressed", "uncompressed", "ratio"))
    for r in sorted(per, key=lambda x: -x[1])[:args.limit]:
        print("%-52s %12d %5d %12d %12d %7.4f"
              % (r[0][-52:], r[1], r[2], r[3], r[4], r[4] / float(r[3])))
    return 0


def cmd_names(args):
    pkg = Package(os.path.join(args.root, args.file))
    names = pkg.names()
    print("%s" % args.file)
    print("names declared : %d   read : %d   residue to the import table : %d"
          % (pkg.summary.name_count, len(names), pkg.name_residue))
    for i, nm in enumerate(names[:args.limit]):
        print("  %5d  %s" % (i, nm))
    return 0


def cmd_tables(args):
    pkg = Package(os.path.join(args.root, args.file))
    names = pkg.names()
    imps = pkg.imports(names)
    exps = pkg.exports(names)
    s = pkg.summary
    print("%s   %d bytes on disk" % (args.file, pkg.filesize))
    print("  logical stream : %d bytes   declared header : %d"
          % (len(pkg.logical()), s.header_size))
    print("  names   declared %6d  read %6d  residue %d"
          % (s.name_count, len(names), pkg.name_residue))
    print("  imports declared %6d  read %6d  residue %d"
          % (s.import_count, len(imps), pkg.import_residue))
    print("  exports declared %6d  read %6d  residue %d"
          % (s.export_count, len(exps), pkg.export_residue))
    print()
    print("  import outer packages : %s"
          % dict(collections.Counter(i["class_package"] for i in imps)))
    print("  import classes        : %s"
          % dict(collections.Counter(i["class"] for i in imps).most_common(8)))
    print()
    cls = collections.Counter(resolve(e["class"], exps, imps) or "Class"
                              for e in exps)
    print("  export classes, top 12:")
    for k, v in cls.most_common(12):
        print("    %-40s %6d" % (k, v))
    print()
    print("  first %d exports:" % min(args.limit, len(exps)))
    for e in exps[:args.limit]:
        print("    %-44s %-28s size %9d offset %9d"
              % (e["name"][:44], (resolve(e["class"], exps, imps) or "Class"),
                 e["size"], e["offset"]))
    return 0


def cmd_closure(args):
    """Read all three tables of every package and publish the residues.

    Rule 1 of this pipeline: a container is not opened until its own
    arithmetic closes. Here that is three numbers per package, and they are
    reported per package rather than in aggregate so that one failure cannot
    hide inside a hundred and twelve successes.
    """
    n = 0
    clean = 0
    tot_names = tot_imps = tot_exps = 0
    tot_logical = 0
    worst = []
    failures = []
    dirty_names = 0
    for p in tagged(args.root):
        try:
            pkg = Package(p)
        except (NotAPackage, struct.error):
            continue
        n += 1
        try:
            names = pkg.names()
            imps = pkg.imports(names)
            exps = pkg.exports(names)
        except (NotAPackage, LzoError, struct.error) as e:
            failures.append((rel(p), str(e)))
            continue
        r = (pkg.name_residue, pkg.import_residue, pkg.export_residue)
        tot_names += len(names)
        tot_imps += len(imps)
        tot_exps += len(exps)
        tot_logical += len(pkg.logical(need=pkg.header_need()))
        if r == (0, 0, 0):
            clean += 1
        else:
            worst.append((rel(p), r))
        # a name that is not printable ASCII is a name table that was read
        # wrongly, or a name field that was not cleared
        for nm in names:
            if any(ord(c) < 32 or ord(c) > 126 for c in nm):
                dirty_names += 1
    print("packages whose three tables were read : %d of %d" % (n - len(failures), n))
    print("names read   : %d" % tot_names)
    print("imports read : %d" % tot_imps)
    print("exports read : %d" % tot_exps)
    print()
    print("residue 0 on all three tables : %d of %d" % (clean, n))
    for r, v in worst:
        print("   %-52s names %+d imports %+d exports %+d" % ((r,) + v))
    for r, e in failures:
        print("   FAILED %-46s %s" % (r, e))
    print()
    print("names holding a byte outside printable ASCII : %d of %d"
          % (dirty_names, tot_names))
    return 0

def cmd_classcensus(args):
    total = collections.Counter()
    per_pkg = []
    read = 0
    exports_read = 0
    for p in tagged(args.root):
        try:
            pkg = Package(p)
        except (NotAPackage, struct.error):
            continue
        if args.only and args.only not in rel(p):
            continue
        try:
            names = pkg.names()
            imps = pkg.imports(names)
            exps = pkg.exports(names)
        except (NotAPackage, LzoError, struct.error) as e:
            print("  %-50s FAILED %s" % (rel(p), e))
            continue
        c = collections.Counter(resolve(e["class"], exps, imps) or "Class"
                                for e in exps)
        total += c
        read += 1
        exports_read += len(exps)
        per_pkg.append((rel(p), len(exps)))
        if args.limit and read >= args.limit:
            break
    print("packages read        : %d" % read)
    print("exports read         : %d" % exports_read)
    print("distinct classes     : %d" % len(total))
    print()
    print("the twenty commonest export classes:")
    for k, v in total.most_common(20):
        print("  %-44s %8d  %6.3f %%"
              % (k, v, 100.0 * v / max(exports_read, 1)))
    return 0


# ---------------------------------------------------------------- selftest

def _summary_bytes(**kw):
    """Build a minimal, valid-shaped summary in memory."""
    f = dict(version=868, licensee=0, header_size=1000, folder="None",
             flags=0, name_count=0, name_offset=0, export_count=0,
             export_offset=0, import_count=0, import_offset=0,
             depends_offset=0, chunks=(), compression_flags=0, tag=TAG)
    f.update(kw)
    d = bytearray()
    d += struct.pack("<I", f["tag"])
    d += struct.pack("<HH", f["version"], f["licensee"])
    d += struct.pack("<i", f["header_size"])
    fn = f["folder"].encode("latin-1") + b"\0"
    d += struct.pack("<i", len(fn)) + fn
    d += struct.pack("<I7i", f["flags"], f["name_count"], f["name_offset"],
                     f["export_count"], f["export_offset"], f["import_count"],
                     f["import_offset"], f["depends_offset"])
    d += struct.pack("<3i", f["header_size"], 0, 0)
    d += struct.pack("<i", 0)
    d += b"\0" * 16
    d += struct.pack("<i", 1) + struct.pack("<3i", 0, 0, 0)
    d += struct.pack("<iiI", 12621, 136, f["compression_flags"])
    d += struct.pack("<i", len(f["chunks"]))
    for c in f["chunks"]:
        d += struct.pack("<4i", *c)
    d += struct.pack("<I", 0)
    d += struct.pack("<i", 0)
    d += struct.pack("<i", 0)
    return bytes(d)


def selftest():
    cases = []

    good = _summary_bytes(name_count=0, name_offset=200, import_offset=200,
                          export_offset=200, depends_offset=200)
    cases.append(("a minimal well-formed summary", good, len(good) + 900,
                  True, []))

    cases.append(("the wrong tag", _summary_bytes(tag=0x12345678), 1000,
                  False, []))

    cases.append(("a folder-name length of 8192, which is what a .tfc gives",
                  struct.pack("<I", TAG) + struct.pack("<HH", 0, 2)
                  + struct.pack("<i", 1087) + struct.pack("<i", 8192)
                  + b"\0" * 64, 85699418, False, []))

    v = _summary_bytes(version=700, name_offset=200, import_offset=200,
                       export_offset=200, depends_offset=200)
    cases.append(("file version 700 instead of 868", v, len(v) + 900,
                  True, ["file version 700, not 868"]))

    v = _summary_bytes(import_count=3, name_offset=100, import_offset=100,
                       export_offset=100 + 3 * 27, depends_offset=200)
    cases.append(("an import table that 28 bytes does not divide", v,
                  len(v) + 900, True, ["import table spans"]))

    v = _summary_bytes(name_offset=500, import_offset=400, export_offset=600,
                       depends_offset=700)
    cases.append(("table offsets out of order", v, len(v) + 900, True,
                  ["ascending order"]))

    v = _summary_bytes(flags=PKG_STORE_COMPRESSED, compression_flags=2,
                       name_offset=100, import_offset=100, export_offset=100,
                       depends_offset=100)
    cases.append(("PKG_StoreCompressed with no chunk table", v, len(v) + 900,
                  True, ["no chunks"]))

    v = _summary_bytes(header_size=99999, name_offset=100, import_offset=100,
                       export_offset=100, depends_offset=100)
    cases.append(("a stored package declaring a header bigger than itself", v,
                  len(v) + 900, True, ["exceeds file"]))

    hs = 4096
    v = _summary_bytes(flags=PKG_STORE_COMPRESSED, compression_flags=2,
                       header_size=hs, name_offset=100, import_offset=100,
                       export_offset=100, depends_offset=100,
                       chunks=((100, 1000, 0, 500),))
    # Two complaints, not one: a chunk at offset 0 is both inside the summary
    # and not at the summary's end. The first run of this selftest expected
    # one and failed, which is the expectation being wrong and not the reader
    # -- recorded in docs/16 rather than quietly relaxed.
    cases.append(("a chunk that starts inside the summary", v, 500,
                  True, ["inside the summary", "not at the end of the "]))

    ok = 0
    accepted = refused = 0
    print("kfpkg selftest: %d specimens built in memory" % len(cases))
    for name, blob, size, should_parse, want in cases:
        try:
            s = Summary(blob, size)
            got = s.validate()
            parsed = True
            accepted += 1
        except (NotAPackage, struct.error) as e:
            parsed = False
            got = [str(e)]
            refused += 1
        if not should_parse:
            passed = not parsed
            note = "refused at parse: %s" % got[0][:60]
        else:
            passed = parsed and len(got) == len(want) and all(
                any(w in g for g in got) for w in want)
            note = ("clean" if not got
                    else "complained: " + "; ".join(g[:52] for g in got))
        print("  %-58s %-5s %s" % (name, "PASS" if passed else "FAIL", note))
        ok += 1 if passed else 0
    print()
    print("parsed %d, refused at parse %d, of %d" % (accepted, refused,
                                                     len(cases)))
    print("%d of %d specimens behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--file")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--only")
    for c in ("selftest", "validate", "census", "chunks", "names", "tables",
              "classcensus", "closure"):
        ap.add_argument("--" + c, action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.validate:
        return cmd_validate(a)
    if a.census:
        return cmd_census(a)
    if a.chunks:
        return cmd_chunks(a)
    if a.names:
        return cmd_names(a)
    if a.tables:
        return cmd_tables(a)
    if a.classcensus:
        return cmd_classcensus(a)
    if a.closure:
        return cmd_closure(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
