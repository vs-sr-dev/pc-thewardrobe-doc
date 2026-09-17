"""vt7a.py -- read the VT7A containers of Broken Sword 5 (the .vt7a files).

Four ASCII letters and a digit are not a format specification.  Everything the
tool claims is derived from the bytes of the seven archives in this object, and
every claim is stated so that it can fail:

    header   char[4] 'VT7A', u32 version, u32 magic2, u32 count
    record   u32 key, u32 offset, u32 size_raw, u32 size_stored
             size_stored == 0  means the member is stored, not compressed,
             and its extent on disk is size_raw.

The falsifiable form of that reading is one number: for every archive,
max(offset + extent) must fall INSIDE the file.  The pre-briefing's reading
(extent == size_raw always) overshoots graphics_common.vt7a by 201,604 bytes;
this one must not overshoot anything.

    validate  <root>            derive the record, prove it, and run a control
    census    <root>            magic census of every member, nothing extracted
    keys      <root>            the key sets, and how the archives overlap
    pairs     <root>            the two graphics archives, side by side
    members   <root> --out F    dump the member table as TSV (offsets, no data)

Nothing is ever extracted to disk.

    python tools/vt7a.py validate "<root>"
"""
import os
import sys
import struct
import collections
import hashlib

MAGIC = b"VT7A"
HDR = 16
REC = 16

VT7A = ["general.vt7a", "graphics_common.vt7a", "graphics_720.vt7a",
        "graphics_1080.vt7a", "movie.vt7a", "music.vt7a", "sfx.vt7a"]


def read_table(path):
    n = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(HDR)
        if head[:4] != MAGIC:
            raise ValueError("%s: magic is %r, not %r" % (path, head[:4], MAGIC))
        version, magic2, count = struct.unpack_from("<III", head, 4)
        if HDR + REC * count > n:
            raise ValueError("%s: table of %d records does not fit in %d bytes"
                             % (path, count, n))
        raw = fh.read(REC * count)
    recs = [struct.unpack_from("<IIII", raw, i * REC) for i in range(count)]
    return n, version, magic2, count, recs


def extent(rec):
    """Bytes the member actually occupies on disk."""
    return rec[3] if rec[3] else rec[2]


# ---------------------------------------------------------------- signatures

def signature(buf):
    if buf[:4] == b"OggS":
        # the codec identification page is not always the first: a stream that
        # carries an Ogg Skeleton puts 'fishead' first and the real codecs
        # after it, which is why 120 bytes is not enough to name a film.
        has = [name for sig, name in ((b"\x80theora", "Theora"),
                                      (b"\x01vorbis", "Vorbis"),
                                      (b"OpusHead", "Opus"))
               if sig in buf]
        if has:
            return "Ogg/" + "+".join(has)
        return "Ogg/other"
    if buf[:4] == b"RIFF" and buf[8:12] == b"WEBP":
        return "WebP"
    if buf[:4] == b"RIFF" and buf[8:12] == b"WAVE":
        return "WAV"
    if buf[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if buf[:2] == b"\xff\xd8":
        return "JPEG"
    if buf[:2] == b"BM":
        return "BMP"
    if buf[:4] == b"DDS ":
        return "DDS"
    if buf[:4] == b"STRM":
        return "STRM"
    if buf[:3] == b"sdw" and buf[3:4] == bytes([0]):
        return "sdw"
    if buf[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        return "zlib"
    if buf[:2] == b"\x1f\x8b":
        return "gzip"
    if buf[:4] == b"\x04\x22\x4d\x18":
        return "lz4"
    if buf[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if buf[:3] == b"<?x" or buf[:1] == b"<":
        return "XML-ish"
    if buf[:4] == b"\x00\x00\x00\x00":
        return "zero-start"
    printable = sum(1 for b in buf[:32] if 32 <= b < 127 or b in (9, 10, 13))
    if printable == 32:
        return "text-ish"
    return "unknown %02X%02X%02X%02X" % tuple(buf[:4])


# ------------------------------------------------------------------ validate

def validate(root):
    print("VT7A, derived from the bytes of seven archives.")
    print()
    print("  header  char[4] 'VT7A', u32 version, u32 magic2, u32 count   (16 bytes)")
    print("  record  u32 key, u32 offset, u32 size_raw, u32 size_stored   (16 bytes)")
    print("  extent  = size_stored if size_stored else size_raw")
    print()
    print("The falsifiable claims:")
    print("  V1  the four header words are the same shape on all seven")
    print("  V2  offset is a multiple of 4096")
    print("  V3  key is strictly increasing (the table is sorted by key)")
    print("  V4  max(offset + extent) <= file size          <-- the one that must not overshoot")
    print("  V5  offsets do not overlap, in table order")
    print("  V6  a member with size_stored != 0 starts with a zlib header")
    print("  V7  a member with size_stored == 0 starts with a recognisable")
    print("      container magic, not with a compressor header")
    print()
    hdr = ("%-22s %8s %6s %11s %13s %13s %9s"
           % ("file", "count", "ver", "hdr end", "max off+ext", "file size", "delta"))
    print(hdr)
    print("-" * len(hdr))
    ok = collections.Counter()
    magic2s = set()
    versions = set()
    total = 0
    for name in VT7A:
        p = os.path.join(root, name)
        n, ver, m2, count, recs = read_table(p)
        total += count
        versions.add(ver)
        magic2s.add(m2)
        mx = max(r[1] + extent(r) for r in recs)
        v2 = all(r[1] % 4096 == 0 for r in recs)
        v3 = all(recs[i][0] < recs[i + 1][0] for i in range(count - 1))
        v4 = (mx <= n)
        srt = sorted(recs, key=lambda r: r[1])
        v5 = all(srt[i][1] + extent(srt[i]) <= srt[i + 1][1]
                 for i in range(count - 1))
        ok["V2"] += v2; ok["V3"] += v3; ok["V4"] += v4; ok["V5"] += v5
        print("%-22s %8d %6d %11d %13d %13d %9d"
              % (name, count, ver, HDR + REC * count, mx, n, n - mx))
        if not (v2 and v3 and v4 and v5):
            print("      V2 %s  V3 %s  V4 %s  V5 %s" % (v2, v3, v4, v5))
    print("-" * len(hdr))
    print("records, all seven archives : %d" % total)
    print("distinct version words      : %s" % sorted(versions))
    print("distinct magic2 words       : %s"
          % ["0x%08X" % m for m in sorted(magic2s)])
    ok["V1"] = 7 if (len(versions) == 1 and len(magic2s) == 1) else 0
    for k in ("V1", "V2", "V3", "V4", "V5"):
        print("%s holds on %d archives of 7" % (k, ok[k]))
    print()
    print("THE CONTROL THAT MUST FAIL: the same table read the naive way,")
    print("with extent == size_raw always.")
    over = 0
    for name in VT7A:
        p = os.path.join(root, name)
        n, ver, m2, count, recs = read_table(p)
        mx = max(r[1] + r[2] for r in recs)
        flag = "OVERSHOOTS by %d" % (mx - n) if mx > n else "inside by %d" % (n - mx)
        if mx > n:
            over += 1
        print("   %-22s %s" % (name, flag))
    print("   the naive reading overshoots %d archive(s) of 7" % over)
    if over == 0:
        print("   *** the control did not fail; this derivation proves nothing ***")
    print()
    print("V6 / V7 -- what actually sits at the declared offset")
    print()
    print("%-22s %8s %8s   %s" % ("file", "stored", "compressed", "first bytes say"))
    v6 = v7 = 0
    for name in VT7A:
        p = os.path.join(root, name)
        n, ver, m2, count, recs = read_table(p)
        sigs_stored = collections.Counter()
        sigs_comp = collections.Counter()
        with open(p, "rb") as fh:
            for r in recs:
                fh.seek(r[1])
                s = signature(fh.read(4096))
                if r[3]:
                    sigs_comp[s] += 1
                else:
                    sigs_stored[s] += 1
        nc = sum(sigs_comp.values())
        ns = sum(sigs_stored.values())
        v6 += (nc == 0 or sigs_comp.get("zlib", 0) == nc)
        v7 += (ns == 0 or sigs_stored.get("zlib", 0) == 0)
        print("%-22s %8d %8d" % (name, ns, nc))
        if ns:
            print("      stored     : %s"
                  % ", ".join("%s %d" % kv for kv in sigs_stored.most_common(6)))
        if nc:
            print("      compressed : %s"
                  % ", ".join("%s %d" % kv for kv in sigs_comp.most_common(6)))
    print()
    print("V6 holds on %d archives of 7 (every compressed member is zlib)" % v6)
    print("V7 holds on %d archives of 7 (no stored member looks like zlib)" % v7)
    return 0


# -------------------------------------------------------------------- census

def census(root):
    print("VT7A member census.  Nothing is extracted: 128 bytes are read at")
    print("each declared offset to name the member, and no more.")
    print()
    grand = collections.Counter()
    grand_b = collections.Counter()
    tot_ext = tot_raw = tot_rec = 0
    per = {}
    for name in VT7A:
        p = os.path.join(root, name)
        n, ver, m2, count, recs = read_table(p)
        sigs = collections.Counter()
        sigb = collections.Counter()
        ext = raw = 0
        with open(p, "rb") as fh:
            for r in recs:
                fh.seek(r[1])
                s = signature(fh.read(4096))
                sigs[s] += 1
                sigb[s] += extent(r)
                ext += extent(r)
                raw += r[2]
        per[name] = (n, count, ext, raw, sigs, sigb)
        grand.update(sigs)
        grand_b.update(sigb)
        tot_ext += ext
        tot_raw += raw
        tot_rec += count
        print("== %s  %d bytes, %d members" % (name, n, count))
        print("   on disk (sum of extents) : %13d   %8.4f %% of the file"
              % (ext, 100.0 * ext / n))
        print("   uncompressed (sum raw)   : %13d   x %.4f"
              % (raw, raw / float(ext) if ext else 0))
        print("   table + padding          : %13d   %8.4f %%"
              % (n - ext, 100.0 * (n - ext) / n))
        for s, c in sigs.most_common():
            print("      %-16s %7d members %14d bytes  %7.3f %%"
                  % (s, c, sigb[s], 100.0 * sigb[s] / n))
        print()
    print("=" * 72)
    print("all seven archives: %d members, %d bytes on disk, %d uncompressed"
          % (tot_rec, tot_ext, tot_raw))
    print("overall expansion factor: x %.4f" % (tot_raw / float(tot_ext)))
    print()
    print("%-18s %9s %16s %9s" % ("signature", "members", "bytes on disk", "share"))
    for s, c in grand.most_common():
        print("%-18s %9d %16d %8.4f %%"
              % (s, c, grand_b[s], 100.0 * grand_b[s] / tot_ext))
    return 0


# ---------------------------------------------------------------------- keys

def keys(root):
    sets = {}
    for name in VT7A:
        p = os.path.join(root, name)
        n, ver, m2, count, recs = read_table(p)
        ks = set(r[0] for r in recs)
        sets[name] = ks
        print("%-22s %6d records, %6d distinct keys%s"
              % (name, count, len(ks), "" if len(ks) == count else "   <-- COLLISION"))
    print()
    print("pairwise intersections of the key sets:")
    names = VT7A
    print("%-22s %s" % ("", " ".join("%8s" % n[:8] for n in names)))
    for a in names:
        row = []
        for b in names:
            row.append("%8d" % (len(sets[a] & sets[b]) if a != b else len(sets[a])))
        print("%-22s %s" % (a, " ".join(row)))
    allk = set()
    dup = 0
    for name in names:
        dup += len(allk & sets[name])
        allk |= sets[name]
    print()
    print("keys, union over the seven archives : %d" % len(allk))
    print("keys appearing in more than one     : %d" % dup)
    print()
    print("key range and density:")
    for name in names:
        ks = sorted(sets[name])
        print("   %-22s min %12d  max %12d  span %12d  density 1 in %.1f"
              % (name, ks[0], ks[-1], ks[-1] - ks[0],
                 (ks[-1] - ks[0]) / float(len(ks))))
    return 0


# --------------------------------------------------------------------- pairs

def pairs(root):
    a_name, b_name = "graphics_720.vt7a", "graphics_1080.vt7a"
    out = {}
    for name in (a_name, b_name):
        p = os.path.join(root, name)
        n, ver, m2, count, recs = read_table(p)
        sigs = collections.Counter()
        with open(p, "rb") as fh:
            for r in recs:
                fh.seek(r[1])
                sigs[signature(fh.read(4096))] += 1
        out[name] = (n, count, recs, sigs)
    print("the two graphics archives, side by side")
    print()
    print("%-30s %16s %16s" % ("", a_name, b_name))
    print("%-30s %16d %16d" % ("bytes", out[a_name][0], out[b_name][0]))
    print("%-30s %16d %16d" % ("members", out[a_name][1], out[b_name][1]))
    for k in ("keys shared", ):
        pass
    ka = set(r[0] for r in out[a_name][2])
    kb = set(r[0] for r in out[b_name][2])
    print("%-30s %16d %16d" % ("distinct keys", len(ka), len(kb)))
    print("%-30s %33d" % ("keys in both", len(ka & kb)))
    sa = sorted(extent(r) for r in out[a_name][2])
    sb = sorted(extent(r) for r in out[b_name][2])
    print("%-30s %16d %16d" % ("smallest member", sa[0], sb[0]))
    print("%-30s %16d %16d" % ("largest member", sa[-1], sb[-1]))
    print("%-30s %16d %16d" % ("median member", sa[len(sa) // 2], sb[len(sb) // 2]))
    print("%-30s %16d %16d" % ("sum of extents", sum(sa), sum(sb)))
    print("%-30s %16.4f %16.4f"
          % ("mean member", sum(sa) / float(len(sa)), sum(sb) / float(len(sb))))
    print()
    print("signatures:")
    allsig = set(out[a_name][3]) | set(out[b_name][3])
    for s in sorted(allsig, key=lambda x: -(out[a_name][3][x] + out[b_name][3][x])):
        print("   %-18s %8d %8d" % (s, out[a_name][3][s], out[b_name][3][s]))
    print()
    print("member bytes: sha1 of the on-disk extent, both archives")
    print("(hashed in a streaming pass; nothing is written out)")
    hashes = {}
    for name in (a_name, b_name):
        p = os.path.join(root, name)
        hs = set()
        with open(p, "rb") as fh:
            for r in sorted(out[name][2], key=lambda x: x[1]):
                fh.seek(r[1])
                h = hashlib.sha1()
                left = extent(r)
                while left:
                    chunk = fh.read(min(1 << 20, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                    h.update(chunk)
                hs.add(h.hexdigest())
        hashes[name] = hs
        print("   %-22s %6d members, %6d distinct sha1"
              % (name, out[name][1], len(hs)))
    sh = hashes[a_name] & hashes[b_name]
    print("   members with identical bytes in both archives : %d" % len(sh))
    return 0


# ------------------------------------------------------------------- members

def members(root, out_path):
    fh_out = open(out_path, "w")
    fh_out.write("archive\tkey\toffset\tsize_raw\tsize_stored\textent\tsig\tsha1\n")
    tot = 0
    for name in VT7A:
        p = os.path.join(root, name)
        n, ver, m2, count, recs = read_table(p)
        with open(p, "rb") as fh:
            for r in sorted(recs, key=lambda x: x[1]):
                fh.seek(r[1])
                head = fh.read(4096)
                sig = signature(head)
                fh.seek(r[1])
                h = hashlib.sha1()
                left = extent(r)
                while left:
                    chunk = fh.read(min(1 << 20, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                    h.update(chunk)
                fh_out.write("%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n"
                             % (name, r[0], r[1], r[2], r[3], extent(r),
                                sig, h.hexdigest()))
                tot += 1
    fh_out.close()
    print("wrote %s : %d members" % (out_path, tot))
    return 0


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd, root = sys.argv[1], sys.argv[2]
    if cmd == "validate":
        return validate(root)
    if cmd == "census":
        return census(root)
    if cmd == "keys":
        return keys(root)
    if cmd == "pairs":
        return pairs(root)
    if cmd == "members":
        return members(root, sys.argv[sys.argv.index("--out") + 1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
