#!/usr/bin/env python3
"""pak.py -- read Broken Sword 3's `data.pak`, derived from the bytes.

The layout is not documented anywhere and the obvious reading of it is wrong.
Taking the file as a table of 16-byte records starting at offset 0 gives a
column that is always zero, a column that increases, a column that does not,
and a table that stops making sense; that is what a naive read produces and it
is what this tool does NOT do.

What closes is one word of framing earlier:

    u32          member count
    count x 16   u32 zero, u32 key, u32 offset, u32 size
    u32          zero
    the members, back to back

The proof that the framing is right is not aesthetic.  Several members are
Windows bitmaps, and a bitmap declares its own length in its fifth to eighth
bytes; under this framing the declared length of the bitmap at `offset` equals
`size`, and under the naive framing it equals the size field of the NEXT
record.  Beyond that, under this framing the members tile the file: sorted by
offset there are zero overlaps, zero gaps, the first member starts immediately
after the table and the last one ends on the last byte of the file.

`key` is strictly increasing over all members, which makes it a sort key and
not an offset; the members are ordered by it so a name can be found by binary
search.  The tool reports it, tests it against the candidate name hashes it
knows, and says so when none of them fit.

Nothing is extracted.  `--census` reads sixteen bytes per member to classify
it; `--wav` reads the format chunk of each RIFF member.  No member is written
to disk, by design: this repository ships no decoded asset.

    python tools/pak.py FILE
    python tools/pak.py FILE --census
    python tools/pak.py FILE --wav
    python tools/pak.py FILE --names
    python tools/pak.py FILE --selftest OTHERFILE
"""
import argparse
import collections
import os
import struct
import sys
import zlib

RW_CHUNKS = {
    0x00000001: "struct", 0x00000002: "string", 0x00000003: "extension",
    0x00000006: "texture", 0x00000007: "material", 0x00000008: "material list",
    0x00000009: "atomic sector", 0x0000000A: "plane sector",
    0x0000000B: "world", 0x0000000E: "frame list", 0x0000000F: "geometry",
    0x00000010: "clump", 0x00000014: "light", 0x00000015: "unicode string",
    0x00000016: "atomic", 0x0000001A: "texture native",
    0x0000001B: "texture dictionary", 0x0000001C: "animation database",
    0x0000001F: "geometry list", 0x00000024: "hanim animation",
}


def load(path):
    n = os.path.getsize(path)
    fh = open(path, "rb")
    raw = fh.read(4)
    if len(raw) < 4:
        raise ValueError("shorter than four bytes")
    count = struct.unpack("<I", raw)[0]
    if count == 0 or 4 + count * 16 + 4 > n:
        raise ValueError("first word %d cannot be a member count in a %d-byte file"
                         % (count, n))
    tab = fh.read(count * 16)
    if len(tab) != count * 16:
        raise ValueError("table of %d records does not fit in the file" % count)
    recs = [struct.unpack_from("<IIII", tab, j * 16) for j in range(count)]
    bad = [j for j, (z, k, o, s) in enumerate(recs)
           if z != 0 or o < 4 + count * 16 or o + s > n]
    if bad:
        raise ValueError("%d of %d records are out of range (first: %d)"
                         % (len(bad), count, bad[0]))
    return fh, n, count, recs


def classify(head):
    if head[:4] == b"RIFF":
        return "RIFF/" + head[8:12].decode("latin-1", "replace")
    if head[:4] == b"\x89PNG":
        return "PNG"
    if head[:2] == b"BM":
        return "BMP"
    if len(head) >= 12:
        t, s, v = struct.unpack_from("<III", head, 0)
        if v == 0x1803FFFF:
            return "RenderWare 0x%08X %s" % (t, RW_CHUNKS.get(t, "(unnamed)"))
    return None


def hashes(name):
    """Candidate 32-bit hashes for a member name, so `key` can be tested."""
    b = name.encode("latin-1", "replace")
    out = {"crc32": zlib.crc32(b) & 0xFFFFFFFF,
           "crc32 lower": zlib.crc32(name.lower().encode("latin-1", "replace")) & 0xFFFFFFFF}
    h = 0
    for c in b:                                   # djb2
        h = (h * 33 + c) & 0xFFFFFFFF
    out["djb2"] = h
    h = 0
    for c in b:                                   # sdbm
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    out["sdbm"] = h
    h = 0
    for c in b:                                   # FNV-1a
        h = ((h ^ c) * 16777619) & 0xFFFFFFFF
    out["fnv1a"] = (h ^ 2166136261) & 0xFFFFFFFF
    h = 2166136261
    for c in b:
        h = ((h ^ c) * 16777619) & 0xFFFFFFFF
    out["fnv1a proper"] = h
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--wav", action="store_true")
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--selftest")
    a = ap.parse_args()

    if a.selftest:
        try:
            load(a.selftest)
        except ValueError as e:
            print("selftest OK: %s refused -- %s" % (os.path.basename(a.selftest), e))
            print()
        else:
            sys.exit("SELFTEST FAILED: %s read as a data.pak" % a.selftest)

    fh, n, count, recs = load(a.path)
    tableend = 4 + count * 16
    fh.seek(tableend)
    pad = fh.read(4)
    lo = min(r[2] for r in recs)
    hi = max(r[2] + r[3] for r in recs)
    tot = sum(r[3] for r in recs)
    byoff = sorted((r[2], r[3]) for r in recs)
    overlap = gap = 0
    end = None
    for off, s in byoff:
        if end is not None:
            if off < end:
                overlap += 1
            elif off > end:
                gap += off - end
        end = max(end or 0, off + s)
    keys = [r[1] for r in recs]
    print("file              : %s  %d bytes" % (os.path.basename(a.path), n))
    print("member count      : %d  (u32 at +0)" % count)
    print("table             : +4 .. +%d = %d bytes" % (tableend, count * 16))
    print("word after table  : %r" % pad)
    print("first member at   : %d   last member ends at %d   file is %d -> %s"
          % (lo, hi, n, "OK" if hi == n else "MISMATCH"))
    print("members tile      : overlaps %d, gaps %d bytes" % (overlap, gap))
    print("member bytes      : %d = %.4f %% of the file" % (tot, 100.0 * tot / n))
    print("framing overhead  : %d bytes = %.4f %%"
          % (n - tot, 100.0 * (n - tot) / n))
    print("field0 zero on    : %d of %d" % (sum(1 for r in recs if r[0] == 0), count))
    print("key strictly increasing : %s" % all(keys[i] > keys[i - 1] for i in range(1, count)))
    print("key range         : 0x%08X .. 0x%08X" % (min(keys), max(keys)))
    print("size range        : %d .. %d" % (min(r[3] for r in recs), max(r[3] for r in recs)))
    print()

    if a.census:
        sig = collections.Counter()
        siz = collections.Counter()
        for z, k, o, s in recs:
            fh.seek(o)
            c = classify(fh.read(16)) or "unrecognised"
            sig[c] += 1
            siz[c] += s
        print("members by signature (sixteen bytes read per member, nothing extracted):")
        print("   %-40s %8s %14s %8s" % ("signature", "members", "bytes", "share"))
        for k, v in sig.most_common():
            print("   %-40s %8d %14d %7.4f %%" % (k, v, siz[k], 100.0 * siz[k] / n))
        print("   %-40s %8d %14d %7.4f %%"
              % ("TOTAL", sum(sig.values()), sum(siz.values()), 100.0 * tot / n))
        print()

    if a.wav:
        fmt = collections.Counter()
        rate = collections.Counter()
        chan = collections.Counter()
        bits = collections.Counter()
        nwav = 0
        wbytes = 0
        secs = 0.0
        for z, k, o, s in recs:
            fh.seek(o)
            head = fh.read(64)
            if head[:4] != b"RIFF" or head[8:12] != b"WAVE":
                continue
            nwav += 1
            wbytes += s
            # walk the RIFF chunks for 'fmt ' and 'data'
            p = 12
            f = d = None
            while p + 8 <= len(head):
                cid = head[p:p + 4]
                cs = struct.unpack_from("<I", head, p + 4)[0]
                if cid == b"fmt ":
                    f = struct.unpack_from("<HHIIHH", head, p + 8)
                    break
                p += 8 + cs + (cs & 1)
            if f:
                tag, ch, sr, bps, align, bitdep = f
                fmt[tag] += 1
                rate[sr] += 1
                chan[ch] += 1
                bits[bitdep] += 1
                if bps:
                    secs += (s - 44) / float(bps)
        print("RIFF/WAVE members : %d, %d bytes = %.4f %% of the file"
              % (nwav, wbytes, 100.0 * wbytes / n))
        print("   format tag     : %s" % ", ".join("0x%04X x%d" % kv for kv in fmt.most_common()))
        print("   sample rate    : %s" % ", ".join("%d x%d" % kv for kv in rate.most_common()))
        print("   channels       : %s" % ", ".join("%d x%d" % kv for kv in chan.most_common()))
        print("   bits per sample: %s" % ", ".join("%d x%d" % kv for kv in bits.most_common()))
        print("   running time   : %.1f s = %d:%02d:%02d  (from the byte rate in each fmt chunk)"
              % (secs, secs // 3600, (secs % 3600) // 60, secs % 60))
        print()

    if a.names:
        # the members that are length-prefixed name tables
        found = 0
        for z, k, o, s in recs:
            fh.seek(o)
            blob = fh.read(min(s, 1 << 20))
            # a name table here is: u32 length, that many ASCII bytes, repeated,
            # but it does not begin at the member's first byte -- there is a
            # short header first, whose length is not assumed here but found.
            start = None
            names = []
            for p in range(0, min(len(blob), 4096)):
                probe = p
                run = []
                while probe + 4 <= len(blob) and len(run) < 4:
                    L = struct.unpack_from("<I", blob, probe)[0]
                    if not (3 <= L <= 64) or probe + 4 + L > len(blob):
                        break
                    w = blob[probe + 4:probe + 4 + L]
                    if not all(32 <= c < 127 for c in w):
                        break
                    run.append(w.decode("ascii"))
                    probe += 4 + L
                if len(run) >= 4:
                    start = p
                    names = run
                    break
            if start is not None:
                found += 1
                if found <= 3:
                    print("member at %d (%d bytes, key 0x%08X) reads as a name table "
                          "from +%d:" % (o, s, k, start))
                    # count them all
                    all_names = []
                    q = start
                    while q + 4 <= len(blob):
                        L = struct.unpack_from("<I", blob, q)[0]
                        if not (1 <= L <= 64) or q + 4 + L > len(blob):
                            break
                        w = blob[q + 4:q + 4 + L]
                        if not all(32 <= c < 127 for c in w):
                            break
                        all_names.append(w.decode("ascii"))
                        q += 4 + L
                    print("      %d names, %d bytes of %d consumed" % (len(all_names), q, s))
                    print("      first 8: %s" % ", ".join(all_names[:8]))
                    print("      last 4 : %s" % ", ".join(all_names[-4:]))
                    kset = set(keys)
                    for hname in ("crc32", "crc32 lower", "djb2", "sdbm",
                                  "fnv1a", "fnv1a proper"):
                        hit = sum(1 for nm in all_names[:500]
                                  if hashes(nm)[hname] in kset)
                        print("      %-14s of the first %d names lands on a key: %d"
                              % (hname, min(500, len(all_names)), hit))
        print("members that read as length-prefixed name tables: %d of %d"
              % (found, count))


if __name__ == "__main__":
    main()
