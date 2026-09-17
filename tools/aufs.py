"""aufs.py -- read the AUFS containers of Broken Sword 5 (the .osa files).

The format is derived from the bytes here, not from any published spec.  What
the tool asserts, it asserts with an EXTERNAL fact: at every offset the table
declares, there must be a recognisable container magic, and the member's
declared length must be reproducible from that container's own framing.

    validate                  derive and check the layout, loudly
    census   <root>           magic census of every member, nothing extracted
    ids      <root>           the id sets, and how the five languages overlap
    chain    <root> [--n N]   walk the Ogg page chain inside sampled members

Nothing is ever extracted to disk.

    python tools/aufs.py validate "<root>"
    python tools/aufs.py census   "<root>"
"""
import os
import sys
import struct
import collections

MAGIC = b"AUFS"
REC = 12          # id u32, offset u32, size u32
HDR = 8           # 'AUFS' + u32 count

OSA = ["english.osa", "english_part2.osa",
       "french.osa", "french_part2.osa",
       "german.osa", "german_part2.osa",
       "italian.osa", "italian_part2.osa",
       "spanish.osa", "spanish_part2.osa"]


def read_table(path):
    """Return (count, [(id, off, size), ...]) or raise."""
    n = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(HDR)
        if head[:4] != MAGIC:
            raise ValueError("%s: magic is %r, not %r" % (path, head[:4], MAGIC))
        count = struct.unpack_from("<I", head, 4)[0]
        if HDR + REC * count > n:
            raise ValueError("%s: table of %d records does not fit in %d bytes"
                             % (path, count, n))
        raw = fh.read(REC * count)
    recs = [struct.unpack_from("<III", raw, i * REC) for i in range(count)]
    return n, count, recs


# ---------------------------------------------------------------- validate

def validate(root):
    print("AUFS, derived: char[4] 'AUFS', u32 count, then count x 12 bytes")
    print("of (u32 id, u32 offset, u32 size).  Header is EIGHT bytes.")
    print()
    print("The falsifiable claims, in order:")
    print("  V1  offset[0] == 8 + 12*count        (the table ends where data starts)")
    print("  V2  offset[i] + size[i] == offset[i+1]  for every adjacent pair")
    print("  V3  offset[last] + size[last] == file size, delta 0")
    print("  V4  a recognisable container magic sits at every offset[i]")
    print()
    hdr = ("%-22s %12s %7s %11s %11s %7s %7s %7s"
           % ("file", "bytes", "count", "off[0]", "8+12n", "V2", "V3", "V4"))
    print(hdr)
    print("-" * len(hdr))
    okv1 = okv2 = okv3 = okv4 = 0
    total_recs = 0
    magics = collections.Counter()
    for name in OSA:
        p = os.path.join(root, name)
        n, count, recs = read_table(p)
        total_recs += count
        expect = HDR + REC * count
        v1 = (recs[0][1] == expect)
        v2 = all(recs[i][1] + recs[i][2] == recs[i + 1][1]
                 for i in range(count - 1))
        end = recs[-1][1] + recs[-1][2]
        v3 = (end == n)
        # V4: read four bytes at every declared offset, in one pass
        bad = 0
        with open(p, "rb") as fh:
            for _id, off, size in recs:
                fh.seek(off)
                m = fh.read(4)
                magics[m] += 1
                if m != b"OggS":
                    bad += 1
        v4 = (bad == 0)
        okv1 += v1; okv2 += v2; okv3 += v3; okv4 += v4
        print("%-22s %12d %7d %11d %11d %7s %7s %7s"
              % (name, n, count, recs[0][1], expect,
                 "yes" if v1 and v2 else "NO",
                 "%+d" % (n - end),
                 "yes" if v4 else "NO %d" % bad))
    print("-" * len(hdr))
    print("V1 holds on %d files of %d" % (okv1, len(OSA)))
    print("V2 holds on %d files of %d" % (okv2, len(OSA)))
    print("V3 holds on %d files of %d" % (okv3, len(OSA)))
    print("V4 holds on %d files of %d" % (okv4, len(OSA)))
    print("records, all files            : %d" % total_recs)
    print()
    print("magic at every declared offset:")
    for m, c in magics.most_common():
        print("   %-12r %8d" % (m, c))
    print()
    print("the control that MUST fail: read the same files with the")
    print("pre-briefing's sixteen-byte header and twelve-byte records.")
    fails = 0
    for name in OSA:
        p = os.path.join(root, name)
        n = os.path.getsize(p)
        with open(p, "rb") as fh:
            fh.seek(4)
            count = struct.unpack("<I", fh.read(4))[0]
            fh.seek(16)
            raw = fh.read(REC * count)
        recs = [struct.unpack_from("<III", raw, i * REC)
                for i in range(len(raw) // REC)]
        with open(p, "rb") as fh:
            fh.seek(recs[0][1] if recs[0][1] < n else 0)
            m = fh.read(4)
        if m != b"OggS":
            fails += 1
    print("   sixteen-byte header: magic at offset[0] is wrong on %d of %d"
          % (fails, len(OSA)))
    if fails != len(OSA):
        print("   *** the control did not fail; the derivation is not safe ***")
    return 0 if (okv1 == okv2 == okv3 == okv4 == len(OSA)) else 1


# ------------------------------------------------------------------ census

OGG_CODEC = [
    (b"\x01vorbis", "Vorbis"),
    (b"OpusHead", "Opus"),
    (b"\x80theora", "Theora"),
    (b"\x7fFLAC", "FLAC"),
    (b"Speex   ", "Speex"),
]


def codec_of(buf):
    for sig, name in OGG_CODEC:
        if sig in buf[:120]:
            return name
    return "unknown"


def census(root):
    print("AUFS member census.  Nothing is extracted: the tool reads the first")
    print("120 bytes of each member to name its codec, and the last 27 bytes of")
    print("the member's final Ogg page to read the granule position.")
    print()
    hdr = ("%-22s %7s %14s %10s %10s   %s"
           % ("file", "members", "bytes", "smallest", "largest", "codecs"))
    print(hdr)
    print("-" * len(hdr))
    grand = collections.Counter()
    grandbytes = 0
    grandrecs = 0
    per_file = {}
    for name in OSA:
        p = os.path.join(root, name)
        n, count, recs = read_table(p)
        codecs = collections.Counter()
        sizes = []
        with open(p, "rb") as fh:
            for _id, off, size in recs:
                fh.seek(off)
                codecs[codec_of(fh.read(120))] += 1
                sizes.append(size)
        tot = sum(sizes)
        grand.update(codecs)
        grandbytes += tot
        grandrecs += count
        per_file[name] = (count, tot, codecs)
        print("%-22s %7d %14d %10d %10d   %s"
              % (name, count, tot, min(sizes), max(sizes),
                 ", ".join("%s %d" % (k, v) for k, v in codecs.most_common())))
    print("-" * len(hdr))
    print("%-22s %7d %14d" % ("TOTAL", grandrecs, grandbytes))
    print()
    print("codecs, all ten files:")
    for k, v in grand.most_common():
        print("   %-10s %8d  %7.4f %%" % (k, v, 100.0 * v / grandrecs))
    return 0


# --------------------------------------------------------------------- ids

def ids(root):
    sets = {}
    for name in OSA:
        p = os.path.join(root, name)
        n, count, recs = read_table(p)
        sets[name] = set(r[0] for r in recs)
        if len(sets[name]) != count:
            print("!! %s: %d records but %d distinct ids"
                  % (name, count, len(sets[name])))
    first = [k for k in OSA if "_part2" not in k]
    second = [k for k in OSA if "_part2" in k]
    for label, group in (("first parts", first), ("second parts", second)):
        print()
        print("== %s ==" % label)
        for k in group:
            print("   %-22s %6d ids" % (k, len(sets[k])))
        inter = set.intersection(*[sets[k] for k in group])
        union = set.union(*[sets[k] for k in group])
        print("   union                  %6d" % len(union))
        print("   in all five            %6d   %7.4f %% of the union"
              % (len(inter), 100.0 * len(inter) / len(union)))
        onlyone = collections.Counter()
        howmany = collections.Counter()
        for i in union:
            carriers = [k for k in group if i in sets[k]]
            howmany[len(carriers)] += 1
            if len(carriers) == 1:
                onlyone[carriers[0]] += 1
        print("   ids by how many languages carry them:")
        for k in sorted(howmany):
            print("      %d language(s) : %6d" % (k, howmany[k]))
        print("   ids carried by exactly one language:")
        for k in group:
            print("      %-22s %6d" % (k, onlyone[k]))
    print()
    print("== across the two parts ==")
    fu = set.union(*[sets[k] for k in first])
    su = set.union(*[sets[k] for k in second])
    print("   first-part union  %6d" % len(fu))
    print("   second-part union %6d" % len(su))
    print("   in both           %6d" % len(fu & su))
    return 0


# ------------------------------------------------------------------- chain

def ogg_chain(fh, off, size):
    """Walk the Ogg page chain from off; return (bytes consumed, pages,
    final granule, ok)."""
    pos = off
    end = off + size
    pages = 0
    granule = -1
    while pos < end:
        fh.seek(pos)
        head = fh.read(27)
        if len(head) < 27 or head[:4] != b"OggS":
            return pos - off, pages, granule, False
        granule = struct.unpack_from("<q", head, 6)[0]
        nseg = head[26]
        segs = fh.read(nseg)
        if len(segs) < nseg:
            return pos - off, pages, granule, False
        pos += 27 + nseg + sum(segs)
        pages += 1
    return pos - off, pages, granule, (pos == end)


def chain(root, n_sample):
    print("Ogg page-chain walk.  A member's declared size is reproduced by")
    print("summing its own page lengths -- an external check on the table.")
    print()
    print("%-22s %8s %8s %8s %10s %14s"
          % ("file", "sampled", "closed", "failed", "pages", "granule sum"))
    tot_s = tot_c = 0
    for name in OSA:
        p = os.path.join(root, name)
        n, count, recs = read_table(p)
        step = max(1, count // n_sample)
        sample = recs[::step][:n_sample]
        closed = failed = pages = 0
        gsum = 0
        with open(p, "rb") as fh:
            for _id, off, size in sample:
                used, pg, gran, ok = ogg_chain(fh, off, size)
                pages += pg
                if ok:
                    closed += 1
                    if gran > 0:
                        gsum += gran
                else:
                    failed += 1
        tot_s += len(sample)
        tot_c += closed
        print("%-22s %8d %8d %8d %10d %14d"
              % (name, len(sample), closed, failed, pages, gsum))
    print()
    print("chains that close exactly: %d of %d sampled (%.4f %%)"
          % (tot_c, tot_s, 100.0 * tot_c / tot_s))
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    root = sys.argv[2] if len(sys.argv) > 2 else None
    if cmd == "validate":
        return validate(root)
    if cmd == "census":
        return census(root)
    if cmd == "ids":
        return ids(root)
    if cmd == "chain":
        n = 40
        if "--n" in sys.argv:
            n = int(sys.argv[sys.argv.index("--n") + 1])
        return chain(root, n)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
