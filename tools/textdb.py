"""textdb.py -- the eight TEXT members inside general.vt7a, and the thing they
prove: the line id in the text table and the member id in the .osa voice
archives are the same number.

    read  <root>            derive the TEXT layout and prove it
    langs <root>            which language each of the eight members holds
    link  <root>            how many text lines have a recorded voice line,
                            in each of the five languages

Nothing is extracted; the members are inflated in memory.

    python tools/textdb.py link "<root>"
"""
import os
import sys
import struct
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from inflate import members, inflate                # noqa: E402
from aufs import read_table as aufs_table, OSA      # noqa: E402

MAGIC = b"TEXT"


def text_members(root):
    out = []
    for r, blob in members(root, "general.vt7a"):
        data = inflate(blob)
        if data[:4] != MAGIC:
            continue
        out.append((r[0], data))
    return out


def parse(data):
    """char[4] 'TEXT', u32 zero, u32 count, then count x (u32 id, u32 offset),
    then the string pool.  The offset is ABSOLUTE from the start of the member,
    which is why the first one is always 12 + 8 * count -- the byte after the
    table.  Reading it as pool-relative puts every string past the end, and
    that is the control."""
    assert data[:4] == MAGIC
    zero, count = struct.unpack_from("<II", data, 4)
    tbl = 12
    pool = tbl + 8 * count
    ids = []
    offs = []
    for i in range(count):
        a, b = struct.unpack_from("<II", data, tbl + 8 * i)
        ids.append(a)
        offs.append(b)
    return zero, count, ids, offs, pool


def get(data, off):
    end = data.find(bytes([0]), off)
    return data[off:end]


def read(root):
    tm = text_members(root)
    print("TEXT members inside general.vt7a : %d" % len(tm))
    print()
    print("derived: char[4] 'TEXT', u32 0, u32 count, count x (u32 id, u32 off),")
    print("then a NUL-terminated string pool; off is ABSOLUTE from the start")
    print("of the member, so the first one equals 12 + 8 * count exactly.")
    print()
    print("The falsifiable claims:")
    print("  T1 the second word is zero on every member")
    print("  T2 count is the same on every member")
    print("  T3 the smallest offset is exactly 12 + 8 * count, and the")
    print("     largest lands inside the member")
    print("  T4 the last string ends at or just before the end of the member")
    print("  T5 the ids are identical, in the same order, on every member")
    print()
    hdr = "%-13s %10s %8s %10s %11s %9s" % ("key", "bytes", "count", "pool at",
                                            "max off", "tail")
    print(hdr)
    print("-" * len(hdr))
    t1 = t3 = t4 = 0
    counts = set()
    idsig = set()
    for key, data in tm:
        zero, count, ids, offs, pool = parse(data)
        t1 += (zero == 0)
        counts.add(count)
        idsig.add(tuple(ids))
        mx = max(offs)
        t3 += (min(offs) == pool and mx < len(data))
        end = data.find(bytes([0]), mx)
        tail = len(data) - (end + 1)
        t4 += (0 <= tail <= 16)
        print("%-13d %10d %8d %10d %11d %9d"
              % (key, len(data), count, pool, mx, tail))
    print("-" * len(hdr))
    print("T1 holds on %d of %d" % (t1, len(tm)))
    print("T2 : distinct counts across the members : %s" % sorted(counts))
    print("T3 holds on %d of %d" % (t3, len(tm)))
    print("T4 holds on %d of %d" % (t4, len(tm)))
    print("T5 : distinct id sequences across the members : %d" % len(idsig))
    print()
    print("TWO CONTROLS, both of which must fail:")
    bad = 0
    for key, data in tm:
        zero, count, ids, offs, pool = parse(data)
        if max(offs) + pool >= len(data):
            bad += 1
    print("   read as POOL-RELATIVE, the last string starts past the end")
    print("   on %d of %d members" % (bad, len(tm)))
    bad2 = 0
    for key, data in tm:
        zero, count = struct.unpack_from("<II", data, 4)
        if 12 + 12 * count >= len(data):
            bad2 += 1
    print("   read with twelve-byte records, the pool starts past the end")
    print("   on %d of %d members" % (bad2, len(tm)))
    return 0


LANGWORDS = {
    "english": [b" the ", b" and ", b" you "],
    "french": [b" les ", b" est ", b" une "],
    "german": [b" ich ", b" nicht ", b" der "],
    "italian": [b" che ", b" non ", b" una "],
    "spanish": [b" que ", b" los ", b" una "],
}


def langs(root):
    tm = text_members(root)
    print("Which language each TEXT member holds, decided by counting three")
    print("common words of each language in the string pool.")
    print()
    print("%-13s %10s   %s" % ("key", "bytes",
                               "  ".join("%-9s" % k for k in LANGWORDS)))
    for key, data in tm:
        zero, count, ids, offs, pool = parse(data)
        blob = data[pool:]
        sc = {k: sum(blob.count(w) for w in v) for k, v in LANGWORDS.items()}
        best = max(sc, key=sc.get)
        print("%-13d %10d   %s   -> %s"
              % (key, len(data),
                 "  ".join("%-9d" % sc[k] for k in LANGWORDS), best))
    return 0


def link(root):
    tm = text_members(root)
    zero, count, ids, offs, pool = parse(tm[0][1])
    tids = set(ids)
    print("text lines in a TEXT member          : %d" % count)
    print("distinct line ids                    : %d" % len(tids))
    print()
    print("Against the voice archives: how many text ids are also the id of a")
    print("recorded Opus member, per language.")
    print()
    print("%-22s %8s %10s %10s %9s"
          % ("osa", "members", "ids in TEXT", "not in TEXT", "coverage"))
    allv = set()
    for name in OSA:
        n, c, recs = aufs_table(os.path.join(root, name))
        vid = set(r[0] for r in recs)
        allv |= vid
        inn = len(vid & tids)
        print("%-22s %8d %10d %10d %8.4f %%"
              % (name, c, inn, c - inn, 100.0 * inn / c))
    print()
    print("voice ids, all ten archives, distinct : %d" % len(allv))
    print("voice ids that are a TEXT line id     : %d  (%.4f %%)"
          % (len(allv & tids), 100.0 * len(allv & tids) / len(allv)))
    print("TEXT lines that have a recording      : %d of %d  (%.4f %%)"
          % (len(tids & allv), len(tids), 100.0 * len(tids & allv) / len(tids)))
    print("TEXT lines with NO recording anywhere : %d" % len(tids - allv))
    print()
    print("THE CONTROL: the same test against a shifted id space (+1), which")
    print("must not match.")
    shifted = set(i + 1 for i in tids)
    print("   voice ids that are a shifted TEXT id : %d  (%.4f %%)"
          % (len(allv & shifted), 100.0 * len(allv & shifted) / len(allv)))
    return 0


def main():
    cmd, root = sys.argv[1], sys.argv[2]
    if cmd == "read":
        return read(root)
    if cmd == "langs":
        return langs(root)
    if cmd == "link":
        return link(root)
    print(__doc__)


if __name__ == "__main__":
    main()
