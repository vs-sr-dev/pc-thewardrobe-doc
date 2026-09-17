"""inflate.py -- inflate the zlib members of a VT7A archive IN MEMORY and say
what they are.  Nothing is written to disk.

The point is not to extract the game.  It is that an object which is 98.44 %
above the entropy threshold contains no readable string until the containers
are opened, and every negative string result in this repository -- including
"Virtual Theatre: 0" -- is only worth what it is worth after this pass.

    what   <root> <archive>          classify every inflated member
    find   <root> <archive> STRING   count a string inside the inflated members
    sample <root> <archive> [--n N]  print the first bytes of N members

    python tools/inflate.py what "<root>" general.vt7a
"""
import os
import sys
import zlib
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table, extent, signature      # noqa: E402


def members(root, arch, only_zlib=True):
    p = os.path.join(root, arch)
    n, ver, m2, count, recs = read_table(p)
    with open(p, "rb") as fh:
        for r in sorted(recs, key=lambda x: x[1]):
            fh.seek(r[1])
            blob = fh.read(extent(r))
            if only_zlib and blob[:1] != bytes([0x78]):
                continue
            yield r, blob


def inflate(blob):
    return zlib.decompress(blob)


def classify(data):
    head = data[:64]
    if len(head) < 4:
        return "shorter than four bytes"
    if head[:4] == b"STRM":
        return "STRM"
    if head[:3] == b"sdw":
        return "sdw"
    if head[:4] == b"RIFF":
        return "RIFF"
    if head[:5] == b"<?xml" or head[:1] == b"<":
        return "XML"
    printable = sum(1 for b in data[:256] if 32 <= b < 127 or b in (9, 10, 13))
    if printable >= 0.95 * min(256, len(data)):
        return "text"
    return "binary %02X%02X%02X%02X" % tuple(head[:4])


def what(root, arch):
    kinds = collections.Counter()
    kb = collections.Counter()
    ok = fail = 0
    raw = comp = 0
    for r, blob in members(root, arch):
        try:
            data = inflate(blob)
        except Exception as e:                      # noqa: BLE001
            fail += 1
            continue
        ok += 1
        raw += len(data)
        comp += len(blob)
        if len(data) != r[2]:
            kinds["SIZE MISMATCH"] += 1
            continue
        k = classify(data)
        kinds[k] += 1
        kb[k] += len(data)
    print("archive              : %s" % arch)
    print("zlib members         : %d" % (ok + fail))
    print("inflated cleanly     : %d" % ok)
    print("failed to inflate    : %d" % fail)
    print("compressed bytes     : %d" % comp)
    print("inflated bytes       : %d   (x %.4f)" % (raw, raw / float(comp)))
    print("declared size_raw matched on every member : %s"
          % ("no, %d mismatches" % kinds["SIZE MISMATCH"]
             if kinds["SIZE MISMATCH"] else "yes, %d of %d" % (ok, ok)))
    print()
    print("%-22s %8s %14s" % ("what it is", "members", "bytes"))
    for k, c in kinds.most_common():
        print("%-22s %8d %14d" % (k, c, kb[k]))
    return 0


def find(root, arch, needle):
    nb = needle.encode("latin-1")
    nw = needle.encode("utf-16-le")
    hits = hitsw = 0
    carriers = 0
    tot = 0
    for r, blob in members(root, arch):
        try:
            data = inflate(blob)
        except Exception:                            # noqa: BLE001
            continue
        tot += 1
        a = data.count(nb)
        b = data.count(nw)
        hits += a
        hitsw += b
        if a or b:
            carriers += 1
    print("%-24s ascii %8d   utf-16 %8d   in %d of %d inflated members"
          % (needle, hits, hitsw, carriers, tot))
    return 0


def sample(root, arch, n):
    shown = 0
    for r, blob in members(root, arch):
        try:
            data = inflate(blob)
        except Exception:                            # noqa: BLE001
            continue
        print("key %-12d off %-12d stored %-9d raw %-9d  %s"
              % (r[0], r[1], r[3], r[2], classify(data)))
        chunk = data[:256]
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        for i in range(0, len(txt), 96):
            print("    %s" % txt[i:i + 96])
        print()
        shown += 1
        if shown >= n:
            break
    return 0


def main():
    cmd, root, arch = sys.argv[1], sys.argv[2], sys.argv[3]
    if cmd == "what":
        return what(root, arch)
    if cmd == "find":
        return find(root, arch, sys.argv[4])
    if cmd == "sample":
        n = 5
        if "--n" in sys.argv:
            n = int(sys.argv[sys.argv.index("--n") + 1])
        return sample(root, arch, n)
    print(__doc__)


if __name__ == "__main__":
    main()
