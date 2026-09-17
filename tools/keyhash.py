"""keyhash.py -- try to break the VT7A key.

The seven VT7A archives keep no member names: each record carries a 32-bit key
and the table is sorted by it.  Broken Sword 3's `data.pak` does the same thing
eleven years earlier, and that is the collection's oldest open question.

This object gives an attack the 2003 one did not have: 4,648 of its members are
XML, and that XML names assets.  If the key is a hash of a name, then hashing
the names the XML mentions must land on keys that are actually in the tables.

The tool harvests candidate names from the inflated XML, runs each through a
list of hash functions in a list of spellings, and counts how many of the
resulting values are keys.  The control is the same measurement against the
same number of random 32-bit values, which must score zero.

    harvest <root> --out F      collect candidate name strings
    attack  <root> --names F    try every (hash, spelling) pair
    report  <root>              what the tables look like from the outside

    python tools/keyhash.py attack "<root>" --names _work/names.txt
"""
import os
import sys
import re
import zlib
import random
import hashlib
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table, VT7A                   # noqa: E402
from inflate import members, inflate                # noqa: E402


# --------------------------------------------------------------- hash zoo

def h_crc32(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def h_adler32(b):
    return zlib.adler32(b) & 0xFFFFFFFF


def h_djb2(b):
    h = 5381
    for c in b:
        h = ((h * 33) + c) & 0xFFFFFFFF
    return h


def h_djb2x(b):
    h = 5381
    for c in b:
        h = ((h * 33) ^ c) & 0xFFFFFFFF
    return h


def h_sdbm(b):
    h = 0
    for c in b:
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def h_fnv1(b):
    h = 0x811C9DC5
    for c in b:
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= c
    return h


def h_fnv1a(b):
    h = 0x811C9DC5
    for c in b:
        h ^= c
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def h_jenkins(b):
    h = 0
    for c in b:
        h = (h + c) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= (h >> 6)
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11)
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h


def h_elf(b):
    h = 0
    for c in b:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


def h_md5_32(b):
    return int.from_bytes(hashlib.md5(b).digest()[:4], "little")


def h_sha1_32(b):
    return int.from_bytes(hashlib.sha1(b).digest()[:4], "little")


def _murmur3(b, seed=0):
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h = seed
    n = len(b) // 4 * 4
    for i in range(0, n, 4):
        k = int.from_bytes(b[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    k = 0
    tail = b[n:]
    for i, c in enumerate(tail):
        k |= c << (8 * i)
    if tail:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(b)
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


HASHES = [("crc32", h_crc32), ("adler32", h_adler32), ("djb2", h_djb2),
          ("djb2-xor", h_djb2x), ("sdbm", h_sdbm), ("fnv1", h_fnv1),
          ("fnv1a", h_fnv1a), ("jenkins", h_jenkins), ("elf", h_elf),
          ("md5[:4]", h_md5_32), ("sha1[:4]", h_sha1_32),
          ("murmur3-0", _murmur3),
          ("murmur3-1", lambda b: _murmur3(b, 1))]


def spellings(name):
    """The same name written the ways a build tool might have written it."""
    out = {name}
    out.add(name.lower())
    out.add(name.upper())
    out.add(name.replace("/", "\\"))
    out.add(name.lower().replace("/", "\\"))
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    out.add(base)
    out.add(base.lower())
    stem = base.rsplit(".", 1)[0]
    out.add(stem)
    out.add(stem.lower())
    return out


# ----------------------------------------------------------------- harvest

TOKEN = re.compile(rb'[A-Za-z0-9_./\\-]{3,120}')


def harvest(root, out_path):
    seen = collections.Counter()
    n = 0
    for r, blob in members(root, "general.vt7a"):
        try:
            data = inflate(blob)
        except Exception:                            # noqa: BLE001
            continue
        n += 1
        for m in TOKEN.finditer(data):
            t = m.group(0)
            if 3 <= len(t) <= 120:
                seen[t] += 1
    with open(out_path, "wb") as fh:
        for t, c in seen.most_common():
            fh.write(t + b"\n")
    print("inflated members read : %d" % n)
    print("distinct tokens       : %d" % len(seen))
    print("wrote %s" % out_path)
    return 0


# ------------------------------------------------------------------ attack

def all_keys(root):
    keys = set()
    per = {}
    for arch in VT7A:
        _n, _v, _m, _c, recs = read_table(os.path.join(root, arch))
        k = set(r[0] for r in recs)
        per[arch] = k
        keys |= k
    return keys, per


def attack(root, names_path):
    keys, per = all_keys(root)
    print("keys in the seven tables : %d distinct" % len(keys))
    names = [l.rstrip(b"\n") for l in open(names_path, "rb")]
    print("candidate names          : %d" % len(names))
    print()
    # build the spelling set once
    forms = set()
    for nm in names:
        try:
            s = nm.decode("latin-1")
        except Exception:                            # noqa: BLE001
            continue
        for f in spellings(s):
            forms.add(f.encode("latin-1"))
    print("distinct spellings tried : %d" % len(forms))
    print()
    print("%-12s %10s %10s %12s" % ("hash", "hits", "control", "verdict"))
    print("-" * 48)
    rnd = random.Random(20260902)
    ctrl_forms = [bytes(rnd.randrange(32, 127) for _ in range(12))
                  for _ in range(min(len(forms), 20000))]
    best = None
    for label, fn in HASHES:
        hits = sum(1 for f in forms if fn(f) in keys)
        ctrl = sum(1 for f in ctrl_forms if fn(f) in keys)
        # scale the control to the same number of trials
        ctrl_scaled = ctrl * len(forms) / float(len(ctrl_forms))
        verdict = "chance"
        if hits > 20 and hits > 5 * max(1.0, ctrl_scaled):
            verdict = "*** SIGNAL ***"
            best = (label, hits)
        print("%-12s %10d %10.1f %12s" % (label, hits, ctrl_scaled, verdict))
    print()
    exp = len(forms) * len(keys) / 2.0 ** 32
    print("expected hits by chance for any 32-bit hash: %.2f" % exp)
    if best:
        print()
        print("SIGNAL on %s with %d hits -- worth pursuing" % best)
    else:
        print()
        print("NO SIGNAL.  None of the %d hash functions, over %d spellings of"
              % (len(HASHES), len(forms)))
        print("%d harvested names, lands on the key space more often than" % len(names))
        print("chance.  The key is not a plain hash of a name that this object")
        print("spells out.  That is a measured negative, not a failure to try.")
    return 0


def report(root):
    keys, per = all_keys(root)
    print("%-22s %8s %14s %14s %12s"
          % ("archive", "keys", "min", "max", "1 in"))
    for arch in VT7A:
        k = sorted(per[arch])
        print("%-22s %8d %14d %14d %12.1f"
              % (arch, len(k), k[0], k[-1], (k[-1] - k[0]) / float(len(k))))
    print()
    print("union over the seven : %d" % len(keys))
    print("sum of the sevens    : %d" % sum(len(v) for v in per.values()))
    print("keys in more than one archive : %d"
          % (sum(len(v) for v in per.values()) - len(keys)))
    print()
    print("the key space, tested for the shape a hash leaves:")
    ks = sorted(keys)
    print("   spread over the full 32-bit range : %.4f %%"
          % (100.0 * (ks[-1] - ks[0]) / 2.0 ** 32))
    buckets = collections.Counter(k >> 28 for k in keys)
    print("   top nibble histogram (a hash should be flat):")
    for i in range(16):
        print("      %X  %6d  %s" % (i, buckets[i],
                                     "#" * (buckets[i] * 40 // max(buckets.values()))))
    lowbits = collections.Counter(k & 1 for k in keys)
    print("   low bit: %d even, %d odd" % (lowbits[0], lowbits[1]))
    return 0


def main():
    cmd, root = sys.argv[1], sys.argv[2]
    if cmd == "harvest":
        return harvest(root, sys.argv[sys.argv.index("--out") + 1])
    if cmd == "attack":
        return attack(root, sys.argv[sys.argv.index("--names") + 1])
    if cmd == "report":
        return report(root)
    print(__doc__)


if __name__ == "__main__":
    main()
