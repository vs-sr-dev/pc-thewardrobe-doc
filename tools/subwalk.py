#!/usr/bin/env python3
"""subwalk.py -- does the size word inside a Cinepak strip include its header?

Two readings of the four-byte sub-chunk header are possible and only one of them
chains. Rather than pick one and hope, this walks every strip of every frame
under both and prints how many strips end exactly on their last byte.

usage: subwalk.py FILE [--payload 44]
"""
import argparse
import collections
import struct


def chunks(data):
    off = 0
    out = []
    while off < len(data):
        tag = data[off:off + 4]
        size = struct.unpack(">I", data[off + 4:off + 8])[0]
        out.append((off, tag, size))
        off += size
    return out


def walk(body, inclusive):
    """Returns (list of (id, size), bytes left over, ok)."""
    p = 0
    got = []
    while p + 4 <= len(body):
        cid, csz = struct.unpack(">2H", body[p:p + 4])
        step = csz if inclusive else csz + 4
        if step < 4 or p + step > len(body):
            return got, len(body) - p, False
        got.append((cid, csz))
        p += step
    return got, len(body) - p, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--payload", type=int, default=44)
    a = ap.parse_args()
    data = open(a.file, "rb").read()
    cs = chunks(data)
    fr = [c for c in cs if c[1] == b"FILM"
          and data[c[0] + 16:c[0] + 20] == b"FRME"]
    for inclusive in (True, False):
        clean = total = 0
        ids = collections.Counter()
        leftover = collections.Counter()
        for off, t, size in fr:
            p = off + a.payload
            end = off + size
            while p + 12 <= end:
                sid, ssz = struct.unpack(">2H", data[p:p + 4])
                if ssz < 12 or p + ssz > end:
                    break
                got, left, ok = walk(data[p + 12:p + ssz], inclusive)
                total += 1
                leftover[left] += 1
                if ok and left == 0:
                    clean += 1
                for cid, csz in got:
                    ids[cid] += 1
                p += ssz
        print("size word %s the four-byte header:"
              % ("INCLUDES" if inclusive else "EXCLUDES"))
        print("   strips that chain to their last byte : %d of %d" % (clean, total))
        print("   leftover byte counts                 : %s"
              % ", ".join("%d (x%d)" % (k, v)
                          for k, v in leftover.most_common(5)))
        print("   sub-chunk ids                        : %s"
              % ", ".join("0x%04x (x%d)" % (k, v) for k, v in ids.most_common()))
        print()


if __name__ == "__main__":
    main()
