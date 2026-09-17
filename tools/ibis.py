#!/usr/bin/env python3
"""ibis.py -- reader for the IBIS ROM container found inside CBEUB's rRom members.

Layout derived from the bytes:

    +0   4    'IBIS'
    +4   u32  version
    +8   ...  pairs of (u32 offset, u32 size), terminated by a zero pair
    then the regions, back to back. The first offset is 0x40 on every file
    seen, which is why a reading that calls +8 a "header size" also makes the
    accounting close -- it is the region-0 offset, and the header is padded
    from its real end (0x28 for four regions) out to 0x40.

--validate is the entry point and must fail loudly on a non-IBIS file.

Usage:
    ibis.py --validate FILE...
    ibis.py --map      FILE...
    ibis.py --extract  FILE --out DIR
"""
import argparse
import os
import struct
import sys

MAGIC = b"IBIS"


class NotIbis(Exception):
    pass


def parse(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 16:
        raise NotIbis("%s: %d bytes is too short" % (path, len(data)))
    if data[:4] != MAGIC:
        raise NotIbis("%s: magic %r, not %r" % (path, data[:4], MAGIC))
    version, = struct.unpack_from("<I", data, 4)
    regions = []
    off = 8
    while off + 8 <= len(data):
        ro, rs = struct.unpack_from("<II", data, off)
        if ro == 0 and rs == 0:
            break
        if ro > len(data) or ro + rs > len(data):
            raise NotIbis(
                "%s: region %d at 0x%X+0x%X runs past the %d-byte file"
                % (path, len(regions), ro, rs, len(data))
            )
        regions.append((ro, rs))
        off += 8
    if not regions:
        raise NotIbis("%s: no regions" % path)
    hdrend = off + 8
    first = regions[0][0]
    # accounting: the regions must tile the file from the first offset with no
    # gap and no overlap, and the last one must end at end-of-file.
    total = first + sum(r[1] for r in regions)
    contiguous = all(
        regions[i][0] + regions[i][1] == regions[i + 1][0]
        for i in range(len(regions) - 1)
    )
    return {
        "path": path,
        "data": data,
        "size": len(data),
        "version": version,
        "first": first,
        "hdrend": hdrend,
        "regions": regions,
        "total": total,
        "residue": len(data) - total,
        "contiguous": contiguous,
        "tail": data[hdrend:first],
    }


def region_bytes(info, i):
    ro, rs = info["regions"][i]
    return info["data"][ro:ro + rs]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--map", action="store_true")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()

    rc = 0
    for path in a.files:
        try:
            info = parse(path)
        except NotIbis as exc:
            print("NOT-IBIS  %s" % exc)
            rc = 1
            continue
        name = os.path.basename(path)
        good = info["residue"] == 0 and info["contiguous"]
        flag = "OK " if good else "BAD"
        print(
            "%s %-12s v%-2d first=0x%02X regions=%d size=%-10d residue=%d contiguous=%s"
            % (flag, name, info["version"], info["first"], len(info["regions"]),
               info["size"], info["residue"], info["contiguous"])
        )
        if not good:
            rc = 1
        if a.map:
            for i, (ro, rs) in enumerate(info["regions"]):
                blob = info["data"][ro:ro + rs]
                zeros = blob.count(0)
                print(
                    "    r%d  off=0x%08X size=0x%08X (%10d)  zeros=%6.2f%%  first8=%s"
                    % (i, ro, rs, rs, 100.0 * zeros / max(rs, 1), blob[:8].hex())
                )
            if any(info["tail"]):
                print("    header tail after terminator is not all zero: %s"
                      % info["tail"].hex())
        if a.extract:
            if not a.out:
                print("--extract needs --out")
                return 2
            os.makedirs(a.out, exist_ok=True)
            stem = os.path.splitext(name)[0]
            for i in range(len(info["regions"])):
                dest = os.path.join(a.out, "%s.r%d" % (stem, i))
                with open(dest, "wb") as fh:
                    fh.write(region_bytes(info, i))
                print("    wrote %s" % dest)
    return rc


if __name__ == "__main__":
    sys.exit(main())
