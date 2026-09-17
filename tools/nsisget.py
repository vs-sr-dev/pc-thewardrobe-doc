#!/usr/bin/env python3
"""nsisget.py -- pull named members out of a decompressed NSIS solid stream.

`nsis.py --census` writes the member list and leaves the decompressed blob on
disc. This takes that pair and copies out the members whose path matches a
substring, without decompressing anything a second time.

It is deliberately a separate tool from the census: extraction is where a
wrong reading turns into wrong bytes on disc, so the census -- which is
checkable against 7-Zip -- comes first and this comes after. Every extracted
member's length is checked against the length the census declared, and the
tool exits non-zero if a single one disagrees.

    python tools/nsisget.py notes/members-english.txt _work/solid/english.bin \\
        prefs.prop _work/out/english
"""
import os
import struct
import sys

TAB = chr(9)
BSL = chr(92)


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    census, blob, needle, outdir = sys.argv[1:5]
    want_ext = None
    if "--ext" in sys.argv:
        want_ext = sys.argv[sys.argv.index("--ext") + 1].lower()
    data_off = None
    rows = []
    body = False
    for line in open(census, encoding="utf-8"):
        if line.startswith("# sha1"):
            body = True
            continue
        if not body:
            bits = line.rstrip("\n").split(TAB)
            if bits[0] == "data_block_offset":
                data_off = int(bits[1])
            continue
        bits = line.rstrip("\n").split(TAB)
        if len(bits) == 4 and needle.lower() in bits[3].lower() and (
                want_ext is None or bits[3].lower().endswith(want_ext)):
            rows.append((bits[0], int(bits[1]), int(bits[2]), bits[3]))
    if data_off is None:
        print("census has no data_block_offset")
        return 2
    os.makedirs(outdir, exist_ok=True)
    bad = 0
    seen = set()
    with open(blob, "rb") as f:
        for sha, size, pos, path in rows:
            flat = path.replace(BSL, "_").replace("$", "").replace(":", "")
            if flat in seen:
                continue
            seen.add(flat)
            f.seek(data_off + pos)
            declared, = struct.unpack("<I", f.read(4))
            declared &= 0x7FFFFFFF
            payload = f.read(declared)
            if declared != size or len(payload) != size:
                print("MISMATCH %s: census %d, stream %d, read %d"
                      % (path, size, declared, len(payload)))
                bad += 1
                continue
            with open(os.path.join(outdir, flat), "wb") as o:
                o.write(payload)
    print("%d matched, %d written, %d mismatched" % (len(rows), len(seen) - bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
