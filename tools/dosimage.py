#!/usr/bin/env python3
"""dosimage.py -- the four packing indicators for a real-mode MS-DOS image,
in one table, with a control column.

The question this exists for: `popcorn.exe` of POP-CORN (LACRAL software,
1988) has 405 blocks of 256 bytes and 405 distinct ones, entropy 6.1130, zero
relocations in 103 KB, and an entry point 360 bytes from the end of the file.
Four indicators, all of which are usually written down as "this is packed" --
and no packer signature anywhere.

The trouble with "usually" is that nobody in this pipeline had ever measured
what an UNpacked DOS binary scores on any of the four. `blockrepeat.py`
already counts repeated blocks, but it does not separate the constant-byte
ones, and a padding-inflated repeat count is exactly the error that cost
pc-skunnybacktotheforest-doc a chapter. So this tool reports, per file:

    bytes      file size on disc
    hdr        MZ header bytes (e_cparhdr * 16), or '-' if not an MZ
    image      declared load image, from e_cp/e_cblp
    resid      file size minus header minus image; +0 means nothing appended
    reloc      relocation entries in the MZ header
    entry      entry-point file offset, and how far it is from EOF
    H          Shannon entropy of the whole file, base 2, bits per byte
    blocks     blocks of --width bytes (default 256), floor division
    distinct   distinct block values
    const      blocks that are a single byte repeated -- padding, mostly
    d/b        distinct over blocks; 1.000 means nothing repeats at all
    printable  fraction of bytes in printable runs of >= 5 characters

and then a summary line saying which files reach d/b == 1.000, because that
is the outlier test the table exists to make.

`--width N` changes the block width. `--csv` prints the same table as CSV.

    python dosimage.py FILE_OR_DIR...
    python dosimage.py --width 16 game/
    python dosimage.py --refuse-check FILE     # must NOT be an MZ; exit 1 if it is

Standard library only. It reads; it never writes and never executes.
"""

import argparse
import math
import os
import re
import struct
import sys

PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")

# Below this many blocks, d/b == 1.000 is arithmetic and not evidence:
# popspeed.exe has four blocks and reaches 1.000 by having four different
# ones. Stated as a constant so the threshold can be argued with.
MIN_BLOCKS = 32


def walk(args):
    out = []
    for a in args:
        if os.path.isdir(a):
            for dp, _, fn in os.walk(a):
                for n in fn:
                    out.append(os.path.join(dp, n))
        elif os.path.isfile(a):
            out.append(a)
        else:
            raise SystemExit("dosimage.py: no such file or directory: %s" % a)
    return sorted(out)


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log(p, 2)
    return h


def mz(data):
    """Return a dict of MZ facts, or None if this is not an MZ image.

    Everything here is arithmetic on the header. It deliberately does not
    interpret a single byte of the load image, because the coverage rule this
    collection uses says that reading an MZ header and stopping does not count
    as identifying the file -- and this tool must not be mistaken for one that
    does.
    """
    if len(data) < 28 or data[:2] not in (b"MZ", b"ZM"):
        return None
    (e_cblp, e_cp, e_crlc, e_cparhdr, _minal, _maxal, _ss, _sp, _csum,
     e_ip, e_cs, e_lfarlc, _ovno) = struct.unpack_from("<13H", data, 2)
    hdr = e_cparhdr * 16
    # e_cp/e_cblp declare the size of the WHOLE FILE in 512-byte pages with a
    # partial last page, header included -- not the size of the load image.
    # Getting that backwards made the first run of this tool print resid -512
    # on three files that mz.py reports at +0, which is how it was caught.
    declared = ((e_cp - 1) * 512 + e_cblp) if e_cblp else e_cp * 512
    if e_cp == 0:
        declared = 0
    image = declared - hdr
    entry = hdr + e_cs * 16 + e_ip
    return {
        "hdr": hdr,
        "image": image,
        "resid": len(data) - declared,
        "reloc": e_crlc,
        "lfarlc": e_lfarlc,
        "entry": entry,
        "from_eof": len(data) - entry,
        "cs_ip": "%04X:%04X" % (e_cs, e_ip),
    }


def blockstats(data, width):
    n = len(data) // width
    seen = {}
    const = 0
    for i in range(n):
        b = data[i * width:(i + 1) * width]
        seen[b] = seen.get(b, 0) + 1
    for b in seen:
        if len(set(b)) == 1:
            const += seen[b]
    return n, len(seen), const


def printable_fraction(data):
    return sum(len(m.group(0)) for m in PRINTABLE.finditer(data)) / float(
        len(data) or 1)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--width", type=int, default=256)
    ap.add_argument("--csv", action="store_true")
    ap.add_argument("--refuse-check", action="store_true",
                    help="assert every path is NOT an MZ; exit 1 if one is")
    args = ap.parse_args(argv)

    if args.width < 1:
        raise SystemExit("dosimage.py: --width must be >= 1")

    paths = walk(args.paths)
    if not paths:
        raise SystemExit("dosimage.py: nothing to read")

    head = ("file", "bytes", "hdr", "image", "resid", "reloc", "entry",
            "fromEOF", "H", "blocks", "distinct", "const", "d/b", "print")
    fmt = ("%-26s %9s %6s %9s %6s %6s %9s %8s %7s %7s %8s %6s %6s %6s")
    rows = []
    ones = []
    notmz = []
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        m = mz(data)
        if m is None:
            notmz.append(p)
        nb, nd, nc = blockstats(data, args.width)
        rows.append((
            os.path.basename(p)[:26],
            len(data),
            m["hdr"] if m else "-",
            m["image"] if m else "-",
            ("%+d" % m["resid"]) if m else "-",
            m["reloc"] if m else "-",
            m["entry"] if m else "-",
            m["from_eof"] if m else "-",
            "%.4f" % entropy(data),
            nb,
            nd,
            nc,
            ("%.3f" % (nd / float(nb))) if nb else "-",
            "%.3f" % printable_fraction(data),
        ))
        # A file of four blocks reaches d/b == 1.000 by having four different
        # blocks, which is no evidence of anything. MIN_BLOCKS is the smallest
        # census this tool will call an outlier on, and it is stated rather
        # than hidden so the threshold can be argued with.
        if nb >= MIN_BLOCKS and nd == nb:
            ones.append(os.path.basename(p))

    if args.refuse_check:
        bad = [p for p in paths if p not in notmz]
        for p in paths:
            print("%-40s %s" % (os.path.basename(p),
                                "NOT-MZ (refused, as required)"
                                if p in notmz else "MZ -- CONTROL FAILED"))
        if bad:
            print("\ndosimage.py: --refuse-check FAILED on %d of %d"
                  % (len(bad), len(paths)))
            return 1
        print("\ndosimage.py: --refuse-check passed on %d of %d"
              % (len(paths), len(paths)))
        return 0

    if args.csv:
        print(",".join(head))
        for r in rows:
            print(",".join(str(x) for x in r))
        return 0

    print(fmt % head)
    for r in rows:
        print(fmt % r)
    print()
    print("files                       %d" % len(rows))
    print("not MZ images               %d  (%s)"
          % (len(notmz), ", ".join(os.path.basename(p) for p in notmz) or "-"))
    print("block width                 %d" % args.width)
    print("files with d/b == 1.000     %d of %d  (%s)"
          % (len(ones), len(rows), ", ".join(ones) or "-"))
    print("  counted only at >= %d blocks; smaller files are excluded"
          % MIN_BLOCKS)
    print()
    print("d/b == 1.000 means not one block of %d bytes occurs twice."
          % args.width)
    print("It is the outlier test; the const column is why it is not the")
    print("repeat count, since padding inflates that and says nothing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
