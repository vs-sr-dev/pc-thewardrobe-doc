#!/usr/bin/env python3
"""xa.py -- the CD-ROM XA extension, read from a disc image rather than a file.

`cdxa.py` exists in this toolbox and does not apply here. It reads Microsoft's
RIFF/CDXA *container* -- raw sectors wearing a WAV hat -- because the object it
was written for had no image, only a file tree. This object is the opposite: a
whole raw image whose primary descriptor carries the XA marker and whose every
directory record carries the XA system-use extension. Different bytes, same
standard, different tool.

Two places to look, and this reads both:

**1. The volume descriptor.** Immediately after the 512-byte application-use
area of a primary descriptor, at offset 1024, an XA disc carries the eight
characters `CD-XA001`. What follows is short and is dumped literally rather than
interpreted beyond what the marker itself guarantees.

**2. Every directory record.** ECMA-119 9.1.13 allows a System Use area after
the file identifier; CD-ROM XA defines a 14-byte structure for it:

     0..3   owner id (group, user), big-endian
     4..5   attributes, big-endian
     6..7   the two characters 'XA'
     8      file number
     9..13  reserved, five bytes

  attributes, bit by bit (bit 15 is the most significant):

     0x0001 owner read     0x0004 owner execute
     0x0010 group read     0x0040 group execute
     0x0100 world read     0x0400 world execute
     0x0800 Mode 2 Form 1  0x1000 Mode 2 Form 2
     0x2000 interleaved    0x4000 CD-DA
     0x8000 directory

The signature at offset 6 is what makes the structure checkable: a record whose
System Use area is 14 bytes but does not spell 'XA' there is not an XA record,
and is counted separately rather than parsed hopefully.

    python tools/xa.py IMAGE
    python tools/xa.py IMAGE --records
    python tools/xa.py IMAGE --joliet
"""

import argparse
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iso9660  # noqa: E402

SECTOR = 2048

ATTR_BITS = [
    (0x0001, "owner-read"), (0x0004, "owner-exec"),
    (0x0010, "group-read"), (0x0040, "group-exec"),
    (0x0100, "world-read"), (0x0400, "world-exec"),
    (0x0800, "mode2form1"), (0x1000, "mode2form2"),
    (0x2000, "interleaved"), (0x4000, "cdda"),
    (0x8000, "directory"),
]


def attr_names(v):
    return "|".join(n for m, n in ATTR_BITS if v & m) or "-"


def raw_records(img, root_lba, root_len):
    """Yield (path, name, isdir, whole record bytes). Walks like iso9660 does
    but keeps the record intact so the System Use tail survives."""
    todo = [(root_lba, root_len, "/")]
    seen = set()
    while todo:
        lba, ln, prefix = todo.pop(0)
        if (lba, ln) in seen:
            continue
        seen.add((lba, ln))
        nsec = (ln + SECTOR - 1) // SECTOR
        data = img.read(lba, nsec)
        off = 0
        while off < min(ln, len(data)):
            rl = data[off]
            if rl == 0:
                off = (off // SECTOR + 1) * SECTOR
                continue
            rec = data[off:off + rl]
            off += rl
            if len(rec) < 33:
                continue
            ext = struct.unpack("<I", rec[2:6])[0]
            dlen = struct.unpack("<I", rec[10:14])[0]
            flags = rec[25]
            nlen = rec[32]
            raw = rec[33:33 + nlen]
            if nlen == 1 and raw in (b"\x00", b"\x01"):
                continue
            name = raw.decode("latin-1")
            isdir = bool(flags & 2)
            yield prefix, name, isdir, rec
            if isdir:
                todo.append((ext, dlen, prefix + name + "/"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--records", action="store_true")
    ap.add_argument("--joliet", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    fh, mm = iso9660.open_image(a.image)
    try:
        vds = iso9660.read_vds(mm)
        print("=== the volume descriptor ===")
        for sec, t, b in vds:
            if t not in (1, 2):
                continue
            marker = bytes(b[1024:1032])
            print("  descriptor at sector %d, type %d" % (sec, t))
            print("    offset 1024..1031 : %r   %s"
                  % (marker, "CD-XA marker present"
                     if marker == b"CD-XA001" else "NOT an XA marker"))
            if marker == b"CD-XA001":
                flags = struct.unpack_from(">H", bytes(b), 1032)[0]
                print("    offset 1032..1033 : flags 0x%04X" % flags)
                print("    offset 1034..1041 : %r" % bytes(b[1034:1042]))
                print("    offset 1042..1049 : %r" % bytes(b[1042:1050]))
                tail = bytes(b[1050:1088])
                print("    offset 1050..1087 : %s"
                      % ("all zero" if not any(tail) else repr(tail)))
        print()

        class _Img:
            def __init__(self, mm):
                self.mm = mm

            def read(self, lba, n):
                return self.mm[lba * SECTOR:(lba + n) * SECTOR]

        img = _Img(mm)
        _sec, b = iso9660.pick(vds, a.joliet)
        rd = bytes(b[156:190])
        root_lba = struct.unpack("<I", rd[2:6])[0]
        root_len = struct.unpack("<I", rd[10:14])[0]

        total = 0
        with_su = Counter()
        sigs = Counter()
        attrs = Counter()
        filenums = Counter()
        owners = Counter()
        reserved_nonzero = 0
        bad = []
        rows = []
        for prefix, name, isdir, rec in raw_records(img, root_lba, root_len):
            total += 1
            nlen = rec[32]
            base = 33 + nlen
            if nlen % 2 == 0:
                base += 1                      # ECMA-119 9.1.12 padding byte
            su = rec[base:]
            with_su[len(su)] += 1
            if len(su) >= 14 and su[6:8] == b"XA":
                sig = "XA"
                at = struct.unpack_from(">H", su, 4)[0]
                fn = su[8]
                own = struct.unpack_from(">I", su, 0)[0]
                attrs[at] += 1
                filenums[fn] += 1
                owners[own] += 1
                if any(su[9:14]):
                    reserved_nonzero += 1
                rows.append((prefix + name, isdir, at, fn, own))
            else:
                sig = "-"
                if len(bad) < 20:
                    bad.append((prefix + name, len(su), bytes(su[:16])))
            sigs[sig] += 1

        print("=== the directory records ===")
        print("  records walked                       %d" % total)
        print("  carrying a 14-byte 'XA' System Use   %d  (%.4f %%)"
              % (sigs["XA"], 100.0 * sigs["XA"] / max(total, 1)))
        print("  not carrying one                     %d" % sigs["-"])
        for p, n, head in bad:
            print("      %-50s su=%d %r" % (p[:50], n, head))
        print()
        print("  System Use area lengths:")
        for n, c in sorted(with_su.items()):
            print("    %3d bytes  %6d" % (n, c))
        print()
        print("  attributes word:")
        for at, c in sorted(attrs.items(), key=lambda kv: -kv[1]):
            print("    0x%04X  %6d   %s" % (at, c, attr_names(at)))
        print()
        print("  file numbers:")
        for fn, c in sorted(filenums.items()):
            print("    %3d  %6d" % (fn, c))
        print("  owner id words:")
        for ow, c in sorted(owners.items()):
            print("    0x%08X  %6d" % (ow, c))
        print("  records with a non-zero five-byte reserved field: %d"
              % reserved_nonzero)
        print()
        if a.records:
            print("%-72s %-6s %-6s %s" % ("path", "attr", "fileno", "flags"))
            for p, isdir, at, fn, own in rows:
                print("%-72s 0x%04X %-6d %s"
                      % (p[:72] + ("/" if isdir else ""), at, fn,
                         attr_names(at)))
    finally:
        mm.close()
        fh.close()


if __name__ == "__main__":
    main()
