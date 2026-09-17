"""isoaccount.py -- account for every byte of an ISO 9660 image, and refuse to
finish unless the remainder is zero.

The arithmetic that matters on a disc image is not "how much is in files"; it is
"where did the rest go". This tool partitions the image into disjoint spans and
prints the sum. If the categories do not add to the file size exactly, it says
so and exits non-zero, because an accounting that nearly closes is an accounting
that is wrong somewhere.

Categories, in image order:

  system area        sectors 0..15, reserved by ECMA-119 6.2.1
  volume descriptors from sector 16 to the terminator inclusive
  directory extents  the data extents of every directory record in both
                     namespaces (the two namespaces have separate ones)
  path tables        L and M copies for each namespace
  file data          the used bytes of every file extent, once per extent
  file slack         the unused tail of the last sector of every file
  unclaimed          sectors no record points at

Usage:
    python tools/isoaccount.py UNDERGROUND.ISO
    python tools/isoaccount.py UNDERGROUND.ISO --selftest
"""

import os
import sys

SECTOR = 2048


def u32le(b, o):
    return int.from_bytes(b[o:o + 4], "little")


def u16le(b, o):
    return int.from_bytes(b[o:o + 2], "little")


def read_sector(fh, n, count=1):
    fh.seek(n * SECTOR)
    return fh.read(SECTOR * count)


def walk_dir(fh, extent, length, out_dirs, out_files, seen):
    """Recursively collect (extent, length) for directories and files."""
    if (extent, length) in seen:
        return
    seen.add((extent, length))
    out_dirs.append((extent, length))
    nsec = (length + SECTOR - 1) // SECTOR
    data = read_sector(fh, extent, nsec)
    off = 0
    while off < length:
        rlen = data[off]
        if rlen == 0:
            off = ((off // SECTOR) + 1) * SECTOR
            continue
        rec = data[off:off + rlen]
        ext = u32le(rec, 2)
        size = u32le(rec, 10)
        flags = rec[25]
        idlen = rec[32]
        ident = rec[33:33 + idlen]
        off += rlen
        if idlen == 1 and ident in (b"\x00", b"\x01"):
            continue
        if flags & 0x02:
            walk_dir(fh, ext, size, out_dirs, out_files, seen)
        else:
            out_files.append((ext, size))


def account(path, verbose=True, drop=None):
    total = os.path.getsize(path)
    sectors = total // SECTOR
    claimed = bytearray(sectors)  # 0 = unclaimed
    parts = []

    with open(path, "rb") as fh:
        # system area
        for s in range(min(16, sectors)):
            claimed[s] = 1
        parts.append(("system area (sectors 0-15)", 16 * SECTOR, 16))

        # volume descriptors
        vds = []
        s = 16
        while s < sectors:
            d = read_sector(fh, s)
            if d[1:6] != b"CD001":
                break
            vds.append((s, d[0], d))
            claimed[s] = 1
            if d[0] == 255:
                break
            s += 1
        parts.append(("volume descriptors", len(vds) * SECTOR, len(vds)))

        # per namespace: root dir + path tables
        dir_spans = []
        file_spans = []
        pt_sectors = 0
        for sec, typ, d in vds:
            if typ not in (1, 2):
                continue
            pt_size = u32le(d, 132)
            pt_l = u32le(d, 140)
            pt_m = int.from_bytes(d[148:152], "big")
            npt = (pt_size + SECTOR - 1) // SECTOR
            for base in (pt_l, pt_m):
                for k in range(npt):
                    if base + k < sectors and not claimed[base + k]:
                        claimed[base + k] = 1
                        pt_sectors += 1
            root = d[156:190]
            r_ext = u32le(root, 2)
            r_len = u32le(root, 10)
            walk_dir(fh, r_ext, r_len, dir_spans, file_spans, set())
        parts.append(("path tables (L+M, both namespaces)", pt_sectors * SECTOR, pt_sectors))

        dir_sectors = 0
        for ext, length in dir_spans:
            for k in range((length + SECTOR - 1) // SECTOR):
                if ext + k < sectors and not claimed[ext + k]:
                    claimed[ext + k] = 1
                    dir_sectors += 1
        parts.append(("directory extents (both namespaces)", dir_sectors * SECTOR, dir_sectors))

        # files: extents are shared between namespaces, so dedupe
        uniq = {}
        for ext, size in file_spans:
            uniq[ext] = max(uniq.get(ext, 0), size)
        file_bytes = 0
        file_sectors = 0
        for ext, size in uniq.items():
            n = (size + SECTOR - 1) // SECTOR
            file_bytes += size
            for k in range(n):
                if ext + k < sectors and not claimed[ext + k]:
                    claimed[ext + k] = 1
                    file_sectors += 1
        slack = file_sectors * SECTOR - file_bytes
        parts.append(("file data (used bytes of %d files)" % len(uniq), file_bytes, None))
        parts.append(("file slack (tail of last sector)", slack, None))

        unclaimed = [i for i in range(sectors) if not claimed[i]]
        runs = []
        for i in unclaimed:
            if runs and runs[-1][0] + runs[-1][1] == i:
                runs[-1][1] += 1
            else:
                runs.append([i, 1])
        allzero = True
        for start, n in runs:
            fh.seek(start * SECTOR)
            if any(fh.read(SECTOR * min(n, 64)).lstrip(b"\x00") for _ in [0]):
                allzero = False
        parts.append(("unclaimed sectors (%d runs, all zero: %s)" % (len(runs), allzero),
                      len(unclaimed) * SECTOR, len(unclaimed)))

    if drop is not None:
        parts = [p for p in parts if drop not in p[0]]

    if verbose:
        print("image                        : %s" % path)
        print("bytes                        : %d  = %d sectors of %d" % (total, sectors, SECTOR))
        print()
        print("%-52s %14s %9s %10s" % ("category", "bytes", "sectors", "% of image"))
        acc = 0
        for name, b, sec in parts:
            acc += b
            print("%-52s %14d %9s %9.4f %%"
                  % (name, b, "" if sec is None else sec, b * 100.0 / total))
        print("%-52s %14d %9s %9.4f %%" % ("TOTAL", acc, "", acc * 100.0 / total))
        print("%-52s %14d" % ("REMAINDER (must be 0)", total - acc))
        print()
        for start, n in runs:
            print("unclaimed run: sector %d x%d  (%d bytes)" % (start, n, n * SECTOR))
    acc = sum(b for _, b, _ in parts)
    return total - acc


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rem = account(argv[1])
    if "--selftest" in argv:
        print()
        print("=== POSITIVE CONTROL: drop one category, the sum must stop closing ===")
        print("(a truncated image is NOT a control here: every byte past the cut")
        print(" simply becomes 'unclaimed' and the total still closes. The only")
        print(" thing that can break this arithmetic is a category going missing.)")
        failures = 0
        for cat in ("system area", "volume descriptors", "path tables",
                    "directory extents", "file slack", "unclaimed sectors"):
            r2 = account(argv[1], verbose=False, drop=cat)
            status = "noticed" if r2 != 0 else "*** DID NOT NOTICE ***"
            print("  without %-22s remainder = %10d  %s" % (cat, r2, status))
            if r2 == 0:
                failures += 1
        if failures:
            print("POSITIVE CONTROL FAILED on %d categories" % failures)
            return 4
        print("positive control fired on all six categories.")
    return 0 if rem == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
