#!/usr/bin/env python3
"""mtarc.py -- reader for the MT Framework .arc container.

The layout is derived from the bytes, not from any published spec:

    +0   4    'ARC\\0'
    +4   u16  version
    +6   u16  entry count
    then <count> entries of 80 bytes:
    +0   64   name, NUL-padded, backslash-separated, no extension
    +64  u32  resource type hash
    +68  u32  compressed size
    +72  u32  uncompressed size and flags
    +76  u32  offset from start of file

Members are raw zlib streams.

--validate runs FIRST and must fail loudly on anything that is not an ARC.
--census only runs on files that validate.

Usage:
    mtarc.py --validate FILE...
    mtarc.py --census   FILE...
    mtarc.py --list     FILE
    mtarc.py --extract  FILE --out DIR [--only SUBSTRING]
"""
import argparse
import os
import struct
import sys
import zlib

MAGIC = b"ARC\x00"
ENTRY_SIZE = 80


class NotAnArc(Exception):
    pass


def read_header(data, path):
    if len(data) < 8:
        raise NotAnArc("%s: only %d bytes, cannot hold a header" % (path, len(data)))
    if data[:4] != MAGIC:
        raise NotAnArc("%s: magic is %r, not %r" % (path, data[:4], MAGIC))
    version, count = struct.unpack_from("<HH", data, 4)
    need = 8 + count * ENTRY_SIZE
    if need > len(data):
        raise NotAnArc(
            "%s: %d entries need %d bytes of table, file is %d"
            % (path, count, need, len(data))
        )
    return version, count


def read_entries(data, count):
    out = []
    for i in range(count):
        off = 8 + i * ENTRY_SIZE
        raw = data[off:off + 64]
        name = raw.split(b"\x00", 1)[0].decode("latin-1")
        thash, csize, usize_flags, doff = struct.unpack_from("<IIII", data, off + 64)
        out.append(
            {
                "index": i,
                "name": name,
                "type": thash,
                "csize": csize,
                "usize": usize_flags & 0x1FFFFFFF,
                "flags": usize_flags >> 29,
                "offset": doff,
            }
        )
    return out


def validate(path, verbose=True):
    """Return a dict of facts, or raise NotAnArc. Never silently passes."""
    with open(path, "rb") as fh:
        data = fh.read()
    version, count = read_header(data, path)
    entries = read_entries(data, count)
    size = len(data)

    problems = []
    end = 0
    for e in entries:
        if e["offset"] + e["csize"] > size:
            problems.append(
                "entry %d (%s) runs past end of file: %d+%d > %d"
                % (e["index"], e["name"], e["offset"], e["csize"], size)
            )
        end = max(end, e["offset"] + e["csize"])
    residue = size - end
    first = min((e["offset"] for e in entries), default=0)

    facts = {
        "path": path,
        "size": size,
        "version": version,
        "count": count,
        "entries": entries,
        "residue": residue,
        "first_offset": first,
        "problems": problems,
    }
    if verbose:
        status = "OK " if not problems else "BAD"
        print(
            "%s %-52s v%-2d entries=%-4d size=%-11d first=0x%X residue=%d"
            % (status, os.path.basename(path), version, count, size, first, residue)
        )
        for p in problems:
            print("      ! " + p)
    return facts


def census(paths):
    from collections import defaultdict

    by_type = defaultdict(lambda: {"n": 0, "c": 0, "u": 0})
    n_arc = n_entry = 0
    residue_zero = 0
    versions = defaultdict(int)
    total_c = total_u = 0
    for p in paths:
        f = validate(p, verbose=False)
        n_arc += 1
        n_entry += f["count"]
        versions[f["version"]] += 1
        if f["residue"] == 0:
            residue_zero += 1
        for e in f["entries"]:
            t = by_type[e["type"]]
            t["n"] += 1
            t["c"] += e["csize"]
            t["u"] += e["usize"]
            total_c += e["csize"]
            total_u += e["usize"]
    print("archives            %d" % n_arc)
    print("entries             %d" % n_entry)
    print("versions            %s" % dict(versions))
    print("residue==0          %d of %d" % (residue_zero, n_arc))
    print("distinct types      %d" % len(by_type))
    print("compressed total    %d" % total_c)
    print("uncompressed total  %d" % total_u)
    print()
    print("%-12s %8s %18s %18s" % ("type", "entries", "compressed", "uncompressed"))
    for t in sorted(by_type, key=lambda k: -by_type[k]["u"]):
        d = by_type[t]
        print("0x%08X   %8d %18d %18d" % (t, d["n"], d["c"], d["u"]))


def member_bytes(path, entry):
    with open(path, "rb") as fh:
        fh.seek(entry["offset"])
        blob = fh.read(entry["csize"])
    out = zlib.decompress(blob)
    if len(out) != entry["usize"]:
        raise ValueError(
            "%s: %s inflated to %d, header declared %d"
            % (path, entry["name"], len(out), entry["usize"])
        )
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--inflate-check", action="store_true")
    ap.add_argument("--hashes", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--only")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()

    if a.census:
        census(a.files)
        return 0

    rc = 0
    for path in a.files:
        try:
            f = validate(path, verbose=a.validate or a.list)
        except NotAnArc as exc:
            print("NOT-AN-ARC  %s" % exc)
            rc = 1
            continue
        if f["problems"]:
            rc = 1
        if a.list:
            for e in f["entries"]:
                print(
                    "  0x%08X %10d %10d 0x%08X  %s"
                    % (e["type"], e["csize"], e["usize"], e["offset"], e["name"])
                )
        if a.hashes:
            import hashlib
            for e in f["entries"]:
                blob = member_bytes(path, e)
                print("%s %10d %-12s 0x%08X %s"
                      % (hashlib.sha1(blob).hexdigest(), len(blob),
                         os.path.basename(path), e["type"], e["name"]))
        if a.inflate_check:
            ok = bad = 0
            for e in f["entries"]:
                try:
                    member_bytes(path, e)
                    ok += 1
                except Exception as exc:
                    bad += 1
                    print("  INFLATE-FAIL %s: %s" % (e["name"], exc))
            print("  inflate ok %d of %d" % (ok, ok + bad))
            if bad:
                rc = 1
        if a.extract:
            if not a.out:
                print("--extract needs --out")
                return 2
            for e in f["entries"]:
                if a.only and a.only not in e["name"]:
                    continue
                dest = os.path.join(a.out, e["name"].replace("\\", os.sep))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(member_bytes(path, e))
                print("  wrote %s (%d)" % (dest, e["usize"]))
    return rc


if __name__ == "__main__":
    sys.exit(main())
