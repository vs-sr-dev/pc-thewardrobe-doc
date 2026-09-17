#!/usr/bin/env python3
"""hashdb.py -- read a GOG offline-installer `goggame-<id>.hashdb`.

This object arrived without `goggame-galaxyFileList.ini`, the manifest the
Galaxy client writes at install time and which defined yesterday's object. What
the offline installer leaves instead is `goggame-<id>.hashdb`: a ZIP holding a
single member of the same name, and that member is a flat table of fixed-width
records.

The format is not documented by GOG. It is derived here from the bytes, and the
derivation is printed so it can be argued with:

    u32  header size (12 on this sample)
    u32  version     (1 on this sample)
    u32  record count
    then `count` records of `(len - header) / count` bytes each, each record a
    NUL-padded name field followed by a fixed-width tail.

The tool refuses to guess: if `(len - header)` is not divisible by `count` it
says so and stops, rather than printing a plausible table.

    python tools/hashdb.py "<root>/goggame-1207665083.hashdb"
    python tools/hashdb.py "<root>/goggame-1207665083.hashdb" --list
    python tools/hashdb.py "<root>/goggame-1207665083.hashdb" --check --root "<root>"

`--check` walks the installation and reports, in both directions, what the table
declares and what the disk holds. `--hex N` dumps the tail of the first N
records so the 32 bytes after the name can be identified rather than assumed.
"""
import argparse
import collections
import hashlib
import os
import struct
import sys
import zipfile


def load(path):
    """Return (inner_name, blob) from the outer ZIP, or die loudly."""
    if not zipfile.is_zipfile(path):
        sys.exit("not a ZIP: %s" % path)
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != 1:
            sys.exit("expected exactly one member, found %d: %r" % (len(names), names))
        info = z.getinfo(names[0])
        blob = z.read(names[0])
    if len(blob) != info.file_size:
        sys.exit("inflated %d bytes, member declares %d" % (len(blob), info.file_size))
    return names[0], info, blob


HEX = set("0123456789abcdefABCDEF")


def header(blob):
    if len(blob) < 12:
        sys.exit("member is %d bytes, too short for a 12-byte header" % len(blob))
    hdr, ver, count = struct.unpack_from("<III", blob, 0)
    if hdr < 12 or hdr > len(blob) or count == 0:
        sys.exit("header does not read as (size=%d, version=%d, count=%d)" % (hdr, ver, count))
    return hdr, ver, count


def parse_narrow(blob, hdr, count):
    """MODE 1 -- the shape Trails in the Sky FC had.

    Constant stride, eight-bit name in a NUL-padded field, 32 hex characters
    of MD5 at offset 1024.  Refuses if the stride is not an integer.
    """
    body = len(blob) - hdr
    if body % count:
        return None, ("(%d - %d) = %d is not divisible by count %d -- the record "
                      "stride is not constant, or the header is not %d bytes"
                      % (len(blob), hdr, body, count, hdr))
    stride = body // count
    recs = []
    for i in range(count):
        off = hdr + i * stride
        rec = blob[off:off + stride]
        z = rec.find(b"\x00")
        name = rec[:z if z >= 0 else stride].decode("latin-1")
        namelen = len(name)
        tail_start = stride
        for j in range(stride - 1, namelen - 1, -1):
            if rec[j] != 0:
                tail_start = j + 1
                break
        digest = None
        t = rec[1024:]
        if len(t) == 32 and all(chr(c) in HEX for c in t):
            digest = t.decode("ascii").lower()
        recs.append((name, rec, namelen, tail_start, digest))
    return ("narrow", stride, recs), None


def parse_wide(blob, hdr, count):
    """MODE 2 -- the shape Broken Sword 3 has, derived here from the bytes.

    The name is UTF-16LE, NUL-terminated by one wide zero.  The MD5, still 32
    ASCII hex characters, sits immediately before the NEXT name, and the
    stride is NOT constant: it grows by one byte for every character in the
    name.  The rule, with n the name's length in characters, is

        name field   1024 + n bytes   (2n of name, the rest zero)
        digest field 32 bytes
        record       1056 + n bytes

    which is what a writer produces when it sizes a 1024-byte buffer for an
    eight-bit name and then writes the name into it as sixteen-bit.  There is
    no length prefix and no record index: the only way to walk the table is to
    read each name and add its length, so a single wrong name desynchronises
    everything after it.  That is why every record is checked: the 32 bytes at
    1024 + n must be hex, or the walk stops and says where.
    """
    recs = []
    off = hdr
    for i in range(count):
        j = off
        chars = []
        while j + 1 < len(blob):
            w = blob[j] | (blob[j + 1] << 8)
            if w == 0:
                break
            chars.append(chr(w))
            j += 2
        name = "".join(chars)
        n = len(name)
        if n == 0:
            return None, ("record %d at +%d has an empty name -- the walk has "
                          "desynchronised" % (i, off))
        dpos = off + 1024 + n
        if dpos + 32 > len(blob):
            return None, ("record %d at +%d wants its digest at +%d, past the "
                          "end of a %d-byte member" % (i, off, dpos, len(blob)))
        t = blob[dpos:dpos + 32]
        if not all(chr(c) in HEX for c in t):
            return None, ("record %d (%r) has no 32 hex characters at +%d "
                          "(1024 + %d): %r -- the +n rule is wrong"
                          % (i, name, dpos, n, t[:16]))
        rec = blob[off:dpos + 32]
        recs.append((name, rec, n, 1024 + n, t.decode("ascii").lower()))
        off = dpos + 32
    if off != len(blob):
        return None, ("%d records consumed %d bytes, the member is %d -- "
                      "%d bytes left over" % (count, off - hdr, len(blob), len(blob) - off))
    return ("wide", None, recs), None


def parse(blob, mode="auto"):
    hdr, ver, count = header(blob)
    tried = []
    for want, fn in (("narrow", parse_narrow), ("wide", parse_wide)):
        if mode not in ("auto", want):
            continue
        got, err = fn(blob, hdr, count)
        if got:
            return hdr, ver, count, got[0], got[1], got[2], tried
        tried.append((want, err))
    lines = ["no reading of this member closes:"]
    for want, err in tried:
        lines.append("   %-7s : %s" % (want, err))
    sys.exit("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--list", action="store_true", help="print every declared name")
    ap.add_argument("--hex", type=int, default=0, metavar="N",
                    help="hex-dump the non-name part of the first N records")
    ap.add_argument("--check", action="store_true", help="compare against a tree")
    ap.add_argument("--mode", default="auto", choices=("auto", "narrow", "wide"),
                    help="record shape: narrow (constant stride, 8-bit names) or wide (variable stride, UTF-16 names)")
    ap.add_argument("--root", default=None, help="installation root for --check")
    a = ap.parse_args()

    inner, info, blob = load(a.path)
    outer = os.path.getsize(a.path)
    print("outer file        : %s  %d bytes" % (os.path.basename(a.path), outer))
    print("members           : 1")
    print("inner name        : %s" % inner)
    print("inner size        : %d bytes  (deflated to %d, ratio %.4f)"
          % (info.file_size, info.compress_size, info.compress_size / float(info.file_size)))
    print("inner date        : %04d-%02d-%02d %02d:%02d:%02d (DOS, local)" % info.date_time)
    print("inner crc32       : %08x" % info.CRC)
    print()

    hdr, ver, count, mode, stride, recs, tried = parse(blob, a.mode)
    print("header            : %d bytes = u32 %d, u32 %d, u32 %d" % (12, hdr, ver, count))
    for want, err in tried:
        print("mode %-7s     : REFUSED -- %s" % (want, err))
    print("mode used         : %s" % mode)
    if mode == "narrow":
        print("records           : %d of %d bytes each" % (count, stride))
        print("arithmetic        : %d + %d x %d = %d   (file is %d)"
              % (hdr, count, stride, hdr + count * stride, len(blob)))
    else:
        widths = collections.Counter(len(r[1]) for r in recs)
        chars = sum(r[2] for r in recs)
        print("records           : %d, variable width, %d distinct widths %d..%d"
              % (count, len(widths), min(widths), max(widths)))
        print("rule              : record = 1024 + n + 32, n = name length in characters")
        print("arithmetic        : %d + %d x 1056 + %d characters = %d   (file is %d)"
              % (hdr, count, chars, hdr + count * 1056 + chars, len(blob)))
        print("bytes left over   : %d" % (len(blob) - (hdr + count * 1056 + chars)))
    print()

    # name field width: the highest offset at which any record has a name byte
    widest = max(r[2] for r in recs)
    tails = collections.Counter(r[3] for r in recs)
    print("longest name      : %d characters" % widest)
    print("last non-zero byte: %s"
          % ", ".join("%d x%d" % (k, v) for k, v in sorted(tails.items())))
    nz = [r for r in recs if r[3] > r[2] + 1]
    print("records with data after the name : %d of %d" % (len(nz), count))
    if nz:
        lo = min(r[3] for r in nz)
        hi = max(r[3] for r in nz)
        print("that data lives between offsets %d and %d" % (lo, hi))
    print()

    exts = collections.Counter(os.path.splitext(r[0])[1].lower() for r in recs)
    print("declared names by extension:")
    for e, n in exts.most_common():
        print("   %-10s %5d" % (e or "(none)", n))
    print()

    if a.hex:
        print("first %d records, everything after the name:" % a.hex)
        for name, rec, namelen, tail, digest in recs[:a.hex]:
            body = rec[namelen:]
            head = body[:64]
            print("   %-40s +%d" % (name, namelen))
            for k in range(0, len(head), 32):
                chunk = head[k:k + 32]
                print("        %04x  %s" % (namelen + k, chunk.hex(" ")))
        print()

    if a.list:
        for name, rec, namelen, tail, digest in recs:
            print("   %s" % name)
        print()

    # the 32 bytes at the end of the name field: narrow mode puts them at a
    # constant 1024, wide mode at 1024 + n, and parse_wide has already refused
    # to return records whose 32 bytes are not hex.
    digests = {}
    hexish = 0
    for name, rec, namelen, tail, digest in recs:
        if digest is None:
            continue
        hexish += 1
        digests[name.replace("\\", "/").lstrip("/").lower()] = digest
    print("records whose last 32 bytes are 32 hex characters : %d of %d"
          % (hexish, count))
    if hexish == count:
        print("   32 hex characters = 128 bits = MD5, RFC 1321")
    print()

    if a.check:
        if not a.root:
            sys.exit("--check needs --root")
        declared = set()
        for name, rec, namelen, tail, digest in recs:
            declared.add(name.replace("\\", "/").lstrip("/").lower())
        on_disk = {}
        for dirpath, dirnames, filenames in os.walk(a.root):
            dirnames.sort()
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, a.root).replace("\\", "/")
                on_disk[rel.lower()] = full
        both = declared & set(on_disk)
        only_decl = sorted(declared - set(on_disk))
        only_disk = sorted(set(on_disk) - declared)
        print("declared          : %d" % len(declared))
        print("on disk           : %d" % len(on_disk))
        print("declared and present : %d" % len(both))
        print("declared and ABSENT  : %d" % len(only_decl))
        for r in only_decl:
            print("      %s" % r)
        print("present and UNDECLARED : %d, %d bytes"
              % (len(only_disk), sum(os.path.getsize(on_disk[r]) for r in only_disk)))
        for r in only_disk:
            print("      %-44s %12d" % (r, os.path.getsize(on_disk[r])))
        print()
        print("declared bytes on disk : %d"
              % sum(os.path.getsize(on_disk[r]) for r in both))
        if digests:
            print()
            print("verifying the 32-hex field as MD5 against the files on disk:")
            ok = bad = 0
            worst = []
            for rel in sorted(both):
                h = hashlib.md5()
                with open(on_disk[rel], "rb") as fh:
                    while True:
                        chunk = fh.read(1 << 20)
                        if not chunk:
                            break
                        h.update(chunk)
                if h.hexdigest() == digests.get(rel):
                    ok += 1
                else:
                    bad += 1
                    if len(worst) < 20:
                        worst.append((rel, digests.get(rel), h.hexdigest()))
            print("   MD5 matches   : %d of %d" % (ok, len(both)))
            print("   MD5 mismatches: %d" % bad)
            for rel, want, got in worst:
                print("      %-40s declared %s  actual %s" % (rel, want, got))


if __name__ == "__main__":
    main()
