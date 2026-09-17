#!/usr/bin/env python3
r"""drpk.py -- read the DRPK container of *Inquisitor* (Wooden Croc / CINEMAX).

The format was derived from the bytes of `01_audio_weapons.dat` in this
session; there is no prior art for it anywhere in this collection and no
public specification is known to the author.

    +0   4   'DRPK'                     -- plaintext, NOT obfuscated
    +4   2   u16 version, always 0      -- plaintext
    +6   .   member payloads, laid end to end, no padding
    ...      entry table, count*24 bytes
    ...      directory table, NUL-terminated directory names
    ...      name table, NUL-terminated leaf names, one per member
    -16  4   u32 member count
    -12  4   u32 directory table length
    -8   4   u32 name table length
    -4   4   u32 largest unpacked member size

**Everything from offset 6 to the end of the file is XOR 0x4A.** The six-byte
header is not. That is why `DRPK` is legible in a hex dump and nothing else
is, and it is why 0x4A ('J') is the most common byte in all twenty-two files:
0x4A is what a run of zero bytes becomes.

Each entry is six little-endian uint32:

    +0   u32  dir offset   -- into the DIRECTORY table, not a flag word
    +4   u32  name offset  -- into the name table
    +8   u32  size         -- the member's size when unpacked
    +12  u32  stored       -- the member's size inside the container
    +16  u32  offset       -- from the start of the FILE, so member 0 is at 6
    +20  u32  first block  -- stored size of the member's first block

The +0 field was called `flags` in this tool's first version, because all
twenty-two members of `01_audio_weapons.dat` carry 0 there. That container has
exactly one directory, `audio\Weapons`, so the offset of its name is zero. The
census over all twenty-two printed several hundred distinct values and the
reading collapsed: `01_img_ui.dat` names 116 directories over 9,508 members
and the field indexes them. **A field that is constant on the one specimen you
derived from is not a field you have read.**

THE CLOSURE TEST IS THE POINT. `offset[k] + stored[k] == offset[k+1]` for
every member, `offset[0] == 6`, and `offset[n-1] + stored[n-1]` must equal the
byte at which the entry table begins. A container that does not close to the
byte is reported as NOT OPEN with its residue printed, and the exit status is
2. A plausible read is not a read.

    python tools/drpk.py validate <file.dat> [...]
    python tools/drpk.py census   <dir-or-files...> [--csv out.csv]
    python tools/drpk.py list     <file.dat>
    python tools/drpk.py selftest
"""
import argparse
import hashlib
import os
import struct
import sys
import time

MAGIC = b"DRPK"
KEY = 0x4A
HEADER = 6
ENTRY = 24
TRAILER = 16


class NotDRPK(Exception):
    pass


class NotClosed(Exception):
    pass


def deobfuscate(buf, start):
    """XOR everything from `start` onward. The header is left alone."""
    out = bytearray(buf)
    for i in range(start, len(out)):
        out[i] ^= KEY
    return bytes(out)


def read_container(path):
    size = os.path.getsize(path)
    if size < HEADER + TRAILER:
        raise NotDRPK("%s: %d bytes is shorter than a header plus a trailer"
                      % (os.path.basename(path), size))
    with open(path, "rb") as fh:
        head = fh.read(HEADER)
        if head[:4] != MAGIC:
            raise NotDRPK("%s: magic is %r, not %r"
                          % (os.path.basename(path), head[:4], MAGIC))
        version = struct.unpack_from("<H", head, 4)[0]
        # The tail is read alone: the payload is up to 444 MB and is never
        # needed to walk the directory.
        fh.seek(-TRAILER, os.SEEK_END)
        trailer = bytes(c ^ KEY for c in fh.read(TRAILER))
        count, prefix_len, name_len, biggest = struct.unpack("<4I", trailer)

        if count == 0:
            raise NotDRPK("%s: member count is zero" % os.path.basename(path))
        tail_len = count * ENTRY + prefix_len + name_len + TRAILER
        if tail_len > size:
            raise NotDRPK(
                "%s: trailer claims %d bytes of directory in a %d-byte file"
                % (os.path.basename(path), tail_len, size))
        table_at = size - tail_len
        fh.seek(table_at)
        tail = bytes(c ^ KEY for c in fh.read(tail_len))

    dirs_blob = tail[count * ENTRY:count * ENTRY + prefix_len]
    names_blob = tail[count * ENTRY + prefix_len:
                      count * ENTRY + prefix_len + name_len]
    if dirs_blob and dirs_blob[-1] != 0:
        raise NotDRPK("%s: directory table is not NUL-terminated"
                      % os.path.basename(path))
    if names_blob and names_blob[-1] != 0:
        raise NotDRPK("%s: name table is not NUL-terminated"
                      % os.path.basename(path))

    members = []
    for k in range(count):
        dir_off, name_off, usize, stored, offset, first = struct.unpack_from(
            "<6I", tail, k * ENTRY)
        if dir_off >= max(prefix_len, 1):
            raise NotDRPK("%s: member %d directory offset %d is past the "
                          "%d-byte directory table"
                          % (os.path.basename(path), k, dir_off, prefix_len))
        if name_off >= name_len:
            raise NotDRPK("%s: member %d name offset %d is past the %d-byte "
                          "name table" % (os.path.basename(path), k,
                                          name_off, name_len))
        end = names_blob.index(b"\x00", name_off)
        leaf = names_blob[name_off:end].decode("latin-1")
        if dirs_blob:
            folder = dirs_blob[dir_off:dirs_blob.index(b"\x00", dir_off)]
            folder = folder.decode("latin-1")
        else:
            folder = ""
        members.append({
            "index": k, "dir_off": dir_off, "name_off": name_off,
            "size": usize, "stored": stored, "offset": offset,
            "first_block": first, "dir": folder, "name": leaf,
            "path": (folder + os.sep + leaf) if folder else leaf,
        })
    dir_names = ([d.decode("latin-1") for d in dirs_blob.split(b"\x00")[:-1]]
                 if dirs_blob else [])
    return {
        "path": path, "file_size": size, "version": version,
        "count": count, "dir_len": prefix_len, "dirs": dir_names,
        "name_len": name_len, "biggest": biggest,
        "table_at": table_at, "tail_len": tail_len, "members": members,
    }


BLOCK_MAX = 32751          # largest `len` field seen over all 112,752 members
STORED = 0x80
PACKED = 0x40
WINDOW = 4096


class NotUnpacked(Exception):
    pass


def unpack_block(payload, out):
    r"""LZSS, 4096-byte ring, 12-bit offset and 4-bit length, appended to `out`.

    The control word is two bytes and its bits are taken MSB-first within byte
    0 and then MSB-first within byte 1 -- sixteen items. A 0 bit is one literal
    byte. A 1 bit is a two-byte match token read BIG-ENDIAN:

        offset = token >> 4          (12 bits)
        length = (token & 0x0F) + 3  (3 .. 18)

    `offset` is a distance into a 4096-byte ring initialised to zero, and
    **offset 0 means distance 4096**, not distance zero. While fewer than 4096
    bytes have been produced that reads unwritten ring cells and emits zeros --
    which is how the encoder writes the 4,044-byte `FLLR` padding chunk of a
    Sound Forge WAV -- but after the ring has filled once it reads real data.

    Both of those were wrong in earlier versions of this function and both were
    caught by the length check in `unpack_member`, not by inspection: treating
    offset 0 as an error raised IndexError on the second token of the first
    member, and treating it as a zero run left every WAV between 1,399 and
    9,700 bytes short.
    """
    i, n = 0, len(payload)
    while i + 2 <= n:
        w0, w1 = payload[i], payload[i + 1]
        i += 2
        for k in range(16):
            if i >= n:
                break
            bit = (w0 >> (7 - k)) & 1 if k < 8 else (w1 >> (15 - k)) & 1
            if not bit:
                out.append(payload[i])
                i += 1
            else:
                if i + 2 > n:
                    raise NotUnpacked("match token truncated")
                token = (payload[i] << 8) | payload[i + 1]
                i += 2
                off, length = token >> 4, (token & 0x0F) + 3
                off = off or WINDOW
                start = len(out) - off
                for _ in range(length):
                    out.append(out[start] if start >= 0 else 0)
                    start += 1


def unpack_member(fh, m):
    """Return the member's bytes, or raise. The length is checked here."""
    fh.seek(m["offset"])
    d = bytes(c ^ KEY for c in fh.read(m["stored"]))
    out = bytearray()
    p, end = 0, len(d) - 2
    while p < end:
        ln = struct.unpack_from("<H", d, p)[0]
        flag = d[p + 2]
        payload = d[p + 3:p + 2 + ln]
        if flag == STORED:
            out += payload
        elif flag == PACKED:
            unpack_block(payload, out)
        else:
            raise NotUnpacked("block flag 0x%02X at %d" % (flag, p))
        p += 2 + ln
    if len(out) != m["size"]:
        raise NotUnpacked("%s unpacked to %d bytes, the entry says %d "
                          "-- residue %+d"
                          % (m["name"], len(out), m["size"],
                             len(out) - m["size"]))
    return bytes(out)


def close_or_raise(c):
    """The residue test. Loud failure is the whole reason this exists."""
    ms = c["members"]
    where = HEADER
    for m in ms:
        if m["offset"] != where:
            raise NotClosed(
                "%s: member %d (%s) starts at %d, expected %d -- residue %+d"
                % (os.path.basename(c["path"]), m["index"], m["name"],
                   m["offset"], where, m["offset"] - where))
        where += m["stored"]
    residue = c["table_at"] - where
    if residue != 0:
        raise NotClosed(
            "%s: payload ends at %d, entry table begins at %d -- residue %+d"
            % (os.path.basename(c["path"]), where, c["table_at"], residue))
    return where


def account(c):
    """Every byte of the file placed in exactly one bucket."""
    payload = sum(m["stored"] for m in c["members"])
    return [
        ("header", HEADER),
        ("member payloads", payload),
        ("entry table", c["count"] * ENTRY),
        ("directory table", c["dir_len"]),
        ("name table", c["name_len"]),
        ("trailer", TRAILER),
    ]


def cmd_validate(paths):
    bad = 0
    for p in paths:
        try:
            c = read_container(p)
            close_or_raise(c)
        except (NotDRPK, NotClosed) as exc:
            print("  REFUSED  %s" % exc)
            bad += 1
            continue
        buckets = account(c)
        total = sum(v for _, v in buckets)
        print("  OK       %-26s %12d bytes, %6d members, residue 0"
              % (os.path.basename(p), c["file_size"], c["count"]))
        for name, v in buckets:
            print("             %-18s %12d" % (name, v))
        print("             %-18s %12d   %s"
              % ("accounted", total,
                 "== file size" if total == c["file_size"] else "MISMATCH"))
        if total != c["file_size"]:
            bad += 1
    return bad


def cmd_list(path):
    c = read_container(path)
    close_or_raise(c)
    print("%s  version %d  %d members  %d directories"
          % (os.path.basename(path), c["version"], c["count"], len(c["dirs"])))
    print("  %5s %12s %12s %10s %s"
          % ("idx", "offset", "stored", "unpacked", "path"))
    for m in c["members"]:
        print("  %5d %12d %12d %10d %s"
              % (m["index"], m["offset"], m["stored"], m["size"], m["path"]))


def walk(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.lower().endswith(".dat"):
                        out.append(os.path.join(root, f))
        else:
            out.append(p)
    return out


def cmd_census(paths, csv_path=None):
    files = walk(paths)
    if not files:
        print("drpk: empty population -- nothing to census", file=sys.stderr)
        return 3
    opened, refused, failed = [], [], []
    for p in files:
        try:
            c = read_container(p)
        except NotDRPK as exc:
            refused.append((p, str(exc)))
            continue
        try:
            close_or_raise(c)
        except NotClosed as exc:
            failed.append((p, str(exc)))
            continue
        opened.append(c)

    print("=== DRPK census ===")
    print("files offered            : %d" % len(files))
    print("refused (not DRPK)       : %d" % len(refused))
    print("opened but did NOT close : %d" % len(failed))
    print("opened, residue 0        : %d" % len(opened))
    for p, why in refused:
        print("  refused: %s" % why)
    for p, why in failed:
        print("  NOT OPEN: %s" % why)
    if not opened:
        return 2 if failed else 3

    print()
    print("%-26s %13s %7s %14s %14s %6s"
          % ("container", "bytes", "members", "stored", "unpacked", "pct"))
    tm = tb = ts = tu = 0
    for c in sorted(opened, key=lambda c: -c["file_size"]):
        st = sum(m["stored"] for m in c["members"])
        us = sum(m["size"] for m in c["members"])
        tm += c["count"]; tb += c["file_size"]; ts += st; tu += us
        print("%-26s %13d %7d %14d %14d %5.1f%%"
              % (os.path.basename(c["path"]), c["file_size"], c["count"],
                 st, us, 100.0 * st / us if us else 0.0))
    print("%-26s %13d %7d %14d %14d %5.1f%%"
          % ("TOTAL", tb, tm, ts, tu, 100.0 * ts / tu if tu else 0.0))

    stored_members = sum(1 for c in opened for m in c["members"]
                         if m["stored"] == m["size"])
    print()
    print("members whose stored size equals their unpacked size : %d of %d"
          % (stored_members, tm))
    print("directories named across the containers              : %d"
          % sum(len(c["dirs"]) for c in opened))
    print("distinct full member paths                           : %d"
          % len({m["path"] for c in opened for m in c["members"]}))

    if csv_path:
        with open(csv_path, "w", encoding="utf-8", newline="") as fh:
            fh.write("container,index,dir,name,offset,stored,size,"
                     "first_block\n")
            for c in opened:
                base = os.path.basename(c["path"])
                for m in c["members"]:
                    fh.write('%s,%d,"%s","%s",%d,%d,%d,%d\n'
                             % (base, m["index"], m["dir"], m["name"],
                                m["offset"], m["stored"], m["size"],
                                m["first_block"]))
        print("\nwrote %s" % csv_path)
    return 0


def cmd_unpack(paths, out_dir, limit=None, sha=False):
    """Unpack every member and check its length against its own entry.

    This is the SECOND closure test. The first says the container's bytes are
    all accounted for; this one says every member's unpacked length is the one
    the directory declares. A member that comes out one byte short is not
    unpacked, and it is reported with its residue.
    """
    files = walk(paths)
    if not files:
        print("drpk: empty population -- nothing to unpack", file=sys.stderr)
        return 3
    tot = ok = bad = 0
    tot_bytes = 0
    digests = {}
    t0 = time.time()
    for p in files:
        try:
            c = read_container(p)
            close_or_raise(c)
        except (NotDRPK, NotClosed) as exc:
            print("  skipped: %s" % exc)
            continue
        base = os.path.basename(p)
        nb = nok = 0
        with open(p, "rb") as fh:
            for m in c["members"]:
                if limit and tot >= limit:
                    break
                tot += 1
                nb += 1
                try:
                    blob = unpack_member(fh, m)
                except NotUnpacked as exc:
                    bad += 1
                    print("  NOT UNPACKED %s :: %s" % (base, exc))
                    continue
                ok += 1
                nok += 1
                tot_bytes += len(blob)
                if sha:
                    digests.setdefault(
                        hashlib.sha1(blob).hexdigest(), []).append(
                            (base, m["path"], len(blob)))
                if out_dir:
                    dest = os.path.join(out_dir, base.replace(".dat", ""),
                                        m["dir"].replace("\\", os.sep),
                                        m["name"])
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as o:
                        o.write(blob)
        print("  %-26s %6d of %6d members unpacked to their declared length"
              % (base, nok, nb))
    print()
    print("members unpacked        : %d of %d" % (ok, tot))
    print("length residue non-zero : %d" % bad)
    print("bytes produced          : %d" % tot_bytes)
    print("elapsed                 : %.1f s" % (time.time() - t0))
    if sha:
        dups = {k: v for k, v in digests.items() if len(v) > 1}
        dup_members = sum(len(v) for v in dups.values())
        dup_bytes = sum(v[0][2] * (len(v) - 1) for v in dups.values())
        print()
        print("distinct sha1 over members : %d of %d" % (len(digests), ok))
        print("members in a repeated group: %d" % dup_members)
        print("redundant bytes            : %d of %d = %.4f %%"
              % (dup_bytes, tot_bytes,
                 100.0 * dup_bytes / tot_bytes if tot_bytes else 0.0))
    return 2 if bad else 0


def cmd_selftest():
    """Four guards, each tripped on its own, on bytes built here.

    A validator that has never been shown a failure is a validator nobody has
    tested. Every case below MUST be refused.
    """
    import tempfile
    cases = []

    def make(name, blob):
        fh = tempfile.NamedTemporaryFile(suffix=".dat", delete=False)
        fh.write(blob)
        fh.close()
        cases.append((name, fh.name))

    def container(members, prefix=b"x\x00", corrupt=None):
        payload = b"".join(d for _, d in members)
        names = b"".join(n + b"\x00" for n, _ in members)
        table = b""
        off = HEADER
        noff = 0
        for n, d in members:
            table += struct.pack("<6I", 0, noff, len(d), len(d), off, len(d))
            off += len(d)
            noff += len(n) + 1
        trailer = struct.pack("<4I", len(members), len(prefix), len(names),
                              max(len(d) for _, d in members))
        body = payload + table + prefix + names + trailer
        if corrupt:
            body = corrupt(body)
        return MAGIC + struct.pack("<H", 0) + bytes(c ^ KEY for c in body)

    good = [(b"a.wav", b"\x01" * 100), (b"b.wav", b"\x02" * 50)]
    make("a good container (must be accepted)", container(good))
    make("wrong magic", b"XXXX" + container(good)[4:])
    make("truncated to a stub", MAGIC + b"\x00\x00" + b"\x00" * 8)
    # a hole: member 1's offset moved four bytes forward
    def hole(body):
        b = bytearray(body)
        base = 150  # payload length
        off_field = base + ENTRY + 16
        cur = struct.unpack_from("<I", b, off_field)[0]
        struct.pack_into("<I", b, off_field, cur + 4)
        return bytes(b)
    make("a four-byte hole between two members", container(good, corrupt=hole))
    # a trailer that claims more directory than the file holds
    def fat(body):
        b = bytearray(body)
        struct.pack_into("<I", b, len(b) - TRAILER, 100000)
        return bytes(b)
    make("a trailer claiming 100000 members", container(good, corrupt=fat))

    ok = True
    for i, (label, path) in enumerate(cases):
        must_pass = (i == 0)
        try:
            c = read_container(path)
            close_or_raise(c)
            verdict, passed = "accepted", True
        except (NotDRPK, NotClosed) as exc:
            verdict, passed = "REFUSED (%s)" % str(exc).split(": ", 1)[-1], False
        good_result = (passed == must_pass)
        ok = ok and good_result
        print("  [%s] %-44s -> %s"
              % ("ok" if good_result else "FAIL", label, verdict))
        os.unlink(path)
    print("selftest: %s" % ("all five guards behave" if ok else "FAILED"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("validate"); p.add_argument("paths", nargs="+")
    p = sub.add_parser("list"); p.add_argument("path")
    p = sub.add_parser("census")
    p.add_argument("paths", nargs="+"); p.add_argument("--csv")
    p = sub.add_parser("unpack")
    p.add_argument("paths", nargs="+")
    p.add_argument("--out")
    p.add_argument("--limit", type=int)
    p.add_argument("--sha1", action="store_true")
    sub.add_parser("selftest")
    args = ap.parse_args()

    if args.cmd == "validate":
        return 2 if cmd_validate(args.paths) else 0
    if args.cmd == "list":
        cmd_list(args.path); return 0
    if args.cmd == "census":
        return cmd_census(args.paths, args.csv)
    if args.cmd == "unpack":
        return cmd_unpack(args.paths, args.out, args.limit, args.sha1)
    if args.cmd == "selftest":
        return cmd_selftest()
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
