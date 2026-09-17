#!/usr/bin/env python3
"""chpak.py -- Chromium's `.pak` resource container, walked and counted.

WHY THIS EXISTS, AND WHY THE BUCKET IS `decoded`
------------------------------------------------
`pc-rpgmaker2000-doc/docs/09` defined four buckets. `SPECIFIED` is a format
whose producer published a description of it. `DECODED` is a format that can be
read and whose producer published no description -- the bucket ITSF went into,
and it has been empty since `pc-rpgmaker2003-doc`.

Chromium's `.pak` is the first candidate in four objects, and the case has to be
argued rather than assumed, because it is not quite ITSF's:

  * Google publishes the READER -- `ui/base/resource/data_pack.cc` is open
    source, and the layout can be read off it;
  * Google publishes no SPECIFICATION. There is no numbered document, no
    versioned grammar, no statement of stability; the format's version field
    has gone 1, 2, 3, 4, 5 without any of the changes being described anywhere
    but in the diff;
  * third parties have written independent readers from that source.

**Published source is not a specification**, and the distinction is the one
this pipeline has been making since the 2000: a specification is a promise to
a reader, and source code is a description of one implementation at one commit.
A format read off an implementation is DECODED. That is the argument; docs/04
carries it, and this tool is what makes it a measurement and not an opinion.

THE FORMAT, AS READ OFF THE ARTEFACT
------------------------------------
Little-endian throughout.

    v4   u32 version(4) | u32 resource_count | u8 encoding
         then (resource_count + 1) x (u16 id, u32 offset)
    v5   u32 version(5) | u8 encoding | u8[3] padding
         | u16 resource_count | u16 alias_count
         then (resource_count + 1) x (u16 id, u32 offset)
         then alias_count x (u16 id, u16 entry_index)

The final entry of the index is a SENTINEL whose offset is the end of the last
resource and whose id is not a resource. Every resource's length is therefore
the difference between consecutive offsets, which is the property that makes
the walk a closure test: **the sentinel's offset must equal the file length**,
and the offsets must be non-decreasing.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**A closed index says nothing about what is inside the resources.** Every
payload here is an opaque byte string as far as this tool is concerned; it
counts them, sizes them and hashes them, and it does not claim to know that
resource 4029 is a string in Amharic. The census therefore reports the
resources' SHAPE -- how many, how big, how many are UTF-8-decodable -- and
never their meaning. `--selftest` asserts that a resource containing binary is
counted and reported as not-text rather than dropped, because a reader that
silently skips what it cannot read produces a census of its own competence.

    python tools/chpak.py validate rpgmakermv-steam/nwjs-lnx/locales/am.pak
    python tools/chpak.py census rpgmakermv-steam
    python tools/chpak.py show <file> --limit 20
    python tools/chpak.py --selftest
"""
import argparse
import collections
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage
import dirguard
import nameguard


class PakError(Exception):
    pass


def parse(blob, path="<bytes>"):
    """Return a dict describing one .pak, or raise PakError."""
    if len(blob) < 20:
        raise PakError("%s: %d bytes is shorter than any header" % (path,
                                                                   len(blob)))
    ver = struct.unpack_from("<I", blob, 0)[0]
    if ver == 5:
        enc = blob[4]
        pad = blob[5:8]
        nres, nali = struct.unpack_from("<HH", blob, 8)
        index = 12
        if pad != b"\x00\x00\x00":
            raise PakError("%s: v5 padding is %r and not three zero bytes"
                           % (path, pad))
    elif ver == 4:
        nres = struct.unpack_from("<I", blob, 4)[0]
        enc = blob[8]
        nali = 0
        index = 9
    else:
        raise PakError("%s: version %d is not 4 or 5" % (path, ver))
    if enc != 1:
        raise PakError("%s: encoding %d is not 1 (UTF-8)" % (path, enc))
    if nres == 0:
        raise PakError("%s: declares zero resources" % path)
    need = index + (nres + 1) * 6 + nali * 4
    if need > len(blob):
        raise PakError("%s: an index of %d entries and %d aliases needs %d "
                       "bytes and the file is %d" % (path, nres, nali, need,
                                                     len(blob)))
    entries = []
    for i in range(nres + 1):
        rid, off = struct.unpack_from("<HI", blob, index + i * 6)
        entries.append((rid, off))
    if entries[0][1] != need:
        raise PakError("%s: the first entry's offset is %d and the header "
                       "ends at %d" % (path, entries[0][1], need))
    for a, b in zip(entries, entries[1:]):
        if b[1] < a[1]:
            raise PakError("%s: offsets go backwards at id %d: %d then %d"
                           % (path, b[0], a[1], b[1]))
    if entries[-1][1] != len(blob):
        raise PakError("%s: the sentinel offset is %d and the file is %d "
                       "bytes -- the index does not close"
                       % (path, entries[-1][1], len(blob)))
    aliases = []
    abase = index + (nres + 1) * 6
    for i in range(nali):
        aid, idx = struct.unpack_from("<HH", blob, abase + i * 4)
        aliases.append((aid, idx))
        if idx > nres:
            raise PakError("%s: alias %d points at entry %d of %d"
                           % (path, aid, idx, nres))
    resources = [(entries[i][0], entries[i][1],
                  entries[i + 1][1] - entries[i][1]) for i in range(nres)]
    payload = sum(r[2] for r in resources)
    return dict(path=path, bytes=len(blob), version=ver, encoding=enc,
                resources=nres, aliases=nali, header=need,
                index_bytes=need - index, entries=entries,
                alias_list=aliases, resource_list=resources,
                payload_bytes=payload,
                residue=len(blob) - need - payload,
                duplicate_ids=nres + 1 - len({e[0] for e in entries}))


def read(path):
    dirguard.want_file(path, "chpak")
    with open(path, "rb") as fh:
        return parse(fh.read(), path)


def pak_files(root):
    """Every .pak under a root, SELECTED BY MAGIC -- which for this format is
    the header arithmetic and not a byte string, because there is no byte
    string to select on."""
    if os.path.isfile(root):
        return [root]
    out = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as fh:
                    head = fh.read(20)
            except OSError:
                continue
            if len(head) < 20:
                continue
            v = struct.unpack_from("<I", head, 0)[0]
            if v == 5 and head[4] == 1 and head[5:8] == b"\x00\x00\x00":
                nres, nali = struct.unpack_from("<HH", head, 8)
                if nres and struct.unpack_from("<I", head, 14)[0] == \
                        12 + (nres + 1) * 6 + nali * 4:
                    out.append(p)
            elif v == 4 and head[8] == 1:
                nres = struct.unpack_from("<I", head, 4)[0]
                if nres and struct.unpack_from("<I", head, 11)[0] == \
                        9 + (nres + 1) * 6:
                    out.append(p)
    return out


def cmd_validate(path):
    try:
        r = read(path)
    except PakError as e:
        print("REFUSED: %s" % e)
        return 1
    print("  bytes        : %d" % r["bytes"])
    print("  version      : %d   encoding %d (1 is UTF-8)"
          % (r["version"], r["encoding"]))
    print("  resources    : %d   aliases %d" % (r["resources"], r["aliases"]))
    print("  header+index : %d bytes" % r["header"])
    print("  payload      : %d bytes" % r["payload_bytes"])
    print("  %d + %d = %d, and the file is %d bytes, RESIDUE %d"
          % (r["header"], r["payload_bytes"], r["header"] + r["payload_bytes"],
             r["bytes"], r["residue"]))
    print("  the sentinel entry's offset IS the file length")
    return 0


def cmd_show(path, limit):
    r = read(path)
    with open(path, "rb") as fh:
        blob = fh.read()
    nameguard.guard()
    print("  %-8s %10s %9s  %s" % ("id", "offset", "length", "first bytes"))
    for rid, off, ln in r["resource_list"][:limit]:
        chunk = blob[off:off + min(ln, 48)]
        try:
            txt = chunk.decode("utf-8")
            shown = repr(txt)
        except UnicodeDecodeError:
            shown = chunk[:16].hex() + " (not UTF-8)"
        print("  %-8d %10d %9d  %s" % (rid, off, ln, nameguard.safe(shown)))
    print()
    print("  %d resources, %d shown" % (r["resources"], min(limit,
                                                            r["resources"])))
    return 0


def cmd_census(root):
    nameguard.guard()
    files = pak_files(root)
    if not files:
        sys.exit("chpak: no file under %r has a .pak header whose arithmetic "
                 "closes -- refusing to report a census over an empty "
                 "population" % root)
    vers = collections.Counter()
    vbytes = collections.Counter()
    closed = 0
    refused = []
    total_res = 0
    total_alias = 0
    total_payload = 0
    total_index = 0
    text = 0
    binary = 0
    inner = collections.Counter()
    sizes = []
    hashes = collections.Counter()
    dup_ids = 0
    for p in files:
        try:
            r = read(p)
        except PakError as e:
            refused.append(str(e))
            continue
        closed += 1
        vers[r["version"]] += 1
        vbytes[r["version"]] += r["bytes"]
        total_res += r["resources"]
        total_alias += r["aliases"]
        total_payload += r["payload_bytes"]
        total_index += r["index_bytes"]
        dup_ids += r["duplicate_ids"]
        with open(p, "rb") as fh:
            blob = fh.read()
        for _rid, off, ln in r["resource_list"]:
            sizes.append(ln)
            chunk = blob[off:off + ln]
            try:
                chunk.decode("utf-8")
                text += 1
            except UnicodeDecodeError:
                binary += 1
                inner[coverage.classify(chunk[:512])[1]] += 1
        hashes[hashlib.sha1(blob).hexdigest()] += 1
    print("files whose .pak header arithmetic closes : %d" % len(files))
    print("index walks that close on the last byte   : %d of %d"
          % (closed, len(files)))
    print()
    print("  by version : %s" % dict(vers))
    print("  bytes      : %s" % dict(vbytes))
    print("  total bytes: %d" % sum(vbytes.values()))
    print()
    print("  resources, summed  : %d" % total_res)
    print("  aliases,   summed  : %d" % total_alias)
    print("  index bytes        : %d" % total_index)
    print("  payload bytes      : %d" % total_payload)
    print("  index + payload    : %d over %d files"
          % (total_index + total_payload, closed))
    print("  duplicate ids inside one index : %d" % dup_ids)
    print()
    if sizes:
        sizes.sort()
        print("  resource sizes : min %d  median %d  max %d  mean %.1f"
              % (sizes[0], sizes[len(sizes) // 2], sizes[-1],
                 sum(sizes) / len(sizes)))
        print("  zero-length resources : %d" % sum(1 for s in sizes if not s))
    print("  resources that decode as UTF-8 : %d of %d"
          % (text, text + binary))
    print("  resources that do not          : %d" % binary)
    print("  and those, classified BY MAGIC with coverage.py's own table:")
    for name, c in inner.most_common(8):
        print("     %6d  %s" % (c, name))
    print()
    print("  distinct file sha1 : %d of %d" % (len(hashes), closed))
    top = hashes.most_common(1)
    if top:
        print("  the commonest byte string appears %d times" % top[0][1])
    print()
    print("  This census counts and sizes resources. It does not read them:")
    print("  what a resource MEANS is not in the container, and a tool that")
    print("  guessed would be reporting its own guess.")
    if refused:
        print()
        print("  REFUSED : %d" % len(refused))
        for e in refused[:10]:
            print("    %s" % e)
        return 1
    return 0


def selftest():
    checks, fails = [], 0

    def ck(name, ok, note=""):
        nonlocal fails
        checks.append((name, ok, note))
        if not ok:
            fails += 1

    def build_v5(payloads, aliases=()):
        n = len(payloads)
        head = struct.pack("<IB3sHH", 5, 1, b"\x00\x00\x00", n, len(aliases))
        base = 12 + (n + 1) * 6 + len(aliases) * 4
        idx = b""
        off = base
        for i, p in enumerate(payloads):
            idx += struct.pack("<HI", 400 + i, off)
            off += len(p)
        idx += struct.pack("<HI", 0, off)
        al = b"".join(struct.pack("<HH", 900 + i, j) for i, j in aliases)
        return head + idx + al + b"".join(payloads)

    def build_v4(payloads):
        n = len(payloads)
        head = struct.pack("<IIB", 4, n, 1)
        base = 9 + (n + 1) * 6
        idx = b""
        off = base
        for i, p in enumerate(payloads):
            idx += struct.pack("<HI", 400 + i, off)
            off += len(p)
        idx += struct.pack("<HI", 0, off)
        return head + idx + b"".join(payloads)

    good5 = build_v5([b"hello", b"world!!", b"\xff\xfe\x00binary"],
                     aliases=((0,), )[0:0] or ((0, 1), ))
    r = parse(good5, "<v5>")
    ck("a v5 index closes on the last byte", r["residue"] == 0)
    ck("its resource and alias counts are read",
       (r["resources"], r["aliases"]) == (3, 1))
    ck("resource lengths come from consecutive offsets",
       [x[2] for x in r["resource_list"]] == [5, 7, 9],
       str([x[2] for x in r["resource_list"]]))
    ck("the payload sums to the file minus the header",
       r["payload_bytes"] + r["header"] == r["bytes"])

    r4 = parse(build_v4([b"abc", b"defg"]), "<v4>")
    ck("a v4 index closes too", r4["residue"] == 0 and r4["version"] == 4)
    ck("v4 has no aliases", r4["aliases"] == 0)

    def refuses(blob, why):
        try:
            parse(blob, "<t>")
        except PakError:
            return True
        return False

    ck("a version other than 4 or 5 is REFUSED",
       refuses(struct.pack("<I", 3) + bytes(40), ""))
    ck("an encoding other than 1 is REFUSED",
       refuses(struct.pack("<IB3sHH", 5, 2, b"\x00\x00\x00", 1, 0)
               + bytes(40), ""))
    ck("non-zero v5 padding is REFUSED",
       refuses(struct.pack("<IB3sHH", 5, 1, b"\x01\x00\x00", 1, 0)
               + bytes(40), ""))
    ck("zero resources is REFUSED",
       refuses(struct.pack("<IB3sHH", 5, 1, b"\x00\x00\x00", 0, 0)
               + bytes(40), ""))
    bad = bytearray(good5)
    bad[-1:] = b""
    ck("THE CLOSURE TEST: one byte short and the sentinel no longer matches",
       refuses(bytes(bad), ""), "this is the whole check")
    bad2 = bytearray(good5)
    struct.pack_into("<I", bad2, 12 + 2, 999999)
    ck("a first offset that is not the end of the header is REFUSED",
       refuses(bytes(bad2), ""))
    bad3 = bytearray(good5)
    struct.pack_into("<I", bad3, 12 + 6 + 2, 12)     # second offset backwards
    ck("offsets that go backwards are REFUSED", refuses(bytes(bad3), ""))
    ck("a file too short for its own index is REFUSED",
       refuses(struct.pack("<IB3sHH", 5, 1, b"\x00\x00\x00", 500, 0)
               + bytes(40), ""))

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.pak"), "wb") as fh:
            fh.write(good5)
        with open(os.path.join(d, "b.dat"), "wb") as fh:
            fh.write(build_v4([b"x" * 10]))
        with open(os.path.join(d, "lie.pak"), "wb") as fh:
            fh.write(b"\x05\x00\x00\x00" + bytes(40))
        found = sorted(os.path.basename(x) for x in pak_files(d))
        ck("selection is by the header arithmetic, not by extension",
           found == ["a.pak", "b.dat"], str(found))
        ck("a file named .pak whose arithmetic fails is not selected",
           "lie.pak" not in found)

        # THE BLIND SPOT: a binary resource is counted, not dropped
        r5 = parse(good5, "<v5>")
        with open(os.path.join(d, "a.pak"), "rb") as fh:
            blob = fh.read()
        nontext = 0
        for _rid, off, ln in r5["resource_list"]:
            try:
                blob[off:off + ln].decode("utf-8")
            except UnicodeDecodeError:
                nontext += 1
        ck("THE BLIND SPOT: a resource that is not UTF-8 is COUNTED and "
           "reported, not skipped", nontext == 1,
           "a reader that skipped it would census its own competence")

        code = 0
        try:
            read(d)
        except SystemExit:
            code = 1
        ck("handed a directory it refuses through dirguard", code == 1)

        empty = os.path.join(d, "e")
        os.makedirs(empty)
        code = 0
        try:
            cmd_census(empty)
        except SystemExit:
            code = 1
        ck("a census over an empty population is REFUSED", code == 1)

    width = max(len(c[0]) for c in checks)
    for name, ok, note in checks:
        print("  %-*s  %s   %s" % (width, name, "ok  " if ok else "FAIL", note))
    print()
    print("%d checks, %d failures" % (len(checks), fails))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?",
                    choices=["validate", "show", "census", "selftest"])
    ap.add_argument("path", nargs="?")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.cmd == "selftest":
        return selftest()
    if not args.cmd:
        ap.error("one of validate, show, census, selftest is required")
    if not args.path:
        ap.error("%s needs a path" % args.cmd)
    if args.cmd == "validate":
        return cmd_validate(args.path)
    if args.cmd == "show":
        return cmd_show(args.path, args.limit)
    return cmd_census(args.path)


if __name__ == "__main__":
    sys.exit(main())
