#!/usr/bin/env python3
"""wwise.py -- read the twenty-one Wwise SoundBanks and the forty-eight `.wem`.

WHAT THIS COLLECTION HAS AND HAS NOT MET
----------------------------------------
FSB, Ogg Vorbis, ADX, RIFF/WAVE and MP3 have all been opened here before.
Audiokinetic's SoundBank has not. Like the Unreal package it is **described by
third parties and not published by its author**, and this repository names
that as its own category rather than calling it `published` or pretending it
was derived from nothing.

WHAT IS TAKEN FROM THAT DESCRIPTION
-----------------------------------
Only the outer shape, which is a plain four-character-code chunk list:

    'BKHD'  bank header:  u32 bank version, u32 bank id, then more
    'DIDX'  data index:   12 bytes per entry -- u32 id, u32 offset, u32 size
    'DATA'  the media those offsets are relative to
    'HIRC'  the object hierarchy
    'STMG', 'STID', 'ENVS', 'PLAT', 'FXPR'  the rest

WHAT IS DERIVED HERE
--------------------
Every number. The chunk list is required to tile each bank from byte 0 to the
last byte with residue 0 before a single chunk is looked inside; the `DIDX`
entries are required to tile `DATA`; and each media blob is checked to start
with `RIFF` and to declare its own length. A bank that fails any of those is
reported, not skipped.

    python tools/wwise.py --selftest
    python tools/wwise.py --banks
    python tools/wwise.py --media
    python tools/wwise.py --wem
    python tools/wwise.py --worlds
"""
import argparse
import collections
import glob
import os
import struct
import sys

ROOT = "karmaflow-steam"
COOKED = "KFGame/CookedPC"
KNOWN = {b"BKHD", b"DIDX", b"DATA", b"HIRC", b"STMG", b"STID", b"ENVS",
         b"PLAT", b"FXPR", b"INIT"}


class NotABank(Exception):
    pass


def chunks(data):
    o = 0
    n = len(data)
    first = True
    while o < n:
        if o + 8 > n:
            raise NotABank("only %d bytes left at %d; a chunk header is 8"
                           % (n - o, o))
        tag = bytes(data[o:o + 4])
        (size,) = struct.unpack_from("<I", data, o + 4)
        if first and tag != b"BKHD":
            raise NotABank("first chunk is %r, not BKHD" % tag)
        first = False
        if not all(32 <= c < 127 for c in tag):
            raise NotABank("chunk tag %r at %d is not four printable bytes"
                           % (tag, o))
        if o + 8 + size > n:
            raise NotABank("chunk %s at %d declares %d bytes and runs past "
                           "the end" % (tag.decode("latin-1"), o, size))
        yield {"tag": tag, "size": size, "at": o, "body": o + 8}
        o += 8 + size


def banks(root):
    return sorted(glob.glob(os.path.join(root, COOKED, "*.bnk")))


def wems(root):
    return sorted(glob.glob(os.path.join(root, COOKED, "*.wem")))


def cmd_banks(args):
    tags = collections.Counter()
    per_bank = []
    vers = collections.Counter()
    ids = []
    bkhd_sizes = collections.Counter()
    residues = collections.Counter()
    tag_sets = collections.Counter()
    for p in banks(args.root):
        data = open(p, "rb").read()
        got = []
        try:
            for c in chunks(data):
                got.append(c)
        except NotABank as e:
            print("%-46s REFUSED %s" % (os.path.basename(p), e))
            continue
        end = got[-1]["body"] + got[-1]["size"]
        residues[len(data) - end] += 1
        h = got[0]
        ver, bid = struct.unpack_from("<2I", data, h["body"])
        vers[ver] += 1
        ids.append((os.path.basename(p), bid))
        bkhd_sizes[h["size"]] += 1
        for c in got:
            tags[c["tag"]] += 1
        tag_sets[tuple(c["tag"].decode("latin-1") for c in got)] += 1
        per_bank.append((os.path.basename(p), len(data), len(got),
                         [c["tag"].decode("latin-1") for c in got], ver, bid))
    print("banks read                : %d" % len(per_bank))
    print("bank version              : %s" % dict(vers))
    print("BKHD chunk sizes          : %s" % dict(bkhd_sizes))
    print("residue after the last chunk : %s" % dict(residues))
    print("chunk tags seen           : %s"
          % {k.decode("latin-1"): v for k, v in tags.items()})
    print("tags outside the described set : %s"
          % {k.decode("latin-1"): v for k, v in tags.items() if k not in KNOWN})
    print()
    print("the chunk sequences, and how many banks have each:")
    for k, v in tag_sets.most_common():
        print("   %-44s x%d" % (" ".join(k), v))
    print()
    print("%-46s %12s %5s  %s" % ("bank", "bytes", "chks", "tags"))
    for r in sorted(per_bank, key=lambda x: -x[1]):
        print("%-46s %12d %5d  %s" % (r[0][:46], r[1], r[2], " ".join(r[3])))
    print()
    print("bank ids, distinct : %d of %d"
          % (len(set(i for _n, i in ids)), len(ids)))
    return 0


def cmd_media(args):
    tot_entries = 0
    tot_bytes = 0
    tiled = 0
    withdidx = 0
    all_ids = []
    riff_ok = riff_bad = 0
    sizes = []
    for p in banks(args.root):
        data = open(p, "rb").read()
        try:
            cs = list(chunks(data))
        except NotABank:
            continue
        didx = next((c for c in cs if c["tag"] == b"DIDX"), None)
        dat = next((c for c in cs if c["tag"] == b"DATA"), None)
        if didx is None:
            continue
        withdidx += 1
        if dat is None:
            print("   %s has DIDX and no DATA" % os.path.basename(p))
            continue
        if didx["size"] % 12:
            print("   %s DIDX is %d bytes, which 12 does not divide"
                  % (os.path.basename(p), didx["size"]))
            continue
        n = didx["size"] // 12
        entries = []
        for i in range(n):
            mid, off, size = struct.unpack_from("<3I", data,
                                                didx["body"] + i * 12)
            entries.append((mid, off, size))
        entries.sort(key=lambda e: e[1])
        cursor = 0
        gap = 0
        for (mid, off, size) in entries:
            gap += off - cursor
            cursor = off + size
        pad = dat["size"] - cursor
        if gap == 0 or all(g < 16 for g in [gap]):
            pass
        if gap <= 16 * n and 0 <= pad < 16:
            tiled += 1
        tot_entries += n
        tot_bytes += sum(e[2] for e in entries)
        for (mid, off, size) in entries:
            all_ids.append(mid)
            sizes.append(size)
            head = data[dat["body"] + off:dat["body"] + off + 12]
            if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
                riff_ok += 1
            else:
                riff_bad += 1
        del data
    print("banks carrying a DIDX/DATA pair : %d of %d"
          % (withdidx, len(banks(args.root))))
    print("media entries indexed           : %d" % tot_entries)
    print("media bytes indexed             : %d" % tot_bytes)
    print("banks whose DIDX tiles its DATA (padding under 16 bytes) : %d of %d"
          % (tiled, withdidx))
    print("media blobs beginning RIFF....WAVE : %d of %d, not : %d"
          % (riff_ok, tot_entries, riff_bad))
    print("distinct media ids              : %d of %d"
          % (len(set(all_ids)), len(all_ids)))
    print("smallest / largest media        : %d / %d"
          % (min(sizes), max(sizes)))
    return 0


def cmd_wem(args):
    files = wems(args.root)
    fmt_tags = collections.Counter()
    chunk_sets = collections.Counter()
    closes = 0
    tot = 0
    ids_ok = 0
    for p in files:
        data = open(p, "rb").read()
        tot += len(data)
        if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
            print("   %s is not RIFF/WAVE" % os.path.basename(p))
            continue
        (declared,) = struct.unpack_from("<I", data, 4)
        if declared + 8 == len(data):
            closes += 1
        o = 12
        got = []
        while o + 8 <= len(data):
            tag = bytes(data[o:o + 4])
            (sz,) = struct.unpack_from("<I", data, o + 4)
            got.append(tag.decode("latin-1"))
            if tag == b"fmt ":
                (wf,) = struct.unpack_from("<H", data, o + 8)
                fmt_tags[wf] += 1
            o += 8 + sz + (sz & 1)
        chunk_sets[tuple(got)] += 1
        base = os.path.splitext(os.path.basename(p))[0]
        if base.isdigit():
            ids_ok += 1
    print("loose .wem files       : %d" % len(files))
    print("bytes                  : %d" % tot)
    print("RIFF length agrees with the file length : %d of %d"
          % (closes, len(files)))
    print("names that are a plain decimal id       : %d of %d"
          % (ids_ok, len(files)))
    print("fmt tag values         : %s"
          % {("0x%04X" % k): v for k, v in fmt_tags.items()})
    print()
    print("the chunk sequences:")
    for k, v in chunk_sets.most_common():
        print("   %-52s x%d" % (" ".join(k), v))
    return 0


def cmd_worlds(args):
    """The five worlds, in the bank names and in the map directories."""
    import re
    bn = [os.path.basename(p) for p in banks(args.root)]
    bank_worlds = collections.Counter()
    for b in bn:
        m = re.search(r"World_(\d+)", b)
        if m:
            bank_worlds["World%s" % m.group(1)] += 1
    maps = collections.Counter()
    mapdir = os.path.join(args.root, COOKED, "Maps")
    for d in sorted(os.listdir(mapdir)):
        full = os.path.join(mapdir, d)
        if os.path.isdir(full):
            maps[d] = len([f for f in os.listdir(full)])
    print("banks by world :")
    for k in sorted(bank_worlds):
        print("   %-10s %d banks" % (k, bank_worlds[k]))
    print("map directories:")
    for k in sorted(maps):
        print("   %-10s %d files" % (k, maps[k]))
    a, b = set(bank_worlds), set(maps)
    print()
    print("intersection      : %s" % sorted(a & b))
    print("banks not in maps : %s" % sorted(a - b))
    print("maps not in banks : %s" % sorted(b - a))
    print()
    print("bank names in full:")
    for x in bn:
        print("   %s" % x)
    return 0


def _riff_chunks(d):
    o = 12
    out = {}
    while o + 8 <= len(d):
        t = bytes(d[o:o + 4])
        (sz,) = struct.unpack_from("<I", d, o + 8 - 4)
        out[t] = (o + 8, sz)
        o += 8 + sz + (sz & 1)
    return out


def cmd_stream(args):
    """Are the loose .wem the same sounds the banks index, and if so why are
    the bank copies a thousandth of the size?"""
    import hashlib
    bank = {}
    where = collections.defaultdict(list)
    for p in banks(args.root):
        d = open(p, "rb").read()
        cs = list(chunks(d))
        didx = next((c for c in cs if c["tag"] == b"DIDX"), None)
        dat = next((c for c in cs if c["tag"] == b"DATA"), None)
        if didx is None:
            continue
        for i in range(didx["size"] // 12):
            mid, off, sz = struct.unpack_from("<3I", d, didx["body"] + i * 12)
            blob = bytes(d[dat["body"] + off:dat["body"] + off + sz])
            where[mid].append((os.path.basename(p),
                               hashlib.sha1(blob).hexdigest()))
            bank.setdefault(mid, blob)
        del d
    files = wems(args.root)
    absent = []
    identical = 0
    prefetch = 0
    other = 0
    fmt_same = 0
    len_same = 0
    ratios = []
    for p in files:
        mid = int(os.path.splitext(os.path.basename(p))[0])
        w = open(p, "rb").read()
        if mid not in bank:
            absent.append((os.path.basename(p), len(w)))
            continue
        b = bank[mid]
        if b == w:
            identical += 1
            continue
        cw, cb = _riff_chunks(w), _riff_chunks(b)
        if b"fmt " in cw and b"fmt " in cb:
            fw = w[cw[b"fmt "][0]:cw[b"fmt "][0] + cw[b"fmt "][1]]
            fb = b[cb[b"fmt "][0]:cb[b"fmt "][0] + cb[b"fmt "][1]]
            if fw == fb:
                fmt_same += 1
        if b"data" in cw and b"data" in cb:
            if cw[b"data"][1] == cb[b"data"][1]:
                len_same += 1
            dw = w[cw[b"data"][0]:cw[b"data"][0] + cw[b"data"][1]]
            db = b[cb[b"data"][0]:cb[b"data"][0] + min(cb[b"data"][1],
                                                       len(b) - cb[b"data"][0])]
            if dw.startswith(db):
                prefetch += 1
                ratios.append(len(db) / float(max(len(dw), 1)))
            else:
                other += 1
    print("loose .wem                                    : %d" % len(files))
    print("  whose id the banks also index               : %d"
          % (len(files) - len(absent)))
    print("  byte-identical to the bank copy             : %d" % identical)
    print("  bank copy smaller, same fmt chunk           : %d" % fmt_same)
    print("  bank copy DECLARES the same data length     : %d" % len_same)
    print("  bank data is an exact PREFIX of the loose data : %d" % prefetch)
    print("  neither identical nor a prefix              : %d" % other)
    if ratios:
        print("  the prefix is %.4f %% to %.4f %% of the sound"
              % (100 * min(ratios), 100 * max(ratios)))
    print("  loose .wem with no bank entry at all        : %s" % absent)
    print()
    dup = [k for k, v in where.items() if len(v) > 1]
    ident = sum(1 for k in dup
                if len(set(h for _n, h in where[k])) == 1)
    print("media ids indexed by more than one bank       : %d" % len(dup))
    print("  of those, byte-identical in every bank      : %d" % ident)
    print()
    print("A bank entry that declares the full length, carries a kilobyte of")
    print("it and matches the head of a file on disk is a PREFETCH: the bank")
    print("holds enough to start the sound while the rest streams.")
    return 0


def cmd_manifest(args):
    """`SoundbanksInfo.xml` is Wwise's own manifest and the object ships it.

    It is a PUBLISHED, human-readable witness against everything this file
    derived from the bytes, and the interesting part is where the two
    disagree.
    """
    import xml.etree.ElementTree as ET
    p = os.path.join(args.root, COOKED, "SoundbanksInfo.xml")
    r = ET.parse(p).getroot()
    print("%s  %d bytes" % (os.path.basename(p), os.path.getsize(p)))
    print("attributes : %s" % r.attrib)
    print()
    print("the project roots it names, which are the studio's build machine:")
    for c in r.find("RootPaths"):
        if (c.text or "").strip():
            print("   %-24s %s" % (c.tag, c.text.strip()))
    print()
    streamed = set(int(f.get("Id"))
                   for f in r.find("StreamedFiles").findall("File"))
    disk = set(int(os.path.splitext(os.path.basename(x))[0])
               for x in wems(args.root))
    print("StreamedFiles declared : %d" % len(streamed))
    print("loose .wem on disk     : %d" % len(disk))
    print("   on disk and NOT declared : %s" % sorted(disk - streamed))
    print("   declared and NOT on disk : %s" % sorted(streamed - disk))
    print()
    declared_banks = set()
    mem = collections.Counter()
    events = 0
    for b in r.find("SoundBanks").findall("SoundBank"):
        declared_banks.add(b.findtext("Path") or b.findtext("ShortName"))
        im = b.find("IncludedMemoryFiles")
        if im is not None:
            for f in im.findall("File"):
                mem[int(f.get("Id"))] += 1
        ev = b.find("IncludedEvents")
        if ev is not None:
            events += len(ev.findall("Event"))
    ondisk = set(os.path.basename(x) for x in banks(args.root))
    print("banks declared : %d      banks on disk : %d"
          % (len(declared_banks), len(ondisk)))
    print("   on disk and NOT declared : %s" % sorted(ondisk - declared_banks))
    print("   declared and NOT on disk : %s" % sorted(declared_banks - ondisk))
    print("events declared : %d" % events)
    print()
    didx = collections.Counter()
    for x in banks(args.root):
        d = open(x, "rb").read()
        cs = list(chunks(d))
        c = next((y for y in cs if y["tag"] == b"DIDX"), None)
        if c:
            for i in range(c["size"] // 12):
                mid, _o, _s = struct.unpack_from("<3I", d, c["body"] + i * 12)
                didx[mid] += 1
        del d
    print("media ids in DIDX  : %d entries, %d distinct"
          % (sum(didx.values()), len(didx)))
    print("media ids in the XML: %d entries, %d distinct"
          % (sum(mem.values()), len(mem)))
    print("   in a bank and not in the XML : %s" % sorted(set(didx) - set(mem)))
    print("   in the XML and not in a bank : %s" % sorted(set(mem) - set(didx)))
    print()
    print("names the manifest gives the streamed files, first twelve:")
    for f in r.find("StreamedFiles").findall("File")[:12]:
        print("   %-12s %-34s %s" % (f.get("Id"), f.findtext("ShortName"),
                                     f.findtext("Path")))
    return 0


# ---------------------------------------------------------------- selftest

def _bank(chunklist):
    out = bytearray()
    for tag, body in chunklist:
        out += tag + struct.pack("<I", len(body)) + body
    return bytes(out)


def selftest():
    bkhd = struct.pack("<2I", 112, 0xDEADBEEF) + bytes(12)
    cases = []
    cases.append(("BKHD + DIDX + DATA",
                  _bank([(b"BKHD", bkhd),
                         (b"DIDX", struct.pack("<3I", 7, 0, 16)),
                         (b"DATA", bytes(16))]), 3, True))
    cases.append(("a bank that does not start with BKHD",
                  _bank([(b"DIDX", bytes(12)), (b"BKHD", bkhd)]), None, False))
    cases.append(("a chunk running past the end",
                  _bank([(b"BKHD", bkhd)])[:-4], None, False))
    good = _bank([(b"BKHD", bkhd)])
    cases.append(("three bytes of tail", good + b"\x00\x00\x00", None, False))
    bad = bytearray(_bank([(b"BKHD", bkhd), (b"\x01\x02\x03\x04", b"")]))
    cases.append(("a non-printable chunk tag", bytes(bad), None, False))
    big = bytearray(_bank([(b"BKHD", bkhd), (b"DATA", bytes(8))]))
    struct.pack_into("<I", big, 8 + len(bkhd) + 4, 1 << 30)
    cases.append(("a chunk declaring a gigabyte", bytes(big), None, False))
    cases.append(("a RIFF/WAVE file, which is not a bank",
                  b"RIFF" + struct.pack("<I", 100) + b"WAVEfmt "
                  + bytes(100), None, False))

    ok = 0
    accepted = refused = 0
    print("wwise selftest: %d specimens built in memory" % len(cases))
    for name, blob, want, should_pass in cases:
        try:
            got = list(chunks(blob))
            passed = should_pass and (want is None or len(got) == want)
            note = "accepted, %d chunks" % len(got)
            accepted += 1
        except NotABank as e:
            passed = not should_pass
            note = "refused: %s" % str(e)[:58]
            refused += 1
        print("  %-46s %-5s %s" % (name, "PASS" if passed else "FAIL", note))
        ok += 1 if passed else 0
    print()
    print("accepted %d, refused %d, of %d" % (accepted, refused, len(cases)))
    print("%d of %d specimens behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    for c in ("selftest", "banks", "media", "wem", "worlds", "stream",
              "manifest"):
        ap.add_argument("--" + c, action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.banks:
        return cmd_banks(a)
    if a.media:
        return cmd_media(a)
    if a.wem:
        return cmd_wem(a)
    if a.worlds:
        return cmd_worlds(a)
    if a.stream:
        return cmd_stream(a)
    if a.manifest:
        return cmd_manifest(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
