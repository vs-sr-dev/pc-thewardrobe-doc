#!/usr/bin/env python3
"""s3m.py -- a census of Scream Tracker 3 modules, selected by the `SCRM`
magic at offset 2Ch and not by the file name (Polanie's are `GRAF.001..018`,
and `GRAF.019` looks like a sibling and is not one).

WHAT IS READ (the S3M header is a public format; this reads the header and
the instrument headers, not the patterns):

    +00   28   title, NUL-padded
    +1C   u8   1Ah        +1D u8 type (16 = module)
    +20   u16  orders     +22 u16 instruments    +24 u16 patterns
    +26   u16  flags      +28 u16 cwtv (tracker: high nibble 1 = Scream
                          Tracker, low 12 bits the version, 1320h = 3.20)
    +2A   u16  ffi (1 signed, 2 unsigned samples)
    +2C   4    `SCRM`
    +30   u8   global volume, initial speed, initial tempo, master volume
    +40   32   channel settings (bit 7 = disabled; 0..7 left PCM, 8..15
               right PCM, 16..24 AdLib melody, 25..28 AdLib drums)
    +60   orders (u8 each), then instrument parapointers (u16, x16),
               then pattern parapointers (u16, x16)
    instrument header: u8 type (0 empty, 1 PCM sample, 2..7 AdLib melody
               and drums), 12-byte DOS file name, ..., `SCRS` at +4Ch
               for a sample or `SCRI` for an AdLib instrument, name at +30h

    python tools/s3m.py census FILE...        one line per file, refusals
    python tools/s3m.py selftest
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402


class Refused(Exception):
    pass


def parse(d):
    if len(d) < 0x60:
        raise Refused("shorter than a header")
    if d[0x2C:0x30] != b"SCRM":
        raise Refused("no SCRM at 2Ch (found %r)" % d[0x2C:0x30])
    if d[0x1C] != 0x1A:
        raise Refused("byte 1Ch is %02Xh, not 1Ah" % d[0x1C])
    title = d[:28].split(b"\0")[0].decode("latin-1")
    typ = d[0x1D]
    orders, ninst, npat, flags, cwtv, ffi = struct.unpack_from("<6H", d, 0x20)
    gv, speed, tempo, mv = d[0x30], d[0x31], d[0x32], d[0x33]
    chan = d[0x40:0x60]
    p = 0x60 + orders
    ipp = struct.unpack_from("<%dH" % ninst, d, p)
    p += 2 * ninst
    ppp = struct.unpack_from("<%dH" % npat, d, p)
    insts = []
    for para in ipp:
        off = para * 16
        if off + 0x50 > len(d):
            raise Refused("instrument header at %d past the end" % off)
        t = d[off]
        fname = d[off + 1:off + 13].split(b"\0")[0].decode("latin-1")
        name = d[off + 0x30:off + 0x4C].split(b"\0")[0].decode("latin-1")
        sig = d[off + 0x4C:off + 0x50]
        insts.append(dict(type=t, fname=fname, name=name, sig=sig))
    used = [c for c in chan if c != 0xFF and not c & 0x80]
    pcm = sum(1 for c in used if c < 16)
    adlib = sum(1 for c in used if 16 <= c < 32)
    return dict(title=title, type=typ, orders=orders, ninst=ninst, npat=npat,
                flags=flags, cwtv=cwtv, ffi=ffi, gv=gv, speed=speed,
                tempo=tempo, mv=mv, insts=insts, chan_pcm=pcm,
                chan_adlib=adlib, order_list=list(d[0x60:0x60 + orders]),
                last_pattern_end=max((pp * 16 for pp in ppp), default=0))


def data_end(d, f):
    """Where the module's own bytes end: the last of the instrument headers
    and the patterns (each pattern is a u16 length then that many bytes)."""
    orders, ninst, npat = f["orders"], f["ninst"], f["npat"]
    q = 0x60 + orders
    ipp = struct.unpack_from("<%dH" % ninst, d, q)
    q += 2 * ninst
    ppp = struct.unpack_from("<%dH" % npat, d, q)
    ends = [q + 2 * npat]
    for pp in ppp:
        if pp:
            off = pp * 16
            ends.append(off + struct.unpack_from("<H", d, off)[0])
    for ip in ipp:
        ends.append(ip * 16 + 0x50)
    return max(ends)


def tail_key(tail, ref, maxperiod=256):
    """If `tail` is `ref` plus a repeating additive key, return (period,
    key bytes, mismatches); else (None, None, mismatches at the best
    period). The key is read off the first bytes and CHECKED on all."""
    n = min(len(tail), len(ref))
    sub = bytes((tail[i] - ref[i]) & 0xFF for i in range(n))
    best = (None, None, n)
    for p in range(1, maxperiod + 1):
        key = sub[:p]
        mism = sum(1 for i in range(n) if sub[i] != key[i % p])
        if mism < best[2]:
            best = (p, key, mism)
        if mism == 0:
            return p, key, 0
    return None, best[1], best[2]


def tracker(cwtv):
    fam = {1: "Scream Tracker", 2: "Imago Orpheus", 3: "Impulse Tracker",
           4: "Schism Tracker", 5: "OpenMPT"}.get(cwtv >> 12, "unknown %X" % (cwtv >> 12))
    return "%s %X.%02X" % (fam, (cwtv >> 8) & 0xF, cwtv & 0xFF)


def cmd_census(paths, exe=None):
    ok = 0
    trackers = {}
    itypes = {}
    ref = open(exe, "rb").read() if exe else None
    tails = []
    for p in paths:
        d = open(p, "rb").read()
        try:
            f = parse(d)
        except Refused as e:
            print("%-9s %7d  REFUSED: %s" % (os.path.basename(p), len(d), e))
            continue
        ok += 1
        end = data_end(d, f)
        tail = d[end:]
        row = dict(name=os.path.basename(p), size=len(d), end=end, tail=len(tail))
        if ref is not None and len(tail) >= 20:
            period, key, mism = tail_key(tail[:len(ref)], ref)
            row.update(period=period, key=key, mism=mism,
                       extra=len(tail) - len(ref))
        tails.append(row)
        t = tracker(f["cwtv"])
        trackers[t] = trackers.get(t, 0) + 1
        kinds = {}
        for i in f["insts"]:
            k = {0: "empty", 1: "sample"}.get(i["type"], "adlib")
            kinds[k] = kinds.get(k, 0) + 1
            itypes[k] = itypes.get(k, 0) + 1
        print("%-9s %7d  %-26r ord %2d ins %2d pat %2d  %s  speed %d tempo %d "
              "chans pcm %d adlib %d  instruments %s  %s"
              % (os.path.basename(p), len(d), f["title"], f["orders"], f["ninst"],
                 f["npat"], t, f["speed"], f["tempo"], f["chan_pcm"],
                 f["chan_adlib"], " ".join("%s:%d" % kv for kv in sorted(kinds.items())),
                 ", ".join(i["fname"] or i["name"] for i in f["insts"])))
    print("\n%d of %d carry SCRM; trackers: %s; instruments: %s"
          % (ok, len(paths), ", ".join("%s x%d" % kv for kv in sorted(trackers.items())),
             ", ".join("%s %d" % kv for kv in sorted(itypes.items()))))
    print("\n-- after the module's own bytes -------------------------------")
    print("%-9s %7s %7s %7s  %s" % ("file", "size", "ends", "tail",
                                     "tail vs --exe" if ref is not None else ""))
    for r in tails:
        note = ""
        if "period" in r:
            if r["period"]:
                note = ("= exe + %d-byte additive key %s, 0 mismatches, %d bytes beyond"
                        % (r["period"], r["key"].hex(), r["extra"]))
            else:
                note = "NOT exe + a repeating key (best %d mismatches)" % r["mism"]
        print("%-9s %7d %7d %7d  %s" % (r["name"], r["size"], r["end"], r["tail"], note))
    if ref is not None:
        hit = sum(1 for r in tails if r.get("period"))
        print("%d of %d tails are the --exe file (%d bytes) under a repeating "
              "additive key" % (hit, len(tails), len(ref)))
        # A module whose tail is LONGER than the exe by a multiple of 28
        # bytes: between its own bytes and the copy sits a table of 28-byte
        # records {u32 exe length, u32 offset of the copy in that file,
        # 20 bytes = 256 - key}. GRAF.012 of Polanie has 18 of them.
        for r in tails:
            extra = r.get("extra", 0)
            if extra <= 0 or extra % 28:
                continue
            d = open(os.path.join(os.path.dirname(paths[0]), r["name"]), "rb").read()
            table = d[r["end"]:r["end"] + extra]
            n = extra // 28
            print("\n%s: %d bytes before its copy = %d records of 28:"
                  % (r["name"], extra, n))
            matched = 0
            for k in range(n):
                size, off = struct.unpack_from("<II", table, 28 * k)
                neg = table[28 * k + 8:28 * k + 28]
                key = bytes((-b) & 0xFF for b in neg)
                who = [t["name"] for t in tails
                       if t.get("key") == key and t["end"] == off]
                if who:
                    matched += 1
                print("  %2d  len %6d  copy at %6d  256-key %s  -> %s"
                      % (k + 1, size, off, neg.hex(), ", ".join(who) or "no file"))
            print("  %d of %d records name a file by (offset, key); the copy "
                  "in %s itself is at %d"
                  % (matched, n, r["name"], r["end"] + extra))
            p2, k2, m2 = tail_key(d[r["end"] + extra:], ref)
            print("  %s's own copy after the table: %s"
                  % (r["name"], "exe + %d-byte key %s, %d mismatches"
                     % (p2, k2.hex(), m2) if p2 else "no repeating key"))
    return 0 if ok else 1


def _specimen(title=b"selftest", ninst=2, adlib=True):
    hdr = bytearray(0x60)
    hdr[:len(title)] = title
    hdr[0x1C] = 0x1A
    hdr[0x1D] = 16
    struct.pack_into("<6H", hdr, 0x20, 2, ninst, 1, 0, 0x1320, 2)
    hdr[0x2C:0x30] = b"SCRM"
    hdr[0x30:0x34] = bytes([64, 6, 125, 48])
    hdr[0x40:0x60] = bytes([0, 8, 16, 17] + [0xFF] * 28)
    body = bytearray(hdr) + bytes([0, 1])
    ipp_at = len(body)
    body += bytes(2 * ninst) + bytes(2)     # pattern pointer
    while len(body) % 16:
        body += b"\0"
    for k in range(ninst):
        off = len(body)
        struct.pack_into("<H", body, ipp_at + 2 * k, off // 16)
        ih = bytearray(0x50)
        ih[0] = 2 if adlib and k else 1
        fname = b"INST%d.ADL" % k if ih[0] == 2 else b"SAMPLE.SMP"
        ih[1:1 + len(fname)] = fname
        ih[0x30:0x36] = b"name%d" % k
        ih[0x4C:0x50] = b"SCRI" if ih[0] == 2 else b"SCRS"
        body += ih
    return bytes(body)


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-56s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    f = parse(_specimen())
    check("specimen parses: title, 2 instruments, ST 3.20",
          f["title"] == "selftest" and f["ninst"] == 2 and tracker(f["cwtv"]) == "Scream Tracker 3.20")
    check("channels: 2 PCM, 2 AdLib", (f["chan_pcm"], f["chan_adlib"]) == (2, 2))
    check("instrument types read: sample then adlib, names read",
          [i["type"] for i in f["insts"]] == [1, 2] and f["insts"][1]["fname"] == "INST1.ADL")
    bad = bytearray(_specimen())
    bad[0x2C:0x30] = b"SCRX"
    try:
        parse(bytes(bad))
        check("refuses without SCRM", False)
    except Refused as e:
        check("refuses without SCRM", "SCRM" in str(e))
    try:
        parse(bytes(range(256)) * 300)
        check("refuses a byte ramp that is no module", False)
    except Refused:
        check("refuses a byte ramp that is no module", True)
    spec = _specimen()
    check("data_end of the specimen is its length", data_end(spec, f) == len(spec))
    ref = bytes(range(256)) * 10
    key = bytes.fromhex("9a0e0182784042b681e0eac5346574edbedc82bc")
    tail = bytes((ref[i] + key[i % 20]) & 0xFF for i in range(len(ref)))
    p, k, m = tail_key(tail, ref)
    check("a 20-byte additive key is found and checked on every byte",
          (p, k, m) == (20, key, 0))
    import hashlib
    noise = b"".join(hashlib.sha1(b"s3m%d" % i).digest() for i in range(130))[:len(ref)]
    p, k, m = tail_key(noise, ref)
    check("hash noise over a ramp is not `ref + key` (period None)",
          p is None and m > 0)
    print("\ns3m.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    if not argv:
        argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "selftest":
        return selftest()
    exe = None
    if "--exe" in argv:
        i = argv.index("--exe")
        exe = argv[i + 1]
        dirguard.want_file(exe, "s3m.py")
        argv = argv[:i] + argv[i + 2:]
    if argv[0] == "census" and len(argv) > 1:
        for p in argv[1:]:
            dirguard.want_file(p, "s3m.py")
        return cmd_census(argv[1:], exe)
    print("s3m.py: census FILE... [--exe FILE] | selftest")
    return 2


if __name__ == "__main__":
    sys.exit(main())
