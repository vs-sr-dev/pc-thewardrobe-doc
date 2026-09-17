#!/usr/bin/env python3
"""is32.py -- read InstallShield's `_INST32I.EX_` bootstrap container.

The four bytes at the front are `2a ab 79 d8`. The pre-briefing writes that
magic as `0x2AAB79D8`, which is the bytes read left to right; as the
little-endian u32 the file's own code would load it is `0xD879AB2A`. This tool
prints both and compares against the byte sequence, because the two
conventions disagree and the object cannot say which the vendor meant.

This is NOT the Z archive of `isz.py` -- different magic, different record
shape, no directory table, no attributes, no dates. What it shares is the
payload codec, which is the same PKWARE DCL implode, and `blast` is imported
from `isz` rather than written twice.

The layout, as derived:

    +0x00  4 bytes  2a ab 79 d8
    +0x04  u16      256
    +0x06  u16      0
    +0x08  70 bytes a copyright banner, NOT NUL-terminated and TRUNCATED --
                    it ends "All Rights Reserve"
    +0x4E  u16      MEMBER COUNT
    +0x50  u16      0
    +0x52           member records, each
                    u32 offset, u32 stored size, u32 expanded size,
                    8 unnamed bytes, u16 length + name, u16 length + name
                    -- the first name is what the member is called once
                    installed, the second is what it is called on disc

THREE CLOSURES, ALL CHECKED

    1. the record table ends exactly where the first member's data begins;
    2. the members' offsets chain with no gap and no overlap;
    3. first offset + the sum of the stored sizes = the length of the file,
       at residue 0.

    python tools/is32.py list _work/members/_INST32I.EX_
    python tools/is32.py extract _work/members/_INST32I.EX_ --out DIR
    python tools/is32.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from isz import blast, ZError            # noqa: E402  the codec, not a copy

SIGNATURE = bytes([0x2A, 0xAB, 0x79, 0xD8])
BANNER_AT, BANNER_LEN = 8, 70
COUNT_AT = 0x4E
FIRST_RECORD = 0x52
FIXED = 20


def parse(data):
    if len(data) < FIRST_RECORD:
        raise ZError("a %d-byte file is too short to be an _INST32I container"
                     % len(data))
    if data[:4] != SIGNATURE:
        raise ZError("the first four bytes are %s, not %s"
                     % (" ".join("%02x" % b for b in data[:4]),
                        " ".join("%02x" % b for b in SIGNATURE)))
    u04, u06 = struct.unpack_from("<2H", data, 4)
    banner = data[BANNER_AT:BANNER_AT + BANNER_LEN].decode("cp437")
    count = struct.unpack_from("<H", data, COUNT_AT)[0]
    if count == 0:
        raise ZError("the container declares zero members")
    p = FIRST_RECORD
    recs = []
    for i in range(count):
        if p + FIXED + 4 > len(data):
            raise ZError("record %d at %d runs past the end of a %d-byte file"
                         % (i, p, len(data)))
        off, stored, expanded = struct.unpack_from("<3I", data, p)
        q = p + FIXED
        names = []
        for _ in range(2):
            n = struct.unpack_from("<H", data, q)[0]
            if q + 2 + n > len(data):
                raise ZError("a name in record %d at %d runs past the end"
                             % (i, q))
            names.append(data[q + 2:q + 2 + n].decode("cp437"))
            q += 2 + n
        if off + stored > len(data):
            raise ZError("record %d (%r) claims %d bytes at %d, past the end "
                         "of a %d-byte file"
                         % (i, names[0], stored, off, len(data)))
        recs.append({"record_at": p, "offset": off, "stored": stored,
                     "expanded": expanded, "name": names[0],
                     "packed_as": names[1]})
        p = q
    return {"u04": u04, "u06": u06, "banner": banner, "count": count,
            "records": recs, "table_end": p, "length": len(data)}


def closures(c):
    recs = c["records"]
    out = []
    out.append(("the record table ends where the first member's data begins",
                c["table_end"] == recs[0]["offset"],
                "table ends at %d, first data at %d"
                % (c["table_end"], recs[0]["offset"])))
    cur = recs[0]["offset"]
    gaps = 0
    for r in recs:
        if r["offset"] != cur:
            gaps += 1
        cur = r["offset"] + r["stored"]
    out.append(("the members' offsets chain with no gap and no overlap",
                gaps == 0, "%d of %d members begin where the previous ended"
                % (len(recs) - gaps, len(recs))))
    out.append(("first offset + stored sizes = the file, residue 0",
                cur == c["length"],
                "%d + %d = %d against %d, residue %d"
                % (recs[0]["offset"], sum(r["stored"] for r in recs), cur,
                   c["length"], c["length"] - cur)))
    return out


def cmd_list(args):
    data = open(args.path, "rb").read()
    c = parse(data)
    print("container   : %s   %d bytes" % (args.path, c["length"]))
    print("signature   : %s   as a little-endian u32 0x%08X   as the bytes "
          "read left to right 0x%02X%02X%02X%02X"
          % (" ".join("%02x" % b for b in SIGNATURE),
             struct.unpack("<I", SIGNATURE)[0], *SIGNATURE))
    print("+0x04, +0x06: %d %d" % (c["u04"], c["u06"]))
    print("banner      : %s" % c["banner"])
    print("            (%d bytes, no terminator, and it stops mid-word)"
          % BANNER_LEN)
    print("members     : %d" % c["count"])
    print()
    print("  %-7s %-14s %-14s %10s %10s %10s"
          % ("rec at", "installed as", "shipped as", "offset", "stored",
             "expanded"))
    for r in c["records"]:
        print("  %-7d %-14s %-14s %10d %10d %10d"
              % (r["record_at"], r["name"], r["packed_as"], r["offset"],
                 r["stored"], r["expanded"]))
    print()
    for label, ok, detail in closures(c):
        print("  %-58s %s   %s" % (label, "ok  " if ok else "FAIL", detail))
    print()
    print("stored   : %d" % sum(r["stored"] for r in c["records"]))
    print("expanded : %d" % sum(r["expanded"] for r in c["records"]))
    return 0


def cmd_extract(args):
    data = open(args.path, "rb").read()
    c = parse(data)
    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)
    ok = 0
    for r in c["records"]:
        body = blast(data[r["offset"]:r["offset"] + r["stored"]],
                     expected=r["expanded"])
        with open(os.path.join(outdir, r["name"]), "wb") as fh:
            fh.write(body)
        print("%-14s %8d stored -> %8d expanded   first two bytes %s"
              % (r["name"], r["stored"], len(body),
                 "".join(chr(b) if 32 <= b < 127 else "." for b in body[:2])))
        ok += 1
    print("%d of %d members expanded to their declared length"
          % (ok, c["count"]))
    return 0


def build(members, sig=SIGNATURE, lie_count=0, break_chain=False,
          short_table=False):
    """Construct a container in memory. Used only by selftest."""
    from isz import make_stream
    blobs = [make_stream(p) for _, p in members]
    head = bytearray(sig)
    head += struct.pack("<2H", 256, 0)
    head += b"Copyright (c) 1990-1995 Stirling Technologies, Inc. All Rights "
    head += b"Reserve"
    assert len(head) == COUNT_AT, len(head)
    head += struct.pack("<2H", len(members) + lie_count, 0)
    table = bytearray()
    for i, ((name, payload), blob) in enumerate(zip(members, blobs)):
        nb, pb = name.encode("cp437"), ("_X%04d._MP" % i).encode("cp437")
        table += struct.pack("<3I", 0, len(blob), len(payload))
        table += b"\x00" * 8
        table += struct.pack("<H", len(nb)) + nb
        table += struct.pack("<H", len(pb)) + pb
    start = len(head) + len(table) - (4 if short_table else 0)
    off = start
    p = 0
    for i, blob in enumerate(blobs):
        struct.pack_into("<I", table, p, off - (3 if break_chain and i else 0))
        off += len(blob)
        p += FIXED + 2 + len(members[i][0]) + 2 + 10
    return bytes(head) + bytes(table) + b"".join(blobs)


def cmd_selftest(args):
    checks = []
    members = [("INSTALL.EXE", b"MZ" + b"payload one" * 40),
               ("BOOT16.EXE", b"MZ" + bytes(range(256)))]

    spec = build(members)
    try:
        c = parse(spec)
        cl = closures(c)
        bodies = [blast(spec[r["offset"]:r["offset"] + r["stored"]],
                        expected=r["expanded"]) for r in c["records"]]
        ok = (c["count"] == 2 and all(x[1] for x in cl)
              and [r["name"] for r in c["records"]] == [m[0] for m in members]
              and bodies == [m[1] for m in members])
        checks.append(("a well-formed container parses, closes and expands",
                       ok, "" if ok else "parsed but a value is wrong"))
    except ZError as e:
        checks.append(("a well-formed container parses, closes and expands",
                       False, str(e)))

    rejects = [
        ("a wrong signature", lambda: parse(build(members, sig=b"MSCF"))),
        ("a member count larger than the table holds",
         lambda: parse(build(members, lie_count=40))),
        ("a twenty-byte file", lambda: parse(bytes(SIGNATURE) + bytes(16))),
        ("a declared count of zero",
         lambda: parse(build(members, lie_count=-2))),
    ]
    for label, fn in rejects:
        try:
            fn()
            checks.append((label + " is rejected", False,
                           "ACCEPTED -- the reader did not object"))
        except (ZError, struct.error) as e:
            checks.append((label + " is rejected", True, str(e)[:66]))

    for label, kw in (("a broken offset chain", {"break_chain": True}),
                      ("a record table that does not meet the data",
                       {"short_table": True})):
        c = parse(build(members, **kw))
        failed_any = [x for x in closures(c) if not x[1]]
        checks.append((label + " is reported as a failed closure",
                       bool(failed_any),
                       failed_any[0][0] if failed_any else "all closures "
                       "passed, which is wrong"))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL",
                                   note))
        if not ok:
            failed += 1
    print()
    print("%d checks, 1 accepted specimen, %d rejected specimens, %d failures"
          % (len(checks), len(rejects), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("list")
    l.add_argument("path")
    l.set_defaults(func=cmd_list)
    x = sub.add_parser("extract")
    x.add_argument("path")
    x.add_argument("--out", required=True)
    x.set_defaults(func=cmd_extract)
    s = sub.add_parser("selftest")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args()
    try:
        return args.func(args)
    except ZError as e:
        print("is32: REFUSED: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
