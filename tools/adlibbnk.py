#!/usr/bin/env python3
"""adlibbnk.py -- census of an Ad Lib instrument bank (.BNK, Ad Lib Inc.'s
Visual Composer / Instrument Maker format, published in the Ad Lib
programmer's documentation): the header, the name directory, the 30-byte
instrument records. Written for BUMPY.BNK of pc-bumpy-doc. NOT the AMOS
`AmBk` bank that pc-baronbaldric-doc's bnk.py reads -- a different format
that happens to share the extension.

    +0   u8 major, u8 minor        version (1.0)
    +2   "ADLIB-"                  signature
    +8   u16 used, u16 total       instruments used / slots
    +12  u32 offset of the names, u32 offset of the data
    names: total x 12 bytes = u16 index, u8 flag (1 = used), char[9]
    data:  total x 30 bytes = u8 percussive, u8 voice, 2 x 13 operator
           bytes (KSL, multiple, feedback, attack, sustain, EG type,
           decay, release, output level, AM, vibrato, KSR, connection),
           u8 wave select x 2

    python tools/adlibbnk.py census FILE...
    python tools/adlibbnk.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

NAME_REC, INS_REC = 12, 30


class Refused(Exception):
    pass


def bank(d):
    if len(d) < 28 or d[2:8] != b"ADLIB-":
        raise Refused("no ADLIB- signature")
    major, minor = d[0], d[1]
    used, total, off_names, off_data = struct.unpack_from("<HHII", d, 8)
    if off_names != 28:
        raise Refused("names at %d, not 28" % off_names)
    if off_data != 28 + NAME_REC * total:
        raise Refused("data at %d, but 28 + 12 x %d = %d" % (off_data, total, 28 + NAME_REC * total))
    if len(d) != off_data + INS_REC * total:
        raise Refused("%d bytes, but data + 30 x %d = %d" % (len(d), total, off_data + INS_REC * total))
    names = []
    for i in range(total):
        idx, flag = struct.unpack_from("<HB", d, off_names + NAME_REC * i)
        nm = d[off_names + NAME_REC * i + 3:off_names + NAME_REC * (i + 1)].split(b"\0")[0].decode("latin-1")
        names.append((idx, flag, nm))
    if sum(1 for n in names if n[1]) != used:
        raise Refused("header says %d used, %d name records are flagged" % (
            used, sum(1 for n in names if n[1])))
    ins = []
    for i in range(total):
        r = d[off_data + INS_REC * i:off_data + INS_REC * (i + 1)]
        ins.append(dict(percussive=r[0], voice=r[1], mod=r[2:15], car=r[15:28], wave=(r[28], r[29])))
    return dict(version=(major, minor), used=used, total=total, names=names, instruments=ins)


def cmd_census(paths):
    nameguard.guard()
    rc = 0
    for path in paths:
        d = open(path, "rb").read()
        try:
            b = bank(d)
        except Refused as e:
            print("REFUSED  %s: %s" % (os.path.basename(path), e))
            rc = 1
            continue
        usedn = [n for n in b["names"] if n[1]]
        print("%s  %d bytes  ADLIB- v%d.%d  %d used of %d slots; 28 + 12 x %d + 30 x %d = %d closes" % (
            os.path.basename(path), len(d), b["version"][0], b["version"][1], b["used"], b["total"],
            b["total"], b["total"], len(d)))
        perc = sum(1 for n in usedn if b["instruments"][n[0]]["percussive"])
        waves = sorted(set(b["instruments"][n[0]]["wave"] for n in usedn))
        print("  names: %s .. %s (%d of them end in '_')" % (
            usedn[0][2], usedn[-1][2], sum(1 for n in usedn if n[2].endswith("_"))))
        print("  percussive %d of %d; wave-select pairs used %s" % (perc, len(usedn), waves))
        print("  indices are the slot numbers in order: %s" % all(n[0] == i for i, n in enumerate(usedn)))
    return rc


def _bank(used, total):
    names = b"".join(struct.pack("<HB", i, 1 if i < used else 0) + ("rol%03d" % i).encode().ljust(9, b"\0")
                     for i in range(total))
    data = b"".join(bytes([0, 0]) + bytes(range(13)) + bytes(range(13)) + bytes([0, 1]) for _ in range(total))
    # the header is 28 bytes: 20 of fields and 8 reserved
    return (b"\x01\x00ADLIB-" + struct.pack("<HHII", used, total, 28, 28 + 12 * total)
            + bytes(8) + names + data)


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-60s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    b = bank(_bank(3, 5))
    check("3 used of 5, names rol000..rol002 flagged", b["used"] == 3 and b["names"][2] == (2, 1, "rol002") and b["names"][3][1] == 0)
    check("an instrument record splits into 2 + 13 + 13 + 2", b["instruments"][0]["car"] == bytes(range(13)) and b["instruments"][0]["wave"] == (0, 1))
    for label, blob, needle in (
            ("a file without the signature", b"\x01\x00ADLIB+" + bytes(30), "signature"),
            ("a bank one byte short", _bank(3, 5)[:-1], "30 x 5"),
            ("a header whose used count lies", _bank(3, 5)[:8] + struct.pack("<H", 4) + _bank(3, 5)[10:], "flagged")):
        try:
            bank(blob)
            check("refuses " + label, False, "accepted")
        except Refused as e:
            check("refuses " + label, needle in str(e), str(e))
    print("\nadlibbnk.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("census", "selftest"))
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    for p in a.args:
        dirguard.want_file(p, "adlibbnk.py")
    return cmd_census(a.args)


if __name__ == "__main__":
    sys.exit(main())
