#!/usr/bin/env python3
"""sdb.py -- read a Windows application-compatibility shim database, `sdbf`.

GOG's installer for this title performs exactly one action beyond copying
files: `"action": "installSDB"` with a GUID and `{app}/goggame.sdb`, 588 bytes.
That is the shop's whole answer to "this is a 2004 game on a modern Windows",
where its answer for the previous object in this collection was a ten-megabyte
DOS emulator.

THE FORMAT, WHICH IS PUBLIC AND IS USED AS SUCH
------------------------------------------------
The container is Microsoft's, described in public reverse-engineering work and
implemented in the Wine and ReactOS trees:

    +0   u32   major version
    +4   u32   minor version
    +8   'sdbf'
    then a stream of TAGs

A TAG is a `u16` whose top four bits are its type and whose low twelve bits are
its identity:

    0x1000 NULL     no data          0x6000 STRINGREF  u32 into the string table
    0x2000 BYTE     1 byte           0x7000 LIST       u32 length, then children
    0x3000 WORD     2 bytes          0x8000 STRING     u32 length, then UTF-16LE
    0x4000 DWORD    4 bytes          0x9000 BINARY     u32 length, then bytes
    0x5000 QWORD    8 bytes

Nothing about that is derived here and the tool says so. What is read out of
**this** specimen is what 3D People's game is being told to do about Windows,
and the one string that gives the game away: `EXE.TLUK.`, which is `KULT.EXE`
with its characters reversed -- the key the shim engine matches on.

    python tools/sdb.py dump     "<root>/goggame.sdb"
    python tools/sdb.py strings  "<root>/goggame.sdb"
    python tools/sdb.py selftest
"""
import argparse
import struct
import sys

TYPES = {0x1: ("NULL", 0), 0x2: ("BYTE", 1), 0x3: ("WORD", 2),
         0x4: ("DWORD", 4), 0x5: ("QWORD", 8), 0x6: ("STRINGREF", 4),
         0x7: ("LIST", None), 0x8: ("STRING", None), 0x9: ("BINARY", None)}


class SdbError(Exception):
    pass


def parse(blob, path="<memory>"):
    if len(blob) < 12:
        raise SdbError("%s: %d bytes, too short for a header" % (path, len(blob)))
    major, minor = struct.unpack_from("<II", blob, 0)
    if blob[8:12] != b"sdbf":
        raise SdbError("%s: bytes 8..11 are %r, not b'sdbf'" % (path, blob[8:12]))

    def walk(lo, hi, depth):
        out = []
        i = lo
        while i + 2 <= hi:
            (tag,) = struct.unpack_from("<H", blob, i)
            i += 2
            t = tag >> 12
            if t not in TYPES:
                raise SdbError("%s: tag 0x%04X at +%d has type %X, which is "
                               "not one of the nine" % (path, tag, i - 2, t))
            name, size = TYPES[t]
            if size is not None:
                if i + size > hi:
                    raise SdbError("%s: a %s at +%d wants %d bytes and %d remain"
                                   % (path, name, i - 2, size, hi - i))
                data = blob[i:i + size]
                i += size
                out.append((depth, tag, name, data, None))
                continue
            if i + 4 > hi:
                raise SdbError("%s: a %s at +%d has no length" % (path, name, i - 2))
            (n,) = struct.unpack_from("<I", blob, i)
            i += 4
            if i + n > hi:
                raise SdbError("%s: a %s at +%d declares %d bytes and %d remain"
                               % (path, name, i - 6, n, hi - i))
            body = blob[i:i + n]
            if name == "LIST":
                out.append((depth, tag, name, b"", n))
                out.extend(walk(i, i + n, depth + 1))
            else:
                out.append((depth, tag, name, body, n))
            i += n
        if i != hi:
            raise SdbError("%s: a tag stream ended %d bytes short of %d"
                           % (path, hi - i, hi))
        return out

    return major, minor, walk(12, len(blob), 0)


def render(name, data):
    if name == "STRING":
        return repr(data.decode("utf-16-le", errors="replace").rstrip("\x00"))
    if name in ("BYTE", "WORD", "DWORD", "QWORD", "STRINGREF"):
        return "%d (0x%s)" % (int.from_bytes(data, "little"), data[::-1].hex())
    if name == "BINARY":
        if len(data) == 16:
            d = data
            return ("GUID {%08x-%04x-%04x-%s-%s}"
                    % (int.from_bytes(d[0:4], "little"),
                       int.from_bytes(d[4:6], "little"),
                       int.from_bytes(d[6:8], "little"),
                       d[8:10].hex(), d[10:16].hex()))
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return "%s  %r" % (data.hex(" "), printable)
    return ""


def cmd_dump(a):
    blob = open(a.path, "rb").read()
    major, minor, tags = parse(blob, a.path)
    print("file    : %s  %d bytes" % (a.path, len(blob)))
    print("version : %d.%d, magic b'sdbf' at +8" % (major, minor))
    print("tags    : %d" % len(tags))
    print()
    for depth, tag, name, data, n in tags:
        pad = "  " * depth
        extra = render(name, data)
        if name == "LIST":
            print("%s0x%04X %-9s %d bytes" % (pad, tag, name, n))
        else:
            print("%s0x%04X %-9s %s" % (pad, tag, name, extra))


def cmd_strings(a):
    blob = open(a.path, "rb").read()
    major, minor, tags = parse(blob, a.path)
    for depth, tag, name, data, n in tags:
        if name == "STRING":
            print("   %s" % data.decode("utf-16-le", errors="replace").rstrip("\x00"))
        elif name == "BINARY" and n == 16:
            print("   %s" % render(name, data))
        elif name == "BINARY":
            t = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            if sum(1 for b in data if 32 <= b < 127) >= 4:
                print("   (binary) %s" % t)


def cmd_selftest(a):
    def tlv(tag, payload):
        return struct.pack("<H", tag) + struct.pack("<I", len(payload)) + payload

    ok = True
    print("POSITIVE -- a built database must parse to exactly these tags:")
    body = (struct.pack("<H", 0x4001) + struct.pack("<I", 7)
            + tlv(0x8002, "kult.exe\x00".encode("utf-16-le")))
    blob = struct.pack("<II", 2, 1) + b"sdbf" + body
    major, minor, tags = parse(blob, "built")
    got = [(t[1], t[2], render(t[2], t[3])) for t in tags]
    good = (major, minor) == (2, 1) and len(tags) == 2 \
        and got[0][1] == "DWORD" and got[1][2] == "'kult.exe'"
    print("   %-5s version %d.%d, %r" % ("ok" if good else "FAIL", major, minor, got))
    ok = ok and good

    print()
    print("NEGATIVE -- these must all be refused:")
    cases = [
        ("empty", b""),
        ("eleven bytes", bytes(11)),
        ("the magic in the wrong place", b"sdbf" + bytes(32)),
        ("a tag type that does not exist",
         struct.pack("<II", 2, 1) + b"sdbf" + struct.pack("<H", 0xA001)),
        ("a string declaring more bytes than remain",
         struct.pack("<II", 2, 1) + b"sdbf" + struct.pack("<H", 0x8001)
         + struct.pack("<I", 4096)),
        ("a dword with two bytes left",
         struct.pack("<II", 2, 1) + b"sdbf" + struct.pack("<H", 0x4001) + b"\x01\x02"),
        ("a TGA header", bytes([0, 0, 2, 0]) + bytes(60)),
    ]
    for name, blob in cases:
        try:
            parse(blob, name)
        except SdbError as exc:
            print("   ok    %-42s refused: %s" % (name, str(exc)[:40]))
        else:
            print("   FAIL  %-42s ACCEPTED" % name)
            ok = False
    print()
    print("1 positive, %d negative, %s"
          % (len(cases), "all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("dump"); p.add_argument("path"); p.set_defaults(fn=cmd_dump)
    p = sub.add_parser("strings"); p.add_argument("path"); p.set_defaults(fn=cmd_strings)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    try:
        rc = a.fn(a)
    except SdbError as exc:
        sys.exit("SdbError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
