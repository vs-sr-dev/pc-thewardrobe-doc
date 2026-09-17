#!/usr/bin/env python3
"""winfnt.py -- read the `FONT` and `FONTDIR` resources inside a Windows 2.x
`.FON` module, which is what `SCRIPT.FON` and `TMSRB.FON` are.

`ne.py` already reads the New Executable wrapper and names the resources; this
opens them. The `FONTINFO` structure is **public** -- it is the `FONT` resource
layout published in the Windows 1.x/2.x SDK and repeated in the Windows 3.x
`Font File Format` note -- and it is used here openly, with the fields named
so a reader can check them against that definition rather than against this
file's assertion.

Version 1 (0x0100) and version 2 (0x0200) share every field below; they
differ in the glyph table that follows it. All little-endian:

    0x00 WORD  dfVersion       0x02 DWORD dfSize
    0x06 char[60] dfCopyright  0x42 WORD  dfType
    0x44 WORD  dfPoints        0x46 WORD  dfVertRes    0x48 WORD dfHorizRes
    0x4A WORD  dfAscent        0x4C WORD  dfInternalLeading
    0x4E WORD  dfExternalLeading
    0x50 BYTE  dfItalic        0x51 BYTE  dfUnderline  0x52 BYTE dfStrikeOut
    0x53 WORD  dfWeight        0x55 BYTE  dfCharSet
    0x56 WORD  dfPixWidth      0x58 WORD  dfPixHeight  0x5A BYTE dfPitchAndFamily
    0x5B WORD  dfAvgWidth      0x5D WORD  dfMaxWidth
    0x5F BYTE  dfFirstChar     0x60 BYTE  dfLastChar
    0x61 BYTE  dfDefaultChar   0x62 BYTE  dfBreakChar
    0x63 WORD  dfWidthBytes    0x65 DWORD dfDevice     0x69 DWORD dfFace
    0x6D DWORD dfBitsPointer   0x71 DWORD dfBitsOffset

`dfType` bit 0 clear means a raster font; the glyph table follows the header,
one `GLYPHENTRY` of WORD width + WORD offset per character for version 2.

    python tools/winfnt.py <file.FON>
    python tools/winfnt.py --selftest
"""
import argparse
import os
import struct
import sys


class Bad(Exception):
    pass


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def ne_resources(buf):
    """The (type, id, offset, length) of every resource. Refuses non-NE."""
    if buf[:2] != b"MZ":
        raise Bad("no MZ signature")
    lfanew = u32(buf, 0x3C)
    if buf[lfanew:lfanew + 2] != b"NE":
        raise Bad("no NE signature at e_lfanew=0x%X" % lfanew)
    rt = lfanew + u16(buf, lfanew + 0x24)
    shift = u16(buf, rt)
    out = []
    p = rt + 2
    while True:
        tid = u16(buf, p)
        if tid == 0:
            break
        count = u16(buf, p + 2)
        p += 8
        for _ in range(count):
            off = u16(buf, p) << shift
            ln = u16(buf, p + 2) << shift
            rid = u16(buf, p + 6)
            out.append((tid & 0x7FFF, rid & 0x7FFF, off, ln))
            p += 12
    if not out:
        raise Bad("no resources in the resource table")
    return out


def fontinfo(b):
    if len(b) < 0x75:
        raise Bad("%d bytes is shorter than a FONTINFO header" % len(b))
    ver = u16(b, 0)
    if ver not in (0x0100, 0x0200, 0x0300):
        raise Bad("dfVersion 0x%04X is not 0x0100, 0x0200 or 0x0300" % ver)
    f = {
        "version": ver, "size": u32(b, 2),
        "copyright": b[6:66].split(b"\x00")[0].decode("cp437", "replace"),
        "type": u16(b, 0x42), "points": u16(b, 0x44),
        "vertres": u16(b, 0x46), "horizres": u16(b, 0x48),
        "ascent": u16(b, 0x4A), "internal_leading": u16(b, 0x4C),
        "external_leading": u16(b, 0x4E),
        "italic": b[0x50], "underline": b[0x51], "strikeout": b[0x52],
        "weight": u16(b, 0x53), "charset": b[0x55],
        "pixwidth": u16(b, 0x56), "pixheight": u16(b, 0x58),
        "pitchfamily": b[0x5A], "avgwidth": u16(b, 0x5B),
        "maxwidth": u16(b, 0x5D), "firstchar": b[0x5F], "lastchar": b[0x60],
        "defaultchar": b[0x61], "breakchar": b[0x62],
        "widthbytes": u16(b, 0x63),
        "face": u32(b, 0x69), "bitsoffset": u32(b, 0x71),
    }
    f["glyphs"] = f["lastchar"] - f["firstchar"] + 1
    if f["face"] and f["face"] < len(b):
        f["facename"] = b[f["face"]:].split(b"\x00")[0].decode("cp437",
                                                               "replace")
    else:
        f["facename"] = ""
    return f


def report(path):
    buf = open(path, "rb").read()
    res = ne_resources(buf)
    fonts = [r for r in res if r[0] == 0x0008]
    dirs = [r for r in res if r[0] == 0x0007]
    print("file        : %s  (%d bytes)" % (os.path.basename(path), len(buf)))
    print("resources   : %d FONTDIR, %d FONT" % (len(dirs), len(fonts)))
    print()
    print("%-5s %-16s %3s %5s %5s %5s %5s %6s %6s %6s %s"
          % ("id", "face", "ver", "pts", "h", "asc", "avgw", "maxw",
             "chars", "bytes", "copyright"))
    total = 0
    for _, rid, off, ln in fonts:
        f = fontinfo(buf[off:off + ln])
        total += ln
        print("%-5d %-16s %3d %5d %5d %5d %5d %6d %6d %6d %s"
              % (rid, f["facename"], f["version"] >> 8, f["points"],
                 f["pixheight"], f["ascent"], f["avgwidth"], f["maxwidth"],
                 f["glyphs"], ln, f["copyright"]))
    print()
    print("FONT resources hold %d bytes of %d = %.4f %% of the module"
          % (total, len(buf), 100.0 * total / len(buf)))
    if dirs:
        off, ln = dirs[0][2], dirs[0][3]
        n = u16(buf, off)
        print("FONTDIR declares %d font(s); the resource table lists %d"
              % (n, len(fonts)))
        if n != len(fonts):
            print("  ** they disagree **")
    return 0


def selftest():
    fails = 0
    for label, buf in (("empty", b""),
                       ("not MZ", b"XX" + b"\x00" * 200),
                       ("MZ but no NE", b"MZ" + b"\x00" * 200)):
        try:
            ne_resources(buf)
            print("  ACCEPTED %-16s -- the reader is lying" % label)
            fails += 1
        except (Bad, struct.error, IndexError) as e:
            print("  refused %-17s %s" % (label, e))
    try:
        fontinfo(b"\x00" * 0x80)
        print("  ACCEPTED a zero FONTINFO -- the reader is lying")
        fails += 1
    except Bad as e:
        print("  refused %-17s %s" % ("zero FONTINFO", e))
    print()
    print("selftest: %d failure(s)" % fails)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.path:
        ap.print_help()
        return 2
    try:
        return report(args.path)
    except Bad as e:
        print("winfnt: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
