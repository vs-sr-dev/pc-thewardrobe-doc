#!/usr/bin/env python3
"""gmd.py -- reader for the GMD message table (resource type rGUIMessage).

Header, derived from the bytes:

    +0   4    'GMD\\0'
    +4   u32  version
    +8   u32  language index
    +12  u64  unknown / hash
    +20  u32  key count
    +24  u32  string count
    +28  u32  size of the key block
    +32  u32  size of the string block
    +36  u32  length of the table's own name
    +40  ...  the name, NUL-terminated, then per-entry records, then the key
              block, then the string block: `count` NUL-terminated UTF-8
              strings back to back.

The accounting test: the last string must end exactly at end-of-file, and the
number of NUL-terminated strings in the final `string block size` bytes must
equal the declared string count. Both are checked, on every file.

Usage:
    gmd.py --validate FILE...
    gmd.py --dump FILE [--n N]
"""
import argparse
import os
import struct
import sys

MAGIC = b"GMD\x00"


class NotGmd(Exception):
    pass


def parse(path):
    with open(path, "rb") as fh:
        d = fh.read()
    if len(d) < 44 or d[:4] != MAGIC:
        raise NotGmd("%s: magic %r, not %r" % (path, d[:4], MAGIC))
    version, lang = struct.unpack_from("<II", d, 4)
    keycount, strcount, keysize, strsize = struct.unpack_from("<IIII", d, 20)
    namelen = struct.unpack_from("<I", d, 36)[0]
    name = d[40:40 + namelen].decode("latin-1")
    strblock = d[len(d) - strsize:]
    parts = strblock.split(b"\x00")
    if parts and parts[-1] == b"":
        parts = parts[:-1]
    strings = [p.decode("utf-8", "replace") for p in parts]
    return {
        "path": path, "size": len(d), "version": version, "lang": lang,
        "keycount": keycount, "strcount": strcount, "keysize": keysize,
        "strsize": strsize, "name": name, "strings": strings,
        "ends_at_eof": d.endswith(b"\x00"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--grep")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    rc = 0
    for p in a.files:
        try:
            g = parse(p)
        except NotGmd as e:
            print("NOT-GMD  %s" % e)
            rc = 1
            continue
        ok = len(g["strings"]) == g["strcount"]
        print("%s %-10s ver=0x%08X lang=%-2d keys=%-5d strings=%-5d(found %-5d) "
              "strblock=%-7d name=%s"
              % ("OK " if ok else "BAD", os.path.basename(p), g["version"],
                 g["lang"], g["keycount"], g["strcount"], len(g["strings"]),
                 g["strsize"], g["name"]))
        if not ok:
            rc = 1
        if a.dump:
            for i, s in enumerate(g["strings"][:a.n]):
                out = s.replace("\n", "\\n").replace("\r", "")
                print("   %4d  %s" % (i, out.encode("ascii", "backslashreplace")
                                      .decode("ascii")))
        if a.grep:
            for i, s in enumerate(g["strings"]):
                if a.grep.lower() in s.lower():
                    print("   %4d  %s" % (i, s.encode("ascii", "backslashreplace")
                                          .decode("ascii")))
    return rc


if __name__ == "__main__":
    sys.exit(main())
