#!/usr/bin/env python3
"""ico.py -- read a Windows icon container, because two of them on this object
are exactly the same length and are not the same file.

`Autorun\\Season Launcher.ico` and `Autorun\\season1.ico` are both 292,878 bytes
and their SHA-1 differ. Two files of identical length carrying different bytes
have three cheap explanations and the directory settles which: the same set of
images re-rendered, a different set that happens to cost the same, or one image
swapped for another of identical size.

THE FORMAT, AS PUBLISHED

    ICONDIR      u16 reserved (0), u16 type (1 = icon), u16 count
    ICONDIRENTRY x count, 16 bytes each:
        u8 width, u8 height   (0 means 256)
        u8 colour count       (0 means >= 256)
        u8 reserved
        u16 planes, u16 bit count
        u32 bytes in resource, u32 offset

  Each image is then either a PNG (its own signature) or a BITMAPINFOHEADER
  followed by an XOR mask and an AND mask, with the header's height twice the
  icon's because it describes both masks as one bitmap. That doubling is the
  test that the entry really is a DIB and not a coincidence.

  The accounting is checked and printed: the last entry's offset plus its
  length must equal the file length, residue 0. A container that does not
  close is reported as not closing rather than parsed anyway.

    python tools/ico.py FILE [FILE ...]
    python tools/ico.py FILE --compare FILE2
"""
import argparse
import hashlib
import os
import struct
import sys

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def read_ico(path):
    b = open(path, "rb").read()
    res, typ, cnt = struct.unpack_from("<HHH", b, 0)
    if res != 0 or typ not in (1, 2) or cnt == 0:
        raise ValueError("%s: not an icon directory (res=%d type=%d count=%d)"
                         % (os.path.basename(path), res, typ, cnt))
    ents = []
    for i in range(cnt):
        off = 6 + i * 16
        w, h, ncol, r2, planes, bits, size, at = struct.unpack_from(
            "<BBBBHHII", b, off)
        img = b[at:at + size]
        kind = "PNG" if img[:8] == PNG_SIG else "DIB"
        dibh = None
        if kind == "DIB" and len(img) >= 40:
            hsz, dw, dh, dpl, dbits = struct.unpack_from("<IiiHH", img, 0)
            dibh = (hsz, dw, dh, dpl, dbits)
        ents.append({"w": w or 256, "h": h or 256, "ncol": ncol,
                     "planes": planes, "bits": bits, "size": size, "off": at,
                     "kind": kind, "dib": dibh,
                     "sha1": hashlib.sha1(img).hexdigest()})
    end = max(e["off"] + e["size"] for e in ents)
    return {"path": path, "bytes": len(b), "type": typ, "count": cnt,
            "entries": ents, "end": end, "residue": len(b) - end,
            "sha1": hashlib.sha1(b).hexdigest()}


def show(d):
    print("%s" % d["path"])
    print("  bytes %d  sha1 %s  images %d  type %d"
          % (d["bytes"], d["sha1"], d["count"], d["type"]))
    print("  last image ends at %d, residue %d  -> %s"
          % (d["end"], d["residue"], "CLOSES" if d["residue"] == 0 else "DOES NOT CLOSE"))
    print("     %4s %4s %5s %6s %10s %10s %-4s %s"
          % ("w", "h", "bits", "ncol", "size", "offset", "kind", "DIB header"))
    for e in d["entries"]:
        dib = ""
        if e["dib"]:
            hsz, dw, dh, dpl, dbits = e["dib"]
            dib = "hdr %d %dx%d planes %d bits %d  height doubled: %s" % (
                hsz, dw, dh, dpl, dbits, "yes" if dh == 2 * e["h"] else "NO")
        print("     %4d %4d %5d %6d %10d %10d %-4s %s"
              % (e["w"], e["h"], e["bits"], e["ncol"], e["size"], e["off"],
                 e["kind"], dib))


def compare(a, b):
    print()
    print("comparing %s and %s" % (os.path.basename(a["path"]),
                                   os.path.basename(b["path"])))
    print("  same length      : %s (%d, %d)"
          % (a["bytes"] == b["bytes"], a["bytes"], b["bytes"]))
    print("  same sha1        : %s" % (a["sha1"] == b["sha1"]))
    print("  same image count : %s (%d, %d)"
          % (a["count"] == b["count"], a["count"], b["count"]))
    ka = [(e["w"], e["h"], e["bits"], e["size"]) for e in a["entries"]]
    kb = [(e["w"], e["h"], e["bits"], e["size"]) for e in b["entries"]]
    print("  same directory   : %s" % (ka == kb))
    if ka != kb:
        for i, (x, y) in enumerate(zip(ka, kb)):
            if x != y:
                print("     entry %d: %s vs %s" % (i, x, y))
    sa = {e["sha1"] for e in a["entries"]}
    sb = {e["sha1"] for e in b["entries"]}
    print("  images in common : %d of %d / %d" % (len(sa & sb), len(sa), len(sb)))
    print("  images differing : %d" % len(sa ^ sb))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--compare", action="store_true")
    args = ap.parse_args()
    ds = []
    for p in args.files:
        try:
            d = read_ico(p)
        except ValueError as exc:
            print("REJECTED %s" % exc)
            continue
        ds.append(d)
        show(d)
    if args.compare and len(ds) == 2:
        compare(ds[0], ds[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
