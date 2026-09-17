#!/usr/bin/env python3
"""bink.py -- count a Bink video from its published header. Nothing is decoded.

Bink is RAD Game Tools' container.  It is not RIFF, so `avi.py` and
`avicheck.py` do not apply to it and are not adapted here.  The header is
public and fixed:

    +0  char[4]  signature: 'BIKb'..'BIKi' for Bink 1, 'KB2a'.. for Bink 2
    +4  u32      file size MINUS 8 (the same convention RIFF uses)
    +8  u32      number of frames
    +12 u32      largest frame, in bytes
    +16 u32      number of frames again
    +20 u32      width
    +24 u32      height
    +28 u32      frame-rate numerator
    +32 u32      frame-rate denominator
    +36 u32      video flags
    +40 u32      number of audio tracks

The frame rate is a RATIO, not a float: 25/1 is PAL, 30000/1001 is NTSC, and
printing it as 29.97 loses the distinction between them.  Both are printed.

    python tools/bink.py FILE...
    python tools/bink.py --census DIR [--ext .bik]
    python tools/bink.py --selftest FILE   (a file that MUST be refused)
"""
import argparse
import collections
import os
import struct
import sys

SIGS = {b"BIKb": "Bink 1, revision b (1999)",
        b"BIKf": "Bink 1, revision f",
        b"BIKg": "Bink 1, revision g",
        b"BIKh": "Bink 1, revision h",
        b"BIKi": "Bink 1, revision i",
        b"KB2a": "Bink 2, revision a",
        b"KB2f": "Bink 2, revision f",
        b"KB2g": "Bink 2, revision g",
        b"KB2i": "Bink 2, revision i",
        b"KB2j": "Bink 2, revision j"}

FLAGS = [(0x00100000, "alpha plane"),
         (0x00040000, "height doubled"),
         (0x00080000, "height interlaced"),
         (0x00010000, "width doubled"),
         (0x00020000, "width interlaced"),
         (0x00000010, "grayscale")]


def read(path, at=None, length=None):
    """`at`/`length` name a member inside a container -- an EmPackFi archive --
    so a Bink video that was never a file on any disk can still be counted."""
    n = os.path.getsize(path) if at is None else length
    with open(path, "rb") as fh:
        if at is not None:
            fh.seek(at)
        h = fh.read(48)
    if len(h) < 44:
        return None, "shorter than a 44-byte header"
    sig = h[0:4]
    if sig not in SIGS:
        return None, "signature %r is not a Bink signature" % sig
    (size, frames, largest, frames2, w, hgt, num, den,
     flags, tracks) = struct.unpack_from("<10I", h, 4)
    return {"path": path, "bytes": n, "sig": sig, "size": size,
            "frames": frames, "largest": largest, "frames2": frames2,
            "w": w, "h": hgt, "num": num, "den": den,
            "flags": flags, "tracks": tracks,
            "closes": size + 8 == n,
            "fps": (float(num) / den if den else 0.0)}, None


def show(r):
    print("%s" % r["path"])
    print("   signature      : %s = %s" % (r["sig"].decode("ascii"), SIGS[r["sig"]]))
    print("   size field     : %d ; +8 = %d ; file is %d -> %s"
          % (r["size"], r["size"] + 8, r["bytes"],
             "OK" if r["closes"] else "MISMATCH"))
    print("   frames         : %d (repeated at +16: %s)"
          % (r["frames"], r["frames"] == r["frames2"]))
    print("   largest frame  : %d bytes" % r["largest"])
    print("   frame          : %d x %d" % (r["w"], r["h"]))
    print("   frame rate     : %d / %d = %.3f fps" % (r["num"], r["den"], r["fps"]))
    print("   duration       : %.2f s" % (r["frames"] / r["fps"] if r["fps"] else 0))
    on = [name for bit, name in FLAGS if r["flags"] & bit]
    print("   video flags    : 0x%08X%s" % (r["flags"], ("  " + ", ".join(on)) if on else ""))
    print("   audio tracks   : %d" % r["tracks"])
    print("   bytes / frame  : %.1f" % (r["bytes"] / float(r["frames"]) if r["frames"] else 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--census")
    ap.add_argument("--ext", default=".bik")
    ap.add_argument("--selftest")
    ap.add_argument("--member", action="append", default=[],
                    help="ARCHIVE:OFFSET:SIZE -- read a Bink header from inside "
                         "a container instead of from a file")
    a = ap.parse_args()

    for spec in a.member:
        arch, off, ln = spec.rsplit(":", 2)
        r, err = read(arch, int(off), int(ln))
        if r is None:
            print("%s @%s: %s" % (arch, off, err))
        else:
            r["path"] = "%s @%s" % (os.path.basename(arch), off)
            show(r)
        print()

    if a.selftest:
        r, err = read(a.selftest)
        if r is not None:
            sys.exit("SELFTEST FAILED: %s read as a Bink file" % a.selftest)
        print("selftest OK: %s refused -- %s" % (os.path.basename(a.selftest), err))
        print()

    for p in a.paths:
        r, err = read(p)
        if r is None:
            print("%s: %s" % (p, err))
        else:
            show(r)
        print()

    if a.census:
        files = []
        for dirpath, dirnames, filenames in os.walk(a.census):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn.lower().endswith(a.ext):
                    files.append(os.path.join(dirpath, fn))
        rows, bad = [], []
        for f in files:
            r, err = read(f)
            (rows if r else bad).append(r or (f, err))
        print("census of %s: %d files, %d read, %d refused"
              % (a.census, len(files), len(rows), len(bad)))
        print()
        print("   %-44s %12s %10s %8s %14s %8s %7s %7s"
              % ("path", "bytes", "frame", "frames", "rate", "seconds", "tracks", "closes"))
        tb = tf = ts = 0
        for r in rows:
            rel = os.path.relpath(r["path"], a.census).replace(os.sep, "/")
            secs = r["frames"] / r["fps"] if r["fps"] else 0
            tb += r["bytes"]
            tf += r["frames"]
            ts += secs
            print("   %-44s %12d %10s %8d %14s %8.1f %7d %7s"
                  % (rel, r["bytes"], "%dx%d" % (r["w"], r["h"]), r["frames"],
                     "%d/%d" % (r["num"], r["den"]), secs, r["tracks"],
                     "yes" if r["closes"] else "NO"))
        print("   %-44s %12d %10s %8d %14s %8.1f"
              % ("TOTAL", tb, "", tf, "", ts))
        print()
        for label, key in (("signature", lambda r: r["sig"].decode("ascii")),
                           ("frame size", lambda r: "%dx%d" % (r["w"], r["h"])),
                           ("frame rate", lambda r: "%d/%d" % (r["num"], r["den"])),
                           ("video flags", lambda r: "0x%08X" % r["flags"]),
                           ("audio tracks", lambda r: r["tracks"]),
                           ("size field + 8 == file", lambda r: r["closes"])):
            c = collections.Counter(key(r) for r in rows)
            print("   %-24s: %s" % (label,
                  ", ".join("%s x%d" % kv for kv in c.most_common())))
        print("   %-24s: %.1f s = %d:%02d" % ("total running time", ts,
                                              int(ts) // 60, int(ts) % 60))
        for f, err in bad:
            print("   REFUSED %s -- %s" % (f, err))


if __name__ == "__main__":
    main()
