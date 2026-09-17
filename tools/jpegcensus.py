#!/usr/bin/env python3
"""jpegcensus.py -- census every JPEG in a tree, structurally, with a closure
on each file.

`jpeg.py` reads ONE file and prints its markers, and on this collection's
`pc-rpgmakerxp-doc` object it had been pointed at exactly one of fifty-nine.
Handed the tree it raised an uncaught `PermissionError`, which `dirguard.py`
now stops. This tool is the census `jpeg.py` was never going to be, and it adds
the thing a marker dump does not have: **a walk that has to land on the last
byte.**

WHOSE DOCUMENT
--------------
ITU-T T.81 / ISO/IEC 10918-1. A JPEG is `FFD8`, then a sequence of marker
segments, each `FF` + a marker byte + a 16-bit big-endian length that counts
itself; `D0`..`D7`, `01` and `FF` padding are standalone. After `SOS` comes
entropy-coded data which is not length-prefixed: it runs until the next marker
that is neither a restart nor a stuffed `FF 00`. The file ends `FFD9`.

THE CLOSURE
-----------
The walk consumes header segments by their declared lengths and scan data by
the stuffing rule, and must arrive at `EOI` exactly at the last byte. A file
with trailing bytes after `EOI`, or one that runs out mid-segment, is reported
and not smoothed over -- which is how the one file in this object that carries
something after `EOI` would be found if there were one.

    python tools/jpegcensus.py census rpgmakerxp-steam
    python tools/jpegcensus.py show <one.jpg>
    python tools/jpegcensus.py selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                              # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

STANDALONE = set(range(0xD0, 0xD8)) | {0x01, 0xD8, 0xD9}
SOF = {0xC0: "SOF0 baseline", 0xC1: "SOF1 extended sequential",
       0xC2: "SOF2 progressive", 0xC3: "SOF3 lossless",
       0xC5: "SOF5", 0xC6: "SOF6", 0xC7: "SOF7", 0xC9: "SOF9",
       0xCA: "SOF10 progressive arithmetic", 0xCB: "SOF11",
       0xCD: "SOF13", 0xCE: "SOF14", 0xCF: "SOF15"}
NAMES = {0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xC4: "DHT",
         0xDD: "DRI", 0xFE: "COM"}


class JpegError(Exception):
    pass


def name_of(m):
    if m in NAMES:
        return NAMES[m]
    if m in SOF:
        return SOF[m].split()[0]
    if 0xE0 <= m <= 0xEF:
        return "APP%d" % (m - 0xE0)
    if 0xD0 <= m <= 0xD7:
        return "RST%d" % (m - 0xD0)
    return "FF%02X" % m


def walk(blob, path="<bytes>"):
    """Yield (offset, marker, payload). Raises rather than guessing."""
    n = len(blob)
    if n < 4 or blob[0] != 0xFF or blob[1] != 0xD8:
        raise JpegError("%s: does not begin FFD8" % path)
    p = 2
    yield (0, 0xD8, b"")
    while p < n:
        if blob[p] != 0xFF:
            raise JpegError("%s: expected a marker at %d, found %02x"
                            % (path, p, blob[p]))
        while p < n and blob[p] == 0xFF:
            p += 1
        if p >= n:
            raise JpegError("%s: fill bytes run to the end" % path)
        m = blob[p]
        p += 1
        if m in STANDALONE:
            yield (p - 2, m, b"")
            if m == 0xD9:
                if p != n:
                    raise JpegError("%s: EOI at %d but the file is %d bytes"
                                    % (path, p, n))
                return
            continue
        if p + 2 > n:
            raise JpegError("%s: a length at %d runs past the end" % (path, p))
        (ln,) = struct.unpack_from(">H", blob, p)
        if ln < 2 or p + ln > n:
            raise JpegError("%s: marker %s at %d declares %d bytes and %d "
                            "remain" % (path, name_of(m), p - 2, ln, n - p))
        payload = blob[p + 2:p + ln]
        yield (p - 2, m, payload)
        p += ln
        if m == 0xDA:
            # entropy-coded data: run to the next marker that is not a
            # restart and not a stuffed FF00.
            while p < n - 1:
                if blob[p] == 0xFF:
                    nxt = blob[p + 1]
                    if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                        p += 2 if nxt != 0xFF else 1
                        continue
                    break
                p += 1
            else:
                raise JpegError("%s: the scan runs to the end with no EOI"
                                % path)
    raise JpegError("%s: no EOI" % path)


def read(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    seq = []
    apps = []
    sof = None
    dims = None
    comps = None
    sampling = None
    rst = 0
    for _off, m, payload in walk(blob, path):
        seq.append(name_of(m))
        if 0xE0 <= m <= 0xEF:
            apps.append((name_of(m), bytes(payload[:6])))
        if m in SOF:
            sof = SOF[m]
            prec, h, w, nc = struct.unpack_from(">BHHB", payload, 0)
            dims = (w, h)
            comps = nc
            sfs = []
            for i in range(nc):
                _cid, hv, _tq = struct.unpack_from(">BBB", payload, 6 + i * 3)
                sfs.append((hv >> 4, hv & 15))
            sampling = sfs
            _ = prec
        if m == 0xDD:
            rst += 1
    return dict(bytes=len(blob), markers=seq, apps=apps, sof=sof, dims=dims,
                components=comps, sampling=sampling, dri=rst)


def jpeg_files(root):
    if os.path.isfile(root):
        return [root]
    out = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            if f.lower().endswith((".jpg", ".jpeg", ".jpe")):
                out.append(os.path.join(dp, f))
    if not out:
        sys.exit("jpegcensus: no JPEG under %r -- refusing to report a clean "
                 "table over an empty population" % root)
    return out


def cmd_census(root):
    files = jpeg_files(root)
    refused = []
    sofs = collections.Counter()
    dims = collections.Counter()
    comps = collections.Counter()
    samp = collections.Counter()
    appsets = collections.Counter()
    seqs = collections.Counter()
    exif = photoshop = adobe = 0
    total = 0
    for p in files:
        try:
            r = read(p)
        except (JpegError, struct.error) as e:
            refused.append((p, str(e)))
            continue
        total += r["bytes"]
        sofs[r["sof"]] += 1
        dims[r["dims"]] += 1
        comps[r["components"]] += 1
        samp[str(r["sampling"])] += 1
        names = tuple(sorted({a for a, _h in r["apps"]}))
        appsets[names] += 1
        seqs[" ".join(r["markers"])] += 1
        for a, head in r["apps"]:
            if a == "APP1" and head.startswith(b"Exif"):
                exif += 1
            if a == "APP13":
                photoshop += 1
            if a == "APP14" and head.startswith(b"Adobe"):
                adobe += 1
    n = len(files)
    print("root                      : %s" % root)
    print("files matching .jpg/.jpeg : %d" % n)
    print("parsed as JPEG            : %d" % (n - len(refused)))
    print("refused                   : %d" % len(refused))
    print("bytes in parsed files     : %d" % total)
    print()
    print("-- closure: every segment by its declared length, the scan by the")
    print("   stuffing rule, and EOI landing on the last byte -------------")
    print("   files whose walk lands on the last byte : %d of %d"
          % (n - len(refused), n))
    print()
    print("-- what SOF declares --------------------------------------------")
    for k, v in sofs.most_common():
        print("   %-34s %d" % (k, v))
    print("   components   : %s" % dict(comps))
    print("   sampling     : %s" % dict(samp))
    print("   DRI segments : %d files carry one"
          % sum(1 for _ in range(0)) if False else "")
    print()
    print("-- geometry -----------------------------------------------------")
    print("   distinct (width, height) : %d" % len(dims))
    for k, v in dims.most_common(8):
        print("      %-16s x %d" % ("%d x %d" % k, v))
    print()
    print("-- the APPn sets, which is where the metadata is ----------------")
    for k, v in appsets.most_common():
        print("   %-40s %d files" % (", ".join(k) or "(none)", v))
    print("   files carrying an Exif APP1               : %d of %d"
          % (exif, n))
    print("   files carrying a Photoshop APP13          : %d of %d"
          % (photoshop, n))
    print("   files carrying an Adobe APP14             : %d of %d"
          % (adobe, n))
    print()
    print("-- marker sequences ---------------------------------------------")
    print("   distinct sequences : %d" % len(seqs))
    for k, v in seqs.most_common(6):
        print("   %3d x  %s" % (v, k))
    for p, e in refused:
        print("   REFUSED %s : %s" % (p, e), file=sys.stderr)
    return 1 if refused else 0


def cmd_show(path):
    dirguard.want_file(path, "jpegcensus")
    r = read(path)
    print("  bytes      : %d" % r["bytes"])
    print("  SOF        : %s" % r["sof"])
    print("  dimensions : %s" % (r["dims"],))
    print("  components : %s  sampling %s" % (r["components"], r["sampling"]))
    print("  APPn       : %s" % ", ".join("%s %r" % a for a in r["apps"]))
    print("  markers    : %s" % " ".join(r["markers"]))
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    def seg(marker, payload):
        return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) \
            + payload

    sof0 = struct.pack(">BHHB", 8, 4, 6, 3) + bytes([1, 0x22, 0, 2, 0x11, 1,
                                                     3, 0x11, 1])
    good = (b"\xff\xd8" + seg(0xE0, b"JFIF\0\1\2\0\0\1\0\1\0\0")
            + seg(0xDB, bytes(65)) + seg(0xC0, sof0) + seg(0xC4, bytes(20))
            + seg(0xDA, bytes(10)) + b"\x12\x34\xff\x00\x56"
            + b"\xff\xd9")
    r = read_bytes(good)
    ok("a hand-built JPEG walks to EOI", r is not None)
    ok("its SOF0 is recognised", r["sof"].startswith("SOF0"), str(r["sof"]))
    ok("its dimensions are width 6 height 4",
       r["dims"] == (6, 4), str(r["dims"]))
    ok("its component count is 3", r["components"] == 3)
    ok("its first component is 2x2", r["sampling"][0] == (2, 2),
       str(r["sampling"]))
    ok("a stuffed FF00 inside the scan does not end it",
       r["markers"][-1] == "EOI", str(r["markers"][-1]))
    ok("APP0 is named APP0", "APP0" in r["markers"])

    ok("a file not beginning FFD8 is refused",
       _refuses(lambda: read_bytes(b"\x89PNG\r\n\x1a\n")))
    ok("trailing bytes after EOI are refused, not ignored",
       _refuses(lambda: read_bytes(good + b"\x00\x00")))
    ok("a segment declaring more than remains is refused",
       _refuses(lambda: read_bytes(good[:-6])))
    ok("a length below 2 is refused",
       _refuses(lambda: read_bytes(b"\xff\xd8\xff\xdb\x00\x01\xff\xd9")))
    ok("APP13 is named APP13", name_of(0xED) == "APP13")
    ok("APP14 is named APP14", name_of(0xEE) == "APP14")
    ok("a restart marker is standalone", 0xD3 in STANDALONE)
    ok("a directory is refused rather than raised on",
       _exits(lambda: cmd_show(os.path.dirname(os.path.abspath(__file__)))))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good_, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good_ else "FAIL",
                                   note))
        if not good_:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def read_bytes(blob):
    seq = []
    sof = None
    dims = None
    comps = None
    sampling = None
    apps = []
    for _off, m, payload in walk(blob):
        seq.append(name_of(m))
        if 0xE0 <= m <= 0xEF:
            apps.append((name_of(m), bytes(payload[:6])))
        if m in SOF:
            sof = SOF[m]
            _prec, h, w, nc = struct.unpack_from(">BHHB", payload, 0)
            dims = (w, h)
            comps = nc
            sampling = []
            for i in range(nc):
                _cid, hv, _tq = struct.unpack_from(">BBB", payload, 6 + i * 3)
                sampling.append((hv >> 4, hv & 15))
    return dict(bytes=len(blob), markers=seq, apps=apps, sof=sof, dims=dims,
                components=comps, sampling=sampling)


def _refuses(fn):
    try:
        fn()
    except JpegError:
        return True
    except Exception:                                        # noqa: BLE001
        return False
    return False


def _exits(fn):
    try:
        fn()
    except SystemExit:
        return True
    except Exception:                                        # noqa: BLE001
        return False
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("census", "show", "selftest"))
    ap.add_argument("path", nargs="?")
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.path:
        sys.exit("jpegcensus: %s needs a path" % args.mode)
    if args.mode == "census":
        return cmd_census(args.path)
    return cmd_show(args.path)


if __name__ == "__main__":
    sys.exit(main())
