#!/usr/bin/env python3
"""oggcensus.py -- census every Ogg Vorbis file in a tree, structurally, with
a per-page checksum and a closure on every file.

`oggmeta.py` reads the Vorbis COMMENT header -- the vendor string and the
`FIELD=value` pairs -- and nothing else. It was written for an object whose
finding was in those fields. On `pc-rpgmakerxp-doc`'s object there are two
hundred Ogg files, not one of them carries a comment field, and everything
worth knowing about them is in the two headers `oggmeta.py` walks past and in
the pages it never counts.

WHAT IS READ, AND FROM WHOSE DOCUMENT
-------------------------------------
The page structure is IETF **RFC 3533**: `OggS`, a version byte, a header-type
byte, a 64-bit granule position, a 32-bit stream serial, a 32-bit page
sequence, a 32-bit CRC, a segment count and that many segment lengths. A page
is therefore `27 + segments + sum(segment lengths)` bytes and a file is a
sequence of pages with nothing between them.

The identification header is Xiph.Org's **Vorbis I** specification, section
4.2.2: `\\x01vorbis`, a version `u32` that must be 0, a channel count, a sample
rate, three bitrate fields and a blocksize byte.

THE THREE CLOSURES
------------------
  * the pages tile the file: walking page lengths from byte 0 lands exactly on
    the last byte, or the file is reported as not closing;
  * every page's CRC-32 is recomputed and checked. Ogg's CRC is its own: the
    polynomial is 0x04C11DB7 **unreflected**, the register starts at zero,
    there is no final inversion, and the four CRC bytes are treated as zero
    while the sum is taken. It is not zlib's CRC and a tool that used zlib's
    would fail on every page;
  * the last page's granule position, divided by the sample rate, is the
    playing time, and the last page must carry the end-of-stream flag.

    python tools/oggcensus.py census rpgmakerxp-steam
    python tools/oggcensus.py show rpgmakerxp-steam/rtp/Audio/BGM/001-Battle01.ogg
    python tools/oggcensus.py selftest
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

MAGIC = b"OggS"
IDENT = b"\x01vorbis"


class OggError(Exception):
    pass


def _crc_table():
    table = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if r & 0x80000000 \
                else (r << 1) & 0xFFFFFFFF
        table.append(r)
    return table


CRC = _crc_table()


def crc32_ogg(data):
    r = 0
    for b in data:
        r = ((r << 8) & 0xFFFFFFFF) ^ CRC[((r >> 24) & 0xFF) ^ b]
    return r


def pages(blob, path="<bytes>"):
    """Yield (offset, length, header_type, granule, serial, seq, crc_ok,
    payload). Raises rather than guessing."""
    p = 0
    n = len(blob)
    if n < 27 or blob[:4] != MAGIC:
        raise OggError("%s: does not begin OggS" % path)
    while p < n:
        if blob[p:p + 4] != MAGIC:
            raise OggError("%s: no page at offset %d (found %r)"
                           % (path, p, blob[p:p + 4]))
        if p + 27 > n:
            raise OggError("%s: a page header at %d runs past the end"
                           % (path, p))
        (ver, htype, granule, serial, seq, crc,
         nseg) = struct.unpack_from("<BBqIIIB", blob, p + 4)
        if ver != 0:
            raise OggError("%s: page at %d declares version %d, not 0"
                           % (path, p, ver))
        if p + 27 + nseg > n:
            raise OggError("%s: the segment table at %d runs past the end"
                           % (path, p))
        segs = blob[p + 27:p + 27 + nseg]
        body = sum(segs)
        length = 27 + nseg + body
        if p + length > n:
            raise OggError("%s: page at %d declares %d bytes and %d remain"
                           % (path, p, length, n - p))
        raw = bytearray(blob[p:p + length])
        raw[22:26] = b"\0\0\0\0"
        ok = crc32_ogg(bytes(raw)) == crc
        yield (p, length, htype, granule, serial, seq, ok,
               blob[p + 27 + nseg:p + length])
        p += length


def identification(payload, path="<bytes>"):
    if payload[:7] != IDENT:
        raise OggError("%s: the first packet is not \\x01vorbis" % path)
    (ver, ch, rate, bmax, bnom, bmin) = struct.unpack_from("<IBIiii",
                                                           payload, 7)
    if ver != 0:
        raise OggError("%s: Vorbis version %d, not 0" % (path, ver))
    return dict(channels=ch, rate=rate, bitrate_max=bmax, bitrate_nominal=bnom,
                bitrate_min=bmin)


def read(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    rows = list(pages(blob, path))
    reach = rows[-1][0] + rows[-1][1]
    ident = identification(rows[0][7], path)
    last = rows[-1]
    eos = bool(last[2] & 0x04)
    granule = last[3]
    serials = {r[4] for r in rows}
    return dict(bytes=len(blob), pages=len(rows), residue=reach - len(blob),
                crc_ok=sum(1 for r in rows if r[6]), eos=eos,
                granule=granule, serials=len(serials),
                seconds=granule / ident["rate"] if ident["rate"] else 0.0,
                **ident)


def ogg_files(root):
    """Every Ogg file under a root, SELECTED BY MAGIC and not by name.

    Repaired on pc-rpgmakermv-doc. This function filtered on `.ogg`, which is
    the defect `pc-rpgmakervxace-doc/docs/12` catalogued in `mzcensus.py` --
    thirteenth appearance there -- living in a tool written in the same
    session that catalogued it. It was found by a check written for
    `audiopair.py` before that tool was pointed at the object, which asserted
    that a file named `.ogg` and containing something else is not collected;
    the assertion failed and this is the repair.

    RFC 3533: a page begins `OggS` and a version byte, which is 0 in every Ogg
    ever shipped. Reading five bytes of every file is the price of the rule.
    """
    if os.path.isfile(root):
        return [root]
    out = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as fh:
                    head = fh.read(5)
            except OSError:
                continue
            if head[:4] == MAGIC and len(head) == 5 and head[4] == 0:
                out.append(p)
    if not out:
        sys.exit("oggcensus: no .ogg under %r -- refusing to report a clean "
                 "table over an empty population" % root)
    return out


def cmd_census(root):
    files = ogg_files(root)
    closed = crcok = crctotal = pagecount = 0
    refused = []
    seconds = 0.0
    chans = collections.Counter()
    rates = collections.Counter()
    nominal = collections.Counter()
    serialone = 0
    eosall = 0
    longest = (0.0, "")
    shortest = (1e9, "")
    total_bytes = 0
    for p in files:
        try:
            r = read(p)
        except (OggError, struct.error) as e:
            refused.append((p, str(e)))
            continue
        total_bytes += r["bytes"]
        pagecount += r["pages"]
        crcok += r["crc_ok"]
        crctotal += r["pages"]
        closed += r["residue"] == 0
        seconds += r["seconds"]
        chans[r["channels"]] += 1
        rates[r["rate"]] += 1
        nominal[r["bitrate_nominal"]] += 1
        serialone += r["serials"] == 1
        eosall += r["eos"]
        rel = os.path.relpath(p, root).replace(os.sep, "/") \
            if os.path.isdir(root) else p
        if r["seconds"] > longest[0]:
            longest = (r["seconds"], rel)
        if r["seconds"] < shortest[0]:
            shortest = (r["seconds"], rel)
    n = len(files)
    print("root                      : %s" % root)
    print("files whose first bytes are OggS : %d" % n)
    print("parsed as Ogg             : %d" % (n - len(refused)))
    print("refused                   : %d" % len(refused))
    print("bytes in parsed files     : %d" % total_bytes)
    print()
    print("-- closure: 27 + segments + sum(segment lengths), page by page ---")
    print("   files closing at residue 0        : %d of %d" % (closed, n))
    print("   pages walked                      : %d" % pagecount)
    print("   pages whose CRC-32 verifies       : %d of %d"
          % (crcok, crctotal))
    print("   files with exactly one stream     : %d of %d" % (serialone, n))
    print("   files whose last page flags EOS   : %d of %d" % (eosall, n))
    print()
    print("-- what the identification header declares ----------------------")
    print("   channels        : %s" % dict(chans))
    print("   sample rates    : %s" % dict(rates))
    print("   nominal bitrate : %s"
          % ", ".join("%d x %d" % (v, k)
                      for k, v in sorted(nominal.items(), reverse=True)))
    print()
    print("-- the clock the granule position is ----------------------------")
    print("   total playing time : %.3f s (%.2f min)"
          % (seconds, seconds / 60.0))
    print("   longest            : %s at %.3f s" % (longest[1], longest[0]))
    print("   shortest           : %s at %.3f s" % (shortest[1], shortest[0]))
    print("   mean               : %.3f s" % (seconds / n if n else 0))
    print()
    print("   The granule position of a Vorbis stream's last page is the")
    print("   number of samples; divided by the sample rate it is the")
    print("   playing time. It is declared by the encoder and this tool does")
    print("   not decode a single sample to check it.")
    for p, e in refused:
        print("   REFUSED %s : %s" % (p, e), file=sys.stderr)
    return 1 if refused or closed != n or crcok != crctotal else 0


def cmd_show(path):
    dirguard.want_file(path, "oggcensus")
    r = read(path)
    for k in sorted(r):
        print("  %-18s %s" % (k, r[k]))
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    # The published check value for Ogg's CRC. The point of testing it is that
    # zlib's CRC-32 of the same bytes is a DIFFERENT number, and a tool that
    # reached for zlib would fail on every page of every file.
    import zlib
    ours = crc32_ogg(b"123456789")
    ok("Ogg's CRC of '123456789' is 0x89A1897F",
       ours == 0x89A1897F, hex(ours))
    ok("and it is not zlib's CRC-32 of the same bytes",
       ours != zlib.crc32(b"123456789"),
       "%s vs %s" % (hex(ours), hex(zlib.crc32(b"123456789"))))
    ok("the empty string sums to zero", crc32_ogg(b"") == 0)

    # a page built by hand, with its own CRC filled in
    def build(htype=0x02, granule=0, serial=7, seq=0, body=b"hello"):
        segs = bytes([len(body)])
        head = (MAGIC + struct.pack("<BBqIIIB", 0, htype, granule, serial,
                                    seq, 0, 1) + segs)
        page = bytearray(head + body)
        c = crc32_ogg(bytes(page))
        page[22:26] = struct.pack("<I", c)
        return bytes(page)

    page = build()
    rows = list(pages(page))
    ok("one hand-built page walks", len(rows) == 1, str(len(rows)))
    ok("its declared length is 27 + 1 + 5 = 33",
       rows[0][1] == 33, str(rows[0][1]))
    ok("its CRC verifies", rows[0][6] is True)
    bad = bytearray(page)
    bad[-1] ^= 0xFF
    ok("one flipped payload bit fails the CRC",
       list(pages(bytes(bad)))[0][6] is False)

    ok("a file not beginning OggS is refused",
       _refuses(lambda: list(pages(b"RIFF" + bytes(40)))))
    ok("a truncated page is refused",
       _refuses(lambda: list(pages(page[:20]))))
    ok("a page declaring more body than exists is refused",
       _refuses(lambda: list(pages(page[:-2]))))
    ok("a page with a non-zero version byte is refused",
       _refuses(lambda: list(pages(build_ver(page)))))

    ident = IDENT + struct.pack("<IBIiii", 0, 2, 44100, 0, 112000, 0) + b"\x01"
    d = identification(ident)
    ok("an identification header reads channels and rate",
       (d["channels"], d["rate"]) == (2, 44100), str(d))
    ok("its nominal bitrate is read",
       d["bitrate_nominal"] == 112000, str(d["bitrate_nominal"]))
    ok("a first packet that is not \\x01vorbis is refused",
       _refuses(lambda: identification(b"\x03vorbis" + bytes(20))))

    ok("a directory is refused rather than raised on",
       _exits(lambda: cmd_show(os.path.dirname(os.path.abspath(__file__)))))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def build_ver(page):
    bad = bytearray(page)
    bad[4] = 9
    return bytes(bad)


def _refuses(fn):
    try:
        fn()
    except OggError:
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
        sys.exit("oggcensus: %s needs a path" % args.mode)
    if args.mode == "census":
        return cmd_census(args.path)
    return cmd_show(args.path)


if __name__ == "__main__":
    sys.exit(main())
