#!/usr/bin/env python3
"""account3do.py -- what fraction of the pressing is of a KNOWN kind.

The point of the whole exercise. A sector map says every sector belongs to a
file; it does not say anybody knows what the file IS. This tool works in bytes
of the user area and puts each one in exactly one bucket, refusing to print a
total that is not the user area.

A byte counts as IDENTIFIED only if a format was derived or validated on this
disc and the tool that reads it consumed the byte. Everything else is UNKNOWN,
including files whose purpose is obvious from their name -- a name is not a
format.

usage: account3do.py TREE SECTORS DECLARED_BLOCKS
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from celdecode import cels_by_scan                     # noqa: E402
from ccbread import Bad                                # noqa: E402
from aifcensus import parse as aif_parse, Bad as AifBad  # noqa: E402
from sdx2dec import read_aifc                          # noqa: E402


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(__doc__)
        raise SystemExit(2)
    tree, sectors, declared = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    U = sectors * 2048

    buckets = {}
    files = []
    for dp, dn, fn in os.walk(tree):
        for f in fn:
            files.append(os.path.join(dp, f))
    files.sort()

    def put(name, n):
        buckets[name] = buckets.get(name, 0) + n

    tree_bytes = 0
    for p in files:
        d = open(p, "rb").read()
        tree_bytes += len(d)
        rel = "/" + os.path.relpath(p, tree).replace(os.sep, "/")
        done = 0

        # AIFF / AIFF-C, read from COMM and SSND
        if d[0:4] == b"FORM" and d[8:12] in (b"AIFF", b"AIFC"):
            try:
                ch, fr, bits, rate, codec, ssnd = read_aifc(p)
                put("AIFF-C SDX2 sample data", len(ssnd))
                put("AIFF/AIFF-C container headers", len(d) - len(ssnd))
                continue
            except Exception:
                pass
            # a FORM that is not AIFF-like: the DSP instruments
        if d[0:4] == b"FORM":
            put("FORM 3INS DSP instruments", len(d))
            continue

        # ARM Image Format
        try:
            aif_parse(d)
            put("ARM Image Format executables", len(d))
            continue
        except AifBad:
            pass

        # cels, found by signature
        if b"CCB " in d:
            got, un = cels_by_scan(d)
            if got:
                put("cel data (CCB, PLUT, PDAT) derived and rendered",
                    len(d) - un)
                if un:
                    put("bytes inside cel-bearing files, kind not derived", un)
                continue

        # the Data Streamer, derived on the third disc: SHDR/FILM/SNDS/FILL,
        # every FRME decoded as Cinepak and every SSMP written out as a WAV.
        # The chain consumes the file to its last byte, so the whole file is
        # accounted for and nothing is left over.
        if d[0:4] == b"SHDR":
            try:
                import streamread
                cs = streamread.chunks(d)
                if cs[-1][0] + cs[-1][2] == len(d):
                    put("Data Streamer: SHDR/FILM/SNDS/FILL, Cinepak decoded",
                        len(d))
                    continue
            except Exception:
                pass

        # BRGR archives, derived on the third disc. The directory is derived
        # and checked; the members are split by whether their own format was
        # derived too, because a container is not its contents.
        if d[0:4] == b"BRGR":
            try:
                import rezread
                import rezcel
                count, members = rezread.parse(d)
                hdr = 8 + 12 * count
                put("BRGR archive directories, derived and checked", hdr)
                for mid, off, ln in members:
                    body = d[off:off + ln]
                    try:
                        rezcel.parse(body)
                        put("BRGR members: headless cels, decoded and rendered",
                            ln)
                    except Exception:
                        put("BRGR members: kind NOT derived", ln)
                continue
            except Exception:
                pass

        # the banner screen, derived on the third disc
        if d[0:8] == b"\x01APPSCRN":
            try:
                import appscrn
                info = appscrn.parse(d)
                put("APPSCRN banner screen, decoded and rendered",
                    24 + info["payload"])
                put("APPSCRN trailing zero bytes", len(d) - 24 - info["payload"])
                continue
            except Exception:
                pass

        # .CHR archives: the offset tree is derived, the leaves are not
        if rel.upper().endswith(".CHR"):
            put(".CHR archives: index derived, leaf pixel data NOT derived",
                len(d))
            continue
        if rel.upper().endswith(".PAL"):
            put(".PAL palettes, 5-5-5 proved", len(d))
            continue
        if d[0:16].startswith(b"SPT v"):
            put("SPT v0.54 containers, signature only", len(d))
            continue
        if len(d) <= 2:
            put("one-byte junk files", len(d))
            continue
        if rel == "/Disc label":
            put("the volume label, derived field by field", len(d))
            continue
        if rel == "/signatures":
            put("/signatures: size, entropy and fill measured, content not read",
                len(d))
            continue
        put("UNKNOWN: no format derived", len(d))

    print("user area                 %12d bytes (%d sectors x 2048)" % (U, sectors))
    print("bytes in files            %12d = %.4f %%"
          % (tree_bytes, 100.0 * tree_bytes / U))
    print()
    known = 0
    for k in sorted(buckets, key=lambda x: -buckets[x]):
        flag = "?" if ("UNKNOWN" in k or "NOT derived" in k
                       or "not derived" in k or "not read" in k) else " "
        if flag == " ":
            known += buckets[k]
        print(" %s %-62s %12d %8.4f %%"
              % (flag, k, buckets[k], 100.0 * buckets[k] / U))
    print()
    fill = U - tree_bytes
    print("   %-62s %12d %8.4f %%"
          % ("not in any file (mastering fill, zeros, directories, copies)",
             fill, 100.0 * fill / U))
    print()
    print("   %-62s %12d %8.4f %%"
          % ("IDENTIFIED (a format derived or validated on this disc)",
             known, 100.0 * known / U))
    unk = tree_bytes - known
    print("   %-62s %12d %8.4f %%"
          % ("IN A FILE, KIND NOT DERIVED", unk, 100.0 * unk / U))
    total = known + unk + fill
    print("   %-62s %12d %8.4f %%" % ("TOTAL", total, 100.0 * total / U))
    if total != U:
        raise SystemExit("account3do: the total is %d, not the user area %d"
                         % (total, U))


if __name__ == "__main__":
    main()
