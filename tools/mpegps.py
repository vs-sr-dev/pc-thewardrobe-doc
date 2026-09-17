#!/usr/bin/env python3
"""mpegps.py -- count an MPEG-1/2 program stream without decoding it.

Two files in this object are named `.avi` or `.dat` and are neither: they begin
`00 00 01 ba`, which is a program stream pack header (ISO/IEC 11172-1 for
MPEG-1, 13818-1 for MPEG-2). This walks the pack and PES layer, counts packs and
packets per stream id, reads the system clock reference at the first and last
pack, and reads the sequence header of the first video packet for size and rate.
It never decodes a macroblock.

What the pack header says, and how the two versions differ:

    MPEG-1  00 00 01 BA  then a byte whose top nibble is 0b0010 : 12-byte header
    MPEG-2  00 00 01 BA  then a byte whose top two bits are 0b01: 14-byte header
                         plus a 3-bit stuffing length in the last byte

    python tools/mpegps.py "<root>/ed6_logo.avi"
    python tools/mpegps.py "<root>" --walk --ext .avi .dat
"""
import argparse
import collections
import os
import struct
import sys

PACK = b"\x00\x00\x01\xba"
SYSHDR = b"\x00\x00\x01\xbb"
END = b"\x00\x00\x01\xb9"
SEQ = b"\x00\x00\x01\xb3"

# ISO/IEC 11172-2 table 2-3
RATES = {1: 23.976, 2: 24.0, 3: 25.0, 4: 29.97, 5: 30.0, 6: 50.0, 7: 59.94, 8: 60.0}
ASPECT = {1: "1:1 (square)", 2: "0.6735", 3: "16:9 (0.7031)", 4: "0.7615",
          6: "4:3 (0.9157)", 8: "1.0950", 12: "1.2015"}


def streamname(sid):
    if sid == 0xBD:
        return "private stream 1"
    if sid == 0xBE:
        return "padding"
    if sid == 0xBF:
        return "private stream 2"
    if 0xC0 <= sid <= 0xDF:
        return "audio %d (MPEG)" % (sid - 0xC0)
    if 0xE0 <= sid <= 0xEF:
        return "video %d" % (sid - 0xE0)
    return "id 0x%02X" % sid


def scr_mpeg1(b, o):
    """33-bit SCR from an MPEG-1 pack header, in 90 kHz units."""
    v = ((b[o] >> 1) & 0x03) << 30
    v |= b[o + 1] << 22
    v |= ((b[o + 2] >> 1) & 0x7F) << 15
    v |= b[o + 3] << 7
    v |= (b[o + 4] >> 1) & 0x7F
    return v


def seqheader(b, o):
    """ISO/IEC 11172-2 sequence header: 12 bits width, 12 height, 4 aspect, 4 rate."""
    w = (b[o] << 4) | (b[o + 1] >> 4)
    h = ((b[o + 1] & 0x0F) << 8) | b[o + 2]
    ar = b[o + 3] >> 4
    fr = b[o + 3] & 0x0F
    br = (b[o + 4] << 10) | (b[o + 5] << 2) | (b[o + 6] >> 6)
    return w, h, ar, fr, br


def scan(path, limit=None):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        first = fh.read(4)
        if first != PACK:
            return None
        fh.seek(0)
        packs = 0
        streams = collections.Counter()
        sbytes = collections.Counter()
        scr_first = scr_last = None
        version = None
        seq = None
        pos = 0
        consumed = 0
        buf = b""
        base = 0
        eof = False
        while True:
            if not eof and len(buf) - (pos - base) < 65536:
                fh.seek(base + len(buf))
                more = fh.read(1 << 20)
                if more:
                    buf += more
                    if len(buf) > (4 << 20):
                        drop = pos - base
                        buf = buf[drop:]
                        base = pos
                else:
                    eof = True
            o = pos - base
            if o + 6 > len(buf):
                break
            tag = buf[o:o + 4]
            if tag == PACK:
                packs += 1
                b5 = buf[o + 4]
                if (b5 & 0xF0) == 0x20:
                    version = version or 1
                    s = scr_mpeg1(buf, o + 4)
                    hdr = 12
                elif (b5 & 0xC0) == 0x40:
                    version = version or 2
                    s = None
                    hdr = 14 + (buf[o + 13] & 0x07)
                else:
                    break
                if s is not None:
                    if scr_first is None:
                        scr_first = s
                    scr_last = s
                pos += hdr
                consumed += hdr
                continue
            if tag == SYSHDR or (tag[:3] == b"\x00\x00\x01" and tag[3] >= 0xBB):
                sid = tag[3]
                plen = struct.unpack_from(">H", buf, o + 4)[0]
                if tag == SYSHDR:
                    pos += 6 + plen
                    consumed += 6 + plen
                    continue
                streams[sid] += 1
                sbytes[sid] += plen
                if seq is None and 0xE0 <= sid <= 0xEF:
                    chunk = buf[o + 6:o + 6 + min(plen, 4096)]
                    k = chunk.find(SEQ)
                    if k >= 0 and k + 12 < len(chunk):
                        seq = seqheader(chunk, k + 4)
                pos += 6 + plen
                consumed += 6 + plen
                continue
            if tag == END:
                pos += 4
                consumed += 4
                break
            break
        return dict(path=path, size=size, packs=packs, streams=streams, sbytes=sbytes,
                    scr_first=scr_first, scr_last=scr_last, version=version,
                    seq=seq, consumed=consumed, stopped_at=pos)


def report(path):
    r = scan(path)
    print("== %s ==" % os.path.basename(path))
    if r is None:
        print("   does not begin 00 00 01 BA -- NOT A PROGRAM STREAM")
        return False
    print("   size              : %d bytes" % r["size"])
    print("   version           : MPEG-%s (from the pack header shape)" % r["version"])
    print("   packs             : %d" % r["packs"])
    print("   bytes walked      : %d = %.4f %% of the file"
          % (r["consumed"], 100.0 * r["consumed"] / r["size"]))
    print("   stopped at offset : %d, %d bytes short of the end"
          % (r["stopped_at"], r["size"] - r["stopped_at"]))
    if r["scr_first"] is not None and r["scr_last"] is not None:
        d = (r["scr_last"] - r["scr_first"]) / 90000.0
        print("   SCR span          : %d .. %d ticks of 90 kHz = %.3f s"
              % (r["scr_first"], r["scr_last"], d))
        if d:
            print("   mean rate         : %.1f bytes/s = %.0f kbit/s"
                  % (r["size"] / d, r["size"] * 8 / d / 1000.0))
    if r["seq"]:
        w, h, ar, fr, br = r["seq"]
        print("   sequence header   : %dx%d  aspect code %d (%s)  frame rate code %d (%s fps)"
              % (w, h, ar, ASPECT.get(ar, "?"), fr, RATES.get(fr, "?")))
        print("   declared bit rate : %d x 400 = %d bit/s" % (br, br * 400))
    print("   packets by stream :")
    for sid, n in sorted(r["streams"].items()):
        print("      0x%02X %-20s %8d packets %14d payload bytes"
              % (sid, streamname(sid), n, r["sbytes"][sid]))
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--walk", action="store_true")
    ap.add_argument("--ext", nargs="*", default=[".mpg", ".mpeg"])
    a = ap.parse_args()
    if not a.walk:
        sys.exit(0 if report(a.path) else 1)
    seen = hit = 0
    for dirpath, dirnames, filenames in os.walk(a.path):
        dirnames.sort()
        for fn in sorted(filenames):
            if os.path.splitext(fn)[1].lower() in [e.lower() for e in a.ext]:
                seen += 1
                if report(os.path.join(dirpath, fn)):
                    hit += 1
                print()
    print("files examined : %d   program streams : %d" % (seen, hit))


if __name__ == "__main__":
    main()
