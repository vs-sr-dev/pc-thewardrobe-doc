#!/usr/bin/env python3
"""xact.py - read Microsoft XACT wave banks, sound banks and global settings.

XACT is the Cross-platform Audio Creation Tool that shipped with the Xbox 360
and the DirectX SDK.  Its three container formats are public and documented in
the SDK headers, and this reader implements them from that definition and says
so:

    WBND   wave bank   .xwb   header, five segments, per-entry format dword
    SDBK   sound bank  .xsb   header with a 64-bit FILETIME and a platform byte
    XGSF   global      .xgs   same header shape, categories and variables

The wave bank header, XACT3 version 46:

    0   'WBND'
    4   dwVersion              46
    8   dwHeaderVersion        44
    12  segment[0] BANKDATA          (offset, length)
    20  segment[1] ENTRYMETADATA
    28  segment[2] SEEKTABLES
    36  segment[3] ENTRYNAMES
    44  segment[4] ENTRYWAVEDATA

BANKDATA holds dwFlags, dwEntryCount, a 64-byte bank name, dwEntryMetaDataSize,
dwEntryNameElementSize, dwAlignment and a compact format dword.  Each entry's
format dword packs, from bit 0: 2 bits codec, 3 bits channels, 18 bits sample
rate, 8 bits block alignment, 1 bit bit-depth.  Codec 0 is PCM, 1 is XMA,
2 is ADPCM, 3 is WMA/xWMA.

The FILETIME in a sound bank header is the only clock in this object's audio,
so it is printed in UTC and never adjusted.

Nothing is decoded and no sample leaves the object.

    python tools/xact.py DIR
    python tools/xact.py FILE [FILE ...] --entries
"""
import argparse
import datetime
import glob
import os
import struct
import sys

CODEC = {0: "PCM", 1: "XMA", 2: "ADPCM", 3: "WMA/xWMA"}
PLATFORM = {1: "Windows", 2: "Xbox 360", 3: "Windows (3)"}


def filetime(v):
    if v == 0:
        return "(zero)"
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).strftime(
                    "%Y-%m-%d %H:%M:%S")
    except Exception:
        return "(out of range)"


class WaveBank(object):
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(4096)
            if head[:4] != b"WBND":
                raise ValueError("not WBND")
            self.version, self.headerversion = struct.unpack_from("<II", head, 4)
            self.seg = [struct.unpack_from("<II", head, 12 + 8 * i) for i in range(5)]
            bdoff, bdlen = self.seg[0]
            bd = head[bdoff:bdoff + bdlen]
            (self.flags, self.entrycount) = struct.unpack_from("<II", bd, 0)
            self.name = bd[8:72].split(b"\x00")[0].decode("latin-1")
            (self.metasize, self.namesize, self.alignment) = \
                struct.unpack_from("<III", bd, 72)
            self.compactfmt = struct.unpack_from("<I", bd, 84)[0]
            # entry metadata
            moff, mlen = self.seg[1]
            fh.seek(moff)
            meta = fh.read(mlen)
            self.entries = []
            stride = self.metasize or 24
            for i in range(self.entrycount):
                r = meta[i * stride:(i + 1) * stride]
                if len(r) < 24:
                    break
                flagsdur, fmt, off, ln = struct.unpack_from("<IIII", r, 0)
                self.entries.append((fmt, off, ln, flagsdur))
            # entry names
            self.names = []
            noff, nlen = self.seg[3]
            if nlen and self.namesize:
                fh.seek(noff)
                nb = fh.read(nlen)
                for i in range(self.entrycount):
                    s = nb[i * self.namesize:(i + 1) * self.namesize]
                    self.names.append(s.split(b"\x00")[0].decode("latin-1"))
            self.dataoff, self.datalen = self.seg[4]

    @staticmethod
    def decode_format(f):
        codec = f & 0x3
        chans = (f >> 2) & 0x7
        rate = (f >> 5) & 0x3FFFF
        align = (f >> 23) & 0xFF
        bits = (f >> 31) & 0x1
        return codec, chans, rate, align, bits

    def summary(self):
        wave = sum(e[2] for e in self.entries)
        fmts = {}
        for fmt, off, ln, fd in self.entries:
            fmts[self.decode_format(fmt)] = fmts.get(self.decode_format(fmt), 0) + 1
        return wave, fmts


def read_sdbk(path):
    with open(path, "rb") as fh:
        h = fh.read(64)
    if h[:4] not in (b"SDBK", b"XGSF"):
        raise ValueError("not SDBK/XGSF")
    tool, fmtver, crc = struct.unpack_from("<HHH", h, 4)
    ft = struct.unpack_from("<Q", h, 10)[0]
    plat = h[18]
    return {
        "magic": h[:4].decode("ascii"),
        "tool": tool, "format": fmtver, "crc": crc,
        "filetime": ft, "when": filetime(ft),
        "platform": plat,
        "rest": h[19:31],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--entries", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    files = []
    for t in a.targets:
        if os.path.isdir(t):
            files.extend(sorted(glob.glob(os.path.join(t, "*"))))
        else:
            files.append(t)

    banks = []
    print("%-22s %10s %5s %5s %9s %10s  %s"
          % ("wave bank", "bytes", "ver", "hdr", "entries", "wave bytes", "formats"))
    print("-" * 100)
    for p in files:
        try:
            wb = WaveBank(p)
        except Exception:
            continue
        wave, fmts = wb.summary()
        # collapse by codec and channel count; the sample rate wobbles by a
        # few Hz per entry on the converted voice banks and printing every
        # distinct value would be a page of noise, so the spread is printed
        # as a range instead.
        coll = {}
        for k, v in fmts.items():
            key = (k[0], k[1])
            lo, hi, n = coll.get(key, (k[2], k[2], 0))
            coll[key] = (min(lo, k[2]), max(hi, k[2]), n + v)
        desc = ", ".join(
            "%s %dch %s x%d" % (CODEC.get(k[0], k[0]), k[1],
                                ("%dHz" % lo) if lo == hi else "%d-%dHz" % (lo, hi), n)
            for k, (lo, hi, n) in sorted(coll.items(), key=lambda kv: -kv[1][2]))
        print("%-22s %10d %5d %5d %9d %10d  %s"
              % (os.path.basename(p), wb.size, wb.version, wb.headerversion,
                 wb.entrycount, wave, desc))
        banks.append(wb)
        if a.entries:
            for i, (fmt, off, ln, fd) in enumerate(wb.entries[:12]):
                nm = wb.names[i] if i < len(wb.names) else ""
                print("        %4d %-32s off %10d len %10d" % (i, nm, off, ln))

    if banks:
        print("-" * 100)
        print("wave banks            : %d" % len(banks))
        print("entries               : %d" % sum(b.entrycount for b in banks))
        print("wave bytes            : %d" % sum(b.summary()[0] for b in banks))
        print("container bytes       : %d" % sum(b.size for b in banks))
        print("bank names            : %s"
              % ", ".join(sorted(set(b.name for b in banks if b.name))))
        print("entry name tables     : %d of %d banks carry one"
              % (sum(1 for b in banks if b.names), len(banks)))

    print()
    print("%-22s %10s %5s %5s %6s %-10s %s"
          % ("sound bank / global", "bytes", "tool", "fmt", "plat", "platform", "FILETIME (UTC)"))
    print("-" * 100)
    n = 0
    for p in files:
        try:
            h = read_sdbk(p)
        except Exception:
            continue
        n += 1
        print("%-22s %10d %5d %5d %6d %-10s %s"
              % (os.path.basename(p), os.path.getsize(p), h["tool"], h["format"],
                 h["platform"], PLATFORM.get(h["platform"], "?"), h["when"]))
    print("-" * 100)
    print("sound banks / globals : %d" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
