#!/usr/bin/env python3
"""xsb2.py - read the OTHER sound bank in this object, the one that is not XACT.

`updata\\soundex\\` holds Microsoft XACT: `WBND` wave banks, `SDBK` sound banks,
an `XGSF` global settings file.  `updata\\sound\\` holds thirteen files with the
same extensions and a completely different format, and the pre-briefing called
both of them XACT because both are named `.xsb` and `.xwb`.  They are not.

The format in `sound\\` is Access Games' own and is derived here from the bytes,
not from any published definition.  It is trivial, it is complete, and it
closes on the byte:

    .xsb    0   'XSB2'
            4   u32  entry count
            8   entry[count], stride 44:
                    0   char[16]  name, NUL padded, always ending '.PCM'
                    16  u32       offset into the matching .xwb
                    20  u32       length in bytes
                    24  u32       sample rate
                    28  u32       channels
                    32  u32       codec id
                    36  u32       loop start, in the codec's own unit
                    40  u32       loop end

    .xwb    a bare concatenation of the streams, no header of its own.

The proofs that this reading is right and not a coincidence are printed by the
tool: entry[i].offset + entry[i].length == entry[i+1].offset for every i, and
the last entry ends exactly at the end of the `.xwb`.  If either fails the tool
says so rather than rounding.

Nothing is decoded and no sample leaves the object.

    python tools/xsb2.py DIR
    python tools/xsb2.py DIR --names        also list entry names
"""
import argparse
import glob
import os
import struct
import sys

STRIDE = 44


def read(path):
    with open(path, "rb") as fh:
        d = fh.read()
    if d[:4] != b"XSB2":
        raise ValueError("not XSB2")
    n = struct.unpack_from("<I", d, 4)[0]
    if 8 + n * STRIDE != len(d):
        raise ValueError("entry count %d does not fill %d bytes" % (n, len(d)))
    out = []
    for i in range(n):
        r = d[8 + i * STRIDE:8 + (i + 1) * STRIDE]
        name = r[:16].split(b"\x00")[0].decode("latin-1")
        off, ln, rate, ch, codec, ls, le = struct.unpack_from("<7I", r, 16)
        out.append((name, off, ln, rate, ch, codec, ls, le))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--names", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    xsbs = sorted(glob.glob(os.path.join(a.target, "*.xsb")))
    tot_entries = tot_wave = tot_index = 0
    rates = {}
    chans = {}
    codecs = {}
    loops = 0
    exts = {}
    print("%-14s %8s %8s %11s %11s %8s  %s"
          % ("bank", "index", "entries", "wave bytes", "xwb bytes", "residue", "closes"))
    print("-" * 84)
    ok = 0
    for p in xsbs:
        try:
            e = read(p)
        except Exception as exc:
            print("%-14s  NOT XSB2: %s" % (os.path.basename(p), exc))
            continue
        xwb = p[:-4] + ".xwb"
        xwbsize = os.path.getsize(xwb) if os.path.exists(xwb) else -1
        wave = sum(x[2] for x in e)
        # contiguity
        contig = True
        cur = 0
        for name, off, ln, rate, ch, codec, ls, le in e:
            if off != cur:
                contig = False
            cur = off + ln
        residue = xwbsize - cur if xwbsize >= 0 else None
        closes = "yes" if (contig and residue == 0) else ("gaps" if not contig else "no")
        if closes == "yes":
            ok += 1
        print("%-14s %8d %8d %11d %11d %8s  %s"
              % (os.path.basename(p), os.path.getsize(p), len(e), wave,
                 xwbsize, residue, closes))
        tot_entries += len(e)
        tot_wave += wave
        tot_index += os.path.getsize(p)
        for name, off, ln, rate, ch, codec, ls, le in e:
            rates[rate] = rates.get(rate, 0) + 1
            chans[ch] = chans.get(ch, 0) + 1
            codecs[codec] = codecs.get(codec, 0) + 1
            if ls or le:
                loops += 1
            ext = os.path.splitext(name)[1].upper()
            exts[ext] = exts.get(ext, 0) + 1
        if a.names:
            for name, off, ln, rate, ch, codec, ls, le in e[:8]:
                print("        %-18s off %10d len %10d %6d Hz %dch codec %d loop %d..%d"
                      % (name, off, ln, rate, ch, codec, ls, le))

    print("-" * 84)
    print("banks                 : %d, of which %d close on the byte" % (len(xsbs), ok))
    print("entries               : %d" % tot_entries)
    print("index bytes (.xsb)    : %d" % tot_index)
    print("wave bytes (.xwb)     : %d" % tot_wave)
    print("index overhead        : %.4f %% of the wave bytes"
          % (100.0 * tot_index / tot_wave if tot_wave else 0))
    print("sample rates          : %s"
          % ", ".join("%d Hz x%d" % (k, v) for k, v in sorted(rates.items(), key=lambda kv: -kv[1])))
    print("channels              : %s"
          % ", ".join("%d ch x%d" % (k, v) for k, v in sorted(chans.items())))
    print("codec ids             : %s"
          % ", ".join("%d x%d" % (k, v) for k, v in sorted(codecs.items())))
    print("entries with a loop   : %d of %d" % (loops, tot_entries))
    print("name extensions       : %s"
          % ", ".join("%s x%d" % (k, v) for k, v in sorted(exts.items(), key=lambda kv: -kv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
