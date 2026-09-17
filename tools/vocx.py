#!/usr/bin/env python3
"""Parse Creative Voice Files, and census the speech container `MONSTER.SOU`.

Two commands, and the order they are run in is the point of the tool.

`check` parses ONE plain VOC file and reports whether it consumed every byte.
It exists so that the parser can be validated against `SAMNMAX/TESTWAVE` --
46,689 bytes of known, unencrypted, uncontained VOC left on the disc by the
audio setup program -- BEFORE it is turned loose on 200,190,289 bytes where a
one-byte misalignment would produce thousands of plausible files and a
convincing percentage. A parser that cannot land exactly on the end of a
2-second test sample has no business counting five hours of speech.

`sou` walks the speech container. Its structure is derived here, not looked up:

  * The file opens `'SOU '` with a big-endian declared length of ZERO, so the
    outer wrapper carries no size and cannot be walked as a chunk.
  * What follows alternates: a `VCTL` chunk with a big-endian length that DOES
    include its own 8-byte header, and then a raw VOC file starting with the
    19-character magic. Walking `VCTL` alone stops after 18 bytes, because the
    VOC that follows is not inside it.
  * So the walk is: read a 4-byte tag; if it is `VCTL`, skip its declared
    length; otherwise expect the VOC magic and hand the rest to the VOC parser,
    which returns the exact end of the file from the VOC's own block chain.
    Where a blob ends is stated by the blob, not by the container.

VOC layout, from Creative's published 1990 format and confirmed byte by byte
against `TESTWAVE`: a 19-byte magic plus EOF+two bytes, a 16-bit offset to the
first block, a 16-bit version and a 16-bit check word; then blocks of
`[type:1][length:3 LE]` and type-specific bodies, terminated by a bare type 0.
Sample rate for an 8-bit type-1 block is `1000000 / (256 - time_constant)`.

Usage:
  python tools/vocx.py check <file.voc>
  python tools/vocx.py sou   <MONSTER.SOU> [--csv out.csv] [--extract dir --max N]
"""
import collections
import os
import sys

MAGIC = b"Creative Voice File\x1a"


def parse_voc(d, base=0):
    """Parse a VOC image starting at d[base]. Returns (end, blocks, info)."""
    if d[base:base + 20] != MAGIC:
        raise ValueError("no VOC magic at %d" % base)
    hdr = int.from_bytes(d[base + 20:base + 22], "little")
    ver = int.from_bytes(d[base + 22:base + 24], "little")
    chk = int.from_bytes(d[base + 24:base + 26], "little")
    p = base + hdr
    blocks = []
    samples = 0
    rate = None
    bits = 8
    chans = 1
    while True:
        if p >= len(d):
            raise ValueError("ran off the end at %d" % p)
        t = d[p]
        if t == 0:
            blocks.append((0, 0, p))
            p += 1
            break
        ln = int.from_bytes(d[p + 1:p + 4], "little")
        body = p + 4
        if t == 1:
            tc = d[body]
            pack = d[body + 1]
            rate = rate or 1000000.0 / (256 - tc)
            samples += ln - 2
            if pack != 0:
                bits = {1: 4, 2: 3, 3: 2}.get(pack, 8)
        elif t == 9:
            rate = rate or int.from_bytes(d[body:body + 4], "little")
            bits = d[body + 4]
            chans = d[body + 5]
            samples += ln - 12
        elif t == 2:
            samples += ln
        elif t == 3:
            tc = d[body + 2]
            samples += int.from_bytes(d[body:body + 2], "little") + 1
        blocks.append((t, ln, p))
        p += 4 + ln
    info = dict(hdr=hdr, ver=ver, chk=chk, rate=rate, bits=bits,
                chans=chans, samples=samples,
                secs=(samples / rate) if rate else 0.0)
    return p, blocks, info


def cmd_check(path):
    d = open(path, "rb").read()
    end, blocks, info = parse_voc(d, 0)
    print("file            %s" % os.path.basename(path))
    print("size            %d" % len(d))
    print("header offset   %d" % info["hdr"])
    print("version         %d.%02d" % (info["ver"] >> 8, info["ver"] & 0xFF))
    print("check word      0x%04x  (0x1234 + ~version = 0x%04x)"
          % (info["chk"], (0x1234 + (~info["ver"] & 0xFFFF)) & 0xFFFF))
    print("blocks          %d" % len(blocks))
    for t, ln, off in blocks:
        print("  type %-2d len %-10d at %d" % (t, ln, off))
    print("sample rate     %s Hz" % (round(info["rate"], 2) if info["rate"] else "?"))
    print("bits/channels   %d / %d" % (info["bits"], info["chans"]))
    print("samples         %d" % info["samples"])
    print("duration        %.4f s" % info["secs"])
    print("parser stopped  %d" % end)
    print("file size       %d" % len(d))
    print("\n%s" % ("CONSUMES THE FILE EXACTLY" if end == len(d)
                    else "LEFTOVER %d BYTES -- PARSER IS WRONG" % (len(d) - end)))
    return 0 if end == len(d) else 1


def cmd_sou(path, csv, extract, maxn):
    d = open(path, "rb").read()
    n = len(d)
    if d[:4] != b"SOU ":
        sys.exit("not a SOU container")
    declared = int.from_bytes(d[4:8], "big")
    print("SOU declared length %d, file %d" % (declared, n))
    p = 8
    vctl_n = vctl_b = 0
    voc_n = voc_b = 0
    samples = collections.Counter()
    rates = collections.Counter()
    secs = 0.0
    rows = []
    bad = 0
    gaps = []
    gap_b = 0
    while p < n:
        tag = d[p:p + 4]
        if tag == b"VCTL":
            ln = int.from_bytes(d[p + 4:p + 8], "big")
            if ln < 8 or p + ln > n:
                print("bad VCTL length %d at %d" % (ln, p)); bad += 1; break
            vctl_n += 1
            vctl_b += ln
            p += ln
            continue
        if d[p:p + 20] == MAGIC:
            try:
                end, blocks, info = parse_voc(d, p)
            except ValueError as e:
                print("VOC parse failed at %d: %s" % (p, e)); bad += 1; break
            voc_n += 1
            voc_b += end - p
            samples[info["bits"]] += info["samples"]
            rates[round(info["rate"] or 0)] += 1
            secs += info["secs"]
            rows.append((p, end - p, round(info["rate"] or 0), info["samples"],
                         info["secs"], len(blocks)))
            if extract and voc_n <= (maxn or 0):
                os.makedirs(extract, exist_ok=True)
                open(os.path.join(extract, "%09d.voc" % p), "wb").write(d[p:end])
            p = end
            continue
        # Resync, loudly. Whatever this is, it is neither a VCTL nor a VOC,
        # and the honest thing is to name it, measure it and carry on rather
        # than stop and report 94 % as if it were the whole file.
        a = d.find(b"VCTL", p)
        b = d.find(MAGIC, p)
        cand = [x for x in (a, b) if x >= 0]
        q = min(cand) if cand else n
        gaps.append((p, q - p))
        gap_b += q - p
        p = q
        continue
    print("VCTL chunks     %d  %d bytes" % (vctl_n, vctl_b))
    print("VOC blobs       %d  %d bytes" % (voc_n, voc_b))
    print("SOU header      8 bytes")
    print("unclaimed runs %d  %d bytes" % (len(gaps), gap_b))
    for off, ln in gaps[:20]:
        print("   at %d  %d bytes" % (off, ln))
    acc = 8 + vctl_b + voc_b + gap_b
    print("accounted       %d of %d = %.6f %%" % (acc, n, 100.0 * acc / n))
    print("unaccounted     %d" % (n - acc))
    print("stopped at      %d" % p)
    print("sample bytes    %d" % sum(samples.values()))
    print("rates (Hz)      %s" % dict(rates.most_common()))
    print("total duration  %.2f s = %.2f min = %.4f h" % (secs, secs / 60, secs / 3600))
    if voc_n:
        print("mean blob       %.1f bytes, %.3f s" % (voc_b / voc_n, secs / voc_n))
    if csv:
        with open(csv, "w") as f:
            f.write("offset,bytes,rate,samples,seconds,blocks\n")
            for r in rows:
                f.write("%d,%d,%d,%d,%.6f,%d\n" % r)
        print("wrote %s (%d rows)" % (csv, len(rows)))
    return 1 if bad else 0


def main(argv):
    csv = None
    extract = None
    maxn = 0
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--csv":
            csv = argv[i + 1]; i += 2
        elif argv[i] == "--extract":
            extract = argv[i + 1]; i += 2
        elif argv[i] == "--max":
            maxn = int(argv[i + 1]); i += 2
        else:
            rest.append(argv[i]); i += 1
    if rest[0] == "check":
        return cmd_check(rest[1])
    if rest[0] == "sou":
        return cmd_sou(rest[1], csv, extract, maxn)
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
