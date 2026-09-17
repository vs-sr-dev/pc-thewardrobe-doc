#!/usr/bin/env python3
"""qsb.py -- the speech: 6,745 files, and what a header has to prove.

Eighty-nine per cent of `queen.1` is `.SB`, and until the header is derived that
figure is a percentage of bytes whose name ends in two letters. This tool turns
it into seconds.

The container, derived from the bytes and validated by making it close:

    0..1     uint16 LE, always 19
    2..3     uint16 LE, the file offset of the first block descriptor
    4..79    nineteen uint32 LE holding 80, 81, ... 98 -- constant in every file
    80..98   nineteen bytes, eighteen of them 5 -- constant in every file
    99..     filler up to the offset named at 2..3
    then     k descriptors of six bytes: uint16, uint16, uint16 length
    then     sum of the lengths, bytes of unsigned 8-bit mono PCM

`k` is not stored. It is recovered by the only honest method available: try
k = 1, 2, 3 ... and keep the one where (first descriptor offset) + 6k + (sum of
the k lengths) is exactly the size of the resource. A file that closes for two
different k would be ambiguous and is reported; none of them do.

The sample rate is the one thing the bytes do not say. `queen.1` contains no
rate field, no WAV header and no VOC header: the engine knows the rate because
it is compiled in. The public ScummVM `queen` engine plays these at
**11,025 Hz, 8-bit unsigned, mono**, and that constant is what `--rate` defaults
to. It is an imported number, not a measured one, and every duration this tool
prints is linear in it -- which is why `census` prints the same totals at
8,000 and 22,050 Hz alongside, so the reader can see exactly how much of the
answer is borrowed.

    python tools/qsb.py validate _game/scummvm/scummvm.exe _game/queen.1 --name 020001P2.SB
    python tools/qsb.py census   _game/scummvm/scummvm.exe _game/queen.1
    python tools/qsb.py census   _game/scummvm/scummvm.exe _game/queen.1 --csv notes/speech.csv
    python tools/qsb.py wav      _game/scummvm/scummvm.exe _game/queen.1 --name 020001P2.SB --out _work/wav
"""

import argparse
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qres  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

RATE = 11025
MAXK = 64
# What ScummVM does instead: it skips a constant number of bytes and plays the
# rest. Kept here so the two readings can be differenced rather than argued.
ENGINE_SKIP = 110


def derive(b):
    """Return (payload_offset, blocks, ambiguous) or (None, [], reason)."""
    if len(b) < 8:
        return None, [], "too short"
    if struct.unpack_from("<H", b, 0)[0] != 19:
        return None, [], "first field is not 19"
    first = struct.unpack_from("<H", b, 2)[0]
    hits = []
    for k in range(1, MAXK + 1):
        end = first + 6 * k
        if end > len(b):
            break
        tot = 0
        for i in range(k):
            tot += struct.unpack_from("<H", b, first + 6 * i + 4)[0]
        if end + tot == len(b):
            blocks = [struct.unpack_from("<HHH", b, first + 6 * i)
                      for i in range(k)]
            hits.append((end, blocks))
    if not hits:
        return None, [], "no k closes"
    if len(hits) > 1:
        return hits[0][0], hits[0][1], "ambiguous: %d values of k close" % len(hits)
    return hits[0][0], hits[0][1], None


def cmd_validate(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    r = d[a.name.upper()]
    b = data[r[2]:r[2] + r[3]]
    print("resource            %s" % r[0])
    print("size                %d bytes" % r[3])
    print("field at 0..1       %d" % struct.unpack_from("<H", b, 0)[0])
    print("field at 2..3       %d  (first block descriptor)"
          % struct.unpack_from("<H", b, 2)[0])
    tbl = [struct.unpack_from("<I", b, 4 + 4 * i)[0] for i in range(19)]
    print("nineteen uint32     %s" % tbl)
    print("nineteen bytes      %s" % list(b[80:99]))
    off, blocks, err = derive(b)
    print()
    if off is None:
        print("DERIVATION FAILED   %s" % err)
        return 2
    print("blocks              %d" % len(blocks))
    for i, (x, y, ln) in enumerate(blocks):
        print("  %-3d  %6d %6d  length %d" % (i, x, y, ln))
    tot = sum(x[2] for x in blocks)
    print("payload starts      %d" % off)
    print("payload bytes       %d" % tot)
    print("arithmetic          %d + %d = %d, size %d, residue %d"
          % (off, tot, off + tot, r[3], r[3] - off - tot))
    print()
    pcm = b[off:off + tot]
    c = Counter(pcm)
    print("payload histogram   0x80 %.2f %%, in 0x70..0x90 %.2f %%, extremes %d..%d"
          % (100.0 * c.get(128, 0) / len(pcm),
             100.0 * sum(c.get(v, 0) for v in range(0x70, 0x91)) / len(pcm),
             min(pcm), max(pcm)))
    print("duration at %d Hz  %.4f s" % (a.rate, tot / a.rate))
    print("engine reading      skip %d bytes -> %d bytes, %.4f s, difference %+d bytes"
          % (ENGINE_SKIP, r[3] - ENGINE_SKIP, (r[3] - ENGINE_SKIP) / a.rate,
             (r[3] - ENGINE_SKIP) - tot))
    return 0


def collect(recs, data, exts):
    out = []
    for name, bundle, off, size in recs:
        e = os.path.splitext(name)[1].upper()
        if e not in exts:
            continue
        b = data[off:off + size]
        if e == ".RAW":
            out.append((name, e, size, 0, size, 1, None, b))
            continue
        po, blocks, err = derive(b)
        if po is None:
            out.append((name, e, size, None, None, 0, err, b))
        else:
            out.append((name, e, size, po, sum(x[2] for x in blocks),
                        len(blocks), err, b))
    return out


def cmd_census(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    rows = collect(recs, data, {".SB", ".RAW", ".BAK"})
    rows = [r for r in rows if not (r[1] == ".BAK" and r[3] is None)]
    total = len(data)
    ok = [r for r in rows if r[4] is not None]
    bad = [r for r in rows if r[4] is None]
    print("bundle              %s (%d bytes)" % (a.bundle, total))
    print("resources examined  %d" % len(rows))
    print("derived             %d" % len(ok))
    print("not derived         %d" % len(bad))
    for r in bad[:10]:
        print("   %-14s %s" % (r[0], r[6]))
    amb = [r for r in ok if r[6]]
    print("ambiguous           %d" % len(amb))
    print()
    print("%-8s %6s %14s %14s %10s %12s"
          % ("ext", "files", "bytes on disc", "payload bytes", "blocks",
             "seconds"))
    for e in (".SB", ".RAW", ".BAK"):
        g = [r for r in ok if r[1] == e]
        if not g:
            continue
        print("%-8s %6d %14d %14d %10d %12.3f"
              % (e, len(g), sum(r[2] for r in g), sum(r[4] for r in g),
                 sum(r[5] for r in g), sum(r[4] for r in g) / a.rate))
    pay = sum(r[4] for r in ok)
    disc = sum(r[2] for r in ok)
    print("%-8s %6d %14d %14d %10d %12.3f"
          % ("total", len(ok), disc, pay, sum(r[5] for r in ok), pay / a.rate))
    print()
    secs = pay / a.rate
    print("recorded sound      %d bytes of payload in %d resources" % (pay, len(ok)))
    print("                    %d bytes on disc = %.4f %% of the bundle"
          % (disc, 100.0 * disc / total))
    print("                    %.3f s = %d h %02d m %06.3f s at %d Hz"
          % (secs, int(secs // 3600), int(secs % 3600 // 60), secs % 60, a.rate))
    print("                    %.3f minutes" % (secs / 60.0))
    print("if the rate were    8000 Hz: %.2f min   22050 Hz: %.2f min"
          % (pay / 8000 / 60, pay / 22050 / 60))
    print()
    sb = [r for r in ok if r[1] == ".SB"]
    lens = sorted(r[4] / a.rate for r in sb)
    print("%-20s %d" % (".SB recordings", len(sb)))
    print("%-20s %.4f s" % ("  mean", sum(lens) / len(lens)))
    print("%-20s %.4f s" % ("  median", lens[len(lens) // 2]))
    print("%-20s %.4f s" % ("  shortest", lens[0]))
    print("%-20s %.4f s" % ("  longest", lens[-1]))
    short = [r for r in sb if r[4] / a.rate < 1.0]
    print("%-20s %d (%.2f %%)" % ("  under one second", len(short),
                                  100.0 * len(short) / len(sb)))
    bk = Counter(r[5] for r in sb)
    print("%-20s %s" % ("  blocks per file", dict(sorted(bk.items()))))
    print()
    print("the header cost     %d bytes of container over %d resources = %.4f %%"
          % (disc - pay, len(ok), 100.0 * (disc - pay) / disc))
    eng = sum(r[2] - ENGINE_SKIP for r in ok if r[1] != ".RAW")
    engall = eng + sum(r[2] for r in ok if r[1] == ".RAW")
    print("engine reading      a flat %d-byte skip gives %d bytes, %+d against"
          % (ENGINE_SKIP, engall, engall - pay))
    print("                    the derived payload, i.e. %+.4f s at %d Hz"
          % ((engall - pay) / a.rate, a.rate))

    if a.silence:
        print()
        z = 0
        near = 0
        for r in ok:
            pcm = r[7][r[3]:r[3] + r[4]]
            c = Counter(pcm)
            z += c.get(128, 0)
            near += sum(c.get(v, 0) for v in range(0x7E, 0x83))
        print("payload histogram   0x80 exactly: %d = %.4f %% of the payload"
              % (z, 100.0 * z / pay))
        print("                    0x7E..0x82:   %d = %.4f %%"
              % (near, 100.0 * near / pay))
        print("                    at %d Hz that is %.2f minutes of digital silence"
              % (a.rate, z / a.rate / 60))

    if a.csv:
        with open(a.csv, "w", encoding="utf-8") as fh:
            fh.write("name,ext,size,payload_offset,payload_bytes,blocks,seconds\n")
            for r in sorted(ok):
                fh.write("%s,%s,%d,%d,%d,%d,%.6f\n"
                         % (r[0], r[1], r[2], r[3], r[4], r[5], r[4] / a.rate))
        print()
        print("wrote %s" % a.csv)
    return 0


def cmd_wav(a):
    buf, data, fo, n, recs, _ = qres.get_table(a.exe, a.bundle, None)
    d = {r[0].upper(): r for r in recs}
    os.makedirs(a.out, exist_ok=True)
    names = [a.name] if a.name else [r[0] for r in recs
                                     if r[0].upper().endswith(".SB")][:a.limit]
    import wave
    for nm in names:
        r = d[nm.upper()]
        b = data[r[2]:r[2] + r[3]]
        off, blocks, err = derive(b)
        pcm = b[off:off + sum(x[2] for x in blocks)]
        w = wave.open(os.path.join(a.out, r[0] + ".wav"), "wb")
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(a.rate)
        w.writeframes(pcm)
        w.close()
    print("wrote %d wav files to %s" % (len(names), a.out))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("validate", cmd_validate), ("census", cmd_census),
                     ("wav", cmd_wav)):
        p = sub.add_parser(name)
        p.add_argument("exe")
        p.add_argument("bundle")
        p.add_argument("--rate", type=int, default=RATE)
        if name in ("validate", "wav"):
            p.add_argument("--name", default=None)
        if name == "wav":
            p.add_argument("--out", required=True)
            p.add_argument("--limit", type=int, default=4)
        if name == "census":
            p.add_argument("--csv", default=None)
            p.add_argument("--silence", action="store_true")
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
