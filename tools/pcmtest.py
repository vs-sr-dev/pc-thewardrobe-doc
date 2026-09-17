#!/usr/bin/env python3
"""pcmtest.py -- decide whether a block of bytes is linear PCM audio, and at
what width, without decoding it and without trusting a file name.

The test is the one property uncompressed audio has and compressed anything
does not: **adjacent samples are correlated**.  For a signal sampled far above
its own bandwidth, x[i] is close to x[i-1], so the mean absolute first
difference is much smaller than the mean absolute deviation.  For compressed or
encrypted bytes the two are equal, because there is no signal left.  The
statistic printed is

    ratio = mean |x[i] - x[i-1]|  /  mean |x[i] - mean(x)|

  ratio near sqrt(2) = 1.414  -> the samples are independent: NOT audio
  ratio well below 1          -> the samples are correlated: a signal

and it is computed for four readings of the same bytes -- signed 8-bit, signed
16-bit little-endian, signed 16-bit big-endian, and 16-bit little-endian read
one byte out of phase.  The reading that wins says how wide the samples are;
the out-of-phase reading is the control that must lose, because if it does not,
the correlation is an artefact of the arithmetic rather than of the data.

    python tools/pcmtest.py FILE [--offset N] [--length N]
    python tools/pcmtest.py --rws FILE          (skips to the 0x080F payload)
    python tools/pcmtest.py --sweep DIR --ext .rws --sample 200

Nothing is decoded and nothing is written.  A positive control (a file that
must read as audio) and a negative control (a file that must not) are the
point of --controls.
"""
import argparse
import collections
import os
import struct
import sys


def stats(buf, fmt, step, phase=0):
    n = (len(buf) - phase) // step
    if n < 64:
        return None
    vals = struct.unpack_from("<%d%s" % (n, fmt) if fmt != ">h" else ">%dh" % n,
                              buf, phase) if fmt != ">h" else \
        struct.unpack_from(">%dh" % n, buf, phase)
    m = sum(vals) / float(n)
    dev = sum(abs(v - m) for v in vals) / float(n)
    diff = sum(abs(vals[i] - vals[i - 1]) for i in range(1, n)) / float(n - 1)
    if dev == 0:
        return None
    return diff / dev, dev, n


def readings(buf):
    out = {}
    for label, fmt, step, phase in (
            ("int8", "b", 1, 0),
            ("int16 LE", "h", 2, 0),
            ("int16 BE", ">h", 2, 0),
            ("int16 LE, one byte out of phase", "h", 2, 1)):
        r = stats(buf, fmt, step, phase)
        if r:
            out[label] = r
    return out


def payload(path):
    """For a .rws: return the bytes of the 0x0000080F child."""
    n = os.path.getsize(path)
    with open(path, "rb") as fh:
        blob = fh.read()
    t, s, v = struct.unpack_from("<III", blob, 0)
    if t != 0x0000080D or 12 + s != n:
        sys.exit("%s: not a closed 0x080D stream" % path)
    off = 12
    while off < n:
        ct, cs, cv = struct.unpack_from("<III", blob, off)
        if ct == 0x0000080F:
            return blob[off + 12:off + 12 + cs]
        off += 12 + cs
    sys.exit("%s: no 0x0000080F child" % path)


def report(label, buf):
    print("%s  (%d bytes)" % (label, len(buf)))
    rs = readings(buf)
    best = min(rs.items(), key=lambda kv: kv[1][0])
    for k, (ratio, dev, n) in sorted(rs.items(), key=lambda kv: kv[1][0]):
        mark = "  <-- lowest" if k == best[0] else ""
        print("   %-34s ratio %.4f   mean deviation %10.1f   %d samples%s"
              % (k, ratio, dev, n, mark))
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--rws", action="store_true")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--length", type=int, default=1 << 18)
    ap.add_argument("--sweep")
    ap.add_argument("--ext", default=".rws")
    ap.add_argument("--sample", type=int, default=200)
    ap.add_argument("--controls", nargs="*", default=[])
    a = ap.parse_args()

    print("statistic: mean |first difference| / mean |deviation from the mean|")
    print("           1.414 = independent samples ; below 1 = a correlated signal")
    print()

    for c in a.controls:
        with open(c, "rb") as fh:
            fh.seek(a.offset)
            buf = fh.read(a.length)
        report("CONTROL  %s" % os.path.basename(c), buf)
        print()

    if a.path:
        buf = payload(a.path) if a.rws else open(a.path, "rb").read()
        buf = buf[a.offset:a.offset + a.length]
        report(os.path.basename(a.path), buf)
        print()

    if a.sweep:
        files = []
        for dirpath, dirnames, filenames in os.walk(a.sweep):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn.lower().endswith(a.ext):
                    files.append(os.path.join(dirpath, fn))
        step = max(1, len(files) // a.sample)
        picked = files[::step][:a.sample]
        winners = collections.Counter()
        ratios = collections.defaultdict(list)
        for f in picked:
            buf = payload(f)[:a.length]
            rs = readings(buf)
            if not rs:
                continue
            w = min(rs.items(), key=lambda kv: kv[1][0])
            winners[w[0]] += 1
            for k, (r, d, n) in rs.items():
                ratios[k].append(r)
        print("sweep of %d files (every %dth of %d) under %s"
              % (len(picked), step, len(files), a.sweep))
        print("   lowest-ratio reading, by count:")
        for k, v in winners.most_common():
            print("        %-34s %d" % (k, v))
        print("   mean ratio by reading:")
        for k, v in sorted(ratios.items(), key=lambda kv: sum(kv[1]) / len(kv[1])):
            print("        %-34s %.4f  (min %.4f max %.4f)"
                  % (k, sum(v) / len(v), min(v), max(v)))


if __name__ == "__main__":
    main()
