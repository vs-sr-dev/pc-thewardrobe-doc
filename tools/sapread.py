#!/usr/bin/env python3
"""sapread.py -- the `.SAP` sound bank: eight bytes, then one or more RIFFs.

Derived from the bytes, not from a description. What the object shows:

    offset 0   dword   a **bit mask**, not a count
    offset 4   dword   a second mask, almost always zero
    offset 8   the first `RIFF....WAVE`, which declares its own size
               ... and immediately after it the next one, and so on
               until the file is consumed.

The mask is the finding. `WEAPON01.SAP` carries 481 = 0b1_1110_0001 in its
first dword and holds **five** WAVs, and 481 has five bits set. A file whose
first dword is 0 holds none and is eight bytes long. So the header does not say
how many sounds are in the bank, it says **which slots of the bank are filled**
-- which is why the values cluster on 1, 3, 7, 15 (the low runs) rather than on
1, 2, 3, 4. The tool asserts popcount(mask0) + popcount(mask1) == the number of
RIFF chunks actually walked, on every file, and reports the failures instead of
hiding them.

Nothing else about the container is assumed: the walk is driven entirely by
each RIFF's own declared size, and a file is only called closed when the walk
lands exactly on its last byte.

The audio is Microsoft ADPCM (WAVE_FORMAT_ADPCM, tag 2), which is public. This
implements it from the definition -- the adaptation table, the seven coefficient
pairs (read from the file's own `fmt ` chunk, not hard-coded), the per-block
predictor/delta/two-sample preamble -- and decodes every block rather than
trusting `nAvgBytesPerSec`. Blocks are independent, so the inner loop runs
across all blocks of a stream at once with numpy; the arithmetic is the scalar
definition, only the loop order changes. `--validate` checks the vectorised
decoder against a scalar reference on one stream before any census is run.

    python tools/sapread.py FILE --validate
    python tools/sapread.py DIR  --census
    python tools/sapread.py DIR  --census --tsv OUT.tsv
    python tools/sapread.py FILE --dump

No constant in this file belongs to any particular disc.
"""

import argparse
import collections
import os
import struct
import sys

import numpy as np

ADAPT = np.array([230, 230, 230, 230, 307, 409, 512, 614,
                  768, 614, 512, 409, 307, 230, 230, 230], dtype=np.int64)


def clamp16(a):
    return np.clip(a, -32768, 32767)


def walk_sap(b):
    """(mask0, mask1, [ (offset, riffsize, fmt_bytes, data_bytes) ], residue)"""
    if len(b) < 8:
        return None
    mask0, mask1 = struct.unpack_from("<II", b, 0)
    out = []
    off = 8
    while off + 8 <= len(b):
        if b[off:off + 4] != b"RIFF":
            break
        sz = struct.unpack_from("<I", b, off + 4)[0]
        end = off + 8 + sz
        if end > len(b) or b[off + 8:off + 12] != b"WAVE":
            break
        fmt = None
        data = None
        q = off + 12
        while q + 8 <= end:
            cid = b[q:q + 4]
            csz = struct.unpack_from("<I", b, q + 4)[0]
            if cid == b"fmt ":
                fmt = bytes(b[q + 8:q + 8 + csz])
            elif cid == b"data":
                data = (q + 8, csz)
            q += 8 + csz + (csz & 1)
        out.append((off, sz, fmt, data))
        off = end
    return mask0, mask1, out, len(b) - off


def parse_fmt(fmt):
    tag, ch, rate, abps, align, bits = struct.unpack_from("<HHIIHH", fmt, 0)
    d = {"tag": tag, "ch": ch, "rate": rate, "abps": abps,
         "align": align, "bits": bits, "coef": None, "spb": None}
    if len(fmt) >= 20:
        cbsize = struct.unpack_from("<H", fmt, 16)[0]
        if cbsize >= 4 and len(fmt) >= 22:
            d["spb"] = struct.unpack_from("<H", fmt, 18)[0]
            ncoef = struct.unpack_from("<H", fmt, 20)[0]
            coef = []
            for i in range(ncoef):
                o = 22 + 4 * i
                if o + 4 <= len(fmt):
                    coef.append(struct.unpack_from("<hh", fmt, o))
            d["coef"] = coef
    return d


def samples_per_block(align, ch):
    """MS-ADPCM: 7 bytes of preamble per channel, then two samples per byte,
    plus the two samples the preamble itself carries."""
    return (align - 7 * ch) * 2 // ch + 2


def decode_block_scalar(blk, ch, coef):
    """The definition, one sample at a time. Reference only."""
    if ch == 1:
        pi = blk[0]
        delta = struct.unpack_from("<h", blk, 1)[0]
        s1 = struct.unpack_from("<h", blk, 3)[0]
        s2 = struct.unpack_from("<h", blk, 5)[0]
        c1, c2 = coef[pi]
        out = [s2, s1]
        for byte in blk[7:]:
            for nib in (byte >> 4, byte & 15):
                n = nib - 16 if nib > 7 else nib
                pred = (s1 * c1 + s2 * c2) >> 8
                pred += n * delta
                pred = max(-32768, min(32767, pred))
                out.append(pred)
                delta = (ADAPT[nib] * delta) >> 8
                if delta < 16:
                    delta = 16
                s2, s1 = s1, pred
        return out
    raise NotImplementedError("scalar reference is mono-only")


def decode_stream(data, fmt):
    """Decode every block of one ADPCM stream. Returns (samples_per_channel,
    blocks, residue_bytes). Blocks are independent, so the per-sample loop runs
    across all of them at once."""
    ch = fmt["ch"]
    align = fmt["align"]
    coef = fmt["coef"] or [(256, 0), (512, -256), (0, 0), (192, 64),
                           (240, 0), (460, -208), (392, -232)]
    nblocks = len(data) // align
    residue = len(data) - nblocks * align
    if nblocks == 0:
        return 0, 0, residue, None
    a = np.frombuffer(data[:nblocks * align], dtype=np.uint8).reshape(
        nblocks, align)
    hdr = 7 * ch
    pi = a[:, :ch].astype(np.int64)
    c = np.array(coef, dtype=np.int64)
    pi = np.clip(pi, 0, len(coef) - 1)
    c1 = c[pi, 0]
    c2 = c[pi, 1]
    words = a[:, ch:hdr].copy().view(np.int16).astype(np.int64)
    words = words.reshape(nblocks, 3, ch)
    delta = words[:, 0, :]
    s1 = words[:, 1, :]
    s2 = words[:, 2, :]
    nib_bytes = a[:, hdr:]
    hi = (nib_bytes >> 4).astype(np.int64)
    lo = (nib_bytes & 15).astype(np.int64)
    nibs = np.empty((nblocks, nib_bytes.shape[1] * 2), dtype=np.int64)
    nibs[:, 0::2] = hi
    nibs[:, 1::2] = lo
    nsamp = nibs.shape[1] // ch
    out = np.empty((nblocks, nsamp + 2, ch), dtype=np.int16)
    out[:, 0, :] = s2
    out[:, 1, :] = s1
    delta = delta.astype(np.int64)
    s1 = s1.astype(np.int64)
    s2 = s2.astype(np.int64)
    for i in range(nsamp):
        nib = nibs[:, i * ch:(i + 1) * ch]
        n = np.where(nib > 7, nib - 16, nib)
        pred = (s1 * c1 + s2 * c2) >> 8
        pred = clamp16(pred + n * delta)
        out[:, i + 2, :] = pred.astype(np.int16)
        delta = np.maximum((ADAPT[nib] * delta) >> 8, 16)
        s2 = s1
        s1 = pred
    return (nsamp + 2) * nblocks, nblocks, residue, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--tsv")
    ap.add_argument("--ext", default=".sap")
    a = ap.parse_args()

    if os.path.isdir(a.path):
        targets = []
        for dp, dn, fn in os.walk(a.path):
            for f in sorted(fn):
                if f.lower().endswith(a.ext):
                    targets.append(os.path.join(dp, f))
    else:
        targets = [a.path]

    if a.validate:
        p = targets[0]
        b = open(p, "rb").read()
        m0, m1, riffs, res = walk_sap(b)
        ok = 0
        tried = 0
        for off, sz, fmt, data in riffs:
            f = parse_fmt(fmt)
            if f["tag"] != 2 or f["ch"] != 1:
                continue
            d = b[data[0]:data[0] + data[1]]
            n, nb, r, out = decode_stream(d, f)
            for k in range(min(nb, 4)):
                ref = decode_block_scalar(d[k * f["align"]:(k + 1) * f["align"]],
                                          1, f["coef"])
                got = list(out[k, :, 0])
                tried += 1
                if ref == got:
                    ok += 1
                else:
                    bad = next(i for i in range(len(ref)) if ref[i] != got[i])
                    print("  block %d differs at sample %d: %d vs %d"
                          % (k, bad, ref[bad], got[bad]))
        print("validate: %s" % p)
        print("  vectorised block == scalar reference   %d/%d" % (ok, tried))
        if ok != tried or tried == 0:
            raise SystemExit("sapread: vectorised decoder disagrees with the "
                             "definition; refusing to census")
        return

    if a.dump:
        for p in targets:
            b = open(p, "rb").read()
            m0, m1, riffs, res = walk_sap(b)
            print("%s  %d bytes" % (p, len(b)))
            print("  mask0 = %d = 0x%08x, popcount %d" % (m0, m0, bin(m0).count("1")))
            print("  mask1 = %d = 0x%08x, popcount %d" % (m1, m1, bin(m1).count("1")))
            print("  RIFFs walked: %d, residue %d" % (len(riffs), res))
            for off, sz, fmt, data in riffs:
                f = parse_fmt(fmt)
                n, nb, r, _ = decode_stream(b[data[0]:data[0] + data[1]], f) \
                    if f["tag"] == 2 else (data[1] * 8 // max(f["bits"], 1)
                                           // max(f["ch"], 1), 0, 0, None)
                print("    off %7d size %7d  tag %d %dch %d Hz %d-bit  "
                      "blocks %d  samples %d  %.6f s"
                      % (off, sz, f["tag"], f["ch"], f["rate"], f["bits"],
                         nb, n, n / f["rate"] if f["rate"] else 0))
        return

    # census
    files = 0
    riff_total = 0
    bytes_total = 0
    secs = 0.0
    unclosed = []
    mask_bad = []
    fmt_hist = collections.Counter()
    mask_hist = collections.Counter()
    per_count = collections.Counter()
    residue_total = 0
    rows = []
    for p in targets:
        b = open(p, "rb").read()
        files += 1
        bytes_total += len(b)
        w = walk_sap(b)
        if w is None:
            unclosed.append((p, "shorter than 8 bytes"))
            continue
        m0, m1, riffs, res = w
        residue_total += res
        if res != 0:
            unclosed.append((p, "residue %d bytes" % res))
        pc = bin(m0).count("1") + bin(m1).count("1")
        if pc != len(riffs):
            mask_bad.append((p, m0, m1, pc, len(riffs)))
        mask_hist[m0] += 1
        per_count[len(riffs)] += 1
        riff_total += len(riffs)
        fsec = 0.0
        for off, sz, fmt, data in riffs:
            if fmt is None or data is None:
                unclosed.append((p, "RIFF at %d has no fmt/data" % off))
                continue
            f = parse_fmt(fmt)
            fmt_hist[(f["tag"], f["ch"], f["rate"], f["bits"])] += 1
            d = b[data[0]:data[0] + data[1]]
            if f["tag"] == 2:
                n, nb, r, _ = decode_stream(d, f)
                if r:
                    unclosed.append((p, "ADPCM stream at %d leaves %d bytes"
                                     % (off, r)))
                if f["spb"] and nb and n != nb * f["spb"]:
                    unclosed.append((p, "decoded %d samples, fmt declares "
                                     "%d/block x %d blocks" % (n, f["spb"], nb)))
            else:
                n = data[1] * 8 // max(f["bits"], 1) // max(f["ch"], 1)
            fsec += n / f["rate"] if f["rate"] else 0.0
        secs += fsec
        rows.append((p, len(b), m0, m1, len(riffs), fsec))

    print("files                        : %d" % files)
    print("bytes                        : %d" % bytes_total)
    print("RIFF/WAVE streams walked     : %d" % riff_total)
    print("container residue, total     : %d bytes" % residue_total)
    print("files that do not close      : %d" % len(set(x[0] for x in unclosed)))
    print("popcount(mask) != stream count: %d of %d" % (len(mask_bad), files))
    print("total decoded duration       : %.9f s = %.4f min" % (secs, secs / 60.0))
    print()
    print("-- streams per file ----------------------------------------------")
    for k in sorted(per_count):
        print("   %3d streams  %5d files" % (k, per_count[k]))
    print()
    print("-- formats, every stream -----------------------------------------")
    for k, v in sorted(fmt_hist.items(), key=lambda kv: -kv[1]):
        print("   tag %d  %d ch  %6d Hz  %2d-bit   %6d streams" % (k + (v,)))
    print()
    print("-- the ten commonest masks ---------------------------------------")
    for k, v in mask_hist.most_common(10):
        print("   0x%08x = %-10d popcount %2d   %5d files"
              % (k, k, bin(k).count("1"), v))
    if mask_bad:
        print()
        print("-- files where popcount(mask) != streams --------------------------")
        for p, m0, m1, pc, n in mask_bad[:20]:
            print("   %-60s mask 0x%08x/0x%08x pc=%d streams=%d"
                  % (os.path.relpath(p, a.path), m0, m1, pc, n))
    if unclosed:
        print()
        print("-- first twenty that do not close ---------------------------------")
        for p, why in unclosed[:20]:
            print("   %-60s %s" % (os.path.relpath(p, a.path), why))

    if a.tsv:
        with open(a.tsv, "w", encoding="utf-8") as fh:
            fh.write("path\tbytes\tmask0\tmask1\tstreams\tseconds\n")
            for r in rows:
                fh.write("%s\t%d\t%d\t%d\t%d\t%.9f\n" % r)
        print()
        print("wrote %s" % a.tsv)


if __name__ == "__main__":
    main()
