#!/usr/bin/env python3
"""wavcheck.py -- close a RIFF/WAVE population on the byte, three ways.

`audio.py` reads the `fmt ` chunk and divides the `data` chunk by the byte rate.
That is one route to a duration and it trusts two header fields. This tool
computes the same duration by two further routes that use different fields, and
prints the largest disagreement across the whole population:

  route A   data chunk bytes / nAvgBytesPerSec          (the byte-rate field)
  route B   data chunk bytes / (nChannels * bits/8) / nSamplesPerSec
  route C   the sum of every chunk header and payload, checked against the
            file size on disk -- not a duration, but the test that says whether
            the container is complete

Route A and route B agree only if nAvgBytesPerSec equals
nSamplesPerSec * nChannels * bits/8, which WAVEFORMATEX requires for PCM and
which a badly written encoder can get wrong. Where they disagree, the file is
named.

The standard used, and named as used: RIFF (Microsoft/IBM Multimedia
Programming Interface and Data Specifications 1.0, 1991) and WAVEFORMATEX.
Format tag 1 is PCM. Nothing is resampled and nothing is written out.

    python tools/wavcheck.py DIR
    python tools/wavcheck.py DIR --list-mismatch
    python tools/wavcheck.py DIR --by-dir
"""

import argparse
import collections
import os
import struct


def read_wav(path):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(12)
        if len(head) < 12 or head[0:4] != b"RIFF" or head[8:12] != b"WAVE":
            return {"path": path, "size": size, "ok": False}
        riffsize = struct.unpack("<I", head[4:8])[0]
        pos = 12
        fmt = None
        datasz = 0
        order = []
        accounted = 12
        while pos + 8 <= size:
            fh.seek(pos)
            hdr = fh.read(8)
            if len(hdr) < 8:
                break
            cid = hdr[0:4]
            sz = struct.unpack("<I", hdr[4:8])[0]
            order.append(cid.decode("latin-1"))
            if cid == b"fmt ":
                fh.seek(pos + 8)
                fmt = fh.read(min(sz, 40))
            elif cid == b"data":
                datasz = sz
            accounted += 8 + sz + (sz & 1)
            pos += 8 + sz + (sz & 1)
        d = {"path": path, "size": size, "ok": fmt is not None,
             "order": ",".join(order), "datasz": datasz,
             "riffsize": riffsize, "accounted": accounted}
        if fmt is not None and len(fmt) >= 16:
            (tag, ch, rate, byterate, align, bits) = struct.unpack(
                "<HHIIHH", fmt[:16])
            d.update(tag=tag, ch=ch, rate=rate, byterate=byterate,
                     align=align, bits=bits)
        return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--ext", default=".wav")
    ap.add_argument("--list-mismatch", action="store_true")
    ap.add_argument("--by-dir", action="store_true")
    a = ap.parse_args()

    files = []
    for dp, dn, fn in os.walk(a.root):
        for f in sorted(fn):
            if f.lower().endswith(a.ext):
                files.append(os.path.join(dp, f))

    n_ok = 0
    n_bad = 0
    totA = totB = 0.0
    worst = 0.0
    worst_path = None
    riff_bad = []
    ab_bad = []
    align_bad = []
    fmts = collections.Counter()
    bydir = collections.defaultdict(lambda: [0, 0, 0.0])
    tags = collections.Counter()
    orders = collections.Counter()

    for p in files:
        d = read_wav(p)
        if not d.get("ok"):
            n_bad += 1
            continue
        n_ok += 1
        tags[d.get("tag")] += 1
        orders[d["order"]] += 1
        fmts[(d["tag"], d["ch"], d["rate"], d["bits"])] += 1
        A = d["datasz"] / d["byterate"] if d["byterate"] else 0.0
        frame = d["ch"] * (d["bits"] // 8)
        B = (d["datasz"] / frame / d["rate"]) if frame and d["rate"] else 0.0
        totA += A
        totB += B
        if abs(A - B) > worst:
            worst = abs(A - B)
            worst_path = p
        if d["byterate"] != d["rate"] * frame:
            ab_bad.append(p)
        if d["align"] != frame:
            align_bad.append(p)
        # route C: the RIFF size field plus 8 must equal the file, and the
        # walked chunks must account for every byte
        if d["riffsize"] + 8 != d["size"] or d["accounted"] != d["size"]:
            riff_bad.append((p, d["size"], d["riffsize"] + 8, d["accounted"]))
        rel = os.path.relpath(os.path.dirname(p), a.root).replace(os.sep, "/")
        e = bydir[rel]
        e[0] += 1
        e[1] += d["size"]
        e[2] += A

    print("files matching %-8s        : %d" % (a.ext, len(files)))
    print("parsed as RIFF/WAVE           : %d" % n_ok)
    print("not RIFF/WAVE                 : %d" % n_bad)
    print("format tags                   : %s"
          % ", ".join("%d x%d" % (k, v) for k, v in tags.most_common()))
    print()
    print("-- route C: does the container close on the file? -------------------")
    print("  files where RIFF size + 8 != file size, or the chunk walk does not")
    print("  account for every byte      : %d of %d" % (len(riff_bad), n_ok))
    for p, sz, rs, ac in riff_bad[:10]:
        print("     %-60s file %d  riff+8 %d  walked %d"
              % (os.path.relpath(p, a.root), sz, rs, ac))
    print()
    print("-- routes A and B ---------------------------------------------------")
    print("  A  data / nAvgBytesPerSec   : %.9f s" % totA)
    print("  B  data / frame / rate      : %.9f s" % totB)
    print("  |A - B| over the population : %.9f s" % abs(totA - totB))
    print("  worst single-file |A - B|   : %.9f s   %s"
          % (worst, os.path.relpath(worst_path, a.root) if worst_path else "-"))
    print("  nAvgBytesPerSec != rate*frame: %d files" % len(ab_bad))
    print("  nBlockAlign     != frame     : %d files" % len(align_bad))
    if a.list_mismatch:
        for p in ab_bad[:20]:
            print("     %s" % os.path.relpath(p, a.root))
    print()
    print("-- formats ----------------------------------------------------------")
    print("   %-5s %3s %8s %5s %8s" % ("tag", "ch", "Hz", "bits", "files"))
    for (t, c, r, b), n in sorted(fmts.items(), key=lambda kv: -kv[1]):
        print("   %-5d %3d %8d %5d %8d" % (t, c, r, b, n))
    print()
    print("-- chunk order --------------------------------------------------")
    for o, n in orders.most_common():
        print("   %-30s %6d" % (o, n))
    if a.by_dir:
        print()
        print("-- by directory -------------------------------------------------")
        for k, (n, b, s) in sorted(bydir.items(), key=lambda kv: -kv[1][1]):
            print("   %-24s %5d files %12d bytes %11.3f s  (%.2f min)"
                  % (k, n, b, s, s / 60.0))


if __name__ == "__main__":
    main()
