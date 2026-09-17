#!/usr/bin/env python3
"""qtbl.py -- find the resource tables hidden inside a binary, and choose one.

`queen.1` has no header, no directory and no terminator. The table that says
where its 7,671 resources start and stop is not on the disc: it is compiled into
`scummvm.exe`, a program written by other people twenty-two years later, and
there is more than one of them in there.

The record shape is the one the ScummVM `queen` engine defines for the
`queen.tbl` files of the original releases. That definition is public and this
tool is using it, which is stated here rather than assumed:

     0..11   name, 12 bytes, upper case, zero padded
    12       bundle number (1 = queen.1)
    13..16   offset into the bundle, big-endian
    17..20   size, big-endian

Twenty-one bytes. The scanner below knows nothing else: no offsets, no counts,
no version numbers. It marks every file position where those 21 bytes could be a
record, joins the positions that are 21 apart into runs, and reports every run.

The point of the tool is what happens next. Several runs describe the file
arithmetically well, and the best-looking wrong one covers 99.9703 % of
`queen.1` with zero holes, zero overlaps and zero duplicate names. Arithmetic
cannot tell it from the right one. Content can: a `.PCX` starts with the byte
`0A`, and on the wrong table not one of them does. So `verify` scores a table by
opening the bytes it points at, and prints both the arithmetic and the content
so that a reader can see which one did the deciding.

    python tools/qtbl.py scan _game/scummvm/scummvm.exe
    python tools/qtbl.py scan _game/scummvm/scummvm.exe --min 100 --join
    python tools/qtbl.py qtbl _game/scummvm/scummvm.exe
    python tools/qtbl.py versions _game/scummvm/scummvm.exe
    python tools/qtbl.py verify _game/scummvm/scummvm.exe _game/queen.1 --at 0x196F6D0 --n 7671
    python tools/qtbl.py verify _game/scummvm/scummvm.exe _game/queen.1 --all --min 100 --join
    python tools/qtbl.py dump _game/scummvm/scummvm.exe --at 0x196F6D0 --n 7671 > notes/table.txt
    python tools/qtbl.py compare _game/scummvm/scummvm.exe --a 0x196F6D0 --na 7671 --b 0x19C9129 --nb 6924
"""

import argparse
import os
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from collections import Counter, defaultdict

import numpy as np

REC = 21
NAMELEN = 12

# The characters a resource name is allowed to use. Upper case only: the engine
# upper-cases before it looks a name up.
ALLOWED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" + b"'")
# The apostrophe is in there because the Amiga release has resources called
# 'JUNGLE'.INS, quotes and all. Leaving it out costs three whole tables.

# What the first bytes of a resource have to be for its extension. Anything not
# named here is not scored. `None` means "no constraint, but the resource must
# be readable".
MAGIC = {
    ".PCX": (b"\x0a",),
    ".CUT": (b"AmBk",),
    ".DOG": (b"AmBk",),
    ".JAS": (b"AmBk",),
    ".SB": (b"\x13\x00",),
    ".BAK": (b"\x13\x00",),
    ".SAM": (b"\x13\x00",),
    ".MUS": (b"\x69\x00",),
    ".RL": (b"\x6a\x00",),
}


def load(path):
    with open(path, "rb") as fh:
        return fh.read()


def valid_mask(buf):
    """Boolean array: could a 21-byte record start here?"""
    b = np.frombuffer(buf, dtype=np.uint8)
    n = len(b)
    allowed = np.zeros(256, dtype=bool)
    for c in ALLOWED:
        allowed[c] = True
    isa = allowed[b]
    isz = b == 0

    lim = n - REC
    if lim <= 0:
        return np.zeros(0, dtype=bool)

    ok = isa[:lim].copy()                      # first character is a real one
    for j in range(NAMELEN):
        ok &= (isa[j:j + lim] | isz[j:j + lim])
    for j in range(NAMELEN - 1):               # once padding starts it never stops
        ok &= ~(isz[j:j + lim] & isa[j + 1:j + 1 + lim])

    bundle = b[NAMELEN:NAMELEN + lim]
    ok &= (bundle >= 1) & (bundle <= 16)

    def be32(off):
        v = np.zeros(lim, dtype=np.uint32)
        for k in range(4):
            v = (v << np.uint32(8)) | b[off + k:off + k + lim].astype(np.uint32)
        return v

    offs = be32(13)
    size = be32(17)
    ok &= size > 0
    ok &= size <= np.uint32(64 * 1024 * 1024)
    ok &= offs <= np.uint32(0x7FFFFFFF)
    return ok


def runs(ok, minlen):
    """Positions p where a chain p, p+21, p+42 ... of valid records starts."""
    out = []
    n = len(ok)
    idx = np.flatnonzero(ok)
    okset = ok
    starts = []
    for p in idx:
        q = p - REC
        if q < 0 or not okset[q]:
            starts.append(int(p))
    for p in starts:
        c = 0
        q = p
        while q < n and okset[q]:
            c += 1
            q += REC
        if c >= minlen:
            out.append((p, c))
    return out


def read_records(buf, at, n):
    recs = []
    for i in range(n):
        o = at + i * REC
        raw = buf[o:o + REC]
        if len(raw) < REC:
            break
        name = raw[:NAMELEN].rstrip(b"\x00").decode("ascii", "replace")
        bundle = raw[NAMELEN]
        off, size = struct.unpack(">II", raw[13:21])
        recs.append((name, bundle, off, size))
    return recs


def arith(recs, bundle_size=None):
    """Holes, overlaps, coverage, duplicates -- the numbers that cannot decide."""
    s = sorted(recs, key=lambda r: r[2])
    total = sum(r[3] for r in recs)
    holes = 0
    hole_bytes = 0
    overlaps = 0
    overlap_bytes = 0
    cur = 0
    for _n, _b, o, z in s:
        if o > cur:
            holes += 1
            hole_bytes += o - cur
        elif o < cur:
            overlaps += 1
            overlap_bytes += cur - o
        cur = max(cur, o + z)
    names = Counter(r[0] for r in recs)
    dup = sum(1 for k, v in names.items() if v > 1)
    end = max(r[2] + r[3] for r in recs) if recs else 0
    d = {
        "n": len(recs),
        "bytes": total,
        "holes": holes,
        "hole_bytes": hole_bytes,
        "overlaps": overlaps,
        "overlap_bytes": overlap_bytes,
        "dupnames": dup,
        "first": min(r[2] for r in recs) if recs else 0,
        "end": end,
        "bundles": sorted({r[1] for r in recs}),
        "sorted_by_name": all(recs[i][0] <= recs[i + 1][0]
                              for i in range(len(recs) - 1)),
        "sorted_by_offset": all(s[i][2] <= s[i + 1][2] for i in range(len(s) - 1)),
    }
    if bundle_size:
        d["coverage"] = 100.0 * total / bundle_size
        d["fits"] = end <= bundle_size
        d["tail"] = bundle_size - end
    return d


def content_score(recs, data):
    """Open what the table points at. This is the test that decides."""
    per = defaultdict(lambda: [0, 0])
    oob = 0
    for name, bundle, off, size in recs:
        if bundle != 1:
            continue
        ext = os.path.splitext(name)[1].upper()
        if ext not in MAGIC:
            continue
        if off + size > len(data):
            oob += 1
            continue
        head = data[off:off + 8]
        per[ext][1] += 1
        if any(head.startswith(m) for m in MAGIC[ext]):
            per[ext][0] += 1
    good = sum(v[0] for v in per.values())
    tot = sum(v[1] for v in per.values())
    return per, good, tot, oob


def fmt_table(d):
    cov = ("%.6f %%" % d["coverage"]) if "coverage" in d else "-"
    return ("n=%-6d bytes=%-11d cov=%-12s holes=%-5d ovl=%-5d dup=%-4d"
            % (d["n"], d["bytes"], cov, d["holes"], d["overlaps"], d["dupnames"]))


def join_runs(cands, buf, gap=REC * 4):
    """Two runs separated by a record the scanner refused are one table.

    The record it refuses here is called `DATA`: twelve bytes with no extension,
    the only one of its kind. A stricter name test than the one above would
    split the real table in two and hand back two beautiful fakes. This joiner
    exists because that is exactly what happened the first time.
    """
    cands = sorted(cands)
    out = []
    i = 0
    while i < len(cands):
        at, n = cands[i]
        end = at + n * REC
        while i + 1 < len(cands):
            nat, nn = cands[i + 1]
            if 0 < nat - end <= gap and (nat - end) % REC == 0:
                n = (nat + nn * REC - at) // REC
                end = at + n * REC
                i += 1
            else:
                break
        out.append((at, n))
        i += 1
    return out


def find_qtbl(buf):
    """The blob is not anonymous: it announces itself with four bytes.

    Once found, its shape falls out without guessing. After the magic comes a
    32-bit big-endian version number, and then the tables run end to end, each
    one preceded by its own 16-bit big-endian record count. Nothing separates
    them and nothing terminates the chain -- it simply stops being parseable,
    which is how this tool decides it has reached the end.
    """
    at = buf.find(b"QTBL")
    if at < 0:
        return None
    ver = struct.unpack(">I", buf[at + 4:at + 8])[0]
    return at, ver


def walk_qtbl(buf, at):
    """Yield (table_offset_in_blob, count, records_file_offset) along the chain."""
    p = at + 8
    out = []
    while p + 2 <= len(buf):
        rel = p - at
        n = struct.unpack(">H", buf[p:p + 2])[0]
        if n == 0 or n > 20000:
            break
        first = buf[p + 2:p + 2 + REC]
        nm = first[:NAMELEN]
        if len(first) < REC or any(c not in ALLOWED and c != 0 for c in nm):
            break
        if not (1 <= first[NAMELEN] <= 16):
            break
        out.append((rel, n, p + 2))
        p += 2 + n * REC
    return out, p


def cmd_qtbl(a):
    buf = load(a.binary)
    got = find_qtbl(buf)
    if not got:
        print("no QTBL blob in %s" % a.binary, file=sys.stderr)
        return 2
    at, ver = got
    print("binary              %s (%d bytes)" % (a.binary, len(buf)))
    print("QTBL magic at       %d = 0x%X" % (at, at))
    print("declared version    %d (32-bit big-endian, right after the magic)" % ver)
    tables, end = walk_qtbl(buf, at)
    print("blob runs to        %d = 0x%X  (%d bytes)" % (end, end, end - at))
    print()
    print("%-6s %-10s %-11s %8s %14s %s"
          % ("#", "tableOffset", "records at", "records", "bytes", "hex"))
    tot = 0
    for i, (rel, n, fo) in enumerate(tables):
        recs = read_records(buf, fo, n)
        b = sum(r[3] for r in recs)
        tot += n
        print("%-6d %-10d %-11d %8d %14d 0x%X" % (i, rel, fo, n, b, fo))
    print()
    print("tables              %d" % len(tables))
    print("records in total    %d" % tot)
    print("bytes of table      %d (%.4f %% of the binary)"
          % (end - at, 100.0 * (end - at) / len(buf)))
    return 0


def cmd_versions(a):
    """The blob's own index, which lives somewhere else entirely.

    ScummVM keeps a list of the game releases it knows, and each entry carries
    the offset of that release's table inside the blob and the size the data
    file is supposed to be. Sixteen bytes each: six of name, two of flags, and
    two little-endian dwords. Little-endian: the list is C data compiled for an
    x86, while the table it points at is big-endian because it was written for
    a 68000. Both byte orders live in the same file.
    """
    buf = load(a.binary)
    got = find_qtbl(buf)
    blob = got[0] if got else 0
    # anchor on any known release string and walk backwards to the array start
    anchor = None
    for tag in (b"PEM10\x00", b"CEM10\x00"):
        i = buf.find(tag)
        if i >= 0:
            anchor = i
            break
    if anchor is None:
        print("no version list found", file=sys.stderr)
        return 2
    start = anchor
    while start >= 16:
        e = buf[start - 16:start]
        if not (32 <= e[0] < 127) or e[6] not in (0, 1, 2, 3):
            break
        start -= 16
    print("binary              %s" % a.binary)
    print("version list at     %d = 0x%X" % (start, start))
    print("entry form          char[6] name, uint8, uint8, uint32 LE tableOffset,")
    print("                    uint32 LE dataFileSize  -- sixteen bytes")
    print()
    print("%-3s %-7s %-3s %-3s %-11s %-11s %14s %s"
          % ("#", "name", "f1", "f2", "tableOffset", "file offset", "dataFileSize",
             "note"))
    i = start
    n = 0
    rows = []
    while True:
        e = buf[i:i + 16]
        if len(e) < 16 or not (65 <= e[0] < 127):
            break
        name = e[:6].rstrip(b"\x00").decode("ascii", "replace")
        f1, f2 = e[6], e[7]
        to, sz = struct.unpack("<II", e[8:16])
        if to > len(buf):
            break
        fo = blob + to + 2
        note = ""
        if a.bundle and sz == os.path.getsize(a.bundle):
            note = "<== matches %s exactly" % os.path.basename(a.bundle)
        print("%-3d %-7s %-3d %-3d %-11d %-11d %14d %s"
              % (n, name, f1, f2, to, fo, sz, note))
        rows.append((name, f1, f2, to, fo, sz))
        n += 1
        i += 16
    print()
    print("entries             %d" % n)
    if a.bundle:
        m = [r for r in rows if r[5] == os.path.getsize(a.bundle)]
        print("entries whose declared size equals the bundle: %d %s"
              % (len(m), [r[0] for r in m]))
    return 0


def cmd_scan(a):
    buf = load(a.binary)
    ok = valid_mask(buf)
    c = runs(ok, a.min)
    print("binary              %s (%d bytes)" % (a.binary, len(buf)))
    print("record form         21 bytes: name[12] bundle[1] offset[4 BE] size[4 BE]")
    print("candidate positions %d" % int(ok.sum()))
    print("runs of >= %d       %d" % (a.min, len(c)))
    if a.join:
        c2 = join_runs(c, buf)
        print("after joining runs separated by whole records: %d" % len(c2))
        c = c2
    print()
    print("%-12s %-8s %8s %14s  %s"
          % ("offset", "hex", "records", "bytes", "span in the binary"))
    for at, n in sorted(c, key=lambda x: -x[1]):
        recs = read_records(buf, at, n)
        print("%-12d 0x%-7X %8d %14d  0x%X..0x%X"
              % (at, at, n, sum(r[3] for r in recs), at, at + n * REC))
    return 0


def cmd_verify(a):
    buf = load(a.binary)
    data = load(a.bundle)
    print("binary              %s" % a.binary)
    print("bundle              %s (%d bytes)" % (a.bundle, len(data)))
    print("the content test    a .PCX begins 0A, an AmBk container begins 'AmBk',")
    print("                    a .SB/.SAM/.BAK begins 13 00, a .MUS 69 00, a .RL 6A 00")
    print()

    if a.all:
        ok = valid_mask(buf)
        c = runs(ok, a.min)
        if a.join:
            c = join_runs(c, buf)
    else:
        c = [(a.at, a.n)]

    rows = []
    for at, n in sorted(c, key=lambda x: -x[1]):
        recs = read_records(buf, at, n)
        if not recs:
            continue
        d = arith(recs, len(data))
        per, good, tot, oob = content_score(recs, data)
        rows.append((at, n, d, per, good, tot, oob))

    print("%-11s %7s %13s %11s %6s %5s %4s %14s"
          % ("offset", "recs", "bytes", "coverage", "holes", "ovl", "dup",
             "content test"))
    for at, n, d, per, good, tot, oob in rows:
        cov = "%.6f %%" % d["coverage"] if d["fits"] else "OVER"
        ct = ("%d/%d = %.1f %%" % (good, tot, 100.0 * good / tot)) if tot else "n/a"
        print("0x%-9X %7d %13d %11s %6d %5d %4d %14s"
              % (at, n, d["bytes"], cov, d["holes"], d["overlaps"],
                 d["dupnames"], ct))

    if rows:
        best = max(rows, key=lambda r: (r[4] / r[5] if r[5] else 0, r[1]))
        at, n, d, per, good, tot, oob = best
        print()
        print("chosen by content: 0x%X, %d records" % (at, n))
        print("  coverage          %d of %d = %.6f %%"
              % (d["bytes"], len(data), d["coverage"]))
        print("  holes             %d (%d bytes)" % (d["holes"], d["hole_bytes"]))
        print("  overlaps          %d (%d bytes)" % (d["overlaps"],
                                                     d["overlap_bytes"]))
        print("  duplicate names   %d" % d["dupnames"])
        print("  first byte used   %d" % d["first"])
        print("  last byte used    %d  (bundle is %d)" % (d["end"], len(data)))
        print("  bundles named     %s" % d["bundles"])
        print("  sorted by name    %s" % d["sorted_by_name"])
        print("  sorted by offset  %s" % d["sorted_by_offset"])
        print("  out of bounds     %d" % oob)
        print("  content, by extension:")
        for ext in sorted(per):
            g, t = per[ext]
            print("    %-6s %5d / %-5d  %6.2f %%" % (ext, g, t,
                                                     100.0 * g / t if t else 0))
    return 0


def cmd_dump(a):
    buf = load(a.binary)
    recs = read_records(buf, a.at, a.n)
    data = load(a.bundle) if a.bundle else None
    print("# name  bundle  offset  size  first8")
    for name, bundle, off, size in recs:
        h = ""
        if data is not None and off + size <= len(data):
            h = data[off:off + 8].hex()
        print("%-13s %d %11d %10d  %s" % (name, bundle, off, size, h))
    return 0


def cmd_compare(a):
    buf = load(a.binary)
    A = read_records(buf, a.a, a.na)
    B = read_records(buf, a.b, a.nb)
    na = {r[0]: r for r in A}
    nb = {r[0]: r for r in B}
    both = set(na) & set(nb)
    print("A  0x%X  %d records, %d distinct names" % (a.a, len(A), len(na)))
    print("B  0x%X  %d records, %d distinct names" % (a.b, len(B), len(nb)))
    print("shared names        %d" % len(both))
    print("only in A           %d" % len(set(na) - set(nb)))
    print("only in B           %d" % len(set(nb) - set(na)))
    same_off = sum(1 for k in both if na[k][2] == nb[k][2])
    same_size = sum(1 for k in both if na[k][3] == nb[k][3])
    print("shared, same offset %d  (%.2f %%)"
          % (same_off, 100.0 * same_off / len(both) if both else 0))
    print("shared, same size   %d  (%.2f %%)"
          % (same_size, 100.0 * same_size / len(both) if both else 0))
    ea = Counter(os.path.splitext(k)[1].upper() or "(none)" for k in set(na) - set(nb))
    eb = Counter(os.path.splitext(k)[1].upper() or "(none)" for k in set(nb) - set(na))
    print("only in A, by extension: %s" % dict(ea.most_common()))
    print("only in B, by extension: %s" % dict(eb.most_common()))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("qtbl")
    q.add_argument("binary")
    q.set_defaults(fn=cmd_qtbl)

    w = sub.add_parser("versions")
    w.add_argument("binary")
    w.add_argument("--bundle", default=None)
    w.set_defaults(fn=cmd_versions)

    s = sub.add_parser("scan")
    s.add_argument("binary")
    s.add_argument("--min", type=int, default=32)
    s.add_argument("--join", action="store_true")
    s.set_defaults(fn=cmd_scan)

    v = sub.add_parser("verify")
    v.add_argument("binary")
    v.add_argument("bundle")
    v.add_argument("--at", type=lambda x: int(x, 0), default=0)
    v.add_argument("--n", type=int, default=0)
    v.add_argument("--all", action="store_true")
    v.add_argument("--min", type=int, default=100)
    v.add_argument("--join", action="store_true")
    v.set_defaults(fn=cmd_verify)

    d = sub.add_parser("dump")
    d.add_argument("binary")
    d.add_argument("--bundle", default=None)
    d.add_argument("--at", type=lambda x: int(x, 0), required=True)
    d.add_argument("--n", type=int, required=True)
    d.set_defaults(fn=cmd_dump)

    c = sub.add_parser("compare")
    c.add_argument("binary")
    c.add_argument("--a", type=lambda x: int(x, 0), required=True)
    c.add_argument("--na", type=int, required=True)
    c.add_argument("--b", type=lambda x: int(x, 0), required=True)
    c.add_argument("--nb", type=int, required=True)
    c.set_defaults(fn=cmd_compare)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
