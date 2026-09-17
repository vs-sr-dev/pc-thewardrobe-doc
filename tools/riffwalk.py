#!/usr/bin/env python3
"""riffwalk.py -- walk a RIFF file's chunk tree and refuse to finish unless the
declared sizes account for the file exactly.

RIFF is a public definition -- Microsoft/IBM, *Multimedia Programming
Interface and Data Specifications 1.0*, 1991 -- and this repository uses public
definitions by saying it is using them. The whole of the format is:

    'RIFF' uint32 size 'form'          the outer chunk; size counts everything
                                       after the size field, so file length
                                       must be size + 8
    'LIST' uint32 size 'type' ...      a container whose payload is chunks
    'xxxx' uint32 size payload         a leaf, padded to an even length

The pad byte is the thing readers get wrong: an odd-length chunk is followed
by one pad byte that is NOT counted in its size. A walker that forgets it
drifts by one and then reports garbage, so this one accounts for the pad bytes
separately and prints how many it consumed.

`avicheck.py` in this box reads AVI. This reads RIFF as such, which is what the
four SoundFont banks on this object need: SoundFont 2 is a RIFF form with
signature `sfbk` and three LIST chunks, `INFO`, `sdta` and `pdta`. Its own
specification is public (E-mu/Creative, *SoundFont 2.01 Technical
Specification*) and this tool asserts only the RIFF layer plus the three
top-level LIST types, because that is what can be checked without decoding a
sample.

    python tools/riffwalk.py FILE
    python tools/riffwalk.py DIR --ext .SF2
    python tools/riffwalk.py FILE --depth 2

Exit 0 when every file walked closed with residue 0, 1 when one did not,
3 on an empty population.
"""
import argparse
import os
import struct
import sys

CONTAINERS = (b"RIFF", b"LIST")


def walk(data, start, end, depth, maxdepth, out, stats):
    pos = start
    while pos + 8 <= end:
        cid = data[pos:pos + 4]
        (size,) = struct.unpack("<I", data[pos + 4:pos + 8])
        body = pos + 8
        if body + size > end:
            out.append((depth, cid, size, pos, "OVERRUNS its parent by %d"
                        % (body + size - end)))
            stats["bad"] += 1
            return end
        form = data[body:body + 4] if cid in CONTAINERS else b""
        out.append((depth, cid, size, pos, form.decode("latin1")))
        stats["chunks"] += 1
        if cid in CONTAINERS and depth < maxdepth:
            walk(data, body + 4, body + size, depth + 1, maxdepth, out, stats)
        pos = body + size
        if size & 1:                     # the pad byte, not counted in size
            pos += 1
            stats["pad"] += 1
    return pos


def one(path, maxdepth, quiet):
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"RIFF":
        print("%-28s REFUSED: not RIFF (first four bytes %r)"
              % (os.path.basename(path), data[:4]))
        return 1
    (outer,) = struct.unpack("<I", data[4:8])
    form = data[8:12]
    residue = len(data) - (outer + 8)
    out = []
    stats = {"chunks": 0, "pad": 0, "bad": 0}
    walk(data, 12, min(len(data), outer + 8), 1, maxdepth, out, stats)
    if not quiet:
        print("file        : %s" % os.path.basename(path))
        print("bytes       : %d" % len(data))
        print("form        : %r" % form)
        print("RIFF size   : %d, + 8 = %d, file - that = %d"
              % (outer, outer + 8, residue))
        for depth, cid, size, pos, note in out:
            print("  %s%-6s %10d @%-10d %s"
                  % ("  " * (depth - 1), cid.decode("latin1"), size, pos, note))
        print("chunks      : %d   pad bytes consumed : %d   malformed : %d"
              % (stats["chunks"], stats["pad"], stats["bad"]))
        print("RESIDUE     : %d" % residue)
    else:
        top = [c[1].decode("latin1") + ":" + c[4] for c in out if c[0] == 1]
        print("%-16s %11d  form=%s residue=%d chunks=%d  %s"
              % (os.path.basename(path), len(data), form.decode("latin1"),
                 residue, stats["chunks"], " ".join(top)))
    return 0 if residue == 0 and stats["bad"] == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--ext")
    ap.add_argument("--depth", type=int, default=2)
    a = ap.parse_args(argv[1:])
    if os.path.isdir(a.path):
        ext = (a.ext or "").upper()
        files = []
        for r, dirs, names in os.walk(a.path):
            dirs.sort()
            for nm in sorted(names):
                if not ext or nm.upper().endswith(ext):
                    files.append(os.path.join(r, nm))
        if not files:
            print("FATAL: no %s under %r -- nothing to walk" % (ext or "files",
                                                                a.path))
            return 3
        bad = 0
        for p in files:
            bad += one(p, a.depth, True)
        print("%d files, %d did not close with residue 0" % (len(files), bad))
        return 1 if bad else 0
    return one(a.path, a.depth, False)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
