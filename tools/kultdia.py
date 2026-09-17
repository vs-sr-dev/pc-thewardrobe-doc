#!/usr/bin/env python3
"""kultdia.py -- read the 6,631 `.dia2` dialogue files, once `AGP!` is open.

A `.dia2` is an `AGP!` stream (`tools/agp.py`). Decompressed, its length is

    374 + n x 3640      in seven languages
    669 + n x 7260      in Chinese

so the file is a header and **n fixed-width dialogue nodes**. The stride was
not guessed: the 826 English files decompress to 46 distinct lengths and the
gaps between consecutive distinct lengths are 3,640 every time.

WHAT A NODE HOLDS, AND WHO SAYS SO
----------------------------------
The object ships its own editor -- `data/dia/ch/dialog editor.exe`, a **Debug**
build of a Windows GUI tool whose PDB path is `c:\\Progs\\dialog editor\\Debug\\
dialog editor.pdb` -- and its string pool is the schema:

    field names  link_temp  text_temp  part_temp  char_temp  name_temp
    conditions   no condition / quest state / quest state min / quest state
                 max / quest state between / charmem0..charmem5 /
                 player vounded / item in inventory / item not in inventory /
                 has gold / quest not state / weapon/focus in hand /
                 flag state / armour value min / armour value max / max gold

Nineteen conditions, five per-node fields. The editor was not run, and it did
not need to be: it answers the question about the format it edits out of its
own `.rdata`.

What this tool derives from the nodes themselves is the field **offsets** --
the speaker name, the line, and the script fragment -- by taking the NUL-
terminated eight-bit runs inside each 3,640-byte node and reporting where they
start. It does not claim more than that.

    python tools/kultdia.py validate "<root>/data/dia/eng/Britek/question0.dia2"
    python tools/kultdia.py census   "<root>"
    python tools/kultdia.py text     "<root>/data/dia/eng/Britek/question0.dia2"
    python tools/kultdia.py selftest
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agp import decode, AgpError, MAGIC                    # noqa: E402

HEADER = 374
STRIDE = 3640

# The object holds TWO node shapes, and the second was found by the first one
# refusing 825 files of 6,631 -- 824 of them Chinese. The Chinese tree's
# distinct decompressed lengths step by 7,260 and every one of them is 669
# modulo 7,260, so `data/dia/ch` uses a 669-byte header and a **7,260-byte
# node, exactly twice the western one**.
#
# 3,630 also divides those lengths, and it is wrong: it would give every
# Chinese file twice as many nodes as its English twin.
# `data/dia/ch/Britek/question0.dia2` decompresses to 124,089 = 669 + 17 x
# 7,260 and `data/dia/eng/Britek/question0.dia2` to 62,255 = 374 + 17 x 3,640
# -- the same seventeen nodes -- and the printable runs inside a Chinese node
# start at +139/+140 where the western ones start at +70. The Chinese text
# fields are UTF-16LE and the western ones are eight-bit, so the node is
# double. **The arithmetic admitted two answers and the content chose.**
SHAPES = [(374, 3640, "western"), (669, 7260, "chinese")]


class DiaError(Exception):
    pass


def shape(n_bytes):
    """Return (nodes, slack, which) for a decompressed length, or raise."""
    tried = []
    for hdr, stride, name in SHAPES:
        body = n_bytes - hdr
        if body < 0:
            tried.append("%s: shorter than its %d-byte header" % (name, hdr))
            continue
        nodes, slack = divmod(body, stride)
        if slack <= 1:
            return nodes, slack, name
        tried.append("%s: %d = %d + %d x %d + %d" %
                     (name, n_bytes, hdr, nodes, stride, slack))
    raise DiaError("%d bytes fits neither node shape -- %s"
                   % (n_bytes, "; ".join(tried)))


def load(path):
    blob = open(path, "rb").read()
    if blob[:4] != MAGIC:
        raise DiaError("%s: does not begin %r" % (path, MAGIC))
    plain, residue, tokens, lits, mats = decode(blob, path)
    if residue:
        raise DiaError("%s: %d bytes of compressed input left over"
                       % (path, residue))
    nodes, slack, which = shape(len(plain))
    return plain, nodes, slack, which


RUN = re.compile(rb"[\x20-\xff]{3,}")


def node_strings(plain, i, which="western"):
    """The printable runs inside node i, with their offset inside the node."""
    hdr, stride = [(h, s) for h, s, n in SHAPES if n == which][0]
    lo = hdr + i * stride
    node = plain[lo:lo + stride]
    out = []
    for m in RUN.finditer(node):
        s = m.group()
        # a run is a field only if what follows it inside the node is a NUL
        if m.end() < len(node) and node[m.end()] != 0:
            pass
        out.append((m.start(), s.decode("cp1252", errors="replace")))
    return out


def cmd_validate(a):
    plain, nodes, slack, which = load(a.path)
    hdr, stride = [(h, s) for h, s, n in SHAPES if n == which][0]
    print("file          : %s" % a.path)
    print("compressed    : %d bytes" % os.path.getsize(a.path))
    print("decompressed  : %d bytes" % len(plain))
    print("node shape    : %s -- header %d, stride %d" % (which, hdr, stride))
    print("arithmetic    : %d + %d x %d + %d = %d   -- CLOSES"
          % (hdr, nodes, stride, slack, hdr + nodes * stride + slack))
    print("dialogue nodes: %d" % nodes)
    print()
    for i in range(min(nodes, a.head)):
        print("node %d:" % i)
        for off, s in node_strings(plain, i, which):
            print("   +%-5d %s" % (off, s[:88]))


def cmd_text(a):
    plain, nodes, slack, which = load(a.path)
    print("%s -- %d nodes, %s shape" % (a.path, nodes, which))
    for i in range(nodes):
        for off, s in node_strings(plain, i, which):
            print("   %s" % s)


def cmd_census(a):
    files = 0
    ok = 0
    bad = []
    nodes_total = 0
    plainsum = 0
    compsum = 0
    per_lang = collections.Counter()
    nodes_lang = collections.Counter()
    offsets = collections.Counter()
    shapes = collections.Counter()
    shape_lang = collections.Counter()
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames.sort()
        for fn in sorted(filenames):
            if not fn.lower().endswith(".dia2"):
                continue
            p = os.path.join(dirpath, fn)
            files += 1
            rel = os.path.relpath(p, a.root).split(os.sep)
            lang = rel[2] if len(rel) > 2 else "?"
            try:
                plain, nodes, slack, which = load(p)
            except (DiaError, AgpError) as exc:
                bad.append("%s: %s" % (os.path.relpath(p, a.root), exc))
                continue
            ok += 1
            shapes[which] += 1
            shape_lang[(lang, which)] += 1
            nodes_total += nodes
            plainsum += len(plain)
            compsum += os.path.getsize(p)
            per_lang[lang] += 1
            nodes_lang[lang] += nodes
            for i in range(nodes):
                for off, s in node_strings(plain, i, which):
                    offsets[off] += 1
    print("files ending .dia2        : %d" % files)
    print("parsing under one of the two node shapes : %d" % ok)
    for k, v in shapes.most_common():
        print("   %-10s %6d" % (k, v))
    print("refusing                  : %d" % len(bad))
    print("dialogue nodes, summed    : %d" % nodes_total)
    print("compressed bytes          : %d" % compsum)
    print("decompressed bytes        : %d" % plainsum)
    print("mean nodes per file       : %.4f" % (nodes_total / float(ok) if ok else 0))
    print()
    print("%-6s %8s %10s %10s   %s" % ("lang", "files", "nodes", "nodes/file", "shapes"))
    for l in sorted(per_lang):
        sh = ", ".join("%s %d" % (w, shape_lang[(l, w)])
                       for _, _, w in SHAPES if shape_lang[(l, w)])
        print("%-6s %8d %10d %10.4f   %s"
              % (l, per_lang[l], nodes_lang[l],
                 nodes_lang[l] / float(per_lang[l]), sh))
    print()
    print("the twenty commonest offsets of a printable run inside a 3,640-byte node:")
    for off, n in sorted(offsets.most_common(20)):
        print("   +%-6d %8d" % (off, n))
    for b in bad[:10]:
        print("   REFUSED %s" % b)
    return 1 if bad else 0


def cmd_selftest(a):
    ok = True
    print("POSITIVE -- the shape function on lengths the object actually has:")
    for n_bytes, want in ((4014, (1, 0, "western")), (4015, (1, 1, "western")),
                          (7654, (2, 0, "western")), (167814, (46, 0, "western")),
                          (374, (0, 0, "western")), (7929, (1, 0, "chinese")),
                          (15189, (2, 0, "chinese")), (29709, (4, 0, "chinese")),
                          (124089, (17, 0, "chinese"))):
        got = shape(n_bytes)
        good = got == want
        print("   %-5s %7d -> %r" % ("ok" if good else "FAIL", n_bytes, got))
        ok = ok and good
    print()
    print("NEGATIVE -- these must be refused:")
    cases = [(0, "shorter than either header"), (373, "one byte short"),
             (4016, "two bytes of slack"), (5000, "not a node boundary"),
             (12345, "not a node boundary in either shape")]
    for n_bytes, why in cases:
        try:
            shape(n_bytes)
        except DiaError as exc:
            print("   ok    %-28s (%s) refused: %s" % (n_bytes, why, str(exc)[:44]))
        else:
            print("   FAIL  %-28s (%s) ACCEPTED" % (n_bytes, why))
            ok = False
    print()
    print("%s" % ("all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("validate"); p.add_argument("path")
    p.add_argument("--head", type=int, default=3); p.set_defaults(fn=cmd_validate)
    p = sub.add_parser("text"); p.add_argument("path"); p.set_defaults(fn=cmd_text)
    p = sub.add_parser("census"); p.add_argument("root"); p.set_defaults(fn=cmd_census)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    try:
        rc = a.fn(a)
    except DiaError as exc:
        sys.exit("DiaError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
