#!/usr/bin/env python3
"""credits.py -- pull the shipped credit rolls out of a decompressed build.

The point of this repository is to publish the 2007 build as a reference, and
the part of that reference nobody can reconstruct from a hash list is **who is
named in it**. This object names them in plain CRLF text inside its own data
containers, so no decoding is needed: the text is found, delimited and printed.

  P.1 governs what is published: a name its owner's employer put inside a
  product they made and sold to the public is published. A shipped credit roll
  is exactly that. Character names are not personal data and are not counted
  as people.

Delimiting is done by structure, not by eye: a credit roll here begins at a
quoted episode title and runs to the end of the printable run that contains
it. The tool prints the byte offset of every block it found and the member it
falls inside, so each block can be pointed at rather than trusted.

    python tools/credits.py _work/solid/english.bin notes/members-english.txt
    python tools/credits.py BLOB CENSUS --out notes/credits-english.txt
"""
import argparse
import re
import sys

TAB = chr(9)
ANCHOR = re.compile(rb"EXECUTIVE PRODUCERS")
PRINTABLE = re.compile(rb"[ -~\r\n\t]{200,}")


def members(census):
    rows = []
    data_off = None
    body = False
    for line in open(census, encoding="utf-8"):
        if line.startswith("# sha1"):
            body = True
            continue
        if not body:
            bits = line.rstrip("\n").split(TAB)
            if bits[0] == "data_block_offset":
                data_off = int(bits[1])
            continue
        bits = line.rstrip("\n").split(TAB)
        if len(bits) == 4:
            rows.append((int(bits[2]), int(bits[1]), bits[3]))
    return data_off, sorted(set(rows))


def owner(rows, rel):
    for pos, size, path in rows:
        if pos <= rel < pos + size + 4:
            return path
    return "(no member)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    ap.add_argument("census")
    ap.add_argument("--out")
    ap.add_argument("--window", type=int, default=24000)
    args = ap.parse_args()

    data_off, rows = members(args.census)
    f = open(args.blob, "rb")
    prev = b""
    off = 0
    hits = []
    while True:
        c = f.read(1 << 24)
        if not c:
            break
        buf = prev + c
        for m in ANCHOR.finditer(buf):
            hits.append(off - len(prev) + m.start())
        prev = buf[-64:]
        off += len(c)

    out = []
    for h in hits:
        f.seek(max(0, h - args.window // 2))
        d = f.read(args.window)
        # take the printable run that CONTAINS the anchor, not the longest one
        # in the window: on two of the six episodes the longest run is a
        # neighbouring block of engine strings and picking it silently dropped
        # the cast list. A block that merely looks plausible is not the block.
        want = min(h, args.window // 2)
        block = b""
        for m in PRINTABLE.finditer(d):
            if m.start() <= want < m.end():
                block = m.group()
                break
        if not block:
            runs = PRINTABLE.findall(d)
            block = max(runs, key=len) if runs else b""
        text = block.decode("latin-1")
        i = text.find("EXECUTIVE PRODUCERS")
        j = text.rfind('"', 0, i)
        start = text.rfind('"', 0, j) if j > 0 else 0
        out.append((h, owner(rows, h - data_off),
                    text[max(0, start):].replace("\r\n", "\n").rstrip()))

    lines = ["# credits.py %s" % args.blob,
             "# blocks found: %d" % len(out), ""]
    for h, who, text in out:
        lines.append("=" * 70)
        lines.append("offset %d, inside %s" % (h, who))
        lines.append("=" * 70)
        lines.append(text)
        lines.append("")
    body = "\n".join(lines)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(body + "\n")
        print("%d credit blocks -> %s" % (len(out), args.out))
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
