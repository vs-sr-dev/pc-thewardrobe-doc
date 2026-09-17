#!/usr/bin/env python3
"""datchain.py -- derive and census the chunk chain of a Final Fantasy XI .DAT.

73.27 % of this object is 52,631 files named <number>.DAT living in 385
directories named <number>, with no name of their own anywhere on the disk.
Their mean entropy is 6.0058, which is where a structured binary format
that has not been compressed lives, and almost every one of them begins
with four printable ASCII bytes.

THE HYPOTHESIS, DERIVED FROM THE BYTES AND NOT FROM A DOCUMENT

`ROM/0/0.DAT` begins:

    00000000  73 79 73 74 01 01 00 00  ...   "syst" then u32 0x00000101
    00000020  63 6f 6c 6c 9f 29 00 00  ...   "coll" then u32 0x0000299f

The second tag stands at offset 32.  Read the u32 after the tag as

    type = v & 0x7F                 v = 0x101 -> type 1
    size = (v >> 7) * 16            v = 0x101 -> 2 * 16 = 32 bytes

and the first chunk is exactly 32 bytes long, which is exactly where the
second tag stands.  That is the hypothesis.  Arithmetic that closes once is
not a structure; the test is whether walking `offset += size` from zero
lands **exactly** on the end of the file, on tens of thousands of files, and
whether every landing site carries four printable bytes.

THE CONTROL THAT MUST FAIL

The same walk is run over files that are known NOT to be .DAT -- the .spw
(`SeWave`), the .bgw (`BGMStream`), the .png, the PE.  If the walk closes on
those too, the walk proves nothing and the tool says so.

Nothing is executed, nothing is contacted, nothing is written to the object.

usage:
  datchain.py walk FILE [FILE ...] [--max N]
  datchain.py census ROOT [--ext .DAT] [--limit N] [--out FILE]
  datchain.py control ROOT
"""

import argparse
import os
import struct
import sys
from collections import Counter

HDR = 16
TYPE_MASK = 0x7F
SIZE_SHIFT = 7
SIZE_MASK = 0x1FFFFF        # 21 bits -- see the note below
SIZE_UNIT = 16
FLAG_SHIFT = 28

# Why the size field is masked and not simply shifted.
#
# In `ROM/0/0.DAT` the chunk `g022` at offset 377,008 carries
# u32 0x60000F85.  Read as (v >> 7) * 16 that is 201,327,088 bytes, which
# is 373 times the whole file.  The next tag actually stands at 377,504,
# i.e. 496 bytes on, and 496 = ((0x60000F85 >> 7) & 0x1F) * 16.  The top
# bits 0x60000000 are therefore FLAGS and not length.
#
# A 22-bit mask was tried first and it was wrong.  In `ROM4/0/0.DAT` the
# chunk `0600` at 5,300,848 carries u32 0x1000062F.  Twenty-two bits give
# 33,554,624 bytes, five times the file.  Twenty-one give
# ((0x1000062F >> 7) & 0x1FFFFF) * 16 = 12 * 16 = 192, and the identical
# `0600`/`0000`/`1700` tags in that file stand at a stride of exactly 192.
# So the word is
#
#     bits  0..6   type       (7 bits)
#     bits  7..27  length     (21 bits, in units of 16 bytes -> max 32 MB)
#     bits 28..31  flags      (4 bits)
#
# and `flags` is censused separately so that the split can be checked
# rather than believed.  The largest chunk seen is 4,709,552 bytes =
# 294,347 units, comfortably inside 2^21.

PRINTABLE = set(range(0x20, 0x7F))


def is_tag(b):
    """Four bytes, printable, NUL-padded on the right.

    The first version of this function demanded four printable bytes and
    the walk stopped on every file at a tag reading `end\\0` -- 65 6e 64 00,
    "end" with one NUL -- carrying u32 0x80, i.e. type 0 and size 16.  That
    is the section terminator, and rejecting it is how a correct walk was
    made to look like a broken one.  The rule is: at least one printable
    byte, then printable or NUL, and no printable byte after a NUL.
    """
    if len(b) != 4 or b[0] not in PRINTABLE:
        return False
    seen_nul = False
    for c in b:
        if c == 0:
            seen_nul = True
        elif c in PRINTABLE:
            if seen_nul:
                return False
        else:
            return False
    return True


def walk(data, max_chunks=0):
    """Walk the chunk chain.  Returns (chunks, verdict, consumed).

    chunks is a list of (offset, tag_bytes, type, size, flags).
    verdict is one of: 'closes', 'overshoots', 'stops-short',
    'bad-tag', 'zero-size'.
    """
    n = len(data)
    off = 0
    chunks = []
    while off < n:
        if off + HDR > n:
            return chunks, "stops-short", off
        tag = data[off:off + 4]
        if not is_tag(tag):
            return chunks, "bad-tag", off
        (v,) = struct.unpack_from("<I", data, off + 4)
        ctype = v & TYPE_MASK
        size = ((v >> SIZE_SHIFT) & SIZE_MASK) * SIZE_UNIT
        flags = v >> FLAG_SHIFT
        if size == 0:
            return chunks, "zero-size", off
        chunks.append((off, tag, ctype, size, flags))
        off += size
        if max_chunks and len(chunks) >= max_chunks:
            return chunks, "truncated", off
        if off > n:
            return chunks, "overshoots", off
    return chunks, ("closes" if off == n else "overshoots"), off


def cmd_walk(args):
    for path in args.file:
        data = open(path, "rb").read()
        chunks, verdict, off = walk(data, args.max)
        print("%s" % path)
        print("  size %d bytes, %d chunks, verdict %s, walk ended at %d (delta %+d)"
              % (len(data), len(chunks), verdict, off, off - len(data)))
        for i, (o, tag, t, s, fl) in enumerate(chunks):
            if args.max and i >= args.max:
                break
            name = "".join(chr(c) if c in PRINTABLE else "." for c in tag)
            print("    %8d  %-6s type %3d  size %9d  flags %d"
                  % (o, name, t, s, fl))
        print()
    return 0


def iter_files(root, exts):
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if exts and os.path.splitext(fn)[1].lower() not in exts:
                continue
            yield os.path.join(dirpath, fn)


def cmd_census(args):
    exts = set(e.lower() for e in args.ext.split(",")) if args.ext else None
    verdicts = Counter()
    tags = Counter()
    types = Counter()
    flagvals = Counter()
    first_tags = Counter()

    chunk_total = 0
    byte_total = 0
    file_total = 0
    bytes_in_closing = 0
    per_branch = Counter()
    per_branch_closing = Counter()
    failures = []
    for path in iter_files(args.root, exts):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        file_total += 1
        byte_total += len(data)
        rel = os.path.relpath(path, args.root).replace(os.sep, "/")
        branch = rel.split("/")[0]
        per_branch[branch] += 1
        chunks, verdict, _off = walk(data)
        verdicts[verdict] += 1
        if verdict == "closes":
            bytes_in_closing += len(data)
            per_branch_closing[branch] += 1
            chunk_total += len(chunks)
            for _o, tag, t, _s, fl in chunks:
                tags[tag] += 1
                types[t] += 1
                flagvals[fl] += 1
            if chunks:
                first_tags[chunks[0][1]] += 1
        elif len(failures) < 40:
            failures.append((rel, len(data), verdict, len(chunks)))
        if args.limit and file_total >= args.limit:
            break

    out = sys.stdout
    if args.out:
        out = open(args.out, "w", encoding="utf-8")

    def w(s=""):
        out.write(s + "\n")

    w("root        : %s" % args.root)
    w("extensions  : %s" % (",".join(sorted(exts)) if exts else "(all)"))
    w("files       : %d" % file_total)
    w("bytes       : %d" % byte_total)
    w()
    w("verdicts:")
    for v, c in verdicts.most_common():
        w("  %-14s %8d  %7.4f %%" % (v, c, 100.0 * c / max(1, file_total)))
    w()
    w("chunks in the files that close : %d" % chunk_total)
    w("bytes in the files that close  : %d  (%.4f %% of the scanned bytes)"
      % (bytes_in_closing, 100.0 * bytes_in_closing / max(1, byte_total)))
    w()
    w("distinct chunk tags : %d" % len(tags))
    w("distinct chunk types: %d" % len(types))
    w()
    w("the twenty commonest chunk tags:")
    for tag, c in tags.most_common(20):
        try:
            name = tag.decode("ascii")
        except UnicodeDecodeError:
            name = repr(tag)
        w("  %-8s %9d  %7.4f %%" % (name, c, 100.0 * c / max(1, chunk_total)))
    w()
    w("the twenty commonest chunk types:")
    for t, c in types.most_common(20):
        w("  %4d %9d  %7.4f %%" % (t, c, 100.0 * c / max(1, chunk_total)))
    w()
    w("the top three bits of the length word, censused separately so that")
    w("the choice of a 22-bit length can be checked and not believed:")
    for fl, c in sorted(flagvals.items()):
        w("  flags %d  %9d  %7.4f %%" % (fl, c, 100.0 * c / max(1, chunk_total)))
    w()
    w("the twenty commonest FIRST tags (the file's own name):")
    for tag, c in first_tags.most_common(20):
        try:
            name = tag.decode("ascii")
        except UnicodeDecodeError:
            name = repr(tag)
        w("  %-8s %9d" % (name, c))
    w()
    w("by branch: files scanned / files that close")
    for b in sorted(per_branch):
        w("  %-10s %7d / %7d  %7.4f %%"
          % (b, per_branch[b], per_branch_closing[b],
             100.0 * per_branch_closing[b] / max(1, per_branch[b])))
    w()
    if failures:
        w("the first %d that do not close:" % len(failures))
        for rel, sz, v, nc in failures:
            w("  %-40s %10d  %-12s %d chunks" % (rel, sz, v, nc))
    if args.out:
        out.close()
        print("wrote %s" % args.out)
    return 0


def cmd_control(args):
    """Run the identical walk over files that are certainly not .DAT.
    If they close, the walk means nothing."""
    print("CONTROL -- the same walk over files that are NOT .DAT.")
    print("If these close, the .DAT result proves nothing.")
    print()
    picks = []
    for dirpath, _d, files in os.walk(args.root):
        for fn in files:
            e = os.path.splitext(fn)[1].lower()
            if e in (".spw", ".bgw", ".png", ".dll", ".exe", ".txt", ".chm"):
                picks.append((e, os.path.join(dirpath, fn)))
        if len(picks) > 4000:
            break
    seen = Counter()
    results = Counter()
    for e, p in picks:
        if seen[e] >= 60:
            continue
        seen[e] += 1
        try:
            data = open(p, "rb").read(8 * 1024 * 1024)
        except OSError:
            continue
        _c, verdict, _o = walk(data)
        results[(e, verdict)] += 1
    print("  ext     verdict         files")
    closes = 0
    for (e, v), c in sorted(results.items()):
        print("  %-7s %-14s %5d" % (e, v, c))
        if v == "closes":
            closes += c
    print()
    print("  control files that closed: %d" % closes)
    if closes == 0:
        print("  CONTROL PASSES: the walk rejects every non-.DAT it was shown.")
    else:
        print("  CONTROL FAILS: the walk accepts things that are not .DAT.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("walk")
    p.add_argument("file", nargs="+")
    p.add_argument("--max", type=int, default=24)
    p.set_defaults(func=cmd_walk)

    p = sub.add_parser("census")
    p.add_argument("root")
    p.add_argument("--ext", default=".dat")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--out")
    p.set_defaults(func=cmd_census)

    p = sub.add_parser("control")
    p.add_argument("root")
    p.set_defaults(func=cmd_control)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
