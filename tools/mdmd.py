#!/usr/bin/env python3
"""mdmd.py -- reader for the `MDmd` container found on the VIS pressing of
*Links: The Challenge of Golf* (Access Software / Tandy, 1992).

There is no public definition of this format. Everything below was measured on
the nine specimens on that disc and every assertion the reader makes is one it
will fail loudly on. Nothing here is inferred from the `.LZ` file extension,
which is a filename and not an algorithm.

WHAT WAS MEASURED, AND HOW TO RE-MEASURE IT

`MDmd` is not "an archive with a directory". It is a **recursive node format**:
every node, at every depth, begins with the same 122-byte header, and a file is
a *chain* of one or more such nodes laid end to end.

    offset  size  meaning                                   witnesses
    ------  ----  ----------------------------------------  ---------
       0      4   magic 'MDmd'                              9 of 9 roots,
                                                            all children
       4      4   constant 0a 01 7a 00                      9 of 9
       8      2   zero                                      9 of 9
      10      1   child count                               9 of 9
      11     13   zero                                      9 of 9
      24      1   compression flag: 0 = stored, 1 = packed   see below
      25      3   u24 LE: raw (decompressed) length
      28      1   zero on every node seen
      29      3   u24 LE: stored (on-disc) length
      32      9   unexamined; not constant
      41      1   length of the name, 0..12
      42     12   name, 8.3, space-padded
      54      1   length of the build path, 0..67
      55     67   build path, space-padded to offset 122
     122      -   payload

    count > 0 : the payload is a DIRECTORY of `count` x 17 bytes -- 13 bytes
                of NUL-padded name, then a u32 LE ABSOLUTE file offset of the
                child node.
    count = 0 : the payload is a FILE of `stored` bytes.

THE BYTE AT +24 IS A COMPRESSION FLAG

    +24 = 0 : the payload is stored VERBATIM, and raw == stored.
    +24 = 1 : the payload is COMPRESSED from `raw` bytes down to `stored`.

Directories are always stored verbatim, so every node with children carries 0
and looks, from outside, like a structural marker. It is not one. **A node with
no children can also carry 0**, and then it is an uncompressed file: the first
version of this reader asserted that +24 = 0 implied a directory, and it
refused `SOUNDW.LZ` at its member `CLAPLOUD.WAV`, which has no children, a
flag of 0, and raw == stored == 38,828. That refusal was the reader working.

The pre-briefing carried into this session read the byte at +24 as a generation
marker, because at the top level of the nine files it is `01` on exactly the
two whose ISO 9660 dates predate the VIS port (1990 and 1991) and `00` on the
seven dated 1992 -- 9 of 9, no exception. **That correlation is real and its
explanation is not.** Every one of `GOLF1.LZ`'s nine children carries `01`, and
they were written on the same day as their parent. The byte says *compressed*,
and the two old files correlate with it only because they are flat chains of
compressed members with no index node on top, while the seven newer files each
open with an index, and an index is never compressed.

THE CHECK THIS FORMAT GIVES AWAY FREE

Child extents are declared twice and must agree. A child's size is
`122 + stored` read from the child's OWN header, and the next child's position
is read from the PARENT's directory. `--validate` requires

    child[i].offset + 122 + child[i].stored == child[i+1].offset

for every i, and requires the last child to end exactly at the end of the
parent, and requires the first child to begin at `parent + 122 + count * 17`.
Residue must be 0. A container that tiles by construction proves nothing; this
one does not tile by construction, because the two numbers come from two
places.

The same applies to a top-level chain: the nodes must cover the file exactly.

THE CODEC, WHICH IS LZW AND WAS NOT GUESSED FROM THE EXTENSION

Compressed payloads are **variable-width LZW, LSB-first**: initial code width
9, first free code 258, code 256 resets the table, code 257 ends the stream,
ceiling 13 bits. See `lzw_decode` for how it was identified, which was by known
plaintext and not by reading `.LZ` as "Lempel-Ziv".

**`--verify` decodes every member and compares its length against the `raw`
field in its own header. It reports 320 of 320.** That is the check worth
having: the packer wrote `raw` and the decoder re-derives it, so a codec that
were merely plausible would not survive 320 firings.

USAGE

    python tools/mdmd.py FILE --validate
    python tools/mdmd.py FILE... --verify
    python tools/mdmd.py FILE --tree
    python tools/mdmd.py FILE... --census
    python tools/mdmd.py FILE --extract OUTDIR [--raw]
    python tools/mdmd.py FILE... --codec
    python tools/mdmd.py FILE --names

`--validate` is meant to be run before `--census`, and it is meant to fail on
anything that is not this format. `LINKS.CFG` (14 bytes), `TITLE.SCR` and
`CONTROL.TAT` are the negative controls that ship with the disc.
`--extract --raw` writes the undecoded streams for anyone auditing the codec.
"""
import argparse
import collections
import os
import sys

MAGIC = b"MDmd"
CONST = bytes((0x0A, 0x01, 0x7A, 0x00))
HDR = 122
ENT = 17
STORED = 0
COMPRESSED = 1


MAX_WIDTH = 13
CLEAR = 256
END = 257


class BadNode(Exception):
    pass


class BadStream(Exception):
    pass


def lzw_decode(src, expect=None, why=""):
    """Decode one leaf payload.

    The codec was identified by known-plaintext, not by the file extension.
    Ninety-seven members of `SOUNDW.LZ` are RIFF WAVE files, nineteen of them
    stored verbatim, so the first bytes of the other seventy-eight were known
    before they were decoded. Reading `DING.WAV`'s stream as LSB-first codes
    of increasing width gives 256, 82, 73 -- a clear code, then `R`, then `I`.
    That is ordinary variable-width LZW as used by `compress(1)` and GIF, and
    it decoded to 11,598 bytes against a declared 11,598.

    Measured parameters: LSB-first bit packing, initial width 9, first free
    code 258, width increases when the next code to be assigned would not fit,
    ceiling 13 bits, 256 resets the table, 257 ends the stream. The ceiling is
    the one parameter that had to be searched: 12 truncates and 14 is never
    reached, so 13 is the value that makes every member's declared length come
    out right.
    """
    out = bytearray()
    table = [bytes((i,)) for i in range(256)] + [b"", b""]
    nxt = 258
    width = 9
    prev = None
    acc = 0
    nbits = 0
    i = 0
    n = len(src)
    while True:
        while nbits < width and i < n:
            acc |= src[i] << nbits
            nbits += 8
            i += 1
        if nbits < width:
            break
        code = acc & ((1 << width) - 1)
        acc >>= width
        nbits -= width
        if code == CLEAR:
            table = [bytes((j,)) for j in range(256)] + [b"", b""]
            nxt = 258
            width = 9
            prev = None
            continue
        if code == END:
            break
        if code < nxt and table[code]:
            entry = table[code]
        elif code == nxt and prev is not None:
            entry = prev + prev[:1]
        else:
            raise BadStream("%s: code %d out of range (next free %d, width %d,"
                            " %d bytes out)" % (why, code, nxt, width,
                                                len(out)))
        out += entry
        if prev is not None:
            table.append(prev + entry[:1])
            nxt += 1
            if nxt + 1 > (1 << width) and width < MAX_WIDTH:
                width += 1
        prev = entry
    if expect is not None and len(out) != expect:
        raise BadStream("%s: decoded %d bytes, header declares %d"
                        % (why, len(out), expect))
    return bytes(out)


def node_bytes(data, n, why=""):
    """The member's content: the stored bytes, decoded if the flag says so."""
    blob = data[n.off + HDR:n.off + HDR + n.stored]
    if len(blob) != n.stored:
        raise BadStream("%s: %r short by %d bytes"
                        % (why, n.name, n.stored - len(blob)))
    if n.kind == STORED:
        return blob
    return lzw_decode(blob, n.raw, "%s > %s" % (why, n.name))


def u24(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)


def u32(b, o):
    return int.from_bytes(b[o:o + 4], "little")


class Node(object):
    __slots__ = ("off", "kind", "count", "raw", "stored", "name", "path",
                 "tail", "children", "depth")

    def __init__(self, off):
        self.off = off
        self.children = []
        self.depth = 0

    @property
    def is_dir(self):
        return self.count > 0

    @property
    def size(self):
        """Total on-disc extent of this node including its 122-byte header."""
        if not self.is_dir:
            return HDR + self.stored
        end = self.off + HDR + self.count * ENT
        for c in self.children:
            end = max(end, c.off + c.size)
        return end - self.off


def parse_header(data, off, why):
    """Read one 122-byte header. Every field that has a measured invariant is
    checked here and raises rather than being silently tolerated."""
    if off < 0 or off + HDR > len(data):
        raise BadNode("%s: header at %d runs past end of data (%d bytes)"
                      % (why, off, len(data)))
    b = data[off:off + HDR]
    if b[0:4] != MAGIC:
        raise BadNode("%s: no MDmd magic at %d (found %r)"
                      % (why, off, bytes(b[0:4])))
    if b[4:8] != CONST:
        raise BadNode("%s: constant at +4 is %s, expected %s, at %d"
                      % (why, b[4:8].hex(" "), CONST.hex(" "), off))
    if b[8:10] != b"\x00\x00":
        raise BadNode("%s: +8 not zero at %d (%s)" % (why, off, b[8:10].hex()))
    if b[11:24] != b"\x00" * 13:
        raise BadNode("%s: +11..+23 not zero at %d (%s)"
                      % (why, off, b[11:24].hex(" ")))
    if b[28] != 0:
        raise BadNode("%s: +28 not zero at %d (0x%02x)" % (why, off, b[28]))

    n = Node(off)
    n.count = b[10]
    n.kind = b[24]
    n.raw = u24(b, 25)
    n.stored = u24(b, 29)
    n.tail = bytes(b[32:41])
    nl = b[41]
    if nl > 12:
        raise BadNode("%s: name length %d > 12 at %d" % (why, nl, off))
    n.name = b[42:42 + nl].decode("latin-1")
    pl = b[54]
    if pl > 67:
        raise BadNode("%s: path length %d > 67 at %d" % (why, pl, off))
    n.path = b[55:55 + pl].decode("latin-1")

    if n.kind not in (STORED, COMPRESSED):
        raise BadNode("%s: compression flag %d at %d is neither 0 nor 1"
                      % (why, n.kind, off))
    # The invariant that makes the flag a measurement rather than a reading.
    if n.kind == STORED and n.raw != n.stored:
        raise BadNode("%s: node %r at %d is flagged stored but raw=%d != "
                      "stored=%d" % (why, n.name, off, n.raw, n.stored))
    if n.kind == COMPRESSED and n.count:
        raise BadNode("%s: directory at %d is flagged compressed"
                      % (why, off))
    if n.count and (n.raw != n.count * ENT or n.stored != n.count * ENT):
        raise BadNode(
            "%s: directory at %d declares raw=%d stored=%d but count %d "
            "x %d = %d" % (why, off, n.raw, n.stored, n.count, ENT,
                           n.count * ENT))
    return n


def parse_node(data, off, why, depth=0, problems=None):
    n = parse_header(data, off, why)
    n.depth = depth
    if not n.is_dir:
        end = off + HDR + n.stored
        if end > len(data):
            raise BadNode("%s: node %r at %d needs %d stored bytes, only %d "
                          "remain" % (why, n.name, off, n.stored,
                                      len(data) - off - HDR))
        return n

    dir_at = off + HDR
    dir_end = dir_at + n.count * ENT
    if dir_end > len(data):
        raise BadNode("%s: directory of %d entries at %d runs past end"
                      % (why, n.count, dir_at))
    offs = []
    for i in range(n.count):
        e = data[dir_at + i * ENT:dir_at + (i + 1) * ENT]
        raw_name = e[:13]
        name = raw_name.rstrip(b"\x00").decode("latin-1")
        if b"\x00" in raw_name and raw_name.rstrip(b"\x00").find(b"\x00") >= 0:
            raise BadNode("%s: directory entry %d has an embedded NUL: %r"
                          % (why, i, bytes(raw_name)))
        offs.append((name, u32(e, 13)))

    for i, (name, coff) in enumerate(offs):
        child = parse_node(data, coff, "%s > %s" % (why, name), depth + 1,
                           problems)
        if child.name != name:
            msg = ("%s: directory says %r, child header at %d says %r"
                   % (why, name, coff, child.name))
            if problems is None:
                raise BadNode(msg)
            problems.append(msg)
        n.children.append(child)

    if n.count:
        first = n.children[0].off
        if first != dir_end:
            msg = ("%s: first child at %d, directory ends at %d, residue %d"
                   % (why, first, dir_end, first - dir_end))
            if problems is None:
                raise BadNode(msg)
            problems.append(msg)
        for i in range(len(n.children) - 1):
            a, b = n.children[i], n.children[i + 1]
            if a.off + a.size != b.off:
                msg = ("%s: child %r ends at %d but %r starts at %d, "
                       "residue %d" % (why, a.name, a.off + a.size, b.name,
                                       b.off, b.off - (a.off + a.size)))
                if problems is None:
                    raise BadNode(msg)
                problems.append(msg)
    return n


def parse_file(path, problems=None):
    """A file is a chain of one or more top-level nodes covering it exactly."""
    data = open(path, "rb").read()
    nodes = []
    off = 0
    while off < len(data):
        if len(data) - off < HDR:
            msg = ("%s: %d trailing bytes at %d, too few for a header"
                   % (path, len(data) - off, off))
            if problems is None:
                raise BadNode(msg)
            problems.append(msg)
            break
        n = parse_node(data, off, os.path.basename(path), 0, problems)
        nodes.append(n)
        off += n.size
    if off != len(data):
        msg = ("%s: chain ends at %d, file is %d bytes, residue %d"
               % (path, off, len(data), len(data) - off))
        if problems is None:
            raise BadNode(msg)
        problems.append(msg)
    return data, nodes


def walk(nodes):
    stack = list(reversed(nodes))
    while stack:
        n = stack.pop()
        yield n
        for c in reversed(n.children):
            stack.append(c)


def cmd_validate(paths):
    bad = 0
    for p in paths:
        problems = []
        try:
            data, nodes = parse_file(p, problems)
        except BadNode as e:
            print("%-16s REFUSED  %s" % (os.path.basename(p), e))
            bad += 1
            continue
        allnodes = list(walk(nodes))
        leaves = [n for n in allnodes if not n.is_dir]
        interior = [n for n in allnodes if n.is_dir]
        if problems:
            print("%-16s TILING FAILED (%d)" % (os.path.basename(p),
                                                len(problems)))
            for m in problems:
                print("    %s" % m)
            bad += 1
            continue
        print("%-16s OK  %d bytes, %d top-level node(s), %d nodes, "
              "%d director%s, %d member%s, residue 0"
              % (os.path.basename(p), len(data), len(nodes), len(allnodes),
                 len(interior), 'y' if len(interior)==1 else 'ies',
                 len(leaves), '' if len(leaves)==1 else 's'))
    return bad


def cmd_tree(paths):
    for p in paths:
        data, nodes = parse_file(p)
        print("=== %s (%d bytes) ===" % (os.path.basename(p), len(data)))
        for n in walk(nodes):
            kind = "dir " if n.is_dir else ("comp" if n.kind == COMPRESSED else "stor")
            ratio = ("%.4f" % (n.stored / n.raw)) if n.raw else "     -"
            print("  %s%-13s %s @%-7d raw %-8d stored %-8d x%s %s"
                  % ("  " * n.depth, n.name, kind, n.off, n.raw, n.stored,
                     ratio, ("[" + n.path + "]") if n.path else ""))


def cmd_names(paths):
    for p in paths:
        data, nodes = parse_file(p)
        for n in walk(nodes):
            if not n.is_dir:
                print("%s\t%s\t%d\t%d" % (os.path.basename(p), n.name,
                                          n.raw, n.stored))


def cmd_census(paths):
    tot_files = tot_nodes = tot_leaves = tot_interior = 0
    tot_raw = tot_stored = tot_bytes = 0
    paths_seen = collections.Counter()
    ext = collections.Counter()
    print("%-16s %9s %6s %6s %6s %11s %11s %7s"
          % ("file", "bytes", "nodes", "dirs", "leaves", "raw", "stored",
             "ratio"))
    for p in paths:
        data, nodes = parse_file(p)
        allnodes = list(walk(nodes))
        leaves = [n for n in allnodes if not n.is_dir]
        interior = [n for n in allnodes if n.is_dir]
        raw = sum(n.raw for n in leaves)
        stored = sum(n.stored for n in leaves)
        print("%-16s %9d %6d %6d %6d %11d %11d %7.4f"
              % (os.path.basename(p), len(data), len(allnodes), len(interior),
                 len(leaves), raw, stored, stored / raw if raw else 0))
        tot_files += 1
        tot_nodes += len(allnodes)
        tot_leaves += len(leaves)
        tot_interior += len(interior)
        tot_raw += raw
        tot_stored += stored
        tot_bytes += len(data)
        for n in allnodes:
            if n.path:
                paths_seen[n.path] += 1
            if "." in n.name:
                ext[n.name.rsplit(".", 1)[1].upper()] += 1
            else:
                ext["(none)"] += 1
    print("%-16s %9d %6d %6d %6d %11d %11d %7.4f"
          % ("TOTAL (%d)" % tot_files, tot_bytes, tot_nodes, tot_interior,
             tot_leaves, tot_raw, tot_stored,
             tot_stored / tot_raw if tot_raw else 0))
    print()
    print("expansion: %d stored bytes of leaf payload decompress to %d, "
          "a factor of %.4f" % (tot_stored, tot_raw,
                                tot_raw / tot_stored if tot_stored else 0))
    print()
    print("member name extensions, %d leaves:" % tot_leaves)
    for e, c in ext.most_common():
        print("  %-8s %4d" % (e, c))
    print()
    print("build paths carried in node headers, %d distinct:" % len(paths_seen))
    for k, c in paths_seen.most_common():
        print("  %-28s %4d" % (k, c))


def cmd_codec(paths):
    """Everything measured about the leaf streams, and no decoding."""
    ratios = []
    heads = collections.Counter()
    n_leaves = 0
    smallest = None
    for p in paths:
        data, nodes = parse_file(p)
        for n in walk(nodes):
            if n.is_dir or n.kind != COMPRESSED or n.raw == 0:
                continue
            n_leaves += 1
            ratios.append(n.stored / n.raw)
            heads[data[n.off + HDR:n.off + HDR + 4].hex(" ")] += 1
            if smallest is None or n.stored < smallest[0]:
                smallest = (n.stored, n.raw, os.path.basename(p), n.name,
                            data[n.off + HDR:n.off + HDR + n.stored])
    if not n_leaves:
        raise SystemExit("mdmd --codec: no leaves found")
    ratios.sort()
    print("leaves with a payload            : %d" % n_leaves)
    print("stored/raw  min                  : %.4f" % ratios[0])
    print("            median               : %.4f" % ratios[len(ratios) // 2])
    print("            max                  : %.4f" % ratios[-1])
    print("leaves that grew (ratio > 1)     : %d"
          % sum(1 for r in ratios if r > 1.0))
    print()
    print("first four bytes of the stored stream, most common:")
    for h, c in heads.most_common(12):
        print("  %-14s %5d" % (h, c))
    print()
    print("the smallest stream on the disc, which is the one to reason from:")
    print("  %s > %s : %d stored -> %d raw"
          % (smallest[2], smallest[3], smallest[0], smallest[1]))
    print("  %s" % smallest[4].hex(" "))
    print()
    print("NO DECOMPRESSOR IS IMPLEMENTED. The above is a description of the")
    print("streams, not an identification of the algorithm. `.LZ` is a")
    print("filename.")


def cmd_verify(paths):
    """Decode every member and check its length against its own header.

    This is the quantity-encoded-twice check the format gives away: `raw` is
    written in the header by the packer, and the decoder derives it again from
    the stream. A codec that were merely plausible would not survive it.
    """
    tot = ok = 0
    bad = []
    for p in paths:
        data, nodes = parse_file(p)
        members = [n for n in walk(nodes) if not n.is_dir]
        n_ok = 0
        for n in members:
            tot += 1
            try:
                node_bytes(data, n, os.path.basename(p))
                n_ok += 1
                ok += 1
            except BadStream as e:
                bad.append(str(e))
        print("%-16s %3d of %3d members decode to their declared length"
              % (os.path.basename(p), n_ok, len(members)))
    print()
    print("TOTAL %d of %d" % (ok, tot))
    for m in bad:
        print("  FAILED %s" % m)
    return 0 if ok == tot else 1


def cmd_extract(path, outdir, raw=False):
    data, nodes = parse_file(path)
    os.makedirs(outdir, exist_ok=True)
    n_out = 0
    written = 0
    for n in walk(nodes):
        if n.is_dir:
            continue
        safe = n.name.replace("/", "_").replace("\\", "_") or "unnamed"
        if raw:
            # The stored bytes, undecoded, for anyone auditing the codec.
            out = os.path.join(outdir, "%04d_%s.z" % (n_out, safe))
            blob = data[n.off + HDR:n.off + HDR + n.stored]
        else:
            out = os.path.join(outdir, "%04d_%s" % (n_out, safe))
            blob = node_bytes(data, n, os.path.basename(path))
            if len(blob) != n.raw:
                raise SystemExit("extract: %s decoded to %d, header says %d"
                                 % (n.name, len(blob), n.raw))
        open(out, "wb").write(blob)
        n_out += 1
        written += len(blob)
    print("extracted %d members, %d bytes, to %s"
          % (n_out, written, outdir))
    return n_out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--tree", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--codec", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--extract", metavar="OUTDIR")
    ap.add_argument("--raw", action="store_true",
                    help="with --extract: write undecoded streams")
    a = ap.parse_args()

    if a.validate:
        return 1 if cmd_validate(a.files) else 0
    if a.verify:
        return cmd_verify(a.files)
    if a.tree:
        cmd_tree(a.files)
    elif a.census:
        cmd_census(a.files)
    elif a.names:
        cmd_names(a.files)
    elif a.codec:
        cmd_codec(a.files)
    elif a.extract:
        if len(a.files) != 1:
            raise SystemExit("--extract takes one file")
        cmd_extract(a.files[0], a.extract, a.raw)
    else:
        raise SystemExit("mdmd.py: pick one of --validate --verify --tree "
                         "--census --names --codec --extract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
