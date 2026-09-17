#!/usr/bin/env python3
"""filmprobe.py -- which words of a FILM chunk vary, and which do not.

Naming a field because it looks like a length is how a reader ends up with a
plausible wrong structure. This does the cheap thing instead: it reads the same
word position out of every chunk of one type in a stream and reports whether it
is constant, and if not, what it ranges over. A field that is constant across
409 frames is not a per-frame quantity whatever it looks like; a field that
tracks the chunk size is a length whatever it is called.

usage: filmprobe.py FILE --type FILM [--words 24]
"""
import argparse
import collections
import struct

PRINTABLE = set(range(0x20, 0x7F))


def chunks(data):
    off = 0
    out = []
    while off < len(data):
        tag = data[off:off + 4]
        size = struct.unpack(">I", data[off + 4:off + 8])[0]
        if size < 8 or off + size > len(data):
            raise SystemExit("bad chain at %d: %r size %d" % (off, tag, size))
        out.append((off, tag, size))
        off += size
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--type", default="FILM")
    ap.add_argument("--sub", default=None,
                    help="only chunks whose word at +16 is this four-character tag")
    ap.add_argument("--words", type=int, default=24)
    a = ap.parse_args()
    data = open(a.file, "rb").read()
    want = (a.type + "    ")[:4].encode("latin1")
    sel = [c for c in chunks(data) if c[1] == want]
    if a.sub:
        s = (a.sub + "    ")[:4].encode("latin1")
        sel = [c for c in sel if data[c[0] + 16:c[0] + 20] == s]
    print("%s: %d chunks of type %r%s"
          % (a.file, len(sel), a.type, " sub %r" % a.sub if a.sub else ""))
    sizes = collections.Counter(s for _, _, s in sel)
    print("chunk sizes: %s"
          % ", ".join("%d (x%d)" % (k, v) for k, v in sizes.most_common(6)))
    print()
    print("%-6s %-10s %s" % ("word", "at", "behaviour"))
    for i in range(a.words):
        vals = []
        for off, t, s in sel:
            if 4 * i + 4 <= s:
                vals.append(struct.unpack(">I", data[off + 4 * i:off + 4 * i + 4])[0])
        if not vals:
            continue
        uniq = sorted(set(vals))
        chars = data[sel[0][0] + 4 * i:sel[0][0] + 4 * i + 4]
        astxt = ("'" + chars.decode("latin1") + "'"
                 if all(c in PRINTABLE for c in chars) else "")
        # does it track the chunk size?
        deltas = collections.Counter(s - v for v, (_, _, s) in zip(vals, sel))
        note = ""
        if len(deltas) == 1:
            note = "  == chunk size - %d" % list(deltas)[0]
        if len(uniq) == 1:
            print("%-6d +%-9d constant 0x%08x = %d %s%s"
                  % (i, 4 * i, uniq[0], uniq[0], astxt, note))
        else:
            print("%-6d +%-9d %d values, %d..%d %s%s"
                  % (i, 4 * i, len(uniq), uniq[0], uniq[-1], astxt, note))
    print()
    print("first chunk, 96 bytes:")
    off, t, s = sel[0]
    for i in range(0, min(96, s), 16):
        row = data[off + i:off + i + 16]
        print("   +%-4d %-48s %s"
              % (i, " ".join("%02x" % x for x in row),
                 "".join(chr(x) if x in PRINTABLE else "." for x in row)))


if __name__ == "__main__":
    main()
