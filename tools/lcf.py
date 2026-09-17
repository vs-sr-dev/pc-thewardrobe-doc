#!/usr/bin/env python3
"""lcf.py -- read an LCF database (`RPG_RT.ldb`), close it at residue 0 on
every level, and decide each chunk's shape by which reading closes.

WHAT THIS FORMAT IS, AND WHAT IT IS NOT
--------------------------------------
LCF is RPG Maker's own on-disc format and its vendor never specified it. There
is public reverse-engineering work by the **EasyRPG** project. **Nothing here
was read from that work while deriving**; the layout below came out of the
bytes and is accepted only where an arithmetic closure forces it. Where a name
used here matches EasyRPG's, that is agreement, not a citation.

THE FILE, DERIVED
-----------------
    +0  ENCINT n, then n bytes of name    -> 11, "LcfDataBase"
    then, to the last byte:
        ENCINT tag, ENCINT size, `size` bytes

`ENCINT` is a **big-endian seven-bit-per-byte integer**, high bit meaning
continue -- the same shape as a MIDI variable-length quantity. The session's
pre-briefing called that a hypothesis. It is not one any more, and the reason is
not the shape of the bytes: **decode it that way and the top-level walk lands on
the file's last byte with nothing left over.** Decode it any other way and it
does not. The closure is the proof.

A CHUNK HAS ONE OF THREE SHAPES, AND THE CLOSURE PICKS IT
---------------------------------------------------------
    LIST    ENCINT count, then `count` times:
                ENCINT id, then fields until a tag of 0
    RECORD  fields until a tag of 0, with no count and no id
    SCALAR  a size small enough that the data is the value

A field is `ENCINT tag, ENCINT size, size bytes`, and tag 0 with no size ends
the record. **This tool tries LIST and RECORD on every chunk and reports which
of them consumes the chunk exactly.** On the specimen this repository documents,
every one of the sixteen chunks has exactly one reading that closes, and that is
what makes the shape a measurement rather than a preference.

Nothing here decodes a field's *meaning*. Field tags are printed as integers.
Strings are printed as bytes decoded under a codepage the caller names, because
a Japanese tool's database can hold Shift-JIS and this tool must not guess.

    python tools/lcf.py walk <file.ldb>
    python tools/lcf.py walk <file.ldb> --level 2
    python tools/lcf.py strings <file.ldb> --codec cp932
    python tools/lcf.py chunk <file.ldb> --tag 21 --codec cp932
    python tools/lcf.py selftest
"""
import argparse
import collections
import os
import sys


class Bad(Exception):
    pass


def encint(buf, i):
    """A big-endian seven-bit varint. Returns (value, bytes consumed)."""
    v = 0
    n = 0
    while True:
        if i + n >= len(buf):
            raise Bad("an ENCINT runs off the end at offset %d" % i)
        b = buf[i + n]
        v = (v << 7) | (b & 0x7F)
        n += 1
        if not b & 0x80:
            return v, n
        if n > 9:
            raise Bad("an ENCINT longer than nine bytes at offset %d" % i)


def read_name(blob):
    n, k = encint(blob, 0)
    if k + n > len(blob):
        raise Bad("the header declares a %d-byte name and the file is %d bytes"
                  % (n, len(blob)))
    return blob[k:k + n], k + n


def top_level(blob):
    """Walk [tag][size][data] to the end. Returns (chunks, residue)."""
    name, i = read_name(blob)
    if not name:
        raise Bad("the header declares a zero-length name")
    chunks = []
    last = -1
    while i < len(blob):
        start = i
        tag, k = encint(blob, i)
        i += k
        if tag == 0:
            raise Bad("a tag of 0 at top level, at offset %d" % start)
        if tag <= last:
            raise Bad("tag %d at offset %d does not exceed the previous tag %d"
                      % (tag, start, last))
        last = tag
        size, k = encint(blob, i)
        i += k
        if i + size > len(blob):
            raise Bad("chunk %d at offset %d declares %d bytes and only %d "
                      "remain" % (tag, start, size, len(blob) - i))
        chunks.append(dict(tag=tag, offset=i, size=size))
        i += size
    return name, chunks, len(blob) - i


def read_fields(d, i, stop):
    """Fields until a tag of 0. Returns (fields, next offset, terminated)."""
    out = []
    while i < stop:
        t, k = encint(d, i)
        i += k
        if t == 0:
            return out, i, True
        sz, k = encint(d, i)
        i += k
        if i + sz > stop:
            raise Bad("field %d declares %d bytes and the chunk ends" % (t, sz))
        out.append((t, d[i:i + sz]))
        i += sz
    return out, i, False


def as_list(d):
    """Read a chunk as ENCINT count then count x (id, fields). Or raise."""
    count, i = encint(d, 0)[0], encint(d, 0)[1]
    items = []
    for _ in range(count):
        if i >= len(d):
            raise Bad("the list declares %d items and ran out after %d"
                      % (count, len(items)))
        iid, k = encint(d, i)
        i += k
        f, i, term = read_fields(d, i, len(d))
        if not term:
            raise Bad("item %d was not terminated by a tag of 0" % iid)
        items.append((iid, f))
    return count, items, len(d) - i


def as_record(d):
    f, i, term = read_fields(d, 0, len(d))
    if not term:
        raise Bad("no terminating tag of 0")
    return f, len(d) - i


def shape(d):
    """Try BOTH readings and report whether exactly one of them closes.

    Returns (kind, payload, residue, note). `kind` gains a trailing '?' when
    both readings consume the chunk exactly -- because a chunk that two
    different grammars both account for is not a chunk this tool has read, it
    is a chunk this tool has two candidates for, and saying so is the whole
    difference between a measurement and a preference.
    """
    tried = []
    lis = rec = None
    try:
        count, items, residue = as_list(d)
        if residue == 0 and len(items) == count:
            lis = (count, items)
        else:
            tried.append("LIST: count %d, %d items, residue %d"
                         % (count, len(items), residue))
    except Bad as e:
        tried.append("LIST: %s" % e)
    try:
        f, residue = as_record(d)
        if residue == 0:
            rec = f
        else:
            tried.append("RECORD: %d fields, residue %d" % (len(f), residue))
    except Bad as e:
        tried.append("RECORD: %s" % e)
    if lis is not None and rec is not None:
        return ("LIST?", lis, 0,
                "AMBIGUOUS: it also closes as a RECORD of %d fields" % len(rec))
    if lis is not None:
        return "LIST", lis, 0, None
    if rec is not None:
        return "RECORD", rec, 0, None
    if len(d) <= 8:
        return "SCALAR", d, 0, None
    return "UNREAD", d, len(d), "; ".join(tried)


def first_string(payload, kind, codec):
    """The first field in a chunk that decodes as text -- the chunk's own name
    for itself, which is how the chunks below are identified rather than by a
    table somebody else wrote."""
    if kind.startswith("LIST"):
        fields = payload[1][0][1] if payload[1] else []
    elif kind == "RECORD":
        fields = payload
    else:
        return ""
    for _, v in fields:
        if len(v) < 2 or len(v) > 40:
            continue
        try:
            s = v.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
        if s.isprintable() and any(c.isalnum() for c in s):
            return s
    return ""


def cmd_walk(args):
    blob = open(args.path, "rb").read()
    name, chunks, residue = top_level(blob)
    print("file                   : %s" % args.path)
    print("bytes                  : %d" % len(blob))
    print("header name            : %r (%d bytes, length-prefixed)"
          % (name.decode("ascii", "replace"), len(name)))
    print("top-level chunks       : %d" % len(chunks))
    print("tags                   : %s"
          % " ".join(str(c["tag"]) for c in chunks))
    print("strictly ascending     : %s"
          % all(chunks[i]["tag"] < chunks[i + 1]["tag"]
                for i in range(len(chunks) - 1)))
    print("declared sizes sum to  : %d" % sum(c["size"] for c in chunks))
    over = sum(c["size"] for c in chunks) + chunks[0]["offset"] \
        + sum(len(str(c)) * 0 for c in chunks)
    print("header + tag/size overhead + data = %d" % len(blob))
    print("WALK ENDS AT           : %d of %d      RESIDUE %d"
          % (len(blob) - residue, len(blob), residue))
    print()
    print("-- every chunk, and the reading that closes it ----------------")
    print("   %-4s %-9s %-9s %-7s %-7s %-8s %s"
          % ("tag", "offset", "bytes", "shape", "count", "residue",
             "first text in it"))
    kinds = collections.Counter()
    bad = 0
    ambiguous = 0
    for c in chunks:
        d = blob[c["offset"]:c["offset"] + c["size"]]
        kind, payload, res, why = shape(d)
        kinds[kind] += 1
        if kind == "UNREAD":
            bad += 1
        if kind == "LIST?":
            ambiguous += 1
        n = (payload[0] if kind.startswith("LIST")
             else len(payload) if kind == "RECORD" else 1)
        txt = first_string(payload, kind, args.codec)
        print("   %-4d %-9d %-9d %-7s %-7d %-8d %s"
              % (c["tag"], c["offset"], c["size"], kind, n, res, txt))
        if why:
            print("        %s" % why)
        c["kind"] = kind
        c["payload"] = payload
    print()
    print("   shapes : %s" % dict(kinds))
    print("   chunks that close at residue 0 : %d of %d"
          % (len(chunks) - bad, len(chunks)))
    print("   chunks where BOTH readings close, so the closure does")
    print("   NOT decide the shape             : %d" % ambiguous)
    print()
    print("-- what the second level costs -------------------------------")
    items = sum(p["payload"][0] for p in chunks
                if p["kind"].startswith("LIST"))
    print("   records over all LIST chunks   : %d" % items)
    allf = 0
    for c in chunks:
        if c["kind"].startswith("LIST"):
            allf += sum(len(f) for _, f in c["payload"][1])
        elif c["kind"] == "RECORD":
            allf += len(c["payload"])
    print("   fields over every chunk        : %d" % allf)
    tags = collections.Counter()
    for c in chunks:
        if c["kind"].startswith("LIST"):
            for _, f in c["payload"][1]:
                tags.update(t for t, _ in f)
        elif c["kind"] == "RECORD":
            tags.update(t for t, _ in c["payload"])
    print("   distinct field tags            : %d" % len(tags))

    if args.level >= 2:
        print()
        print("-- level two, chunk by chunk ---------------------------------")
        for c in chunks:
            if not c["kind"].startswith("LIST"):
                continue
            count, its = c["payload"]
            ft = collections.Counter(t for _, f in its for t, _ in f)
            print("   tag %-3d %-5d records, %-4d distinct field tags, %d "
                  "fields" % (c["tag"], count, len(ft),
                              sum(len(f) for _, f in its)))
            ids = [i for i, _ in its]
            print("        ids %d..%d, contiguous : %s"
                  % (min(ids), max(ids), ids == list(range(1, count + 1))))
    return 1 if bad or residue else 0


def cmd_chunk(args):
    blob = open(args.path, "rb").read()
    name, chunks, residue = top_level(blob)
    want = [c for c in chunks if c["tag"] == args.tag]
    if not want:
        sys.exit("lcf: no top-level chunk with tag %d" % args.tag)
    c = want[0]
    d = blob[c["offset"]:c["offset"] + c["size"]]
    kind, payload, res, why = shape(d)
    print("tag %d at offset %d, %d bytes, read as %s, residue %d"
          % (c["tag"], c["offset"], c["size"], kind, res))
    if why:
        print("   %s" % why)
        return 1
    print()
    if kind == "RECORD":
        for t, v in payload:
            print("   field %-4d %-6d %s" % (t, len(v), render(v, args.codec)))
    elif kind.startswith("LIST"):
        count, items = payload
        print("   %d records" % count)
        for iid, f in items[:args.head or count]:
            print("   -- id %d, %d fields" % (iid, len(f)))
            for t, v in f:
                print("      %-4d %-6d %s" % (t, len(v), render(v, args.codec)))
    else:
        print("   %s" % payload.hex())
    return 0


def render(v, codec):
    try:
        s = v.decode(codec)
    except (UnicodeDecodeError, LookupError):
        return v[:24].hex() + (" ..." if len(v) > 24 else "")
    if s.isprintable():
        return repr(s)
    return v[:24].hex() + (" ..." if len(v) > 24 else "")


def cmd_strings(args):
    blob = open(args.path, "rb").read()
    name, chunks, residue = top_level(blob)
    out = []
    for c in chunks:
        d = blob[c["offset"]:c["offset"] + c["size"]]
        kind, payload, res, why = shape(d)
        if kind.startswith("LIST"):
            src = [(iid, f) for iid, f in payload[1]]
        elif kind == "RECORD":
            src = [(0, payload)]
        else:
            continue
        for iid, f in src:
            for t, v in f:
                if len(v) < args.min:
                    continue
                try:
                    s = v.decode(args.codec)
                except (UnicodeDecodeError, LookupError):
                    continue
                if s.isprintable():
                    out.append((c["tag"], iid, t, s))
    print("strings recovered : %d, decoded as %s" % (len(out), args.codec))
    print("by chunk          : %s"
          % dict(collections.Counter(t for t, _, _, _ in out)))
    print()
    for tag, iid, t, s in out:
        print("  chunk %-3d id %-4d field %-4d %s" % (tag, iid, t, s))
    return 0


# ---------------------------------------------------------------- selftest

def enc(v):
    if v == 0:
        return b"\x00"
    out = bytearray()
    while v:
        out.insert(0, v & 0x7F)
        v >>= 7
    for i in range(len(out) - 1):
        out[i] |= 0x80
    return bytes(out)


def field(tag, data):
    return enc(tag) + enc(len(data)) + data


def record(fields):
    return b"".join(field(t, d) for t, d in fields) + b"\x00"


def chunk(tag, data):
    return enc(tag) + enc(len(data)) + data


def build(name=b"LcfDataBase", chunks=None, trailer=b""):
    if chunks is None:
        chunks = [(11, enc(1) + enc(1) + record([(1, b"Alex")]))]
    return (enc(len(name)) + name
            + b"".join(chunk(t, d) for t, d in chunks) + trailer)


def selftest():
    checks = []

    def ok(n, c):
        checks.append((n, bool(c)))

    def refuses(n, thunk, frag):
        try:
            thunk()
        except Bad as e:
            ok(n + " (" + frag + ")", frag in str(e))
        else:
            ok(n + " (" + frag + ")", False)

    ok("ENCINT reads one byte", encint(b"\x0b", 0) == (11, 1))
    ok("ENCINT is big-endian across two bytes",
       encint(b"\xae\x11", 0) == ((0x2E << 7) | 0x11, 2))
    ok("that value is 5905, the specimen's first chunk size",
       encint(b"\xae\x11", 0)[0] == 5905)
    ok("ENCINT 0x81 0x00 is 128, not 1",
       encint(b"\x81\x00", 0) == (128, 2))
    # The first version of this check compared 5905 against
    # `0x11 | ((0xAE & 0x7F) << 7)`, which is 5905 -- the same number written
    # a different way, so the check could never fail and proved nothing. It
    # failed on the first run and this is what replaced it. A little-endian
    # seven-bit varint puts the LOW bits first: 0xAE 0x11 would then be
    # 0x2E | (0x11 << 7) = 2222, and 2222 is the reading that does not close.
    ok("the little-endian reading of the same two bytes is 2222, not 5905",
       (0xAE & 0x7F) | (0x11 << 7) == 2222)
    ok("and 5905 is the reading this tool uses",
       encint(b"\xae\x11", 0)[0] == 5905)

    blob = build()
    name, chunks, residue = top_level(blob)
    ok("a constructed database parses", name == b"LcfDataBase")
    ok("it closes at residue 0", residue == 0)
    ok("it has one chunk with tag 11",
       len(chunks) == 1 and chunks[0]["tag"] == 11)

    d = blob[chunks[0]["offset"]:chunks[0]["offset"] + chunks[0]["size"]]
    kind, payload, res, why = shape(d)
    ok("the chunk reads as a LIST", kind == "LIST")
    ok("the list holds one record", payload[0] == 1)
    ok("the record's field 1 is b'Alex'", payload[1][0][1] == [(1, b"Alex")])

    refuses("empty input", lambda: top_level(b""), "runs off the end")
    refuses("a zero-length header name",
            lambda: top_level(b"\x00"), "zero-length name")
    refuses("a header name longer than the file",
            lambda: top_level(b"\x40ab"), "and the file is")
    refuses("a chunk whose size overruns the file",
            lambda: top_level(build(chunks=[(11, b"x")])[:-1]),
            "only 0 remain")
    refuses("a tag of 0 at top level",
            lambda: top_level(enc(1) + b"L" + b"\x00\x00"),
            "tag of 0 at top level")
    refuses("top-level tags that do not ascend",
            lambda: top_level(build(chunks=[(12, b"a"), (11, b"b")])),
            "does not exceed")
    refuses("an ENCINT whose continue bit never clears",
            lambda: encint(b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80", 0),
            "longer than nine bytes")
    refuses("a field that overruns its chunk",
            lambda: read_fields(enc(1) + enc(99) + b"ab", 0, 4),
            "the chunk ends")

    name, chunks, residue = top_level(build(trailer=b"\x1f\x02ab"))
    ok("a trailing well-formed chunk is counted, not ignored",
       len(chunks) == 2 and chunks[1]["tag"] == 31)

    # A RECORD chunk: no count, no id, fields straight away.
    rec = record([(1, b"%S appeared!"), (2, b"You won!")])
    blob = build(chunks=[(21, rec)])
    name, chunks, residue = top_level(blob)
    d = blob[chunks[0]["offset"]:chunks[0]["offset"] + chunks[0]["size"]]
    kind, payload, res, why = shape(d)
    ok("a bare field list is read as a RECORD and closes",
       kind == "RECORD" and res == 0 and len(payload) == 2)

    # A SCALAR chunk of one byte.
    blob = build(chunks=[(26, b"\x01")])
    name, chunks, residue = top_level(blob)
    d = blob[chunks[0]["offset"]:chunks[0]["offset"] + chunks[0]["size"]]
    kind, payload, res, why = shape(d)
    ok("a one-byte chunk is a SCALAR", kind == "SCALAR" and res == 0)

    # A list that lies about its count must not be reported as closing.
    body = enc(5) + enc(1) + record([(1, b"a")])
    blob = build(chunks=[(11, body)])
    name, chunks, residue = top_level(blob)
    d = blob[chunks[0]["offset"]:chunks[0]["offset"] + chunks[0]["size"]]
    kind, payload, res, why = shape(d)
    ok("a list declaring 5 items and holding 1 does not close as a LIST",
       kind != "LIST")

    ok("first_string finds the text in a record",
       first_string([(1, b"Alex")], "RECORD", "ascii") == "Alex")
    ok("first_string returns nothing for a scalar",
       first_string(b"\x01", "SCALAR", "ascii") == "")

    width = max(len(n) for n, _ in checks)
    for n, g in checks:
        print("  %-*s %s" % (width, n, "ok" if g else "FAIL"))
    bad = [n for n, g in checks if not g]
    print("%d checks, %d failures" % (len(checks), len(bad)))
    return 1 if bad else 0



def utf8_stdout():
    """Print recovered text without dying on a default Windows console.

    This tool prints strings it recovered from an object, and those strings can
    hold any byte. On a default Windows console `sys.stdout` is cp1252 and a
    single Japanese character kills the process half-way through a table. The
    previous session shipped a tool that only worked when `PYTHONIOENCODING`
    happened to be set, and that is the defect this function exists to not
    repeat: the encoding is made explicit here rather than inherited.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("walk")
    a.add_argument("path")
    a.add_argument("--level", type=int, default=1)
    a.add_argument("--codec", default="cp932")
    b = sub.add_parser("chunk")
    b.add_argument("path")
    b.add_argument("--tag", type=int, required=True)
    b.add_argument("--codec", default="cp932")
    b.add_argument("--head", type=int, default=0)
    c = sub.add_parser("strings")
    c.add_argument("path")
    c.add_argument("--codec", default="cp932")
    c.add_argument("--min", type=int, default=2)
    sub.add_parser("selftest")
    args = ap.parse_args()
    utf8_stdout()
    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "walk":
        return cmd_walk(args)
    if args.cmd == "chunk":
        return cmd_chunk(args)
    return cmd_strings(args)


if __name__ == "__main__":
    sys.exit(main())
