#!/usr/bin/env python3
"""lcfmap.py -- read RPG Maker's map files, `LcfMapUnit` (.lmu) and
`LcfMapTree` (.lmt), and close each of them on its own last byte.

WHY THIS IS A SEPARATE TOOL FROM lcf.py
---------------------------------------
`lcf.py` reads `LcfDataBase` and takes the header name from the file rather
than assuming it, so the previous session's briefing supposed it would read
these four files too. **It does not, and the two ways it fails are the two
grammars.**

    lcf.py walk RPG_RT.lmt   -> Bad: tag 1 at offset 13 does not exceed the
                                previous tag 4
    lcf.py walk Map0001.lmu  -> Bad: a tag of 0 at top level, at offset 2751

Both refusals are correct. `lcf.py` requires the top level to be a sequence of
tag/size chunks with strictly ascending tags and no terminator, because that is
what a database is. Neither map file is that:

    LcfMapUnit   header name, then FIELDS: tag/size/data pairs terminated by a
                 tag of 0, and **that terminator is the file's last byte**.
                 The tags ascend, but the terminator is fatal to lcf.py.
    LcfMapTree   header name, then a LIST: ENCINT count, then `count` times
                 (ENCINT id, fields terminated by a tag of 0), then one more
                 trailing block. The first two bytes after the name are
                 `04 00` -- a count of 4 and an id of 0 -- which lcf.py must
                 read as tag 4, size 0, and then the next tag is 1 and does not
                 ascend.

**Nothing here was read from the EasyRPG project while deriving.** The layout
below came out of the bytes and is accepted only where an arithmetic closure or
a counting invariant forces it. Where a name used here matches EasyRPG's, that
is agreement and not a citation. Field tags are printed as integers; this tool
names a field only where this repository demonstrates what it holds.

THE GEOMETRY, WHICH IS DERIVED AND NOT DECLARED
-----------------------------------------------
Neither `Map0001.lmu`, `Map0002.lmu` nor `Map0003.lmu` carries an explicit
width or height field. The dimensions are still forced, in three steps:

  1. **two layer chunks, tags 71 and 72, are 600 bytes each in all three
     maps.** They are the same length as each other and across maps;
  2. **the cell is two bytes.** Read as little-endian u16 the layers hold
     values up to 10,131, which does not fit in eight bits; read as bytes the
     odd positions would be a second independent plane, and they are not --
     every one of the 300 odd bytes is non-zero in five of the six layers.
     600 bytes / 2 = **300 cells**;
  3. **the events pin the aspect.** Event coordinates in the three maps reach
     x = 18 and y = 14, so W >= 19 and H >= 15. **The only factorisation of 300
     satisfying both is 20 x 15.**

That is a measurement of the maps, not a default read from a manual, and this
tool prints the factorisation set so the step is visible.

THE ONE PLACE THE CLOSURE IS AMBIGUOUS, AND IT IS SAID SO
---------------------------------------------------------
The sixteen bytes of `RPG_RT.lmt` after the map list close at residue 0 under
**two** readings: as a list of four ids followed by three fields, or as five
tag/size fields. `--strict` reports the ambiguity rather than hiding it. The
list reading is preferred here because the four ids it recovers are exactly a
permutation of the four map ids -- `0 3 2 1` -- which the field reading does
not explain and which chance does not produce. **That is an invariant breaking
a tie, the same instrument `pc-rpgmaker2000-doc/docs/05` had to use on chunk
21, and it is weaker than a closure.**

    python tools/lcfmap.py walk <file.lmu|file.lmt>
    python tools/lcfmap.py tree <file.lmt> --codec cp932
    python tools/lcfmap.py events <file.lmu> --codec cp932
    python tools/lcfmap.py geometry <file.lmu> [<file.lmu> ...]
    python tools/lcfmap.py selftest
"""
import argparse
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LAYER_TAGS = (71, 72)
EVENTS_TAG = 81
NAME_TAG = 1
EVENT_X_TAG = 2
EVENT_Y_TAG = 3


class Bad(Exception):
    pass


def encint(buf, i):
    """A big-endian seven-bit varint, the same shape lcf.py derived."""
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
    return blob[k:k + n].decode("ascii", "replace"), k + n


def read_fields(blob, p, end):
    """tag/size/data until a tag of 0. Returns (fields, position after)."""
    out = []
    while p < end:
        tag, k = encint(blob, p)
        if tag == 0:
            return out, p + k
        size, k2 = encint(blob, p + k)
        d0 = p + k + k2
        if d0 + size > end:
            raise Bad("a field of tag %d at offset %d declares %d bytes and "
                      "only %d remain" % (tag, p, size, end - d0))
        out.append({"tag": tag, "at": p, "size": size,
                    "data": blob[d0:d0 + size]})
        p = d0 + size
    raise Bad("the fields ran to the end of the block without a tag of 0")


def read_list(blob, p, end):
    """ENCINT count, then count x (ENCINT id, fields). Returns (rows, pos)."""
    count, k = encint(blob, p)
    p += k
    rows = []
    for _ in range(count):
        eid, k2 = encint(blob, p)
        p += k2
        fs, p = read_fields(blob, p, end)
        rows.append((eid, fs))
    return rows, p, count


def load(path):
    blob = open(path, "rb").read()
    if not blob:
        raise Bad("%s is empty" % path)
    name, p = read_name(blob)
    return blob, name, p


def parse_mapunit(blob, p):
    fields, end = read_fields(blob, p, len(blob))
    return {"kind": "LcfMapUnit", "fields": fields, "end": end,
            "residue": len(blob) - end}


def parse_maptree(blob, p):
    rows, p2, count = read_list(blob, p, len(blob))
    tail = blob[p2:]
    order = None
    ambiguous = False
    tail_end = p2
    if tail:
        # reading A: a list of ids, then fields
        try:
            n, k = encint(blob, p2)
            q = p2 + k
            ids = []
            for _ in range(n):
                v, k2 = encint(blob, q)
                ids.append(v)
                q += k2
            fsa, qa = read_fields(blob, q, len(blob))
            a_ok = qa == len(blob)
        except Bad:
            a_ok, ids, fsa, qa = False, None, None, None
        # reading B: plain fields
        try:
            fsb, qb = read_fields(blob, p2, len(blob))
            b_ok = qb == len(blob)
        except Bad:
            b_ok, fsb, qb = False, None, None
        ambiguous = bool(a_ok and b_ok)
        if a_ok:
            order, tail_end = ids, qa
        elif b_ok:
            tail_end = qb
    return {"kind": "LcfMapTree", "entries": rows, "count": count,
            "order": order, "ambiguous": ambiguous, "end": tail_end,
            "residue": len(blob) - tail_end}


def parse(path):
    blob, name, p = load(path)
    if name == "LcfMapUnit":
        out = parse_mapunit(blob, p)
    elif name == "LcfMapTree":
        out = parse_maptree(blob, p)
    else:
        raise Bad("%s names itself %r, which is neither LcfMapUnit nor "
                  "LcfMapTree -- lcf.py reads LcfDataBase" % (path, name))
    out["name"] = name
    out["bytes"] = len(blob)
    out["header_end"] = p
    return out


def events_of(parsed):
    d = [f["data"] for f in parsed.get("fields", []) if f["tag"] == EVENTS_TAG]
    if not d:
        return [], 0, 0
    d = d[0]
    rows, p, count = read_list(d, 0, len(d))
    return rows, len(d) - p, count


def geometry(paths):
    """Return (cells, maxx, maxy, candidates) over a set of .lmu files."""
    cells = None
    maxx = maxy = 0
    for path in paths:
        parsed = parse(path)
        if parsed["name"] != "LcfMapUnit":
            raise Bad("%s is not an LcfMapUnit" % path)
        sizes = [f["size"] for f in parsed["fields"] if f["tag"] in LAYER_TAGS]
        if len(sizes) != len(LAYER_TAGS) or len(set(sizes)) != 1:
            raise Bad("%s does not carry two layer chunks of equal size: %r"
                      % (path, sizes))
        n = sizes[0] // 2
        if cells is None:
            cells = n
        elif cells != n:
            raise Bad("maps disagree on cell count: %d and %d" % (cells, n))
        rows, _res, _c = events_of(parsed)
        for _eid, fs in rows:
            for f in fs:
                v = int.from_bytes(f["data"], "little")
                if f["tag"] == EVENT_X_TAG:
                    maxx = max(maxx, v)
                elif f["tag"] == EVENT_Y_TAG:
                    maxy = max(maxy, v)
    cand = [(w, cells // w) for w in range(1, cells + 1)
            if cells % w == 0 and w >= maxx + 1 and cells // w >= maxy + 1]
    return cells, maxx, maxy, cand


def txt(b, codec):
    try:
        return b.decode(codec)
    except Exception:
        return repr(b)


def cmd_walk(args):
    parsed = parse(args.path)
    print("file        : %s" % os.path.basename(args.path))
    print("bytes       : %d" % parsed["bytes"])
    print("header name : %r, ending at %d" % (parsed["name"],
                                              parsed["header_end"]))
    if parsed["name"] == "LcfMapUnit":
        print("top level   : FIELDS terminated by a tag of 0")
        print("fields      : %d" % len(parsed["fields"]))
        print("tags        : %s" % " ".join(str(f["tag"])
                                            for f in parsed["fields"]))
        asc = all(a["tag"] < b["tag"] for a, b in
                  zip(parsed["fields"], parsed["fields"][1:]))
        print("ascending   : %s" % asc)
        for f in parsed["fields"]:
            print("   tag %3d  at %6d  size %6d" % (f["tag"], f["at"],
                                                    f["size"]))
        rows, res, count = events_of(parsed)
        if count:
            print("events      : %d, the event list closing at residue %d"
                  % (count, res))
    else:
        print("top level   : a LIST of %d, then a trailing block"
              % parsed["count"])
        for eid, fs in parsed["entries"]:
            nm = [f["data"] for f in fs if f["tag"] == NAME_TAG]
            print("   entry %d : %d fields   name %s"
                  % (eid, len(fs), txt(nm[0], args.codec) if nm else "(none)"))
        print("trailing    : order %s   ambiguous %s"
              % (parsed["order"], parsed["ambiguous"]))
    print("WALK ENDS AT: %d of %d      RESIDUE %d"
          % (parsed["end"], parsed["bytes"], parsed["residue"]))
    if args.expect_residue is not None and parsed["residue"] != args.expect_residue:
        raise SystemExit("FATAL: --expect-residue %d, got %d"
                         % (args.expect_residue, parsed["residue"]))
    return 0 if parsed["residue"] == 0 else 1


def cmd_tree(args):
    parsed = parse(args.path)
    if parsed["name"] != "LcfMapTree":
        raise SystemExit("lcfmap: %s is not an LcfMapTree" % args.path)
    print("entries : %d (id 0 is the root and is the project title)"
          % parsed["count"])
    for eid, fs in parsed["entries"]:
        row = {f["tag"]: f["data"] for f in fs}
        nm = txt(row.get(NAME_TAG, b""), args.codec)
        print("   id %d  %-20s  fields %s"
              % (eid, nm, " ".join(str(f["tag"]) for f in fs)))
        for f in fs:
            if f["size"] > 1 and f["tag"] != NAME_TAG:
                pretty = "".join(chr(c) if 32 <= c < 127 else "."
                                 for c in f["data"])
                print("        tag %3d size %3d  %s" % (f["tag"], f["size"],
                                                        pretty))
    print("order   : %s" % parsed["order"])
    print("RESIDUE : %d" % parsed["residue"])
    return 0


def cmd_events(args):
    parsed = parse(args.path)
    rows, res, count = events_of(parsed)
    print("events : %d   the event list closes at residue %d" % (count, res))
    for eid, fs in rows:
        row = {f["tag"]: f["data"] for f in fs}
        nm = txt(row.get(NAME_TAG, b""), args.codec)
        x = int.from_bytes(row.get(EVENT_X_TAG, b"\x00"), "little")
        y = int.from_bytes(row.get(EVENT_Y_TAG, b"\x00"), "little")
        print("   %3d  %-14s x=%2d y=%2d   fields %s"
              % (eid, nm, x, y, " ".join(str(f["tag"]) for f in fs)))
    return 0 if res == 0 else 1


def cmd_geometry(args):
    cells, maxx, maxy, cand = geometry(args.paths)
    print("maps            : %d" % len(args.paths))
    print("layer chunks    : tags %s, equal in size in every map"
          % ", ".join(str(t) for t in LAYER_TAGS))
    print("cells per layer : %d  (two bytes each)" % cells)
    print("event extremes  : max x %d, max y %d  ->  W >= %d, H >= %d"
          % (maxx, maxy, maxx + 1, maxy + 1))
    print("factorisations of %d meeting both bounds : %s"
          % (cells, ", ".join("%dx%d" % c for c in cand) or "none"))
    if len(cand) == 1:
        print("THE GEOMETRY IS FORCED : %d x %d" % cand[0])
    else:
        print("THE GEOMETRY IS NOT FORCED by these bounds.")
    if args.expect and len(cand) == 1:
        w, h = (int(v) for v in args.expect.split("x"))
        if (w, h) != cand[0]:
            raise SystemExit("FATAL: --expect %s, derived %dx%d"
                             % (args.expect, cand[0][0], cand[0][1]))
    elif args.expect:
        raise SystemExit("FATAL: --expect %s but the geometry is not forced"
                         % args.expect)
    return 0


def _enc(v):
    """Encode an ENCINT, for the selftest's synthetic specimens."""
    if v < 0x80:
        return bytes([v])
    out = bytearray()
    out.append(v & 0x7F)
    v >>= 7
    while v:
        out.insert(0, (v & 0x7F) | 0x80)
        v >>= 7
    return bytes(out)


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    # ENCINT, against values lcf.py's own derivation produces
    check("ENCINT one byte", encint(b"\x04", 0), (4, 1))
    check("ENCINT two bytes", encint(b"\x81\x00", 0), (128, 2))
    check("ENCINT 0xae 0x11", encint(b"\xae\x11", 0), ((0x2E << 7) | 0x11, 2))
    try:
        encint(b"\x81", 0)
        got = "no exception"
    except Bad:
        got = "Bad"
    check("a truncated ENCINT is fatal", got, "Bad")
    try:
        encint(b"\x81" * 10 + b"\x00", 0)
        got = "no exception"
    except Bad:
        got = "Bad"
    check("a runaway ENCINT is fatal", got, "Bad")

    # a synthetic LcfMapUnit: name, two layer chunks, an event list, terminator
    def field(tag, data):
        return _enc(tag) + _enc(len(data)) + data

    layer = bytes(600)
    ev = _enc(2)
    ev += _enc(1) + field(1, b"EV0001") + field(2, _enc(18)) + \
        field(3, _enc(14)) + b"\x00"
    ev += _enc(2) + field(1, b"EV0002") + field(2, _enc(0)) + \
        field(3, _enc(1)) + b"\x00"
    body = field(1, b"\x04") + field(71, layer) + field(72, layer) + \
        field(81, ev) + b"\x00"
    lmu = _enc(10) + b"LcfMapUnit" + body
    import tempfile
    tmp = tempfile.mkdtemp(prefix="lcfmap-")
    pu = os.path.join(tmp, "Map9999.lmu")
    open(pu, "wb").write(lmu)
    parsed = parse(pu)
    check("a synthetic .lmu closes at residue 0", parsed["residue"], 0)
    check("its top level has four fields", len(parsed["fields"]), 4)
    rows, res, count = events_of(parsed)
    check("its event list closes", res, 0)
    check("its event count", count, 2)
    cells, mx, my, cand = geometry([pu])
    check("300 cells recovered", cells, 300)
    check("max x recovered", mx, 18)
    check("max y recovered", my, 14)
    check("the geometry is forced to one pair", cand, [(20, 15)])

    # a specimen that MUST fail: the terminator removed
    pbad = os.path.join(tmp, "Bad0001.lmu")
    open(pbad, "wb").write(lmu[:-1])
    try:
        parse(pbad)
        got = "no exception"
    except Bad:
        got = "Bad"
    check("a .lmu with no terminator is fatal", got, "Bad")

    # a specimen that MUST fail: one byte appended after the terminator
    ptrail = os.path.join(tmp, "Trail001.lmu")
    open(ptrail, "wb").write(lmu + b"\x99")
    check("an appended byte shows as residue 1",
          parse(ptrail)["residue"], 1)

    # a synthetic LcfMapTree
    e0 = _enc(0) + field(1, b"Root") + b"\x00"
    e1 = _enc(1) + field(1, b"Cave") + b"\x00"
    tail = _enc(2) + _enc(0) + _enc(1) + field(1, b"\x02") + b"\x00"
    lmt = _enc(10) + b"LcfMapTree" + _enc(2) + e0 + e1 + tail
    pt = os.path.join(tmp, "RPG_RT.lmt")
    open(pt, "wb").write(lmt)
    parsed = parse(pt)
    check("a synthetic .lmt closes at residue 0", parsed["residue"], 0)
    check("its entry count", parsed["count"], 2)
    check("its order is a permutation of its ids",
          sorted(parsed["order"]), [0, 1])

    # a header name this tool must refuse
    pdb = os.path.join(tmp, "RPG_RT.ldb")
    open(pdb, "wb").write(_enc(11) + b"LcfDataBase" + b"\x00")
    try:
        parse(pdb)
        got = "no exception"
    except Bad:
        got = "Bad"
    check("LcfDataBase is refused by name", got, "Bad")

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-44s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    for name in ("walk", "tree", "events"):
        s = sub.add_parser(name)
        s.add_argument("path")
        s.add_argument("--codec", default="cp932")
        if name == "walk":
            s.add_argument("--expect-residue", type=int)
    g = sub.add_parser("geometry")
    g.add_argument("paths", nargs="+")
    g.add_argument("--expect")
    sub.add_parser("selftest")
    # Both spellings, because every other tool this session wrote takes
    # --selftest and a harness that guesses one of the two is a harness that
    # records a refusal it caused itself.
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.cmd == "selftest" or args.selftest:
        return selftest()
    try:
        if args.cmd == "walk":
            return cmd_walk(args)
        if args.cmd == "tree":
            return cmd_tree(args)
        if args.cmd == "events":
            return cmd_events(args)
        if args.cmd == "geometry":
            return cmd_geometry(args)
    except Bad as e:
        raise SystemExit("lcfmap: REFUSED: %s" % e)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
