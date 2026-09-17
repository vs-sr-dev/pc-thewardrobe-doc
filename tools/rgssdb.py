#!/usr/bin/env python3
"""rgssdb.py -- read the sixteen `.rxdata` of an RPG Maker XP installation as a
game database rather than as a byte count.

`marshal48.py` answers *what shape is this document*. This answers *what does it
say*, and it does two things that reader cannot:

1. **It derives the two payloads Marshal itself cannot see.** `Table` and
   `Color` are dumped by their own classes with `_dump`, so to Marshal they are
   opaque byte strings -- 2,023 of the 18,657 values in this object. Their
   layouts are worked out here from the bytes and each is given a closure:

       Table   5 x int32 (dimensions, xsize, ysize, zsize, cell count)
               followed by `cell count` x int16.
               20 + 2n against the declared payload length, residue 0.
       Color   4 x float64, little-endian, red green blue alpha.
               32 against the declared payload length, residue 0.

   **The help file documents what these classes MEAN and not how they are
   dumped** -- "each element takes up 2 signed bytes", "each component is
   handled with a floating point value" -- so the semantics are the vendor's
   and the byte layout is derived here. That is the one place in this object
   where the DERIVED bucket has anything in it.

2. **It cross-checks the derivation against fields the vendor documents.**
   A map's `@data` Table declares its own x and y, and the map object declares
   `@width` and `@height` beside it. Two structures written by different code
   paths agreeing is a stronger statement than one structure closing.

    python tools/rgssdb.py summary <System/Data>
    python tools/rgssdb.py tables  <System/Data>
    python tools/rgssdb.py names   <System/Data>
    python tools/rgssdb.py selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import marshal48                                             # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TABLE_HEADER = 20
COLOR_SIZE = 32


class Bad(Exception):
    pass


def table_of(payload):
    """(dims, x, y, z, cells, residue). A residue of 0 is the closure."""
    if len(payload) < TABLE_HEADER:
        raise Bad("a Table payload of %d bytes cannot hold a 20-byte header"
                  % len(payload))
    dims, x, y, z, cells = struct.unpack_from("<5i", payload, 0)
    residue = TABLE_HEADER + cells * 2 - len(payload)
    return dims, x, y, z, cells, residue


def color_of(payload):
    if len(payload) != COLOR_SIZE:
        raise Bad("a Color payload of %d bytes is not 32" % len(payload))
    return struct.unpack("<4d", payload)


def each_value(v, seen=None):
    if seen is None:
        seen = set()
    if id(v) in seen:
        return
    seen.add(id(v))
    yield v
    if isinstance(v, marshal48.RObject):
        for _n, x in v.ivars:
            yield from each_value(x, seen)
    elif isinstance(v, marshal48.RWithIvars):
        yield from each_value(v.value, seen)
    elif isinstance(v, marshal48.RUserMarshal):
        yield from each_value(v.value, seen)
    elif isinstance(v, list):
        for e in v:
            if isinstance(e, tuple):
                yield from each_value(e[0], seen)
                yield from each_value(e[1], seen)
            else:
                yield from each_value(e, seen)


def rxfiles(root):
    """Select by MAGIC, not by extension -- see `marshal48.marshal_files`.

    This filtered on the literal string `.rxdata`, which is the name the
    previous object gave this format. The format did not change between the two
    products; the extension did, to `.rvdata2`. One selection rule now lives in
    `marshal48.py` and this calls it, so the two cannot drift apart again.
    """
    if not os.path.isdir(root):
        sys.exit("rgssdb: %s is not a directory of Marshal documents" % root)
    out = [os.path.join(root, n) for n in sorted(os.listdir(root))
           if os.path.isfile(os.path.join(root, n))
           and marshal48.is_marshal48(os.path.join(root, n))]
    if not out:
        sys.exit("rgssdb: no file under %r begins with the Marshal 4.8 "
                 "signature -- refusing to report a clean table over an "
                 "empty population" % root)
    return out


def load_all(root):
    docs = {}
    for p in rxfiles(root):
        with open(p, "rb") as fh:
            data = fh.read()
        root_val, reader = marshal48.load(data, p)
        docs[os.path.basename(p)] = (root_val, reader, len(data))
    return docs


def cmd_summary(root):
    docs = load_all(root)
    print("  %-24s %-22s %7s %8s %s"
          % ("file", "root", "entries", "leading", "what it is"))
    total_entries = 0
    nil_first = 0
    arrays = 0
    for name in sorted(docs):
        val, _r, _n = docs[name]
        if isinstance(val, list) and val and isinstance(val[0], tuple):
            kind, n, lead = "Hash", len(val), "-"
        elif isinstance(val, list):
            arrays += 1
            n = len(val)
            lead = "nil" if (val and val[0] is marshal48.NIL) else "a value"
            nil_first += lead == "nil"
            kind = "Array"
            total_entries += n - (1 if lead == "nil" else 0)
        elif isinstance(val, marshal48.RObject):
            kind, n, lead = val.cls, len(val.ivars), "-"
        else:
            kind, n, lead = type(val).__name__, 0, "-"
        print("  %-24s %-22s %7d %8s"
              % (name, kind, n, lead))
    print()
    print("  Array-rooted files                       : %d" % arrays)
    print("  of those whose element 0 is nil          : %d" % nil_first)
    print("  records they hold once the nil is dropped: %d" % total_entries)
    print()
    print("  A leading nil is one-based indexing written down: the editor's")
    print("  ids start at 1 and the serialiser keeps slot 0 empty rather than")
    print("  subtracting. The one Array that does NOT do it is the one whose")
    print("  entries are not addressed by id.")
    return 0


def cmd_tables(root):
    docs = load_all(root)
    tables = colors = 0
    tclosed = cclosed = 0
    dims = collections.Counter()
    shapes = collections.Counter()
    bad = []
    for name in sorted(docs):
        val, _r, _n = docs[name]
        for v in each_value(val):
            if not isinstance(v, marshal48.RUserDef):
                continue
            if v.cls == "Table":
                tables += 1
                try:
                    d, x, y, z, cells, residue = table_of(v.payload)
                except Bad as e:
                    bad.append((name, "Table", str(e)))
                    continue
                dims[d] += 1
                shapes[(d, x, y, z)] += 1
                if residue == 0 and cells == x * max(y, 1) * max(z, 1):
                    tclosed += 1
                else:
                    bad.append((name, "Table",
                                "dims %d %dx%dx%d cells %d residue %d"
                                % (d, x, y, z, cells, residue)))
            elif v.cls == "Color":
                colors += 1
                try:
                    color_of(v.payload)
                    cclosed += 1
                except Bad as e:
                    bad.append((name, "Color", str(e)))
            else:
                bad.append((name, v.cls, "an unexpected _dump class"))
    print("  Table payloads       : %d" % tables)
    print("    closing at residue 0 and cell count = x*y*z : %d of %d"
          % (tclosed, tables))
    print("    by declared dimensionality : %s"
          % ", ".join("%dD x %d" % (k, v) for k, v in sorted(dims.items())))
    print("  Color payloads       : %d" % colors)
    print("    32 bytes read as four float64 : %d of %d" % (cclosed, colors))
    print()
    print("  the eight commonest Table shapes (dims, x, y, z):")
    for shape, n in shapes.most_common(8):
        print("    %-22s x %d" % (str(shape), n))
    if bad:
        print()
        print("  FAILURES : %d" % len(bad), file=sys.stderr)
        for row in bad[:20]:
            print("    %s %s %s" % row, file=sys.stderr)
    return 1 if bad else 0


def cmd_names(root):
    docs = load_all(root)

    def text(v):
        if isinstance(v, marshal48.RWithIvars):
            v = v.value
        return v.text() if isinstance(v, marshal48.RString) else None

    def field(obj, name):
        for n, v in getattr(obj, "ivars", []):
            if n == name:
                return v
        return None

    for name in sorted(docs):
        val, _r, _n = docs[name]
        if not isinstance(val, list) or (val and isinstance(val[0], tuple)):
            continue
        names = []
        for e in val:
            if isinstance(e, marshal48.RObject):
                t = text(field(e, "@name"))
                if t is not None:
                    names.append(t)
        if not names:
            continue
        print("%s : %d named records" % (name, len(names)))
        for i in range(0, len(names), 4):
            print("    " + "".join("%-24s" % n[:23] for n in names[i:i + 4]))
        print()

    # the map, which is the only one
    for name, (val, _r, _n) in docs.items():
        if isinstance(val, marshal48.RObject) and val.cls == "RPG::Map":
            w = h = None
            tbl = None
            for n, v in val.ivars:
                if n == "@width":
                    w = v
                if n == "@height":
                    h = v
                if n == "@data" and isinstance(v, marshal48.RUserDef):
                    tbl = table_of(v.payload)
            print("%s : RPG::Map, @width %s @height %s" % (name, w, h))
            if tbl:
                d, x, y, z, cells, residue = tbl
                print("    its @data Table declares %dD %d x %d x %d, "
                      "%d cells, residue %d" % (d, x, y, z, cells, residue))
                print("    the Table's x and y against the map's own "
                      "@width and @height : %s"
                      % ("they agree" if (x == w and y == h)
                         else "THEY DISAGREE"))
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    p = struct.pack("<5i", 3, 20, 15, 3, 900) + b"\0" * 1800
    d, x, y, z, cells, residue = table_of(p)
    ok("a 3-D Table reads its four sizes", (d, x, y, z, cells)
       == (3, 20, 15, 3, 900), str((d, x, y, z, cells)))
    ok("20 + 900 x 2 = 1820 closes at residue 0", residue == 0, str(residue))
    ok("the cell count is the product of the three sizes",
       cells == x * y * z)

    p = struct.pack("<5i", 1, 17, 1, 1, 17) + b"\0" * 34
    d, x, y, z, cells, residue = table_of(p)
    ok("a 1-D Table of 17 is 20 + 34 = 54 bytes",
       residue == 0 and len(p) == 54, "%d %d" % (residue, len(p)))

    p = struct.pack("<5i", 3, 20, 15, 3, 900) + b"\0" * 1799
    ok("a Table one byte short does NOT close",
       table_of(p)[5] != 0, str(table_of(p)[5]))
    ok("a Table payload shorter than its header is refused",
       _refuses(lambda: table_of(b"\0" * 8)))

    c = struct.pack("<4d", 255.0, 128.0, 0.0, 255.0)
    ok("a Color is four float64", color_of(c) == (255.0, 128.0, 0.0, 255.0),
       str(color_of(c)))
    ok("a Color is 32 bytes", len(c) == 32)
    ok("a Color of the wrong length is refused",
       _refuses(lambda: color_of(b"\0" * 16)))

    # the constant the object hides in RPG::System's undocumented field
    ok("7829367 is 0x777777", 7829367 == 0x777777, hex(7829367))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def _refuses(fn):
    try:
        fn()
    except Bad:
        return True
    except Exception:                                        # noqa: BLE001
        return False
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("summary", "tables", "names",
                                     "selftest"))
    ap.add_argument("root", nargs="?")
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.root:
        sys.exit("rgssdb: %s needs the directory holding the .rxdata"
                 % args.mode)
    if args.mode == "summary":
        return cmd_summary(args.root)
    if args.mode == "tables":
        return cmd_tables(args.root)
    return cmd_names(args.root)


if __name__ == "__main__":
    sys.exit(main())
