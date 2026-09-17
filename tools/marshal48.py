#!/usr/bin/env python3
"""marshal48.py -- a reader for Ruby's Marshal format, major 4 minor 8, and the
closure test that has now worked on five formats.

WHAT THIS IS FOR
----------------
`pc-rpgmakerxp-doc`'s object stores its whole database in sixteen `.rxdata`
files, every one of which begins `04 08`. That is Ruby's `Marshal.dump` output:
a self-describing byte stream in which **the names of the classes and of their
instance variables are written into the document**. It is the opposite of the
LCF problem three objects ago, where numbered tags had to be given meanings by
closing an arithmetic.

THE GRAMMAR, WHICH IS ONE CHARACTER PER TYPE
--------------------------------------------
After the two version bytes comes exactly one object, and every object begins
with one type byte:

    0   nil                     [   array      long count, then that many
    T   true                    {   hash       long count, then key/value pairs
    F   false                   }   hash with a default value
    i   fixnum                  o   object     symbol, long count, ivar pairs
    l   bignum                  U   user-marshalled object
    f   float (as text)         u   user-defined dump (opaque payload)
    :   symbol (new)            C   an instance of a subclass of a core class
    ;   symbol back-reference   S   struct
    "   string                  /   regexp
    I   ivar-decorated object   e   extended object
    @   object back-reference   c/m/M  class, module, old-style module
                                d   T_DATA

INTEGERS CARRY AN OFFSET OF FIVE AND IT IS THE FIRST THING TO GET WRONG
-----------------------------------------------------------------------
A `long` is one signed byte `c`:

    c == 0                 the value is 0
    5 <= c <= 127          the value is c - 5        <-- the offset
    -128 <= c <= -5        the value is c + 5
    1 <= c <= 4            c more bytes follow, little-endian, positive
    -4 <= c <= -1          -c more bytes follow, little-endian, negative

So `0e` is **9** and not 14, `6a` is **101**, `5f` is **90** and `06` is **1**.
A reader that skips the offset reads every count in every file five too high
and still gets a plausible-looking answer out of the first few, which is why
this tool's closure test is a walk to the last byte and not a header dump.

THE CLOSURE TEST
----------------
`walk` parses one file and prints the offset it stopped at beside the file's
length. **A correct walk lands on the last byte.** Anything else -- short,
long, or an exception -- is a failure and is printed as one. The same test
closed ITSF nine times, LCF sixteen, LcfMapUnit three and PSD once.

    python tools/marshal48.py walk  rpgmakerxp-steam/System/Data/Actors.rxdata
    python tools/marshal48.py census rpgmakerxp-steam/System/Data
    python tools/marshal48.py classes rpgmakerxp-steam/System/Data
    python tools/marshal48.py dump   <file> --depth 3
    python tools/marshal48.py selftest
"""
import argparse
import collections
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class MarshalError(Exception):
    pass


# ---------------------------------------------------------------- the values
#
# Parsed values are kept as small tagged objects rather than as native Python
# ones, because the point of this reader is to say WHAT IS IN THE FILE and a
# Ruby Hash whose keys are Ruby Symbols is not a Python dict.

class RObject(object):
    __slots__ = ("cls", "ivars")

    def __init__(self, cls, ivars):
        self.cls = cls
        self.ivars = ivars          # list of (symbol, value), order preserved

    def __repr__(self):
        return "#<%s %d ivars>" % (self.cls, len(self.ivars))


class RUserDef(object):
    """An object the class dumps itself with `_dump`. RGSS uses this for
    `Table`, which is how a map's tile grid is stored: the payload is opaque to
    Marshal and its shape belongs to the class, not to the format."""
    __slots__ = ("cls", "payload")

    def __init__(self, cls, payload):
        self.cls = cls
        self.payload = payload

    def __repr__(self):
        return "#<%s _dump %d bytes>" % (self.cls, len(self.payload))


class RUserMarshal(object):
    __slots__ = ("cls", "value")

    def __init__(self, cls, value):
        self.cls = cls
        self.value = value

    def __repr__(self):
        return "#<%s marshal_dump>" % self.cls


class RSymbol(str):
    """A Ruby Symbol. Subclasses str so it prints and compares as its name,
    but keeps its own type so a dump can show the leading colon."""
    __slots__ = ()


class RString(object):
    __slots__ = ("raw",)

    def __init__(self, raw):
        self.raw = raw

    def text(self):
        for enc in ("utf-8", "cp932", "latin-1"):
            try:
                return self.raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return self.raw.decode("latin-1", "replace")

    def __repr__(self):
        return "%r" % self.text()


class RStruct(object):
    __slots__ = ("cls", "members")

    def __init__(self, cls, members):
        self.cls = cls
        self.members = members


class RClassRef(object):
    __slots__ = ("kind", "name")

    def __init__(self, kind, name):
        self.kind = kind
        self.name = name


class RExtended(object):
    __slots__ = ("module", "value")

    def __init__(self, module, value):
        self.module = module
        self.value = value


class RWithIvars(object):
    """The `I` decoration: a value plus instance variables. On a String the
    ivars are almost always just `:E` (the encoding flag), which is why this
    keeps the inner value reachable rather than folding the pair together."""
    __slots__ = ("value", "ivars")

    def __init__(self, value, ivars):
        self.value = value
        self.ivars = ivars


class RBignum(object):
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value


NIL = object()


# --------------------------------------------------------------- the reader

class Reader(object):
    def __init__(self, data, path="<bytes>"):
        self.d = data
        self.p = 0
        self.path = path
        self.symbols = []
        self.objects = []
        self.counts = collections.Counter()      # type byte -> occurrences
        self.classes = collections.Counter()     # class name -> instances
        self.ivars = collections.defaultdict(collections.Counter)
        self.max_depth = 0

    # -- primitives

    def byte(self):
        if self.p >= len(self.d):
            raise MarshalError("ran off the end at offset %d of %d"
                               % (self.p, len(self.d)))
        b = self.d[self.p]
        self.p += 1
        return b

    def take(self, n):
        if n < 0:
            raise MarshalError("negative length %d at offset %d"
                               % (n, self.p))
        if self.p + n > len(self.d):
            raise MarshalError("length %d at offset %d runs past the end (%d)"
                               % (n, self.p, len(self.d)))
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def long(self):
        """The offset-of-five integer. Getting this wrong is the documented
        way to misread every count in the file."""
        c = self.byte()
        if c > 127:
            c -= 256
        if c == 0:
            return 0
        if c > 4:
            return c - 5
        if c < -4:
            return c + 5
        if c > 0:
            n = 0
            for i in range(c):
                n |= self.byte() << (8 * i)
            return n
        n = -1
        for i in range(-c):
            n &= ~(0xFF << (8 * i))
            n |= self.byte() << (8 * i)
        return n

    # -- tables

    def new_symbol(self, name):
        s = RSymbol(name)
        self.symbols.append(s)
        return s

    def reserve(self):
        """Register a slot BEFORE the contents are read, because a container
        may contain a back-reference to itself."""
        self.objects.append(None)
        return len(self.objects) - 1

    def place(self, idx, value):
        self.objects[idx] = value
        return value

    # -- the grammar

    def symbol(self):
        t = self.byte()
        if t == ord(":"):
            return self.new_symbol(self.take(self.long()).decode("utf-8",
                                                                 "replace"))
        if t == ord(";"):
            i = self.long()
            if not 0 <= i < len(self.symbols):
                raise MarshalError("symbol link %d out of range (%d known) at "
                                   "offset %d" % (i, len(self.symbols),
                                                  self.p))
            return self.symbols[i]
        if t == ord("I"):
            # An ivar-decorated symbol: Ruby writes this for a symbol whose
            # encoding is not US-ASCII. Read the symbol, then its ivars.
            s = self.symbol()
            for _ in range(self.long()):
                self.symbol()
                self.value(0)
            return s
        raise MarshalError("expected a symbol at offset %d, found %r"
                           % (self.p - 1, bytes([t])))

    def value(self, depth=0):
        self.max_depth = max(self.max_depth, depth)
        t = self.byte()
        ch = chr(t)
        self.counts[ch] += 1

        if ch == "0":
            return NIL
        if ch == "T":
            return True
        if ch == "F":
            return False
        if ch == "i":
            return self.long()
        if ch == ";" or ch == ":":
            self.p -= 1
            return self.symbol()
        if ch == "@":
            i = self.long()
            if not 0 <= i < len(self.objects):
                raise MarshalError("object link %d out of range (%d known) at "
                                   "offset %d" % (i, len(self.objects),
                                                  self.p))
            return self.objects[i]

        if ch == '"':
            idx = self.reserve()
            return self.place(idx, RString(self.take(self.long())))
        if ch == "f":
            idx = self.reserve()
            return self.place(idx, float_of(self.take(self.long())))
        if ch == "l":
            idx = self.reserve()
            sign = self.byte()
            words = self.long()
            raw = self.take(words * 2)
            n = int.from_bytes(raw, "little")
            return self.place(idx, RBignum(-n if sign == ord("-") else n))
        if ch == "[":
            idx = self.reserve()
            n = self.long()
            out = []
            self.place(idx, out)
            for _ in range(n):
                out.append(self.value(depth + 1))
            return out
        if ch == "{" or ch == "}":
            idx = self.reserve()
            n = self.long()
            out = []
            self.place(idx, out)
            for _ in range(n):
                k = self.value(depth + 1)
                v = self.value(depth + 1)
                out.append((k, v))
            if ch == "}":
                self.value(depth + 1)                       # the default
            return out
        if ch == "o":
            idx = self.reserve()
            cls = self.symbol()
            self.classes[str(cls)] += 1
            n = self.long()
            ivars = []
            obj = RObject(str(cls), ivars)
            self.place(idx, obj)
            for _ in range(n):
                name = self.symbol()
                self.ivars[str(cls)][str(name)] += 1
                ivars.append((str(name), self.value(depth + 1)))
            return obj
        if ch == "u":
            idx = self.reserve()
            cls = self.symbol()
            self.classes[str(cls)] += 1
            payload = self.take(self.long())
            return self.place(idx, RUserDef(str(cls), payload))
        if ch == "U":
            idx = self.reserve()
            cls = self.symbol()
            self.classes[str(cls)] += 1
            return self.place(idx, RUserMarshal(str(cls),
                                                self.value(depth + 1)))
        if ch == "C":
            idx = self.reserve()
            cls = self.symbol()
            self.classes[str(cls)] += 1
            return self.place(idx, RUserMarshal(str(cls),
                                                self.value(depth + 1)))
        if ch == "S":
            idx = self.reserve()
            cls = self.symbol()
            self.classes[str(cls)] += 1
            n = self.long()
            members = []
            st = RStruct(str(cls), members)
            self.place(idx, st)
            for _ in range(n):
                name = self.symbol()
                members.append((str(name), self.value(depth + 1)))
            return st
        if ch == "I":
            inner = self.value(depth)
            n = self.long()
            ivars = []
            for _ in range(n):
                name = self.symbol()
                ivars.append((str(name), self.value(depth + 1)))
            return RWithIvars(inner, ivars)
        if ch == "e":
            mod = self.symbol()
            return RExtended(str(mod), self.value(depth + 1))
        if ch == "/":
            idx = self.reserve()
            src = self.take(self.long())
            self.byte()                                     # options
            return self.place(idx, RString(src))
        if ch in "cm":
            idx = self.reserve()
            name = self.take(self.long()).decode("utf-8", "replace")
            return self.place(idx, RClassRef(ch, name))
        if ch == "M":
            idx = self.reserve()
            name = self.take(self.long()).decode("utf-8", "replace")
            return self.place(idx, RClassRef("M", name))
        if ch == "d":
            idx = self.reserve()
            cls = self.symbol()
            self.classes[str(cls)] += 1
            return self.place(idx, RUserMarshal(str(cls),
                                                self.value(depth + 1)))
        raise MarshalError("unknown type byte %r (0x%02x) at offset %d"
                           % (ch, t, self.p - 1))

    def parse(self):
        if len(self.d) < 3:
            raise MarshalError("%d bytes is too short to be a Marshal document"
                               % len(self.d))
        if self.d[0] != 0x04 or self.d[1] != 0x08:
            raise MarshalError("not Marshal 4.8: version bytes are %02x %02x"
                               % (self.d[0], self.d[1]))
        self.p = 2
        root = self.value(0)
        return root


def float_of(raw):
    s = raw.decode("ascii", "replace")
    if s == "inf":
        return float("inf")
    if s == "-inf":
        return float("-inf")
    if s == "nan":
        return float("nan")
    try:
        return float(s.split("\0")[0])
    except ValueError:
        return 0.0


def load(data, path="<bytes>"):
    r = Reader(data, path)
    root = r.parse()
    return root, r


# ------------------------------------------------------------------ reports

def is_marshal48(path):
    """The signature, read from the file.

    Ruby `Marshal` 4.8 is `04 08` followed by exactly one type character. Two
    bytes alone are far too weak to select on -- one file in 65,536 begins
    `04 08` by accident -- so the third byte is checked against the grammar,
    which is the same discipline `coverage.py`'s probe uses and for the same
    reason.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(3)
    except OSError:
        return False
    return (len(head) == 3 and head[0] == 0x04 and head[1] == 0x08
            and head[2:3] in TYPE_BYTES)


# Every type character Marshal 4.8 can begin a document with. Kept as a set of
# one-byte strings so the membership test above reads the same way the parser's
# dispatch does.
TYPE_BYTES = {bytes([c]) for c in b"0TFilfu:;\"I[{}oUCSc/me@dM'"}


def marshal_files(target):
    """Select by MAGIC, not by extension.

    THIS IS THE REPAIR, and it is worth naming what it repairs.

    This function used to read:

        if os.path.isfile(p) and name.lower().endswith(".rxdata")

    `.rxdata` is what `pc-rpgmakerxp-doc`'s object called this format.
    `pc-rpgmakervxace-doc`'s object calls the SAME format -- byte-identical
    version bytes, same grammar, same parser -- `.rvdata2`, and so this reader,
    which walks all 117 of them to the last byte when handed one at a time,
    refused the whole directory and printed a clean refusal message while doing
    it.

    The reader was right and the selection was wrong. That is `mzcensus.py`'s
    twelve-appearance defect -- filtering by extension where a magic exists --
    inside a tool that was one session old, and the honest fix is not a longer
    list of extensions. It is to open the file.
    """
    if os.path.isdir(target):
        out = []
        for name in sorted(os.listdir(target)):
            p = os.path.join(target, name)
            if os.path.isfile(p) and is_marshal48(p):
                out.append(p)
        if not out:
            sys.exit("marshal48: no file under %r begins with the Marshal 4.8 "
                     "signature -- refusing to report a clean table over an "
                     "empty population" % target)
        return out
    if not os.path.isfile(target):
        sys.exit("marshal48: no such file or directory: %s" % target)
    return [target]


# The old name, kept so that nothing which imported it breaks silently. It is
# an alias and not a copy: there is one selection rule in this box now.
rxdata_files = marshal_files


def describe(root):
    if isinstance(root, list) and root and isinstance(root[0], tuple):
        return "Hash of %d" % len(root)
    if isinstance(root, list):
        return "Array of %d" % len(root)
    if isinstance(root, RObject):
        return "Object %s with %d ivars" % (root.cls, len(root.ivars))
    return type(root).__name__


def walk(paths, quiet=False):
    closed = failed = 0
    total = 0
    print("  %-24s %9s %9s %8s  %s"
          % ("file", "bytes", "consumed", "residue", "root"))
    for p in paths:
        data = open(p, "rb").read()
        total += len(data)
        try:
            root, r = load(data, p)
        except MarshalError as e:
            failed += 1
            print("  %-24s %9d %9s %8s  PARSE FAILED: %s"
                  % (os.path.basename(p), len(data), "-", "-", e))
            continue
        residue = len(data) - r.p
        ok = residue == 0
        closed += ok
        failed += not ok
        print("  %-24s %9d %9d %8d  %s%s"
              % (os.path.basename(p), len(data), r.p, residue,
                 describe(root), "" if ok else "   <-- DID NOT CLOSE"))
    print()
    print("  files %d   bytes %d" % (len(paths), total))
    print("  the walk lands on the last byte : %d of %d" % (closed, len(paths)))
    if failed:
        print("  FILES THAT DID NOT CLOSE : %d" % failed, file=sys.stderr)
    return 1 if failed else 0


def census(paths):
    types = collections.Counter()
    classes = collections.Counter()
    ivars = collections.defaultdict(collections.Counter)
    per_file = []
    closed = 0
    for p in paths:
        data = open(p, "rb").read()
        root, r = load(data, p)
        if r.p == len(data):
            closed += 1
        types.update(r.counts)
        classes.update(r.classes)
        for cls, names in r.ivars.items():
            ivars[cls].update(names)
        per_file.append((os.path.basename(p), len(data), describe(root),
                         len(r.symbols), len(r.objects), r.max_depth))
    print("  %-24s %9s  %-22s %7s %8s %6s"
          % ("file", "bytes", "root", "symbols", "objects", "depth"))
    for row in per_file:
        print("  %-24s %9d  %-22s %7d %8d %6d" % row)
    print()
    print("  closing at residue 0 : %d of %d" % (closed, len(paths)))
    print()
    print("  TYPE BYTES, over every value in every file")
    for ch, n in sorted(types.items(), key=lambda kv: -kv[1]):
        print("    %r  %8d   %s" % (ch, n, TYPE_NAMES.get(ch, "?")))
    print("    %s" % ("-" * 20))
    print("    total values : %d" % sum(types.values()))
    print()
    print("  CLASS NAMES, counted by walking and not by grep : %d distinct"
          % len(classes))
    for name, n in sorted(classes.items()):
        print("    %-34s %7d instances   %3d distinct ivars"
              % (name, n, len(ivars[name])))
    allivars = set()
    for names in ivars.values():
        allivars |= set(names)
    print()
    print("  distinct instance-variable names over all classes : %d"
          % len(allivars))
    return 0


def classes_report(paths):
    ivars = collections.defaultdict(collections.Counter)
    classes = collections.Counter()
    where = collections.defaultdict(set)
    for p in paths:
        data = open(p, "rb").read()
        _root, r = load(data, p)
        classes.update(r.classes)
        # `where` is taken from the CLASS census and not from the ivar census,
        # because a class dumped with `_dump` -- Table and Color, 2,023 of the
        # 18,657 values here -- has no ivars at all and was being reported as
        # appearing in no file.
        for cls in r.classes:
            where[cls].add(os.path.basename(p))
        for cls, names in r.ivars.items():
            ivars[cls].update(names)
    for name in sorted(classes):
        print("%s   %d instances   in %s"
              % (name, classes[name], ", ".join(sorted(where[name])) or "-"))
        fields = sorted(ivars[name])
        for i in range(0, len(fields), 4):
            print("    " + "  ".join("%-22s" % f for f in fields[i:i + 4]))
        print()
    print("classes %d   fields %d"
          % (len(classes), len({f for c in ivars for f in ivars[c]})))
    return 0


TYPE_NAMES = {
    "0": "nil", "T": "true", "F": "false", "i": "fixnum", "l": "bignum",
    "f": "float", ":": "symbol", ";": "symbol link", '"': "string",
    "I": "ivar-decorated", "[": "array", "{": "hash", "}": "hash+default",
    "o": "object", "U": "user-marshalled", "u": "user-defined dump",
    "C": "core subclass", "S": "struct", "/": "regexp", "e": "extended",
    "@": "object link", "c": "class", "m": "module", "M": "old module",
    "d": "T_DATA",
}


def render(v, depth, maxdepth, out, indent=""):
    if depth > maxdepth:
        out.append(indent + "...")
        return
    if v is NIL:
        out.append(indent + "nil")
    elif isinstance(v, RSymbol):
        out.append(indent + ":" + str(v))
    elif isinstance(v, RString):
        out.append(indent + repr(v.text()))
    elif isinstance(v, RObject):
        out.append(indent + "#<%s>" % v.cls)
        for name, val in v.ivars:
            out.append(indent + "  " + name + " =")
            render(val, depth + 1, maxdepth, out, indent + "    ")
    elif isinstance(v, RUserDef):
        out.append(indent + "#<%s _dump %d bytes>" % (v.cls, len(v.payload)))
    elif isinstance(v, RUserMarshal):
        out.append(indent + "#<%s>" % v.cls)
        render(v.value, depth + 1, maxdepth, out, indent + "  ")
    elif isinstance(v, RWithIvars):
        render(v.value, depth, maxdepth, out, indent)
    elif isinstance(v, list):
        if v and isinstance(v[0], tuple):
            out.append(indent + "{%d}" % len(v))
            for k, val in v:
                render(k, depth + 1, maxdepth, out, indent + "  ")
                render(val, depth + 1, maxdepth, out, indent + "    =>")
        else:
            out.append(indent + "[%d]" % len(v))
            for e in v:
                render(e, depth + 1, maxdepth, out, indent + "  ")
    else:
        out.append(indent + repr(v))


def dump(path, maxdepth):
    data = open(path, "rb").read()
    root, r = load(data, path)
    out = []
    render(root, 0, maxdepth, out)
    for line in out:
        print(line)
    print()
    print("consumed %d of %d, residue %d" % (r.p, len(data), len(data) - r.p))
    return 0 if r.p == len(data) else 1


# ----------------------------------------------------------------- selftest

def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    def val(raw):
        return load(b"\x04\x08" + raw)

    # the offset of five, which is the thing to get wrong
    ok("a long byte 0x0e is 9 and not 14", Reader(b"\x0e").long() == 9)
    ok("a long byte 0x6a is 101", Reader(b"\x6a").long() == 101)
    ok("a long byte 0x5f is 90", Reader(b"\x5f").long() == 90)
    ok("a long byte 0x06 is 1", Reader(b"\x06").long() == 1)
    ok("a long byte 0x00 is 0", Reader(b"\x00").long() == 0)
    ok("a long byte 0x05 is 0", Reader(b"\x05").long() == 0)
    ok("a long byte 0xfa is -1", Reader(b"\xfa").long() == -1)
    ok("a long byte 0x01 introduces one more byte",
       Reader(b"\x01\xc8").long() == 200)
    ok("a long byte 0x02 introduces two more, little-endian",
       Reader(b"\x02\x2c\x01").long() == 300)
    ok("a long byte 0xff introduces one negative byte",
       Reader(b"\xff\x38").long() == -200)

    # the scalars
    ok("nil parses", val(b"0")[0] is NIL)
    ok("true parses", val(b"T")[0] is True)
    ok("false parses", val(b"F")[0] is False)
    ok("a fixnum parses", val(b"i\x0e")[0] == 9)
    root, rr = val(b'"\x0ahello')
    ok("a string parses and closes", isinstance(root, RString)
       and root.text() == "hello" and rr.p == len(b"\x04\x08" + b'"\x0ahello'))

    # containers, and the counts that come from the offset rule
    root, rr = val(b"[\x08i\x06i\x07i\x08")
    ok("an Array of 3 has three elements", isinstance(root, list)
       and len(root) == 3 and root == [1, 2, 3], repr(root))
    root, _ = val(b"{\x06:\x06ai\x0b")
    ok("a Hash of 1 has one pair", len(root) == 1 and root[0][1] == 6,
       repr(root))

    # symbols and their back-references
    root, rr = val(b"[\x07:\x06a;\x00")
    ok("a symbol link resolves to the same symbol",
       root[0] == "a" and root[1] == "a" and rr.p == 2 + 7, repr(root))

    # objects, which is where the class names live
    obj = b"o:\x0fRPG::Actor\x06:\x0a@namei\x0c"
    root, rr = val(obj)
    ok("an object carries its class name",
       isinstance(root, RObject) and root.cls == "RPG::Actor", repr(root))
    ok("an object carries its ivar names",
       root.ivars == [("@name", 7)], repr(root.ivars))
    ok("an object walk closes on the last byte",
       rr.p == len(b"\x04\x08" + obj), "%d" % rr.p)
    ok("the class census counted one RPG::Actor",
       rr.classes["RPG::Actor"] == 1)
    ok("the ivar census counted @name under RPG::Actor",
       rr.ivars["RPG::Actor"]["@name"] == 1)

    # an object back-reference
    root, _ = val(b"[\x07\"\x06a@\x06")
    ok("an object link points at the object already read",
       root[1] is root[0], repr(root))

    # a user-defined dump, which is how RGSS stores a Table
    root, rr = val(b"u:\x0aTable\x0b\x01\x02\x03\x04\x05\x06")
    ok("a _dump payload is taken by its declared length",
       isinstance(root, RUserDef) and root.cls == "Table"
       and root.payload == b"\x01\x02\x03\x04\x05\x06", repr(root))
    ok("a _dump walk closes", rr.p == 2 + len(b"u:\x0aTable\x0b") + 6)

    # an ivar-decorated string, which is how a UTF-8 String arrives
    root, rr = val(b'I"\x0ahello\x06:\x06ET')
    ok("an I-decorated string keeps its inner value",
       isinstance(root, RWithIvars) and root.value.text() == "hello",
       repr(root))
    ok("an I-decorated string walk closes",
       rr.p == 2 + len(b'I"\x0ahello\x06:\x06ET'))

    # THE REFUSALS -- a reader that cannot fail has not been tested
    def refuses(raw):
        try:
            load(raw)
        except MarshalError:
            return True
        return False

    ok("a file with no version bytes is refused", refuses(b"[\x08"))
    ok("Marshal 4.7 is refused", refuses(b"\x04\x07[\x06i\x06"))
    ok("an unknown type byte is refused", refuses(b"\x04\x08\x99"))
    ok("a truncated string is refused", refuses(b"\x04\x08\"\x20abc"))
    ok("a truncated array is refused", refuses(b"\x04\x08[\x0ai\x06"))
    ok("a symbol link out of range is refused", refuses(b"\x04\x08;\x0a"))
    ok("an object link out of range is refused", refuses(b"\x04\x08@\x0a"))
    ok("an empty file is refused", refuses(b""))
    ok("a two-byte file is refused", refuses(b"\x04\x08"))

    # trailing bytes are NOT a parse error, and that is the point of `walk`:
    # the closure test is a separate statement from the parse succeeding.
    root, rr = load(b"\x04\x08i\x06\xff\xff")
    ok("trailing bytes parse but do not close",
       root == 1 and rr.p == 4 and rr.p != 6, "consumed %d of 6" % rr.p)

    # ---------------------------------------------------------------- the
    # SELECTION, repaired on pc-rpgmakervxace-doc. Seven checks, of which four
    # assert a REFUSAL, because the defect was not that the reader said no: it
    # was that the selector never handed it the file.
    import tempfile as _tf
    import shutil as _sh
    d = _tf.mkdtemp(prefix="marshal48-selftest-")
    try:
        def put(name, data):
            with open(os.path.join(d, name), "wb") as fh:
                fh.write(data)
            return os.path.join(d, name)

        p_old = put("Actors.rxdata", b"\x04\x08[\x06i\x06")
        p_new = put("Map001.rvdata2", b"\x04\x08o:\x0dRPG::Map\x00")
        p_none = put("readme.txt", b"this is a text file\n")
        p_near = put("decoy.rvdata2", b"\x04\x08\x99nonsense")
        p_short = put("tiny.rvdata2", b"\x04\x08")

        ok("THE REPAIR: a .rvdata2 is selected, and the extension the "
           "previous object used is not what selects it",
           is_marshal48(p_new) is True)
        ok("and the previous object's .rxdata is STILL selected, by the "
           "same rule",
           is_marshal48(p_old) is True)
        ok("a text file in the same directory is REFUSED",
           is_marshal48(p_none) is False)
        ok("04 08 followed by a byte the grammar cannot start with is "
           "REFUSED even though the extension matches",
           is_marshal48(p_near) is False)
        ok("a two-byte file of 04 08 is REFUSED",
           is_marshal48(p_short) is False)
        ok("a directory yields exactly the two Marshal documents, in name "
           "order, and neither of the three decoys",
           [os.path.basename(x) for x in marshal_files(d)]
           == ["Actors.rxdata", "Map001.rvdata2"],
           " ".join(os.path.basename(x) for x in marshal_files(d)))
        empty = _tf.mkdtemp(prefix="marshal48-empty-")
        try:
            raised = False
            try:
                marshal_files(empty)
            except SystemExit:
                raised = True
            ok("a directory with NO Marshal document is refused rather than "
               "reported as a clean empty table", raised is True)
        finally:
            _sh.rmtree(empty, ignore_errors=True)
    finally:
        _sh.rmtree(d, ignore_errors=True)

    # P19's named blind spot for this reader: **a walk landing on the last
    # byte says nothing about whether the values were interpreted correctly.**
    # These two are the check written against it -- a document whose bytes are
    # fully consumed but whose VALUE is wrong must be catchable, so the walk's
    # closure and the parsed value are asserted separately.
    root, rr = load(b"\x04\x08i\x7f")
    ok("BLIND SPOT: closure and value are separate assertions -- a fully "
       "consumed document still has to yield the RIGHT number",
       rr.p == len(b"\x04\x08i\x7f") and root == 122, "root=%r" % (root,))
    root, rr = load(b"\x04\x08[\x07i\x06i\x07")
    ok("and a two-element array is two elements and not one",
       root == [1, 2] and rr.p == 8, "root=%r" % (root,))

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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode",
                    choices=("walk", "census", "classes", "dump", "selftest"))
    ap.add_argument("target", nargs="?")
    ap.add_argument("--depth", type=int, default=2)
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.target:
        sys.exit("marshal48: %s needs a file or a directory" % args.mode)
    if args.mode == "dump":
        if os.path.isdir(args.target):
            sys.exit("marshal48: dump wants one file, not a directory: %s"
                     % args.target)
        return dump(args.target, args.depth)
    paths = rxdata_files(args.target)
    if args.mode == "walk":
        return walk(paths)
    if args.mode == "census":
        return census(paths)
    return classes_report(paths)


if __name__ == "__main__":
    sys.exit(main())
