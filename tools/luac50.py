#!/usr/bin/env python3
"""luac50.py -- read Lua 5.0 precompiled chunks to the constants and the
function tree. NOT a patch of `luac52.py`: the 5.0 header, the function layout
and the instruction fields all differ, and the two tools say so.

The claim, stated the way luac52.py states it
---------------------------------------------
Lua 5.0's bytecode is **published as source and not as a specification**:
`lundump.c` (5.0.2) writes it and reads it back, `lopcodes.h` fixes the
instruction fields. What makes the reading checkable is arithmetic -- a chunk
read correctly consumes exactly the bytes it occupies, and every count is
explicit -- and that closure is the only positive control the format offers.
Inside a container that does not say where a chunk ends (an FSAS `.spr`), the
closure is also what MEASURES the chunk: the end of the walk is its length.

The header, from lundump.c 5.0 `DumpHeader`  (22 bytes here)
-------------------------------------------------------------

    1b 4c 75 61   "\\x1bLua"
    50            version 5.0
    01            endianness: 1 = little
    04            sizeof(int)
    04            sizeof(size_t)
    04            sizeof(Instruction)
    06 08 09 09   SIZE_OP, SIZE_A, SIZE_B, SIZE_C  (bits)
    08            sizeof(lua_Number)  <- EIGHT: a double (5.2's is a 4-byte float)
    <Number>      TEST_NUMBER 3.14159265358979323846e7 (lundump.h 5.0: E7,
                  31,415,926.5 -- the first draft of this tool said E8 and
                  was refused by the object's own first chunk)

Where 5.2 differs, so nobody points the wrong tool: 5.2 has a format byte
after the version, no SIZE_* bytes, a `LUAC_TAIL` of six bytes, and
`lastlinedefined`; 5.0 has none of those.

A function (`DumpFunction`), recursively
-----------------------------------------

    String source            (size_t length incl. NUL, then bytes; 0 = none;
                              nested functions write 0 when it equals the parent's)
    int  lineDefined
    u8   nups, u8 numparams, u8 is_vararg, u8 maxstacksize
    Locals:    int n, then n x (String name, int startpc, int endpc)
    Lines:     int n, then n x int
    Upvalues:  int n, then n x String
    Constants: int n, then n x (u8 type; 3 = Number, 4 = String, 0 = nil)
    Protos:    int n, then n x function
    Code:      int n, then n x u32 instruction

Instruction fields (lopcodes.h 5.0): op bits 0-5, A bits 6-13, C bits 14-22,
B bits 23-31, Bx bits 14-31. Only `GETGLOBAL`/`SETGLOBAL` (Kst[Bx]) and
`LOADK` are read here, to list what the scripts call by name; nothing is
executed.

    python tools/luac50.py dump FILE [--at OFF]      one chunk: tree and constants
    python tools/luac50.py close FILE [--at OFF]     where the chunk ends
    python tools/luac50.py census FILE               every chunk found by magic
    python tools/luac50.py globals FILE [--top N]    GETGLOBAL names, counted
    python tools/luac50.py strings FILE              every string constant
    python tools/luac50.py selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                  # noqa: E402
import nameguard                                 # noqa: E402

nameguard.guard()

MAGIC = b"\x1bLua"
VERSION = 0x50
TEST_NUMBER = 3.14159265358979323846e7

OPNAMES = ("MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL",
           "GETTABLE", "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE",
           "SELF", "ADD", "SUB", "MUL", "DIV", "POW", "UNM", "NOT", "CONCAT",
           "JMP", "EQ", "LT", "LE", "TEST", "CALL", "TAILCALL", "RETURN",
           "FORLOOP", "TFORLOOP", "TFORPREP", "SETLIST", "SETLISTO", "CLOSE",
           "CLOSURE")
OP_LOADK, OP_GETGLOBAL, OP_SETGLOBAL = 1, 5, 7


class Bad(Exception):
    pass


class Reader(object):
    def __init__(self, blob, at=0):
        self.b = blob
        self.i = at
        self.end = len(blob)
        self.little = True
        self.size_int = 4
        self.size_t = 4
        self.size_instr = 4
        self.size_num = 8

    def take(self, n):
        if self.i + n > self.end:
            raise Bad("chunk runs %d bytes past the end at %d"
                      % (self.i + n - self.end, self.i))
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def byte(self):
        return self.take(1)[0]

    def int(self):
        v = self.take(self.size_int)
        return int.from_bytes(v, "little" if self.little else "big", signed=True)

    def size(self):
        v = self.take(self.size_t)
        return int.from_bytes(v, "little" if self.little else "big")

    def number(self):
        v = self.take(self.size_num)
        fmt = ("<" if self.little else ">") + ("d" if self.size_num == 8 else "f")
        return struct.unpack(fmt, v)[0]

    def string(self):
        n = self.size()
        if n == 0:
            return None
        s = self.take(n)
        if s[-1:] != b"\x00":
            raise Bad("string of %d at %d does not end in NUL" % (n, self.i - n))
        return s[:-1].decode("latin-1")


def read_header(r):
    if r.take(4) != MAGIC:
        raise Bad("no \\x1bLua signature")
    v = r.byte()
    if v != VERSION:
        raise Bad("version byte 0x%02X, not 0x50 (5.2 is 0x52: luac52.py)" % v)
    r.little = r.byte() == 1
    r.size_int = r.byte()
    r.size_t = r.byte()
    r.size_instr = r.byte()
    sizes = (r.byte(), r.byte(), r.byte(), r.byte())          # OP, A, B, C
    r.size_num = r.byte()
    if sizes != (6, 8, 9, 9):
        raise Bad("instruction field sizes %s, not (6, 8, 9, 9)" % (sizes,))
    if r.size_instr != 4 or r.size_int not in (4, 8) or r.size_t not in (4, 8):
        raise Bad("odd sizes int %d size_t %d instr %d"
                  % (r.size_int, r.size_t, r.size_instr))
    if r.size_num not in (4, 8):
        raise Bad("sizeof(lua_Number) %d" % r.size_num)
    t = r.number()
    if abs(t - TEST_NUMBER) > 1.0:
        raise Bad("test number %r is not 3.14159265358979e7" % t)
    return {"little": r.little, "int": r.size_int, "size_t": r.size_t,
            "number": r.size_num}


def read_function(r, parent_source=None, depth=0):
    if depth > 200:
        raise Bad("function nesting deeper than 200")
    f = {}
    src = r.string()
    f["source"] = src if src is not None else parent_source
    f["line"] = r.int()
    f["nups"] = r.byte()
    f["numparams"] = r.byte()
    f["is_vararg"] = r.byte()
    f["maxstack"] = r.byte()
    n = r.int()
    if n < 0 or n > 1 << 20:
        raise Bad("%d locals" % n)
    f["locals"] = [(r.string(), r.int(), r.int()) for _ in range(n)]
    n = r.int()
    if n < 0 or n > 1 << 24:
        raise Bad("%d line entries" % n)
    f["lines"] = [r.int() for _ in range(n)]
    n = r.int()
    if n < 0 or n > 255:
        raise Bad("%d upvalues" % n)
    f["upvalues"] = [r.string() for _ in range(n)]
    n = r.int()
    if n < 0 or n > 1 << 20:
        raise Bad("%d constants" % n)
    k = []
    for _ in range(n):
        t = r.byte()
        if t == 3:
            k.append(r.number())
        elif t == 4:
            k.append(r.string())
        elif t == 0:
            k.append(None)
        else:
            raise Bad("constant type %d at %d" % (t, r.i - 1))
    f["k"] = k
    n = r.int()
    if n < 0 or n > 1 << 16:
        raise Bad("%d protos" % n)
    f["p"] = [read_function(r, f["source"], depth + 1) for _ in range(n)]
    n = r.int()
    if n < 0 or n > 1 << 24:
        raise Bad("%d instructions" % n)
    raw = r.take(n * r.size_instr)
    f["code"] = list(struct.unpack(("<" if r.little else ">") + "%dI" % n, raw))
    return f


def undump(blob, at=0):
    """(header, main function, end offset). Raises Bad."""
    r = Reader(blob, at)
    h = read_header(r)
    f = read_function(r)
    return h, f, r.i


def decode(word):
    op = word & 0x3F
    a = (word >> 6) & 0xFF
    c = (word >> 14) & 0x1FF
    b = (word >> 23) & 0x1FF
    bx = (word >> 14) & 0x3FFFF
    return op, a, b, c, bx


def walk(f, depth=0):
    yield depth, f
    for p in f["p"]:
        for x in walk(p, depth + 1):
            yield x


def globals_of(f):
    """Counter of GETGLOBAL names and Counter of SETGLOBAL names over the tree."""
    get, put = collections.Counter(), collections.Counter()
    for _d, fn in walk(f):
        for w in fn["code"]:
            op, a, b, c, bx = decode(w)
            if op in (OP_GETGLOBAL, OP_SETGLOBAL) and bx < len(fn["k"]):
                name = fn["k"][bx]
                if isinstance(name, str):
                    (get if op == OP_GETGLOBAL else put)[name] += 1
    return get, put


def strings_of(f):
    out = []
    for _d, fn in walk(f):
        out.extend(k for k in fn["k"] if isinstance(k, str))
    return out


def stats(f):
    n_fn = n_code = n_k = n_str = 0
    for _d, fn in walk(f):
        n_fn += 1
        n_code += len(fn["code"])
        n_k += len(fn["k"])
        n_str += sum(1 for k in fn["k"] if isinstance(k, str))
    return n_fn, n_code, n_k, n_str


def find_chunks(blob):
    """Every offset at which a 5.0 header stands (by magic, not by name)."""
    out = []
    i = blob.find(MAGIC)
    while i >= 0:
        if blob[i + 4:i + 5] == b"\x50":
            out.append(i)
        i = blob.find(MAGIC, i + 1)
    return out


def load(path):
    dirguard.want_file(path, "luac50")
    with open(path, "rb") as fh:
        return fh.read()


def _kshow(v):
    if isinstance(v, str):
        return repr(v)
    if v is None:
        return "nil"
    if float(v).is_integer():
        return str(int(v))
    return repr(v)


def cmd_dump(a):
    blob = load(a.paths[0])
    try:
        h, f, end = undump(blob, a.at)
    except Bad as e:
        sys.exit("luac50: %s" % e)
    print("header: little=%s int=%d size_t=%d number=%d bytes; chunk %d..%d "
          "(%d bytes)" % (h["little"], h["int"], h["size_t"], h["number"],
                          a.at, end, end - a.at))
    n_fn, n_code, n_k, n_str = stats(f)
    print("functions %d  instructions %d  constants %d (%d strings)"
          % (n_fn, n_code, n_k, n_str))
    for depth, fn in walk(f):
        print("%sfunction source=%r line=%d params=%d vararg=%d upvalues=%d "
              "stack=%d code=%d k=%d locals=%d lines=%d"
              % ("  " * depth, fn["source"], fn["line"], fn["numparams"],
                 fn["is_vararg"], fn["nups"], fn["maxstack"], len(fn["code"]),
                 len(fn["k"]), len(fn["locals"]), len(fn["lines"])))
        for i, k in enumerate(fn["k"][:a.limit]):
            print("%s   k[%d] = %s" % ("  " * depth, i, _kshow(k)))
        if len(fn["k"]) > a.limit:
            print("%s   ... %d more" % ("  " * depth, len(fn["k"]) - a.limit))
    if a.disasm:
        for depth, fn in walk(f):
            print("%s-- code of function at line %d" % ("  " * depth, fn["line"]))
            for pc, w in enumerate(fn["code"][:a.limit]):
                op, A, B, C, Bx = decode(w)
                name = OPNAMES[op] if op < len(OPNAMES) else "OP%d" % op
                extra = ""
                if op in (OP_LOADK, OP_GETGLOBAL, OP_SETGLOBAL) and Bx < len(fn["k"]):
                    extra = "  ; " + _kshow(fn["k"][Bx])
                print("%s   %4d  %-10s A=%d B=%d C=%d Bx=%d%s"
                      % ("  " * depth, pc, name, A, B, C, Bx, extra))
    return 0


def cmd_close(a):
    blob = load(a.paths[0])
    try:
        h, f, end = undump(blob, a.at)
    except Bad as e:
        sys.exit("luac50: %s" % e)
    total = len(blob)
    print("chunk at %d ends at %d (%d bytes); file %d; residue %d"
          % (a.at, end, end - a.at, total, total - end))
    return 0 if (a.at == 0 and end == total) or a.at else 1


def cmd_census(a):
    blob = load(a.paths[0])
    offs = find_chunks(blob)
    ok = bad = 0
    gets = collections.Counter()
    ends = []
    for o in offs:
        try:
            h, f, end = undump(blob, o)
        except Bad as e:
            bad += 1
            if a.verbose:
                print("  %d: REFUSED %s" % (o, e))
            continue
        ok += 1
        ends.append((o, end))
        g, _s = globals_of(f)
        gets.update(g)
        if a.verbose:
            n_fn, n_code, n_k, n_str = stats(f)
            print("  %10d  %7d bytes  fn %3d  code %5d  k %4d  str %4d  %s"
                  % (o, end - o, n_fn, n_code, n_k, n_str,
                     ", ".join(repr(x) for x in strings_of(f)[:3])))
    print("%s: %d headers by magic (\\x1bLua + 0x50); %d read to closure, "
          "%d refused" % (nameguard.safe(a.paths[0]), len(offs), ok, bad))
    if ends:
        tot = sum(e - o for o, e in ends)
        print("bytes in chunks %d; smallest %d, largest %d"
              % (tot, min(e - o for o, e in ends), max(e - o for o, e in ends)))
        adj = sum(1 for (o1, e1), (o2, e2) in zip(ends, ends[1:]) if e1 == o2)
        print("chunks that begin exactly where the previous ends: %d of %d pairs"
              % (adj, max(len(ends) - 1, 0)))
    print("distinct GETGLOBAL names %d; top %d:" % (len(gets), a.top))
    for name, n in gets.most_common(a.top):
        print("  %6d  %s" % (n, name))
    return 0


def cmd_globals(a):
    blob = load(a.paths[0])
    gets, sets = collections.Counter(), collections.Counter()
    for o in find_chunks(blob):
        try:
            h, f, end = undump(blob, o)
        except Bad:
            continue
        g, s = globals_of(f)
        gets.update(g)
        sets.update(s)
    print("GETGLOBAL: %d distinct names" % len(gets))
    for name, n in gets.most_common(a.top):
        print("  %6d  %s" % (n, name))
    print("SETGLOBAL: %d distinct names" % len(sets))
    for name, n in sets.most_common(a.top):
        print("  %6d  %s" % (n, name))
    return 0


def cmd_strings(a):
    blob = load(a.paths[0])
    for o in find_chunks(blob):
        try:
            h, f, end = undump(blob, o)
        except Bad:
            continue
        for s in strings_of(f):
            print("%d\t%s" % (o, s))
    return 0


# ----------------------------------------------------------------- selftest
def _s(txt):
    if txt is None:
        return struct.pack("<I", 0)
    b = txt.encode("latin-1") + b"\x00"
    return struct.pack("<I", len(b)) + b


def _build(consts=("hello", 42.0, None), code=(0x00000005, 0x0000001B),
           nested=0, source="=(none)"):
    """A 5.0 chunk: header, one function with the given constants and code,
    `nested` empty child functions."""
    h = MAGIC + bytes([VERSION, 1, 4, 4, 4, 6, 8, 9, 9, 8]) + struct.pack("<d", TEST_NUMBER)

    def fn(consts, code, nested, src):
        out = _s(src) + struct.pack("<I", 7) + bytes([0, 0, 0, 2])
        out += struct.pack("<I", 1) + _s("x") + struct.pack("<II", 0, 1)   # 1 local
        out += struct.pack("<I", len(code)) + b"".join(struct.pack("<I", 1) for _ in code)
        out += struct.pack("<I", 0)                                         # upvalues
        out += struct.pack("<I", len(consts))
        for k in consts:
            if isinstance(k, str):
                out += b"\x04" + _s(k)
            elif k is None:
                out += b"\x00"
            else:
                out += b"\x03" + struct.pack("<d", k)
        out += struct.pack("<I", nested)
        for _ in range(nested):
            out += fn((), (0x0000001B,), 0, None)
        out += struct.pack("<I", len(code)) + b"".join(struct.pack("<I", w) for w in code)
        return out
    return h + fn(consts, code, nested, source)


def cmd_selftest(_a):
    checks = []
    blob = _build()
    h, f, end = undump(blob)
    checks.append(("a built chunk consumes exactly its bytes", end == len(blob),
                   "%d of %d" % (end, len(blob))))
    checks.append(("its constants come back", f["k"] == ["hello", 42.0, None],
                   str(f["k"])))
    checks.append(("its source is read", f["source"] == "=(none)", ""))
    checks.append(("a GETGLOBAL Bx=0 names constant 0",
                   globals_of(f)[0] == {"hello": 1}, str(globals_of(f)[0])))
    b2 = _build(nested=2)
    h, f, end = undump(b2)
    checks.append(("two nested functions are walked and inherit the source",
                   len(f["p"]) == 2 and f["p"][1]["source"] == "=(none)"
                   and end == len(b2), ""))
    checks.append(("a byte cut off the end is REFUSED",
                   _refuses(blob[:-1]), ""))
    checks.append(("a byte added to the end leaves a residue of 1",
                   undump(blob + b"\x00")[2] == len(blob), ""))
    b52 = MAGIC + b"\x52" + blob[5:]
    checks.append(("a 5.2 version byte is REFUSED and names luac52.py",
                   _refuses(b52, "luac52"), ""))
    bad = bytearray(blob)
    bad[10] = 7                                 # SIZE_A = 7
    checks.append(("wrong instruction field sizes are REFUSED",
                   _refuses(bytes(bad)), ""))
    bad = bytearray(blob)
    bad[21] ^= 0x40                             # break the test number's exponent
    checks.append(("a wrong test number is REFUSED", _refuses(bytes(bad)), ""))
    checks.append(("find_chunks finds two chunks in a concatenation, by magic",
                   find_chunks(blob + b"xx" + blob) == [0, len(blob) + 2], ""))
    checks.append(("decode splits op/A/B/C/Bx per lopcodes.h 5.0",
                   decode((3 << 23) | (5 << 14) | (2 << 6) | 5) == (5, 2, 3, 5, (3 << 9) | 5),
                   str(decode((3 << 23) | (5 << 14) | (2 << 6) | 5))))
    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL", note))
        failed += 0 if ok else 1
    print()
    print("%d checks, %d failures (0 skipped: the selftest builds its own chunks)"
          % (len(checks), failed))
    return 1 if failed else 0


def _refuses(blob, needle=None):
    try:
        undump(blob)
    except Bad as e:
        return needle is None or needle in str(e)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("selftest", "dump", "close", "census",
                                     "globals", "strings"))
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--at", type=int, default=0)
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--disasm", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    if a.mode == "selftest":
        return cmd_selftest(a)
    if not a.paths:
        ap.error("give a file")
    return {"dump": cmd_dump, "close": cmd_close, "census": cmd_census,
            "globals": cmd_globals, "strings": cmd_strings}[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
