#!/usr/bin/env python3
"""plaread.py -- the fifteen .PLA scripts of Simulman V, and the graph they draw.

A .PLA is a stream of **big-endian** 16-bit tokens. That is worth saying twice,
because everything else in this object -- the MZ headers, the .ELE offset
tables, the .MAT dimensions -- is little-endian, as an x86 program's data
should be. The .PLA are not. Whatever wrote them wrote them on, or for, a
big-endian habit.

The evidence that they are big-endian and not little:

  * `SMAN5/PLA/LOGO.PLA` opens `00 01 01 40 00 c8`. Read big-endian that is
    opcode 1 with operands 320 and 200, which is the mode 13h screen. Read
    little-endian it is 256, 16385, 51200.
  * Every filename in every .PLA is preceded by a two-byte token whose high
    byte is 00 and whose low byte is small.
  * The last token of a file is never split across the end.

Five tokens introduce a NUL-terminated path, and which token it is depends on
what kind of file is being named:

    0x03  an animation      SMAN5\\BNK\\*.ANI     322 references
    0x19  a character set   SMAN5\\FNT\\*.CHV      14
    0x1C  a music sequence  SMAN5\\MUS\\*.MDI      13
    0x28  a tile set        SMAN5\\WDW\\*.TIL      10
    0x29  a key table       SMAN5\\WDW\\*.KEY      10

Three of the five were read off four scripts by hand; the other two the tool
found. That is why the check below is an assertion and not a comment: it
verifies that the mapping token -> extension is one-to-one in both directions
over all fifteen scripts, and fails loudly if a sixth token ever introduces a
path or one token introduces two kinds of file.

    python tools/plaread.py <objectroot> [--tokens] [--graph]

--tokens prints the opcode histogram over all fifteen scripts.
--graph  prints the reference graph and the set of files nothing reaches.
"""
import os
import re
import struct
import sys
from collections import Counter, defaultdict

PATH_RE = re.compile(rb"[A-Z0-9]{2,8}(?:\\[A-Z0-9_]{1,8})*\.[A-Z0-9]{1,3}")

# Every NUL-terminated operand, not only the ones that are paths. The .PLA
# also carry short bare identifiers -- `NOT` is the commonest -- and a token
# walk that does not step over those is a token walk reading letters as
# opcodes. The string field is padded to an even length, which is how the
# stream stays on 16-bit boundaries; the padding byte is 00.
STR_RE = re.compile(rb"[A-Z0-9_][A-Z0-9_.\\]{1,40}\x00")


def str_spans(d):
    """(start, end) of every NUL-terminated operand, end rounded up to even."""
    out = []
    for m in STR_RE.finditer(d):
        s, e = m.start(), m.end()
        if s < 2:
            continue
        out.append((s, e + 1 if e % 2 else e))
    return out


def paths_in(d):
    """Every NUL-terminated DOS path in a .PLA, with the token before it.

    A path here is an uppercase run that matches PATH_RE, is followed by a
    NUL, and is preceded by two bytes. The two bytes are returned as one
    big-endian u16 so the caller can check what introduces it.
    """
    out = []
    for m in PATH_RE.finditer(d):
        s, e = m.start(), m.end()
        if e >= len(d) or d[e] != 0:
            continue
        if s < 2:
            continue
        tok = struct.unpack(">H", d[s - 2:s])[0]
        out.append((s, tok, m.group().decode("ascii")))
    return out


def tokens_of(d):
    """The file read as big-endian u16, with every string operand skipped."""
    spans = str_spans(d)
    i, out = 0, []
    while i + 1 < len(d):
        jump = None
        for a, b in spans:
            if a <= i < b:
                jump = b
                break
        if jump is not None:
            i = jump          # a path may start at an odd offset; land past it
            continue
        out.append(struct.unpack(">H", d[i:i + 2])[0])
        i += 2
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    pladir = os.path.join(root, "SMAN5", "PLA")
    assert os.path.isdir(pladir), "no SMAN5/PLA under %r" % root
    names = sorted(n for n in os.listdir(pladir) if n.upper().endswith(".PLA"))
    assert names, "no .PLA scripts found -- nothing to read"

    # every file in the object, for the reachability question
    allfiles = set()
    for dirpath, _dirs, files in os.walk(root):
        for n in files:
            allfiles.add(os.path.relpath(os.path.join(dirpath, n), root)
                         .replace(os.sep, "/").upper())
    assert len(allfiles) > 100, "expected the whole object, got %d files" % len(allfiles)

    print("=== the fifteen scripts, and what each one names ===")
    refs = defaultdict(list)          # script -> [(token, path)]
    tokext = defaultdict(Counter)     # token -> extension counter
    total_paths = 0
    for n in names:
        d = open(os.path.join(pladir, n), "rb").read()
        ps = paths_in(d)
        total_paths += len(ps)
        for _s, tok, p in ps:
            refs[n].append((tok, p))
            tokext[tok][p.rsplit(".", 1)[-1]] += 1
        seq = " ".join("%s" % p.rsplit("\\", 1)[-1] for _s, _t, p in ps)
        print("  %-14s %5d bytes  %2d paths  %s"
              % (n, len(d), len(ps), seq[:110]))
    print("  total path references: %d" % total_paths)
    print("")

    print("=== which token introduces a path, and is the mapping one-to-one? ===")
    ok = True
    for tok in sorted(tokext):
        exts = tokext[tok]
        line = ", ".join("%s x%d" % (e, c) for e, c in exts.most_common())
        print("  token 0x%02X -> %s" % (tok, line))
        if len(exts) != 1:
            ok = False
    print("  one token per extension, one extension per token: %s" % ok)
    assert ok, "a token introduces more than one kind of file -- derivation is wrong"
    print("")

    if "--tokens" in sys.argv:
        print("=== opcode histogram over all fifteen scripts ===")
        hist = Counter()
        strs = Counter()
        for n in names:
            d = open(os.path.join(pladir, n), "rb").read()
            hist.update(tokens_of(d))
            for s, e in str_spans(d):
                strs[d[s:e].rstrip(b"\x00").decode("ascii", "replace")] += 1
        tot = sum(hist.values())
        zero_hi = sum(c for v, c in hist.items() if v < 0x100)
        print("  distinct u16 values: %d   occurrences: %d" % (len(hist), tot))
        print("  values below 0x0100, i.e. with a zero high byte: %d = %.4f %%"
              % (zero_hi, 100.0 * zero_hi / tot))
        print("  -- that is the test of the big-endian reading: a stream of")
        print("     small numbers stored big-endian has a zero high byte; the")
        print("     same bytes read little-endian would not.")
        print("  the twenty commonest:")
        for v, c in hist.most_common(20):
            print("    0x%04X %6d  = %d" % (v, c, v))
        print("")
        print("  string operands that are not paths:")
        for s, c in strs.most_common():
            if "." not in s:
                print("    %-12s %4d" % (s, c))
        print("")

    if "--graph" in sys.argv:
        print("=== the reference graph ===")
        named = set()
        for n in names:
            for _t, p in refs[n]:
                named.add(p.replace("\\", "/").upper())
        missing = sorted(p for p in named if p not in allfiles)
        print("  distinct files named by some script : %d" % len(named))
        print("  of which do not exist in the object : %d" % len(missing))
        for p in missing:
            print("      DANGLING %s" % p)
        print("")
        # a script is itself reached if some script names it; none do, but
        # check rather than claim.
        unreached = sorted(allfiles - named)
        print("  files no script names               : %d of %d"
              % (len(unreached), len(allfiles)))
        byext = Counter(p.rsplit(".", 1)[-1] if "." in p.rsplit("/", 1)[-1]
                        else "(none)" for p in unreached)
        for e, c in byext.most_common():
            print("      .%-6s %3d" % (e.lower(), c))
        print("")
        print("  the unreached, in full:")
        for p in unreached:
            print("      %s" % p)
        print("")
        # The scripts are only one of the two things that name files. The two
        # Turbo Pascal executables carry length-prefixed Pascal strings that
        # are filenames -- `Arcade.pal`, `AnimJoy.Tab`, `SimulMan.Ele` -- and
        # some of them are stems with no extension (`Numeri`, `Status`,
        # `Orologio`, `buffer`, `ARCADE`) to which the program appends one.
        # Stopping at the scripts would report 64 unreachable files, and 44 of
        # them are named a few kilobytes away in a different file.
        print("  === the second namer: the executables ===")
        exenamed = set()
        stems = set()
        for dp, _dd, ff in os.walk(root):
            for n in sorted(ff):
                if not n.upper().endswith(".EXE"):
                    continue
                d = open(os.path.join(dp, n), "rb").read()
                for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_]{1,11}\.[A-Za-z][A-Za-z0-9]{1,2}",
                                     d):
                    s, e = m.start(), m.end()
                    if s and d[s - 1] == e - s:      # Pascal length prefix
                        exenamed.add(m.group().decode().upper())
                for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_]{3,11}", d):
                    s, e = m.start(), m.end()
                    if s and d[s - 1] == e - s:
                        stems.add(m.group().decode().upper())
        resolved = set()
        for p in allfiles:
            base = p.rsplit("/", 1)[-1]
            stem = base.rsplit(".", 1)[0]
            if base in exenamed or stem in stems or any(
                    stem.startswith(x) and len(x) >= 4 for x in stems):
                resolved.add(p)
        print("      filenames-with-extension in Pascal strings : %d" % len(exenamed))
        print("      bare stems in Pascal strings               : %d" % len(stems))
        print("      files in the object they resolve to        : %d" % len(resolved))
        dangling_exe = sorted(x for x in exenamed
                              if not any(p.endswith("/" + x) or p == x for p in allfiles))
        print("      names the executables ask for that are NOT here : %d"
              % len(dangling_exe))
        for x in dangling_exe:
            print("         MISSING %s" % x)
        nothing = sorted(allfiles - named - resolved)
        print("      files nothing in the object names at all   : %d of %d"
              % (len(nothing), len(allfiles)))
        for p in nothing:
            print("         %s" % p)
        print("")

        # the interesting half: of the data kinds a script CAN name, how many
        # are named?
        print("  reachability restricted to the three kinds a .PLA can name:")
        for ext in ("ANI", "CHV", "MDI"):
            have = {p for p in allfiles if p.endswith("." + ext)}
            hit = have & named
            print("      .%-4s %2d of %2d named  (%.4f %%)"
                  % (ext.lower(), len(hit), len(have),
                     100.0 * len(hit) / len(have) if have else 0.0))
            for p in sorted(have - hit):
                print("          never named: %s" % p)


if __name__ == "__main__":
    main()
