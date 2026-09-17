#!/usr/bin/env python3
"""kftext.py -- where the game's text is, given that the file the engine looks
in first is zero bytes long.

THE QUESTION
------------
`KFGame/Localization/INT/KFGame.int` is **0 bytes**. That is the file UDK
reads for the English strings of a game whose package is called `KFGame`, and
it is empty. So either the game shows no text, or the text is somewhere else.

WHAT THIS PROGRAM DOES
----------------------
Three censuses, in order.

1. **The localisation tree.** 206 files begin `FF FE 5B 00` -- a UTF-16LE
   byte-order mark followed by `[`, the first character of an `.ini`-style
   section header. They are read as text, and the question asked of them is
   whose they are.
2. **The `.int` files under the game's own localisation directory**, by name
   and by size.
3. **The packages.** Every export whose class name contains `Subtitle` is
   scanned for length-prefixed strings, which is how UE3 serialises an
   `FString`: a signed `i32` count, positive for ANSI and negative for
   UTF-16LE, then that many characters including the terminator. The strings
   that come out are the game's script.

    python tools/kftext.py --selftest
    python tools/kftext.py --loc
    python tools/kftext.py --subtitles
    python tools/kftext.py --subtitles --show 40
"""
import argparse
import collections
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kfpkg as upkg                                       # noqa: E402

ROOT = "karmaflow-steam"
BOM16 = b"\xff\xfe"


def utf16_files(root):
    for r, _d, fs in os.walk(root):
        for f in sorted(fs):
            p = os.path.join(r, f)
            try:
                with open(p, "rb") as fh:
                    head = fh.read(4)
            except OSError:
                continue
            if head[:2] == BOM16:
                yield p, head


def strings_in(d, a, b, minlen=2):
    """Every UE3 FString that lies wholly inside [a, b)."""
    out = []
    o = a
    while o + 4 <= b:
        (n,) = struct.unpack_from("<i", d, o)
        if minlen <= n <= 8192 and o + 4 + n <= b:
            s = d[o + 4:o + 4 + n]
            if s.endswith(b"\x00") and all(
                    32 <= c < 127 or c in (9, 10, 13) for c in s[:-1]):
                out.append(s[:-1].decode("latin-1"))
                o += 4 + n
                continue
        if -8192 <= n <= -minlen and o + 4 + (-n) * 2 <= b:
            s = d[o + 4:o + 4 + (-n) * 2]
            try:
                t = s.decode("utf-16-le")
            except UnicodeDecodeError:
                t = None
            if t and t.endswith("\x00") and all(
                    31 < ord(c) < 0x3000 for c in t[:-1]):
                out.append(t[:-1])
                o += 4 + (-n) * 2
                continue
        o += 1
    return out


CUE = re.compile(r"^([0-9]+(?:[.,][0-9]+)?)#(.*)#([0-9]+(?:[.,][0-9]+)?)\s*$")


def cmd_loc(args):
    files = list(utf16_files(args.root))
    print("files beginning with a UTF-16LE BOM : %d" % len(files))
    print("of those, whose fourth byte is `[`  : %d"
          % sum(1 for _p, h in files if h == b"\xff\xfe[\x00"))
    tot = sum(os.path.getsize(p) for p, _h in files)
    print("bytes                               : %d" % tot)
    bydir = collections.Counter(
        os.path.dirname(os.path.relpath(p, args.root)).replace("\\", "/")
        for p, _h in files)
    print()
    print("by directory:")
    for k, v in sorted(bydir.items()):
        print("   %-40s %d" % (k, v))
    print()
    print("the game's own localisation directory, in full:")
    d = os.path.join(args.root, "KFGame", "Localization", "INT")
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f)
        size = os.path.getsize(p)
        note = ""
        if size == 0:
            note = "  <-- EMPTY"
        else:
            txt = open(p, "rb").read().decode("utf-16-le", errors="replace")
            secs = re.findall(r"^\[(.+?)\]", txt, re.M)
            keys = len(re.findall(r"^[^\[\r\n]+=", txt, re.M))
            note = "  %d sections, %d keys, first [%s]" % (
                len(secs), keys, secs[0] if secs else "")
        print("   %-28s %8d%s" % (f, size, note))
    print()
    print("names of the game's own localisation files that carry the game's")
    print("own name : %s"
          % [f for f in sorted(os.listdir(d)) if f.lower().startswith("kf")])
    print("and their sizes : %s"
          % [os.path.getsize(os.path.join(d, f))
             for f in sorted(os.listdir(d)) if f.lower().startswith("kf")])
    return 0


def cmd_subtitles(args):
    cues = []
    per_pkg = collections.Counter()
    classes = collections.Counter()
    exports = 0
    pkgs = 0
    for p in sorted(upkg.tagged(args.root)):
        try:
            pkg = upkg.Package(p)
            names = pkg.names()
            imps = pkg.imports(names)
            exps = pkg.exports(names)
        except Exception:
            continue
        want = [x for x in exps
                if "Subtitle" in (upkg.resolve(x["class"], exps, imps) or "")]
        if not want:
            continue
        pkgs += 1
        pkg._logical = None
        d = pkg.logical()
        for x in want:
            exports += 1
            cls = upkg.resolve(x["class"], exps, imps) or ""
            classes[cls] += 1
            for s in strings_in(d, x["offset"], x["offset"] + x["size"], 4):
                m = CUE.match(s)
                if m:
                    cues.append((upkg.rel(p), x["name"], m.group(1),
                                 m.group(2), m.group(3)))
                    per_pkg[upkg.rel(p)] += 1
        pkg._logical = None
    print("packages holding a Subtitle-class export : %d" % pkgs)
    print("those exports                            : %d" % exports)
    print("by class                                 : %s" % dict(classes))
    print("cue strings matching  start#text#end     : %d" % len(cues))
    print()
    print("by package:")
    for k, v in sorted(per_pkg.items()):
        print("   %-56s %4d" % (k, v))
    print()
    commas = sum(1 for c in cues if "," in c[2] or "," in c[4])
    dots = sum(1 for c in cues if "." in c[2] or "." in c[4])
    print("cues whose timing uses a decimal COMMA : %d" % commas)
    print("cues whose timing uses a decimal POINT : %d" % dots)
    print("   A comma for the decimal separator is the Dutch convention and")
    print("   the English one is a point. These are hand-typed cue sheets.")
    print()
    words = sum(len(c[3].split()) for c in cues)
    print("words of dialogue and narration : %d" % words)
    curly = sum(1 for c in cues if "’" in c[3])
    straight = sum(1 for c in cues if "'" in c[3])
    print("cues with a curly apostrophe    : %d" % curly)
    print("cues with a straight apostrophe : %d" % straight)
    print()
    if args.show:
        print("the first %d cues, in package order:" % args.show)
        for c in cues[:args.show]:
            print("   %-40s %7s -> %-7s  %s"
                  % (os.path.basename(c[0])[:40], c[2], c[4], c[3]))
    return 0


def selftest():
    cases = []
    blob = struct.pack("<i", 6) + b"hello\x00"
    cases.append(("an ANSI FString", strings_in(blob, 0, len(blob)) == ["hello"]))
    w = "ciaò\x00".encode("utf-16-le")
    blob = struct.pack("<i", -5) + w
    cases.append(("a UTF-16 FString",
                  strings_in(blob, 0, len(blob)) == ["ciaò"]))
    blob = struct.pack("<i", 9999) + b"short"
    cases.append(("a length that does not fit is not a string",
                  strings_in(blob, 0, len(blob)) == []))
    blob = struct.pack("<i", 6) + b"he\x01lo\x00"
    cases.append(("a control byte inside is not a string",
                  strings_in(blob, 0, len(blob)) == []))
    blob = struct.pack("<i", 5) + b"hello"
    cases.append(("no NUL terminator is not a string",
                  strings_in(blob, 0, len(blob)) == []))
    m = CUE.match("13,5#The title of Guardian is for me to claim#18 ")
    cases.append(("a cue with a decimal comma parses",
                  bool(m) and m.group(1) == "13,5" and m.group(3) == "18"))
    cases.append(("a bare sentence is not a cue",
                  CUE.match("The title of Guardian") is None))
    cases.append(("a cue with a decimal point parses",
                  bool(CUE.match("2.5#x#3.0"))))
    ok = sum(1 for _n, v in cases if v)
    print("kftext selftest: %d specimens built in memory" % len(cases))
    for n, v in cases:
        print("  %-52s %s" % (n, "PASS" if v else "FAIL"))
    print()
    print("%d of %d behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--show", type=int, default=0)
    for c in ("selftest", "loc", "subtitles"):
        ap.add_argument("--" + c, action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.loc:
        return cmd_loc(a)
    if a.subtitles:
        return cmd_subtitles(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
