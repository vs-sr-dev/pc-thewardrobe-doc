#!/usr/bin/env python3
"""cptext.py -- census the high bytes of a text file and decode it under a
named DOS codepage.

CP437 and CP866 are published, they are both in Python's standard library, and
the only thing worth doing carefully is saying WHICH one and WHY. This tool
makes the choice visible instead of hiding it inside a `.decode()` call:

  * it counts the bytes >= 0x80 and how many distinct values they take;
  * it reports which lines carry them, so that a file that is ASCII everywhere
    except one line says so;
  * it decodes under each candidate codepage and prints the differing lines
    side by side, because the census cannot choose and a human can.

CP437 and CP866 agree on 0x00..0x7F and on the box-drawing range 0xB0..0xDF.
They disagree on 0x80..0xAF and 0xE0..0xFF, where CP437 has accented Latin and
CP866 has Cyrillic. **So a file whose high bytes are all in 0xB0..0xDF cannot
be told apart by these two codepages at all**, and this tool says that rather
than picking one.

    python tools/cptext.py census _work/members/readme.txt
    python tools/cptext.py decode _work/members/readme.txt --cp cp866
    python tools/cptext.py selftest
"""
import argparse
import collections
import sys

CANDIDATES = ("cp437", "cp866", "cp1251", "latin-1")
AMBIGUOUS_LO, AMBIGUOUS_HI = 0xB0, 0xDF


def census(data):
    high = [b for b in data if b >= 0x80]
    distinct = sorted(set(high))
    shared = [b for b in distinct if AMBIGUOUS_LO <= b <= AMBIGUOUS_HI]
    return {
        "bytes": len(data),
        "high": len(high),
        "distinct": distinct,
        "shared_only": len(shared) == len(distinct) and bool(distinct),
        "counts": collections.Counter(high),
    }


def high_lines(data):
    out = []
    for i, line in enumerate(data.split(b"\n"), 1):
        n = sum(1 for b in line if b >= 0x80)
        if n:
            out.append((i, n, line))
    return out


def cmd_census(args):
    data = open(args.path, "rb").read()
    c = census(data)
    print("file           : %s" % args.path)
    print("bytes          : %d" % c["bytes"])
    print("bytes >= 0x80  : %d" % c["high"])
    print("distinct values: %d" % len(c["distinct"]))
    if c["distinct"]:
        print("  %s" % " ".join("0x%02x" % b for b in c["distinct"]))
    print("all of them in the CP437/CP866 shared box-drawing range 0xB0..0xDF"
          " : %s" % ("YES -- the two codepages cannot be told apart here"
                     if c["shared_only"] else "no"))
    lines = high_lines(data)
    print("lines carrying a high byte : %d of %d"
          % (len(lines), len(data.split(b"\n"))))
    for i, n, line in lines[:args.show]:
        print("  line %-4d %2d high bytes" % (i, n))
    if len(lines) > args.show:
        print("  ... %d more" % (len(lines) - args.show))
    return 0


def cmd_decode(args):
    data = open(args.path, "rb").read()
    cps = [args.cp] if args.cp else list(CANDIDATES)
    lines = high_lines(data)
    if args.whole:
        for cp in cps:
            print("=== %s ===" % cp)
            sys.stdout.write(data.decode(cp))
            print()
        return 0
    print("file : %s   -- only the %d lines carrying a byte >= 0x80"
          % (args.path, len(lines)))
    for i, n, line in lines:
        print()
        print("line %d, %d high bytes:" % (i, n))
        for cp in cps:
            try:
                print("  %-8s %s" % (cp, line.decode(cp).rstrip("\r")))
            except UnicodeDecodeError as e:
                print("  %-8s UNDECODABLE: %s" % (cp, e))
    return 0


def cmd_selftest(args):
    checks = []

    # CP866 Cyrillic and CP437 accented Latin over the same bytes.
    b = bytes([0x8E, 0x87, 0x88])
    checks.append(("the same three bytes decode differently under the two "
                   "codepages",
                   b.decode("cp866") != b.decode("cp437"),
                   "%r vs %r" % (b.decode("cp866"), b.decode("cp437"))))

    # The shared box-drawing range really is shared.
    box = bytes(range(AMBIGUOUS_LO, AMBIGUOUS_HI + 1))
    checks.append(("0xB0..0xDF is identical under CP437 and CP866",
                   box.decode("cp437") == box.decode("cp866"), ""))

    # A pure box-drawing file must be reported as undecidable.
    c = census(b"+" + box + b"+")
    checks.append(("a file whose high bytes are all box drawing is reported "
                   "as undecidable", c["shared_only"], ""))

    # A file with a Cyrillic-range byte must NOT be reported as undecidable.
    c = census(b"x" + bytes([0x8E]))
    checks.append(("a file with a byte outside that range is not reported as "
                   "undecidable", not c["shared_only"], ""))

    # A pure ASCII file has no high bytes and is not undecidable either.
    c = census(b"plain ascii")
    checks.append(("a pure ASCII file reports zero high bytes and is not "
                   "called undecidable",
                   c["high"] == 0 and not c["shared_only"], ""))

    # The line finder must find the right line and only that one.
    lines = high_lines(b"one\ntwo " + bytes([0x8E]) + b"\nthree\n")
    checks.append(("the line finder returns exactly the line with the high "
                   "byte", [l[0] for l in lines] == [2], str(lines[:1])))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL",
                                   note))
        if not ok:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    # This tool prints Cyrillic and box drawing by design. A Windows console
    # defaulting to CP1252 raises UnicodeEncodeError halfway through a table,
    # which would make the selftest fail for a reason that has nothing to do
    # with the checks. Force UTF-8 where the stream allows it and fall back to
    # replacement characters where it does not; never crash on output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("census")
    c.add_argument("path")
    c.add_argument("--show", type=int, default=10)
    c.set_defaults(func=cmd_census)
    d = sub.add_parser("decode")
    d.add_argument("path")
    d.add_argument("--cp")
    d.add_argument("--whole", action="store_true")
    d.set_defaults(func=cmd_decode)
    s = sub.add_parser("selftest")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
