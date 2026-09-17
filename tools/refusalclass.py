#!/usr/bin/env python3
"""refusalclass.py -- classify `refusals.py`'s refusals by WHY they refused,
because "42 refused" counts two different things as one.

`pc-rpgmaker2000-doc/docs/12` measured this by hand on one object and found
that **23 of 40 "refusals" were argparse errors that never read a byte**. A
tool that says `error: invalid choice: 'rpgmaker2003-steam'` has told you
nothing about the object; it has told you its command line differs from the one
the harness guessed. Counting that identically to a reader that opened four
bytes and rejected them is not a measurement.

Doing it by hand once is an observation. Doing it by program makes it a
repeatable measurement with a second population, which is the only way to know
whether the ratio is a property of the harness or of the object.

FOUR CLASSES, each with the text that identifies it:

    argparse   the tool's own argument parser rejected the command line
    oserror    the path was wrong for it -- a directory where it wanted a
               file, or a file that is not there
    format     it read bytes and said no
    exception  it fell over

The classes are decided from `refusals.py`'s own captured message, so the
classification can be checked against the file it reads.

    python tools/refusalclass.py notes/refusals.txt
    python tools/refusalclass.py notes/refusals.txt --expect-argparse 23
    python tools/refusalclass.py --selftest
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

ARGPARSE = (
    "error: argument", "error: unrecognized arguments",
    "error: the following arguments are required", "error: invalid choice",
    "usage:", "error: argument cmd", "error: one of the arguments",
)
OSERROR = (
    "No such file or directory", "FileNotFoundError", "IsADirectoryError",
    "PermissionError", "NotADirectoryError", "Errno 2", "Errno 13",
    "Errno 21",
)
EXCEPTION = (
    "Traceback", "Error:", "ValueError", "KeyError", "IndexError",
    "TypeError", "AttributeError", "ZeroDivisionError", "struct.error",
)
ROW = re.compile(r"^(\S+\.py)\s+(REFUSED|exit \d+)\s*(.*)$")


def classify(message):
    m = message
    for needle in OSERROR:
        if needle in m:
            return "oserror"
    for needle in ARGPARSE:
        if needle in m:
            return "argparse"
    for needle in EXCEPTION:
        if needle in m:
            return "exception"
    return "format"


def parse(path):
    rows = []
    cur = None
    for line in open(path, encoding="utf-8", errors="replace"):
        m = ROW.match(line.rstrip("\n"))
        if m:
            cur = {"tool": m.group(1), "verdict": m.group(2),
                   "message": m.group(3)}
            rows.append(cur)
        elif cur is not None and line.startswith(" " * 20):
            frag = line.strip()
            if not frag.startswith("for:"):
                cur["message"] += " " + frag
    if not rows:
        raise SystemExit("refusalclass: no rows parsed from %s -- the shape "
                         "of refusals.py's output changed and this tool is "
                         "now lying" % path)
    return rows


def run(args):
    # Handed a DIRECTORY -- which is what `refusals.py` itself takes, so it is
    # the natural slip -- this used to raise `PermissionError` out of `open()`
    # and print a five-line traceback carrying an absolute path, which is also
    # a rule-7 hazard. That is the `dirguard` class, third instance, after
    # `ne.py` and `jpeg.py`.
    dirguard.want_file(args.path, "refusalclass")
    rows = parse(args.path)
    refused = [r for r in rows if r["verdict"] == "REFUSED"]
    zero = [r for r in rows if r["verdict"] != "REFUSED"]
    counts = collections.Counter(classify(r["message"]) for r in refused)

    print("readers in the report        : %d" % len(rows))
    print("refused with a non-zero exit : %d" % len(refused))
    print("exited 0 anyway              : %d" % len(zero))
    print()
    print("  %-12s %5s   %s" % ("class", "count", "what it means"))
    meanings = {
        "argparse": "the command line, not the object -- no byte was read",
        "oserror": "the path was wrong for it",
        "format": "it read bytes and said no",
        "exception": "it fell over",
    }
    total = 0
    for c in ("argparse", "oserror", "format", "exception"):
        print("  %-12s %5d   %s" % (c, counts[c], meanings[c]))
        total += counts[c]
    print("  %-12s %5d" % ("TOTAL", total))
    print("  the four classes sum to the refusal total : %s"
          % (total == len(refused)))
    print()
    for c in ("format", "exception", "oserror"):
        named = [r["tool"] for r in refused if classify(r["message"]) == c]
        if named:
            print("  %-10s : %s" % (c, ", ".join(sorted(named))))
    print()
    if len(refused):
        print("  argparse share of the refusals : %d of %d = %.4f %%"
              % (counts["argparse"], len(refused),
                 100.0 * counts["argparse"] / len(refused)))
    if args.expect_argparse is not None and counts["argparse"] != args.expect_argparse:
        raise SystemExit("FATAL: --expect-argparse %d, got %d"
                         % (args.expect_argparse, counts["argparse"]))
    return 0


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    check("an invalid choice is argparse",
          classify("x.py: error: argument cmd: invalid choice: 'root'"),
          "argparse")
    check("unrecognized arguments is argparse",
          classify("x.py: error: unrecognized arguments: root"), "argparse")
    check("a required argument is argparse",
          classify("error: the following arguments are required: path"),
          "argparse")
    check("a missing file is an OS error",
          classify("FileNotFoundError: [Errno 2] No such file or directory"),
          "oserror")
    check("an OS error wins over a usage line",
          classify("usage: x.py ... FileNotFoundError: [Errno 2]"),
          "oserror")
    check("a magic refusal is a format refusal",
          classify("REFUSED: magic is 0x00505A4D, not 0x8C655D13"), "format")
    check("a traceback is an exception",
          classify("Traceback (most recent call last): ZeroDivisionError"),
          "exception")
    check("a plain refusal with no marker is a format refusal",
          classify("not a ZIP"), "format")

    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="refusalclass-")
    try:
        p = os.path.join(tmp, "r.txt")
        open(p, "w").write(
            "isz.py           REFUSED  REFUSED: magic is 0x1, not 0x2\n"
            "                          for: an InstallShield archive\n"
            "agp.py           REFUSED  agp.py: error: invalid choice: 'x'\n"
            "                          for: the .agp archive\n"
            "lcf.py           exit 0     distinct field tags : 133\n"
            "                          for: an LCF database\n")
        rows = parse(p)
        check("three rows parsed", len(rows), 3)
        check("two refused", sum(1 for r in rows
                                 if r["verdict"] == "REFUSED"), 2)
        cl = [classify(r["message"]) for r in rows
              if r["verdict"] == "REFUSED"]
        check("one format and one argparse", sorted(cl),
              ["argparse", "format"])
        check("the 'for:' line is not folded into the message",
              "InstallShield" in rows[0]["message"], False)

        empty = os.path.join(tmp, "e.txt")
        open(empty, "w").write("nothing here\n")
        try:
            parse(empty)
            got = "no exception"
        except SystemExit:
            got = "SystemExit"
        check("a report with no rows is fatal", got, "SystemExit")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-50s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--expect-argparse", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.path == "selftest":
        return selftest()
    if not args.path:
        raise SystemExit("refusalclass: a refusals report is required "
                         "(or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
