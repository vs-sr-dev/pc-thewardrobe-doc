#!/usr/bin/env python3
"""toolsdiff.py -- compare this repository's tools/ against another's, file by
file, by sha1.

Every session in this pipeline inherits the previous session's box and then
adds to it. The claim "522 arrived and 528 leave" is only worth making if
somebody checked it, and the check is not `wc -l`: it is a set comparison plus
a hash comparison, because a file that was silently edited has the same name
and the same count.

Loud by construction:

  * `--expect-differing N` fails when the differing count is not N;
  * `--expect-common N` fails when the common count is not N;
  * a missing directory on either side is fatal rather than an empty report.

    python tools/toolsdiff.py ../pc-rpgmaker2000-doc/tools
    python tools/toolsdiff.py ../pc-rpgmaker2000-doc/tools --expect-differing 0
"""
import argparse
import hashlib
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def sha1(path):
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def collect(d):
    if not os.path.isdir(d):
        raise SystemExit("toolsdiff: not a directory: %s" % d)
    out = {}
    for name in sorted(os.listdir(d)):
        if name.endswith(".py"):
            out[name] = sha1(os.path.join(d, name))
    if not out:
        raise SystemExit("toolsdiff: no .py files in %s -- refusing to report "
                         "an empty comparison as agreement" % d)
    return out


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("theirs", nargs="?")
    ap.add_argument("--mine", default=os.path.join(root, "tools"))
    ap.add_argument("--ignore", action="append", default=[],
                    help="a file name to exclude from BOTH sides, named in the "
                         "report so the exclusion is visible")
    ap.add_argument("--expect-differing", type=int)
    ap.add_argument("--expect-common", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.theirs:
        raise SystemExit("toolsdiff: a directory to compare against is "
                         "required (or --selftest)")

    mine = collect(args.mine)
    theirs = collect(args.theirs)
    for name in args.ignore:
        mine.pop(name, None)
        theirs.pop(name, None)

    only_mine = sorted(set(mine) - set(theirs))
    only_theirs = sorted(set(theirs) - set(mine))
    common = sorted(set(mine) & set(theirs))
    differing = [n for n in common if mine[n] != theirs[n]]

    print("mine   : %s" % os.path.relpath(args.mine, root))
    print("theirs : %s" % args.theirs)
    if args.ignore:
        print("ignored on both sides : %s" % ", ".join(sorted(args.ignore)))
    print()
    print("mine   : %d .py     theirs : %d .py" % (len(mine), len(theirs)))
    print("only mine   : %s" % (", ".join(only_mine) or "none"))
    print("only theirs : %s" % (", ".join(only_theirs) or "none"))
    print("common      : %d    differing   : %d" % (len(common),
                                                    len(differing)))
    for n in differing:
        print("   DIFFERS  %-24s mine %s  theirs %s"
              % (n, mine[n][:12], theirs[n][:12]))

    bad = []
    if args.expect_differing is not None and len(differing) != args.expect_differing:
        bad.append("--expect-differing %d : got %d"
                   % (args.expect_differing, len(differing)))
    if args.expect_common is not None and len(common) != args.expect_common:
        bad.append("--expect-common %d : got %d"
                   % (args.expect_common, len(common)))
    if bad:
        print()
        for b in bad:
            print("FATAL: %s" % b)
        raise SystemExit(1)


def selftest():
    import shutil
    import tempfile
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    tmp = tempfile.mkdtemp(prefix="toolsdiff-")
    try:
        a = os.path.join(tmp, "a")
        b = os.path.join(tmp, "b")
        os.makedirs(a)
        os.makedirs(b)
        for d in (a, b):
            open(os.path.join(d, "same.py"), "w").write("same\n")
        open(os.path.join(a, "edited.py"), "w").write("one\n")
        open(os.path.join(b, "edited.py"), "w").write("two\n")
        open(os.path.join(a, "onlymine.py"), "w").write("m\n")
        open(os.path.join(b, "onlytheirs.py"), "w").write("t\n")
        open(os.path.join(a, "notpython.txt"), "w").write("ignored\n")

        mine = collect(a)
        theirs = collect(b)
        check("non-.py files are skipped", "notpython.txt" in mine, False)
        check("mine has three .py", len(mine), 3)
        common = sorted(set(mine) & set(theirs))
        check("two common", len(common), 2)
        differing = [n for n in common if mine[n] != theirs[n]]
        check("one differs", differing, ["edited.py"])
        check("only mine", sorted(set(mine) - set(theirs)), ["onlymine.py"])
        check("only theirs", sorted(set(theirs) - set(mine)),
              ["onlytheirs.py"])
        check("identical files hash equal", mine["same.py"], theirs["same.py"])

        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        try:
            collect(empty)
            got = "no exception"
        except SystemExit:
            got = "SystemExit"
        check("an empty directory is fatal", got, "SystemExit")

        try:
            collect(os.path.join(tmp, "nope"))
            got = "no exception"
        except SystemExit:
            got = "SystemExit"
        check("a missing directory is fatal", got, "SystemExit")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-38s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
